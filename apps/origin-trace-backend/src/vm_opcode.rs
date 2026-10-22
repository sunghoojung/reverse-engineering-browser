use crate::{
    durable,
    error::{Error, Result},
    evidence, vm,
};
use regex::Regex;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::LazyLock,
};

#[path = "vm_opcode_wasm.rs"]
mod wasm;

const PRODUCER_VERSION: &str = "2.1.0";
const MAX_SAMPLES: usize = 4096;
const MAX_HANDLERS: usize = 1024;
const MAX_SNAPSHOTS: usize = 16;
const MAX_WORKSPACES: usize = 256;
const MAX_UNKNOWNS: usize = 256;
const SNAPSHOT_PREVIEW_BYTES: usize = 4096;

static FUNCTION_SIGNATURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\bfunction\b[^{}]{0,1024}|\([^(){}]{0,1024}\)\s*=>|[A-Za-z_$][\w$]*\s*=>)\s*\{")
        .expect("function signature")
});
static SWITCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bswitch\s*\(").expect("switch"));
static CASE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bcase\s+(0x[0-9a-f]+|\d+)\s*:").expect("integer case"));
static INDEXED_HANDLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(handlers?|opcodes?)\s*\[\s*(0x[0-9a-f]+|\d+)\s*\]\s*=\s*(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
    )
    .expect("indexed handler")
});
static COMPUTED_HANDLER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:handlers?|opcodes?)\s*\[\s*([^\]]+)\s*\]\s*=\s*(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
    )
    .expect("computed handler")
});
static INDEXED_DISPATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\[((?:[^\[\]]+|\[[^\[\]]*\])+)\]\s*\(")
        .expect("indexed dispatch")
});
static NUMERIC_OBJECT_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)\b(0x[0-9a-f]+|\d+)\s*:\s*(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
    )
    .expect("numeric object handler")
});
static NUMERIC_METHOD_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)\b(0x[0-9a-f]+|\d+)\s*\([^)]*\)\s*\{").expect("numeric object method")
});
static COMPUTED_OBJECT_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)\[[^\]]+\]\s*:\s*(?:function\b|\([^)]*\)\s*=>)")
        .expect("computed object handler")
});
static STACK_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bstack\b").expect("stack identifier"));
static REGISTER_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:regs|registers?)\b").expect("register identifier"));
static CASE_BOUNDARY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bcase\b[^:;{}]*:|\bdefault\s*:").expect("case boundary"));
static BYTE_READ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(program|bytecode|code|instructions|bytes)\s*\[\s*(pc|ip|instructionPointer|offset|cursor)\s*(?:(\+\+)|\+\s*([0-9]+))?\s*\]")
        .expect("adjacent byte read")
});
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$]*$").expect("identifier"));
static CONDITIONAL_READ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:if|for|while|switch|try|catch)\b|\?|&&|\|\|").expect("conditional read")
});

pub(crate) fn is_snapshot_candidate(value: &Value) -> bool {
    value["kind"] == "bytecode_buffer" || value["capture_origin"] == "runtime_typed_array"
}

pub(crate) fn validate_snapshot_artifact(value: &Value) -> Result<()> {
    let identifiers = [
        "artifact_id",
        "session_id",
        "navigation_id",
        "frame_id",
        "parent_artifact_id",
        "creator_event_id",
        "execution_context_id",
    ];
    let hash = value["sha256"].as_str().unwrap_or("");
    let valid = value["protocol_version"] == 1
        && identifiers
            .iter()
            .all(|key| evidence::canonical(&value[*key], 64, false))
        && value["execution_context_id"] != "0"
        && value["kind"] == "bytecode_buffer"
        && value["capture_origin"] == "runtime_typed_array"
        && value["url"].as_str().is_some_and(|text| !text.is_empty())
        && value["mime_type"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
        && value["byte_size"].as_u64().is_some()
        && value["sensitive"] == false
        && hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value["content_path"] == format!("blobs/{hash}.bin");
    if !valid {
        return Err(Error::new(
            500,
            "The VM snapshot manifest contains a malformed record",
        ));
    }
    Ok(())
}

fn integer(text: &str) -> Option<u32> {
    if text.starts_with("0x") || text.starts_with("0X") {
        u32::from_str_radix(&text[2..], 16).ok()
    } else {
        text.parse().ok()
    }
}

fn matching(bytes: &[u8], opening: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(opening) {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn without_nested_functions(region: &str) -> String {
    let mut masked = vm::mask(region).into_bytes();
    let source = String::from_utf8(masked.clone()).expect("masked JavaScript");
    let mut ranges = Vec::new();
    for signature in FUNCTION_SIGNATURE.find_iter(&source) {
        let opening = signature.end() - 1;
        if let Some(closing) = matching(&masked, opening, b'{', b'}') {
            ranges.push((opening + 1, closing));
        }
    }
    for (start, end) in ranges {
        masked[start..end].fill(b' ');
    }
    String::from_utf8(masked).expect("nested function masking")
}

// These are deliberately syntactic checks, not an evaluator or a data-flow
// proof. An unrecognized selector cannot establish a fixed opcode mapping.
fn direct_selector(expression: &str, region: &str, depth: usize) -> bool {
    let expression = expression.trim();
    if integer(expression).is_some()
        || BYTE_READ
            .find(expression)
            .is_some_and(|m| m.start() == 0 && m.end() == expression.len())
    {
        return true;
    }
    if depth == 8 || !IDENTIFIER.is_match(expression) {
        return false;
    }
    let name = regex::escape(expression);
    let mutation = Regex::new(&format!(
        r"(?:\b{name}\s*(?:\+\+|--|[+\-^|&*/%<>=]+=)|(?:\+\+|--)\s*\b{name}\b)"
    ))
    .expect("selector mutation");
    if mutation.is_match(region) {
        return false;
    }
    let assignment =
        Regex::new(&format!(r"\bconst\s+{name}\s*=\s*([^;{{}}\n]+)")).expect("selector binding");
    let mut assignments = assignment.captures_iter(region);
    let Some(binding) = assignments.next() else {
        return false;
    };
    // Multiple writes and alias cycles are ambiguous, not a data-flow proof.
    assignments.next().is_none()
        && direct_selector(
            &binding[1],
            &region[..binding.get(0).expect("const binding").start()],
            depth + 1,
        )
}

fn operand_width(body: &str) -> (usize, &'static str) {
    let body = without_nested_functions(body);
    let reads = BYTE_READ.captures_iter(&body).take(5).collect::<Vec<_>>();
    if reads.is_empty() {
        return (
            0,
            "Operand width is unknown: no adjacent bytecode indexed read is visible.",
        );
    }
    if CONDITIONAL_READ.is_match(&body) {
        return (
            0,
            "Operand width is unknown: indexed reads are conditional or repeated.",
        );
    }
    let first = &reads[0];
    let mut remainder = body.as_bytes().to_vec();
    for read in &reads {
        let matched = read.get(0).expect("byte read");
        remainder[matched.start()..matched.end()].fill(b' ');
    }
    let pointer_write = Regex::new(&format!(
        r"(?:\b{0}\s*(?:\+\+|--|[+\-*/^|&%<>=]*=)|(?:\+\+|--)\s*\b{0}\b)",
        regex::escape(&first[2])
    ))
    .expect("operand pointer write");
    if reads.len() > 1
        && pointer_write.is_match(std::str::from_utf8(&remainder).expect("masked reads"))
    {
        return (
            0,
            "Operand width is unknown: the instruction pointer changes between indexed reads.",
        );
    }
    let incrementing = first.get(3).is_some();
    let mut offsets = BTreeSet::new();
    for (index, read) in reads.iter().enumerate() {
        let matched = read.get(0).expect("indexed read");
        let tail = body[matched.end()..].trim_start();
        static INDEXED_WRITE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^(?:=[^=]|=$|[+\-*/%&|^<>=]+=|\+\+|--)").expect("indexed write")
        });
        let prefix = body[..matched.start()].trim_end();
        if INDEXED_WRITE.is_match(tail) || prefix.ends_with("++") || prefix.ends_with("--") {
            return (
                0,
                "Operand width is unknown: an indexed access writes bytecode.",
            );
        }
        if read[1] != first[1] || read[2] != first[2] || read.get(3).is_some() != incrementing {
            return (
                0,
                "Operand width is unknown: indexed reads do not form one adjacent sequence.",
            );
        }
        let offset = if incrementing {
            index
        } else {
            read.get(4)
                .map_or(Some(0), |m| m.as_str().parse::<usize>().ok())
                .unwrap_or(usize::MAX)
        };
        offsets.insert(offset);
    }
    let width = offsets.len();
    if !matches!(width, 1 | 2 | 4) || offsets.iter().copied().ne(0..width) {
        return (
            0,
            "Operand width is unknown: no bounded 1, 2, or 4 byte sequence is visible.",
        );
    }
    (
        width,
        "Operand width is a static guess from adjacent bytecode indexed reads.",
    )
}

fn add_handler(
    handlers: &mut BTreeMap<u32, Value>,
    opcode: u32,
    handler_index: Option<u32>,
    range: (usize, usize),
    body: &str,
    note: &str,
) -> bool {
    if handlers.len() >= MAX_HANDLERS && !handlers.contains_key(&opcode) {
        return false;
    }
    handlers.entry(opcode).or_insert_with(|| {
        let (width, width_note) = operand_width(body);
        let mut value = json!({
            "opcode": opcode,
            "state": "inferred",
            "source": {"byte_offset": range.0, "byte_size": (range.1 - range.0).max(1)},
            "operand_width": width,
            "sample_count": 0,
            "notes": format!("{note} {width_note}"),
            "effects": [],
        });
        if let Some(index) = handler_index {
            value["handler_index"] = json!(index);
        }
        value
    });
    true
}

fn function_body(region: &str, header: regex::Match<'_>) -> Option<(usize, usize)> {
    let opening = if header.as_str().ends_with('{') {
        header.end() - 1
    } else {
        let opening = region[header.end()..].find('{')? + header.end();
        let tail = region[header.end()..opening].trim();
        if header.as_str().ends_with("function") {
            static PARAMETERS: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r"^(?:[A-Za-z_$][\w$]*\s*)?\([^(){};]*\)$").expect("function parameters")
            });
            if !PARAMETERS.is_match(tail) {
                return None;
            }
        } else if !tail.is_empty() {
            return None;
        }
        opening
    };
    Some((opening, matching(region.as_bytes(), opening, b'{', b'}')?))
}

fn shallow_braces(region: &str) -> String {
    let mut bytes = region.as_bytes().to_vec();
    let mut depth = 0usize;
    for byte in &mut bytes {
        match *byte {
            b'{' => {
                depth += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
            }
            _ if depth > 0 => {
                *byte = b' ';
            }
            _ => (),
        }
    }
    String::from_utf8(bytes).expect("masked object members")
}

fn object_handlers(
    region: &str,
    base: usize,
    blocked_tables: &BTreeSet<String>,
    handlers: &mut BTreeMap<u32, Value>,
    unknowns: &mut Vec<String>,
    handler_limit_hit: &mut bool,
) {
    let mut names = BTreeSet::new();
    for captures in INDEXED_DISPATCH.captures_iter(region) {
        names.insert(captures[1].to_owned());
    }
    names.extend([
        "handler".into(),
        "handlers".into(),
        "opcode".into(),
        "opcodes".into(),
    ]);
    for name in names {
        if blocked_tables.contains(&name) {
            continue;
        }
        let assignment = Regex::new(&format!(r"\b{}\s*=\s*\{{", regex::escape(&name)))
            .expect("object assignment");
        for candidate in assignment.find_iter(region) {
            let opening = candidate.end() - 1;
            let Some(closing) = matching(region.as_bytes(), opening, b'{', b'}') else {
                continue;
            };
            let object = &region[opening + 1..closing];
            // Nested helper bodies remain available for the source citation,
            // but numbers inside them are not object-map entries.
            let entries = shallow_braces(object);
            for pattern in [&*NUMERIC_OBJECT_ENTRY, &*NUMERIC_METHOD_ENTRY] {
                for captures in pattern.captures_iter(&entries) {
                    let Some(opcode) = integer(&captures[1]) else {
                        continue;
                    };
                    let matched = captures.get(0).expect("object handler match");
                    let Some((body_start, body_end)) = function_body(object, matched) else {
                        continue;
                    };
                    let offset = base + opening + 1;
                    if !add_handler(
                        handlers,
                        opcode,
                        Some(opcode),
                        (offset + matched.start(), offset + body_end + 1),
                        &object[body_start + 1..body_end],
                        "A numeric object-map handler is statically visible.",
                    ) {
                        *handler_limit_hit = true;
                    }
                }
            }
            if COMPUTED_OBJECT_ENTRY.is_match(&entries) {
                unknowns.push(
                    "A computed object-map property cannot be assigned a static opcode.".into(),
                );
            }
        }
    }
}

fn static_handlers(
    source: &str,
    start: usize,
    end: usize,
) -> (Vec<Value>, String, Vec<String>, Vec<Value>) {
    let region = vm::mask(&source[start..end]);
    let outer = without_nested_functions(&region);
    let mut handlers = BTreeMap::new();
    let mut unknowns = Vec::new();
    let mut omissions = Vec::new();
    let mut handler_limit_hit = false;
    let mut blocked_tables = BTreeSet::new();
    for captures in INDEXED_DISPATCH.captures_iter(&outer) {
        if !direct_selector(
            &captures[2],
            &outer[..captures.get(0).expect("dispatch match").start()],
            0,
        ) {
            blocked_tables.insert(captures[1].to_owned());
            unknowns.push("A computed, position-dependent, or saved-state handler selector has no proven fixed opcode mapping.".into());
        }
    }
    let mut previous_switch_end = 0;
    for switch_match in SWITCH.find_iter(&outer) {
        if switch_match.start() < previous_switch_end {
            continue;
        }
        let opening_paren = switch_match.end() - 1;
        let Some(closing_paren) = matching(region.as_bytes(), opening_paren, b'(', b')') else {
            continue;
        };
        let Some(opening_brace) = region[closing_paren + 1..]
            .find('{')
            .map(|offset| closing_paren + 1 + offset)
        else {
            continue;
        };
        let Some(closing_brace) = matching(region.as_bytes(), opening_brace, b'{', b'}') else {
            continue;
        };
        previous_switch_end = closing_brace + 1;
        if !direct_selector(
            &region[opening_paren + 1..closing_paren],
            &outer[..switch_match.start()],
            0,
        ) {
            unknowns.push("A computed, position-dependent, or saved-state switch selector has no proven fixed opcode mapping.".into());
            continue;
        }
        let body = &region[opening_brace + 1..closing_brace];
        let mut depth = 0usize;
        let mut cursor = 0;
        let labels = CASE_BOUNDARY
            .find_iter(body)
            .filter(|label| {
                for byte in body.as_bytes()[cursor..label.start()].iter() {
                    match byte {
                        b'{' => depth += 1,
                        b'}' => depth = depth.saturating_sub(1),
                        _ => (),
                    }
                }
                cursor = label.start();
                depth == 0
            })
            .collect::<Vec<_>>();
        for (index, label) in labels.iter().enumerate() {
            let Some(captures) = CASE.captures(label.as_str()) else {
                continue;
            };
            let Some(opcode) = integer(&captures[1]) else {
                continue;
            };
            let mut last_label = index;
            while let Some(next) = labels.get(last_label + 1) {
                if !body[labels[last_label].end()..next.start()]
                    .trim()
                    .is_empty()
                {
                    break;
                }
                last_label += 1;
            }
            let case_end = labels
                .get(last_label + 1)
                .map_or(body.len(), |next| next.start());
            let offset = start + opening_brace + 1;
            if !add_handler(
                &mut handlers,
                opcode,
                None,
                (offset + label.start(), offset + case_end),
                &body[label.end()..case_end],
                "An integer switch handler is statically visible.",
            ) {
                handler_limit_hit = true;
            }
        }
    }
    for captures in INDEXED_HANDLER.captures_iter(&region) {
        if blocked_tables.contains(&captures[1]) {
            continue;
        }
        let Some(opcode) = integer(&captures[2]) else {
            continue;
        };
        let matched = captures.get(0).expect("indexed handler match");
        let Some((body_start, body_end)) = function_body(&region, matched) else {
            continue;
        };
        if !add_handler(
            &mut handlers,
            opcode,
            Some(opcode),
            (start + matched.start(), start + body_end + 1),
            &region[body_start + 1..body_end],
            "A numeric indexed handler assignment is statically visible.",
        ) {
            handler_limit_hit = true;
        }
    }
    for captures in COMPUTED_HANDLER.captures_iter(&region) {
        if integer(captures[1].trim()).is_none() {
            unknowns.push("A computed handler index cannot be assigned a static opcode.".into());
        }
    }
    object_handlers(
        &region,
        start,
        &blocked_tables,
        &mut handlers,
        &mut unknowns,
        &mut handler_limit_hit,
    );
    if handler_limit_hit {
        omissions.push(json!({"reason":"handler-limit","detail":"Only the first 1024 distinct opcode candidates are retained."}));
    }
    let stack_count = STACK_IDENTIFIER.find_iter(&region).count();
    let register_count = REGISTER_IDENTIFIER.find_iter(&region).count();
    let model = match (stack_count, register_count) {
        (0, 0) => {
            unknowns
                .push("No stack or register identifier is visible in the dispatch region.".into());
            "unknown"
        }
        (stack, registers) if stack > registers => "stack",
        (stack, registers) if registers > stack => "register",
        _ => {
            unknowns.push(
                "Stack and register identifiers are equally visible in the dispatch region.".into(),
            );
            "unknown"
        }
    };
    unknowns.sort();
    unknowns.dedup();
    (
        handlers.into_values().collect(),
        model.into(),
        unknowns,
        omissions,
    )
}

fn event_identity(event: &Value) -> Option<(String, u32, String)> {
    if !["session_id", "sequence_number"]
        .iter()
        .all(|key| evidence::canonical(&event[*key], 64, true))
    {
        return None;
    }
    let process = event["process_id"].as_u64()?;
    if process == 0 || process > u64::from(u32::MAX) {
        return None;
    }
    Some((
        event["session_id"].as_str()?.into(),
        process as u32,
        event["sequence_number"].as_str()?.into(),
    ))
}

fn event_reference(event: &Value) -> Value {
    json!({"session_id":event["session_id"], "process_id":event["process_id"],
           "sequence_number":event["sequence_number"]})
}

fn event_payload(event: &Value, kind: &str) -> Option<Vec<u8>> {
    if event["category"] != "vm"
        || event["type"] != kind
        || !matches!(event["protocol_version"].as_u64(), Some(2 | 3))
        || event_identity(event).is_none()
        || event
            .get("payload_truncated")
            .is_some_and(|value| value != false)
        || event.get("payload_size").is_some_and(|value| value != 128)
        || event
            .get("payload_encoding")
            .is_some_and(|value| value != "hex")
        || event
            .get("flags")
            .is_some_and(|value| value.as_u64().is_none_or(|flags| flags & 1 != 0))
    {
        return None;
    }
    let text = event["payload"].as_str()?;
    if text.len() != 256 {
        return None;
    }
    let payload = hex::decode(text).ok()?;
    (payload[0..4] == [1, 0, 128, 0]).then_some(payload)
}

fn read_u64(payload: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        payload[offset..offset + 8]
            .try_into()
            .expect("fixed payload range"),
    )
}

fn sample(
    event: &Value,
    artifact: &Value,
    invocations: &BTreeMap<(String, u32, String), &Value>,
) -> Option<Value> {
    if ["artifact_id", "session_id", "navigation_id", "frame_id"]
        .iter()
        .any(|key| event[*key] != artifact[*key])
    {
        return None;
    }
    let payload = event_payload(event, "vm_dispatch_sample")?;
    let finding = read_u64(&payload, 24);
    let investigation = read_u64(&payload, 32);
    let interpreter = read_u64(&payload, 40);
    let bytecode = read_u64(&payload, 48);
    if payload[20..24].iter().any(|byte| *byte != 0)
        || finding == 0
        || investigation == 0
        || interpreter == 0
        || interpreter.to_string() != artifact["artifact_id"].as_str()?
        || payload[56] != 0
        || payload[58..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let u32_at = |offset| {
        u32::from_le_bytes(
            payload[offset..offset + 4]
                .try_into()
                .expect("sample range"),
        )
    };
    let mut result = json!({
        "event":event_reference(event),
        "instruction_pointer":u32_at(4), "instruction_pointer_units":"unknown",
        "opcode":u32_at(8), "handler_index":u32_at(12), "sample_index":u32_at(16),
        "operand_count":payload[57], "finding_id":finding.to_string(),
        "investigation_id":investigation.to_string(), "interpreter_artifact_id":interpreter.to_string(),
        "bytecode_artifact_id":bytecode.to_string(), "invocation_id":null, "invocation_event":null,
    });
    if let Some(parent) = event["parent_event_id"].as_str() {
        let mut identity = event_identity(event)?;
        identity.2 = parent.into();
        if let Some(marker) = invocations.get(&identity)
            && [
                "artifact_id",
                "session_id",
                "navigation_id",
                "frame_id",
                "process_id",
            ]
            .iter()
            .all(|key| marker[*key] == event[*key])
            && parent.parse::<u64>().ok()?
                < event["sequence_number"].as_str()?.parse::<u64>().ok()?
            && bytecode != 0
            && let Some(bytes) = event_payload(marker, "vm_finding")
        {
            let label_size = u16::from_le_bytes(bytes[8..10].try_into().ok()?) as usize;
            // This exact typed native marker declares only owned fixture units.
            // A label alone, a nearby timestamp, or shared frame is insufficient.
            if bytes[4..8] == [3, 0, 1, 4]
                && label_size <= 40
                && bytes[10..24].iter().all(|byte| *byte == 0)
                && read_u64(&bytes, 24) == finding
                && read_u64(&bytes, 32) == investigation
                && read_u64(&bytes, 40) != 0
                && read_u64(&bytes, 48) == bytecode
                && bytes[56..72].iter().all(|byte| *byte == 0)
                && bytes[72 + label_size..].iter().all(|byte| *byte == 0)
                && matches!(
                    &bytes[72..72 + label_size],
                    b"owned-register-v1" | b"owned-stack-v1"
                )
            {
                result["instruction_pointer_units"] = json!("instruction-index");
                result["invocation_id"] = json!(read_u64(&bytes, 40).to_string());
                result["invocation_event"] = event_reference(marker);
            }
        }
    }
    Some(result)
}

fn snapshots(root: &Path, interpreter: &Value, artifacts: &[Value]) -> (Vec<Value>, Vec<Value>) {
    let linked = artifacts
        .iter()
        .filter(|artifact| {
            artifact["parent_artifact_id"] != "0"
                && artifact["parent_artifact_id"] == interpreter["artifact_id"]
                && artifact["session_id"] == interpreter["session_id"]
                && artifact["navigation_id"] == interpreter["navigation_id"]
                && artifact["frame_id"] == interpreter["frame_id"]
        })
        .collect::<Vec<_>>();
    let mut omissions = Vec::new();
    if linked.len() > MAX_SNAPSHOTS {
        omissions.push(json!({"reason":"snapshot-limit","detail":"Only the first 16 linked runtime snapshots are retained."}));
    }
    let snapshots = linked
        .into_iter()
        .take(MAX_SNAPSHOTS)
        .map(
            |artifact| match evidence::verified_range(root, artifact, 0, SNAPSHOT_PREVIEW_BYTES) {
                Ok(bytes) => json!({
                    "artifact_id": artifact["artifact_id"],
                    "origin": "runtime-typed-array",
                    "sha256": artifact["sha256"],
                    "byte_count": artifact["byte_size"],
                    "preview_hex": hex::encode(&bytes),
                    "truncated": artifact["byte_size"].as_u64().unwrap_or(0) > bytes.len() as u64,
                    "unavailable_reason": null,
                }),
                Err(error) => {
                    let reason =
                        format!("Runtime snapshot bytes are unavailable: {}", error.message)
                            .chars()
                            .take(240)
                            .collect::<String>();
                    json!({
                        "artifact_id": artifact["artifact_id"],
                        "origin": "runtime-typed-array",
                        "sha256": artifact["sha256"],
                        "byte_count": artifact["byte_size"],
                        "preview_hex": null,
                        "truncated": false,
                        "unavailable_reason": reason,
                    })
                }
            },
        )
        .collect();
    (snapshots, omissions)
}

/// Bytes of the dispatch instruction shared by the most handlers.
/// Preserve its module-relative offset separately from runtime bytecode snapshots.
fn captured_module_preview(artifact: &Value, bytes: &[u8], handlers: &[Value]) -> Option<Value> {
    let mut counts = BTreeMap::<(u64, u64), usize>::new();
    for handler in handlers {
        let Some(offset) = handler["source"]["byte_offset"].as_u64() else {
            continue;
        };
        let Some(size) = handler["source"]["byte_size"].as_u64() else {
            continue;
        };
        if size == 0 {
            continue;
        }
        *counts.entry((offset, size)).or_default() += 1;
    }
    // Most handlers, then the lowest offset.
    let ((offset, size), _) = counts.iter().max_by_key(|((offset, size), count)| {
        (*count, std::cmp::Reverse(*offset), std::cmp::Reverse(*size))
    })?;
    let start = usize::try_from(*offset).ok()?;
    let full = usize::try_from(*size).ok()?;
    let end = start.checked_add(full)?;
    let slice = bytes.get(start..end)?;
    let truncated = slice.len() > SNAPSHOT_PREVIEW_BYTES;
    let preview = if truncated {
        &slice[..SNAPSHOT_PREVIEW_BYTES]
    } else {
        slice
    };
    Some(json!({
        "artifact_id": artifact["artifact_id"],
        "byte_offset": offset,
        "byte_count": slice.len(),
        "preview_hex": hex::encode(preview),
        "truncated": truncated,
    }))
}

pub(crate) fn workspace(
    root: &Path,
    artifact: &Value,
    bytes: &[u8],
    result: &Value,
    snapshot_artifacts: &[Value],
    events: &[Value],
) -> Option<Value> {
    if result["tier"] != "likely-vm" {
        return None;
    }
    let runtime = result["runtime"].as_str()?;
    let (mut handlers, model, mut unknowns, mut omissions) = match runtime {
        "javascript" => {
            let source = std::str::from_utf8(bytes).ok()?;
            let region = result["observations"]
                .as_array()?
                .iter()
                .find_map(|observation| {
                    (observation["rule_id"] == "js.dispatch-loop").then_some((
                        observation["function_region"]["byte_offset"].as_u64()? as usize,
                        observation["function_region"]["byte_size"].as_u64()? as usize,
                    ))
                })?;
            let end = region.0.checked_add(region.1)?;
            if end > source.len()
                || !source.is_char_boundary(region.0)
                || !source.is_char_boundary(end)
            {
                return None;
            }
            static_handlers(source, region.0, end)
        }
        "webassembly" => {
            let (handlers, unknowns, omissions) = wasm::handlers(bytes, result)?;
            (handlers, "unknown".into(), unknowns, omissions)
        }
        _ => return None,
    };
    if handlers.is_empty() {
        omissions.push(json!({"reason":"handler-unavailable","detail":"No static integer handler candidate was visible in the dispatch region."}));
    }
    let owned = if runtime == "javascript" {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|source| crate::vm_effects::attach_owned(source, &mut handlers))
    } else {
        None
    };
    let invocations = events
        .iter()
        .filter(|event| event["type"] == "vm_finding")
        .filter_map(|event| event_identity(event).map(|identity| (identity, event)))
        .collect::<BTreeMap<_, _>>();
    let mut samples = BTreeMap::<u32, u64>::new();
    let mut retained_samples = Vec::new();
    let mut sample_count = 0u64;
    for event in events {
        if runtime == "javascript"
            && let Some(value) = sample(event, artifact, &invocations)
        {
            let opcode = value["opcode"].as_u64().expect("sample opcode") as u32;
            *samples.entry(opcode).or_default() += 1;
            sample_count += 1;
            if retained_samples.len() < MAX_SAMPLES {
                retained_samples.push(value);
            }
        }
    }
    if sample_count == 0 {
        omissions.push(json!({"reason":"sampler-unavailable", "detail":
            "No runtime dispatch samples were retained. Static dispatch, Canvas calls and buffer snapshots do not prove a guest PC. Brave has no guest dispatch emitter; owned native fixtures are separate producers."}));
    } else if sample_count > retained_samples.len() as u64 {
        omissions.push(json!({"reason":"sample-limit", "detail":"Only the first 4096 accepted sample records are retained; counts include all accepted samples."}));
    }
    for handler in &mut handlers {
        let Some(opcode) = handler["opcode"].as_u64().map(|value| value as u32) else {
            continue;
        };
        if let Some(count) = samples.get(&opcode) {
            handler["sample_count"] = json!(count);
            handler["state"] = json!("observed");
        }
    }
    for opcode in samples.keys() {
        if !handlers
            .iter()
            .any(|handler| handler["opcode"].as_u64() == Some(u64::from(*opcode)))
        {
            unknowns.push(format!(
                "Observed opcode {opcode} has no static handler candidate in the dispatch region."
            ));
        }
    }
    let (snapshots, snapshot_omissions) = snapshots(root, artifact, snapshot_artifacts);
    omissions.extend(snapshot_omissions);
    // Source instruction bytes are display evidence, not a zero-based guest image.
    // They must never supply snapshot identity, traversal, or coverage bytes.
    let module_preview = (runtime == "webassembly")
        .then(|| captured_module_preview(artifact, bytes, &handlers))
        .flatten();
    if snapshots.is_empty() {
        let module = runtime == "webassembly";
        if let Some(snapshot) = result.get("bytecode_snapshot")
            && snapshot["snapshot_hex"].is_string()
        {
            omissions.push(json!({
                "reason": "static-initializer-only",
                "detail": if module {
                    "A bounded static initializer exists in vm-analysis-v1, but no runtime snapshot was retained for this captured module. The handler list comes from the module bytes."
                } else {
                    "A bounded static initializer exists in vm-analysis-v1, but no runtime snapshot names this allocating script in the same session, navigation, and frame."
                }
            }));
        } else if module {
            omissions.push(json!({"reason":"runtime-snapshot-unavailable", "detail":
                "No runtime snapshot was retained for this captured module. The handler list comes from the module bytes, not an allocating script."}));
        } else {
            omissions.push(json!({"reason":"runtime-snapshot-unavailable", "detail":
                "No runtime snapshot names this captured allocating script in the same session, navigation, and frame. The allocating script may not have been captured."}));
        }
    }
    unknowns.sort();
    unknowns.dedup();
    if unknowns.len() > MAX_UNKNOWNS {
        unknowns.truncate(MAX_UNKNOWNS);
        omissions.push(json!({
            "reason": "unknown-limit",
            "detail": "Only the first 256 residual unknowns are retained."
        }));
    }
    let entry = owned
        .as_ref()
        .and_then(|declaration| declaration["entry_offset"].as_u64())
        .and_then(|offset| u32::try_from(offset).ok());
    let mut traversal = crate::vm_reachability::walk(&snapshots, &handlers, entry);
    if omissions
        .iter()
        .any(|omission| omission["reason"] == "snapshot-limit")
    {
        traversal["complete"] = json!(false);
        let frontier = traversal["frontier"]
            .as_array_mut()
            .expect("bounded frontier");
        if frontier.len() < 256 {
            frontier.push(json!({"artifact_id":null,"byte_offset":null,"reason":"snapshot-gap"}));
        }
    }
    if traversal["complete"] != true {
        omissions.push(json!({"reason":"reachable-frontier","detail":"The bounded instruction walk has unresolved entries or edges."}));
    }
    let attributions = crate::vm_reachability::attributions(&traversal, &handlers);
    let coverage = crate::vm_byte_coverage::coverage(
        &snapshots,
        handlers.len(),
        &attributions,
        &unknowns,
        omissions,
    );
    let mut workspace = json!({
        "interpreter_artifact_id": artifact["artifact_id"],
        "source_artifact_sha256": artifact["sha256"],
        "runtime": result["runtime"],
        "capture_mode": "unknown",
        "sample_count": sample_count,
        "samples": retained_samples,
        "finding_id": result["finding_id"],
        "model": model,
        "handlers": handlers,
        "snapshots": snapshots,
        "coverage": coverage,
        "unknowns": unknowns,
        "traversal": traversal,
    });
    if let Some(preview) = module_preview {
        workspace["captured_module_preview"] = preview;
    }
    if let Some(snapshot) = workspace["snapshots"]
        .as_array()
        .and_then(|items| items.first())
    {
        workspace["bytecode_artifact_id"] = snapshot["artifact_id"].clone();
    }
    Some(workspace)
}

pub(crate) fn store(root: &Path, analysis: &Value, mut workspaces: Vec<Value>) -> Result<Value> {
    if workspaces.len() > MAX_WORKSPACES {
        workspaces.truncate(MAX_WORKSPACES);
        if let Some(last) = workspaces.last_mut() {
            last["coverage"]["complete"] = json!(false);
            last["coverage"]["omissions"]
                .as_array_mut()
                .expect("workspace omissions")
                .push(json!({"reason":"workspace-limit","detail":"Only the first 256 likely-VM workspaces are retained."}));
        }
    }
    let handler_count = workspaces
        .iter()
        .map(|workspace| workspace["handlers"].as_array().map_or(0, Vec::len))
        .sum::<usize>();
    let snapshot_count = workspaces
        .iter()
        .map(|workspace| workspace["snapshots"].as_array().map_or(0, Vec::len))
        .sum::<usize>();
    let sample_count = workspaces
        .iter()
        .filter_map(|workspace| workspace["sample_count"].as_u64())
        .sum::<u64>();
    let unknown_count = workspaces
        .iter()
        .map(|workspace| workspace["unknowns"].as_array().map_or(0, Vec::len))
        .sum::<usize>();
    let mut document = json!({
        "contract_version": 2,
        "document_kind": "vm-opcode-workspace",
        "capture_mode": analysis["capture_mode"],
        "producer": {"id":"origin-trace-vm-opcode","version":PRODUCER_VERSION},
        "profile_digest": analysis["profile_digest"],
        "analysis_digest": analysis["document_digest"],
        "inputs": {"artifact_manifest_digest":analysis["inputs"]["artifact_manifest_digest"],
            "event_store_digest":analysis["inputs"]["event_store_digest"],
            "capture_provenance_digest":analysis["inputs"]["capture_provenance_digest"]},
        "workspaces": workspaces,
        "summary": {
            "workspace_count": workspaces.len(),
            "handler_count": handler_count,
            "snapshot_count": snapshot_count,
            "sample_count": sample_count,
            "unknown_count": unknown_count,
        },
    });
    document["document_digest"] = json!(vm::digest(&document)?);
    durable::write_private(
        &root.join("analysis/vm-opcode-workspace-v2.json"),
        &vm::canonical(&document)?,
    )?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf};

    fn fixture(name: &str) -> String {
        fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/fixtures/vm-dynamic-debug")
                .join(name),
        )
        .expect("VM fixture")
    }

    fn event(opcode: u32) -> Value {
        let mut payload = vec![0u8; 128];
        payload[0..2].copy_from_slice(&1u16.to_le_bytes());
        payload[2..4].copy_from_slice(&128u16.to_le_bytes());
        payload[8..12].copy_from_slice(&opcode.to_le_bytes());
        payload[24..32].copy_from_slice(&1u64.to_le_bytes());
        payload[32..40].copy_from_slice(&1u64.to_le_bytes());
        payload[40..48].copy_from_slice(&1u64.to_le_bytes());
        json!({
            "protocol_version":2,
            "session_id":"1",
            "sequence_number":"1",
            "process_id":1,
            "navigation_id":"1",
            "frame_id":"1",
            "artifact_id":"1",
            "request_id":"0",
            "category":"vm",
            "type":"vm_dispatch_sample",
            "payload":hex::encode(payload),
        })
    }

    fn analyze(source: &str, events: &[Value]) -> (tempfile::TempDir, Value, Value) {
        analyze_artifact_with_snapshot(source.as_bytes(), "javascript", events, None)
    }

    fn analyze_artifact(
        bytes: &[u8],
        kind: &str,
        events: &[Value],
    ) -> (tempfile::TempDir, Value, Value) {
        analyze_artifact_with_snapshot(bytes, kind, events, None)
    }

    fn analyze_with_snapshot(
        source: &str,
        events: &[Value],
        snapshot: Option<&[u8]>,
    ) -> (tempfile::TempDir, Value, Value) {
        analyze_artifact_with_snapshot(source.as_bytes(), "javascript", events, snapshot)
    }

    fn analyze_artifact_with_snapshot(
        bytes: &[u8],
        kind: &str,
        events: &[Value],
        snapshot: Option<&[u8]>,
    ) -> (tempfile::TempDir, Value, Value) {
        let root = tempfile::tempdir().expect("artifact store");
        fs::create_dir_all(root.path().join("blobs")).expect("blob directory");
        let hash = hex::encode(Sha256::digest(bytes));
        fs::write(root.path().join(format!("blobs/{hash}.bin")), bytes).expect("source blob");
        let artifact = json!({
            "protocol_version":1,
            "artifact_id":"1",
            "session_id":"1",
            "navigation_id":"1",
            "frame_id":"1",
            "parent_artifact_id":"0",
            "creator_event_id":"0",
            "execution_context_id":"1",
            "capture_origin": if kind == "wasm" { "webassembly_compile" } else { "dynamic_javascript" },
            "kind":kind,
            "url":"fixture://vm-dynamic-debug/source",
            "mime_type": if kind == "wasm" { "application/wasm" } else { "text/javascript" },
            "byte_size":bytes.len(),
            "sha256":hash,
            "sensitive":false,
            "content_path":format!("blobs/{hash}.bin"),
        });
        fs::write(
            root.path().join("manifest.jsonl"),
            format!(
                "{}\n",
                serde_json::to_string(&artifact).expect("manifest record")
            ),
        )
        .expect("manifest");
        if let Some(bytes) = snapshot {
            let hash = hex::encode(Sha256::digest(bytes));
            fs::write(root.path().join(format!("blobs/{hash}.bin")), bytes).unwrap();
            let mut snapshot = artifact.clone();
            snapshot["artifact_id"] = json!("2");
            snapshot["parent_artifact_id"] = json!("1");
            snapshot["capture_origin"] = json!("runtime_typed_array");
            snapshot["kind"] = json!("bytecode_buffer");
            snapshot["mime_type"] = json!("application/octet-stream");
            snapshot["byte_size"] = json!(bytes.len());
            snapshot["sha256"] = json!(hash);
            snapshot["content_path"] = json!(format!("blobs/{hash}.bin"));
            fs::write(
                root.path().join("manifest.jsonl"),
                format!("{artifact}\n{snapshot}\n"),
            )
            .unwrap();
        }
        let event_store = root.path().join("events.jsonl");
        let event_lines = events
            .iter()
            .map(|value| serde_json::to_string(value).expect("event record"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&event_store, event_lines).expect("event store");
        let analysis = crate::vm::store(root.path(), &event_store).expect("VM documents");
        let workspace: Value = serde_json::from_slice(
            &fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json"))
                .expect("opcode workspace"),
        )
        .expect("workspace JSON");
        (root, analysis, workspace)
    }

    fn assert_schema(document: &Value) {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .expect("opcode workspace schema");
        let validator = jsonschema::validator_for(&schema).expect("workspace validator");
        if let Err(error) = validator.validate(document) {
            panic!("workspace schema error: {error}");
        }
        let expected = document["document_digest"].clone();
        let mut unsigned = document.clone();
        unsigned
            .as_object_mut()
            .expect("workspace object")
            .remove("document_digest");
        assert_eq!(expected, vm::digest(&unsigned).expect("workspace digest"));
    }

    fn wasm_fixture(name: &str) -> Vec<u8> {
        let fixtures: Value = serde_json::from_str(&fixture("wasm-dispatch.json")).unwrap();
        hex::decode(fixtures[name].as_str().unwrap()).unwrap()
    }

    #[test]
    fn wasm_dispatch_workspaces_preserve_inferred_and_unknown_arms() {
        for name in ["br_table", "call_indirect"] {
            let bytes = wasm_fixture(name);
            // Validation and analysis are inert; no WebAssembly instance is created.
            wasmparser::Validator::new().validate_all(&bytes).unwrap();
            let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
            assert_eq!(analysis["results"][0]["tier"], "likely-vm");
            assert_eq!(document["summary"]["workspace_count"], 1);
            let workspace = &document["workspaces"][0];
            assert_eq!(workspace["runtime"], "webassembly");
            assert_eq!(workspace["model"], "unknown");
            let handlers = workspace["handlers"].as_array().unwrap();
            assert_eq!(handlers.len(), if name == "br_table" { 3 } else { 1 });
            let unknown = handlers.last().unwrap();
            assert!(unknown["opcode"].is_null());
            assert_eq!(unknown["state"], "unknown");
            assert!(unknown.get("handler_index").is_none());
            assert_eq!(unknown["sample_count"], 0);
            for handler in handlers {
                let offset = handler["source"]["byte_offset"].as_u64().unwrap() as usize;
                assert_eq!(bytes[offset], if name == "br_table" { 0x0e } else { 0x11 });
            }
            if name == "br_table" {
                assert_eq!(handlers[0]["opcode"], 0);
                assert_eq!(handlers[1]["opcode"], 1);
                assert_eq!(handlers[0]["state"], "inferred");
                let snapshot = &workspace["captured_module_preview"];
                assert!(snapshot.get("origin").is_none());
                assert!(snapshot.get("sha256").is_none());
                assert_eq!(
                    snapshot["artifact_id"],
                    workspace["interpreter_artifact_id"]
                );
                assert!(
                    handlers
                        .iter()
                        .all(|handler| handler["source"] == handlers[0]["source"])
                );
                let offset = handlers[0]["source"]["byte_offset"].as_u64().unwrap() as usize;
                let size = handlers[0]["source"]["byte_size"].as_u64().unwrap() as usize;
                let instruction = &bytes[offset..offset + size];
                assert_eq!(instruction[0], 0x0e);
                assert_eq!(snapshot["byte_offset"], offset);
                assert!(offset > 0);
                assert_eq!(snapshot["preview_hex"], hex::encode(instruction));
                assert_eq!(snapshot["truncated"], false);
                assert_eq!(snapshot["byte_count"], instruction.len());
            }
            assert_eq!(workspace["snapshots"], json!([]));
            assert!(workspace.get("bytecode_artifact_id").is_none());
            assert_eq!(workspace["coverage"]["retained_snapshot_bytes"], 0);
            assert_eq!(workspace["coverage"]["characterized_bytes"], 0);
            assert_eq!(workspace["traversal"]["entry_offsets"], json!([]));
            assert_eq!(workspace["traversal"]["instructions"], json!([]));
            assert_eq!(
                workspace["traversal"]["frontier"],
                json!([{
                    "artifact_id": null, "byte_offset": null, "reason": "snapshot-unavailable"
                }])
            );
            assert_eq!(document["summary"]["snapshot_count"], 0);
            assert_eq!(workspace["coverage"]["complete"], false);
            let module_bytes = workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|omission| omission["reason"] == "runtime-snapshot-unavailable")
                .collect::<Vec<_>>();
            assert_eq!(module_bytes.len(), 1);
            assert_eq!(
                module_bytes[0]["detail"],
                "No runtime snapshot was retained for this captured module. The handler list comes from the module bytes, not an allocating script."
            );
            assert_schema(&document);
        }
        let (_, analysis, document) = analyze_artifact(&wasm_fixture("non_vm"), "wasm", &[]);
        assert_eq!(analysis["summary"]["likely_vm_count"], 0);
        assert_eq!(document["summary"]["workspace_count"], 0);
        assert_schema(&document);
    }

    #[test]
    fn captured_module_preview_coexists_without_retargeting_runtime_snapshot() {
        let bytes = wasm_fixture("br_table");
        let (_, _, document) =
            analyze_artifact_with_snapshot(&bytes, "wasm", &[], Some(&[0xaa, 0xbb]));
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["captured_module_preview"]["artifact_id"], "1");
        assert_eq!(workspace["snapshots"].as_array().unwrap().len(), 1);
        assert_eq!(workspace["snapshots"][0]["artifact_id"], "2");
        assert_eq!(workspace["snapshots"][0]["origin"], "runtime-typed-array");
        assert_eq!(workspace["snapshots"][0]["preview_hex"], "aabb");
        assert_eq!(workspace["bytecode_artifact_id"], "2");
        assert_eq!(workspace["coverage"]["retained_snapshot_bytes"], 2);
        assert_eq!(document["summary"]["snapshot_count"], 1);
        assert_schema(&document);
    }

    #[test]
    fn captured_module_preview_preserves_offsets_and_bounds_without_runtime_identity() {
        let artifact = json!({"artifact_id":"5"});
        let bytes = (0..5000)
            .map(|index| (index % 256) as u8)
            .collect::<Vec<_>>();
        let handler = |offset, size| json!({"source":{"byte_offset":offset,"byte_size":size}});
        let handlers = [handler(20, 3), handler(10, 3)];
        let preview = captured_module_preview(&artifact, &bytes, &handlers).unwrap();
        assert_eq!(preview["byte_offset"], 10);
        assert_eq!(preview["byte_count"], 3);
        assert_eq!(preview["preview_hex"], hex::encode(&bytes[10..13]));
        assert_eq!(preview["truncated"], false);
        let preview = captured_module_preview(&artifact, &bytes, &[handler(20, 4500)]).unwrap();
        assert_eq!(preview["byte_offset"], 20);
        assert_eq!(preview["byte_count"], 4500);
        assert_eq!(preview["preview_hex"], hex::encode(&bytes[20..4116]));
        assert_eq!(preview["truncated"], true);
        assert!(captured_module_preview(&artifact, &bytes, &[handler(5000, 1)]).is_none());
        assert!(captured_module_preview(&artifact, &bytes, &[handler(0, 0)]).is_none());
        assert!(captured_module_preview(&artifact, &bytes, &[]).is_none());
    }

    #[test]
    fn wasm_selectors_are_scoped_to_each_dispatch_site() {
        let bytes = wasm_fixture("two_br_tables");
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
        let handlers = document["workspaces"][0]["handlers"].as_array().unwrap();
        assert_eq!(handlers.len(), 6);
        assert_eq!(handlers[0]["opcode"], 0);
        assert_eq!(handlers[3]["opcode"], 0);
        assert_ne!(handlers[0]["source"], handlers[3]["source"]);
        assert_schema(&document);
    }

    #[test]
    fn wasm_handler_cap_and_selected_function_boundary() {
        let mut bytes = wasm_fixture("br_table");
        let code = bytes.iter().position(|byte| *byte == 0x0a).unwrap();
        let body_start = code + 4;
        let dispatch = bytes[body_start..]
            .iter()
            .position(|byte| *byte == 0x0e)
            .unwrap()
            + body_start;
        let mut body = bytes[body_start..dispatch].to_vec();
        // 1025 targets, all loop label 0, followed by default label 0.
        body.extend_from_slice(&[0x0e, 0x81, 0x08]);
        body.extend(std::iter::repeat_n(0, 1026));
        body.extend_from_slice(&[0x0b, 0x0b]);
        fn leb(mut value: usize) -> Vec<u8> {
            let mut bytes = Vec::new();
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                bytes.push(byte | if value > 0 { 0x80 } else { 0 });
                if value == 0 {
                    return bytes;
                }
            }
        }
        let mut section = vec![1];
        section.extend(leb(body.len()));
        section.extend(body);
        bytes.truncate(code + 1);
        bytes.extend(leb(section.len()));
        bytes.extend(section);
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
        let workspace = &document["workspaces"][0];
        assert_eq!(
            workspace["handlers"].as_array().unwrap().len(),
            MAX_HANDLERS
        );
        assert!(
            workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "handler-limit")
        );
        assert_schema(&document);

        // A detector-selected body must match the exact module coordinates.
        let result = json!({"observations":[{"rule_id":"wasm.dispatch-loop",
            "coordinate":{"function_body_offset":0,"function_body_size":1}}]});
        assert!(wasm::handlers(&bytes, &result).is_none());
    }

    #[test]
    fn wasm_snapshot_cap_is_shared_with_javascript() {
        let bytes = wasm_fixture("br_table");
        let (root, analysis, _) = analyze_artifact(&bytes, "wasm", &[]);
        let interpreter: Value =
            serde_json::from_str(&fs::read_to_string(root.path().join("manifest.jsonl")).unwrap())
                .unwrap();
        let hash = hex::encode(Sha256::digest([1u8]));
        fs::write(root.path().join(format!("blobs/{hash}.bin")), [1u8]).unwrap();
        let snapshots = (0..17)
            .map(|index| {
                json!({
                    "artifact_id": (index + 2).to_string(), "parent_artifact_id":"1",
                    "session_id":"1", "navigation_id":"1", "frame_id":"1",
                    "sha256":hash, "byte_size":1, "content_path":format!("blobs/{hash}.bin")
                })
            })
            .collect::<Vec<_>>();
        let workspace = workspace(
            root.path(),
            &interpreter,
            &bytes,
            &analysis["results"][0],
            &snapshots,
            &[],
        )
        .unwrap();
        assert_eq!(
            workspace["snapshots"].as_array().unwrap().len(),
            MAX_SNAPSHOTS
        );
        assert!(
            workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "snapshot-limit")
        );
    }

    #[test]
    fn owned_effects_bind_exact_sources_and_keep_observed_rows_inferred() {
        for source in [
            include_str!("../../../tools/fixtures/vm-workspace-effects/stack.js"),
            include_str!("../../../tools/fixtures/vm-workspace-effects/register.js"),
            include_str!("../../../tools/fixtures/native-vm-dispatch/stack-reference.js"),
            include_str!("../../../tools/fixtures/native-vm-dispatch/register-reference.js"),
        ] {
            let (_, _, document) = analyze(source, &[event(1)]);
            let rows = document["workspaces"][0]["handlers"].as_array().unwrap();
            assert_eq!(rows.len(), 8);
            assert!(
                rows.iter()
                    .all(|row| row["effects"][0]["evidence_class"] == "inferred")
            );
            assert_eq!(rows[0]["state"], "observed");
            assert_schema(&document);
            let (_, _, altered) = analyze(&format!("{source}\n"), &[event(1)]);
            assert!(
                altered["workspaces"][0]["handlers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["effects"] == json!([]))
            );
            assert_schema(&altered);
        }
    }

    #[test]
    fn owned_byte_layout_characterizes_verified_snapshot_without_executing_source() {
        let source = include_str!("../../../tools/fixtures/vm-workspace-effects/stack.js");
        let (_, _, document) = analyze_with_snapshot(source, &[event(1)], Some(&[1, 7, 8]));
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["coverage"]["characterized_bytes"], 3);
        assert_eq!(workspace["coverage"]["retained_snapshot_bytes"], 3);
        assert_eq!(workspace["coverage"]["complete"], true);
        assert_eq!(
            workspace["samples"][0]["instruction_pointer_units"],
            "unknown"
        );
        assert_schema(&document);
    }

    #[test]
    fn production_walk_retains_unknown_frontier_and_unreachable_bytes() {
        let source = include_str!("../../../tools/fixtures/vm-workspace-effects/stack.js");
        for (bytes, reason, characterized) in [
            (vec![1, 7, 255, 8], "unknown-opcode", 2),
            (vec![6, 99, 8], "past-snapshot", 2),
            (vec![1], "truncated-instruction", 0),
        ] {
            let (_, _, document) = analyze_with_snapshot(source, &[event(1)], Some(&bytes));
            let workspace = &document["workspaces"][0];
            assert_eq!(workspace["traversal"]["complete"], false);
            assert_eq!(workspace["traversal"]["frontier"][0]["reason"], reason);
            assert_eq!(workspace["coverage"]["complete"], false);
            assert_eq!(workspace["coverage"]["characterized_bytes"], characterized);
            assert_schema(&document);
        }
        let (_, _, document) = analyze_with_snapshot(source, &[event(1)], Some(&[8, 1, 7]));
        assert_eq!(document["workspaces"][0]["traversal"]["complete"], true);
        assert_eq!(
            document["workspaces"][0]["coverage"]["characterized_bytes"],
            1
        );
        assert_eq!(document["workspaces"][0]["coverage"]["complete"], false);
        assert_schema(&document);
    }

    #[test]
    fn stack_and_register_fixtures_produce_bounded_workspaces() {
        let (_, stack_analysis, stack) = analyze(&fixture("stack-vm.js"), &[event(80)]);
        assert_eq!(stack_analysis["summary"]["likely_vm_count"], 1);
        assert_eq!(stack["summary"]["workspace_count"], 1);
        assert_eq!(stack["workspaces"][0]["model"], "stack");
        assert_eq!(
            stack["workspaces"][0]["handlers"].as_array().unwrap().len(),
            4
        );
        let push = stack["workspaces"][0]["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|handler| handler["opcode"] == 80)
            .expect("push handler");
        assert_eq!(push["state"], "observed");
        assert_eq!(push["sample_count"], 1);
        let start = push["source"]["byte_offset"].as_u64().unwrap() as usize;
        let size = push["source"]["byte_size"].as_u64().unwrap() as usize;
        let cited = &fixture("stack-vm.js")[start..start + size];
        assert!(cited.starts_with("case 80:"));
        assert!(cited.contains("stack.push(program[pc++] - 48)"));
        assert!(!cited.contains("case 81:"));
        assert_eq!(push["operand_width"], 1);
        assert_eq!(
            stack["workspaces"][0]["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h["opcode"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [80, 81, 82, 83]
        );
        assert_schema(&stack);

        let (_, register_analysis, register) = analyze(&fixture("register-vm.js"), &[]);
        assert_eq!(register_analysis["summary"]["likely_vm_count"], 1);
        assert_eq!(register["workspaces"][0]["model"], "register");
        assert_eq!(
            register["workspaces"][0]["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| (
                    h["opcode"].as_u64().unwrap(),
                    h["operand_width"].as_u64().unwrap()
                ))
                .collect::<Vec<_>>(),
            [(16, 2), (17, 2), (18, 1), (19, 0)]
        );
        assert!(
            register["workspaces"][0]["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|handler| handler["state"] == "inferred")
        );
        assert!(
            register["workspaces"][0]["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "sampler-unavailable")
        );
        assert_schema(&register);
    }

    #[test]
    fn xor_fixture_links_verified_post_decode_snapshot() {
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/fixtures/vm-dynamic-debug/xor-decoded");
        let root = tempfile::tempdir().expect("artifact store");
        fs::create_dir_all(root.path().join("blobs")).expect("blob directory");
        fs::copy(
            fixture_root.join("manifest.jsonl"),
            root.path().join("manifest.jsonl"),
        )
        .expect("fixture manifest");
        for hash in [
            "aba178af847d52cbe0819d83a74bfdac897feeb1c28389c7768f332e2190834e",
            "7faf3df3cefb51668c15e6ce97d40465fbf4b8673eb555debc22140faae9cd7a",
        ] {
            fs::copy(
                fixture_root.join(format!("blobs/{hash}.bin")),
                root.path().join(format!("blobs/{hash}.bin")),
            )
            .expect("fixture blob");
        }
        let events = root.path().join("events.jsonl");
        fs::write(&events, b"").expect("event store");
        crate::vm::store(root.path(), &events).expect("VM documents");
        let workspace: Value = serde_json::from_slice(
            &fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json"))
                .expect("opcode workspace"),
        )
        .expect("workspace JSON");
        assert_eq!(workspace["summary"]["workspace_count"], 1);
        assert_eq!(workspace["workspaces"][0]["bytecode_artifact_id"], "2");
        assert_eq!(
            workspace["workspaces"][0]["snapshots"][0]["preview_hex"],
            hex::encode(b"P1P2QS\n")
        );
        assert!(
            !workspace["workspaces"][0]["snapshots"][0]["preview_hex"]
                .as_str()
                .unwrap()
                .contains("5c783061")
        );
        assert_schema(&workspace);
    }

    #[test]
    fn snapshot_parent_and_scope_are_exact_and_metadata_is_validated() {
        let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/fixtures/vm-dynamic-debug/xor-decoded");
        let records = fs::read_to_string(fixture_root.join("manifest.jsonl")).unwrap();
        let artifacts: Vec<Value> = records
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let interpreter = &artifacts[0];
        let snapshot = &artifacts[1];
        validate_snapshot_artifact(snapshot).unwrap();
        assert_eq!(
            snapshots(&fixture_root, interpreter, &[snapshot.clone()])
                .0
                .len(),
            1
        );
        for field in [
            "parent_artifact_id",
            "session_id",
            "navigation_id",
            "frame_id",
        ] {
            let mut mismatch = snapshot.clone();
            mismatch[field] = json!("0");
            assert!(
                snapshots(&fixture_root, interpreter, &[mismatch])
                    .0
                    .is_empty(),
                "{field}"
            );
        }
        for (field, value) in [
            ("execution_context_id", "0"),
            ("kind", "javascript"),
            ("capture_origin", "dynamic_javascript"),
        ] {
            let mut invalid = snapshot.clone();
            invalid[field] = json!(value);
            assert!(validate_snapshot_artifact(&invalid).is_err(), "{field}");
        }
    }

    #[test]
    fn javascript_dispatch_without_a_handler_table_stays_a_candidate() {
        let source = "function run(code, pc, stack, table) {\nwhile (pc < code.length) { const opcode = code[pc++]; table[opcode](stack); stack.push(1); }\n}";
        let (_, analysis, workspace) = analyze(source, &[]);
        let result = &analysis["results"][0];
        assert_eq!(result["runtime"], "javascript");
        assert_eq!(result["tier"], "candidate");
        assert_eq!(result["vm_score"], 75);
        assert_eq!(result["status"], "partial");
        assert_eq!(result["coverage"]["complete"], false);
        assert_eq!(
            result["coverage"]["omissions"],
            json!([{
                "reason": "handler-unavailable",
                "detail": "The dispatch pattern did not yield a static handler table, so this artifact stays a candidate."
            }])
        );
        assert_eq!(analysis["summary"]["candidate_count"], 1);
        assert_eq!(analysis["summary"]["likely_vm_count"], 0);
        assert_eq!(workspace["summary"]["workspace_count"], 1);
        assert!(
            workspace["workspaces"][0]["handlers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            workspace["workspaces"][0]["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "handler-unavailable")
        );
        assert_schema(&workspace);
        let schema: Value =
            serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json"))
                .unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&analysis)
            .expect("handler-less JavaScript analysis");
    }

    #[test]
    fn canvas_burst_and_snapshot_do_not_create_guest_dispatch_evidence() {
        let mut events = (0..256)
            .map(|index| {
                let mut host = event(80);
                host["sequence_number"] = json!((index + 2).to_string());
                host["category"] = json!("canvas");
                host["type"] = json!("api_call");
                host["payload"] = json!(hex::encode(b"canvas.getImageData"));
                host
            })
            .collect::<Vec<_>>();
        // An invocation marker alone is not a dispatch sample either.
        events.insert(0, invocation());
        let (root, _, document) =
            analyze_with_snapshot(&fixture("stack-vm.js"), &events, Some(&[1, 2, 3]));
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["sample_count"], 0);
        assert_eq!(workspace["samples"], json!([]));
        assert_eq!(workspace["snapshots"].as_array().unwrap().len(), 1);
        assert!(
            workspace["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|handler| { handler["state"] != "observed" && handler["sample_count"] == 0 })
        );
        let omission = workspace["coverage"]["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|omission| omission["reason"] == "sampler-unavailable")
            .unwrap();
        assert!(
            omission["detail"]
                .as_str()
                .unwrap()
                .contains("no guest dispatch emitter")
        );
        assert!(omission["detail"].as_str().unwrap().len() <= 240);
        assert_schema(&document);
        // Exercise the shipped strict consumer on the actual emitted document,
        // not a hand-written fixture that could miss a backend/frontend bound.
        let model =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../research-ui/evidence_models.js");
        let checked = std::process::Command::new("node")
            .args([
                "--eval",
                r#"
const fs = require('node:fs');
const validate = new Function(fs.readFileSync(process.argv[1], 'utf8') +
  '\nreturn isVmOpcodeWorkspaceDocument;')();
const document = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
if (!validate(document)) throw new Error('Backend workspace rejected by shipped UI validator');
"#,
            ])
            .arg(model)
            .arg(root.path().join("analysis/vm-opcode-workspace-v2.json"))
            .output()
            .expect("Node.js is required for the shipped UI contract regression");
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    #[test]
    fn packed_long_switch_does_not_create_a_workspace() {
        let (_, analysis, workspace) = analyze(&fixture("packed-non-vm.js"), &[]);
        assert_eq!(analysis["summary"]["likely_vm_count"], 0);
        assert_eq!(workspace["summary"]["workspace_count"], 0);
        assert_schema(&workspace);
    }

    #[test]
    fn computed_handler_names_stay_unknown() {
        let source = "while(pc<program.length){handlers[key]=function(){};handlers[7]=function(){};handlers[program[pc++]]();}";
        let (handlers, _, unknowns, _) = static_handlers(source, 0, source.len());
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0]["opcode"], 7);
        assert!(unknowns.iter().any(|unknown| unknown.contains("computed")));
    }

    fn change_payload(event: &mut Value, change: impl FnOnce(&mut Vec<u8>)) {
        let mut bytes = hex::decode(event["payload"].as_str().unwrap()).unwrap();
        change(&mut bytes);
        event["payload"] = json!(hex::encode(bytes));
    }

    fn invocation() -> Value {
        let mut marker = event(0);
        marker["type"] = json!("vm_finding");
        marker["sequence_number"] = json!("1");
        let mut bytes = vec![0u8; 128];
        bytes[0..8].copy_from_slice(&[1, 0, 128, 0, 3, 0, 1, 4]);
        let label = b"owned-stack-v1";
        bytes[8..10].copy_from_slice(&(label.len() as u16).to_le_bytes());
        for offset in [24, 32, 40] {
            bytes[offset..offset + 8].copy_from_slice(&1u64.to_le_bytes());
        }
        bytes[48..56].copy_from_slice(&2u64.to_le_bytes());
        bytes[72..72 + label.len()].copy_from_slice(label);
        marker["payload"] = json!(hex::encode(bytes));
        marker
    }

    #[test]
    fn dispatch_retains_exact_payload_and_scoped_invocation_units() {
        let mut value = event(80);
        value["sequence_number"] = json!("2");
        value["parent_event_id"] = json!("1");
        change_payload(&mut value, |bytes| {
            bytes[4..8].copy_from_slice(&10u32.to_le_bytes());
            bytes[12..16].copy_from_slice(&3u32.to_le_bytes());
            bytes[16..20].copy_from_slice(&8u32.to_le_bytes());
            bytes[48..56].copy_from_slice(&2u64.to_le_bytes());
            bytes[57] = 2;
        });
        let (_, _, document) = analyze(&fixture("stack-vm.js"), &[invocation(), value.clone()]);
        let workspace = &document["workspaces"][0];
        let sample = &workspace["samples"][0];
        assert_eq!(sample["instruction_pointer"], 10);
        assert_eq!(sample["handler_index"], 3);
        assert_eq!(sample["sample_index"], 8);
        assert_eq!(sample["operand_count"], 2);
        assert_eq!(sample["bytecode_artifact_id"], "2");
        assert_eq!(sample["instruction_pointer_units"], "instruction-index");
        assert_eq!(sample["invocation_id"], "1");
        assert_eq!(sample["invocation_event"]["sequence_number"], "1");
        assert_eq!(sample["event"]["sequence_number"], "2");
        assert_eq!(workspace["sample_count"], 1);
        assert_eq!(
            workspace["source_artifact_sha256"],
            hex::encode(Sha256::digest(fixture("stack-vm.js")))
        );
        assert_schema(&document);

        for wrong in [
            "session_id",
            "process_id",
            "navigation_id",
            "frame_id",
            "artifact_id",
        ] {
            let mut marker = invocation();
            marker[wrong] = if wrong == "process_id" {
                json!(9)
            } else {
                json!("9")
            };
            let (_, _, rejected) = analyze(&fixture("stack-vm.js"), &[marker, value.clone()]);
            assert_eq!(
                rejected["workspaces"][0]["samples"][0]["instruction_pointer_units"], "unknown",
                "{wrong}"
            );
            assert!(rejected["workspaces"][0]["samples"][0]["invocation_id"].is_null());
        }
        let mut marker = invocation();
        change_payload(&mut marker, |bytes| bytes[112] = 1);
        let (_, _, rejected) = analyze(&fixture("stack-vm.js"), &[marker, value]);
        assert_eq!(
            rejected["workspaces"][0]["samples"][0]["instruction_pointer_units"],
            "unknown"
        );
    }

    #[test]
    fn dispatch_rejects_wrong_interpreter_scope_short_reserved_and_truncated() {
        let source = fixture("stack-vm.js");
        let mut cases = Vec::new();
        for offset in [20, 24, 32, 40, 56, 58, 64, 72, 112, 127] {
            let mut value = event(80);
            change_payload(&mut value, |bytes| {
                if [24, 32, 40].contains(&offset) {
                    bytes[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
                } else {
                    bytes[offset] = 1;
                }
            });
            cases.push(value);
        }
        let mut wrong_interpreter = event(80);
        change_payload(&mut wrong_interpreter, |bytes| {
            bytes[40..48].copy_from_slice(&2u64.to_le_bytes())
        });
        cases.push(wrong_interpreter);
        let mut short = event(80);
        change_payload(&mut short, |bytes| {
            bytes.pop();
        });
        cases.push(short);
        for key in ["session_id", "navigation_id", "frame_id", "artifact_id"] {
            let mut value = event(80);
            value[key] = json!("2");
            cases.push(value);
        }
        let mut truncated = event(80);
        truncated["payload_truncated"] = json!(true);
        cases.push(truncated);
        for value in cases {
            let (_, _, document) = analyze(&source, &[value]);
            let workspace = &document["workspaces"][0];
            assert_eq!(workspace["sample_count"], 0);
            assert!(workspace["samples"].as_array().unwrap().is_empty());
            assert!(
                workspace["handlers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|handler| handler["state"] == "inferred")
            );
            assert!(
                workspace["coverage"]["omissions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["reason"] == "sampler-unavailable")
            );
            assert_schema(&document);
        }
    }

    #[test]
    fn dispatch_unknown_opcode_and_retention_limit_preserve_total_counts() {
        let mut events = Vec::new();
        for index in 0..MAX_SAMPLES + 2 {
            let mut value = event(if index == 0 { 99 } else { 80 });
            value["sequence_number"] = json!((index + 1).to_string());
            events.push(value);
        }
        let (_, _, document) = analyze(&fixture("stack-vm.js"), &events);
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["samples"].as_array().unwrap().len(), MAX_SAMPLES);
        assert_eq!(workspace["sample_count"], MAX_SAMPLES + 2);
        assert_eq!(document["summary"]["sample_count"], MAX_SAMPLES + 2);
        assert_eq!(workspace["samples"][0]["opcode"], 99);
        let push = workspace["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["opcode"] == 80)
            .unwrap();
        assert_eq!(push["sample_count"], MAX_SAMPLES + 1);
        assert!(
            workspace["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row.as_str().unwrap().contains("99"))
        );
        assert!(
            workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["reason"] == "sample-limit")
        );
        assert_schema(&document);
    }

    #[test]
    fn workspace_v1_is_not_guessed_into_v2() {
        let (_, _, mut document) = analyze(&fixture("stack-vm.js"), &[]);
        document["contract_version"] = json!(1);
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .unwrap();
        assert!(
            !jsonschema::validator_for(&schema)
                .unwrap()
                .is_valid(&document)
        );
    }

    #[test]
    fn numeric_object_map_entries_are_handler_candidates() {
        let source = "const table={1:function(){},0x2:()=>{}};while(pc<program.length){stack.push(table[program[pc++]]());}";
        let (handlers, model, _, _) = static_handlers(source, 0, source.len());
        assert_eq!(model, "stack");
        assert_eq!(
            handlers
                .iter()
                .map(|handler| handler["opcode"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(
            handlers
                .iter()
                .all(|handler| handler["handler_index"] == handler["opcode"])
        );
    }
    #[test]
    fn handler_ranges_include_nested_helpers_and_exclude_neighbor_cases() {
        let source = "/*é*/ function setup(){handlers[7]=function(){function helper(){return 5;}stack.push(program[pc++]);};} while(pc<program.length){handlers[program[pc++]]();}";
        let start = source.find("function setup").unwrap();
        let (handlers, _, _, _) = static_handlers(source, start, source.len());
        assert_eq!(handlers.len(), 1);
        let handler = &handlers[0];
        let offset = handler["source"]["byte_offset"].as_u64().unwrap() as usize;
        let size = handler["source"]["byte_size"].as_u64().unwrap() as usize;
        assert_eq!(
            &source[offset..offset + size],
            "handlers[7]=function(){function helper(){return 5;}stack.push(program[pc++]);}"
        );
        assert_eq!(handler["operand_width"], 1);

        let source = "switch(program[pc++]){case 1: switch(state){case 99: break;} break; case 2: return; default: throw 0;}";
        let (handlers, _, _, _) = static_handlers(source, 0, source.len());
        assert_eq!(
            handlers
                .iter()
                .map(|h| h["opcode"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [1, 2]
        );
        let end = handlers[0]["source"]["byte_offset"].as_u64().unwrap()
            + handlers[0]["source"]["byte_size"].as_u64().unwrap();
        assert_eq!(end as usize, source.find("case 2:").unwrap());
    }

    #[test]
    fn operand_guesses_are_bounded_adjacent_and_explicit_when_unknown() {
        for (body, expected) in [
            ("stack.push(program[pc++]);", 1),
            ("stack.push(program[pc++] | program[pc++] << 8);", 2),
            (
                "return bytes[ip] | bytes[ip+1] << 8 | bytes[ip+2] << 16 | bytes[ip+3] << 24;",
                4,
            ),
            ("return bytes[ip] + bytes[ip+2];", 0),
            ("return bytes[ip++] + bytes[ip++] + bytes[ip++];", 0),
            ("if(state) return bytes[ip++];", 0),
            ("let a=bytes[ip++]; ip+=8; return a+bytes[ip++];", 0),
            ("return stack.pop();", 0),
            ("program[pc++] = 1;", 0),
            ("bytes[ip] += 1;", 0),
            ("++bytes[ip];", 0),
            ("let a=bytes[ip++]; ++ip; return a+bytes[ip++];", 0),
            ("function helper(){return bytes[ip++];} return helper();", 0),
        ] {
            let source = format!("handlers[1]=function(){{{body}}};");
            let (handlers, _, _, _) = static_handlers(&source, 0, source.len());
            assert_eq!(handlers[0]["operand_width"], expected, "{body}");
            assert!(
                handlers[0]["notes"]
                    .as_str()
                    .unwrap()
                    .contains(if expected == 0 {
                        "unknown"
                    } else {
                        "static guess"
                    })
            );
        }
    }

    #[test]
    fn position_and_saved_state_selectors_do_not_invent_opcodes() {
        for expression in [
            "program[pc++] ^ pc",
            "program[pc++] + state",
            "decode(program[pc++])",
            "mapping[program[pc++]]",
        ] {
            for dispatch in [
                "switch(selector){case 7:stack.push(1);break;}",
                "handlers[selector]();",
            ] {
                let source =
                    format!("handlers[7]=function(){{}}; const selector={expression}; {dispatch}");
                let (handlers, _, unknowns, _) = static_handlers(&source, 0, source.len());
                if dispatch.starts_with("switch") {
                    // An unrelated literal table assignment remains independent.
                    assert_eq!(handlers.len(), 1);
                    assert!(handlers[0].get("handler_index").is_some());
                } else {
                    assert!(handlers.is_empty(), "{source}");
                }
                assert!(
                    unknowns
                        .iter()
                        .any(|s| s.contains("no proven fixed opcode mapping"))
                );
            }
        }
        let source = "let opcode=program[pc++]; opcode ^= saved; switch(opcode){case 9:break;}";
        assert!(static_handlers(source, 0, source.len()).0.is_empty());
        let source = "const opcode=program[pc++];const alias=opcode;switch(alias){case 9:break;}";
        assert_eq!(static_handlers(source, 0, source.len()).0[0]["opcode"], 9);
    }

    #[test]
    fn computed_objects_and_expression_arrows_do_not_borrow_other_bodies() {
        let source = "const handlers={[key]:()=>{},7(){return program[pc++];},a8:()=>{},9:()=>{const nested={99:()=>{}};}};handlers[program[pc++]]();";
        let (handlers, _, unknowns, _) = static_handlers(source, 0, source.len());
        assert_eq!(
            handlers
                .iter()
                .map(|h| h["opcode"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [7, 9]
        );
        assert!(unknowns.iter().any(|s| s.contains("computed")));
        let source = "handlers[1]=x=>x,handlers[2]=()=>{};";
        let (handlers, _, _, _) = static_handlers(source, 0, source.len());
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0]["opcode"], 2);
    }

    #[test]
    fn handler_cap_preserves_named_omission() {
        let source = (0..1025)
            .map(|i| format!("handlers[{i}]=function(){{}};"))
            .collect::<String>();
        let (handlers, _, _, omissions) = static_handlers(&source, 0, source.len());
        assert_eq!(handlers.len(), MAX_HANDLERS);
        assert_eq!(handlers.last().unwrap()["opcode"], 1023);
        assert_eq!(
            omissions,
            vec![
                json!({"reason":"handler-limit","detail":"Only the first 1024 distinct opcode candidates are retained."})
            ]
        );
    }
    #[test]
    fn mutable_and_late_selectors_stay_unknown_and_fallthrough_cites_shared_body() {
        for source in [
            "let opcode=program[pc++]; ++opcode; switch(opcode){case 9:break;}",
            "let opcode=program[pc++]; opcode <<= 1; switch(opcode){case 9:break;}",
            "switch(opcode){case 9:break;} const opcode=program[pc++];",
            "const alias=opcode;const opcode=program[pc++];switch(alias){case 9:break;}",
        ] {
            assert!(
                static_handlers(source, 0, source.len()).0.is_empty(),
                "{source}"
            );
        }
        let source = "switch(program[pc++]){case 1: case 2: stack.push(program[pc++]);break;default:return;}";
        let (handlers, _, _, _) = static_handlers(source, 0, source.len());
        assert_eq!(handlers.len(), 2);
        for handler in handlers {
            let offset = handler["source"]["byte_offset"].as_u64().unwrap() as usize;
            let size = handler["source"]["byte_size"].as_u64().unwrap() as usize;
            assert!(source[offset..offset + size].contains("stack.push"));
            assert_eq!(handler["operand_width"], 1);
        }
    }
}
