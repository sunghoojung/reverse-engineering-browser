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

#[path = "vm_opcode_native_guest.rs"]
mod native_guest;
#[path = "vm_opcode_native_module.rs"]
mod native_module;
#[path = "vm_opcode_native_wasm.rs"]
mod native_wasm;
#[path = "vm_opcode_wasm.rs"]
mod wasm;

const PRODUCER_VERSION: &str = "2.9.0";
const MAX_SAMPLES: usize = 4096;
const MAX_HANDLERS: usize = 1024;
const MAX_SNAPSHOTS: usize = 16;
const MAX_WORKSPACES: usize = 256;
const MAX_UNKNOWNS: usize = 256;
const SNAPSHOT_PREVIEW_BYTES: usize = 4096;

fn count_label(count: u32, singular: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

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
    if value["capture_origin"] == "native_wasm_guest" {
        return evidence::validate_artifact(&mut value.clone());
    }
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

/// Why a dispatch site yields no opcode claims. Its arms or constants are
/// not guest opcodes.
fn withheld_reason(
    roles: &vm::dispatch_shape::Roles,
    role: Option<vm::dispatch_shape::Role>,
) -> String {
    use vm::dispatch_shape::Role;
    match role {
        Some(Role::InterpreterCandidate) => String::new(),
        Some(Role::Multiplexer) => "A one-shot router dispatches on a call argument. Its case values route one call and are not claimed as guest opcodes.".into(),
        Some(Role::Other) => "A dispatch site is not a cursor-advancing loop. Its case values are not claimed as guest opcodes.".into(),
        None if roles.limited() => "A dispatch site was not classified: the classification work limit was reached. Its case values are not claimed as guest opcodes.".into(),
        None => "A dispatch site has no structural classification. Its case values are not claimed as guest opcodes.".into(),
    }
}

static OBJECT_ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*\{").expect("object assignment"));
static INDEXED_TABLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_$][\w$]*)\s*\[").expect("indexed table"));

/// Handlers `static_handlers` recovered, after the opcode-claim gate.
struct Gated {
    handlers: Vec<Value>,
    withheld: usize,
    unknowns: Vec<String>,
}

/// The opcode-claim gate: a pure post-filter on recovered handlers. It keeps
/// a switch case only when that switch is a classified interpreter-candidate
/// site, and a table entry only when the region dispatches through that
/// table (`t[op](...)`, `t[op].call(...)`) at an interpreter-candidate site.
/// It never adds a handler and never feeds recovery, tier or score.
fn gate_handlers(
    source: &str,
    start: usize,
    end: usize,
    handlers: Vec<Value>,
    roles: &vm::dispatch_shape::Roles,
) -> Gated {
    use vm::dispatch_shape::Role;
    let region = vm::mask(&source[start..end]);
    let outer = without_nested_functions(&region);
    // The switches recovery reads, found the same way it finds them.
    let mut switches = Vec::new();
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
        switches.push((switch_match.start(), opening_brace, closing_brace));
    }
    // Every site that dispatches through a named table, nested functions
    // included, as recovery collects table names from the whole region.
    let mut table_roles = BTreeMap::<String, Vec<Option<Role>>>::new();
    for captures in vm::dispatch_shape::javascript::INDEXED_CALL.captures_iter(&region) {
        let at = start + captures.get(0).expect("indexed call").start();
        table_roles
            .entry(captures[1].to_owned())
            .or_default()
            .push(roles.get(at));
    }
    let objects = OBJECT_ASSIGNMENT
        .captures_iter(&region)
        .filter_map(|captures| {
            let opening = captures.get(0)?.end() - 1;
            let closing = matching(region.as_bytes(), opening, b'{', b'}')?;
            Some((opening, closing, captures[1].to_owned()))
        })
        .collect::<Vec<_>>();
    let mut kept = Vec::new();
    let mut unknowns = Vec::new();
    let mut withheld = 0usize;
    for handler in handlers {
        let at = handler["source"]["byte_offset"].as_u64().unwrap_or(0) as usize;
        let relative = at.saturating_sub(start);
        let verdict = if handler.get("handler_index").is_none() {
            switches
                .iter()
                .find(|(_, open, close)| *open < relative && relative < *close)
                .map(|(keyword, _, _)| roles.get(start + keyword))
                .unwrap_or(None)
        } else {
            let table = INDEXED_TABLE
                .captures(&region[relative.min(region.len())..])
                .map(|captures| captures[1].to_owned())
                .or_else(|| {
                    objects
                        .iter()
                        .filter(|(open, close, _)| *open < relative && relative < *close)
                        .max_by_key(|(open, _, _)| *open)
                        .map(|(_, _, name)| name.clone())
                });
            table
                .and_then(|name| table_roles.get(&name))
                .map(|sites| {
                    if sites.contains(&Some(Role::InterpreterCandidate)) {
                        Some(Role::InterpreterCandidate)
                    } else {
                        sites.iter().copied().find(Option::is_some).flatten()
                    }
                })
                .unwrap_or(Some(Role::Other))
        };
        if verdict == Some(Role::InterpreterCandidate) {
            kept.push(handler);
        } else {
            withheld += 1;
            unknowns.push(withheld_reason(roles, verdict));
        }
    }
    unknowns.sort();
    unknowns.dedup();
    Gated {
        handlers: kept,
        withheld,
        unknowns,
    }
}

#[cfg(test)]
thread_local! {
    /// Differential tests run the workspace without the opcode-claim gate.
    static GATE_DISABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn gate_enabled() -> bool {
    #[cfg(test)]
    {
        !GATE_DISABLED.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        true
    }
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
        || (event_identity(event).is_none()
            && crate::vm_dispatch_input::report_reference(event).is_none())
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

pub(crate) struct DispatchBudgetLoss {
    pub artifact_id: String,
    pub session_id: String,
    pub navigation_id: String,
    pub frame_id: String,
    pub dropped: u64,
}

/// A vm gap names a dispatch-budget loss when its artifact id is the interpreter
/// and its payload is the decimal observation count. Queue-full gaps leave the
/// artifact id at zero and stay ordinary capture gaps.
pub(crate) fn dispatch_budget_loss(event: &Value) -> Option<DispatchBudgetLoss> {
    if event["category"] != "vm" || event["type"] != "gap" {
        return None;
    }
    let artifact = event.get("artifact_id")?;
    if !evidence::canonical(artifact, 64, true) {
        return None;
    }
    let payload = hex::decode(event["payload"].as_str()?).ok()?;
    if payload.is_empty()
        || payload.len() > 20
        || payload[0] == b'0'
        || !payload.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let dropped = std::str::from_utf8(&payload).ok()?.parse::<u64>().ok()?;
    if dropped == 0 {
        return None;
    }
    Some(DispatchBudgetLoss {
        artifact_id: artifact.as_str()?.to_owned(),
        session_id: event["session_id"].as_str()?.to_owned(),
        navigation_id: event["navigation_id"].as_str()?.to_owned(),
        frame_id: event["frame_id"].as_str()?.to_owned(),
        dropped,
    })
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
    let caller = match event["type"].as_str()? {
        "vm_dispatch_report" => {
            crate::vm_dispatch_input::report_reference(event)?;
            let value = event.get("dispatch_provenance")?;
            if !crate::vm_dispatch_input::provenance(value, artifact) {
                return None;
            }
            Some(value)
        }
        "vm_dispatch_sample" if event.get("dispatch_provenance").is_none() => None,
        _ => return None,
    };
    let payload = event_payload(event, event["type"].as_str()?)?;
    let finding = read_u64(&payload, 24);
    let investigation = read_u64(&payload, 32);
    let interpreter = read_u64(&payload, 40);
    let bytecode = read_u64(&payload, 48);
    if payload[20..24].iter().any(|byte| *byte != 0)
        || finding == 0
        || investigation == 0
        || interpreter == 0
        || interpreter.to_string() != artifact["artifact_id"].as_str()?
        || (caller.is_some() && bytecode != 0)
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
    if let Some(provenance) = caller {
        result["provenance"] = provenance.clone();
        return Some(result);
    }
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
            artifact["kind"] != "wasm_guest_adapter"
                && artifact["parent_artifact_id"] != "0"
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
                    "origin": if artifact["capture_origin"] == "native_wasm_guest" { "native-wasm-guest" } else { "runtime-typed-array" },
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
                        "origin": if artifact["capture_origin"] == "native_wasm_guest" { "native-wasm-guest" } else { "runtime-typed-array" },
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

/// A retained sample proves a guest ISA only when its PC units are real and
/// the opcode hits exactly one static handler. Owned exact-hash effects are
/// the other proof. Static arms, unknown PC units, and repeated selectors do not.
fn guest_opcode_isa_proven(
    samples: &[Value],
    handlers: &[Value],
    owned: Option<&Value>,
    module_roles: Option<&vm::dispatch_shape::Roles>,
) -> bool {
    // A Wasm arm proves a guest opcode only at an interpreter-candidate site.
    // Router and ordinary branch arms stay selectors whatever a sample says.
    let interpreter_arm = |handler: &Value| {
        module_roles.is_none_or(|roles| {
            handler["source"]["byte_offset"]
                .as_u64()
                .is_some_and(|offset| {
                    roles.get(offset as usize)
                        == Some(vm::dispatch_shape::Role::InterpreterCandidate)
                })
        })
    };
    let mut sites = BTreeMap::<u32, usize>::new();
    for handler in handlers {
        if let Some(opcode) = handler["opcode"].as_u64() {
            *sites.entry(opcode as u32).or_default() += 1;
        }
    }
    let sample_proves = samples.iter().any(|sample| {
        let units = sample["instruction_pointer_units"].as_str();
        if units != Some("instruction-index") && units != Some("byte-offset") {
            return false;
        }
        let Some(opcode) = sample["opcode"].as_u64().map(|value| value as u32) else {
            return false;
        };
        sites.get(&opcode).copied() == Some(1)
            && handlers.iter().any(|handler| {
                handler["opcode"].as_u64() == Some(u64::from(opcode))
                    && handler["state"] == "observed"
                    && handler["sample_count"].as_u64().unwrap_or(0) > 0
                    && interpreter_arm(handler)
            })
    });
    if sample_proves {
        return true;
    }
    let Some(declaration) = owned else {
        return false;
    };
    if !handlers
        .iter()
        .any(|handler| crate::vm_effects::unique_effect(handler).is_some())
    {
        return false;
    }
    // Byte-addressed owned programs publish an entry offset. Native owned
    // programs keep that offset null and name instruction-index units by
    // exact-hash declaration. Neither path reads an identifier out of an
    // arbitrary page script.
    let declared_model = matches!(declaration["model"].as_str(), Some("stack" | "register"));
    declared_model
        && (declaration["entry_offset"].as_u64().is_some()
            || (declaration["entry_offset"].is_null()
                && declaration["operand_endianness"].is_null()))
}

/// Effect cells are the only machine-state evidence. A null register index
/// does not invent a register file, and a stack-shaped identifier does not
/// count as an observed stack.
fn machine_state(handlers: &[Value]) -> Option<Value> {
    let mut stack = false;
    let mut max_register: Option<u64> = None;
    for handler in handlers {
        let Some(effects) = handler.get("effects").and_then(|value| value.as_array()) else {
            continue;
        };
        for effect in effects {
            for key in ["reads", "writes"] {
                let Some(cells) = effect.get(key).and_then(|value| value.as_array()) else {
                    continue;
                };
                for cell in cells {
                    match cell["space"].as_str() {
                        Some("stack") => stack = true,
                        Some("register") => {
                            if let Some(index) = canonical_index(&cell["index"]) {
                                max_register =
                                    Some(max_register.map_or(index, |prior| prior.max(index)));
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }
    if !stack && max_register.is_none() {
        return None;
    }
    Some(json!({
        "register_count": max_register.map(|index| index + 1),
        "stack_observed": if stack { Some(true) } else { None::<bool> },
    }))
}

fn canonical_index(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text == "0" {
        return Some(0);
    }
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let index = text.parse::<u64>().ok()?;
    (index < 65536).then_some(index)
}

fn workspace_evidence_class(
    samples: &[Value],
    handlers: &[Value],
    owned: Option<&Value>,
    inventory: Option<&Value>,
    module_roles: Option<&vm::dispatch_shape::Roles>,
) -> Option<&'static str> {
    if guest_opcode_isa_proven(samples, handlers, owned, module_roles) {
        return Some("guest-opcode-isa");
    }
    if let Some(candidates) = inventory
        .and_then(|value| value.get("candidates"))
        .and_then(|value| value.as_array())
    {
        let class_of = |name| candidates.iter().any(|site| site["evidence_class"] == name);
        if class_of("handler-table-candidate") {
            return Some("handler-table-candidate");
        }
        if class_of("call-indirect-table") {
            return Some("call-indirect-table");
        }
        if class_of("cff-helper") {
            return Some("cff-helper");
        }
    }
    handlers
        .iter()
        .any(|handler| handler["opcode"].as_u64().is_some())
        .then_some("handler-table-candidate")
}

pub(crate) fn workspace(
    root: &Path,
    artifact: &Value,
    bytes: &[u8],
    result: &Value,
    snapshot_artifacts: &[Value],
    events: &[Value],
    budget_losses: &[DispatchBudgetLoss],
) -> Option<Value> {
    // A ranked Wasm table may be worth inspecting without enough independent
    // evidence for likely-vm. Keeping its static workspace never raises that tier.
    let static_wasm_candidate = result["runtime"] == "webassembly"
        && result["tier"] == "candidate"
        && result["frontend"]["dispatch_inventory"]["selected_byte_offset"].is_u64();
    if result["tier"] != "likely-vm" && !static_wasm_candidate {
        return None;
    }
    let runtime = result["runtime"].as_str()?;
    // Roles of every classified site, recomputed in full from the artifact
    // bytes: the gate never reads the bounded listed document.
    let roles = gate_enabled()
        .then(|| vm::dispatch_roles(runtime, bytes))
        .flatten();
    let (mut handlers, model, mut unknowns, mut omissions, module_dispatch, handler_tables) =
        match runtime {
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
                // Recovery is the unchanged path that also decides the tier.
                // The gate only removes claims from its output afterwards.
                let (handlers, model, mut unknowns, mut omissions) =
                    static_handlers(source, region.0, end);
                let handlers = match &roles {
                    Some(roles) => {
                        let gated = gate_handlers(source, region.0, end, handlers, roles);
                        unknowns.extend(gated.unknowns);
                        if gated.withheld > 0 {
                            omissions.push(json!({"reason":"handler-withheld","detail":format!(
                                "Static recovery found {} that no switch or table tied to a cursor-loop interpreter-candidate site supports, so they are not claimed as guest opcodes. The tier is unchanged.",
                                count_label(gated.withheld as u32, "opcode candidate")
                            )}));
                        }
                        gated.handlers
                    }
                    None => handlers,
                };
                (handlers, model, unknowns, omissions, None, Vec::new())
            }
            "webassembly" => {
                let extracted = wasm::handlers(bytes, result)?;
                (
                    extracted.handlers,
                    "unknown".into(),
                    extracted.unknowns,
                    extracted.omissions,
                    Some(extracted.dispatch),
                    extracted.handler_tables,
                )
            }
            _ => return None,
        };
    if result["frontend"]["dispatch_inventory"]["omitted_site_count"]
        .as_u64()
        .unwrap_or(0)
        > 0
    {
        omissions.push(json!({"reason":"dispatch-inventory-limit","detail":"The module-wide count includes every decoded dispatch site; only the top 256 ranked sites are listed."}));
    }
    // Withheld handlers are named separately: recovery did find them.
    if handlers.is_empty()
        && !omissions
            .iter()
            .any(|omission| omission["reason"] == "handler-withheld")
    {
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
    let mut native_samples = BTreeSet::<u32>::new();
    let mut caller_count = 0u64;
    let mut retained_samples = Vec::new();
    let mut sample_count = 0u64;
    for event in events {
        if let Some(value) = sample(event, artifact, &invocations) {
            let opcode = value["opcode"].as_u64().expect("sample opcode") as u32;
            if value.get("provenance").is_some() {
                caller_count += 1;
            } else {
                native_samples.insert(opcode);
            }
            *samples.entry(opcode).or_default() += 1;
            sample_count += 1;
            if retained_samples.len() < MAX_SAMPLES {
                retained_samples.push(value);
            }
        }
    }
    // One lazily decoded index serves both native streams for this artifact.
    let mut module = (artifact["kind"] == "wasm")
        .then(|| native_module::Module::parse(bytes))
        .flatten();
    let observations = native_wasm::collect(artifact, module.as_mut(), events);
    let guest_samples = native_guest::collect(
        root,
        artifact,
        bytes,
        module.as_mut(),
        snapshot_artifacts,
        events,
    );
    let budget_dropped = budget_losses
        .iter()
        .filter(|loss| {
            loss.artifact_id == artifact["artifact_id"].as_str().unwrap_or("")
                && loss.session_id == artifact["session_id"].as_str().unwrap_or("")
                && loss.navigation_id == artifact["navigation_id"].as_str().unwrap_or("")
                && loss.frame_id == artifact["frame_id"].as_str().unwrap_or("")
        })
        .fold(0u64, |total, loss| total.saturating_add(loss.dropped));
    if caller_count > 0 {
        omissions.push(json!({"reason":"caller-samples-unverified", "detail":
            "Caller-supplied dispatch reports were retained, not independently observed by a native sampler. They cannot confirm handlers, PC units, invocation identity or host-call causality."}));
    }
    let undecodable = observations.undecodable + guest_samples.undecodable;
    if undecodable > 0 {
        omissions.push(json!({"reason":"native-wasm-module-undecodable","detail":format!(
            "The captured module's sections did not decode, so {} native Wasm observations and {} native guest samples could not be checked against an exact site.",
            observations.undecodable, guest_samples.undecodable
        )}));
    }
    if native_samples.is_empty()
        && observations.count == 0
        && guest_samples.count == 0
        && budget_dropped == 0
        && undecodable == 0
    {
        omissions.push(json!({"reason":"sampler-unavailable", "detail":
            "No native dispatch samples were retained. Rebuild with native guest capture, enable an exact matching adapter, and inspect capture omissions. Static dispatch, Canvas calls and snapshots alone do not prove a guest PC."}));
    }
    if sample_count > retained_samples.len() as u64 {
        omissions.push(json!({"reason":"sample-limit", "detail":"Only the first 4096 accepted sample records are retained; counts include all accepted samples."}));
    }
    if budget_dropped > 0 {
        omissions.push(json!({"reason":"dispatch-sample-budget", "detail": format!(
            "The 16-sample dispatch budget omitted {budget_dropped} observations for this interpreter. Retained samples are a capped trace, not a complete guest dispatch."
        )}));
    }
    let mut opcode_sites = BTreeMap::<u32, usize>::new();
    for handler in &handlers {
        if let Some(opcode) = handler["opcode"].as_u64() {
            *opcode_sites.entry(opcode as u32).or_default() += 1;
        }
    }
    for handler in &mut handlers {
        let Some(opcode) = handler["opcode"].as_u64().map(|value| value as u32) else {
            continue;
        };
        // A repeated selector is local to its br_table. One sample must not
        // mark every site observed or the handler counts exceed the samples.
        if opcode_sites.get(&opcode).copied().unwrap_or(0) > 1 {
            continue;
        }
        if let Some(count) = samples.get(&opcode) {
            handler["sample_count"] = json!(count);
            if native_samples.contains(&opcode) {
                handler["state"] = json!("observed");
            }
        }
    }
    observations.attach(&mut handlers);
    guest_samples.attach(&mut handlers);
    if guest_samples.invalid > 0 {
        omissions.push(json!({"reason":"native-guest-sample-invalid","detail":format!("Rejected {} malformed or mismatched native guest samples.",guest_samples.invalid)}));
    }
    if guest_samples.count > guest_samples.rows.len() as u64 {
        omissions.push(json!({"reason":"native-guest-sample-limit","detail":"Only the first 4096 native guest samples are retained."}));
    }
    if observations.invalid > 0 {
        omissions.push(json!({"reason":"native-wasm-observation-invalid","detail":format!("Rejected {} malformed, mismatched or out-of-scope native Wasm observations.", observations.invalid)}));
    }
    if observations.count > observations.rows.len() as u64 {
        omissions.push(json!({"reason":"native-wasm-observation-limit","detail":"Only the first 4096 native Wasm observations are retained; counts include all accepted observations."}));
    }
    if observations.count > 0 {
        unknowns.push("Native br_table observations prove physical Wasm site and selector execution, not a guest PC, guest opcode ISA, invocation or host-call causality.".into());
    }
    if opcode_sites
        .iter()
        .any(|(opcode, count)| *count > 1 && samples.contains_key(opcode))
    {
        unknowns.push(
            "A reported opcode matches more than one static dispatch site, so it stays unbound."
                .into(),
        );
    }
    for opcode in samples.keys() {
        if !handlers
            .iter()
            .any(|handler| handler["opcode"].as_u64() == Some(u64::from(*opcode)))
        {
            unknowns.push(format!(
                "Reported opcode {opcode} has no static handler candidate in the dispatch region."
            ));
        }
    }
    // Counted before coverage, which is complete only without unknowns.
    if runtime == "webassembly"
        && let Some(roles) = &roles
    {
        let routed = handlers
            .iter()
            .filter_map(|handler| handler["source"]["byte_offset"].as_u64())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|offset| {
                roles
                    .get(*offset as usize)
                    .is_some_and(|role| role != vm::dispatch_shape::Role::InterpreterCandidate)
            })
            .count();
        if routed > 0 {
            unknowns.push(format!(
                "{} {} not a cursor-loop interpreter. Those arms are Wasm branch selectors, not guest opcodes.",
                count_label(routed as u32, "retained dispatch site"),
                if routed == 1 { "is" } else { "are" }
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
    // Module bytes are not a guest snapshot. Name that static-only stop
    // instead of an empty snapshot frontier when the dispatch sites exist.
    let static_module = runtime == "webassembly" && snapshots.is_empty() && !handlers.is_empty();
    if static_module {
        traversal["entry_offsets"] = json!([]);
        traversal["instructions"] = json!([]);
        traversal["edges"] = json!([]);
        traversal["frontier"] = json!([{
            "artifact_id": null,
            "byte_offset": null,
            "reason": "static-module-only"
        }]);
        traversal["complete"] = json!(false);
    }
    if traversal["complete"] != true {
        if static_module {
            let dispatch = module_dispatch.as_ref().expect("wasm dispatch summary");
            omissions.push(json!({
                "reason": "static-module-dispatch",
                "detail": format!(
                    "Static module walk kept {} across {}. Guest-byte traversal has no runtime snapshot and does not infer a guest PC.",
                    count_label(dispatch.sites, "dispatch site"),
                    count_label(dispatch.functions, "function")
                ),
            }));
        } else {
            omissions.push(json!({"reason":"reachable-frontier","detail":"The bounded instruction walk has unresolved entries or edges."}));
        }
    }
    let evidence_class = workspace_evidence_class(
        &retained_samples,
        &handlers,
        owned.as_ref(),
        result
            .get("frontend")
            .and_then(|frontend| frontend.get("dispatch_inventory")),
        roles.as_ref().filter(|_| runtime == "webassembly"),
    );
    let machine = machine_state(&handlers);
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
        // Physical and guest callbacks fire for the same br_table execution at
        // an adapter site, so each native stream keeps its own count below.
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
    if runtime == "webassembly" {
        workspace["native_guest_samples"] = json!(guest_samples.rows);
        workspace["native_guest_sample_count"] = json!(guest_samples.count);
        workspace["native_wasm_observations"] = json!(observations.rows);
        workspace["native_wasm_observation_count"] = json!(observations.count);
    }
    if runtime == "webassembly"
        && let Some(inventory) = result["frontend"].get("dispatch_inventory")
    {
        workspace["dispatch_inventory"] = inventory.clone();
    }
    if let Some(classification) = result["frontend"].get("dispatch_classification") {
        workspace["dispatch_classification"] = classification.clone();
    }
    if let Some(class) = evidence_class {
        workspace["evidence_class"] = json!(class);
    }
    if let Some(state) = machine {
        workspace["machine_state"] = state;
    }
    if !handler_tables.is_empty() {
        workspace["handler_tables"] = json!(handler_tables);
    }
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

// The C++ golden tests build a real evidence store from native encoder output.
// When the named variable is set, copy that exact store (manifest, events and
// content-addressed blobs) for consumers such as the rendered UI acceptance, so
// they never mirror the fixture by hand.
#[cfg(test)]
fn export_golden_evidence(root: &std::path::Path, variable: &str) {
    let Ok(out) = std::env::var(variable) else {
        return;
    };
    let out = std::path::Path::new(&out);
    std::fs::create_dir_all(out.join("blobs")).unwrap();
    for name in ["manifest.jsonl", "events.jsonl"] {
        std::fs::copy(root.join(name), out.join(name)).unwrap();
    }
    for entry in std::fs::read_dir(root.join("blobs")).unwrap() {
        let path = entry.unwrap().path();
        std::fs::copy(&path, out.join("blobs").join(path.file_name().unwrap())).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf};

    /// Static handler extraction with the same JavaScript classification
    /// that `analyze` records for the whole source.
    fn classified_handlers(
        source: &str,
        start: usize,
        end: usize,
    ) -> (Vec<Value>, String, Vec<String>, Vec<Value>) {
        let roles = vm::dispatch_roles("javascript", source.as_bytes()).expect("roles");
        let (handlers, model, mut unknowns, omissions) = static_handlers(source, start, end);
        let gated = gate_handlers(source, start, end, handlers, &roles);
        unknowns.extend(gated.unknowns);
        unknowns.sort();
        unknowns.dedup();
        (gated.handlers, model, unknowns, omissions)
    }

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

    #[test]
    fn native_wasm_observations_bind_only_exact_sites_and_default() {
        let bytes = wasm_fixture("two_br_tables");
        for selector in [0, 2, u32::MAX] {
            let event = native_wasm::tests::event(selector);
            let (_, _, document) = analyze_artifact(&bytes, "wasm", &[event.clone(), event]);
            assert_schema(&document);
            let workspace = &document["workspaces"][0];
            assert_eq!(workspace["sample_count"], 0);
            assert_eq!(workspace["native_wasm_observation_count"], 1);
            assert_eq!(workspace["samples"], json!([]));
            let observed = workspace["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|h| h["state"] == "observed")
                .collect::<Vec<_>>();
            assert_eq!(observed.len(), 1);
            assert_eq!(observed[0]["source"]["byte_offset"], 47);
            assert_eq!(observed[0]["native_wasm_sample_count"], 1);
            assert_ne!(workspace["evidence_class"], "guest-opcode-isa");
        }
        let mut conflict = native_wasm::tests::event(1);
        conflict["flags"] = json!(1);
        let (_, _, document) =
            analyze_artifact(&bytes, "wasm", &[native_wasm::tests::event(0), conflict]);
        assert_eq!(
            document["workspaces"][0]["native_wasm_observation_count"],
            0
        );
    }
    #[test]
    fn native_wasm_observation_requires_digest_verified_artifact() {
        let bytes = wasm_fixture("br_table");
        let (root, _, document) = analyze_artifact(&bytes, "wasm", &[native_wasm::tests::event(0)]);
        let hash = document["workspaces"][0]["source_artifact_sha256"]
            .as_str()
            .unwrap();
        let mut corrupted = bytes;
        corrupted[47] = 0x01;
        fs::write(root.path().join(format!("blobs/{hash}.bin")), corrupted).unwrap();
        crate::vm::store(root.path(), &root.path().join("events.jsonl")).unwrap();
        let rebuilt: Value = serde_json::from_slice(
            &fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(rebuilt["workspaces"], json!([]));
    }

    fn budget_gap(sequence: u64, dropped: u64) -> Value {
        json!({
            "protocol_version":2,
            "session_id":"1",
            "sequence_number":sequence.to_string(),
            "process_id":1,
            "navigation_id":"1",
            "frame_id":"1",
            "artifact_id":"1",
            "request_id":"0",
            "category":"vm",
            "type":"gap",
            "payload_encoding":"hex",
            "payload":hex::encode(dropped.to_string()),
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
            assert_eq!(workspace["sample_count"], 0);
            assert_eq!(workspace["traversal"]["entry_offsets"], json!([]));
            assert_eq!(workspace["traversal"]["instructions"], json!([]));
            assert_eq!(workspace["traversal"]["edges"], json!([]));
            assert_eq!(
                workspace["traversal"]["frontier"],
                json!([{
                    "artifact_id": null, "byte_offset": null, "reason": "static-module-only"
                }])
            );
            let static_walk = workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|omission| omission["reason"] == "static-module-dispatch")
                .expect("static module walk");
            assert_eq!(
                static_walk["detail"],
                "Static module walk kept 1 dispatch site across 1 function. Guest-byte traversal has no runtime snapshot and does not infer a guest PC."
            );
            assert!(
                workspace["coverage"]["omissions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|omission| omission["reason"] != "reachable-frontier")
            );
            assert_eq!(document["summary"]["snapshot_count"], 0);
            assert_eq!(workspace["coverage"]["complete"], false);
            assert!(
                workspace["coverage"]["omissions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|omission| omission["reason"] == "sampler-unavailable")
            );
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
    fn wasm_workspace_keeps_dispatch_samples_for_its_module() {
        let bytes = wasm_fixture("br_table");
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[event(0)]);
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["runtime"], "webassembly");
        assert_eq!(workspace["sample_count"], 1);
        assert_eq!(workspace["samples"][0]["opcode"], 0);
        assert_eq!(workspace["samples"][0]["interpreter_artifact_id"], "1");
        assert_eq!(
            workspace["samples"][0]["instruction_pointer_units"],
            "unknown"
        );
        assert!(
            workspace["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|handler| handler["opcode"] == 0 && handler["state"] == "observed")
        );
        assert!(
            workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|omission| omission["reason"] != "sampler-unavailable")
        );
        assert_eq!(workspace["coverage"]["complete"], false);
        assert_schema(&document);
    }

    #[test]
    fn dispatch_budget_gap_keeps_a_capped_trace_incomplete() {
        let source = fixture("stack-vm.js");
        let (_, _, with_samples) = analyze(&source, &[event(80), budget_gap(9, 16)]);
        let workspace = &with_samples["workspaces"][0];
        assert_eq!(workspace["sample_count"], 1);
        let omissions = workspace["coverage"]["omissions"].as_array().unwrap();
        let budget = omissions
            .iter()
            .find(|omission| omission["reason"] == "dispatch-sample-budget")
            .expect("budget omission");
        assert!(budget["detail"].as_str().unwrap().contains("omitted 16"));
        assert!(budget["detail"].as_str().unwrap().len() <= 240);
        assert!(
            omissions
                .iter()
                .all(|omission| omission["reason"] != "sampler-unavailable")
        );
        assert_eq!(workspace["coverage"]["complete"], false);
        assert_schema(&with_samples);

        let (_, _, dropped_only) = analyze(&source, &[budget_gap(4, 16)]);
        let empty = &dropped_only["workspaces"][0];
        assert_eq!(empty["sample_count"], 0);
        assert!(
            empty["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "dispatch-sample-budget")
        );
        assert!(
            empty["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|omission| omission["reason"] != "sampler-unavailable")
        );
        assert_eq!(empty["coverage"]["complete"], false);
        assert_schema(&dropped_only);

        let mut other_artifact = budget_gap(4, 3);
        other_artifact["artifact_id"] = json!("9");
        let (_, _, unrelated) = analyze(&source, &[event(80), other_artifact]);
        assert!(
            unrelated["workspaces"][0]["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|omission| omission["reason"] != "dispatch-sample-budget")
        );
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

    fn leb(mut value: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                return bytes;
            }
        }
    }

    fn wasm_section(id: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(leb(body.len() as u32));
        out.extend(body);
        out
    }

    /// Authored module. `element_funcs` installs those function indexes in table 0.
    fn wasm_module(bodies: &[&[u8]], element_funcs: Option<&[u32]>) -> Vec<u8> {
        let mut module = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        module.extend(wasm_section(1, &[0x01, 0x60, 0x00, 0x00]));
        let mut functions = leb(bodies.len() as u32);
        functions.extend(std::iter::repeat_n(0u8, bodies.len()));
        module.extend(wasm_section(3, &functions));
        if let Some(funcs) = element_funcs {
            let mut table = vec![0x01, 0x70, 0x00];
            table.extend(leb(funcs.len() as u32));
            module.extend(wasm_section(4, &table));
        }
        module.extend(wasm_section(5, &[0x01, 0x00, 0x01]));
        if let Some(funcs) = element_funcs {
            let mut element = vec![0x01, 0x00, 0x41, 0x00, 0x0b];
            element.extend(leb(funcs.len() as u32));
            for func in funcs {
                element.extend(leb(*func));
            }
            module.extend(wasm_section(9, &element));
        }
        let mut code = leb(bodies.len() as u32);
        for body in bodies {
            code.extend(leb(body.len() as u32));
            code.extend(*body);
        }
        module.extend(wasm_section(10, &code));
        module
    }

    fn br_table(selectors: u32) -> Vec<u8> {
        let mut bytes = vec![0x0e];
        bytes.extend(leb(selectors));
        bytes.extend(std::iter::repeat_n(0u8, selectors as usize + 1));
        bytes
    }

    fn ranked_dispatch_body(arms: u32, signals: bool) -> Vec<u8> {
        let mut body = vec![0x01, 0x01, 0x7f, 0x03, 0x40];
        if signals {
            body.extend([
                0x20, 0x00, 0x41, 0x01, 0x6a, 0x21, 0x00, 0x41, 0x00, 0x2d, 0x00, 0x00, 0x1a,
            ]);
        }
        body.extend([0x41, 0x00]);
        body.extend(br_table(arms));
        body.extend([0x0b, 0x0b]);
        body
    }

    fn br_table_targets(targets: &[u32], default: u32) -> Vec<u8> {
        let mut bytes = vec![0x0e];
        bytes.extend(leb(targets.len() as u32));
        for target in targets {
            bytes.extend(leb(*target));
        }
        bytes.extend(leb(default));
        bytes
    }

    fn ranked_body_with_targets(targets: &[u32], default: u32, signals: bool) -> Vec<u8> {
        let mut body = vec![0x01, 0x01, 0x7f, 0x03, 0x40];
        if signals {
            body.extend([
                0x20, 0x00, 0x41, 0x01, 0x6a, 0x21, 0x00, 0x41, 0x00, 0x2d, 0x00, 0x00, 0x1a,
            ]);
        }
        // Two nested blocks give label depths 0, 1, and 2 (the loop).
        body.extend([0x02, 0x40, 0x02, 0x40, 0x41, 0x00]);
        body.extend(br_table_targets(targets, default));
        body.extend([0x0b, 0x0b, 0x0b, 0x0b]);
        body
    }

    #[test]
    fn wasm_large_table_stays_a_handler_candidate_ahead_of_an_11_arm_helper() {
        // Relationship from a static module pass: dozens of ≥100-arm tables
        // beside small helpers, no plaintext guest bytecode, no proven ISA.
        // The numbers are not a score and the bytes are not that module.
        let helper = ranked_body_with_targets(&[0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 2], 0, true);
        let large = ranked_dispatch_body(100, false);
        let indirect = vec![0x00, 0x03, 0x40, 0x41, 0x00, 0x11, 0x00, 0x00, 0x0b, 0x0b];
        let bytes = wasm_module(&[&helper, &large, &indirect], Some(&[0, 1, 0]));
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
        let workspace = &document["workspaces"][0];
        let inventory = &workspace["dispatch_inventory"];
        assert_eq!(inventory["candidates"][0]["arm_count"], 100);
        assert_eq!(
            inventory["candidates"][0]["evidence_class"],
            "handler-table-candidate"
        );
        let helper_site = inventory["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|site| site["arm_count"] == 11)
            .unwrap();
        assert_eq!(helper_site["evidence_class"], "cff-helper");
        assert_eq!(helper_site["classification"], "cff-helper-candidate");
        assert_ne!(
            inventory["selected_byte_offset"],
            helper_site["byte_offset"]
        );
        let indirect_site = inventory["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|site| site["kind"] == "call_indirect")
            .unwrap();
        assert_eq!(indirect_site["evidence_class"], "call-indirect-table");
        assert!(indirect_site["arm_count"].is_null());
        assert_eq!(workspace["evidence_class"], "handler-table-candidate");
        assert_ne!(workspace["evidence_class"], "guest-opcode-isa");
        assert_eq!(workspace["model"], "unknown");
        assert!(workspace.get("machine_state").is_none());
        assert_eq!(workspace["sample_count"], 0);
        assert_eq!(
            workspace["traversal"]["frontier"][0]["reason"],
            "static-module-only"
        );
        assert!(
            workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "sampler-unavailable")
        );
        let tables = workspace["handler_tables"].as_array().unwrap();
        let large_table = tables
            .iter()
            .find(|table| table["arm_count"] == 100)
            .unwrap();
        assert_eq!(large_table["evidence_class"], "handler-table-candidate");
        assert_eq!(large_table["unique_target_count"], 1);
        assert_eq!(large_table["clusters"][0]["selector_count"], 100);
        assert_eq!(
            large_table["clusters"][0]["selectors"]
                .as_array()
                .unwrap()
                .len(),
            32
        );
        let small_table = tables
            .iter()
            .find(|table| table["arm_count"] == 11)
            .unwrap();
        assert_eq!(small_table["evidence_class"], "cff-helper");
        assert_eq!(small_table["unique_target_count"], 3);
        assert_eq!(small_table["clusters"][0]["target"], 0);
        assert_eq!(
            small_table["clusters"][0]["selectors"],
            json!([0, 2, 4, 6, 8])
        );
        assert_eq!(
            small_table["clusters"][1]["selectors"],
            json!([1, 3, 5, 7, 9])
        );
        assert_eq!(small_table["clusters"][2]["selectors"], json!([10]));
        let element = tables
            .iter()
            .find(|table| table["kind"] == "element")
            .unwrap();
        assert_eq!(element["evidence_class"], "call-indirect-table");
        assert_eq!(element["entry_count"], 3);
        assert_eq!(element["unique_target_count"], 2);
        assert_eq!(element["clusters"][0]["target"], 0);
        assert_eq!(element["clusters"][0]["selector_count"], 2);
        assert_eq!(element["clusters"][0]["selectors"], json!([0, 2]));
        assert!(
            inventory["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .all(|site| site["evidence_class"] != "guest-opcode-isa")
        );
        let handlers = workspace["handlers"].as_array().unwrap();
        let selected = inventory["selected_byte_offset"].as_u64().unwrap();
        assert_eq!(
            handlers
                .iter()
                .filter(|handler| handler["source"]["byte_offset"] == selected)
                .count(),
            101
        );
        assert!(
            handlers
                .iter()
                .all(|handler| handler["state"] != "observed")
        );
        assert_schema(&document);
    }

    #[test]
    fn wasm_module_ranking_selects_large_site_not_early_helper() {
        for (arms, signals) in [(200, true), (700, false)] {
            let helper = ranked_dispatch_body(8, true);
            let large = ranked_dispatch_body(arms, signals);
            let bytes = wasm_module(&[&helper, &large], None);
            wasmparser::Validator::new().validate_all(&bytes).unwrap();
            let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
            let result = &analysis["results"][0];
            assert_eq!(
                result["tier"],
                if signals { "likely-vm" } else { "candidate" }
            );
            let inventory = &result["frontend"]["dispatch_inventory"];
            assert_eq!(inventory["site_count"], 2);
            assert_eq!(inventory["candidates"][0]["function_index"], 1);
            assert_eq!(inventory["candidates"][0]["arm_count"], arms);
            assert_eq!(
                inventory["candidates"][0]["classification"],
                "dispatch-candidate"
            );
            // Every explicit arm in the fixture repeats label 0, plus the same
            // default. Clustering reports one Wasm target and does not demote
            // the large table to a helper or invent a guest opcode.
            assert_eq!(inventory["candidates"][0]["unique_target_count"], 1);
            assert!(inventory["candidates"][0]["element_fanout"].is_null());
            assert_eq!(inventory["candidates"][1]["arm_count"], 8);
            assert_eq!(inventory["candidates"][1]["unique_target_count"], 1);
            assert!(inventory["candidates"][1]["element_fanout"].is_null());
            assert_eq!(
                inventory["candidates"][1]["classification"],
                "cff-helper-candidate"
            );
            let workspace = &document["workspaces"][0];
            assert_eq!(workspace["dispatch_inventory"], *inventory);
            assert_eq!(
                workspace["handlers"].as_array().unwrap().len(),
                arms as usize + 1
            );
            assert_eq!(
                workspace["handlers"][0]["source"]["byte_offset"],
                inventory["selected_byte_offset"]
            );
            assert_eq!(workspace["sample_count"], 0);
            assert!(
                workspace["handlers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|h| h["state"] != "observed")
            );
            assert_schema(&document);
        }
    }

    #[test]
    fn wasm_nested_small_table_loses_to_larger_in_loop_table() {
        // A deeper small table still has the structural signals. A later larger
        // table has fewer signals and a shallower loop. Arm scale selects the
        // larger table. No guest opcode is observed.
        let mut helper = ranked_dispatch_body(16, true);
        helper.splice(3..3, [0x03, 0x40]);
        helper.insert(helper.len() - 1, 0x0b);
        let large = ranked_dispatch_body(200, false);
        let bytes = wasm_module(&[&helper, &large], None);
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
        assert_eq!(analysis["results"][0]["tier"], "candidate");
        let inventory = &document["workspaces"][0]["dispatch_inventory"];
        assert_eq!(inventory["candidates"][0]["function_index"], 1);
        assert_eq!(inventory["candidates"][0]["arm_count"], 200);
        assert_eq!(inventory["candidates"][0]["unique_target_count"], 1);
        assert!(inventory["candidates"][0]["element_fanout"].is_null());
        assert_eq!(
            inventory["candidates"][0]["classification"],
            "dispatch-candidate"
        );
        assert_eq!(inventory["candidates"][1]["arm_count"], 16);
        assert_eq!(inventory["candidates"][1]["unique_target_count"], 1);
        assert!(inventory["candidates"][1]["element_fanout"].is_null());
        assert_eq!(
            inventory["candidates"][1]["classification"],
            "cff-helper-candidate"
        );
        assert!(
            inventory["candidates"][1]["loop_depth"].as_u64().unwrap()
                > inventory["candidates"][0]["loop_depth"].as_u64().unwrap()
        );
        let handlers = document["workspaces"][0]["handlers"].as_array().unwrap();
        assert_eq!(handlers.len(), 201);
        assert_eq!(
            handlers[0]["source"]["byte_offset"],
            inventory["selected_byte_offset"]
        );
        assert!(
            handlers
                .iter()
                .all(|handler| handler["state"] != "observed")
        );
        assert_eq!(document["workspaces"][0]["sample_count"], 0);
        assert_schema(&document);
    }

    #[test]
    fn wasm_indirect_element_fanout_ranks_without_inventing_arm_count() {
        let helper = ranked_dispatch_body(8, true);
        let indirect = vec![0x00, 0x03, 0x40, 0x41, 0x00, 0x11, 0x00, 0x00, 0x0b, 0x0b];
        let large = ranked_dispatch_body(200, false);
        let mut owned = vec![helper, indirect];
        owned.extend(std::iter::repeat_n(vec![0x00, 0x0b], 38));
        owned.push(large);
        let bodies = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let element = (0..40).collect::<Vec<_>>();
        let bytes = wasm_module(&bodies, Some(&element));
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
        assert_eq!(analysis["results"][0]["tier"], "candidate");
        let inventory = &document["workspaces"][0]["dispatch_inventory"];
        let sites = inventory["candidates"].as_array().unwrap();
        assert_eq!(sites.len(), 3);
        assert_eq!(sites[0]["function_index"], 40);
        assert_eq!(sites[0]["arm_count"], 200);
        assert_eq!(sites[0]["unique_target_count"], 1);
        assert!(sites[0]["element_fanout"].is_null());
        assert_eq!(sites[0]["classification"], "dispatch-candidate");
        assert_eq!(sites[1]["kind"], "call_indirect");
        assert!(sites[1]["arm_count"].is_null());
        assert!(sites[1]["unique_target_count"].is_null());
        assert_eq!(sites[1]["element_fanout"], 40);
        assert_eq!(sites[1]["loop_depth"], 1);
        assert_eq!(sites[1]["classification"], "indirect-handler-candidate");
        assert_eq!(sites[2]["arm_count"], 8);
        assert_eq!(sites[2]["unique_target_count"], 1);
        assert!(sites[2]["element_fanout"].is_null());
        assert_eq!(sites[2]["classification"], "cff-helper-candidate");
        assert_eq!(inventory["selected_byte_offset"], sites[0]["byte_offset"]);
        let handlers = document["workspaces"][0]["handlers"].as_array().unwrap();
        assert_eq!(handlers.len(), 201);
        assert!(handlers.iter().all(|handler| {
            handler["notes"].as_str().unwrap().contains("unproven")
                && handler["state"] != "observed"
                && handler["sample_count"] == 0
        }));
        assert_eq!(document["workspaces"][0]["sample_count"], 0);
        assert_schema(&document);
    }

    #[test]
    fn wasm_repeated_branch_targets_cluster_without_collapsing_arms() {
        // loop { block { block { br_table [0, 1, 0, 1] default 0 } } }
        let body = [
            0x00, 0x03, 0x40, 0x02, 0x40, 0x02, 0x40, 0x41, 0x00, 0x0e, 0x04, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let bytes = wasm_module(&[&body], None);
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
        let inventory = &document["workspaces"][0]["dispatch_inventory"];
        let site = &inventory["candidates"][0];
        assert_eq!(site["kind"], "br_table");
        assert_eq!(site["arm_count"], 4);
        assert_eq!(site["unique_target_count"], 2);
        assert!(site["element_fanout"].is_null());
        assert_eq!(site["classification"], "cff-helper-candidate");
        assert_eq!(site["loop_depth"], 1);
        let handlers = document["workspaces"][0]["handlers"].as_array().unwrap();
        assert_eq!(handlers.len(), 5);
        let depths = handlers
            .iter()
            .map(|handler| handler["notes"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(depths.iter().any(|note| note.contains("label depth 0")));
        assert!(depths.iter().any(|note| note.contains("label depth 1")));
        assert!(depths.iter().all(|note| note.contains("unproven")));
        assert_eq!(document["workspaces"][0]["sample_count"], 0);
        assert_schema(&document);
    }

    #[test]
    fn wasm_ranking_uses_ip_patterns_loop_depth_body_size_and_stable_offsets() {
        let plain = ranked_dispatch_body(200, false);
        let signaled = ranked_dispatch_body(200, true);
        let mut larger = signaled.clone();
        larger.splice(
            larger.len() - 1..larger.len() - 1,
            std::iter::repeat_n(0x01, 500),
        );
        let mut nested = signaled.clone();
        nested.splice(3..3, [0x03, 0x40]);
        nested.insert(nested.len() - 1, 0x0b);
        for (left, right, selected) in [
            (&plain, &signaled, 1),
            (&signaled, &larger, 1),
            (&larger, &nested, 1),
            (&signaled, &signaled, 0),
        ] {
            let bytes = wasm_module(&[left, right], None);
            wasmparser::Validator::new().validate_all(&bytes).unwrap();
            let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
            assert_eq!(
                document["workspaces"][0]["dispatch_inventory"]["candidates"][0]["function_index"],
                selected
            );
            for (name, value) in [("VmAnalysis", &analysis), ("VmOpcodeWorkspace", &document)] {
                let spec: Value =
                    serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap();
                let schema = json!({"$ref":format!("#/components/schemas/{name}"),"components":spec["components"]});
                jsonschema::validator_for(&schema)
                    .unwrap()
                    .validate(value)
                    .unwrap();
            }
            assert_schema(&document);
        }
    }

    #[test]
    fn wasm_ranking_is_site_local_and_decodes_past_arm_retention_limit() {
        for (small, large) in [(8, 200), (2048, 4096)] {
            let mut body = ranked_dispatch_body(small, true);
            body.pop();
            body.extend([0x03, 0x40, 0x41, 0x00]);
            body.extend(br_table(large));
            body.extend([0x0b, 0x0b]);
            let bytes = wasm_module(&[&body], None);
            wasmparser::Validator::new().validate_all(&bytes).unwrap();
            let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
            let workspace = &document["workspaces"][0];
            let inventory = &workspace["dispatch_inventory"];
            assert_eq!(inventory["site_count"], 2);
            assert_eq!(inventory["candidates"][0]["arm_count"], large);
            assert_eq!(
                workspace["handlers"][0]["source"]["byte_offset"],
                inventory["selected_byte_offset"]
            );
            assert_eq!(
                workspace["handlers"].as_array().unwrap().len(),
                ((small + large + 2) as usize).min(MAX_HANDLERS)
            );
            assert_schema(&document);
        }
    }

    #[test]
    fn wasm_large_site_stress_keeps_selected_after_metadata_cap() {
        // 128 large tables previously retained 128 * 1024 Arm objects before
        // imposing the output cap. The lazy emitter constructs at most 1024.
        // The second case also puts the selected instruction past the site cap.
        for (sites, arms) in [(128, 2048), (1100, 1)] {
            let mut body = ranked_dispatch_body(arms, true);
            body.pop();
            for _ in 1..sites {
                body.extend([0x03, 0x40, 0x41, 0x00]);
                body.extend(br_table(arms));
                body.push(0x0b);
            }
            body.extend([0x03, 0x40, 0x41, 0x00]);
            body.extend(br_table(4096));
            body.extend([0x0b, 0x0b]);
            let bytes = wasm_module(&[&body], None);
            wasmparser::Validator::new().validate_all(&bytes).unwrap();
            let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
            let workspace = &document["workspaces"][0];
            assert_eq!(workspace["dispatch_inventory"]["site_count"], sites + 1);
            assert_eq!(
                workspace["dispatch_inventory"]["candidates"][0]["arm_count"],
                4096
            );
            assert_eq!(
                workspace["handlers"].as_array().unwrap().len(),
                MAX_HANDLERS
            );
            assert_eq!(
                workspace["handlers"][0]["source"]["byte_offset"],
                workspace["dispatch_inventory"]["selected_byte_offset"]
            );
            let omissions = workspace["coverage"]["omissions"].as_array().unwrap();
            assert!(omissions.iter().any(|o| o["reason"] == "handler-limit"));
            assert_eq!(
                omissions
                    .iter()
                    .any(|o| o["reason"] == "dispatch-site-limit"),
                sites > 1024
            );
            assert_schema(&document);
        }
    }

    #[test]
    fn wasm_inventory_includes_nonloop_and_indirect_sites_without_claiming_targets() {
        let selected = ranked_dispatch_body(8, true);
        let mut nonloop = vec![0x00, 0x02, 0x40, 0x41, 0x00];
        nonloop.extend(br_table(700));
        nonloop.extend([0x0b, 0x41, 0x00, 0x11, 0x00, 0x00, 0x0b]);
        let bytes = wasm_module(&[&selected, &nonloop], Some(&[0]));
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
        let inventory = &document["workspaces"][0]["dispatch_inventory"];
        assert_eq!(inventory["site_count"], 3);
        assert_eq!(inventory["br_table_count"], 2);
        assert_eq!(inventory["call_indirect_count"], 1);
        assert_eq!(inventory["candidates"][0]["function_index"], 0);
        let indirect = inventory["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|site| site["kind"] == "call_indirect")
            .unwrap();
        assert!(indirect["arm_count"].is_null());
        assert!(indirect["unique_target_count"].is_null());
        assert_eq!(indirect["element_fanout"], 1);
        assert_eq!(indirect["classification"], "indirect-handler-candidate");
        assert_eq!(indirect["loop_depth"], 0);
        let large = inventory["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|site| site["arm_count"] == 700)
            .unwrap();
        assert_eq!(large["unique_target_count"], 1);
        assert!(large["element_fanout"].is_null());
        assert_eq!(large["classification"], "dispatch-candidate");
        assert_eq!(large["loop_depth"], 0);
        assert_schema(&document);
    }

    #[test]
    fn wasm_inventory_counts_all_sites_but_bounds_ranked_metadata() {
        let body = ranked_dispatch_body(8, true);
        let bytes = wasm_module(&vec![body.as_slice(); 300], None);
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
        let inventory = &document["workspaces"][0]["dispatch_inventory"];
        assert_eq!(inventory["site_count"], 300);
        assert_eq!(inventory["candidates"].as_array().unwrap().len(), 256);
        assert_eq!(inventory["omitted_site_count"], 44);
        assert_eq!(inventory["candidates"][0]["function_index"], 0);
        assert_eq!(analysis["results"][0]["coverage"]["complete"], false);
        assert!(
            document["workspaces"][0]["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["reason"] == "dispatch-inventory-limit")
        );
        assert_schema(&document);
    }

    #[test]
    fn wasm_related_br_tables_join_the_workspace_and_unrelated_ones_stay_out() {
        // f0 is the ranked interpreter: loop, advancing local, memory read, call.
        let selected = [
            0x01, 0x01, 0x7f, 0x03, 0x40, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x21, 0x00, 0x41, 0x00,
            0x2d, 0x00, 0x00, 0x1a, 0x10, 0x01, 0x41, 0x00,
        ]
        .into_iter()
        .chain(br_table(2))
        .chain([0x0b, 0x0b])
        .collect::<Vec<_>>();
        // f1 has no dispatch site. It only reaches f2.
        let wrapper = vec![0x00, 0x10, 0x02, 0x0b];
        let related = [0x00, 0x03, 0x40, 0x41, 0x00]
            .into_iter()
            .chain(br_table(4))
            .chain([0x0b, 0x0b])
            .collect::<Vec<_>>();
        let unrelated = [0x00, 0x03, 0x40, 0x41, 0x00]
            .into_iter()
            .chain(br_table(2))
            .chain([0x0b, 0x0b])
            .collect::<Vec<_>>();
        let bytes = wasm_module(&[&selected, &wrapper, &related, &unrelated], None);
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
        assert_eq!(analysis["results"][0]["tier"], "likely-vm");
        let workspace = &document["workspaces"][0];
        let handlers = workspace["handlers"].as_array().unwrap();
        assert_eq!(handlers.len(), 8);
        let sources = handlers
            .iter()
            .map(|handler| {
                (
                    handler["source"]["byte_offset"].as_u64().unwrap(),
                    handler["source"]["byte_size"].as_u64().unwrap(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(sources.len(), 2);
        for (offset, _) in &sources {
            assert_eq!(bytes[*offset as usize], 0x0e);
        }
        assert!(
            handlers
                .iter()
                .filter(|handler| handler["label"]
                    .as_str()
                    .unwrap()
                    .starts_with("br_table selector"))
                .count()
                >= 2
        );
        assert!(
            handlers
                .iter()
                .any(|handler| handler["label"] == "br_table f2 selector 0")
        );
        assert!(
            handlers
                .iter()
                .any(|handler| handler["label"] == "br_table f2 selector 3")
        );
        assert!(handlers.iter().all(|handler| {
            handler["notes"].as_str().unwrap().contains("unproven")
                && handler["state"] != "observed"
                && handler["sample_count"] == 0
                && handler["effects"] == json!([])
        }));
        assert!(
            handlers
                .iter()
                .any(|handler| handler["opcode"].is_null() && handler["state"] == "unknown")
        );
        let preview = &workspace["captured_module_preview"];
        let related_source = handlers
            .iter()
            .find(|handler| handler["label"] == "br_table f2 selector 0")
            .unwrap()["source"]
            .clone();
        assert_eq!(preview["artifact_id"], workspace["interpreter_artifact_id"]);
        assert_eq!(preview["byte_offset"], related_source["byte_offset"]);
        assert_eq!(preview["byte_count"], related_source["byte_size"]);
        assert!(preview.get("origin").is_none());
        assert!(preview.get("sha256").is_none());
        let start = preview["byte_offset"].as_u64().unwrap() as usize;
        let size = preview["byte_count"].as_u64().unwrap() as usize;
        assert_eq!(
            preview["preview_hex"],
            hex::encode(&bytes[start..start + size])
        );
        assert_eq!(preview["truncated"], false);
        assert_eq!(workspace["snapshots"], json!([]));
        assert_eq!(workspace["coverage"]["characterized_bytes"], 0);
        assert_eq!(workspace["coverage"]["retained_snapshot_bytes"], 0);
        assert_eq!(workspace["sample_count"], 0);
        assert!(workspace.get("bytecode_artifact_id").is_none());
        let reasons = workspace["coverage"]["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|omission| omission["reason"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(reasons.contains(&"sampler-unavailable"));
        assert!(reasons.contains(&"runtime-snapshot-unavailable"));
        assert!(reasons.contains(&"snapshot-bytes-unavailable"));
        assert!(reasons.contains(&"static-module-dispatch"));
        assert!(reasons.contains(&"dispatch-neighborhood"));
        assert!(!reasons.contains(&"reachable-frontier"));
        assert_eq!(
            workspace["traversal"]["frontier"][0]["reason"],
            "static-module-only"
        );
        assert!(workspace["traversal"]["frontier"][0]["byte_offset"].is_null());
        let static_walk = workspace["coverage"]["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|omission| omission["reason"] == "static-module-dispatch")
            .unwrap();
        assert_eq!(
            static_walk["detail"],
            "Static module walk kept 2 dispatch sites across 2 functions. Guest-byte traversal has no runtime snapshot and does not infer a guest PC."
        );
        let neighborhood = workspace["coverage"]["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|omission| omission["reason"] == "dispatch-neighborhood")
            .unwrap();
        assert!(
            neighborhood["detail"]
                .as_str()
                .unwrap()
                .starts_with("1 in-loop")
        );
        assert!(neighborhood["detail"].as_str().unwrap().len() <= 240);
        assert_schema(&document);
    }

    /// Element slots are real table indexes: a segment at offset 1 starts at
    /// slot 1, a second segment at offset 5 starts at slot 5, and the empty
    /// slots in between are not renumbered.
    #[test]
    fn wasm_element_tables_keep_real_slot_indexes_across_offset_segments() {
        let bytes = include_bytes!(
            "../../../tools/fixtures/dispatch-shapes/handler-table-interpreter.wasm"
        );
        let (_, _, document) = analyze_artifact(bytes, "wasm", &[]);
        let workspace = &document["workspaces"][0];
        let element = workspace["handler_tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["kind"] == "element")
            .unwrap();
        assert_eq!(element["table_index"], 0);
        assert_eq!(element["entry_count"], 5);
        let slots = element["clusters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|cluster| {
                (
                    cluster["target"].as_u64().unwrap(),
                    cluster["selectors"].clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            slots,
            [
                (0, json!([1])),
                (1, json!([2])),
                (2, json!([3])),
                (3, json!([5])),
                (4, json!([6])),
            ]
        );
        assert_eq!(
            element["segments"],
            json!([
                {"segment_index":0,"placement":"placed","offset":1,"global_index":null,"entry_count":3},
                {"segment_index":1,"placement":"placed","offset":5,"global_index":null,"entry_count":2},
            ])
        );
        assert_schema(&document);
    }

    #[test]
    fn wasm_call_indirect_table_functions_contribute_br_tables() {
        let selected = [
            0x01, 0x01, 0x7f, 0x03, 0x40, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x21, 0x00, 0x41, 0x00,
            0x2d, 0x00, 0x00, 0x1a, 0x41, 0x00, 0x11, 0x00, 0x00, 0x0b, 0x0b,
        ];
        let related = [0x00, 0x03, 0x40, 0x41, 0x00]
            .into_iter()
            .chain(br_table(3))
            .chain([0x0b, 0x0b])
            .collect::<Vec<_>>();
        let unrelated = [0x00, 0x03, 0x40, 0x41, 0x00]
            .into_iter()
            .chain(br_table(2))
            .chain([0x0b, 0x0b])
            .collect::<Vec<_>>();
        let bytes = wasm_module(&[&selected, &related, &unrelated], Some(&[1]));
        wasmparser::Validator::new().validate_all(&bytes).unwrap();
        let (_, analysis, document) = analyze_artifact(&bytes, "wasm", &[]);
        assert_eq!(analysis["results"][0]["tier"], "likely-vm");
        let workspace = &document["workspaces"][0];
        let handlers = workspace["handlers"].as_array().unwrap();
        assert!(
            handlers
                .iter()
                .any(|handler| handler["label"] == "call_indirect target"
                    && handler["opcode"].is_null()
                    && handler["state"] == "unknown")
        );
        assert!(
            handlers
                .iter()
                .any(|handler| handler["label"] == "br_table f1 selector 0"
                    && handler["state"] == "inferred"
                    && handler["opcode"] == 0)
        );
        assert!(
            handlers
                .iter()
                .any(|handler| handler["label"] == "br_table f1 selector 2")
        );
        assert!(
            !handlers
                .iter()
                .any(|handler| handler["label"].as_str().unwrap().contains("f2"))
        );
        let cited = handlers
            .iter()
            .map(|handler| handler["source"]["byte_offset"].as_u64().unwrap() as usize)
            .collect::<BTreeSet<_>>();
        assert!(
            cited
                .iter()
                .all(|offset| bytes[*offset] == 0x0e || bytes[*offset] == 0x11)
        );
        assert_eq!(workspace["coverage"]["characterized_bytes"], 0);
        assert_eq!(workspace["sample_count"], 0);
        assert_eq!(
            workspace["traversal"]["frontier"][0]["reason"],
            "static-module-only"
        );
        assert_schema(&document);
    }

    #[test]
    fn repeated_wasm_selectors_do_not_absorb_one_dispatch_sample() {
        let bytes = wasm_fixture("two_br_tables");
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[event(0)]);
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["sample_count"], 1);
        assert_eq!(workspace["samples"][0]["opcode"], 0);
        assert_ne!(workspace["evidence_class"], "guest-opcode-isa");
        assert!(
            workspace["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|handler| { handler["state"] != "observed" && handler["sample_count"] == 0 })
        );
        assert!(
            workspace["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown
                    .as_str()
                    .unwrap()
                    .contains("more than one static dispatch site"))
        );
        assert!(
            workspace["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|omission| omission["reason"] != "sampler-unavailable")
        );
        assert_eq!(workspace["coverage"]["characterized_bytes"], 0);
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
            let workspace = &document["workspaces"][0];
            assert_eq!(workspace["evidence_class"], "guest-opcode-isa");
            if workspace["model"] == "stack" {
                assert_eq!(workspace["machine_state"]["stack_observed"], true);
            }
            if let Some(state) = workspace.get("machine_state") {
                assert!(state["register_count"].as_u64().unwrap_or(0) <= 65536);
            }
            assert_schema(&document);
            let (_, _, altered) = analyze(&format!("{source}\n"), &[event(1)]);
            assert!(
                altered["workspaces"][0]["handlers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| row["effects"] == json!([]))
            );
            assert_eq!(
                altered["workspaces"][0]["evidence_class"],
                "handler-table-candidate"
            );
            assert!(altered["workspaces"][0].get("machine_state").is_none());
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
            snapshots(&fixture_root, interpreter, std::slice::from_ref(snapshot))
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
                .starts_with("No native dispatch samples were retained. Rebuild with native guest capture, enable an exact matching adapter,")
        );
        let detail = omission["detail"].as_str().unwrap();
        assert!(detail.contains("inspect capture omissions"));
        assert!(!detail.contains("no guest dispatch emitter"));
        assert!(detail.len() <= 240);
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
        let (handlers, _, unknowns, _) = classified_handlers(source, 0, source.len());
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
        let (handlers, model, _, _) = classified_handlers(source, 0, source.len());
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
        let (handlers, _, _, _) = classified_handlers(source, start, source.len());
        assert_eq!(handlers.len(), 1);
        let handler = &handlers[0];
        let offset = handler["source"]["byte_offset"].as_u64().unwrap() as usize;
        let size = handler["source"]["byte_size"].as_u64().unwrap() as usize;
        assert_eq!(
            &source[offset..offset + size],
            "handlers[7]=function(){function helper(){return 5;}stack.push(program[pc++]);}"
        );
        assert_eq!(handler["operand_width"], 1);

        let source = "while(pc<program.length){switch(program[pc++]){case 1: switch(state){case 99: break;} break; case 2: return; default: throw 0;}}";
        let (handlers, _, _, _) = classified_handlers(source, 0, source.len());
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
            // Operand widths are read only for tables an interpreter loop uses.
            let source = format!(
                "handlers[1]=function(){{{body}}};while(pc<program.length){{handlers[program[pc++]]();}}"
            );
            let (handlers, _, _, _) = classified_handlers(&source, 0, source.len());
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
                let (handlers, _, unknowns, _) = classified_handlers(&source, 0, source.len());
                // A literal table that no interpreter-candidate dispatch uses
                // supplies no opcodes, whatever the switch beside it does.
                assert!(handlers.is_empty(), "{source}");
                assert!(
                    unknowns
                        .iter()
                        .any(|s| s.contains("no proven fixed opcode mapping"))
                );
            }
        }
        let source = "let opcode=program[pc++]; opcode ^= saved; switch(opcode){case 9:break;}";
        assert!(classified_handlers(source, 0, source.len()).0.is_empty());
        let source = "while(pc<program.length){const opcode=program[pc++];const alias=opcode;switch(alias){case 9:break;}}";
        assert_eq!(
            classified_handlers(source, 0, source.len()).0[0]["opcode"],
            9
        );
    }

    fn review_fixture(name: &str) -> String {
        fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/fixtures/dispatch-review")
                .join(name),
        )
        .expect("review fixture")
    }

    /// Every owned input the differential invariant covers: repository
    /// fixtures, dispatch-shape fixtures, review repro copies and generated
    /// review inputs, as (name, bytes, kind).
    fn differential_inputs() -> Vec<(String, Vec<u8>, &'static str)> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut inputs = Vec::new();
        for directory in [
            "tools/fixtures/dispatch-shapes",
            "tools/fixtures/dispatch-review",
            "tools/fixtures/vm-dynamic-debug",
            "tools/fixtures/vm-dynamic-debug/xor-decoded",
            "tools/fixtures/vm-workspace-effects",
            "tools/fixtures/native-vm-dispatch",
            "tools/fixtures/vm-analysis-packs",
            "apps/runtime-hook-demo",
            "apps/runtime-hook-demo/ghostwire-worker",
        ] {
            let mut paths = fs::read_dir(root.join(directory))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            paths.sort();
            for path in paths {
                let kind = match path.extension().and_then(|ext| ext.to_str()) {
                    Some("js" | "mjs") => "javascript",
                    Some("wasm") => "wasm",
                    _ => continue,
                };
                inputs.push((
                    path.strip_prefix(&root).unwrap().display().to_string(),
                    fs::read(&path).unwrap(),
                    kind,
                ));
            }
        }
        for name in ["wasm-dispatch.json", "wasm-ranked-dispatch.json"] {
            let modules: Value = serde_json::from_str(
                &fs::read_to_string(root.join("tools/fixtures/vm-dynamic-debug").join(name))
                    .unwrap(),
            )
            .unwrap();
            for (key, value) in modules.as_object().unwrap() {
                if let Some(hex) = value.as_str()
                    && let Ok(bytes) = hex::decode(hex)
                {
                    inputs.push((format!("{name}#{key}"), bytes, "wasm"));
                }
            }
        }
        for (name, source) in vm::review_inputs::javascript() {
            inputs.push((format!("review:{name}"), source.into_bytes(), "javascript"));
        }
        for (name, bytes) in vm::review_inputs::wasm() {
            inputs.push((format!("review:{name}"), bytes, "wasm"));
        }
        inputs
    }

    fn tier_and_score(bytes: &[u8], kind: &str, gate: bool) -> (Value, Value) {
        GATE_DISABLED.with(|disabled| disabled.set(!gate));
        let (_, analysis, _) = analyze_artifact(bytes, kind, &[]);
        GATE_DISABLED.with(|disabled| disabled.set(false));
        let result = &analysis["results"][0];
        (result["tier"].clone(), result["vm_score"].clone())
    }

    /// Differential invariant: on every owned input, tier and score with the
    /// opcode-claim gate equal those of the unchanged base recovery path,
    /// which is the same pipeline with the gate off.
    #[test]
    fn classification_never_changes_tier_or_score_on_any_owned_input() {
        let inputs = differential_inputs();
        assert!(inputs.len() >= 90, "{} differential inputs", inputs.len());
        let mut differences = Vec::new();
        for (name, bytes, kind) in &inputs {
            let gated = tier_and_score(bytes, kind, true);
            let base = tier_and_score(bytes, kind, false);
            if gated != base {
                differences.push(format!("{name}: gated {gated:?}, base {base:?}"));
            }
        }
        assert!(differences.is_empty(), "{}", differences.join("\n"));
    }

    /// Second review, blockers: tier and score are the unchanged base
    /// recovery's. A table dispatched in a nested function keeps base's
    /// likely-vm, and a loop dispatch beside a router stays a candidate.
    #[test]
    fn nested_and_loop_body_dispatch_keep_base_tiers() {
        let (_, analysis, _) = analyze(&review_fixture("t1_nested_ops.js"), &[]);
        assert_eq!(analysis["results"][0]["tier"], "likely-vm");
        assert_eq!(analysis["results"][0]["vm_score"], 65);
        let (_, analysis, _) = analyze(&review_fixture("v2e_loopbody.js"), &[]);
        assert_eq!(analysis["results"][0]["tier"], "candidate");
        assert_eq!(analysis["results"][0]["vm_score"], 80);
    }

    fn handler_opcodes(document: &Value) -> Vec<u64> {
        document["workspaces"][0]["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|handler| handler["opcode"].as_u64())
            .collect()
    }

    /// Second review: the gate reads the full classification, not the 256
    /// listed sites, and an interpreter region is never starved of budget
    /// by larger noise regions.
    #[test]
    fn listing_and_budget_never_starve_the_interpreter() {
        for name in ["s2_listing", "s1b_budget"] {
            let (_, analysis, document) = analyze(&vm::review_inputs::javascript_named(name), &[]);
            assert_eq!(analysis["results"][0]["tier"], "likely-vm", "{name}");
            assert_eq!(handler_opcodes(&document), [1, 2, 3], "{name}");
            assert!(
                !document["workspaces"][0]["unknowns"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|unknown| unknown
                        .as_str()
                        .unwrap()
                        .contains("not a cursor-advancing loop")),
                "{name}"
            );
        }
    }

    /// Second review: an element table lists at most 64 segments and counts
    /// the rest.
    #[test]
    fn element_segments_past_the_listing_bound_are_counted() {
        let elems = (0..70)
            .map(|i| format!("(elem (i32.const {i}) func $h)"))
            .collect::<String>();
        let bytes = wat::parse_str(format!(
            r#"(module (memory 1)
              (type $t (func (param i32) (result i32)))
              (table 80 funcref)
              (func $h (type $t) (local.get 0))
              {elems}
              (func (export "run") (param $code i32) (param $len i32) (result i32)
                (local $pc i32) (local $acc i32)
                (block $exit (loop $again
                  (br_if $exit (i32.ge_u (local.get $pc) (local.get $len)))
                  (local.set $acc (call_indirect (type $t) (local.get $acc)
                    (i32.load8_u (i32.add (local.get $code) (local.get $pc)))))
                  (local.set $pc (i32.add (local.get $pc) (i32.const 1)))
                  (br $again)))
                (local.get $acc)))"#
        ))
        .unwrap();
        let (_, _, document) = analyze_artifact(&bytes, "wasm", &[]);
        let element = document["workspaces"][0]["handler_tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["kind"] == "element")
            .unwrap()
            .clone();
        assert_eq!(element["segments"].as_array().unwrap().len(), 64);
        assert_eq!(element["omitted_segment_count"], 6);
    }

    /// Review regression: classification never changes a tier. Where the gate
    /// withholds recovered handlers, the tier stays and a distinct omission
    /// names the withholding; demotion still follows genuine recovery only.
    #[test]
    fn classification_never_changes_tier_and_names_withheld_handlers() {
        let statement_do = "function run(code, stack){var pc=0; do switch(code[pc++]){case 1: stack.push(code[pc++]); break; case 2: stack.pop(); break; case 3: return stack;} while(pc<code.length);}";
        let (_, analysis, document) = analyze(statement_do, &[]);
        assert_eq!(analysis["results"][0]["tier"], "likely-vm");
        assert_eq!(
            document["workspaces"][0]["handlers"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        // A helper-computed next pc is not an arithmetic cursor advance, so
        // the switch is not an interpreter candidate and opcodes are withheld.
        let helper_step = "function run(code, stack){var pc=0; while(pc<code.length){switch(code[pc]){case 1: stack.push(code[pc+1]); break; case 2: stack.pop(); break; case 3: return stack;} pc=next(code,pc);}}";
        let (_, analysis, document) = analyze(helper_step, &[]);
        let result = &analysis["results"][0];
        let workspace = &document["workspaces"][0];
        assert_eq!(result["tier"], "likely-vm", "{}", result["coverage"]);
        assert_eq!(workspace["handlers"], json!([]));
        let reasons = workspace["coverage"]["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|omission| omission["reason"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(reasons.contains(&"handler-withheld"), "{reasons:?}");
        assert!(!reasons.contains(&"handler-unavailable"), "{reasons:?}");
        assert!(
            !result["coverage"]["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "handler-unavailable")
        );
        assert_schema(&document);
    }

    /// Review regression: opcode handlers come only from a table or switch
    /// tied to a classified interpreter-candidate site. A `.call` dispatch, a
    /// temporary, a nested function or no dispatch at all yields none.
    #[test]
    fn opcode_handlers_require_a_classified_interpreter_table_or_switch() {
        for source in [
            "function route(k,code,stack){let pc=0;const handlers={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){}};while(pc<code.length){stack.push(code[pc++]);}switch(k){case 9:break;}return handlers[k].call(null,stack);}",
            "function route(k,x,stack){const handlers={1:function(){stack.push(x)},2:function(){stack.pop()},3:function(){stack.length=0}};for(const v of x){switch(v.kind){case 1:log(v);break;}}return handlers[k].call(null,x);}",
            "function route(k,x,stack){const handlers={1:function(){stack.push(x)},2:function(){stack.pop()},3:function(){stack.length=0}};for(const v of x){log(v);}return handlers[k](x);}",
            "function run(code,stack){let pc=0;const handlers={1:function(){stack.push(code[pc++])},2:function(){stack.pop()}};while(pc<code.length){const h=handlers[code[pc++]];h(stack);}}",
            "function run(code,stack){let pc=0;handlers[1]=function(){stack.push(code[pc++])};handlers[2]=function(){stack.pop()};while(pc<code.length){stack.push(code[pc++]);}}",
        ] {
            let start = source.find('{').unwrap() + 1;
            let end = source.rfind('}').unwrap();
            let (handlers, _, _, _) = classified_handlers(source, start, end);
            assert_eq!(handlers, Vec::<Value>::new(), "{source}");
        }
        let (_, analysis, document) = analyze(
            "function route(k,code,stack){let pc=0;const handlers={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){}};while(pc<code.length){stack.push(code[pc++]);}switch(k){case 9:break;}return handlers[k].call(null,stack);}",
            &[],
        );
        assert_eq!(
            analysis["results"][0]["frontend"]["dispatch_classification"]["role_counts"]["interpreter-candidate"],
            0
        );
        if let Some(workspace) = document["workspaces"].as_array().unwrap().first() {
            assert_eq!(workspace["handlers"], json!([]));
        }
        // The same table tied to a cursor-loop dispatch keeps its handlers,
        // including a dispatch loop in a nested function of the region.
        for source in [
            "function run(code,stack){let pc=0;const handlers={1:function(){stack.push(code[pc++])},2:function(){stack.pop()}};while(pc<code.length){handlers[code[pc++]](stack);}}",
            "function run(code,stack){let pc=0;const handlers={1:function(){stack.push(code[pc++])},2:function(){stack.pop()}};function inner(){while(pc<code.length){handlers[code[pc++]](stack);}}return inner;}",
        ] {
            let start = source.find('{').unwrap() + 1;
            let (handlers, _, _, _) = classified_handlers(source, start, source.len() - 1);
            assert_eq!(handlers.len(), 2, "{source}");
        }
    }

    /// Review regression: per-region truncation must rank interpreter
    /// candidates first and count every classified site.
    #[test]
    fn many_ordinary_calls_never_hide_an_interpreter_switch() {
        let calls = (0..300).map(|i| format!("t[n{i}](x);")).collect::<String>();
        let source = format!(
            "function run(code, stack, t, x){{var pc=0; {calls} while(pc<code.length){{switch(code[pc++]){{case 1: stack.push(code[pc++]); break; case 2: stack.pop(); break; case 3: return stack;}}}}}}"
        );
        let (_, analysis, document) = analyze(&source, &[]);
        let classification = &analysis["results"][0]["frontend"]["dispatch_classification"];
        assert_eq!(classification["site_count"], 301);
        assert_eq!(classification["omitted_site_count"], 301 - 256);
        assert_eq!(classification["role_counts"]["interpreter-candidate"], 1);
        assert!(
            classification["sites"]
                .as_array()
                .unwrap()
                .iter()
                .any(|site| site["instruction"] == "switch"
                    && site["role"] == "interpreter-candidate")
        );
        assert_eq!(analysis["results"][0]["tier"], "likely-vm");
        assert_eq!(
            document["workspaces"][0]["handlers"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    /// Review regression: classifier work is bounded per region and per
    /// artifact, and hitting the bound is a visible omission.
    #[test]
    fn javascript_classification_work_is_bounded_and_reported() {
        let body = (0..8000)
            .map(|i| format!("var v{i}=1;t[v{i}](x);"))
            .collect::<String>();
        let source = format!("function run(t,x){{{body}}}");
        let classification = vm::javascript_classification(&source);
        let omissions = classification["omissions"].as_array().expect("omissions");
        assert!(
            omissions
                .iter()
                .any(|omission| omission["reason"] == "classification-work-limit"),
            "{omissions:?}"
        );
        let unclassified = omissions
            .iter()
            .filter_map(|omission| omission["omitted_records"].as_u64())
            .sum::<u64>();
        assert_eq!(
            classification["site_count"].as_u64().unwrap() + unclassified,
            8000
        );
        // Work, not wall time: steps per classified site stay constant as the
        // region grows, so lookups are indexed rather than rescanned.
        let work = |count: usize| {
            let body = (0..count)
                .map(|i| format!("var v{i}=1;t[v{i}](x);"))
                .collect::<String>();
            let (document, steps) =
                vm::javascript_classification_work(&format!("function run(t,x){{{body}}}"));
            assert_eq!(document["site_count"], count);
            steps
        };
        let (small, large) = (work(1000), work(2000));
        assert!(small <= 16 * 1000, "{small} work units for 1000 sites");
        assert!(large <= 2 * small, "{small} then {large}");
        // All classifier work, including bracket pairing and buffer scans,
        // stays linear in the input: a doubled input at most doubles it.
        let total = |source: String| vm::javascript_classification_work(&source).1;
        // Definitions and sites grow together: per-site buffer scans would
        // make this quadratic.
        let bufkind = |size: usize| {
            total(format!(
                "function big(c,x){{var p=0;{}while(p<c.length){{{}}}}}",
                "c=x;".repeat(size),
                "switch(c[p++]){case 1:case 2:case 3:p+=1}".repeat(size / 4)
            ))
        };
        let pairs = |count: usize| {
            total(format!(
                "function big(s,x){{{}{}}}",
                "if(/\\(/.test(s))x++;".repeat(count),
                "if(/\\]/.test(s))x++;".repeat(count)
            ))
        };
        for (name, measure) in [
            ("pairing", &pairs as &dyn Fn(usize) -> u64),
            ("buffer_kind", &bufkind),
        ] {
            let (small, large) = (measure(2000), measure(4000));
            assert!(
                large <= small * 2 + small / 5,
                "{name}: {small} then {large} work units"
            );
        }
    }

    /// Case values become opcode handlers only at a cursor-loop interpreter
    /// candidate. A one-shot fetch and a router on an argument claim none.
    #[test]
    fn loopless_and_router_dispatch_claim_no_opcode_handlers() {
        let source = "switch(program[pc++]){case 1: stack.push(1); break; case 2: return;}";
        let (handlers, _, unknowns, _) = classified_handlers(source, 0, source.len());
        assert!(handlers.is_empty());
        assert!(
            unknowns
                .iter()
                .any(|s| s.contains("not a cursor-advancing loop"))
        );
        // Recovery itself finds nothing for a switch on an argument; the
        // classification names it a router.
        let source = "function route(k,x){switch(k){case 1: return a(x); case 2: return b(x); case 3: return c(x);}}";
        let start = source.find('{').unwrap() + 1;
        let (handlers, _, _, _) = classified_handlers(source, start, source.len() - 1);
        assert!(handlers.is_empty());
        assert_eq!(
            vm::javascript_classification(source)["role_counts"]["multiplexer"],
            1
        );
        let source = "while(pc<program.length){switch(program[pc++]){case 1: stack.push(1); break; case 2: return;}}";
        assert_eq!(classified_handlers(source, 0, source.len()).0.len(), 2);
    }

    #[test]
    fn computed_objects_and_expression_arrows_do_not_borrow_other_bodies() {
        let source = "const handlers={[key]:()=>{},7(){return program[pc++];},a8:()=>{},9:()=>{const nested={99:()=>{}};}};while(pc<program.length){handlers[program[pc++]]();}";
        let (handlers, _, unknowns, _) = classified_handlers(source, 0, source.len());
        assert_eq!(
            handlers
                .iter()
                .map(|h| h["opcode"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            [7, 9]
        );
        assert!(unknowns.iter().any(|s| s.contains("computed")));
        let source = "handlers[1]=x=>x,handlers[2]=()=>{};while(pc<program.length){handlers[program[pc++]]();}";
        let (handlers, _, _, _) = classified_handlers(source, 0, source.len());
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0]["opcode"], 2);
        // Without a dispatch that uses the table, it supplies no opcodes.
        let source = "handlers[1]=x=>x,handlers[2]=()=>{};";
        assert!(classified_handlers(source, 0, source.len()).0.is_empty());
    }

    #[test]
    fn handler_cap_preserves_named_omission() {
        let mut source = (0..1025)
            .map(|i| format!("handlers[{i}]=function(){{}};"))
            .collect::<String>();
        source.push_str("while(pc<program.length){handlers[program[pc++]]();}");
        let (handlers, _, _, omissions) = classified_handlers(&source, 0, source.len());
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
                classified_handlers(source, 0, source.len()).0.is_empty(),
                "{source}"
            );
        }
        let source = "while(pc<program.length){switch(program[pc++]){case 1: case 2: stack.push(program[pc++]);break;default:return;}}";
        let (handlers, _, _, _) = classified_handlers(source, 0, source.len());
        assert_eq!(handlers.len(), 2);
        for handler in handlers {
            let offset = handler["source"]["byte_offset"].as_u64().unwrap() as usize;
            let size = handler["source"]["byte_size"].as_u64().unwrap() as usize;
            assert!(source[offset..offset + size].contains("stack.push"));
            assert_eq!(handler["operand_width"], 1);
        }
    }
}
