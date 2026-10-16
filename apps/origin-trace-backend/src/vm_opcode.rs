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

const PRODUCER_VERSION: &str = "1.0.0";
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
        r"(?i)\b(?:handlers?|opcodes?)\s*\[\s*(0x[0-9a-f]+|\d+)\s*\]\s*=\s*(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)",
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
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\[(?:[^\[\]]+|\[[^\[\]]*\])+\]\s*\(")
        .expect("indexed dispatch")
});
static NUMERIC_OBJECT_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)(0x[0-9a-f]+|\d+)\s*:\s*(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")
        .expect("numeric object handler")
});
static NUMERIC_METHOD_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)(0x[0-9a-f]+|\d+)\s*\([^)]*\)\s*\{").expect("numeric object method")
});
static COMPUTED_OBJECT_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)\[[^\]]+\]\s*:\s*(?:function\b|\([^)]*\)\s*=>)")
        .expect("computed object handler")
});
static STACK_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bstack\b").expect("stack identifier"));
static REGISTER_IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:regs|registers?)\b").expect("register identifier"));
static STATEFUL_MAPPING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:stateful[\s_-]*opcode|position[\s_-]*dependent[\s_-]*mapping)\b")
        .expect("stateful mapping")
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

fn add_handler(
    handlers: &mut BTreeMap<u32, Value>,
    opcode: u32,
    handler_index: Option<u32>,
    offset: usize,
    size: usize,
    note: &str,
) -> bool {
    if handlers.len() >= MAX_HANDLERS && !handlers.contains_key(&opcode) {
        return false;
    }
    handlers.entry(opcode).or_insert_with(|| {
        let mut value = json!({
            "opcode": opcode,
            "state": "inferred",
            "source": {"byte_offset": offset, "byte_size": size.max(1)},
            "operand_width": 0,
            "sample_count": 0,
            "notes": note,
        });
        if let Some(index) = handler_index {
            value["handler_index"] = json!(index);
        }
        value
    });
    true
}

fn object_handlers(
    region: &str,
    base: usize,
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
        let assignment = Regex::new(&format!(r"\b{}\s*=\s*\{{", regex::escape(&name)))
            .expect("object assignment");
        for candidate in assignment.find_iter(region) {
            let opening = candidate.end() - 1;
            let Some(closing) = matching(region.as_bytes(), opening, b'{', b'}') else {
                continue;
            };
            let object = &region[opening + 1..closing];
            for pattern in [&*NUMERIC_OBJECT_ENTRY, &*NUMERIC_METHOD_ENTRY] {
                for captures in pattern.captures_iter(object) {
                    let Some(opcode) = integer(&captures[1]) else {
                        continue;
                    };
                    let matched = captures.get(0).expect("object handler match");
                    if !add_handler(
                        handlers,
                        opcode,
                        Some(opcode),
                        base + opening + 1 + matched.start(),
                        matched.len(),
                        "A numeric object-map handler is statically visible.",
                    ) {
                        *handler_limit_hit = true;
                    }
                }
            }
            if COMPUTED_OBJECT_ENTRY.is_match(object) {
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
    let region = without_nested_functions(&source[start..end]);
    let mut handlers = BTreeMap::new();
    let mut unknowns = Vec::new();
    let mut omissions = Vec::new();
    let mut handler_limit_hit = false;
    for switch_match in SWITCH.find_iter(&region) {
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
        let body = &region[opening_brace + 1..closing_brace];
        for captures in CASE.captures_iter(body) {
            let Some(opcode) = integer(&captures[1]) else {
                continue;
            };
            let matched = captures.get(0).expect("case match");
            if !add_handler(
                &mut handlers,
                opcode,
                None,
                start + opening_brace + 1 + matched.start(),
                matched.len(),
                "An integer switch case is statically visible in the dispatch region.",
            ) {
                handler_limit_hit = true;
            }
        }
    }
    for captures in INDEXED_HANDLER.captures_iter(&region) {
        let Some(opcode) = integer(&captures[1]) else {
            continue;
        };
        let matched = captures.get(0).expect("indexed handler match");
        if !add_handler(
            &mut handlers,
            opcode,
            Some(opcode),
            start + matched.start(),
            matched.len(),
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
    if STATEFUL_MAPPING.is_match(&region) {
        unknowns.push(
            "The source mentions a stateful opcode or position-dependent mapping; no fixed mapping is inferred."
                .into(),
        );
    }
    unknowns.sort();
    unknowns.dedup();
    (
        handlers.into_values().collect(),
        model.into(),
        unknowns,
        omissions,
    )
}

fn sample_opcode(event: &Value, artifact: &Value) -> Option<u32> {
    if event["category"] != "vm"
        || event["type"] != "vm_dispatch_sample"
        || event["artifact_id"] != artifact["artifact_id"]
    {
        return None;
    }
    let payload = hex::decode(event["payload"].as_str()?).ok()?;
    if payload.len() != 128 {
        return None;
    }
    let version = u16::from_le_bytes(payload[0..2].try_into().ok()?);
    let payload_size = u16::from_le_bytes(payload[2..4].try_into().ok()?);
    let reserved_alignment = u32::from_le_bytes(payload[20..24].try_into().ok()?);
    let finding_id = u64::from_le_bytes(payload[24..32].try_into().ok()?);
    let investigation_id = u64::from_le_bytes(payload[32..40].try_into().ok()?);
    let flags = payload[56];
    let reserved0 = u16::from_le_bytes(payload[58..60].try_into().ok()?);
    let reserved1 = u32::from_le_bytes(payload[60..64].try_into().ok()?);
    let reserved2 = u64::from_le_bytes(payload[64..72].try_into().ok()?);
    if version != 1
        || payload_size != 128
        || reserved_alignment != 0
        || finding_id == 0
        || investigation_id == 0
        || flags != 0
        || reserved0 != 0
        || reserved1 != 0
        || reserved2 != 0
        || payload[72..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    Some(u32::from_le_bytes(payload[8..12].try_into().ok()?))
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

pub(crate) fn workspace(
    root: &Path,
    artifact: &Value,
    source: &str,
    result: &Value,
    snapshot_artifacts: &[Value],
    events: &[Value],
) -> Option<Value> {
    if result["tier"] != "likely-vm" || result["runtime"] != "javascript" {
        return None;
    }
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
    if end > source.len() || !source.is_char_boundary(region.0) || !source.is_char_boundary(end) {
        return None;
    }
    let (mut handlers, model, mut unknowns, mut omissions) = static_handlers(source, region.0, end);
    if handlers.is_empty() {
        omissions.push(json!({"reason":"handler-unavailable","detail":"No static integer handler candidate was visible in the dispatch region."}));
    }
    let mut samples = BTreeMap::<u32, u64>::new();
    for event in events {
        if let Some(opcode) = sample_opcode(event, artifact) {
            *samples.entry(opcode).or_default() += 1;
        }
    }
    if samples.is_empty() {
        omissions.push(json!({"reason":"sampler-unavailable"}));
    }
    for handler in &mut handlers {
        let opcode = handler["opcode"].as_u64().expect("handler opcode") as u32;
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
    if snapshots.is_empty() {
        if let Some(snapshot) = result.get("bytecode_snapshot")
            && snapshot["snapshot_hex"].is_string()
        {
            omissions.push(json!({
                "reason": "static-initializer-only",
                "detail": "A bounded static initializer exists in vm-analysis-v1, but no runtime snapshot names this allocating script in the same session, navigation, and frame."
            }));
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
    let snapshot_bytes = snapshots
        .iter()
        .filter_map(|snapshot| snapshot["preview_hex"].as_str())
        .map(|preview| preview.len() / 2)
        .sum::<usize>();
    let complete = omissions.is_empty() && unknowns.is_empty();
    let mut workspace = json!({
        "interpreter_artifact_id": artifact["artifact_id"],
        "finding_id": result["finding_id"],
        "model": model,
        "handlers": handlers,
        "snapshots": snapshots,
        "coverage": {
            "complete": complete,
            "characterized_opcodes": handlers.len(),
            "snapshot_bytes": snapshot_bytes,
            "omissions": omissions,
        },
        "unknowns": unknowns,
    });
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
        .flat_map(|workspace| workspace["handlers"].as_array().into_iter().flatten())
        .filter_map(|handler| handler["sample_count"].as_u64())
        .sum::<u64>();
    let unknown_count = workspaces
        .iter()
        .map(|workspace| workspace["unknowns"].as_array().map_or(0, Vec::len))
        .sum::<usize>();
    let mut document = json!({
        "contract_version": 1,
        "document_kind": "vm-opcode-workspace",
        "producer": {"id":"origin-trace-vm-opcode","version":PRODUCER_VERSION},
        "profile_digest": analysis["profile_digest"],
        "analysis_digest": analysis["document_digest"],
        "inputs": analysis["inputs"],
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
        &root.join("analysis/vm-opcode-workspace-v1.json"),
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
        let root = tempfile::tempdir().expect("artifact store");
        fs::create_dir_all(root.path().join("blobs")).expect("blob directory");
        let hash = hex::encode(Sha256::digest(source.as_bytes()));
        fs::write(root.path().join(format!("blobs/{hash}.bin")), source).expect("source blob");
        let artifact = json!({
            "protocol_version":1,
            "artifact_id":"1",
            "session_id":"1",
            "navigation_id":"1",
            "frame_id":"1",
            "parent_artifact_id":"0",
            "creator_event_id":"0",
            "execution_context_id":"1",
            "capture_origin":"dynamic_javascript",
            "kind":"javascript",
            "url":"fixture://vm-dynamic-debug/source.js",
            "mime_type":"text/javascript",
            "byte_size":source.len(),
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
        let event_store = root.path().join("events.jsonl");
        let event_lines = events
            .iter()
            .map(|value| serde_json::to_string(value).expect("event record"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&event_store, event_lines).expect("event store");
        let analysis = crate::vm::store(root.path(), &event_store).expect("VM documents");
        let workspace: Value = serde_json::from_slice(
            &fs::read(root.path().join("analysis/vm-opcode-workspace-v1.json"))
                .expect("opcode workspace"),
        )
        .expect("workspace JSON");
        (root, analysis, workspace)
    }

    fn assert_schema(document: &Value) {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v1.schema.json"
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
        assert!(fixture("stack-vm.js")[start..start + size].starts_with("case 80:"));
        assert_schema(&stack);

        let (_, register_analysis, register) = analyze(&fixture("register-vm.js"), &[]);
        assert_eq!(register_analysis["summary"]["likely_vm_count"], 1);
        assert_eq!(register["workspaces"][0]["model"], "register");
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
            &fs::read(root.path().join("analysis/vm-opcode-workspace-v1.json"))
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
}
