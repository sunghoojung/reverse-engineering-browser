//! Explicit, local caller reports. This serializer is not a runtime sampler.
use crate::{
    durable,
    error::{Error, Result},
    evidence,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_SAMPLES: usize = 4096;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    contract_version: u32,
    source: String,
    interpreter_artifact_id: String,
    source_artifact_sha256: String,
    session_id: String,
    navigation_id: String,
    frame_id: String,
    finding_id: String,
    investigation_id: String,
    samples: Vec<Sample>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    instruction_pointer: u32,
    opcode: u32,
    handler_index: u32,
    sample_index: u32,
    operand_count: u8,
}

fn nonzero_id(value: &str) -> Result<u64> {
    if !evidence::canonical(&json!(value), 64, true) {
        return Err(Error::bad(
            "Caller sample identity must be a canonical nonzero uint64 string",
        ));
    }
    Ok(value.parse().expect("validated uint64"))
}

fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) fn provenance(value: &Value, artifact: &Value) -> bool {
    valid_provenance(value) && value["source_artifact_sha256"] == artifact["sha256"]
}
fn valid_provenance(value: &Value) -> bool {
    value.as_object().is_some_and(|object| object.len() == 3)
        && value["source"] == "caller-supplied"
        && digest(&value["source_artifact_sha256"])
        && digest(&value["input_sha256"])
}

/// Analysis-only namespace. Native VM event_reference continues
/// to reject process zero; no native parent can name these reports.
pub(crate) fn report_reference(event: &Value) -> Option<(String, u32, String)> {
    if event["type"] != "vm_dispatch_report"
        || event["category"] != "vm"
        || event["process_id"] != 0
        || event["parent_event_id"] != "0"
        || !valid_provenance(&event["dispatch_provenance"])
        || !["session_id", "sequence_number"]
            .iter()
            .all(|key| evidence::canonical(&event[key], 64, true))
    {
        return None;
    }
    Some((
        event["session_id"].as_str()?.into(),
        0,
        event["sequence_number"].as_str()?.into(),
    ))
}

/// Validate all input before atomically publishing a new private JSONL file.
/// No browser, live store, native event identity, or invocation is modified.
pub fn write(root: &Path, input: &Path, output: &Path) -> Result<usize> {
    let bytes = durable::read_private(input, MAX_INPUT_BYTES)?
        .ok_or_else(|| Error::bad("Caller sample input was not found"))?;
    let document: Input = serde_json::from_slice(&bytes).map_err(|_| {
        Error::bad("Invalid caller sample document; expected the closed v1 contract")
    })?;
    if document.contract_version != 1
        || document.source != "caller-supplied"
        || document.samples.is_empty()
        || document.samples.len() > MAX_SAMPLES
    {
        return Err(Error::bad(
            "Caller sample input requires v1, caller-supplied source, and 1..4096 samples",
        ));
    }
    let interpreter = nonzero_id(&document.interpreter_artifact_id)?;
    let finding = nonzero_id(&document.finding_id)?;
    let investigation = nonzero_id(&document.investigation_id)?;
    for value in [
        &document.session_id,
        &document.navigation_id,
        &document.frame_id,
    ] {
        nonzero_id(value)?;
    }
    let artifact = evidence::find_artifact_bounded(
        root,
        &document.interpreter_artifact_id,
        10000,
        64 * 1024 * 1024,
    )?;
    if artifact["kind"] != "wasm"
        || artifact["sha256"] != document.source_artifact_sha256
        || artifact["session_id"] != document.session_id
        || artifact["navigation_id"] != document.navigation_id
        || artifact["frame_id"] != document.frame_id
    {
        return Err(Error::bad(
            "Caller samples do not match the captured Wasm artifact digest and scope",
        ));
    }
    if artifact["byte_size"].as_u64().unwrap_or(u64::MAX) > MAX_ARTIFACT_BYTES {
        return Err(Error::bad(
            "Caller sample artifact exceeds the 64 MiB verification limit",
        ));
    }
    let header = evidence::verified_range(root, &artifact, 0, 8)?;
    if header != b"\0asm\x01\0\0\0" {
        return Err(Error::bad(
            "Caller sample artifact is not a version-1 Wasm module",
        ));
    }
    let mut previous = None;
    let mut encoded = Vec::new();
    let input_digest = Sha256::digest(&bytes);
    let sequence_base = u64::from_le_bytes(input_digest[..8].try_into().expect("digest prefix"))
        % (u64::MAX - MAX_SAMPLES as u64);
    let provenance = json!({"source":"caller-supplied", "source_artifact_sha256":document.source_artifact_sha256,
        "input_sha256":hex::encode(input_digest)});
    for (index, sample) in document.samples.iter().enumerate() {
        if previous.is_some_and(|previous| sample.sample_index <= previous) {
            return Err(Error::bad(
                "Caller sample indices must be strictly increasing",
            ));
        }
        previous = Some(sample.sample_index);
        // Preserve the fixed native payload layout, not native provenance.
        // Bytecode, parent, invocation and PC units are deliberately unknown.
        let mut payload = [0u8; 128];
        payload[..2].copy_from_slice(&1u16.to_le_bytes());
        payload[2..4].copy_from_slice(&128u16.to_le_bytes());
        for (offset, value) in [
            (4, sample.instruction_pointer),
            (8, sample.opcode),
            (12, sample.handler_index),
            (16, sample.sample_index),
        ] {
            payload[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(24, finding), (32, investigation), (40, interpreter)] {
            payload[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        payload[57] = sample.operand_count;
        let event = json!({"protocol_version":2, "session_id":document.session_id,
            "navigation_id":document.navigation_id, "frame_id":document.frame_id,
            "artifact_id":document.interpreter_artifact_id, "process_id":0,
            "thread_id":0, "sequence_number":(sequence_base + index as u64 + 1).to_string(), "parent_event_id":"0",
            "monotonic_time_ns":"0", "request_id":"0", "category":"vm", "type":"vm_dispatch_report",
            "payload_size":128, "payload_encoding":"hex", "payload":hex::encode(payload),
            "dispatch_provenance":provenance});
        serde_json::to_writer(&mut encoded, &event)?;
        encoded.push(b'\n');
    }
    durable::write_private_noclobber(output, &encoded)?;
    Ok(document.samples.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, Value) {
        let root = tempfile::tempdir().unwrap();
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../tools/fixtures/vm-dynamic-debug/wasm-dispatch.json"
        ))
        .unwrap();
        let bytes = hex::decode(fixtures["br_table"].as_str().unwrap()).unwrap();
        let digest = hex::encode(Sha256::digest(&bytes));
        fs::create_dir(root.path().join("blobs")).unwrap();
        fs::write(root.path().join(format!("blobs/{digest}.bin")), &bytes).unwrap();
        let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"2","navigation_id":"3","frame_id":"4",
            "parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"webassembly_compile",
            "kind":"wasm","mime_type":"application/wasm","url":"fixture://owned/dispatch.wasm","byte_size":bytes.len(),
            "sha256":digest,"sensitive":false,"content_path":format!("blobs/{digest}.bin")});
        fs::write(root.path().join("manifest.jsonl"), format!("{artifact}\n")).unwrap();
        let input = json!({"contract_version":1,"source":"caller-supplied","interpreter_artifact_id":"1",
            "source_artifact_sha256":digest,"session_id":"2","navigation_id":"3","frame_id":"4",
            "finding_id":"5","investigation_id":"6","samples":[{"instruction_pointer":123,"opcode":0,
            "handler_index":0,"sample_index":0,"operand_count":0}]});
        (root, input)
    }
    fn import(root: &Path, input: &Value) -> Result<usize> {
        fs::write(root.join("input.json"), serde_json::to_vec(input).unwrap()).unwrap();
        write(root, &root.join("input.json"), &root.join("reports.jsonl"))
    }
    fn reports(root: &Path) -> Vec<Value> {
        fs::read_to_string(root.join("reports.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn analyze(root: &Path, events: &[Value]) -> (Value, Value) {
        fs::write(
            root.join("analysis-input.jsonl"),
            events
                .iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let documents =
            crate::vm::store_documents(root, &root.join("analysis-input.jsonl")).unwrap();
        let workspace = documents.opcode_workspace.unwrap();
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&workspace)
            .unwrap();
        (workspace, documents.host_links.unwrap())
    }
    fn has_omission(document: &Value, reason: &str) -> bool {
        document["workspaces"][0]["coverage"]["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["reason"] == reason)
    }
    #[test]
    fn caller_reports_reach_workspace_without_native_proof_or_host_parentage() {
        let (root, input) = fixture();
        let (before, _) = analyze(root.path(), &[]);
        assert_eq!(before["workspaces"][0]["sample_count"], 0);
        assert!(has_omission(&before, "sampler-unavailable"));
        assert_eq!(import(root.path(), &input).unwrap(), 1);
        let mut events = reports(root.path());
        let payload = hex::decode(events[0]["payload"].as_str().unwrap()).unwrap();
        assert_eq!(payload.len(), 128);
        assert_eq!(u32::from_le_bytes(payload[4..8].try_into().unwrap()), 123);
        assert!(payload[48..57].iter().all(|byte| *byte == 0));
        let mut host = events[0].clone();
        host["type"] = json!("api_call");
        host["category"] = json!("runtime");
        host["sequence_number"] = json!("2");
        host["process_id"] = json!(7);
        host["parent_event_id"] = events[0]["sequence_number"].clone();
        events.push(host);
        let (document, links) = analyze(root.path(), &events);
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["sample_count"], 1);
        assert_eq!(
            workspace["samples"][0]["provenance"]["source"],
            "caller-supplied"
        );
        assert_eq!(
            workspace["samples"][0]["instruction_pointer_units"],
            "unknown"
        );
        assert!(workspace["samples"][0]["invocation_id"].is_null());
        assert!(
            workspace["handlers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|handler| handler["state"] != "observed")
        );
        assert!(has_omission(&document, "sampler-unavailable"));
        assert!(has_omission(&document, "caller-samples-unverified"));
        assert_eq!(
            links["workspaces"][0]["links"][0]["reason"],
            "dispatch-samples-unavailable"
        );
        assert!(links["workspaces"][0]["links"][0]["guest_position"].is_null());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.path().join("reports.jsonl"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let original = fs::read(root.path().join("reports.jsonl")).unwrap();
        assert!(import(root.path(), &input).is_err());
        assert_eq!(
            fs::read(root.path().join("reports.jsonl")).unwrap(),
            original
        );
    }
    #[test]
    fn malformed_or_mismatched_reports_never_publish_partial_output() {
        for (key, value) in [
            ("contract_version", json!(2)),
            ("source", json!("native")),
            ("interpreter_artifact_id", json!("01")),
            ("finding_id", json!("0")),
            ("investigation_id", json!("18446744073709551616")),
            ("source_artifact_sha256", json!("a".repeat(64))),
            ("session_id", json!("8")),
            ("navigation_id", json!("8")),
            ("frame_id", json!("8")),
            ("process_id", json!(7)),
            ("samples", json!([])),
        ] {
            let (root, mut input) = fixture();
            input[key] = value;
            assert!(import(root.path(), &input).is_err(), "{key}");
            assert!(!root.path().join("reports.jsonl").exists());
        }
        for (key, value) in [
            ("instruction_pointer", json!(4294967296u64)),
            ("opcode", json!(-1)),
            ("handler_index", json!(1.5)),
            ("operand_count", json!(256)),
            ("parent_event_id", json!("1")),
            ("instruction_pointer_units", json!("byte-offset")),
        ] {
            let (root, mut input) = fixture();
            input["samples"][0][key] = value;
            assert!(import(root.path(), &input).is_err(), "{key}");
            assert!(!root.path().join("reports.jsonl").exists());
        }
        let (root, mut input) = fixture();
        input["samples"] = json!([input["samples"][0].clone(), input["samples"][0].clone()]);
        assert!(import(root.path(), &input).is_err());
        assert!(!root.path().join("reports.jsonl").exists());
    }
    #[test]
    fn bounds_and_tampered_artifacts_fail_closed() {
        let (root, mut input) = fixture();
        input["samples"] = json!(vec![input["samples"][0].clone(); MAX_SAMPLES + 1]);
        assert!(import(root.path(), &input).is_err());
        fs::write(
            root.path().join("input.json"),
            vec![b' '; MAX_INPUT_BYTES + 1],
        )
        .unwrap();
        assert!(
            write(
                root.path(),
                &root.path().join("input.json"),
                &root.path().join("reports.jsonl")
            )
            .is_err()
        );
        let (root, input) = fixture();
        fs::write(
            root.path().join(format!(
                "blobs/{}.bin",
                input["source_artifact_sha256"].as_str().unwrap()
            )),
            b"tampered",
        )
        .unwrap();
        assert!(import(root.path(), &input).is_err());
        assert!(!root.path().join("reports.jsonl").exists());
    }
    #[test]
    fn unknown_provenance_and_mixed_samples_do_not_upgrade_caller_opcodes() {
        let (root, input) = fixture();
        import(root.path(), &input).unwrap();
        let events = reports(root.path());
        for bad in [
            Value::Null,
            json!({"source":"native"}),
            json!({"source":"caller-supplied", "input_sha256":"a".repeat(64), "source_artifact_sha256":"b".repeat(64)}),
        ] {
            let mut invalid = events[0].clone();
            invalid["dispatch_provenance"] = bad;
            let (document, _) = analyze(root.path(), &[invalid]);
            assert_eq!(document["workspaces"][0]["sample_count"], 0);
            assert!(has_omission(&document, "sampler-unavailable"));
        }
        let mut native = events[0].clone();
        native
            .as_object_mut()
            .unwrap()
            .remove("dispatch_provenance");
        native["sequence_number"] = events[0]["sequence_number"].clone();
        native["type"] = json!("vm_dispatch_sample");
        native["process_id"] = json!(7);
        let mut bytes = hex::decode(native["payload"].as_str().unwrap()).unwrap();
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        native["payload"] = json!(hex::encode(bytes));
        let mut invalid = events[0].clone();
        invalid["process_id"] = native["process_id"].clone();
        invalid["dispatch_provenance"]["source"] = json!("native");
        let (document, _) = analyze(root.path(), &[events[0].clone(), native.clone(), invalid]);
        assert_eq!(document["workspaces"][0]["sample_count"], 2);
        assert!(has_omission(&document, "caller-samples-unverified"));
        let handlers = document["workspaces"][0]["handlers"].as_array().unwrap();
        assert_eq!(
            handlers.iter().find(|h| h["opcode"] == 0).unwrap()["state"],
            "inferred"
        );
        assert_eq!(
            handlers.iter().find(|h| h["opcode"] == 1).unwrap()["state"],
            "observed"
        );
        // Conflicting report identities remove reports only, never an equally
        // numbered native record in the nonzero-process namespace.
        let mut conflicting = events[0].clone();
        conflicting["payload"] = json!("00".repeat(128));
        let (document, _) = analyze(root.path(), &[events[0].clone(), conflicting, native]);
        assert_eq!(document["workspaces"][0]["sample_count"], 1);
        assert!(
            document["workspaces"][0]["samples"][0]
                .get("provenance")
                .is_none()
        );
    }
    #[test]
    fn full_caller_budget_is_retained_without_false_native_coverage() {
        let (root, mut input) = fixture();
        let sample = input["samples"][0].clone();
        input["samples"] = json!(
            (0..MAX_SAMPLES)
                .map(|index| {
                    let mut row = sample.clone();
                    row["sample_index"] = json!(index);
                    row
                })
                .collect::<Vec<_>>()
        );
        assert_eq!(import(root.path(), &input).unwrap(), MAX_SAMPLES);
        let (document, _) = analyze(root.path(), &reports(root.path()));
        assert_eq!(document["workspaces"][0]["sample_count"], MAX_SAMPLES);
        assert_eq!(
            document["workspaces"][0]["samples"]
                .as_array()
                .unwrap()
                .len(),
            MAX_SAMPLES
        );
        assert!(has_omission(&document, "sampler-unavailable"));
        assert!(has_omission(&document, "caller-samples-unverified"));
        assert!(!has_omission(&document, "sample-limit"));
    }
}
