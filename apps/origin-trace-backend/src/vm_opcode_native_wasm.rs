//! Physical native Wasm observations, never inferred guest ISA or guest-PC samples.
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wasmparser::{Operator, Parser, Payload, TypeRef};

#[derive(Default)]
pub(super) struct Observations {
    pub rows: Vec<Value>,
    pub count: u64,
    pub invalid: u64,
    counts: BTreeMap<(u32, Option<u32>), u64>,
}

fn sites(bytes: &[u8]) -> Option<BTreeMap<u32, (u32, u32)>> {
    let mut sites = BTreeMap::new();
    let mut function = 0u32;
    let mut instructions = 0usize;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.ok()? {
            Payload::ImportSection(reader) => {
                for import in reader {
                    if matches!(import.ok()?.ty, TypeRef::Func(_)) {
                        function = function.checked_add(1)?;
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let mut reader = body.get_operators_reader().ok()?;
                while !reader.eof() {
                    instructions += 1;
                    if instructions > 1_000_000 {
                        return None;
                    }
                    let offset = u32::try_from(reader.original_position()).ok()?;
                    if let Operator::BrTable { targets } = reader.read().ok()? {
                        sites.insert(offset, (function, targets.len()));
                    }
                }
                function = function.checked_add(1)?;
            }
            _ => {}
        }
    }
    Some(sites)
}

fn observation(
    event: &Value,
    artifact: &Value,
    sites: &BTreeMap<u32, (u32, u32)>,
) -> Option<Value> {
    if event["protocol_version"] != 3
        || event["payload_size"] != 128
        || event["payload_encoding"] != "hex"
        || event["payload_truncated"] != false
        || ["artifact_id", "session_id", "navigation_id", "frame_id"]
            .iter()
            .any(|key| event[*key] != artifact[*key])
        || event.get("dispatch_provenance").is_some()
        || event["parent_event_id"] != "0"
        || event["flags"].as_u64().is_none_or(|v| v != 0)
        || event["thread_id"]
            .as_u64()
            .is_none_or(|v| v == 0 || v > u32::MAX as u64)
        || !crate::evidence::canonical(&event["monotonic_time_ns"], 64, true)
        || !crate::evidence::canonical(&event["frame_id"], 64, true)
        || !crate::evidence::canonical(&event["artifact_id"], 64, true)
    {
        return None;
    }
    let bytes = super::event_payload(event, "wasm_dispatch_observation")?;
    if bytes[24..].iter().any(|v| *v != 0) {
        return None;
    }
    let at =
        |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed payload"));
    let function = at(4);
    let offset = at(8);
    let selector = at(12);
    let count = at(16);
    let index = at(20);
    if function >= 16 * 1024 * 1024
        || !(8..16 * 1024 * 1024).contains(&offset)
        || count >= 16 * 1024 * 1024
        || index >= 16
        || sites.get(&offset) != Some(&(function, count))
    {
        return None;
    }
    Some(
        json!({"event":super::event_reference(event),"function_index":function,"module_byte_offset":offset,
        "selector":selector,"table_count":count,"sample_index":index,"selected_arm":selector.min(count),"is_default":selector >= count}),
    )
}

pub(super) fn collect(artifact: &Value, bytes: &[u8], events: &[Value]) -> Observations {
    let mut output = Observations::default();
    if artifact["kind"] != "wasm" {
        return output;
    }
    // The caller verified the artifact digest and deduplicated event identities.
    // Decode the module once per artifact, not once per sample or by URL.
    let Some(sites) = sites(bytes) else {
        return output;
    };
    for event in events.iter().filter(|e| {
        e["type"] == "wasm_dispatch_observation" && e["artifact_id"] == artifact["artifact_id"]
    }) {
        let Some(row) = observation(event, artifact, &sites) else {
            output.invalid += 1;
            continue;
        };
        output.count += 1;
        let offset = row["module_byte_offset"].as_u64().expect("offset") as u32;
        let selector = (!row["is_default"].as_bool().expect("default"))
            .then(|| row["selector"].as_u64().expect("selector") as u32);
        *output.counts.entry((offset, selector)).or_default() += 1;
        if output.rows.len() < super::MAX_SAMPLES {
            output.rows.push(row);
        }
    }
    output
}

impl Observations {
    pub fn attach(&self, handlers: &mut [Value]) {
        for handler in handlers {
            let Some(offset) = handler["source"]["byte_offset"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
            else {
                continue;
            };
            let selector = handler["opcode"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok());
            if selector.is_none()
                && !handler["label"]
                    .as_str()
                    .is_some_and(|v| v.starts_with("br_table ") && v.ends_with("default"))
            {
                continue;
            }
            if let Some(count) = self.counts.get(&(offset, selector)) {
                handler["native_wasm_sample_count"] = json!(count);
                handler["sample_count"] =
                    json!(handler["sample_count"].as_u64().unwrap_or(0) + count);
                handler["state"] = json!("observed");
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    fn module() -> Vec<u8> {
        hex::decode("0061736d010000000104016000000302010005030100010a1d011b01017f0340200041016a210041002d00001a41000e020000000b0b").unwrap()
    }
    fn artifact(event: &Value) -> Value {
        json!({"kind":"wasm","artifact_id":event["artifact_id"],"session_id":event["session_id"],"navigation_id":event["navigation_id"],"frame_id":event["frame_id"]})
    }
    pub(crate) fn event(selector: u32) -> Value {
        let mut bytes = [0u8; 128];
        bytes[..4].copy_from_slice(&[1, 0, 128, 0]);
        bytes[8..12].copy_from_slice(&47u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&selector.to_le_bytes());
        bytes[16..20].copy_from_slice(&2u32.to_le_bytes());
        json!({"protocol_version":3,"session_id":"1","sequence_number":"1","process_id":1,"thread_id":1,"monotonic_time_ns":"1","navigation_id":"1","frame_id":"1","artifact_id":"1","parent_event_id":"0","flags":0,"payload_size":128,"payload_encoding":"hex","payload_truncated":false,"category":"vm","type":"wasm_dispatch_observation","payload":hex::encode(bytes)})
    }
    #[test]
    fn native_wasm_exact_site_and_scope() {
        let event = event(u32::MAX);
        let artifact = artifact(&event);
        let output = collect(&artifact, &module(), std::slice::from_ref(&event));
        assert_eq!(output.count, 1);
        assert_eq!(output.rows[0]["is_default"], true);
        assert_eq!(output.rows[0]["selected_arm"], 2);
        for field in [
            "payload_size",
            "payload_encoding",
            "payload_truncated",
            "protocol_version",
            "thread_id",
            "monotonic_time_ns",
            "parent_event_id",
            "flags",
        ] {
            for value in [None, Some(Value::Null), Some(json!([]))] {
                let mut bad = event.clone();
                if let Some(value) = value {
                    bad[field] = value;
                } else {
                    bad.as_object_mut().unwrap().remove(field);
                }
                assert_eq!(
                    collect(&artifact, &module(), &[bad]).count,
                    0,
                    "field {field}"
                );
            }
        }
        for field in ["session_id", "navigation_id", "frame_id"] {
            let mut bad = event.clone();
            bad[field] = json!("2");
            assert_eq!(collect(&artifact, &module(), &[bad]).count, 0);
        }
        for (offset, value) in [(4, 1u32), (8, 46), (16, 3), (20, 16), (24, 1)] {
            let mut bad = event.clone();
            let mut bytes = hex::decode(bad["payload"].as_str().unwrap()).unwrap();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            bad["payload"] = json!(hex::encode(bytes));
            assert_eq!(collect(&artifact, &module(), &[bad]).count, 0);
        }
        let mut handlers = vec![
            json!({"source":{"byte_offset":47},"opcode":null,"label":"br_table default","sample_count":0}),
            json!({"source":{"byte_offset":70},"opcode":null,"label":"br_table default","sample_count":0}),
        ];
        output.attach(&mut handlers);
        assert_eq!(handlers[0]["sample_count"], 1);
        assert_eq!(handlers[1]["sample_count"], 0);
    }
    #[test]
    fn native_wasm_imported_function_index_and_retention() {
        let original = module();
        let mut bytes = original[..14].to_vec();
        bytes.extend_from_slice(&[2, 7, 1, 1, b'm', 1, b'f', 0, 0]);
        bytes.extend_from_slice(&original[14..]);
        assert_eq!(sites(&bytes).unwrap().get(&56), Some(&(1, 2)));
        let mut event = event(0);
        let mut payload = hex::decode(event["payload"].as_str().unwrap()).unwrap();
        payload[4..8].copy_from_slice(&1u32.to_le_bytes());
        payload[8..12].copy_from_slice(&56u32.to_le_bytes());
        event["payload"] = json!(hex::encode(&payload));
        let artifact = artifact(&event);
        assert_eq!(
            collect(&artifact, &bytes, std::slice::from_ref(&event)).count,
            1
        );
        payload[4..8].copy_from_slice(&0u32.to_le_bytes());
        let mut wrong = event.clone();
        wrong["payload"] = json!(hex::encode(payload));
        assert_eq!(collect(&artifact, &bytes, &[wrong]).count, 0);
        let events = (1..=4097)
            .map(|i| {
                let mut event = event.clone();
                event["sequence_number"] = json!(i.to_string());
                event
            })
            .collect::<Vec<_>>();
        let output = collect(&artifact, &bytes, &events);
        assert_eq!(output.count, 4097);
        assert_eq!(output.rows.len(), 4096);
    }
    #[test]
    #[ignore = "requires actual C++ producer; make check supplies REB_NATIVE_WASM_GOLDEN"]
    fn native_wasm_cpp_golden() {
        let exe = std::env::var("REB_NATIVE_WASM_GOLDEN").expect("actual C++ producer required");
        for case in [
            "default",
            "arm",
            "wide-identities",
            "envelope-version",
            "reserved",
            "version",
            "size",
            "truncated",
            "big-endian",
            "sample-index",
            "offset",
            "function",
            "count",
            "flags",
            "parent",
            "identity",
        ] {
            let process = std::process::Command::new(&exe)
                .args(["--case", case])
                .output()
                .expect("run C++ producer");
            assert!(
                process.status.success(),
                "C++ case {case}: {}",
                String::from_utf8_lossy(&process.stderr)
            );
            let event: Value = serde_json::from_slice(&process.stdout).expect("EventToJson output");
            let output = collect(&artifact(&event), &module(), std::slice::from_ref(&event));
            assert_eq!(
                output.count,
                u64::from(matches!(case, "default" | "arm" | "wide-identities")),
                "C++ case {case}"
            );
            if matches!(case, "default" | "arm" | "wide-identities") {
                use sha2::{Digest, Sha256};
                let root = tempfile::tempdir().unwrap();
                let bytes = module();
                let hash = hex::encode(Sha256::digest(&bytes));
                std::fs::create_dir(root.path().join("blobs")).unwrap();
                std::fs::write(root.path().join(format!("blobs/{hash}.bin")), &bytes).unwrap();
                let mut manifest = artifact(&event);
                for (key,value) in json!({"protocol_version":1,"parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"unknown","url":"fixture://native-wasm-golden","mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")}).as_object().unwrap() {manifest[key]=value.clone();}
                std::fs::write(root.path().join("manifest.jsonl"), format!("{manifest}\n"))
                    .unwrap();
                let events = root.path().join("events.jsonl");
                std::fs::write(&events, format!("{event}\n")).unwrap();
                crate::vm::store(root.path(), &events).unwrap();
                let document: Value = serde_json::from_slice(
                    &std::fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json"))
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    document["workspaces"][0]["native_wasm_observation_count"], 1,
                    "golden product path {case}"
                );
                let schema: Value = serde_json::from_str(include_str!(
                    "../../../protocol/vm-opcode-workspace-v2.schema.json"
                ))
                .unwrap();
                jsonschema::validator_for(&schema)
                    .unwrap()
                    .validate(&document)
                    .unwrap();
                if case == "wide-identities"
                    && let Ok(path) = std::env::var("REB_NATIVE_WASM_WORKSPACE_OUTPUT")
                {
                    std::fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
                }
            }
        }
    }
}
