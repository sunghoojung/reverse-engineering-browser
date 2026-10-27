//! Physical native Wasm observations, never inferred guest ISA or guest-PC samples.
use super::native_module::Module;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Observations {
    pub rows: Vec<Value>,
    pub count: u64,
    pub invalid: u64,
    /// Records for a module whose section structure did not decode. They are
    /// neither accepted nor rejected and stay visible as an omission.
    pub undecodable: u64,
    counts: BTreeMap<(u32, Option<u32>), u64>,
}

fn observation(event: &Value, artifact: &Value, module: &mut Module<'_>) -> Option<Value> {
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
        || module
            .function(function)
            .is_none_or(|facts| facts.br_tables.get(&offset) != Some(&count))
    {
        return None;
    }
    Some(
        json!({"event":super::event_reference(event),"function_index":function,"module_byte_offset":offset,
        "selector":selector,"table_count":count,"sample_index":index,"selected_arm":selector.min(count),"is_default":selector >= count}),
    )
}

pub(super) fn collect(
    artifact: &Value,
    mut module: Option<&mut Module<'_>>,
    events: &[Value],
) -> Observations {
    let mut output = Observations::default();
    if artifact["kind"] != "wasm" {
        return output;
    }
    // The caller verified the artifact digest and deduplicated event identities.
    for event in events.iter().filter(|e| {
        e["type"] == "wasm_dispatch_observation" && e["artifact_id"] == artifact["artifact_id"]
    }) {
        let Some(module) = module.as_deref_mut() else {
            output.undecodable += 1;
            continue;
        };
        let Some(row) = observation(event, artifact, module) else {
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
    fn read(artifact: &Value, bytes: &[u8], events: &[Value]) -> Observations {
        collect(artifact, Module::parse(bytes).as_mut(), events)
    }
    fn leb(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            out.push(if value == 0 { byte } else { byte | 0x80 });
            if value == 0 {
                break;
            }
        }
    }
    /// The `module()` fixture with `nops` extra instructions before its loop.
    /// Returns the module and the module byte offset of its br_table.
    pub(crate) fn padded_module(nops: usize) -> (Vec<u8>, u32) {
        let original = module();
        let mut body = vec![1, 1, 0x7f];
        body.extend(std::iter::repeat_n(0x01, nops));
        body.extend_from_slice(&original[30..]);
        let mut entry = Vec::new();
        leb(body.len(), &mut entry);
        let site_in_entry = entry.len() + 3 + nops + 17;
        entry.extend_from_slice(&body);
        let mut section = vec![1];
        let site_in_section = section.len() + site_in_entry;
        section.extend_from_slice(&entry);
        let mut bytes = original[..23].to_vec();
        bytes.push(0x0a);
        leb(section.len(), &mut bytes);
        let site = bytes.len() + site_in_section;
        bytes.extend_from_slice(&section);
        assert_eq!(bytes[site], 0x0e);
        (bytes, site as u32)
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
        let output = read(&artifact, &module(), std::slice::from_ref(&event));
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
                assert_eq!(read(&artifact, &module(), &[bad]).count, 0, "field {field}");
            }
        }
        for field in ["session_id", "navigation_id", "frame_id"] {
            let mut bad = event.clone();
            bad[field] = json!("2");
            assert_eq!(read(&artifact, &module(), &[bad]).count, 0);
        }
        for (offset, value) in [(4, 1u32), (8, 46), (16, 3), (20, 16), (24, 1)] {
            let mut bad = event.clone();
            let mut bytes = hex::decode(bad["payload"].as_str().unwrap()).unwrap();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            bad["payload"] = json!(hex::encode(bytes));
            assert_eq!(read(&artifact, &module(), &[bad]).count, 0);
        }
        let mut handlers = vec![
            json!({"source":{"byte_offset":47},"opcode":null,"label":"br_table default","sample_count":0}),
            json!({"source":{"byte_offset":70},"opcode":null,"label":"br_table default","sample_count":0}),
        ];
        output.attach(&mut handlers);
        assert_eq!(handlers[0]["native_wasm_sample_count"], 1);
        assert_eq!(handlers[0]["sample_count"], 0);
        assert!(handlers[1].get("native_wasm_sample_count").is_none());
    }
    #[test]
    fn native_wasm_imported_function_index_and_retention() {
        let original = module();
        let mut bytes = original[..14].to_vec();
        bytes.extend_from_slice(&[2, 7, 1, 1, b'm', 1, b'f', 0, 0]);
        bytes.extend_from_slice(&original[14..]);
        let mut index = Module::parse(&bytes).unwrap();
        assert_eq!(index.function(1).unwrap().br_tables.get(&56), Some(&2));
        assert!(index.function(0).is_none(), "imported function has no body");
        let mut event = event(0);
        let mut payload = hex::decode(event["payload"].as_str().unwrap()).unwrap();
        payload[4..8].copy_from_slice(&1u32.to_le_bytes());
        payload[8..12].copy_from_slice(&56u32.to_le_bytes());
        event["payload"] = json!(hex::encode(&payload));
        let artifact = artifact(&event);
        assert_eq!(
            read(&artifact, &bytes, std::slice::from_ref(&event)).count,
            1
        );
        payload[4..8].copy_from_slice(&0u32.to_le_bytes());
        let mut wrong = event.clone();
        wrong["payload"] = json!(hex::encode(payload));
        assert_eq!(read(&artifact, &bytes, &[wrong]).count, 0);
        let events = (1..=4097)
            .map(|i| {
                let mut event = event.clone();
                event["sequence_number"] = json!(i.to_string());
                event
            })
            .collect::<Vec<_>>();
        let output = read(&artifact, &bytes, &events);
        assert_eq!(output.count, 4097);
        assert_eq!(output.rows.len(), 4096);
    }
    // Modules are bounded by the 16 MiB artifact limit, not by an
    // instruction count that silently discards every record.
    #[test]
    fn native_wasm_large_module_keeps_exact_site_observations() {
        let (bytes, site) = padded_module(1_000_001);
        assert_eq!(padded_module(0), (module(), 47));
        let mut event = event(0);
        let mut payload = hex::decode(event["payload"].as_str().unwrap()).unwrap();
        payload[8..12].copy_from_slice(&site.to_le_bytes());
        event["payload"] = json!(hex::encode(&payload));
        let artifact = artifact(&event);
        let output = read(&artifact, &bytes, std::slice::from_ref(&event));
        assert_eq!((output.count, output.invalid), (1, 0));
        payload[8..12].copy_from_slice(&(site - 1).to_le_bytes());
        event["payload"] = json!(hex::encode(&payload));
        let output = read(&artifact, &bytes, std::slice::from_ref(&event));
        assert_eq!(
            (output.count, output.invalid),
            (0, 1),
            "a nop is not a site"
        );
        let output = collect(&artifact, None, std::slice::from_ref(&event));
        assert_eq!(
            (output.count, output.invalid, output.undecodable),
            (0, 0, 1),
            "an undecodable module is reported, not dropped"
        );
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
            let output = read(&artifact(&event), &module(), std::slice::from_ref(&event));
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
