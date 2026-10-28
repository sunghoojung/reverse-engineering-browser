use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};

fn fixture(root: &Path) -> Value {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../tools/fixtures/vm-dynamic-debug/wasm-dispatch.json"
    ))
    .unwrap();
    let bytes = hex::decode(fixtures["br_table"].as_str().unwrap()).unwrap();
    let hash = hex::encode(Sha256::digest(&bytes));
    fs::create_dir(root.join("blobs")).unwrap();
    fs::write(root.join(format!("blobs/{hash}.bin")), &bytes).unwrap();
    let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"2","navigation_id":"3","frame_id":"4",
        "parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"webassembly_compile",
        "kind":"wasm","mime_type":"application/wasm","url":"fixture://owned/dispatch.wasm","byte_size":bytes.len(),
        "sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
    fs::write(root.join("manifest.jsonl"), format!("{artifact}\n")).unwrap();
    let input = json!({"contract_version":1,"source":"caller-supplied","interpreter_artifact_id":"1",
        "source_artifact_sha256":hash,"session_id":"2","navigation_id":"3","frame_id":"4","finding_id":"5",
        "investigation_id":"6","samples":[{"instruction_pointer":123,"opcode":0,"handler_index":0,"sample_index":0,"operand_count":0}]});
    fs::write(root.join("input.json"), input.to_string()).unwrap();
    input
}
fn writer(root: &Path, output: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_origin-trace-vm-dispatch-writer"))
        .arg("--artifacts")
        .arg(root)
        .arg("--input")
        .arg(root.join("input.json"))
        .arg("--output")
        .arg(root.join(output))
        .output()
        .unwrap()
}
fn analyze(root: &Path, events: &str) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_origin-trace-vm"))
        .arg("--artifacts")
        .arg(root)
        .arg("--events")
        .arg(root.join(events))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&fs::read(root.join("analysis/vm-opcode-workspace-v2.json")).unwrap())
        .unwrap()
}
#[test]
fn cli_reports_roundtrip_without_becoming_native_samples() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let result = writer(root.path(), "reports.jsonl");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("unverified"));
    assert!(writer(root.path(), "second.jsonl").status.success());
    let first = fs::read(root.path().join("reports.jsonl")).unwrap();
    assert_eq!(first, fs::read(root.path().join("second.jsonl")).unwrap());
    let report: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(report["type"], "vm_dispatch_report");
    assert_eq!(report["process_id"], 0);
    let doc = analyze(root.path(), "reports.jsonl");
    assert_eq!(doc["workspaces"][0]["sample_count"], 1);
    assert_eq!(
        doc["workspaces"][0]["samples"][0]["provenance"],
        report["dispatch_provenance"]
    );
    assert_eq!(doc["workspaces"][0]["handlers"][0]["state"], "inferred");
    // Combining duplicate input does not double-count it. Normalizers that drop
    // unknown metadata cannot turn this analysis-only type into native proof.
    fs::write(
        root.path().join("duplicate.jsonl"),
        [first.clone(), first.clone()].concat(),
    )
    .unwrap();
    assert_eq!(
        analyze(root.path(), "duplicate.jsonl")["workspaces"][0]["sample_count"],
        1
    );
    for patch in [
        "strip-provenance",
        "rename-native",
        "native-process",
        "unknown-source",
        "foreign-bytecode",
    ] {
        let mut event = report.clone();
        match patch {
            "strip-provenance" => {
                event.as_object_mut().unwrap().remove("dispatch_provenance");
            }
            "rename-native" => {
                event["type"] = json!("vm_dispatch_sample");
            }
            "native-process" => {
                event["process_id"] = json!(7);
            }
            "foreign-bytecode" => {
                let mut payload = hex::decode(event["payload"].as_str().unwrap()).unwrap();
                payload[48] = 1;
                event["payload"] = json!(hex::encode(payload));
            }
            _ => {
                event["dispatch_provenance"]["source"] = json!("native");
            }
        }
        fs::write(root.path().join("invalid.jsonl"), format!("{event}\n")).unwrap();
        assert_eq!(
            analyze(root.path(), "invalid.jsonl")["workspaces"][0]["sample_count"],
            0,
            "{patch}"
        );
    }
    assert!(!writer(root.path(), "reports.jsonl").status.success());
    assert_eq!(fs::read(root.path().join("reports.jsonl")).unwrap(), first);
}
#[test]
fn cli_rejects_duplicate_fields_and_symlinks_without_output() {
    let root = tempfile::tempdir().unwrap();
    let input = fixture(root.path());
    let duplicate = input
        .to_string()
        .replacen('{', "{\"source\":\"caller-supplied\",", 1);
    fs::write(root.path().join("input.json"), duplicate).unwrap();
    assert!(!writer(root.path(), "reports.jsonl").status.success());
    assert!(!root.path().join("reports.jsonl").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        fs::write(root.path().join("target.json"), input.to_string()).unwrap();
        fs::remove_file(root.path().join("input.json")).unwrap();
        symlink(
            root.path().join("target.json"),
            root.path().join("input.json"),
        )
        .unwrap();
        assert!(!writer(root.path(), "reports.jsonl").status.success());
        assert!(!root.path().join("reports.jsonl").exists());
        fs::remove_file(root.path().join("input.json")).unwrap();
        fs::write(root.path().join("input.json"), input.to_string()).unwrap();
        symlink(
            root.path().join("target.json"),
            root.path().join("reports.jsonl"),
        )
        .unwrap();
        assert!(!writer(root.path(), "reports.jsonl").status.success());
        assert_eq!(
            fs::read_to_string(root.path().join("target.json")).unwrap(),
            input.to_string()
        );
    }
}

origin_trace_backend::javascript_worker_test_entry!();
