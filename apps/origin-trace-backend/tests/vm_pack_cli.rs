use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../tools/fixtures/vm-analysis-packs/{name}"))
}
fn compare(output: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_origin-trace-vm-pack"))
        .arg("compare")
        .arg("--pack")
        .arg(fixture("pack.json"))
        .arg("--left")
        .arg(fixture("build-a.workspace.json"))
        .args(["--left-artifact", "1"])
        .arg("--right")
        .arg(fixture("build-b.workspace.json"))
        .args(["--right-artifact", "1"])
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}
#[test]
fn offline_pack_cli_compares_owned_builds_and_writes_private_no_clobber_report() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("comparison.json");
    let output = compare(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["network_requests"], 0);
    let bytes = std::fs::read(&path).unwrap();
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status["document_digest"], report["document_digest"]);
    assert_eq!(
        report["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["status"] == "moved")
            .count(),
        1
    );
    assert!(!compare(&path).status.success());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(!compare(&link).status.success());
        assert!(origin_trace_backend::vm_pack::read(&link).is_err());
    }
    assert!(
        !compare(&directory.path().join("missing/report.json"))
            .status
            .success()
    );
}

#[test]
fn offline_pack_cli_applies_default_rankings_and_refuses_executable_extensions() {
    use serde_json::json;
    use sha2::{Digest, Sha256};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let source = b"navigator; canvas;";
    let hash = hex::encode(Sha256::digest(source));
    std::fs::create_dir(root.join("blobs")).unwrap();
    std::fs::write(root.join(format!("blobs/{hash}.bin")), source).unwrap();
    let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"javascript","url":"https://owned.test/source.js","mime_type":"text/javascript","byte_size":source.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
    std::fs::write(root.join("manifest.jsonl"), format!("{artifact}\n")).unwrap();
    std::fs::write(root.join("events.jsonl"), "").unwrap();
    let generic = origin_trace_backend::vm::store(root, &root.join("events.jsonl")).unwrap();
    let pack = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/anti-bot-pack-v1.json");
    let output_path = root.join("ranking.json");
    let apply = |pack: &std::path::Path, output: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_origin-trace-vm-pack"))
            .arg("apply")
            .arg("--pack")
            .arg(pack)
            .arg("--analysis")
            .arg(root.join("analysis/vm-analysis-v1.json"))
            .arg("--output")
            .arg(output)
            .output()
            .unwrap()
    };
    let output = apply(&pack, &output_path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&std::fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(report["rankings"][0]["anti_bot_score"], 50);
    assert_eq!(report["generic_analysis"], generic);
    let mut invalid: Value = serde_json::from_slice(&std::fs::read(pack).unwrap()).unwrap();
    invalid["execute"] = json!("fixture_decoder()");
    let invalid_path = root.join("invalid-pack.json");
    std::fs::write(&invalid_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
    let refused_output = root.join("refused.json");
    assert!(!apply(&invalid_path, &refused_output).status.success());
    assert!(!refused_output.exists());
}
