//! Pack HTTP adapter and reb-api discovery use the exact offline semantics.
use origin_trace_backend::vm_pack;
use serde_json::{Value, json};
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn vm_pack_http_cli_parity_and_rejections() {
    let root = tempfile::tempdir().unwrap();
    let endpoint = root.path().join("endpoint");
    let binary = env!("CARGO_BIN_EXE_origin-trace-backend");
    let mut command = Command::new(binary);
    command
        .args(["--port", "0", "--endpoint-file"])
        .arg(&endpoint)
        .args(["--analyst-runner", binary])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (flag, name) in [
        ("--store", "events.jsonl"),
        ("--trace-store", "traces.jsonl"),
        ("--signal-store", "signals.jsonl"),
        ("--artifacts", "artifacts"),
        ("--api-collection", "collection.json"),
        ("--local-analyst", "analyst.json"),
    ] {
        command.arg(flag).arg(root.path().join(name));
    }
    let mut server = Server(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    let url = loop {
        if let Ok(text) = std::fs::read_to_string(&endpoint) {
            break text.trim().to_owned();
        }
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "backend exited before binding"
        );
        assert!(Instant::now() < deadline, "backend startup deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let fixture = |name| {
        vm_pack::read(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../tools/fixtures/vm-analysis-packs/{name}")),
        )
        .unwrap()
    };
    let body = json!({"pack":fixture("pack.json"),"left":fixture("build-a.workspace.json"),"left_artifact":"1","right":fixture("build-b.workspace.json"),"right_artifact":"1"});
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let evidence = root.path().join("owned-empty-evidence");
    std::fs::create_dir(&evidence).unwrap();
    std::fs::write(evidence.join("manifest.jsonl"), "").unwrap();
    std::fs::write(evidence.join("events.jsonl"), "").unwrap();
    let analysis =
        origin_trace_backend::vm::store(&evidence, &evidence.join("events.jsonl")).unwrap();
    let pack: Value =
        serde_json::from_str(include_str!("../assets/anti-bot-pack-v1.json")).unwrap();
    let apply_body = json!({"pack":pack,"analysis":analysis});
    let applied = client
        .post(format!("{url}/api/analysis/vm/packs/apply"))
        .json(&apply_body)
        .send()
        .await
        .unwrap();
    assert_eq!(applied.status(), 200);
    assert_eq!(
        applied.json::<Value>().await.unwrap(),
        vm_pack::apply(&pack, &analysis).unwrap()
    );
    let route = format!("{url}/api/analysis/vm/packs/compare");
    let response = client.post(&route).json(&body).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let report: Value = response.json().await.unwrap();
    assert_eq!(
        report,
        vm_pack::request(&serde_json::to_vec(&body).unwrap(), true).unwrap()
    );
    let response = client
        .post(&route)
        .header("content-type", "text/plain")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 415);
    let response = client
        .post(&route)
        .header("origin", "https://external.invalid")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let mut stale = body.clone();
    stale["left"]["document_digest"] = json!("0".repeat(64));
    assert_eq!(
        client
            .post(&route)
            .json(&stale)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(&route)
            .header("content-type", "application/json")
            .body(r#"{"pack":{},"pack":{}}"#)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    // Send only oversized headers: rejection precedes body ingestion, so a
    // client uploading a giant body could otherwise observe a broken pipe.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let address = url.strip_prefix("http://").unwrap();
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(format!("POST /api/analysis/vm/packs/compare HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", vm_pack::MAX_INPUT_BYTES + 1).as_bytes()).await.unwrap();
    let mut refusal = String::new();
    tokio::time::timeout(Duration::from_secs(3), socket.read_to_string(&mut refusal))
        .await
        .unwrap()
        .unwrap();
    assert!(refusal.starts_with("HTTP/1.1 400"));
    let body_file = root.path().join("request.json");
    std::fs::write(&body_file, body.to_string()).unwrap();
    let base_url = url.clone();
    let called = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_reb-api"))
            .args([
                "call",
                "vm_pack_compare",
                "--base-url",
                &base_url,
                "--body-file",
            ])
            .arg(body_file)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        called.status.success(),
        "{}",
        String::from_utf8_lossy(&called.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&called.stdout).unwrap(),
        report
    );
    for operation in ["vm_pack_apply", "vm_pack_compare"] {
        let description = Command::new(env!("CARGO_BIN_EXE_reb-api"))
            .args(["describe", operation])
            .output()
            .unwrap();
        assert!(
            description.status.success(),
            "{}",
            String::from_utf8_lossy(&description.stderr)
        );
        assert!(String::from_utf8_lossy(&description.stdout).contains(operation));
    }
}
