use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Server {
    child: Child,
    root: tempfile::TempDir,
    url: String,
    client: reqwest::Client,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Server {
    async fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let endpoint = root.path().join("endpoint");
        let mut child = Command::new(env!("CARGO_BIN_EXE_origin-trace-backend"));
        child
            .args(["--port", "0", "--endpoint-file"])
            .arg(&endpoint)
            .args(["--store"])
            .arg(root.path().join("events.jsonl"))
            .args(["--trace-store"])
            .arg(root.path().join("trace.jsonl"))
            .args(["--signal-store"])
            .arg(root.path().join("signals.jsonl"))
            .args(["--artifacts"])
            .arg(root.path().join("artifacts"))
            .args(["--api-collection"])
            .arg(root.path().join("collection.json"))
            .args(["--local-analyst"])
            .arg(root.path().join("analyst.json"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut child = child.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let url = loop {
            if let Ok(url) = std::fs::read_to_string(&endpoint) {
                break url.trim().to_owned();
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "Backend exited during startup"
            );
            assert!(
                Instant::now() < deadline,
                "Backend endpoint startup timeout"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        Self {
            child,
            root,
            url,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }
    async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{path}", self.url))
            .send()
            .await
            .unwrap()
    }
    async fn action(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(format!("{}{path}", self.url))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    fn file(&self, path: &str, bytes: &[u8]) {
        let p = self.root.path().join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
}
#[tokio::test]
async fn locality_static_allowlist_and_malformed_actions() {
    let server = Server::start().await;
    assert_eq!(server.get("/api/health").await.status(), 200);
    assert_eq!(
        server
            .client
            .get(format!("{}/api/health", server.url))
            .header("Host", "example.test:7319")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/health", server.url))
            .header("Origin", "https://example.test")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        server
            .client
            .get(format!("{}/api/health", server.url))
            .header("Sec-Fetch-Site", "cross-site")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    for path in [
        "/server.py",
        "/Cargo.toml",
        "/analyst_runner_node.js",
        "/../origin-trace-backend/Cargo.toml",
        "/api/events?limit=oops",
    ] {
        assert!(
            !server.get(path).await.status().is_success(),
            "Unexpectedly accepted {path}"
        );
    }
    assert_eq!(server.get("/index.html").await.status(), 200);
    let layout = server.get("/pane_layout.js").await;
    assert_eq!(layout.status(), 200);
    assert!(
        layout.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/javascript")
    );
    assert!(
        layout
            .text()
            .await
            .unwrap()
            .contains("function initializePaneLayout")
    );
    assert_eq!(
        server
            .action("/api/debugger/actions", json!({"action":"unknown"}))
            .await
            .status(),
        400
    );
    assert_eq!(
        server
            .action("/api/debugger/actions", json!({"action":"pause"}))
            .await
            .status(),
        409
    );
    assert_eq!(
        server
            .client
            .post(format!("{}/api/capture/actions", server.url))
            .header("Content-Type", "application/json")
            .body("[]")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
}
#[tokio::test]
async fn durable_workspace_conflict_and_private_permissions() {
    let server = Server::start().await;
    let initial: Value = server
        .get("/api/api-collection")
        .await
        .json()
        .await
        .unwrap();
    let body = json!({"action":"replace_api_collection","expected_generation":initial["generation"],"folders":[{"id":1,"name":"API Collection","parent_id":null,"variables":[]},{"id":2,"name":"Fixture folder","parent_id":1,"variables":[]}],"requests":[]});
    assert_eq!(
        server
            .action("/api/api-collection/actions", body.clone())
            .await
            .status(),
        200
    );
    assert_eq!(
        server
            .action("/api/api-collection/actions", body)
            .await
            .status(),
        409
    );
    let persisted: Value =
        serde_json::from_slice(&std::fs::read(server.root.path().join("collection.json")).unwrap())
            .unwrap();
    assert_eq!(persisted["generation"], 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(server.root.path().join("collection.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let response = server.get("/api/api-collection").await;
    let etag = response.headers()["etag"].clone();
    assert_eq!(
        server
            .client
            .get(format!("{}/api/api-collection", server.url))
            .header("If-None-Match", etag)
            .send()
            .await
            .unwrap()
            .status(),
        304
    );
}
#[tokio::test]
async fn verified_range_from_large_artifact_and_corruption_rejection() {
    let server = Server::start().await;
    let bytes = vec![b'x'; 20 * 1024 * 1024];
    let hash = hex::encode(Sha256::digest(&bytes));
    let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"javascript","url":"https://example.test/source.js","mime_type":"text/javascript","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
    server.file(
        "artifacts/manifest.jsonl",
        format!("{artifact}\n").as_bytes(),
    );
    server.file(&format!("artifacts/blobs/{hash}.bin"), &bytes);
    let response = server
        .get("/api/artifacts/1/content?offset=16777216&limit=16")
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-artifact-truncated"], "true");
    assert_eq!(response.bytes().await.unwrap().as_ref(), &bytes[..16]);
    let mut corrupt = bytes;
    corrupt[0] = b'y';
    server.file(&format!("artifacts/blobs/{hash}.bin"), &corrupt);
    assert_eq!(
        server
            .get("/api/artifacts/1/content?offset=16777216&limit=16")
            .await
            .status(),
        500
    );
}
#[test]
fn vm_reports_malformed_input_and_preserves_valid_evidence() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("manifest.jsonl"), b"not-json\n{}\n").unwrap();
    let events = root.path().join("events.jsonl");
    std::fs::write(&events, b"not-json\n{}\n").unwrap();
    let document = origin_trace_backend::vm::store(root.path(), &events).unwrap();
    assert_eq!(document["input_coverage"]["complete"], false);
    assert_eq!(document["summary"]["failed_count"], 1);
    assert_eq!(
        document["input_coverage"]["omissions"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert!(Path::new(&root.path().join("analysis/vm-analysis-v1.json")).is_file());
}

#[tokio::test]
async fn wasm_inspection_preserves_offsets_identity_limits_and_original_bytes() {
    let server = Server::start().await;
    fn leb(mut n: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (n & 127) as u8;
            n >>= 7;
            bytes.push(byte | if n > 0 { 128 } else { 0 });
            if n == 0 {
                break;
            }
        }
        bytes
    }
    fn section(module: &mut Vec<u8>, id: u8, data: &[u8]) {
        module.push(id);
        module.extend(leb(data.len()));
        module.extend(data);
    }
    fn module(nops: usize) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 1, 0x7f]);
        section(
            &mut bytes,
            2,
            &[1, 3, b'e', b'n', b'v', 4, b's', b'e', b'e', b'd', 0, 0],
        );
        section(&mut bytes, 3, &[1, 0]);
        section(&mut bytes, 7, &[1, 3, b'r', b'u', b'n', 0, 1]);
        let mut body = vec![0, 0x10, 0, 0x41, 7, 0x6a];
        body.extend(vec![1; nops]);
        body.push(0x0b);
        let mut code = vec![1];
        code.extend(leb(body.len()));
        code.extend(body);
        section(&mut bytes, 10, &code);
        bytes
    }
    let put = |bytes: &[u8], kind: &str| {
        let hash = hex::encode(Sha256::digest(bytes));
        let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":kind,"url":"https://example.test/module.wasm","mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        server.file(
            "artifacts/manifest.jsonl",
            format!("{artifact}\n").as_bytes(),
        );
        server.file(&format!("artifacts/blobs/{hash}.bin"), bytes);
        hash
    };
    let bytes = module(0);
    let hash = put(&bytes, "wasm");
    let response = server.get("/api/wasm?artifact_id=1").await;
    assert_eq!(response.status(), 200);
    let report: Value = response.json().await.unwrap();
    let spec: Value = serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap();
    jsonschema::validator_for(&spec["components"]["schemas"]["WasmInspection"])
        .unwrap()
        .validate(&report)
        .unwrap();
    assert_eq!(report["status"], "decoded");
    assert_eq!(report["sha256"], hash);
    assert_eq!(report["imported_functions"], 1);
    assert_eq!(report["defined_functions"], 1);
    let rows = report["rows"].as_array().unwrap();
    let op = rows
        .iter()
        .find(|r| {
            r["kind"] == "instruction" && r["text"].as_str().unwrap().starts_with("i32.const")
        })
        .unwrap();
    assert_eq!(op["function_index"], 1);
    let start = op["byte_offset"].as_u64().unwrap() as usize;
    let end = op["byte_end"].as_u64().unwrap() as usize;
    assert_eq!(&bytes[start..end], &[0x41, 7]);
    let repeated: Value = server
        .get("/api/wasm?artifact_id=1")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(repeated, report);
    assert_eq!(
        server
            .get("/api/artifacts/1/content")
            .await
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        bytes
    );
    let output = Command::new(env!("CARGO_BIN_EXE_origin-trace-wasm"))
        .arg("--artifacts")
        .arg(server.root.path().join("artifacts"))
        .args(["--artifact-id", "1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        report
    );
    // Names may contain newlines. They must not create additional display rows
    // and silently shift instruction links to unrelated original bytes.
    let mut multiline = bytes.clone();
    let name = multiline.windows(3).position(|w| w == b"env").unwrap();
    multiline[name..name + 3].copy_from_slice(b"\n\r\t");
    put(&multiline, "wasm");
    let escaped: Value = server
        .get("/api/wasm?artifact_id=1")
        .await
        .json()
        .await
        .unwrap();
    let escaped_rows = escaped["rows"].as_array().unwrap();
    assert!(escaped_rows.iter().all(|r| {
        !r["text"]
            .as_str()
            .unwrap()
            .contains(['\n', '\r', '\t', '\u{2028}', '\u{2029}'])
    }));
    assert!(
        escaped_rows
            .iter()
            .any(|r| r["kind"] == "import" && r["text"].as_str().unwrap().contains("\\n\\r\\t"))
    );
    assert_eq!(
        escaped_rows
            .iter()
            .find(|r| r["kind"] == "instruction"
                && r["text"].as_str().unwrap().starts_with("i32.const")),
        Some(op)
    );
    let mut unicode_name = bytes.clone();
    unicode_name[name..name + 3].copy_from_slice("\u{2028}".as_bytes());
    put(&unicode_name, "wasm");
    let escaped: Value = server
        .get("/api/wasm?artifact_id=1")
        .await
        .json()
        .await
        .unwrap();
    assert!(
        escaped["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["kind"] == "import" && r["text"].as_str().unwrap().contains("\\u{2028}"))
    );
    put(&bytes, "wasm");
    for query in [
        "",
        "?artifact_id=01",
        "?artifact_id=0",
        "?artifact_id=1&artifact_id=1",
    ] {
        assert_eq!(server.get(&format!("/api/wasm{query}")).await.status(), 400);
    }
    assert_eq!(server.get("/api/wasm?artifact_id=2").await.status(), 404);
    put(&bytes, "javascript");
    assert_eq!(server.get("/api/wasm?artifact_id=1").await.status(), 400);
    put(&module(10000), "wasm");
    let partial: Value = server
        .get("/api/wasm?artifact_id=1")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(partial["status"], "partial");
    assert_eq!(partial["rows"].as_array().unwrap().len(), 8192);
    assert!(!partial["omissions"].as_array().unwrap().is_empty());
    put(&vec![0; 2 * 1024 * 1024 + 1], "wasm");
    assert_eq!(server.get("/api/wasm?artifact_id=1").await.status(), 400);
    put(b"\0asm\x01\0\0\0", "wasm");
    let empty: Value = server
        .get("/api/wasm?artifact_id=1")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(empty["status"], "decoded");
    assert_eq!(empty["instructions"], 0);
    for malformed in [
        vec![],
        vec![0, 97, 115, 109],
        b"\0asm\x01\0\0\0\x0a\x02\x01\x7f".to_vec(),
    ] {
        put(&malformed, "wasm");
        assert_eq!(server.get("/api/wasm?artifact_id=1").await.status(), 422);
    }
    let mut missing_end = bytes.clone();
    missing_end.pop();
    let code = bytes.windows(4).position(|w| w == [0x0a, 9, 1, 7]).unwrap();
    missing_end[code + 1] -= 1;
    missing_end[code + 3] -= 1;
    put(&missing_end, "wasm");
    assert_eq!(server.get("/api/wasm?artifact_id=1").await.status(), 422);
    let mut trailing = bytes.clone();
    trailing.extend([0xff]);
    put(&trailing, "wasm");
    assert_eq!(server.get("/api/wasm?artifact_id=1").await.status(), 422);
    let hash = put(&bytes, "wasm");
    let mut corrupt = bytes.clone();
    corrupt[0] = 1;
    server.file(&format!("artifacts/blobs/{hash}.bin"), &corrupt);
    assert_eq!(server.get("/api/wasm?artifact_id=1").await.status(), 500);
}
