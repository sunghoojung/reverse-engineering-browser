//! Confirmed live Wasm commands through the HTTP routes.
//! The peer is the contract engine. No Brave process and no invented bytes.
#![cfg(unix)]

use origin_trace_backend::live_wasm::{
    Attachment, Engine, FIXTURE_DOCUMENT_EPOCH, FIXTURE_DOCUMENT_HIGH, FIXTURE_DOCUMENT_LOW,
    FIXTURE_INSTANCE, FIXTURE_WAT, Peer, Val,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    url: String,
    client: reqwest::Client,
    _root: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    async fn start(socket: Option<&Path>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let endpoint = root.path().join("endpoint");
        let mut command = Command::new(env!("CARGO_BIN_EXE_origin-trace-backend"));
        command
            .args(["--port", "0", "--endpoint-file"])
            .arg(&endpoint)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(socket) = socket {
            command.arg("--live-wasm-socket").arg(socket);
        }
        for (flag, name) in [
            ("--store", "events.jsonl"),
            ("--trace-store", "trace.jsonl"),
            ("--signal-store", "signals.jsonl"),
            ("--artifacts", "artifacts"),
            ("--api-collection", "collection.json"),
            ("--local-analyst", "analyst.json"),
        ] {
            command.arg(flag).arg(root.path().join(name));
        }
        let mut child = command.spawn().unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let url = loop {
            if let Ok(url) = std::fs::read_to_string(&endpoint) {
                break url.trim().to_owned();
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "backend exited before publishing its endpoint"
            );
            assert!(
                Instant::now() < deadline,
                "backend startup exceeded its deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        Self {
            child,
            url,
            client,
            _root: root,
        }
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let response = self
            .client
            .get(format!("{}{path}", self.url))
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response.json().await.unwrap();
        (status, body)
    }

    async fn post(&self, body: &Value) -> (u16, Value) {
        let response = self
            .client
            .post(format!("{}/api/live-wasm/actions", self.url))
            .json(body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response.json().await.unwrap();
        (status, body)
    }
}

fn engine() -> Engine {
    let bytes = wat::parse_str(FIXTURE_WAT).unwrap();
    Engine::load(
        &bytes,
        Attachment {
            instance_id: FIXTURE_INSTANCE,
            document_token_high: FIXTURE_DOCUMENT_HIGH,
            document_token_low: FIXTURE_DOCUMENT_LOW,
            document_epoch: FIXTURE_DOCUMENT_EPOCH,
        },
    )
    .unwrap()
}

fn identity(instance: &str, epoch: &str) -> Value {
    json!({
        "confirmed": true,
        "instance_id": instance,
        "document_token_high": "11",
        "document_token_low": "13",
        "document_epoch": epoch,
    })
}

fn with_identity(action: Value, instance: &str, epoch: &str) -> Value {
    let mut body = identity(instance, epoch);
    for (key, value) in action.as_object().unwrap() {
        body[key] = value.clone();
    }
    body
}

#[tokio::test]
async fn missing_peer_reports_unsupported_without_inventing_bytes() {
    let server = Server::start(None).await;
    let (status, state) = server.get("/api/live-wasm").await;
    assert_eq!(status, 200);
    assert_eq!(state["availability"], "unsupported");
    assert_eq!(state["reason"], "browser_command_unsupported");
    assert!(state["budget"].is_null());
    assert!(state["attachments"].as_array().unwrap().is_empty());
    assert!(state["observations"].as_array().unwrap().is_empty());
    let (status, denied) = server.get("/api/live-wasm?memory=memory").await;
    assert_eq!(status, 400);
    assert_eq!(denied["code"], "invalid_request");
    let (status, error) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 0,
                "length": 1
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 503);
    assert_eq!(error["code"], "dependency_unavailable");
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("No memory was read")
    );
}

#[tokio::test]
async fn confirmed_write_is_visible_to_a_later_confirmed_read() {
    let peer = Peer::spawn(engine()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    let (status, wrote) = server
        .post(&with_identity(
            json!({
                "action": "write_memory",
                "memory": "memory",
                "offset": 8,
                "bytes": [1, 2, 255]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{wrote}");
    assert_eq!(wrote["status"], "ok");
    assert_eq!(wrote["entered"], false);
    assert_eq!(wrote["memory"]["bytes"], json!([1, 2, 255]));
    let (status, read) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 8,
                "length": 3
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["status"], "ok");
    assert_eq!(read["memory"]["bytes"], json!([1, 2, 255]));
    assert_eq!(read["memory"]["byte_length"], 65536);
    assert_eq!(read["memory"]["shared"], false);
    let (status, bounds) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 65535,
                "length": 2
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{bounds}");
    assert_eq!(bounds["status"], "out_of_bounds");
    assert_eq!(bounds["entered"], false);
    assert!(bounds["memory"].is_null());
    let (status, clipped) = server
        .post(&with_identity(
            json!({
                "action": "write_memory",
                "memory": "memory",
                "offset": 65535,
                "bytes": [9, 9]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{clipped}");
    assert_eq!(clipped["status"], "out_of_bounds");
    assert!(clipped["memory"].is_null());
    let (status, tail) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 65535,
                "length": 1
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{tail}");
    assert_eq!(tail["memory"]["bytes"], json!([0]));
    let (status, missing) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "other",
                "offset": 0,
                "length": 1
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{missing}");
    assert_eq!(missing["status"], "unknown_memory");
    assert_eq!(missing["entered"], false);
    assert!(missing["memory"].is_null());
}

#[tokio::test]
async fn confirmed_export_call_returns_result_or_trap() {
    let peer = Peer::spawn(engine()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    let (status, add) = server
        .post(&with_identity(
            json!({
                "action": "call_export",
                "export": "add",
                "arguments": [
                    {"type": "i32", "bits": "20"},
                    {"type": "i32", "bits": "22"}
                ]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{add}");
    assert_eq!(add["status"], "ok");
    assert_eq!(add["entered"], true);
    assert_eq!(add["results"], json!([{"type": "i32", "bits": "42"}]));
    assert_eq!(add["function_index"], 0);
    let (status, negative) = server
        .post(&with_identity(
            json!({
                "action": "call_export",
                "export": "add",
                "arguments": [
                    {"type": "i32", "bits": "4294967295"},
                    {"type": "i32", "bits": "0"}
                ]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{negative}");
    assert_eq!(
        negative["results"],
        json!([{"type": "i32", "bits": "4294967295"}])
    );
    let (status, wrapped) = server
        .post(&with_identity(
            json!({
                "action": "call_export",
                "export": "add",
                "arguments": [
                    {"type": "i32", "bits": "4294967295"},
                    {"type": "i32", "bits": "1"}
                ]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{wrapped}");
    assert_eq!(wrapped["results"], json!([{"type": "i32", "bits": "0"}]));
    let (status, trap) = server
        .post(&with_identity(
            json!({"action": "call_export", "export": "trap", "arguments": []}),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{trap}");
    assert_eq!(trap["status"], "trap");
    assert_eq!(trap["entered"], true);
    assert!(trap["results"].is_null());
    let (status, hang) = server
        .post(&with_identity(
            json!({
                "action": "call_export",
                "export": "hang",
                "arguments": [{"type": "i32", "bits": "1"}]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{hang}");
    assert_eq!(hang["status"], "did_not_return");
    assert_eq!(hang["entered"], true);
    assert!(hang["results"].is_null());
    let (status, missing) = server
        .post(&with_identity(
            json!({"action": "call_export", "export": "missing", "arguments": []}),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{missing}");
    assert_eq!(missing["status"], "unknown_export");
    assert_eq!(missing["entered"], false);
    assert_eq!(missing["export"], "missing");
    assert!(missing["function_index"].is_null());
}

#[tokio::test]
async fn confirmed_function_index_call_enters_only_when_the_type_matches() {
    let peer = Peer::spawn(engine()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    let (status, state) = server.get("/api/live-wasm").await;
    assert_eq!(status, 200, "{state}");
    let functions = state["attachments"][0]["functions"].as_array().unwrap();
    let index = functions
        .iter()
        .find(|func| func["export"].is_null() && func["params"] == json!(["i32"]))
        .unwrap()["index"]
        .as_u64()
        .unwrap();
    let (status, entered) = server
        .post(&with_identity(
            json!({
                "action": "call_function",
                "function_index": index,
                "arguments": [{"type": "i32", "bits": "7"}]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{entered}");
    assert_eq!(entered["status"], "ok");
    assert_eq!(entered["entered"], true);
    assert_eq!(entered["results"], json!([{"type": "i32", "bits": "7"}]));
    assert_eq!(entered["samples_consumed"], 1);
    let used = server.get("/api/live-wasm").await.1["dispatch_samples_used"].clone();
    let (status, refused) = server
        .post(&with_identity(
            json!({
                "action": "call_function",
                "function_index": index,
                "arguments": [{"type": "i64", "bits": "1"}]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{refused}");
    assert_eq!(refused["status"], "signature_mismatch");
    assert_eq!(refused["entered"], false);
    assert!(refused["results"].is_null());
    assert_eq!(refused["samples_consumed"], 0);
    let (status, state) = server.get("/api/live-wasm").await;
    assert_eq!(status, 200);
    assert_eq!(state["dispatch_samples_used"], used);
    assert_eq!(state["observations"].as_array().unwrap().len(), 1);
    let (status, unknown) = server
        .post(&with_identity(
            json!({
                "action": "call_function",
                "function_index": 99,
                "arguments": []
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{unknown}");
    assert_eq!(unknown["status"], "unknown_function");
    assert_eq!(unknown["entered"], false);
    let (status, wide) = server
        .post(&with_identity(
            json!({
                "action": "call_function",
                "function_index": 16777215,
                "arguments": []
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{wide}");
    assert_eq!(wide["status"], "unknown_function");
    assert_eq!(wide["entered"], false);
    assert_eq!(wide["function_index"], 16777215);
    let (status, wider) = server
        .post(&with_identity(
            json!({
                "action": "call_function",
                "function_index": 16777216,
                "arguments": []
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 400, "{wider}");
    let (status, state) = server.get("/api/live-wasm").await;
    assert_eq!(status, 200, "{state}");
    assert_eq!(state["dispatch_samples_used"], used);
    assert_eq!(state["observations"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn stale_document_or_different_instance_is_refused() {
    let peer = Peer::spawn(engine()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    let (status, wrote) = server
        .post(&with_identity(
            json!({
                "action": "write_memory",
                "memory": "memory",
                "offset": 8,
                "bytes": [1, 2, 255]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{wrote}");
    peer.with_engine(|engine| engine.navigate());
    let (status, stale) = server
        .post(&with_identity(
            json!({
                "action": "write_memory",
                "memory": "memory",
                "offset": 8,
                "bytes": [9]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{stale}");
    assert_eq!(stale["status"], "stale_document");
    assert_eq!(stale["entered"], false);
    assert!(stale["memory"].is_null());
    assert_eq!(stale["document_epoch"], "1");
    let (status, read) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 8,
                "length": 3
            }),
            "7",
            "2",
        ))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["memory"]["bytes"], json!([1, 2, 255]));
    let (status, wrong) = server
        .post(&with_identity(
            json!({
                "action": "write_memory",
                "memory": "memory",
                "offset": 8,
                "bytes": [9]
            }),
            "8",
            "2",
        ))
        .await;
    assert_eq!(status, 200, "{wrong}");
    assert_eq!(wrong["status"], "instance_mismatch");
    assert_eq!(wrong["entered"], false);
    assert!(wrong["memory"].is_null());
    assert_eq!(wrong["instance_id"], "8");
    let (status, read) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 8,
                "length": 3
            }),
            "7",
            "2",
        ))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["memory"]["bytes"], json!([1, 2, 255]));
}

#[tokio::test]
async fn live_call_dispatch_observations_share_page_script_budget_and_identity() {
    let mut engine = engine();
    let index = engine.br_table_function().unwrap();
    engine.run_page_script(index, &[Val::I32(1)]);
    let peer = Peer::spawn(engine).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    let (status, called) = server
        .post(&with_identity(
            json!({
                "action": "call_function",
                "function_index": index,
                "arguments": [{"type": "i32", "bits": "0"}]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{called}");
    assert_eq!(called["status"], "ok");
    assert_eq!(called["entered"], true);
    assert_eq!(called["sample_indexes"], json!([1]));
    assert_eq!(called["budget_gap"], false);
    let (status, state) = server.get("/api/live-wasm").await;
    assert_eq!(status, 200, "{state}");
    assert_eq!(state["budget"], 16);
    assert_eq!(state["dispatch_samples_used"], 2);
    let observations = state["observations"].as_array().unwrap();
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0]["source"], "page_script");
    assert_eq!(observations[1]["source"], "live_call");
    assert_eq!(observations[0]["sample_index"], 0);
    assert_eq!(observations[1]["sample_index"], 1);
    assert_eq!(observations[0]["kind"], "sample");
    assert_eq!(observations[1]["kind"], "sample");
    for field in [
        "instance_id",
        "document_token_high",
        "document_token_low",
        "document_epoch",
        "function_index",
        "module_byte_offset",
    ] {
        assert_eq!(observations[0][field], observations[1][field], "{field}");
    }
    assert_ne!(observations[0]["selector"], observations[1]["selector"]);
    let before = observations.len();
    let (status, refused) = server
        .post(&with_identity(
            json!({
                "action": "call_function",
                "function_index": index,
                "arguments": [{"type": "i64", "bits": "1"}]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{refused}");
    assert_eq!(refused["status"], "signature_mismatch");
    assert_eq!(refused["entered"], false);
    let state = server.get("/api/live-wasm").await.1;
    assert_eq!(state["dispatch_samples_used"], 2);
    assert_eq!(state["observations"].as_array().unwrap().len(), before);
}

#[tokio::test]
async fn unconfirmed_action_does_not_reach_the_peer() {
    let peer = Peer::spawn(engine()).unwrap();
    let server = Server::start(Some(peer.socket())).await;
    let (status, error) = server
        .post(&json!({
            "action": "write_memory",
            "instance_id": "7",
            "document_token_high": "11",
            "document_token_low": "13",
            "document_epoch": "1",
            "memory": "memory",
            "offset": 0,
            "bytes": [9]
        }))
        .await;
    assert_eq!(status, 400, "{error}");
    assert_eq!(error["code"], "invalid_request");
    let mut denied = with_identity(
        json!({
            "action": "write_memory",
            "memory": "memory",
            "offset": 0,
            "bytes": [9]
        }),
        "7",
        "1",
    );
    denied["confirmed"] = json!(false);
    let (status, error) = server.post(&denied).await;
    assert_eq!(status, 400, "{error}");
    let (status, error) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 0,
                "length": 4097
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 400, "{error}");
    let (status, error) = server
        .post(&with_identity(
            json!({
                "action": "call_export",
                "export": "add",
                "arguments": [{"type": "i32", "bits": "4294967296"}]
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 400, "{error}");
    let (status, read) = server
        .post(&with_identity(
            json!({
                "action": "read_memory",
                "memory": "memory",
                "offset": 0,
                "length": 1
            }),
            "7",
            "1",
        ))
        .await;
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["memory"]["bytes"], json!([0]));
    let commands = peer.with_engine(|engine| engine.commands());
    assert_eq!(commands, 1);
}

origin_trace_backend::javascript_worker_test_entry!();
