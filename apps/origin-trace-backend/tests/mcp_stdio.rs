use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    time::{Duration, Instant},
};

struct Server {
    child: Child,
    url: String,
    _root: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Server {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let endpoint = root.path().join("endpoint");
        let mut child = Command::new(env!("CARGO_BIN_EXE_origin-trace-backend"))
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
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let url = loop {
            if let Ok(url) = std::fs::read_to_string(&endpoint) {
                let url = url.trim().to_owned();
                if !url.is_empty() {
                    break url;
                }
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "backend exited during startup"
            );
            assert!(Instant::now() < deadline, "backend endpoint timeout");
            std::thread::sleep(Duration::from_millis(20));
        };
        Self {
            child,
            url,
            _root: root,
        }
    }
}

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}
impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Mcp {
    fn start(url: &str, allow_effects: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_reb-api"));
        command
            .args(["mcp", "--base-url", url, "--timeout", "15"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if allow_effects {
            command.arg("--allow-effects");
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut mcp = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        let response = mcp.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "reb-api-test", "version": "0.3.2"}
            }),
        );
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(response["result"]["serverInfo"]["name"], "origin-trace");
        assert_eq!(response["result"]["serverInfo"]["version"], "0.3.2");
        mcp.notify(json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }));
        mcp
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }));
        self.read_matching(id)
    }

    fn notify(&mut self, message: Value) {
        self.send(&message);
    }

    fn send(&mut self, message: &Value) {
        serde_json::to_writer(&mut self.stdin, message).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();
    }

    fn read_matching(&mut self, id: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for MCP response {id}"
            );
            let mut line = String::new();
            let count = self.stdout.read_line(&mut line).unwrap();
            assert!(count > 0, "MCP server closed stdout");
            let message: Value = serde_json::from_str(line.trim()).unwrap();
            if message["id"] == id {
                return message;
            }
        }
    }
}

fn specification() -> Value {
    serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap()
}

fn operation<'a>(spec: &'a Value, id: &str) -> (&'a str, &'a str, &'a Value) {
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, definition) in item.as_object().unwrap() {
            if definition["operationId"] == id {
                return (method, path, definition);
            }
        }
    }
    panic!("missing operation {id}");
}

fn required_parameters(definition: &Value) -> Vec<String> {
    definition["parameters"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|parameter| parameter["required"] == true)
        .map(|parameter| parameter["name"].as_str().unwrap().to_owned())
        .collect()
}

fn is_binary(definition: &Value) -> bool {
    definition["responses"]["200"]["content"]
        .get("application/octet-stream")
        .is_some()
}

fn response_schema(spec: &Value, definition: &Value) -> Value {
    let schema = &definition["responses"]["200"]["content"]["application/json"]["schema"];
    let mut document = if let Some(reference) = schema["$ref"].as_str() {
        let pointer = reference.strip_prefix('#').unwrap();
        spec.pointer(pointer).unwrap().clone()
    } else {
        schema.clone()
    };
    if let Some(object) = document.as_object_mut() {
        object.insert("components".to_owned(), spec["components"].clone());
    }
    document
}

fn tool_text(message: &Value) -> &str {
    message["result"]["content"][0]["text"].as_str().unwrap()
}

#[tokio::test]
async fn openapi_mcp_matches_the_live_loopback_api() {
    let spec = specification();
    assert_eq!(spec["x-reb-mcp"]["transport"], "stdio");
    assert_eq!(spec["x-reb-mcp"]["default_tools"], "read_only_eligible");
    assert_eq!(spec["x-reb-mcp"]["binary_inline"], false);
    assert_eq!(spec["x-reb-mcp"]["oversized_json"], "structural_summary");
    assert_eq!(spec["x-reb-mcp"]["summary_string_chars"], 160);
    assert_eq!(spec["x-reb-mcp"]["batching"], false);
    assert_eq!(spec["x-reb-mcp"]["message_limit_bytes"], 33_554_432);
    assert_eq!(
        spec["x-reb-mcp"]["protocols"],
        json!(["2024-11-05", "2025-03-26", "2025-06-18"])
    );
    let server = Server::start();
    let discovery: Value = serde_json::from_slice(
        &Command::new(env!("CARGO_BIN_EXE_reb-api"))
            .args(["list", "--json"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let eligible = discovery["operations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|operation| operation["read_only_eligible"] == true)
        .map(|operation| operation["operation_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut mcp = Mcp::start(&server.url, false);
    let listed = mcp.request("tools/list", json!({}));
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(names, eligible);
    assert!(!names.iter().any(|name| name == "debugger_action"));
    assert!(!names.iter().any(|name| name == "native_console_action"));

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let mut checked = 0u32;
    for name in &names {
        let (method, path, definition) = operation(&spec, name);
        let required = required_parameters(definition);
        if is_binary(definition) {
            let mut arguments = serde_json::Map::new();
            for name in &required {
                arguments.insert(name.clone(), json!("1"));
            }
            let response = mcp.request("tools/call", json!({"name": name, "arguments": arguments}));
            assert_eq!(response["result"]["isError"], true, "{name}");
            assert!(
                tool_text(&response).contains("does not inline binary responses"),
                "{name}: {}",
                tool_text(&response)
            );
            checked += 1;
            continue;
        }
        if !required.is_empty() || definition.get("requestBody").is_some() {
            let response = mcp.request("tools/call", json!({"name": name, "arguments": {}}));
            assert_eq!(response["result"]["isError"], true, "{name}");
            let text = tool_text(&response);
            assert!(
                text.contains("Missing parameter") || text.contains("requires a JSON object body"),
                "{name}: {text}"
            );
            checked += 1;
            continue;
        }
        assert_eq!(method, "get", "{name}");
        assert!(!path.contains('{'), "{name} has an unsubstituted path");
        let response = mcp.request("tools/call", json!({"name": name, "arguments": {}}));
        assert_eq!(
            response["result"]["isError"],
            false,
            "{name}: {}",
            tool_text(&response)
        );
        let body: Value = serde_json::from_str(tool_text(&response)).unwrap();
        let direct: Value = client
            .get(format!("{}{}", server.url.trim_end_matches('/'), path))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body, direct, "{name} MCP body differs from HTTP");
        if body.is_object() {
            assert_eq!(response["result"]["structuredContent"], body, "{name}");
        }
        let schema = response_schema(&spec, definition);
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("{name} schema did not compile: {error}"));
        assert!(
            validator.is_valid(&body),
            "{name} does not match its OpenAPI response schema: {body}"
        );
        checked += 1;
    }
    assert!(checked >= 10, "checked only {checked} tools");

    let before = client
        .get(format!("{}/api/debugger", server.url.trim_end_matches('/')))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let rejected = mcp.request(
        "tools/call",
        json!({"name": "debugger_action", "arguments": {"body": {"action": "pause"}}}),
    );
    assert!(rejected.get("result").is_none(), "{rejected}");
    assert_eq!(rejected["error"]["code"], -32602);
    assert!(
        rejected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("No request was sent")
    );
    let after = client
        .get(format!("{}/api/debugger", server.url.trim_end_matches('/')))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(before, after, "rejected MCP action changed debugger state");

    let unknown = mcp.request("tools/call", json!({"name": "not_an_operation"}));
    assert!(unknown.get("result").is_none(), "{unknown}");
    assert_eq!(unknown["error"]["code"], -32602);
    assert!(
        unknown["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown OpenAPI operationId")
    );

    let events = client
        .get(format!("{}/api/events", server.url.trim_end_matches('/')))
        .send()
        .await
        .unwrap();
    assert!(events.status().is_success());
    let etag = events
        .headers()
        .get("etag")
        .expect("events etag")
        .to_str()
        .unwrap()
        .to_owned();
    events.bytes().await.unwrap();
    let conditional = mcp.request(
        "tools/call",
        json!({"name": "get_events", "arguments": {"If-None-Match": etag}}),
    );
    assert_eq!(
        conditional["result"]["isError"],
        false,
        "{}",
        tool_text(&conditional)
    );
    assert_eq!(
        conditional["result"]["structuredContent"]["http_status"],
        304
    );
    assert_eq!(conditional["result"]["structuredContent"]["etag"], etag);
    let conditional_body: Value = serde_json::from_str(tool_text(&conditional)).unwrap();
    assert_eq!(conditional_body, conditional["result"]["structuredContent"]);

    let mut effects = Mcp::start(&server.url, true);
    let expanded = effects.request("tools/list", json!({}));
    let expanded_names = expanded["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(expanded_names.contains(&"debugger_action"));
    assert!(expanded_names.contains(&"get_vm_analysis"));
    let health = effects.request("tools/call", json!({"name": "get_health"}));
    assert_eq!(health["result"]["isError"], false);
    assert_eq!(health["result"]["structuredContent"]["status"], "ok");
}

#[test]
fn mcp_stdio_rejects_batches_and_requests_before_initialize() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["mcp", "--base-url", "http://127.0.0.1:1", "--timeout", "5"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let send = |stdin: &mut ChildStdin, message: &Value| {
        serde_json::to_writer(&mut *stdin, message).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    };
    let read = |stdout: &mut BufReader<std::process::ChildStdout>| {
        let mut line = String::new();
        let count = stdout.read_line(&mut line).unwrap();
        assert!(count > 0, "MCP server closed stdout");
        serde_json::from_str::<Value>(line.trim()).unwrap()
    };
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    let early = read(&mut stdout);
    assert_eq!(early["error"]["code"], -32600, "{early}");
    assert!(
        early["error"]["message"]
            .as_str()
            .unwrap()
            .contains("No request was sent")
    );
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": "ping-1", "method": "ping"}),
    );
    let ping = read(&mut stdout);
    assert_eq!(ping["id"], "ping-1");
    assert!(ping.get("result").is_some(), "{ping}");
    send(
        &mut stdin,
        &json!([{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]),
    );
    let batch = read(&mut stdout);
    assert_eq!(batch["id"], Value::Null);
    assert_eq!(batch["error"]["code"], -32600, "{batch}");
    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}
        }),
    );
    let initialized = read(&mut stdout);
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}),
    );
    let listed = read(&mut stdout);
    assert!(listed["result"]["tools"].as_array().unwrap().len() >= 10);
    send(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 5, "method": "initialize"}),
    );
    let duplicate = read(&mut stdout);
    assert_eq!(duplicate["error"]["code"], -32600, "{duplicate}");
    drop(stdin);
    let _ = child.wait();
}

#[test]
fn mcp_rejects_a_non_loopback_root_before_stdio() {
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["mcp", "--base-url", "https://example.test:443"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("loopback"), "{stderr}");
}
