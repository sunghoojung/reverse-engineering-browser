use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
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
        Self::start_on(0)
    }
    fn start_on(port: u16) -> Self {
        Self::start_config(port, None)
    }
    fn start_config(port: u16, active_endpoint: Option<&std::path::Path>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let endpoint = root.path().join("endpoint");
        let mut command = Command::new(env!("CARGO_BIN_EXE_origin-trace-backend"));
        if let Some(active_endpoint) = active_endpoint {
            command
                .arg("--active-endpoint-file")
                .arg(active_endpoint)
                .arg("--socket")
                .arg(root.path().join("owned-disconnected-broker.sock"));
        }
        let mut child = command
            .args(["--port", &port.to_string(), "--endpoint-file"])
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
                // Session and canonical files are separate atomic publications.
                // Wait for both requested readiness signals, not just the first.
                if !url.is_empty()
                    && active_endpoint.is_none_or(|path| {
                        std::fs::read_to_string(path).is_ok_and(|active| active.trim() == url)
                    })
                {
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
        let mut args = vec![
            "mcp".to_owned(),
            "--base-url".to_owned(),
            url.to_owned(),
            "--timeout".to_owned(),
            "15".to_owned(),
        ];
        if allow_effects {
            args.push("--allow-effects".to_owned());
        }
        Self::start_with(args)
    }

    fn start_with(args: Vec<String>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_reb-api"));
        command
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Self::from_command(&mut command)
    }

    fn from_command(command: &mut Command) -> Self {
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
                "clientInfo": {"name": "reb-api-test", "version": "0.5.2"}
            }),
        );
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(response["result"]["serverInfo"]["name"], "origin-trace");
        assert_eq!(response["result"]["serverInfo"]["version"], "0.5.2");
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

    /// Waits for the server to exit on its own, with stdin still open.
    fn exit_code(&mut self) -> Option<i32> {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            assert!(Instant::now() < deadline, "retired MCP server kept running");
            std::thread::sleep(Duration::from_millis(20));
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
    // The saved invocation sites are readable. Resolving runs the analysis
    // worker and changing the set changes the app's next capture, so both
    // stay hidden until --allow-effects.
    assert!(names.iter().any(|name| name == "get_js_invocation_sites"));
    assert!(
        !names
            .iter()
            .any(|name| name == "resolve_js_invocation_site" || name == "js_invocation_site_action")
    );

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
        // A waiting read takes its shortest wait here; only its own elapsed
        // time can differ between the two calls.
        let (arguments, query) = if name == "wait_for_events" {
            (json!({"timeout_ms": 1}), "?timeout_ms=1")
        } else {
            (json!({}), "")
        };
        let response = mcp.request("tools/call", json!({"name": name, "arguments": arguments}));
        assert_eq!(
            response["result"]["isError"],
            false,
            "{name}: {}",
            tool_text(&response)
        );
        let mut body: Value = serde_json::from_str(tool_text(&response)).unwrap();
        let mut direct: Value = client
            .get(format!(
                "{}{}{query}",
                server.url.trim_end_matches('/'),
                path
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        if name == "get_session_context" {
            assert!(direct["allow_effects"].is_null());
            direct["allow_effects"] = json!(false);
            direct["effects_admission"] = json!("read_only_projection");
        }
        if name == "wait_for_events" {
            assert_eq!(body["wait"]["timed_out"], true);
            body["wait"]["waited_ms"] = direct["wait"]["waited_ms"].clone();
        }
        assert_eq!(body, direct, "{name} MCP body differs from HTTP");
        if body.is_object() && name != "wait_for_events" {
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
            .contains("Unknown OpenAPI operationId")
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
    assert!(!expanded_names.contains(&"debugger_action"));
    assert!(!expanded_names.contains(&"get_debugger"));
    assert!(!expanded_names.contains(&"get_debugger_source"));
    assert!(expanded_names.contains(&"get_vm_analysis"));
    let health = effects.request("tools/call", json!({"name": "get_health"}));
    assert_eq!(health["result"]["isError"], false);
    assert_eq!(health["result"]["structuredContent"]["status"], "ok");
}

#[test]
fn mcp_stdio_rejects_batches_and_requests_before_initialize() {
    let server = Server::start();
    let mut child = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["mcp", "--base-url", &server.url, "--timeout", "5"])
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
    assert!(output.stdout.is_empty(), "stdio started before rejection");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("loopback"), "{stderr}");
    assert!(!stderr.contains("example.test"), "{stderr}");
}

fn mcp_output(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn assert_mcp_stopped(output: &std::process::Output, stderr_needle: &str) {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "stdout was not empty: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(stderr_needle), "{stderr}");
    assert!(
        stderr.contains("No tools were advertised")
            || stderr.contains("No other session")
            || stderr.contains("No tool request was sent"),
        "{stderr}"
    );
}

fn serve_http(status: &str, body: &[u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_vec();
    let status = status.to_string();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0_u8; 4096];
        let _ = stream.read(&mut buf);
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(&body);
    });
    format!("http://{address}")
}

fn closed_loopback() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

#[test]
fn mcp_help_names_explicit_endpoint_sources_and_effects_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["mcp", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for text in [
        "--session-dir",
        "--endpoint-file",
        "--base-url",
        "--allow-effects",
        "not authorization",
        "newer session",
    ] {
        assert!(stdout.contains(text), "{text}\n{stdout}");
    }
}

#[test]
fn mcp_refuses_a_dead_or_unhealthy_endpoint_before_stdio() {
    let dead = mcp_output(&["mcp", "--base-url", &closed_loopback(), "--timeout", "2"]);
    assert_mcp_stopped(&dead, "/api/health");
    assert!(
        !String::from_utf8_lossy(&dead.stderr).contains("SECRET_EVIDENCE_PATH"),
        "{}",
        String::from_utf8_lossy(&dead.stderr)
    );

    let secret = br#"{"status":"degraded","store":"SECRET_EVIDENCE_PATH"}"#;
    let degraded = serve_http("200 OK", secret);
    let output = mcp_output(&["mcp", "--base-url", &degraded, "--timeout", "2"]);
    assert_mcp_stopped(&output, "did not report status ok");
    assert!(
        !output
            .stderr
            .windows(secret.len())
            .any(|window| window == secret)
    );

    let denied = serve_http("500 Internal Server Error", secret);
    let output = mcp_output(&["mcp", "--base-url", &denied, "--timeout", "2"]);
    assert_mcp_stopped(&output, "HTTP 500");
    assert!(
        !output
            .stderr
            .windows(secret.len())
            .any(|window| window == secret)
    );

    let mut oversized = br#"{"status":"ok","store":"SECRET_EVIDENCE_PATH","pad":""#.to_vec();
    oversized.extend(std::iter::repeat_n(b'x', 70_000));
    oversized.extend(br#""}"#);
    let huge = serve_http("200 OK", &oversized);
    let output = mcp_output(&["mcp", "--base-url", &huge, "--timeout", "2"]);
    assert_mcp_stopped(&output, "64 KiB");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("SECRET_EVIDENCE_PATH"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let healthy = serve_http(
        "200 OK",
        br#"{"status":"ok","store":"SECRET_EVIDENCE_PATH"}"#,
    );
    let output = mcp_output(&["mcp", "--base-url", &healthy, "--timeout", "2"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "health body reached stdout");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("SECRET_EVIDENCE_PATH"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn mcp_session_dir_uses_the_selected_directory_only() {
    let server = Server::start();
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("42");
    let newer = root.path().join("100");
    std::fs::create_dir(&selected).unwrap();
    std::fs::create_dir(&newer).unwrap();
    let _selected = publish(&selected.join("research-ui.endpoint"), &server.url);
    let _newer = publish(&newer.join("research-ui.endpoint"), &closed_loopback());
    let mut mcp = Mcp::start_with(
        [
            "mcp".to_owned(),
            "--session-dir".to_owned(),
            selected.to_string_lossy().into_owned(),
            "--timeout".to_owned(),
            "15".to_owned(),
        ]
        .to_vec(),
    );
    let listed = mcp.request("tools/list", json!({}));
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(names.contains(&"get_health"));
    assert!(!names.contains(&"debugger_action"));
    let health = mcp.request("tools/call", json!({"name": "get_health", "arguments": {}}));
    assert_eq!(health["result"]["isError"], false, "{health}");
    assert_eq!(health["result"]["structuredContent"]["status"], "ok");

    let missing = root.path().join("7");
    std::fs::create_dir(&missing).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["mcp", "--session-dir"])
        .arg(&missing)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_mcp_stopped(&output, "research-ui.endpoint");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no newer session"), "{stderr}");

    let handshake = root.path().join("handshake");
    std::fs::write(&handshake, format!("{}/?native=1\n", server.url)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["mcp", "--endpoint-file"])
        .arg(&handshake)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("loopback"), "{stderr}");
    assert!(!stderr.contains("native=1"), "{stderr}");
}

#[test]
fn reb_api_mcp_wrapper_selects_one_session_and_can_pass_effects() {
    let check = repo_path("tools/check-reb-api-mcp.sh");
    let output = Command::new(&check).output().expect("wrapper check");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let server = Server::start();
    let root = tempfile::tempdir().unwrap();
    let endpoint = root.path().join("research-ui.endpoint");
    let _published = publish(&endpoint, &server.url);
    let mut command = Command::new(repo_path("scripts/reb-api-mcp.sh"));
    command
        .args(["--endpoint-file"])
        .arg(&endpoint)
        .args(["--timeout", "15"])
        .env("REB_API", env!("CARGO_BIN_EXE_reb-api"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut mcp = Mcp::from_command(&mut command);
    let listed = mcp.request("tools/list", json!({}));
    let names = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(names.contains(&"get_health"), "{names:?}");
    assert!(!names.contains(&"debugger_action"), "{names:?}");
    drop(mcp);

    let dead = root.path().join("dead.endpoint");
    let _dead = publish(&dead, &closed_loopback());
    let run = |endpoint: &std::path::Path| {
        Command::new(repo_path("scripts/reb-api-mcp.sh"))
            .args(["--endpoint-file"])
            .arg(endpoint)
            .args(["--timeout", "2"])
            .env("REB_API", env!("CARGO_BIN_EXE_reb-api"))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let output = run(&dead);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("No tool request was sent"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A killed backend's file still names a port that may now be another
    // backend's. Without its publisher it is refused before any request.
    let stale = root.path().join("stale.endpoint");
    std::fs::write(&stale, format!("{}\n", server.url)).unwrap();
    let output = run(&stale);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("is stale"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Publishes `url` at `path` as a running backend does. The file has a live
/// publisher until the returned value drops.
fn publish(path: &std::path::Path, url: &str) -> origin_trace_backend::PublishedEndpoint {
    let address = url.trim_start_matches("http://").parse().unwrap();
    origin_trace_backend::PublishedEndpoint::new(Some(path), address).unwrap()
}

fn repo_path(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

struct LiveApi {
    url: String,
    addr: std::net::SocketAddr,
    health: std::sync::Arc<std::sync::Mutex<Value>>,
    paths: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl LiveApi {
    fn start() -> Self {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        };
        // Blocking accept. A nonblocking listener made accepted sockets inherit
        // O_NONBLOCK on macOS, and a read timeout then surfaced as WouldBlock.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let health = Arc::new(Mutex::new(json!({
            "status": "ok", "instance_id": "1:100", "capture_mode": "live", "broker_connected": true
        })));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (worker_health, worker_paths, worker_stop) =
            (health.clone(), paths.clone(), stop.clone());
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                if serve_live_request(&mut stream, &worker_health, &worker_paths).is_err() {
                    continue;
                }
            }
        });
        Self {
            url,
            addr,
            health,
            paths,
            stop,
            worker: Some(worker),
        }
    }
}
fn serve_live_request(
    stream: &mut std::net::TcpStream,
    health: &std::sync::Mutex<Value>,
    paths: &std::sync::Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let Some(path) = line
        .split_whitespace()
        .nth(1)
        .map(|path| path.split('?').next().unwrap_or(path).to_owned())
    else {
        return Ok(());
    };
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    paths.lock().unwrap().push(path.clone());
    let body = if path == "/api/health" {
        health.lock().unwrap().clone()
    } else if path == "/api/session/context" {
        fixture_session_context(&health.lock().unwrap())
    } else {
        json!({"events": []})
    };
    let bytes = serde_json::to_vec(&body).unwrap();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    )?;
    stream.write_all(&bytes)
}
fn fixture_session_context(health: &Value) -> Value {
    let capture = health["capture_mode"].as_str().unwrap_or("unknown");
    let broker = health["broker_connected"].as_bool() == Some(true);
    let admission = if capture == "live" && broker {
        "ready"
    } else if capture == "live" {
        "native_capture_unavailable"
    } else if capture == "idle" {
        "idle"
    } else {
        "not_live_capture"
    };
    json!({
        "protocol_version": 1,
        "instance_id": health["instance_id"],
        "endpoint": "http://127.0.0.1:9",
        "capture_mode": capture,
        "debugger_state": "unavailable",
        "broker_connected": broker,
        "live_admission": admission,
        "generation": 0,
        "debugger_protocol_version": 1,
        "target_document_epoch": 0,
        "capture_epoch": 0,
        "target": null,
        "wasm_scripts": [],
        "wasm_scripts_omitted": 0,
        "wasm_artifacts": {"items": [], "window_truncated": false, "items_omitted": 0},
        "debugger_etag": "\"debugger-0\"",
        "allow_effects": null,
        "effects_admission": "caller_specific_unknown",
        "limits": {
            "items_per_inventory": 16,
            "url_policy": "origin_or_wasm_label",
            "title_policy": "omitted",
            "artifact_linkage": "not_inferred"
        },
        "consistency": "independent_debugger_snapshot_and_manifest_tail"
    })
}
impl Drop for LiveApi {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        // Unblock a blocking accept without inheriting nonblocking mode.
        let _ = std::net::TcpStream::connect_timeout(&self.addr, Duration::from_secs(2));
        let result = self.worker.take().unwrap().join();
        // Keep a worker failure visible, but never abort while reporting the
        // original test assertion through an additional destructor panic.
        if !std::thread::panicking() {
            result.expect("live API fixture worker panicked");
        }
    }
}

#[test]
fn canonical_wrapper_reconnects_without_retargeting_pending_tools() {
    let first = LiveApi::start();
    let second = LiveApi::start();
    let home = tempfile::tempdir().unwrap();
    let canonical = home.path().join(".config/origin-trace/reb-api.endpoint");
    let mut _published = publish(&canonical, &first.url);
    let start = || {
        let mut command = Command::new(repo_path("scripts/reb-api-mcp.sh"));
        command
            .args(["--allow-effects", "--timeout", "2"])
            .env("HOME", home.path())
            .env("REB_API", env!("CARGO_BIN_EXE_reb-api"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Mcp::from_command(&mut command)
    };
    let mut mcp = start();
    assert_eq!(first.paths.lock().unwrap().as_slice(), ["/api/health"]);
    let override_attempt = mcp.request(
        "tools/call",
        json!({"name": "get_health", "arguments": {"x-reb-expected-instance": "0:0"}}),
    );
    assert_eq!(override_attempt["result"]["isError"], true);
    assert_eq!(
        first.paths.lock().unwrap().as_slice(),
        ["/api/health"],
        "tool arguments overrode the transport precondition"
    );
    _published = publish(&canonical, &second.url);
    let changed = mcp.request(
        "tools/call",
        json!({"name": "capture_action", "arguments": {"body": {"action": "stop"}}}),
    );
    assert_eq!(changed["result"]["isError"], true, "{changed}");
    assert!(tool_text(&changed).contains("Reconnect"), "{changed}");
    assert!(second.paths.lock().unwrap().is_empty());
    // A retired connection exits after its refusal, so the client sees the
    // disconnect instead of a live server that refuses every call.
    assert_eq!(mcp.exit_code(), Some(3), "retired connection kept serving");
    drop(mcp);
    assert_eq!(
        first.paths.lock().unwrap().len(),
        1,
        "old backend received an action"
    );
    // A non-tool request is refused as a JSON-RPC error before the exit.
    for method in ["tools/list", "initialize"] {
        _published = publish(&canonical, &first.url);
        let mut listing = start();
        _published = publish(&canonical, &second.url);
        let rejected = listing.request(method, json!({}));
        assert_eq!(rejected["error"]["code"], -32000, "{rejected}");
        assert!(rejected.get("result").is_none(), "{rejected}");
        assert_eq!(listing.exit_code(), Some(3), "{method}");
    }
    assert!(second.paths.lock().unwrap().is_empty());
    assert!(
        first
            .paths
            .lock()
            .unwrap()
            .iter()
            .all(|path| path == "/api/health"),
        "old backend received an action"
    );
    _published = publish(&canonical, &second.url);
    let mut reconnected = start();
    let healthy = reconnected.request("tools/call", json!({"name": "get_health"}));
    assert_eq!(healthy["result"]["isError"], false, "{healthy}");
    assert_eq!(
        second.paths.lock().unwrap().len(),
        3,
        "reconnect, preflight and call use new endpoint"
    );
    *second.health.lock().unwrap() = json!({"status": "ok", "instance_id": "1:100", "capture_mode": "idle", "broker_connected": true, "store": "PRIVATE_PATH"});
    let idle = reconnected.request("tools/call", json!({"name": "get_events"}));
    assert_eq!(idle["result"]["isError"], true, "{idle}");
    assert_eq!(idle["result"]["structuredContent"]["code"], "idle_backend");
    for expected in [
        &second.url,
        "code=idle_backend",
        "capture_mode=idle",
        "broker_connected=true",
    ] {
        assert!(tool_text(&idle).contains(expected), "{idle}");
    }
    assert!(!tool_text(&idle).contains("PRIVATE_PATH"));
    assert!(
        second
            .paths
            .lock()
            .unwrap()
            .iter()
            .all(|path| path == "/api/health")
    );
    let context = reconnected.request("tools/call", json!({"name": "get_session_context"}));
    assert_eq!(context["result"]["isError"], false, "{context}");
    assert_eq!(
        context["result"]["structuredContent"]["live_admission"],
        "idle"
    );
    assert_eq!(
        context["result"]["structuredContent"]["capture_mode"],
        "idle"
    );
    assert_eq!(
        context["result"]["structuredContent"]["endpoint"],
        second.url
    );
    assert!(
        context["result"]["structuredContent"]["wasm_scripts"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        context["result"]["structuredContent"]["wasm_artifacts"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        second
            .paths
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.as_str() == "/api/session/context")
            .count(),
        1
    );
    *second.health.lock().unwrap() = json!({"status": "ok", "instance_id": "1:100", "capture_mode": "live", "broker_connected": false});
    let unattached = reconnected.request("tools/call", json!({"name": "get_events"}));
    assert_eq!(
        unattached["result"]["structuredContent"]["code"], "native_capture_unavailable",
        "{unattached}"
    );
    assert!(tool_text(&unattached).contains("broker_connected=false"));
    let before_replacement = second.paths.lock().unwrap().len();
    *second.health.lock().unwrap() = json!({"status": "ok", "capture_mode": "live", "broker_connected": true, "instance_id": "2:200"});
    let replacement = reconnected.request("tools/call", json!({"name": "get_events"}));
    assert_eq!(replacement["result"]["isError"], true, "{replacement}");
    assert!(tool_text(&replacement).contains("backend instance changed"));
    assert_eq!(
        second.paths.lock().unwrap().len(),
        before_replacement + 1,
        "instance mismatch retired the connection before dispatch"
    );
    assert_eq!(
        second.paths.lock().unwrap().last().map(String::as_str),
        Some("/api/health")
    );
    assert_eq!(
        reconnected.exit_code(),
        Some(3),
        "replaced instance kept serving"
    );
    assert_eq!(second.paths.lock().unwrap().len(), before_replacement + 1);
    let mut invalidated = start();
    drop(_published);
    std::fs::write(&canonical, "https://example.test/secret").unwrap();
    let invalid = invalidated.request("tools/call", json!({"name": "get_health"}));
    assert_eq!(invalid["result"]["isError"], true);
    assert!(!tool_text(&invalid).contains("example.test"));
    assert_eq!(invalidated.exit_code(), Some(3));
}

#[test]
fn live_requirement_rejects_idle_unknown_and_disconnected_health_without_leaks() {
    // Live means a live-mode backend with its native event broker connected.
    for (capture, broker, accepted) in [
        ("live", json!(true), true),
        ("idle", json!(true), false),
        ("demo", json!(true), false),
        ("live", json!(false), false),
        ("live", json!("PRIVATE_STATE"), false),
        ("live", Value::Null, false),
        ("PRIVATE_MODE", json!(true), false),
    ] {
        let health = serde_json::to_vec(&json!({"status": "ok", "instance_id": "1:100", "capture_mode": capture, "broker_connected": broker, "debugger_state": "running", "store": "PRIVATE_PATH"})).unwrap();
        let url = serve_http("200 OK", &health);
        let output = mcp_output(&[
            "mcp",
            "--base-url",
            &url,
            "--require-live",
            "--timeout",
            "2",
        ]);
        assert_eq!(
            output.status.success(),
            accepted,
            "{capture} {broker}: {output:?}"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("PRIVATE_"), "{stderr}");
        if !accepted {
            assert!(stderr.contains(&url), "{stderr}");
            assert!(stderr.contains("capture_mode="), "{stderr}");
            assert!(stderr.contains("broker_connected="), "{stderr}");
            let code = if capture == "idle" {
                "code=idle_backend"
            } else if capture == "live" {
                "code=native_capture_unavailable"
            } else {
                "code=state_conflict"
            };
            assert!(stderr.contains(code), "{stderr}");
        }
    }
}

#[test]
fn idle_backend_cannot_publish_the_active_live_endpoint() {
    let root = tempfile::tempdir().unwrap();
    let endpoint = root.path().join("active.endpoint");
    let output = Command::new(env!("CARGO_BIN_EXE_origin-trace-backend"))
        .arg("--active-endpoint-file")
        .arg(&endpoint)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!endpoint.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--socket"));
}

#[test]
fn backend_replacement_after_health_cannot_receive_an_old_instances_action() {
    // Exercise the actual backend, not a model of the precondition: its port is
    // reused after MCP health succeeds and before the client dispatches a tool.
    let first = Server::start();
    let url = first.url.clone();
    let port = url::Url::parse(&url).unwrap().port().unwrap();
    let mut mcp = Mcp::start(&url, true);
    drop(first);
    let second = Server::start_on(port);
    assert_eq!(second.url, url);
    let rejected = mcp.request(
        "tools/call",
        json!({
            "name": "capture_action", "arguments": {"body": {"action": "stop"}}
        }),
    );
    assert_eq!(rejected["result"]["isError"], true, "{rejected}");
    let error: Value = serde_json::from_str(tool_text(&rejected)).unwrap();
    assert_eq!(error["http_status"], 409, "{error}");
    assert_eq!(error["code"], "state_conflict", "{error}");
    assert!(
        error["error"]
            .as_str()
            .unwrap()
            .contains("No operation was dispatched")
    );
    let mut reconnected = Mcp::start(&url, true);
    let health = reconnected.request("tools/call", json!({"name": "get_health"}));
    assert_eq!(health["result"]["isError"], false, "{health}");
}

#[tokio::test]
async fn instance_precondition_rejects_duplicate_headers_before_body_dispatch() {
    let server = Server::start();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let health: Value = client
        .get(format!("{}/api/health", server.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = health["instance_id"].as_str().unwrap();
    for headers in [vec![id, id], vec![id, "0:0"], vec!["not-an-instance"]] {
        let mut request = client.post(format!("{}/api/capture/actions", server.url));
        for value in headers {
            request = request.header("x-reb-expected-instance", value);
        }
        let response = request.body("not json").send().await.unwrap();
        assert_eq!(response.status().as_u16(), 409);
        let error: Value = response.json().await.unwrap();
        assert_eq!(error["code"], "state_conflict");
    }
}

#[test]
fn live_backend_publishes_the_canonical_alias_without_idle_takeover() {
    let root = tempfile::tempdir().unwrap();
    let canonical = root.path().join("canonical.endpoint");
    let live = Server::start_config(0, Some(&canonical));
    assert_eq!(
        std::fs::read_to_string(&canonical).unwrap().trim(),
        live.url
    );
    let _idle = Server::start();
    assert_eq!(
        std::fs::read_to_string(&canonical).unwrap().trim(),
        live.url
    );
}

#[test]
fn session_context_reports_actual_mcp_admission_and_action_guidance() {
    let server = Server::start();
    for allow_effects in [false, true] {
        let mut mcp = Mcp::start(&server.url, allow_effects);
        let response = mcp.request("tools/call", json!({"name":"get_session_context"}));
        let context = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(context["allow_effects"], allow_effects);
        assert_eq!(context["endpoint"], server.url);
        assert_eq!(context["capture_mode"], "idle");
        assert_eq!(context["live_admission"], "idle");
        assert!(context["wasm_scripts"].as_array().unwrap().is_empty());
        assert!(
            context["wasm_artifacts"]["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let health = mcp.request("tools/call", json!({"name":"get_health"}));
        assert_eq!(
            context["instance_id"],
            health["result"]["structuredContent"]["instance_id"]
        );
        let spec = specification();
        let (_, _, definition) = operation(&spec, "get_session_context");
        assert!(
            jsonschema::validator_for(&response_schema(&spec, definition))
                .unwrap()
                .is_valid(context)
        );
        assert!(tool_text(&response).len() < 8192);
        if !allow_effects {
            continue;
        }
        {
            let (name, valid) = ("capture_action", "stop");
            let response = mcp.request("tools/call", json!({"name":name,"arguments":{"body":{}}}));
            assert_eq!(response["result"]["isError"], true);
            let error = &response["result"]["structuredContent"];
            assert_eq!(error["code"], "invalid_request");
            assert!(
                error["details"]["allowed_actions"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(valid))
            );
            assert_eq!(error["details"]["missing_fields"], json!(["action"]));
            let response = mcp.request(
                "tools/call",
                json!({"name":name,"arguments":{"body":{"action":valid}}}),
            );
            assert_eq!(response["result"]["isError"], true);
            let error: Value = serde_json::from_str(tool_text(&response)).unwrap();
            assert_eq!(error["code"], "idle_backend");
        }
    }
}

origin_trace_backend::javascript_worker_test_entry!();

fn tool_names(response: &Value) -> Vec<String> {
    response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect()
}

/// A stand-in for run-live-session.sh: it runs the real backend in live mode
/// with the same ready line, TERM cleanup and capture labels, records the
/// switches it was given, and copies the invocation site file it was asked to
/// arm. A stand-in browser records how it was invoked and, like a connected
/// capture browser, adds a native record to the session's store.
#[cfg(unix)]
struct AgentFixture {
    root: tempfile::TempDir,
    home: std::path::PathBuf,
    sessions: std::path::PathBuf,
    socket: std::path::PathBuf,
    record: std::path::PathBuf,
    _broker: std::os::unix::net::UnixListener,
}

#[cfg(unix)]
impl AgentFixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let sessions = root.path().join("sessions");
        std::fs::create_dir_all(&home).unwrap();
        let socket = root.path().join("broker.sock");
        let broker = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let record = root.path().join("brave-args");
        let brave = root.path().join("brave.sh");
        let event = r#"{"protocol_version":3,"session_id":"1","sequence_number":"1","monotonic_time_ns":"1","navigation_id":"1","frame_id":"1","artifact_id":"0","request_id":"1","process_id":7,"category":"network","type":"request_started","payload_encoding":"hex","payload":"","payload_size":0}"#;
        std::fs::write(
            &brave,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{record}'\nfor arg; do case $arg in --user-data-dir=*) profile=${{arg#--user-data-dir=}};; esac; done\nprintf '%s\\n' '{event}' >> \"$(dirname \"$profile\")/events.jsonl\"\n",
                record = record.display()
            ),
        )
        .unwrap();
        let launcher = root.path().join("launcher.sh");
        std::fs::write(
            &launcher,
            format!(
                r#"#!/bin/bash
set -euo pipefail
mkdir -p "$REB_LIVE_SESSION_ROOT"
dir="$REB_LIVE_SESSION_ROOT/$((4242 + $(ls "$REB_LIVE_SESSION_ROOT" | wc -l)))"
mkdir -p "$dir/profile" "$dir/artifacts"
printf '%s\n' "$REB_NATIVE_WASM_DISPATCH $REB_CAPTURE_CATEGORY_MASK $REB_USE_SYSTEM_KEYCHAIN $REB_CONSOLE_DOCUMENT_START $REB_CAPTURE_REQUEST_CONTENT ${{REB_NATIVE_JS_INVOCATION_SITES-unset}} ${{REB_NATIVE_JS_INVOCATION_DIGESTS-unset}}" > "$dir/options"
printf '%s\n' "${{REB_NATIVE_JS_INVOCATION_IF_SUPPORTED-unset}} ${{REB_JS_INVOCATION_SITE_STORE-unset}}" > "$dir/site-store"
printf '%s\n' "${{REB_NATIVE_REQUEST_STACKS-unset}} ${{REB_NATIVE_REQUEST_STACKS_IF_SUPPORTED-unset}}" > "$dir/stacks"
printf '%s\n' "${{REB_REQUEST_CONTENT_BUDGET_MIB-unset}}" > "$dir/content-budget"
labels=()
if [[ -n "${{REB_NATIVE_JS_INVOCATION_SITES-}}" ]]; then
  cp "$REB_NATIVE_JS_INVOCATION_SITES" "$dir/sites"
  labels+=(--js-invocation-session-sites "$REB_NATIVE_JS_INVOCATION_SITES" --js-invocation-session-state armed)
  [[ "$REB_NATIVE_JS_INVOCATION_DIGESTS" == 1 ]] && labels+=(--js-invocation-session-digests)
fi
[[ "$REB_CAPTURE_REQUEST_CONTENT" == 1 ]] && labels+=(--session-request-content)
[[ "$REB_CONSOLE_DOCUMENT_START" == 1 ]] && labels+=(--session-document-start)
[[ "${{REB_NATIVE_REQUEST_STACKS-0}}" == 1 ]] && labels+=(--session-request-stacks)
ln -s "test-host-$$" "$dir/profile/SingletonLock"
# The stand-in broker holds its event store guard for its life, as the real
# broker does; the backend reads that lock as the broker running.
guard="$dir/events.jsonl.reb-lock-v1"
printf 'REB_EVIDENCE_GUARD_V1\n' > "$guard"
chmod 600 "$guard"
python3 -I -c 'import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(3600)' "$guard" "$dir/broker.ready" &
broker=$!
echo "$broker" > "$dir/broker.pid"
for _ in $(seq 1 400); do [[ -e "$dir/broker.ready" ]] && break; sleep 0.05; done
"{backend}" --port 0 --endpoint-file "$dir/research-ui.endpoint" \
  --active-endpoint-file "$REB_ACTIVE_ENDPOINT_FILE" \
  --store "$dir/events.jsonl" --trace-store "$dir/trace.jsonl" \
  --signal-store "$dir/signals.jsonl" --artifacts "$dir/artifacts" \
  --api-collection "$dir/c.json" --local-analyst "$dir/a.json" \
  --js-invocation-site-store "$REB_JS_INVOCATION_SITE_STORE" \
  --socket "$TEST_BROKER_SOCKET" --brave-binary "$REB_BRAVE_BINARY" \
  --brave-profile "$dir/profile" --launcher-pid "$$" ${{labels[@]+"${{labels[@]}}"}} >/dev/null 2>&1 &
backend=$!
trap 'kill "$broker" 2>/dev/null || true; wait "$broker" 2>/dev/null || true; kill "$backend" 2>/dev/null; wait "$backend" 2>/dev/null; echo ended > "$dir/ended"; exit 0' TERM
for _ in $(seq 1 400); do [[ -s "$dir/research-ui.endpoint" ]] && break; sleep 0.05; done
echo "Origin Trace live session $(basename "$dir")"
wait "$backend"
"#,
                backend = env!("CARGO_BIN_EXE_origin-trace-backend")
            ),
        )
        .unwrap();
        for script in [&brave, &launcher] {
            std::fs::set_permissions(script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            home,
            sessions,
            socket,
            record,
            _broker: broker,
            root,
        }
    }

    /// `reb-api mcp` that may start sessions, run from a shell whose
    /// environment carries every capture switch the packaged app sets. None
    /// of them may reach an agent session.
    fn mcp(&self) -> Mcp {
        let mut command = Command::new(env!("CARGO_BIN_EXE_reb-api"));
        command
            .args([
                "mcp",
                "--allow-effects",
                "--allow-session-start",
                "--require-live",
                "--timeout",
                "15",
            ])
            .env("HOME", &self.home)
            .env(
                "REB_LIVE_SESSION_SCRIPT",
                self.root.path().join("launcher.sh"),
            )
            .env("REB_LIVE_SESSION_ROOT", &self.sessions)
            .env("REB_BRAVE_BINARY", self.root.path().join("brave.sh"))
            .env("REB_CONSOLE_DOCUMENT_START", "1")
            .env("REB_CAPTURE_REQUEST_CONTENT", "1")
            .env(
                "REB_NATIVE_JS_INVOCATION_SITES",
                self.root.path().join("sites.json"),
            )
            .env("REB_NATIVE_JS_INVOCATION_DIGESTS", "1")
            .env("REB_NATIVE_JS_INVOCATION_IF_SUPPORTED", "1")
            .env("REB_NATIVE_REQUEST_STACKS", "1")
            .env("REB_NATIVE_REQUEST_STACKS_IF_SUPPORTED", "1")
            .env("REB_REQUEST_CONTENT_BUDGET_MIB", "999")
            .env(
                "REB_JS_INVOCATION_SITE_STORE",
                self.root.path().join("app-sites.json"),
            )
            .env("TEST_BROKER_SOCKET", &self.socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        Mcp::from_command(&mut command)
    }

    fn session(&self, id: &str) -> std::path::PathBuf {
        self.sessions.join(id)
    }

    fn agent_sessions(&self) -> std::path::PathBuf {
        self.home.join(".config/origin-trace/agent-sessions")
    }

    fn wait_ended(&self, id: &str) {
        let path = self.session(id).join("ended");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "the launcher was not asked to stop"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The agent path end to end: an unbound connection starts a session with
/// named options, is moved to that exact backend, opens a URL in its capture
/// browser, ends it, and is unbound again.
#[cfg(unix)]
#[test]
fn an_agent_starts_drives_and_ends_its_own_live_session() {
    let fixture = AgentFixture::new();
    let mut mcp = fixture.mcp();
    let listed = mcp.request("tools/list", json!({}));
    let names = tool_names(&listed);
    assert!(names.iter().any(|name| name == "start_live_session"));
    assert!(names.iter().any(|name| name == "session_action"));
    let start = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "start_live_session")
        .unwrap();
    assert_eq!(start["annotations"]["openWorldHint"], true);
    assert_eq!(start["inputSchema"]["additionalProperties"], false);
    // Sensitive capture is offered, behind its explicit confirmation.
    for option in ["canvas_images", "request_content", "js_invocation_digests"] {
        assert!(start["inputSchema"]["properties"].get(option).is_some());
    }

    let unbound = mcp.request("tools/call", json!({"name": "get_events"}));
    assert_eq!(unbound["result"]["isError"], true);
    assert!(tool_text(&unbound).contains("No live session is bound"));

    let refused = mcp.request(
        "tools/call",
        json!({"name": "start_live_session", "arguments": {"guest_adapter": "/tmp/recipe.json"}}),
    );
    assert_eq!(refused["result"]["isError"], true);
    assert!(tool_text(&refused).contains("requires wasm_dispatch"));
    let sensitive = mcp.request(
        "tools/call",
        json!({"name": "start_live_session", "arguments": {"canvas_images": true}}),
    );
    assert_eq!(sensitive["result"]["isError"], true);
    assert!(tool_text(&sensitive).contains("requires confirm_sensitive_capture"));
    let sessions = &fixture.sessions;
    assert!(!sessions.exists() || std::fs::read_dir(sessions).unwrap().next().is_none());

    let started = mcp.request(
        "tools/call",
        json!({"name": "start_live_session", "arguments": {
            "url": "https://example.test/page", "wasm_dispatch": true, "timeout_seconds": 30
        }}),
    );
    assert_eq!(
        started["result"]["isError"],
        false,
        "{}",
        tool_text(&started)
    );
    let session = &started["result"]["structuredContent"];
    assert_eq!(session["session_id"], "4242");
    assert_eq!(session["url_opened"], true);
    assert_eq!(session["capture_observed"], true);
    assert_eq!(session["canonical_endpoint"], false);
    assert_eq!(session["options"]["wasm_dispatch"], true);
    assert!(session.get("session_dir").is_none());
    assert!(!tool_text(&started).contains(fixture.root.path().to_str().unwrap()));
    let profile = fixture.session("4242").join("profile");
    let arguments = std::fs::read_to_string(&fixture.record).unwrap();
    assert!(arguments.contains(&format!("--user-data-dir={}", profile.display())));
    assert!(
        arguments
            .lines()
            .any(|line| line == "https://example.test/page")
    );
    // Inherited switches reach nothing: no request content, document-start
    // permission, invocation sites, digests or request stacks.
    assert_eq!(
        std::fs::read_to_string(fixture.session("4242").join("options")).unwrap(),
        "1 4095 0 0 0 unset 0\n"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.session("4242").join("stacks")).unwrap(),
        "0 unset\n"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.session("4242").join("content-budget")).unwrap(),
        "unset\n"
    );
    // Nor may it read or change the app's saved invocation sites.
    let store = std::fs::read_to_string(fixture.session("4242").join("site-store")).unwrap();
    assert_eq!(
        store,
        format!(
            "unset {}\n",
            fixture
                .agent_sessions()
                .join("js-invocation-sites-v1.json")
                .display()
        )
    );

    let context = mcp.request("tools/call", json!({"name": "get_session_context"}));
    assert_eq!(context["result"]["isError"], false);
    let context: Value = serde_json::from_str(tool_text(&context)).unwrap();
    assert_eq!(context["instance_id"], session["instance_id"]);
    assert_eq!(context["live_admission"], "ready");
    assert_eq!(
        context["capture_options"],
        json!({"source":"launcher","request_content":false,"canvas_images":false,
            "request_stacks":false,"document_start":"not_permitted",
            "js_invocation":{"state":"not_armed","count":0,"digests":false}})
    );
    let summary = mcp.request("tools/call", json!({"name": "get_session_summary"}));
    assert_eq!(summary["result"]["isError"], false);

    let bad = mcp.request(
        "tools/call",
        json!({"name": "session_action", "arguments": {"body": {"action": "open_url", "url": "ftp://example.test/"}}}),
    );
    assert_eq!(bad["result"]["isError"], true);
    // Starting again replaces the session this connection started.
    let again = mcp.request(
        "tools/call",
        json!({"name": "start_live_session", "arguments": {"timeout_seconds": 30}}),
    );
    assert_eq!(again["result"]["isError"], false, "{}", tool_text(&again));
    assert_eq!(again["result"]["structuredContent"]["session_id"], "4243");
    assert_eq!(
        again["result"]["structuredContent"]["capture_observed"],
        Value::Null
    );
    fixture.wait_ended("4242");
    // At capture expiry the broker removes its socket and exits. Under
    // --require-live other tools are then refused, but ending must still work.
    std::fs::remove_file(&fixture.socket).unwrap();
    let broker = std::fs::read_to_string(fixture.session("4243").join("broker.pid")).unwrap();
    assert!(
        Command::new("kill")
            .arg(broker.trim())
            .status()
            .unwrap()
            .success()
    );
    {
        use std::os::fd::AsRawFd;
        let guard =
            std::fs::File::open(fixture.session("4243").join("events.jsonl.reb-lock-v1")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            assert!(Instant::now() < deadline, "stand-in broker kept its lock");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let expired = mcp.request("tools/call", json!({"name": "get_events"}));
    assert_eq!(expired["result"]["isError"], true);
    let ended = mcp.request(
        "tools/call",
        json!({"name": "session_action", "arguments": {"body": {"action": "end", "confirm": true}}}),
    );
    assert_eq!(ended["result"]["isError"], false, "{}", tool_text(&ended));
    fixture.wait_ended("4243");
    let after = mcp.request("tools/call", json!({"name": "get_events"}));
    assert_eq!(after["result"]["isError"], true);
    assert!(tool_text(&after).contains("No live session is bound"));
}

/// Request content, document-start permission, invocation sites and value
/// digests reach an agent session only when its start names them, each
/// exactly as named, and each is shown in the result, the launch log and the
/// session context. The caller's environment sets all of them and still
/// changes nothing.
#[cfg(unix)]
#[test]
fn agent_session_options_are_named_never_inherited() {
    let fixture = AgentFixture::new();
    let mut mcp = fixture.mcp();
    let site = |offset: u32| {
        format!(
            r#"{{"anchor_offset":{offset},"artifact_id":"12","artifact_sha256":"{a}","byte_offset":{offset},"shape":"function-entry","source_length":456,"source_sha256":"{b}"}}"#,
            a = "a".repeat(64),
            b = "b".repeat(64)
        )
    };
    let site_file = |offsets: &[u32]| {
        format!(
            r#"{{"sites":[{}],"version":1}}"#,
            offsets
                .iter()
                .map(|o| site(*o))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let agent_file = fixture.root.path().join("agent-sites.json");
    std::fs::write(&agent_file, site_file(&[120])).unwrap();
    let call = |mcp: &mut Mcp, arguments: Value| {
        mcp.request(
            "tools/call",
            json!({"name": "start_live_session", "arguments": arguments}),
        )
    };
    // Refusals send nothing and start nothing.
    for (arguments, needle) in [
        (
            json!({"request_content": true}),
            "requires confirm_sensitive_capture",
        ),
        (
            json!({"js_invocation_digests": true, "confirm_sensitive_capture": true}),
            "requires js_invocation_sites or js_invocation_saved_sites",
        ),
        (
            json!({"js_invocation_saved_sites": true, "js_invocation_digests": true}),
            "requires confirm_sensitive_capture",
        ),
        (
            json!({"js_invocation_saved_sites": true, "js_invocation_sites": agent_file}),
            "not both",
        ),
        (json!({"js_invocation_sites": "sites.json"}), "absolute"),
        (
            json!({"request_content": true, "confirm_sensitive_capture": true, "category_mask": 1024}),
            "Network and Artifact",
        ),
        (
            json!({"js_invocation_saved_sites": true}),
            "saved set, which is empty",
        ),
        (
            json!({"request_content_budget_mib": 64}),
            "requires request_content",
        ),
        (
            json!({"request_stacks": true, "category_mask": 256}),
            "request_stacks needs Network and Artifact",
        ),
    ] {
        let refused = call(&mut mcp, arguments.clone());
        assert_eq!(refused["result"]["isError"], true, "{arguments}");
        assert!(
            tool_text(&refused).contains(needle),
            "{arguments}: {}",
            tool_text(&refused)
        );
    }
    let garbage = fixture.root.path().join("garbage.json");
    std::fs::write(&garbage, "{}").unwrap();
    let refused = call(&mut mcp, json!({"js_invocation_sites": garbage}));
    assert!(tool_text(&refused).contains("not a native-js-invocation-sites-v1 file"));
    assert!(
        !fixture.sessions.exists()
            || std::fs::read_dir(&fixture.sessions)
                .unwrap()
                .next()
                .is_none()
    );

    let launch_logs = || {
        let mut logs = std::fs::read_dir(fixture.agent_sessions())
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path().join("launch.log");
                path.is_file().then_some(path)
            })
            .collect::<Vec<_>>();
        logs.sort_by_key(|path| std::fs::metadata(path).unwrap().modified().unwrap());
        logs
    };

    // Document-start permission, request content and a site file the agent
    // wrote, armed from a private copy.
    let started = call(
        &mut mcp,
        json!({"document_start": true, "request_content": true,
            "request_content_budget_mib": 64, "request_stacks": true,
            "confirm_sensitive_capture": true, "js_invocation_sites": agent_file,
            "timeout_seconds": 30}),
    );
    assert_eq!(
        started["result"]["isError"],
        false,
        "{}",
        tool_text(&started)
    );
    let result = &started["result"]["structuredContent"];
    assert_eq!(result["session_id"], "4242");
    assert_eq!(result["js_invocation_sites_armed"], 1);
    for (option, value) in [
        ("document_start", json!(true)),
        ("request_content", json!(true)),
        ("request_content_budget_mib", json!(64)),
        ("request_stacks", json!(true)),
        ("js_invocation_saved_sites", json!(false)),
        ("js_invocation_digests", json!(false)),
        ("canvas_images", json!(false)),
    ] {
        assert_eq!(result["options"][option], value, "{option}");
    }
    let options = std::fs::read_to_string(fixture.session("4242").join("options")).unwrap();
    let fields = options.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields[..5], ["0", "4095", "0", "1", "1"]);
    assert_eq!(fields[6], "0");
    let copy = std::path::Path::new(fields[5]);
    assert_ne!(copy, agent_file.as_path());
    assert!(
        copy.starts_with(fixture.agent_sessions()),
        "{}",
        copy.display()
    );
    assert_eq!(
        std::fs::read_to_string(fixture.session("4242").join("sites")).unwrap(),
        site_file(&[120])
    );
    assert_eq!(
        std::fs::read_to_string(fixture.session("4242").join("stacks")).unwrap(),
        "1 unset\n",
        "named stacks are strict"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.session("4242").join("content-budget")).unwrap(),
        "64\n"
    );
    let log = std::fs::read_to_string(launch_logs().last().unwrap()).unwrap();
    let first = log.lines().next().unwrap();
    let named: Value =
        serde_json::from_str(first.strip_prefix("Agent session options: ").unwrap()).unwrap();
    assert_eq!(named["document_start"], true);
    assert_eq!(named["request_content"], true);
    assert_eq!(named["js_invocation_site_count"], 1);
    let context = mcp.request("tools/call", json!({"name": "get_session_context"}));
    let context: Value = serde_json::from_str(tool_text(&context)).unwrap();
    assert_eq!(
        context["capture_options"],
        json!({"source":"launcher","request_content":true,"canvas_images":false,
            "request_stacks":true,"document_start":"permitted",
            "js_invocation":{"state":"armed","count":1,"digests":false}})
    );

    // The agent sessions' own saved set, written as js_invocation_site_action
    // writes it, arms with digests. The app's set is never read.
    std::fs::write(
        fixture.agent_sessions().join("js-invocation-sites-v1.json"),
        site_file(&[120, 200]),
    )
    .unwrap();
    std::fs::write(
        fixture.root.path().join("app-sites.json"),
        site_file(&[300]),
    )
    .unwrap();
    let saved = call(
        &mut mcp,
        json!({"js_invocation_saved_sites": true, "js_invocation_digests": true,
            "confirm_sensitive_capture": true, "timeout_seconds": 30}),
    );
    assert_eq!(saved["result"]["isError"], false, "{}", tool_text(&saved));
    assert_eq!(saved["result"]["structuredContent"]["session_id"], "4243");
    assert_eq!(
        saved["result"]["structuredContent"]["js_invocation_sites_armed"],
        2
    );
    fixture.wait_ended("4242");
    let options = std::fs::read_to_string(fixture.session("4243").join("options")).unwrap();
    let fields = options.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields[..5], ["0", "4095", "0", "0", "0"]);
    assert_eq!(fields[6], "1");
    assert_eq!(
        std::fs::read_to_string(fixture.session("4243").join("sites")).unwrap(),
        site_file(&[120, 200])
    );
    assert_eq!(
        std::fs::read_to_string(fixture.session("4243").join("content-budget")).unwrap(),
        "unset\n"
    );
    let context = mcp.request("tools/call", json!({"name": "get_session_context"}));
    let context: Value = serde_json::from_str(tool_text(&context)).unwrap();
    assert_eq!(
        context["capture_options"]["js_invocation"],
        json!({"state":"armed","count":2,"digests":true})
    );
    assert_eq!(
        context["capture_options"]["document_start"],
        "not_permitted"
    );
    assert_eq!(context["capture_options"]["request_content"], false);
    assert_eq!(context["capture_options"]["request_stacks"], false);

    let ended = mcp.request(
        "tools/call",
        json!({"name": "session_action", "arguments": {"body": {"action": "end", "confirm": true}}}),
    );
    assert_eq!(ended["result"]["isError"], false, "{}", tool_text(&ended));
    fixture.wait_ended("4243");
}

/// The CLI keeps the start tool's gates: a request content budget needs
/// request content, which needs the sensitive-capture confirmation.
#[cfg(unix)]
#[test]
fn session_start_cli_gates_the_request_content_budget() {
    for (arguments, needle) in [
        (
            &["--request-content-budget-mib", "64"][..],
            "--request-content",
        ),
        (
            &["--request-content", "--request-content-budget-mib", "64"][..],
            "--confirm-sensitive-capture",
        ),
        (
            &[
                "--request-content",
                "--confirm-sensitive-capture",
                "--request-content-budget-mib",
                "4097",
            ][..],
            "from 1 to 4096",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
            .args(["session", "start"])
            .args(arguments)
            .env("REB_LIVE_SESSION_SCRIPT", "/nonexistent/launcher.sh")
            .env_remove("REB_LIVE_SESSION_ROOT")
            .output()
            .unwrap();
        assert!(!output.status.success(), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(needle), "{arguments:?}: {stderr}");
    }
}

#[test]
fn session_tools_need_their_flag_and_a_session_started_here() {
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["mcp", "--allow-session-start"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--allow-effects"));
    let server = Server::start();
    let mut mcp = Mcp::start(&server.url, true);
    let names = tool_names(&mcp.request("tools/list", json!({})));
    assert!(!names.iter().any(|name| name == "session_action"));
    assert!(!names.iter().any(|name| name == "start_live_session"));
    let hidden = mcp.request("tools/call", json!({"name": "start_live_session"}));
    assert_eq!(hidden["error"]["code"], -32602);
    let end = json!({"name": "session_action", "arguments": {"body": {"action": "end", "confirm": true}}});
    let gated = mcp.request("tools/call", end.clone());
    assert_eq!(gated["error"]["code"], -32602);
    // With session start allowed, a connection bound to a session it did not
    // start still cannot drive or end that session.
    let mut starter = Mcp::start_with(vec![
        "mcp".into(),
        "--base-url".into(),
        server.url.clone(),
        "--allow-effects".into(),
        "--allow-session-start".into(),
    ]);
    let refused = starter.request("tools/call", end);
    assert_eq!(refused["result"]["isError"], true);
    assert!(tool_text(&refused).contains("acts only on a session this connection started"));
}
