//! Real private helper reached through the shipped HTTP routes and reb-api.
//! No fake VM, interpreter, transport, or response fixture substitutes for it.
#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::LazyLock,
    time::{Duration, Instant},
};

static SPEC: LazyLock<Value> =
    LazyLock::new(|| serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap());
static GOLDENS: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../tools/fixtures/owned-vm-golden-transitions-v1.json"
    ))
    .unwrap()
});

struct Server {
    child: Child,
    root: tempfile::TempDir,
    url: String,
    client: reqwest::Client,
}
impl Drop for Server {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        // The backend's SIGTERM handler stops/reaps its separately owned helper
        // before exiting. Abruptly killing only the backend would skip that path.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Server {
    async fn start(helper: &Path) -> Self {
        let root = tempfile::tempdir().unwrap();
        let endpoint = root.path().join("endpoint");
        let mut command = Command::new(env!("CARGO_BIN_EXE_origin-trace-backend"));
        command
            .args(["--port", "0", "--endpoint-file"])
            .arg(&endpoint)
            .arg("--owned-vm-fixture")
            .arg(helper)
            // No unrelated worker availability subprocess is needed by this test.
            .arg("--analyst-runner")
            .arg(env!("CARGO_BIN_EXE_origin-trace-backend"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
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
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let child = command.spawn().unwrap();
        let mut server = Self {
            child,
            root,
            url: String::new(),
            client,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(url) = std::fs::read_to_string(&endpoint) {
                server.url = url.trim().to_owned();
                break;
            }
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "Backend exited before publishing its endpoint"
            );
            assert!(
                Instant::now() < deadline,
                "Backend startup exceeded its deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        server
    }
    async fn get(&self, path: &str) -> Value {
        let response = self
            .client
            .get(format!("{}{path}", self.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let value = response.json().await.unwrap();
        assert_view(&value);
        value
    }
    async fn action(&self, request: &Value) -> Value {
        assert_schema("OwnedVmDebuggerAction", request);
        let response = self
            .client
            .post(format!("{}/api/vm-debugger/actions", self.url))
            .json(request)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let value = response.json().await.unwrap();
        assert_eq!(status, 200, "HTTP VM control failed: {value}");
        assert_view(&value);
        assert_eq!(value["command_id"], request["command_id"]);
        assert_eq!(value["ack"], "completed");
        value
    }
    async fn rejected(&self, request: &Value, expected_code: &str) {
        let response = self
            .client
            .post(format!("{}/api/vm-debugger/actions", self.url))
            .json(request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 409);
        let value: Value = response.json().await.unwrap();
        assert_schema("Error", &value);
        assert_eq!(value["code"], expected_code);
    }
    fn cli(
        &self,
        operation: &str,
        body: Option<&Value>,
        params: &[String],
        read_only: bool,
    ) -> Value {
        let mut command = Command::new(env!("CARGO_BIN_EXE_reb-api"));
        command.args([
            "call",
            operation,
            "--base-url",
            &self.url,
            "--timeout",
            "10",
        ]);
        if read_only {
            command.arg("--read-only");
        }
        if let Some(body) = body {
            let path = self.root.path().join("explicit-cli-request.json");
            std::fs::write(&path, serde_json::to_vec(body).unwrap()).unwrap();
            command.arg("--body-file").arg(path);
        }
        for param in params {
            command.arg("--param").arg(param);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_view(&value);
        if let Some(body) = body {
            assert_eq!(value["command_id"], body["command_id"]);
            assert_eq!(value["ack"], "completed");
        }
        value
    }
    async fn stop_gracefully(mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "Backend graceful shutdown failed: {status}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Backend failed to stop its owned helper"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
fn assert_schema(name: &str, value: &Value) {
    let document =
        json!({"$ref":format!("#/components/schemas/{name}"),"components":SPEC["components"]});
    let validator = jsonschema::validator_for(&document).unwrap();
    if let Err(error) = validator.validate(value) {
        panic!("{name}: {error}");
    }
}
fn assert_view(value: &Value) {
    assert_schema("OwnedVmDebuggerState", value);
}
fn count(view: &Value) -> u64 {
    view["session"]["executed_count"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}
fn request(view: &Value, action: &str, command: &str) -> Value {
    let mut body = json!({"action":action,"command_id":command});
    for field in [
        "backend_instance_id",
        "session_id",
        "run_id",
        "run_generation",
    ] {
        body[field] = view["session"][field].clone();
    }
    if matches!(action, "run" | "step") {
        body["expected_control_revision"] = view["session"]["control_revision"].clone();
    }
    if action == "step" {
        body["expected_executed_count"] = view["session"]["executed_count"].clone();
    }
    body
}
fn selector(view: &Value) -> Vec<String> {
    [
        "backend_instance_id",
        "session_id",
        "run_id",
        "run_generation",
    ]
    .into_iter()
    .map(|key| format!("{key}={}", view["session"][key].as_str().unwrap()))
    .collect()
}
fn assert_golden(view: &Value, fixture: &str) {
    assert_view(view);
    let completed = count(view) as usize;
    assert!(completed <= 9);
    let session = &view["session"];
    let golden = &GOLDENS[fixture];
    assert_eq!(session["fixture"], fixture);
    assert_eq!(session["program_id"], format!("owned-{fixture}-v1"));
    assert_eq!(session["execution_state_known"], true);
    assert_eq!(session["initial_snapshot"], golden["initial"]);
    assert_eq!(
        session["current_snapshot"],
        if completed == 0 {
            golden["initial"].clone()
        } else {
            golden["transitions"][completed - 1]["after"].clone()
        }
    );
    let records = session["records"].as_array().unwrap();
    assert_eq!(records.len(), completed);
    assert_eq!(session["retained_count"], completed.to_string());
    let mut previous_tick = 0;
    for (index, observed) in records.iter().enumerate() {
        let mut observed = observed.clone();
        let tick: u64 = observed["tick"].as_str().unwrap().parse().unwrap();
        assert!(tick > 0 && tick >= previous_tick);
        previous_tick = tick;
        observed.as_object_mut().unwrap().remove("tick");
        assert_eq!(observed, golden["transitions"][index]);
    }
    assert_eq!(
        session["recorder"]["stats"]["attempted"],
        completed.to_string()
    );
    assert_eq!(
        session["recorder"]["stats"]["recorded"],
        completed.to_string()
    );
    for key in [
        "full",
        "malformed",
        "wrong_document",
        "stale_generation",
        "exhausted",
        "expired",
        "partial",
    ] {
        assert_eq!(session["recorder"]["stats"][key], "0");
    }
}

#[tokio::test]
#[ignore = "requires REB_OWNED_VM_TEST_HELPER pointing to the built native helper"]
async fn owned_vm_real_helper_http_cli_lifecycle() {
    let helper = PathBuf::from(
        std::env::var_os("REB_OWNED_VM_TEST_HELPER").expect("Set REB_OWNED_VM_TEST_HELPER"),
    );
    assert!(helper.is_file(), "Build the owned VM native helper first");
    let server = Server::start(&helper).await;
    let idle = server.get("/api/vm-debugger").await;
    assert_eq!(idle["available"], true);
    assert!(idle["session"].is_null());
    let discovery = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["list", "--json"])
        .output()
        .unwrap();
    assert!(discovery.status.success());
    let discovery: Value = serde_json::from_slice(&discovery.stdout).unwrap();
    for (id, eligible) in [
        ("get_vm_debugger", true),
        ("get_vm_debugger_trace", true),
        ("vm_debugger_action", false),
    ] {
        let operation = discovery["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["operation_id"] == id)
            .unwrap();
        assert_eq!(operation["read_only_eligible"], eligible);
    }
    for fixture in ["register", "stack"] {
        let create =
            json!({"action":"create","command_id":format!("create-{fixture}"),"fixture":fixture});
        let mut view = if fixture == "register" {
            server.action(&create).await
        } else {
            server.cli("vm_debugger_action", Some(&create), &[], false)
        };
        assert_eq!(view["session"]["state"], "paused");
        assert_eq!(count(&view), 0);
        assert_golden(&view, fixture);
        tokio::time::sleep(Duration::from_millis(600)).await;
        let untouched = server.get("/api/vm-debugger").await;
        assert_eq!(untouched["session"], view["session"]);
        assert_eq!(server.cli("get_vm_debugger", None, &[], true), untouched);
        let step = request(&view, "step", "first-step");
        view = server.cli("vm_debugger_action", Some(&step), &[], false);
        assert_eq!(count(&view), 1);
        assert_golden(&view, fixture);
        server.rejected(&step, "stale_generation").await;
        assert_eq!(count(&server.get("/api/vm-debugger").await), 1);
        view = server.action(&request(&view, "run", "run")).await;
        assert_eq!(view["session"]["state"], "running");
        assert_eq!(count(&view), 1);
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                view = server.get("/api/vm-debugger").await;
                if count(&view) >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        view = server.action(&request(&view, "pause", "pause")).await;
        assert_eq!(view["session"]["state"], "paused");
        assert!(count(&view) >= 2 && count(&view) < 9);
        assert_golden(&view, fixture);
        let paused_session = view["session"].clone();
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            server.get("/api/vm-debugger").await["session"],
            paused_session
        );
        let trace = server.cli("get_vm_debugger_trace", None, &selector(&view), true);
        assert_eq!(trace["session"], paused_session);
        let trace_http = server
            .get(&format!(
                "/api/vm-debugger/trace?{}",
                selector(&view).join("&")
            ))
            .await;
        assert_eq!(trace, trace_http);
        // Every control is blocked locally in read-only mode, with a valid
        // explicit body, and the paused native state remains byte-for-byte equal.
        for action in ["create", "run", "pause", "step", "stop", "reset", "close"] {
            let body = if action == "create" {
                create.clone()
            } else {
                request(&view, action, action)
            };
            let path = server.root.path().join("read-only.json");
            std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
            let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
                .args([
                    "call",
                    "vm_debugger_action",
                    "--read-only",
                    "--base-url",
                    &server.url,
                ])
                .arg("--body-file")
                .arg(path)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&output.stderr).contains("No request was sent"));
            assert_eq!(
                server.get("/api/vm-debugger").await["session"],
                paused_session
            );
        }
        while count(&view) < 9 {
            let next = count(&view) + 1;
            let body = request(&view, "step", &format!("step-{next}"));
            view = if next % 2 == 0 {
                server.action(&body).await
            } else {
                server.cli("vm_debugger_action", Some(&body), &[], false)
            };
            assert_eq!(count(&view), next);
            assert_golden(&view, fixture);
        }
        assert_eq!(view["session"]["state"], "halted");
        for action in ["run", "step"] {
            server
                .rejected(&request(&view, action, "halted-reject"), "state_conflict")
                .await;
        }
        assert_eq!(count(&server.get("/api/vm-debugger").await), 9);
        let old = view.clone();
        view = server.cli(
            "vm_debugger_action",
            Some(&request(&view, "reset", "reset")),
            &[],
            false,
        );
        assert_eq!(view["session"]["state"], "paused");
        assert_eq!(count(&view), 0);
        assert_golden(&view, fixture);
        assert_eq!(view["session"]["session_id"], old["session"]["session_id"]);
        assert_ne!(view["session"]["run_id"], old["session"]["run_id"]);
        assert_ne!(
            view["session"]["run_generation"],
            old["session"]["run_generation"]
        );
        for action in ["pause", "step", "stop", "reset", "close"] {
            server
                .rejected(&request(&old, action, "stale"), "stale_generation")
                .await;
        }
        let stale_trace = server
            .client
            .get(format!(
                "{}/api/vm-debugger/trace?{}",
                server.url,
                selector(&old).join("&")
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(stale_trace.status(), 409);
        assert_eq!(count(&server.get("/api/vm-debugger").await), 0);
        view = server.action(&request(&view, "step", "before-stop")).await;
        view = server.action(&request(&view, "stop", "stop")).await;
        assert_eq!(view["session"]["state"], "stopped");
        assert_eq!(count(&view), 1);
        assert_golden(&view, fixture);
        let stopped = view["session"].clone();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(server.get("/api/vm-debugger").await["session"], stopped);
        view = server
            .action(&request(&view, "reset", "reset-stopped"))
            .await;
        assert_eq!(count(&view), 0);
        assert_golden(&view, fixture);
        let closed = server.cli(
            "vm_debugger_action",
            Some(&request(&view, "close", "close")),
            &[],
            false,
        );
        assert!(closed["session"].is_null());
        assert!(server.get("/api/vm-debugger").await["session"].is_null());
    }
    // No browser/evidence producer or unrelated worker was needed or invoked.
    for file in [
        "events.jsonl",
        "trace.jsonl",
        "signals.jsonl",
        "collection.json",
        "analyst.json",
    ] {
        assert!(!server.root.path().join(file).exists());
    }
    server.stop_gracefully().await;
}
