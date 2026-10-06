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
        Self::start_with_args(&[]).await
    }
    async fn start_with_args(args: &[String]) -> Self {
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
        let mut child = child.args(args).spawn().unwrap();
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
fn specification() -> Value {
    serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap()
}
fn assert_schema(spec: &Value, schema: &Value, value: &Value, label: &str) {
    let document = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "$ref":"#/checked",
        "checked":schema,
        "components":spec["components"]
    });
    let validator = jsonschema::validator_for(&document).unwrap();
    if let Err(error) = validator.validate(value) {
        panic!("{label}: {error}");
    }
}
async fn assert_contract_response(
    response: reqwest::Response,
    method: &str,
    route: &str,
    expected_status: u16,
) -> Vec<u8> {
    assert_eq!(
        response.status().as_u16(),
        expected_status,
        "{method} {route}"
    );
    let spec = specification();
    let operation = &spec["paths"][route][method];
    assert!(
        operation["operationId"].is_string(),
        "Unknown operation: {method} {route}"
    );
    let contract = &operation["responses"][expected_status.to_string()];
    assert!(
        contract.is_object(),
        "Undocumented status: {method} {route} {expected_status}"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    for (name, header) in contract["headers"].as_object().into_iter().flatten() {
        let value = response.headers().get(name).unwrap_or_else(|| {
            panic!("Missing declared header: {method} {route} {expected_status} {name}")
        });
        assert_schema(
            &spec,
            &header["schema"],
            &json!(value.to_str().unwrap()),
            name,
        );
    }
    let content_type = response.headers().get("content-type").map(|value| {
        value
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .trim()
            .to_owned()
    });
    let bytes = response.bytes().await.unwrap().to_vec();
    if expected_status == 304 {
        assert!(bytes.is_empty());
        assert!(contract.get("content").is_none());
    } else {
        let content_type = content_type.expect("Response Content-Type");
        let schema = &contract["content"][&content_type]["schema"];
        assert!(
            !schema.is_null(),
            "Undocumented content type: {method} {route} {content_type}"
        );
        if content_type == "application/json" {
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_schema(
                &spec,
                schema,
                &value,
                &format!("{method} {route} {expected_status}"),
            );
        } else {
            assert_eq!(content_type, "application/octet-stream");
            assert_eq!(schema["type"], "string");
            assert_eq!(schema["format"], "binary");
        }
    }
    bytes
}
#[test]
fn openapi_references_and_debugger_action_result_maps_are_consistent() {
    use std::collections::BTreeSet;
    fn references(spec: &Value, value: &Value) {
        match value {
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    assert!(
                        reference.starts_with("#/"),
                        "Nonlocal reference: {reference}"
                    );
                    assert!(
                        spec.pointer(&reference[1..]).is_some(),
                        "Unresolved reference: {reference}"
                    );
                }
                for value in object.values() {
                    references(spec, value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    references(spec, value);
                }
            }
            _ => (),
        }
    }
    let spec = specification();
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(spec["security"], json!([]));
    references(&spec, &spec);
    let mut ids = BTreeSet::new();
    for item in spec["paths"].as_object().unwrap().values() {
        for operation in item.as_object().unwrap().values() {
            let id = operation["operationId"].as_str().unwrap();
            assert!(ids.insert(id), "Duplicate operation ID: {id}");
        }
    }
    assert_eq!(ids.len(), 22, "Review route coverage when the API changes");
    let schemas = &spec["components"]["schemas"];
    let actions = schemas["DebuggerAction"]["oneOf"].as_array().unwrap();
    let results = &schemas["DebuggerResult"];
    let mappings = results["x-action-results"].as_object().unwrap();
    let mut names = BTreeSet::new();
    for action in actions {
        let name = action["properties"]["action"]["const"].as_str().unwrap();
        assert!(names.insert(name), "Duplicate action: {name}");
        let reference = action["x-result-schema"].as_str().unwrap();
        assert!(
            spec.pointer(&reference[1..]).is_some(),
            "Unresolved action result: {name}"
        );
        assert_eq!(
            mappings[name]["$ref"], reference,
            "Mismatched result: {name}"
        );
        assert!(
            results["oneOf"]
                .as_array()
                .unwrap()
                .contains(&mappings[name])
        );
    }
    assert_eq!(
        names.len(),
        59,
        "Review debugger action coverage when the dispatcher changes"
    );
    assert_eq!(names, mappings.keys().map(String::as_str).collect());
    let empty: Value = serde_json::from_str(include_str!("../assets/debugger-empty.json")).unwrap();
    // These two actions return state, unlike the generic acknowledgement.
    // The clear action is also exercised through live HTTP below; stopping an
    // active memory trace still needs the separate browser end-to-end gate.
    for (action, field, state) in [
        (
            "clear_request_interception_result",
            "experiment",
            "request_interception",
        ),
        ("stop_memory_origin_trace", "trace", "memory_origin_trace"),
    ] {
        assert_schema(
            &spec,
            &mappings[action],
            &json!({"ok":true,field:empty[state],"generation":0}),
            action,
        );
    }
    // Source-backed fixtures for the disk-read deadlines in evidence.rs. The
    // HTTP suite does not deliberately stall artifact I/O for thirty seconds.
    let deadline_schema = &spec["paths"]["/api/artifacts/{artifact_id}/content"]["get"]["responses"]
        ["408"]["content"]["application/json"]["schema"];
    assert_eq!(deadline_schema["$ref"], "#/components/schemas/Error");
    for message in [
        "Artifact manifest read exceeded its deadline",
        "Artifact verification exceeded its deadline",
    ] {
        assert_schema(
            &spec,
            deadline_schema,
            &json!({"error":message,"code":"unspecified","details":{}}),
            message,
        );
    }
}
#[test]
fn execution_metadata_covers_operations_actions_and_dispatch_without_safe_defaults() {
    use std::collections::BTreeSet;
    let spec = specification();
    assert_eq!(
        spec["x-reb-execution-policy"],
        json!({
            "version":1,"advisory":true,"automatic_retry":"never","idempotence":"unproven"
        })
    );
    let schema = &spec["components"]["schemas"]["RebExecutionMetadata"];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let check = |entry: &Value, label: &str| {
        assert_schema(&spec, schema, entry, label);
        let mut prerequisites = BTreeSet::new();
        for prerequisite in entry["prerequisites"].as_array().unwrap() {
            assert!(
                prerequisites.insert(prerequisite["id"].as_str().unwrap()),
                "Duplicate prerequisite: {label}"
            );
        }
        for source in entry["sources"].as_array().unwrap() {
            let path = source["path"].as_str().unwrap();
            assert!(path.starts_with("apps/origin-trace-backend/src/"));
            let contents = std::fs::read_to_string(root.join(path)).unwrap();
            let symbol = source["symbol"]
                .as_str()
                .unwrap()
                .rsplit("::")
                .next()
                .unwrap();
            assert!(
                contents.contains(&format!("fn {symbol}(")),
                "Missing source symbol: {path}::{symbol}"
            );
        }
    };
    let mut operation_count = 0;
    for item in spec["paths"].as_object().unwrap().values() {
        for operation in item.as_object().unwrap().values() {
            let label = operation["operationId"].as_str().unwrap();
            check(&operation["x-reb-execution"], label);
            assert_eq!(
                operation["x-reb-execution-schema"]["$ref"],
                "#/components/schemas/RebExecutionMetadata"
            );
            assert!(
                operation["x-reb-execution"]["prerequisites"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["id"] == "local-request")
            );
            operation_count += 1;
        }
    }
    assert_eq!(operation_count, 22);
    let schemas = &spec["components"]["schemas"];
    let mut action_count = 0;
    for name in [
        "CaptureAction",
        "DecoderAction",
        "CollectionAction",
        "AnalystAction",
        "DebuggerAction",
        "NativeConsoleAction",
    ] {
        let variants = schemas[name]["oneOf"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![schemas[name].clone()]);
        let mut names = BTreeSet::new();
        for variant in variants {
            let action = variant["properties"]["action"]["const"].as_str().unwrap();
            assert!(
                names.insert(action.to_owned()),
                "Duplicate action: {name}/{action}"
            );
            let entry = &variant["x-reb-execution"];
            check(entry, action);
            assert_eq!(entry["kind"], "action");
            let fields = entry["confirmations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|confirmation| {
                    let field = confirmation["field"].as_str().unwrap();
                    assert!(
                        variant["properties"].get(field).is_some(),
                        "Unknown confirmation: {action}/{field}"
                    );
                    jsonschema::validator_for(&confirmation["when"]).unwrap();
                    field
                })
                .collect::<BTreeSet<_>>();
            let expected = variant["properties"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .filter(|field| field.contains("confirm"))
                .collect::<BTreeSet<_>>();
            assert_eq!(fields, expected, "Confirmation coverage: {action}");
            action_count += 1;
        }
    }
    assert_eq!(action_count, 74);
    // Source checks intentionally follow the dispatch syntax. If it changes,
    // audit the new handler before updating this narrow test helper.
    fn arms<'a>(source: &'a str, start: &str, end: &str, indent: usize) -> BTreeSet<&'a str> {
        let body = source
            .split_once(start)
            .unwrap()
            .1
            .split_once(end)
            .unwrap()
            .0;
        let prefix = " ".repeat(indent);
        body.lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .filter(|line| line.starts_with('"') || line.starts_with("| \""))
            .flat_map(|line| {
                line.split("=>")
                    .next()
                    .unwrap()
                    .split('"')
                    .skip(1)
                    .step_by(2)
            })
            .collect()
    }
    let action_names = |name: &str| {
        schemas[name]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .map(|variant| variant["properties"]["action"]["const"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
    };
    for (name, source, start, end, indent) in [
        (
            "DebuggerAction",
            include_str!("../src/debugger/mod.rs"),
            "        match action {",
            "    async fn breakpoint",
            12,
        ),
        (
            "DecoderAction",
            include_str!("../src/decoder.rs"),
            "        match action {",
            "        if !worker::executable",
            12,
        ),
        (
            "AnalystAction",
            include_str!("../src/app.rs"),
            "\"/api/local-analyst/actions\" => match",
            "\"/api/debugger/actions\"",
            16,
        ),
    ] {
        assert_eq!(
            action_names(name),
            arms(source, start, end, indent),
            "Dispatch coverage: {name}"
        );
    }
    assert_eq!(action_names("DebuggerAction").len(), 59);
    for (name, source, pattern) in [
        (
            "NativeConsoleAction",
            include_str!("../src/native_console.rs"),
            r#"action\s*(?:==|!=)\s*"([a-z_]+)""#,
        ),
        (
            "CaptureAction",
            include_str!("../src/app.rs"),
            r#""action":"([a-z_]+)""#,
        ),
    ] {
        let pattern = regex::Regex::new(pattern).unwrap();
        let names = pattern
            .captures_iter(source)
            .map(|capture| capture.get(1).unwrap().as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(action_names(name), names, "Dispatch coverage: {name}");
    }
    let workspace = include_str!("../src/workspace.rs")
        .split_once("let expected_action = match kind {")
        .unwrap()
        .1
        .split_once("        };")
        .unwrap()
        .0;
    assert_eq!(
        workspace
            .lines()
            .filter_map(|line| line.split('"').nth(1))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            schemas["CollectionAction"]["properties"]["action"]["const"]
                .as_str()
                .unwrap(),
            "replace_local_analyst_workspace"
        ])
    );
}

#[test]
fn execution_metadata_keeps_destructive_conditional_and_unproven_effects_visible() {
    let spec = specification();
    let action = |schema: &str, name: &str| {
        spec["components"]["schemas"][schema]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["properties"]["action"]["const"] == name)
            .unwrap()["x-reb-execution"]
            .clone()
    };
    let effect = |entry: &Value, name: &str| {
        entry["effects"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|v| v == name)
            || entry["state_dependent_effects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|condition| {
                    condition["effects"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| v == name)
                })
    };
    assert!(effect(&action("CaptureAction", "clear"), "data-discard"));
    assert_eq!(
        action("CaptureAction", "clear")["confirmations"][0]["field"],
        "confirm"
    );
    let vm = &spec["paths"]["/api/analysis/vm"]["get"]["x-reb-execution"];
    assert!(effect(vm, "filesystem-write"));
    assert!(!vm["state_dependent_effects"].as_array().unwrap().is_empty());
    let native_state = &spec["paths"]["/api/native-console"]["get"]["x-reb-execution"];
    for kind in ["process-stop", "filesystem-write", "data-discard"] {
        assert!(effect(native_state, kind));
    }
    for name in ["cancel_automation_recipe", "disarm_automation_recipes"] {
        assert!(effect(&action("DebuggerAction", name), "network-access"));
    }
    for kind in ["analysis", "process-launch", "process-stop"] {
        assert!(effect(
            &action("DebuggerAction", "configure_runtime_field_test"),
            kind
        ));
    }
    for name in [
        "search_heap_snapshot",
        "capture_heap_diff_baseline",
        "compare_heap_diff",
        "clear_heap_diff_baseline",
    ] {
        assert!(effect(&action("DebuggerAction", name), "filesystem-write"));
    }
    for name in [
        "add_watch",
        "evaluate_watches",
        "search_live_objects",
        "run_repeater_request",
    ] {
        assert!(effect(&action("DebuggerAction", name), "code-execution"));
    }
    for entry in [
        action("DebuggerAction", "run_repeater_request"),
        action("NativeConsoleAction", "evaluate"),
    ] {
        assert!(entry["confirmations"].as_array().unwrap().is_empty());
    }
    assert!(
        !action("NativeConsoleAction", "runtime")["uncertainties"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for name in [
        "/api/events",
        "/api/artifacts",
        "/api/api-collection",
        "/api/local-analyst",
    ] {
        assert!(!effect(
            &spec["paths"][name]["get"]["x-reb-execution"],
            "browser-control"
        ));
    }
    let confirmation = action("DecoderAction", "jwt_create")["confirmations"][0].clone();
    let predicate = jsonschema::validator_for(&confirmation["when"]).unwrap();
    assert!(predicate.is_valid(&json!({"algorithm":"none"})));
    assert!(!predicate.is_valid(&json!({"algorithm":"HS256"})));
    assert!(!predicate.is_valid(&json!({})));
    let confirmation =
        action("DebuggerAction", "configure_runtime_field_test")["confirmations"][0].clone();
    let predicate = jsonschema::validator_for(&confirmation["when"]).unwrap();
    assert!(predicate.is_valid(&json!({"enabled":true})));
    assert!(!predicate.is_valid(&json!({"enabled":false})));
    let run = action("AnalystAction", "run_local_analyst_script");
    let sensitive = run["confirmations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["field"] == "confirmed_sensitive")
        .unwrap();
    let predicate = jsonschema::validator_for(&sensitive["when"]).unwrap();
    assert!(predicate.is_valid(&json!({"evidence":{"selected_artifact":{"sensitive":true}}})));
    assert!(!predicate.is_valid(&json!({"evidence":{"selected_artifact":null}})));
    // Empty records or invented-safe effects are not valid metadata.
    let schema =
        jsonschema::validator_for(&spec["components"]["schemas"]["RebExecutionMetadata"]).unwrap();
    assert!(!schema.is_valid(&json!({})));
    let mut altered = action("CaptureAction", "clear");
    altered["effects"] = json!(["read-only"]);
    assert!(!schema.is_valid(&altered));
}

#[tokio::test]
async fn openapi_responses_match_live_local_http_and_conditional_reads() {
    let server = Server::start().await;
    for route in [
        "/api/health",
        "/api/decoder",
        "/api/api-collection",
        "/api/local-analyst",
        "/api/local-analyst/runner",
        "/api/debugger",
        "/api/native-console",
        "/api/events",
        "/api/artifacts",
        "/api/analysis/vm",
    ] {
        let response = server.get(route).await;
        let etag = response.headers().get("etag").cloned();
        assert_contract_response(response, "get", route, 200).await;
        if let Some(etag) = etag {
            let response = server
                .client
                .get(format!("{}{route}", server.url))
                .header("if-none-match", etag)
                .send()
                .await
                .unwrap();
            assert_contract_response(response, "get", route, 304).await;
        }
    }
    for (path, route, status) in [
        ("/api/events?limit=oops", "/api/events", 400),
        ("/api/events?limit=1&limit=2", "/api/events", 400),
        ("/api/artifacts?limit=", "/api/artifacts", 400),
        (
            "/api/artifacts?limit=9223372036854775808",
            "/api/artifacts",
            400,
        ),
        ("/api/analysis/vm?request_id=oops", "/api/analysis/vm", 400),
        ("/api/analysis/vm?request_id=01", "/api/analysis/vm", 400),
        ("/api/debugger?wait_ms=25001", "/api/debugger", 400),
        ("/api/debugger/source", "/api/debugger/source", 400),
        (
            "/api/debugger/source?script_id=missing",
            "/api/debugger/source",
            409,
        ),
        ("/api/deobfuscation", "/api/deobfuscation", 400),
        ("/api/origin-trace", "/api/origin-trace", 400),
        (
            "/api/request-signal-profile",
            "/api/request-signal-profile",
            400,
        ),
        ("/api/wasm?artifact_id=missing", "/api/wasm", 400),
    ] {
        assert_contract_response(server.get(path).await, "get", route, status).await;
    }
    // A valid signed limit still clamps; malformed input must not become a 500.
    for route in ["/api/events", "/api/artifacts"] {
        assert_contract_response(
            server.get(&format!("{route}?limit=-1")).await,
            "get",
            route,
            200,
        )
        .await;
    }
    let denied = server
        .client
        .get(format!("{}/api/health", server.url))
        .header("Origin", "https://example.test")
        .send()
        .await
        .unwrap();
    assert_contract_response(denied, "get", "/api/health", 403).await;
    for path in ["/api/api-collection", "/api/local-analyst"] {
        let original: Value = server.get(path).await.json().await.unwrap();
        let (action, field) = if path.ends_with("api-collection") {
            ("replace_api_collection", "requests")
        } else {
            ("replace_local_analyst_workspace", "files")
        };
        let mut folders = original["folders"].as_array().unwrap().clone();
        let mut folder = json!({"id":2,"name":"Contract fixture","parent_id":1});
        if field == "requests" {
            folder["variables"] = json!([]);
        }
        folders.push(folder);
        let request = json!({"action":action,"expected_generation":original["generation"],
            "folders":folders,field:original[field]});
        let route = format!("{path}/actions");
        let response = server.action(&route, request.clone()).await;
        assert!(
            response.headers().get("etag").is_none(),
            "Replacement has no ETag contract"
        );
        assert_contract_response(response, "post", &route, 200).await;
        assert_contract_response(server.action(&route, request).await, "post", &route, 409).await;
    }
    for request in [
        json!({"action":"add_watch","expression":"1"}),
        json!({"action":"clear_request_interception_result"}),
    ] {
        let action = request["action"].as_str().unwrap().to_owned();
        let bytes = assert_contract_response(
            server.action("/api/debugger/actions", request).await,
            "post",
            "/api/debugger/actions",
            200,
        )
        .await;
        let spec = specification();
        let mapping = &spec["components"]["schemas"]["DebuggerResult"]["x-action-results"][&action];
        assert_schema(
            &spec,
            mapping,
            &serde_json::from_slice::<Value>(&bytes).unwrap(),
            &action,
        );
    }
}
#[tokio::test]
async fn openapi_action_envelopes_and_stored_failures_are_json_errors() {
    let server = Server::start().await;
    let spec = specification();
    for (route, operations) in spec["paths"].as_object().unwrap() {
        if operations.get("post").is_none() {
            continue;
        }
        for body in ["[]", "{"] {
            let response = server
                .client
                .post(format!("{}{route}", server.url))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            assert_contract_response(response, "post", route, 400).await;
        }
    }
    let mut analyst = json!({"action":"run_local_analyst_script","protocol_version":1,
        "run_id":1,"script_id":1,"library_generation":0,"source":"return 1;",
        "variables":{},"evidence":{"events":[],"artifacts":[],"trace_edges":[],
            "signal_profiles":[],"vm_analysis":null,"selected_artifact":null,"summary":{}},
        "confirmed":true,"confirmed_sensitive":false});
    assert_schema(
        &spec,
        &json!({"$ref":"#/components/schemas/AnalystAction"}),
        &analyst,
        "Boolean sensitive-capture confirmation",
    );
    let analyst_schema = json!({"$ref":"#/components/schemas/AnalystAction",
        "components":spec["components"]});
    let analyst_validator = jsonschema::validator_for(&analyst_schema).unwrap();
    for invalid in [Value::Null, json!("false"), json!(0), json!({})] {
        analyst["confirmed_sensitive"] = invalid;
        assert!(analyst_validator.validate(&analyst).is_err());
        assert_contract_response(
            server
                .action("/api/local-analyst/actions", analyst.clone())
                .await,
            "post",
            "/api/local-analyst/actions",
            400,
        )
        .await;
    }
    for (file, route) in [
        ("events.jsonl", "/api/events"),
        ("artifacts/manifest.jsonl", "/api/artifacts"),
        ("collection.json", "/api/api-collection"),
        ("analyst.json", "/api/local-analyst"),
    ] {
        server.file(file, b"not-json\n");
        assert_contract_response(server.get(route).await, "get", route, 500).await;
    }
    for (method, path, status) in [
        (reqwest::Method::GET, "/api/missing", 404),
        (reqwest::Method::PUT, "/api/health", 405),
    ] {
        let response = server
            .client
            .request(method, format!("{}{path}", server.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_schema(
            &spec,
            &json!({"$ref":"#/components/schemas/Error"}),
            &response.json::<Value>().await.unwrap(),
            path,
        );
    }
}
#[tokio::test]
async fn openapi_request_body_deadline_is_a_documented_json_error() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = Server::start().await;
    let address = server.url.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("POST /api/capture/actions HTTP/1.1\r\nHost: {address}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{").as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(raw).unwrap();
    assert!(response.starts_with("HTTP/1.1 408 "), "{response}");
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    let value: Value = serde_json::from_str(body).unwrap();
    assert_eq!(value["error"], "The request body deadline was exceeded");
    assert_eq!(value["code"], "timeout");
    assert_eq!(value["details"], json!({"phase":"request_body"}));
    let spec = specification();
    // Every POST goes through the same bounded body reader.
    for (route, item) in spec["paths"].as_object().unwrap() {
        if let Some(operation) = item.get("post") {
            let schema = &operation["responses"]["408"]["content"]["application/json"]["schema"];
            assert!(
                schema.is_object(),
                "Missing body deadline response: {route}"
            );
            assert_schema(&spec, schema, &value, route);
        }
    }
}
#[tokio::test]
async fn incomplete_request_body_keeps_coarse_reason_and_legacy_text() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = Server::start().await;
    let address = server.url.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("POST /api/debugger/actions HTTP/1.1\r\nHost: {address}\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{").as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(raw).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    let value: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(value["error"], "The request body exceeds its size limit");
    assert_eq!(value["code"], "invalid_request");
    assert_eq!(value["details"], json!({}));
}
fn metadata_event(sequence: u64) -> Value {
    json!({"protocol_version":3,"session_id":"1","sequence_number":sequence.to_string(),"monotonic_time_ns":(sequence*1000).to_string(),"navigation_id":"1","frame_id":"1","artifact_id":"0","request_id":sequence.to_string(),"process_id":100,"thread_id":101,"tab_id":1,"category":"network","type":"request_started","payload_encoding":"hex","payload":hex::encode("GET fixture.local"),"payload_size":17,"parent_event_id":"0","browser_context_id_high":"1","browser_context_id_low":"2","initiator_request_id":0,"initiator_process_id":0,"status_code":0,"error_code":0,"resource_type":13,"flags":0,"payload_truncated":false,"encoded_data_length":"0","decoded_body_length":"0"})
}
fn jsonl(records: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        serde_json::to_writer(&mut bytes, record).unwrap();
        bytes.push(b'\n');
    }
    bytes
}
async fn assert_poll_response(server: &Server, path: &str, expected: Value) {
    let response = server.get(path).await;
    assert_eq!(response.status(), 200);
    let etag = response.headers()["etag"].clone();
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        serde_json::to_vec(&expected).unwrap()
    );
    let unchanged = server
        .client
        .get(format!("{}{path}", server.url))
        .header("If-None-Match", etag)
        .send()
        .await
        .unwrap();
    assert_eq!(unchanged.status(), 304);
    assert!(unchanged.bytes().await.unwrap().is_empty());
}
fn event_response(events: &[Value]) -> Value {
    json!({"count":events.len(),"events":events,"broker_connected":true,"capture_mode":"idle","capture_stopped":false,"capture_controls_available":false})
}
#[tokio::test]
async fn evidence_polling_preserves_bytes_windows_and_file_changes() {
    let server = Server::start().await;
    assert_poll_response(&server, "/api/events", event_response(&[])).await;
    let mut events: Vec<_> = (1..=5001).map(metadata_event).collect();
    server.file("events.jsonl", &jsonl(&events));
    assert_poll_response(
        &server,
        "/api/events?limit=2",
        event_response(&events[4999..]),
    )
    .await;
    assert_poll_response(
        &server,
        "/api/events?limit=9999",
        event_response(&events[1..]),
    )
    .await;
    let response = server.get("/api/events?limit=2").await;
    let previous_etag = response.headers()["etag"].clone();
    drop(response);
    // The next poll sees appended evidence, including a complete final record
    // without a newline, rather than retaining an earlier response tree.
    events.push(metadata_event(5002));
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(server.root.path().join("events.jsonl"))
            .unwrap();
        file.write_all(&serde_json::to_vec(events.last().unwrap()).unwrap())
            .unwrap();
    }
    let response = server
        .client
        .get(format!("{}/api/events?limit=2", server.url))
        .header("If-None-Match", previous_etag)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.bytes().await.unwrap().as_ref(),
        serde_json::to_vec(&event_response(&events[5000..])).unwrap()
    );
    server.file("rotated.jsonl", &jsonl(&[metadata_event(9000)]));
    std::fs::rename(
        server.root.path().join("rotated.jsonl"),
        server.root.path().join("events.jsonl"),
    )
    .unwrap();
    assert_poll_response(
        &server,
        "/api/events",
        event_response(&[metadata_event(9000)]),
    )
    .await;
    server.file("events.jsonl", b"");
    assert_poll_response(&server, "/api/events", event_response(&[])).await;
    for bad in [b"not-json\n".to_vec(), b"[]\n".to_vec(), vec![b'x'; 4097]] {
        server.file("events.jsonl", &bad);
        assert_eq!(server.get("/api/events").await.status(), 500);
    }
    let mut invalid = metadata_event(1);
    invalid["payload"] = json!("not-hex");
    server.file("events.jsonl", &jsonl(&[invalid]));
    assert_eq!(server.get("/api/events").await.status(), 500);
    server.file("events.jsonl", &jsonl(&[metadata_event(2)]));
    assert_poll_response(&server, "/api/events", event_response(&[metadata_event(2)])).await;
    #[cfg(unix)]
    {
        std::fs::remove_file(server.root.path().join("events.jsonl")).unwrap();
        std::os::unix::fs::symlink(
            server.root.path().join("endpoint"),
            server.root.path().join("events.jsonl"),
        )
        .unwrap();
        assert_eq!(server.get("/api/events").await.status(), 500);
    }
}
#[tokio::test]
async fn artifact_polling_preserves_public_fields_and_validation() {
    let server = Server::start().await;
    let response = |artifacts: &[Value]| json!({"count":artifacts.len(),"artifacts":artifacts,"artifact_receiver_configured":false,"artifact_receiver_connected":false});
    assert_poll_response(&server, "/api/artifacts", response(&[])).await;
    let hash = "a".repeat(64);
    let records: Vec<_> = (1..=5001).map(|id| {
        let mut record = json!({"protocol_version":1,"artifact_id":id.to_string(),"session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"javascript","url":format!("http://fixture.local/script-{id}.js"),"mime_type":"text/javascript","byte_size":1024,"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin"),"fixture_private_field":"must-not-be-disclosed"});
        if id % 2 == 0 {
            record["execution_context_id"] = json!("7");
            record["capture_origin"] = json!("dynamic_javascript");
        }
        record
    }).collect();
    let expected: Vec<_> = records
        .iter()
        .cloned()
        .map(|mut record| {
            let object = record.as_object_mut().unwrap();
            object.remove("content_path");
            object.remove("fixture_private_field");
            object.entry("execution_context_id").or_insert(json!("0"));
            object.entry("capture_origin").or_insert(json!("unknown"));
            record
        })
        .collect();
    server.file("artifacts/manifest.jsonl", &jsonl(&records));
    assert_poll_response(
        &server,
        "/api/artifacts?limit=2",
        response(&expected[4999..]),
    )
    .await;
    assert_poll_response(
        &server,
        "/api/artifacts?limit=9999",
        response(&expected[1..]),
    )
    .await;
    server.file(
        "artifacts/manifest.jsonl",
        &jsonl(&[records[0].clone(), records[0].clone()]),
    );
    assert_eq!(server.get("/api/artifacts").await.status(), 500);
    for bad in [b"not-json\n".to_vec(), b"[]\n".to_vec(), vec![b'x'; 8193]] {
        server.file("artifacts/manifest.jsonl", &bad);
        assert_eq!(server.get("/api/artifacts").await.status(), 500);
    }
    let mut invalid = records[0].clone();
    invalid["sensitive"] = json!(true);
    server.file("artifacts/manifest.jsonl", &jsonl(&[invalid]));
    assert_eq!(server.get("/api/artifacts").await.status(), 500);
    server.file("artifacts/manifest.jsonl", b"");
    assert_poll_response(&server, "/api/artifacts", response(&[])).await;
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
    let conflict = server.action("/api/api-collection/actions", body).await;
    assert_eq!(conflict.status(), 409);
    let conflict: Value = conflict.json().await.unwrap();
    assert_eq!(
        conflict["error"],
        "API Collection changed in another window; refresh before saving"
    );
    assert_eq!(conflict["code"], "stale_generation");
    assert_eq!(
        conflict["details"],
        json!({"expected_generation":0,"current_generation":1})
    );
    assert_schema(
        &specification(),
        &json!({"$ref":"#/components/schemas/Error"}),
        &conflict,
        "stale generation",
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
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"artifact-1.bin\""
    );
    assert_eq!(
        assert_contract_response(response, "get", "/api/artifacts/{artifact_id}/content", 200)
            .await,
        &bytes[..16]
    );
    let response = server
        .get(&format!("/api/artifacts/1/content?offset={}", bytes.len()))
        .await;
    assert_eq!(response.headers()["x-artifact-truncated"], "false");
    assert!(
        assert_contract_response(response, "get", "/api/artifacts/{artifact_id}/content", 200)
            .await
            .is_empty()
    );
    for query in [
        "offset=-1",
        "offset=oops",
        "offset=20971521",
        "offset=1&offset=2",
        "limit=oops",
    ] {
        assert_contract_response(
            server
                .get(&format!("/api/artifacts/1/content?{query}"))
                .await,
            "get",
            "/api/artifacts/{artifact_id}/content",
            400,
        )
        .await;
    }
    let mut corrupt = bytes;
    corrupt[0] = b'y';
    server.file(&format!("artifacts/blobs/{hash}.bin"), &corrupt);
    assert_contract_response(
        server
            .get("/api/artifacts/1/content?offset=16777216&limit=16")
            .await,
        "get",
        "/api/artifacts/{artifact_id}/content",
        500,
    )
    .await;
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

fn vm_artifact(root: &Path, source: &[u8], frame: &str) -> Value {
    let hash = hex::encode(Sha256::digest(source));
    std::fs::create_dir_all(root.join("blobs")).unwrap();
    std::fs::write(root.join(format!("blobs/{hash}.bin")), source).unwrap();
    let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"2","frame_id":frame,"parent_artifact_id":"0","creator_event_id":"0","kind":"javascript","url":"https://synthetic.test/source.js","mime_type":"text/javascript","byte_size":source.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
    std::fs::write(
        root.join("manifest.jsonl"),
        jsonl(std::slice::from_ref(&artifact)),
    )
    .unwrap();
    artifact
}
fn vm_event(category: &str, sequence: u64, process: u32, artifact: &str) -> Value {
    let mut event = metadata_event(sequence);
    event["navigation_id"] = json!("2");
    event["frame_id"] = json!("3");
    event["artifact_id"] = json!(artifact);
    event["process_id"] = json!(process);
    event["category"] = json!(category);
    event["type"] = json!(if category == "network" {
        "request_started"
    } else {
        "api_call"
    });
    event
}
fn assert_vm_document(document: &Value) {
    let schema: Value =
        serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json")).unwrap();
    jsonschema::validator_for(&schema)
        .unwrap()
        .validate(document)
        .unwrap();
    let spec = specification();
    assert_schema(
        &spec,
        &spec["components"]["schemas"]["VmAnalysis"],
        document,
        "VM analysis",
    );
    let mut original = document.clone();
    let digest = original
        .as_object_mut()
        .unwrap()
        .remove("document_digest")
        .unwrap();
    assert_eq!(
        digest,
        hex::encode(Sha256::digest(
            origin_trace_backend::vm::canonical(&original).unwrap()
        ))
    );
}
fn analyze_vm(root: &Path, events: &[Value]) -> Value {
    let path = root.join("events.jsonl");
    std::fs::write(&path, jsonl(events)).unwrap();
    let document = origin_trace_backend::vm::store(root, &path).unwrap();
    assert_vm_document(&document);
    document
}
#[test]
fn vm_runtime_audio_is_bounded_relevance_not_vm_structure_or_value_capture() {
    for source in [
        "function run(code) { let pc=0, stack=[]; while (pc<code.length) { switch(code[pc++]) { case 1: stack.push(1); break; default: return; } } }",
        "const answer = 42;",
    ] {
        let root = tempfile::tempdir().unwrap();
        let artifact = vm_artifact(root.path(), source.as_bytes(), "3");
        let manifest = std::fs::read(root.path().join("manifest.jsonl")).unwrap();
        let baseline = analyze_vm(root.path(), &[]);
        let mut events = vec![
            vm_event("web_audio", 1, 10, "0"),
            vm_event("web_audio", 2, 10, "1"),
            vm_event("web_audio", 3, 10, "1"),
        ];
        // Unused captured fields must not become analysis content.
        events[1]["private_sample"] = json!("must-not-copy-audio-samples-or-parameters");
        for (sequence, key, value) in [
            (4, "type", "request_started"),
            (5, "frame_id", "9"),
            (6, "session_id", "9"),
            (7, "navigation_id", "9"),
            (8, "category", "unknown"),
        ] {
            let mut event = vm_event("web_audio", sequence, 10, "1");
            event[key] = json!(value);
            events.push(event);
        }
        let document = analyze_vm(root.path(), &events);
        let result = &document["results"][0];
        for key in [
            "vm_score",
            "tier",
            "evidence_families",
            "observations",
            "finding_id",
        ] {
            assert_eq!(result[key], baseline["results"][0][key], "{key}");
        }
        assert_eq!(result["anti_bot_score"], 25);
        let observations = result["anti_bot_observations"].as_array().unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["rule_id"], "antibot.runtime-web-audio");
        assert_eq!(observations[0]["state"], "observed");
        assert_eq!(
            observations[0]["event"],
            json!({"session_id":"1","process_id":10,"sequence_number":"2"})
        );
        assert!(observations[0].get("coordinate").is_none());
        let nodes = result["graph"]["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 5);
        assert!(nodes.iter().any(|n| n["id"] == "event:1:10:1"));
        assert!(
            result["graph"]["edges"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["from"] == "event:1:10:1" && e["state"] == "correlated")
        );
        assert!(!document.to_string().contains("must-not-copy"));
        assert_eq!(document["producer"]["version"], "1.1.1");
        assert_eq!(
            document["profile"]["runtime_rule_weights"]["antibot.runtime-web-audio"],
            25
        );
        assert_eq!(analyze_vm(root.path(), &events), document);
        assert_eq!(
            std::fs::read(root.path().join("manifest.jsonl")).unwrap(),
            manifest
        );
        assert_eq!(
            std::fs::read(root.path().join(artifact["content_path"].as_str().unwrap())).unwrap(),
            source.as_bytes()
        );
        assert_eq!(
            std::fs::read(root.path().join("events.jsonl")).unwrap(),
            jsonl(&events)
        );
    }
}
#[test]
fn vm_runtime_identity_disambiguates_processes_and_rejects_conflicts() {
    let root = tempfile::tempdir().unwrap();
    vm_artifact(root.path(), b"const answer=42;", "3");
    let canvas = vm_event("canvas", 1, 10, "1");
    let mut events = vec![canvas.clone(), vm_event("navigator", 1, 11, "1"), canvas];
    for process in [10, 11] {
        let mut event = vm_event("network", 2, process, "0");
        event["request_id"] = json!("55");
        events.push(event);
    }
    let audio = vm_event("web_audio", 3, 10, "1");
    let mut conflict = audio.clone();
    conflict["category"] = json!("canvas");
    events.extend([audio.clone(), conflict, audio]);
    for (key, value) in [
        ("process_id", json!(0)),
        ("process_id", json!(4294967296u64)),
        ("process_id", Value::Null),
        ("sequence_number", json!("0")),
        ("session_id", json!("0")),
        ("protocol_version", json!(99)),
        ("protocol_version", Value::Null),
    ] {
        let mut event = vm_event("web_audio", 4, 10, "1");
        event[key] = value;
        events.push(event);
    }
    let document = analyze_vm(root.path(), &events);
    assert_eq!(document["input_coverage"]["complete"], false);
    assert_eq!(
        document["input_coverage"]["omissions"]
            .as_array()
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        document["input_coverage"]["omissions"][0]["reason"],
        "conflicting-event-identity"
    );
    let result = &document["results"][0];
    assert_eq!(result["anti_bot_score"], 50);
    assert_eq!(result["related_request_ids"], json!(["55"]));
    let nodes = result["graph"]["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 6);
    let ids = nodes
        .iter()
        .map(|n| n["id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), nodes.len());
    for id in [
        "event:1:10:1",
        "event:1:11:1",
        "request:1:10:2",
        "request:1:11:2",
    ] {
        assert!(ids.contains(id), "{id}");
    }
    assert!(!ids.contains("event:1:10:3"));
}
#[test]
fn vm_native_gap_markers_preserve_preceding_signal_identity() {
    let root = tempfile::tempdir().unwrap();
    vm_artifact(root.path(), b"const answer=42;", "3");
    let mut audio = vm_event("web_audio", 1, 10, "1");
    audio["protocol_version"] = json!(2);
    let mut gap = audio.clone();
    gap["type"] = json!("gap");
    gap["frame_id"] = json!("0");
    gap["navigation_id"] = json!("0");
    gap["artifact_id"] = json!("0");
    gap["payload"] = json!(hex::encode("2"));
    gap["payload_size"] = json!(1);
    for events in [vec![audio.clone(), gap.clone()], vec![gap, audio]] {
        let document = analyze_vm(root.path(), &events);
        assert_eq!(
            document["input_coverage"]["omissions"],
            json!([{"reason":"capture-gap","observed_records":1}])
        );
        let result = &document["results"][0];
        assert_eq!(result["anti_bot_score"], 25);
        assert_eq!(result["status"], "partial");
        assert_eq!(result["graph"]["nodes"].as_array().unwrap().len(), 3);
        assert_eq!(result["anti_bot_observations"][0]["event_sequence"], "1");
    }
}
#[test]
fn vm_runtime_unknown_frames_do_not_invent_shared_context() {
    let root = tempfile::tempdir().unwrap();
    let mut artifact = vm_artifact(root.path(), b"const answer=42;", "0");
    let mut event = vm_event("web_audio", 1, 10, "0");
    event["frame_id"] = json!("0");
    let document = analyze_vm(root.path(), &[event.clone()]);
    let result = &document["results"][0];
    assert_eq!(result["anti_bot_score"], 0);
    assert_eq!(result["status"], "partial");
    assert_eq!(
        result["coverage"]["omissions"],
        json!([{"reason":"runtime-frame-attribution-unavailable","omitted_records":1}])
    );
    event["artifact_id"] = json!("1");
    let document = analyze_vm(root.path(), &[event.clone()]);
    assert_eq!(
        document["results"][0]["anti_bot_observations"][0]["state"],
        "observed"
    );
    assert_eq!(document["results"][0]["anti_bot_score"], 25);
    artifact["artifact_id"] = json!("0");
    std::fs::write(root.path().join("manifest.jsonl"), jsonl(&[artifact])).unwrap();
    event["artifact_id"] = json!("0");
    assert_eq!(
        analyze_vm(root.path(), &[event])["results"][0]["anti_bot_score"],
        0
    );
}
#[test]
fn vm_runtime_graph_limit_is_explicit_and_preserves_representative() {
    let root = tempfile::tempdir().unwrap();
    vm_artifact(root.path(), b"const answer=42;", "3");
    let mut events = (1..=1030)
        .map(|sequence| vm_event("web_audio", sequence, 10, "0"))
        .collect::<Vec<_>>();
    // Stronger attribution remains visible even when it arrived after the cap.
    events[1029]["artifact_id"] = json!("1");
    events.push(vm_event("network", 1031, 10, "0"));
    let document = analyze_vm(root.path(), &events);
    let result = &document["results"][0];
    assert_eq!(result["anti_bot_score"], 25);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["graph"]["edges"].as_array().unwrap().len(), 1024);
    assert_eq!(result["graph"]["nodes"].as_array().unwrap().len(), 1025);
    assert_eq!(result["anti_bot_observations"][0]["event_sequence"], "1030");
    assert!(
        result["graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["id"] == "event:1:10:1030")
    );
    assert_eq!(
        result["coverage"]["omissions"],
        json!([{"reason":"runtime-graph-edge-limit","omitted_records":8}])
    );
    assert_eq!(result["related_request_ids"], json!([]));
}
#[tokio::test]
async fn vm_http_refreshes_event_only_changes_and_agrees_with_cli() {
    let server = Server::start().await;
    let root = server.root.path().join("artifacts");
    vm_artifact(&root, b"const answer=42;", "3");
    server.file("events.jsonl", b"");
    let response = server.get("/api/analysis/vm").await;
    assert_eq!(response.status(), 200);
    let initial_etag = response.headers()["etag"].clone();
    let baseline: Value = response.json().await.unwrap();
    assert_vm_document(&baseline);
    let mut events = vec![vm_event("web_audio", 1, 10, "1")];
    server.file("events.jsonl", &jsonl(&events));
    let response = server
        .client
        .get(format!("{}/api/analysis/vm", server.url))
        .header("If-None-Match", &initial_etag)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let etag = response.headers()["etag"].clone();
    assert_ne!(etag, initial_etag);
    let document: Value = response.json().await.unwrap();
    assert_vm_document(&document);
    assert_eq!(document["results"][0]["anti_bot_score"], 25);
    assert_ne!(
        document["inputs"]["event_store_digest"],
        baseline["inputs"]["event_store_digest"]
    );
    let response = server
        .client
        .get(format!("{}/api/analysis/vm", server.url))
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_contract_response(response, "get", "/api/analysis/vm", 304).await;
    // Restored/copied evidence can preserve size and mtime. Atomic replacement
    // must still invalidate the cached attribution through file identity.
    let event_path = server.root.path().join("events.jsonl");
    let metadata = event_path.metadata().unwrap();
    let modified = metadata.modified().unwrap();
    events[0]["artifact_id"] = json!("0");
    let replacement = server.root.path().join("replacement.jsonl");
    std::fs::write(&replacement, jsonl(&events)).unwrap();
    std::fs::File::open(&replacement)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(replacement.metadata().unwrap().len(), metadata.len());
    assert_eq!(
        replacement.metadata().unwrap().modified().unwrap(),
        modified
    );
    std::fs::rename(&replacement, &event_path).unwrap();
    let response = server
        .client
        .get(format!("{}/api/analysis/vm", server.url))
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let document: Value = response.json().await.unwrap();
    assert_vm_document(&document);
    assert_eq!(
        document["results"][0]["anti_bot_observations"][0]["state"],
        "correlated"
    );
    let output = server.root.path().join("cli.json");
    let status = Command::new(env!("CARGO_BIN_EXE_origin-trace-vm"))
        .arg("--artifacts")
        .arg(&root)
        .arg("--events")
        .arg(server.root.path().join("events.jsonl"))
        .arg("--output")
        .arg(&output)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(output).unwrap()).unwrap(),
        document
    );
    // In-place changes with restored mtime are distinguished by change time.
    events[0]["artifact_id"] = json!("1");
    server.file("events.jsonl", &jsonl(&events));
    std::fs::File::open(&event_path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let rewritten: Value = server.get("/api/analysis/vm").await.json().await.unwrap();
    assert_eq!(
        rewritten["results"][0]["anti_bot_observations"][0]["state"],
        "observed"
    );
    assert_vm_document(&rewritten);
    #[cfg(unix)]
    {
        // A cached regular file cannot be exchanged for a symlink, even when
        // its target presents the same bytes, size, and modification time.
        let linked = server.root.path().join("linked-evidence.jsonl");
        std::fs::write(&linked, jsonl(&events)).unwrap();
        std::fs::File::open(&linked)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        std::fs::remove_file(&event_path).unwrap();
        std::os::unix::fs::symlink(&linked, &event_path).unwrap();
        assert_contract_response(
            server.get("/api/analysis/vm").await,
            "get",
            "/api/analysis/vm",
            500,
        )
        .await;
        std::fs::remove_file(&event_path).unwrap();
    }
    server.file("events.jsonl", b"not-json\n");
    let malformed: Value = server.get("/api/analysis/vm").await.json().await.unwrap();
    assert_eq!(malformed["input_coverage"]["complete"], false);
    assert_eq!(malformed["results"][0]["anti_bot_score"], 0);
    assert_vm_document(&malformed);
    server.file("events.jsonl", b"");
    let cleared: Value = server.get("/api/analysis/vm").await.json().await.unwrap();
    assert_eq!(cleared, baseline);
    std::fs::remove_file(server.root.path().join("events.jsonl")).unwrap();
    let missing: Value = server.get("/api/analysis/vm").await.json().await.unwrap();
    assert_eq!(missing, baseline);
}

fn put_vm_lexical_sources(server: &Server, sources: &[String]) -> Vec<Value> {
    let artifacts = sources
        .iter()
        .enumerate()
        .map(|(index, source)| {
            let hash = hex::encode(Sha256::digest(source.as_bytes()));
            let path = format!("blobs/{hash}.bin");
            server.file(&format!("artifacts/{path}"), source.as_bytes());
            json!({"protocol_version":1,"artifact_id":(index+1).to_string(),"session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"javascript","url":"https://example.test/lexical.js","mime_type":"text/javascript","byte_size":source.len(),"sha256":hash,"sensitive":false,"content_path":path})
        })
        .collect::<Vec<_>>();
    let manifest = artifacts
        .iter()
        .map(|artifact| format!("{artifact}\n"))
        .collect::<String>();
    server.file("artifacts/manifest.jsonl", manifest.as_bytes());
    server.file("events.jsonl", b"");
    artifacts
}

#[tokio::test]
async fn vm_lexical_scoring_ignores_comments_strings_and_raw_templates() {
    let server = Server::start().await;
    let ghost = "while (x) { switch (code[pc++]) { case 1: stack.push(1); return; } }";
    let mut sources = Vec::new();
    for inert in [
        format!("/* {ghost} */"),
        format!("// {ghost}\n"),
        format!("const text = '{ghost}';"),
        format!("const text = \"{ghost}\";"),
        format!("const text = `{ghost}`;"),
    ] {
        sources.push(inert.clone());
        sources.push(format!("function harmless() {{ {inert}\n }}"));
    }
    put_vm_lexical_sources(&server, &sources);
    let document: Value = serde_json::from_slice(
        &assert_contract_response(
            server.get("/api/analysis/vm").await,
            "get",
            "/api/analysis/vm",
            200,
        )
        .await,
    )
    .unwrap();
    assert_eq!(document["results"].as_array().unwrap().len(), sources.len());
    for (result, source) in document["results"].as_array().unwrap().iter().zip(&sources) {
        assert_eq!(result["status"], "complete", "{source}");
        assert_eq!(result["tier"], "none", "{source}");
        assert_eq!(result["vm_score"], 0, "{source}");
        assert_eq!(result["observations"], json!([]), "{source}");
        assert_eq!(result["evidence_families"], json!([]), "{source}");
    }
}

#[tokio::test]
async fn vm_lexical_scoring_preserves_positive_evidence_and_utf8_coordinates() {
    let server = Server::start().await;
    let ghost = "🧪 한글 switch (code[pc++]) { case 1: stack.push(1); return; }";
    let noise = [
        String::new(),
        format!("/* {ghost} */"),
        format!("// {ghost}\n"),
        format!("const text = '{ghost}';"),
        format!("const text = \"{ghost}\";"),
        format!("const text = `{ghost}`;"),
    ];
    let sources = noise
        .iter()
        .map(|inert| format!("const π = 1; /* 前置 */\nfunction run(code, pc, stack, table) {{\n{inert}\nwhile (pc < code.length) {{ const opcode = code[pc++]; table[opcode](stack); stack.push(1); }}\n}}"))
        .collect::<Vec<_>>();
    put_vm_lexical_sources(&server, &sources);
    let document: Value = server.get("/api/analysis/vm").await.json().await.unwrap();
    let results = document["results"].as_array().unwrap();
    assert_eq!(results.len(), sources.len());
    let baseline = &results[0];
    assert_eq!(baseline["tier"], "likely-vm");
    assert_eq!(baseline["vm_score"], 75);
    assert_eq!(
        baseline["evidence_families"],
        json!(["bytecode", "dispatch", "instruction-pointer", "state"])
    );
    for ((result, source), inert) in results.iter().zip(&sources).zip(&noise) {
        assert_eq!(result["tier"], baseline["tier"]);
        assert_eq!(result["vm_score"], baseline["vm_score"]);
        assert_eq!(result["evidence_families"], baseline["evidence_families"]);
        assert_eq!(result["coverage"]["observed_bytes"], source.len());
        let observations = result["observations"].as_array().unwrap();
        let original = baseline["observations"].as_array().unwrap();
        assert_eq!(observations.len(), original.len());
        for (observation, expected) in observations.iter().zip(original) {
            let start = observation["coordinate"]["byte_offset"].as_u64().unwrap() as usize;
            let size = observation["coordinate"]["byte_size"].as_u64().unwrap() as usize;
            let old_start = expected["coordinate"]["byte_offset"].as_u64().unwrap() as usize;
            assert_eq!(start, old_start + inert.len());
            assert_eq!(
                source.get(start..start + size).unwrap(),
                sources[0].get(old_start..old_start + size).unwrap()
            );
            let mut normalized = observation.clone();
            normalized["coordinate"] = expected["coordinate"].clone();
            normalized["function_region"] = expected["function_region"].clone();
            assert_eq!(&normalized, expected, "{source}");
            let region = &observation["function_region"];
            let region_start = region["byte_offset"].as_u64().unwrap() as usize;
            let region_size = region["byte_size"].as_u64().unwrap() as usize;
            assert_eq!(region_start, source.find("{\n").unwrap() + 1);
            assert_eq!(region_start + region_size, source.len() - 1);
        }
    }
}

#[tokio::test]
async fn vm_lexical_scoring_retains_dispatch_families_and_original_artifacts() {
    let server = Server::start().await;
    let prefix = "const π = '🧪'; /* 字节 */\nconst code = Uint8Array.of(0, 255, 0x80, 127);\n";
    let sources = [
        "function run() { let pc = 0, stack = []; while (pc < code.length) { switch (code[pc++]) { case 0: stack.push(1); return stack; } } }",
        "function run() { let pc = 0, stack = []; const handlers = [load, halt]; while (pc < code.length) { const opcode = code[pc++]; handlers[opcode](stack); stack.push(1); if (!stack.length) return; } }",
        "const run = () => { let pc = 0, registers = []; const handlers = {load, halt}; for (;;) { const opcode = code[pc++]; handlers[opcode](registers); registers[0] = 1; if (!registers.length) break; } };",
        "function run() { let pc = 0, stack = []; while (pc < code.length) { switch (code[pc++]) { case 'load': stack.push(1); return stack; } } }",
    ]
    .iter()
    .map(|source| format!("{prefix}{source}"))
    .collect::<Vec<_>>();
    let artifacts = put_vm_lexical_sources(&server, &sources);
    let manifest_path = server.root.path().join("artifacts/manifest.jsonl");
    let manifest = std::fs::read(&manifest_path).unwrap();
    let response = server.get("/api/analysis/vm").await;
    let etag = response.headers()["etag"].clone();
    let document: Value = serde_json::from_slice(
        &assert_contract_response(response, "get", "/api/analysis/vm", 200).await,
    )
    .unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../protocol/vm-analysis-v1.schema.json")).unwrap();
    assert_eq!(document["results"].as_array().unwrap().len(), sources.len());
    jsonschema::validator_for(&schema)
        .unwrap()
        .validate(&document)
        .unwrap();
    assert_eq!(document["producer"]["version"], "1.1.1");
    assert_eq!(document["profile"]["javascript_scoring_version"], 2);
    assert_eq!(document["profile"]["runtime_evidence_version"], 2);
    let profile = origin_trace_backend::vm::canonical(&document["profile"]).unwrap();
    assert_eq!(
        document["profile_digest"],
        hex::encode(Sha256::digest(&profile))
    );
    let mut prior_profile = document["profile"].clone();
    prior_profile
        .as_object_mut()
        .unwrap()
        .remove("javascript_scoring_version");
    assert_ne!(
        document["profile_digest"],
        hex::encode(Sha256::digest(
            origin_trace_backend::vm::canonical(&prior_profile).unwrap()
        ))
    );
    // Unchanged evidence must remain deterministic, including the public ETag.
    assert_contract_response(
        server
            .client
            .get(format!("{}/api/analysis/vm", server.url))
            .header("If-None-Match", etag)
            .send()
            .await
            .unwrap(),
        "get",
        "/api/analysis/vm",
        304,
    )
    .await;
    let output = server.root.path().join("cli.json");
    let cli = Command::new(env!("CARGO_BIN_EXE_origin-trace-vm"))
        .arg("--artifacts")
        .arg(server.root.path().join("artifacts"))
        .arg("--events")
        .arg(server.root.path().join("events.jsonl"))
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        cli.status.success(),
        "{}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_document: Value = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    assert_eq!(document, cli_document);
    assert_eq!(std::fs::read(manifest_path).unwrap(), manifest);
    assert_eq!(
        std::fs::read(server.root.path().join("events.jsonl")).unwrap(),
        b""
    );
    for ((result, artifact), source) in document["results"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&artifacts)
        .zip(&sources)
    {
        assert_eq!(result["status"], "complete");
        assert_eq!(result["tier"], "likely-vm");
        assert_eq!(result["vm_score"], 95);
        assert_eq!(
            result["evidence_families"],
            json!([
                "bytecode",
                "dispatch",
                "exits",
                "handlers",
                "instruction-pointer",
                "state"
            ])
        );
        assert_eq!(result["artifact_sha256"], artifact["sha256"]);
        let snapshot = &result["bytecode_snapshot"];
        assert_eq!(snapshot["snapshot_hex"], "00ff807f");
        assert_eq!(snapshot["original_byte_count"], 4);
        assert_eq!(
            snapshot["sha256"],
            hex::encode(Sha256::digest([0, 255, 128, 127]))
        );
        assert_eq!(
            snapshot["producer"]["byte_offset"],
            source.find("Uint8Array.of").unwrap()
        );
        assert_eq!(snapshot["truncated"], false);
        let stored = server
            .root
            .path()
            .join("artifacts")
            .join(artifact["content_path"].as_str().unwrap());
        assert_eq!(std::fs::read(stored).unwrap(), source.as_bytes());
        assert_eq!(
            server
                .get(&format!(
                    "/api/artifacts/{}/content",
                    artifact["artifact_id"].as_str().unwrap()
                ))
                .await
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            source.as_bytes()
        );
    }
}

#[tokio::test]
async fn vm_lexical_scoring_preserves_region_failures_and_limits() {
    let server = Server::start().await;
    let sources = vec![
        "function broken() { while (code[pc++]) { stack.push(1); }".into(),
        "function harmless() {}\n".repeat(4098),
        "function loop() { while (true) {} } function dispatch() { switch (code[pc++]) { case 1: stack.push(1); return; } }".into(),
    ];
    put_vm_lexical_sources(&server, &sources);
    let document: Value = server.get("/api/analysis/vm").await.json().await.unwrap();
    let results = document["results"].as_array().unwrap();
    assert_eq!(results.len(), sources.len());
    assert_eq!(results[0]["status"], "failed");
    assert_eq!(results[0]["error"]["code"], "malformed-artifact");
    assert_eq!(results[1]["status"], "partial");
    assert_eq!(results[1]["tier"], "none");
    assert_eq!(results[1]["coverage"]["complete"], false);
    assert_eq!(
        results[1]["coverage"]["omissions"][0]["reason"],
        "javascript-function-region-limit"
    );
    assert_eq!(results[2]["tier"], "candidate");
    assert_eq!(results[2]["vm_score"], 75);
    assert!(
        !results[2]["observations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["rule_id"] == "js.dispatch-loop")
    );
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

#[tokio::test]
async fn error_reasons_preserve_http_text_targets_limits_and_cli_contracts() {
    let missing = tempfile::tempdir().unwrap();
    let server = Server::start_with_args(&[
        "--decoder".into(),
        missing.path().join("missing-helper").display().to_string(),
    ])
    .await;
    for (route, body, status, code, text) in [
        (
            "/api/debugger/actions",
            json!({"action":"select_target","target_id":"synthetic_private_target"}),
            409,
            "target_unavailable",
            "Debugger target is unavailable",
        ),
        (
            "/api/decoder/actions",
            json!({"action":"jwt_inspect","protocol_version":1,"token":"synthetic_private_token"}),
            503,
            "dependency_unavailable",
            "The native decoder executable is unavailable",
        ),
        (
            "/api/native-console/actions",
            json!({"action":"targets","session_id":"1"}),
            409,
            "state_conflict",
            "Start a native console session first",
        ),
    ] {
        let response = server.action(route, body).await;
        let bytes = assert_contract_response(response, "post", route, status).await;
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["code"], code);
        assert_eq!(result["error"], text);
        assert_eq!(result["details"], json!({}));
        assert!(!result.to_string().contains("synthetic_private"));
        assert!(result.get("retryable").is_none());
    }
    let state: Value = server.get("/api/debugger").await.json().await.unwrap();
    assert!(state["target"].is_null());
    for _ in 0..100 {
        assert_eq!(
            server
                .action(
                    "/api/debugger/actions",
                    json!({"action":"add_watch","expression":"synthetic_private_expression"})
                )
                .await
                .status(),
            200
        );
    }
    let response = server
        .action(
            "/api/debugger/actions",
            json!({"action":"add_watch","expression":"synthetic_private_expression"}),
        )
        .await;
    assert_eq!(response.status(), 409);
    let result: Value = response.json().await.unwrap();
    assert_eq!(result["error"], "Watch expression limit reached");
    assert_eq!(result["code"], "resource_limit");
    assert_eq!(result["details"], json!({}));

    let body = server.root.path().join("request.json");
    std::fs::write(
        &body,
        br#"{"action":"select_target","target_id":"synthetic_private_target"}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args([
            "call",
            "debugger_action",
            "--base-url",
            &server.url,
            "--body-file",
        ])
        .arg(&body)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let value: Value =
        serde_json::from_str(stderr.trim().strip_prefix("HTTP 409: ").unwrap()).unwrap();
    assert_eq!(value["error"], "Debugger target is unavailable");
    assert_eq!(value["code"], "target_unavailable");
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args([
            "call",
            "debugger_action",
            "--base-url",
            &server.url,
            "--json-errors",
            "--body-file",
        ])
        .arg(&body)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let value: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(
        value,
        json!({"http_status":409,"code":"target_unavailable","details":{},"error":"Debugger target is unavailable","error_truncated":false})
    );

    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args(["describe", "debugger_action", "--action", "select_target"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let description: Value = serde_json::from_slice(&output.stdout).unwrap();
    let spec = specification();
    assert_eq!(
        description["x-reb-execution-policy"],
        spec["x-reb-execution-policy"]
    );
    assert_eq!(
        description["x-reb-execution"],
        spec["paths"]["/api/debugger/actions"]["post"]["x-reb-execution"]
    );
    let selected = spec["components"]["schemas"]["DebuggerAction"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["properties"]["action"]["const"] == "select_target")
        .unwrap();
    assert_eq!(
        description["x-reb-selected-action-execution"],
        selected["x-reb-execution"]
    );
    assert_eq!(
        description["components"]["schemas"]["RebExecutionMetadata"],
        spec["components"]["schemas"]["RebExecutionMetadata"]
    );
    for component in ["Error", "ErrorCode", "ErrorDetails", "SafeInteger"] {
        assert_eq!(
            description["components"]["schemas"][component],
            specification()["components"]["schemas"][component]
        );
    }
    let spec = specification();
    let validator = jsonschema::validator_for(
        &json!({"$ref":"#/components/schemas/Error", "components":spec["components"]}),
    )
    .unwrap();
    for patch in [
        json!({"credentials":"synthetic_private_token"}),
        json!({"phase":"invented"}),
        json!({"cause":"raw captured diagnostic"}),
    ] {
        assert!(
            validator
                .validate(&json!({"error":"failure","code":"unspecified","details":patch}))
                .is_err()
        );
    }
    assert!(
        validator
            .validate(&json!({"error":"failure","code":"invented","details":{}}))
            .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn http_200_application_failures_have_reasons_and_keep_cli_transport_exit_status() {
    use std::os::unix::fs::PermissionsExt;
    let helper_root = tempfile::tempdir().unwrap();
    let helper = helper_root.path().join("analyst-fixture");
    let failure = json!({"protocol_version":1,"run_id":1,"script_id":1,"library_generation":1,
        "ok":false,"outcome":"failed","result_type":"error","result_text":"","result_truncated":false,
        "logs":[],"logs_truncated":false,"duration_ms":1,"error":"Synthetic application failure"});
    std::fs::write(
        &helper,
        format!("#!/bin/sh\n/bin/cat >/dev/null\nprintf '%s\\n' '{failure}'\n"),
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let decoder = helper_root.path().join("decoder-fixture");
    let rejected_token = json!({"protocol_version":1,"ok":false,"algorithm":"","signature_status":"invalid","header_json":"","payload_json":"","token_bytes":12,"signature_bytes":0,"error":"Synthetic token failure"});
    std::fs::write(
        &decoder,
        format!("#!/bin/sh\n/bin/cat >/dev/null\nprintf '%s\\n' '{rejected_token}'\n"),
    )
    .unwrap();
    std::fs::set_permissions(&decoder, std::fs::Permissions::from_mode(0o700)).unwrap();
    let server = Server::start_with_args(&[
        "--analyst-runner".into(),
        helper.display().to_string(),
        "--decoder".into(),
        decoder.display().to_string(),
    ])
    .await;
    let response = server
        .action(
            "/api/decoder/actions",
            json!({"action":"jwt_inspect","protocol_version":1,"token":"private_fixture_token"}),
        )
        .await;
    let bytes = assert_contract_response(response, "post", "/api/decoder/actions", 200).await;
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["code"], "application_failed");
    assert_eq!(result["details"], json!({}));
    assert!(!result.to_string().contains("private_fixture_token"));
    for (key, value) in rejected_token.as_object().unwrap() {
        assert_eq!(&result[key], value);
    }

    let saved = server.action("/api/local-analyst/actions", json!({"action":"replace_local_analyst_workspace","expected_generation":0,
        "folders":[{"id":1,"name":"Analyst Workspace","parent_id":null}],"files":[{"id":1,"folder_id":1,"name":"Fixture","kind":"analyst-script","language":"javascript","content":"return 1;"}]})).await;
    assert_eq!(saved.status(), 200, "{}", saved.text().await.unwrap());
    let request = json!({"action":"run_local_analyst_script","protocol_version":1,"run_id":1,"script_id":1,"library_generation":1,"source":"return 1;",
        "variables":{},"evidence":{"events":[],"artifacts":[],"trace_edges":[],"signal_profiles":[],"vm_analysis":null,"selected_artifact":null,"summary":{}},"confirmed":true,"confirmed_sensitive":false});
    let response = server
        .action("/api/local-analyst/actions", request.clone())
        .await;
    let bytes = assert_contract_response(response, "post", "/api/local-analyst/actions", 200).await;
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["code"], "application_failed");
    assert_eq!(result["details"], json!({"phase":"worker"}));
    for (key, value) in failure.as_object().unwrap() {
        assert_eq!(&result[key], value);
    }

    let body = server.root.path().join("request.json");
    std::fs::write(&body, request.to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_reb-api"))
        .args([
            "call",
            "analyst_action",
            "--json-errors",
            "--base-url",
            &server.url,
            "--body-file",
        ])
        .arg(&body)
        .output()
        .unwrap();
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["outcome"], "failed");
    assert_eq!(result["code"], "application_failed");

    // The synthetic helper consumes input but neither evaluates source nor replies.
    std::fs::write(
        &helper,
        "#!/bin/sh\n/bin/cat >/dev/null\nexec /bin/sleep 60\n",
    )
    .unwrap();
    let response = server
        .action("/api/local-analyst/actions", request.clone())
        .await;
    let bytes = assert_contract_response(response, "post", "/api/local-analyst/actions", 200).await;
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["outcome"], "timed_out");
    assert_eq!(result["code"], "timeout");
    assert_eq!(result["details"], json!({"phase":"worker"}));

    let client = server.client.clone();
    let url = format!("{}/api/local-analyst/actions", server.url);
    let pending =
        tokio::spawn(async move { client.post(url).json(&request).send().await.unwrap() });
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let state: Value = server
            .get("/api/local-analyst/runner")
            .await
            .json()
            .await
            .unwrap();
        if state["active_run_id"] == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "Fixture run never became active");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server
            .action(
                "/api/local-analyst/actions",
                json!({"action":"cancel_local_analyst_script","run_id":1})
            )
            .await
            .status(),
        200
    );
    let response = pending.await.unwrap();
    let bytes = assert_contract_response(response, "post", "/api/local-analyst/actions", 200).await;
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["ok"], false);
    assert_eq!(result["outcome"], "cancelled");
    assert_eq!(result["code"], "cancelled");
    assert_eq!(result["details"], json!({"phase":"worker"}));
}

#[tokio::test]
async fn cli_json_errors_handle_legacy_foreign_and_incomplete_http_responses() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn call(body: Vec<u8>, extra_length: usize, structured: bool) -> std::process::Output {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                request.push(stream.read_u8().await.unwrap());
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 8192);
            }
            stream.write_all(format!("HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nX-Secret: private_header\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()+extra_length).as_bytes()).await.unwrap();
            // An oversized response can be closed by the bounded CLI reader.
            let _ = stream.write_all(&body).await;
        });
        let output = tokio::task::spawn_blocking(move || {
            let mut cli = Command::new(env!("CARGO_BIN_EXE_reb-api"));
            cli.args(["call", "get_health", "--base-url", &url]);
            if structured {
                cli.arg("--json-errors");
            }
            cli.output().unwrap()
        })
        .await
        .unwrap();
        server.await.unwrap();
        output
    }
    let legacy = serde_json::to_vec(&json!({"error":"雪".repeat(300)})).unwrap();
    let output = call(legacy.clone(), 0, false).await;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "HTTP 409: {}\n",
            String::from_utf8_lossy(&legacy)
                .chars()
                .take(500)
                .collect::<String>()
        )
    );
    let output = call(legacy, 0, true).await;
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(value["error"].as_str().unwrap().len(), 510);
    assert_eq!(value["error_truncated"], true);
    assert_eq!(value["code"], "unspecified");
    assert_eq!(value["http_status"], 409);

    for body in [b"<html>private_body</html>".to_vec(),b"{private_body".to_vec(),
        serde_json::to_vec(&json!({"error":{},"code":"foreign","details":{"raw":"private_body"}})).unwrap(),
        serde_json::to_vec(&json!({"error":"Known message","code":"state_conflict","details":{"raw":"private_body"}})).unwrap()] {
        let output = call(body,0,true).await;
        assert_eq!(output.status.code(),Some(1));
        assert!(output.stdout.is_empty());
        let value: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(value["http_status"],409);
        assert_eq!(value["details"],json!({}));
        assert!(!value.to_string().contains("private"));
        assert_eq!(value.as_object().unwrap().len(),5);
    }
    for (body, extra_length, message) in [
        (
            b"{private_body".to_vec(),
            100,
            "API error response could not be read",
        ),
        (
            vec![b'x'; 64 * 1024 * 1024 + 1],
            0,
            "API response exceeds 64 MiB",
        ),
    ] {
        let output = call(body, extra_length, true).await;
        assert_eq!(output.status.code(), Some(2));
        let value: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            value,
            json!({"http_status":409,"code":"unspecified","details":{},"error":message,"error_truncated":false})
        );
    }
}
