use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;
#[derive(Parser)]
#[command(about = "Call the versioned Origin Trace loopback API by operation ID")]
struct Options {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    List {
        /// Print versioned JSON discovery, including observational-call eligibility.
        #[arg(long)]
        json: bool,
    },
    /// Print the complete embedded OpenAPI document without contacting a server.
    Spec,
    Describe {
        operation_id: String,
        /// Restrict a multiplexed operation to one documented action.
        #[arg(long)]
        action: Option<String>,
    },
    Call {
        operation_id: String,
        #[arg(
            long,
            required_unless_present = "endpoint_file",
            conflicts_with = "endpoint_file"
        )]
        base_url: Option<String>,
        #[arg(long)]
        endpoint_file: Option<PathBuf>,
        #[arg(long = "param")]
        params: Vec<String>,
        #[arg(long)]
        body_file: Option<String>,
        #[arg(long)]
        output: Option<String>,
        #[arg(long)]
        show_headers: bool,
        /// Print a bounded JSON envelope to stderr for non-2xx HTTP responses.
        #[arg(long, conflicts_with = "show_headers")]
        json_errors: bool,
        /// Reject non-observational API operations before reading inputs or dispatch.
        /// This is an opt-in local guard, not authorization or capture redaction.
        #[arg(long)]
        read_only: bool,
        #[arg(long, default_value_t = 30.0)]
        timeout: f64,
    },
    /// Serve the embedded OpenAPI document as a local stdio MCP server.
    /// Tools are operation IDs. There is no second HTTP API.
    ///
    /// Pass exactly one endpoint: `--base-url`, `--endpoint-file`, or
    /// `--session-dir`. `--session-dir` reads `research-ui.endpoint` from that
    /// directory and does not consider a newer session. `/api/health` must
    /// report status ok before any tool is advertised. The health document is
    /// not printed.
    Mcp {
        #[arg(
            long,
            required_unless_present_any = ["endpoint_file", "session_dir"],
            conflicts_with_all = ["endpoint_file", "session_dir"]
        )]
        base_url: Option<String>,
        #[arg(long, conflicts_with_all = ["base_url", "session_dir"])]
        endpoint_file: Option<PathBuf>,
        /// Directory of one selected live session. Reads `research-ui.endpoint`
        /// there and does not search for a newer session.
        #[arg(
            long,
            value_name = "DIR",
            conflicts_with_all = ["base_url", "endpoint_file"]
        )]
        session_dir: Option<PathBuf>,
        /// Also list operations that are not read-only. This is not authorization,
        /// capture redaction, or permission to send results to a model provider.
        #[arg(long)]
        allow_effects: bool,
        /// Require live capture and a running or paused debugger at startup
        /// and before every tool call. Does not authorize capture or effects.
        #[arg(long)]
        require_live: bool,
        #[arg(long, default_value_t = 30.0)]
        timeout: f64,
    },
}
#[path = "reb_api/mcp.rs"]
mod mcp;
fn specification() -> Result<Value, serde_json::Error> {
    serde_json::from_str(include_str!("../../../../protocol/openapi.json"))
}
type Operation = (String, String, Value);
fn operations(spec: &Value) -> Result<BTreeMap<String, Operation>, String> {
    let mut result = BTreeMap::new();
    let paths = spec["paths"]
        .as_object()
        .ok_or("OpenAPI paths must be an object")?;
    for (path, item) in paths {
        for (method, definition) in item
            .as_object()
            .ok_or("OpenAPI path item must be an object")?
        {
            if ["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
                let id = definition["operationId"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| format!("Missing operation ID: {method} {path}"))?;
                if result
                    .insert(
                        id.to_owned(),
                        (method.to_uppercase(), path.clone(), definition.clone()),
                    )
                    .is_some()
                {
                    return Err(format!("Duplicate operation ID: {id}"));
                }
            }
        }
    }
    Ok(result)
}
fn reference_target<'a>(spec: &'a Value, reference: &str) -> Result<&'a Value, String> {
    let pointer = reference
        .strip_prefix('#')
        .filter(|pointer| pointer.starts_with("/components/"))
        .ok_or_else(|| format!("Unsupported OpenAPI reference: {reference}"))?;
    spec.pointer(pointer)
        .ok_or_else(|| format!("Unresolved OpenAPI reference: {reference}"))
}
fn resolve<'a>(spec: &'a Value, mut value: &'a Value) -> Result<&'a Value, String> {
    let mut visited = BTreeSet::new();
    while let Some(reference) = value.get("$ref") {
        let reference = reference.as_str().ok_or("OpenAPI $ref must be a string")?;
        if !visited.insert(reference) {
            return Err(format!("Cyclic OpenAPI reference alias: {reference}"));
        }
        value = reference_target(spec, reference)?;
    }
    Ok(value)
}
fn references(value: &Value) -> Result<BTreeSet<String>, String> {
    let mut result = BTreeSet::new();
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if matches!(key.as_str(), "$ref" | "x-result-schema") {
                        result.insert(
                            value
                                .as_str()
                                .ok_or_else(|| format!("OpenAPI {key} must be a string"))?
                                .to_owned(),
                        );
                    } else {
                        pending.push(value);
                    }
                }
            }
            Value::Array(values) => pending.extend(values),
            _ => {}
        }
    }
    Ok(result)
}
fn include_components(spec: &Value, detail: &mut Value) -> Result<(), String> {
    let mut pending = references(detail)?;
    let mut included = BTreeSet::new();
    let mut components = json!({});
    while let Some(reference) = pending.pop_first() {
        reference_target(spec, &reference)?;
        let parts = reference.split('/').collect::<Vec<_>>();
        if parts.len() < 4 || parts[2].is_empty() || parts[3].is_empty() {
            return Err(format!("Invalid OpenAPI component reference: {reference}"));
        }
        let root = parts[..4].join("/");
        if included.insert(root.clone()) {
            // Copy each owning component once. Internal $defs and recursive refs
            // retain their original pointers without exponential inline expansion.
            let component = reference_target(spec, &root)?;
            pending.extend(references(component)?);
            let section = parts[2].replace("~1", "/").replace("~0", "~");
            let name = parts[3].replace("~1", "/").replace("~0", "~");
            components[section][name] = component.clone();
        }
    }
    detail["components"] = components;
    Ok(())
}
fn describe(spec: &Value, operation: &Operation, action: Option<&str>) -> Result<Value, String> {
    let (method, path, definition) = operation;
    let policy = spec
        .get("x-reb-execution-policy")
        .filter(|policy| {
            policy["version"] == 1
                && policy["advisory"] == true
                && policy["automatic_retry"] == "never"
                && policy["idempotence"] == "unproven"
        })
        .ok_or("Missing or unsupported execution policy")?;
    let mut detail = definition.clone();
    detail["x-reb-execution-policy"] = policy.clone();
    detail["method"] = json!(method);
    detail["path"] = json!(path);
    for key in ["summary", "description", "requestBody", "responses"] {
        detail[key] = definition[key].clone();
    }
    detail["parameters"] = definition.get("parameters").cloned().unwrap_or(json!([]));
    let schema = resolve(
        spec,
        &definition["requestBody"]["content"]["application/json"]["schema"],
    )?;
    let mut actions = Vec::new();
    let mut variants = BTreeMap::new();
    if let Some(one_of) = schema.get("oneOf") {
        for variant in one_of.as_array().ok_or("OpenAPI oneOf must be an array")? {
            if let Some(name) = resolve(spec, variant)?["properties"]["action"]["const"].as_str() {
                actions.push(name);
                if variants.insert(name, variant).is_some() {
                    return Err(format!("Duplicate action discriminator: {name}"));
                }
            }
        }
    }
    if !actions.is_empty() {
        detail["actions"] = json!(actions);
    }
    if let Some(action) = action {
        let variant = variants.get(action).ok_or_else(|| {
            format!(
                "Unknown action: {action} for operation {}",
                definition["operationId"]
            )
        })?;
        // Keep the operation's common guards, locality and body limits intact.
        // Missing action metadata must not inherit an apparently safe default.
        let execution = resolve(spec, variant)?
            .get("x-reb-execution")
            .filter(|value| value["kind"] == "action")
            .ok_or_else(|| {
                format!("Missing or unsupported execution metadata for action: {action}")
            })?;
        detail["x-reb-selected-action-execution"] = execution.clone();
        let mut selected = schema.clone();
        selected["oneOf"] = json!([variant]);
        detail["requestBody"]["content"]["application/json"]["schema"] = selected;
        detail["action"] = json!(action);
        let response = resolve(
            spec,
            &definition["responses"]["200"]["content"]["application/json"]["schema"],
        )?;
        if let Some(results) = response.get("x-action-results") {
            let result = results
                .get(action)
                .ok_or_else(|| format!("Missing response schema for action: {action}"))?;
            let mut selected = response.clone();
            selected["oneOf"] = json!([result]);
            selected["x-action-results"] = json!({action: result});
            detail["responses"]["200"]["content"]["application/json"]["schema"] = selected;
        }
    }
    include_components(spec, &mut detail)?;
    Ok(detail)
}
fn root_url(value: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let url = Url::parse(value.trim())?;
    if url.scheme() != "http"
        || !["127.0.0.1", "localhost", "[::1]"].contains(&url.host_str().unwrap_or(""))
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("API URL must be an HTTP loopback server root with a port".into());
    }
    Ok(url)
}

// The embedded, reviewed catalog is the only authority for this opt-in guard.
// Do not classify by HTTP verb: some GETs control browsers or write caches,
// while package comparison POSTs only analyze supplied data. Unknown metadata
// fails closed. Output files and incidental server activity are not sandboxed.
fn read_only_eligible(spec: &Value, definition: &Value) -> bool {
    let policy = &spec["x-reb-execution-policy"];
    if policy["version"] != 1
        || policy["advisory"] != true
        || policy["automatic_retry"] != "never"
        || policy["idempotence"] != "unproven"
    {
        return false;
    }
    let execution = &definition["x-reb-execution"];
    let Some(schema) = spec.pointer("/components/schemas/RebExecutionMetadata") else {
        return false;
    };
    jsonschema::validator_for(schema).is_ok_and(|validator| validator.is_valid(execution))
        && execution["kind"] == "operation"
        && execution["effects"]
            .as_array()
            .is_some_and(|effects| effects.iter().all(|effect| effect == "analysis"))
        && ["state_dependent_effects", "uncertainties", "confirmations"]
            .iter()
            .all(|field| execution[field].as_array().is_some_and(Vec::is_empty))
}

fn discovery(spec: &Value, ops: &BTreeMap<String, Operation>) -> Value {
    json!({
        "format": "reb-api-discovery-v1",
        "execution_policy": spec["x-reb-execution-policy"],
        "operations": ops.iter().map(|(id, (method, path, definition))| json!({
            "operation_id": id,
            "method": method,
            "path": path,
            "summary": definition["summary"],
            "execution": definition["x-reb-execution"],
            "read_only_eligible": read_only_eligible(spec, definition),
        })).collect::<Vec<_>>()
    })
}

fn endpoint_text(
    base_url: Option<String>,
    endpoint_file: Option<PathBuf>,
) -> Result<String, Box<dyn std::error::Error>> {
    base_url
        .or_else(|| endpoint_file.and_then(|path| std::fs::read_to_string(path).ok()))
        .ok_or_else(|| "Cannot read endpoint file".into())
}

fn validated_loopback_root(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.lines().nth(1).is_some() {
        return Err(
            "Endpoint must be one HTTP loopback server root. No tools were advertised.".into(),
        );
    }
    root_url(trimmed).map_err(|_| {
        "Endpoint is not an HTTP loopback server root with a port. A native UI URL with a query is not the API root. Use the selected session's research-ui.endpoint. No tools were advertised."
    })?;
    Ok(trimmed.to_owned())
}

fn read_endpoint_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Symlink aliases are allowed; a replaced FIFO must not hang reconnect.
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "Endpoint file does not exist: {}. Start the selected Origin Trace session, or pass that session's research-ui.endpoint. No tools were advertised.",
                path.display()
            )
            .into());
        }
        Err(error) => {
            return Err(format!("Cannot read endpoint file {}: {error}.", path.display()).into());
        }
    };
    if !file.metadata()?.is_file() {
        return Err("Endpoint path must be a regular file. No tools were advertised.".into());
    }
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(format!(
            "Endpoint file {} is larger than 1024 bytes. No tools were advertised.",
            path.display()
        )
        .into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        format!(
            "Endpoint file {} is not UTF-8. No tools were advertised.",
            path.display()
        )
    })?;
    validated_loopback_root(text)
}

fn read_session_endpoint(dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "Session directory is a symlink: {}. Pass the selected directory itself. No other session was selected.",
                dir.display()
            )
            .into());
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(format!(
                "Session path is not a directory: {}. No other session was selected.",
                dir.display()
            )
            .into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "Session directory does not exist: {}. No other session was selected.",
                dir.display()
            )
            .into());
        }
        Err(error) => {
            return Err(format!(
                "Cannot read session directory {}: {error}. No other session was selected.",
                dir.display()
            )
            .into());
        }
    }
    let path = dir.join("research-ui.endpoint");
    read_endpoint_file(&path).map_err(|error| {
        format!("{error} This directory was selected explicitly; no newer session was considered.")
            .into()
    })
}

fn resolve_mcp_endpoint(
    base_url: Option<String>,
    endpoint_file: Option<PathBuf>,
    session_dir: Option<PathBuf>,
) -> Result<String, Box<dyn std::error::Error>> {
    match (base_url, endpoint_file, session_dir) {
        (Some(base_url), None, None) => validated_loopback_root(&base_url),
        (None, Some(path), None) => read_endpoint_file(&path),
        (None, None, Some(dir)) => read_session_endpoint(&dir),
        _ => Err(
            "Pass exactly one of --base-url, --endpoint-file, or --session-dir. No session was selected.".into(),
        ),
    }
}

struct LiveRefusal {
    code: &'static str,
    capture_mode: String,
    debugger_state: String,
    message: String,
}
struct McpHealth {
    instance_id: Option<String>,
    live_refusal: Option<LiveRefusal>,
}

// Health runs before stdio so a client cannot list tools for a missing session.
// The document names local evidence paths. Only allowlisted health fields enter
// diagnostics; the body is never printed. `no_proxy` keeps the probe on loopback.
async fn probe_mcp_health(
    base: &str,
    timeout: f64,
) -> Result<McpHealth, Box<dyn std::error::Error>> {
    let mut url = root_url(base)?;
    url.set_path("/api/health");
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs_f64(timeout))
        .build()?;
    let response = match client
        .get(url)
        .header("accept", "application/json")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return Err(format!(
                "Selected loopback API {base} did not respond at /api/health ({error}). Reconnect after starting the intended session. No tool request was sent."
            )
            .into());
        }
    };
    let status = response.status().as_u16();
    if status != 200 {
        return Err(format!(
            "Selected loopback API /api/health returned HTTP {status}. No tools were advertised."
        )
        .into());
    }
    let bytes = read_capped_body(response, 64 * 1024).await?;
    let value: Value = serde_json::from_slice(&bytes).map_err(
        |_| "Selected loopback API /api/health was not a JSON object. No tools were advertised.",
    )?;
    if value.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(
            "Selected loopback API /api/health did not report status ok. No tools were advertised."
                .into(),
        );
    }
    let instance_id = value["instance_id"]
        .as_str()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id.bytes().all(|byte| byte.is_ascii_digit() || byte == b':')
        })
        .map(str::to_owned);
    Ok(McpHealth {
        instance_id,
        live_refusal: live_refusal(base, &value),
    })
}

async fn confirm_mcp_health(
    base: &str,
    timeout: f64,
    require_live: bool,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let health = probe_mcp_health(base, timeout).await?;
    if require_live {
        if let Some(refusal) = health.live_refusal {
            return Err(refusal.message.into());
        }
        if health.instance_id.is_none() {
            return Err(format!("Live endpoint {base} has no supported instance_id. Rebuild the backend before connecting with --require-live. No tool request was sent.").into());
        }
    }
    Ok(health.instance_id)
}

fn live_refusal(base: &str, value: &Value) -> Option<LiveRefusal> {
    let capture = value["capture_mode"]
        .as_str()
        .filter(|mode| matches!(*mode, "live" | "idle" | "demo"))
        .unwrap_or("unknown");
    let debugger = value["debugger_state"]
        .as_str()
        .filter(|state| {
            matches!(
                *state,
                "running"
                    | "paused"
                    | "unavailable"
                    | "disconnected"
                    | "connecting"
                    | "waiting"
                    | "crashed"
            )
        })
        .unwrap_or("unknown");
    if capture == "live" && matches!(debugger, "running" | "paused") {
        return None;
    }
    let code = if capture == "idle" {
        "idle_backend"
    } else if capture == "live" {
        "debugger_unavailable"
    } else {
        "state_conflict"
    };
    Some(LiveRefusal {
        code,
        capture_mode: capture.to_owned(),
        debugger_state: debugger.to_owned(),
        message: format!(
            "code={code} Live capture is unavailable at {base}: capture_mode={capture}, debugger_state={debugger}. Reconnect after the intended live debugger is ready, or explicitly select a stored-evidence endpoint without --require-live. No tool request was sent."
        ),
    })
}

struct McpEndpointGuard {
    endpoint_file: Option<PathBuf>,
    require_live: bool,
    retired: bool,
    instance_id: Option<String>,
}

impl McpEndpointGuard {
    fn verify_instance(&mut self, base: &str, current: Option<String>) -> Result<(), String> {
        if self.instance_id != current {
            self.retired = true;
        }
        self.verify_endpoint(base)
    }
    fn verify_endpoint(&mut self, base: &str) -> Result<(), String> {
        if !self.retired
            && let Some(path) = &self.endpoint_file
        {
            // Never transfer a pending operation to a new session. A fresh
            // stdio process resolves the file again after client reconnect.
            self.retired = !read_endpoint_file(path).is_ok_and(|current| current == base);
        }
        if self.retired {
            return Err(format!(
                "Selected endpoint file or backend instance changed or became unavailable (connected endpoint {base}). Reconnect the MCP server to resolve the current endpoint and reselect evidence before acting. No tool request was sent."
            ));
        }
        Ok(())
    }
}

async fn read_capped_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(
            |_| "Selected loopback API /api/health could not be read. No tools were advertised.",
        )?;
        let Some(chunk) = chunk else {
            break;
        };
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(
                "Selected loopback API /api/health exceeded 64 KiB. No tools were advertised."
                    .into(),
            );
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
fn check_timeout(timeout: f64) -> Result<(), Box<dyn std::error::Error>> {
    if !timeout.is_finite() || timeout <= 0.0 || timeout > 3600.0 {
        return Err("Timeout must be finite and between 0 and 3600 seconds".into());
    }
    Ok(())
}
struct CompletedExchange {
    status: u16,
    headers: BTreeMap<String, String>,
    bytes: Vec<u8>,
    /// The body could not be read. `bytes` is a fixed diagnostic, not a partial response.
    unreadable: bool,
}
struct ExchangeRequest<'a> {
    method: &'a str,
    path: &'a str,
    definition: &'a Value,
    base: &'a str,
    params: &'a BTreeMap<String, String>,
    body: Option<Vec<u8>>,
    timeout: f64,
    json_errors: bool,
    missing_body: &'a str,
    expected_instance: Option<&'a str>,
}
async fn exchange(
    request: ExchangeRequest<'_>,
) -> Result<CompletedExchange, Box<dyn std::error::Error>> {
    let ExchangeRequest {
        method,
        path,
        definition,
        base,
        params,
        body,
        timeout,
        json_errors,
        missing_body,
        expected_instance,
    } = request;
    let mut url = root_url(base)?;
    let mut route = path.to_owned();
    let definitions = definition["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for parameter in &definitions {
        if parameter["required"] == true
            && !params.contains_key(parameter["name"].as_str().unwrap())
        {
            return Err(format!("Missing parameter: {}", parameter["name"]).into());
        }
    }
    let mut headers = Vec::new();
    let mut query = Vec::new();
    for (name, value) in params {
        let parameter = definitions
            .iter()
            .find(|parameter| parameter["name"] == name.as_str())
            .ok_or_else(|| format!("Unknown parameter: {name}"))?;
        match parameter["in"].as_str() {
            Some("path") => {
                if value.is_empty() {
                    return Err("Path parameter cannot be empty".into());
                }
                let encoded = url::form_urlencoded::byte_serialize(value.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20");
                route = route.replace(&format!("{{{name}}}"), &encoded);
            }
            Some("query") => query.push((name.clone(), value.clone())),
            Some("header") => headers.push((name.clone(), value.clone())),
            _ => return Err("Unsupported parameter location".into()),
        }
    }
    url = url.join(&route)?;
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    let binary = definition["responses"]["200"]["content"]
        .get("application/octet-stream")
        .is_some();
    let export_package = definition["operationId"] == "export_evidence_package";
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs_f64(timeout))
        .build()?;
    let mut request = client.request(method.parse()?, url).header(
        "accept",
        if binary {
            "application/octet-stream"
        } else {
            "application/json"
        },
    );
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if let Some(instance) = expected_instance {
        request = request.header("x-reb-expected-instance", instance);
    }
    if definition.get("requestBody").is_some() {
        let raw = body.ok_or(missing_body)?;
        let limit = definition["x-max-body-bytes"]
            .as_u64()
            .unwrap_or(2 * 1024 * 1024);
        if raw.len() as u64 > limit {
            return Err("Request body exceeds its byte limit".into());
        }
        if definition["operationId"] == "compare_evidence_packages" {
            origin_trace_backend::evidence_comparison::preflight(&raw)?;
            request = request.header("content-type", "application/json").body(raw);
        } else if matches!(
            definition["operationId"].as_str(),
            Some("validate_evidence_package" | "export_evidence_package" | "compare_float32")
        ) {
            if definition["operationId"] == "compare_float32" {
                origin_trace_backend::float32::validate_request_bytes(&raw)?;
            } else {
                origin_trace_backend::evidence_package::parse_bytes(&raw)?;
            }
            request = request.header("content-type", "application/json").body(raw);
        } else {
            let parsed: Value = serde_json::from_slice(&raw)?;
            if !parsed.is_object() {
                return Err("Request body must be a JSON object".into());
            }
            request = request.json(&parsed);
        }
    } else if body.is_some() {
        return Err("Operation does not accept a body".into());
    }
    let mut response = request.send().await?;
    let status = response.status();
    let response_headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if status.as_u16() == 304 {
        return Ok(CompletedExchange {
            status: 304,
            headers: response_headers,
            bytes: Vec::new(),
            unreadable: false,
        });
    }
    let mut bytes = Vec::new();
    let response_limit = if export_package && status.is_success() {
        origin_trace_backend::evidence_package::MAX_BYTES
    } else if definition["operationId"] == "compare_evidence_packages" && status.is_success() {
        origin_trace_backend::evidence_comparison::MAX_RESULT_BYTES
    } else {
        64 * 1024 * 1024
    };
    loop {
        let chunk = match response.chunk().await {
            Ok(chunk) => chunk,
            Err(_) if json_errors && !status.is_success() => {
                return Ok(CompletedExchange {
                    status: status.as_u16(),
                    headers: response_headers,
                    bytes: br#"{"error":"API error response could not be read"}"#.to_vec(),
                    unreadable: true,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let Some(chunk) = chunk else {
            break;
        };
        if bytes.len().saturating_add(chunk.len()) > response_limit {
            if json_errors && !status.is_success() {
                return Ok(CompletedExchange {
                    status: status.as_u16(),
                    headers: response_headers,
                    bytes: br#"{"error":"API response exceeds 64 MiB"}"#.to_vec(),
                    unreadable: true,
                });
            }
            return Err(if export_package {
                "Evidence package response exceeds its byte limit"
            } else {
                "API response exceeds 64 MiB"
            }
            .into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if status.is_success() && !binary {
        if export_package {
            let result = origin_trace_backend::evidence_package::validate_bytes(&bytes)?;
            if result["status"] != "valid" {
                return Err("The exported evidence package failed validation".into());
            }
        } else {
            let _: Value = serde_json::from_slice(&bytes)?;
        }
    }
    Ok(CompletedExchange {
        status: status.as_u16(),
        headers: response_headers,
        bytes,
        unreadable: false,
    })
}
async fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let options = Options::parse();
    let spec = specification()?;
    let ops = operations(&spec)?;
    match options.command {
        Action::Spec => {
            println!("{}", serde_json::to_string_pretty(&spec)?);
            Ok(0)
        }
        Action::List { json: machine } => {
            if machine {
                println!("{}", serde_json::to_string_pretty(&discovery(&spec, &ops))?);
            } else {
                for (id, (method, path, _)) in &ops {
                    println!("{id}\t{method}\t{path}");
                }
            }
            Ok(0)
        }
        Action::Mcp {
            base_url,
            endpoint_file,
            session_dir,
            allow_effects,
            require_live,
            timeout,
        } => {
            check_timeout(timeout)?;
            let mut guard = McpEndpointGuard {
                endpoint_file: endpoint_file.clone().or_else(|| {
                    session_dir
                        .as_ref()
                        .map(|dir| dir.join("research-ui.endpoint"))
                }),
                require_live,
                retired: false,
                instance_id: None,
            };
            let base = resolve_mcp_endpoint(base_url, endpoint_file, session_dir)?;
            guard.instance_id = confirm_mcp_health(&base, timeout, require_live).await?;
            guard.verify_endpoint(&base)?;
            mcp::serve(&spec, &ops, &base, allow_effects, timeout, guard).await
        }
        Action::Describe {
            operation_id,
            action,
        } => {
            let operation = ops
                .get(&operation_id)
                .ok_or_else(|| format!("Unknown operation: {operation_id}"))?;
            let detail = describe(&spec, operation, action.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&detail)?);
            Ok(0)
        }
        Action::Call {
            operation_id,
            base_url,
            endpoint_file,
            params,
            body_file,
            output,
            show_headers,
            json_errors,
            read_only,
            timeout,
        } => {
            let operation = ops
                .get(&operation_id)
                .ok_or_else(|| format!("Unknown operation: {operation_id}"))?;
            let (method, path, definition) = operation;
            if read_only && !read_only_eligible(&spec, definition) {
                return Err(format!(
                    "--read-only rejects operation {}; inspect its execution metadata with describe. No request was sent",
                    definition["operationId"].as_str().unwrap_or("unknown")
                )
                .into());
            }
            check_timeout(timeout)?;
            let binary = definition["responses"]["200"]["content"]
                .get("application/octet-stream")
                .is_some();
            if binary && output.is_none() {
                return Err("Binary responses require --output PATH or --output -".into());
            }
            let mut values = BTreeMap::new();
            for param in params {
                let (name, value) = param
                    .split_once('=')
                    .filter(|(name, _)| !name.is_empty())
                    .ok_or("--param must be NAME=VALUE")?;
                if value.contains(['\r', '\n'])
                    || values.insert(name.to_owned(), value.to_owned()).is_some()
                {
                    return Err("Duplicate parameter or line break in parameter".into());
                }
            }
            let body = if definition.get("requestBody").is_some() {
                let path =
                    body_file.ok_or("Operation requires --body-file PATH or --body-file -")?;
                let mut raw = Vec::new();
                let limit = definition["x-max-body-bytes"]
                    .as_u64()
                    .unwrap_or(2 * 1024 * 1024);
                if path == "-" {
                    std::io::stdin().take(limit + 1).read_to_end(&mut raw)?;
                } else {
                    std::fs::File::open(path)?
                        .take(limit + 1)
                        .read_to_end(&mut raw)?;
                }
                if raw.len() as u64 > limit {
                    return Err("Request body exceeds its byte limit".into());
                }
                Some(raw)
            } else if body_file.is_some() {
                return Err("Operation does not accept a body".into());
            } else {
                None
            };
            let base = endpoint_text(base_url, endpoint_file)?;
            let completed = exchange(ExchangeRequest {
                method,
                path,
                definition,
                base: &base,
                params: &values,
                body,
                timeout,
                json_errors,
                missing_body: "Operation requires --body-file PATH or --body-file -",
                expected_instance: None,
            })
            .await?;
            if show_headers {
                eprintln!(
                    "{}",
                    json!({"status": completed.status, "headers": completed.headers})
                );
            }
            if completed.unreadable {
                eprintln!(
                    "{}",
                    bounded_http_error(&spec, completed.status, &completed.bytes)
                );
                return Ok(2);
            }
            if completed.status == 304 {
                return Ok(0);
            }
            if !(200..300).contains(&completed.status) {
                if json_errors {
                    eprintln!(
                        "{}",
                        bounded_http_error(&spec, completed.status, &completed.bytes)
                    );
                } else {
                    eprintln!(
                        "HTTP {}: {}",
                        completed.status,
                        String::from_utf8_lossy(&completed.bytes)
                            .chars()
                            .take(500)
                            .collect::<String>()
                    );
                }
                return Ok(1);
            }
            if let Some(path) = output {
                if path == "-" {
                    std::io::stdout().write_all(&completed.bytes)?;
                } else {
                    origin_trace_backend::write_private_noclobber(
                        std::path::Path::new(&path),
                        &completed.bytes,
                    )?;
                }
            } else {
                let value: Value = serde_json::from_slice(&completed.bytes)?;
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            Ok(0)
        }
    }
}
// This mode projects known fields only. A legacy or non-JSON response must
// never turn into a raw body/header dump or a prose-derived reason.
fn bounded_http_error(spec: &Value, status: u16, bytes: &[u8]) -> Value {
    let value = serde_json::from_slice::<Value>(bytes).unwrap_or(Value::Null);
    let message = value["error"]
        .as_str()
        .unwrap_or("API returned an unrecognized error response");
    let mut end = message.len().min(512);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = json!({"http_status":status,"code":"unspecified","details":{},
        "error":&message[..end],"error_truncated":end < message.len()});
    if value["error"].is_string()
        && spec["components"]["schemas"]["ErrorCode"]["enum"]
            .as_array()
            .is_some_and(|codes| codes.contains(&value["code"]))
    {
        result["code"] = value["code"].clone();
        let schema =
            json!({"$ref":"#/components/schemas/ErrorDetails","components":spec["components"]});
        if jsonschema::validator_for(&schema)
            .is_ok_and(|validator| validator.is_valid(&value["details"]))
            && origin_trace_backend::action_guidance::valid_details(spec, &value["details"])
        {
            result["details"] = value["details"].clone();
        }
    }
    result
}
#[tokio::main]
async fn main() {
    match run().await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("reb-api: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_classification_uses_effects_not_the_http_verb() {
        let spec = specification().unwrap();
        let ops = operations(&spec).unwrap();
        for id in [
            "get_health",
            "get_api_observation_catalog",
            "get_network_request",
            "get_origin_trace",
            "get_events",
            "get_artifacts",
            "inspect_wasm",
            "validate_evidence_package",
            "export_evidence_package",
            "compare_evidence_packages",
            "compare_float32",
        ] {
            assert!(read_only_eligible(&spec, &ops[id].2), "{id}");
        }
        for id in [
            "capture_action",
            "analyst_action",
            "decoder_action",
            "native_console_action",
            "replace_api_collection",
            "get_native_console",
            "get_vm_analysis",
            "get_source_facts",
            "get_deobfuscation",
        ] {
            assert!(!read_only_eligible(&spec, &ops[id].2), "{id}");
        }
    }

    #[test]
    fn read_only_classification_fails_closed_on_unknown_or_incomplete_metadata() {
        let spec = specification().unwrap();
        let operation = operations(&spec).unwrap()["get_health"].2.clone();
        let mut missing = operation.clone();
        missing.as_object_mut().unwrap().remove("x-reb-execution");
        assert!(!read_only_eligible(&spec, &missing));
        for field in [
            "kind",
            "effects",
            "state_dependent_effects",
            "uncertainties",
            "confirmations",
            "prerequisites",
            "notes",
            "sources",
        ] {
            let mut incomplete = operation.clone();
            incomplete["x-reb-execution"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(!read_only_eligible(&spec, &incomplete), "{field}");
        }
        for (field, value) in [
            ("effects", json!(["unreviewed-effect"])),
            ("effects", json!(null)),
            ("kind", json!("action-dependent")),
            ("uncertainties", json!(["unknown target behavior"])),
            (
                "state_dependent_effects",
                json!([{"effects":["filesystem-write"],"when":"cache miss"}]),
            ),
            (
                "confirmations",
                json!([{"field":"confirmed","value":true,"when":{}}]),
            ),
            ("new_guard", json!(true)),
        ] {
            let mut unknown = operation.clone();
            unknown["x-reb-execution"][field] = value;
            assert!(!read_only_eligible(&spec, &unknown), "{field}");
        }
        for (field, value) in [
            ("version", json!(2)),
            ("advisory", json!(false)),
            ("automatic_retry", json!("allowed")),
            ("idempotence", json!(null)),
        ] {
            let mut unknown = spec.clone();
            unknown["x-reb-execution-policy"][field] = value;
            assert!(!read_only_eligible(&unknown, &operation), "{field}");
        }
        let mut unknown = spec.clone();
        unknown["components"]["schemas"]
            .as_object_mut()
            .unwrap()
            .remove("RebExecutionMetadata");
        assert!(!read_only_eligible(&unknown, &operation));
    }

    #[test]
    fn read_only_guard_and_json_discovery_are_opt_in() {
        assert!(matches!(
            Options::try_parse_from(["reb-api", "list"])
                .unwrap()
                .command,
            Action::List { json: false }
        ));
        assert!(matches!(
            Options::try_parse_from(["reb-api", "list", "--json"])
                .unwrap()
                .command,
            Action::List { json: true }
        ));
        let args = [
            "reb-api",
            "call",
            "get_health",
            "--base-url",
            "http://127.0.0.1:7319",
        ];
        assert!(matches!(
            Options::try_parse_from(args).unwrap().command,
            Action::Call {
                read_only: false,
                ..
            }
        ));
        assert!(matches!(
            Options::try_parse_from(args.into_iter().chain(["--read-only"]))
                .unwrap()
                .command,
            Action::Call {
                read_only: true,
                ..
            }
        ));
        assert!(Options::try_parse_from(["reb-api", "call", "get_health", "--read-only"]).is_err());
    }

    fn assert_self_contained(detail: &Value) {
        for reference in references(detail).unwrap() {
            assert!(
                detail
                    .pointer(reference.strip_prefix('#').unwrap())
                    .is_some(),
                "Unresolved reference in description: {reference}"
            );
        }
    }

    #[test]
    fn json_errors_are_bounded_structured_and_do_not_classify_legacy_prose() {
        let spec = specification().unwrap();
        let long = "timeout cancelled secret 雪".repeat(200);
        let value = bounded_http_error(
            &spec,
            409,
            &serde_json::to_vec(&json!({"error":long,"stack":"do not copy"})).unwrap(),
        );
        assert_eq!(value["http_status"], 409);
        assert_eq!(value["code"], "unspecified");
        assert_eq!(value["details"], json!({}));
        assert_eq!(value["error_truncated"], true);
        let message = value["error"].as_str().unwrap();
        assert!(message.len() <= 512 && long.starts_with(message));
        assert_eq!(value.as_object().unwrap().len(), 5);
        for bytes in [
            &b"<html>private raw body</html>"[..],
            b"{",
            b"null",
            b"[]",
            b"{\"error\":{\"secret\":\"private\"}}",
        ] {
            let value = bounded_http_error(&spec, 502, bytes);
            assert_eq!(value["code"], "unspecified");
            assert_eq!(
                value["error"],
                "API returned an unrecognized error response"
            );
            assert_eq!(value["error_truncated"], false);
            assert!(!value.to_string().contains("private"));
        }
        let typed = json!({"error":"The command timed out","code":"command_outcome_unknown","details":{"phase":"command_exchange","cause":"timeout"},"headers":{"authorization":"private"}});
        let value = bounded_http_error(&spec, 409, &serde_json::to_vec(&typed).unwrap());
        assert_eq!(value["code"], typed["code"]);
        assert_eq!(value["details"], typed["details"]);
        assert_eq!(value["error_truncated"], false);
        for reason in ["stale_capture", "request_not_retained", "ambiguous_request"] {
            let typed = json!({"error":"Exact selection unavailable","code":"state_conflict",
                "details":{"selection_reason":reason}});
            let value = bounded_http_error(&spec, 409, &serde_json::to_vec(&typed).unwrap());
            assert_eq!(value["details"], typed["details"]);
        }
        for details in [
            json!({"raw":"private"}),
            json!({"phase":"invented"}),
            json!({"selection_reason":"synthetic-private-unknown"}),
            json!({"expected_generation":u64::MAX}),
        ] {
            let value = bounded_http_error(
                &spec,
                409,
                &serde_json::to_vec(
                    &json!({"error":"failure","code":"state_conflict","details":details}),
                )
                .unwrap(),
            );
            assert_eq!(value["code"], "state_conflict");
            assert_eq!(value["details"], json!({}));
        }
    }
    #[test]
    fn json_error_mode_is_opt_in_and_does_not_dump_headers() {
        let args = [
            "reb-api",
            "call",
            "get_health",
            "--base-url",
            "http://127.0.0.1:7319",
        ];
        assert!(matches!(
            Options::try_parse_from(args).unwrap().command,
            Action::Call {
                json_errors: false,
                ..
            }
        ));
        assert!(matches!(
            Options::try_parse_from(args.into_iter().chain(["--json-errors"]))
                .unwrap()
                .command,
            Action::Call {
                json_errors: true,
                ..
            }
        ));
        assert!(
            Options::try_parse_from(args.into_iter().chain(["--json-errors", "--show-headers"]))
                .is_err()
        );
    }

    #[test]
    fn mcp_requires_a_loopback_endpoint_and_hides_effects_by_default() {
        assert!(Options::try_parse_from(["reb-api", "mcp"]).is_err());
        assert!(matches!(
            Options::try_parse_from(["reb-api", "mcp", "--base-url", "http://127.0.0.1:7319",])
                .unwrap()
                .command,
            Action::Mcp {
                allow_effects: false,
                ..
            }
        ));
        assert!(matches!(
            Options::try_parse_from([
                "reb-api",
                "mcp",
                "--base-url",
                "http://127.0.0.1:7319",
                "--allow-effects",
            ])
            .unwrap()
            .command,
            Action::Mcp {
                allow_effects: true,
                ..
            }
        ));
        assert!(matches!(
            Options::try_parse_from(["reb-api", "mcp", "--session-dir", "/tmp/session"])
                .unwrap()
                .command,
            Action::Mcp {
                allow_effects: false,
                session_dir: Some(_),
                base_url: None,
                endpoint_file: None,
                ..
            }
        ));
        for extra in [
            vec!["--session-dir", "/tmp/session"],
            vec!["--endpoint-file", "endpoint"],
        ] {
            let mut args = vec!["reb-api", "mcp", "--base-url", "http://127.0.0.1:7319"];
            args.extend(extra);
            assert!(Options::try_parse_from(args).is_err());
        }
        assert!(
            Options::try_parse_from([
                "reb-api",
                "mcp",
                "--endpoint-file",
                "endpoint",
                "--session-dir",
                "/tmp/session",
            ])
            .is_err()
        );
    }

    #[test]
    fn session_dir_reads_only_its_own_endpoint_file() {
        let root = tempfile::tempdir().unwrap();
        let selected = root.path().join("7");
        let newer = root.path().join("8");
        std::fs::create_dir(&selected).unwrap();
        std::fs::create_dir(&newer).unwrap();
        std::fs::write(
            selected.join("research-ui.endpoint"),
            "http://127.0.0.1:9\n",
        )
        .unwrap();
        std::fs::write(newer.join("research-ui.endpoint"), "http://127.0.0.1:10\n").unwrap();
        assert_eq!(
            read_session_endpoint(&selected).unwrap(),
            "http://127.0.0.1:9"
        );
        let missing = root.path().join("9");
        std::fs::create_dir(&missing).unwrap();
        let error = read_session_endpoint(&missing).unwrap_err().to_string();
        assert!(error.contains("research-ui.endpoint"), "{error}");
        assert!(error.contains("no newer session"), "{error}");
        let link = root.path().join("linked");
        std::os::unix::fs::symlink(&newer, &link).unwrap();
        let error = read_session_endpoint(&link).unwrap_err().to_string();
        assert!(error.contains("symlink"), "{error}");
        let handshake = root.path().join("handshake");
        std::fs::write(&handshake, "http://127.0.0.1:9/?native=1\n").unwrap();
        let error = read_endpoint_file(&handshake).unwrap_err().to_string();
        assert!(error.contains("loopback"), "{error}");
        assert!(!error.contains("native=1"), "{error}");
        let absent = root.path().join("missing-endpoint");
        let error = read_endpoint_file(&absent).unwrap_err().to_string();
        assert!(error.contains("does not exist"), "{error}");
        assert!(validated_loopback_root("https://example.test:443").is_err());
    }

    #[test]
    fn every_description_includes_its_reachable_components() {
        let spec = specification().unwrap();
        for operation in operations(&spec).unwrap().values() {
            let detail = describe(&spec, operation, None).unwrap();
            assert_self_contained(&detail);
            assert_eq!(detail["operationId"], operation.2["operationId"]);
            assert_eq!(detail["requestBody"], operation.2["requestBody"]);
            assert_eq!(detail["responses"], operation.2["responses"]);
            assert_eq!(detail["x-max-body-bytes"], operation.2["x-max-body-bytes"]);
            assert_eq!(detail["x-reb-execution"], operation.2["x-reb-execution"]);
            assert_eq!(
                detail["x-reb-execution-policy"],
                spec["x-reb-execution-policy"]
            );
            assert!(
                detail["components"]["schemas"]
                    .get("RebExecutionMetadata")
                    .is_some()
            );
        }
        let health = describe(&spec, &operations(&spec).unwrap()["get_health"], None).unwrap();
        assert!(health["components"]["schemas"].get("Health").is_some());
        assert!(health["components"]["schemas"].get("Error").is_some());
        assert!(
            health["components"]["schemas"]
                .get("DebuggerAction")
                .is_none()
        );
        assert!(health.get("actions").is_none());
        assert!(health["requestBody"].is_null());
    }

    #[test]
    fn evidence_package_discovery_is_self_contained_and_inert() {
        let spec = specification().unwrap();
        let ops = operations(&spec).unwrap();
        let operation = &ops["validate_evidence_package"];
        assert_eq!(operation.0, "POST");
        assert_eq!(operation.1, "/api/evidence/packages/validate");
        let detail = describe(&spec, operation, None).unwrap();
        assert_self_contained(&detail);
        assert_eq!(detail["x-max-body-bytes"], 4 * 1024 * 1024);
        assert_eq!(detail["x-reb-execution"]["effects"], json!(["analysis"]));
        assert_eq!(detail["x-reb-execution-policy"]["automatic_retry"], "never");
        assert!(detail.get("actions").is_none());
        assert_eq!(
            detail["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/EvidencePackage"
        );
        assert_eq!(
            detail["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/EvidencePackageValidationResult"
        );
        for name in [
            "EvidencePackage",
            "EvidencePackageValidationResult",
            "EvidencePackageEventMetadata",
            "EvidencePackageArtifactMetadata",
            "EvidencePackageRelationship",
            "EvidencePackageGap",
            "Error",
            "RebExecutionMetadata",
        ] {
            assert!(
                detail["components"]["schemas"].get(name).is_some(),
                "{name}"
            );
        }
        assert!(
            detail["components"]["schemas"]
                .get("DebuggerAction")
                .is_none()
        );
        assert!(describe(&spec, operation, Some("validate")).is_err());
    }

    #[test]
    fn every_documented_action_can_be_described_without_a_server() {
        let spec = specification().unwrap();
        for operation in operations(&spec).unwrap().values() {
            let detail = describe(&spec, operation, None).unwrap();
            for action in detail["actions"].as_array().into_iter().flatten() {
                let name = action.as_str().unwrap();
                let selected = describe(&spec, operation, Some(name)).unwrap();
                assert_self_contained(&selected);
                assert_eq!(selected["action"], name);
                assert_eq!(selected["actions"], detail["actions"]);
                let variants =
                    selected["requestBody"]["content"]["application/json"]["schema"]["oneOf"]
                        .as_array()
                        .unwrap();
                assert_eq!(variants.len(), 1);
                assert_eq!(
                    resolve(&selected, &variants[0]).unwrap()["properties"]["action"]["const"],
                    name
                );
                assert_eq!(selected["x-reb-execution"], detail["x-reb-execution"]);
                assert_eq!(
                    selected["x-reb-selected-action-execution"],
                    resolve(&selected, &variants[0]).unwrap()["x-reb-execution"]
                );
                assert_eq!(
                    selected["x-reb-execution-policy"]["automatic_retry"],
                    "never"
                );
            }
        }
    }

    #[test]
    fn selected_native_action_keeps_constraints_and_mapped_response() {
        let mut spec = specification().unwrap();
        // Exercise optional response mapping without reviving a removed CDP route.
        spec["paths"]["/api/capture/actions"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"] = json!({"oneOf":[{"$ref":"#/components/schemas/CaptureResult"}],"x-action-results":{"clear":{"$ref":"#/components/schemas/CaptureResult"}}});
        let ops = operations(&spec).unwrap();
        let operation = &ops["capture_action"];
        let detail = describe(&spec, operation, Some("clear")).unwrap();
        let request = &detail["requestBody"]["content"]["application/json"]["schema"]["oneOf"][0];
        assert_eq!(request["required"], json!(["action", "confirm"]));
        assert_eq!(request["properties"]["confirm"]["const"], true);
        let response = &detail["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(response["oneOf"].as_array().unwrap().len(), 1);
        assert_eq!(
            response["oneOf"][0]["$ref"],
            "#/components/schemas/CaptureResult"
        );
        assert_eq!(response["x-action-results"].as_object().unwrap().len(), 1);
        assert_eq!(detail["responses"]["409"], operation.2["responses"]["409"]);
        assert_eq!(detail["x-max-body-bytes"], 256);
        assert_self_contained(&detail);
    }

    #[test]
    fn action_without_a_result_mapping_keeps_the_success_contract() {
        let spec = specification().unwrap();
        let operation = &operations(&spec).unwrap()["decoder_action"];
        let detail = describe(&spec, operation, Some("jwt_inspect")).unwrap();
        assert_eq!(detail["responses"], operation.2["responses"]);
        assert_self_contained(&detail);
    }

    #[test]
    fn unknown_actions_fail_explicitly() {
        let spec = specification().unwrap();
        let ops = operations(&spec).unwrap();
        for id in ["capture_action", "get_health"] {
            assert!(
                describe(&spec, &ops[id], Some("not_an_action"))
                    .unwrap_err()
                    .contains("Unknown action")
            );
        }
        let mut spec = spec;
        let mut operation = ops["capture_action"].clone();
        operation.2["responses"]["200"]["content"]["application/json"]["schema"] =
            json!({"oneOf":[{"$ref":"#/components/schemas/CaptureResult"}],"x-action-results":{}});
        spec["components"]["schemas"]["CaptureAction"]["oneOf"][0]["x-result-schema"] =
            json!("#/components/schemas/CaptureResult");
        assert!(
            describe(&spec, &operation, Some("stop"))
                .unwrap_err()
                .contains("Missing response schema")
        );
    }

    #[test]
    fn missing_or_unsupported_action_metadata_never_inherits_a_default() {
        for replacement in [Value::Null, json!({"kind": "operation"})] {
            let mut spec = specification().unwrap();
            let action = spec["components"]["schemas"]["CaptureAction"]["oneOf"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v["properties"]["action"]["const"] == "stop")
                .unwrap();
            action["x-reb-execution"] = replacement;
            assert!(
                describe(
                    &spec,
                    &operations(&spec).unwrap()["capture_action"],
                    Some("stop")
                )
                .unwrap_err()
                .contains("execution metadata")
            );
        }
        for policy in [
            Value::Null,
            json!({"version":2,"advisory":true,"automatic_retry":"never","idempotence":"unproven"}),
        ] {
            let mut spec = specification().unwrap();
            spec["x-reb-execution-policy"] = policy;
            assert!(
                describe(&spec, &operations(&spec).unwrap()["get_health"], None)
                    .unwrap_err()
                    .contains("execution policy")
            );
        }
    }

    #[test]
    fn component_closure_retains_nested_and_recursive_pointers_once() {
        let spec = json!({"components": {"schemas": {
            "Node/~": {"$defs": {"node": {"type": "object", "properties": {
                "next": {"$ref": "#/components/schemas/Node~1~0/$defs/node"},
                "label": {"$ref": "#/components/schemas/Label"}
            }}}},
            "Label": {"type": "string"},
            "Unused": {"type": "integer"}
        }}});
        let mut detail = json!({"schema": {"$ref": "#/components/schemas/Node~1~0/$defs/node"}});
        include_components(&spec, &mut detail).unwrap();
        assert_eq!(
            detail["components"]["schemas"].as_object().unwrap().len(),
            2
        );
        assert_self_contained(&detail);
        assert_eq!(
            detail["components"]["schemas"]["Node/~"],
            spec["components"]["schemas"]["Node/~"]
        );
    }

    #[test]
    fn malformed_and_missing_references_fail_instead_of_returning_partial_output() {
        let spec = json!({"components": {"schemas": {"Present": {"type": "string"}}}});
        for reference in [
            json!(false),
            json!("#/components/schemas/Missing"),
            json!("https://example.invalid/schema"),
            json!("#/paths"),
        ] {
            let mut detail = json!({"schema": {"$ref": reference}});
            assert!(include_components(&spec, &mut detail).is_err());
            assert!(resolve(&spec, &detail["schema"]).is_err());
        }
    }

    #[test]
    fn long_alias_chains_resolve_and_alias_cycles_fail() {
        let mut spec = json!({"components": {"schemas": {"End": {"type": "string"}}}});
        for index in 0..32 {
            let next = if index == 31 {
                "End".to_owned()
            } else {
                format!("Alias{}", index + 1)
            };
            spec["components"]["schemas"][format!("Alias{index}")] =
                json!({"$ref": format!("#/components/schemas/{next}")});
        }
        let root = json!({"$ref": "#/components/schemas/Alias0"});
        assert_eq!(resolve(&spec, &root).unwrap()["type"], "string");
        spec["components"]["schemas"]["End"] = root.clone();
        assert!(
            resolve(&spec, &root)
                .unwrap_err()
                .contains("Cyclic OpenAPI reference alias")
        );
        let mut detail = json!({"schema": root});
        include_components(&spec, &mut detail).unwrap();
        assert_eq!(
            detail["components"]["schemas"].as_object().unwrap().len(),
            33
        );
        assert_self_contained(&detail);
    }

    #[test]
    fn operation_discovery_rejects_malformed_and_duplicate_ids() {
        for spec in [
            json!({}),
            json!({"paths": {"/test": null}}),
            json!({"paths": {"/test": {"get": {}}}}),
            json!({"paths": {"/test": {"get": {"operationId": ""}}}}),
        ] {
            assert!(operations(&spec).is_err());
        }
        let spec = json!({"paths": {"/test": {"get": {"operationId": "same"}, "post": {"operationId": "same"}}}});
        assert!(
            operations(&spec)
                .unwrap_err()
                .contains("Duplicate operation ID")
        );
    }

    #[test]
    fn describe_action_flag_is_optional_and_call_still_requires_an_endpoint() {
        assert!(Options::try_parse_from(["reb-api", "list"]).is_ok());
        assert!(Options::try_parse_from(["reb-api", "spec"]).is_ok());
        assert!(Options::try_parse_from(["reb-api", "describe", "capture_action"]).is_ok());
        assert!(
            Options::try_parse_from(["reb-api", "describe", "capture_action", "--action", "stop"])
                .is_ok()
        );
        assert!(Options::try_parse_from(["reb-api", "call", "capture_action"]).is_err());
        assert!(
            Options::try_parse_from([
                "reb-api",
                "call",
                "capture_action",
                "--base-url",
                "http://127.0.0.1:7319",
                "--action",
                "stop"
            ])
            .is_err()
        );
    }
}
