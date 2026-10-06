use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::PathBuf,
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
    List,
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
        #[arg(long, default_value_t = 30.0)]
        timeout: f64,
    },
}
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
async fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let options = Options::parse();
    let spec = specification()?;
    let ops = operations(&spec)?;
    let id = match &options.command {
        Action::Spec => {
            println!("{}", serde_json::to_string_pretty(&spec)?);
            return Ok(0);
        }
        Action::List => {
            for (id, (method, path, _)) in &ops {
                println!("{id}\t{method}\t{path}");
            }
            return Ok(0);
        }
        Action::Describe { operation_id, .. } | Action::Call { operation_id, .. } => operation_id,
    };
    let operation = ops
        .get(id)
        .ok_or_else(|| format!("Unknown operation: {id}"))?;
    if let Action::Describe { action, .. } = &options.command {
        let detail = describe(&spec, operation, action.as_deref())?;
        println!("{}", serde_json::to_string_pretty(&detail)?);
        return Ok(0);
    }
    let (method, path, definition) = operation;
    let Action::Call {
        base_url,
        endpoint_file,
        params,
        body_file,
        output,
        show_headers,
        json_errors,
        timeout,
        ..
    } = options.command
    else {
        unreachable!()
    };
    if !timeout.is_finite() || timeout <= 0.0 || timeout > 3600.0 {
        return Err("Timeout must be finite and between 0 and 3600 seconds".into());
    }
    let base = base_url
        .or_else(|| endpoint_file.and_then(|p| std::fs::read_to_string(p).ok()))
        .ok_or("Cannot read endpoint file")?;
    let mut url = root_url(&base)?;
    let mut route = path.clone();
    let mut values = BTreeMap::new();
    for param in params {
        let (name, value) = param
            .split_once('=')
            .filter(|(n, _)| !n.is_empty())
            .ok_or("--param must be NAME=VALUE")?;
        if value.contains(['\r', '\n'])
            || values.insert(name.to_owned(), value.to_owned()).is_some()
        {
            return Err("Duplicate parameter or line break in parameter".into());
        }
    }
    let definitions = definition["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for d in &definitions {
        if d["required"] == true && !values.contains_key(d["name"].as_str().unwrap()) {
            return Err(format!("Missing parameter: {}", d["name"]).into());
        }
    }
    let mut headers = Vec::new();
    let mut query = Vec::new();
    for (name, value) in values {
        let d = definitions
            .iter()
            .find(|d| d["name"] == name)
            .ok_or_else(|| format!("Unknown parameter: {name}"))?;
        match d["in"].as_str() {
            Some("path") => {
                if value.is_empty() {
                    return Err("Path parameter cannot be empty".into());
                }
                let encoded = url::form_urlencoded::byte_serialize(value.as_bytes())
                    .collect::<String>()
                    .replace('+', "%20");
                route = route.replace(&format!("{{{name}}}"), &encoded);
            }
            Some("query") => query.push((name, value)),
            Some("header") => headers.push((name, value)),
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
    if binary != output.is_some() {
        return Err("Binary responses require --output PATH or --output -; JSON responses do not accept --output".into());
    }
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
    if definition.get("requestBody").is_some() {
        let path = body_file.ok_or("Operation requires --body-file PATH or --body-file -")?;
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
        let body: Value = serde_json::from_slice(&raw)?;
        if !body.is_object() {
            return Err("Request body must be a JSON object".into());
        }
        request = request.json(&body);
    } else if body_file.is_some() {
        return Err("Operation does not accept a body".into());
    }
    let mut response = request.send().await?;
    let status = response.status();
    if show_headers {
        eprintln!(
            "{}",
            json!({"status":status.as_u16(),"headers":response.headers().iter().map(|(k,v)|(k.as_str(),v.to_str().unwrap_or(""))).collect::<BTreeMap<_,_>>() })
        );
    }
    if status.as_u16() == 304 {
        return Ok(0);
    }
    let mut bytes = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(chunk) => chunk,
            Err(_) if json_errors && !status.is_success() => {
                eprintln!(
                    "{}",
                    bounded_http_error(
                        &spec,
                        status.as_u16(),
                        br#"{"error":"API error response could not be read"}"#
                    )
                );
                return Ok(2);
            }
            Err(error) => return Err(error.into()),
        };
        let Some(chunk) = chunk else {
            break;
        };
        if bytes.len().saturating_add(chunk.len()) > 64 * 1024 * 1024 {
            if json_errors && !status.is_success() {
                eprintln!(
                    "{}",
                    bounded_http_error(
                        &spec,
                        status.as_u16(),
                        br#"{"error":"API response exceeds 64 MiB"}"#
                    )
                );
                return Ok(2);
            }
            return Err("API response exceeds 64 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        if json_errors {
            eprintln!("{}", bounded_http_error(&spec, status.as_u16(), &bytes));
        } else {
            eprintln!(
                "HTTP {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(500)
                    .collect::<String>()
            );
        }
        return Ok(1);
    }
    if let Some(path) = output {
        if path == "-" {
            std::io::stdout().write_all(&bytes)?;
        } else {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?
                .write_all(&bytes)?;
        }
    } else {
        let value: Value = serde_json::from_slice(&bytes)?;
        println!("{}", serde_json::to_string_pretty(&value)?);
    }
    Ok(0)
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
        for details in [
            json!({"raw":"private"}),
            json!({"phase":"invented"}),
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
    fn selected_debugger_action_keeps_constraints_and_mapped_response() {
        let spec = specification().unwrap();
        let operation = &operations(&spec).unwrap()["debugger_action"];
        let detail = describe(&spec, operation, Some("add_watch")).unwrap();
        let request = &detail["requestBody"]["content"]["application/json"]["schema"]["oneOf"][0];
        assert_eq!(request["required"], json!(["action", "expression"]));
        assert_eq!(
            request["properties"]["expression"]["x-max-utf8-bytes"],
            4096
        );
        let response = &detail["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(response["oneOf"].as_array().unwrap().len(), 1);
        assert_eq!(
            response["oneOf"][0]["$ref"],
            "#/components/schemas/DebuggerAcknowledgementResult"
        );
        assert_eq!(response["x-action-results"].as_object().unwrap().len(), 1);
        assert_eq!(detail["responses"]["409"], operation.2["responses"]["409"]);
        assert_eq!(detail["x-max-body-bytes"], 131072);
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
        for id in ["debugger_action", "get_health"] {
            assert!(
                describe(&spec, &ops[id], Some("not_an_action"))
                    .unwrap_err()
                    .contains("Unknown action")
            );
        }
        let mut spec = spec;
        spec["components"]["schemas"]["DebuggerResult"]["x-action-results"]
            .as_object_mut()
            .unwrap()
            .remove("pause");
        assert!(
            describe(&spec, &ops["debugger_action"], Some("pause"))
                .unwrap_err()
                .contains("Missing response schema")
        );
    }

    #[test]
    fn missing_or_unsupported_action_metadata_never_inherits_a_default() {
        for replacement in [Value::Null, json!({"kind": "operation"})] {
            let mut spec = specification().unwrap();
            let action = spec["components"]["schemas"]["DebuggerAction"]["oneOf"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|v| v["properties"]["action"]["const"] == "pause")
                .unwrap();
            action["x-reb-execution"] = replacement;
            assert!(
                describe(
                    &spec,
                    &operations(&spec).unwrap()["debugger_action"],
                    Some("pause")
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
        assert!(Options::try_parse_from(["reb-api", "describe", "debugger_action"]).is_ok());
        assert!(
            Options::try_parse_from([
                "reb-api",
                "describe",
                "debugger_action",
                "--action",
                "pause"
            ])
            .is_ok()
        );
        assert!(Options::try_parse_from(["reb-api", "call", "debugger_action"]).is_err());
        assert!(
            Options::try_parse_from([
                "reb-api",
                "call",
                "debugger_action",
                "--base-url",
                "http://127.0.0.1:7319",
                "--action",
                "pause"
            ])
            .is_err()
        );
    }
}
