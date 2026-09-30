use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
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
    Describe {
        operation_id: String,
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
        #[arg(long, default_value_t = 30.0)]
        timeout: f64,
    },
}
fn specification() -> Value {
    serde_json::from_str(include_str!("../../../../protocol/openapi.json"))
        .expect("Versioned OpenAPI document")
}
fn operations(spec: &Value) -> BTreeMap<String, (String, String, Value)> {
    let mut result = BTreeMap::new();
    for (path, item) in spec["paths"].as_object().expect("OpenAPI paths") {
        for (method, definition) in item.as_object().expect("OpenAPI operation") {
            if ["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
                result.insert(
                    definition["operationId"]
                        .as_str()
                        .expect("Operation ID")
                        .into(),
                    (method.to_uppercase(), path.clone(), definition.clone()),
                );
            }
        }
    }
    result
}
fn resolve<'a>(spec: &'a Value, mut value: &'a Value) -> &'a Value {
    for _ in 0..16 {
        let Some(reference) = value["$ref"].as_str().and_then(|s| s.strip_prefix('#')) else {
            break;
        };
        let Some(resolved) = spec.pointer(reference) else {
            break;
        };
        value = resolved;
    }
    value
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
    let spec = specification();
    let ops = operations(&spec);
    let id = match &options.command {
        Action::List => {
            for (id, (method, path, _)) in &ops {
                println!("{id}\t{method}\t{path}");
            }
            return Ok(0);
        }
        Action::Describe { operation_id } | Action::Call { operation_id, .. } => operation_id,
    };
    let (method, path, definition) = ops
        .get(id)
        .ok_or_else(|| format!("Unknown operation: {id}"))?;
    if matches!(options.command, Action::Describe { .. }) {
        let schema = resolve(
            &spec,
            &definition["requestBody"]["content"]["application/json"]["schema"],
        );
        let mut detail = json!({"operationId":id,"method":method,"path":path,"summary":definition["summary"],"description":definition["description"],"parameters":definition.get("parameters").unwrap_or(&json!([])),"requestBody":definition["requestBody"],"responses":definition["responses"]});
        let actions = schema["oneOf"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| resolve(&spec, v)["properties"]["action"]["const"].as_str())
            .collect::<Vec<_>>();
        if !actions.is_empty() {
            detail["actions"] = json!(actions);
        }
        println!("{}", serde_json::to_string_pretty(&detail)?);
        return Ok(0);
    }
    let Action::Call {
        base_url,
        endpoint_file,
        params,
        body_file,
        output,
        show_headers,
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
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > 64 * 1024 * 1024 {
            return Err("API response exceeds 64 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        eprintln!(
            "HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
                .chars()
                .take(500)
                .collect::<String>()
        );
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
