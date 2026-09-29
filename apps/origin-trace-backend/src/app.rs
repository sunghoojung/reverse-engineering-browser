use crate::config::Options;
use crate::evidence::read_json_lines;
use crate::response::{self, HttpResponse};
use serde_json::json;
use std::fs;
use std::path::{Component, Path, PathBuf};
use tiny_http::{Method, Request};

const PUBLIC_ARTIFACT_FIELDS: [&str; 15] = [
    "protocol_version",
    "artifact_id",
    "session_id",
    "navigation_id",
    "frame_id",
    "parent_artifact_id",
    "creator_event_id",
    "execution_context_id",
    "capture_origin",
    "kind",
    "url",
    "mime_type",
    "byte_size",
    "sha256",
    "sensitive",
];

const UI_ASSETS: [&str; 8] = [
    "index.html",
    "app.css",
    "app_state.js",
    "evidence_models.js",
    "source_syntax.js",
    "traffic_view.js",
    "request_value_test.js",
    "app.js",
];

pub struct App {
    options: Options,
    ui_root: PathBuf,
    port: u16,
}

impl App {
    pub fn new(options: Options, port: u16) -> Self {
        Self {
            options,
            ui_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../research-ui"),
            port,
        }
    }

    pub fn handle(&self, request: Request) {
        let (path, query) = request.url().split_once('?').unwrap_or((request.url(), ""));
        let response = if path.starts_with("/api/") && !self.is_trusted(&request) {
            response::error("Local request origin rejected", 403)
        } else if request.method() != &Method::Get {
            response::error("Unsupported action", 405)
        } else {
            self.get(path, query)
        };
        let _ = request.respond(response);
    }

    fn get(&self, path: &str, query: &str) -> HttpResponse {
        match path {
            "/api/health" => response::json(self.health(), 200),
            "/api/events" => self.events(query),
            "/api/request-signal-profile" => self.records(&self.options.signal_store, "profiles"),
            "/api/artifacts" => self.artifacts(query),
            _ if path.starts_with("/api/") => {
                response::error("Endpoint is not implemented by the Rust backend", 501)
            }
            _ => self.static_asset(path),
        }
    }

    fn health(&self) -> serde_json::Value {
        json!({
            "status":"ok", "store":self.options.store, "store_exists":self.options.store.exists(),
            "trace_store":self.options.trace_store, "trace_store_exists":self.options.trace_store.exists(),
            "signal_store":self.options.signal_store, "signal_store_exists":self.options.signal_store.exists(),
            "artifact_store":self.options.artifacts, "artifact_store_exists":self.options.artifacts.exists(),
            "capture_mode":if self.options.demo_evidence {"demo"} else {"idle"}, "debugger_state":"disconnected"
        })
    }

    fn records(&self, path: &Path, key: &str) -> HttpResponse {
        match read_json_lines(path) {
            Ok(records) => response::json(json!({ key: records }), 200),
            Err(error) => response::error(error.to_string(), 500),
        }
    }

    fn events(&self, query: &str) -> HttpResponse {
        let limit = match parse_limit(query) {
            Ok(limit) => limit,
            Err(error) => return response::error(error, 500),
        };
        match read_json_lines(&self.options.store) {
            Ok(records) => {
                let events = newest(records, limit);
                response::json(
                    json!({"count":events.len(), "events":events, "broker_connected":false,
                    "capture_mode":if self.options.demo_evidence {"demo"} else {"idle"},
                    "capture_stopped":false, "capture_controls_available":false}),
                    200,
                )
            }
            Err(error) => response::error(error.to_string(), 500),
        }
    }

    fn artifacts(&self, query: &str) -> HttpResponse {
        let limit = match parse_limit(query) {
            Ok(limit) => limit,
            Err(error) => return response::error(error, 500),
        };
        match read_json_lines(&self.options.artifacts.join("manifest.jsonl")) {
            Ok(records) => {
                let artifacts = newest(records, limit)
                    .into_iter()
                    .map(public_artifact)
                    .collect::<Vec<_>>();
                response::json(
                    json!({"count":artifacts.len(), "artifacts":artifacts,
                    "artifact_receiver_configured":false, "artifact_receiver_connected":false}),
                    200,
                )
            }
            Err(error) => response::error(error.to_string(), 500),
        }
    }

    fn static_asset(&self, request_path: &str) -> HttpResponse {
        let relative = if request_path == "/" {
            Path::new("index.html")
        } else {
            Path::new(request_path.trim_start_matches('/'))
        };
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
            || !relative
                .to_str()
                .is_some_and(|asset| UI_ASSETS.contains(&asset))
        {
            return response::error("Not found", 404);
        }
        match fs::read(self.ui_root.join(relative)) {
            Ok(body) => response::bytes(body, content_type(relative)),
            Err(_) => response::error("Not found", 404),
        }
    }

    fn is_trusted(&self, request: &Request) -> bool {
        let expected = [
            format!("127.0.0.1:{}", self.port),
            format!("localhost:{}", self.port),
            format!("[::1]:{}", self.port),
        ];
        let host = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str());
        if !host.is_some_and(|host| expected.iter().any(|value| value == host)) {
            return false;
        }
        if request
            .headers()
            .iter()
            .any(|h| h.field.equiv("Sec-Fetch-Site") && h.value.as_str() == "cross-site")
        {
            return false;
        }
        request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Origin"))
            .is_none_or(|header| {
                expected
                    .iter()
                    .any(|host| header.value.as_str() == format!("http://{host}"))
            })
    }
}

fn parse_limit(query: &str) -> Result<usize, String> {
    let value = query
        .split('&')
        .find_map(|part| part.strip_prefix("limit="))
        .unwrap_or("500");
    value
        .parse::<usize>()
        .map(|limit| limit.clamp(1, 5_000))
        .map_err(|error| error.to_string())
}

fn newest(mut records: Vec<serde_json::Value>, limit: usize) -> Vec<serde_json::Value> {
    records.drain(..records.len().saturating_sub(limit));
    records
}

fn public_artifact(mut artifact: serde_json::Value) -> serde_json::Value {
    if let Some(object) = artifact.as_object_mut() {
        object.retain(|field, _| PUBLIC_ARTIFACT_FIELDS.contains(&field.as_str()));
    }
    artifact
}

fn content_type(path: &Path) -> &'static [u8] {
    match path.extension().and_then(|value| value.to_str()) {
        Some("css") => b"text/css; charset=utf-8",
        Some("html") => b"text/html; charset=utf-8",
        Some("js") => b"text/javascript; charset=utf-8",
        Some("png") => b"image/png",
        _ => b"application/octet-stream",
    }
}
