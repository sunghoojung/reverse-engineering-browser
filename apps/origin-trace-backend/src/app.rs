use crate::{
    analyst::Analyst,
    config::Options,
    debugger::Debugger,
    decoder::Decoder,
    deobfuscation::Deobfuscator,
    durable,
    error::{Error, Result},
    evidence, origin_trace, validation, vm, wasm,
    workspace::{Kind, Store},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, Semaphore};

const UI_ASSETS: [&str; 10] = [
    "index.html",
    "app.css",
    "app_state.js",
    "evidence_models.js",
    "source_syntax.js",
    "traffic_view.js",
    "request_value_test.js",
    "field_provenance.js",
    "app.js",
    "pane_layout.js",
];
pub struct App {
    options: Options,
    port: u16,
    ui_root: PathBuf,
    collection: Arc<Store>,
    workspace: Arc<Store>,
    decoder: Decoder,
    analyst: Analyst,
    deobfuscator: Deobfuscator,
    pub debugger: Arc<Debugger>,
    capture_stopped: AtomicBool,
    capture: Mutex<()>,
    io: Arc<Semaphore>,
    analysis: Mutex<Option<(String, Value)>>,
}
impl App {
    pub async fn stop(&self) {
        self.analyst.stop();
        self.debugger.stop().await;
    }
    pub async fn new(options: Options, port: u16) -> Arc<Self> {
        let app = Arc::new(Self {
            port,
            ui_root: options.ui_root(),
            collection: Arc::new(Store::new(options.api_collection.clone(), Kind::Collection)),
            workspace: Arc::new(Store::new(options.local_analyst.clone(), Kind::Analyst)),
            decoder: Decoder::new(options.worker(
                &options.decoder,
                "OriginTraceDecoder",
                "build/reb-decoder",
            )),
            analyst: Analyst::new(&options).await,
            deobfuscator: Deobfuscator::new(options.worker(
                &options.deobfuscator,
                "OriginTraceDeobfuscator",
                "apps/deobfuscator-worker/target/debug/reb-deobfuscator-worker",
            )),
            debugger: Debugger::new(&options),
            options,
            capture_stopped: AtomicBool::new(false),
            capture: Mutex::new(()),
            io: Arc::new(Semaphore::new(4)),
            analysis: Mutex::new(None),
        });
        app.debugger.start().await;
        app
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self.clone())
    }
    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self
            .io
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::new(503, "Evidence reader is unavailable"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|e| Error::new(500, e.to_string()))?
    }
    async fn broker_connected(&self) -> bool {
        self.options.socket.is_none() || socket_connected(self.options.socket.as_deref()).await
    }
    async fn receiver_connected(&self) -> bool {
        socket_connected(self.options.artifact_socket.as_deref()).await
    }
    async fn get(&self, path: &str, q: &Query, headers: &HeaderMap) -> Result<Response> {
        let mut etag = None;
        let value = match path {
            "/api/health" => {
                json!({"status":"ok","store":self.options.store,"store_exists":self.options.store.exists(),"trace_store":self.options.trace_store,"trace_store_exists":self.options.trace_store.exists(),"signal_store":self.options.signal_store,"signal_store_exists":self.options.signal_store.exists(),"artifact_store":self.options.artifacts,"artifact_store_exists":self.options.artifacts.exists(),"artifact_receiver_configured":self.options.artifact_socket.is_some(),"artifact_receiver_connected":self.receiver_connected().await,"api_collection_store":self.collection.path,"api_collection_store_exists":self.collection.path.exists(),"local_analyst_store":self.workspace.path,"local_analyst_store_exists":self.workspace.path.exists(),"local_analyst_runner_available":self.analyst.state()["available"],"decoder_available":self.decoder.state()["available"],"broker_connected":self.broker_connected().await,"capture_mode":self.options.capture_mode(),"debugger_state":self.debugger.snapshot()["state"]})
            }
            "/api/decoder" => self.decoder.state(),
            "/api/wasm" => {
                let id = q.required("artifact_id")?.to_owned();
                let root = self.options.artifacts.clone();
                self.blocking(move || wasm::load(&root, &id)).await?
            }
            "/api/api-collection" | "/api/local-analyst" => {
                let store = if path.ends_with("api-collection") {
                    self.collection.clone()
                } else {
                    self.workspace.clone()
                };
                let value = self
                    .blocking(move || store.load())
                    .await
                    .map_err(|e| Error::new(500, e.message))?;
                etag = Some(format!(
                    "\"{}-{}\"",
                    if path.ends_with("api-collection") {
                        "api-collection"
                    } else {
                        "local-analyst"
                    },
                    value["generation"]
                ));
                value
            }
            "/api/local-analyst/runner" => self.analyst.state(),
            "/api/debugger" => {
                let wait = q.number("wait_ms", Some("0"), 32, false)?;
                if wait > 25000 {
                    return Err(Error::bad(
                        "Debugger wait must be between 0 and 25000 milliseconds",
                    ));
                }
                let notified = self.debugger.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let value = self.debugger.snapshot();
                let current = format!("\"debugger-{}\"", value["generation"]);
                if wait > 0
                    && headers.get("if-none-match").and_then(|v| v.to_str().ok())
                        == Some(current.as_str())
                {
                    let _ = tokio::time::timeout(Duration::from_millis(wait), notified).await;
                }
                let value = self.debugger.snapshot();
                etag = Some(format!("\"debugger-{}\"", value["generation"]));
                value
            }
            "/api/debugger/source" => self.debugger.source(q.required("script_id")?).await?,
            "/api/deobfuscation" => {
                let script = q.one("script_id")?;
                let artifact = q.one("artifact_id")?;
                if script.is_some() == artifact.is_some() {
                    return Err(Error::bad("Specify exactly one script ID or artifact ID"));
                }
                let mode = q.one("mode")?.unwrap_or("analysis");
                if !["analysis", "derived"].contains(&mode) {
                    return Err(Error::bad("Deobfuscation mode is invalid"));
                }
                let assumption = q.one("assume_intrinsics")?.unwrap_or("0");
                if !["0", "1"].contains(&assumption) {
                    return Err(Error::bad("Intrinsic assumption must be 0 or 1"));
                }
                let (source, truncated) = if let Some(id) = script {
                    let script = self.debugger.source(id).await?;
                    (
                        script["source"].as_str().unwrap().to_owned(),
                        script["truncated"] == true,
                    )
                } else {
                    let artifact = self.find_artifact(artifact.unwrap()).await?;
                    if artifact["kind"] != "javascript" {
                        return Err(Error::bad("Artifact is not JavaScript"));
                    }
                    let root = self.options.artifacts.clone();
                    let bytes = self
                        .blocking(move || evidence::content(&root, &artifact, 4 * 1024 * 1024))
                        .await?;
                    (
                        String::from_utf8(bytes)
                            .map_err(|_| Error::bad("Artifact is not valid UTF-8 JavaScript"))?,
                        false,
                    )
                };
                let mut result = self
                    .deobfuscator
                    .analyze(&source, assumption == "1", mode == "derived")
                    .await?;
                result["script_id"] = json!(script);
                result["artifact_id"] = json!(artifact);
                result["mode"] = json!(mode);
                result["source_truncated"] = json!(truncated);
                result
            }
            "/api/events" => {
                let limit = q.limit(500, 5000)?;
                let connected = self.broker_connected().await;
                let stopped = self.capture_stopped.load(Ordering::Acquire);
                etag = Some(evidence::resource_etag(
                    &self.options.store,
                    &format!(
                        "{}-{}-{limit}-{}",
                        u8::from(connected),
                        self.options.capture_mode(),
                        u8::from(stopped)
                    ),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let path = self.options.store.clone();
                let events = self
                    .blocking(move || {
                        let events = evidence::recent(&path, limit, 4096, "event")?;
                        for event in &events {
                            validate_event(event)?;
                        }
                        Ok(events)
                    })
                    .await?;
                let mut result = json!({"count":events.len(),"events":events,"broker_connected":connected,"capture_mode":self.options.capture_mode(),"capture_stopped":stopped,"capture_controls_available":self.options.broker_pid.is_some()});
                if self.options.capture_mode() == "demo" {
                    result["canvas_render_captures"] =
                        serde_json::from_str(include_str!("../assets/demo-canvas.json"))
                            .expect("Demo canvas capture");
                }
                result
            }
            "/api/artifacts" => {
                let limit = q.limit(500, 5000)?;
                let configured = self.options.artifact_socket.is_some();
                let connected = self.receiver_connected().await;
                etag = Some(evidence::resource_etag(
                    &self.options.artifacts.join("manifest.jsonl"),
                    &format!("{limit}-{}-{}", u8::from(configured), u8::from(connected)),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let root = self.options.artifacts.clone();
                let artifacts = self
                    .blocking(move || evidence::artifacts(&root, limit))
                    .await?;
                json!({"count":artifacts.len(),"artifacts":artifacts.iter().map(evidence::public_artifact).collect::<Vec<_>>(),"artifact_receiver_configured":configured,"artifact_receiver_connected":connected})
            }
            "/api/origin-trace" => {
                let request = q.required("request_id")?.to_owned();
                q.number("request_id", None, 64, false)?;
                let process = q.one("root_process_id")?;
                let sequence = q.one("root_sequence_number")?;
                if process.is_some() != sequence.is_some() {
                    return Err(Error::bad(
                        "Root process ID and sequence number must be supplied together",
                    ));
                }
                let process = process
                    .map(|_| {
                        q.number("root_process_id", None, 32, false)
                            .map(|n| n as u32)
                    })
                    .transpose()?;
                let sequence = sequence.map(str::to_owned);
                if sequence.is_some() {
                    q.number("root_sequence_number", None, 64, false)?;
                }
                let options = self.options.clone();
                etag = Some(evidence::resource_etag(
                    &options.store,
                    &format!(
                        "{}:{}:{request}:{process:?}:{sequence:?}",
                        evidence::resource_etag(&options.trace_store, ""),
                        evidence::resource_etag(&options.artifacts.join("manifest.jsonl"), "")
                    ),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                self.blocking(move || {
                    origin_trace::build(
                        &evidence::recent(&options.store, 10000, 4096, "event")?,
                        &evidence::recent(&options.trace_store, 30000, 4096, "origin trace edge")?,
                        &evidence::artifacts(&options.artifacts, 10000)?,
                        &request,
                        process,
                        sequence.as_deref(),
                    )
                })
                .await?
            }
            "/api/request-signal-profile" => {
                let session = q.required("session_id")?.to_owned();
                let request = q.required("request_id")?.to_owned();
                let sequence = q.required("root_sequence_number")?.to_owned();
                let process = q.number("root_process_id", None, 32, false)?;
                for key in ["session_id", "request_id", "root_sequence_number"] {
                    q.number(key, None, 64, true)?;
                }
                etag = Some(evidence::resource_etag(
                    &self.options.signal_store,
                    &format!("{session}:{request}:{process}:{sequence}"),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let path = self.options.signal_store.clone();
                self.blocking(move || {
                    let profiles = evidence::recent(&path, 10000, 16384, "request signal profile")?;
                    for profile in &profiles {
                        validation::schema("SignalProfile", profile, 500)?;
                    }
                    profiles
                        .into_iter()
                        .rev()
                        .find(|p| {
                            p["session_id"] == session
                                && p["request_id"] == request
                                && p["root_event"]["process_id"] == process
                                && p["root_event"]["sequence_number"] == sequence
                        })
                        .ok_or_else(|| {
                            Error::new(
                                404,
                                "No request signal profile matches the selected request",
                            )
                        })
                })
                .await?
            }
            "/api/analysis/vm" => {
                let request = q.one("request_id")?;
                if request.is_some() {
                    q.number("request_id", None, 64, false)?;
                }
                let signature =
                    evidence::resource_etag(&self.options.artifacts.join("manifest.jsonl"), "");
                let mut cache = self.analysis.lock().await;
                if cache.as_ref().is_none_or(|(s, _)| *s != signature) {
                    let root = self.options.artifacts.clone();
                    let store = self.options.store.clone();
                    let value = self.blocking(move || vm::store(&root, &store)).await?;
                    *cache = Some((signature, value));
                }
                let mut value = cache.as_ref().unwrap().1.clone();
                if let Some(request) = request {
                    value["selection"] = json!({"kind":"request","request_id":request,"edge_semantics":"correlated-not-causal"});
                    value["results"].as_array_mut().unwrap().retain(|r| {
                        r["related_request_ids"]
                            .as_array()
                            .is_some_and(|a| a.contains(&json!(request)))
                    });
                    let ids = value["results"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| r["artifact_id"].clone())
                        .collect::<Vec<_>>();
                    value["mixed_findings"].as_array_mut().unwrap().retain(|f| {
                        f["artifact_ids"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|id| ids.contains(id)))
                    });
                }
                etag = Some(format!(
                    "\"{}-{}\"",
                    value["document_digest"].as_str().unwrap(),
                    request.unwrap_or("all")
                ));
                value
            }
            _ if path.starts_with("/api/artifacts/") && path.ends_with("/content") => {
                let id = &path["/api/artifacts/".len()..path.len() - "/content".len()];
                let artifact = self.find_artifact(id).await?;
                let offset = q.number("offset", Some("0"), 64, false)? as usize;
                let total = artifact["byte_size"].as_u64().unwrap_or(0) as usize;
                if offset > total {
                    return Err(Error::bad("Artifact content offset exceeds byte size"));
                }
                let limit = q.limit(2097152, 2097152)?;
                let root = self.options.artifacts.clone();
                let bytes = self
                    .blocking(move || evidence::verified_range(&root, &artifact, offset, limit))
                    .await?;
                let end = offset.saturating_add(bytes.len());
                let mut response = bytes_response(bytes, "application/octet-stream");
                let h = response.headers_mut();
                h.insert(
                    "content-security-policy",
                    HeaderValue::from_static("sandbox"),
                );
                h.insert(
                    "content-disposition",
                    HeaderValue::from_str(&format!("attachment; filename=\"artifact-{id}.bin\""))
                        .map_err(|_| Error::bad("Artifact ID is invalid"))?,
                );
                for (key, value) in [
                    ("x-artifact-total-bytes", total.to_string()),
                    ("x-artifact-offset", offset.to_string()),
                    (
                        "x-artifact-truncated",
                        if end < total { "true" } else { "false" }.into(),
                    ),
                ] {
                    h.insert(key, HeaderValue::from_str(&value).unwrap());
                }
                return Ok(response);
            }
            _ if path.starts_with("/api/") => {
                return Err(Error::new(404, "Application resource not found"));
            }
            _ => {
                let asset = if path == "/" {
                    "index.html"
                } else {
                    path.strip_prefix('/').unwrap_or("")
                };
                if !UI_ASSETS.contains(&asset) {
                    return Err(Error::new(404, "Not found"));
                }
                let path = self.ui_root.join(asset);
                let bytes = tokio::fs::read(path)
                    .await
                    .map_err(|_| Error::new(404, "Not found"))?;
                return Ok(bytes_response(
                    bytes,
                    if asset.ends_with(".html") {
                        "text/html; charset=utf-8"
                    } else if asset.ends_with(".css") {
                        "text/css; charset=utf-8"
                    } else {
                        "text/javascript; charset=utf-8"
                    },
                ));
            }
        };
        if matches_etag(headers, etag.as_deref()) {
            return Ok(not_modified(etag.as_deref().unwrap()));
        }
        let mut response = axum::Json(value).into_response();
        if let Some(etag) = etag {
            response
                .headers_mut()
                .insert("etag", HeaderValue::from_str(&etag).unwrap());
        }
        Ok(response)
    }
    async fn find_artifact(&self, id: &str) -> Result<Value> {
        if validation::canonical(&json!(id), 64, false, "Artifact ID").is_err() {
            return Err(Error::new(404, "Artifact not found"));
        }
        let root = self.options.artifacts.clone();
        let id = id.to_owned();
        self.blocking(move || evidence::find_artifact(&root, &id))
            .await
    }
    async fn post(&self, path: &str, value: &Value) -> Result<Value> {
        match path {
            "/api/decoder/actions" => self.decoder.action(value).await,
            "/api/api-collection/actions" => {
                let store = self.collection.clone();
                let value = value.clone();
                self.blocking(move || store.replace(&value)).await
            }
            "/api/local-analyst/actions" => match value["action"].as_str().unwrap_or("") {
                "replace_local_analyst_workspace" => {
                    let store = self.workspace.clone();
                    let value = value.clone();
                    self.blocking(move || store.replace(&value)).await
                }
                "run_local_analyst_script" => {
                    let store = self.workspace.clone();
                    let workspace = self.blocking(move || store.load()).await?;
                    self.analyst.run(value, &workspace).await
                }
                "cancel_local_analyst_script" => {
                    validation::fields(value, &["action", "run_id"], "Analyst cancellation")?;
                    let cancelled = self.analyst.cancel(&value["run_id"])?;
                    Ok(json!({"ok":true,"run_id":value["run_id"],"cancel_requested":cancelled}))
                }
                _ => Err(Error::bad("Analyst workspace action is invalid")),
            },
            "/api/debugger/actions" => self.debugger.action(value).await,
            "/api/capture/actions" => {
                let _guard = self.capture.lock().await;
                let pid = self
                    .options
                    .broker_pid
                    .filter(|p| *p > 0)
                    .ok_or_else(|| Error::conflict("Live capture controls are unavailable"))?;
                if self.options.socket.is_none() {
                    return Err(Error::conflict("Live capture controls are unavailable"));
                }
                if *value == json!({"action":"stop"}) {
                    if self.broker_connected().await {
                        #[cfg(unix)]
                        if unsafe { libc::kill(pid, libc::SIGUSR1) } != 0 {
                            return Err(std::io::Error::last_os_error().into());
                        }
                        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                        while self.broker_connected().await {
                            if tokio::time::Instant::now() >= deadline {
                                return Err(Error::new(408, "Native capture did not stop in time"));
                            }
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                    self.capture_stopped.store(true, Ordering::Release);
                } else if *value == json!({"action":"clear","confirm":true}) {
                    if self.broker_connected().await {
                        return Err(Error::conflict(
                            "Stop native capture before clearing events",
                        ));
                    }
                    let paths = vec![
                        self.options.store.clone(),
                        self.options.trace_store.clone(),
                        self.options.signal_store.clone(),
                    ];
                    self.blocking(move || {
                        for path in paths {
                            if path.exists() {
                                durable::truncate_private(&path)?;
                            }
                        }
                        Ok(())
                    })
                    .await?;
                } else {
                    return Err(Error::bad("Capture action is invalid"));
                }
                Ok(
                    json!({"ok":true,"capture_stopped":self.capture_stopped.load(Ordering::Acquire),"broker_connected":self.broker_connected().await}),
                )
            }
            _ => Err(Error::new(404, "Application resource not found")),
        }
    }
    fn trusted(&self, headers: &HeaderMap) -> bool {
        if headers.get_all("host").iter().count() != 1
            || headers.get_all("origin").iter().count() > 1
            || headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site")
        {
            return false;
        }
        let valid = |raw: &str, host: bool| {
            let candidate = if host {
                format!("http://{raw}")
            } else {
                raw.into()
            };
            url::Url::parse(&candidate).is_ok_and(|u| {
                u.scheme() == "http"
                    && ["localhost", "127.0.0.1", "::1", "[::1]"]
                        .contains(&u.host_str().unwrap_or(""))
                    && u.port_or_known_default() == Some(self.port)
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.path() == "/"
                    && u.query().is_none()
                    && u.fragment().is_none()
            })
        };
        headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| valid(h, true))
            && headers
                .get("origin")
                .is_none_or(|h| h.to_str().is_ok_and(|h| valid(h, false)))
    }
}
async fn handle(State(app): State<Arc<App>>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let result = async {
        if (path.starts_with("/api/") || parts.method == Method::POST)
            && !app.trusted(&parts.headers)
        {
            return Err(Error::new(403, "Local request origin rejected"));
        }
        let query = Query::new(parts.uri.query().unwrap_or(""));
        if parts.method == Method::GET {
            app.get(path, &query, &parts.headers).await
        } else if parts.method == Method::POST {
            let maximum = validation::SPEC["paths"][path]["post"]["x-max-body-bytes"]
                .as_u64()
                .ok_or_else(|| Error::new(404, "Application resource not found"))?
                as usize;
            if parts.headers.get_all("content-length").iter().count() != 1
                || parts.headers.contains_key("transfer-encoding")
            {
                return Err(Error::bad("A valid content length is required"));
            }
            let length = parts
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|n| *n > 0 && *n <= maximum)
                .ok_or_else(|| Error::bad("The request body size is invalid"))?;
            let bytes = tokio::time::timeout(Duration::from_secs(5), to_bytes(body, maximum))
                .await
                .map_err(|_| Error::new(408, "The request body deadline was exceeded"))?
                .map_err(|_| Error::bad("The request body exceeds its size limit"))?;
            if bytes.len() != length {
                return Err(Error::bad("The request body length is invalid"));
            }
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| Error::bad("The request body is malformed JSON"))?;
            if !value.is_object() {
                return Err(Error::bad("The request body must be an object"));
            }
            app.post(path, &value)
                .await
                .map(|value| axum::Json(value).into_response())
        } else {
            Err(Error::new(405, "Unsupported method"))
        }
    }
    .await;
    let mut response = match result {
        Ok(response) => response,
        Err(e) => e.into_response(),
    };
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
struct Query(BTreeMap<String, Vec<String>>);
impl Query {
    fn new(raw: &str) -> Self {
        let mut values = BTreeMap::<String, Vec<String>>::new();
        for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            values
                .entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        Self(values)
    }
    fn one(&self, key: &str) -> Result<Option<&str>> {
        match self.0.get(key) {
            None => Ok(None),
            Some(values) if values.len() == 1 => Ok(Some(&values[0])),
            _ => Err(Error::bad(format!("Specify {key} only once"))),
        }
    }
    fn required(&self, key: &str) -> Result<&str> {
        self.one(key)?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::bad(format!("{key} is required")))
    }
    fn number(&self, key: &str, default: Option<&str>, bits: u32, nonzero: bool) -> Result<u64> {
        validation::canonical(
            &json!(
                self.one(key)?
                    .or(default)
                    .ok_or_else(|| Error::bad(format!("{key} is required")))?
            ),
            bits,
            nonzero,
            key,
        )
    }
    fn limit(&self, default: usize, max: usize) -> Result<usize> {
        self.one("limit")?.map_or(Ok(default), |s| {
            s.parse::<i64>()
                .map(|n| n.clamp(1, max as i64) as usize)
                .map_err(|_| Error::bad("Limit is invalid"))
        })
    }
}
fn matches_etag(headers: &HeaderMap, etag: Option<&str>) -> bool {
    etag.is_some_and(|tag| headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(tag))
}
fn not_modified(etag: &str) -> Response {
    let mut response = StatusCode::NOT_MODIFIED.into_response();
    response
        .headers_mut()
        .insert("etag", HeaderValue::from_str(etag).unwrap());
    response
}
fn bytes_response(bytes: Vec<u8>, mime: &'static str) -> Response {
    let mut response = Response::new(Body::from(bytes));
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static(mime));
    response
}
async fn socket_connected(path: Option<&Path>) -> bool {
    let Some(path) = path else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        tokio::fs::metadata(path)
            .await
            .is_ok_and(|m| m.file_type().is_socket())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}
fn validate_event(value: &Value) -> Result<()> {
    for key in [
        "session_id",
        "sequence_number",
        "monotonic_time_ns",
        "navigation_id",
        "frame_id",
        "artifact_id",
        "request_id",
    ] {
        validation::canonical(&value[key], 64, false, key)
            .map_err(|e| Error::new(500, e.message))?;
    }
    if !matches!(value["protocol_version"].as_u64(), Some(2 | 3))
        || !value["category"].is_string()
        || !value["type"].is_string()
        || !value["process_id"]
            .as_u64()
            .is_some_and(|n| n <= u32::MAX as u64)
    {
        return Err(Error::new(
            500,
            "The evidence store contains a malformed event",
        ));
    }
    let payload = value["payload"]
        .as_str()
        .ok_or_else(|| Error::new(500, "Event payload is invalid"))?;
    if value["payload_encoding"] != "hex"
        || payload.len() > 256
        || hex::decode(payload)
            .ok()
            .is_none_or(|p| value["payload_size"] != p.len())
    {
        return Err(Error::new(500, "Event payload is invalid"));
    }
    Ok(())
}
