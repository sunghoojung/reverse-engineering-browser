use crate::{
    analysis_catalog,
    analyst::Analyst,
    config::Options,
    debugger::Debugger,
    decoder::Decoder,
    deobfuscation::Deobfuscator,
    error::{Code, Error, Phase, Reason, Result},
    evidence, evidence_comparison, evidence_package, float32,
    native_console::NativeConsole,
    origin_trace, source_facts, validation, vm, wasm,
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
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, TryAcquireError};

const UI_ASSETS: [&str; 19] = [
    "index.html",
    "app.css",
    "app_state.js",
    "evidence_models.js",
    "evidence_package.js",
    "float32_inspector.js",
    "evidence_comparison.js",
    "source_syntax.js",
    "source_facts.js",
    "investigation_navigation.js",
    "investigation_notebook.js",
    "traffic_view.js",
    "traffic_comparison.js",
    "request_value_test.js",
    "field_provenance.js",
    "app.js",
    "pane_layout.js",
    "native_console.js",
    "native_console_completion.js",
];
#[derive(Clone, Copy)]
enum PackageOperation {
    Validate,
    Export,
    Compare,
}
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
    native_console: NativeConsole,
    capture_stopped: AtomicBool,
    capture: Mutex<()>,
    io: Arc<Semaphore>,
    package_io: Arc<Semaphore>,
    analysis: Mutex<Option<(String, Value)>>,
}
impl App {
    pub async fn stop(&self) {
        self.analyst.stop();
        self.debugger.stop().await;
        self.native_console.stop().await;
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
            native_console: NativeConsole::new(&options),
            options,
            capture_stopped: AtomicBool::new(false),
            capture: Mutex::new(()),
            io: Arc::new(Semaphore::new(4)),
            package_io: Arc::new(Semaphore::new(2)),
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
    async fn package_operation(
        &self,
        bytes: Vec<u8>,
        operation: PackageOperation,
        admitted: Option<OwnedSemaphorePermit>,
    ) -> Result<Vec<u8>> {
        // Share the existing blocking-I/O admission pool, with a narrower package
        // cap and a single bounded wait. A dropped caller cannot release permits
        // while its blocking validation work is still running.
        let permits = tokio::time::timeout(Duration::from_secs(1), async {
            let package = match admitted {
                Some(permit) => permit,
                None => self.package_io.clone().acquire_owned().await.map_err(|_| {
                    Error::new(503, "Package operations are unavailable")
                        .with_code(Code::DependencyUnavailable)
                })?,
            };
            let io = self.io.clone().acquire_owned().await.map_err(|_| {
                Error::new(503, "Package operations are unavailable")
                    .with_code(Code::DependencyUnavailable)
            })?;
            Ok::<_, Error>((package, io))
        })
        .await
        .map_err(|_| {
            Error::new(408, "Package admission deadline exceeded").with_code(Code::Timeout)
        })??;
        let events = self.options.store.clone();
        let artifacts = self.options.artifacts.clone();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        tokio::task::spawn_blocking(move || {
            let _permits = permits;
            match operation {
                PackageOperation::Export => {
                    evidence_package::export_bytes_at(&bytes, &events, &artifacts, deadline)
                }
                PackageOperation::Compare => {
                    evidence_comparison::compare_bytes_at(&bytes, deadline)
                }
                PackageOperation::Validate => {
                    serde_json::to_vec(&evidence_package::validate_bytes(&bytes)?)
                        .map_err(|_| Error::new(500, "Package validation failed"))
                }
            }
        })
        .await
        .map_err(|_| Error::new(500, "Package validator failed"))?
    }
    async fn float32_operation(&self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        let permit = tokio::time::timeout(Duration::from_secs(1), self.io.clone().acquire_owned())
            .await
            .map_err(|_| {
                Error::new(408, "Float32 admission deadline exceeded").with_code(Code::Timeout)
            })?
            .map_err(|_| {
                Error::new(503, "Float32 diagnostics unavailable")
                    .with_code(Code::DependencyUnavailable)
            })?;
        let root = self.options.artifacts.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            float32::compare_bytes(&root, &bytes)
        })
        .await
        .map_err(|_| Error::new(500, "Float32 diagnostic task failed"))?
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
            "/api/analysis/catalog" => analysis_catalog::catalog()?,
            "/api/decoder" => self.decoder.state(),
            "/api/native-console" => self.native_console.state().await,
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
            "/api/source-facts" => {
                // Never infer identity from a URL, live script, or selected UI row.
                if q.0
                    .keys()
                    .any(|key| !["session_id", "artifact_id"].contains(&key.as_str()))
                {
                    return Err(Error::bad(
                        "Source facts require only session_id and artifact_id",
                    ));
                }
                q.number("session_id", None, 64, false)?;
                q.number("artifact_id", None, 64, false)?;
                let session = q.required("session_id")?.to_owned();
                let id = q.required("artifact_id")?.to_owned();
                let root = self.options.artifacts.clone();
                let (source, identity) = self
                    .blocking(move || source_facts::load(&root, &session, &id))
                    .await?;
                let mut result = self.deobfuscator.source_facts(&source).await?;
                result["source"] = identity;
                result
            }
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
                let mut result = json!({"count":events.len(),"broker_connected":connected,"capture_mode":self.options.capture_mode(),"capture_stopped":stopped,"capture_controls_available":self.options.broker_pid.is_some()});
                // json! serializes borrowed values; move the retained window instead
                // of allocating a second complete evidence tree on every refresh.
                result["events"] = Value::Array(events);
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
                let mut artifacts = self
                    .blocking(move || evidence::artifacts(&root, limit))
                    .await?;
                for artifact in &mut artifacts {
                    artifact
                        .as_object_mut()
                        .expect("Validated artifact object")
                        .retain(|key, _| evidence::PUBLIC_ARTIFACT_FIELDS.contains(&key.as_str()));
                }
                let mut result = json!({"count":artifacts.len(),"artifact_receiver_configured":configured,"artifact_receiver_connected":connected});
                result["artifacts"] = Value::Array(artifacts);
                result
            }
            "/api/origin-trace" => {
                let request = q.required("request_id")?.to_owned();
                q.number("request_id", None, 64, false)?;
                let session = q.one("session_id")?.map(str::to_owned);
                if session.is_some() {
                    q.number("session_id", None, 64, true)?;
                }
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
                        "{}:{}:{request}:{session:?}:{process:?}:{sequence:?}",
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
                        session.as_deref(),
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
                let signature = format!(
                    "{}:{}",
                    analysis_input_signature(&self.options.artifacts.join("manifest.jsonl")),
                    analysis_input_signature(&self.options.store),
                );
                let mut cache = self.analysis.lock().await;
                if !cfg!(unix) || cache.as_ref().is_none_or(|(s, _)| *s != signature) {
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
            "/api/native-console/actions" => self.native_console.action(value).await,
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
                    self.blocking(move || evidence::clear_stores(&paths))
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
            // Comparison bodies can contain two 4 MiB originals. Reserve the
            // existing package permit before ingesting them, with no body queue.
            // Keep this permit through blocking work; body timeout/disconnect or
            // dispatch admission failure releases it without starting comparison.
            let comparison_permit = if path == "/api/evidence/packages/compare" {
                Some(
                    app.package_io
                        .clone()
                        .try_acquire_owned()
                        .map_err(|error| match error {
                            TryAcquireError::NoPermits => {
                                Error::new(503, "Comparison capacity is full; retry explicitly")
                                    .with_code(Code::ResourceLimit)
                            }
                            TryAcquireError::Closed => {
                                Error::new(503, "Package operations are unavailable")
                                    .with_code(Code::DependencyUnavailable)
                            }
                        })?,
                )
            } else {
                None
            };
            let bytes = tokio::time::timeout(Duration::from_secs(5), to_bytes(body, maximum))
                .await
                .map_err(|_| {
                    Error::new(408, "The request body deadline was exceeded")
                        .with_reason(Reason::at(Code::Timeout, Phase::RequestBody))
                })?
                .map_err(|_| Error::bad("The request body exceeds its size limit"))?;
            if bytes.len() != length {
                return Err(Error::bad("The request body length is invalid"));
            }
            if let Some(operation) = match path {
                "/api/evidence/packages/validate" => Some(PackageOperation::Validate),
                "/api/evidence/packages/export" => Some(PackageOperation::Export),
                "/api/evidence/packages/compare" => Some(PackageOperation::Compare),
                _ => None,
            } {
                return app
                    .package_operation(bytes.to_vec(), operation, comparison_permit)
                    .await
                    .map(|bytes| ([("content-type", "application/json")], bytes).into_response());
            }
            if path == "/api/float32/compare" {
                return app
                    .float32_operation(bytes.to_vec())
                    .await
                    .map(|bytes| ([("content-type", "application/json")], bytes).into_response());
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
fn analysis_input_signature(path: &Path) -> String {
    // Evidence can be restored or atomically replaced with the same length and
    // mtime. Unix file identity and change time prevent reusing that old result.
    // Other platforms recompute analysis rather than relying on a weaker key.
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        path.symlink_metadata()
            .map(|m| format!("{}:{}:{}:{}", m.dev(), m.ino(), m.ctime(), m.ctime_nsec()))
            .unwrap_or_else(|error| format!("{:?}", error.kind()))
    };
    #[cfg(not(unix))]
    let identity = String::new();
    evidence::resource_etag(path, &identity)
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[tokio::test]
    async fn package_admission_reasons_preserve_limits_and_release_waiting_permits() {
        for (package_pool, closed) in [(true, true), (false, true), (true, false), (false, false)] {
            let root = tempfile::tempdir().unwrap();
            let mut options = Options::parse_from(["origin-trace-backend"]);
            options.store = root.path().join("events.jsonl");
            options.trace_store = root.path().join("trace.jsonl");
            options.signal_store = root.path().join("signals.jsonl");
            options.artifacts = root.path().join("artifacts");
            options.api_collection = root.path().join("collection.json");
            options.local_analyst = root.path().join("analyst.json");
            // Avoid even the analyst's startup availability subprocess. No
            // analysis is requested, so this executable is never launched.
            options.analyst_runner = Some(std::env::current_exe().unwrap());
            let app = App::new(options, 0).await;
            let pool = if package_pool {
                &app.package_io
            } else {
                &app.io
            };
            let held = if closed {
                pool.close();
                None
            } else {
                Some(
                    pool.clone()
                        .acquire_many_owned(pool.available_permits() as u32)
                        .await
                        .unwrap(),
                )
            };
            let error = app
                .package_operation(b"{}".to_vec(), PackageOperation::Validate, None)
                .await
                .unwrap_err();
            assert_eq!(error.status, if closed { 503 } else { 408 });
            assert_eq!(
                serde_json::to_value(&error).unwrap(),
                json!({
                    "error": if closed { "Package operations are unavailable" } else {
                        "Package admission deadline exceeded"
                    },
                    "code": if closed { "dependency_unavailable" } else { "timeout" },
                    "details": {}
                })
            );
            drop(held);
            if !closed {
                let bytes = app
                    .package_operation(
                        include_bytes!("../assets/evidence-packages/golden-v1.json").to_vec(),
                        PackageOperation::Validate,
                        None,
                    )
                    .await
                    .unwrap();
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(value["status"], "valid");
                assert_eq!(app.package_io.available_permits(), 2);
                assert_eq!(app.io.available_permits(), 4);
            } else if !package_pool {
                assert_eq!(app.package_io.available_permits(), 2);
            }
            app.stop().await;
        }
    }
    #[tokio::test]
    async fn float32_admission_reasons_and_permit_release() {
        for closed in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut options = Options::parse_from(["origin-trace-backend"]);
            options.artifacts = root.path().join("absent");
            options.analyst_runner = Some(std::env::current_exe().unwrap());
            let app = App::new(options, 0).await;
            let permit = app.io.clone().acquire_many_owned(4).await.unwrap();
            if closed {
                app.io.close();
            }
            let error = app.float32_operation(b"{}".to_vec()).await.unwrap_err();
            assert_eq!(error.status, if closed { 503 } else { 408 });
            assert_eq!(
                serde_json::to_value(&error).unwrap()["code"],
                if closed {
                    "dependency_unavailable"
                } else {
                    "timeout"
                }
            );
            drop(permit);
            if !closed {
                assert_eq!(
                    app.float32_operation(b"{}".to_vec())
                        .await
                        .unwrap_err()
                        .status,
                    400
                );
                assert_eq!(app.io.available_permits(), 4);
            }
            app.stop().await;
        }
    }
    #[tokio::test]
    async fn comparison_prebody_admission_rejects_saturation_and_releases_cancelled_bodies() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let root = tempfile::tempdir().unwrap();
        let mut options = Options::parse_from(["origin-trace-backend"]);
        options.store = root.path().join("events.jsonl");
        options.trace_store = root.path().join("trace.jsonl");
        options.signal_store = root.path().join("signals.jsonl");
        options.artifacts = root.path().join("artifacts");
        options.api_collection = root.path().join("collection.json");
        options.local_analyst = root.path().join("analyst.json");
        options.analyst_runner = Some(std::env::current_exe().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = App::new(options, address.port()).await;
        let router = app.router();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let wait_permits = |expected| {
            let app = app.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(2), async move {
                    while app.package_io.available_permits() != expected {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
            }
        };
        let header = format!(
            "POST /api/evidence/packages/compare HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{",
            evidence_comparison::MAX_REQUEST_BYTES
        );
        let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
        first.write_all(header.as_bytes()).await.unwrap();
        wait_permits(1).await;
        let mut second = tokio::net::TcpStream::connect(address).await.unwrap();
        second.write_all(header.as_bytes()).await.unwrap();
        wait_permits(0).await;
        // The asserted permits are an admission barrier, not a timing sleep.
        // These stalled requests have supplied one byte, not two large bodies.
        let request = Request::builder()
            .method("POST")
            .uri("/api/evidence/packages/compare")
            .header("host", address.to_string())
            .header("content-length", evidence_comparison::MAX_REQUEST_BYTES)
            .body(Body::empty())
            .unwrap();
        let rejected = handle(State(app.clone()), request).await;
        assert_eq!(rejected.status(), 503);
        let value: Value =
            serde_json::from_slice(&to_bytes(rejected.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(value["code"], "resource_limit");
        assert_eq!(app.package_io.available_permits(), 0);
        // Cancellation releases a pre-body lease, allowing an explicit new call.
        first.shutdown().await.unwrap();
        drop(first);
        wait_permits(1).await;
        let p: Value =
            serde_json::from_slice(include_bytes!("../assets/evidence-packages/golden-v1.json"))
                .unwrap();
        let body=serde_json::to_vec(&json!({"left":p,"right":p,"normalization_profile":evidence_comparison::PROFILE,"facets":["events"]})).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/api/evidence/packages/compare")
            .header("host", address.to_string())
            .header("content-length", body.len())
            .body(Body::from(body))
            .unwrap();
        assert_eq!(handle(State(app.clone()), request).await.status(), 200);
        assert_eq!(app.package_io.available_permits(), 1);
        // The second stalled body reaches its real body deadline and releases
        // the lease, without blocking or launching any comparison worker.
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(7), second.read_to_end(&mut raw))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8(raw).unwrap().starts_with("HTTP/1.1 408 "));
        wait_permits(2).await;
        app.package_io.close();
        let request = Request::builder()
            .method("POST")
            .uri("/api/evidence/packages/compare")
            .header("host", address.to_string())
            .header("content-length", 100)
            .body(Body::empty())
            .unwrap();
        let rejected = handle(State(app.clone()), request).await;
        assert_eq!(rejected.status(), 503);
        let value: Value =
            serde_json::from_slice(&to_bytes(rejected.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(value["code"], "dependency_unavailable");
        app.stop().await;
        server.abort();
        let _ = server.await;
    }
}
