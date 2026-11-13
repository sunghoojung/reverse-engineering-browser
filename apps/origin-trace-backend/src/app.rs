use crate::{
    analysis_catalog,
    analyst::Analyst,
    artifact_lookup::ArtifactLookupCache,
    artifact_map, artifact_query, artifact_text,
    capture::{self, Capture, StopRefusal},
    config::{CaptureMode, Options},
    decoder::Decoder,
    deobfuscation::Deobfuscator,
    error::{Code, Error, Phase, Reason, Result},
    event_query, event_window, evidence, evidence_comparison, evidence_package, float32,
    js_invocation_sites,
    live_browser::LiveBrowser,
    live_wasm::LiveWasm,
    native_console::NativeConsole,
    native_debugger_pause::NativeDebuggerPause,
    origin_trace,
    owned_vm_debugger::OwnedVmDebugger,
    request_cookies, request_headers,
    request_index::{self, RequestIndex},
    session_context, session_summary, source_facts, source_format, validation, vm, wasm, wasm_diff,
    wasm_graph, wasm_identification, wasm_pseudocode,
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
use sha2::Digest;
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore, TryAcquireError};

const UI_ASSETS: [&str; 78] = [
    "index.html",
    "block_graph.css",
    "block_graph.js",
    "wasm_readable.js",
    "wasm_readable.css",
    "block_graph_layout.js",
    "wasm_diff_view.css",
    "wasm_diff_view.js",
    "graph_layout_client.js",
    "flow_graph.css",
    "flow_graph.js",
    "flow_graph_layout.js",
    "flow_timeline.js",
    "flow_workspace.css",
    "flow_workspace.js",
    "app.css",
    "entropy_map.css",
    "entropy_map.js",
    "wasm_identification.css",
    "wasm_identification.js",
    "agent_panel.css",
    "agent_panel.js",
    "session_panel.css",
    "session_panel.js",
    "agent_runtime_claude.js",
    "agent_runtime_chatgpt.js",
    "command_palette.js",
    "app_state.js",
    "evidence_models.js",
    "evidence_package.js",
    "float32_inspector.js",
    "evidence_comparison.js",
    "source_syntax.js",
    "source_format.js",
    "code_view.js",
    "source_facts.js",
    "source_search.js",
    "source_tree.js",
    "investigation_navigation.js",
    "investigation_notebook.js",
    "evidence_names.js",
    "wasm_function_names.js",
    "invocation_sites.js",
    "request_stack.js",
    "debugger_pause.js",
    "debugger_pause.css",
    "traffic_view.js",
    "network_scope.js",
    "request_tabs.js",
    "traffic_response.js",
    "traffic_headers.js",
    "traffic_cookies.js",
    "traffic_payload.js",
    "traffic_index.js",
    "traffic_filter.js",
    "traffic_columns.js",
    "traffic_overview.js",
    "captured_client.js",
    "captured_export_formats.js",
    "vm_semantics.js",
    "vm_static.js",
    "vm_static_view.js",
    "vm_analysis_packs.js",
    "vm_opcode_ledger.js",
    "vm_opcode_ledger_view.js",
    "vm_contextual.js",
    "vm_contextual_evidence.js",
    "vm_contextual_view.js",
    "vm_debugger.js",
    "vm_program_workspace.js",
    "app.js",
    "pane_layout.js",
    "native_console.js",
    "native_console_completion.js",
    "xrefs_view.js",
    "xrefs_view.css",
    "wasm_runner.js",
    "wasm_runner.css",
    "debugger_sidebar.js",
    "debugger_sidebar.css",
];
/// Flags a blocking read (cross-references or an artifact map) as abandoned
/// when its request future is dropped.
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
enum PackageOperation {
    Validate,
    Export,
    Compare,
}
struct VmDocumentsCache {
    signature: String,
    analysis: Value,
    opcode_workspace: Result<Value>,
    host_links: Result<Value>,
}

/// What every route reports about the capture, from one observation.
#[derive(Clone, Copy)]
struct CaptureView {
    mode: CaptureMode,
    state: capture::State,
}
impl CaptureView {
    /// Health and events keep the UI's reading of `broker_connected`: false
    /// means a live broker is gone, so a backend without one reports true.
    /// Session context and summary report only a running live broker.
    /// `capture_state` names the lifecycle on all of them.
    fn source_connected(self) -> bool {
        self.mode != CaptureMode::Live || self.state.broker_running()
    }
    fn stopped(self) -> bool {
        self.state == capture::State::Stopped
    }
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
    source_format: source_format::SourceFormat,
    /// Process-lifetime identity for `/api/health` and `X-REB-Expected-Instance`.
    instance_id: String,
    native_console: NativeConsole,
    live_wasm: LiveWasm,
    native_debugger_pause: NativeDebuggerPause,
    owned_vm_debugger: OwnedVmDebugger,
    vm_experiments: crate::vm_experiment::Experiments,
    /// Offline runs of captured Wasm functions; derived records only.
    wasm_runs: crate::wasm_run::Runs,
    /// The live capture lifecycle; `capture` serializes stop and clear.
    lifecycle: Capture,
    capture: Mutex<()>,
    io: Arc<Semaphore>,
    package_io: Arc<Semaphore>,
    analysis: Mutex<Option<VmDocumentsCache>>,
    /// Cursors of the current cross-reference selection; one entry only.
    xrefs: Arc<crate::xrefs::Cursors>,
    /// The store's drop gaps, extended only over appended bytes.
    gaps: Arc<crate::gap_tally::GapTally>,
    /// The last flow graph and the store snapshot it describes.
    flow_graph: Arc<crate::flow_graph::Cache>,
    /// Researcher Wasm function names, reread only when the library changes.
    wasm_names: Arc<crate::wasm_names::Cache>,
    /// The Analyst library's last ETag and the file state it was computed
    /// from, so the UI's 2 s names poll costs one `stat` while nothing changed.
    analyst_etag: Arc<std::sync::Mutex<Option<(crate::wasm_names::Fingerprint, String)>>>,
    events: Arc<Mutex<event_window::EventWindowCache>>,
    requests: Arc<Mutex<RequestIndex>>,
    initiator_frames: Arc<std::sync::Mutex<crate::request_stack::InitiatorFrames>>,
    observation_sites: Arc<std::sync::Mutex<crate::request_stack::ObservationSites>>,
    artifact_lookup: Arc<Mutex<ArtifactLookupCache>>,
    /// Bounds concurrent `/api/events/wait` callers; a full pool refuses.
    event_waiters: Arc<Semaphore>,
    live_browser: LiveBrowser,
    invocation_sites: Arc<js_invocation_sites::Store>,
    invocation_session: js_invocation_sites::Session,
    /// Script-text digests of immutable artifacts, by artifact SHA-256.
    text_digests: Arc<std::sync::Mutex<BTreeMap<String, String>>>,
}
fn cached_artifact_lookup(
    mut cache: OwnedMutexGuard<ArtifactLookupCache>,
    root: &Path,
    id: &str,
    stream: impl FnOnce(std::time::Instant) -> Result<Value>,
) -> Result<Value> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let indexed = cache.find_until(root, id, deadline);
    // Noncacheable full scans retain their reader permit and deadline,
    // but must not serialize unrelated lookups behind this cache guard.
    drop(cache);
    match indexed? {
        Some(value) => Ok(value),
        None => stream(deadline),
    }
}

impl App {
    pub async fn stop(&self) {
        let mut index = self.requests.clone().lock_owned().await;
        let _ = tokio::task::spawn_blocking(move || index.maintain()).await;
        self.analyst.stop();
        self.native_console.stop().await;
        if self.owned_vm_debugger.stop().await.is_err() {
            eprintln!("Owned VM helper shutdown could not be confirmed");
        }
    }
    pub async fn new(options: Options, port: u16) -> Arc<Self> {
        let native_console = NativeConsole::new(&options);
        let live_wasm = LiveWasm::new(options.live_wasm_socket.clone());
        let native_debugger_pause =
            NativeDebuggerPause::new(options.native_debugger_socket.clone());
        let invocation_sites = Arc::new(js_invocation_sites::Store::new(
            options.js_invocation_site_store.clone(),
        ));
        let invocation_session = js_invocation_sites::Session::read(
            options.js_invocation_session_sites.as_deref(),
            options.js_invocation_session_state.as_deref(),
            options.js_invocation_session_digests,
            &invocation_sites,
        );
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
            source_format: source_format::SourceFormat::default(),
            instance_id: format!(
                "{}:{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            native_console,
            live_wasm,
            native_debugger_pause,
            owned_vm_debugger: OwnedVmDebugger::new(options.worker(
                &options.owned_vm_fixture,
                "OriginTraceOwnedVmFixture",
                "build/reb-native-vm-fixture",
            )),
            vm_experiments: crate::vm_experiment::Experiments::new(
                options.artifacts.clone(),
                options.worker(
                    &options.owned_vm_fixture,
                    "OriginTraceOwnedVmFixture",
                    "build/reb-native-vm-fixture",
                ),
            ),
            wasm_runs: crate::wasm_run::Runs::new(options.artifacts.clone()),
            live_browser: LiveBrowser::new(&options),
            lifecycle: Capture::new(&options),
            requests: Arc::new(Mutex::new(RequestIndex::new(&options.store))),
            initiator_frames: Arc::default(),
            observation_sites: Arc::default(),
            invocation_sites,
            invocation_session,
            text_digests: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            options,
            capture: Mutex::new(()),
            io: Arc::new(Semaphore::new(4)),
            package_io: Arc::new(Semaphore::new(2)),
            analysis: Mutex::new(None),
            xrefs: Arc::default(),
            gaps: Arc::default(),
            flow_graph: Arc::default(),
            wasm_names: Arc::default(),
            analyst_etag: Arc::default(),
            events: Arc::new(Mutex::new(event_window::EventWindowCache::default())),
            artifact_lookup: Arc::new(Mutex::new(ArtifactLookupCache::default())),
            event_waiters: Arc::new(Semaphore::new(event_query::MAX_WAITERS)),
        });
        app.native_console.arm_live_bridge().await;
        let index = app.requests.clone();
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(request_index::PERSIST_INTERVAL);
            loop {
                ticks.tick().await;
                let mut index = index.clone().lock_owned().await;
                let _ = tokio::task::spawn_blocking(move || index.maintain()).await;
            }
        });
        app
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().fallback(handle).with_state(self.clone())
    }
    async fn read_event_window(&self, limit: usize) -> Result<event_window::EventWindow> {
        // Serialize cache owners before acquiring shared reader slots. Waiting
        // event polls cannot consume all four slots needed by other readers.
        let mut cache = self.events.clone().lock_owned().await;
        let path = self.options.store.clone();
        self.blocking(move || cache.read(&path, limit, validate_event))
            .await
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
    async fn vm_documents(&self) -> Result<(Value, Result<Value>)> {
        let signature = format!(
            "{}:{}:{}",
            analysis_input_signature(&self.options.artifacts.join("manifest.jsonl")),
            analysis_input_signature(&self.options.store),
            analysis_input_signature(&self.options.artifacts.join(vm::capture_mode::FILE_NAME)),
        );
        let mut cache = self.analysis.lock().await;
        if !cfg!(unix)
            || cache
                .as_ref()
                .is_none_or(|cached| cached.signature != signature)
        {
            let root = self.options.artifacts.clone();
            let store = self.options.store.clone();
            let documents = self
                .blocking(move || vm::store_documents(&root, &store))
                .await?;
            *cache = Some(VmDocumentsCache {
                signature,
                analysis: documents.analysis,
                opcode_workspace: documents.opcode_workspace,
                host_links: documents.host_links,
            });
        }
        let cached = cache.as_ref().expect("VM analysis cache");
        Ok((cached.analysis.clone(), cached.opcode_workspace.clone()))
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
    /// One observation of the capture for every route that reports it.
    fn capture_view(&self) -> CaptureView {
        CaptureView {
            mode: self.options.capture_mode(),
            state: self.lifecycle.state(),
        }
    }
    /// The graph documents are built as text so one large function never holds
    /// a parsed JSON tree in this process.
    async fn wasm_graph_route(&self, path: &str, raw_query: &str) -> Result<Response> {
        let q = Query::new(raw_query);
        if q.0
            .keys()
            .any(|key| !["artifact_id", "function"].contains(&key.as_str()))
        {
            return Err(Error::bad(
                "WASM graph routes take artifact_id and, for the graph route, function",
            ));
        }
        let id = q.required("artifact_id")?.to_owned();
        let root = self.options.artifacts.clone();
        let names = self.names_reader();
        let document = if path == "/api/wasm/functions" {
            if q.one("function")?.is_some() {
                return Err(Error::bad("The WASM function list takes only artifact_id"));
            }
            self.blocking(move || wasm_graph::function_index_named(&root, &id, Some(&names())))
                .await?
        } else {
            let function = q
                .required("function")?
                .parse::<u32>()
                .map_err(|_| Error::bad("A WASM function index is an unsigned 32-bit integer"))?;
            self.blocking(move || {
                wasm_graph::function_graph_named(&root, &id, function, Some(&names()))
            })
            .await?
        };
        Ok(([("content-type", "application/json")], document).into_response())
    }
    /// Reads the researcher Wasm names on a blocking thread: one `stat` while
    /// the library is unchanged, a bounded reread when it changed.
    fn names_reader(&self) -> impl Fn() -> Arc<crate::wasm_names::Names> + Send + 'static {
        let (cache, store) = (self.wasm_names.clone(), self.workspace.clone());
        move || cache.get(&store)
    }
    /// The readable lift is built as text, like the graph documents, and
    /// recomputed per window so nothing retains a whole function's lines.
    async fn wasm_pseudocode_route(&self, raw_query: &str) -> Result<Response> {
        let q = Query::new(raw_query);
        if q.0.keys().any(|key| {
            !["artifact_id", "function", "line_offset", "line_limit"].contains(&key.as_str())
        }) {
            return Err(Error::bad(
                "The WASM readable view takes artifact_id and function with optional line_offset and line_limit",
            ));
        }
        let id = q.required("artifact_id")?.to_owned();
        let function = q
            .required("function")?
            .parse::<u32>()
            .map_err(|_| Error::bad("A WASM function index is an unsigned 32-bit integer"))?;
        let offset = q.number("line_offset", Some("0"), 32, false)? as usize;
        let default = wasm_pseudocode::DEFAULT_LINE_LIMIT.to_string();
        let limit = q.number("line_limit", Some(&default), 32, true)? as usize;
        let root = self.options.artifacts.clone();
        let names = self.names_reader();
        let document = self
            .blocking(move || {
                wasm_pseudocode::pseudocode_named(
                    &root,
                    &id,
                    function,
                    offset,
                    limit,
                    Some(&names()),
                )
            })
            .await?;
        Ok(([("content-type", "application/json")], document).into_response())
    }
    /// Two artifact IDs and an optional page. A misspelled parameter fails
    /// instead of returning an unfiltered table the caller reads as filtered.
    async fn wasm_diff_route(&self, raw_query: &str) -> Result<Response> {
        // The deadline counts from arrival, including the wait for a reader.
        let started = std::time::Instant::now();
        let q = Query::new(raw_query);
        if q.0.keys().any(|key| {
            ![
                "artifact_id",
                "compare_artifact_id",
                "status",
                "row_offset",
                "row_limit",
            ]
            .contains(&key.as_str())
        }) {
            return Err(Error::bad(
                "The WASM module diff takes artifact_id and compare_artifact_id with optional status, row_offset and row_limit",
            ));
        }
        let a = q.required("artifact_id")?.to_owned();
        let b = q.required("compare_artifact_id")?.to_owned();
        let offset = q.number("row_offset", Some("0"), 32, false)? as usize;
        let default = wasm_diff::PAGE_DEFAULT_ROWS.to_string();
        let limit = q.number("row_limit", Some(&default), 32, true)? as usize;
        let page = wasm_diff::Page::new(offset, limit, q.one("status")?)?;
        let root = self.options.artifacts.clone();
        let document = self
            .blocking(move || wasm_diff::diff(&root, &a, &b, &page, started))
            .await?;
        Ok(axum::Json(document).into_response())
    }
    async fn receiver_connected(&self) -> bool {
        socket_connected(self.options.artifact_socket.as_deref()).await
    }
    async fn get(&self, path: &str, raw_query: &str, headers: &HeaderMap) -> Result<Response> {
        if path == "/api/vm-debugger/trace" {
            return self
                .owned_vm_debugger
                .trace(raw_query)
                .await
                .map(|value| axum::Json(value).into_response());
        }
        if path == "/api/wasm/functions" || path == "/api/wasm/graph" {
            return self.wasm_graph_route(path, raw_query).await;
        }
        if path == "/api/wasm/runs" {
            let q = Query::new(raw_query);
            q.only(&["artifact_id", "limit"], &[])?;
            let artifact = match q.one("artifact_id")? {
                Some(id) => {
                    validation::canonical(&json!(id), 64, true, "Artifact ID")?;
                    Some(id.to_owned())
                }
                None => None,
            };
            let limit = q.number("limit", Some("1"), 64, true)?;
            if limit > 64 {
                return Err(Error::bad("limit must be between 1 and 64"));
            }
            let root = self.options.artifacts.clone();
            let value = self
                .blocking(move || crate::wasm_run::list(&root, artifact.as_deref(), limit as usize))
                .await?;
            return Ok(axum::Json(value).into_response());
        }
        if path == "/api/wasm/pseudocode" {
            return self.wasm_pseudocode_route(raw_query).await;
        }
        if path == "/api/wasm/diff" {
            return self.wasm_diff_route(raw_query).await;
        }
        let q = Query::new(raw_query);
        let mut etag = None;
        let value = match path {
            "/api/health" => {
                let capture = self.capture_view();
                json!({"status":"ok","instance_id":self.instance_id,"store":self.options.store,"store_exists":self.options.store.exists(),"trace_store":self.options.trace_store,"trace_store_exists":self.options.trace_store.exists(),"signal_store":self.options.signal_store,"signal_store_exists":self.options.signal_store.exists(),"artifact_store":self.options.artifacts,"artifact_store_exists":self.options.artifacts.exists(),"artifact_receiver_configured":self.options.artifact_socket.is_some(),"artifact_receiver_connected":self.receiver_connected().await,"api_collection_store":self.collection.path,"api_collection_store_exists":self.collection.path.exists(),"local_analyst_store":self.workspace.path,"local_analyst_store_exists":self.workspace.path.exists(),"local_analyst_runner_available":self.analyst.state()["available"],"decoder_available":self.decoder.state()["available"],"broker_connected":capture.source_connected(),"capture_mode":capture.mode.as_str(),"capture_state":capture.state.as_str(),"debugger_state":"unavailable"})
            }
            "/api/session/context" => {
                if !q.0.is_empty() {
                    return Err(Error::bad("Session context takes no query parameters"));
                }
                let snapshot = session_context::retired_debugger(&self.instance_id);
                let root = self.options.artifacts.clone();
                let mut value = session_context::with_artifacts(
                    snapshot,
                    self.blocking(move || session_context::artifacts(&root)),
                )
                .await?;
                value["protocol_version"] = json!(1);
                value["endpoint"] = json!(format!(
                    "http://{}:{}",
                    if self.options.host.contains(':') {
                        "[::1]"
                    } else {
                        "127.0.0.1"
                    },
                    self.port
                ));
                let capture = self.capture_view();
                value["capture_mode"] = json!(capture.mode.as_str());
                let broker_connected = capture.state.broker_running();
                value["live_admission"] = json!(session_context::live_admission(
                    capture.mode.as_str(),
                    broker_connected,
                ));
                value["broker_connected"] = json!(broker_connected);
                value["capture_state"] = json!(capture.state.as_str());
                value["capture_options"] = session_context::capture_options(
                    &self.options,
                    &self.invocation_session.value(),
                );
                value["allow_effects"] = Value::Null;
                value["effects_admission"] = json!("caller_specific_unknown");
                value["limits"] = json!({"items_per_inventory":session_context::ITEMS,"url_policy":"origin_or_wasm_label","title_policy":"omitted","artifact_linkage":"not_inferred"});
                etag = Some(session_context::etag(&value));
                value
            }
            "/api/analysis/catalog" => analysis_catalog::catalog()?,
            "/api/decoder" => self.decoder.state(),
            "/api/live-wasm" => {
                if !q.0.is_empty() {
                    return Err(Error::bad("Live Wasm state takes no query parameters"));
                }
                self.live_wasm.state()?
            }
            "/api/native-debugger" => {
                let query = native_debugger_query(&q)?;
                let console = self.native_console.state().await;
                let watch = self.native_console.watch();
                let store = self.options.store.clone();
                // The peer exchange blocks, like the live Wasm read.
                let pause = self.native_debugger_pause.clone();
                tokio::task::spawn_blocking(move || {
                    crate::native_debugger::state(&store, &console, watch, &query, &pause)
                })
                .await
                .map_err(|_| Error::new(500, "Native debugger state read failed"))??
            }
            "/api/native-console" => self.native_console.state().await,
            "/api/native-console/document-start" => {
                if q.0.keys().any(|key| key != "after_sequence") {
                    return Err(Error::bad(
                        "Document-start reads take only an optional after_sequence cursor",
                    ));
                }
                // A misspelled cursor must fail rather than silently replay the
                // whole retained page as if it were new output.
                let after = match q.one("after_sequence")? {
                    Some(value) => validation::canonical(
                        &json!(value),
                        64,
                        false,
                        "Document-start output cursor",
                    )?,
                    None => 0,
                };
                self.native_console.document_start(after).await?
            }
            "/api/analysis/vm/experiments" => self.vm_experiments.list()?,
            "/api/vm-debugger" => self.owned_vm_debugger.state().await?,
            "/api/wasm" => {
                // A misspelled filter must fail rather than return a
                // whole-module document the caller will read as scoped.
                if q.0.keys().any(|key| {
                    !["artifact_id", "sections", "row_offset", "row_limit"].contains(&key.as_str())
                }) {
                    return Err(Error::bad(
                        "WASM inspection takes artifact_id with optional sections, row_offset and row_limit",
                    ));
                }
                let id = q.required("artifact_id")?.to_owned();
                let sections = q
                    .one("sections")?
                    .map(wasm::requested_sections)
                    .transpose()?;
                let window = if q.any(&["row_offset", "row_limit"]) {
                    let offset = q.number("row_offset", Some("0"), 32, false)? as usize;
                    let default = wasm::WINDOW_MAX_ROWS.to_string();
                    let limit = q.number("row_limit", Some(&default), 32, true)? as usize;
                    if limit > wasm::WINDOW_MAX_ROWS {
                        return Err(Error::bad("row_limit is at most 2048"));
                    }
                    Some((offset, limit))
                } else {
                    None
                };
                let root = self.options.artifacts.clone();
                let names = self.names_reader();
                self.blocking(move || {
                    let mut document = wasm::load(&root, &id, sections.as_ref())?;
                    if let Some((offset, limit)) = window {
                        wasm::window(&mut document, offset, limit)?;
                    }
                    crate::wasm_names::annotate_inspection(&mut document, &names());
                    Ok(document)
                })
                .await?
            }
            "/api/wasm/identification" => {
                if q.0
                    .keys()
                    .any(|key| !["artifact_id", "row_offset", "row_limit"].contains(&key.as_str()))
                {
                    return Err(Error::bad(
                        "WASM identification takes artifact_id with optional row_offset and row_limit",
                    ));
                }
                let id = q.required("artifact_id")?.to_owned();
                let offset = q.number("row_offset", Some("0"), 32, false)? as usize;
                let default = wasm_identification::SUGGESTION_PAGE.to_string();
                let limit = q.number("row_limit", Some(&default), 32, true)? as usize;
                if limit > wasm_identification::SUGGESTION_PAGE {
                    return Err(Error::bad("row_limit is at most 1024"));
                }
                let root = self.options.artifacts.clone();
                self.blocking(move || wasm_identification::load(&root, &id, offset, limit))
                    .await?
            }
            "/api/artifact-map" => {
                if q.0.keys().any(|key| key != "artifact_id") {
                    return Err(Error::bad("Artifact map takes only artifact_id"));
                }
                let id = q.required("artifact_id")?.to_owned();
                let artifact = self.find_artifact(&id).await?;
                let root = self.options.artifacts.clone();
                let cancelled = Arc::new(AtomicBool::new(false));
                // Dropped when the client abandons the request, so a stale map
                // stops reading instead of holding a shared reader permit.
                let _stale = CancelOnDrop(cancelled.clone());
                self.blocking(move || artifact_map::build(&root, &artifact, &cancelled))
                    .await?
            }
            "/api/api-collection" | "/api/local-analyst" => {
                let analyst = path.ends_with("local-analyst");
                let store = if analyst {
                    self.workspace.clone()
                } else {
                    self.collection.clone()
                };
                // An unchanged library file answers its last ETag without a
                // read. The state is taken before the read below, so a write
                // racing that read leaves a stale state and the next poll reads.
                let before = analyst.then(|| crate::wasm_names::fingerprint(&store.path));
                if let Some(state) = before
                    && let Some((cached, tag)) = self.analyst_etag.lock().unwrap().as_ref()
                    && *cached == state
                    && state.is_some()
                    && matches_etag(headers, Some(tag))
                {
                    return Ok(not_modified(tag));
                }
                // These documents are at most 1–2 MiB. Do not wait behind VM
                // analysis or Wasm inspection, which hold the shared reader permits.
                let (value, digest) = tokio::task::spawn_blocking(move || {
                    store.load().map(|value| {
                        // A store replaced outside this backend can repeat a
                        // generation; its content still tells them apart.
                        let bytes = serde_json::to_vec(&value).unwrap_or_default();
                        let digest = hex::encode(&sha2::Sha256::digest(bytes)[..8]);
                        (value, digest)
                    })
                })
                .await
                .map_err(|e| Error::new(500, e.to_string()))?
                .map_err(|e| Error::new(500, e.message))?;
                etag = Some(format!(
                    "\"{}-{}-{digest}\"",
                    if path.ends_with("api-collection") {
                        "api-collection"
                    } else {
                        "local-analyst"
                    },
                    value["generation"]
                ));
                if let (Some(state), Some(tag)) = (before, etag.as_ref()) {
                    *self.analyst_etag.lock().unwrap() = Some((state, tag.clone()));
                }
                value
            }
            "/api/local-analyst/runner" => self.analyst.state(),
            "/api/source-facts" => {
                // Never infer identity from a URL, live script, or selected UI row.
                if q.0.keys().any(|key| {
                    ![
                        "session_id",
                        "artifact_id",
                        "region_start_byte",
                        "region_end_byte",
                    ]
                    .contains(&key.as_str())
                }) {
                    return Err(Error::bad(
                        "Source facts require session_id and artifact_id with an optional region",
                    ));
                }
                q.number("session_id", None, 64, false)?;
                q.number("artifact_id", None, 64, false)?;
                // A region narrows analysis of the same verified bytes. Half a
                // range is a caller mistake, not a default to invent. Offsets
                // admit the contract's full unsigned 64-bit form; one past the
                // artifact is refused by the byte-range check below.
                let offset = |key| {
                    q.number(key, None, 64, false)
                        .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
                };
                let region = match (q.one("region_start_byte")?, q.one("region_end_byte")?) {
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        Some((offset("region_start_byte")?, offset("region_end_byte")?))
                    }
                    _ => {
                        return Err(Error::bad(
                            "A source facts region requires region_start_byte and region_end_byte",
                        ));
                    }
                };
                let session = q.required("session_id")?.to_owned();
                let id = q.required("artifact_id")?.to_owned();
                let root = self.options.artifacts.clone();
                let (source, identity) = self
                    .blocking(move || source_facts::load(&root, &session, &id))
                    .await?;
                if let Some((start, end)) = region
                    && (start > end
                        || end > source.len()
                        || !source.is_char_boundary(start)
                        || !source.is_char_boundary(end))
                {
                    return Err(Error::bad(
                        "A source facts region must be an original byte range in this artifact",
                    ));
                }
                let mut result = self.deobfuscator.source_facts(&source, region).await?;
                result["source"] = identity;
                result
            }
            "/api/source-format" => {
                q.only(
                    &["session_id", "artifact_id"],
                    &["start_line", "line_count", "language"],
                )?;
                q.number("session_id", None, 64, false)?;
                q.number("artifact_id", None, 64, false)?;
                let language = match q.one("language")? {
                    None => None,
                    Some(value) => Some(
                        source_format::Language::parse(value)
                            .ok_or_else(|| Error::bad("language must be javascript or json"))?,
                    ),
                };
                let window = match (q.one("start_line")?, q.one("line_count")?) {
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        let start_line = q.number("start_line", None, 64, true)?;
                        let line_count = q.number("line_count", None, 64, true)?;
                        if line_count > source_format::MAX_WINDOW_LINES {
                            return Err(Error::bad(
                                "line_count exceeds the formatted window limit",
                            ));
                        }
                        Some(source_format::Window {
                            start_line,
                            line_count,
                        })
                    }
                    _ => {
                        return Err(Error::bad(
                            "A formatted window requires start_line and line_count",
                        ));
                    }
                };
                let session = q.required("session_id")?.to_owned();
                let id = q.required("artifact_id")?.to_owned();
                let root = self.options.artifacts.clone();
                let (source, identity, language) = self
                    .blocking(move || source_format::load(&root, &session, &id, language))
                    .await?;
                self.source_format
                    .format(source, identity, language, window)
                    .await?
            }
            "/api/js-invocation-sites" => {
                if !q.0.is_empty() {
                    return Err(Error::bad(
                        "The saved invocation site set takes no query parameters",
                    ));
                }
                self.invocation_site_set().await?
            }
            "/api/js-invocation-sites/resolve" => {
                q.only(&["session_id", "artifact_id", "name", "byte_offset"], &[])?;
                let target = js_invocation_sites::Target::from_fields(
                    q.one("name")?.map(|name| json!(name)).as_ref(),
                    match q.one("byte_offset")? {
                        Some(_) => Some(json!(q.number("byte_offset", None, 32, false)?)),
                        None => None,
                    }
                    .as_ref(),
                )?;
                self.resolve_invocation_site(
                    q.required("session_id")?,
                    q.required("artifact_id")?,
                    &target,
                    None,
                )
                .await?
                .0
            }
            "/api/request-stack" => {
                const NAMES: [&str; 3] =
                    ["request_id", "navigation_sequence", "observation_sequence"];
                q.only(&["session_id", "process_id"], &NAMES)?;
                let session = match q.one("session_id")? {
                    Some(_) => Some(q.number("session_id", None, 64, true)?),
                    None => None,
                };
                let process = q.number("process_id", None, 32, true)?;
                let named: Vec<&str> = NAMES
                    .into_iter()
                    .filter(|name| q.0.contains_key(*name))
                    .collect();
                let [name] = named[..] else {
                    return Err(Error::bad(
                        "Specify exactly one of request_id, navigation_sequence and observation_sequence",
                    ));
                };
                let value = q.number(name, None, 64, true)?;
                let (store, artifacts, requests) = (
                    self.options.store.clone(),
                    self.options.artifacts.clone(),
                    self.requests.clone(),
                );
                let names = self.names_reader();
                self.blocking(move || {
                    let mut document = match name {
                        "navigation_sequence" => crate::request_stack::navigation_document(
                            &store, &artifacts, &requests, session, process, value,
                        ),
                        "observation_sequence" => crate::request_stack::observation_document(
                            &store, &artifacts, &requests, session, process, value,
                        ),
                        _ => crate::request_stack::document(
                            &store, &artifacts, &requests, session, process, value,
                        ),
                    }?;
                    crate::wasm_names::annotate_request_stack(&mut document, &names());
                    Ok(document)
                })
                .await?
            }
            "/api/deobfuscation" => {
                let artifact = q.required("artifact_id")?;
                let mode = q.one("mode")?.unwrap_or("analysis");
                if !["analysis", "derived"].contains(&mode) {
                    return Err(Error::bad("Deobfuscation mode is invalid"));
                }
                let assumption = q.one("assume_intrinsics")?.unwrap_or("0");
                if !["0", "1"].contains(&assumption) {
                    return Err(Error::bad("Intrinsic assumption must be 0 or 1"));
                }
                let record = self.find_artifact(artifact).await?;
                if record["kind"] != "javascript" {
                    return Err(Error::bad("Artifact is not JavaScript"));
                }
                let root = self.options.artifacts.clone();
                let bytes = self
                    .blocking(move || evidence::content(&root, &record, 4 * 1024 * 1024))
                    .await?;
                let source = String::from_utf8(bytes)
                    .map_err(|_| Error::bad("Artifact is not valid UTF-8 JavaScript"))?;
                let mut result = self
                    .deobfuscator
                    .analyze(&source, assumption == "1", mode == "derived")
                    .await?;
                // Version 1 keeps the field; live scripts left with CDP.
                result["script_id"] = Value::Null;
                result["artifact_id"] = json!(artifact);
                result["mode"] = json!(mode);
                result["source_truncated"] = json!(false);
                result
            }
            "/api/events" => {
                // An unknown or misspelled filter must fail rather than return
                // the unfiltered tail that a caller would read as filtered.
                q.only(&event_query::EVENT_QUERY_KEYS, &["limit"])?;
                let limit = q.limit(500, 5000)?;
                if q.any(&event_query::EVENT_QUERY_KEYS) {
                    return self.filtered_events(&q, limit, headers).await;
                }
                let capture = self.capture_view();
                etag = Some(event_window::etag(
                    &self.options.store,
                    &format!(
                        "{}-{limit}-{}",
                        capture.mode.as_str(),
                        capture.state.as_str()
                    ),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let window = self.read_event_window(limit).await?;
                let mut result = json!({
                    "count": window.events.len(),
                    "sequence_gaps": window.sequence_gaps.to_string(),
                    "sequence_gaps_saturated": window.sequence_gaps_saturated,
                    "queue_drops": window.queue_drops.to_string(),
                    "queue_drops_saturated": window.queue_drops_saturated,
                    "named_gaps": window.named_gaps.iter().map(|gap| json!({
                        "category": gap.category,
                        "reason": gap.reason,
                        "count": gap.count.to_string()
                    })).collect::<Vec<_>>(),
                    "event_window": window.coverage
                });
                // json! serializes borrowed values; move the retained window instead
                // of allocating a second complete evidence tree on every refresh.
                let mut events = window.events;
                event_query::annotate_events(&mut events);
                result["events"] = Value::Array(events);
                result["network_events"] = Value::Array(window.network_events);
                self.event_state(&mut result, capture);
                if capture.mode == CaptureMode::Demo {
                    result["canvas_render_captures"] =
                        serde_json::from_str(include_str!("../assets/demo-canvas.json"))
                            .expect("Demo canvas capture");
                }
                result
            }
            "/api/requests" => {
                let query = request_index::RequestQuery::parse(&q, raw_query)?;
                let tag = headers
                    .get("if-none-match")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let mut index = self.requests.clone().lock_owned().await;
                let (frames, root) = (
                    self.initiator_frames.clone(),
                    self.options.artifacts.clone(),
                );
                return match self
                    .blocking(move || {
                        let mut answer = index.respond(&query, tag.as_deref())?;
                        let mut settled = true;
                        if let request_index::Answer::Document(document, _) = &mut answer {
                            settled = frames
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .resolve(document, &root);
                        }
                        Ok((answer, settled))
                    })
                    .await?
                {
                    (request_index::Answer::Unchanged(tag), _) => Ok(not_modified(&tag)),
                    (request_index::Answer::Document(document, tag), settled) => {
                        let mut response = axum::Json(document).into_response();
                        // Frames left for a later answer must not be cached behind a 304.
                        if settled {
                            response
                                .headers_mut()
                                .insert("etag", HeaderValue::from_str(&tag).unwrap());
                        }
                        Ok(response)
                    }
                };
            }
            "/api/artifacts" => {
                q.only(&artifact_query::ARTIFACT_QUERY_KEYS, &["limit"])?;
                let limit = q.limit(500, 5000)?;
                let configured = self.options.artifact_socket.is_some();
                let connected = self.receiver_connected().await;
                let filtered = q.any(&artifact_query::ARTIFACT_QUERY_KEYS);
                etag = Some(evidence::resource_etag(
                    &self.options.artifacts.join("manifest.jsonl"),
                    &format!(
                        "{limit}-{}-{}{}",
                        u8::from(configured),
                        u8::from(connected),
                        if filtered {
                            format!("-query:{raw_query}")
                        } else {
                            String::new()
                        }
                    ),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                if filtered {
                    let filter = artifact_query::ArtifactFilter::parse(&q)?;
                    let cursor = event_query::cursor(&q)?;
                    let root = self.options.artifacts.clone();
                    let (page, filter) = self
                        .blocking(move || {
                            artifact_query::read(&root, &filter, cursor, limit)
                                .map(|page| (page, filter))
                        })
                        .await?;
                    let mut result = json!({"count":page.records.len(),"artifact_receiver_configured":configured,"artifact_receiver_connected":connected});
                    result["query"] = artifact_query::query_document(&page, &filter, cursor, limit);
                    result["artifacts"] = Value::Array(page.records);
                    result
                } else {
                    let root = self.options.artifacts.clone();
                    let mut artifacts = self
                        .blocking(move || evidence::artifacts(&root, limit))
                        .await?;
                    for artifact in &mut artifacts {
                        artifact
                            .as_object_mut()
                            .expect("Validated artifact object")
                            .retain(|key, _| {
                                evidence::PUBLIC_ARTIFACT_FIELDS.contains(&key.as_str())
                            });
                    }
                    let mut result = json!({"count":artifacts.len(),"artifact_receiver_configured":configured,"artifact_receiver_connected":connected});
                    result["artifacts"] = Value::Array(artifacts);
                    result
                }
            }
            "/api/events/wait" => {
                q.only(&event_query::EVENT_QUERY_KEYS, &["limit", "timeout_ms"])?;
                return self.wait_for_events(&q).await;
            }
            "/api/session/summary" => {
                if !q.0.is_empty() {
                    return Err(Error::bad("Session summary takes no query parameters"));
                }
                let capture = self.capture_view();
                let state = (
                    capture.mode.as_str(),
                    capture.state.broker_running(),
                    capture.stopped(),
                    self.options.artifact_socket.is_some(),
                    self.receiver_connected().await,
                    capture.state.as_str(),
                );
                // The store's tag is taken before the request index reads it.
                let before = event_window::etag(
                    &self.options.store,
                    &session_summary::etag_key(
                        &format!("{state:?}"),
                        &evidence::resource_etag(
                            &self.options.artifacts.join("manifest.jsonl"),
                            "",
                        ),
                    ),
                );
                // Per request, so they come from the request index's rows. The
                // index is held only for its counts, and a failure leaves the
                // rest of the summary standing.
                let index = self.requests.clone().lock_owned().await;
                let (counts, progress) = self
                    .blocking(move || {
                        let mut index = index;
                        let counts = index.response_bodies().map_err(|error| error.message);
                        Ok((counts, index.progress_marker()))
                    })
                    .await?;
                // The counts can be mid-store on an unchanged file, so the tag
                // names the progress they were read at. An answer without them
                // is not tagged, so a revalidation reads the index again.
                etag = counts
                    .is_ok()
                    .then(|| session_summary::etag(&before, &progress));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let store = self.options.store.clone();
                let artifacts = self.options.artifacts.clone();
                let instance = self.instance_id.clone();
                let content_limits = session_context::content_limits(&self.options);
                let mut summary = self
                    .blocking(move || {
                        let mut summary = session_summary::build(
                            &store,
                            &artifacts,
                            &session_summary::CaptureState {
                                instance_id: &instance,
                                capture_mode: state.0,
                                broker_connected: state.1,
                                capture_stopped: state.2,
                                artifact_receiver_configured: state.3,
                                artifact_receiver_connected: state.4,
                                content_limits,
                            },
                        )?;
                        session_summary::add_response_bodies(&mut summary, counts);
                        Ok(summary)
                    })
                    .await?;
                summary["capture_state"] = json!(state.5);
                summary
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
                        Some(&options.artifacts),
                    )
                })
                .await?
            }
            "/api/request-headers" => {
                q.only(&["session_id", "request_id"], &[])?;
                let session = q.required("session_id")?.to_owned();
                let request = q.required("request_id")?.to_owned();
                for key in ["session_id", "request_id"] {
                    q.number(key, None, 64, true)?;
                }
                let filter = event_query::event_filter(&q)?;
                let options = self.options.clone();
                // Coverage also depends on how far the index has read, with no store change.
                let progress = self.requests.lock().await.progress_marker();
                etag = Some(evidence::resource_etag(
                    &options.store,
                    &format!(
                        "{}:{session}:{request}:{progress}",
                        evidence::resource_etag(&options.artifacts.join("manifest.jsonl"), "")
                    ),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let gaps = self.gaps.clone();
                let requests = self.requests.clone();
                self.blocking(move || {
                    let range =
                        requests
                            .blocking_lock()
                            .member_range(Some(&session), None, &request)?;
                    let detail =
                        event_query::read_request_records(&options.store, range, 1024, &filter)?;
                    let artifacts =
                        evidence::artifacts_named(&options.artifacts, &detail.records, |_| false)?;
                    let drops = gaps.drops(&options.store, &session)?;
                    let mut document = request_headers::build(
                        &detail.records,
                        &drops,
                        &artifacts,
                        &options.artifacts,
                        &session,
                        &request,
                    );
                    document["coverage"] = detail.coverage.to_json();
                    Ok(document)
                })
                .await?
            }
            "/api/request-cookies" => {
                q.only(&["session_id", "request_id"], &[])?;
                let session = q.required("session_id")?.to_owned();
                let request = q.required("request_id")?.to_owned();
                for key in ["session_id", "request_id"] {
                    q.number(key, None, 64, true)?;
                }
                let filter = event_query::event_filter(&q)?;
                let options = self.options.clone();
                let progress = self.requests.lock().await.progress_marker();
                etag = Some(evidence::resource_etag(
                    &options.store,
                    &format!(
                        "cookies:{}:{session}:{request}:{progress}",
                        evidence::resource_etag(&options.artifacts.join("manifest.jsonl"), "")
                    ),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let gaps = self.gaps.clone();
                let requests = self.requests.clone();
                self.blocking(move || {
                    let range =
                        requests
                            .blocking_lock()
                            .member_range(Some(&session), None, &request)?;
                    let detail =
                        event_query::read_request_records(&options.store, range, 1024, &filter)?;
                    let artifacts =
                        evidence::artifacts_named(&options.artifacts, &detail.records, |_| false)?;
                    let drops = gaps.drops(&options.store, &session)?;
                    let mut document = request_cookies::build(
                        &detail.records,
                        &drops,
                        &artifacts,
                        &options.artifacts,
                        &session,
                        &request,
                    );
                    document["coverage"] = detail.coverage.to_json();
                    Ok(document)
                })
                .await?
            }
            "/api/cookie-provenance" => {
                q.only(&["session_id", "name"], &[])?;
                let session = q.required("session_id")?.to_owned();
                q.number("session_id", None, 64, true)?;
                let name = q.required("name")?.to_owned();
                if name.len() > 4096 {
                    return Err(Error::bad("name is longer than 4096 bytes"));
                }
                let filter = event_query::event_filter(&Query::new(&format!(
                    "session_id={session}&category=network"
                )))?;
                let options = self.options.clone();
                let progress = self.requests.lock().await.progress_marker();
                etag = Some(evidence::resource_etag(
                    &options.store,
                    &format!(
                        "provenance:{}:{session}:{name}:{progress}",
                        evidence::resource_etag(&options.artifacts.join("manifest.jsonl"), "")
                    ),
                ));
                if matches_etag(headers, etag.as_deref()) {
                    return Ok(not_modified(etag.as_deref().unwrap()));
                }
                let gaps = self.gaps.clone();
                let requests = self.requests.clone();
                self.blocking(move || {
                    // A cookie spans the session, so no one request's bytes bound it.
                    let detail =
                        event_query::read_request_records(&options.store, None, 5000, &filter)?;
                    // Script writes resolve through this session's stacks and sources.
                    let artifacts =
                        evidence::artifacts_named(&options.artifacts, &detail.records, |a| {
                            a["session_id"].as_str() == Some(session.as_str())
                                && matches!(
                                    a["kind"].as_str(),
                                    Some("stack" | "javascript" | "wasm")
                                )
                        })?;
                    let complete = detail.coverage.complete();
                    let identities = |process: u64| {
                        requests
                            .blocking_lock()
                            .identities(&session, process as u32)
                            .map_or((HashMap::new(), complete), |(indexed, exhaustive)| {
                                (
                                    crate::request_stack::decode_indexed_identities(
                                        process as u32,
                                        &indexed,
                                    ),
                                    exhaustive || complete,
                                )
                            })
                    };
                    let drops = gaps.drops(&options.store, &session)?;
                    let mut document = request_cookies::provenance(
                        &detail.records,
                        &drops,
                        &artifacts,
                        &options.artifacts,
                        &session,
                        &name,
                        &identities,
                    );
                    document["coverage"] = detail.coverage.to_json();
                    Ok(document)
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
                let session = q.one("session_id")?;
                let process = q.one("root_process_id")?;
                let sequence = q.one("root_sequence_number")?;
                let selected = [request, session, process, sequence]
                    .iter()
                    .any(Option::is_some);
                let process_id = if selected {
                    if [request, session, process, sequence]
                        .iter()
                        .any(Option::is_none)
                    {
                        return Err(Error::bad(
                            "Exact VM request selection requires request_id, session_id, root_process_id and root_sequence_number",
                        ));
                    }
                    q.number("request_id", None, 64, true)?;
                    q.number("session_id", None, 64, true)?;
                    q.number("root_sequence_number", None, 64, true)?;
                    q.number("root_process_id", None, 32, true)?
                } else {
                    0
                };
                let (mut value, _) = self.vm_documents().await?;
                if selected {
                    crate::vm_request_links::select(
                        &mut value,
                        request.unwrap(),
                        session.unwrap(),
                        process_id,
                        sequence.unwrap(),
                    );
                }
                etag = Some(format!(
                    "\"{}-{}-{}-{}-{}\"",
                    value["document_digest"].as_str().unwrap(),
                    request.unwrap_or("all"),
                    session.unwrap_or("all"),
                    process.unwrap_or("all"),
                    sequence.unwrap_or("all")
                ));
                value
            }
            "/api/flow-graph" => {
                q.only(&["session_id"], &[])?;
                let session = q.number("session_id", None, 64, true)?;
                let stores = crate::store_scan::Stores {
                    events: self.options.store.clone(),
                    artifacts: self.options.artifacts.clone(),
                };
                let cache = self.flow_graph.clone();
                // A client that moved on leaves no scan running.
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let _cancel_on_drop = CancelOnDrop(cancel.clone());
                let names = self.names_reader();
                let graph = self
                    .blocking(move || {
                        let graph = crate::flow_graph::run(&stores, session, &cache, &cancel)?;
                        crate::wasm_names::annotate_flow_graph_bytes(graph, &names())
                    })
                    .await?;
                return Ok(bytes_response(graph, "application/json"));
            }
            "/api/xrefs" => {
                let query = crate::xrefs::XrefQuery::parse(&q)?;
                // Only the analysis already cached: this route never computes
                // or publishes one.
                let handler = match query.vm_target() {
                    Some((artifact, sha256, byte_offset, byte_size)) => {
                        let cache = self.analysis.lock().await;
                        Some(match cache.as_ref().map(|c| c.opcode_workspace.as_ref()) {
                            Some(Ok(document)) => crate::xrefs::vm_handler_input(
                                document,
                                &artifact,
                                &sha256,
                                byte_offset,
                                byte_size,
                            ),
                            _ => crate::xrefs::VmHandlerInput::not_ready(),
                        })
                    }
                    None => None,
                };
                let stores = crate::store_scan::Stores {
                    events: self.options.store.clone(),
                    artifacts: self.options.artifacts.clone(),
                };
                let cursors = self.xrefs.clone();
                // A dropped request abandons its scan; a client that moved on
                // leaves no read running.
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let _cancel_on_drop = CancelOnDrop(cancel.clone());
                let names = self.names_reader();
                self.blocking(move || {
                    let mut document =
                        crate::xrefs::run(&query, &stores, &cursors, handler, &cancel)?;
                    crate::wasm_names::annotate_xrefs(&mut document, &names());
                    Ok(document)
                })
                .await?
            }
            "/api/analysis/vm/host-links" => {
                let _ = self.vm_documents().await?;
                let value = self
                    .analysis
                    .lock()
                    .await
                    .as_ref()
                    .expect("VM analysis cache")
                    .host_links
                    .clone()?;
                etag = Some(format!(
                    "\"{}\"",
                    value["document_digest"].as_str().unwrap()
                ));
                value
            }
            "/api/analysis/vm/opcodes" => {
                let (_, workspace) = self.vm_documents().await?;
                let value = workspace.map_err(|error| {
                    Error::new(
                        error.status,
                        format!("VM opcode workspace is unavailable: {}", error.message),
                    )
                })?;
                etag = Some(format!(
                    "\"{}\"",
                    value["document_digest"]
                        .as_str()
                        .ok_or_else(|| Error::new(500, "VM opcode workspace is malformed"))?
                ));
                value
            }
            "/api/artifacts/search" => {
                q.only(
                    &artifact_query::ARTIFACT_QUERY_KEYS[..8],
                    &["q", "match_case", "offset", "limit"],
                )?;
                let query = artifact_text::SearchRequest::query(q.required("q")?)?;
                let match_case = match q.one("match_case")? {
                    None | Some("false") => false,
                    Some("true") => true,
                    Some(_) => return Err(Error::bad("match_case must be true or false")),
                };
                let request = artifact_text::SearchRequest {
                    query,
                    match_case,
                    filter: artifact_query::ArtifactFilter::parse(&q)?,
                    offset: q.number("offset", Some("0"), 32, false)? as usize,
                    limit: q.limit(50, artifact_text::SEARCH_MAX_LIMIT)?,
                };
                let root = self.options.artifacts.clone();
                self.blocking(move || artifact_text::search(&root, &request))
                    .await?
            }
            _ if path.starts_with("/api/artifacts/") && path.ends_with("/text") => {
                q.only(&["offset", "length", "encoding"], &[])?;
                let id = &path["/api/artifacts/".len()..path.len() - "/text".len()];
                let artifact = self.find_artifact(id).await?;
                let encoding = artifact_text::Encoding::parse(q.one("encoding")?)?;
                let offset = q.number("offset", Some("0"), 64, false)? as usize;
                let default = encoding.page_bytes().to_string();
                let length = q.number("length", Some(&default), 32, true)? as usize;
                let root = self.options.artifacts.clone();
                self.blocking(move || {
                    artifact_text::page(&root, &artifact, offset, length, encoding)
                })
                .await?
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
    fn event_state(&self, document: &mut Value, capture: CaptureView) {
        document["broker_connected"] = json!(capture.source_connected());
        document["capture_mode"] = json!(capture.mode.as_str());
        document["capture_stopped"] = json!(capture.stopped());
        document["capture_state"] = json!(capture.state.as_str());
        document["capture_controls_available"] = json!(self.lifecycle.controls_available());
    }
    /// A filtered or cursor-paged event read. It bypasses the polling cache:
    /// the UI window stays exactly as it was for callers without filters.
    async fn filtered_events(
        &self,
        q: &Query,
        limit: usize,
        headers: &HeaderMap,
    ) -> Result<Response> {
        let filter = event_query::event_filter(q)?;
        let cursor = event_query::cursor(q)?;
        let capture = self.capture_view();
        let may_hold_sites = filter.may_hold_sites();
        // The store's tag digests its whole contents, so it is computed once;
        // what the page's sites depend on is folded into it.
        let base = event_window::etag(
            &self.options.store,
            &format!(
                "query:{}-{}-{limit}:{cursor:?}:{}",
                capture.mode.as_str(),
                capture.state.as_str(),
                filter.echo()
            ),
        );
        let tag = |sources: &str| {
            if sources.is_empty() {
                base.clone()
            } else {
                format!(
                    "\"{}\"",
                    hex::encode(sha2::Sha256::digest(format!("{base}{sources}")))
                )
            }
        };
        let etag = tag(&self.sites_tag(may_hold_sites));
        if matches_etag(headers, Some(&etag)) {
            return Ok(not_modified(&etag));
        }
        let (path, artifacts, requests, sites) = (
            self.options.store.clone(),
            self.options.artifacts.clone(),
            self.requests.clone(),
            self.observation_sites.clone(),
        );
        let newest_first = !matches!(cursor, event_query::Cursor::After(_));
        let mut document = self
            .blocking(move || {
                let mut tally = event_query::Tally::default();
                let page = event_query::read_page(
                    &path,
                    cursor,
                    limit,
                    event_query::SCAN_BYTES,
                    event_query::DAMAGED_LINE_BYTES,
                    event_query::event_visitor(&filter, &mut tally),
                )?;
                let mut document =
                    event_query::events_document(&page, &tally, &filter, cursor, limit);
                observation_sites(
                    &path,
                    &artifacts,
                    &requests,
                    &sites,
                    &mut document,
                    newest_first,
                );
                Ok(document)
            })
            .await?;
        // The tag of the state before the read: whatever landed while the
        // page was read makes the next read's tag differ, so it is never
        // called unchanged. A read that resolved sites costs one more full
        // answer. A page still holding a deferred site gets a tag no later
        // read matches, since reading it again is its recourse.
        let deferred = document["events"].as_array().is_some_and(|events| {
            events.iter().any(|event| {
                event["debugger_observation"]["site"]["resolution"]["status"] == "deferred"
            })
        });
        let etag = if deferred {
            tag(&format!(":deferred-{}", unique_token()))
        } else {
            etag
        };
        self.event_state(&mut document, capture);
        let mut response = axum::Json(document).into_response();
        response
            .headers_mut()
            .insert("etag", HeaderValue::from_str(&etag).unwrap());
        Ok(response)
    }
    /// What a page's sites depend on besides the store, for its tag: the
    /// artifacts retained, the script identities indexed and what was resolved
    /// since. The index's position is read without waiting or refreshing;
    /// while the index is busy the tag is one no client holds, so the page is
    /// read again rather than called unchanged.
    fn sites_tag(&self, may_hold_sites: bool) -> String {
        if !may_hold_sites {
            return String::new();
        }
        // The manifest's identity as well as its length: a replaced manifest
        // of the same length can name other artifacts for the same scripts.
        let manifest = crate::request_stack::manifest_tag(&self.options.artifacts);
        let generation = self
            .observation_sites
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation();
        let index = match self.requests.try_lock() {
            Ok(index) => index
                .position()
                .map_or_else(|| "none".to_owned(), |(epoch, at)| format!("{epoch}-{at}")),
            Err(_) => format!("busy-{}", unique_token()),
        };
        format!(":sites-{manifest}-{index}-{generation}")
    }
    /// Returns as soon as a record after the cursor matches, or when the
    /// timeout passes. Without `after`, only records written after the call
    /// count. No reader permit is held between polls.
    async fn wait_for_events(&self, q: &Query) -> Result<Response> {
        let mut filter = event_query::event_filter(q)?;
        let timeout = event_query::wait_timeout(q)?;
        let limit = q.limit(100, 5000)?;
        let start = match event_query::cursor(q)? {
            event_query::Cursor::Before(_) => {
                return Err(Error::bad("A wait reads forward; pass after, not before"));
            }
            event_query::Cursor::After(offset) => Some(offset),
            event_query::Cursor::Tail => None,
        };
        let waiter = self
            .event_waiters
            .clone()
            .try_acquire_owned()
            .map_err(|_| event_query::waiters_full())?;
        let began = tokio::time::Instant::now();
        let deadline = began + Duration::from_millis(timeout);
        let path = self.options.store.clone();
        let origin = match start {
            Some(offset) => offset,
            None => {
                let path = path.clone();
                self.blocking(move || event_query::current_boundary(&path))
                    .await?
            }
        };
        let mut cursor = origin;
        let mut tally = event_query::Tally::default();
        let mut seen_length = None;
        let mut last = None;
        loop {
            let length = tokio::fs::metadata(&path).await.map(|m| m.len()).ok();
            if length != seen_length {
                seen_length = length;
                let read_path = path.clone();
                let (page, counted, kept) = self
                    .blocking(move || {
                        let page = event_query::read_page(
                            &read_path,
                            event_query::Cursor::After(cursor),
                            limit,
                            event_query::SCAN_BYTES,
                            event_query::DAMAGED_LINE_BYTES,
                            event_query::event_visitor(&filter, &mut tally),
                        )?;
                        Ok((page, tally, filter))
                    })
                    .await?;
                tally = counted;
                filter = kept;
                cursor = page.scan_end;
                if page.exhausted {
                    // Unread bytes remain; read them on the next poll even if
                    // the file length has not changed.
                    seen_length = None;
                }
                let found = !page.records.is_empty();
                last = Some(page);
                if found {
                    break;
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            tokio::time::sleep((deadline - now).min(Duration::from_millis(200))).await;
        }
        let last = last.unwrap_or_else(|| event_query::Page {
            records: Vec::new(),
            scan_start: origin,
            scan_end: origin,
            store_end: seen_length.unwrap_or(0),
            limited: false,
            exhausted: false,
        });
        let timed_out = last.records.is_empty();
        let page = event_query::Page {
            scan_start: origin,
            ..last
        };
        // How long the wait itself took, before any site of what it found is
        // resolved; the waiting slot is free from here on.
        let waited = began.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        drop(waiter);
        let cursor = event_query::Cursor::After(origin);
        let mut document = event_query::events_document(&page, &tally, &filter, cursor, limit);
        if !timed_out {
            let (store, artifacts, requests, sites) = (
                self.options.store.clone(),
                self.options.artifacts.clone(),
                self.requests.clone(),
                self.observation_sites.clone(),
            );
            document = self
                .blocking(move || {
                    observation_sites(&store, &artifacts, &requests, &sites, &mut document, false);
                    Ok(document)
                })
                .await?;
        }
        self.event_state(&mut document, self.capture_view());
        document["wait"] = json!({
            "timed_out": timed_out,
            "timeout_ms": timeout,
            "waited_ms": waited,
        });
        Ok(axum::Json(document).into_response())
    }
    /// Resolves a name or byte offset in one exact retained artifact to one
    /// site, or to a refusal with its candidates. Identity is never inferred
    /// from a URL. Returns the document and the artifact record.
    async fn resolve_invocation_site(
        &self,
        session: &str,
        id: &str,
        target: &js_invocation_sites::Target,
        label: Option<&str>,
    ) -> Result<(Value, Value)> {
        validation::canonical(&json!(session), 64, false, "session_id")?;
        validation::canonical(&json!(id), 64, false, "artifact_id")?;
        let artifact = self.find_artifact(id).await?;
        if artifact["session_id"] != session {
            return Err(Error::new(
                404,
                "Artifact not found in the requested session",
            ));
        }
        if artifact["kind"] != "javascript" {
            return Err(Error::bad("Artifact is not JavaScript"));
        }
        let root = self.options.artifacts.clone();
        let record = artifact.clone();
        let raw = self
            .blocking(move || {
                evidence::content(&root, &record, js_invocation_sites::MAX_SOURCE_BYTES)
            })
            .await?;
        let request = js_invocation_sites::worker_request(&raw, target)?;
        let response = self.deobfuscator.invocation_site(request).await?;
        js_invocation_sites::validate_worker(&raw, target, &response)?;
        let store = self.invocation_sites.clone();
        let saved = tokio::task::spawn_blocking(move || store.load())
            .await
            .map_err(|e| Error::new(500, e.to_string()))??;
        let document =
            js_invocation_sites::resolution(&raw, &artifact, target, &response, label, &saved)?;
        Ok((document, artifact))
    }
    /// The saved set, whether this session retained each saved version, and
    /// what this session's launcher armed.
    async fn invocation_site_set(&self) -> Result<Value> {
        let store = self.invocation_sites.clone();
        let saved = tokio::task::spawn_blocking(move || store.load())
            .await
            .map_err(|e| Error::new(500, e.to_string()))??;
        let root = self.options.artifacts.clone();
        let digests = self.text_digests.clone();
        let listed = saved.clone();
        let retained = self
            .blocking(move || {
                // A store without a manifest has retained nothing yet.
                let artifacts = if root.join("manifest.jsonl").exists() {
                    evidence::artifacts(&root, 5000)?
                } else {
                    Vec::new()
                };
                // At most four same-URL artifacts are read per listing; their
                // digests are cached by content SHA-256, which never changes.
                let mut reads = 0;
                Ok(listed
                    .iter()
                    .map(|saved| {
                        js_invocation_sites::retained(saved, &artifacts, |artifact| {
                            let sha = artifact["sha256"].as_str()?.to_owned();
                            if let Some(known) = digests.lock().ok()?.get(&sha) {
                                return Some(known.clone());
                            }
                            if reads >= 4 {
                                return None;
                            }
                            reads += 1;
                            let raw = evidence::content(
                                &root,
                                artifact,
                                js_invocation_sites::MAX_SOURCE_BYTES,
                            )
                            .ok()?;
                            let digest = js_invocation_sites::text_digest(&raw)?;
                            let mut cache = digests.lock().ok()?;
                            if cache.len() >= 256 {
                                cache.clear();
                            }
                            cache.insert(sha, digest.clone());
                            Some(digest)
                        })
                    })
                    .collect::<Vec<_>>())
            })
            .await?;
        Ok(js_invocation_sites::set_document(
            &saved,
            retained,
            &self.invocation_session,
        ))
    }
    async fn invocation_site_action(&self, value: &Value) -> Result<Value> {
        let store = self.invocation_sites.clone();
        let mut result = match value["action"].as_str() {
            Some("add") => {
                let target = js_invocation_sites::Target::from_fields(
                    value.get("name"),
                    value.get("byte_offset"),
                )?;
                let (document, artifact) = self
                    .resolve_invocation_site(
                        value["session_id"].as_str().unwrap_or_default(),
                        value["artifact_id"].as_str().unwrap_or_default(),
                        &target,
                        value["label"].as_str(),
                    )
                    .await?;
                // A refusal saves nothing; it returns the reason and candidates.
                if document["status"] != "resolved" {
                    json!({"ok": true, "added": false, "resolution": document})
                } else {
                    let saved = js_invocation_sites::saved_from(&document, &artifact)
                        .ok_or_else(|| Error::new(500, "The resolved site could not be saved"))?;
                    self.blocking(move || store.add(saved)).await?;
                    json!({"ok": true, "added": true, "resolution": document})
                }
            }
            Some("remove") => {
                let sha = value["source_sha256"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                let anchor = value["anchor_offset"].as_u64().unwrap_or(u64::MAX);
                let anchor = u32::try_from(anchor)
                    .map_err(|_| Error::bad("anchor_offset must be a UTF-16 offset"))?;
                self.blocking(move || store.remove(&sha, anchor)).await?;
                json!({"ok": true, "removed": true})
            }
            Some("clear") => {
                let cleared = self.blocking(move || store.clear()).await?;
                json!({"ok": true, "cleared": cleared})
            }
            _ => return Err(Error::bad("Invocation site action is invalid")),
        };
        result["set"] = self.invocation_site_set().await?;
        Ok(result)
    }
    async fn find_artifact(&self, id: &str) -> Result<Value> {
        if validation::canonical(&json!(id), 64, false, "Artifact ID").is_err() {
            return Err(Error::new(404, "Artifact not found"));
        }
        let root = self.options.artifacts.clone();
        let id = id.to_owned();
        // Wait for the cache before taking a shared reader permit.
        let cache = self.artifact_lookup.clone().lock_owned().await;
        self.blocking(move || {
            cached_artifact_lookup(cache, &root, &id, |deadline| {
                evidence::find_artifact_until(&root, &id, deadline)
            })
        })
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
                "set_wasm_function_name" => {
                    let store = self.workspace.clone();
                    let value = value.clone();
                    self.blocking(move || crate::wasm_names::set_function_name(&store, &value))
                        .await
                }
                "cancel_local_analyst_script" => {
                    validation::fields(value, &["action", "run_id"], "Analyst cancellation")?;
                    let cancelled = self.analyst.cancel(&value["run_id"])?;
                    Ok(json!({"ok":true,"run_id":value["run_id"],"cancel_requested":cancelled}))
                }
                _ => Err(Error::bad("Analyst workspace action is invalid")),
            },
            "/api/live-wasm/actions" => self.live_wasm.action(value),
            "/api/native-debugger/actions" => {
                // The command blocks on the peer socket, so it does not run
                // on an async worker.
                let pause = self.native_debugger_pause.clone();
                let command = value.clone();
                tokio::task::spawn_blocking(move || {
                    crate::native_debugger::action(&command, &pause)
                })
                .await
                .map_err(|_| Error::new(500, "Native debugger command failed"))?
            }
            "/api/native-console/actions" => self.native_console.action(value).await,
            "/api/js-invocation-sites/actions" => {
                validation::schema("JsInvocationSiteAction", value, 400)?;
                self.invocation_site_action(value).await
            }
            "/api/session/actions" => {
                validation::schema("SessionAction", value, 400)?;
                if self.options.capture_mode() != CaptureMode::Live {
                    return Err(Error::conflict(
                        "This backend is not a live capture session. No browser was changed.",
                    )
                    .with_code(Code::IdleBackend));
                }
                let recording = self.lifecycle.state() == capture::State::Running;
                self.live_browser.action(value, recording).await
            }
            "/api/capture/actions" => {
                validation::schema("CaptureAction", value, 400)?;
                self.capture_action(value).await
            }
            _ => Err(Error::new(404, "Application resource not found")),
        }
    }
    /// Stop and clear change the capture only through `Capture`'s
    /// transitions; `capture` keeps them from interleaving.
    async fn capture_action(&self, value: &Value) -> Result<Value> {
        let mode = self.options.capture_mode();
        if mode != CaptureMode::Live {
            return Err(Error::conflict(format!(
                "{} backend: live capture controls are unavailable",
                if mode == CaptureMode::Demo {
                    "Demo"
                } else {
                    "Idle"
                }
            ))
            .with_code(Code::IdleBackend));
        }
        if !self.lifecycle.controls_available() {
            return Err(Error::conflict("Live capture controls are unavailable"));
        }
        let _guard = self.capture.lock().await;
        if *value == json!({"action":"stop"}) {
            self.stop_capture().await?;
        } else if *value == json!({"action":"clear","confirm":true}) {
            if self.lifecycle.state().broker_running() {
                return Err(Error::conflict(
                    "Stop native capture before clearing events",
                ));
            }
            let paths = vec![
                self.options.store.clone(),
                self.options.trace_store.clone(),
                self.options.signal_store.clone(),
            ];
            let mut index = self.requests.clone().lock_owned().await;
            let (gaps, sites) = (self.gaps.clone(), self.observation_sites.clone());
            self.blocking(move || {
                index.discard()?;
                gaps.reset();
                // Kept observation sites belong to the evidence being cleared.
                sites
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clear();
                evidence::clear_stores(&paths)
            })
            .await?;
        } else {
            return Err(Error::bad("Capture action is invalid"));
        }
        let capture = self.capture_view();
        Ok(
            json!({"ok":true,"capture_stopped":capture.stopped(),"broker_connected":capture.source_connected(),"capture_state":capture.state.as_str()}),
        )
    }
    /// Signals a running broker and waits for it to exit. A timed-out stop
    /// stays requested, and a retry signals again.
    async fn stop_capture(&self) -> Result<()> {
        let unavailable = |message: &str| {
            Error::conflict(format!("{message}: stop was not dispatched"))
                .with_code(Code::DependencyUnavailable)
        };
        match self.lifecycle.request_stop() {
            Ok(_) | Err(StopRefusal::NotRunning(capture::State::Stopped)) => {}
            Err(StopRefusal::NotRunning(capture::State::Lost)) => {
                return Err(unavailable(
                    "The live capture broker exited without shutting down",
                ));
            }
            Err(StopRefusal::NotRunning(_)) => {
                return Err(unavailable("The live capture broker already ended"));
            }
            Err(StopRefusal::UnconfirmedBroker) => {
                return Err(unavailable(
                    "The configured broker PID is not the process this session started with",
                ));
            }
            Err(StopRefusal::Signal(error)) => return Err(error.into()),
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.lifecycle.state().broker_running() {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::new(
                    408,
                    "Native capture did not stop in time. The stop request was delivered; stop again to retry.",
                )
                .with_code(Code::Timeout));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
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
        if path == "/api/debugger" || path.starts_with("/api/debugger/") {
            return Err(Error::new(
                410,
                "CDP functionality was removed; this operation has no native replacement.",
            )
            .with_code(Code::DebuggerUnavailable));
        }
        // A preflight can race a backend restart at the same port. Bind each
        // cooperating client's request to this process before any dispatch.
        // This is a conflict precondition, not authentication or authorization.
        if parts.headers.contains_key("x-reb-expected-instance") {
            let expected = parts.headers.get_all("x-reb-expected-instance");
            if expected.iter().count() != 1
                || expected.iter().next().and_then(|value| value.to_str().ok())
                    != Some(app.instance_id.as_str())
            {
                return Err(Error::new(409, "Backend instance changed. Reconnect and reselect the intended session. No operation was dispatched.")
                    .with_code(Code::StateConflict));
            }
        }
        if parts.method == Method::GET {
            app.get(path, parts.uri.query().unwrap_or(""), &parts.headers)
                .await
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
            let comparison_permit = if matches!(
                path,
                "/api/evidence/packages/compare"
                    | "/api/analysis/vm/packs/apply"
                    | "/api/analysis/vm/packs/compare"
            ) {
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
            // Typed parse with unknown and duplicate keys refused.
            if path == "/api/wasm/runs" {
                return app
                    .wasm_runs
                    .run(&bytes)
                    .await
                    .map(|value| axum::Json(value).into_response());
            }
            // Typed parse of up to 8 MiB of numbers, never a generic JSON tree.
            if path == "/api/graph-layout" {
                return crate::graph_layout::route(bytes.to_vec())
                    .await
                    .map(|bytes| ([("content-type", "application/json")], bytes).into_response());
            }
            if matches!(
                path,
                "/api/vm-debugger/actions"
                    | "/api/analysis/vm/experiments"
                    | "/api/analysis/vm/packs/apply"
                    | "/api/analysis/vm/packs/compare"
            ) {
                let content_type = parts
                    .headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("");
                let mut fields = content_type.split(';').map(str::trim);
                let media = fields.next().unwrap_or("");
                let charset = fields.next();
                if parts.headers.get_all("content-type").iter().count() != 1
                    || !media.eq_ignore_ascii_case("application/json")
                    || fields.next().is_some()
                    || charset.is_some_and(|value| {
                        !value.eq_ignore_ascii_case("charset=utf-8")
                            && !value.eq_ignore_ascii_case("charset=\"utf-8\"")
                    })
                {
                    return Err(Error::new(
                        415,
                        "Owned VM controls require application/json with optional UTF-8 charset",
                    ));
                }
                if matches!(
                    path,
                    "/api/analysis/vm/packs/apply" | "/api/analysis/vm/packs/compare"
                ) {
                    let comparison = path.ends_with("/compare");
                    let bytes = bytes.to_vec();
                    return tokio::task::spawn_blocking(move || {
                        let _permit = comparison_permit;
                        crate::vm_pack::request(&bytes, comparison)
                    })
                    .await
                    .map_err(|_| Error::new(500, "VM pack analysis failed"))?
                    .map(|value| axum::Json(value).into_response());
                }
                if path == "/api/analysis/vm/experiments" {
                    let (_, workspace) = app.vm_documents().await?;
                    return app
                        .vm_experiments
                        .run(&bytes, workspace?)
                        .await
                        .map(|value| axum::Json(value).into_response());
                }
                return app
                    .owned_vm_debugger
                    .action_bytes(&bytes)
                    .await
                    .map(|value| axum::Json(value).into_response());
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
/// A token no earlier tag contains.
fn unique_token() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos())
}

/// Decodes the debugger observations of a filtered or waiting event page and
/// resolves their own frames (protocol/native-debugger-observation-v1.md),
/// newest first on a backward page. A page without one reads nothing more.
fn observation_sites(
    store: &Path,
    artifacts: &Path,
    requests: &Mutex<RequestIndex>,
    sites: &std::sync::Mutex<crate::request_stack::ObservationSites>,
    document: &mut Value,
    newest_first: bool,
) {
    let Some(events) = document["events"].as_array_mut() else {
        return;
    };
    let observed = events.iter().any(|event| {
        event["type"]
            .as_str()
            .is_some_and(|kind| crate::debugger_observation::TYPES.contains(&kind))
    });
    if observed {
        crate::request_stack::ObservationSites::annotate(
            sites,
            store,
            artifacts,
            requests,
            events,
            newest_first,
        );
    }
}

/// `get_native_debugger` filters: one observation type, one native frame
/// named by all three identities, and a backward byte cursor.
fn native_debugger_query(q: &Query) -> Result<crate::debugger_observation::Query> {
    use crate::debugger_observation::{PAGE, Query as Observations, RECENT, TYPES, Thread};
    q.only(
        &[
            "type",
            "session_id",
            "process_id",
            "frame_id",
            "before",
            "limit",
        ],
        &[],
    )?;
    let kind = match q.one("type")? {
        Some(kind) => Some(
            *TYPES
                .iter()
                .find(|known| **known == kind)
                .ok_or_else(|| Error::bad(format!("type must be one of {}", TYPES.join(", "))))?,
        ),
        None => None,
    };
    let thread = match ["session_id", "process_id", "frame_id"].map(|key| q.0.contains_key(key)) {
        [false, false, false] => None,
        [true, true, true] => Some(Thread {
            session: q.number("session_id", None, 64, true)?,
            process: q.number("process_id", None, 32, true)?,
            frame: q.number("frame_id", None, 64, true)?,
        }),
        _ => {
            return Err(Error::bad(
                "A thread scope names session_id, process_id and frame_id together",
            ));
        }
    };
    let before = match q.one("before")? {
        Some(_) => Some(q.number("before", None, 64, false)?),
        None => None,
    };
    Ok(Observations {
        kind,
        thread,
        before,
        limit: q.limit(RECENT, PAGE)?,
    })
}
pub(crate) struct Query(BTreeMap<String, Vec<String>>);
impl Query {
    pub(crate) fn new(raw: &str) -> Self {
        let mut values = BTreeMap::<String, Vec<String>>::new();
        for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            values
                .entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        Self(values)
    }
    pub(crate) fn one(&self, key: &str) -> Result<Option<&str>> {
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
    pub(crate) fn number(
        &self,
        key: &str,
        default: Option<&str>,
        bits: u32,
        nonzero: bool,
    ) -> Result<u64> {
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
    /// Rejects any key outside the listed ones.
    pub(crate) fn only(&self, keys: &[&str], extra: &[&str]) -> Result<()> {
        match self
            .0
            .keys()
            .find(|key| !keys.contains(&key.as_str()) && !extra.contains(&key.as_str()))
        {
            Some(key) => Err(Error::bad(format!(
                "Unknown query parameter {key}. Accepted: {}",
                keys.iter()
                    .chain(extra)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
            None => Ok(()),
        }
    }
    fn any(&self, keys: &[&str]) -> bool {
        keys.iter().any(|key| self.0.contains_key(*key))
    }
    pub(crate) fn limit(&self, default: usize, max: usize) -> Result<usize> {
        self.one("limit")?.map_or(Ok(default), |s| {
            s.parse::<i64>()
                .map(|n| n.clamp(1, max as i64) as usize)
                .map_err(|_| Error::bad("Limit is invalid"))
        })
    }
}
fn analysis_input_signature(path: &Path) -> String {
    // Evidence can be restored or atomically replaced with the same length and
    // mtime. Unix identity includes change time and a content hash so a
    // same-size rewrite still misses the cache when ctime does not advance.
    // The hash is not taken through a symlink. Other platforms recompute
    // analysis rather than relying on a weaker key.
    #[cfg(unix)]
    let identity = evidence::observed_identity(path, false);
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
fn bytes_response(bytes: impl Into<Body>, mime: &'static str) -> Response {
    let mut response = Response::new(bytes.into());
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
pub(crate) fn validate_event(value: &Value) -> Result<()> {
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
    async fn event_cache_waiters_do_not_occupy_shared_reader_permits() {
        let root = tempfile::tempdir().unwrap();
        let mut options = Options::parse_from(["origin-trace-backend"]);
        options.store = root.path().join("events.jsonl");
        options.trace_store = root.path().join("trace.jsonl");
        options.signal_store = root.path().join("signals.jsonl");
        options.artifacts = root.path().join("artifacts");
        options.api_collection = root.path().join("collection.json");
        options.local_analyst = root.path().join("analyst.json");
        options.analyst_runner = Some(std::env::current_exe().unwrap());
        let app = App::new(options, 0).await;
        let held = app.events.lock().await;
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let app = app.clone();
            tasks.push(tokio::spawn(
                async move { app.read_event_window(5000).await },
            ));
        }
        // All polls can wait on the cache while unrelated artifact work retains
        // all four shared blocking-reader slots.
        tokio::task::yield_now().await;
        assert_eq!(app.io.available_permits(), 4);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), app.blocking(|| Ok(7)))
                .await
                .unwrap()
                .unwrap(),
            7
        );
        drop(held);
        for task in tasks {
            assert!(task.await.unwrap().unwrap().events.is_empty());
        }
        app.stop().await;
    }

    #[tokio::test]
    async fn artifact_streaming_fallback_releases_cache_but_retains_reader_permit() {
        let root = tempfile::tempdir().unwrap();
        // A sparse over-byte-cap manifest selects fallback without expensive reads.
        std::fs::File::create(root.path().join("manifest.jsonl"))
            .unwrap()
            .set_len(256 * 1024 * 1024 + 1)
            .unwrap();
        let cache = Arc::new(Mutex::new(ArtifactLookupCache::default()));
        let guard = cache.clone().lock_owned().await;
        let io = Arc::new(Semaphore::new(1));
        let permit = io.clone().acquire_owned().await.unwrap();
        let started = std::time::Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            cached_artifact_lookup(guard, root.path(), "1", |deadline| {
                assert!(
                    cache.try_lock().is_ok(),
                    "streaming cannot hold the cache guard"
                );
                assert_eq!(
                    io.available_permits(),
                    0,
                    "streaming must retain reader admission"
                );
                assert!(deadline >= started + Duration::from_secs(5));
                assert!(deadline <= std::time::Instant::now() + Duration::from_secs(5));
                Ok(json!("streamed"))
            })
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, "streamed");
    }

    #[tokio::test]
    async fn wasm_diff_deadline_counts_from_arrival_not_from_the_reader_permit() {
        // A request that waits for a reader past the deadline gets a partial
        // answer as soon as it runs: the deadline counts from arrival.
        let root = tempfile::tempdir().unwrap();
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(artifacts.join("blobs")).unwrap();
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/fixtures/wasm-module-diff");
        let mut manifest = String::new();
        for (id, name) in [("1", "build-a"), ("2", "build-b")] {
            let bytes = std::fs::read(fixtures.join(format!("{name}.wasm"))).unwrap();
            let hash = hex::encode(sha2::Sha256::digest(&bytes));
            std::fs::write(artifacts.join(format!("blobs/{hash}.bin")), &bytes).unwrap();
            manifest.push_str(&format!(
                "{}\n",
                json!({"protocol_version":1,"artifact_id":id,"session_id":"1","navigation_id":"1",
                    "frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"wasm",
                    "url":format!("fixture://{name}.wasm"),"mime_type":"application/wasm",
                    "byte_size":bytes.len(),"sha256":hash,"sensitive":false,
                    "content_path":format!("blobs/{hash}.bin")})
            ));
        }
        std::fs::write(artifacts.join("manifest.jsonl"), manifest).unwrap();
        let mut options = Options::parse_from(["origin-trace-backend"]);
        options.store = root.path().join("events.jsonl");
        options.trace_store = root.path().join("trace.jsonl");
        options.signal_store = root.path().join("signals.jsonl");
        options.artifacts = artifacts;
        options.api_collection = root.path().join("collection.json");
        options.local_analyst = root.path().join("analyst.json");
        let app = App::new(options, 0).await;
        let held = app.io.clone().acquire_many_owned(4).await.unwrap();
        let request = {
            let app = app.clone();
            tokio::spawn(async move {
                app.wasm_diff_route("artifact_id=1&compare_artifact_id=2")
                    .await
            })
        };
        tokio::time::sleep(wasm_diff::DEADLINE + Duration::from_millis(200)).await;
        drop(held);
        let response = request.await.unwrap().unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "partial", "{}", body["omissions"]);
        assert!(body["omissions"].to_string().contains("deadline"));
        app.stop().await;
    }

    #[tokio::test]
    async fn artifact_cache_waiters_and_cancellation_preserve_reader_admission() {
        let root = tempfile::tempdir().unwrap();
        let mut options = Options::parse_from(["origin-trace-backend"]);
        options.store = root.path().join("events.jsonl");
        options.trace_store = root.path().join("trace.jsonl");
        options.signal_store = root.path().join("signals.jsonl");
        options.artifacts = root.path().join("artifacts");
        options.api_collection = root.path().join("collection.json");
        options.local_analyst = root.path().join("analyst.json");
        options.analyst_runner = Some(std::env::current_exe().unwrap());
        let app = App::new(options, 0).await;
        let held = app.artifact_lookup.lock().await;
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let app = app.clone();
            tasks.push(tokio::spawn(async move { app.find_artifact("1").await }));
        }
        tokio::task::yield_now().await;
        assert_eq!(app.io.available_permits(), 4);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), app.blocking(|| Ok(7)))
                .await
                .unwrap()
                .unwrap(),
            7
        );
        for task in tasks.drain(..4) {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        drop(held);
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap_err().status, 404);
        }
        assert_eq!(app.io.available_permits(), 4);
        assert_eq!(app.find_artifact("1").await.unwrap_err().status, 404);
        app.stop().await;
    }

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
