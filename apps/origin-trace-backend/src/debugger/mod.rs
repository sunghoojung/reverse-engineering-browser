mod automation;
mod body_diff;
mod connection;
mod experiment;
mod fields;
mod heap;
mod hooks;
mod network;
mod objects;
mod parse;
mod repeater;
mod requests;
mod workers;
use crate::{
    config::Options,
    durable,
    error::{Code, Error, Result},
    validation,
};
use connection::{Connection, Event};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore};

pub struct Debugger {
    options: Options,
    transport: PathBuf,
    state: Mutex<Value>,
    connection: AsyncMutex<Option<Arc<Connection>>>,
    preferred: Mutex<Option<String>>,
    pub changed: Notify,
    actions: AsyncMutex<()>,
    refreshing: AsyncMutex<()>,
    stop: Notify,
    network_workers: Arc<Semaphore>,
    watch_id: AtomicU64,
    console_id: AtomicU64,
    heap: heap::Heap,
    memory_id: AtomicU64,
    memory_click: AtomicBool,
    memory_started: Mutex<Option<std::time::Instant>>,
    experiment: experiment::Experiment,
    repeater: repeater::Repeater,
    stopping: AtomicBool,
    objects: objects::Objects,
    automation: automation::Automation,
    workers: workers::Workers,
    hooks: hooks::Hooks,
    fields: fields::Fields,
}
impl Debugger {
    pub fn new(options: &Options) -> Arc<Self> {
        let mut state: Value =
            serde_json::from_str(include_str!("../../assets/debugger-empty.json"))
                .expect("Debugger initial state");
        if options.devtools_active_port.is_some() {
            state["state"] = json!("waiting");
        }
        state["network"]["capture_enabled"] = json!(options.capture_network_content);
        state["network"]["capture_epoch"] = json!(0);
        state["network"]["instance_id"] = json!(format!(
            "{}:{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Arc::new(Self {
            options: options.clone(),
            transport: options.worker(
                &options.debugger_transport,
                "OriginTraceDebuggerTransport",
                "build/reb-debugger-transport",
            ),
            state: Mutex::new(state),
            connection: AsyncMutex::new(None),
            preferred: Mutex::new(None),
            changed: Notify::new(),
            actions: AsyncMutex::new(()),
            refreshing: AsyncMutex::new(()),
            stop: Notify::new(),
            network_workers: Arc::new(Semaphore::new(8)),
            watch_id: AtomicU64::new(1),
            console_id: AtomicU64::new(1),
            heap: heap::Heap::new(),
            memory_id: AtomicU64::new(1),
            memory_click: AtomicBool::new(false),
            memory_started: Mutex::new(None),
            experiment: experiment::Experiment::new(),
            repeater: repeater::Repeater::new(),
            stopping: AtomicBool::new(false),
            objects: objects::Objects::new(),
            automation: automation::Automation::new(),
            workers: workers::Workers::new(),
            hooks: hooks::Hooks::new(),
            fields: fields::Fields::new(),
        })
    }
    pub fn snapshot(&self) -> Value {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn update(&self, edit: impl FnOnce(&mut Value)) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        edit(&mut state);
        let generation = state["generation"].as_u64().unwrap_or(0).saturating_add(1);
        state["generation"] = json!(generation);
        drop(state);
        self.changed.notify_waiters();
    }
    fn set_state(&self, state: &str, error: Option<&str>) {
        self.update(|s| {
            s["state"] = json!(state);
            s["error"] = json!(error.map(|e| validation::truncate(e, 512)));
        });
    }
    pub async fn start(self: &Arc<Self>) {
        self.start_automation();
        self.start_hooks();
        if self.options.devtools_active_port.is_none() {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Some(debugger) = weak.upgrade() {
                if debugger.stopping.load(Ordering::Acquire) {
                    break;
                }
                let result = debugger.refresh().await;
                if result.is_ok() {
                    let _ = debugger.refresh_experiment().await;
                    let _ = debugger.refresh_workers().await;
                }
                if let Err(e) = result {
                    debugger.set_state("waiting", Some(&e.message));
                }
                if debugger.stopping.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! {_=debugger.stop.notified()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>()}
            }
        });
    }
    pub async fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.stop.notify_waiters();
        let _refresh = self.refreshing.lock().await;
        if self.experiment.context().is_some() {
            let _ = self.dispose_experiment().await;
        }
        if let Some(connection) = self.connection.lock().await.take() {
            connection.close().await;
        }
    }
    fn endpoint(&self) -> Result<(u16, String)> {
        let path = self
            .options
            .devtools_active_port
            .as_ref()
            .ok_or_else(|| Error::conflict("Live debugging is not enabled"))?;
        let bytes = durable::read_private(path, 4096)?
            .ok_or_else(|| Error::conflict("Waiting for the authorized browser debugger"))?;
        let body = std::str::from_utf8(&bytes)
            .map_err(|_| Error::conflict("The browser debugger endpoint is malformed"))?;
        let lines = body.lines().collect::<Vec<_>>();
        if lines.len() < 2 || !lines[0].bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::conflict(
                "The browser debugger endpoint is incomplete",
            ));
        }
        let port = lines[0]
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| Error::conflict("The browser debugger port is invalid"))?;
        let url = if lines[1].starts_with('/') {
            format!("ws://127.0.0.1:{port}{}", lines[1])
        } else {
            lines[1].into()
        };
        connection::local_websocket(&url)?;
        Ok((port, url))
    }
    async fn discover(&self) -> Result<Vec<Value>> {
        let (port, _) = self.endpoint()?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| Error::conflict(e.to_string()))?;
        let mut response = client
            .get(format!("http://127.0.0.1:{port}/json/list"))
            .send()
            .await
            .map_err(|e| Error::conflict(e.to_string()))?
            .error_for_status()
            .map_err(|e| Error::conflict(e.to_string()))?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::conflict(e.to_string()))?
        {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(Error::protocol("Browser target list exceeds 2 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let values: Value = serde_json::from_slice(&bytes)?;
        let values = values
            .as_array()
            .filter(|a| a.len() <= 512)
            .ok_or_else(|| Error::protocol("Browser returned a malformed target list"))?;
        let mut targets = Vec::new();
        for v in values {
            if [("id", 4096), ("type", 128), ("webSocketDebuggerUrl", 65536)]
                .iter()
                .any(|(key, max)| {
                    !v[key]
                        .as_str()
                        .is_some_and(|s| !s.is_empty() && s.len() <= *max)
                })
            {
                continue;
            }
            let socket = v["webSocketDebuggerUrl"].as_str().unwrap();
            connection::local_websocket(socket)?;
            let title = v["title"].as_str().unwrap_or("");
            let url = v["url"].as_str().unwrap_or("");
            if title.len() > 65536 || url.len() > 65536 {
                continue;
            }
            targets.push(json!({"id":v["id"],"type":v["type"],"title":title,"url":url,"web_socket_url":socket}));
        }
        Ok(targets)
    }
    async fn refresh(self: &Arc<Self>) -> Result<()> {
        let _refresh = self.refreshing.lock().await;
        if self.stopping.load(Ordering::Acquire) {
            return Err(Error::conflict("Debugger is stopping"));
        }
        let targets = self.discover().await?;
        let public = targets
            .iter()
            .take(128)
            .map(public_target)
            .collect::<Vec<_>>();
        let tabs = targets.iter().filter(|t| t["type"] == "page").count();
        if self.snapshot()["targets"] != json!(public) || self.snapshot()["live_tab_count"] != tabs
        {
            self.update(|s| {
                s["targets"] = json!(public);
                s["live_tab_count"] = json!(tabs);
            });
        }
        let current = self.connection.lock().await.clone();
        let current_target = self.snapshot()["target"]["id"].as_str().map(str::to_owned);
        let preferred = self
            .preferred
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if current.as_ref().is_some_and(|c| !c.is_closed())
            && current_target
                .as_ref()
                .is_some_and(|id| targets.iter().any(|t| t["id"] == *id))
            && preferred
                .as_ref()
                .is_none_or(|id| current_target.as_ref() == Some(id))
        {
            return Ok(());
        }
        if let Some(connection) = self.connection.lock().await.take() {
            connection.close().await;
        }
        let target = preferred
            .as_ref()
            .and_then(|id| targets.iter().find(|t| t["id"] == *id))
            .or_else(|| {
                targets.iter().find(|t| {
                    t["type"] == "page"
                        && !t["url"].as_str().unwrap_or("").starts_with("devtools://")
                })
            })
            .ok_or_else(|| Error::conflict("Waiting for a browser page target"))?;
        self.set_state("connecting", None);
        let (connection, mut events) =
            Connection::open(&self.transport, target["web_socket_url"].as_str().unwrap()).await?;
        self.hooks.candidate_epoch.fetch_add(1, Ordering::AcqRel);
        // A main reconnect does not re-enable already attached worker debuggers.
        // Their cleared descriptors cannot be treated as a complete catalog.
        let retained_workers = self.workers.has_sessions();
        self.update(|s| {
            let incomplete = retained_workers
                || s["scripts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|script| script["target_type"] == "worker");
            s["target"] = public_target(target);
            s["scripts"] = json!([]);
            self.hooks.candidate_sources_reset();
            self.hooks
                .candidate_catalog_incomplete
                .store(incomplete, Ordering::Release);
            s["paused"] = Value::Null;
            s["network"]["capture_epoch"] = json!(
                s["network"]["capture_epoch"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_add(1)
            );
            s["network"]["target_id"] = target["id"].clone();
            s["network"]["requests"] = json!([]);
            s["network"]["dropped"] = json!(0);
        });
        *self.connection.lock().await = Some(connection.clone());
        let weak = Arc::downgrade(self);
        let event_connection = connection.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let Some(debugger) = weak.upgrade() else {
                    break;
                };
                if !debugger
                    .connection
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &event_connection))
                {
                    break;
                }
                match event {
                    Event::Barrier(sender) => {
                        let _ = sender.send(());
                    }
                    Event::Message(Ok(value), _permit) => debugger.event(value).await,
                    Event::Message(Err(e), _permit) => {
                        debugger.set_state("waiting", Some(&e.message));
                        debugger.update(|s| s["paused"] = Value::Null);
                        break;
                    }
                }
            }
        });
        for (method, params) in [
            ("Inspector.enable", json!({})),
            ("Runtime.enable", json!({})),
            ("Page.enable", json!({})),
            ("Debugger.enable", json!({"maxScriptsCacheSize":104857600})),
            ("Debugger.setAsyncCallStackDepth", json!({"maxDepth":32})),
            ("Log.enable", json!({})),
        ] {
            connection
                .command(method, params, Duration::from_secs(3))
                .await?;
        }
        if self.options.capture_network_content {
            connection.command("Network.enable",json!({"maxTotalBufferSize":16777216,"maxResourceBufferSize":2097152,"maxPostDataSize":131072}),Duration::from_secs(3)).await?;
        }
        self.restore().await?;
        if self.snapshot()["paused"].is_null() && self.snapshot()["state"] != "crashed" {
            self.set_state("running", None);
        }
        Ok(())
    }
    async fn command(&self, method: &str, params: Value) -> Result<Value> {
        self.command_for(method, params, Duration::from_secs(3))
            .await
    }
    async fn command_for(&self, method: &str, params: Value, deadline: Duration) -> Result<Value> {
        let connection = self.connection.lock().await.clone().ok_or_else(|| {
            Error::conflict("Debugger target is unavailable").with_code(Code::TargetUnavailable)
        })?;
        connection.command(method, params, deadline).await
    }
    async fn browser_command(&self, method: &str, params: Value) -> Result<Value> {
        let (_, url) = self.endpoint()?;
        let (connection, _events) = Connection::open(&self.transport, &url).await?;
        let result = connection
            .command(method, params, Duration::from_secs(5))
            .await;
        connection.close().await;
        result
    }
    pub async fn source(&self, id: &str) -> Result<Value> {
        validation::text(&json!(id), "Script ID", 4096, false, false)?;
        let script = self.snapshot()["scripts"]
            .as_array()
            .and_then(|a| a.iter().find(|s| s["script_id"] == id))
            .cloned()
            .ok_or_else(|| {
                Error::conflict("Script is unavailable").with_code(Code::TargetUnavailable)
            })?;
        if script["length"].as_u64().unwrap_or(0) > 2097152 {
            return Err(Error::conflict(
                "Live script exceeds the 2 MiB viewer limit",
            ));
        }
        let target = script
            .get("target_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| self.snapshot()["target"]["id"].as_str().map(str::to_owned))
            .ok_or_else(|| {
                Error::conflict("Debugger target is unavailable").with_code(Code::TargetUnavailable)
            })?;
        let session = self.hook_session(&target).await?;
        let result = session
            .command(
                "Debugger.getScriptSource",
                json!({"scriptId":script.get("cdp_script_id").unwrap_or(&json!(id))}),
                Duration::from_secs(5),
            )
            .await?;
        let source = result["scriptSource"]
            .as_str()
            .or_else(|| result["bytecode"].as_str())
            .ok_or_else(|| Error::protocol("Debugger returned malformed script source"))?;
        let bounded = validation::truncate(source, 2097152);
        Ok(
            json!({"protocol_version":1,"script_id":id,"source":bounded,"truncated":bounded.len()!=source.len()}),
        )
    }
    pub async fn action(self: &Arc<Self>, request: &Value) -> Result<Value> {
        validation::schema("DebuggerAction", request, 400)?;
        let action = request["action"]
            .as_str()
            .ok_or_else(|| Error::bad("Debugger action is required"))?;
        let snapshot = self.snapshot();
        if ["armed", "capturing", "stepping", "stopping"].contains(
            &snapshot["memory_origin_trace"]["state"]
                .as_str()
                .unwrap_or(""),
        ) && action != "stop_memory_origin_trace"
        {
            return Err(Error::conflict(
                "Memory Origin Trace controls the debugger until it finishes or is stopped",
            ));
        }
        check_action_owner(action, &snapshot)?;
        let _action = if [
            "stop_memory_origin_trace",
            "disarm_runtime_hooks",
            "cancel_repeater_request",
            "cancel_automation_recipe",
            "disarm_automation_recipes",
        ]
        .contains(&action)
        {
            None
        } else {
            Some(
                self.actions
                    .try_lock()
                    .map_err(|_| Error::conflict("Another debugger action is running"))?,
            )
        };
        match action {
            "pause" | "resume" | "step_over" | "step_into" | "step_out" => {
                let method = match action {
                    "pause" => "Debugger.pause",
                    "resume" => "Debugger.resume",
                    "step_over" => "Debugger.stepOver",
                    "step_into" => "Debugger.stepInto",
                    _ => "Debugger.stepOut",
                };
                self.command(
                    method,
                    if action == "step_into" {
                        json!({"breakOnAsyncCall":true})
                    } else {
                        json!({})
                    },
                )
                .await?;
            }
            "restart_frame" => {
                self.command(
                    "Debugger.restartFrame",
                    json!({"callFrameId":request["call_frame_id"],"mode":"StepInto"}),
                )
                .await?;
            }
            "set_breakpoint" => return self.breakpoint(request).await,
            "remove_breakpoint" => {
                self.command(
                    "Debugger.removeBreakpoint",
                    json!({"breakpointId":request["breakpoint_id"]}),
                )
                .await?;
                self.update(|s| {
                    s["breakpoints"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|b| b["id"] != request["breakpoint_id"])
                });
            }
            "update_breakpoint" => {
                let mut previous = self.snapshot()["breakpoints"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|b| b["id"] == request["breakpoint_id"])
                    .cloned()
                    .ok_or_else(|| Error::conflict("Breakpoint is unavailable"))?;
                previous["kind"] = request["kind"].clone();
                previous["expression"] = request["expression"].clone();
                let result = self.breakpoint(&previous).await?;
                self.command(
                    "Debugger.removeBreakpoint",
                    json!({"breakpointId":request["breakpoint_id"]}),
                )
                .await?;
                self.update(|s| {
                    s["breakpoints"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|b| b["id"] != request["breakpoint_id"])
                });
                return Ok(result);
            }
            "set_breakpoints_active" => {
                self.command(
                    "Debugger.setBreakpointsActive",
                    json!({"active":request["active"]}),
                )
                .await?;
                self.update(|s| s["settings"]["breakpoints_active"] = request["active"].clone());
            }
            "set_pause_on_exceptions" => {
                self.command(
                    "Debugger.setPauseOnExceptions",
                    json!({"state":request["mode"]}),
                )
                .await?;
                self.update(|s| s["settings"]["pause_on_exceptions"] = request["mode"].clone());
            }
            "set_xhr_breakpoint"
            | "remove_xhr_breakpoint"
            | "set_event_breakpoint"
            | "remove_event_breakpoint" => {
                let xhr = action.contains("xhr");
                let adding = action.starts_with("set_");
                let key = if xhr {
                    "xhr_breakpoints"
                } else {
                    "event_breakpoints"
                };
                let field = if xhr { "pattern" } else { "event_name" };
                if adding
                    && self.snapshot()["settings"][key].as_array().unwrap().len()
                        >= if xhr { 100 } else { 256 }
                {
                    return Err(Error::conflict("Debugger breakpoint limit reached")
                        .with_code(Code::ResourceLimit));
                }
                let method = match action {
                    "set_xhr_breakpoint" => "DOMDebugger.setXHRBreakpoint",
                    "remove_xhr_breakpoint" => "DOMDebugger.removeXHRBreakpoint",
                    "set_event_breakpoint" => "DOMDebugger.setEventListenerBreakpoint",
                    _ => "DOMDebugger.removeEventListenerBreakpoint",
                };
                self.command(
                    method,
                    json!({if xhr {"url"} else {"eventName"}:request[field]}),
                )
                .await?;
                self.update(|s| {
                    let values = s["settings"][key].as_array_mut().unwrap();
                    if adding {
                        if !values.contains(&request[field]) {
                            values.push(request[field].clone());
                        }
                    } else {
                        values.retain(|v| *v != request[field]);
                    }
                });
            }
            "add_watch" => {
                if self.snapshot()["watches"].as_array().unwrap().len() >= 100 {
                    return Err(Error::conflict("Watch expression limit reached")
                        .with_code(Code::ResourceLimit));
                }
                self.update(|s| {let id=self.watch_id.fetch_add(1,Ordering::Relaxed);s["watches"].as_array_mut().unwrap().push(json!({"id":id.to_string(),"expression":request["expression"],"result":null,"error":null}));});
            }
            "remove_watch" => self.update(|s| {
                s["watches"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|w| w["id"] != request["watch_id"])
            }),
            "evaluate_watches" => {
                self.watches(request["call_frame_id"].as_str().unwrap())
                    .await?
            }
            "select_target" => {
                let id = request["target_id"].as_str().unwrap();
                if !self.snapshot()["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t["id"] == id)
                {
                    return Err(Error::conflict("Debugger target is unavailable")
                        .with_code(Code::TargetUnavailable));
                }
                self.clear_object_search().await;
                self.heap
                    .baseline
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                self.update(|s| s["heap_diff_baseline"] = Value::Null);
                *self.preferred.lock().unwrap_or_else(|e| e.into_inner()) = Some(id.into());
                if let Some(connection) = self.connection.lock().await.take() {
                    connection.close().await;
                }
            }
            "search_heap_snapshot"
            | "capture_heap_diff_baseline"
            | "compare_heap_diff"
            | "clear_heap_diff_baseline" => return self.heap_action(request).await,
            "start_memory_origin_trace" => return self.start_memory(request).await,
            "stop_memory_origin_trace" => return self.stop_memory().await,
            "clear_memory_origin_trace" => self.update(|s| {
                s["memory_origin_trace"] =
                    serde_json::from_str::<Value>(include_str!("../../assets/debugger-empty.json"))
                        .unwrap()["memory_origin_trace"]
                        .clone()
            }),
            "bind_runtime_candidate" => return self.bind_candidate(request).await,
            "add_runtime_hook" => return self.add_hook(request).await,
            "remove_runtime_hook" => return self.remove_hook(request),
            "arm_runtime_hooks" => return self.arm_hooks(request).await,
            "disarm_runtime_hooks" => return self.disarm_hooks().await,
            "clear_runtime_hook_hits" => return self.clear_hook_hits(),
            "configure_runtime_field_test" => return self.configure_field(request).await,
            "compare_runtime_field_test" => return self.compare_field(request),
            "add_automation_recipe" | "update_automation_recipe" | "remove_automation_recipe" => {
                return self.edit_recipe(request, action);
            }
            "run_automation_recipe" => return self.run_recipe(request).await,
            "arm_automation_recipes" => return self.arm_recipes(request).await,
            "disarm_automation_recipes" => return self.disarm_recipes().await,
            "cancel_automation_recipe" => return self.cancel_recipe().await,
            "clear_automation_runs" => return self.clear_recipe_runs(),
            "search_live_objects" => return self.search_objects(request, false).await,
            "navigate_object_experiment" => return self.navigate_object(request).await,
            "search_object_experiment" => return self.search_objects(request, true).await,
            "mutate_object_experiment" => return self.mutate_object(request).await,
            "create_request_interception_experiment" => return self.create_experiment().await,
            "set_action_scope" => return self.set_scope(request).await,
            "create_experiment_page" => return self.experiment_page(request, false).await,
            "close_experiment_page" => return self.experiment_page(request, true).await,
            "configure_request_interception" => return self.configure_interception(request).await,
            "run_request_interception" => return self.run_interception(request).await,
            "dispose_request_interception_experiment" => return self.dispose_experiment().await,
            "clear_request_interception_result" => {
                self.update(|s| s["request_interception"]["result"] = Value::Null);
                let s = self.snapshot();
                return Ok(
                    json!({"ok":true,"experiment":s["request_interception"],"generation":s["generation"]}),
                );
            }
            "configure_repeater_variables" => return self.repeater_variables(request),
            "run_repeater_request" => return self.run_repeater(request).await,
            "cancel_repeater_request" => return self.cancel_repeater().await,
            "compare_repeater_history" => return self.compare_repeater(request),
            "clear_repeater_history" => return self.clear_repeater(),
            "clear_console" => self.update(|s| s["console"] = json!([])),
            _ => {
                return Err(Error::conflict(format!(
                    "Debugger action {action} is not available in this state"
                )));
            }
        }
        Ok(json!({"ok":true,"generation":self.snapshot()["generation"]}))
    }
    async fn breakpoint(&self, r: &Value) -> Result<Value> {
        let url = r["url"].as_str().unwrap_or("");
        let script = r["script_id"].as_str().unwrap_or("");
        let kind = r["kind"].as_str().unwrap_or(
            if r["condition"].as_str().is_some_and(|s| !s.is_empty()) {
                "conditional"
            } else {
                "line"
            },
        );
        let expression = r["expression"]
            .as_str()
            .or_else(|| r["condition"].as_str())
            .unwrap_or("");
        let line = r["line"]
            .as_u64()
            .ok_or_else(|| Error::bad("Breakpoint line is invalid"))?;
        let column = r["column"].as_u64().unwrap_or(0);
        if url.is_empty() && script.is_empty()
            || kind != "line" && expression.is_empty()
            || self.snapshot()["breakpoints"].as_array().unwrap().len() >= 1000
        {
            return Err(Error::conflict(
                "Breakpoint source, expression, or capacity is invalid",
            ));
        }
        let condition = if kind == "line" {
            "".into()
        } else if kind == "logpoint" {
            format!("console.log({expression}), false")
        } else {
            expression.into()
        };
        if condition.len() > 4096 {
            return Err(Error::bad("Breakpoint condition is oversized"));
        }
        let result = if url.is_empty() {
            self.command("Debugger.setBreakpoint",json!({"location":{"scriptId":script,"lineNumber":line,"columnNumber":column},"condition":condition})).await?
        } else {
            self.command(
                "Debugger.setBreakpointByUrl",
                json!({"url":url,"lineNumber":line,"columnNumber":column,"condition":condition}),
            )
            .await?
        };
        let id = validation::text(&result["breakpointId"], "Breakpoint ID", 4096, false, false)
            .map_err(|e| Error::protocol(e.message))?;
        let locations = if url.is_empty() {
            vec![result["actualLocation"].clone()]
        } else {
            result["locations"]
                .as_array()
                .ok_or_else(|| Error::protocol("Debugger returned malformed breakpoint locations"))?
                .clone()
        };
        let truncated = locations.len() > 256;
        let record = json!({"id":id,"url":url,"script_id":script,"line":line,"column":column,"condition":condition,"kind":kind,"expression":expression,"locations":locations.iter().take(256).filter_map(parse::location).collect::<Vec<_>>(),"locations_truncated":truncated});
        self.update(|s| {
            s["breakpoints"]
                .as_array_mut()
                .unwrap()
                .retain(|b| b["id"] != id);
            s["breakpoints"]
                .as_array_mut()
                .unwrap()
                .push(record.clone());
        });
        Ok(json!({"ok":true,"breakpoint":record,"generation":self.snapshot()["generation"]}))
    }
    async fn restore(&self) -> Result<()> {
        let snapshot = self.snapshot();
        let settings = &snapshot["settings"];
        self.command(
            "Debugger.setBreakpointsActive",
            json!({"active":settings["breakpoints_active"]}),
        )
        .await?;
        self.command(
            "Debugger.setPauseOnExceptions",
            json!({"state":settings["pause_on_exceptions"]}),
        )
        .await?;
        for pattern in settings["xhr_breakpoints"].as_array().unwrap() {
            self.command("DOMDebugger.setXHRBreakpoint", json!({"url":pattern}))
                .await?;
        }
        for name in settings["event_breakpoints"].as_array().unwrap() {
            self.command(
                "DOMDebugger.setEventListenerBreakpoint",
                json!({"eventName":name}),
            )
            .await?;
        }
        self.update(|s| s["breakpoints"] = json!([]));
        for breakpoint in snapshot["breakpoints"].as_array().unwrap() {
            if breakpoint["url"].as_str().is_some_and(|s| !s.is_empty()) {
                self.breakpoint(breakpoint).await?;
            }
        }
        Ok(())
    }
    async fn event(self: &Arc<Self>, message: Value) {
        let method = message["method"].as_str().unwrap_or("");
        let p = &message["params"];
        match method {
            "Debugger.scriptParsed"=>if let Some(script)=parse::script(p) {self.update(|s| {self.hooks.candidate_source_changed(s["target"]["id"].as_str().unwrap_or(""));let scripts=s["scripts"].as_array_mut().unwrap();scripts.retain(|v|v["script_id"]!=script["script_id"]);if scripts.len()>=5000 {self.hooks.candidate_catalog_incomplete.store(true,Ordering::Release);scripts.remove(0);}scripts.push(script);});}else{self.hooks.candidate_catalog_incomplete.store(true,Ordering::Release);self.hooks.candidate_epoch.fetch_add(1,Ordering::AcqRel);},
            "Runtime.executionContextDestroyed"|"Runtime.executionContextsCleared"=>{self.update(|s| {self.hooks.candidate_source_changed(s["target"]["id"].as_str().unwrap_or(""));let clear=method.ends_with("Cleared");s["scripts"].as_array_mut().unwrap().retain(|v|v["target_type"]=="worker" || (!clear && v["execution_context_id"]!=p["executionContextId"]));let ids=s["scripts"].as_array().unwrap().iter().map(|v|v["script_id"].clone()).collect::<Vec<_>>();for b in s["breakpoints"].as_array_mut().unwrap() {b["locations"].as_array_mut().unwrap().retain(|l|ids.contains(&l["script_id"]));}})},
            "Page.frameNavigated"=>{if !p["frame"]["parentId"].is_string() {self.hooks.candidate_epoch.fetch_add(1,Ordering::AcqRel);self.clear_object_search().await;self.hooks_navigated().await;}},
            "Debugger.paused"=>{let target=self.snapshot()["target"]["id"].as_str().unwrap_or("").to_owned();if self.hook_pause(&target,p.clone()) {return;}let pause=parse::pause(p);self.update(|s| {s["state"]=json!("paused");s["error"]=Value::Null;s["paused"]=pause;});let generation=self.snapshot()["generation"].as_u64().unwrap();let weak=Arc::downgrade(self);tokio::spawn(async move {if let Some(debugger)=weak.upgrade() {if debugger.memory_active(debugger.snapshot()["memory_origin_trace"]["trace_id"].as_u64().unwrap()) {debugger.memory_pause(debugger.snapshot()["paused"].clone()).await;} else {debugger.enrich(generation).await;}}});},
            "Debugger.resumed"=>self.update(|s| {if s["state"]!="crashed" {s["state"]=json!("running");s["paused"]=Value::Null;}}),
            "Debugger.breakpointResolved"=>if let Some(location)=parse::location(&p["location"]) {self.update(|s| {if let Some(b)=s["breakpoints"].as_array_mut().unwrap().iter_mut().find(|b|b["id"]==p["breakpointId"]) {let locations=b["locations"].as_array_mut().unwrap();if !locations.contains(&location) {if locations.len()<256 {locations.push(location);} else {b["locations_truncated"]=json!(true);}}}});},
            "Runtime.exceptionThrown" => {let d=&p["exceptionDetails"];let value=if d["exception"].is_object() {d["exception"].clone()} else {json!({"type":"string","value":d["text"].as_str().unwrap_or("Exception")})};self.append_console(&json!({"type":"error","timestamp":p["timestamp"],"args":[value],"stackTrace":d["stackTrace"]}));},
            "Log.entryAdded" => {let e=&p["entry"];self.append_console(&json!({"type":e["level"].as_str().unwrap_or("info"),"timestamp":e["timestamp"],"args":[{"type":"string","value":e["text"].as_str().unwrap_or("")}],"stackTrace":e["stackTrace"]}));},
            "Runtime.consoleAPICalled"=>self.update(|s| {let id=self.console_id.fetch_add(1,Ordering::Relaxed);let console=s["console"].as_array_mut().unwrap();console.push(parse::console(p,id));if console.len()>500 {console.remove(0);}}),
            "Inspector.targetCrashed"=>self.update(|s| {s["state"]=json!("crashed");s["paused"]=Value::Null;s["error"]=json!("Browser renderer crashed. Reload the browser tab to reconnect. Captured evidence is retained.");}),
            "Inspector.targetReloadedAfterCrash"=>self.set_state("running",None),
            "HeapProfiler.addHeapSnapshotChunk"=>self.heap_chunk(p).await,
            _ if method.starts_with("Network.")=>{let target=self.snapshot()["target"]["id"].as_str().unwrap_or("").to_owned();if self.experiment.context().is_some()&&self.snapshot()["runtime_hooks"]["target_id"]==target {self.hook_network(&target,method,p).await;}self.network(method,p).await;},
            _=>(),
        }
    }
    fn append_console(&self, p: &Value) {
        self.update(|s| {
            let id = self.console_id.fetch_add(1, Ordering::Relaxed);
            let entries = s["console"].as_array_mut().unwrap();
            entries.push(parse::console(p, id));
            if entries.len() > 500 {
                entries.remove(0);
            }
        });
    }
    async fn enrich(&self, _generation: u64) {
        let snapshot = self.snapshot();
        let mut pause = snapshot["paused"].clone();
        let original = pause.clone();
        if pause.is_null() {
            return;
        }
        let mut count = 0;
        let mut partial = false;
        for frame in pause["call_frames"].as_array_mut().unwrap() {
            for scope in frame["scopes"].as_array_mut().unwrap() {
                if count >= 2000 {
                    partial = true;
                    continue;
                }
                let Some(id) = scope["object"]["object_id"].as_str() else {
                    continue;
                };
                if let Ok(result) = self
                    .command(
                        "Runtime.getProperties",
                        json!({"objectId":id,"ownProperties":true,"generatePreview":true}),
                    )
                    .await
                {
                    let raw = result["result"].as_array().cloned().unwrap_or_default();
                    let max = 100.min(2000 - count);
                    partial |= raw.len() > max;
                    let properties = raw
                        .iter()
                        .take(max)
                        .filter_map(parse::property)
                        .collect::<Vec<_>>();
                    count += properties.len();
                    scope["properties"] = json!(properties);
                } else {
                    partial = true;
                }
            }
        }
        pause["scope_coverage"] = json!({"status":if partial {"partial"} else {"complete"},"properties":count,"limit":2000});
        self.update(|s| {
            if s["paused"] == original {
                s["paused"] = pause;
            }
        });
        if let Some(id) = original["call_frames"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|f| f["id"].as_str())
        {
            let _ = self.watches(id).await;
        }
    }
    async fn watches(&self, frame: &str) -> Result<()> {
        let snapshot = self.snapshot();
        if !snapshot["paused"]["call_frames"]
            .as_array()
            .is_some_and(|a| a.iter().any(|f| f["id"] == frame))
        {
            return Err(Error::conflict("Call frame is unavailable"));
        }
        for watch in snapshot["watches"].as_array().unwrap() {
            let result=self.command("Debugger.evaluateOnCallFrame",json!({"callFrameId":frame,"expression":watch["expression"],"silent":true,"generatePreview":true,"throwOnSideEffect":true,"timeout":100})).await;
            self.update(|s| {
                if let Some(w) = s["watches"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|w| w["id"] == watch["id"])
                {
                    match result {
                        Ok(value) => {
                            w["result"] = parse::remote(&value["result"]).unwrap_or(Value::Null);
                            w["error"] = value
                                .get("exceptionDetails")
                                .map(|v| {
                                    json!(validation::truncate(
                                        v["text"].as_str().unwrap_or("Evaluation failed"),
                                        512
                                    ))
                                })
                                .unwrap_or(Value::Null);
                        }
                        Err(e) => {
                            w["result"] = Value::Null;
                            w["error"] = json!(e.message);
                        }
                    }
                }
            });
        }
        Ok(())
    }
}
fn public_target(value: &Value) -> Value {
    json!({"id":value["id"],"type":value["type"],"title":value["title"],"url":value["url"]})
}

fn check_action_owner(action: &str, s: &Value) -> Result<()> {
    if s["request_interception"]["state"] == "running" {
        return Err(Error::conflict(
            "The isolated experiment controls the debugger until its request finishes",
        ));
    }
    if !s["repeater"]["active_execution"].is_null() && action != "cancel_repeater_request" {
        return Err(Error::conflict(
            "Repeater controls the isolated target until its request finishes or is cancelled",
        ));
    }
    if ["navigating", "searching", "mutating"]
        .contains(&s["object_experiment"]["state"].as_str().unwrap_or(""))
    {
        return Err(Error::conflict(
            "Object Lab controls the isolated target until its action finishes",
        ));
    }
    if ["arming", "armed", "handling", "stopping"]
        .contains(&s["runtime_hooks"]["state"].as_str().unwrap_or(""))
        && action != "disarm_runtime_hooks"
    {
        return Err(Error::conflict(
            "Runtime Hooks controls the isolated target until it is disarmed",
        ));
    }
    if (!s["automation_recipes"]["active_run"].is_null()
        || ["arming", "running", "stopping"]
            .contains(&s["automation_recipes"]["state"].as_str().unwrap_or("")))
        && !["cancel_automation_recipe", "disarm_automation_recipes"].contains(&action)
    {
        return Err(Error::conflict(
            "Automation Recipes controls the isolated target until its run finishes or is cancelled",
        ));
    }
    if s["automation_recipes"]["auto_armed"] == true
        && ![
            "add_automation_recipe",
            "update_automation_recipe",
            "remove_automation_recipe",
            "arm_automation_recipes",
            "disarm_automation_recipes",
            "run_automation_recipe",
            "cancel_automation_recipe",
            "clear_automation_runs",
            "navigate_object_experiment",
            "dispose_request_interception_experiment",
        ]
        .contains(&action)
    {
        return Err(Error::conflict(
            "Automatic recipes control the isolated target until they are disarmed",
        ));
    }
    Ok(())
}
