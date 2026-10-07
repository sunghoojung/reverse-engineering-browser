use super::{
    Debugger,
    connection::{Connection, Event},
    requests,
};
use crate::{
    error::{Code, Error, Result},
    validation,
};
use base64::Engine;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

pub(super) struct Experiment {
    context: Mutex<Option<String>>,
    primary: Mutex<Option<String>>,
    pub pages: AsyncMutex<BTreeMap<String, Arc<Connection>>>,
    rule: Mutex<Value>,
    configured: Mutex<bool>,
    lifecycle: AsyncMutex<()>,
    pending: Arc<Semaphore>,
    sequence: AtomicU64,
    audit: AtomicU64,
}
impl Experiment {
    pub fn new() -> Self {
        Self {
            context: Mutex::new(None),
            primary: Mutex::new(None),
            pages: AsyncMutex::new(BTreeMap::new()),
            rule: Mutex::new(requests::default_rule()),
            configured: Mutex::new(false),
            lifecycle: AsyncMutex::new(()),
            pending: Arc::new(Semaphore::new(16)),
            sequence: AtomicU64::new(1),
            audit: AtomicU64::new(1),
        }
    }
    pub fn context(&self) -> Option<String> {
        self.context
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
impl Debugger {
    pub(super) fn group_response(&self, key: &str) -> Value {
        let s = self.snapshot();
        json!({"ok":true,key:s[key],"generation":s["generation"]})
    }
    fn experiment_response(&self) -> Value {
        let s = self.snapshot();
        json!({"ok":true,"experiment":s["request_interception"],"action_scope":s["action_scope"],"object_experiment":s["object_experiment"],"runtime_hooks":s["runtime_hooks"],"automation_recipes":s["automation_recipes"],"repeater":s["repeater"],"generation":s["generation"]})
    }
    pub(super) fn isolated_target(&self, group: &str, navigated: bool) -> Result<String> {
        let s = self.snapshot();
        let id = s[group]["target_id"].as_str().ok_or_else(|| {
            Error::conflict("The disposable experiment page is unavailable")
                .with_code(Code::TargetUnavailable)
        })?;
        if self.experiment.context().is_none()
            || s[group]["isolated"] != true
            || s["target"]["id"] != id
            || !["running", "paused"].contains(&s["state"].as_str().unwrap_or(""))
        {
            return Err(Error::conflict(
                "This tool requires its attached disposable Experiment page",
            ));
        }
        if s["request_interception"]["pending_requests"]
            .as_u64()
            .unwrap_or(0)
            > 0
        {
            return Err(Error::conflict(
                "Wait for paused Experiment requests to finish",
            ));
        }
        if navigated
            && (s[group]["navigation_id"].as_u64().unwrap_or(0) == 0 || s[group]["url"] == "")
        {
            return Err(Error::conflict(
                "Open an HTTP or HTTPS page in Object Lab before searching",
            ));
        }
        Ok(id.into())
    }
    pub(super) async fn create_experiment(self: &Arc<Self>) -> Result<Value> {
        if self.experiment.context().is_some() {
            return Err(Error::conflict("An isolated experiment already exists"));
        }
        if !["running", "paused"].contains(&self.snapshot()["state"].as_str().unwrap_or("")) {
            return Err(Error::conflict(
                "Attach a browser target before creating an experiment",
            ));
        }
        let id = self.experiment.sequence.fetch_add(1, Ordering::Relaxed);
        self.update(|s| begin_experiment(s, id, validation::now_ms()));
        let context = self
            .browser_command("Target.createBrowserContext", json!({}))
            .await?;
        let context = validation::text(
            &context["browserContextId"],
            "Browser context ID",
            4096,
            false,
            false,
        )
        .map_err(|e| Error::protocol(e.message))?
        .to_owned();
        *self
            .experiment
            .context
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(context.clone());
        let page = self
            .browser_command(
                "Target.createTarget",
                json!({"url":"about:blank","browserContextId":context,"background":true}),
            )
            .await;
        let page = match page {
            Ok(v) => v,
            Err(e) => {
                let deleted = self
                    .browser_command(
                        "Target.disposeBrowserContext",
                        json!({"browserContextId":context}),
                    )
                    .await
                    .is_ok();
                if deleted {
                    *self
                        .experiment
                        .context
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = None;
                }
                self.update(|s| {
                    s["request_interception"]["state"] = json!("error");
                    s["request_interception"]["isolated"] = json!(!deleted);
                    s["request_interception"]["message"] = json!(e.message);
                });
                return Err(e);
            }
        };
        let page = validation::text(
            &page["targetId"],
            "Experiment target ID",
            4096,
            false,
            false,
        )
        .map_err(|e| Error::protocol(e.message))?
        .to_owned();
        *self
            .experiment
            .primary
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(page.clone());
        *self.preferred.lock().unwrap_or_else(|e| e.into_inner()) = Some(page.clone());
        *self
            .experiment
            .rule
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = requests::default_rule();
        *self
            .experiment
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = false;
        self.update(|s| {
            let empty: Value =
                serde_json::from_str(include_str!("../../assets/debugger-empty.json")).unwrap();
            for key in [
                "object_experiment",
                "runtime_hooks",
                "automation_recipes",
                "repeater",
            ] {
                let library = if key == "automation_recipes" {
                    Some((s[key]["recipes"].clone(), s[key]["source_bytes"].clone()))
                } else {
                    None
                };
                s[key] = empty[key].clone();
                s[key]["session_id"] = json!(id);
                s[key]["state"] = json!("ready");
                if key != "repeater" {
                    s[key]["isolated"] = json!(true);
                    s[key]["target_id"] = json!(page);
                }
                if let Some((recipes, bytes)) = library {
                    s[key]["recipes"] = recipes;
                    s[key]["source_bytes"] = bytes;
                }
            }
            s["request_interception"]["state"] = json!("ready");
            s["request_interception"]["isolated"] = json!(true);
            s["request_interception"]["target_id"] = json!(page);
            s["request_interception"]["rule"] = requests::public_rule(&requests::default_rule());
            s["request_interception"]["message"] =
                json!("Disposable Experiment page created. Configure a bounded request rule.");
            s["action_scope"] = empty["action_scope"].clone();
            s["action_scope"]["state"] = json!("discovering");
        });
        self.refresh().await?;
        self.refresh_experiment().await?;
        Ok(self.experiment_response())
    }
    pub(super) async fn refresh_experiment(self: &Arc<Self>) -> Result<()> {
        let _lifecycle = self.experiment.lifecycle.lock().await;
        let Some(context) = self.experiment.context() else {
            return Ok(());
        };
        let result = self.browser_command("Target.getTargets", json!({})).await?;
        let raw = result["targetInfos"]
            .as_array()
            .filter(|a| a.len() <= 512)
            .ok_or_else(|| Error::protocol("Malformed browser context targets"))?;
        let owned = raw
            .iter()
            .filter(|t| t["browserContextId"] == context && t["type"] == "page")
            .collect::<Vec<_>>();
        let overflow = owned.len().saturating_sub(8);
        let targets = owned.into_iter().take(8).cloned().collect::<Vec<_>>();
        let known = self.discover().await?;
        let mode = self.snapshot()["action_scope"]["mode"].clone();
        let selected = self.snapshot()["action_scope"]["target_id"].clone();
        let configured = *self
            .experiment
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let rule = self
            .experiment
            .rule
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut pages = self.experiment.pages.lock().await;
        let obsolete = pages
            .keys()
            .filter(|id| !targets.iter().any(|t| t["targetId"] == **id))
            .cloned()
            .collect::<Vec<_>>();
        for id in obsolete {
            if let Some(c) = pages.remove(&id) {
                c.close().await;
            }
        }
        let mut error = None;
        let mut added = Vec::new();
        for target in &targets {
            let Some(id) = target["targetId"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 4096)
            else {
                continue;
            };
            if pages.get(id).is_some_and(|c| !c.is_closed()) {
                continue;
            }
            if let Some(old) = pages.remove(id) {
                old.close().await;
                self.forget_automation_page(id);
            }
            let Some(endpoint) = known
                .iter()
                .find(|t| t["id"] == id)
                .and_then(|t| t["web_socket_url"].as_str())
            else {
                continue;
            };
            match Connection::open(&self.transport, endpoint).await {
                Ok((c, mut events)) => {
                    let ready=async {c.command("Target.setAutoAttach",json!({"autoAttach":true,"waitForDebuggerOnStart":false,"flatten":true,"filter":[{"type":"worker","exclude":false}]}),Duration::from_secs(3)).await?;c.command("Runtime.enable",json!({}),Duration::from_secs(3)).await?;c.command("Page.enable",json!({}),Duration::from_secs(3)).await?;if configured&&scope_matches(&mode,&selected,id) {c.command("Fetch.enable",json!({"patterns":[{"urlPattern":rule["url_pattern"],"requestStage":"Request"}],"handleAuthRequests":false}),Duration::from_secs(3)).await?;}Ok::<_,Error>(())}.await;
                    if let Err(e) = ready {
                        error = Some(e.message);
                        c.close().await;
                        continue;
                    }
                    pages.insert(id.into(), c.clone());
                    added.push((id.to_owned(), c.clone()));
                    let weak = Arc::downgrade(self);
                    let id = id.to_owned();
                    let captured_context = context.clone();
                    tokio::spawn(async move {
                        while let Some(event) = events.recv().await {
                            match event {
                                Event::Barrier(sender) => {
                                    let _ = sender.send(());
                                }
                                Event::Message(Ok(message), _permit) => {
                                    let Some(debugger) = weak.upgrade() else {
                                        break;
                                    };
                                    if debugger.experiment.context().as_ref()
                                        != Some(&captured_context)
                                    {
                                        break;
                                    }
                                    if message["method"] == "Fetch.requestPaused" {
                                        debugger
                                            .interception_pause(
                                                &id,
                                                c.clone(),
                                                message["params"].clone(),
                                            )
                                            .await;
                                    } else if message["method"] == "Runtime.bindingCalled" {
                                        debugger.automation_binding(
                                            &id,
                                            c.clone(),
                                            &message["params"],
                                        );
                                    } else if message["method"] == "Page.loadEventFired" {
                                        debugger.queue_recipe_trigger(&id, "after-load");
                                    }
                                }
                                Event::Message(Err(_), _permit) => break,
                            }
                        }
                    });
                }
                Err(e) => error = Some(e.message),
            }
        }
        let mut public = Vec::new();
        for t in targets {
            let Some(id) = t["targetId"].as_str() else {
                continue;
            };
            public.push(json!({"id":id,"type":"page","title":validation::truncate(t["title"].as_str().unwrap_or(""),512),"url":if t["url"].as_str().unwrap_or("").starts_with("http") {requests::redacted(t["url"].as_str().unwrap())} else {validation::truncate(t["url"].as_str().unwrap_or(""),8192)},"connected":pages.get(id).is_some_and(|c|!c.is_closed()),"matched":scope_matches(&mode,&selected,id)}));
        }
        drop(pages);
        let matched = public.iter().filter(|t| t["matched"] == true).count();
        let connected = public
            .iter()
            .filter(|t| t["matched"] == true && t["connected"] == true)
            .count();
        let state =
            if error.is_some() || mode == "target" && !public.iter().any(|t| t["id"] == selected) {
                "error"
            } else if public.is_empty() {
                "discovering"
            } else if overflow > 0 || matched != connected {
                "partial"
            } else {
                "ready"
            };
        let message = error.unwrap_or_else(|| match state {
            "error" => {
                "The selected page target is no longer available. Choose a new scope.".into()
            }
            "discovering" => "Discovering bounded page targets in the disposable context.".into(),
            "partial" => format!("{connected} of {matched} matched targets are connected."),
            _ if mode == "global" => {
                format!("Mutable rules apply to all {matched} disposable page targets.")
            }
            _ => "Mutable rules apply only to the selected disposable page target.".into(),
        });
        if self.snapshot()["action_scope"]["targets"] != json!(public)
            || self.snapshot()["action_scope"]["state"] != state
        {
            self.update(|s| {
                let a = &mut s["action_scope"];
                a["targets"] = json!(public);
                a["state"] = json!(state);
                a["matched_target_count"] = json!(matched);
                a["connected_target_count"] = json!(connected);
                a["target_overflow"] = json!(overflow);
                a["message"] = json!(message);
            });
        }
        for (id, c) in added {
            if let Err(e) = self.install_automation_page(&id, c).await {
                self.update(|s| {
                    s["automation_recipes"]["state"] = json!("error");
                    s["automation_recipes"]["last_failure"] = json!(e.message);
                });
            }
            self.queue_recipe_trigger(&id, "created");
        }
        Ok(())
    }
    async fn configure_scope_connections(
        &self,
        mode: &Value,
        selected: &Value,
        rule: &Value,
        configured: bool,
    ) -> Result<()> {
        let pages = self.experiment.pages.lock().await.clone();
        if pages.is_empty() {
            return Err(Error::conflict("No isolated page session is connected")
                .with_code(Code::TargetUnavailable));
        }
        for (id, c) in pages {
            let matched = scope_matches(mode, selected, &id);
            c.command(if matched&&configured {"Fetch.enable"} else {"Fetch.disable"},if matched&&configured {json!({"patterns":[{"urlPattern":rule["url_pattern"],"requestStage":"Request"}],"handleAuthRequests":false})} else {json!({})},Duration::from_secs(3)).await?;
        }
        Ok(())
    }
    fn require_scope_idle(&self) -> Result<()> {
        let s = self.snapshot();
        if self.experiment.context().is_none() {
            return Err(Error::conflict(
                "Create an isolated Experiment context first",
            ));
        }
        if s["request_interception"]["pending_requests"]
            .as_u64()
            .unwrap_or(0)
            > 0
            || s["request_interception"]["state"] == "running"
            || s["automation_recipes"]["auto_armed"] == true
            || !s["automation_recipes"]["active_run"].is_null()
            || !s["repeater"]["active_execution"].is_null()
        {
            return Err(Error::conflict(
                "Finish or disarm active scoped work before changing its targets",
            ));
        }
        Ok(())
    }
    pub(super) async fn set_scope(self: &Arc<Self>, r: &Value) -> Result<Value> {
        let lifecycle = self.experiment.lifecycle.lock().await;
        self.require_scope_idle()?;
        let mode = &r["mode"];
        if ![json!("global"), json!("target")].contains(mode) {
            return Err(Error::bad("Action scope mode is invalid"));
        }
        let selected = if mode == "global" {
            Value::Null
        } else {
            r["target_id"].clone()
        };
        if mode == "target"
            && !self.snapshot()["action_scope"]["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == selected)
        {
            return Err(
                Error::conflict("Action scope requires an owned disposable page")
                    .with_code(Code::TargetUnavailable),
            );
        }
        let old = self.snapshot()["action_scope"].clone();
        let rule = self
            .experiment
            .rule
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let configured = *self
            .experiment
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Err(e) = self
            .configure_scope_connections(mode, &selected, &rule, configured)
            .await
        {
            let rollback = self
                .configure_scope_connections(&old["mode"], &old["target_id"], &rule, configured)
                .await;
            if rollback.is_err() {
                self.update(|s| {
                    s["action_scope"]["state"] = json!("error");
                    s["action_scope"]["message"] = json!(
                        "Scope rollback failed. Dispose the context before running more rules."
                    );
                });
            }
            return Err(e);
        }
        self.update(|s| {
            s["action_scope"]["mode"] = mode.clone();
            s["action_scope"]["target_id"] = selected;
            s["action_scope"]["revision"] =
                json!(s["action_scope"]["revision"].as_u64().unwrap() + 1);
        });
        drop(lifecycle);
        self.refresh_experiment().await?;
        Ok(self.group_response("action_scope"))
    }
    pub(super) async fn experiment_page(self: &Arc<Self>, r: &Value, close: bool) -> Result<Value> {
        self.require_scope_idle()?;
        if close {
            let id = r["target_id"]
                .as_str()
                .ok_or_else(|| Error::bad("Target ID is required"))?;
            if self
                .experiment
                .primary
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_deref()
                == Some(id)
                || !self.snapshot()["action_scope"]["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t["id"] == id)
            {
                return Err(Error::conflict(
                    "Only an additional owned disposable page can be closed",
                ));
            }
            if self
                .browser_command("Target.closeTarget", json!({"targetId":id}))
                .await?["success"]
                != true
            {
                return Err(Error::conflict(
                    "Browser did not confirm that the page closed",
                ));
            }
            self.refresh_experiment().await?;
            return Ok(self.group_response("action_scope"));
        }
        if self.snapshot()["action_scope"]["targets"]
            .as_array()
            .unwrap()
            .len()
            >= 8
        {
            return Err(
                Error::conflict("Disposable page limit reached").with_code(Code::ResourceLimit)
            );
        }
        let address = r
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or("about:blank");
        if address != "about:blank" {
            requests::url(address)?;
        }
        let page=self.browser_command("Target.createTarget",json!({"url":address,"browserContextId":self.experiment.context(),"background":true})).await?;
        self.refresh_experiment().await?;
        let mut response = self.group_response("action_scope");
        response["target_id"] = page["targetId"].clone();
        Ok(response)
    }
    pub(super) async fn configure_interception(&self, r: &Value) -> Result<Value> {
        let _lifecycle = self.experiment.lifecycle.lock().await;
        self.isolated_target("request_interception", false)?;
        let rule = requests::rule(r)?;
        let old = self
            .experiment
            .rule
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let configured = *self
            .experiment
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let scope = self.snapshot()["action_scope"].clone();
        if let Err(e) = self
            .configure_scope_connections(&scope["mode"], &scope["target_id"], &rule, true)
            .await
        {
            if self
                .configure_scope_connections(&scope["mode"], &scope["target_id"], &old, configured)
                .await
                .is_err()
            {
                self.update(|s| {
                    s["request_interception"]["state"] = json!("error");
                    s["request_interception"]["message"] = json!(
                        "Interception rollback failed. Dispose the context before proceeding."
                    );
                });
            }
            return Err(e);
        }
        *self
            .experiment
            .rule
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = rule.clone();
        *self
            .experiment
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        self.update(|s| {
            s["request_interception"]["rule"] = requests::public_rule(&rule);
            s["request_interception"]["state"] = json!("ready");
            s["request_interception"]["result"] = Value::Null;
            s["request_interception"]["message"] =
                json!("Bounded interception rule armed on the selected disposable scope.");
        });
        let s = self.snapshot();
        Ok(json!({"ok":true,"experiment":s["request_interception"],"generation":s["generation"]}))
    }
    pub(super) async fn run_interception(&self, r: &Value) -> Result<Value> {
        self.isolated_target("request_interception", false)?;
        let normalized = requests::request(r)?;
        let scope = self.snapshot()["action_scope"].clone();
        let pages = self.experiment.pages.lock().await.clone();
        let id = r
            .get("target_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                scope["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|t| t["matched"] == true && t["connected"] == true)
                    .and_then(|t| t["id"].as_str().map(str::to_owned))
            })
            .ok_or_else(|| {
                Error::conflict("No matched isolated page is connected")
                    .with_code(Code::TargetUnavailable)
            })?;
        if !scope_matches(&scope["mode"], &scope["target_id"], &id) {
            return Err(Error::conflict(
                "Request target is outside the configured scope",
            ));
        }
        let c = pages
            .get(&id)
            .ok_or_else(|| Error::conflict("Isolated page is disconnected"))?;
        self.update(|s| {s["request_interception"]["state"]=json!("running");s["request_interception"]["result"]=Value::Null;s["request_interception"]["last_request"]=json!({"url":requests::redacted(normalized["url"].as_str().unwrap()),"method":normalized["method"],"header_count":normalized["headers"].as_array().unwrap().len(),"body_bytes":normalized["body"].as_str().unwrap().len(),"target_id":id});});
        let configuration = json!({"url":normalized["url"],"method":normalized["method"],"headers":requests::header_map(&normalized["headers"]),"body":normalized["body"],"timeoutMs":15000,"headerLimit":64,"headerValueLimit":2048,"headerTotalLimit":16384,"responseByteLimit":65536});
        let result=async {let evaluated=c.command("Runtime.evaluate",json!({"expression":format!("({})({configuration})",include_str!("../../assets/request-interception-function.js")),"returnByValue":true,"awaitPromise":true,"silent":true,"userGesture":false,"timeout":15000}),Duration::from_secs(17)).await?;if evaluated["exceptionDetails"].is_object() {return Err(Error::conflict("The isolated request runner failed"));}requests::result(&evaluated["result"]["value"],false)}.await;
        match result {
            Ok(result) => {
                self.update(|s| {
                    s["request_interception"]["state"] = json!("ready");
                    s["request_interception"]["result"] = result.clone();
                    s["request_interception"]["message"] = json!(if result["ok"] == true {
                        format!(
                            "Experiment request completed with status {}.",
                            result["status"]
                        )
                    } else {
                        format!("Experiment request failed: {}", result["error"])
                    });
                });
            }
            Err(e) => {
                self.update(|s| {
                    s["request_interception"]["state"] = json!("error");
                    s["request_interception"]["message"] = json!(e.message);
                });
                return Err(e);
            }
        }
        let s = self.snapshot();
        Ok(json!({"ok":true,"experiment":s["request_interception"],"generation":s["generation"]}))
    }
    pub(super) async fn dispose_experiment(&self) -> Result<Value> {
        let _lifecycle = self.experiment.lifecycle.lock().await;
        let context = self
            .experiment
            .context()
            .ok_or_else(|| Error::conflict("No disposable experiment exists"))?;
        if self.snapshot()["repeater"]["active_execution"].is_object() {
            let _ = self.cancel_repeater().await;
        }
        if self.snapshot()["automation_recipes"]["auto_armed"] == true
            || !self.snapshot()["automation_recipes"]["active_run"].is_null()
        {
            let _ = self.disarm_recipes().await;
        }
        let _ = self.disarm_hooks().await;
        self.close_workers().await;
        self.clear_object_search().await;
        self.browser_command(
            "Target.disposeBrowserContext",
            json!({"browserContextId":context}),
        )
        .await?;
        *self
            .experiment
            .context
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .experiment
            .primary
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self.preferred.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let pages = std::mem::take(&mut *self.experiment.pages.lock().await);
        for (_, c) in pages {
            c.close().await;
        }
        if let Some(c) = self.connection.lock().await.take() {
            c.close().await;
        }
        *self
            .experiment
            .rule
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = requests::default_rule();
        *self
            .experiment
            .configured
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = false;
        self.automation.erase_session();
        self.fields.erase_session();
        let empty: Value = serde_json::from_str(include_str!("../../assets/debugger-empty.json"))
            .expect("Debugger initial state");
        self.update(|s| {
            let experiment=&mut s["request_interception"];
            experiment["state"]=json!("disposed");experiment["isolated"]=json!(false);experiment["target_id"]=Value::Null;
            experiment["disposed_at_ms"]=json!(validation::now_ms());experiment["pending_requests"]=json!(0);
            experiment["message"]=json!("Disposable context deleted. The ephemeral result and audit remain visible.");
            let revision=s["action_scope"]["revision"].as_u64().unwrap().saturating_add(1);
            s["action_scope"]=empty["action_scope"].clone();s["action_scope"]["state"]=json!("disposed");s["action_scope"]["revision"]=json!(revision);
            for (group,message) in [
                ("repeater","Disposable context deleted. Repeater variables, request bodies, responses, and history were cleared."),
                ("object_experiment","Disposable context deleted. Object references, mutation values, previews, and audit records were cleared."),
                ("runtime_hooks","Disposable context deleted. Hook code, captured bindings, return values, and hit records were cleared."),
                ("automation_recipes","Disposable context deleted. Variables, results, logs, and automatic execution state were erased; recipe definitions remain local."),
            ] {
                let session=s[group]["session_id"].clone();
                let recipes=s[group].get("recipes").cloned();let bytes=s[group].get("source_bytes").cloned();
                s[group]=empty[group].clone();s[group]["session_id"]=session;s[group]["state"]=json!("disposed");s[group]["message"]=json!(message);
                if let Some(recipes)=recipes {s[group]["recipes"]=recipes;}
if let Some(bytes)=bytes {s[group]["source_bytes"]=bytes;}
            }
        });
        Ok(self.experiment_response())
    }
    async fn interception_pause(self: &Arc<Self>, id: &str, c: Arc<Connection>, p: Value) {
        let Some(request_id) = p["requestId"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .map(str::to_owned)
        else {
            c.close().await;
            return;
        };
        let permit = self.experiment.pending.clone().try_acquire_owned();
        let weak = Arc::downgrade(self);
        let id = id.to_owned();
        let session = self.snapshot()["request_interception"]["experiment_id"].clone();
        let rule = self
            .experiment
            .rule
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if permit.is_ok() {
            self.update(|s| {
                s["request_interception"]["pending_requests"] =
                    json!(16 - self.experiment.pending.available_permits())
            });
        }
        tokio::spawn(async move {
            let Some(debugger) = weak.upgrade() else {
                return;
            };
            let request = &p["request"];
            let mut params = json!({"requestId":request_id});
            let mut command = "Fetch.continueRequest";
            let mut outcome = "continued";
            let mut detail = "Request continued unchanged.".to_owned();
            let mut guard = None;
            match permit {
                Err(_) => {
                    outcome = "error";
                    detail = "Paused-request limit reached; request continued unchanged.".into();
                }
                Ok(permit) => {
                    guard = Some(permit);
                    let method = request["method"].as_str().unwrap_or("UNKNOWN");
                    if let Some(h) = preflight(request, &rule) {
                        command = "Fetch.fulfillRequest";
                        params["responseCode"] = json!(204);
                        params["responseHeaders"] = h;
                        params["body"] = json!("");
                        outcome = "fulfilled";
                        detail = "Synthetic credential-free CORS preflight returned.".into();
                    } else if rule["method_filter"] != ""
                        && rule["method_filter"] != method.to_ascii_uppercase()
                    {
                        outcome = "bypassed";
                        detail = "Request method did not match the armed rule.".into();
                    } else {
                        match rule["mode"].as_str().unwrap() {
                            "block" | "drop" => {
                                command = "Fetch.failRequest";
                                params["errorReason"] = json!(if rule["mode"] == "block" {
                                    "BlockedByClient"
                                } else {
                                    "Aborted"
                                });
                                outcome = if rule["mode"] == "block" {
                                    "blocked"
                                } else {
                                    "dropped"
                                };
                                detail = format!(
                                    "Request failed with {}.",
                                    params["errorReason"].as_str().unwrap()
                                );
                            }
                            "rewrite" => {
                                for (from, to) in
                                    [("rewrite_url", "url"), ("rewrite_method", "method")]
                                {
                                    if rule[from] != "" {
                                        params[to] = rule[from].clone();
                                    }
                                }
                                if !rule["rewrite_headers"].as_array().unwrap().is_empty() {
                                    params["headers"] = rule["rewrite_headers"].clone();
                                }
                                if rule["rewrite_body"] != "" {
                                    params["postData"] = json!(
                                        base64::engine::general_purpose::STANDARD
                                            .encode(rule["rewrite_body"].as_str().unwrap())
                                    );
                                }
                                outcome = "rewritten";
                                detail = "Bounded request overrides applied.".into();
                            }
                            "fulfill" => {
                                command = "Fetch.fulfillRequest";
                                params["responseCode"] = rule["response_code"].clone();
                                params["responseHeaders"] = rule["response_headers"].clone();
                                params["body"] = json!(
                                    base64::engine::general_purpose::STANDARD
                                        .encode(rule["response_body"].as_str().unwrap())
                                );
                                outcome = "fulfilled";
                                detail = format!(
                                    "Synthetic response {} returned.",
                                    rule["response_code"]
                                );
                            }
                            _ => (),
                        }
                    }
                }
            }
            if let Err(e) = c.command(command, params, Duration::from_secs(3)).await {
                outcome = "error";
                detail = e.message;
                let _ = c
                    .command(
                        "Fetch.continueRequest",
                        json!({"requestId":request_id}),
                        Duration::from_secs(1),
                    )
                    .await;
            }
            drop(guard);
            if debugger.snapshot()["request_interception"]["experiment_id"] != session {
                return;
            }
            debugger.update(|s| {s["request_interception"]["pending_requests"]=json!(if debugger.experiment.context().is_some() {16-debugger.experiment.pending.available_permits()} else {0});let entry=json!({"id":debugger.experiment.audit.fetch_add(1,Ordering::Relaxed),"occurred_at_ms":validation::now_ms(),"request_id":validation::truncate(&request_id,256),"target_id":id,"method":validation::truncate(request["method"].as_str().unwrap_or(""),32),"url":requests::redacted(request["url"].as_str().unwrap_or("")),"resource_type":validation::truncate(p["resourceType"].as_str().unwrap_or("Other"),128),"rule_mode":rule["mode"],"outcome":outcome,"detail":validation::truncate(&detail,512)});let a=s["request_interception"]["audit"].as_array_mut().unwrap();let evicted=a.len()==128;if evicted {a.remove(0);}a.push(entry);if evicted {s["request_interception"]["audit_evictions"]=json!(s["request_interception"]["audit_evictions"].as_u64().unwrap()+1);}});
        });
    }
}
// Disposed Interceptor results remain inspectable until a new lifetime starts.
// Reset the whole group before browser creation, including on creation failure.
fn begin_experiment(state: &mut Value, id: u64, created_at_ms: u64) {
    let empty: Value = serde_json::from_str(include_str!("../../assets/debugger-empty.json"))
        .expect("Debugger initial state");
    state["request_interception"] = empty["request_interception"].clone();
    state["request_interception"]["experiment_id"] = json!(id);
    state["request_interception"]["created_at_ms"] = json!(created_at_ms);
    state["request_interception"]["state"] = json!("creating");
}

fn scope_matches(mode: &Value, selected: &Value, id: &str) -> bool {
    mode == "global" || *selected == id
}
fn preflight(request: &Value, rule: &Value) -> Option<Value> {
    if rule["mode"] != "fulfill" || request["method"] != "OPTIONS" {
        return None;
    }
    let h = request["headers"].as_object()?;
    let lookup = |name: &str| {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.as_str())
    };
    let method = requests::method(lookup("access-control-request-method")?).ok()?;
    if rule["method_filter"] != "" && rule["method_filter"] != method {
        return None;
    }
    let names = lookup("access-control-request-headers").unwrap_or("");
    if names.len() > 2048 {
        return None;
    }
    let entries = if names.trim().is_empty() {
        vec![]
    } else {
        names
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    if entries.len() > 64
        || entries.iter().any(|s| {
            s.is_empty()
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                || [
                    "authorization",
                    "cookie",
                    "proxy-authorization",
                    "set-cookie",
                ]
                .contains(&s.as_str())
        })
    {
        return None;
    }
    let mut out = vec![
        json!({"name":"access-control-allow-origin","value":"*"}),
        json!({"name":"access-control-allow-methods","value":method}),
    ];
    if !names.is_empty() {
        out.push(json!({"name":"access-control-allow-headers","value":entries.join(", ")}));
    }
    Some(json!(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_experiment_erases_prior_interceptor_lifetime() {
        let mut state: Value =
            serde_json::from_str(include_str!("../../assets/debugger-empty.json")).unwrap();
        let empty = state["request_interception"].clone();
        state["request_interception"]["result"] = json!({"body": "authored old result"});
        state["request_interception"]["last_request"] = json!({"url": "https://fixture.invalid/"});
        state["request_interception"]["audit"] = json!([{"detail": "authored old audit"}]);
        state["request_interception"]["audit_evictions"] = json!(4);
        state["request_interception"]["disposed_at_ms"] = json!(99);
        state["request_interception"]["rule"]["mode"] = json!("block");
        let other_groups = state["automation_recipes"].clone();
        begin_experiment(&mut state, 1, 100);
        let mut expected = empty;
        expected["experiment_id"] = json!(1);
        expected["created_at_ms"] = json!(100);
        expected["state"] = json!("creating");
        assert_eq!(state["request_interception"], expected);
        assert_eq!(state["automation_recipes"], other_groups);
    }
}
