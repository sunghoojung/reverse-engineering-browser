//! Passive browser-wide HTTP capture. One transport, immutable flattened-session owners.
use super::{
    Debugger,
    connection::{Connection, Event},
    network_capture::{Owner, next_id},
};
use crate::error::{Error, Result};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) struct BrowserCapture {
    connection: Mutex<Option<Arc<Connection>>>,
    targets: Mutex<BTreeMap<String, Value>>,
    waiting: Mutex<VecDeque<String>>,
    retry: Mutex<Option<Instant>>,
    failures: Mutex<BTreeMap<String, Instant>>,
    pending: Mutex<BTreeMap<String, Instant>>,
}
impl BrowserCapture {
    pub fn new() -> Self {
        Self {
            connection: Mutex::new(None),
            targets: Mutex::new(BTreeMap::new()),
            waiting: Mutex::new(VecDeque::new()),
            retry: Mutex::new(None),
            failures: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
        }
    }
    fn current(&self, c: &Arc<Connection>) -> bool {
        self.connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, c))
    }
}
fn eligible(t: &Value) -> bool {
    matches!(
        t["type"].as_str(),
        Some("page" | "iframe" | "worker" | "shared_worker" | "service_worker")
    ) && !t["url"].as_str().unwrap_or("").starts_with("devtools://")
}
fn target(info: &Value) -> Option<Value> {
    let id = info["targetId"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 4096)?;
    let kind = info["type"].as_str().filter(|s| s.len() <= 128)?;
    let title = info["title"].as_str().unwrap_or("");
    let url = info["url"].as_str().unwrap_or("");
    if title.len() > 65536 || url.len() > 65536 {
        return None;
    }
    Some(json!({"id":id,"type":kind,"title":title,"url":url}))
}
fn auto_attach() -> Value {
    json!({"autoAttach":true,"waitForDebuggerOnStart":false,"flatten":true,"filter":[{"type":"page"},{"type":"iframe"},{"type":"worker"},{"type":"shared_worker"},{"type":"service_worker"},{"exclude":true}]})
}
impl Debugger {
    pub(super) async fn close_browser_capture(&self) {
        let c = self
            .capture
            .browser
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(c) = c {
            c.close().await;
        }
    }
    fn browser_status(&self) {
        if self
            .capture
            .browser
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_none_or(|c| c.is_closed())
        {
            return;
        }
        let targets = self
            .capture
            .browser
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let owners = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ids = owners
            .values()
            .filter(|o| {
                o.session.is_some()
                    && o.ready.load(Ordering::Acquire)
                    && !o.retired.load(Ordering::Acquire)
            })
            .map(|o| o.target["id"].clone())
            .collect::<Vec<_>>();
        let missing=targets.values().filter(|t|eligible(t)&&!ids.contains(&t["id"])).map(|t|json!({"id":t["id"],"title":crate::validation::truncate(t["title"].as_str().unwrap_or(""),128)})).collect::<Vec<_>>();
        let count = targets.values().filter(|t| eligible(t)).count();
        let limit = self.options.capture_target_limit as usize;
        self.update(|s| {
            let v = &mut s["network"]["capture_status"];
            v["scope"] = json!("http-browser-targets");
            v["transport_mode"] = json!("browser-sessions");
            v["startup_mode"] = json!("passive");
            v["message"]=json!("Passive browser target capture starts after attachment and Network.enable; first requests are not guaranteed. WebSockets remain selected-target scoped.");
            v["target_limit"] = json!(limit);
            v["attached_targets"] = json!(ids.len());
            v["eligible_targets"] = json!(count);
            v["attached_target_ids"] = json!(ids);
            v["target_overflow"] = json!(count.saturating_sub(limit));
            v["failed_targets"] = json!(
                self.capture
                    .browser
                    .failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .len()
            );
            v["unattached_targets"] = json!(missing.iter().take(16).collect::<Vec<_>>());
            v["unattached_targets_omitted"] = json!(missing.len().saturating_sub(16));
            v["state"] = json!(if count == 0 {
                "waiting"
            } else if missing.is_empty() {
                "ready"
            } else {
                "partial"
            });
            v["discovery_stale"] = json!(false);
        });
    }
    fn remember_capture_target(&self, info: &Value) {
        let Some(t) = target(info).filter(eligible) else {
            return;
        };
        let id = t["id"].as_str().unwrap().to_owned();
        let mut targets = self
            .capture
            .browser
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !targets.contains_key(&id) && targets.len() >= 512 {
            drop(targets);
            self.update(|s| {
                let v = &mut s["network"]["capture_status"];
                v["gaps"] = json!(v["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                v["last_error"] =
                    json!("Browser target catalog capacity exceeded; some targets are unknown.");
            });
            return;
        }
        if !targets.contains_key(&id) {
            self.capture
                .browser
                .waiting
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_back(id.clone());
        }
        targets.insert(id, t);
    }
    fn queue_capture_target(&self, id: String) {
        let targets = self
            .capture
            .browser
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !targets.contains_key(&id) {
            return;
        }
        let mut waiting = self
            .capture
            .browser
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if waiting.len() < 512 && !waiting.contains(&id) {
            waiting.push_back(id);
        }
    }
    pub(super) async fn refresh_browser_capture(self: &Arc<Self>) -> bool {
        let existing = self
            .capture
            .browser
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(c) = existing.filter(|c| !c.is_closed()) {
            let expired = {
                let mut pending = self
                    .capture
                    .browser
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let expired = pending
                    .iter()
                    .filter(|(_, until)| Instant::now() >= **until)
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                for id in &expired {
                    pending.remove(id);
                }
                expired
            };
            if !expired.is_empty() {
                self.update(|s| {
                    let v = &mut s["network"]["capture_status"];
                    v["gaps"] = json!(
                        v["gaps"]
                            .as_u64()
                            .unwrap_or(0)
                            .saturating_add(expired.len() as u64)
                    );
                    v["last_error"] = json!(
                        "Capture attachment was acknowledged without a session event; retrying."
                    );
                });
            }
            for id in expired {
                self.capture
                    .browser
                    .failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.clone(), Instant::now() + Duration::from_secs(5));
                self.queue_capture_target(id);
            }
            self.promote_capture_target(&c).await;
            return true;
        }
        if self
            .capture
            .browser
            .retry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|until| Instant::now() < until)
        {
            return false;
        }
        match self.open_browser_capture().await {
            Ok(()) => true,
            Err(error) => {
                let current = self
                    .capture
                    .browser
                    .connection
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(c) = current {
                    self.retire_browser_owners(
                        &c,
                        &format!("Browser capture setup failed: {}", error.message),
                    );
                }
                self.close_browser_capture().await;
                *self
                    .capture
                    .browser
                    .retry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) =
                    Some(Instant::now() + Duration::from_secs(30));
                self.update(|s| {
                    let v = &mut s["network"]["capture_status"];
                    v["scope"] = json!("http-page-targets");
                    v["transport_mode"] = json!("page-fallback");
                    v["startup_mode"] = json!("passive");
                    v["target_limit"] = json!(8);
                    v["message"]=json!("Page polling fallback starts after attachment; worker and out-of-process iframe coverage is unavailable. First requests are not guaranteed.");
                    v["last_error"] = json!(crate::validation::truncate(
                        &format!(
                            "Browser capture unavailable; page polling fallback: {}",
                            error.message
                        ),
                        512
                    ));
                });
                false
            }
        }
    }
    async fn open_browser_capture(self: &Arc<Self>) -> Result<()> {
        let (_, url) = self.endpoint()?;
        let (c, mut events) = Connection::open(&self.transport, &url).await?;
        if let Err(error) = c
            .command(
                "Target.setDiscoverTargets",
                json!({"discover":true}),
                Duration::from_secs(3),
            )
            .await
        {
            c.close().await;
            return Err(error);
        }
        let initial = match c
            .command("Target.getTargets", json!({}), Duration::from_secs(3))
            .await
        {
            Ok(v) if v["targetInfos"].as_array().is_some_and(|a| a.len() <= 512) => v,
            _ => {
                c.close().await;
                return Err(Error::conflict(
                    "Browser Target discovery is unsupported or malformed",
                ));
            }
        };
        // Retire legacy fallback connections before enabling multiplexed capture.
        let old = std::mem::take(
            &mut *self
                .capture
                .owners
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for owner in old.into_values() {
            self.retire_capture(
                &owner,
                "Capture transport changed; unfinished evidence has a gap.",
            );
            if let Some(c) = &owner.connection {
                c.close().await;
            }
        }
        self.capture
            .browser
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.capture
            .browser
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.capture
            .browser
            .failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.capture
            .browser
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        for info in initial["targetInfos"].as_array().unwrap() {
            self.remember_capture_target(info);
        }
        *self
            .capture
            .browser
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(c.clone());
        let weak = Arc::downgrade(self);
        let event_connection = c.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let Some(d) = weak.upgrade() else {
                    break;
                };
                if !d.capture.browser.current(&event_connection) {
                    break;
                }
                match event {
                    Event::Barrier(sender) => {
                        let _ = sender.send(());
                    }
                    Event::Message(Ok(m), _permit) => {
                        d.browser_capture_event(&event_connection, m).await
                    }
                    Event::Message(Err(error), _permit) => {
                        d.retire_browser_owners(&event_connection, &error.message);
                        break;
                    }
                }
            }
        });
        c.command(
            "Target.setAutoAttach",
            auto_attach(),
            Duration::from_secs(3),
        )
        .await?;
        self.browser_status();
        Ok(())
    }
    fn retire_browser_owners(&self, c: &Arc<Connection>, reason: &str) {
        if !self.capture.browser.current(c) {
            return;
        }
        let owners = std::mem::take(
            &mut *self
                .capture
                .owners
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for owner in owners.into_values() {
            self.retire_capture(&owner, reason);
        }
        self.update(|s| {
            let status = &mut s["network"]["capture_status"];
            status["gaps"] = json!(status["gaps"].as_u64().unwrap_or(0).saturating_add(1));
            status["last_error"] = json!(crate::validation::truncate(reason, 512));
            s["network"]["capture_status"]["state"] = json!("partial");
            s["network"]["capture_status"]["discovery_stale"] = json!(true);
            s["network"]["capture_status"]["attached_targets"] = json!(0);
            s["network"]["capture_status"]["attached_target_ids"] = json!([]);
        });
    }
    async fn detach_capture_session(
        &self,
        c: &Arc<Connection>,
        session: &str,
        parent: Option<&str>,
    ) {
        if let Err(error) = c
            .command_session(
                "Target.detachFromTarget",
                json!({"sessionId":session}),
                Duration::from_secs(1),
                parent,
            )
            .await
        {
            // An uncertain detach must not leave Network buffers accumulating on
            // repeated retries. Closing this one client releases all its sessions.
            self.retire_browser_owners(c, &format!("Capture detach failed: {}", error.message));
            c.close().await;
        }
    }
    async fn browser_capture_event(self: &Arc<Self>, c: &Arc<Connection>, m: Value) {
        let p = &m["params"];
        match m["method"].as_str().unwrap_or("") {
            "Target.targetCreated" | "Target.targetInfoChanged" => {
                self.remember_capture_target(&p["targetInfo"]);
                self.browser_status();
            }
            "Target.attachedToTarget" => {
                self.remember_capture_target(&p["targetInfo"]);
                let Some(session) = p["sessionId"]
                    .as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 4096)
                else {
                    self.retire_browser_owners(c, "Malformed capture attachment session ID");
                    c.close().await;
                    return;
                };
                let parent = match m.get("sessionId") {
                    None => None,
                    Some(v) if v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 4096) => {
                        v.as_str()
                    }
                    _ => {
                        self.retire_browser_owners(c, "Malformed capture parent session ID");
                        c.close().await;
                        return;
                    }
                };
                let duplicate = self
                    .capture
                    .owners
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .find(|o| o.session.as_deref() == Some(session))
                    .map(|o| o.target["id"] == p["targetInfo"]["targetId"]);
                if let Some(same_target) = duplicate {
                    if !same_target {
                        self.retire_browser_owners(
                            c,
                            "Capture session identity was reused for a different target",
                        );
                        c.close().await;
                    }
                    return;
                }
                let info = target(&p["targetInfo"]).filter(|t| {
                    self.capture
                        .browser
                        .targets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains_key(t["id"].as_str().unwrap())
                });
                let limit = self.options.capture_target_limit as usize;
                let owner = {
                    let mut owners = self
                        .capture
                        .owners
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let mut pending = self
                        .capture
                        .browser
                        .pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if let Some(t) = &info {
                        pending.remove(t["id"].as_str().unwrap());
                    }
                    info.filter(eligible)
                        .filter(|t| {
                            p["waitingForDebugger"] != true
                                && owners.len() + pending.len() < limit
                                && !owners.contains_key(t["id"].as_str().unwrap())
                        })
                        .and_then(|t| {
                            next_id(&self.capture.next_owner).map(|number| {
                                let owner = Arc::new(Owner {
                                    id: number.to_string(),
                                    target: t,
                                    connection: Some(c.clone()),
                                    session: Some(session.to_owned()),
                                    parent_session: parent.map(str::to_owned),
                                    retired: AtomicBool::new(false),
                                    ready: AtomicBool::new(false),
                                });
                                owners.insert(
                                    owner.target["id"].as_str().unwrap().to_owned(),
                                    owner.clone(),
                                );
                                owner
                            })
                        })
                };
                if let Some(owner) = owner {
                    let d = self.clone();
                    let c = c.clone();
                    tokio::spawn(async move {
                        d.initialize_browser_owner(c, owner).await;
                    });
                } else {
                    if let Some(id) = p["targetInfo"]["targetId"].as_str() {
                        self.queue_capture_target(id.to_owned());
                    }
                    if p["waitingForDebugger"] == true {
                        self.update(|s| {
                            let status = &mut s["network"]["capture_status"];
                            status["gaps"] = json!(status["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                            status["last_error"] = json!("Passive capture declined a target waiting for a debugger; startup ownership is unknown, so it was not resumed.");
                        });
                    }
                    // Unknown startup ownership is not permission to resume a paused target.
                    self.detach_capture_session(c, session, parent).await;
                }
                self.browser_status();
            }
            "Target.targetCrashed" | "Inspector.targetCrashed" => {
                let root = self
                    .capture
                    .owners
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .find(|o| {
                        if m["method"] == "Inspector.targetCrashed" {
                            o.session.as_deref() == m["sessionId"].as_str()
                        } else {
                            o.target["id"] == p["targetId"]
                        }
                    })
                    .cloned();
                let Some(root) = root else {
                    return;
                };
                let removed = {
                    let mut owners = self
                        .capture
                        .owners
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let mut sessions =
                        std::collections::BTreeSet::from([root.session.clone().unwrap()]);
                    loop {
                        let before = sessions.len();
                        for o in owners.values() {
                            if o.parent_session
                                .as_ref()
                                .is_some_and(|p| sessions.contains(p))
                                && let Some(sid) = &o.session
                            {
                                sessions.insert(sid.clone());
                            }
                        }
                        if sessions.len() == before {
                            break;
                        }
                    }
                    let keys = owners
                        .iter()
                        .filter(|(_, o)| o.session.as_ref().is_some_and(|s| sessions.contains(s)))
                        .map(|(id, _)| id.clone())
                        .collect::<Vec<_>>();
                    keys.into_iter()
                        .filter_map(|id| owners.remove(&id))
                        .collect::<Vec<_>>()
                };
                for owner in removed {
                    let id = owner.target["id"].as_str().unwrap().to_owned();
                    self.capture
                        .browser
                        .failures
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(id.clone(), Instant::now() + Duration::from_secs(5));
                    self.queue_capture_target(id);
                    self.retire_capture(&owner,"Capture target crashed; unfinished evidence is unavailable and attachment will retry.");
                }
                self.detach_capture_session(
                    c,
                    root.session.as_deref().unwrap(),
                    root.parent_session.as_deref(),
                )
                .await;
                self.browser_status();
            }
            "Target.detachedFromTarget" | "Target.targetDestroyed" => {
                let destroyed = m["method"] == "Target.targetDestroyed";
                let id = p["targetId"].as_str();
                let sid = p["sessionId"].as_str();
                let removed = {
                    let mut owners = self
                        .capture
                        .owners
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let mut sessions = std::collections::BTreeSet::new();
                    if let Some(sid) = sid {
                        sessions.insert(sid.to_owned());
                    }
                    for o in owners.values() {
                        if destroyed
                            && o.target["id"].as_str() == id
                            && let Some(session) = &o.session
                        {
                            sessions.insert(session.clone());
                        }
                    }
                    loop {
                        let old = sessions.len();
                        for o in owners.values() {
                            if o.parent_session
                                .as_ref()
                                .is_some_and(|parent| sessions.contains(parent))
                                && let Some(session) = &o.session
                            {
                                sessions.insert(session.clone());
                            }
                        }
                        if sessions.len() == old {
                            break;
                        }
                    }
                    let keys = owners
                        .iter()
                        .filter(|(_, o)| o.session.as_ref().is_some_and(|s| sessions.contains(s)))
                        .map(|(id, _)| id.clone())
                        .collect::<Vec<_>>();
                    keys.into_iter()
                        .filter_map(|id| owners.remove(&id))
                        .collect::<Vec<_>>()
                };
                let was_owned = !removed.is_empty();
                for owner in removed {
                    self.queue_capture_target(owner.target["id"].as_str().unwrap().to_owned());
                    self.retire_capture(
                        &owner,
                        "Browser target or ancestor detached; unfinished evidence is unavailable.",
                    );
                }
                if destroyed && let Some(id) = id {
                    self.capture
                        .browser
                        .pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(id);
                    self.capture
                        .browser
                        .failures
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(id);
                    self.capture
                        .browser
                        .targets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(id);
                    self.capture
                        .browser
                        .waiting
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|v| v != id);
                }
                if was_owned || destroyed {
                    self.promote_capture_target(c).await;
                }
                self.browser_status();
            }
            method
                if method.starts_with("Network.") && !method.starts_with("Network.webSocket") =>
            {
                let owner = self
                    .capture
                    .owners
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .find(|o| o.session.as_deref() == m["sessionId"].as_str())
                    .cloned();
                if let Some(owner) = owner {
                    self.network_for(&owner, method, p).await;
                }
            }
            _ => {}
        }
    }
    async fn initialize_browser_owner(self: &Arc<Self>, c: Arc<Connection>, owner: Arc<Owner>) {
        let session = owner.session.as_deref();
        let budget = 134217728u64 / u64::from(self.options.capture_target_limit);
        let result=async {
            c.command_session("Network.enable",json!({"maxTotalBufferSize":budget,"maxResourceBufferSize":budget.min(2097152),"maxPostDataSize":131072}),Duration::from_secs(3),session).await?;
            c.command_session("Target.setAutoAttach",auto_attach(),Duration::from_secs(3),session).await?;
            Ok::<_,Error>(())
        }.await;
        if self.stopping.load(Ordering::Acquire)
            || !self.capture.browser.current(&c)
            || owner.retired.load(Ordering::Acquire)
        {
            return;
        }
        match result {
            Ok(()) => {
                self.capture
                    .browser
                    .failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(owner.target["id"].as_str().unwrap());
                owner.ready.store(true, Ordering::Release);
            }
            Err(error) => {
                self.capture
                    .browser
                    .failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        owner.target["id"].as_str().unwrap().to_owned(),
                        Instant::now() + Duration::from_secs(5),
                    );
                self.retire_capture(
                    &owner,
                    &format!(
                        "Browser target capture initialization failed: {}",
                        error.message
                    ),
                );
                {
                    let mut owners = self
                        .capture
                        .owners
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let id = owner.target["id"].as_str().unwrap();
                    if owners
                        .get(id)
                        .is_some_and(|current| Arc::ptr_eq(current, &owner))
                    {
                        owners.remove(id);
                    }
                }
                self.queue_capture_target(owner.target["id"].as_str().unwrap().to_owned());
                self.detach_capture_session(&c, session.unwrap(), owner.parent_session.as_deref())
                    .await;
            }
        }
        self.browser_status();
    }
    async fn promote_capture_target(&self, c: &Arc<Connection>) {
        if !self.capture.browser.current(c) || c.is_closed() {
            return;
        }
        let id = {
            let owners = self
                .capture
                .owners
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut pending = self
                .capture
                .browser
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if owners.len() + pending.len() >= self.options.capture_target_limit as usize {
                return;
            }
            let mut waiting = self
                .capture
                .browser
                .waiting
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let failures = self
                .capture
                .browser
                .failures
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let index = waiting.iter().position(|id| {
                !owners.contains_key(id)
                    && !pending.contains_key(id)
                    && failures
                        .get(id)
                        .is_none_or(|until| Instant::now() >= *until)
            });
            let id = index.and_then(|i| waiting.remove(i));
            if let Some(id) = &id {
                pending.insert(id.clone(), Instant::now() + Duration::from_secs(5));
            }
            id
        };
        if let Some(id) = id {
            let result = c
                .command(
                    "Target.attachToTarget",
                    json!({"targetId":&id,"flatten":true}),
                    Duration::from_secs(2),
                )
                .await;
            if !self.capture.browser.current(c) {
                return;
            }
            if let Err(error) = result {
                self.capture
                    .browser
                    .pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
                self.capture
                    .browser
                    .failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.clone(), Instant::now() + Duration::from_secs(5));
                self.queue_capture_target(id);
                self.update(|s| {
                    s["network"]["capture_status"]["last_error"] =
                        json!(crate::validation::truncate(&error.message, 512))
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn supported_targets_and_metadata_are_bounded() {
        for kind in [
            "page",
            "iframe",
            "worker",
            "shared_worker",
            "service_worker",
        ] {
            let value = target(&json!({"targetId":"owned", "type":kind,"url":"http://localhost/"}))
                .unwrap();
            assert!(eligible(&value));
        }
        assert!(!eligible(&json!({"type":"browser"})));
        assert!(!eligible(
            &json!({"type":"page","url":"devtools://inspect"})
        ));
        assert!(target(&json!({"targetId":"x".repeat(4097),"type":"page"})).is_none());
        assert!(
            target(&json!({"targetId":"owned","type":"page","title":"x".repeat(65537)})).is_none()
        );
    }
    #[test]
    fn target_limit_is_explicit_and_resource_bounded() {
        let defaults = crate::config::Options::try_parse_from(["test"]).unwrap();
        assert_eq!(defaults.capture_target_limit, 32);
        for limit in [1, 8, 32, 128] {
            let options = crate::config::Options::try_parse_from([
                "test",
                "--capture-target-limit",
                &limit.to_string(),
            ])
            .unwrap();
            assert_eq!(options.capture_target_limit, limit);
            assert!((134217728u64 / u64::from(limit)) * u64::from(limit) <= 134217728);
        }
        for invalid in ["0", "129", "-1"] {
            assert!(
                crate::config::Options::try_parse_from(["test", "--capture-target-limit", invalid])
                    .is_err()
            );
        }
        assert_eq!(auto_attach()["waitForDebuggerOnStart"], false);
    }
    #[test]
    fn waiting_catalog_cannot_grow_past_target_bound() {
        let d = Debugger::new(&crate::config::Options::parse_from(["test"]));
        for index in 0..600 {
            d.remember_capture_target(&json!({"targetId":format!("target-{index}"),"type":"page"}));
        }
        for index in 0..600 {
            d.queue_capture_target(format!("target-{index}"));
        }
        assert_eq!(d.capture.browser.targets.lock().unwrap().len(), 512);
        assert_eq!(d.capture.browser.waiting.lock().unwrap().len(), 512);
        assert_eq!(d.snapshot()["network"]["capture_status"]["gaps"], 88);
    }
}
