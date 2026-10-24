//! Passive browser-wide HTTP capture. One transport, immutable flattened-session owners.
use super::{
    Debugger,
    connection::{Connection, Event},
    network_capture::{Owner, next_id},
};
use crate::error::{Cause, Code, Error};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

// Fixed diagnostic vocabulary. This is the last failed browser setup attempt,
// retained through page fallback and cleared only after successful browser setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum BrowserSetupStage {
    Endpoint,
    TransportOpen,
    DiscoverTargets,
    GetTargets,
    GetTargetsShape,
}
struct BrowserSetupFailure {
    stage: BrowserSetupStage,
    error: Error,
}
impl BrowserSetupFailure {
    fn at(stage: BrowserSetupStage, error: Error) -> Self {
        Self { stage, error }
    }
    fn reason(&self) -> &'static str {
        match self.error.reason.cause() {
            Some(Cause::Timeout) => "timeout",
            Some(Cause::Disconnected) => "disconnected",
            Some(Cause::TransportFailure) => "transport-failure",
            Some(Cause::InvalidReply) => "invalid-reply",
            None => match self.error.reason.code {
                Code::ProtocolError => "protocol-error",
                Code::ApplicationFailed => "command-rejected",
                Code::DependencyUnavailable => "dependency-unavailable",
                Code::ResourceLimit => "resource-limit",
                Code::Timeout => "timeout",
                Code::InvalidRequest => "invalid-request",
                Code::StateConflict => "state-conflict",
                Code::StaleGeneration => "stale-generation",
                Code::TargetUnavailable => "target-unavailable",
                Code::Cancelled => "cancelled",
                Code::CommandOutcomeUnknown => "outcome-unknown",
                Code::Unspecified => "unspecified",
            },
        }
    }
}

type CleanupKey = (usize, String, Option<String>);
struct CleanupJob {
    connection: Arc<Connection>,
    session: String,
    parent: Option<String>,
    target: Option<String>,
    gone: Arc<AtomicBool>,
}
impl CleanupJob {
    fn key(&self) -> CleanupKey {
        (
            Arc::as_ptr(&self.connection) as usize,
            self.session.clone(),
            self.parent.clone(),
        )
    }
}
enum CleanupOutcome {
    AlreadyGone,
    Failed,
}
struct CleanupProof {
    target: Option<String>,
    gone: Arc<AtomicBool>,
}
#[derive(Default)]
struct CleanupQueue {
    waiting: VecDeque<CleanupJob>,
    keys: BTreeMap<CleanupKey, CleanupProof>,
}

// A connection remembers retired IDs without allowing tab/worker churn to grow
// memory forever. At the bound, supplementary list admission fails closed;
// browser Target events continue to drive capture until reconnection.
const MAX_RETIRED_LIST_TARGETS: usize = 4096;

pub(super) struct BrowserCapture {
    connection: Mutex<Option<Arc<Connection>>>,
    targets: Mutex<BTreeMap<String, Value>>,
    waiting: Mutex<VecDeque<String>>,
    retry: Mutex<Option<Instant>>,
    failures: Mutex<BTreeMap<String, Instant>>,
    pending: Mutex<BTreeMap<String, Instant>>,
    destroyed: Mutex<BTreeSet<String>>,
    admission: Arc<tokio::sync::Mutex<()>>,
    admission_epoch: AtomicU64,
    catalog_incomplete: AtomicBool,
    catalog_epoch: AtomicU64,
    catalog_retry: Mutex<Instant>,
    cleanup: Arc<tokio::sync::Semaphore>,
    cleanup_queue: Mutex<CleanupQueue>,
    cleanup_closing: AtomicBool,
    // Document loaders and URLs observed after Network.enable. A committed
    // main frame that is absent here raced attachment and is not replayed.
    seen_documents: Mutex<SeenDocuments>,
    document_navigation_gaps: AtomicU64,
}
struct SeenDocuments {
    loaders: BTreeSet<(String, String)>,
    urls: BTreeSet<(String, String)>,
    charged: BTreeSet<(String, String)>,
}
impl SeenDocuments {
    const MAX: usize = 4096;
    fn insert(set: &mut BTreeSet<(String, String)>, key: (String, String)) -> bool {
        if set.contains(&key) {
            return true;
        }
        if set.len() >= Self::MAX {
            return false;
        }
        set.insert(key);
        true
    }
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
            destroyed: Mutex::new(BTreeSet::new()),
            admission: Arc::new(tokio::sync::Mutex::new(())),
            admission_epoch: AtomicU64::new(0),
            catalog_incomplete: AtomicBool::new(false),
            catalog_epoch: AtomicU64::new(0),
            catalog_retry: Mutex::new(Instant::now()),
            cleanup: Arc::new(tokio::sync::Semaphore::new(4)),
            cleanup_queue: Mutex::new(CleanupQueue::default()),
            cleanup_closing: AtomicBool::new(false),
            seen_documents: Mutex::new(SeenDocuments {
                loaders: BTreeSet::new(),
                urls: BTreeSet::new(),
                charged: BTreeSet::new(),
            }),
            document_navigation_gaps: AtomicU64::new(0),
        }
    }
    pub(super) fn current(&self, c: &Arc<Connection>) -> bool {
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
fn fill_empty_target_titles(state: &mut Value, target_id: &str, title: &str) {
    if target_id.is_empty() || title.is_empty() {
        return;
    }
    let Some(rows) = state["network"]["requests"].as_array_mut() else {
        return;
    };
    for row in rows {
        if row["target_id"].as_str() == Some(target_id)
            && row["target_title"].as_str().unwrap_or("").is_empty()
        {
            row["target_title"] = json!(title);
        }
    }
}
fn auto_attach() -> Value {
    json!({"autoAttach":true,"waitForDebuggerOnStart":false,"flatten":true,"filter":[{"type":"page"},{"type":"iframe"},{"type":"worker"},{"type":"shared_worker"},{"type":"service_worker"},{"exclude":true}]})
}
fn http_document_url(url: &str) -> bool {
    (url.starts_with("https://") || url.starts_with("http://")) && url.len() <= 65536
}
/// Network.enable does not replay a navigation that already committed.
/// Passive capture reads `Target.getTargetInfo` rather than `Page.getFrameTree`:
/// a Page command would leave the observational session. A loader id, when the
/// snapshot has one, is the navigation identity. Otherwise the committed
/// http(s) URL is the proof, and a seen Document request for that URL is not
/// a miss.
pub(super) fn unobserved_committed_document(
    snapshot: &Value,
    seen_loaders: &BTreeSet<String>,
    seen_urls: &BTreeSet<String>,
) -> Option<String> {
    let frame = snapshot
        .get("frameTree")
        .and_then(|tree| tree.get("frame"))
        .or_else(|| snapshot.get("targetInfo"))?;
    let url = frame.get("url")?.as_str()?;
    if !http_document_url(url) {
        return None;
    }
    match frame.get("loaderId").and_then(Value::as_str) {
        Some(loader) if !loader.is_empty() && loader.len() <= 4096 => {
            if seen_loaders.contains(loader) {
                None
            } else {
                Some(loader.to_owned())
            }
        }
        _ => {
            if seen_urls.contains(url) {
                None
            } else {
                Some(format!("url:{url}"))
            }
        }
    }
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
    pub(super) fn note_debugger_event_drops(&self, dropped: u64) {
        if dropped == 0 {
            return;
        }
        self.update(|state| {
            let status = &mut state["network"]["capture_status"];
            let total = status["event_queue_drops"]
                .as_u64()
                .unwrap_or(0)
                .saturating_add(dropped);
            status["event_queue_drops"] = json!(total);
            if status["state"] == "ready" || status["state"] == "waiting" {
                status["state"] = json!("partial");
            }
            status["last_error"] = json!(crate::validation::truncate(
                &format!(
                    "Debugger event queue dropped {dropped} events; the browser connection stayed open."
                ),
                512
            ));
        });
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
        let list_limited = self.list_discovery_limited();
        let document_gaps = self
            .capture
            .browser
            .document_navigation_gaps
            .load(Ordering::Acquire);
        self.update(|s| {
            let v = &mut s["network"]["capture_status"];
            v["scope"] = json!("http-browser-targets");
            v["transport_mode"] = json!("browser-sessions");
            v["startup_mode"] = json!("passive");
            v["message"]=json!("Passive browser target capture starts after attachment and Network.enable. A full URL from before that enable is not guaranteed; an unmatched native row stays in Traffic as host-only metadata. WebSockets remain selected-target scoped.");
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
            let incomplete = self.capture.browser.catalog_incomplete.load(Ordering::Acquire) || list_limited;
            if list_limited {
                v["message"] = json!("Passive browser target events remain enabled. List-only discovery is disabled because retired target history reached its bound; capture reconnection resets it. Requests before Network.enable remain unavailable.");
            }
            v["catalog_incomplete"] = json!(incomplete);
            v["document_navigation_gaps"] = json!(document_gaps);
            let event_drops = v["event_queue_drops"].as_u64().unwrap_or(0) > 0;
            // A committed document that raced Network.enable is coverage loss
            // even when every known target is attached. ready/gaps:0 hid it.
            v["state"] = json!(
                if event_drops {
                    "partial"
                } else if incomplete || document_gaps > 0 {
                    if count == 0 && !incomplete { "waiting" } else { "partial" }
                } else if count == 0 {
                    "waiting"
                } else if missing.is_empty() {
                    "ready"
                } else {
                    "partial"
                }
            );
            v["discovery_stale"] = json!(false);
        });
    }
    pub(crate) fn catalog_target_title(&self, id: &str) -> Option<Value> {
        if id.is_empty() {
            return None;
        }
        self.capture
            .browser
            .targets
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(id)
            .and_then(|recorded| recorded.get("title"))
            .filter(|title| title.as_str().is_some_and(|text| !text.is_empty()))
            .cloned()
    }
    fn fill_captured_request_titles(&self, info: &Value) {
        let Some(recorded) = target(info) else {
            return;
        };
        let Some(id) = recorded["id"].as_str() else {
            return;
        };
        let Some(title) = recorded["title"].as_str().filter(|text| !text.is_empty()) else {
            return;
        };
        let id = id.to_owned();
        let title = title.to_owned();
        self.update(|state| fill_empty_target_titles(state, &id, &title));
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
        self.remember_capture_target_locked(&mut targets, id, t);
    }
    fn remember_capture_target_locked(
        &self,
        targets: &mut BTreeMap<String, Value>,
        id: String,
        t: Value,
    ) -> bool {
        self.capture
            .browser
            .catalog_epoch
            .fetch_add(1, Ordering::AcqRel);
        if !targets.contains_key(&id)
            && targets.len() >= 512
            && !self.make_catalog_room_for_page(targets, &t)
        {
            self.mark_capture_catalog_incomplete();
            return false;
        }
        let fresh = !targets.contains_key(&id);
        targets.insert(id.clone(), t);
        if fresh {
            let mut waiting = self
                .capture
                .browser
                .waiting
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            Self::admit_waiting_target(&mut waiting, targets, id);
        }
        true
    }
    // A full catalog used to reject the page under test while workers occupied
    // every slot. Only a waiting non-page that is not an owner can move aside.
    fn make_catalog_room_for_page(
        &self,
        targets: &mut BTreeMap<String, Value>,
        incoming: &Value,
    ) -> bool {
        if incoming["type"] != "page" {
            return false;
        }
        let owners = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let pending = self
            .capture
            .browser
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut waiting = self
            .capture
            .browser
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let displace = waiting
            .iter()
            .rev()
            .find(|queued| {
                targets
                    .get(queued.as_str())
                    .is_some_and(|record| record["type"] != "page")
                    && !owners.contains_key(queued.as_str())
                    && !pending.contains_key(queued.as_str())
            })
            .cloned();
        let Some(displace) = displace else {
            return false;
        };
        waiting.retain(|queued| queued != &displace);
        drop(waiting);
        drop(pending);
        drop(owners);
        targets.remove(&displace);
        self.mark_capture_catalog_incomplete();
        true
    }
    fn admit_waiting_target(
        waiting: &mut VecDeque<String>,
        targets: &BTreeMap<String, Value>,
        id: String,
    ) {
        if waiting.iter().any(|queued| queued == &id) {
            return;
        }
        let page = targets
            .get(&id)
            .is_some_and(|target| target["type"] == "page");
        if waiting.len() >= 512 {
            if !page {
                return;
            }
            let Some(evict) = waiting.iter().rposition(|queued| {
                targets
                    .get(queued)
                    .is_none_or(|target| target["type"] != "page")
            }) else {
                return;
            };
            waiting.remove(evict);
        }
        if page {
            let at = waiting
                .iter()
                .position(|queued| {
                    targets
                        .get(queued)
                        .is_none_or(|target| target["type"] != "page")
                })
                .unwrap_or(waiting.len());
            waiting.insert(at, id);
        } else {
            waiting.push_back(id);
        }
    }
    fn mark_capture_catalog_incomplete(&self) {
        self.capture
            .browser
            .catalog_epoch
            .fetch_add(1, Ordering::AcqRel);
        if !self
            .capture
            .browser
            .catalog_incomplete
            .swap(true, Ordering::AcqRel)
        {
            self.update(|s| {
                let status = &mut s["network"]["capture_status"];
                status["gaps"] = json!(status["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                status["last_error"] = json!("Browser target catalog capacity exceeded; counts exclude unknown targets until reconciliation.");
            });
        }
    }
    async fn reconcile_capture_catalog(&self, c: &Arc<Connection>) {
        if !self
            .capture
            .browser
            .catalog_incomplete
            .load(Ordering::Acquire)
        {
            return;
        }
        {
            let mut retry = self
                .capture
                .browser
                .catalog_retry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if Instant::now() < *retry {
                return;
            }
            *retry = Instant::now() + Duration::from_secs(5);
        }
        let epoch = self.capture.browser.catalog_epoch.load(Ordering::Acquire);
        let result = c
            .command("Target.getTargets", json!({}), Duration::from_secs(2))
            .await;
        if c.is_closed() || !self.capture.browser.current(c) {
            return;
        }
        if let Ok(value) = result
            && let Some(infos) = value["targetInfos"].as_array()
        {
            let mut targets = self
                .capture
                .browser
                .targets
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Events processed while the snapshot was in flight take precedence.
            // Apply atomically with catalog events so a destroyed target cannot
            // be resurrected by an older snapshot.
            if !c.is_closed()
                && self.capture.browser.current(c)
                && self.capture.browser.catalog_epoch.load(Ordering::Acquire) == epoch
            {
                let mut complete = infos.len() <= 4096;
                for info in infos.iter().take(4096) {
                    if let Some(t) = target(info).filter(eligible) {
                        let id = t["id"].as_str().unwrap().to_owned();
                        complete &= self.remember_capture_target_locked(&mut targets, id, t);
                    }
                }
                if !complete {
                    self.mark_capture_catalog_incomplete();
                } else {
                    self.capture
                        .browser
                        .catalog_incomplete
                        .store(false, Ordering::Release);
                }
            }
        }
        self.browser_status();
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
        Self::admit_waiting_target(&mut waiting, &targets, id);
    }
    pub(super) fn capture_list_snapshot(&self) -> Option<(Arc<Connection>, u64)> {
        let connection = self
            .capture
            .browser
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .filter(|connection| !connection.is_closed())?;
        Some((
            connection,
            self.capture.browser.catalog_epoch.load(Ordering::Acquire),
        ))
    }
    fn list_discovery_limited(&self) -> bool {
        self.capture
            .browser
            .destroyed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
            >= MAX_RETIRED_LIST_TARGETS
    }
    // Called with the catalog lock held, as is list admission. The retained set
    // is never evicted into accepting an old list identity again.
    fn remember_destroyed_list_target(&self, id: &str) {
        if id.is_empty() || id.len() > 4096 {
            return;
        }
        let mut destroyed = self
            .capture
            .browser
            .destroyed
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if destroyed.len() >= MAX_RETIRED_LIST_TARGETS {
            return;
        }
        destroyed.insert(id.to_owned());
        if destroyed.len() == MAX_RETIRED_LIST_TARGETS {
            self.update(|state| {
                let status = &mut state["network"]["capture_status"];
                status["gaps"] = json!(status["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                status["last_error"] = json!("Retired target history reached its bound; list-only discovery is disabled until capture reconnects. Browser target events still capture new pages.");
            });
        }
    }
    /// Supplement browser Target events with a bounded http(s) list snapshot.
    /// Connection and epoch are captured BEFORE the HTTP request. Validation and
    /// insertion share the catalog lock with destruction, so neither a delayed
    /// reply nor a concurrent destroy can resurrect a target. No startup holds,
    /// browser-root auto-attach, or target resumption are requested.
    pub(super) fn admit_discovered_http_pages(
        self: &Arc<Self>,
        discovered: &[Value],
        connection: &Arc<Connection>,
        epoch: u64,
    ) {
        let admitted = {
            let mut targets = self
                .capture
                .browser
                .targets
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if connection.is_closed()
                || !self.capture.browser.current(connection)
                || self.capture.browser.catalog_epoch.load(Ordering::Acquire) != epoch
            {
                return;
            }
            let destroyed = self
                .capture
                .browser
                .destroyed
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if destroyed.len() >= MAX_RETIRED_LIST_TARGETS {
                return;
            }
            let mut admitted = false;
            for page in discovered.iter().take(512) {
                if page["type"] != "page" {
                    continue;
                }
                let Some(url) = page["url"].as_str() else {
                    continue;
                };
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    continue;
                }
                let Some(id) = page["id"]
                    .as_str()
                    .filter(|id| !id.is_empty() && id.len() <= 4096)
                else {
                    continue;
                };
                if targets.contains_key(id) || destroyed.contains(id) {
                    continue;
                }
                let Some(record) = target(&json!({"targetId": id, "type": "page",
                    "title": page["title"].as_str().unwrap_or(""), "url": url}))
                else {
                    continue;
                };
                // Use this insertion's outcome, not queue length: the independent
                // admission pump may drain other entries concurrently.
                admitted |=
                    self.remember_capture_target_locked(&mut targets, id.to_owned(), record);
            }
            admitted
        };
        if admitted {
            self.schedule_capture_admission(connection);
            self.browser_status();
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
            self.reconcile_capture_catalog(&c).await;
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
            for id in expired {
                if self.record_capture_admission_failure(
                    &c,
                    &id,
                    "Capture attachment was acknowledged without a session event; retrying.",
                ) {
                    self.update(|s| {
                        let v = &mut s["network"]["capture_status"];
                        v["gaps"] = json!(v["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                    });
                }
            }
            self.schedule_capture_admission(&c);
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
            Ok(ready) => ready,
            Err(failure) => {
                let stage = failure.stage;
                let reason = failure.reason();
                let error = failure.error;
                self.update(|s| {
                    s["network"]["capture_status"]["browser_setup_failure"] =
                        json!({"stage":stage,"reason":reason});
                });
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
    async fn open_browser_capture(
        self: &Arc<Self>,
    ) -> std::result::Result<bool, BrowserSetupFailure> {
        let Some((_, url)) = self
            .endpoint_if_published()
            .map_err(|e| BrowserSetupFailure::at(BrowserSetupStage::Endpoint, e))?
        else {
            // The regular refresh loop will retry after publication. Do not
            // impose the capability-failure backoff or report page fallback.
            return Ok(false);
        };
        let (c, mut events) = Connection::open(&self.transport, &url)
            .await
            .map_err(|e| BrowserSetupFailure::at(BrowserSetupStage::TransportOpen, e))?;
        if let Err(error) = c
            .command(
                "Target.setDiscoverTargets",
                json!({"discover":true}),
                Duration::from_secs(3),
            )
            .await
        {
            c.close().await;
            return Err(BrowserSetupFailure::at(
                BrowserSetupStage::DiscoverTargets,
                error,
            ));
        }
        let initial = match c
            .command("Target.getTargets", json!({}), Duration::from_secs(3))
            .await
        {
            Ok(v) if v["targetInfos"].is_array() => v,
            Ok(_) => {
                c.close().await;
                return Err(BrowserSetupFailure::at(
                    BrowserSetupStage::GetTargetsShape,
                    Error::protocol("Browser Target discovery returned malformed targets"),
                ));
            }
            Err(error) => {
                c.close().await;
                return Err(BrowserSetupFailure::at(
                    BrowserSetupStage::GetTargets,
                    error,
                ));
            }
        };
        self.capture
            .browser
            .catalog_incomplete
            .store(false, Ordering::Release);
        {
            let mut queue = self
                .capture
                .browser
                .cleanup_queue
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            while let Some(job) = queue.waiting.pop_front() {
                queue.keys.remove(&job.key());
            }
        }
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
        {
            let mut seen = self
                .capture
                .browser
                .seen_documents
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            seen.loaders.clear();
            seen.urls.clear();
            seen.charged.clear();
        }
        self.capture
            .browser
            .document_navigation_gaps
            .store(0, Ordering::Release);
        self.capture
            .browser
            .destroyed
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
        self.capture
            .handoff_lineage
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.capture
            .handoff_lineage_complete
            .store(true, Ordering::Release);
        for info in initial["targetInfos"].as_array().unwrap().iter().take(4096) {
            self.remember_capture_target(info);
        }
        if initial["targetInfos"].as_array().unwrap().len() > 4096 {
            self.mark_capture_catalog_incomplete();
        }
        {
            let mut current = self
                .capture
                .browser
                .connection
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.capture
                .browser
                .cleanup_closing
                .store(false, Ordering::Release);
            *current = Some(c.clone());
        }
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
                let dropped = event_connection.take_dropped_events();
                if dropped > 0 {
                    d.note_debugger_event_drops(dropped);
                }
                match event {
                    Event::Barrier(sender) => {
                        let _ = sender.send(());
                    }
                    Event::Message(Ok(m), _permit) => {
                        d.browser_capture_event(&event_connection, m).await
                    }
                    Event::Message(Err(error), _permit) => {
                        if !d.capture.browser.cleanup_closing.load(Ordering::Acquire) {
                            d.retire_browser_owners(&event_connection, &error.message);
                        }
                        break;
                    }
                }
            }
        });
        // Browser-root auto-attach can throttle window.open even with
        // waitForDebuggerOnStart=false. Passive capture must not enable it.
        // Discovery plus explicit attachment keeps startup best-effort without
        // requiring a Runtime resume on targets whose startup we do not own.
        self.schedule_capture_admission(&c);
        self.browser_status();
        self.update(|s| {
            s["network"]["capture_status"]["browser_setup_failure"] = Value::Null;
        });
        Ok(true)
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
    fn record_capture_cleanup(&self, c: &Arc<Connection>, outcome: CleanupOutcome) -> bool {
        // Hold identity through the state update so a late cleanup reply cannot
        // charge a replacement connection. No await or nested browser lock.
        let current = self
            .capture
            .browser
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !current
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, c))
        {
            return false;
        }
        let (field, first_failure) = match outcome {
            CleanupOutcome::AlreadyGone => ("cleanup_already_gone", false),
            CleanupOutcome::Failed => (
                "cleanup_failures",
                !self
                    .capture
                    .browser
                    .cleanup_closing
                    .swap(true, Ordering::AcqRel),
            ),
        };
        self.update(|state| {
            let status = &mut state["network"]["capture_status"];
            status[field] = json!(status[field].as_u64().unwrap_or(0).saturating_add(1));
        });
        first_failure
    }
    fn confirm_capture_cleanup_gone(
        &self,
        c: &Arc<Connection>,
        session: Option<&str>,
        parent: Option<&str>,
        destroyed_target: Option<&str>,
    ) {
        // A parent session's teardown also destroys its recursive attachments,
        // even when their individual detach notifications never reach us. Use
        // only recorded owners on this connection, and validate the root's
        // parent route before propagating that proof. Target identity alone in
        // a detachedFromTarget event does not prove a session ended.
        let owners = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|owner| {
                owner
                    .connection
                    .as_ref()
                    .is_some_and(|connection| Arc::ptr_eq(connection, c))
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut ended = std::collections::BTreeSet::new();
        for owner in &owners {
            let exact_session = owner.session.as_deref() == session
                && session.is_some()
                && owner.parent_session.as_deref() == parent;
            let exact_target =
                destroyed_target.is_some() && owner.target["id"].as_str() == destroyed_target;
            if (exact_session || exact_target)
                && let Some(sid) = &owner.session
            {
                ended.insert(sid.clone());
            }
        }
        loop {
            let before = ended.len();
            for owner in &owners {
                if owner
                    .parent_session
                    .as_ref()
                    .is_some_and(|parent| ended.contains(parent))
                    && let Some(sid) = &owner.session
                {
                    ended.insert(sid.clone());
                }
            }
            if ended.len() == before {
                break;
            }
        }
        // Do not nest owners -> cleanup locks: cleanup saturation takes the
        // reverse order when it retires a browser connection. The Arc snapshot
        // above retains only bounded, immutable session ancestry.
        let queue = self
            .capture
            .browser
            .cleanup_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for ((connection, sid, owner_parent), proof) in &queue.keys {
            if *connection != Arc::as_ptr(c) as usize {
                continue;
            }
            let exact_session = session == Some(sid.as_str()) && owner_parent.as_deref() == parent;
            let exact_target =
                destroyed_target.is_some() && destroyed_target == proof.target.as_deref();
            let ended_ancestor = owner_parent
                .as_ref()
                .is_some_and(|parent| ended.contains(parent));
            if exact_session || exact_target || ended_ancestor {
                proof.gone.store(true, Ordering::Release);
            }
        }
    }
    async fn detach_capture_session(&self, job: &CleanupJob) {
        let c = &job.connection;
        if job.gone.load(Ordering::Acquire) {
            self.record_capture_cleanup(c, CleanupOutcome::AlreadyGone);
            return;
        }
        if let Err(error) = c
            .command_session(
                "Target.detachFromTarget",
                json!({"sessionId":job.session}),
                Duration::from_secs(1),
                job.parent.as_deref(),
            )
            .await
        {
            // A protocol rejection may race an earlier lifecycle event queued
            // for the same client. Drain it before consulting exact bounded proof.
            // A timeout, malformed reply or transport failure is never excused.
            if error.reason.code == Code::ApplicationFailed
                && !c.is_closed()
                && c.barrier().await.is_ok()
                && !c.is_closed()
                && self.capture.browser.current(c)
                && job.gone.load(Ordering::Acquire)
            {
                self.record_capture_cleanup(c, CleanupOutcome::AlreadyGone);
                return;
            }
            // Claim the current connection's first causal failure before closing.
            // Its ensuing EOF must not retire owners twice or erase this reason.
            if self.record_capture_cleanup(c, CleanupOutcome::Failed) {
                self.retire_browser_owners(c, &format!("Capture detach failed: {}", error.message));
            }
            c.close().await;
        }
    }
    fn schedule_capture_detach(
        self: &Arc<Self>,
        c: &Arc<Connection>,
        session: &str,
        parent: Option<&str>,
        target: Option<&str>,
    ) {
        if !self.capture.browser.current(c) || c.is_closed() {
            return;
        }
        let job = CleanupJob {
            connection: c.clone(),
            session: session.to_owned(),
            parent: parent.map(str::to_owned),
            target: target.filter(|id| id.len() <= 4096).map(str::to_owned),
            gone: Arc::new(AtomicBool::new(false)),
        };
        let mut queue = self
            .capture
            .browser
            .cleanup_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !self.capture.browser.current(c) || c.is_closed() {
            return;
        }
        let key = job.key();
        if queue.keys.contains_key(&key) {
            return;
        }
        if queue.keys.len() >= 512 {
            let first_failure = {
                let current = self
                    .capture
                    .browser
                    .connection
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                current
                    .as_ref()
                    .is_some_and(|active| Arc::ptr_eq(active, c))
                    && !self
                        .capture
                        .browser
                        .cleanup_closing
                        .swap(true, Ordering::AcqRel)
            };
            if first_failure {
                self.retire_browser_owners(c, "Capture cleanup capacity exceeded; closing this client leaves an explicit gap.");
                c.request_close();
                let c = c.clone();
                tokio::spawn(async move {
                    c.close().await;
                });
            }
            return;
        }
        queue.keys.insert(
            key,
            CleanupProof {
                target: job.target.clone(),
                gone: job.gone.clone(),
            },
        );
        queue.waiting.push_back(job);
        // Ordinary shared-worker fan-out may produce many alternate sessions.
        // Bound queued metadata independently from the four wire commands.
        for _ in 0..4 {
            let Ok(permit) = self.capture.browser.cleanup.clone().try_acquire_owned() else {
                break;
            };
            let d = self.clone();
            tokio::spawn(async move {
                loop {
                    let job = {
                        let mut queue = d
                            .capture
                            .browser
                            .cleanup_queue
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        match queue.waiting.pop_front() {
                            Some(job) => job,
                            None => {
                                // Release under the queue lock: a concurrent enqueue
                                // must either see this slot or be drained by us.
                                drop(permit);
                                return;
                            }
                        }
                    };
                    if d.capture.browser.current(&job.connection) && !job.connection.is_closed() {
                        d.detach_capture_session(&job).await;
                    }
                    d.capture
                        .browser
                        .cleanup_queue
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .keys
                        .remove(&job.key());
                }
            });
        }
    }

    async fn browser_capture_event(self: &Arc<Self>, c: &Arc<Connection>, m: Value) {
        let p = &m["params"];
        match m["method"].as_str().unwrap_or("") {
            "Target.targetCreated" | "Target.targetInfoChanged" => {
                self.remember_capture_target(&p["targetInfo"]);
                self.fill_captured_request_titles(&p["targetInfo"]);
                self.schedule_capture_admission(c);
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
                self.remember_handoff_lineage(c, &p["targetInfo"], parent);
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
                    self.schedule_capture_detach(
                        c,
                        session,
                        parent,
                        p["targetInfo"]["targetId"].as_str(),
                    );
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
                self.schedule_capture_detach(
                    c,
                    root.session.as_deref().unwrap(),
                    root.parent_session.as_deref(),
                    root.target["id"].as_str(),
                );
                self.browser_status();
            }
            "Target.detachedFromTarget" | "Target.targetDestroyed" => {
                let destroyed = m["method"] == "Target.targetDestroyed";
                let id = p["targetId"].as_str();
                let sid = p["sessionId"].as_str();
                self.confirm_capture_cleanup_gone(
                    c,
                    sid,
                    m["sessionId"].as_str(),
                    if destroyed { id } else { None },
                );
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
                    // Admission failures use this same catalog lock so a late
                    // attach error cannot resurrect a destroyed target's state.
                    let mut targets = self
                        .capture
                        .browser
                        .targets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
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
                    targets.remove(id);
                    self.remember_destroyed_list_target(id);
                    self.capture
                        .browser
                        .catalog_epoch
                        .fetch_add(1, Ordering::AcqRel);
                    *self
                        .capture
                        .browser
                        .catalog_retry
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Instant::now();
                    self.capture
                        .browser
                        .waiting
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|v| v != id);
                }
                if was_owned || destroyed {
                    self.schedule_capture_admission(c);
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
                    if method == "Network.loadingFinished"
                        && let Some(source) = self.main_resource_completion_owner(c, &owner, p)
                    {
                        self.network_for_body_owner(&source, &owner, method, p)
                            .await;
                    } else {
                        self.network_for(&owner, method, p).await;
                    }
                }
            }
            _ => {}
        }
    }
    pub(super) fn note_document_request(&self, target_id: &str, loader_id: &str, url: &str) {
        if target_id.is_empty() || target_id.len() > 4096 {
            return;
        }
        let mut seen = self
            .capture
            .browser
            .seen_documents
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !loader_id.is_empty() && loader_id.len() <= 4096 {
            SeenDocuments::insert(
                &mut seen.loaders,
                (target_id.to_owned(), loader_id.to_owned()),
            );
        }
        if http_document_url(url) {
            SeenDocuments::insert(&mut seen.urls, (target_id.to_owned(), url.to_owned()));
        }
    }
    fn note_committed_document(&self, owner: &Owner, snapshot: &Value) {
        let Some(target_id) = owner.target["id"].as_str().filter(|id| !id.is_empty()) else {
            return;
        };
        let token = {
            let seen = self
                .capture
                .browser
                .seen_documents
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let loaders = seen
                .loaders
                .iter()
                .filter(|(target, _)| target == target_id)
                .map(|(_, loader)| loader.clone())
                .collect::<BTreeSet<_>>();
            let urls = seen
                .urls
                .iter()
                .filter(|(target, _)| target == target_id)
                .map(|(_, url)| url.clone())
                .collect::<BTreeSet<_>>();
            unobserved_committed_document(snapshot, &loaders, &urls)
        };
        let Some(token) = token else {
            return;
        };
        {
            let mut seen = self
                .capture
                .browser
                .seen_documents
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let key = (target_id.to_owned(), token);
            if seen.charged.contains(&key) || seen.charged.len() >= SeenDocuments::MAX {
                return;
            }
            seen.charged.insert(key);
        }
        let gaps = self
            .capture
            .browser
            .document_navigation_gaps
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.update(|state| {
            let status = &mut state["network"]["capture_status"];
            status["document_navigation_gaps"] = json!(gaps);
            status["last_error"] = json!("A page target was already navigated when Network capture attached; its document request was not replayed.");
            if status["state"] == "ready" {
                status["state"] = json!("partial");
            }
        });
    }
    async fn observe_attached_document(self: &Arc<Self>, c: &Arc<Connection>, owner: &Arc<Owner>) {
        let kind = owner.target["type"].as_str().unwrap_or("");
        if kind != "page" && kind != "iframe" {
            return;
        }
        // Flush Network events that arrived while enable was in flight, then
        // read the target URL that already committed. A second barrier covers
        // a document event queued during that read. Page domain commands stay
        // unused so attachment remains passive.
        if c.barrier().await.is_err() {
            return;
        }
        let info = c
            .command_session(
                "Target.getTargetInfo",
                json!({}),
                Duration::from_secs(2),
                owner.session.as_deref(),
            )
            .await;
        if c.barrier().await.is_err() {
            return;
        }
        if let Ok(info) = info {
            self.note_committed_document(owner, &info);
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
                self.observe_attached_document(&c, &owner).await;
                if self.stopping.load(Ordering::Acquire)
                    || !self.capture.browser.current(&c)
                    || owner.retired.load(Ordering::Acquire)
                {
                    return;
                }
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
                self.schedule_capture_detach(
                    &c,
                    session.unwrap(),
                    owner.parent_session.as_deref(),
                    owner.target["id"].as_str(),
                );
            }
        }
        self.browser_status();
    }
    fn schedule_capture_admission(self: &Arc<Self>, c: &Arc<Connection>) {
        self.capture
            .browser
            .admission_epoch
            .fetch_add(1, Ordering::AcqRel);
        let Ok(admission) = self.capture.browser.admission.clone().try_lock_owned() else {
            return;
        };
        let weak = Arc::downgrade(self);
        let c = c.clone();
        tokio::spawn(async move {
            let Some(d) = weak.upgrade() else {
                return;
            };
            let mut observed = d.capture.browser.admission_epoch.load(Ordering::Acquire);
            // One independent pump, four commands in flight. Never block the
            // event dispatcher on attach replies or startup handshakes.
            for _ in 0..d.options.capture_target_limit.div_ceil(4) {
                observed = d.capture.browser.admission_epoch.load(Ordering::Acquire);
                let attempts = tokio::join!(
                    d.promote_capture_target(&c),
                    d.promote_capture_target(&c),
                    d.promote_capture_target(&c),
                    d.promote_capture_target(&c)
                );
                if !attempts.0
                    && !attempts.1
                    && !attempts.2
                    && !attempts.3
                    && d.capture.browser.admission_epoch.load(Ordering::Acquire) == observed
                {
                    break;
                }
            }
            drop(admission);
            // An event racing the final batch/lock release must not lose its
            // wakeup. Closed/replaced connections are rejected by promotion.
            if d.capture.browser.current(&c)
                && d.capture.browser.admission_epoch.load(Ordering::Acquire) != observed
            {
                d.schedule_capture_admission(&c);
            }
        });
    }
    fn record_capture_admission_failure(
        &self,
        c: &Arc<Connection>,
        id: &str,
        reason: &str,
    ) -> bool {
        let targets = self
            .capture
            .browser
            .targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if c.is_closed() || !self.capture.browser.current(c) || !targets.contains_key(id) {
            return false;
        }
        let owners = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // The event can establish a valid owner before its command reply arrives.
        // Owner initialization, not a stale attach ACK, controls its health.
        if owners.get(id).is_some_and(|o| {
            !o.retired.load(Ordering::Acquire)
                && o.connection
                    .as_ref()
                    .is_some_and(|owner| Arc::ptr_eq(owner, c))
        }) {
            return false;
        }
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
            .insert(id.to_owned(), Instant::now() + Duration::from_secs(5));
        let mut waiting = self
            .capture
            .browser
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Self::admit_waiting_target(&mut waiting, &targets, id.to_owned());
        self.update(|s| {
            s["network"]["capture_status"]["last_error"] =
                json!(crate::validation::truncate(reason, 512))
        });
        true
    }
    async fn promote_capture_target(&self, c: &Arc<Connection>) -> bool {
        if !self.capture.browser.current(c) || c.is_closed() {
            return false;
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
                return false;
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
            if !self.capture.browser.current(c)
                || !self
                    .capture
                    .browser
                    .targets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains_key(&id)
            {
                return false;
            }
            if let Err(error) = result {
                self.record_capture_admission_failure(c, &id, &error.message);
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn setup_diagnostics_use_structured_reasons_not_error_text() {
        use crate::error::Reason;
        let unknown = BrowserSetupFailure::at(
            BrowserSetupStage::TransportOpen,
            Error::conflict("timed out SECRET"),
        );
        assert_eq!(unknown.reason(), "state-conflict");
        for (cause, expected) in [
            (Cause::Timeout, "timeout"),
            (Cause::Disconnected, "disconnected"),
            (Cause::TransportFailure, "transport-failure"),
            (Cause::InvalidReply, "invalid-reply"),
        ] {
            let failure = BrowserSetupFailure::at(
                BrowserSetupStage::GetTargets,
                Error::conflict("SECRET").with_reason(Reason::uncertain(cause)),
            );
            assert_eq!(failure.stage, BrowserSetupStage::GetTargets);
            assert_eq!(failure.reason(), expected);
        }
        assert_eq!(
            BrowserSetupFailure::at(
                BrowserSetupStage::DiscoverTargets,
                Error::conflict("SECRET").with_code(Code::ApplicationFailed),
            )
            .reason(),
            "command-rejected"
        );
        assert_eq!(
            BrowserSetupFailure::at(
                BrowserSetupStage::GetTargetsShape,
                Error::protocol("SECRET"),
            )
            .reason(),
            "protocol-error"
        );
    }
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
    fn later_target_title_fills_rows_captured_before_the_document_title() {
        let mut state = json!({"network":{"requests":[
            {"target_id":"tab","target_title":"","url":"https://accounts.example/demo"},
            {"target_id":"tab","target_title":"already named"},
            {"target_id":"other","target_title":""}
        ]}});
        fill_empty_target_titles(&mut state, "tab", "Example demo");
        assert_eq!(
            state["network"]["requests"][0]["target_title"],
            "Example demo"
        );
        assert_eq!(
            state["network"]["requests"][1]["target_title"],
            "already named"
        );
        assert_eq!(state["network"]["requests"][2]["target_title"], "");
        fill_empty_target_titles(&mut state, "tab", "");
        assert_eq!(
            state["network"]["requests"][0]["target_title"],
            "Example demo"
        );
    }
    #[test]
    fn retired_list_target_history_is_bounded_and_reports_its_limit_once() {
        let d = Debugger::new(&crate::config::Options::parse_from(["test"]));
        for index in 0..MAX_RETIRED_LIST_TARGETS + 1024 {
            let _catalog = d.capture.browser.targets.lock().unwrap();
            d.remember_destroyed_list_target(&format!("retired-{index}"));
        }
        assert_eq!(
            d.capture.browser.destroyed.lock().unwrap().len(),
            MAX_RETIRED_LIST_TARGETS
        );
        assert!(d.list_discovery_limited());
        assert_eq!(d.snapshot()["network"]["capture_status"]["gaps"], 1);
        assert!(
            d.snapshot()["network"]["capture_status"]["last_error"]
                .as_str()
                .unwrap()
                .contains("list-only discovery is disabled")
        );
        d.capture.browser.destroyed.lock().unwrap().clear();
        assert!(!d.list_discovery_limited());
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
        assert_eq!(d.snapshot()["network"]["capture_status"]["gaps"], 1);
        assert!(d.capture.browser.catalog_incomplete.load(Ordering::Acquire));
        assert_eq!(
            d.capture
                .browser
                .waiting
                .lock()
                .unwrap()
                .front()
                .map(String::as_str),
            Some("target-0")
        );
        assert!(
            !d.capture
                .browser
                .targets
                .lock()
                .unwrap()
                .contains_key("target-599")
        );
    }
    #[test]
    fn page_targets_are_admitted_ahead_of_workers() {
        let d = Debugger::new(&crate::config::Options::parse_from(["test"]));
        d.remember_capture_target(
            &json!({"targetId":"worker","type":"worker","url":"http://localhost/w","title":"w"}),
        );
        d.remember_capture_target(&json!({
            "targetId":"page",
            "type":"page",
            "url":"https://accounts.hcaptcha.com/demo",
            "title":"hCaptcha Demo"
        }));
        let waiting = d.capture.browser.waiting.lock().unwrap().clone();
        assert_eq!(waiting.front().map(String::as_str), Some("page"));
        assert_eq!(waiting.get(1).map(String::as_str), Some("worker"));
    }
    #[test]
    fn a_full_worker_catalog_admits_the_page_under_test() {
        let d = Debugger::new(&crate::config::Options::parse_from(["test"]));
        for index in 0..512 {
            d.remember_capture_target(
                &json!({"targetId":format!("worker-{index}"),"type":"worker","url":"http://localhost/w"}),
            );
        }
        d.remember_capture_target(&json!({
            "targetId":"page",
            "type":"page",
            "url":"https://accounts.hcaptcha.com/demo",
            "title":"hCaptcha Demo"
        }));
        {
            let targets = d.capture.browser.targets.lock().unwrap();
            assert!(targets.contains_key("page"));
            assert!(!targets.contains_key("worker-511"));
            assert_eq!(targets.len(), 512);
        }
        let waiting = d.capture.browser.waiting.lock().unwrap().clone();
        assert_eq!(waiting.front().map(String::as_str), Some("page"));
        assert!(!waiting.iter().any(|id| id == "worker-511"));
        assert!(d.capture.browser.catalog_incomplete.load(Ordering::Acquire));
    }
    #[test]
    fn debugger_event_drops_stay_visible_without_closing_capture() {
        let mut options = crate::config::Options::parse_from(["test"]);
        options.capture_network_content = true;
        let d = Debugger::new(&options);
        assert_eq!(
            d.snapshot()["network"]["capture_status"]["state"],
            "waiting"
        );
        d.note_debugger_event_drops(0);
        assert!(d.snapshot()["network"]["capture_status"]["event_queue_drops"].is_null());
        d.note_debugger_event_drops(3);
        d.note_debugger_event_drops(2);
        let status = d.snapshot()["network"]["capture_status"].clone();
        assert_eq!(status["event_queue_drops"], 5);
        assert_eq!(status["state"], "partial");
        assert_eq!(status["gaps"], 0);
        assert!(
            status["last_error"]
                .as_str()
                .unwrap()
                .starts_with("Debugger event queue dropped ")
        );
        assert!(
            status["last_error"]
                .as_str()
                .unwrap()
                .contains("stayed open")
        );
    }
    #[test]
    fn committed_http_document_without_a_seen_loader_is_a_navigation_gap() {
        let tree = json!({"frameTree":{"frame":{
            "id":"main","loaderId":"navigation","url":"https://accounts.example/demo"
        }}});
        let missed = unobserved_committed_document(&tree, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(missed.as_deref(), Some("navigation"));
        let mut loaders = BTreeSet::from(["navigation".to_owned()]);
        assert_eq!(
            unobserved_committed_document(&tree, &loaders, &BTreeSet::new()),
            None
        );
        loaders.clear();
        assert_eq!(
            unobserved_committed_document(
                &json!({"frameTree":{"frame":{"url":"about:blank","loaderId":"blank"}}}),
                &loaders,
                &BTreeSet::new()
            ),
            None
        );
        let url_only = json!({"frameTree":{"frame":{"url":"https://accounts.example/demo"}}});
        assert_eq!(
            unobserved_committed_document(&url_only, &BTreeSet::new(), &BTreeSet::new()).as_deref(),
            Some("url:https://accounts.example/demo")
        );
        let target_info =
            json!({"targetInfo":{"type":"page","url":"https://accounts.example/demo"}});
        assert_eq!(
            unobserved_committed_document(&target_info, &BTreeSet::new(), &BTreeSet::new())
                .as_deref(),
            Some("url:https://accounts.example/demo")
        );
        let mut urls = BTreeSet::from(["https://accounts.example/demo".to_owned()]);
        assert_eq!(
            unobserved_committed_document(&url_only, &BTreeSet::new(), &urls),
            None
        );
        // A later favicon does not count as the document loader.
        loaders.insert("favicon".to_owned());
        urls.clear();
        assert_eq!(
            unobserved_committed_document(&tree, &loaders, &urls).as_deref(),
            Some("navigation")
        );
        let debugger = Debugger::new(&crate::config::Options::parse_from(["test"]));
        let owner = Owner::fixture(
            "owner",
            json!({"id":"tab","type":"page","title":"","url":""}),
        );
        debugger.note_document_request("tab", "favicon", "https://accounts.example/favicon.ico");
        debugger.note_committed_document(&owner, &tree);
        debugger.note_committed_document(&owner, &tree);
        let status = debugger.snapshot()["network"]["capture_status"].clone();
        // Capture starts disabled until a session is enabled. The miss is still
        // counted, and only an already-ready session is downgraded to partial.
        assert_eq!(status["document_navigation_gaps"], 1);
        assert_eq!(status["state"], "disabled");
        assert_eq!(status["gaps"], 0);
        assert_eq!(
            status["last_error"],
            "A page target was already navigated when Network capture attached; its document request was not replayed."
        );
        debugger.update(|state| {
            state["network"]["capture_status"]["state"] = json!("ready");
        });
        debugger.note_committed_document(
            &Owner::fixture(
                "owner-ready",
                json!({"id":"tab-ready","type":"page","title":"","url":""}),
            ),
            &tree,
        );
        assert_eq!(
            debugger.snapshot()["network"]["capture_status"]["state"],
            "partial"
        );
        assert_eq!(
            debugger.snapshot()["network"]["capture_status"]["document_navigation_gaps"],
            2
        );
        assert_eq!(debugger.snapshot()["network"]["capture_status"]["gaps"], 0);
        debugger.note_document_request("tab", "navigation", "https://accounts.example/demo");
        let owner_seen = Owner::fixture(
            "owner-2",
            json!({"id":"tab-2","type":"page","title":"","url":""}),
        );
        debugger.note_document_request("tab-2", "navigation", "https://accounts.example/demo");
        debugger.note_committed_document(
            &owner_seen,
            &json!({"frameTree":{"frame":{
                "loaderId":"navigation","url":"https://accounts.example/demo"
            }}}),
        );
        assert_eq!(
            debugger.snapshot()["network"]["capture_status"]["document_navigation_gaps"],
            2,
            "a loader already seen on Document requestWillBeSent is not another miss"
        );
    }
}
