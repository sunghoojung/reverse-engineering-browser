//! HTTP capture owns separate page connections; debugger focus never owns its ledger.
use super::{
    Debugger,
    connection::{Connection, Event},
};
use crate::error::{Error, Result};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const TARGET_LIMIT: usize = 8;
pub(super) struct Owner {
    pub id: String,
    pub target: Value,
    pub connection: Option<Arc<Connection>>,
    pub session: Option<String>,
    pub parent_session: Option<String>,
    pub retired: AtomicBool,
    pub(super) ready: AtomicBool,
}
pub(super) struct Capture {
    pub(super) owners: Mutex<BTreeMap<String, Arc<Owner>>>,
    retry: Mutex<BTreeMap<String, (u32, Instant)>>,
    pub(super) next_owner: AtomicU64,
    next_row: AtomicU64,
    pub(super) browser: super::network_browser::BrowserCapture,
    pub(super) holds: super::network_hold::Holds,
}
pub(super) fn next_id(counter: &AtomicU64) -> Option<u64> {
    let mut value = counter.load(Ordering::Relaxed);
    loop {
        let next = value.checked_add(1)?;
        match counter.compare_exchange_weak(value, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Some(value),
            Err(current) => value = current,
        }
    }
}
impl Capture {
    pub fn new() -> Self {
        Self {
            owners: Mutex::new(BTreeMap::new()),
            retry: Mutex::new(BTreeMap::new()),
            next_owner: AtomicU64::new(1),
            next_row: AtomicU64::new(1),
            browser: super::network_browser::BrowserCapture::new(),
            holds: super::network_hold::Holds::default(),
        }
    }
    pub fn row_id(&self, owner: &Owner) -> Option<String> {
        next_id(&self.next_row).map(|n| format!("cdp:{}:{n}", owner.id))
    }
}
impl Owner {
    #[cfg(test)]
    pub(super) fn fixture(id: &str, target: Value) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            target,
            connection: None,
            session: None,
            parent_session: None,
            retired: AtomicBool::new(false),
            ready: AtomicBool::new(true),
        })
    }
}
impl Debugger {
    pub(super) fn retire_capture(&self, owner: &Owner, reason: &str) {
        if owner.retired.swap(true, Ordering::AcqRel) {
            return;
        }
        self.update(|state| {
            let status = &mut state["network"]["capture_status"];
            status["state"] = json!("partial");
            status["gaps"] = json!(status["gaps"].as_u64().unwrap_or(0).saturating_add(1));
            status["last_error"] = json!(crate::validation::truncate(reason, 512));
            for row in state["network"]["requests"].as_array_mut().unwrap() {
                if row["capture_owner"] != owner.id {
                    continue;
                }
                if row["state"] == "pending" {
                    row["state"] = json!("failed");
                    row["error_text"] = json!(reason);
                }
                if row["response"]["body"]["state"] == "loading" {
                    row["response"]["body"]["state"] = json!("error");
                    row["response"]["body"]["reason"] =
                        json!(crate::validation::truncate(reason, 512));
                }
            }
        });
    }
    pub(super) async fn close_captures(&self) {
        self.close_browser_capture().await;
        let owners = std::mem::take(
            &mut *self
                .capture
                .owners
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for (_, owner) in owners {
            self.retire_capture(
                &owner,
                "HTTP capture ended; unfinished evidence is unavailable.",
            );
            if let Some(c) = &owner.connection {
                c.close().await;
            }
        }
    }
    pub(super) async fn refresh_captures(self: &Arc<Self>, targets: &[Value]) {
        if !self.options.capture_network_content {
            return;
        }
        if self.refresh_browser_capture().await {
            return;
        }
        let mut eligible = targets
            .iter()
            .filter(|t| {
                t["type"] == "page" && !t["url"].as_str().unwrap_or("").starts_with("devtools://")
            })
            .cloned()
            .collect::<Vec<_>>();
        eligible.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let eligible_count = eligible.len();
        let all_eligible = eligible.clone();
        // Keep healthy owners stable at capacity; new target ordering cannot
        // repeatedly evict a page and create unnecessary capture gaps.
        let existing = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        eligible.sort_by_key(|t| !existing.iter().any(|id| t["id"] == *id));
        eligible.truncate(TARGET_LIMIT);
        self.capture
            .retry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|id, _| eligible.iter().any(|t| t["id"] == *id));
        let removed = {
            let mut owners = self
                .capture
                .owners
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let ids = owners
                .iter()
                .filter(|(id, owner)| {
                    owner.retired.load(Ordering::Acquire)
                        || owner.connection.as_ref().is_none_or(|c| c.is_closed())
                        || !eligible.iter().any(|t| t["id"] == **id)
                })
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            ids.into_iter()
                .filter_map(|id| owners.remove(&id))
                .collect::<Vec<_>>()
        };
        for owner in removed {
            self.retire_capture(
                &owner,
                "HTTP target closed or disconnected; capture has a gap.",
            );
            if let Some(c) = &owner.connection {
                c.close().await;
            }
        }
        let mut opens = tokio::task::JoinSet::new();
        for target in eligible {
            let id = target["id"].as_str().unwrap();
            if self
                .capture
                .owners
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(id)
                || self
                    .capture
                    .retry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(id)
                    .is_some_and(|(_, until)| Instant::now() < *until)
            {
                continue;
            }
            let debugger = self.clone();
            opens.spawn(async move {
                let id = target["id"].as_str().unwrap().to_owned();
                (id, debugger.open_capture(target).await)
            });
        }
        while let Some(opened) = opens.join_next().await {
            if let Ok((id, result)) = opened {
                if let Err(error) = result {
                    let mut retry = self.capture.retry.lock().unwrap_or_else(|e| e.into_inner());
                    let attempts = retry.get(&id).map_or(1, |(n, _)| n.saturating_add(1));
                    retry.insert(
                        id,
                        (
                            attempts,
                            Instant::now()
                                + Duration::from_secs(2u64.saturating_pow(attempts.min(5)).min(30)),
                        ),
                    );
                    drop(retry);
                    self.update(|s| {
                        s["network"]["capture_status"]["last_error"] =
                            json!(crate::validation::truncate(&error.message, 512))
                    });
                } else {
                    self.capture
                        .retry
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&id);
                }
            } else if let Err(error) = opened {
                self.update(|s| {
                    s["network"]["capture_status"]["last_error"] =
                        json!(crate::validation::truncate(
                            &format!("HTTP capture setup task failed: {error}"),
                            512
                        ));
                });
            }
        }
        let attached_ids = self
            .capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|o| {
                o.ready.load(Ordering::Acquire)
                    && !o.retired.load(Ordering::Acquire)
                    && o.connection.as_ref().is_some_and(|c| !c.is_closed())
            })
            .map(|owner| owner.target["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let attached = attached_ids.len();
        let unattached = all_eligible.iter().filter(|target| !attached_ids.iter().any(|id|target["id"]==*id))
            .map(|target| json!({"id":target["id"],"title":crate::validation::truncate(target["title"].as_str().unwrap_or(""),128)}))
            .collect::<Vec<_>>();
        let failed = self
            .capture
            .retry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        let old = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state["network"]["capture_status"].clone()
        };
        let mut status = old.clone();
        status["state"] = json!(if eligible_count == 0 {
            "waiting"
        } else if attached == eligible_count {
            "ready"
        } else {
            "partial"
        });
        status["attached_targets"] = json!(attached);
        status["eligible_targets"] = json!(eligible_count);
        status["target_overflow"] = json!(eligible_count.saturating_sub(TARGET_LIMIT));
        status["failed_targets"] = json!(failed);
        status["discovery_stale"] = json!(false);
        status["catalog_incomplete"] = json!(false);
        status["attached_target_ids"] = json!(attached_ids);
        status["unattached_targets"] = json!(unattached.iter().take(16).collect::<Vec<_>>());
        status["unattached_targets_omitted"] = json!(unattached.len().saturating_sub(16));
        if old != status {
            self.update(|s| {
                // Event tasks may report a gap after the comparison snapshot.
                // Never replace their cumulative counters or last diagnostic.
                for key in [
                    "state",
                    "attached_targets",
                    "eligible_targets",
                    "target_overflow",
                    "failed_targets",
                    "discovery_stale",
                    "catalog_incomplete",
                    "attached_target_ids",
                    "unattached_targets",
                    "unattached_targets_omitted",
                ] {
                    s["network"]["capture_status"][key] = status[key].clone();
                }
            });
        }
    }
    async fn open_capture(self: &Arc<Self>, target: Value) -> Result<()> {
        let number = next_id(&self.capture.next_owner)
            .ok_or_else(|| Error::conflict("HTTP capture owner capacity exhausted"))?;
        let (connection, mut events) =
            Connection::open(&self.transport, target["web_socket_url"].as_str().unwrap()).await?;
        let id = target["id"].as_str().unwrap().to_owned();
        let owner = Arc::new(Owner {
            id: number.to_string(),
            target,
            connection: Some(connection.clone()),
            session: None,
            parent_session: None,
            retired: AtomicBool::new(false),
            ready: AtomicBool::new(false),
        });
        self.capture
            .owners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.clone(), owner.clone());
        let weak = Arc::downgrade(self);
        let event_owner = owner.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let Some(debugger) = weak.upgrade() else {
                    break;
                };
                if event_owner.retired.load(Ordering::Acquire) {
                    break;
                }
                match event {
                    Event::Barrier(sender) => {
                        let _ = sender.send(());
                    }
                    Event::Message(Ok(message), _permit) => {
                        if let Some(method) = message["method"].as_str().filter(|m| {
                            m.starts_with("Network.") && !m.starts_with("Network.webSocket")
                        }) {
                            debugger
                                .network_for(&event_owner, method, &message["params"])
                                .await;
                        }
                    }
                    Event::Message(Err(error), _permit) => {
                        debugger.retire_capture(
                            &event_owner,
                            &format!(
                                "HTTP capture disconnected: {}",
                                crate::validation::truncate(&error.message, 400)
                            ),
                        );
                        break;
                    }
                }
            }
        });
        if let Err(error)=connection.command("Network.enable",json!({"maxTotalBufferSize":16777216,"maxResourceBufferSize":2097152,"maxPostDataSize":131072}),Duration::from_secs(3)).await {
            self.retire_capture(&owner,"HTTP capture initialization failed; retry pending.");
            self.capture.owners.lock().unwrap_or_else(|e|e.into_inner()).remove(&id);
            connection.close().await;
            return Err(error);
        }
        owner.ready.store(true, Ordering::Release);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    fn debugger() -> Arc<Debugger> {
        let mut options = crate::config::Options::parse_from(["test"]);
        options.capture_network_content = true;
        Debugger::new(&options)
    }
    fn request(raw: &str) -> Value {
        json!({"requestId":raw,"timestamp":1.0,"request":{"url":"http://localhost/synthetic","method":"GET","headers":{}}})
    }
    #[tokio::test]
    async fn http_owners_isolate_reused_ids_and_survive_focus_change() {
        let d = debugger();
        let a = Owner::fixture("a", json!({"id":"page-a","title":"A"}));
        let b = Owner::fixture("b", json!({"id":"page-b","title":"B"}));
        for owner in [&a, &b] {
            d.network_for(owner, "Network.requestWillBeSent", &request("same"))
                .await;
        }
        d.update(|s| {
            s["target"] = json!({"id":"page-b"});
            s["network"]["capture_epoch"] = json!(4);
        });
        d.network_for(
            &a,
            "Network.responseReceived",
            &json!({"requestId":"same","response":{"status":201,"headers":{}}}),
        )
        .await;
        d.network_for(
            &b,
            "Network.responseReceived",
            &json!({"requestId":"same","response":{"status":202,"headers":{}}}),
        )
        .await;
        let s = d.snapshot();
        let rows = s["network"]["requests"].as_array().unwrap();
        assert_eq!(rows[0]["target_id"], "page-a");
        assert_eq!(rows[0]["status"], 201);
        assert_eq!(rows[1]["target_id"], "page-b");
        assert_eq!(rows[1]["status"], 202);
        assert_ne!(rows[0]["id"], rows[1]["id"]);
        let mut redirect = request("same");
        redirect["redirectResponse"] = json!({"status":302,"headers":{}});
        d.network_for(&a, "Network.requestWillBeSent", &redirect)
            .await;
        let s = d.snapshot();
        let rows = s["network"]["requests"].as_array().unwrap();
        assert_eq!(rows[0]["status"], 302);
        assert_eq!(rows[1]["status"], 202);
        assert_ne!(rows[0]["id"], rows[2]["id"]);
    }
    #[tokio::test]
    async fn http_retirement_retains_rows_and_rejects_late_events() {
        let d = debugger();
        let owner = Owner::fixture("old", json!({"id":"page-a"}));
        d.network_for(&owner, "Network.requestWillBeSent", &request("same"))
            .await;
        d.retire_capture(&owner, "Synthetic target closure");
        d.network_for(
            &owner,
            "Network.responseReceived",
            &json!({"requestId":"same","response":{"status":200,"headers":{}}}),
        )
        .await;
        d.network_for(&owner, "Network.requestWillBeSent", &request("late"))
            .await;
        let replacement = Owner::fixture("new", json!({"id":"page-a"}));
        d.network_for(&replacement, "Network.requestWillBeSent", &request("same"))
            .await;
        let s = d.snapshot();
        let rows = s["network"]["requests"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["state"], "failed");
        assert!(rows[0]["status"].is_null());
        assert_eq!(rows[0]["response"]["body"]["state"], "error");
        assert_ne!(rows[0]["id"], rows[1]["id"]);
        assert_eq!(s["network"]["capture_status"]["gaps"], 1);
    }
    #[tokio::test]
    async fn http_ids_never_reuse_evicted_redirect_hops_and_exhaustion_is_visible() {
        let d = debugger();
        let owner = Owner::fixture("a", json!({"id":"page-a"}));
        let mut ids = std::collections::BTreeSet::new();
        for _ in 0..1002 {
            d.network_for(&owner, "Network.requestWillBeSent", &request("reused"))
                .await;
            assert!(
                ids.insert(
                    d.snapshot()["network"]["requests"]
                        .as_array()
                        .unwrap()
                        .last()
                        .unwrap()["id"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                )
            );
        }
        assert_eq!(
            d.snapshot()["network"]["requests"]
                .as_array()
                .unwrap()
                .len(),
            1000
        );
        assert_eq!(d.snapshot()["network"]["dropped"], 2);
        d.capture.next_row.store(u64::MAX, Ordering::Relaxed);
        d.network_for(&owner, "Network.requestWillBeSent", &request("exhausted"))
            .await;
        assert_eq!(d.snapshot()["network"]["dropped"], 3);
    }
}
