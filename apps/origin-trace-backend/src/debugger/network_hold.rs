//! Bounded startup holds, available only to the backend-owned disposable browser.
//! Runtime resume is sent only for a waiting attachment on our own connection.
use super::{Debugger, connection::Connection};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub(super) struct Hold {
    connection: Arc<Connection>,
    started: Instant,
    deferred: bool,
}
#[derive(Default)]
pub(super) struct Holds {
    sessions: Mutex<BTreeMap<(usize, String), Hold>>,
}
impl Debugger {
    pub(super) fn register_capture_hold(&self, c: &Arc<Connection>, session: &str) -> bool {
        if !self.options.capture_first_owned {
            return false;
        }
        let mut held = self
            .capture
            .holds
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = (Arc::as_ptr(c) as usize, session.to_owned());
        if held.contains_key(&key) {
            return true;
        }
        if held.len() >= 256 {
            return false;
        }
        held.insert(
            key,
            Hold {
                connection: c.clone(),
                started: Instant::now(),
                deferred: false,
            },
        );
        self.update(|s| s["network"]["capture_status"]["held_targets"] = json!(held.len()));
        true
    }
    // At most one bounded duplicate-owner waiter per registered hold.
    pub(super) fn defer_capture_hold(&self, c: &Arc<Connection>, session: &str) -> Option<bool> {
        let mut held = self
            .capture
            .holds
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let hold = held.get_mut(&(Arc::as_ptr(c) as usize, session.to_owned()))?;
        let first = !hold.deferred;
        hold.deferred = true;
        Some(first)
    }
    pub(super) async fn resume_capture_hold(
        &self,
        c: &Arc<Connection>,
        session: &str,
        reason: Option<&str>,
    ) {
        let hold = {
            let mut held = self
                .capture
                .holds
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            held.remove(&(Arc::as_ptr(c) as usize, session.to_owned()))
        };
        if let Some(hold) = hold {
            self.release_capture_session(c, session, reason, hold.started.elapsed())
                .await;
        }
    }
    pub(super) async fn release_capture_session(
        &self,
        c: &Arc<Connection>,
        session: &str,
        reason: Option<&str>,
        elapsed: Duration,
    ) {
        // The deadline includes the command writer queue. If the transport cannot
        // acknowledge resume, close our client so its attachment cannot retain a hold.
        let releasing = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            c.command_session(
                "Runtime.runIfWaitingForDebugger",
                json!({}),
                Duration::from_secs(1),
                Some(session),
            ),
        )
        .await;
        let acknowledged = matches!(result, Ok(Ok(_)));
        let count = self
            .capture
            .holds
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len();
        // Keep the first cleanup failure, and never replace a newer connection's
        // diagnostics with an old session's eventual release result.
        self.update_capture_hold(c, |s, report_error| {
            let v = &mut s["network"]["capture_status"];
            v["held_targets"] = json!(count);
            v["hold_max_ms"] = json!(v["hold_max_ms"].as_u64().unwrap_or(0).max((elapsed + releasing.elapsed()).as_millis().min(u64::MAX as u128) as u64));
            let counter = if acknowledged { "resumed_targets" } else { "resume_failures" };
            v[counter] = json!(v[counter].as_u64().unwrap_or(0).saturating_add(1));
            if let Some(reason) = reason {
                v["gaps"] = json!(v["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                if report_error { v["last_error"] = json!(reason); }
            }
            if !acknowledged {
                v["gaps"] = json!(v["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                if report_error {
                    v["last_error"] = json!("Startup resume was not acknowledged; capture transport closed to release its attachments. Early evidence may be missing.");
                    v["state"] = json!("partial");
                }
            }
        });
        if !acknowledged {
            c.close().await;
        }
    }
    pub(super) async fn release_capture_holds(&self, c: &Arc<Connection>) {
        let sessions = self
            .capture
            .holds
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, h)| Arc::ptr_eq(c, &h.connection))
            .map(|((_, id), _)| id.clone())
            .collect::<Vec<_>>();
        // Concurrent bounded commands avoid N sequential timeout seconds during shutdown.
        let futures = sessions.iter().map(|id| {
            self.resume_capture_hold(
                c,
                id,
                Some("Capture-first stopped or disconnected; startup capture may be incomplete."),
            )
        });
        futures_util::future::join_all(futures).await;
    }
    pub(super) fn start_capture_hold_watchdog(self: &Arc<Self>, c: Arc<Connection>) {
        if !self.options.capture_first_owned {
            return;
        }
        let weak = Arc::downgrade(self);
        let connection = Arc::downgrade(&c);
        c.observe_events(Arc::new(move |event| {
            if event["method"] != "Target.attachedToTarget" { return; }
            if event["params"]["waitingForDebugger"] == false { return; }
            let (Some(d), Some(c)) = (weak.upgrade(), connection.upgrade()) else { return; };
            let session = event["params"]["sessionId"].as_str().filter(|s| !s.is_empty() && s.len() <= 4096);
            if event["params"]["waitingForDebugger"] != true || session.is_none_or(|session| !d.register_capture_hold(&c, session)) {
                // Unknown/overflowing control state cannot retain a browser hold.
                // Closing the transport releases every attachment on this client.
                d.update(|s| {
                    let v = &mut s["network"]["capture_status"];
                    v["gaps"] = json!(v["gaps"].as_u64().unwrap_or(0).saturating_add(1));
                    v["last_error"] = json!("Capture-first hold metadata or capacity invalid; closing capture transport to release startup holds.");
                });
                c.request_close();
                tokio::spawn(async move { c.close().await; });
            }
        }));
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let Some(d) = weak.upgrade() else {
                    c.close().await;
                    break;
                };
                if c.is_closed() {
                    d.release_capture_holds(&c).await;
                    break;
                }
                let expired = d
                    .capture
                    .holds
                    .sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .filter(|(_, h)| {
                        Arc::ptr_eq(&c, &h.connection)
                            && h.started.elapsed() >= Duration::from_secs(4)
                    })
                    .map(|((_, id), _)| id.clone())
                    .collect::<Vec<_>>();
                if !expired.is_empty() {
                    d.update(|s| {
                        let v = &mut s["network"]["capture_status"];
                        v["hold_timeouts"] = json!(
                            v["hold_timeouts"]
                                .as_u64()
                                .unwrap_or(0)
                                .saturating_add(expired.len() as u64)
                        );
                    });
                    // Do not await resume acknowledgements in the timer loop:
                    // one slow batch must not delay another target's deadline.
                    for id in expired {
                        let hold = d
                            .capture
                            .holds
                            .sessions
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&(Arc::as_ptr(&c) as usize, id.clone()));
                        if let Some(hold) = hold {
                            let d = d.clone();
                            let c = c.clone();
                            tokio::spawn(async move {
                                d.release_capture_session(&c, &id,
                                    Some("Capture-first setup deadline expired; target resumed before capture was ready."), hold.started.elapsed()).await;
                            });
                        }
                    }
                }
            }
        });
    }
}
