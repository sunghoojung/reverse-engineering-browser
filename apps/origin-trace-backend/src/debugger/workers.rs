use super::{
    Debugger,
    connection::{Connection, Event},
    parse,
};
use crate::{
    error::{Error, Result},
    validation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
#[derive(Clone)]
pub(super) struct Session {
    pub connection: Arc<Connection>,
    pub id: Option<String>,
}
impl Session {
    pub async fn command(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.connection
            .command_session(method, params, timeout, self.id.as_deref())
            .await
    }
}
pub(super) struct Workers {
    sessions: Mutex<BTreeMap<String, Session>>,
    refresh: tokio::sync::Mutex<()>,
    retry: Mutex<BTreeMap<String, (u32, std::time::Instant)>>,
}
impl Workers {
    pub(super) fn has_sessions(&self) -> bool {
        !self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
            refresh: tokio::sync::Mutex::new(()),
            retry: Mutex::new(BTreeMap::new()),
        }
    }
}
impl Debugger {
    pub(super) async fn hook_session(&self, target: &str) -> Result<Session> {
        if self.snapshot()["target"]["id"] == target {
            let c = self
                .connection
                .lock()
                .await
                .clone()
                .filter(|c| !c.is_closed())
                .ok_or_else(|| Error::conflict("Isolated page debugger is unavailable"))?;
            return Ok(Session {
                connection: c,
                id: None,
            });
        }
        self.workers
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(target)
            .filter(|s| !s.connection.is_closed())
            .cloned()
            .ok_or_else(|| Error::conflict("The isolated worker debugger is unavailable"))
    }
    pub(super) async fn close_workers(&self) {
        self.hooks
            .candidate_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let _refresh = self.workers.refresh.lock().await;
        self.workers
            .retry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let sessions = std::mem::take(
            &mut *self
                .workers
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for (_, s) in sessions {
            s.connection.close().await;
        }
        self.update(|s| {
            s["scripts"]
                .as_array_mut()
                .unwrap()
                .retain(|s| s.get("target_type").is_none_or(|t| *t != "worker"));
            s["runtime_hooks"]["workers"] = json!([]);
            s["runtime_hooks"]["worker_overflow"] = json!(0);
        });
    }
    pub(super) async fn refresh_workers(self: &Arc<Self>) -> Result<()> {
        let _refresh = self.workers.refresh.lock().await;
        let Some(context) = self.experiment.context() else {
            return Ok(());
        };
        let info = self.browser_command("Target.getTargets", json!({})).await?;
        let raw = info["targetInfos"]
            .as_array()
            .filter(|a| a.len() <= 512)
            .ok_or_else(|| Error::protocol("Malformed worker target list"))?;
        let known = self.discover().await?;
        let mut candidates = raw
            .iter()
            .filter(|t| t["browserContextId"] == context && t["type"] == "worker")
            .filter_map(|t| known.iter().find(|k| k["id"] == t["targetId"]).cloned())
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let overflow = candidates.len().saturating_sub(8);
        candidates.truncate(8);
        self.workers
            .retry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|id, _| candidates.iter().any(|t| t["id"] == *id));
        let removed = {
            let mut sessions = self
                .workers
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let ids = sessions
                .iter()
                .filter(|(id, s)| {
                    s.connection.is_closed() || !candidates.iter().any(|t| t["id"] == **id)
                })
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            ids.into_iter()
                .filter_map(|id| sessions.remove(&id).map(|s| (id, s)))
                .collect::<Vec<_>>()
        };
        for (id, s) in removed {
            s.connection.close().await;
            if self.snapshot()["runtime_hooks"]["definitions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["target_id"] == id)
            {
                let _ = self.disarm_hooks().await;
                self.update(|s| {
                    s["runtime_hooks"]["definitions"] = json!([]);
                    s["runtime_hooks"]["state"] = json!("error");
                    s["runtime_hooks"]["last_failure"] =
                        json!("The isolated worker disconnected. Its hooks were cleared.");
                });
            }
            self.update(|s| {
                s["scripts"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|s| s["target_id"] != id)
            });
        }
        let (_, browser_url) = self.endpoint()?;
        let mut error = None;
        for target in &candidates {
            let id = target["id"].as_str().unwrap();
            if self
                .workers
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(id)
            {
                continue;
            }
            if self
                .workers
                .retry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(id)
                .is_some_and(|(_, until)| std::time::Instant::now() < *until)
            {
                continue;
            }
            let opened = async {
                let (connection, mut events) =
                    Connection::open(&self.transport, &browser_url).await?;
                let attached = connection
                    .command(
                        "Target.attachToTarget",
                        json!({"targetId":id,"flatten":true}),
                        Duration::from_secs(5),
                    )
                    .await?;
                let session_id = validation::text(
                    &attached["sessionId"],
                    "Worker session ID",
                    4096,
                    false,
                    false,
                )
                .map_err(|e| Error::protocol(e.message))?
                .to_owned();
                let session = Session {
                    connection: connection.clone(),
                    id: Some(session_id.clone()),
                };
                self.workers
                    .sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.into(), session.clone());
                let weak = Arc::downgrade(self);
                let target_id = id.to_owned();
                let captured_context = context.clone();
                tokio::spawn(async move {
                    while let Some(event) = events.recv().await {
                        match event {
                            Event::Barrier(sender) => {
                                let _ = sender.send(());
                            }
                            Event::Message(Ok(message), _permit) => {
                                let Some(d) = weak.upgrade() else {
                                    break;
                                };
                                if d.experiment.context().as_deref() != Some(&captured_context) {
                                    break;
                                }
                                if message["sessionId"] == session_id {
                                    d.worker_event(&target_id, message).await;
                                }
                            }
                            Event::Message(Err(_), _permit) => break,
                        }
                    }
                });
                for (method, params) in [
                    ("Runtime.runIfWaitingForDebugger", json!({})),
                    ("Runtime.enable", json!({})),
                    ("Debugger.enable", json!({"maxScriptsCacheSize":33554432})),
                    ("Network.enable", json!({"maxPostDataSize":0})),
                    (
                        "Debugger.setBreakpointsActive",
                        json!({"active":self.snapshot()["settings"]["breakpoints_active"]}),
                    ),
                ] {
                    session
                        .command(method, params, Duration::from_secs(3))
                        .await?;
                }
                Ok::<_, Error>(())
            }
            .await;
            if let Err(e) = opened {
                error = Some(e.message);
                {
                    let mut retry = self.workers.retry.lock().unwrap_or_else(|e| e.into_inner());
                    let attempts = retry.get(id).map_or(1, |(n, _)| n.saturating_add(1));
                    retry.insert(
                        id.into(),
                        (
                            attempts,
                            std::time::Instant::now()
                                + Duration::from_secs(2u64.saturating_pow(attempts.min(5)).min(30)),
                        ),
                    );
                }
                let removed = self
                    .workers
                    .sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(id);
                if let Some(s) = removed {
                    s.connection.close().await;
                }
            } else {
                self.workers
                    .retry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(id);
            }
        }
        let public = candidates
            .iter()
            .map(|v| json!({"id":v["id"],"type":v["type"],"title":v["title"],"url":v["url"]}))
            .collect::<Vec<_>>();
        if self.snapshot()["runtime_hooks"]["workers"] != json!(public)
            || self.snapshot()["runtime_hooks"]["worker_overflow"] != overflow
            || error.is_some()
        {
            self.update(|s| {
                s["runtime_hooks"]["workers"] = json!(public);
                s["runtime_hooks"]["worker_overflow"] = json!(overflow);
                if let Some(e) = error {
                    s["runtime_hooks"]["last_failure"] = json!(validation::truncate(
                        &format!("Worker debugger attach failed: {e}"),
                        512
                    ));
                }
            });
        }
        Ok(())
    }
    async fn worker_event(self: &Arc<Self>, target: &str, message: Value) {
        let p = &message["params"];
        match message["method"].as_str().unwrap_or("") {
            "Debugger.scriptParsed" => {
                if let Some(mut script) = parse::script(p) {
                    let id = script["script_id"].as_str().unwrap().to_owned();
                    let public_id = format!(
                        "w:{}:{id}",
                        &hex::encode(Sha256::digest(target.as_bytes()))[..16]
                    );
                    if public_id.len() > 4096 {
                        self.hooks
                            .candidate_catalog_incomplete
                            .store(true, std::sync::atomic::Ordering::Release);
                        self.hooks
                            .candidate_epoch
                            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                        return;
                    }
                    script["script_id"] = json!(public_id);
                    script["cdp_script_id"] = json!(id);
                    script["target_id"] = json!(target);
                    script["target_type"] = json!("worker");
                    self.hooks
                        .candidate_epoch
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    self.update(|s| {
                        let scripts = s["scripts"].as_array_mut().unwrap();
                        scripts.retain(|v| v["script_id"] != script["script_id"]);
                        if scripts.len() >= 5000 {
                            self.hooks
                                .candidate_catalog_incomplete
                                .store(true, std::sync::atomic::Ordering::Release);
                            scripts.remove(0);
                        }
                        scripts.push(script);
                    });
                } else {
                    self.hooks
                        .candidate_catalog_incomplete
                        .store(true, std::sync::atomic::Ordering::Release);
                    self.hooks
                        .candidate_epoch
                        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                }
            }
            "Runtime.executionContextDestroyed" | "Runtime.executionContextsCleared" => {
                self.hooks
                    .candidate_epoch
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                self.update(|s| {
                    s["scripts"].as_array_mut().unwrap().retain(|script| {
                        script["target_id"] != target
                            || (message["method"] == "Runtime.executionContextDestroyed"
                                && script["execution_context_id"] != p["executionContextId"])
                    });
                });
            }
            "Debugger.paused" => {
                if !self.hook_pause(target, p.clone())
                    && let Ok(s) = self.hook_session(target).await
                {
                    tokio::spawn(async move {
                        let _ = s
                            .command("Debugger.resume", json!({}), Duration::from_secs(3))
                            .await;
                    });
                }
            }
            "Network.requestWillBeSent"
            | "Network.requestWillBeSentExtraInfo"
            | "Network.responseReceived" => {
                self.hook_network(target, message["method"].as_str().unwrap(), p)
                    .await
            }
            _ => (),
        }
    }
}

#[cfg(test)]
mod candidate_catalog_tests {
    use super::*;
    use clap::Parser;
    use std::sync::atomic::Ordering;
    #[tokio::test]
    async fn candidate_worker_catalog_preserves_other_contexts_and_taints_rejected_public_ids() {
        let debugger = Debugger::new(&crate::config::Options::parse_from(["test"]));
        for context in [1, 2] {
            debugger.worker_event("worker", json!({"method":"Debugger.scriptParsed", "params":{
                "scriptId":context.to_string(), "url":"http://localhost/worker.js", "executionContextId":context
            }})).await;
        }
        debugger.worker_event("worker", json!({"method":"Runtime.executionContextDestroyed","params":{"executionContextId":1}})).await;
        let snapshot = debugger.snapshot();
        assert_eq!(snapshot["scripts"].as_array().unwrap().len(), 1);
        assert_eq!(snapshot["scripts"][0]["execution_context_id"], 2);
        debugger
            .worker_event(
                "worker",
                json!({"method":"Debugger.scriptParsed","params":{
                    "scriptId":"a".repeat(4096),"url":"http://localhost/worker.js"
                }}),
            )
            .await;
        assert!(
            debugger
                .hooks
                .candidate_catalog_incomplete
                .load(Ordering::Acquire)
        );
    }
}
