//! Captured Hooks are explicit live-page mutations, not isolated-world execution.
//! A tab id alone is not an owner: reconnects, document replacement and source
//! changes must retire an ordinary hook just as they retire a bound candidate.
use super::*;
use sha2::{Digest, Sha256};

fn stale() -> Error {
    Error::conflict(
        "The captured target, document, source or hook session changed. Select the source again explicitly.",
    )
}
fn document(s: &Value) -> Value {
    json!({"instance_id":s["network"]["instance_id"],"connection_epoch":s["network"]["capture_epoch"],
        "document_epoch":s["target_document_epoch"],"target_id":s["target"]["id"]})
}
fn document_current(s: &Value, owner: &Value) -> bool {
    owner.is_object()
        && owner["instance_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
        && owner["connection_epoch"].as_u64().is_some()
        && owner["document_epoch"].as_u64().is_some()
        && owner["target_id"].as_str().is_some_and(|id| !id.is_empty())
        && *owner == document(s)
        && ["running", "paused"].contains(&s["state"].as_str().unwrap_or(""))
}
impl Debugger {
    pub(super) fn prepare_hook_target(&self, request: &Value) -> Result<Option<Value>> {
        if self.experiment.context().is_some() {
            self.isolated_target("runtime_hooks", false)?;
            if request.get("captured_source").is_some() {
                return Err(stale());
            }
            return Ok(None);
        }
        let s = self.snapshot();
        let requested = &request["captured_source"];
        let owner = &requested["owner"];
        if !document_current(&s, owner)
            || request["expected_session_id"] != s["runtime_hooks"]["session_id"]
            || requested["script_id"] != request["script_id"]
        {
            return Err(stale());
        }
        let script = s["scripts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|script| {
                script["script_id"] == requested["script_id"]
                    && script["language"] == "JavaScript"
                    && script["target_type"] != "worker"
                    && script.get("target_id").unwrap_or(&s["target"]["id"]) == &owner["target_id"]
                    && script["hash"].as_str().is_some_and(|hash| !hash.is_empty())
                    && script["hash"] == requested["source_hash"]
                    && script["execution_context_id"] == requested["execution_context_id"]
            })
            .ok_or_else(stale)?;
        if s["runtime_hooks"]["isolated"] == true {
            if s["runtime_hooks"]["captured_owner"] != *owner {
                return Err(stale());
            }
        } else {
            let session = self.experiment.next_session();
            let mut adopted = false;
            self.update(|current| {
                if !document_current(current, owner)
                    || current["runtime_hooks"]["session_id"] != request["expected_session_id"]
                    || !current["scripts"].as_array().unwrap().contains(script)
                {
                    return;
                }
                adopted = true;
                let hooks = &mut current["runtime_hooks"];
                hooks["isolated"] = json!(true); // Legacy admission flag, not a sandbox claim.
                hooks["captured_owner"] = owner.clone();
                hooks["target_id"] = owner["target_id"].clone();
                hooks["session_id"] = json!(session);
                hooks["state"] = json!("ready");
                hooks["message"] = json!("Hooks target the selected live captured document. Arming may mutate its page, cookies or storage; no isolated sandbox is used.");
            });
            if !adopted {
                return Err(stale());
            }
        }
        Ok(Some(owner.clone()))
    }
    pub(super) fn check_captured_action(&self, request: &Value, cleanup: bool) -> Result<()> {
        let s = self.snapshot();
        // A delayed captured cleanup must not become an unscoped disposable
        // cleanup after another action creates a replacement context.
        if request
            .get("expected_session_id")
            .is_some_and(|id| *id != s["runtime_hooks"]["session_id"])
        {
            return Err(stale());
        }
        if self.experiment.context().is_some() {
            return if request.get("captured_owner").is_some() {
                Err(stale())
            } else {
                Ok(())
            };
        }
        if s["runtime_hooks"]["session_id"].as_u64().unwrap_or(0) == 0 && cleanup {
            return Ok(());
        }
        if request["expected_session_id"] != s["runtime_hooks"]["session_id"] {
            return Err(stale());
        }
        if !cleanup
            && (!document_current(&s, &s["runtime_hooks"]["captured_owner"])
                || request["captured_owner"] != s["runtime_hooks"]["captured_owner"]
                || request["expected_definition_ids"]
                    != json!(
                        s["runtime_hooks"]["definitions"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|d| d["id"].clone())
                            .collect::<Vec<_>>()
                    ))
        {
            return Err(stale());
        }
        Ok(())
    }
    pub(super) fn cancel_hook_action_for_session(&self, request: &Value) -> Result<()> {
        // Session replacement commits through update(), under this same lock.
        // Do not let a validated-but-delayed cleanup cancel its successor's arm.
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let hooks = &state["runtime_hooks"];
        let expected = request.get("expected_session_id");
        if expected.is_some_and(|id| *id != hooks["session_id"])
            || (expected.is_none() && !hooks["captured_owner"].is_null())
        {
            return Err(stale());
        }
        self.hooks.epoch.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    pub(super) fn make_captured_guard(
        &self,
        owner: &Value,
        script: &Value,
        source: &str,
    ) -> Result<Value> {
        let guard = json!({"owner":owner,"script":script,"session_id":self.snapshot()["runtime_hooks"]["session_id"],
            "source_sha256":hex::encode(Sha256::digest(source.as_bytes()))});
        self.check_captured_guard(&guard)?;
        Ok(guard)
    }
    pub(super) fn captured_guard_current(s: &Value, guard: &Value) -> bool {
        document_current(s, &guard["owner"])
            && s["runtime_hooks"]["captured_owner"] == guard["owner"]
            && s["runtime_hooks"]["session_id"] == guard["session_id"]
            && s["runtime_hooks"]["target_id"] == guard["owner"]["target_id"]
            && s["scripts"]
                .as_array()
                .is_some_and(|scripts| scripts.contains(&guard["script"]))
    }
    pub(super) fn check_captured_guard(&self, guard: &Value) -> Result<()> {
        if self.experiment.context().is_some()
            || !Self::captured_guard_current(&self.snapshot(), guard)
        {
            return Err(stale());
        }
        Ok(())
    }
    pub(super) async fn verify_captured_arm(&self, definition: &Value) -> Result<()> {
        let Some(guard) = definition.get("captured_guard") else {
            return Ok(());
        };
        self.check_captured_guard(guard)?;
        let source = self
            .source(definition["script_id"].as_str().ok_or_else(stale)?)
            .await?;
        self.check_captured_guard(guard)?;
        if source["truncated"] == true
            || source["source"].as_str().is_none_or(|text| {
                guard["source_sha256"] != hex::encode(Sha256::digest(text.as_bytes()))
            })
        {
            return Err(stale());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt;
    const SOURCE: &str = "function f(){return 1;}";
    struct Fixture {
        dir: tempfile::TempDir,
        debugger: Arc<Debugger>,
        session: Session,
    }
    impl Fixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let transport = dir.path().join("transport");
            let parser = dir.path().join("parser");
            std::fs::write(dir.path().join("source"), SOURCE).unwrap();
            // Match repository Python checks without relying on a system shim.
            // Resolve before the parser worker clears its environment; do not
            // warm up Python or alter the production transport's startup budget.
            let interpreter =
                std::env::split_paths(&std::env::var_os("PATH").expect("Python PATH"))
                    .map(|directory| directory.join("python3"))
                    .find(|path| worker::executable(path))
                    .expect("Fixture requires python3 on PATH")
                    .canonicalize()
                    .unwrap();
            let python = r#"import sys,json,struct,pathlib,time
root=pathlib.Path(__file__).parent
inp=sys.stdin.buffer; out=sys.stdout.buffer
def emit(v):
 b=b'' if v is None else json.dumps(v).encode();out.write(b'REB\x01'+struct.pack('>I',len(b))+b);out.flush()
emit(None)
while True:
 h=inp.read(8)
 if not h:break
 q=json.loads(inp.read(struct.unpack('>I',h[4:])[0]));m=q['method']
 with (root/'commands').open('a') as log:log.write(json.dumps(q)+'\n')
 r={}
 if m=='Debugger.getScriptSource':
  (root/'source_seen').touch()
  while (root/'source_gate').exists():time.sleep(.005)
  r={'scriptSource':(root/'source').read_text()}
 if m=='Debugger.getPossibleBreakpoints':r={'locations':[{'scriptId':'7','lineNumber':0,'columnNumber':13,'type':'return'}]}
 if m=='Debugger.setBreakpoint':
  (root/'point_seen').touch()
  while (root/'point_gate').exists():time.sleep(.005)
  r={'breakpointId':'owned-point'}
 if m=='Debugger.removeBreakpoint' and (root/'fail_remove').exists():emit({'id':q['id'],'error':{'message':'fixture removal failure'}});continue
 emit({'id':q['id'],'result':r})
"#;
            let parser_source = format!(
                "import sys,json,pathlib,time\nsys.stdin.read()\nr=pathlib.Path(__file__).parent\n(r/'parser_seen').touch()\nwhile (r/'parser_gate').exists():time.sleep(.005)\nprint(json.dumps({{\"schema\":\"reb-deobfuscator-worker-v1\",\"ok\":True,\"function_location\":{{\"kind\":\"function_declaration\",\"start\":0,\"end\":{},\"body_start\":13}}}}))\n",
                SOURCE.len()
            );
            let quote = |path: &std::path::Path| {
                format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
            };
            for (path, body) in [(&transport, python), (&parser, parser_source.as_str())] {
                let source = path.with_extension("py");
                std::fs::write(&source, body).unwrap();
                // exec keeps the interpreter as the owned/reaped child, even
                // when the worker's environment deliberately contains no PATH.
                std::fs::write(
                    path,
                    format!(
                        "#!/bin/sh\nexec {} {} \"$@\"\n",
                        quote(&interpreter),
                        quote(&source)
                    ),
                )
                .unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let mut options = crate::config::Options::parse_from(["test"]);
            options.deobfuscator = Some(parser);
            let debugger = Debugger::new(&options);
            let (connection, _events) =
                super::super::super::connection::Connection::open(&transport, "ws://127.0.0.1:1")
                    .await
                    .unwrap();
            *debugger.connection.lock().await = Some(connection.clone());
            debugger.update(|s| {
                s["state"] = json!("running");
                s["target"]["id"] = json!("page-A");
                s["target_document_epoch"] = json!(1);
            });
            debugger.event(json!({"method":"Debugger.scriptParsed","params":{"scriptId":"7","url":"https://example.test/a.js","hash":"cdp-hash","executionContextId":3,"startLine":0,"startColumn":0,"endLine":0,"endColumn":SOURCE.len(),"scriptLanguage":"JavaScript","length":SOURCE.len()}})).await;
            Self {
                dir,
                debugger,
                session: Session {
                    connection,
                    id: None,
                },
            }
        }
        fn add(&self) -> Value {
            let s = self.debugger.snapshot();
            let script = &s["scripts"][0];
            json!({"action":"add_runtime_hook","label":"Captured","script_id":"7","line":0,"column":13,"entry_enabled":true,"return_enabled":false,
                "expected_session_id":s["runtime_hooks"]["session_id"],"captured_source":{"owner":document(&s),"script_id":"7","source_hash":script["hash"],"execution_context_id":3}})
        }
        fn arm(&self) -> Value {
            let s = self.debugger.snapshot();
            json!({"action":"arm_runtime_hooks","confirmed":true,"expected_session_id":s["runtime_hooks"]["session_id"],"captured_owner":document(&s),"expected_definition_ids":s["runtime_hooks"]["definitions"].as_array().unwrap().iter().map(|d|d["id"].clone()).collect::<Vec<_>>()})
        }
        fn commands(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("commands")).unwrap_or_default()
        }
        async fn seen(&self, name: &str) {
            tokio::time::timeout(Duration::from_secs(3), async {
                while !self.dir.path().join(name).exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
    }
    #[tokio::test]
    async fn captured_add_arm_cleanup_and_reuse_use_production_actions() {
        let f = Fixture::new().await;
        let d = &f.debugger;
        let first = d.action(&f.add()).await.unwrap();
        assert_eq!(
            first["runtime_hooks"]["definitions"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(f.commands().contains("getScriptSource"));
        assert!(!f.commands().contains("setBreakpoint"));
        assert!(!f.commands().contains("createIsolatedWorld"));
        let session = first["runtime_hooks"]["session_id"].clone();
        let mut unconfirmed = f.arm();
        unconfirmed["confirmed"] = json!(false);
        assert!(d.action(&unconfirmed).await.is_err());
        d.action(&f.arm()).await.unwrap();
        assert_eq!(d.snapshot()["runtime_hooks"]["state"], "armed");
        std::fs::write(f.dir.path().join("fail_remove"), "").unwrap();
        let erase =
            json!({"action":"disarm_runtime_hooks","erase":true,"expected_session_id":session});
        assert!(d.action(&erase).await.is_err());
        assert_eq!(
            d.snapshot()["runtime_hooks"]["active_points"],
            1,
            "Failed removal stays retryable"
        );
        assert!(
            d.action(&f.add()).await.is_err(),
            "Residual points block definition edits"
        );
        assert!(d.hook_pause(
            "page-A",
            f.session.clone(),
            json!({"reason":"other","hitBreakpoints":["owned-point"]})
        ));
        let mut receiver = d.hooks.receiver.lock().unwrap().take().unwrap();
        let residual = receiver.recv().await.unwrap();
        assert!(
            !residual.executable,
            "Failed cleanup must not authorize another execution"
        );
        d.process_hook_pause(&residual).await.unwrap();
        d.finish_hook_pause(&residual).await;
        assert!(!f.commands().contains("evaluateOnCallFrame"));
        d.event(json!({"method":"Page.frameNavigated","params":{"frame":{"id":"main"}}}))
            .await;
        assert_eq!(
            d.snapshot()["runtime_hooks"]["state"],
            "error",
            "Navigation cannot hide failed cleanup"
        );
        assert_eq!(d.snapshot()["runtime_hooks"]["active_points"], 1);
        std::fs::remove_file(f.dir.path().join("fail_remove")).unwrap();
        d.update(|s| {
            s["state"] = json!("waiting");
            s["target"]["id"] = json!("page-B");
            s["scripts"] = json!([]);
        });
        d.action(&erase).await.unwrap();
        assert_eq!(d.snapshot()["runtime_hooks"]["state"], "disposed");
        assert!(!f.commands().contains("disposeBrowserContext"));
        d.update(|s| {
            s["state"] = json!("running");
            s["target"]["id"] = json!("page-A");
            s["scripts"] = json!([
                first["runtime_hooks"]["definitions"][0]["captured_guard"]["script"].clone()
            ]);
        });
        d.action(&f.add()).await.unwrap();
        assert!(
            d.snapshot()["runtime_hooks"]["session_id"]
                .as_u64()
                .unwrap()
                > session.as_u64().unwrap()
        );
        assert!(
            d.action(&erase).await.is_err(),
            "Old erase cannot erase a replacement session"
        );
        f.session.connection.close().await;
    }
    #[tokio::test]
    async fn captured_add_rejects_reused_script_id_and_async_document_or_source_change() {
        for phase in ["before", "source", "parser"] {
            let f = Fixture::new().await;
            let request = f.add();
            if phase == "before" {
                f.debugger.update(|s| s["target"]["id"] = json!("page-B"));
                assert!(f.debugger.action(&request).await.is_err());
                assert!(f.commands().is_empty());
            } else {
                let gate = f.dir.path().join(format!("{phase}_gate"));
                std::fs::write(&gate, "").unwrap();
                let d = f.debugger.clone();
                let action = tokio::spawn(async move { d.action(&request).await });
                f.seen(&format!("{phase}_seen")).await;
                if phase == "source" {
                    f.debugger
                        .event(json!({"method":"Page.documentOpened","params":{}}))
                        .await;
                } else {
                    f.debugger
                        .update(|s| s["scripts"][0]["hash"] = json!("replacement-source"));
                }
                std::fs::remove_file(gate).unwrap();
                assert!(action.await.unwrap().is_err());
                assert_eq!(
                    f.debugger.snapshot()["runtime_hooks"]["definitions"],
                    json!([])
                );
                assert!(!f.commands().contains("setBreakpoint"));
            }
            f.session.connection.close().await;
        }
    }
    #[tokio::test]
    async fn captured_arm_revalidates_full_source_and_exact_consent() {
        let f = Fixture::new().await;
        f.debugger.action(&f.add()).await.unwrap();
        let request = f.arm();
        let mut wrong = request.clone();
        wrong["expected_definition_ids"] = json!([]);
        assert!(f.debugger.action(&wrong).await.is_err());
        std::fs::write(f.dir.path().join("source"), "function f(){return 2;}").unwrap();
        assert!(
            f.debugger.action(&request).await.is_err(),
            "Unchanged advertised CDP hash must not hide altered source bytes"
        );
        assert!(!f.commands().contains("setBreakpoint"));
        f.session.connection.close().await;
    }
    #[test]
    fn captured_cleanup_replacement_between_validation_and_cancellation_preserves_new_epoch() {
        let d = Debugger::new(&crate::config::Options::parse_from(["test"]));
        d.update(|s| {
            s["runtime_hooks"]["session_id"] = json!(1);
            s["runtime_hooks"]["captured_owner"] = json!({"target_id":"page-A"});
        });
        let old = json!({"expected_session_id":1});
        d.check_captured_action(&old, true).unwrap();
        // Force the reviewer's exact interleaving: initial validation succeeds,
        // then another action installs the successor before cancellation.
        d.update(|s| s["runtime_hooks"]["session_id"] = json!(2));
        d.hooks.epoch.store(17, Ordering::Release);
        assert!(d.cancel_hook_action_for_session(&old).is_err());
        assert_eq!(d.hooks.epoch.load(Ordering::Acquire), 17);
        assert!(d.cancel_hook_action_for_session(&json!({})).is_err());
        assert_eq!(d.hooks.epoch.load(Ordering::Acquire), 17);
        d.cancel_hook_action_for_session(&json!({"expected_session_id":2}))
            .unwrap();
        assert_eq!(
            d.hooks.epoch.load(Ordering::Acquire),
            18,
            "Current cleanup still cancels an in-flight arm"
        );
    }

    #[tokio::test]
    async fn captured_cleanup_rechecks_session_after_joining_action_serialization() {
        for erase in [false, true] {
            let f = Fixture::new().await;
            f.debugger.action(&f.add()).await.unwrap();
            let old = f.debugger.snapshot()["runtime_hooks"]["session_id"].clone();
            let lock = f.debugger.actions.lock().await;
            let d = f.debugger.clone();
            let erase = tokio::spawn(async move {
                d.action(
                &json!({"action":"disarm_runtime_hooks","erase":erase,"expected_session_id":old}),
            )
            .await
            });
            tokio::task::yield_now().await;
            // Model an action that owns the mutex completing a replacement session.
            f.debugger
                .update(|s| s["runtime_hooks"]["session_id"] = json!(99));
            drop(lock);
            assert!(erase.await.unwrap().is_err());
            assert_eq!(f.debugger.snapshot()["runtime_hooks"]["session_id"], 99);
            assert_eq!(
                f.debugger.snapshot()["runtime_hooks"]["definitions"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            f.session.connection.close().await;
        }
    }

    #[tokio::test]
    async fn captured_old_connection_events_cannot_repopulate_new_catalog_or_pause() {
        let old = Fixture::new().await;
        let replacement = Fixture::new().await;
        *old.debugger.connection.lock().await = Some(replacement.session.connection.clone());
        old.debugger.update(|s| {
            s["target"]["id"] = json!("page-B");
            s["scripts"] = json!([]);
        });
        for message in [
            json!({"method":"Debugger.scriptParsed","params":{"scriptId":"old","url":"https://example.test/old.js"}}),
            json!({"method":"Debugger.paused","params":{"reason":"other","callFrames":[],"hitBreakpoints":[]}}),
            json!({"method":"Runtime.executionContextsCleared","params":{}}),
            json!({"method":"Page.frameNavigated","params":{"frame":{"id":"old","url":"https://example.test/old"}}}),
        ] {
            let before = old.debugger.snapshot();
            old.debugger
                .event_from(message, Some(old.session.clone()))
                .await;
            assert_eq!(old.debugger.snapshot(), before);
        }
        let before = old.debugger.snapshot();
        old.debugger
            .connection_failed(
                &old.session.connection,
                &Error::conflict("late old transport failure"),
            )
            .await;
        assert_eq!(
            old.debugger.snapshot(),
            before,
            "Old transport failure cannot clear the replacement pause state"
        );
        old.session.connection.close().await;
        replacement.session.connection.close().await;
    }

    #[tokio::test]
    async fn captured_partial_arm_retains_failed_cleanup_until_explicit_retry() {
        let f = Fixture::new().await;
        f.debugger.action(&f.add()).await.unwrap();
        std::fs::write(f.dir.path().join("point_gate"), "").unwrap();
        std::fs::write(f.dir.path().join("fail_remove"), "").unwrap();
        let request = f.arm();
        let d = f.debugger.clone();
        let arming = tokio::spawn(async move { d.action(&request).await });
        f.seen("point_seen").await;
        f.debugger.update(|s| s["target_document_epoch"] = json!(2));
        std::fs::remove_file(f.dir.path().join("point_gate")).unwrap();
        assert!(arming.await.unwrap().is_err());
        assert_eq!(f.debugger.snapshot()["runtime_hooks"]["active_points"], 1);
        assert_eq!(f.debugger.snapshot()["runtime_hooks"]["state"], "error");
        std::fs::remove_file(f.dir.path().join("fail_remove")).unwrap();
        let session = f.debugger.snapshot()["runtime_hooks"]["session_id"].clone();
        f.debugger.action(&json!({"action":"disarm_runtime_hooks","erase":true,"expected_session_id":session})).await.unwrap();
        assert_eq!(f.debugger.snapshot()["runtime_hooks"]["active_points"], 0);
        f.session.connection.close().await;
    }

    #[tokio::test]
    async fn captured_pause_never_claims_mixed_or_resumes_replaced_pause() {
        let f = Fixture::new().await;
        f.debugger.action(&f.add()).await.unwrap();
        f.debugger.action(&f.arm()).await.unwrap();
        let d = &f.debugger;
        assert!(!d.hook_pause(
            "page-A",
            f.session.clone(),
            json!({"reason":"other","hitBreakpoints":["owned-point","user-point"]})
        ));
        assert!(d.hook_pause(
            "page-A",
            f.session.clone(),
            json!({"reason":"other","hitBreakpoints":["owned-point"]})
        ));
        let mut receiver = d.hooks.receiver.lock().unwrap().take().unwrap();
        let old = receiver.recv().await.unwrap();
        assert!(!d.hook_pause(
            "page-A",
            f.session.clone(),
            json!({"reason":"exception","hitBreakpoints":[]})
        ));
        d.finish_hook_pause(&old).await;
        assert!(!f.commands().contains("Debugger.resume"));
        assert!(d.hook_pause(
            "page-A",
            f.session.clone(),
            json!({"reason":"other","hitBreakpoints":["owned-point"]})
        ));
        let current = receiver.recv().await.unwrap();
        d.finish_hook_pause(&current).await;
        assert_eq!(f.commands().matches("Debugger.resume").count(), 1);
        f.session.connection.close().await;
    }
}
