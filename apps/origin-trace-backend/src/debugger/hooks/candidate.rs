//! An explicit, ephemeral bridge. CDP hashes remain opaque version tokens;
//! only SHA-256 of complete UTF-8 getScriptSource text crosses target lifetimes.
use super::*;
use sha2::{Digest, Sha256};

const LIMIT: usize = 2 * 1024 * 1024;
const SCAN_BYTES: usize = 8 * 1024 * 1024;
const SCAN_SCRIPTS: usize = 64;

fn lifetime(s: &Value) -> Value {
    json!([
        s["runtime_hooks"]["session_id"],
        s["request_interception"]["created_at_ms"],
        s["runtime_hooks"]["target_id"],
        s["target"]["id"],
        s["object_experiment"]["navigation_id"]
    ])
}
fn catalog(s: &Value, target: &Value) -> Vec<Value> {
    s["scripts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|script| {
            script["language"] == "JavaScript"
                && script.get("target_id").unwrap_or(&s["target"]["id"]) == target
        })
        .cloned()
        .collect()
}
fn external(script: &Value, s: &Value) -> bool {
    let address = script["url"].as_str().unwrap_or("");
    (address.starts_with("http://") || address.starts_with("https://"))
        && script["has_source_url"] != true
        && script["start_line"] == 0
        && script["start_column"] == 0
        && (script["target_type"] == "worker" || script["url"] != s["target"]["url"])
}
fn digest_matches(source: &str, r: &Value) -> bool {
    !source.starts_with('\u{feff}')
        && !source.contains('\u{fffd}')
        && source.len() <= LIMIT
        && r["source_bytes"].as_u64() == Some(source.len() as u64)
        && r["source_sha256"] == hex::encode(Sha256::digest(source.as_bytes()))
}
impl Debugger {
    pub(super) fn candidate_worker_admitted(document: &Value, bytes: usize) -> bool {
        document["schema"] == "reb-deobfuscator-worker-v1"
            && document["ok"] == true
            && document["source_bytes"].as_u64() == Some(bytes as u64)
            && document["function_location"]["candidate_eligible"] == true
            && [
                "function_declaration",
                "function_expression",
                "arrow_function",
                "method_definition",
            ]
            .contains(&document["function_location"]["kind"].as_str().unwrap_or(""))
    }

    pub(super) fn candidate_commit_current(s: &Value, guard: &Value, epoch: u64) -> bool {
        s["runtime_hooks"]["isolated"] == true
            && s["runtime_hooks"]["target_id"] == s["target"]["id"]
            && s["runtime_hooks"]["session_id"] == guard["session_id"]
            && s["request_interception"]["created_at_ms"] == guard["created_at_ms"]
            && s["object_experiment"]["navigation_id"] == guard["navigation_id"]
            && guard["epoch"].as_u64() == Some(epoch)
            && catalog(s, &guard["target_id"]).contains(&guard["script"])
    }

    pub(super) fn check_candidate_definition(&self, definition: &Value) -> Result<()> {
        if let Some(guard) = definition.get("candidate_guard")
            && (self
                .hooks
                .candidate_catalog_incomplete
                .load(Ordering::Acquire)
                || !Self::candidate_commit_current(
                    &self.snapshot(),
                    guard,
                    self.hooks.candidate_epoch.load(Ordering::Acquire),
                ))
        {
            return Err(Error::conflict(
                "Candidate source catalog changed. Disarm and bind again before using this candidate.",
            ));
        }
        Ok(())
    }
    fn candidate_owner(&self, r: &Value) -> Result<Value> {
        self.isolated_target("runtime_hooks", false)?;
        if self
            .hooks
            .candidate_catalog_incomplete
            .load(Ordering::Acquire)
        {
            return Err(Error::conflict(
                "Source catalog is incomplete after eviction or an unsupported descriptor. Create a fresh disposable context; uniqueness is unverified.",
            ));
        }
        let s = self.snapshot();
        if r["digest_version"] != "reb-live-script-utf8-v1"
            || r["session_id"] != s["runtime_hooks"]["session_id"]
            || r["created_at_ms"] != s["request_interception"]["created_at_ms"]
            || r["navigation_id"] != s["object_experiment"]["navigation_id"]
            || s["object_experiment"]["navigation_id"]
                .as_u64()
                .unwrap_or(0)
                == 0
            || s["object_experiment"]["state"] == "navigating"
        {
            return Err(Error::conflict(
                "Candidate experiment lifetime changed. Bind again explicitly.",
            ));
        }
        let target = &r["target_id"];
        if target != &s["runtime_hooks"]["target_id"]
            && !s["runtime_hooks"]["workers"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|w| &w["id"] == target)
        {
            return Err(Error::conflict(
                "Choose an attached target in this disposable context.",
            ));
        }
        Ok(s)
    }
    pub(super) async fn resolve_candidate(&self, r: &Value) -> Result<(Value, String)> {
        let epoch = self.hooks.candidate_epoch.load(Ordering::Acquire);
        let snapshot = self.candidate_owner(r)?;
        let scripts = catalog(&snapshot, &r["target_id"]);
        if scripts.is_empty() || scripts.len() > SCAN_SCRIPTS {
            return Err(Error::conflict(
                "Candidate source scan requires 1–64 scripts in the selected target; uniqueness is unverified.",
            ));
        }
        let mut total = 0;
        let mut found = None;
        for script in &scripts {
            total += script["length"].as_u64().unwrap_or(LIMIT as u64 + 1) as usize;
            if total > SCAN_BYTES {
                return Err(Error::conflict(
                    "Candidate source scan exceeds 8 MiB; uniqueness is unverified.",
                ));
            }
        }
        total = 0;
        for script in &scripts {
            let source = self.source(script["script_id"].as_str().unwrap()).await?;
            let current = self.candidate_owner(r)?;
            if self.hooks.candidate_epoch.load(Ordering::Acquire) != epoch
                || lifetime(&current) != lifetime(&snapshot)
                || catalog(&current, &r["target_id"]) != scripts
            {
                return Err(Error::conflict(
                    "Candidate target or sources changed during the scan.",
                ));
            }
            let text = source["source"]
                .as_str()
                .ok_or_else(|| Error::protocol("Candidate source is unavailable"))?;
            total += text.len();
            if source["truncated"] != false || total > SCAN_BYTES {
                return Err(Error::conflict(
                    "Candidate source scan is incomplete; uniqueness is unverified.",
                ));
            }
            if digest_matches(text, r) {
                if !external(script, &snapshot) {
                    return Err(Error::bad(
                        "Candidate requires external JavaScript without inline offsets or sourceURL.",
                    ));
                }
                if found.is_some() {
                    return Err(Error::conflict(
                        "Ambiguous candidate: identical bytes occur in multiple sources of this target.",
                    ));
                }
                found = Some((script.clone(), text.to_owned()));
            }
        }
        found.ok_or_else(|| Error::conflict("No exact candidate bytes in the selected target. Changed or missing source; URL matches are not used."))
    }
    pub(in crate::debugger) async fn bind_candidate(&self, r: &Value) -> Result<Value> {
        self.hooks_editable()?;
        if self.snapshot()["runtime_hooks"]["definitions"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|definition| definition.get("candidate_guard").is_some())
        {
            return Err(Error::conflict(
                "Remove the previous candidate observation hook before binding another. No definition was changed.",
            ));
        }
        let epoch = self.hooks.candidate_epoch.load(Ordering::Acquire);
        tokio::time::timeout(Duration::from_secs(15), async {
            let (script, source) = self.resolve_candidate(r).await?;
            let start = r["start_byte"].as_u64().unwrap() as usize;
            let end = r["end_byte"].as_u64().unwrap() as usize;
            if start >= end || source.get(start..end).is_none() {
                return Err(Error::bad("Candidate range is outside the original UTF-8 source."));
            }
            let location = coordinate(&source, &script, start)?;
            let mut guard = r.clone();
            guard["script"] = script.clone();
            guard["epoch"] = json!(epoch);
            self.add_hook_with_candidate(&json!({"label":"Field candidate · observe", "script_id":script["script_id"],
                "line":location["line"],"column":location["column"],"entry_enabled":false,"return_enabled":true,
                "entry_mode":"source","return_mode":"none"}), Some(&guard)).await
        }).await.map_err(|_| Error::conflict("Candidate binding exceeded its 15-second deadline. No hook was added."))?
    }
    pub(super) fn candidate_guard_current(
        &self,
        guard: &Value,
        script: &Value,
        source: &str,
    ) -> Result<()> {
        let s = self.candidate_owner(guard)?;
        if self.hooks.candidate_epoch.load(Ordering::Acquire)
            != guard["epoch"].as_u64().unwrap_or(u64::MAX)
            || &guard["script"] != script
            || !catalog(&s, &guard["target_id"]).contains(script)
            || !digest_matches(source, guard)
        {
            return Err(Error::conflict(
                "Candidate source or lifetime changed. No hook was added.",
            ));
        }
        Ok(())
    }
    pub(super) async fn verify_candidate_arm(&self, definition: &Value) -> Result<()> {
        let Some(guard) = definition.get("candidate_guard") else {
            return Ok(());
        };
        tokio::time::timeout(Duration::from_secs(15), async {
            let (script, source) = self.resolve_candidate(guard).await?;
            if script != guard["script"] {
                return Err(Error::conflict(
                    "Candidate script identity changed before arming.",
                ));
            }
            let f = self
                .locate_function(
                    &source,
                    &script,
                    definition["line"].as_u64().unwrap(),
                    definition["column"].as_u64().unwrap(),
                    Some(guard),
                )
                .await?;
            if f["start"] != definition["function_start"] || f["end"] != definition["function_end"]
            {
                return Err(Error::conflict("Candidate function changed before arming."));
            }
            let current = self.candidate_owner(guard)?;
            if !Self::candidate_commit_current(
                &current,
                guard,
                self.hooks.candidate_epoch.load(Ordering::Acquire),
            ) {
                return Err(Error::conflict("Candidate target changed before arming."));
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            Error::conflict(
                "Candidate verification exceeded its 15-second deadline; hooks were not armed.",
            )
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> Value {
        json!({"script_id":"reused","target_id":"page","language":"JavaScript","url":"http://localhost/source.js",
            "hash":"opaque-cdp-token","start_line":0,"start_column":0,"has_source_url":false,"length":40})
    }
    fn state() -> Value {
        json!({"runtime_hooks":{"isolated":true,"target_id":"page","session_id":4},
            "request_interception":{"created_at_ms":111},"object_experiment":{"navigation_id":2},
            "target":{"id":"page","url":"http://localhost/page"},"scripts":[source()]})
    }
    fn guard() -> Value {
        json!({"target_id":"page","session_id":4,"created_at_ms":111,"navigation_id":2,"epoch":7,"script":source()})
    }
    #[test]
    fn candidate_epoch_lifetime_and_exact_script_must_all_match() {
        assert!(Debugger::candidate_commit_current(&state(), &guard(), 7));
        assert!(!Debugger::candidate_commit_current(&state(), &guard(), 8));
        for (group, key, value) in [
            ("runtime_hooks", "session_id", json!(5)),
            ("runtime_hooks", "isolated", json!(false)),
            ("request_interception", "created_at_ms", json!(112)),
            ("object_experiment", "navigation_id", json!(3)),
            ("target", "id", json!("other")),
        ] {
            let mut s = state();
            s[group][key] = value;
            assert!(
                !Debugger::candidate_commit_current(&s, &guard(), 7),
                "{group}.{key}"
            );
        }
        for key in ["hash", "execution_context_id", "script_id", "target_id"] {
            let mut s = state();
            s["scripts"][0][key] = json!("changed");
            assert!(
                !Debugger::candidate_commit_current(&s, &guard(), 7),
                "{key}"
            );
        }
    }
    #[test]
    fn digest_is_utf8_text_not_cdp_hash_and_encoding_is_narrow() {
        let text = "function f(){return '雪';}\r\n";
        let r = json!({"source_bytes":text.len(),"source_sha256":hex::encode(Sha256::digest(text.as_bytes()))});
        assert!(digest_matches(text, &r));
        assert!(!digest_matches(&text.replace("\r\n", "\n"), &r));
        assert!(!digest_matches(
            &format!("{text}// changed at the same URL"),
            &r
        ));
        for text in ["\u{feff}x", "\u{fffd}"] {
            assert!(!digest_matches(
                text,
                &json!({"source_bytes":text.len(),"source_sha256":hex::encode(Sha256::digest(text.as_bytes()))})
            ));
        }
        assert!(external(&source(), &state()));
        for (key, value) in [
            ("start_line", json!(1)),
            ("start_column", json!(1)),
            ("has_source_url", json!(true)),
            ("url", json!("http://localhost/page")),
            ("url", json!("eval-source")),
        ] {
            let mut source = source();
            source[key] = value;
            assert!(!external(&source, &state()), "{key}");
        }
    }
    #[test]
    fn action_contract_rejects_original_ids_missing_lifetime_and_oversized_ranges() {
        let r = json!({"action":"bind_runtime_candidate","digest_version":"reb-live-script-utf8-v1",
            "source_sha256":"a".repeat(64),"source_bytes":40,"start_byte":1,"end_byte":2,
            "target_id":"page","session_id":4,"created_at_ms":111,"navigation_id":2});
        assert!(validation::schema("DebuggerAction", &r, 400).is_ok());
        for key in [
            "target_id",
            "source_sha256",
            "created_at_ms",
            "navigation_id",
        ] {
            let mut invalid = r.clone();
            invalid.as_object_mut().unwrap().remove(key);
            assert!(
                validation::schema("DebuggerAction", &invalid, 400).is_err(),
                "{key}"
            );
        }
        let mut invalid = r.clone();
        invalid["script_id"] = json!("original");
        assert!(validation::schema("DebuggerAction", &invalid, 400).is_err());
        invalid = r;
        invalid["source_bytes"] = json!(LIMIT + 1);
        assert!(validation::schema("DebuggerAction", &invalid, 400).is_err());
    }
    #[tokio::test]
    async fn rejected_and_evicted_catalogs_never_claim_unique_candidate_coverage() {
        use clap::Parser;
        let options = crate::config::Options::parse_from(["test"]);
        let debugger = Debugger::new(&options);
        assert!(
            !debugger
                .hooks
                .candidate_catalog_incomplete
                .load(Ordering::Acquire)
        );
        debugger.event(json!({"method":"Debugger.scriptParsed","params":{"scriptId":"bad","url":"x".repeat(65537)}})).await;
        assert!(
            debugger
                .hooks
                .candidate_catalog_incomplete
                .load(Ordering::Acquire)
        );
        let epoch = debugger.hooks.candidate_epoch.load(Ordering::Acquire);
        assert!(epoch > 0);
        debugger
            .event(json!({"method":"Runtime.executionContextsCleared","params":{}}))
            .await;
        assert!(
            debugger
                .hooks
                .candidate_catalog_incomplete
                .load(Ordering::Acquire),
            "context clearing does not repair historical completeness"
        );
        let debugger = Debugger::new(&options);
        debugger.update(|s| {
            s["scripts"] = json!(
                (0..5000)
                    .map(|id| json!({"script_id":id.to_string()}))
                    .collect::<Vec<_>>()
            )
        });
        debugger.event(json!({"method":"Debugger.scriptParsed","params":{"scriptId":"new","url":"http://localhost/new.js","hash":"opaque"}})).await;
        assert!(
            debugger
                .hooks
                .candidate_catalog_incomplete
                .load(Ordering::Acquire)
        );
        assert_eq!(
            debugger.snapshot()["scripts"].as_array().unwrap().len(),
            5000
        );
    }
    #[test]
    fn candidate_bridge_refuses_old_missing_or_mismatched_worker_eligibility() {
        let valid = json!({"schema":"reb-deobfuscator-worker-v1","ok":true,"source_bytes":40,
            "function_location":{"kind":"function_declaration","candidate_eligible":true}});
        assert!(Debugger::candidate_worker_admitted(&valid, 40));
        assert!(!Debugger::candidate_worker_admitted(&valid, 41));
        for flag in [Value::Null, json!(false), json!("true")] {
            let mut response = valid.clone();
            response["function_location"]["candidate_eligible"] = flag;
            assert!(!Debugger::candidate_worker_admitted(&response, 40));
        }
        let mut legacy = valid.clone();
        legacy["function_location"]
            .as_object_mut()
            .unwrap()
            .remove("candidate_eligible");
        assert!(!Debugger::candidate_worker_admitted(&legacy, 40));
        let mut invalid = valid;
        invalid["function_location"]["kind"] = json!("generator_function");
        assert!(!Debugger::candidate_worker_admitted(&invalid, 40));
    }
    #[tokio::test]
    async fn page_context_events_never_erase_worker_catalog_with_reused_context_ids() {
        use clap::Parser;
        let debugger = Debugger::new(&crate::config::Options::parse_from(["test"]));
        debugger.update(|s| s["scripts"] = json!([
            {"script_id":"page-one","execution_context_id":1},
            {"script_id":"page-two","execution_context_id":2},
            {"script_id":"worker-one","target_id":"worker","target_type":"worker","execution_context_id":1}
        ]));
        debugger.event(json!({"method":"Runtime.executionContextDestroyed","params":{"executionContextId":1}})).await;
        assert_eq!(debugger.snapshot()["scripts"].as_array().unwrap().len(), 2);
        debugger
            .event(json!({"method":"Runtime.executionContextsCleared","params":{}}))
            .await;
        assert_eq!(
            debugger.snapshot()["scripts"],
            json!([
                {"script_id":"worker-one","target_id":"worker","target_type":"worker","execution_context_id":1}
            ])
        );
    }
}
