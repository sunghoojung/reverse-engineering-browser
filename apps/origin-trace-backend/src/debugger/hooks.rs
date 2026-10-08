mod candidate;
use super::{Debugger, parse, requests, workers::Session};
use crate::{
    error::{Error, Result},
    provenance, validation, worker,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{process::Command, sync::mpsc};
pub(super) struct Hooks {
    next: AtomicU64,
    hit: AtomicU64,
    epoch: AtomicU64,
    pub(super) candidate_epoch: AtomicU64,
    pub(super) candidate_catalog_incomplete: AtomicBool,
    candidate_sources: Mutex<BTreeMap<String, u64>>,
    candidate_source_sequence: AtomicU64,
    points: Mutex<BTreeMap<(String, String), Value>>,
    queue: mpsc::Sender<Pause>,
    receiver: Mutex<Option<mpsc::Receiver<Pause>>>,
    execution: tokio::sync::Mutex<()>,
}
struct Pause {
    target: String,
    params: Value,
    matches: Vec<Value>,
    epoch: u64,
}
impl Hooks {
    // Called inside the debugger state edit that changes this target's catalog.
    // No revision lock is held across an await or while acquiring state.
    pub(super) fn candidate_source_changed(&self, target: &str) {
        let mut revisions = self
            .candidate_sources
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let next = self
            .candidate_source_sequence
            .load(Ordering::Relaxed)
            .checked_add(1);
        if target.is_empty()
            || (!revisions.contains_key(target) && revisions.len() >= 9)
            || next.is_none()
        {
            self.candidate_catalog_incomplete
                .store(true, Ordering::Release);
            self.candidate_epoch.fetch_add(1, Ordering::AcqRel);
            return;
        }
        let next = next.unwrap();
        self.candidate_source_sequence
            .store(next, Ordering::Relaxed);
        revisions.insert(target.to_owned(), next);
    }
    pub(super) fn candidate_source_revision(&self, target: &str) -> Option<u64> {
        self.candidate_sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(target)
            .copied()
    }
    pub(super) fn candidate_source_removed(&self, target: &str) {
        self.candidate_sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(target);
    }
    pub(super) fn candidate_sources_reset(&self) {
        self.candidate_sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
    pub fn new() -> Self {
        let (queue, receiver) = mpsc::channel(2);
        Self {
            next: AtomicU64::new(1),
            hit: AtomicU64::new(1),
            epoch: AtomicU64::new(0),
            candidate_epoch: AtomicU64::new(0),
            candidate_catalog_incomplete: AtomicBool::new(false),
            candidate_sources: Mutex::new(BTreeMap::new()),
            candidate_source_sequence: AtomicU64::new(0),
            points: Mutex::new(BTreeMap::new()),
            queue,
            receiver: Mutex::new(Some(receiver)),
            execution: tokio::sync::Mutex::new(()),
        }
    }
}
fn source_label(s: &str) -> String {
    if s.is_empty() {
        return "(anonymous script)".into();
    }
    if s.starts_with("data:") {
        return "data:(inline script)".into();
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return requests::redacted(s);
    }
    let s = s
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .to_owned();
    validation::truncate(&s, 8192)
}
fn preview(v: &Value, capture: bool) -> Value {
    let Some(mut p) = parse::remote(v) else {
        return Value::Null;
    };
    let object = p.as_object_mut().unwrap();
    object.remove("object_id");
    object.remove("preview");
    object.insert(
        "string_sha256".into(),
        if capture && v["type"] == "string" {
            provenance::project(&json!({"operation":"string_digest","value":v["value"]}))
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        },
    );
    for key in ["value", "description", "unserializable_value", "class_name"] {
        if let Some(text) = object[key].as_str() {
            let truncated = text.len() > 512;
            let value = validation::truncate(text, 512);
            object.insert(key.into(), json!(value));
            if key == "value" && truncated {
                object.insert("value_truncated".into(), json!(true));
            }
        }
    }
    p
}
fn coordinate(source: &str, script: &Value, offset: usize) -> Result<Value> {
    let prefix = source
        .get(..offset)
        .ok_or_else(|| Error::protocol("Function locator split a UTF-8 character"))?;
    let line = prefix.bytes().filter(|b| *b == b'\n').count() as u64;
    let column = prefix.rsplit('\n').next().unwrap().encode_utf16().count() as u64;
    Ok(
        json!({"line":script["start_line"].as_u64().unwrap()+line,"column":column+if line==0 {script["start_column"].as_u64().unwrap()} else {0}}),
    )
}
impl Debugger {
    pub(super) fn hooks_editable(&self) -> Result<()> {
        self.isolated_target("runtime_hooks", false)?;
        if ["arming", "armed", "handling", "stopping"].contains(
            &self.snapshot()["runtime_hooks"]["state"]
                .as_str()
                .unwrap_or(""),
        ) {
            return Err(Error::conflict(
                "Disarm Runtime Hooks before changing definitions",
            ));
        }
        Ok(())
    }
    async fn locate_function(
        &self,
        source: &str,
        script: &Value,
        line: u64,
        column: u64,
        candidate: Option<&Value>,
    ) -> Result<Value> {
        let relative = line
            .checked_sub(script["start_line"].as_u64().unwrap())
            .ok_or_else(|| Error::bad("Hook cursor is outside the script"))?
            as usize;
        let lines = source.split('\n').collect::<Vec<_>>();
        let current = lines
            .get(relative)
            .ok_or_else(|| Error::bad("Hook cursor is outside the script"))?;
        let column = column
            .checked_sub(if relative == 0 {
                script["start_column"].as_u64().unwrap()
            } else {
                0
            })
            .ok_or_else(|| Error::bad("Hook cursor is outside the script"))?
            as usize;
        let mut units = 0;
        let mut byte = None;
        for (at, c) in current.char_indices() {
            if units == column {
                byte = Some(at);
                break;
            }
            units += c.len_utf16();
            if units > column {
                return Err(Error::bad("Hook cursor splits a UTF-16 character"));
            }
        }
        let byte = byte.ok_or_else(|| Error::bad("Hook cursor must point inside a function"))?;
        let offset = lines
            .iter()
            .take(relative)
            .map(|l| l.len() + 1)
            .sum::<usize>()
            + byte;
        let path = self.options.worker(
            &self.options.deobfuscator,
            "OriginTraceDeobfuscator",
            "apps/deobfuscator-worker/target/debug/reb-deobfuscator-worker",
        );
        let mut command = Command::new(path);
        command.env_clear().env("LANG", "C").env("LC_ALL", "C");
        let mut query = json!({"source":source,"function_at_byte":offset});
        if let Some(candidate) = candidate {
            query["candidate_end_byte"] = candidate["end_byte"].clone();
        }
        let result = worker::run(
            &mut command,
            &serde_json::to_vec(&query)?,
            4096,
            Duration::from_secs(5),
        )
        .await?;
        if !result.success {
            return Err(Error::conflict("Function targeting worker failed"));
        }
        let document: Value = serde_json::from_slice(&result.bytes)
            .map_err(|_| Error::protocol("Malformed function targeting output"))?;
        let f = &document["function_location"];
        if candidate.is_some() && !Self::candidate_worker_admitted(&document, source.len()) {
            return Err(Error::bad(
                "Unsupported candidate: choose a literal inside a synchronous function body; comments, async/generator functions and templates are not supported.",
            ));
        }
        if document["schema"] != "reb-deobfuscator-worker-v1"
            || document["ok"] != true
            || ![
                "function_declaration",
                "function_expression",
                "arrow_function",
                "method_definition",
                "generator_function_declaration",
                "generator_function",
            ]
            .contains(&f["kind"].as_str().unwrap_or(""))
        {
            return Err(Error::bad(
                "No enclosing JavaScript function was found at the cursor",
            ));
        }
        let start = f["start"]
            .as_u64()
            .ok_or_else(|| Error::protocol("Malformed function span"))?
            as usize;
        let end = f["end"]
            .as_u64()
            .ok_or_else(|| Error::protocol("Malformed function span"))? as usize;
        let body = f["body_start"]
            .as_u64()
            .ok_or_else(|| Error::protocol("Malformed function span"))? as usize;
        if !(start <= offset && offset < end && end <= source.len() && start <= body && body < end)
        {
            return Err(Error::bad(
                "No enclosing JavaScript function was found at the cursor",
            ));
        }
        Ok(
            json!({"kind":f["kind"],"start":coordinate(source,script,start)?,"end":coordinate(source,script,end)?,"body_start":coordinate(source,script,body)?}),
        )
    }
    pub(super) async fn add_hook(&self, r: &Value) -> Result<Value> {
        self.add_hook_with_candidate(r, None).await
    }
    async fn add_hook_with_candidate(&self, r: &Value, candidate: Option<&Value>) -> Result<Value> {
        self.hooks_editable()?;
        let snapshot = self.snapshot();
        if snapshot["runtime_hooks"]["definitions"]
            .as_array()
            .unwrap()
            .len()
            >= 8
        {
            return Err(Error::conflict("Runtime Hook definition limit reached"));
        }
        let label = requests::text(&r["label"], "Hook label", 128, false)?
            .trim()
            .to_owned();
        if label.is_empty() {
            return Err(Error::bad("Hook label is required"));
        }
        let id = requests::text(&r["script_id"], "Script ID", 4096, false)?;
        let script = snapshot["scripts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["script_id"] == id && s["language"] == "JavaScript")
            .ok_or_else(|| Error::conflict("Runtime Hooks requires a live JavaScript source"))?;
        let line = validation::integer(&r["line"], "Hook line", 0, i32::MAX as u64)?;
        let column = validation::integer(
            r.get("column").unwrap_or(&json!(0)),
            "Hook column",
            0,
            i32::MAX as u64,
        )?;
        if line < script["start_line"].as_u64().unwrap()
            || line > script["end_line"].as_u64().unwrap()
        {
            return Err(Error::bad("Hook location is outside the selected script"));
        }
        let boolean = |key| {
            r.get(key)
                .unwrap_or(&json!(true))
                .as_bool()
                .ok_or_else(|| Error::bad("Hook phases must be boolean"))
        };
        let entry = boolean("entry_enabled")?;
        let returns = boolean("return_enabled")?;
        if !entry && !returns {
            return Err(Error::bad("Hook requires an entry or return phase"));
        }
        let mode = r
            .get("entry_mode")
            .unwrap_or(&json!("source"))
            .as_str()
            .filter(|s| ["source", "function"].contains(s))
            .ok_or_else(|| Error::bad("Hook entry mode is invalid"))?
            .to_owned();
        let text = |key, max| requests::text(r.get(key).unwrap_or(&json!("")), key, max, true);
        let expression = text("function_expression", 1024)?.trim().to_owned();
        let condition = text("condition", 1024)?;
        let entry_logic = text("entry_logic", 8192)?;
        let return_logic = text("return_logic", 8192)?;
        let return_mode = r
            .get("return_mode")
            .unwrap_or(&json!("none"))
            .as_str()
            .filter(|s| ["none", "json", "expression"].contains(s))
            .ok_or_else(|| Error::bad("Return mode is invalid"))?
            .to_owned();
        let return_expression = if return_mode == "expression" {
            let e = text("return_expression", 8192)?.trim().to_owned();
            if e.is_empty() {
                return Err(Error::bad("Return expression is required"));
            }
            e
        } else {
            String::new()
        };
        let value = if return_mode == "json" {
            r.get("return_value")
                .ok_or_else(|| Error::bad("JSON replacement is required"))?
                .clone()
        } else {
            Value::Null
        };
        let bytes = if return_mode == "json" {
            let mut entries = 0;
            validate_hook_json(&value, 0, &mut entries)?;
            let size = serde_json::to_vec(&value)?.len();
            if size > 8192 {
                return Err(Error::bad("Hook replacement exceeds 8 KiB"));
            }
            size
        } else {
            0
        };
        if return_mode != "none" && !returns
            || mode == "function"
                && (expression.is_empty()
                    || !entry
                    || returns
                    || !return_logic.is_empty()
                    || return_mode != "none")
            || mode == "source" && !expression.is_empty()
        {
            return Err(Error::bad(
                "Live-function targeting requires an expression and entry-only capture; return replacement requires the return phase",
            ));
        }
        let target = script
            .get("target_id")
            .cloned()
            .unwrap_or(snapshot["runtime_hooks"]["target_id"].clone());
        self.hook_session(
            target
                .as_str()
                .ok_or_else(|| Error::conflict("Hook target is unavailable"))?,
        )
        .await?;
        let function = if mode == "function" {
            json!({"kind":"live_function_object","start":{"line":line,"column":column},"end":{"line":line,"column":column},"body_start":{"line":line,"column":column}})
        } else {
            let source = self.source(&id).await?;
            if source["truncated"] == true {
                return Err(Error::bad("Runtime Hooks cannot target a truncated script"));
            }
            let text = source["source"].as_str().unwrap();
            if let Some(guard) = candidate {
                self.candidate_guard_current(guard, script, text)?;
            }
            let function = self
                .locate_function(text, script, line, column, candidate)
                .await?;
            if let Some(guard) = candidate {
                self.candidate_guard_current(guard, script, text)?;
            }
            function
        };
        let mut definition = json!({"id":self.hooks.next.fetch_add(1,Ordering::Relaxed),"label":label,"script_id":id,"cdp_script_id":script.get("cdp_script_id").unwrap_or(&script["script_id"]),"target_id":target,"target_type":script.get("target_type").unwrap_or(&json!("page")),"entry_mode":mode,"function_expression":expression,"url":source_label(script["url"].as_str().unwrap_or("")),"line":line,"column":column,"function_kind":function["kind"],"function_start":function["start"],"function_end":function["end"],"target_line":function["body_start"]["line"],"target_column":function["body_start"]["column"],"entry_enabled":entry,"return_enabled":returns,"condition":condition,"entry_logic":entry_logic,"return_logic":return_logic,"return_mode":return_mode,"return_expression":return_expression,"return_value":value,"return_value_bytes":bytes,"resolved":null});
        if let Some(guard) = candidate {
            definition["candidate_guard"] = guard.clone();
        }
        let mut accepted = false;
        self.update(|s| {
            if let Some(guard) = candidate
                && !Self::candidate_commit_current(s, guard, &self.hooks)
            {
                return;
            }
            accepted = true;
            s["runtime_hooks"]["definitions"]
                .as_array_mut()
                .unwrap()
                .push(definition);
            s["runtime_hooks"]["state"] = json!("ready");
            s["runtime_hooks"]["message"] = json!(
                "Runtime Hook definition added. Confirm isolated-page execution before arming."
            );
        });
        if !accepted {
            return Err(Error::conflict(
                "Candidate owner changed before definition insertion.",
            ));
        }
        Ok(self.group_response("runtime_hooks"))
    }
    pub(super) fn remove_hook(&self, r: &Value) -> Result<Value> {
        self.hooks_editable()?;
        let id = validation::integer(&r["hook_id"], "Hook ID", 1, validation::MAX_SAFE_INTEGER)?;
        if !self.snapshot()["runtime_hooks"]["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["id"] == id)
        {
            return Err(Error::conflict("Hook definition is unavailable"));
        }
        self.update(|s| {
            s["runtime_hooks"]["definitions"]
                .as_array_mut()
                .unwrap()
                .retain(|h| h["id"] != id);
            s["runtime_hooks"]["message"] = json!("Runtime Hook definition removed.");
        });
        Ok(self.group_response("runtime_hooks"))
    }
    pub(super) async fn arm_hooks(&self, r: &Value) -> Result<Value> {
        self.hooks_editable()?;
        if r["confirmed"] != true {
            return Err(Error::bad(
                "Runtime Hooks requires explicit isolated-page mutation confirmation",
            ));
        }
        let s = self.snapshot();
        if s["settings"]["breakpoints_active"] != true
            || s["runtime_hooks"]["definitions"]
                .as_array()
                .unwrap()
                .is_empty()
        {
            return Err(Error::conflict(
                "Add a hook and activate debugger breakpoints before arming",
            ));
        }
        let epoch = self.hooks.epoch.fetch_add(1, Ordering::AcqRel) + 1;
        self.update(|s| {
            s["runtime_hooks"]["state"] = json!("arming");
            s["runtime_hooks"]["last_failure"] = Value::Null;
        });
        let mut definitions = s["runtime_hooks"]["definitions"]
            .as_array()
            .unwrap()
            .clone();
        let mut installed: BTreeMap<(String, String), Value> = BTreeMap::new();
        let result=async {self.command("Network.enable",json!({"maxPostDataSize":if self.options.capture_network_content {131072} else {0}})).await?;for d in &mut definitions {self.verify_candidate_arm(d).await?;let target=d["target_id"].as_str().unwrap().to_owned();let session=self.hook_session(&target).await?;self.check_candidate_definition(d)?;let mut specs=Vec::new();
            if d["entry_mode"]=="function" {let group=format!("reb-hook-function-{}-{}",s["runtime_hooks"]["session_id"],d["id"]);let evaluated=session.command("Runtime.evaluate",json!({"expression":d["function_expression"],"objectGroup":group,"silent":true,"returnByValue":false,"throwOnSideEffect":true,"awaitPromise":false,"timeout":100}),Duration::from_secs(3)).await;let installed_function=async {let v=evaluated?;if v["exceptionDetails"].is_object()||v["result"]["type"]!="function" {return Err(Error::bad("Live-function expression did not resolve without side effects to a function"));}let id=validation::text(&v["result"]["objectId"],"Function object ID",4096,false,false).map_err(|e|Error::protocol(e.message))?;session.command("Debugger.setBreakpointOnFunctionCall",json!({"objectId":id}),Duration::from_secs(3)).await}.await;let _=session.command("Runtime.releaseObjectGroup",json!({"objectGroup":group}),Duration::from_secs(3)).await;let point=installed_function?;let id=validation::text(&point["breakpointId"],"Hook breakpoint ID",4096,false,false).map_err(|e|Error::protocol(e.message))?;installed.insert((target.clone(),id.into()),json!({"hook_id":d["id"],"target_id":target,"phases":["entry"]}));d["resolved"]=json!({"entry_points":1,"return_points":0});}
            else {let locations=session.command("Debugger.getPossibleBreakpoints",json!({"start":{"scriptId":d["cdp_script_id"],"lineNumber":d["target_line"],"columnNumber":d["target_column"]},"restrictToFunction":true}),Duration::from_secs(3)).await?;self.check_candidate_definition(d)?;let locations=locations["locations"].as_array().filter(|a|a.len()<=100000).ok_or_else(||Error::protocol("Malformed or oversized hook locations"))?;let mut points=BTreeMap::new();let first=locations.iter().find_map(parse::location).ok_or_else(||Error::bad("No breakable function was found for the hook"))?;if first["script_id"]!=d["cdp_script_id"] {return Err(Error::protocol("Hook location refers to another script"));}
if d["entry_enabled"]==true {points.insert((first["line"].as_u64().unwrap(),first["column"].as_u64().unwrap()),(first.clone(),vec!["entry"]));}let mut returns=0;for raw in locations {if raw["type"]!="return"||d["return_enabled"]!=true {continue;}let Some(loc)=parse::location(raw).filter(|l|l["script_id"]==d["cdp_script_id"]) else {continue;};let key=(loc["line"].as_u64().unwrap(),loc["column"].as_u64().unwrap());let point=points.entry(key).or_insert((loc,vec![]));if !point.1.contains(&"return") {point.1.push("return");returns+=1;}
if returns>32 {return Err(Error::bad("Hook exceeds 32 synchronous return points"));}}
if d["return_enabled"]==true&&returns==0 {return Err(Error::bad("Hook has no synchronous return point"));}for (_, (location,phases)) in points {specs.push(json!({"location":location,"phases":phases,"target_id":target,"hook_id":d["id"]}));}d["resolved"]=json!({"entry_points":if d["entry_enabled"]==true {1} else {0},"return_points":returns});
                for spec in specs {if installed.len()>=64 {return Err(Error::bad("Hooks exceed the 64 active-point limit"));}let loc=&spec["location"];let result=session.command("Debugger.setBreakpoint",json!({"location":{"scriptId":loc["script_id"],"lineNumber":loc["line"],"columnNumber":loc["column"]}}),Duration::from_secs(3)).await?;let id=validation::text(&result["breakpointId"],"Hook breakpoint ID",4096,false,false).map_err(|e|Error::protocol(e.message))?;installed.insert((target.clone(),id.into()),spec);self.check_candidate_definition(d)?;}}
            if self.hooks.epoch.load(Ordering::Acquire)!=epoch {return Err(Error::conflict("Runtime Hooks arming was cancelled"));}}
            Ok::<_,Error>(())}.await;
        if let Err(e) = result {
            for ((target, id), _) in installed {
                if let Ok(s) = self.hook_session(&target).await {
                    let _ = s
                        .command(
                            "Debugger.removeBreakpoint",
                            json!({"breakpointId":id}),
                            Duration::from_secs(3),
                        )
                        .await;
                }
            }
            self.update(|s| {
                s["runtime_hooks"]["state"] = json!("disarmed");
                s["runtime_hooks"]["last_failure"] = json!(e.message);
                s["runtime_hooks"]["message"] =
                    json!("Hook arming failed. Review the definition before retrying.");
            });
            return Err(e);
        }
        let count = installed.len();
        *self.hooks.points.lock().unwrap_or_else(|e| e.into_inner()) = installed;
        let mut committed = false;
        self.update(|s| {
            if self.hooks.epoch.load(Ordering::Acquire) != epoch
                || definitions.iter().any(|d| {
                    d.get("candidate_guard")
                        .is_some_and(|guard| !Self::candidate_commit_current(s, guard, &self.hooks))
                })
            {
                return;
            }
            committed = true;
            s["runtime_hooks"]["definitions"] = json!(definitions);
            s["runtime_hooks"]["active_points"] = json!(count);
            s["runtime_hooks"]["state"] = json!("armed");
            s["runtime_hooks"]["message"] = json!(format!(
                "Armed {} hooks across {count} bounded points.",
                definitions.len()
            ));
        });
        if !committed {
            self.disarm_hooks().await?;
            return Err(Error::conflict(
                "Candidate ownership changed before arming completed; installed points were removed.",
            ));
        }
        Ok(self.group_response("runtime_hooks"))
    }
    pub(super) async fn disarm_hooks(&self) -> Result<Value> {
        self.hooks.epoch.fetch_add(1, Ordering::AcqRel);
        let _execution = self.hooks.execution.lock().await;
        let points =
            std::mem::take(&mut *self.hooks.points.lock().unwrap_or_else(|e| e.into_inner()));
        self.update(|s| s["runtime_hooks"]["state"] = json!("stopping"));
        let mut errors = Vec::new();
        for ((target, id), _) in points {
            if let Ok(session) = self.hook_session(&target).await
                && let Err(e) = session
                    .command(
                        "Debugger.removeBreakpoint",
                        json!({"breakpointId":id}),
                        Duration::from_secs(3),
                    )
                    .await
            {
                errors.push(e.message);
            }
        }
        self.update(|s| {
            s["runtime_hooks"]["active_points"] = json!(0);
            s["runtime_hooks"]["state"] = json!(if errors.is_empty() {
                "disarmed"
            } else {
                "error"
            });
            s["runtime_hooks"]["message"] = json!(if errors.is_empty() {
                "Runtime Hooks disarmed. Definitions remain editable.".to_owned()
            } else {
                validation::truncate(&errors.join("; "), 512)
            });
        });
        if !errors.is_empty() {
            return Err(Error::conflict(errors.join("; ")));
        }
        Ok(self.group_response("runtime_hooks"))
    }
    pub(super) fn clear_hook_hits(&self) -> Result<Value> {
        self.hooks_editable()?;
        self.update(|s| {
            let h = &mut s["runtime_hooks"];
            for k in ["total_hits", "hit_evictions", "request_evictions"] {
                h[k] = json!(0);
            }
            h["hits"] = json!([]);
            h["requests"] = json!([]);
            h["field_test"]["observations"] = json!([]);
            h["field_test"]["observation_evictions"] = json!(0);
            h["field_test"]["comparison"] = Value::Null;
            h["last_failure"] = Value::Null;
        });
        Ok(self.group_response("runtime_hooks"))
    }
    pub(super) fn hook_pause(self: &Arc<Self>, target: &str, params: Value) -> bool {
        let matches = {
            let points = self.hooks.points.lock().unwrap_or_else(|e| e.into_inner());
            params["hitBreakpoints"]
                .as_array()
                .into_iter()
                .flatten()
                .take(1000)
                .filter_map(|id| points.get(&(target.into(), id.as_str()?.into())).cloned())
                .collect::<Vec<_>>()
        };
        if matches.is_empty() {
            return false;
        }
        if self
            .hooks
            .queue
            .try_send(Pause {
                target: target.into(),
                params,
                matches,
                epoch: self.hooks.epoch.load(Ordering::Acquire),
            })
            .is_err()
        {
            self.update(|s| {
                s["runtime_hooks"]["last_failure"] =
                    json!("Runtime Hook pause queue capacity exceeded. Hooks require disarming.");
                s["runtime_hooks"]["state"] = json!("stopping");
            });
            let d = Arc::clone(self);
            let target = target.to_owned();
            tokio::spawn(async move {
                if let Ok(session) = d.hook_session(&target).await {
                    let _ = session
                        .command("Debugger.resume", json!({}), Duration::from_secs(3))
                        .await;
                }
                let _ = d.disarm_hooks().await;
            });
        }
        true
    }
    pub(super) fn start_hooks(self: &Arc<Self>) {
        let Some(mut receiver) = self
            .hooks
            .receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return;
        };
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Some(pause) = receiver.recv().await {
                let Some(d) = weak.upgrade() else {
                    break;
                };
                let result = d.process_hook_pause(&pause).await;
                if let Err(e) = &result {
                    d.update(|s| {
                        s["runtime_hooks"]["last_failure"] =
                            json!(validation::truncate(&e.message, 512));
                    });
                }
                if let Ok(session) = d.hook_session(&pause.target).await {
                    let _ = session
                        .command(
                            "Runtime.releaseObjectGroup",
                            json!({"objectGroup":"reb-runtime-hook"}),
                            Duration::from_secs(3),
                        )
                        .await;
                    let _ = session
                        .command("Debugger.resume", json!({}), Duration::from_secs(3))
                        .await;
                }
                if d.snapshot()["runtime_hooks"]["total_hits"]
                    .as_u64()
                    .unwrap()
                    >= 512
                    || d.snapshot()["runtime_hooks"]["state"] == "stopping"
                    || result.is_err()
                {
                    let _ = d.disarm_hooks().await;
                } else if d.hooks.epoch.load(Ordering::Acquire) == pause.epoch {
                    d.update(|s| s["runtime_hooks"]["state"] = json!("armed"));
                }
            }
        });
    }
    async fn process_hook_pause(&self, p: &Pause) -> Result<()> {
        let _execution = self.hooks.execution.lock().await;
        if self.hooks.epoch.load(Ordering::Acquire) != p.epoch {
            return Ok(());
        }
        let session = self.hook_session(&p.target).await?;
        let frame = p.params["callFrames"]
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| Error::protocol("Hook pause omitted its top frame"))?;
        let frame_id = validation::text(&frame["callFrameId"], "Call frame ID", 4096, false, false)
            .map_err(|e| Error::protocol(e.message))?;
        self.update(|s| s["runtime_hooks"]["state"] = json!("handling"));
        for point in &p.matches {
            let hook = self.snapshot()["runtime_hooks"]["definitions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["id"] == point["hook_id"])
                .cloned();
            let Some(hook) = hook else {
                continue;
            };
            self.check_candidate_definition(&hook)?;
            for phase in point["phases"].as_array().unwrap() {
                if self.hooks.epoch.load(Ordering::Acquire) != p.epoch
                    || self.snapshot()["runtime_hooks"]["total_hits"]
                        .as_u64()
                        .unwrap()
                        >= 512
                {
                    return Ok(());
                }
                let phase = phase.as_str().unwrap();
                let capture = self.snapshot()["runtime_hooks"]["field_test"]["enabled"] == true;
                let original = if phase == "return" {
                    preview(&frame["returnValue"], capture)
                } else {
                    Value::Null
                };
                let mut replacement = Value::Null;
                let mut bindings = vec![];
                let mut truncated = false;
                let mut operation = "observed";
                let executed=async {if hook["condition"]!="" {let result=evaluate(&session,frame_id,&format!("Boolean(({}))",hook["condition"].as_str().unwrap()),true,true).await?;if result["value"]!=true {operation="skipped";return Ok::<_,Error>(());}}
                if let Some(scope)=frame["scopeChain"].as_array().into_iter().flatten().take(12).find(|s|s["type"]=="local")&& let Some(id)=scope["object"]["objectId"].as_str().filter(|s|s.len()<=4096) {let properties=session.command("Runtime.getProperties",json!({"objectId":id,"ownProperties":true,"accessorPropertiesOnly":false,"generatePreview":true}),Duration::from_secs(1)).await?;let a=properties["result"].as_array().ok_or_else(||Error::protocol("Malformed hook bindings"))?;truncated=a.len()>32;for property in a.iter().take(32) {let Some(name)=property["name"].as_str() else {continue;};let accessor=property["get"].is_object()||property["set"].is_object();let value=if property["value"].is_object() {preview(&property["value"], capture)} else {json!({"type":if accessor {"accessor"} else {"unavailable"},"subtype":null,"class_name":null,"description":if accessor {"Accessor not invoked"} else {"Not initialized or unavailable"},"value":null,"unserializable_value":null,"value_truncated":false})};bindings.push(json!({"name":validation::truncate(name,256),"value":value,"accessor":accessor}));}}
                if self.hooks.epoch.load(Ordering::Acquire)!=p.epoch {return Ok(());}let logic=&hook[if phase=="entry" {"entry_logic"} else {"return_logic"}];if logic!="" {let result=evaluate(&session,frame_id,&format!("(()=>{{\n{}\n}})()",logic.as_str().unwrap()),false,false).await?;if result["subtype"]=="promise" {return Err(Error::bad("Injected logic returned a Promise; only synchronous logic is supported"));}operation="logic_run";}
                if phase=="return"&&hook["return_mode"]!="none" {if frame["returnValue"]["subtype"]=="promise" {return Err(Error::bad("Promise return values cannot be synchronously replaced"));}let argument=if hook["return_mode"]=="json" {let value=&hook["return_value"];let kind=match value {Value::Null=>"null",Value::Bool(_)=>"bool",Value::Number(n) if n.is_i64()||n.is_u64()=>"int",Value::Number(_)=>"float",Value::String(_)=>"str",Value::Array(_)=>"list",Value::Object(_)=>"dict"};replacement=json!({"string_sha256":if capture {provenance::project(&json!({"operation":"string_digest","value":value})).unwrap_or(Value::Null)} else {Value::Null},"type":kind,"subtype":null,"class_name":null,"description":validation::truncate(&value.to_string(),512),"value":if value.is_array()||value.is_object() {Value::Null} else {value.clone()},"unserializable_value":null,"value_truncated":hook["return_value_bytes"].as_u64().unwrap()>512});json!({"value":value})} else {let result=evaluate(&session,frame_id,hook["return_expression"].as_str().unwrap(),false,false).await?;if result["subtype"]=="promise" {return Err(Error::bad("A Promise cannot be a synchronous return replacement"));}replacement=preview(&result, capture);if let Some(value)=result.get("value") {json!({"value":value})}else if let Some(value)=result.get("unserializableValue") {json!({"unserializableValue":value})}else if let Some(id)=result.get("objectId") {json!({"objectId":id})}else {return Err(Error::bad("Hook expression result cannot be returned"));}};if self.hooks.epoch.load(Ordering::Acquire)!=p.epoch {return Ok(());}session.command("Debugger.setReturnValue",json!({"newValue":argument}),Duration::from_secs(3)).await?;operation="return_overridden";}Ok(())}.await;
                self.check_candidate_definition(&hook)?;
                if self.hooks.epoch.load(Ordering::Acquire) != p.epoch {
                    return Ok(());
                }
                let error = executed.err().map(|e| e.message);
                if error.is_some() {
                    operation = "failed";
                }
                let location = parse::location(&frame["location"])
                    .unwrap_or(json!({"line":hook["line"],"column":hook["column"]}));
                self.update(|s| {
                    // CDP IDs are local to a target. Live-function hooks can execute
                    // in a different script from the one selected during setup.
                    let script = s["scripts"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|script| {
                            script["target_id"]
                                .as_str()
                                .unwrap_or(s["target"]["id"].as_str().unwrap_or(""))
                                == p.target
                                && script.get("cdp_script_id").unwrap_or(&script["script_id"])
                                    == &location["script_id"]
                        });
                    let script_id = script
                        .map(|script| script["script_id"].clone())
                        .unwrap_or(json!(""));
                    let source_hash = script
                        .map(|script| script["hash"].clone())
                        .unwrap_or(Value::Null);
                    let source = source_label(
                        script
                            .and_then(|script| script["url"].as_str())
                            .or(frame["url"].as_str())
                            .unwrap_or(""),
                    );
                    let hit = json!({
                        "script_id": script_id,
                        "source_hash": source_hash,
                        "id": self.hooks.hit.fetch_add(1, Ordering::Relaxed),
                        "occurred_at_ms": validation::now_ms(),
                        "session_id": s["runtime_hooks"]["session_id"],
                        "hook_id": hook["id"],
                        "target_id": hook["target_id"],
                        "target_type": hook["target_type"],
                        "label": hook["label"],
                        "source": source,
                        "function": validation::truncate(
                            frame["functionName"].as_str().filter(|s| !s.is_empty())
                                .unwrap_or("(anonymous)"), 256),
                        "category": phase,
                        "operation": operation,
                        "line": location["line"],
                        "column": location["column"],
                        "bindings": bindings,
                        "bindings_truncated": truncated,
                        "original_return": original,
                        "replacement_return": replacement,
                        "error": error.as_ref().map(|e| validation::truncate(e, 512)),
                    });
                    let h = &mut s["runtime_hooks"];
                    h["total_hits"] = json!(h["total_hits"].as_u64().unwrap() + 1);
                    let hits = h["hits"].as_array_mut().unwrap();
                    let evicted = hits.len() == 128;
                    if evicted {
                        hits.remove(0);
                    }
                    hits.push(hit);
                    if evicted {
                        h["hit_evictions"] = json!(h["hit_evictions"].as_u64().unwrap() + 1);
                    }
                    if error.is_some() {
                        h["last_failure"] = json!(error);
                    }
                });
            }
        }
        Ok(())
    }
    pub(super) async fn hooks_navigated(&self) {
        self.hooks.candidate_epoch.fetch_add(1, Ordering::AcqRel);
        if !self.snapshot()["runtime_hooks"]["definitions"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            let _ = self.disarm_hooks().await;
            self.update(|s| {
                s["runtime_hooks"]["definitions"] = json!([]);
                s["runtime_hooks"]["state"] = json!("ready");
                s["runtime_hooks"]["last_failure"] = json!(
                    "The page navigated. Script identifiers changed, so all hooks were cleared."
                );
            });
        }
    }
}
async fn evaluate(
    session: &Session,
    frame: &str,
    expression: &str,
    by_value: bool,
    side_effect: bool,
) -> Result<Value> {
    let result=session.command("Debugger.evaluateOnCallFrame",json!({"callFrameId":frame,"expression":expression,"objectGroup":"reb-runtime-hook","includeCommandLineAPI":false,"silent":true,"returnByValue":by_value,"generatePreview":!by_value,"throwOnSideEffect":side_effect,"timeout":100}),Duration::from_secs(1)).await?;
    if result["exceptionDetails"].is_object() {
        return Err(Error::bad("Runtime Hooks evaluation threw an exception"));
    }
    if !result["result"]["type"].is_string() {
        return Err(Error::protocol("Malformed hook evaluation"));
    }
    Ok(result["result"].clone())
}
fn validate_hook_json(v: &Value, depth: usize, entries: &mut usize) -> Result<()> {
    if depth > 8 {
        return Err(Error::bad("Hook JSON exceeds depth 8"));
    }
    match v {
        Value::Number(n) => {
            if n.as_i64()
                .is_some_and(|n| n.unsigned_abs() > validation::MAX_SAFE_INTEGER)
                || n.as_u64().is_some_and(|n| n > validation::MAX_SAFE_INTEGER)
            {
                return Err(Error::bad("Hook integer exceeds JavaScript's exact range"));
            }
        }
        Value::String(s) => {
            if s.len() > 8192 {
                return Err(Error::bad("Hook JSON string exceeds 8 KiB"));
            }
        }
        Value::Array(a) => {
            *entries += a.len();
            if *entries > 256 {
                return Err(Error::bad("Hook JSON exceeds 256 entries"));
            }
            for v in a {
                validate_hook_json(v, depth + 1, entries)?;
            }
        }
        Value::Object(o) => {
            *entries += o.len();
            if *entries > 256 {
                return Err(Error::bad("Hook JSON exceeds 256 entries"));
            }
            for (k, v) in o {
                if k.len() > 4096 {
                    return Err(Error::bad("Hook JSON key is invalid"));
                }
                validate_hook_json(v, depth + 1, entries)?;
            }
        }
        _ => (),
    }
    Ok(())
}
