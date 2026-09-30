use super::Debugger;
use crate::{
    error::{Error, Result},
    validation, worker,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{fs::File, io::AsyncWriteExt, process::Command, sync::Mutex as AsyncMutex};
pub(super) struct Heap {
    collector: Mutex<Option<Arc<Collector>>>,
    operation: AsyncMutex<()>,
    pub(super) baseline: Mutex<Option<Arc<Capture>>>,
}
pub(super) struct Capture {
    file: tempfile::NamedTempFile,
    target: String,
    at: u64,
    bytes: AtomicU64,
}
struct Collector {
    capture: Arc<Capture>,
    writer: AsyncMutex<File>,
    chunks: AtomicU64,
    error: Mutex<Option<String>>,
}
struct Registered<'a>(&'a Heap);
impl Drop for Registered<'_> {
    fn drop(&mut self) {
        self.0
            .collector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
}
impl Heap {
    pub fn new() -> Self {
        Self {
            collector: Mutex::new(None),
            operation: AsyncMutex::new(()),
            baseline: Mutex::new(None),
        }
    }
}
impl Debugger {
    fn memory_elapsed(&self) -> u64 {
        self.memory_started
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(0, |t| {
                t.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
            })
    }

    pub(super) async fn heap_chunk(&self, p: &Value) {
        let collector = self
            .heap
            .collector
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(collector) = collector else {
            return;
        };
        let Some(chunk) = p["chunk"].as_str() else {
            *collector.error.lock().unwrap_or_else(|e| e.into_inner()) =
                Some("Debugger returned a malformed heap snapshot chunk".into());
            return;
        };
        let mut writer = collector.writer.lock().await;
        let size = collector.capture.bytes.load(Ordering::Acquire);
        if collector
            .error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return;
        }
        if chunk.len() > 8 * 1024 * 1024 || size + chunk.len() as u64 > 256 * 1024 * 1024 {
            *collector.error.lock().unwrap_or_else(|e| e.into_inner()) =
                Some("Heap snapshot chunk or total capture byte limit exceeded".into());
            return;
        }
        if let Err(e) = writer.write_all(chunk.as_bytes()).await {
            *collector.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
            return;
        }
        collector
            .capture
            .bytes
            .fetch_add(chunk.len() as u64, Ordering::Release);
        collector.chunks.fetch_add(1, Ordering::Release);
    }
    async fn capture_heap(&self) -> Result<Arc<Capture>> {
        let snapshot = self.snapshot();
        let target = snapshot["target"]["id"]
            .as_str()
            .ok_or_else(|| Error::conflict("Debugger target is unavailable"))?;
        let file = tempfile::Builder::new()
            .prefix("reb-heap-")
            .suffix(".heapsnapshot")
            .tempfile()?;
        let writer = File::from_std(file.reopen()?);
        let capture = Arc::new(Capture {
            file,
            target: target.into(),
            at: validation::now_ms(),
            bytes: AtomicU64::new(0),
        });
        let collector = Arc::new(Collector {
            capture: capture.clone(),
            writer: AsyncMutex::new(writer),
            chunks: AtomicU64::new(0),
            error: Mutex::new(None),
        });
        {
            let mut active = self
                .heap
                .collector
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if active.is_some() {
                return Err(Error::conflict(
                    "A heap snapshot capture is already running",
                ));
            }
            *active = Some(collector.clone());
        }
        let _registered = Registered(&self.heap);
        let connection = self
            .connection
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::conflict("Debugger target is unavailable"))?;
        connection
            .command("HeapProfiler.enable", json!({}), Duration::from_secs(3))
            .await?;
        let result = connection
            .command(
                "HeapProfiler.takeHeapSnapshot",
                json!({"reportProgress":false,"captureNumericValue":true,"exposeInternals":false}),
                Duration::from_secs(60),
            )
            .await;
        if let Err(e) = result {
            connection.close().await;
            return Err(e);
        }
        connection.barrier().await?;
        collector.writer.lock().await.flush().await?;
        if let Some(error) = collector
            .error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(Error::conflict(error));
        }
        if collector.chunks.load(Ordering::Acquire) == 0
            || capture.bytes.load(Ordering::Acquire) == 0
        {
            return Err(Error::protocol("Debugger returned an empty heap snapshot"));
        }
        if self.snapshot()["target"]["id"] != capture.target {
            return Err(Error::conflict(
                "Debugger target changed during heap snapshot capture",
            ));
        }
        Ok(capture)
    }
    async fn heap_worker(&self, args: Vec<String>, seconds: u64) -> Result<Value> {
        let path = self.options.worker(
            &self.options.heap_snapshot,
            "OriginTraceHeapSnapshot",
            "build/reb-heap-snapshot",
        );
        if !worker::executable(&path) {
            return Err(Error::new(
                503,
                "Native heap snapshot analysis is unavailable; run make heap-snapshot",
            ));
        }
        let output = worker::run(
            Command::new(&path).args(args),
            &[],
            512 * 1024,
            Duration::from_secs(seconds),
        )
        .await?;
        if !output.success {
            return Err(Error::conflict(if output.stderr.is_empty() {
                "Native heap snapshot analysis rejected the snapshot".into()
            } else {
                validation::truncate(String::from_utf8_lossy(&output.stderr).trim(), 512)
            }));
        }
        serde_json::from_slice(&output.bytes)
            .map_err(|_| Error::protocol("Native heap snapshot analysis returned malformed JSON"))
    }
    pub(super) async fn heap_action(&self, r: &Value) -> Result<Value> {
        let _operation = self
            .heap
            .operation
            .try_lock()
            .map_err(|_| Error::conflict("Heap snapshot comparison is running"))?;
        let action = r["action"].as_str().unwrap();
        if action == "clear_heap_diff_baseline" {
            self.heap
                .baseline
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            self.update(|s| s["heap_diff_baseline"] = Value::Null);
            return Ok(json!({"ok":true,"generation":self.snapshot()["generation"]}));
        }
        if action == "compare_heap_diff" {
            let baseline = self
                .heap
                .baseline
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .ok_or_else(|| Error::conflict("Capture a heap snapshot baseline first"))?;
            if self.snapshot()["target"]["id"] != baseline.target {
                return Err(Error::conflict(
                    "Heap snapshot baseline belongs to a different debugger target",
                ));
            }
        }
        let current = self.capture_heap().await?;
        if action == "capture_heap_diff_baseline" {
            let metadata = json!({"target_id":current.target,"file_bytes":current.bytes.load(Ordering::Acquire),"captured_at_ms":current.at});
            *self.heap.baseline.lock().unwrap_or_else(|e| e.into_inner()) = Some(current);
            self.update(|s| s["heap_diff_baseline"] = metadata.clone());
            return Ok(
                json!({"ok":true,"baseline":metadata,"generation":self.snapshot()["generation"]}),
            );
        }
        let mut args = Vec::new();

        let key = if action == "compare_heap_diff" {
            let baseline = self
                .heap
                .baseline
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .ok_or_else(|| Error::conflict("Capture a heap snapshot baseline first"))?;
            if baseline.target != current.target {
                return Err(Error::conflict(
                    "Heap snapshot baseline belongs to a different debugger target",
                ));
            }
            args.extend([
                "--baseline".into(),
                baseline.file.path().display().to_string(),
                "--current".into(),
                current.file.path().display().to_string(),
                "--limit".into(),
                "50".into(),
            ]);
            "diff"
        } else {
            let query = r["query"].as_str().unwrap_or("").trim();
            if query.is_empty() {
                return Err(Error::bad("Heap snapshot search requires a value"));
            }
            args.extend([
                "--snapshot".into(),
                current.file.path().display().to_string(),
                "--query".into(),
                query.into(),
                "--scope".into(),
                r["scope"].as_str().unwrap_or("all").into(),
                "--limit".into(),
                "50".into(),
            ]);
            if r["case_sensitive"] == true {
                args.push("--case-sensitive".into());
            }
            "snapshot"
        };
        let document = self
            .heap_worker(args, if key == "diff" { 60 } else { 20 })
            .await?;
        if key == "snapshot" {
            validation::schema("HeapSnapshotSearch", &document, 422)?;
            heap_counts(&document)?;
        }
        let result = json!({"ok":true,key:document,"generation":self.snapshot()["generation"]});
        if key == "diff" {
            validation::schema("DebuggerDiffResult", &result, 422)?;
        }
        Ok(result)
    }
    pub(super) async fn start_memory(self: &Arc<Self>, r: &Value) -> Result<Value> {
        if self.snapshot()["state"] != "running" || self.heap.operation.try_lock().is_err() {
            return Err(Error::conflict(
                "Memory Origin Trace requires a running target and an idle heap collector",
            ));
        }
        let query = r["query"].as_str().unwrap_or("").trim();
        if query.is_empty() {
            return Err(Error::bad("Memory Origin Trace requires a value"));
        }
        let snapshot = self.snapshot();
        let existing = snapshot["settings"]["event_breakpoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| [json!("click"), json!("listener:click")].contains(v));
        let id = self.memory_id.fetch_add(1, Ordering::Relaxed);
        if !existing {
            self.command(
                "DOMDebugger.setEventListenerBreakpoint",
                json!({"eventName":"click","targetName":"*"}),
            )
            .await?;
        }
        self.memory_click.store(!existing, Ordering::Release);
        *self
            .memory_started
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
        self.update(|s|s["memory_origin_trace"]=json!({"protocol_version":1,"trace_id":id,"state":"armed","target_id":s["target"]["id"],"query":query,"scope":r["scope"].as_str().unwrap_or("all"),"case_sensitive":r["case_sensitive"]==true,"before_steps":r["before_steps"].as_u64().unwrap_or(3),"after_steps":r["after_steps"].as_u64().unwrap_or(8),"step_limit":32,"step_count":0,"first_match_step":null,"started_at_ms":validation::now_ms(),"elapsed_ms":0,"partial":false,"limit_reason":null,"message":"Trace armed. Click the page action that creates the value.","steps":[]}));
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(300)).await;
            if let Some(debugger) = weak.upgrade()
                && debugger.memory_active(id)
            {
                debugger
                    .finish_memory(
                        id,
                        "not_found",
                        "Trace reached its five-minute limit.",
                        true,
                        Some("time_limit"),
                        true,
                    )
                    .await;
            }
        });
        Ok(
            json!({"ok":true,"trace":self.snapshot()["memory_origin_trace"],"generation":self.snapshot()["generation"]}),
        )
    }
    pub(super) fn memory_active(&self, id: u64) -> bool {
        let s = self.snapshot();
        s["memory_origin_trace"]["trace_id"] == id
            && ["armed", "capturing", "stepping", "stopping"]
                .contains(&s["memory_origin_trace"]["state"].as_str().unwrap_or(""))
    }
    pub(super) async fn stop_memory(&self) -> Result<Value> {
        let trace = self.snapshot()["memory_origin_trace"].clone();
        let id = trace["trace_id"].as_u64().unwrap();
        if !self.memory_active(id) {
            return Err(Error::conflict("Memory Origin Trace is not running"));
        }
        if trace["state"] == "capturing" {
            self.update(|s| s["memory_origin_trace"]["state"] = json!("stopping"));
        } else {
            self.finish_memory(id, "aborted", "Trace stopped.", false, None, true)
                .await;
        }
        Ok(
            json!({"ok":true,"trace":self.snapshot()["memory_origin_trace"],"generation":self.snapshot()["generation"]}),
        )
    }
    pub(super) async fn memory_pause(self: &Arc<Self>, pause: Value) {
        let snapshot = self.snapshot();
        let trace = snapshot["memory_origin_trace"].clone();
        let id = trace["trace_id"].as_u64().unwrap();
        if !self.memory_active(id) {
            return;
        }
        self.update(|s| s["memory_origin_trace"]["state"] = json!("capturing"));
        let result = async {
            let _operation = self
                .heap
                .operation
                .try_lock()
                .map_err(|_| Error::conflict("A heap operation is already running"))?;
            let capture = self.capture_heap().await?;
            let mut args = vec![
                "--snapshot".into(),
                capture.file.path().display().to_string(),
                "--query".into(),
                trace["query"].as_str().unwrap().into(),
                "--scope".into(),
                trace["scope"].as_str().unwrap().into(),
                "--probe".into(),
            ];
            if trace["case_sensitive"] == true {
                args.push("--case-sensitive".into());
            }
            let result = self.heap_worker(args, 20).await?;
            validate_probe(&result, trace["scope"].as_str().unwrap())?;
            Ok::<_, Error>((capture, result))
        }
        .await;
        if !self.memory_active(id) {
            return;
        }
        if self.snapshot()["memory_origin_trace"]["state"] == "stopping" {
            self.finish_memory(id, "aborted", "Trace stopped.", false, None, true)
                .await;
            return;
        }
        let (capture, probe) = match result {
            Ok(result) => result,
            Err(e) => {
                self.finish_memory(id, "error", &e.message, true, None, true)
                    .await;
                return;
            }
        };
        let elapsed = self.memory_elapsed();
        let mut completion = None;
        let mut expected = 0;
        self.update(|s| {
            if s["paused"]!=pause {completion=Some(("error","Debugger pause changed before the heap probe completed.".to_owned(),true,Some("pause_changed")));return;}
            let trace=&mut s["memory_origin_trace"];let step=trace["step_count"].as_u64().unwrap()+1;expected=step;trace["step_count"]=json!(step);let partial=["node_limit_reached","edge_limit_reached","string_limit_reached"].iter().any(|k|probe[k]==true);if partial {trace["partial"]=json!(true);trace["limit_reason"]=json!("snapshot_coverage");}
            let first=probe["match_found"]==true && trace["first_match_step"].is_null();if first {trace["first_match_step"]=json!(step);}
            let location=memory_location(&snapshot,&pause);
            trace["steps"].as_array_mut().unwrap().push(json!({"id":format!("origin-{id}-{step}"),"step":step,"captured_at_ms":validation::now_ms(),"capture_bytes":capture.bytes.load(Ordering::Acquire),"duration_ms":probe["duration_ms"],"analyzed_nodes":probe["analyzed_nodes"],"total_nodes":probe["total_nodes"],"indexed_edges":probe["indexed_edges"],"total_edges":probe["total_edges"],"matched":probe["match_found"],"coverage_partial":partial,"is_first_match":first,"location":location,"match":probe["match"]}));
            if trace["first_match_step"].is_null() {let before=trace["before_steps"].as_u64().unwrap() as usize;let steps=trace["steps"].as_array_mut().unwrap();while steps.len()>before {steps.remove(0);}}
            trace["elapsed_ms"]=json!(elapsed);
            if trace["first_match_step"].as_u64().is_some_and(|first|step-first>=trace["after_steps"].as_u64().unwrap()) {completion=Some(("found",format!("First appearance found at debugger step {}.",trace["first_match_step"]),false,None));}
            else if step>=32 {completion=Some((if trace["first_match_step"].is_null() {"not_found"} else {"found"},"Trace reached its 32-step limit.".into(),true,Some("step_limit")));}
            else {trace["state"]=json!("stepping");trace["message"]=json!(if trace["first_match_step"].is_null() {"Value not present yet; stepping out to the next function boundary."} else {"First appearance found; collecting the requested after-window."});}
        });
        if let Some((state, message, partial, reason)) = completion {
            self.finish_memory(id, state, &message, partial, reason, true)
                .await;
            return;
        }
        if let Err(e) = self.command("Debugger.stepOut", json!({})).await {
            self.finish_memory(id, "error", &e.message, true, None, false)
                .await;
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2500)).await;
            if let Some(debugger) = weak.upgrade() {
                let trace = debugger.snapshot()["memory_origin_trace"].clone();
                if debugger.memory_active(id)
                    && trace["state"] == "stepping"
                    && trace["step_count"] == expected
                {
                    let found = !trace["first_match_step"].is_null();
                    debugger
                        .finish_memory(
                            id,
                            if found { "found" } else { "not_found" },
                            if found {
                                "Execution returned before another function-boundary pause."
                            } else {
                                "Execution returned before the value appeared."
                            },
                            found,
                            found.then_some("execution_quiet"),
                            false,
                        )
                        .await;
                }
            }
        });
    }
    async fn finish_memory(
        &self,
        id: u64,
        state: &str,
        message: &str,
        partial: bool,
        reason: Option<&str>,
        resume: bool,
    ) {
        if !self.memory_active(id) {
            return;
        }
        self.update(|s| {
            let trace = &mut s["memory_origin_trace"];
            trace["state"] = json!(state);
            trace["message"] = json!(validation::truncate(message, 512));
            trace["partial"] = json!(trace["partial"] == true || partial);
            if let Some(reason) = reason {
                trace["limit_reason"] = json!(reason);
            }
            trace["elapsed_ms"] = json!(self.memory_elapsed());
        });
        if self.memory_click.swap(false, Ordering::AcqRel) {
            let _ = self
                .command(
                    "DOMDebugger.removeEventListenerBreakpoint",
                    json!({"eventName":"click","targetName":"*"}),
                )
                .await;
        }
        if resume && self.snapshot()["state"] == "paused" {
            let _ = self.command("Debugger.resume", json!({})).await;
        }
    }
}
fn heap_counts(v: &Value) -> Result<()> {
    for (part, total) in [
        ("analyzed_nodes", "total_nodes"),
        ("matched_nodes", "analyzed_nodes"),
        ("reachable_nodes", "analyzed_nodes"),
        ("indexed_edges", "total_edges"),
    ] {
        if v[part].as_u64().unwrap_or(u64::MAX) > v[total].as_u64().unwrap_or(0) {
            return Err(Error::protocol(
                "Native heap snapshot returned invalid coverage",
            ));
        }
    }
    if v["file_bytes"].as_u64().unwrap_or(u64::MAX) > 256 * 1024 * 1024 {
        return Err(Error::protocol(
            "Native heap snapshot exceeds its byte limit",
        ));
    }
    Ok(())
}
fn validate_probe(v: &Value, scope: &str) -> Result<()> {
    if v["protocol_version"] != 1 || v["scope"] != scope {
        return Err(Error::protocol(
            "Native heap snapshot probe returned an unexpected scope or version",
        ));
    }
    for key in [
        "file_bytes",
        "total_nodes",
        "analyzed_nodes",
        "reachable_nodes",
        "total_edges",
        "indexed_edges",
        "total_strings",
        "duration_ms",
    ] {
        validation::integer(&v[key], key, 0, validation::MAX_SAFE_INTEGER)
            .map_err(|e| Error::protocol(e.message))?;
    }
    for key in [
        "match_found",
        "reachability_indexed",
        "node_limit_reached",
        "edge_limit_reached",
        "string_limit_reached",
    ] {
        if !v[key].is_boolean() {
            return Err(Error::protocol(
                "Native heap snapshot probe returned invalid limits",
            ));
        }
    }
    for (part, total) in [
        ("analyzed_nodes", "total_nodes"),
        ("reachable_nodes", "total_nodes"),
        ("indexed_edges", "total_edges"),
    ] {
        if v[part].as_u64().unwrap() > v[total].as_u64().unwrap() {
            return Err(Error::protocol(
                "Native heap snapshot probe returned invalid coverage",
            ));
        }
    }
    if (v["match_found"] == true) != v["match"].is_object() {
        return Err(Error::protocol(
            "Native heap snapshot probe returned a malformed match",
        ));
    }
    if v["match"].is_object() {
        validation::canonical(&v["match"]["id"], 64, false, "Heap node ID")
            .map_err(|e| Error::protocol(e.message))?;
        validation::integer(
            &v["match"]["self_size"],
            "Heap node size",
            0,
            validation::MAX_SAFE_INTEGER,
        )
        .map_err(|e| Error::protocol(e.message))?;
    }
    Ok(())
}

fn memory_location(snapshot: &Value, pause: &Value) -> Value {
    let frames = pause["call_frames"].as_array();
    let mut selected = frames.and_then(|a| a.first());
    let mut filtered = false;
    let url = |f: &Value| {
        f["url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                snapshot["scripts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|s| s["script_id"] == f["location"]["script_id"])
                    .and_then(|s| s["url"].as_str())
                    .unwrap_or("")
                    .to_owned()
            })
    };
    for frame in frames.into_iter().flatten() {
        let lower = url(frame).to_lowercase();
        if ["chrome-extension:", "devtools:", "extensions::"]
            .iter()
            .any(|s| lower.starts_with(s))
            || [
                "/node_modules/",
                "react",
                "react-dom",
                "redux",
                "vue",
                "angular",
                "jquery",
                "lodash",
                "rxjs",
                "core-js",
                "regenerator-runtime",
                "polyfill",
                "webpack",
                "vite",
                "rollup",
                "parcel",
                "zone.js",
            ]
            .iter()
            .any(|s| lower.contains(s))
        {
            filtered = true;
            continue;
        }
        selected = Some(frame);
        break;
    }
    selected.map(|f|json!({"script_id":f["location"]["script_id"],"url":validation::truncate(&url(f),65536),"function_name":validation::truncate(f["function_name"].as_str().unwrap_or("(anonymous)"),512),"line":f["location"]["line"],"column":f["location"]["column"],"framework_filtered":filtered})).unwrap_or_else(||json!({"script_id":"","url":"","function_name":"(unknown)","line":0,"column":0,"framework_filtered":filtered}))
}
