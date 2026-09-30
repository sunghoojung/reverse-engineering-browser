use super::{Debugger, requests};
use crate::{
    error::{Error, Result},
    validation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) struct Repeater {
    pub next: AtomicU64,
    pub key: String,
}
impl Repeater {
    pub fn new() -> Self {
        use std::io::Read;
        let mut bytes = [0; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .expect("Operating system random source");
        Self {
            next: AtomicU64::new(1),
            key: format!("__reb_repeater_{}", hex::encode(bytes)),
        }
    }
}
impl Debugger {
    fn repeater_ready(&self) -> Result<()> {
        let s = self.snapshot();
        if self.experiment.context().is_none()
            || s["target"]["id"] != s["request_interception"]["target_id"]
            || !["running", "paused"].contains(&s["state"].as_str().unwrap_or(""))
        {
            return Err(Error::conflict("The isolated Repeater target is not ready"));
        }
        Ok(())
    }
    pub(super) fn repeater_variables(&self, r: &Value) -> Result<Value> {
        self.repeater_ready()?;
        let variables = requests::variables(r.get("variables").unwrap_or(&json!({})))?;
        self.update(|s| {
            s["repeater"]["variables"] = variables.clone();
            s["repeater"]["state"] = json!("ready");
            s["repeater"]["message"] = json!(format!(
                "{} session-scoped Repeater variables are ready.",
                variables.as_array().unwrap().len()
            ));
        });
        Ok(self.group_response("repeater"))
    }
    pub(super) async fn run_repeater(self: &Arc<Self>, r: &Value) -> Result<Value> {
        self.repeater_ready()?;
        let template = requests::template(r)?;
        let (resolved, names) =
            requests::resolve(&template, &self.snapshot()["repeater"]["variables"])?;
        if !self.snapshot()["repeater"]["active_execution"].is_null() {
            return Err(Error::conflict("A Repeater request is already running"));
        }
        let execution = self.repeater.next.fetch_add(1, Ordering::Relaxed);
        let session = self.snapshot()["repeater"]["session_id"].clone();
        let started = validation::now_ms();
        let connection = self
            .connection
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::conflict("Isolated page is disconnected"))?;
        self.update(|s| {s["repeater"]["state"]=json!("running");s["repeater"]["active_execution"]=json!({"execution_id":execution,"started_at_ms":started,"request":template,"resolved_url":requests::redacted(resolved["url"].as_str().unwrap()),"resolved_method":resolved["method"],"variable_names":names,"collection_request_id":template["collection_request_id"],"cancel_requested":false});s["repeater"]["message"]=json!("Sending one credential-free Repeater request through the disposable page.");});
        let key = json!(self.repeater.key).to_string();
        let identifier = json!(execution.to_string()).to_string();
        let expression = format!(
            "(() => {{ const key={key},id={identifier};let registry=globalThis[key];if(!(registry instanceof Map)){{registry=new Map();Object.defineProperty(globalThis,key,{{value:registry,configurable:true}});}}if(registry.size>=1||registry.has(id))return false;registry.set(id,new AbortController());return true; }})()"
        );
        let installation=connection.command("Runtime.evaluate",json!({"expression":expression,"returnByValue":true,"awaitPromise":false,"silent":true,"userGesture":false}),Duration::from_secs(3)).await;
        if !installation
            .as_ref()
            .is_ok_and(|v| v["result"]["value"] == true)
        {
            let e = installation.err().unwrap_or_else(|| {
                Error::conflict("Repeater could not reserve a request controller")
            });
            self.update(|s| {
                s["repeater"]["active_execution"] = Value::Null;
                s["repeater"]["state"] = json!("error");
                s["repeater"]["message"] = json!(e.message);
            });
            return Err(e);
        }
        let configuration = json!({"url":resolved["url"],"method":resolved["method"],"headers":requests::header_map(&resolved["headers"]),"body":resolved["body"],"timeoutMs":resolved["timeout_ms"],"headerLimit":64,"headerValueLimit":2048,"headerTotalLimit":16384,"responseByteLimit":65536,"controllerRegistryKey":self.repeater.key,"executionId":execution.to_string()});
        let weak = Arc::downgrade(self);
        let timeout = resolved["timeout_ms"].as_u64().unwrap();
        tokio::spawn(async move {
            let clock = Instant::now();
            let evaluated=connection.command("Runtime.evaluate",json!({"expression":format!("({})({configuration})",include_str!("../../assets/request-interception-function.js")),"returnByValue":true,"awaitPromise":true,"silent":true,"userGesture":false,"timeout":timeout}),Duration::from_millis(timeout+2000)).await;
            let result = evaluated.and_then(|value| {
                if value["exceptionDetails"].is_object() {
                    return Err(Error::conflict(
                        "The isolated Repeater runner failed before returning a result",
                    ));
                }
                requests::result(&value["result"]["value"], true)
            });
            let Some(debugger) = weak.upgrade() else {
                return;
            };
            let s = debugger.snapshot();
            if s["repeater"]["session_id"] != session
                || s["repeater"]["active_execution"]["execution_id"] != execution
            {
                return;
            }
            let response=result.unwrap_or_else(|e| {let cancelled=s["repeater"]["active_execution"]["cancel_requested"]==true;json!({"protocol_version":1,"ok":false,"status":0,"status_text":"","url":"","headers":[],"headers_truncated":false,"body":"","body_truncated":false,"error":if cancelled {"Request cancelled".to_owned()} else {validation::truncate(&e.message,512)},"duration_ms":clock.elapsed().as_millis().min(35000) as u64,"cancelled":cancelled,"timed_out":false,"body_sha256":hex::encode(Sha256::digest(b""))})});
            debugger.update(|s| {let state=if response["ok"]==true {"complete"} else if response["cancelled"]==true {"cancelled"} else if response["timed_out"]==true {"timed_out"} else {"error"};let mut entry=json!({"id":execution,"started_at_ms":started,"completed_at_ms":validation::now_ms().max(started),"state":state,"collection_request_id":template["collection_request_id"],"variable_names":names,"request":template,"resolved_request":resolved,"response":response});let bytes=serde_json::to_vec(&entry).unwrap().len();entry["stored_bytes"]=json!(bytes);let r=&mut s["repeater"];let mut retained=r["history_bytes"].as_u64().unwrap() as usize;let mut evictions=0;let history=r["history"].as_array_mut().unwrap();while !history.is_empty()&&(history.len()>=24||retained+bytes>524288) {let old=history.remove(0);retained=retained.saturating_sub(old["stored_bytes"].as_u64().unwrap() as usize);evictions+=1;}history.push(entry);retained+=bytes;let successful=history.iter().filter(|e|e["response"]["ok"]==true).collect::<Vec<_>>();let comparison=if successful.len()>=2 {Some(requests::compare(successful[successful.len()-2],successful[successful.len()-1]))} else {None};let ids=history.iter().map(|e|e["id"].clone()).collect::<Vec<_>>();r["history_bytes"]=json!(retained);r["history_evictions"]=json!(r["history_evictions"].as_u64().unwrap()+evictions);if let Some(c)=comparison {r["comparison"]=c;} else if !r["comparison"].is_null()&&(!ids.contains(&r["comparison"]["baseline_id"])||!ids.contains(&r["comparison"]["current_id"])) {r["comparison"]=Value::Null;}r["active_execution"]=Value::Null;r["state"]=json!("ready");r["message"]=json!(if response["ok"]==true {format!("Repeater request completed with status {}.",response["status"])} else if response["cancelled"]==true {"Repeater request was cancelled.".into()} else if response["timed_out"]==true {"Repeater request reached its timeout.".into()} else {format!("Repeater request failed: {}",response["error"])});});
        });
        Ok(self.group_response("repeater"))
    }
    pub(super) async fn cancel_repeater(&self) -> Result<Value> {
        let id = self.snapshot()["repeater"]["active_execution"]["execution_id"]
            .as_u64()
            .ok_or_else(|| Error::conflict("No Repeater request is running"))?;
        self.update(|s| {
            s["repeater"]["active_execution"]["cancel_requested"] = json!(true);
            s["repeater"]["state"] = json!("cancelling");
            s["repeater"]["message"] = json!("Cancelling the active Repeater request.");
        });
        let key = json!(self.repeater.key).to_string();
        let identifier = json!(id.to_string()).to_string();
        let expression = format!(
            "(() => {{const registry=globalThis[{key}],controller=registry instanceof Map?registry.get({identifier}):null;if(!(controller instanceof AbortController))return false;controller.abort();return true;}})()"
        );
        let result=self.command("Runtime.evaluate",json!({"expression":expression,"returnByValue":true,"awaitPromise":false,"silent":true,"userGesture":false})).await.and_then(|v|v["result"]["value"].as_bool().ok_or_else(||Error::protocol("Malformed cancellation result")));
        if !result.as_ref().is_ok_and(|v| *v) {
            self.update(|s| {
                if s["repeater"]["active_execution"]["execution_id"] == id {
                    s["repeater"]["active_execution"]["cancel_requested"] = json!(false);
                    s["repeater"]["state"] = json!("running");
                    s["repeater"]["message"] = json!(if result.is_err() {
                        "Cancellation could not be delivered; the request is still running."
                    } else {
                        "The request completed before cancellation was delivered."
                    });
                }
            });
        }
        result?;
        Ok(self.group_response("repeater"))
    }
    pub(super) fn compare_repeater(&self, r: &Value) -> Result<Value> {
        let a = validation::integer(
            &r["baseline_id"],
            "Baseline ID",
            1,
            validation::MAX_SAFE_INTEGER,
        )?;
        let b = validation::integer(
            &r["current_id"],
            "Current ID",
            1,
            validation::MAX_SAFE_INTEGER,
        )?;
        if a == b {
            return Err(Error::bad(
                "Repeater comparison requires distinct identifiers",
            ));
        }
        let s = self.snapshot();
        let history = s["repeater"]["history"].as_array().unwrap();
        let a = history
            .iter()
            .find(|e| e["id"] == a && e["response"]["ok"] == true)
            .ok_or_else(|| Error::conflict("Baseline response is unavailable"))?;
        let b = history
            .iter()
            .find(|e| e["id"] == b && e["response"]["ok"] == true)
            .ok_or_else(|| Error::conflict("Current response is unavailable"))?;
        self.update(|s| s["repeater"]["comparison"] = requests::compare(a, b));
        Ok(self.group_response("repeater"))
    }
    pub(super) fn clear_repeater(&self) -> Result<Value> {
        if !self.snapshot()["repeater"]["active_execution"].is_null() {
            return Err(Error::conflict(
                "Finish or cancel the active Repeater request before clearing history",
            ));
        }
        self.update(|s| {
            let r = &mut s["repeater"];
            r["history"] = json!([]);
            r["history_bytes"] = json!(0);
            r["history_evictions"] = json!(0);
            r["comparison"] = Value::Null;
            r["message"] = json!("Repeater history and comparisons were cleared.");
        });
        Ok(self.group_response("repeater"))
    }
}
