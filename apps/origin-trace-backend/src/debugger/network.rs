use super::Debugger;
use crate::{
    error::{Error, Result},
    provenance, validation,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
fn bounded(v: &Value, max: usize) -> (String, bool) {
    let s = v.as_str().unwrap_or("");
    (validation::truncate(s, max), s.len() > max)
}
fn url(v: &Value) -> (String, bool) {
    let (s, truncated) = bounded(v, 65536);
    match url::Url::parse(&s) {
        Ok(mut url) => {
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.set_fragment(None);
            (url.to_string(), truncated)
        }
        Err(_) => (String::new(), !s.is_empty()),
    }
}
fn headers(v: &Value) -> Vec<Value> {
    let mut output = Vec::new();
    let mut retained = 0;
    for (key, value) in v.as_object().into_iter().flatten() {
        let Some(value) = value.as_str() else {
            continue;
        };
        let key = validation::truncate(key, 128);
        if key.is_empty() {
            continue;
        }
        let value = if [
            "authorization",
            "cookie",
            "proxy-authorization",
            "set-cookie",
        ]
        .contains(&key.to_ascii_lowercase().as_str())
        {
            "<redacted>".into()
        } else {
            validation::truncate(value, 8192)
        };
        if output.len() >= 128 || retained + key.len() + value.len() > 65536 {
            break;
        }
        retained += key.len() + value.len();
        output.push(json!([key, value]));
    }
    output
}
fn mime(headers: &[Value], fallback: &str) -> String {
    headers
        .iter()
        .find(|h| {
            h[0].as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("content-type"))
        })
        .and_then(|h| h[1].as_str())
        .unwrap_or(fallback)
        .into()
}
fn record<'a>(state: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    state["network"]["requests"]
        .as_array_mut()?
        .iter_mut()
        .rev()
        .find(|r| r["protocol_request_id"] == id)
}
fn response(state: &mut Value, p: &Value) {
    let Some(id) = p["requestId"].as_str() else {
        return;
    };
    let Some(record) = record(state, id) else {
        return;
    };
    let r = &p["response"];
    if !r.is_object() {
        return;
    }
    let h = headers(&r["headers"]);
    let (m, _) = bounded(&r["mimeType"], 512);
    record["status"] = r["status"]
        .as_f64()
        .map(|n| json!(n as i64))
        .unwrap_or(Value::Null);
    for (key, raw, max) in [
        ("status_text", "statusText", 512),
        ("protocol", "protocol", 128),
    ] {
        record[key] = json!(bounded(&r[raw], max).0);
    }
    record["mime_type"] = json!(m);
    record["from_disk_cache"] = json!(r["fromDiskCache"] == true);
    record["from_service_worker"] = json!(r["fromServiceWorker"] == true);
    record["response"]["body"]["mime"] = json!(mime(&h, &m));
    record["response"]["headers"] = json!(h);
    if record["method"] == "HEAD" || [204, 205, 304].iter().any(|s| record["status"] == *s) {
        record["response"]["body"]["state"] = json!("empty");
        record["response"]["body"]["reason"] = json!("This HTTP response has no body.");
    }
}
fn finish(state: &mut Value, p: &Value, failed: bool, redirected: bool) -> Option<String> {
    let id = p["requestId"].as_str()?;
    let record = record(state, id)?;
    record["state"] = json!(if failed { "failed" } else { "complete" });
    if let Some(time) = p["timestamp"].as_f64() {
        let duration =
            (time * 1000.0 - record["started_monotonic_ms"].as_f64().unwrap_or(0.0)).max(0.0);
        record["duration_ms"] = json!((duration * 1000.0).round_ties_even() / 1000.0);
    }
    if let Some(size) = p["encodedDataLength"].as_f64() {
        record["encoded_data_length"] = json!(size.max(0.0).round_ties_even() as u64);
    }
    if failed {
        let error = bounded(&p["errorText"], 512).0;
        record["error_text"] = json!(error);
        record["response"]["body"]["state"] = json!("error");
        record["response"]["body"]["reason"] = json!(if error.is_empty() {
            "The request failed before a response body was available."
        } else {
            &error
        });
        return None;
    }
    if redirected {
        record["response"]["body"]["state"] = json!("missing");
        record["response"]["body"]["reason"] =
            json!("CDP does not retain response bodies for redirect hops.");
        return None;
    }
    if record["response"]["body"]["state"] == "empty" {
        return None;
    }
    record["response"]["body"]["state"] = json!("loading");
    record["response"]["body"]["reason"] = json!("Loading response body through CDP.");
    record["id"].as_str().map(str::to_owned)
}
impl Debugger {
    pub(super) async fn network(self: &Arc<Self>, method: &str, p: &Value) {
        if !self.options.capture_network_content {
            return;
        }
        let mut retrieve = None;
        match method {
            "Network.requestWillBeSent" => {
                let Some(id) = p["requestId"]
                    .as_str()
                    .filter(|s| !s.is_empty() && s.len() <= 4096)
                else {
                    return;
                };
                let request = &p["request"];
                let Some(timestamp) = p["timestamp"].as_f64() else {
                    return;
                };
                let (url, truncated) = url(&request["url"]);
                let (method, method_truncated) = bounded(&request["method"], 32);
                if url.is_empty() || method.is_empty() {
                    return;
                }
                let headers = headers(&request["headers"]);
                let mime = mime(&headers, "text/plain");
                let body = if let Some(data) = request["postData"].as_str() {
                    json!({"state":"available","mime":mime,"text":validation::truncate(data,131072),"base64":"","truncated":data.len()>131072,"reason":""})
                } else {
                    json!({"state":if request["hasPostData"]==true {"missing"} else {"empty"},"mime":mime,"text":"","base64":"","truncated":false,"reason":if request["hasPostData"]==true {"CDP reported request data but did not retain its bytes."} else {"This request has no body."}})
                };
                self.update(|s| {
                    if p["redirectResponse"].is_object() {response(s,&json!({"requestId":id,"response":p["redirectResponse"]}));finish(s,&json!({"requestId":id,"timestamp":timestamp,"encodedDataLength":p["redirectResponse"]["encodedDataLength"]}),false,true);}
                    let target=s["target"]["id"].as_str().unwrap_or("unknown").to_owned();let title=s["target"]["title"].clone();let initiator=provenance::project(&json!({"operation":"call_sites","initiator":p["initiator"],"target_id":target,"scripts":provenance::catalog(s)})).unwrap_or_else(|_|json!({"sites":[],"gaps":["initiator_unavailable"]}));let requests=s["network"]["requests"].as_array_mut().unwrap();let redirect=requests.iter().filter(|r|r["protocol_request_id"]==id).count();let suffix=if redirect>0 {format!(":redirect:{redirect}")} else {String::new()};
                    let r=json!({"initiator":initiator,"id":format!("cdp:{target}:{id}{suffix}"),"protocol_request_id":id,"target_id":target,"target_title":title,"url":url,"url_truncated":truncated,"method":method,"method_truncated":method_truncated,"resource_type":bounded(&p["type"],128).0,"document_url":url::Url::parse(p["documentURL"].as_str().unwrap_or("")).ok().map(|mut u| {let _=u.set_username("");let _=u.set_password(None);u.set_fragment(None);u.to_string()}).unwrap_or_default(),"started_monotonic_ms":timestamp*1000.0,"wall_time_ms":p["wallTime"].as_f64().map(|v|(v*1000.0).round_ties_even() as u64).unwrap_or(0),"state":"pending","status":null,"status_text":"","protocol":"","mime_type":"","duration_ms":null,"encoded_data_length":0,"from_disk_cache":false,"from_service_worker":false,"error_text":"","request":{"headers":headers,"body":body},"response":{"headers":[],"body":{"state":"loading","mime":"","text":"","base64":"","truncated":false,"reason":"Waiting for the response to complete."}}});
                    if requests.len()>=1000 {requests.remove(0);let dropped=s["network"]["dropped"].as_u64().unwrap_or(0)+1;s["network"]["dropped"]=json!(dropped);}s["network"]["requests"].as_array_mut().unwrap().push(r);
                });
            }
            "Network.responseReceived" => self.update(|s| response(s, p)),
            "Network.loadingFinished" | "Network.loadingFailed" => {
                self.update(|s| retrieve = finish(s, p, method.ends_with("Failed"), false))
            }
            _ => (),
        }
        if let Some(public) = retrieve {
            let Some(protocol) = p["requestId"].as_str().map(str::to_owned) else {
                return;
            };
            let permit = match self.network_workers.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    self.update(|s| {
                        if let Some(record) = s["network"]["requests"]
                            .as_array_mut()
                            .unwrap()
                            .iter_mut()
                            .find(|r| r["id"] == public)
                        {
                            record["response"]["body"]["state"] = json!("error");
                            record["response"]["body"]["reason"] =
                                json!("The bounded response-body retrieval queue was full.");
                        }
                    });
                    return;
                }
            };
            let connection = self.connection.lock().await.clone();
            let weak = Arc::downgrade(self);
            tokio::spawn(async move {
                let _permit = permit;
                let result = if let Some(connection) = connection {
                    connection
                        .command(
                            "Network.getResponseBody",
                            json!({"requestId":protocol}),
                            Duration::from_secs(5),
                        )
                        .await
                        .and_then(|v| body(&v))
                } else {
                    Err(Error::conflict("Debugger target is unavailable"))
                };
                if let Some(debugger) = weak.upgrade() {
                    debugger.update(|s| {
                        if let Some(record) = s["network"]["requests"]
                            .as_array_mut()
                            .unwrap()
                            .iter_mut()
                            .find(|r| r["id"] == public)
                        {
                            match result {
                                Ok(value) => {
                                    let mime = record["response"]["body"]["mime"].clone();
                                    record["response"]["body"] = value;
                                    record["response"]["body"]["mime"] = mime;
                                }
                                Err(e) => {
                                    record["response"]["body"]["state"] = json!("error");
                                    record["response"]["body"]["reason"] =
                                        json!(validation::truncate(&e.message, 512));
                                }
                            }
                        }
                    });
                }
            });
        }
    }
}
fn body(v: &Value) -> Result<Value> {
    let raw = v["body"]
        .as_str()
        .ok_or_else(|| Error::protocol("CDP returned a malformed response body"))?;
    let (text, base64, truncated) = if v["base64Encoded"] == true {
        let bytes = STANDARD
            .decode(raw)
            .map_err(|_| Error::protocol("CDP returned invalid base64 response data"))?;
        (
            String::new(),
            STANDARD.encode(&bytes[..bytes.len().min(131072)]),
            bytes.len() > 131072,
        )
    } else {
        (
            validation::truncate(raw, 131072),
            String::new(),
            raw.len() > 131072,
        )
    };
    Ok(
        json!({"state":"available","mime":"","text":text,"base64":base64,"truncated":truncated,"reason":""}),
    )
}
