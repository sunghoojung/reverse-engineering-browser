use super::{Debugger, requests};
use crate::{
    error::{Error, Result},
    provenance, validation, worker,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{process::Command, sync::Semaphore};
pub(super) struct Fields {
    key: Mutex<[u8; 32]>,
    revision: AtomicU64,
    next: AtomicU64,
    request: AtomicU64,
    slots: Arc<Semaphore>,
}
fn key() -> [u8; 32] {
    use std::io::Read;
    let mut bytes = [0; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("Operating system random source");
    bytes
}
impl Fields {
    pub fn erase_session(&self) {
        *self.key.lock().unwrap_or_else(|e| e.into_inner()) = key();
        self.revision.fetch_add(1, Ordering::AcqRel);
    }

    pub fn new() -> Self {
        Self {
            key: Mutex::new(key()),
            revision: AtomicU64::new(0),
            next: AtomicU64::new(1),
            request: AtomicU64::new(1),
            slots: Arc::new(Semaphore::new(2)),
        }
    }
}
fn empty(status: &str) -> Value {
    json!({"status":status,"sha256":null,"preview":"","bytes":0})
}
fn selected(s: &str, raw: bool) -> Value {
    if s.len() > 4096 {
        return empty("value_too_large");
    }
    let string_value = if raw {
        json!(s)
    } else {
        serde_json::from_str::<Value>(s).unwrap_or(Value::Null)
    };
    let string_digest =
        provenance::project(&json!({"operation":"string_digest","value":string_value}))
            .unwrap_or(Value::Null);
    json!({"status":"available","string_sha256":string_digest,"sha256":hex::encode(Sha256::digest(s.as_bytes())), "preview":validation::truncate(s,256),"bytes":s.len()})
}
fn context_digest(address: &str, kind: &str, selector: &str, key: &[u8; 32]) -> Option<String> {
    let u = url::Url::parse(address).ok()?;
    let query = u.query().unwrap_or("");
    if query.len() > 8192 {
        return None;
    }
    let query = if kind == "query" {
        let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
        if pairs.len() > 1024 {
            return None;
        }
        let mut encoder = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            if k != selector {
                encoder.append_pair(&k, &v);
            }
        }
        encoder.finish()
    } else {
        query.to_owned()
    };
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for i in 0..32 {
        inner[i] ^= key[i];
        outer[i] ^= key[i];
    }
    let mut digest = Sha256::new();
    digest.update(inner);
    digest.update(query.as_bytes());
    let mut final_digest = Sha256::new();
    final_digest.update(outer);
    final_digest.update(digest.finalize());
    Some(hex::encode(final_digest.finalize()))
}
fn select_header(headers: &Value, selector: &str) -> Value {
    let Some(headers) = headers.as_object() else {
        return empty("uncaptured");
    };
    let matches = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(selector))
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return empty("missing");
    }
    if matches.len() != 1 || !matches[0].is_string() {
        return empty("ambiguous");
    }
    if matches[0].as_str().unwrap().len() > 4096 {
        return empty("value_too_large");
    }
    selected(&matches[0].to_string(), false)
}
fn select_pairs(source: &str, selector: &str) -> Value {
    if source.len() > 131072 {
        return empty("truncated");
    }
    let pairs = url::form_urlencoded::parse(source.as_bytes()).collect::<Vec<_>>();
    if pairs.len() > 1024 {
        return empty("unavailable");
    }
    let matches = pairs
        .into_iter()
        .filter(|(name, _)| name == selector)
        .map(|(_, v)| v)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return empty("missing");
    }
    if matches.len() != 1 {
        return empty("ambiguous");
    }
    selected(&json!(matches[0]).to_string(), false)
}
impl Debugger {
    pub(super) async fn configure_field(&self, r: &Value) -> Result<Value> {
        self.hooks_editable()?;
        let enabled = r["enabled"]
            .as_bool()
            .ok_or_else(|| Error::bad("Field enabled state must be boolean"))?;
        let mut field: Value =
            serde_json::from_str::<Value>(include_str!("../../assets/debugger-empty.json"))
                .unwrap()["runtime_hooks"]["field_test"]
                .clone();
        if enabled {
            if r["confirmed"] != true {
                return Err(Error::bad(
                    "Field capture requires explicit isolated-context confirmation",
                ));
            }
            let address = requests::text(&r["url"], "Field URL", 8192, false)?;
            let u = requests::url(&address)?;
            if u.query().is_some() || requests::redacted(&address) != address {
                return Err(Error::bad(
                    "Field URL must omit credentials, query, and fragment",
                ));
            }
            let method = requests::text(
                r.get("method").unwrap_or(&json!("POST")),
                "Field method",
                32,
                false,
            )?;
            if !method.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(Error::bad("Field method must be an uppercase HTTP method"));
            }
            let kind = r
                .get("kind")
                .unwrap_or(&json!("json"))
                .as_str()
                .filter(|s| ["json", "form", "query", "header", "body"].contains(s))
                .ok_or_else(|| Error::bad("Unsupported request value type"))?
                .to_owned();
            let pointer = requests::text(
                r.get("pointer").unwrap_or(&json!("")),
                "Field selector",
                256,
                true,
            )?;
            if kind == "json"
                && (!pointer.starts_with('/')
                    || pointer
                        .split('/')
                        .skip(1)
                        .any(|part| part.replace("~0", "").replace("~1", "").contains('~')))
                || ["form", "query", "header"].contains(&kind.as_str()) && pointer.is_empty()
                || kind == "body" && !pointer.is_empty()
                || kind == "header"
                    && !pointer
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
            {
                return Err(Error::bad("Invalid request value selector"));
            }
            self.command("Network.enable",json!({"maxPostDataSize":if self.options.capture_network_content {131072} else {0}})).await?;
            field["enabled"] = json!(true);
            field["url"] = json!(address);
            field["method"] = json!(method);
            field["kind"] = json!(kind);
            field["pointer"] = json!(pointer);
        }
        *self.fields.key.lock().unwrap_or_else(|e| e.into_inner()) = key();
        self.fields.revision.fetch_add(1, Ordering::AcqRel);
        self.update(|s| s["runtime_hooks"]["field_test"] = field);
        if !enabled && !self.options.capture_network_content {
            let _ = self.command("Network.disable", json!({})).await;
        }
        Ok(self.group_response("runtime_hooks"))
    }
    pub(super) fn compare_field(&self, r: &Value) -> Result<Value> {
        self.hooks_editable()?;
        let a = validation::integer(
            &r["baseline_id"],
            "Baseline observation ID",
            1,
            validation::MAX_SAFE_INTEGER,
        )?;
        let b = validation::integer(
            &r["variant_id"],
            "Variant observation ID",
            1,
            validation::MAX_SAFE_INTEGER,
        )?;
        if a == b {
            return Err(Error::bad("Choose two distinct field observations"));
        }
        let s = self.snapshot();
        let field = &s["runtime_hooks"]["field_test"];
        let observed = field["observations"].as_array().unwrap();
        let baseline = observed
            .iter()
            .find(|o| o["id"] == a && o["status"] == "available")
            .ok_or_else(|| Error::conflict("Baseline observation is unavailable"))?;
        let variant = observed
            .iter()
            .find(|o| o["id"] == b && o["status"] == "available")
            .ok_or_else(|| Error::conflict("Variant observation is unavailable"))?;
        if ["url", "method", "target_id"]
            .iter()
            .any(|key| baseline[*key] != variant[*key])
        {
            return Err(Error::bad(
                "Field observations must belong to the same request target",
            ));
        }
        let hits = s["runtime_hooks"]["hits"].as_array().unwrap();
        let related = |o: &Value, id: &Value| o["related_hit_ids"].as_array().unwrap().contains(id);
        let changed_hit = hits.iter().find(|h| {
            related(variant, &h["id"])
                && h["operation"] == "return_overridden"
                && h["category"] == "return"
        });
        let baseline_hit = hits.iter().find(|h| {
            related(baseline, &h["id"])
                && h["operation"] == "observed"
                && h["category"] == "return"
                && changed_hit.is_some_and(|c| {
                    h["source_hash"]
                        .as_str()
                        .is_some_and(|hash| !hash.is_empty())
                        && [
                            "target_id",
                            "source",
                            "script_id",
                            "source_hash",
                            "function",
                            "line",
                            "column",
                        ]
                        .iter()
                        .all(|key| h[*key] == c[*key])
                })
        });
        let overridden = hits
            .iter()
            .any(|h| related(baseline, &h["id"]) && h["operation"] == "return_overridden");
        let changed = baseline["sha256"] != variant["sha256"];
        let context = baseline["query_context_sha256"].is_string()
            && baseline["query_context_sha256"] == variant["query_context_sha256"];
        self.update(|s|s["runtime_hooks"]["field_test"]["comparison"]=json!({"baseline_id":a,"variant_id":b,"changed":changed,"same_query_context":context,"intervention_hit_id":changed_hit.map(|h|h["id"].clone()),"baseline_overridden":overridden,"interpretation":if changed&&context&&changed_hit.is_some()&&baseline_hit.is_some()&&!overridden {"intervention-associated"} else {"inconclusive"}}));
        Ok(self.group_response("runtime_hooks"))
    }
    async fn extract_field_value(
        &self,
        kind: &str,
        pointer: &str,
        body: Option<&str>,
        address: &str,
        headers: &Value,
    ) -> Value {
        match kind {
            "header" => select_header(headers, pointer),
            "query" => match url::Url::parse(address) {
                Ok(u) => select_pairs(u.query().unwrap_or(""), pointer),
                Err(_) => empty("unavailable"),
            },
            "form" => body.map_or_else(|| empty("uncaptured"), |b| select_pairs(b, pointer)),
            "body" => body.map_or_else(
                || empty("uncaptured"),
                |b| {
                    if b.len() > 131072 {
                        empty("truncated")
                    } else {
                        selected(b, true)
                    }
                },
            ),
            "json" => {
                let Some(body) = body else {
                    return empty("uncaptured");
                };
                if body.len() > 131072 {
                    return empty("truncated");
                }
                let path = self.options.worker(
                    &self.options.deobfuscator,
                    "reb-deobfuscator-worker",
                    "apps/deobfuscator-worker/target/debug/reb-deobfuscator-worker",
                );
                let mut command = Command::new(path);
                command.env_clear().env("LANG", "C").env("LC_ALL", "C");
                let request = serde_json::to_vec(
                    &json!({"operation":"request_field","body":body,"pointer":pointer}),
                )
                .unwrap();
                let result =
                    worker::run(&mut command, &request, 8192, Duration::from_secs(1)).await;
                let Ok(result) = result else {
                    return empty("unavailable");
                };
                if !result.success {
                    return empty("unavailable");
                }
                let Ok(v) = serde_json::from_slice::<Value>(&result.bytes) else {
                    return empty("unavailable");
                };
                let statuses = [
                    "available",
                    "missing",
                    "invalid_json",
                    "invalid_pointer",
                    "body_too_large",
                    "value_too_large",
                    "unavailable",
                    "error",
                    "uncaptured",
                    "truncated",
                    "ambiguous",
                ];
                let Some(status) = v["status"].as_str().filter(|s| statuses.contains(s)) else {
                    return empty("unavailable");
                };
                if v["schema"] != "reb-request-field-v1" {
                    return empty("unavailable");
                }
                if status == "available" {
                    match v["value"].as_str().filter(|s| s.len() <= 4096) {
                        Some(value) => selected(value, false),
                        None => empty("unavailable"),
                    }
                } else if v["value"].is_null() {
                    empty(status)
                } else {
                    empty("unavailable")
                }
            }
            _ => empty("unavailable"),
        }
    }
    pub(super) async fn hook_network(self: &Arc<Self>, target: &str, method: &str, p: &Value) {
        let Some(request_id) = p["requestId"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 4096)
        else {
            return;
        };
        let s = self.snapshot();
        let field = &s["runtime_hooks"]["field_test"];
        if method == "Network.responseReceived" {
            let status = p["response"]["status"]
                .as_f64()
                .filter(|n| (100.0..=599.0).contains(n));
            if let Some(status) = status {
                self.update(|s| {
                    if let Some(r) = s["runtime_hooks"]["requests"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .rev()
                        .find(|r| r["target_id"] == target && r["request_id"] == request_id)
                    {
                        r["status"] = json!(status as u64);
                    }
                });
            }
            return;
        }
        if method == "Network.requestWillBeSentExtraInfo" {
            if field["enabled"] == true && field["kind"] == "header" {
                let mut result = select_header(&p["headers"], field["pointer"].as_str().unwrap());
                let digest = result
                    .as_object_mut()
                    .unwrap()
                    .remove("string_sha256")
                    .unwrap_or(Value::Null);
                if result["status"] == "available" {
                    let s_snapshot = s.clone();
                    self.update(|s| {
                        let field = &mut s["runtime_hooks"]["field_test"];
                        if let Some(o) = field["observations"]
                            .as_array_mut()
                            .unwrap()
                            .iter_mut()
                            .rev()
                            .find(|o| o["target_id"] == target && o["request_id"] == request_id)
                        {
                            let id = o["id"].clone();
                            // ExtraInfo can arrive after the original extraction. Keep its
                            // request-time cutoff and observed call sites when updating a header.
                            let retained = provenance::project(&json!({"operation":"snapshot","hits":s_snapshot["runtime_hooks"]["hits"],"target_id":target,"occurred_at_ms":o["occurred_at_ms"]}));
                            if let Ok(retained) = retained {
                                let gaps = o["provenance"]["gaps"].as_array().into_iter().flatten().filter(|gap| matches!(gap.as_str(),Some("initiator_unavailable"|"malformed_call_site"|"call_site_limit"|"async_parent_unresolved"))).cloned().collect::<Vec<_>>();
                                if let Ok(projection) = provenance::project(&json!({"operation":"build","selected_digest":digest,"hits":retained["hits"],"limited":retained["limited"],"call_sites":{"sites":o["provenance"]["call_sites"],"gaps":gaps}})) { o["provenance"] = projection; }
                            }
                            for (k, v) in result.as_object().unwrap() {
                                o[k] = v.clone();
                            }
                            if field["comparison"]["baseline_id"] == id
                                || field["comparison"]["variant_id"] == id
                            {
                                field["comparison"] = Value::Null;
                            }
                        }
                    });
                }
            }
            return;
        }
        if method != "Network.requestWillBeSent" {
            return;
        }
        let request = &p["request"];
        let Some(raw_url) = request["url"].as_str().filter(|u| u.len() <= 8192) else {
            return;
        };
        let address = requests::redacted(raw_url);
        if address.is_empty() {
            return;
        }
        let method = request["method"].as_str().unwrap_or("");
        let safe = url::Url::parse(raw_url).is_ok_and(|u| {
            u.username().is_empty() && u.password().is_none() && u.fragment().is_none()
        });
        let matched = field["enabled"] == true
            && safe
            && field["url"] == address
            && field["method"] == method;
        let active =
            ["armed", "handling"].contains(&s["runtime_hooks"]["state"].as_str().unwrap_or(""));
        if !matched && !active {
            return;
        }
        let now = validation::now_ms();
        let hits = s["runtime_hooks"]["hits"].as_array().unwrap();
        let recent = |id: &str| {
            hits.iter()
                .rev()
                .find(|h| {
                    h["target_id"] == id
                        && h["occurred_at_ms"]
                            .as_u64()
                            .is_some_and(|t| now >= t && now - t <= 5000)
                })
                .map(|h| h["id"].clone())
        };
        let mut related = Vec::new();
        if active {
            if let Some(page) = s["runtime_hooks"]["target_id"].as_str().and_then(recent) {
                related.push(page);
            }
            if target != s["runtime_hooks"]["target_id"].as_str().unwrap_or("")
                && let Some(worker) = recent(target)
            {
                related.push(worker);
            }
        }
        let kind = field["kind"].as_str().unwrap().to_owned();
        let pointer = field["pointer"].as_str().unwrap().to_owned();
        let session = s["runtime_hooks"]["session_id"].clone();
        let revision = self.fields.revision.load(Ordering::Acquire);
        let query = context_digest(
            raw_url,
            &kind,
            &pointer,
            &self.fields.key.lock().unwrap_or_else(|e| e.into_inner()),
        );
        let mut permit = if matched {
            self.fields.slots.clone().try_acquire_owned().ok()
        } else {
            None
        };
        let mut status = "uncaptured";
        if matched
            && (["query", "header"].contains(&kind.as_str())
                || request["postData"].is_string()
                || request["hasPostData"] == true)
        {
            status = if permit.is_some() {
                "pending"
            } else {
                "unavailable"
            };
            if ["json", "form", "body"].contains(&kind.as_str())
                && request["postData"]
                    .as_str()
                    .is_some_and(|b| b.len() > 131072)
            {
                status = "truncated";
            }
        }
        if query.is_none() {
            status = "truncated";
        }
        if status != "pending" {
            permit = None;
        }
        let observation = if matched {
            Some(self.fields.next.fetch_add(1, Ordering::Relaxed))
        } else {
            None
        };
        let mut provenance_input = if matched {
            let retained = provenance::project(
                &json!({"operation":"snapshot","hits":if active {json!(hits)} else {json!([])},"target_id":target,"occurred_at_ms":now}),
            );
            let sites = provenance::project(
                &json!({"operation":"call_sites","initiator":p["initiator"],"target_id":target,"scripts":provenance::catalog(&s)}),
            );
            match (retained, sites) {
                (Ok(retained), Ok(sites)) => Some(
                    json!({"operation":"build","hits":retained["hits"],"limited":retained["limited"],"call_sites":sites,"selected_digest":null}),
                ),
                _ => None,
            }
        } else {
            None
        };
        let initial_provenance = provenance_input
            .as_ref()
            .and_then(|input| provenance::project(input).ok());
        if matched && initial_provenance.is_none() {
            status = "error";
            permit = None;
        }
        self.update(|s| {let h=&mut s["runtime_hooks"];let target_type=if h["target_id"]==target {"page"} else {"worker"};let record=json!({"id":self.fields.request.fetch_add(1,Ordering::Relaxed),"occurred_at_ms":now,"target_id":target,"target_type":if h["target_id"]==target {"page"} else {"worker"},"request_id":request_id,"url":address,"method":validation::truncate(method,32),"resource_type":validation::truncate(p["type"].as_str().unwrap_or(""),32),"status":null,"related_hit_ids":related,"relation":if related.is_empty() {"unlinked"} else {"same-context temporal proximity, inferred"}});let requests=h["requests"].as_array_mut().unwrap();let evicted=requests.len()==128;if evicted {requests.remove(0);}requests.push(record);if evicted {h["request_evictions"]=json!(h["request_evictions"].as_u64().unwrap()+1);}
if let Some(id)=observation {let mut o=json!({"id":id,"occurred_at_ms":now,"target_id":target,"request_id":request_id,"target_type":target_type,"url":address,"method":validation::truncate(method,32),"query_context_sha256":query,"related_hit_ids":related,"status":status,"sha256":null,"preview":"","bytes":0});if let Some(projection)=&initial_provenance {o["provenance"]=projection.clone();}else {h["last_failure"]=json!("Field provenance projection rejected malformed evidence");}let field=&mut h["field_test"];let observations=field["observations"].as_array_mut().unwrap();let evicted=if observations.len()==16 {Some(observations.remove(0)["id"].clone())} else {None};observations.push(o);if let Some(id)=evicted {field["observation_evictions"]=json!(field["observation_evictions"].as_u64().unwrap()+1);if field["comparison"]["baseline_id"]==id||field["comparison"]["variant_id"]==id {field["comparison"]=Value::Null;}}}});
        if let (Some(permit), Some(id)) = (permit, observation) {
            let weak = Arc::downgrade(self);
            let target = target.to_owned();
            let request_id = request_id.to_owned();
            let address = raw_url.to_owned();
            let body = request["postData"]
                .as_str()
                .filter(|b| b.len() <= 131072)
                .map(str::to_owned);
            let headers = if kind == "header" {
                request["headers"]
                    .as_object()
                    .map(|h| {
                        json!(
                            h.iter()
                                .filter(|(k, v)| k.eq_ignore_ascii_case(&pointer)
                                    && v.as_str().is_some_and(|s| s.len() <= 131072))
                                .collect::<BTreeMap<_, _>>()
                        )
                    })
                    .unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            let extra = p["hasExtraInfo"] == true;
            tokio::spawn(async move {
                let _permit = permit;
                let Some(d) = weak.upgrade() else {
                    return;
                };
                let mut body = body;
                if body.is_none()
                    && ["json", "form", "body"].contains(&kind.as_str())
                    && let Ok(s) = d.hook_session(&target).await
                    && let Ok(result) = s
                        .command(
                            "Network.getRequestPostData",
                            json!({"requestId":request_id}),
                            Duration::from_secs(1),
                        )
                        .await
                {
                    body = result["postData"].as_str().map(str::to_owned);
                }
                let mut result = d
                    .extract_field_value(&kind, &pointer, body.as_deref(), &address, &headers)
                    .await;
                if kind == "header" && extra && result["status"] == "missing" {
                    result = empty("unavailable");
                }
                let digest = result
                    .as_object_mut()
                    .unwrap()
                    .remove("string_sha256")
                    .unwrap_or(Value::Null);
                if let Some(input) = &mut provenance_input {
                    input["selected_digest"] = digest;
                    match provenance::project(input) {
                        Ok(projection) => result["provenance"] = projection,
                        Err(_) => result = empty("error"),
                    }
                }
                if d.fields.revision.load(Ordering::Acquire) != revision
                    || d.snapshot()["runtime_hooks"]["session_id"] != session
                {
                    return;
                }
                d.update(|s| {
                    if let Some(o) = s["runtime_hooks"]["field_test"]["observations"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|o| o["id"] == id && o["status"] == "pending")
                    {
                        for (key, value) in result.as_object().unwrap() {
                            o[key] = value.clone();
                        }
                    }
                });
            });
        }
    }
}
