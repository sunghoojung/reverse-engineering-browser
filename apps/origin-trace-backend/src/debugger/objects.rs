use super::{Debugger, connection::Connection, requests};
use crate::{
    error::{Error, Result},
    validation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
pub(super) struct Objects {
    retained: Mutex<Option<Retained>>,
    next: AtomicU64,
    navigation: AtomicU64,
    audit: AtomicU64,
}
struct Retained {
    group: String,
    objects: String,
    connection: Arc<Connection>,
    indices: BTreeSet<u64>,
    search: u64,
    session: Value,
    navigation: Value,
    target: String,
}
impl Objects {
    pub fn new() -> Self {
        Self {
            retained: Mutex::new(None),
            next: AtomicU64::new(1),
            navigation: AtomicU64::new(1),
            audit: AtomicU64::new(1),
        }
    }
}
fn criteria(r: &Value) -> Result<Value> {
    let property = requests::text(
        r.get("property_query").unwrap_or(&json!("")),
        "Property query",
        512,
        true,
    )?;
    let value = requests::text(
        r.get("value_query").unwrap_or(&json!("")),
        "Value query",
        512,
        true,
    )?;
    let class = requests::text(
        r.get("class_query").unwrap_or(&json!("")),
        "Class query",
        512,
        true,
    )?;
    let boolean = |key| -> Result<bool> {
        r.get(key)
            .unwrap_or(&json!(false))
            .as_bool()
            .ok_or_else(|| Error::bad("Search options must be boolean"))
    };
    let shape = requests::text(
        r.get("shape").unwrap_or(&json!("")),
        "Search shape",
        4096,
        true,
    )?;
    let shape = if shape.trim().is_empty() {
        Value::Null
    } else {
        let v: Value = serde_json::from_str(&shape)
            .map_err(|_| Error::bad("Search shape must be valid JSON"))?;
        if !v.is_object() && !v.is_array() {
            return Err(Error::bad("Search shape must be an object or array"));
        }
        v
    };
    let threshold = r
        .get("similarity_threshold")
        .unwrap_or(&json!(0.75))
        .as_f64()
        .filter(|n| n.is_finite() && (0.0..=1.0).contains(n))
        .ok_or_else(|| Error::bad("Similarity threshold must be between 0 and 1"))?;
    if property.is_empty() && value.is_empty() && class.is_empty() && shape.is_null() {
        return Err(Error::bad(
            "Live object search requires at least one criterion",
        ));
    }
    Ok(
        json!({"propertyQuery":property,"valueQuery":value,"classQuery":class,"regex":boolean("regex")?,"caseSensitive":boolean("case_sensitive")?,"shape":shape,"includeShapeValues":boolean("include_shape_values")?,"similarityThreshold":threshold,"resultLimit":50,"scanLimit":25000,"previewProperties":16,"propertyScanLimit":256,"timeoutMs":750}),
    )
}
fn search_result(v: &Value) -> Result<Value> {
    if v["protocolVersion"] != 2 || v["resultLimit"] != 50 {
        return Err(Error::protocol("Malformed live object search result"));
    }
    let mut output = json!({"protocol_version":2});
    for (a, b) in [
        ("analyzed", "analyzed"),
        ("totalObjects", "total_objects"),
        ("resultLimit", "result_limit"),
        ("durationMs", "duration_ms"),
    ] {
        output[b] = json!(
            validation::integer(&v[a], a, 0, validation::MAX_SAFE_INTEGER)
                .map_err(|e| Error::protocol(e.message))?
        );
    }
    for (a, b) in [
        ("resultLimitReached", "result_limit_reached"),
        ("scanLimitReached", "scan_limit_reached"),
        ("propertyLimitReached", "property_limit_reached"),
        ("timedOut", "timed_out"),
    ] {
        output[b] = json!(
            v[a].as_bool()
                .ok_or_else(|| Error::protocol("Malformed live object coverage"))?
        );
    }
    let results = v["results"]
        .as_array()
        .filter(|a| a.len() <= 50)
        .ok_or_else(|| Error::protocol("Too many live object results"))?;
    output["results"] = json!(results.iter().map(object).collect::<Result<Vec<_>>>()?);
    Ok(output)
}
fn object(v: &Value) -> Result<Value> {
    let text = |key, max| -> Result<String> {
        Ok(validation::truncate(
            v[key]
                .as_str()
                .ok_or_else(|| Error::protocol("Malformed live object text"))?,
            max,
        ))
    };
    let count = validation::integer(&v["propertyCount"], "Property count", 0, i32::MAX as u64)
        .map_err(|e| Error::protocol(e.message))?;
    let truncated = v["propertiesTruncated"]
        .as_bool()
        .ok_or_else(|| Error::protocol("Malformed property coverage"))?;
    if !v["similarity"].is_null()
        && !v["similarity"]
            .as_f64()
            .is_some_and(|n| n.is_finite() && (0.0..=1.0).contains(&n))
    {
        return Err(Error::protocol("Malformed object similarity"));
    }
    let properties=v["preview"].as_array().filter(|a|a.len()<=16).ok_or_else(||Error::protocol("Malformed object preview"))?.iter().map(|p| {let text=|key,max|->Result<String>{Ok(validation::truncate(p[key].as_str().ok_or_else(||Error::protocol("Malformed property preview"))?,max))};Ok(json!({"name":text("name",512)?,"type":text("type",128)?,"value":text("value",512)?}))}).collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"id":text("id",128)?,"class_name":text("className",256)?,"property_count":count,"properties_truncated":truncated,"similarity":v["similarity"],"preview":properties}),
    )
}
fn object_id(v: &Value, field: &str) -> Result<String> {
    if v["exceptionDetails"].is_object() {
        return Err(Error::conflict("Live object search failed in the target"));
    }
    validation::text(
        &v[field]["objectId"],
        "Runtime object ID",
        4096,
        false,
        false,
    )
    .map(str::to_owned)
    .map_err(|e| Error::protocol(e.message))
}
impl Debugger {
    pub(super) async fn clear_object_search(&self) {
        let retained = self
            .objects
            .retained
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(r) = retained {
            let _ = r
                .connection
                .command(
                    "Runtime.releaseObjectGroup",
                    json!({"objectGroup":r.group}),
                    Duration::from_secs(3),
                )
                .await;
        }
        self.update(|s| {
            s["object_experiment"]["search_id"] = json!(0);
            s["object_experiment"]["search"] = Value::Null;
            s["object_experiment"]["results"] = json!([]);
            s["object_experiment"]["last_mutation"] = Value::Null;
        });
    }
    pub(super) async fn search_objects(&self, r: &Value, isolated: bool) -> Result<Value> {
        let criteria = criteria(r)?;
        let snapshot = self.snapshot();
        let target = if isolated {
            self.isolated_target("object_experiment", true)?
        } else {
            snapshot["target"]["id"]
                .as_str()
                .ok_or_else(|| Error::conflict("Debugger target is unavailable"))?
                .into()
        };
        let connection = self
            .connection
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::conflict("Debugger target is unavailable"))?;
        let search = self.objects.next.fetch_add(1, Ordering::Relaxed);
        let session = snapshot["object_experiment"]["session_id"].clone();
        let navigation = snapshot["object_experiment"]["navigation_id"].clone();
        if isolated {
            self.clear_object_search().await;
            self.update(|s| {
                s["object_experiment"]["state"] = json!("searching");
                s["object_experiment"]["message"] =
                    json!("Searching the isolated page without invoking property getters.");
            });
        }
        let group = if isolated {
            format!("reb-object-experiment-{session}-{navigation}-{search}")
        } else {
            "reb-live-object-search".into()
        };
        let mut prototype = None;
        let mut objects = None;
        let result=async {let p=connection.command("Runtime.evaluate",json!({"expression":"Object.prototype","objectGroup":group,"silent":true}),Duration::from_secs(3)).await?;prototype=Some(object_id(&p,"result")?);let mut params=json!({"prototypeObjectId":prototype});if isolated {params["objectGroup"]=json!(group);}let queried=connection.command("Runtime.queryObjects",params,Duration::from_secs(5)).await?;objects=Some(object_id(&queried,"objects")?);let result=connection.command("Runtime.callFunctionOn",json!({"objectId":objects,"functionDeclaration":include_str!("../../assets/live-object-search-function.js"),"arguments":[{"value":criteria}],"returnByValue":true,"silent":true,"awaitPromise":false,"userGesture":false,"timeout":750}),Duration::from_secs(3)).await?;if result["exceptionDetails"].is_object() {return Err(Error::conflict("Live object search failed in the target"));}search_result(&result["result"]["value"])}.await;
        if let Some(id) = prototype {
            let _ = connection
                .command(
                    "Runtime.releaseObject",
                    json!({"objectId":id}),
                    Duration::from_secs(3),
                )
                .await;
        }
        if !isolated {
            if let Some(id) = objects {
                let _ = connection
                    .command(
                        "Runtime.releaseObject",
                        json!({"objectId":id}),
                        Duration::from_secs(3),
                    )
                    .await;
            }
            return result
                .map(|v| json!({"ok":true,"search":v,"generation":self.snapshot()["generation"]}));
        }
        let result = match result {
            Ok(result) => result,
            Err(e) => {
                let _ = connection
                    .command(
                        "Runtime.releaseObjectGroup",
                        json!({"objectGroup":group}),
                        Duration::from_secs(3),
                    )
                    .await;
                self.update(|s| {
                    s["object_experiment"]["state"] = json!("error");
                    s["object_experiment"]["message"] = json!(e.message);
                });
                return Err(e);
            }
        };
        let validate = || -> Result<BTreeSet<u64>> {
            let mut indices = BTreeSet::new();
            for row in result["results"].as_array().unwrap() {
                let id = row["id"].as_str().unwrap();
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::protocol("Invalid Object Lab result identifier"));
                }
                let index = id
                    .parse::<u64>()
                    .map_err(|_| Error::protocol("Invalid Object Lab index"))?;
                if index >= result["total_objects"].as_u64().unwrap() || !indices.insert(index) {
                    return Err(Error::protocol("Stale Object Lab result identifier"));
                }
            }
            let current = self.snapshot();
            if current["object_experiment"]["session_id"] != session
                || current["object_experiment"]["navigation_id"] != navigation
                || current["target"]["id"] != target
            {
                return Err(Error::conflict("Object Lab search became stale"));
            }
            Ok(indices)
        };
        let indices = match validate() {
            Ok(indices) => indices,
            Err(e) => {
                let _ = connection
                    .command(
                        "Runtime.releaseObjectGroup",
                        json!({"objectGroup":group}),
                        Duration::from_secs(3),
                    )
                    .await;
                return Err(e);
            }
        };
        *self
            .objects
            .retained
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Retained {
            group,
            objects: objects.unwrap(),
            connection,
            indices,
            search,
            session,
            navigation,
            target,
        });
        self.update(|s| {
            s["object_experiment"]["state"] = json!("loaded");
            s["object_experiment"]["search_id"] = json!(search);
            let mut summary = result.clone();
            summary.as_object_mut().unwrap().remove("results");
            s["object_experiment"]["search"] = summary;
            s["object_experiment"]["results"] = result["results"].clone();
            s["object_experiment"]["message"] = json!(format!(
                "Found {} matching live objects in the isolated page.",
                result["results"].as_array().unwrap().len()
            ));
        });
        Ok(self.group_response("object_experiment"))
    }
    pub(super) async fn navigate_object(&self, r: &Value) -> Result<Value> {
        let address = requests::text(&r["url"], "Object Lab URL", 8192, false)?
            .trim()
            .to_owned();
        requests::url(&address)?;
        let target = self.isolated_target("object_experiment", false)?;
        self.clear_object_search().await;
        let navigation = self.objects.navigation.fetch_add(1, Ordering::Relaxed);
        let connection = self
            .connection
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::conflict("Isolated page is unavailable"))?;
        self.update(|s| {
            s["object_experiment"]["state"] = json!("navigating");
            s["object_experiment"]["navigation_id"] = json!(navigation);
            s["object_experiment"]["url"] = json!(requests::redacted(&address));
            s["object_experiment"]["message"] =
                json!("Opening one credential-free page inside the disposable context.");
        });
        let result=async {let result=connection.command("Page.navigate",json!({"url":address}),Duration::from_secs(5)).await?;if result["errorText"].as_str().is_some_and(|s|!s.is_empty()) {return Err(Error::conflict(format!("Object Lab navigation failed: {}",result["errorText"])));}let deadline=tokio::time::Instant::now()+Duration::from_secs(15);loop {if tokio::time::Instant::now()>=deadline {return Err(Error::conflict("Object Lab page did not become interactive within 15 seconds"));}
if let Ok(result)=connection.command("Runtime.evaluate",json!({"expression":"({protocolVersion:1,readyState:document.readyState,url:location.href})","returnByValue":true,"silent":true,"throwOnSideEffect":true}),Duration::from_secs(2)).await {let v=&result["result"]["value"];if result["exceptionDetails"].is_null()&&v["protocolVersion"]==1&&[json!("interactive"),json!("complete")].contains(&v["readyState"]) {let address=v["url"].as_str().ok_or_else(||Error::protocol("Malformed navigation URL"))?;let mut url=url::Url::parse(address).map_err(|_|Error::conflict("Navigation URL is invalid"))?;url.set_fragment(None);requests::url(url.as_str())?;return Ok(requests::redacted(url.as_str()));}}tokio::time::sleep(Duration::from_millis(50)).await;}}.await;
        if self.snapshot()["target"]["id"] != target
            || self.snapshot()["object_experiment"]["navigation_id"] != navigation
        {
            return Err(Error::conflict("Object Lab navigation became stale"));
        }
        match result {
            Ok(address) => self.update(|s| {
                s["object_experiment"]["state"] = json!("loaded");
                s["object_experiment"]["url"] = json!(address);
                s["object_experiment"]["message"] =
                    json!("Isolated page loaded. Run a bounded live-object search.");
            }),
            Err(e) => {
                self.update(|s| {
                    s["object_experiment"]["state"] = json!("error");
                    s["object_experiment"]["message"] = json!(e.message);
                });
                return Err(e);
            }
        }
        Ok(self.group_response("object_experiment"))
    }
    pub(super) async fn mutate_object(&self, r: &Value) -> Result<Value> {
        if ![json!("set"), json!("delete")].contains(&r["operation"]) || r["confirmed"] != true {
            return Err(Error::bad(
                "Object Lab mutation requires a valid operation and explicit confirmation",
            ));
        }
        let operation = r["operation"].as_str().unwrap();
        let search = validation::integer(
            &r["search_id"],
            "Search ID",
            1,
            validation::MAX_SAFE_INTEGER,
        )?;
        let result_id = requests::text(&r["result_id"], "Result ID", 128, false)?;
        let index = result_id
            .parse::<u64>()
            .map_err(|_| Error::bad("Invalid result identifier"))?;
        let property = requests::text(&r["property"], "Property name", 256, false)?;
        if ["__proto__", "constructor", "prototype"].contains(&property.as_str())
            || property.chars().any(|c| c < ' ' || c == '\u{7f}')
        {
            return Err(Error::bad("Object Lab property name is not allowed"));
        }
        let (bytes, digest) = if operation == "set" {
            let value = r
                .get("value")
                .ok_or_else(|| Error::bad("Object Lab set requires a JSON value"))?;
            let mut entries = 0;
            validate_value(value, 0, &mut entries)?;
            let bytes = serde_json::to_vec(value)?;
            if bytes.len() > 16384 {
                return Err(Error::bad("Object Lab JSON value exceeds 16 KiB"));
            }
            (bytes.len(), Some(hex::encode(Sha256::digest(&bytes))))
        } else {
            if r.get("value").is_some() {
                return Err(Error::bad("Object Lab delete does not accept a value"));
            }
            (0, None)
        };
        let target = self.isolated_target("object_experiment", true)?;
        let s = self.snapshot();
        if s["object_experiment"]["mutation_attempts"]
            .as_u64()
            .unwrap()
            >= 256
        {
            return Err(Error::conflict(
                "Object Lab reached the 256-attempt session limit",
            ));
        }
        let (connection, objects, group, session, navigation) = {
            let retained = self
                .objects
                .retained
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let r = retained
                .as_ref()
                .filter(|r| {
                    r.search == search
                        && r.target == target
                        && r.indices.contains(&index)
                        && r.session == s["object_experiment"]["session_id"]
                        && r.navigation == s["object_experiment"]["navigation_id"]
                })
                .ok_or_else(|| {
                    Error::conflict("Object Lab result is stale; run the live-object search again")
                })?;
            (
                r.connection.clone(),
                r.objects.clone(),
                r.group.clone(),
                r.session.clone(),
                r.navigation.clone(),
            )
        };
        let selected = s["object_experiment"]["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == result_id)
            .cloned()
            .ok_or_else(|| Error::conflict("Object Lab result is unavailable"))?;
        self.update(|s| {
            s["object_experiment"]["mutation_attempts"] = json!(
                s["object_experiment"]["mutation_attempts"]
                    .as_u64()
                    .unwrap()
                    + 1
            );
            s["object_experiment"]["state"] = json!("mutating");
            s["object_experiment"]["message"] = json!(format!(
                "Applying one confirmed {operation} operation inside Object Lab."
            ));
        });
        let mut candidate = None;
        let result=async {let result=connection.command("Runtime.callFunctionOn",json!({"objectId":objects,"functionDeclaration":"function(index){const value=this[index];if((typeof value!==\"object\"&&typeof value!==\"function\")||value===null)throw new TypeError(\"Object Lab result is unavailable\");return value;}","arguments":[{"value":index}],"returnByValue":false,"objectGroup":group,"silent":true}),Duration::from_secs(3)).await?;candidate=Some(object_id(&result,"result")?);let mut config=json!({"operation":operation,"property":property,"previewProperties":16,"resultId":result_id,"similarity":selected["similarity"]});if operation=="set" {config["value"]=r["value"].clone();}let evaluated=connection.command("Runtime.callFunctionOn",json!({"objectId":candidate,"functionDeclaration":include_str!("../../assets/object-experiment-mutate-function.js"),"arguments":[{"value":config}],"returnByValue":true,"silent":true,"awaitPromise":false,"userGesture":false,"timeout":1000}),Duration::from_secs(3)).await?;if evaluated["exceptionDetails"].is_object() {return Err(Error::conflict("Object Lab mutation failed in the target"));}mutation(&evaluated["result"]["value"])}.await;
        if let Some(id) = candidate {
            let _ = connection
                .command(
                    "Runtime.releaseObject",
                    json!({"objectId":id}),
                    Duration::from_secs(3),
                )
                .await;
        }
        let m=result.unwrap_or_else(|e|json!({"ok":false,"outcome":"error","error":validation::truncate(&e.message,512),"before":empty_descriptor(),"after":empty_descriptor(),"object":null}));
        if self.snapshot()["object_experiment"]["session_id"] != session
            || self.snapshot()["object_experiment"]["navigation_id"] != navigation
        {
            return Err(Error::conflict("Object Lab mutation became stale"));
        }
        self.update(|s| {let o=&mut s["object_experiment"];let id=self.objects.audit.fetch_add(1,Ordering::Relaxed);let audit=json!({"id":id,"occurred_at_ms":validation::now_ms(),"session_id":session,"navigation_id":navigation,"search_id":search,"result_id":result_id,"operation":operation,"property":property,"target_class":selected["class_name"],"outcome":m["outcome"],"success":m["ok"],"before_type":m["before"]["type"],"after_type":m["after"]["type"],"value_bytes":bytes,"value_digest":digest,"url":o["url"]});let entries=o["audit"].as_array_mut().unwrap();let evicted=entries.len()==128;if evicted {entries.remove(0);}entries.push(audit);if evicted {o["audit_evictions"]=json!(o["audit_evictions"].as_u64().unwrap()+1);}let stale=o["search_id"]!=search;if !stale {if !m["object"].is_null() {for result in o["results"].as_array_mut().unwrap() {if result["id"]==result_id {*result=m["object"].clone();}}}o["state"]=json!("loaded");}o["last_mutation"]=json!({"audit_id":id,"ok":m["ok"],"operation":operation,"property":property,"result_id":result_id,"outcome":m["outcome"],"error":m["error"],"before":m["before"],"after":m["after"],"value_bytes":bytes,"value_digest":digest});o["message"]=json!(if m["ok"]==true {format!("Object Lab {operation} completed and audit entry {id} was recorded.")} else {format!("Object Lab rejected the mutation: {}",m["error"])});});
        Ok(self.group_response("object_experiment"))
    }
}
fn validate_value(v: &Value, depth: usize, entries: &mut usize) -> Result<()> {
    if depth > 8 {
        return Err(Error::bad("Object Lab JSON value exceeds depth 8"));
    }
    match v {
        Value::Number(n) => {
            if n.as_i64()
                .is_some_and(|n| n.unsigned_abs() > validation::MAX_SAFE_INTEGER)
                || n.as_u64().is_some_and(|n| n > validation::MAX_SAFE_INTEGER)
            {
                return Err(Error::bad(
                    "Object Lab integer exceeds JavaScript's exact range",
                ));
            }
        }
        Value::String(s) => {
            if s.len() > 4096 {
                return Err(Error::bad("Object Lab JSON string exceeds 4 KiB"));
            }
        }
        Value::Array(a) => {
            *entries += a.len();
            if *entries > 256 {
                return Err(Error::bad("Object Lab JSON value exceeds 256 entries"));
            }
            for v in a {
                validate_value(v, depth + 1, entries)?;
            }
        }
        Value::Object(o) => {
            *entries += o.len();
            if *entries > 256 {
                return Err(Error::bad("Object Lab JSON value exceeds 256 entries"));
            }
            for (k, v) in o {
                if k.len() > 4096 {
                    return Err(Error::bad("Object Lab JSON object key exceeds 4 KiB"));
                }
                validate_value(v, depth + 1, entries)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn empty_descriptor() -> Value {
    json!({"exists":false,"type":"unknown","class_name":"","writable":false,"configurable":false,"preview":null})
}
fn descriptor(v: &Value) -> Result<Value> {
    let kind = validation::text(&v["type"], "Descriptor type", 128, false, true)
        .map_err(|e| Error::protocol(e.message))?;
    let class = v
        .get("className")
        .unwrap_or(&json!(""))
        .as_str()
        .filter(|s| s.len() <= 256)
        .ok_or_else(|| Error::protocol("Malformed descriptor class"))?
        .to_owned();
    let boolfield = |k| {
        v[k].as_bool()
            .ok_or_else(|| Error::protocol("Malformed property descriptor"))
    };
    let preview = if v["preview"].is_null() {
        Value::Null
    } else {
        json!(validation::truncate(
            v["preview"]
                .as_str()
                .ok_or_else(|| Error::protocol("Malformed descriptor preview"))?,
            512
        ))
    };
    Ok(
        json!({"exists":boolfield("exists")?,"type":kind,"class_name":class,"writable":boolfield("writable")?,"configurable":boolfield("configurable")?,"preview":preview}),
    )
}
fn mutation(v: &Value) -> Result<Value> {
    if v["protocolVersion"] != 1
        || !v["ok"].is_boolean()
        || ![
            "created",
            "updated",
            "deleted",
            "missing",
            "non_configurable",
            "rejected",
            "accessor",
            "non_writable",
            "non_extensible",
            "error",
        ]
        .contains(&v["outcome"].as_str().unwrap_or(""))
        || (!v["error"].is_null() && !v["error"].as_str().is_some_and(|s| s.len() <= 512))
        || v["ok"] != v["error"].is_null()
    {
        return Err(Error::protocol("Malformed Object Lab mutation result"));
    }
    let object = if v["object"].is_null() {
        if v["ok"] == true {
            return Err(Error::protocol(
                "Object Lab omitted the patched object preview",
            ));
        }
        Value::Null
    } else {
        object(&v["object"])?
    };
    Ok(
        json!({"ok":v["ok"],"outcome":v["outcome"],"error":v["error"],"before":descriptor(&v["before"])? ,"after":descriptor(&v["after"])? ,"object":object}),
    )
}
