//! Explicit, short-lived live handles. Retained module bytes do not prove live
//! instance ownership; never select or join objects by URL or artifact name.
use super::{Debugger, connection::Connection};
use crate::{
    error::{Error, Result},
    validation,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const LIMIT: usize = 32;
const LIFETIME: Duration = Duration::from_secs(60);
const BOUNDED_ARRAY: &str = include_str!("../../assets/live-wasm-list.js");

pub(super) struct WasmLive {
    next: AtomicU64,
    retained: Mutex<Option<Arc<Listing>>>,
}
struct Listing {
    id: u64,
    target: Value,
    epoch: Value,
    session: Value,
    navigation: Value,
    context: Option<String>,
    scope: &'static str,
    captured: Value,
    connection: Arc<Connection>,
    group: String,
    created: Instant,
    objects: BTreeMap<String, (String, String)>,
}
impl WasmLive {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            retained: Mutex::new(None),
        }
    }
}
fn remote_id(response: &Value, field: &str) -> Result<String> {
    if response["exceptionDetails"].is_object() {
        return Err(Error::conflict(
            "Live Wasm inspection failed in the selected target; verify that its WebAssembly built-ins are available",
        ));
    }
    validation::text(
        &response[field]["objectId"],
        "Live Wasm object handle",
        4096,
        false,
        false,
    )
    .map(str::to_owned)
    .map_err(|_| Error::protocol("Debugger returned no live Wasm object handle"))
}
impl Debugger {
    pub(super) async fn clear_live_wasm(&self) {
        let retained = {
            let mut retained = self
                .wasm_live
                .retained
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.wasm_live.next.fetch_add(1, Ordering::AcqRel);
            retained.take()
        };
        if let Some(listing) = retained {
            release_group(&listing.connection, &listing.group).await;
        }
    }
    async fn live_wasm_current(&self, listing: &Listing) -> Result<()> {
        let connection = self.connection.lock().await;
        self.live_wasm_current_on(listing, connection.as_ref())
    }
    fn live_wasm_current_on(
        &self,
        listing: &Listing,
        connection: Option<&Arc<Connection>>,
    ) -> Result<()> {
        if listing.connection.has_dropped_events() {
            return Err(Error::conflict(
                "Debugger events were lost; attached document ownership is uncertain. Reconnect the debugger and list live Wasm objects again. Other pages are refused.",
            ));
        }
        let context = self.experiment.context();
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.wasm_live.next.load(Ordering::Acquire) != listing.id.saturating_add(1)
            || listing.created.elapsed() >= LIFETIME
            || !same_owner(listing, &state, context.as_deref())
            || listing.connection.is_closed()
            || !connection.is_some_and(|c| Arc::ptr_eq(c, &listing.connection))
        {
            return Err(Error::conflict(
                "Live Wasm selection expired or its page/document changed; list live Wasm objects again. Other pages are refused.",
            ));
        }
        Ok(())
    }
    async fn synchronize_live_wasm(&self, listing: &Listing) -> Result<()> {
        self.live_wasm_current(listing).await?;
        // Bound queue admission as well as acknowledgement. No ownership locks
        // remain held while queued lifecycle events are applied.
        tokio::time::timeout(Duration::from_secs(5), listing.connection.barrier())
            .await
            .map_err(|_| Error::conflict("Live Wasm ownership event barrier timed out"))??;
        self.live_wasm_current(listing).await
    }
    async fn live_wasm_command(
        &self,
        listing: &Listing,
        method: &str,
        params: Value,
        deadline: Duration,
    ) -> Result<Value> {
        self.synchronize_live_wasm(listing).await?;
        listing.connection.command_guarded(method, params, deadline, || {
            self.connection.try_lock().is_ok_and(|connection| {
                self.live_wasm_current_on(listing, connection.as_ref()).is_ok()
            })
        }).await?.ok_or_else(|| Error::conflict(
            "Live Wasm command was not sent because document ownership could not be revalidated; reconnect and list objects again",
        ))
    }
    async fn expire_live_wasm(&self, id: u64) {
        let expired = {
            let mut retained = self
                .wasm_live
                .retained
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if retained
                .as_ref()
                .is_some_and(|r| r.id == id && r.created.elapsed() >= LIFETIME)
            {
                retained.take()
            } else {
                None
            }
        };
        if let Some(expired) = expired {
            release_group(&expired.connection, &expired.group).await;
        }
    }
    pub(super) async fn list_live_wasm(self: &Arc<Self>, request: &Value) -> Result<Value> {
        let s = self.snapshot();
        let scope = classify_live_wasm(request, &s, self.experiment.context().as_deref())?;
        let connection = self
            .connection
            .lock()
            .await
            .clone()
            .filter(|c| !c.is_closed())
            .ok_or_else(|| {
                Error::conflict("Attach a running debugger target before listing live Wasm objects")
            })?;
        self.clear_live_wasm().await;
        let id = self.wasm_live.next.fetch_add(1, Ordering::Relaxed);
        let group = format!("reb-live-wasm-{id}");
        let mut listing = Listing {
            id,
            target: s["target"]["id"].clone(),
            epoch: s["target_document_epoch"].clone(),
            session: s["object_experiment"]["session_id"].clone(),
            navigation: s["object_experiment"]["navigation_id"].clone(),
            context: if scope == "object_experiment" {
                self.experiment.context()
            } else {
                None
            },
            scope,
            captured: if scope == "captured_document" {
                request["captured_owner"].clone()
            } else {
                Value::Null
            },
            connection: connection.clone(),
            group: group.clone(),
            created: Instant::now(),
            objects: BTreeMap::new(),
        };
        let mut rows = Vec::new();
        let mut coverage = Vec::new();
        let result: Result<()> = async {
            for (constructor, kind) in [
                ("Instance", "instance"), ("Module", "module"), ("Memory", "memory")
            ] {
                self.live_wasm_current(&listing).await?;
                let prototype = self.live_wasm_command(&listing,
                    "Runtime.evaluate",
                    json!({"expression": format!("WebAssembly.{constructor}.prototype"),
                        "objectGroup": group, "silent": true, "timeout": 1000}),
                    Duration::from_secs(3),
                ).await?;
                let prototype = remote_id(&prototype, "result")?;
                let all = self.live_wasm_command(&listing,
                    "Runtime.queryObjects",
                    json!({"prototypeObjectId": prototype, "objectGroup": group}),
                    Duration::from_secs(5),
                ).await?;
                let all = remote_id(&all, "objects")?;
                let count = self.live_wasm_command(&listing,
                    "Runtime.callFunctionOn",
                    json!({"objectId": all, "functionDeclaration": "function(){return this.length;}",
                        "returnByValue": true, "silent": true, "timeout": 1000}),
                    Duration::from_secs(3),
                ).await?;
                let total = validation::integer(
                    &count["result"]["value"], "Live Wasm object count", 0,
                    validation::MAX_SAFE_INTEGER,
                ).map_err(|_| Error::protocol("Debugger returned an invalid live Wasm count"))?;
                let bounded = self.live_wasm_command(&listing,
                    "Runtime.callFunctionOn",
                    json!({"objectId": all, "functionDeclaration": BOUNDED_ARRAY,
                        "objectGroup": group, "silent": true, "timeout": 1000}),
                    Duration::from_secs(3),
                ).await?;
                let bounded = remote_id(&bounded, "result")?;
                let props = self.live_wasm_command(&listing,
                    "Runtime.getProperties",
                    json!({"objectId": bounded, "ownProperties": true, "generatePreview": false}),
                    Duration::from_secs(3),
                ).await?;
                for object in [&prototype, &all, &bounded] {
                    connection.command(
                        "Runtime.releaseObject", json!({"objectId": object}),
                        Duration::from_secs(3),
                    ).await?;
                }
                let descriptors = props["result"].as_array().filter(|a| a.len() <= LIMIT + 1)
                    .ok_or_else(|| Error::protocol("Debugger returned an oversized live Wasm listing"))?;
                let mut found = 0;
                for property in descriptors {
                    if property["name"] == "length" { continue; }
                    let index = property["name"].as_str().and_then(|s| s.parse::<usize>().ok())
                        .filter(|n| *n < LIMIT)
                        .ok_or_else(|| Error::protocol("Debugger returned an invalid live Wasm index"))?;
                    if property.get("get").is_some() || property["value"]["subtype"] == "proxy"
                        || property["value"]["className"] != constructor {
                        return Err(Error::protocol("Debugger returned a non-Wasm object for its prototype"));
                    }
                    let handle = remote_id(property, "value")?;
                    let key = format!("{kind}:{index}");
                    if listing.objects.insert(key.clone(), (kind.into(), handle)).is_some() {
                        return Err(Error::protocol("Debugger repeated a live Wasm object index"));
                    }
                    rows.push(json!({"id": key, "kind": kind, "script_id": null,
                        "artifact_id": null, "linkage": "unavailable"}));
                    found += 1;
                }
                if found as u64 != total.min(LIMIT as u64) {
                    return Err(Error::protocol("Debugger live Wasm count and listing disagree"));
                }
                coverage.push(json!({"kind": kind, "total_objects": total,
                    "returned_objects": found, "truncated": total > LIMIT as u64}));
            }
            self.synchronize_live_wasm(&listing).await
        }.await;
        if let Err(error) = result {
            release_group(&connection, &group).await;
            return Err(error);
        }
        // The public handle lifetime starts when collection finishes, not when
        // the first potentially slow renderer query began.
        listing.created = Instant::now();
        let result = json!({"ok":true,"generation":self.state.lock().unwrap_or_else(|e| e.into_inner())["generation"],"wasm":{"listing_id":id,"target_id":listing.target,"document_epoch":listing.epoch,"expires_after_ms":60000,"per_kind_limit":LIMIT,"objects":rows,"coverage":coverage,"scope":"selected-default-realm","owner_scope":listing.scope,"captured_owner":listing.captured,"linkage_reason":"CDP prototype queries do not prove module-to-script/artifact identity; no name or URL join is inferred"}});
        if let Err(error) = validation::schema("DebuggerLiveWasmResult", &result, 422) {
            release_group(&connection, &group).await;
            return Err(error);
        }
        let admitted = {
            let mut retained = self
                .wasm_live
                .retained
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.wasm_live.next.load(Ordering::Acquire) == id.saturating_add(1) {
                *retained = Some(Arc::new(listing));
                true
            } else {
                false
            }
        };
        if !admitted {
            release_group(&connection, &group).await;
            return Err(Error::conflict(
                "Live Wasm listing was superseded or invalidated; list objects again",
            ));
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::time::sleep(LIFETIME).await;
            if let Some(debugger) = weak.upgrade() {
                debugger.expire_live_wasm(id).await;
            }
        });
        Ok(result)
    }
    pub(super) async fn read_live_wasm(&self, request: &Value) -> Result<Value> {
        let snapshot = self.snapshot();
        let scope = classify_live_wasm(request, &snapshot, self.experiment.context().as_deref())?;
        let listing = self
            .wasm_live
            .retained
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| {
                Error::conflict("List live Wasm objects before reading a memory slice")
            })?;
        if request["listing_id"] != listing.id
            || request["target_id"] != listing.target
            || listing.scope != scope
            || (scope == "captured_document" && request["captured_owner"] != listing.captured)
            || (scope == "object_experiment" && request.get("captured_owner").is_some())
        {
            return Err(Error::conflict(
                "Live Wasm listing or target does not match this request. List objects again. Captured reads repeat captured_owner; Object Lab reads omit it. Other pages are refused.",
            ));
        }
        self.live_wasm_current(&listing).await?;
        let (kind, object) = request["object_id"]
            .as_str()
            .and_then(|id| listing.objects.get(id))
            .ok_or_else(|| Error::conflict("The selected live Wasm object was not retained"))?;
        if kind == "module" || (kind == "instance") != request.get("export_name").is_some() {
            return Err(Error::bad(
                "Select a Memory directly, or an Instance with an explicit memory export_name; a Module has no live memory",
            ));
        }
        let response = self.live_wasm_command(&listing, "Runtime.callFunctionOn",json!({"objectId":object,"functionDeclaration":include_str!("../../assets/live-wasm-slice.js"),"arguments":[{"value":kind},{"value":request["export_name"]},{"value":request["offset"]},{"value":request["length"]}],"returnByValue":true,"silent":true,"userGesture":false,"awaitPromise":false,"timeout":1000}),Duration::from_secs(3)).await?;
        if response["exceptionDetails"].is_object() {
            return Err(Error::conflict(
                "Unable to read this Wasm memory slice: verify the memory export, current buffer range (maximum 4096 bytes), and unchanged WebAssembly built-ins",
            ));
        }
        self.synchronize_live_wasm(&listing).await?;
        let slice = &response["result"]["value"];
        validate_slice(slice, request)?;
        let result = json!({"ok":true,"generation":self.state.lock().unwrap_or_else(|e| e.into_inner())["generation"],"memory":{"listing_id":listing.id,"target_id":listing.target,"object_id":request["object_id"],"owner_scope":listing.scope,"export_name":request["export_name"],"offset":slice["offset"],"length":slice["length"],"byte_length":slice["byte_length"],"bytes":slice["bytes"],"shared":slice["shared"],"atomic":false}});
        validation::schema("DebuggerLiveWasmMemoryResult", &result, 422)?;
        Ok(result)
    }
}
fn attached_document(state: &Value) -> Value {
    json!({"instance_id":state["network"]["instance_id"],"connection_epoch":state["network"]["capture_epoch"],
        "document_epoch":state["target_document_epoch"],"target_id":state["target"]["id"]})
}
fn owner_pins(owner: &Value) -> bool {
    owner.as_object().is_some_and(|object| object.len() == 4)
        && owner["instance_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty() && id.len() <= 256)
        && owner["connection_epoch"].as_u64().is_some()
        && owner["document_epoch"].as_u64().is_some()
        && owner["target_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty() && id.len() <= 4096)
}
fn page_attached(state: &Value) -> bool {
    matches!(state["state"].as_str(), Some("running" | "paused"))
        && state["target"]["id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
        && state["request_interception"]["pending_requests"]
            .as_u64()
            .unwrap_or(0)
            == 0
}
/// Object Lab stays the disposable path. A captured page is admitted only when
/// the request names that exact attached page and confirms the effect. A
/// different target, worker, or unconfirmed baseline tab is refused.
fn classify_live_wasm(
    request: &Value,
    state: &Value,
    experiment: Option<&str>,
) -> Result<&'static str> {
    if request.get("captured_owner").is_some() && request["confirmed"] != true {
        return Err(Error::bad(
            "Captured Wasm inspection requires confirmed true. Missing fields: confirmed, captured_owner.instance_id, captured_owner.connection_epoch, captured_owner.document_epoch, captured_owner.target_id. Effects: code-execution and browser-control. Other pages are refused.",
        ));
    }
    if !page_attached(state) {
        return Err(Error::conflict(
            "Attach the debugger to one page before live Wasm inspection. Other pages are refused.",
        ));
    }
    if request["target_id"] != state["target"]["id"] {
        return Err(Error::conflict(
            "target_id is not the attached debugger page. Other pages are refused.",
        ));
    }
    if request.get("captured_owner").is_some() {
        if experiment.is_some() {
            return Err(Error::conflict(
                "A disposable Experiment context is active, so captured_owner is refused. Use Object Lab on that disposable page, or dispose the experiment and confirm the attached page. Other pages are refused.",
            ));
        }
        if state["target"]["type"] != "page"
            || !owner_pins(&request["captured_owner"])
            || request["captured_owner"] != attached_document(state)
        {
            return Err(Error::conflict(
                "captured_owner does not match the attached page. Required fields: instance_id, connection_epoch, document_epoch, target_id. Workers are refused. Other pages are refused.",
            ));
        }
        return Ok("captured_document");
    }
    if experiment.is_none()
        || state["object_experiment"]["isolated"] != true
        || state["object_experiment"]["target_id"] != state["target"]["id"]
        || state["object_experiment"]["navigation_id"]
            .as_u64()
            .unwrap_or(0)
            == 0
        || state["object_experiment"]["url"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        return Err(Error::conflict(
            "Live Wasm inspection needs the navigated disposable Object Lab page, or confirmed true plus captured_owner for the exact attached page. Missing captured fields: confirmed, captured_owner.instance_id, captured_owner.connection_epoch, captured_owner.document_epoch, captured_owner.target_id. Other pages are refused.",
        ));
    }
    Ok("object_experiment")
}
fn same_owner(listing: &Listing, state: &Value, context: Option<&str>) -> bool {
    if !page_attached(state)
        || listing.target != state["target"]["id"]
        || listing.epoch != state["target_document_epoch"]
    {
        return false;
    }
    if listing.scope == "captured_document" {
        return context.is_none()
            && listing.context.is_none()
            && state["target"]["type"] == "page"
            && listing.captured == attached_document(state);
    }
    context.is_some()
        && listing.scope == "object_experiment"
        && listing.captured.is_null()
        && listing.context.as_deref() == context
        && listing.target == state["object_experiment"]["target_id"]
        && listing.session == state["object_experiment"]["session_id"]
        && listing.navigation == state["object_experiment"]["navigation_id"]
        && state["object_experiment"]["isolated"] == true
        && state["object_experiment"]["navigation_id"]
            .as_u64()
            .is_some_and(|id| id > 0)
        && state["object_experiment"]["url"]
            .as_str()
            .is_some_and(|url| !url.is_empty())
}
async fn release_group(connection: &Connection, group: &str) {
    if connection
        .command(
            "Runtime.releaseObjectGroup",
            json!({"objectGroup": group}),
            Duration::from_secs(3),
        )
        .await
        .is_err()
    {
        // An unconfirmed release must not accumulate unbounded renderer roots.
        // Retire this exact handle-owning Arc, never the debugger's possibly
        // replaced current connection. This stops only the transport helper,
        // not the browser. Remote retention is uncertain until disconnect.
        connection.close().await;
    }
}

fn validate_slice(slice: &Value, request: &Value) -> Result<()> {
    let length = request["length"]
        .as_u64()
        .filter(|n| (1..=4096).contains(n))
        .ok_or_else(|| Error::bad("Memory length must be 1 through 4096 bytes"))?;
    let offset = request["offset"]
        .as_u64()
        .filter(|n| *n <= validation::MAX_SAFE_INTEGER)
        .ok_or_else(|| Error::bad("Memory offset must be a safe unsigned integer"))?;
    let size = slice["byte_length"]
        .as_u64()
        .filter(|n| *n <= validation::MAX_SAFE_INTEGER)
        .ok_or_else(|| Error::protocol("Invalid Wasm buffer length"))?;
    if slice["length"] != length
        || slice["offset"] != offset
        || !slice["shared"].is_boolean()
        || offset.checked_add(length).is_none_or(|end| end > size)
        || !slice["bytes"].as_array().is_some_and(|bytes| {
            bytes.len() == length as usize
                && bytes.iter().all(|b| b.as_u64().is_some_and(|n| n <= 255))
        })
    {
        return Err(Error::protocol(
            "Debugger returned an invalid or out-of-range Wasm memory slice",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slice_validation_rejects_malformed_or_unbounded_data() {
        let request = json!({"offset":2,"length":2});
        let good = json!({"offset":2,"length":2,"byte_length":4,"bytes":[0,255],"shared":false});
        assert!(validate_slice(&good, &request).is_ok());
        for (key, value) in [
            ("offset", json!(1)),
            ("length", json!(1)),
            ("byte_length", json!(3)),
            ("bytes", json!([0, 256])),
            ("bytes", json!([0])),
            ("shared", json!(null)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_slice(&bad, &request).is_err());
        }
        for length in [0, 4097, u64::MAX] {
            assert!(validate_slice(&good, &json!({"offset":0,"length":length})).is_err());
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn live_wasm_lifecycle_releases_groups_and_preserves_newer_owners() {
        use clap::Parser;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("transport");
        let source = dir.path().join("transport.py");
        let python = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("python3"))
            .find(|p| crate::worker::executable(p))
            .unwrap();
        std::fs::write(&source, r#"import sys,json,struct,pathlib
root=pathlib.Path(__file__).parent
inp=sys.stdin.buffer;out=sys.stdout.buffer
def emit(v):
 b=b'' if v is None else json.dumps(v).encode();out.write(b'REB\x01'+struct.pack('>I',len(b))+b);out.flush()
emit(None)
while True:
 h=inp.read(8)
 if not h:break
 q=json.loads(inp.read(struct.unpack('>I',h[4:])[0]))
 with (root/'commands').open('a') as f:f.write(json.dumps(q)+'\n')
 if q['method']=='Owned.dropLifecycle':
  for _ in range(512):emit({'method':'Runtime.consoleAPICalled','params':{}})
  emit({'method':'Page.frameNavigated','params':{'frame':{'id':'replacement'}}})
  emit({'method':'Runtime.executionContextsCleared','params':{}})
  emit({'id':q['id'],'result':{}})
 elif (root/'reject-release').exists():emit({'id':q['id'],'error':{'code':-32000,'message':'owned cleanup refusal'}})
 else:emit({'id':q['id'],'result':{}})
"#).unwrap();
        std::fs::write(
            &helper,
            format!(
                "#!/bin/sh\nexec '{}' '{}' \"$@\"\n",
                python.display(),
                source.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (connection, _events) = Connection::open(&helper, "ws://127.0.0.1:1").await.unwrap();
        let debugger = Debugger::new(&crate::config::Options::parse_from(["test"]));
        *debugger.connection.lock().await = Some(connection.clone());
        let make_listing = |id, expired| {
            Arc::new(Listing {
                id,
                target: json!("page"),
                epoch: json!(3),
                session: json!(4),
                navigation: json!(5),
                context: Some("owned".into()),
                scope: "object_experiment",
                captured: Value::Null,
                connection: connection.clone(),
                group: format!("listing-{id}"),
                created: if expired {
                    Instant::now() - LIFETIME
                } else {
                    Instant::now()
                },
                objects: BTreeMap::new(),
            })
        };
        let listing = make_listing(1, false);
        let state = json!({"target":{"id":"page"},"target_document_epoch":3,"state":"running","object_experiment":{"target_id":"page","session_id":4,"navigation_id":5,"isolated":true,"url":"http://127.0.0.1/owned"},"request_interception":{"pending_requests":0}});
        assert!(same_owner(&listing, &state, Some("owned")));
        for (pointer, value) in [
            ("/target/id", json!("other")),
            ("/target_document_epoch", json!(4)),
            ("/object_experiment/session_id", json!(6)),
            ("/object_experiment/navigation_id", json!(6)),
            ("/object_experiment/isolated", json!(false)),
            ("/state", json!("waiting")),
            ("/request_interception/pending_requests", json!(1)),
        ] {
            let mut changed = state.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(!same_owner(&listing, &changed, Some("owned")), "{pointer}");
        }
        assert!(!same_owner(&listing, &state, None));
        assert!(!same_owner(&listing, &state, Some("replacement")));
        let captured_owner = json!({"instance_id":"instance","connection_epoch":2,"document_epoch":3,"target_id":"page"});
        let captured = Listing {
            id: 1,
            target: json!("page"),
            epoch: json!(3),
            session: json!(0),
            navigation: json!(0),
            context: None,
            scope: "captured_document",
            captured: captured_owner.clone(),
            connection: connection.clone(),
            group: "listing-captured".into(),
            created: Instant::now(),
            objects: BTreeMap::new(),
        };
        let captured_state = json!({"target":{"id":"page","type":"page"},"target_document_epoch":3,"state":"paused","network":{"instance_id":"instance","capture_epoch":2},"object_experiment":{"isolated":false},"request_interception":{"pending_requests":0}});
        assert!(same_owner(&captured, &captured_state, None));
        assert!(!same_owner(&captured, &captured_state, Some("owned")));
        for (pointer, value) in [
            ("/target/type", json!("worker")),
            ("/target/id", json!("other")),
            ("/network/instance_id", json!("other")),
            ("/network/capture_epoch", json!(9)),
            ("/target_document_epoch", json!(4)),
            ("/state", json!("waiting")),
            ("/request_interception/pending_requests", json!(1)),
        ] {
            let mut changed = captured_state.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(!same_owner(&captured, &changed, None), "{pointer}");
        }
        let lab = json!({"action":"list_live_wasm_objects","target_id":"page"});
        let experiment_state = json!({"target":{"id":"page","type":"page"},"target_document_epoch":3,"state":"running","network":{"instance_id":"instance","capture_epoch":2},"object_experiment":{"target_id":"page","session_id":4,"navigation_id":5,"isolated":true,"url":"http://127.0.0.1/owned"},"request_interception":{"pending_requests":0}});
        assert_eq!(
            classify_live_wasm(&lab, &experiment_state, Some("owned")).unwrap(),
            "object_experiment"
        );
        assert!(
            classify_live_wasm(&lab, &experiment_state, None)
                .unwrap_err()
                .message
                .contains("disposable")
        );
        assert!(
            classify_live_wasm(&lab, &captured_state, None)
                .unwrap_err()
                .message
                .contains("Missing captured fields")
        );
        let mut confirmed = json!({"action":"list_live_wasm_objects","target_id":"page","confirmed":true,"captured_owner":captured_owner.clone()});
        assert_eq!(
            classify_live_wasm(&confirmed, &captured_state, None).unwrap(),
            "captured_document"
        );
        assert!(
            classify_live_wasm(&confirmed, &captured_state, Some("owned"))
                .unwrap_err()
                .message
                .contains("disposable")
        );
        confirmed["confirmed"] = json!(false);
        assert!(
            classify_live_wasm(&confirmed, &captured_state, None)
                .unwrap_err()
                .message
                .contains("confirmed")
        );
        confirmed["confirmed"] = json!(true);
        confirmed["captured_owner"]["target_id"] = json!("other-page");
        assert!(
            classify_live_wasm(&confirmed, &captured_state, None)
                .unwrap_err()
                .message
                .contains("Other pages are refused")
        );
        confirmed["target_id"] = json!("other-page");
        confirmed["captured_owner"]["target_id"] = json!("other-page");
        let mut other_page = captured_state.clone();
        other_page["target"]["id"] = json!("demo");
        assert!(
            classify_live_wasm(&confirmed, &other_page, None)
                .unwrap_err()
                .message
                .contains("target_id")
        );
        let mut worker = captured_state.clone();
        worker["target"]["type"] = json!("worker");
        confirmed = json!({"action":"read_live_wasm_memory","target_id":"page","confirmed":true,"captured_owner":captured_owner});
        assert!(
            classify_live_wasm(&confirmed, &worker, None)
                .unwrap_err()
                .message
                .contains("Workers")
        );
        assert!(!connection.has_dropped_events());
        connection
            .command("Owned.dropLifecycle", json!({}), Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(connection.take_dropped_events(), 2);
        assert_eq!(connection.take_dropped_events(), 0);
        assert!(
            connection.has_dropped_events(),
            "Draining telemetry cannot repair lifecycle ownership"
        );
        assert!(
            same_owner(&listing, &state, Some("owned")),
            "Nominal identity did not observe the lost navigation"
        );
        let lost = debugger.live_wasm_current(&listing).await.unwrap_err();
        assert!(lost.message.contains("events were lost"));
        // Even before queue draining, the initial synchronization refuses loss
        // rather than sending a query or blocking behind the full event queue.
        assert!(
            debugger
                .live_wasm_command(
                    &listing,
                    "Runtime.evaluate",
                    json!({}),
                    Duration::from_secs(3)
                )
                .await
                .unwrap_err()
                .message
                .contains("events were lost")
        );
        let put = |listing| {
            *debugger.wasm_live.retained.lock().unwrap() = Some(listing);
        };
        put(listing);
        debugger.clear_live_wasm().await;
        assert!(debugger.wasm_live.retained.lock().unwrap().is_none());
        put(make_listing(2, true));
        debugger.expire_live_wasm(1).await;
        assert_eq!(
            debugger
                .wasm_live
                .retained
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .id,
            2
        );
        debugger.expire_live_wasm(2).await;
        assert!(debugger.wasm_live.retained.lock().unwrap().is_none());
        put(make_listing(3, false));
        debugger.expire_live_wasm(3).await;
        assert!(debugger.wasm_live.retained.lock().unwrap().is_some());
        debugger
            .event(json!({"method":"Runtime.executionContextsCleared","params":{}}))
            .await;
        assert!(debugger.wasm_live.retained.lock().unwrap().is_none());
        put(make_listing(4, false));
        debugger
            .connection_failed(&connection, &Error::conflict("owned disconnect"))
            .await;
        assert!(debugger.wasm_live.retained.lock().unwrap().is_none());
        let commands = std::fs::read_to_string(dir.path().join("commands")).unwrap();
        assert!(
            !commands.contains("Runtime.evaluate"),
            "Lost ownership must refuse before execution"
        );
        let groups = commands
            .lines()
            .filter(|line| !line.contains("Owned.dropLifecycle"))
            .map(|line| {
                serde_json::from_str::<Value>(line).unwrap()["params"]["objectGroup"].clone()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            groups,
            vec![
                json!("listing-1"),
                json!("listing-2"),
                json!("listing-3"),
                json!("listing-4")
            ]
        );
        std::fs::write(dir.path().join("reject-release"), "1").unwrap();
        let (replacement, _events) = Connection::open(&helper, "ws://127.0.0.1:2").await.unwrap();
        *debugger.connection.lock().await = Some(replacement.clone());
        assert!(
            !replacement.has_dropped_events(),
            "A fresh transport has independent event history"
        );
        put(make_listing(5, false));
        debugger.clear_live_wasm().await;
        assert!(
            connection.is_closed(),
            "Unconfirmed cleanup retires the handle owner"
        );
        assert!(
            !replacement.is_closed(),
            "Stale cleanup must preserve the replacement connection"
        );
        assert!(Arc::ptr_eq(
            debugger.connection.lock().await.as_ref().unwrap(),
            &replacement
        ));
        replacement.close().await;
    }
}
