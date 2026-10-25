//! Observational own-descriptor map of an explicitly selected paused binding.
//! An object shaped like Wasm imports is not evidence it was instantiated/called.
use super::{Connection, Debugger};
use crate::{
    error::{Error, Result},
    validation,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

const MAX_PROPERTIES: usize = 256;
const MAX_MODULES: usize = 16;
const MAX_IMPORTS: usize = 64;
const DEADLINE: Duration = Duration::from_secs(4);

fn stale() -> Error {
    Error::conflict(
        "The selected pause, document, source or connection changed. Refresh and select the binding again.",
    )
}
fn remaining(started: Instant) -> Result<Duration> {
    let remaining = DEADLINE.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(Error::conflict("Import object inspection deadline reached"));
    }
    Ok(remaining)
}
async fn synchronize(connection: &Connection, started: Instant) -> Result<()> {
    if connection.is_closed() || connection.has_dropped_events() {
        return Err(stale());
    }
    // Replies bypass the event consumer. Drain earlier lifecycle messages before
    // trusting a snapshot, and never extend the overall budget for a busy queue.
    tokio::time::timeout(remaining(started)?, connection.barrier())
        .await
        .map_err(|_| Error::conflict("Import object inspection deadline reached"))??;
    if connection.is_closed() || connection.has_dropped_events() {
        return Err(stale());
    }
    Ok(())
}
fn document(s: &Value) -> Value {
    json!({"instance_id":s["network"]["instance_id"],"connection_epoch":s["network"]["capture_epoch"],
        "document_epoch":s["target_document_epoch"],"target_id":s["target"]["id"]})
}
fn frame_identity(frame: &Value) -> Value {
    json!({"id":frame["id"],"location":frame["location"],"function_location":frame["function_location"],
        "scopes":frame["scopes"].as_array().into_iter().flatten().map(|scope|
            json!({"type":scope["type"],"object":scope["object"]})).collect::<Vec<_>>()})
}
fn omission(omissions: &mut Vec<&'static str>, reason: &'static str) {
    if !omissions.contains(&reason) {
        omissions.push(reason);
    }
}
fn properties<'a>(reply: &'a Value, omissions: &mut Vec<&'static str>) -> Result<&'a [Value]> {
    if reply.get("exceptionDetails").is_some() {
        return Err(Error::conflict("Import object descriptors are unavailable"));
    }
    let values = reply["result"]
        .as_array()
        .ok_or_else(|| Error::protocol("Malformed import object descriptors"))?;
    if values.len() > MAX_PROPERTIES {
        omission(omissions, "property-limit");
    }
    let values = &values[..values.len().min(MAX_PROPERTIES)];
    let mut names = BTreeSet::new();
    for property in values {
        if property.get("symbol").is_none()
            && let Some(name) = property["name"].as_str()
            && !names.insert(name)
        {
            return Err(Error::protocol("Duplicate own property descriptors"));
        }
    }
    Ok(values)
}
fn data_value(property: &Value) -> std::result::Result<&Value, &'static str> {
    if property.get("get").is_some() || property.get("set").is_some() {
        return Err("accessor-not-invoked");
    }
    if property["wasThrown"] == true || property["isOwn"] == false || !property["value"].is_object()
    {
        return Err("unavailable");
    }
    if property["value"]["subtype"] == "proxy" {
        return Err("proxy-not-inspected");
    }
    Ok(&property["value"])
}
fn object_id(value: &Value) -> Option<&str> {
    (value["subtype"] != "proxy" && matches!(value["type"].as_str(), Some("object" | "function")))
        .then(|| {
            value["objectId"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 4096)
        })
        .flatten()
}
fn name(property: &Value) -> Option<&str> {
    if property.get("symbol").is_some() {
        return None;
    }
    property["name"].as_str().filter(|name| name.len() <= 256)
}
struct Inspection<'a> {
    debugger: &'a Debugger,
    connection: Arc<Connection>,
    owner: Value,
    generation: Value,
    frame: Value,
    epoch: u64,
    source_revision: u64,
    source_locations: Mutex<BTreeMap<String, Value>>,
    started: Instant,
}
impl Inspection<'_> {
    async fn current(&self) -> Result<()> {
        synchronize(&self.connection, self.started).await?;
        {
            // Compare compact owner tokens under the state lock. Never clone a
            // debugger snapshot (Traffic/history/source catalogs) for each import.
            let s = self
                .debugger
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if s["state"] != "paused"
                || document(&s) != self.owner
                || self.debugger.pause_epoch.load(Ordering::Acquire) != self.epoch
                || self
                    .debugger
                    .hooks
                    .candidate_catalog_incomplete
                    .load(Ordering::Acquire)
                || self
                    .debugger
                    .hooks
                    .candidate_source_revision(self.owner["target_id"].as_str().unwrap())
                    != Some(self.source_revision)
                || !s["paused"]["call_frames"].as_array().is_some_and(|frames| {
                    frames.iter().any(|frame| {
                        frame["id"] == self.frame["id"] && frame_identity(frame) == self.frame
                    })
                })
            {
                return Err(stale());
            }
        }
        if !self
            .debugger
            .connection
            .lock()
            .await
            .as_ref()
            .is_some_and(|connection| {
                Arc::ptr_eq(connection, &self.connection)
                    && !connection.is_closed()
                    && !connection.has_dropped_events()
            })
        {
            return Err(stale());
        }
        Ok(())
    }
    async fn descriptors(&self, id: &str) -> Result<Value> {
        self.current().await?;
        let remaining = remaining(self.started)?;
        let result = match tokio::time::timeout(
            remaining,
            self.connection.command(
                "Runtime.getProperties",
                json!({"objectId":id,
            "ownProperties":true,"accessorPropertiesOnly":false,"generatePreview":false}),
                remaining.min(Duration::from_secs(1)),
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                // Cancellation may interrupt a framed pipe write. Retire only
                // this transport, never a concurrently selected replacement.
                self.connection.close().await;
                return Err(Error::conflict("Import object inspection deadline reached"));
            }
        };
        self.current().await?;
        result
    }
    fn location(&self, reply: &Value, omissions: &mut Vec<&'static str>) -> Option<Value> {
        let properties = reply["internalProperties"].as_array()?;
        if properties.len() > MAX_PROPERTIES {
            omission(omissions, "property-limit");
            return None;
        }
        let mut locations = properties
            .iter()
            .filter(|property| property["name"] == "[[FunctionLocation]]");
        let location = super::parse::location(&locations.next()?["value"]["value"])?;
        if locations.next().is_some() {
            return None;
        }
        let id = location["script_id"].as_str()?;
        let mut cache = self
            .source_locations
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !cache.contains_key(id) {
            let s = self
                .debugger
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut scripts = s["scripts"].as_array()?.iter().filter(|script| {
                script["script_id"] == id
                    && script["language"] == "JavaScript"
                    && script["target_type"] != "worker"
                    && script.get("target_id").unwrap_or(&s["target"]["id"])
                        == &self.owner["target_id"]
                    && script["hash"].as_str().is_some_and(|hash| !hash.is_empty())
            });
            let script = scripts.next()?;
            if scripts.next().is_some() {
                return None;
            }
            cache.insert(id.to_owned(), json!({"source_hash":script["hash"],"execution_context_id":script["execution_context_id"]}));
        }
        let script = &cache[id];
        Some(
            json!({"script_id":id,"line":location["line"],"column":location["column"],
            "source_hash":script["source_hash"],"execution_context_id":script["execution_context_id"]}),
        )
    }
}
impl Debugger {
    pub(super) async fn inspect_paused_import_object(&self, request: &Value) -> Result<Value> {
        let started = Instant::now();
        let connection = self.connection.lock().await.clone().ok_or_else(stale)?;
        synchronize(&connection, started).await?;
        // Snapshot and pause serial are read under the same lock used by event commits.
        let (owner, generation, frame, epoch, source_revision) = {
            let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if s["state"] != "paused"
                || request["expected_generation"] != s["generation"]
                || request["owner"] != document(&s)
                || self
                    .hooks
                    .candidate_catalog_incomplete
                    .load(Ordering::Acquire)
            {
                return Err(stale());
            }
            let frame = s["paused"]["call_frames"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|frame| frame["id"] == request["call_frame_id"])
                .ok_or_else(stale)?;
            if !s["scripts"].as_array().is_some_and(|scripts| {
                scripts.iter().any(|script| {
                    script["script_id"] == frame["location"]["script_id"]
                        && script["language"] == "JavaScript"
                        && script["target_type"] != "worker"
                        && script["hash"].as_str().is_some_and(|hash| !hash.is_empty())
                        && script.get("target_id").unwrap_or(&s["target"]["id"])
                            == &s["target"]["id"]
                })
            }) {
                return Err(stale());
            }
            let revision = self
                .hooks
                .candidate_source_revision(s["target"]["id"].as_str().ok_or_else(stale)?)
                .ok_or_else(stale)?;
            (
                document(&s),
                s["generation"].clone(),
                frame_identity(frame),
                self.pause_epoch.load(Ordering::Acquire),
                revision,
            )
        };
        let scope_index =
            validation::integer(&request["scope_index"], "Scope index", 0, 11)? as usize;
        let scope = frame["scopes"].get(scope_index).ok_or_else(stale)?;
        // Only selected lexical scopes are traversed, never globals or arbitrary handles.
        if !matches!(scope["type"].as_str(), Some("local" | "closure" | "block"))
            || scope["object"]["subtype"] == "proxy"
        {
            return Err(Error::bad(
                "Select a non-proxy local, closure or block scope",
            ));
        }
        let scope_id = validation::text(
            &scope["object"]["object_id"],
            "Scope object",
            4096,
            false,
            false,
        )?
        .to_owned();
        let binding = validation::text(&request["binding_name"], "Binding name", 256, false, true)?;
        let inspection = Inspection {
            debugger: self,
            connection,
            owner,
            generation,
            frame,
            epoch,
            source_revision,
            source_locations: Mutex::new(BTreeMap::new()),
            started,
        };
        let mut omissions = Vec::new();
        let scope_reply = inspection.descriptors(&scope_id).await?;
        let bindings = properties(&scope_reply, &mut omissions)?
            .iter()
            .filter(|property| property["name"] == binding)
            .collect::<Vec<_>>();
        if bindings.len() != 1 {
            return Err(Error::conflict(
                "The selected own binding is absent, ambiguous or beyond the descriptor limit",
            ));
        }
        let root = data_value(bindings[0])
            .map_err(|reason| Error::conflict(format!("Import binding {reason}")))?;
        let root_id = object_id(root)
            .ok_or_else(|| Error::bad("Selected binding is not an inspectable object"))?;
        let root_reply = inspection.descriptors(root_id).await?;
        let namespaces = properties(&root_reply, &mut omissions)?;
        if namespaces.len() > MAX_MODULES {
            omission(&mut omissions, "module-limit");
        }
        let mut modules = Vec::new();
        let mut imported = 0;
        for namespace in namespaces.iter().take(MAX_MODULES) {
            if imported == MAX_IMPORTS {
                omission(&mut omissions, "import-limit");
                break;
            }
            if inspection.started.elapsed() >= DEADLINE {
                omission(&mut omissions, "deadline");
                break;
            }
            let Some(module_name) = name(namespace) else {
                omission(&mut omissions, "name-limit-or-symbol");
                continue;
            };
            let mut module = json!({"module_name":module_name,"state":"inspected","imports":[]});
            let namespace = match data_value(namespace) {
                Ok(value) => value,
                Err(reason) => {
                    module["state"] = json!(reason);
                    modules.push(module);
                    continue;
                }
            };
            let Some(id) = object_id(namespace) else {
                module["state"] = json!("not-object");
                modules.push(module);
                continue;
            };
            let reply = inspection.descriptors(id).await?;
            for property in properties(&reply, &mut omissions)? {
                if imported == MAX_IMPORTS {
                    omission(&mut omissions, "import-limit");
                    break;
                }
                if inspection.started.elapsed() >= DEADLINE {
                    omission(&mut omissions, "deadline");
                    break;
                }
                let Some(import_name) = name(property) else {
                    omission(&mut omissions, "name-limit-or-symbol");
                    continue;
                };
                let mut row = json!({"import_name":import_name,"state":"not-function","host_function_name":null,"host_location":null,"guest_position":null});
                match data_value(property) {
                    Err(reason) => row["state"] = json!(reason),
                    Ok(value) if value["type"] == "function" => {
                        row["state"] = json!("function");
                        if let Some(id) = object_id(value) {
                            let reply = inspection.descriptors(id).await?;
                            let names = properties(&reply, &mut omissions)?
                                .iter()
                                .filter(|property| property["name"] == "name")
                                .collect::<Vec<_>>();
                            if names.len() == 1
                                && let Ok(value) = data_value(names[0])
                                && let Some(name) =
                                    value["value"].as_str().filter(|name| name.len() <= 256)
                            {
                                row["host_function_name"] = json!(name);
                            }
                            row["host_location"] = inspection
                                .location(&reply, &mut omissions)
                                .unwrap_or(Value::Null);
                        }
                    }
                    _ => {}
                }
                imported += 1;
                module["imports"].as_array_mut().unwrap().push(row);
            }
            modules.push(module);
        }
        inspection.current().await?;
        Ok(
            json!({"ok":true,"generation":inspection.generation,"import_object":{
            "contract_version":1,"provenance":"selected-paused-own-properties","invocation":"unproven","guest_position":null,
            "owner":inspection.owner,"call_frame_id":request["call_frame_id"],"scope_index":scope_index,
            "binding_name":binding,"observed_at_ms":validation::now_ms(),"modules":modules,"omissions":omissions}}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::connection::Event;
    use super::*;
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt;
    use tokio::sync::mpsc;

    struct Fixture {
        dir: tempfile::TempDir,
        debugger: Arc<Debugger>,
    }
    impl Fixture {
        async fn new() -> Self {
            let (fixture, events) = Self::with_events().await;
            Self::consume(fixture.debugger.clone(), events, false);
            fixture
        }
        fn consume(debugger: Arc<Debugger>, mut events: mpsc::Receiver<Event>, defer: bool) {
            tokio::spawn(async move {
                let mut queued = Vec::new();
                while let Some(event) = events.recv().await {
                    match event {
                        Event::Barrier(sender) => {
                            for message in queued.drain(..) {
                                debugger.event(message).await;
                            }
                            let _ = sender.send(());
                        }
                        Event::Message(Ok(message), _) if defer => queued.push(message),
                        Event::Message(Ok(message), _) => debugger.event(message).await,
                        Event::Message(Err(_), _) => break,
                    }
                }
            });
        }
        async fn with_events() -> (Self, mpsc::Receiver<Event>) {
            let dir = tempfile::tempdir().unwrap();
            let interpreter = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|directory| directory.join("python3"))
                .find(|path| crate::worker::executable(path))
                .unwrap()
                .canonicalize()
                .unwrap();
            let source = dir.path().join("transport.py");
            std::fs::write(&source, r#"import sys,json,struct,pathlib,time
root=pathlib.Path(__file__).parent
inp=sys.stdin.buffer;out=sys.stdout.buffer
def emit(v):
 b=b'' if v is None else json.dumps(v).encode();out.write(b'REB\x01'+struct.pack('>I',len(b))+b);out.flush()
emit(None)
while True:
 h=inp.read(8)
 if not h:break
 if (root/'write-gate').exists():
  (root/'write-seen').touch()
  while (root/'write-gate').exists():time.sleep(.002)
 q=json.loads(inp.read(struct.unpack('>I',h[4:])[0]))
 with (root/'commands').open('a') as log:log.write(json.dumps(q)+'\n')
 oid=q['params']['objectId']
 if oid=='host':
  (root/'seen').touch()
  while (root/'gate').exists():time.sleep(.002)
 if (root/'events').exists():
  messages=json.loads((root/'events').read_text()).get(oid,[])
  if len(messages)>512:emit({'method':'Fixture.beforeBurst','params':{}})
  for event in messages:emit(event)
 data=json.loads((root/'objects').read_text())
 emit({'id':q['id'],'result':data[oid]})
"#).unwrap();
            let transport = dir.path().join("transport");
            let quote =
                |p: &std::path::Path| format!("'{}'", p.to_str().unwrap().replace('\'', "'\\''"));
            std::fs::write(
                &transport,
                format!(
                    "#!/bin/sh\nexec {} {}\n",
                    quote(&interpreter),
                    quote(&source)
                ),
            )
            .unwrap();
            std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
            let object = |id| json!({"type":"object","objectId":id});
            let property = |name, value| json!({"name":name,"value":value,"isOwn":true});
            let objects = json!({
                "scope":{"result":[property("imports",object("imports"))]},
                "imports":{"result":[property("env",object("env")),{"name":"accessor_namespace","get":{"type":"function","objectId":"getter"}},property("proxy_namespace",json!({"type":"object","subtype":"proxy","objectId":"proxy"}))]},
                "env":{"result":[property("clock",json!({"type":"function","objectId":"host"})),{"name":"getter_import","get":{"type":"function","objectId":"getter"}},property("proxy_import",json!({"type":"function","subtype":"proxy","objectId":"proxy"})),property("memory",object("memory"))]},
                "host":{"result":[property("name",json!({"type":"string","value":"ownedClock"}))],"internalProperties":[{"name":"[[FunctionLocation]]","value":{"type":"object","subtype":"internal#location","value":{"scriptId":"7","lineNumber":1,"columnNumber":2}}}]}
            });
            std::fs::write(dir.path().join("objects"), objects.to_string()).unwrap();
            let debugger = Debugger::new(&crate::config::Options::parse_from(["test"]));
            let (connection, events) = Connection::open(&transport, "ws://127.0.0.1:1")
                .await
                .unwrap();
            *debugger.connection.lock().await = Some(connection);
            debugger.update(|s| {
                s["state"]=json!("paused");s["target"]=json!({"id":"owned-page"});s["target_document_epoch"]=json!(3);
                s["scripts"]=json!([{"script_id":"7","hash":"owned-source","language":"JavaScript","execution_context_id":2}]);
                debugger.hooks.candidate_source_changed("owned-page");
                s["paused"]=json!({"call_frames":[{"id":"frame-1","location":{"script_id":"7","line":0,"column":1},"function_location":null,
                    "scopes":[{"type":"local","object":{"type":"object","subtype":null,"object_id":"scope"},"properties":[]}]}]});
            });
            (Self { dir, debugger }, events)
        }
        fn request(&self) -> Value {
            let snapshot = self.debugger.snapshot();
            json!({"action":"inspect_paused_import_object","expected_generation":snapshot["generation"],"owner":document(&snapshot),
                "call_frame_id":"frame-1","scope_index":0,"binding_name":"imports"})
        }
        fn objects(&self, edit: impl FnOnce(&mut Value)) {
            let path = self.dir.path().join("objects");
            let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            edit(&mut value);
            std::fs::write(path, value.to_string()).unwrap();
        }
        fn commands(&self) -> Vec<Value> {
            std::fs::read_to_string(self.dir.path().join("commands"))
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
        async fn close(self) {
            self.debugger.stop().await;
        }
    }
    #[tokio::test]
    async fn paused_import_map_resolves_only_own_data_functions_without_execution() {
        let f = Fixture::new().await;
        let before = f.debugger.snapshot();
        let result = f.debugger.action(&f.request()).await.unwrap();
        validation::schema("DebuggerImportObjectResult", &result, 500).unwrap();
        validation::schema("DebuggerResult", &result, 500).unwrap();
        let map = &result["import_object"];
        assert_eq!(map["invocation"], "unproven");
        assert!(map["guest_position"].is_null());
        let rows = &map["modules"][0]["imports"];
        assert_eq!(rows[0]["import_name"], "clock");
        assert_eq!(rows[0]["host_function_name"], "ownedClock");
        assert_eq!(rows[0]["host_location"]["source_hash"], "owned-source");
        assert_eq!(rows[0]["host_location"]["line"], 1);
        assert!(rows[0]["guest_position"].is_null());
        assert_eq!(rows[1]["state"], "accessor-not-invoked");
        assert_eq!(rows[2]["state"], "proxy-not-inspected");
        assert_eq!(rows[3]["state"], "not-function");
        assert_eq!(map["modules"][1]["state"], "accessor-not-invoked");
        assert_eq!(map["modules"][2]["state"], "proxy-not-inspected");
        assert_eq!(
            f.debugger.snapshot(),
            before,
            "Inspection must not mutate debugger state or hook consent"
        );
        let commands = f.commands();
        assert_eq!(commands.len(), 4);
        assert!(
            commands
                .iter()
                .all(|q| q["method"] == "Runtime.getProperties"
                    && q["params"]["ownProperties"] == true
                    && q["params"]["generatePreview"] == false)
        );
        assert!(!result.to_string().contains("objectId"));
        f.close().await;
    }
    #[tokio::test]
    async fn import_map_rejects_stale_owner_frame_scope_and_snapshot_before_commands() {
        let f = Fixture::new().await;
        for (key, value) in [
            ("expected_generation", json!(0)),
            ("call_frame_id", json!("other")),
            ("scope_index", json!(1)),
            (
                "owner",
                json!({"instance_id":"wrong","connection_epoch":0,"document_epoch":3,"target_id":"owned-page"}),
            ),
        ] {
            let mut r = f.request();
            r[key] = value;
            assert!(f.debugger.action(&r).await.is_err());
        }
        f.debugger
            .update(|s| s["paused"]["call_frames"][0]["scopes"][0]["type"] = json!("global"));
        assert!(f.debugger.action(&f.request()).await.is_err());
        assert!(f.commands().is_empty());
        f.close().await;
    }
    #[tokio::test]
    async fn import_map_rejects_accessor_proxy_or_ambiguous_root_binding() {
        let f = Fixture::new().await;
        for value in [
            json!([{"name":"imports","get":{"type":"function","objectId":"getter"}}]),
            json!([{"name":"imports","value":{"type":"object","subtype":"proxy","objectId":"proxy"}}]),
            json!([{"name":"imports","value":{"type":"object","objectId":"imports"}},{"name":"imports","value":{"type":"object","objectId":"imports"}}]),
        ] {
            f.objects(|o| o["scope"]["result"] = value);
            assert!(f.debugger.action(&f.request()).await.is_err());
        }
        assert!(
            f.commands()
                .iter()
                .all(|q| q["params"]["objectId"] == "scope")
        );
        f.close().await;
    }
    #[tokio::test]
    async fn import_map_discards_results_when_pause_source_or_document_changes() {
        for change in ["pause", "source", "document", "resume", "connection"] {
            let f = Fixture::new().await;
            std::fs::write(f.dir.path().join("gate"), b"").unwrap();
            let debugger = f.debugger.clone();
            let request = f.request();
            let task = tokio::spawn(async move { debugger.action(&request).await });
            tokio::time::timeout(Duration::from_secs(3), async {
                while !f.dir.path().join("seen").exists() {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
            f.debugger.update(|s| match change {
                // Same call-frame/object IDs can recur at a later pause.
                "pause" => {
                    f.debugger.pause_epoch.fetch_add(1, Ordering::AcqRel);
                }
                "source" => {
                    s["scripts"][0]["hash"] = json!("replacement");
                    f.debugger.hooks.candidate_source_changed("owned-page");
                }
                "document" => s["target_document_epoch"] = json!(4),
                "resume" => s["state"] = json!("running"),
                _ => {}
            });
            let retired = if change == "connection" {
                f.debugger.connection.lock().await.take()
            } else {
                None
            };
            std::fs::remove_file(f.dir.path().join("gate")).unwrap();
            assert!(task.await.unwrap().is_err(), "{change}");
            if let Some(connection) = retired {
                connection.close().await;
            }
            f.close().await;
        }
    }
    #[tokio::test]
    async fn import_map_drains_queued_lifecycle_events_before_accepting_descriptors() {
        for change in ["source", "document", "reused-pause"] {
            let (f, events) = Fixture::with_events().await;
            let pause = json!({"reason":"other","callFrames":[{"callFrameId":"frame-1",
                "functionName":"ownedGlue","url":"http://127.0.0.1/owned.js",
                "location":{"scriptId":"7","lineNumber":0,"columnNumber":1},
                "scopeChain":[{"type":"local","object":{"type":"object","objectId":"scope"}}]}]});
            f.debugger
                .update(|s| s["paused"] = super::super::parse::pause(&pause));
            let original_frame = frame_identity(&f.debugger.snapshot()["paused"]["call_frames"][0]);
            let messages = match change {
                "source" => {
                    json!([{"method":"Runtime.executionContextDestroyed","params":{"executionContextId":2}}])
                }
                "document" => json!([{"method":"Page.documentOpened","params":{}}]),
                _ => {
                    json!([{"method":"Debugger.resumed","params":{}}, {"method":"Debugger.paused","params":pause}])
                }
            };
            std::fs::write(
                f.dir.path().join("events"),
                json!({"host":messages}).to_string(),
            )
            .unwrap();
            // Hold wire-ordered lifecycle events until a reader barrier. Replies
            // still resolve directly, reproducing a delayed event consumer without sleeps.
            Fixture::consume(f.debugger.clone(), events, true);
            let result = f.debugger.action(&f.request()).await;
            assert!(result.is_err(), "queued {change} must invalidate the map");
            if change == "reused-pause" {
                assert_eq!(
                    frame_identity(&f.debugger.snapshot()["paused"]["call_frames"][0]),
                    original_frame
                );
                assert_eq!(f.debugger.pause_epoch.load(Ordering::Acquire), 2);
            }
            f.close().await;
        }
    }
    #[tokio::test]
    async fn import_map_drains_before_selection_and_bounds_event_barriers() {
        let (f, events) = Fixture::with_events().await;
        let request = f.request();
        let connection = f.debugger.connection.lock().await.clone().unwrap();
        std::fs::write(
            f.dir.path().join("events"),
            json!({"scope":[{
                "method":"Runtime.executionContextDestroyed","params":{"executionContextId":2}
            }]})
            .to_string(),
        )
        .unwrap();
        connection
            .command(
                "Runtime.getProperties",
                json!({"objectId":"scope"}),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        Fixture::consume(f.debugger.clone(), events, true);
        assert!(f.debugger.action(&request).await.is_err());
        assert_eq!(
            f.commands().len(),
            1,
            "Queued invalidation rejects before selection reads"
        );
        f.close().await;

        let (f, _events) = Fixture::with_events().await;
        let connection = f.debugger.connection.lock().await.clone().unwrap();
        let started = Instant::now() - (DEADLINE - Duration::from_millis(10));
        let result =
            tokio::time::timeout(Duration::from_secs(1), synchronize(&connection, started))
                .await
                .unwrap();
        assert!(
            result.unwrap_err().message.contains("deadline"),
            "A stalled consumer cannot extend the inspection budget"
        );
        assert!(f.commands().is_empty());
        f.close().await;
    }
    #[tokio::test]
    async fn import_map_deadline_retires_only_its_partially_written_connection() {
        let f = Fixture::new().await;
        let replacement = Fixture::new().await;
        let connection = f.debugger.connection.lock().await.clone().unwrap();
        let newer = replacement
            .debugger
            .connection
            .lock()
            .await
            .clone()
            .unwrap();
        std::fs::write(f.dir.path().join("write-gate"), b"").unwrap();
        let debugger = f.debugger.clone();
        let retained = connection.clone();
        let task = tokio::spawn(async move {
            let s = debugger.snapshot();
            let inspection = Inspection {
                debugger: &debugger,
                connection: retained,
                owner: document(&s),
                generation: s["generation"].clone(),
                frame: frame_identity(&s["paused"]["call_frames"][0]),
                epoch: debugger.pause_epoch.load(Ordering::Acquire),
                source_revision: debugger
                    .hooks
                    .candidate_source_revision("owned-page")
                    .unwrap(),
                source_locations: Mutex::new(BTreeMap::new()),
                started: Instant::now() - (DEADLINE - Duration::from_millis(500)),
            };
            // Private stress input fills the pipe while its reader holds after
            // the frame header. Public scope/object IDs remain bounded to 4 KiB.
            inspection.descriptors(&"x".repeat(1024 * 1024)).await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !f.dir.path().join("write-seen").exists() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        *f.debugger.connection.lock().await = Some(newer.clone());
        let result = task.await.unwrap();
        assert!(result.unwrap_err().message.contains("deadline"));
        assert!(
            connection.is_closed(),
            "Partially written frames cannot be reused"
        );
        assert!(
            !newer.is_closed(),
            "Never close a selected replacement transport"
        );
        assert!(
            f.debugger
                .connection
                .lock()
                .await
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &newer))
        );
        f.close().await;
        replacement.close().await;
    }
    #[tokio::test]
    async fn import_map_rejects_prior_and_inflight_connection_event_loss() {
        for prior in [true, false] {
            let (f, mut events) = Fixture::with_events().await;
            let connection = f.debugger.connection.lock().await.clone().unwrap();
            let messages = vec![json!({"method":"Debugger.resumed","params":{}}); 600];
            let key = if prior { "scope" } else { "host" };
            std::fs::write(
                f.dir.path().join("events"),
                json!({key:messages}).to_string(),
            )
            .unwrap();
            if prior {
                // Fill the real bounded queue without consuming it. The reply
                // proves the reader already accounted for all preceding drops.
                connection
                    .command(
                        "Runtime.getProperties",
                        json!({"objectId":"scope"}),
                        Duration::from_secs(1),
                    )
                    .await
                    .unwrap();
                assert!(connection.take_dropped_events() > 0);
                assert_eq!(connection.take_dropped_events(), 0);
                assert!(
                    connection.has_dropped_events(),
                    "Draining diagnostics cannot repair lifecycle evidence"
                );
                assert!(f.debugger.action(&f.request()).await.is_err());
                assert_eq!(
                    f.commands().len(),
                    1,
                    "Prior loss rejects before sending descriptors"
                );
            } else {
                let debugger = f.debugger.clone();
                let request = f.request();
                let task = tokio::spawn(async move { debugger.action(&request).await });
                // Acknowledge initial barriers, then deliberately stop this
                // consumer before the final reply's burst. No timing sleeps.
                loop {
                    match events.recv().await.unwrap() {
                        Event::Barrier(sender) => {
                            let _ = sender.send(());
                        }
                        Event::Message(Ok(message), _) => {
                            assert_eq!(message["method"], "Fixture.beforeBurst");
                            break;
                        }
                        _ => panic!("Unexpected fixture event"),
                    }
                }
                assert!(task.await.unwrap().is_err());
                assert!(connection.has_dropped_events());
            }
            f.close().await;
        }
    }
    #[tokio::test]
    async fn import_map_limits_and_unavailable_locations_are_explicit() {
        let f = Fixture::new().await;
        f.objects(|o| {
            o["imports"]["result"]=json!((0..300).map(|i|json!({"name":format!("module-{i}"),"value":{"type":"object","objectId":"env"}})).collect::<Vec<_>>());
            o["env"]["result"]=json!((0..300).map(|i|json!({"name":format!("function-{i}"),"value":{"type":"number","value":i}})).collect::<Vec<_>>());
        });
        let r = f.debugger.action(&f.request()).await.unwrap();
        validation::schema("DebuggerImportObjectResult", &r, 500).unwrap();
        let m = &r["import_object"];
        assert_eq!(m["modules"].as_array().unwrap().len(), 1);
        assert_eq!(
            m["modules"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["imports"].as_array().unwrap().len())
                .sum::<usize>(),
            MAX_IMPORTS
        );
        assert_eq!(
            m["omissions"],
            json!(["property-limit", "module-limit", "import-limit"])
        );
        f.close().await;
        let f = Fixture::new().await;
        f.objects(|o| o["host"]["internalProperties"] = json!([]));
        let r = f.debugger.action(&f.request()).await.unwrap();
        assert!(r["import_object"]["modules"][0]["imports"][0]["host_location"].is_null());
        f.close().await;
    }
}
