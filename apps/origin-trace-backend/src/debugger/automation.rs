use super::{Debugger, connection::Connection, requests};
use crate::{
    error::{Error, Result},
    validation, workspace,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

pub(super) struct Automation {
    next_recipe: AtomicU64,
    next_run: AtomicU64,
    epoch: AtomicU64,
    variables: Mutex<Value>,
    nonce: Mutex<Option<String>>,
    pub binding: String,
    scripts: Mutex<BTreeMap<String, String>>,
    active: Mutex<Option<Active>>,
    serial: Arc<Semaphore>,
    queue: mpsc::Sender<Trigger>,
    receiver: Mutex<Option<mpsc::Receiver<Trigger>>>,
}
struct Active {
    id: u64,
    document: Option<String>,
    target: String,
    connection: Arc<Connection>,
    _permit: OwnedSemaphorePermit,
}
struct Trigger {
    epoch: u64,
    target: String,
    kind: String,
}
fn random() -> String {
    use std::io::Read;
    let mut bytes = [0; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("Operating system random source");
    hex::encode(bytes)
}
impl Automation {
    pub fn erase_session(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        *self.variables.lock().unwrap_or_else(|e| e.into_inner()) = json!({});
        self.nonce.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.active.lock().unwrap_or_else(|e| e.into_inner()).take();
    }

    pub fn new() -> Self {
        let (queue, receiver) = mpsc::channel(16);
        Self {
            next_recipe: AtomicU64::new(1),
            next_run: AtomicU64::new(1),
            epoch: AtomicU64::new(0),
            variables: Mutex::new(json!({})),
            nonce: Mutex::new(None),
            binding: format!("rebAutomationReport{}", random()),
            scripts: Mutex::new(BTreeMap::new()),
            active: Mutex::new(None),
            serial: Arc::new(Semaphore::new(1)),
            queue,
            receiver: Mutex::new(Some(receiver)),
        }
    }
}
fn recipe(r: &Value) -> Result<Value> {
    let label = requests::text(&r["label"], "Recipe label", 128, false)?
        .trim()
        .to_owned();
    let source = requests::text(&r["source"], "Recipe source", 16384, false)?;
    if label.is_empty() || source.trim().is_empty() {
        return Err(Error::bad("Recipe label and source are required"));
    }
    let trigger = r
        .get("trigger")
        .unwrap_or(&json!("manual"))
        .as_str()
        .filter(|t| ["manual", "created", "before-load", "after-load"].contains(t))
        .ok_or_else(|| Error::bad("Recipe trigger is invalid"))?
        .to_owned();
    let enabled = r
        .get("enabled")
        .unwrap_or(&json!(true))
        .as_bool()
        .ok_or_else(|| Error::bad("Recipe enabled state must be boolean"))?;
    Ok(
        json!({"label":label,"trigger":trigger,"enabled":enabled,"source":source,"source_bytes":source.len()}),
    )
}
fn configuration(r: &Value, variables: &Value, binding: bool) -> Value {
    json!({"source":r["source"],"variables":variables,"resultLimit":if binding {4096} else {16384},"logLimit":if binding {4} else {32},"logBytes":if binding {512} else {1024},"timeoutMs":2000})
}
fn result(v: &Value) -> Result<Value> {
    if v["protocolVersion"] != 1 {
        return Err(Error::protocol("Malformed automation result"));
    }
    let boolean = |k| {
        v[k].as_bool()
            .ok_or_else(|| Error::protocol("Malformed automation coverage"))
    };
    let text = |k, max| {
        validation::text(&v[k], k, max, true, true)
            .map(str::to_owned)
            .map_err(|e| Error::protocol(e.message))
    };
    let ok = boolean("ok")?;
    let error = validation::text(
        v.get("error").unwrap_or(&json!("")),
        "Automation error",
        512,
        true,
        true,
    )
    .map_err(|e| Error::protocol(e.message))?
    .to_owned();
    if !ok && error.is_empty() {
        return Err(Error::protocol(
            "Failed automation result omitted its error",
        ));
    }
    let logs = v["logs"]
        .as_array()
        .filter(|a| a.len() <= 32)
        .ok_or_else(|| Error::protocol("Too many automation logs"))?
        .iter()
        .map(|log| {
            let level = log["level"]
                .as_str()
                .filter(|s| ["log", "info", "warn", "error"].contains(s))
                .ok_or_else(|| Error::protocol("Malformed automation log level"))?;
            let text = validation::text(&log["text"], "Log text", 1024, true, true)
                .map_err(|e| Error::protocol(e.message))?;
            Ok(json!({"level":level,"text":text}))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"ok":ok,"result_type":text("resultType",64)?,"result_text":text("resultText",16384)?,"result_truncated":boolean("resultTruncated")?,"logs":logs,"logs_truncated":boolean("logsTruncated")?,"elapsed_ms":validation::integer(&v["elapsedMs"],"Recipe duration",0,7000).map_err(|e|Error::protocol(e.message))?,"timed_out":boolean("timedOut")?,"error":error}),
    )
}
fn failure(message: &str) -> Value {
    json!({"ok":false,"result_type":"error","result_text":"","result_truncated":false,"logs":[],"logs_truncated":false,"elapsed_ms":0,"timed_out":false,"error":validation::truncate(message,512)})
}
impl Debugger {
    fn automation_editable(&self) -> Result<()> {
        let s = self.snapshot();
        if s["automation_recipes"]["auto_armed"] == true
            || !s["automation_recipes"]["active_run"].is_null()
        {
            return Err(Error::conflict(
                "Disarm or finish Automation Recipes before editing the recipe library",
            ));
        }
        Ok(())
    }
    pub(super) fn edit_recipe(&self, r: &Value, action: &str) -> Result<Value> {
        self.automation_editable()?;
        let s = self.snapshot();
        let mut recipes = s["automation_recipes"]["recipes"]
            .as_array()
            .unwrap()
            .clone();
        let mut selected = None;
        if action == "add_automation_recipe" {
            if recipes.len() >= 16 {
                return Err(Error::conflict("Automation recipe limit reached"));
            }
            let mut r = recipe(r)?;
            r["id"] = json!(self.automation.next_recipe.fetch_add(1, Ordering::Relaxed));
            recipes.push(r.clone());
            selected = Some(r);
        } else {
            let id = validation::integer(
                &r["recipe_id"],
                "Recipe ID",
                1,
                validation::MAX_SAFE_INTEGER,
            )?;
            let index = recipes
                .iter()
                .position(|v| v["id"] == id)
                .ok_or_else(|| Error::conflict("Automation recipe is unavailable"))?;
            if action == "remove_automation_recipe" {
                recipes.remove(index);
            } else {
                let mut r = recipe(r)?;
                r["id"] = json!(id);
                recipes[index] = r.clone();
                selected = Some(r);
            }
        }
        let bytes = recipes
            .iter()
            .map(|r| r["source_bytes"].as_u64().unwrap())
            .sum::<u64>();
        if bytes > 65536 {
            return Err(Error::conflict(
                "Automation recipe library exceeds the 64 KiB source limit",
            ));
        }
        self.update(|s| {
            s["automation_recipes"]["recipes"] = json!(recipes);
            s["automation_recipes"]["source_bytes"] = json!(bytes);
            s["automation_recipes"]["message"] = json!("Automation recipe library updated.");
        });
        let mut response = self.group_response("automation_recipes");
        if let Some(recipe) = selected {
            response["recipe"] = recipe;
        }
        Ok(response)
    }
    async fn automation_pages(&self) -> Result<BTreeMap<String, Arc<Connection>>> {
        self.isolated_target("automation_recipes", false)?;
        let scope = self.snapshot()["action_scope"].clone();
        if scope["state"] != "ready" {
            return Err(Error::conflict(
                "All matched disposable page sessions must be connected",
            ));
        }
        let ids = scope["targets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["matched"] == true)
            .filter_map(|t| t["id"].as_str())
            .collect::<Vec<_>>();
        let pages = self.experiment.pages.lock().await.clone();
        let matched = pages
            .into_iter()
            .filter(|(id, c)| ids.contains(&id.as_str()) && !c.is_closed())
            .collect::<BTreeMap<_, _>>();
        if matched.is_empty() {
            return Err(Error::conflict("No matched disposable page is available"));
        }
        Ok(matched)
    }
    fn start_recipe_run(
        &self,
        r: &Value,
        (kind, automatic): (&str, bool),
        target: &str,
        c: Arc<Connection>,
        document: Option<String>,
        permit: OwnedSemaphorePermit,
    ) -> Result<u64> {
        let s = self.snapshot();
        let a = &s["automation_recipes"];
        if a["total_runs"].as_u64().unwrap() >= 256
            || automatic && a["automatic_runs"].as_u64().unwrap() >= 64
        {
            return Err(Error::conflict("Automation session run limit reached"));
        }
        let id = self.automation.next_run.fetch_add(1, Ordering::Relaxed);
        let source = s["action_scope"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == target)
            .map(|t| t["url"].clone())
            .unwrap_or(json!("about:blank"));
        *self
            .automation
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Active {
            id,
            document,
            target: target.into(),
            connection: c,
            _permit: permit,
        });
        self.update(|s| {let a=&mut s["automation_recipes"];a["active_run"]=json!({"id":id,"recipe_id":r["id"],"label":r["label"],"trigger":kind,"source":source,"target_id":target,"started_at_ms":validation::now_ms(),"cancel_requested":false});a["total_runs"]=json!(a["total_runs"].as_u64().unwrap()+1);if automatic {a["automatic_runs"]=json!(a["automatic_runs"].as_u64().unwrap()+1);}a["state"]=json!("running");a["message"]=json!(format!("Running {} for {kind}.",r["label"].as_str().unwrap()));});
        Ok(id)
    }
    fn finish_recipe_run(&self, id: u64, result: &Value, outcome: Option<&str>) -> Option<Value> {
        let mut active = self
            .automation
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !active.as_ref().is_some_and(|a| a.id == id) {
            return self.snapshot()["automation_recipes"]["runs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == id)
                .cloned();
        }
        let mut finished = None;
        self.update(|s| {let a=&mut s["automation_recipes"];let current=a["active_run"].clone();if current["id"]!=id {return;}let cancelled=current["cancel_requested"]==true;let outcome=if cancelled {"cancelled"} else {outcome.unwrap_or(if result["ok"]==true {"completed"} else {"failed"})};let duration=validation::now_ms().saturating_sub(current["started_at_ms"].as_u64().unwrap());let run=json!({"id":id,"session_id":a["session_id"],"recipe_id":current["recipe_id"],"label":current["label"],"occurred_at_ms":current["started_at_ms"],"source":current["source"],"category":current["trigger"],"operation":outcome,"duration_ms":duration,"target_id":current["target_id"],"result_type":result["result_type"],"result_text":result["result_text"],"result_truncated":result["result_truncated"],"logs":result["logs"],"logs_truncated":result["logs_truncated"],"error":if cancelled {json!("Recipe cancelled")} else {result["error"].clone()}});let runs=a["runs"].as_array_mut().unwrap();let evicted=runs.len()==64;if evicted {runs.remove(0);}runs.push(run.clone());if evicted {a["run_evictions"]=json!(a["run_evictions"].as_u64().unwrap()+1);}a["active_run"]=Value::Null;a["state"]=json!(if a["auto_armed"]==true {"armed"} else {"ready"});a["last_failure"]=if ["failed","timed_out"].contains(&outcome) {result["error"].clone()} else {Value::Null};a["message"]=json!(format!("{} {} in {duration} ms.",current["label"].as_str().unwrap(),outcome.replace('_'," ")));finished=Some(run);});
        active.take();
        finished
    }
    async fn execute_recipe(
        &self,
        r: &Value,
        kind: &str,
        automatic: bool,
        target: &str,
        c: Arc<Connection>,
        permit: OwnedSemaphorePermit,
    ) -> Result<Option<Value>> {
        let id = self.start_recipe_run(r, (kind, automatic), target, c.clone(), None, permit)?;
        let variables = self
            .automation
            .variables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let configuration = configuration(r, &variables, false);
        let evaluated=c.command("Runtime.evaluate",json!({"expression":format!("({})({configuration})\n//# sourceURL=reb-automation-runner.js",include_str!("../../assets/automation-recipe-function.js")),"returnByValue":true,"awaitPromise":true,"silent":true,"userGesture":false,"allowUnsafeEvalBlockedByCSP":true,"timeout":2000}),Duration::from_secs(4)).await.and_then(|v| {if v["exceptionDetails"].is_object() {return Err(Error::conflict("The automation recipe failed before returning a result"));}result(&v["result"]["value"])});
        let (output, outcome) = match evaluated {
            Ok(r) => {
                let timeout = r["timed_out"] == true;
                (r, if timeout { Some("timed_out") } else { None })
            }
            Err(e) => {
                let timeout = e.message.contains("timed out") || e.message.contains("terminated");
                (
                    failure(if timeout {
                        "Recipe exceeded the 2 second execution limit"
                    } else {
                        &e.message
                    }),
                    if timeout { Some("timed_out") } else { None },
                )
            }
        };
        let finished = self.finish_recipe_run(id, &output, outcome);
        if outcome == Some("timed_out") || automatic && output["ok"] == false {
            if automatic {
                let _ = self.disarm_recipes().await;
            }
            let _ = c
                .command(
                    "Runtime.terminateExecution",
                    json!({}),
                    Duration::from_secs(3),
                )
                .await;
            let _ = c
                .command(
                    "Page.reload",
                    json!({"ignoreCache":true}),
                    Duration::from_secs(3),
                )
                .await;
        }
        Ok(finished)
    }
    pub(super) async fn run_recipe(&self, r: &Value) -> Result<Value> {
        if r["confirmed"] != true {
            return Err(Error::bad(
                "Confirm manual page-context code execution before running a recipe",
            ));
        }
        self.automation_editable()?;
        let id = validation::integer(
            &r["recipe_id"],
            "Recipe ID",
            1,
            validation::MAX_SAFE_INTEGER,
        )?;
        let recipe = self.snapshot()["automation_recipes"]["recipes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .cloned()
            .ok_or_else(|| Error::conflict("Automation recipe is unavailable"))?;
        let variables =
            workspace::variables(r.get("variables").unwrap_or(&json!({})), 64, 16384, true)?;
        let bytes = variables
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| k.len() + v.as_str().unwrap().len())
            .sum::<usize>();
        let pages = self.automation_pages().await?;
        *self
            .automation
            .variables
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = variables.clone();
        self.update(|s| {
            s["automation_recipes"]["variable_count"] = json!(variables.as_object().unwrap().len());
            s["automation_recipes"]["variable_bytes"] = json!(bytes);
        });
        let mut runs = Vec::new();
        for (id, c) in pages {
            let permit = self
                .automation
                .serial
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::conflict("Another Automation Recipe is already running"))?;
            if let Some(run) = self
                .execute_recipe(&recipe, "manual", false, &id, c, permit)
                .await?
            {
                runs.push(run);
            }
        }
        let mut response = self.group_response("automation_recipes");
        response["run"] = runs.last().cloned().unwrap_or(Value::Null);
        response["runs"] = json!(runs);
        Ok(response)
    }
    pub(super) fn start_automation(self: &Arc<Self>) {
        let Some(mut receiver) = self
            .automation
            .receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        else {
            return;
        };
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            while let Some(trigger) = receiver.recv().await {
                let Some(debugger) = weak.upgrade() else {
                    break;
                };
                if debugger.automation.epoch.load(Ordering::Acquire) != trigger.epoch
                    || debugger.snapshot()["automation_recipes"]["auto_armed"] != true
                {
                    continue;
                }
                let recipes = debugger.snapshot()["automation_recipes"]["recipes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["enabled"] == true && r["trigger"] == trigger.kind)
                    .cloned()
                    .collect::<Vec<_>>();
                for recipe in recipes {
                    let permit = tokio::select! {permit=debugger.automation.serial.clone().acquire_owned()=>match permit {Ok(p)=>p,Err(_)=>return},_=debugger.stop.notified()=>return};
                    if debugger.automation.epoch.load(Ordering::Acquire) != trigger.epoch
                        || debugger.snapshot()["automation_recipes"]["auto_armed"] != true
                    {
                        break;
                    }
                    let pages = match debugger.automation_pages().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let Some(c) = pages.get(&trigger.target) else {
                        break;
                    };
                    if let Err(e) = debugger
                        .execute_recipe(
                            &recipe,
                            &trigger.kind,
                            true,
                            &trigger.target,
                            c.clone(),
                            permit,
                        )
                        .await
                    {
                        debugger.update(|s| {
                            s["automation_recipes"]["last_failure"] = json!(e.message);
                            s["automation_recipes"]["message"] = json!(e.message);
                        });
                        let _ = debugger.disarm_recipes().await;
                        break;
                    }
                }
            }
        });
    }
    pub(super) fn queue_recipe_trigger(&self, target: &str, kind: &str) {
        let s = self.snapshot();
        if s["automation_recipes"]["auto_armed"] != true
            || !s["action_scope"]["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == target && t["matched"] == true)
        {
            return;
        }
        if self
            .automation
            .queue
            .try_send(Trigger {
                epoch: self.automation.epoch.load(Ordering::Acquire),
                target: target.into(),
                kind: kind.into(),
            })
            .is_err()
        {
            self.update(|s| {
                s["automation_recipes"]["dropped_triggers"] = json!(
                    s["automation_recipes"]["dropped_triggers"]
                        .as_u64()
                        .unwrap()
                        + 1
                )
            });
        }
    }
    pub(super) fn forget_automation_page(&self, id: &str) {
        self.automation
            .scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }
    fn before_load_source(&self, variables: &Value, nonce: &str) -> String {
        let recipes = self.snapshot()["automation_recipes"]["recipes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["enabled"] == true && r["trigger"] == "before-load")
            .cloned()
            .collect::<Vec<_>>();
        let configs = json!(
            recipes
                .iter()
                .map(|r| json!({"recipeId":r["id"],"config":configuration(r,variables,true)}))
                .collect::<Vec<_>>()
        );
        include_str!("../../assets/automation-before-load.js")
            .replace("@@binding@@", &json!(self.automation.binding).to_string())
            .replace("@@encoded_nonce@@", &json!(nonce).to_string())
            .replace("@@encoded_configs@@", &configs.to_string())
            .replace(
                "@@AUTOMATION_RECIPE_FUNCTION@@",
                include_str!("../../assets/automation-recipe-function.js"),
            )
            .replace("@@MAX_AUTOMATION_BINDING_REPORT_BYTES@@", "8192")
    }
    pub(super) async fn install_automation_page(&self, id: &str, c: Arc<Connection>) -> Result<()> {
        let s = self.snapshot();
        if s["automation_recipes"]["auto_armed"] != true
            || !s["action_scope"]["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == id && t["matched"] == true)
        {
            return Ok(());
        }
        let nonce = self
            .automation
            .nonce
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(nonce) = nonce else {
            return Ok(());
        };
        if self
            .automation
            .scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
        {
            return Ok(());
        }
        let variables = self
            .automation
            .variables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let source = self.before_load_source(&variables, &nonce);
        c.command(
            "Runtime.addBinding",
            json!({"name":self.automation.binding}),
            Duration::from_secs(3),
        )
        .await?;
        let script = match c
            .command(
                "Page.addScriptToEvaluateOnNewDocument",
                json!({"source":source,"runImmediately":false}),
                Duration::from_secs(3),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = c
                    .command(
                        "Runtime.removeBinding",
                        json!({"name":self.automation.binding}),
                        Duration::from_secs(3),
                    )
                    .await;
                return Err(e);
            }
        };
        let identifier = validation::text(
            &script["identifier"],
            "Automation script ID",
            4096,
            false,
            false,
        )
        .map_err(|e| Error::protocol(e.message))?
        .to_owned();
        self.automation
            .scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id.into(), identifier);
        Ok(())
    }
    pub(super) async fn arm_recipes(self: &Arc<Self>, r: &Value) -> Result<Value> {
        if r["confirmed"] != true {
            return Err(Error::bad(
                "Confirm automatic page-context code execution before arming recipes",
            ));
        }
        self.automation_editable()?;
        let pages = self.automation_pages().await?;
        let recipes = self.snapshot()["automation_recipes"]["recipes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["enabled"] == true && r["trigger"] != "manual")
            .cloned()
            .collect::<Vec<_>>();
        if recipes.is_empty() || recipes.len() > 8 {
            return Err(Error::bad("Enable between 1 and 8 automatic recipes"));
        }
        let variables =
            workspace::variables(r.get("variables").unwrap_or(&json!({})), 64, 16384, true)?;
        let bytes = variables
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| k.len() + v.as_str().unwrap().len())
            .sum::<usize>();
        *self
            .automation
            .variables
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = variables.clone();
        *self
            .automation
            .nonce
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            if recipes.iter().any(|r| r["trigger"] == "before-load") {
                Some(random())
            } else {
                None
            };
        self.automation.epoch.fetch_add(1, Ordering::AcqRel);
        self.update(|s| {
            let a = &mut s["automation_recipes"];
            a["state"] = json!("arming");
            a["auto_armed"] = json!(true);
            a["variable_count"] = json!(variables.as_object().unwrap().len());
            a["variable_bytes"] = json!(bytes);
        });
        for (id, c) in &pages {
            if let Err(e) = self.install_automation_page(id, c.clone()).await {
                let _ = self.disarm_recipes().await;
                self.update(|s| {
                    s["automation_recipes"]["state"] = json!("error");
                    s["automation_recipes"]["last_failure"] = json!(e.message);
                });
                return Err(e);
            }
        }
        self.update(|s| {
            s["automation_recipes"]["state"] = json!("armed");
            s["automation_recipes"]["message"] =
                json!("Automatic recipes armed. Created recipes are running now.");
        });
        for id in pages.keys() {
            self.queue_recipe_trigger(id, "created");
        }
        Ok(self.group_response("automation_recipes"))
    }
    pub(super) async fn disarm_recipes(&self) -> Result<Value> {
        let s = self.snapshot();
        if s["automation_recipes"]["auto_armed"] != true
            && self
                .automation
                .active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_none()
            && self
                .automation
                .scripts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        {
            return Err(Error::conflict(
                "Automation Recipes is not armed or running",
            ));
        }
        self.automation.epoch.fetch_add(1, Ordering::AcqRel);
        self.update(|s| {
            s["automation_recipes"]["auto_armed"] = json!(false);
            s["automation_recipes"]["state"] = json!("stopping");
            if s["automation_recipes"]["active_run"].is_object() {
                s["automation_recipes"]["active_run"]["cancel_requested"] = json!(true);
            }
        });
        let active = self
            .automation
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|a| (a.id, a.connection.clone()));
        let scripts = std::mem::take(
            &mut *self
                .automation
                .scripts
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        let pages = self.experiment.pages.lock().await.clone();
        let mut errors = Vec::new();
        if let Some((_, c)) = &active
            && let Err(e) = c
                .command(
                    "Runtime.terminateExecution",
                    json!({}),
                    Duration::from_secs(3),
                )
                .await
        {
            errors.push(e.message);
        }
        for (id, script) in scripts {
            if let Some(c) = pages.get(&id) {
                if let Err(e) = c
                    .command(
                        "Page.removeScriptToEvaluateOnNewDocument",
                        json!({"identifier":script}),
                        Duration::from_secs(3),
                    )
                    .await
                {
                    errors.push(e.message);
                }
                if let Err(e) = c
                    .command(
                        "Runtime.removeBinding",
                        json!({"name":self.automation.binding}),
                        Duration::from_secs(3),
                    )
                    .await
                {
                    errors.push(e.message);
                }
            }
        }
        if let Some((id, c)) = active {
            if let Err(e) = c
                .command(
                    "Page.reload",
                    json!({"ignoreCache":true}),
                    Duration::from_secs(3),
                )
                .await
            {
                errors.push(e.message);
            }
            self.finish_recipe_run(id, &failure("Recipe cancelled"), Some("cancelled"));
        }
        *self
            .automation
            .variables
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = json!({});
        *self
            .automation
            .nonce
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.update(|s| {
            let a = &mut s["automation_recipes"];
            a["variable_count"] = json!(0);
            a["variable_bytes"] = json!(0);
            a["state"] = json!(if errors.is_empty() { "ready" } else { "error" });
            a["message"] = json!(if errors.is_empty() {
                "Automatic recipes disarmed and session variables erased.".into()
            } else {
                validation::truncate(&errors.join("; "), 512)
            });
        });
        if !errors.is_empty() {
            return Err(Error::conflict(errors.join("; ")));
        }
        Ok(self.group_response("automation_recipes"))
    }
    pub(super) async fn cancel_recipe(&self) -> Result<Value> {
        if self.snapshot()["automation_recipes"]["auto_armed"] == true {
            return self.disarm_recipes().await;
        }
        let (id, c) = self
            .automation
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|a| (a.id, a.connection.clone()))
            .ok_or_else(|| Error::conflict("No Automation Recipe is running"))?;
        self.update(|s| {
            s["automation_recipes"]["active_run"]["cancel_requested"] = json!(true);
            s["automation_recipes"]["state"] = json!("stopping");
        });
        c.command(
            "Runtime.terminateExecution",
            json!({}),
            Duration::from_secs(3),
        )
        .await?;
        c.command(
            "Page.reload",
            json!({"ignoreCache":true}),
            Duration::from_secs(3),
        )
        .await?;
        self.finish_recipe_run(id, &failure("Recipe cancelled"), Some("cancelled"));
        Ok(self.group_response("automation_recipes"))
    }
    pub(super) fn clear_recipe_runs(&self) -> Result<Value> {
        self.automation_editable()?;
        self.update(|s| {
            let a = &mut s["automation_recipes"];
            a["runs"] = json!([]);
            for field in [
                "run_evictions",
                "total_runs",
                "automatic_runs",
                "dropped_triggers",
                "variable_count",
                "variable_bytes",
            ] {
                a[field] = json!(0);
            }
            a["last_failure"] = Value::Null;
            a["message"] =
                json!("Automation run results, logs, counters, and variables were cleared.");
        });
        *self
            .automation
            .variables
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = json!({});
        Ok(self.group_response("automation_recipes"))
    }
    pub(super) fn automation_binding(
        self: &Arc<Self>,
        target: &str,
        c: Arc<Connection>,
        p: &Value,
    ) {
        if p["name"] != self.automation.binding {
            return;
        }
        let Some(payload) = p["payload"].as_str().filter(|s| s.len() <= 8192) else {
            return;
        };
        let Ok(v) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let s = self.snapshot();
        let nonce = self
            .automation
            .nonce
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if v["protocolVersion"] != 1
            || nonce.as_deref() != v["nonce"].as_str()
            || nonce.is_none()
            || s["automation_recipes"]["auto_armed"] != true
            || !s["action_scope"]["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == target && t["matched"] == true)
        {
            return;
        }
        let Some(document) = v["documentId"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
        else {
            return;
        };
        let Some(recipe) = s["automation_recipes"]["recipes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r["id"] == v["recipeId"] && r["enabled"] == true && r["trigger"] == "before-load"
            })
        else {
            return;
        };
        if v["kind"] == "start" {
            let permit = match self.automation.serial.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    self.update(|s| {
                        s["automation_recipes"]["dropped_triggers"] = json!(
                            s["automation_recipes"]["dropped_triggers"]
                                .as_u64()
                                .unwrap()
                                + 1
                        )
                    });
                    return;
                }
            };
            let id = match self.start_recipe_run(
                recipe,
                ("before-load", true),
                target,
                c.clone(),
                Some(document.into()),
                permit,
            ) {
                Ok(id) => id,
                Err(e) => {
                    self.update(|s| s["automation_recipes"]["last_failure"] = json!(e.message));
                    return;
                }
            };
            let weak = Arc::downgrade(self);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let Some(d) = weak.upgrade() else {
                    return;
                };
                if d.snapshot()["automation_recipes"]["active_run"]["id"] == id {
                    let _ = c
                        .command(
                            "Runtime.terminateExecution",
                            json!({}),
                            Duration::from_secs(3),
                        )
                        .await;
                    let _ = c
                        .command(
                            "Page.reload",
                            json!({"ignoreCache":true}),
                            Duration::from_secs(3),
                        )
                        .await;
                    d.finish_recipe_run(
                        id,
                        &failure("Recipe exceeded the 2 second execution limit"),
                        Some("timed_out"),
                    );
                    let _ = d.disarm_recipes().await;
                }
            });
        } else if v["kind"] == "done" {
            let active = self
                .automation
                .active
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .filter(|a| a.target == target && a.document.as_deref() == Some(document))
                .map(|a| a.id);
            if let Some(id) = active
                .filter(|_| s["automation_recipes"]["active_run"]["recipe_id"] == recipe["id"])
            {
                let normalized = result(&v["result"]);
                let failed = !normalized.as_ref().is_ok_and(|r| r["timed_out"] != true);
                let result = normalized.unwrap_or_else(|e| failure(&e.message));
                self.finish_recipe_run(
                    id,
                    &result,
                    if result["timed_out"] == true {
                        Some("timed_out")
                    } else {
                        None
                    },
                );
                if failed {
                    let weak = Arc::downgrade(self);
                    tokio::spawn(async move {
                        if let Some(d) = weak.upgrade() {
                            let _ = d.disarm_recipes().await;
                        }
                    });
                }
            }
        }
    }
}
