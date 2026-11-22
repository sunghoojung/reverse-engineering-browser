use crate::{
    config::Options,
    error::{Code, Confirmation, Error, Phase, Reason, Result},
    validation, worker, workspace,
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::watch};

pub struct Analyst {
    executable: Option<PathBuf>,
    native: bool,
    directory: PathBuf,
    active: Mutex<Option<(u64, watch::Sender<bool>)>>,
}
/// A validated run, before its host reads the stored artifact it names.
pub struct Run {
    request: Value,
    selected: Option<(String, String)>,
    confirmed_sensitive: bool,
}
impl Run {
    /// Takes the request whole, so its evidence snapshot moves into the run
    /// instead of being copied.
    pub fn new(value: Value, workspace: &Value) -> Result<Self> {
        let confirmed_sensitive = value["confirmed_sensitive"] == true;
        let (request, selected) = normalize(value, workspace)?;
        Ok(Self {
            request,
            selected,
            confirmed_sensitive,
        })
    }
    /// The selected artifact's ID, when the run includes one.
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_ref().map(|(id, _)| id.as_str())
    }
    /// Checks the stored record against the reference the page sent, and
    /// sensitivity against the manifest rather than the page, before any of
    /// its bytes are read.
    pub fn admit(&self, artifact: &Value) -> Result<()> {
        let (_, sha256) = self
            .selected
            .as_ref()
            .ok_or_else(|| Error::bad("This run includes no selected artifact"))?;
        // The kinds Sources never lists: header blocks, cookie lists, request
        // bodies and targets, canvas images and stacks are read only with
        // their own evidence, never by a script.
        if NOT_SOURCES.contains(&artifact["kind"].as_str().unwrap_or("")) {
            return Err(Error::bad(
                "Only an artifact Sources lists can be a run's selected artifact",
            ));
        }
        if artifact["sha256"] != sha256.as_str() {
            return Err(Error::conflict(
                "The selected artifact changed; select it again before running",
            ));
        }
        // Only the stored record says whether the artifact is sensitive, so
        // the contract cannot ask for this confirmation before a run names
        // one. The refusal names the field, before any byte is read.
        if artifact["sensitive"] == true && !self.confirmed_sensitive {
            return Err(Error::new(
                400,
                "The selected artifact is sensitive; confirm inclusion of its bytes with confirmed_sensitive before running",
            )
            .with_reason(Reason::confirmation(Confirmation::ConfirmedSensitive)));
        }
        Ok(())
    }
}
const NOT_SOURCES: [&str; 7] = [
    "canvas_data_url",
    "request_body",
    "request_target",
    "request_headers",
    "response_headers",
    "cookie_list",
    "stack",
];
/// The manifest fields a script sees for the selected artifact. Its bytes
/// follow the runner's JSON header instead of being copied into it.
const SELECTED_FIELDS: [&str; 16] = [
    "protocol_version",
    "artifact_id",
    "session_id",
    "navigation_id",
    "frame_id",
    "parent_artifact_id",
    "creator_event_id",
    "execution_context_id",
    "capture_origin",
    "kind",
    "origin",
    "url",
    "mime_type",
    "byte_size",
    "sha256",
    "sensitive",
];
struct Active<'a>(&'a Analyst);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.active.lock() {
            *active = None;
        }
    }
}
impl Analyst {
    pub async fn new(options: &Options) -> Self {
        let native = options.worker(
            &options.analyst_runner,
            "OriginTraceAnalystRunner",
            "build/reb-analyst-runner",
        );
        let directory = options.ui_root();
        let (executable, is_native) = if worker::executable(&native) {
            (Some(native), true)
        } else {
            let node = std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|directory| directory.join("node"))
                    .find(|path| worker::executable(path))
            });
            let available = tokio::time::timeout(
                Duration::from_secs(2),
                Command::new(node.as_deref().unwrap_or(std::path::Path::new("node")))
                    .arg("--version")
                    .output(),
            )
            .await
            .ok()
            .and_then(|o| o.ok())
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.trim()
                    .trim_start_matches('v')
                    .split('.')
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .is_some_and(|v| v >= 22);
            (if available { node } else { None }, false)
        };
        Self {
            executable,
            native: is_native,
            directory,
            active: Mutex::new(None),
        }
    }
    pub fn stop(&self) {
        if let Some((_, sender)) = self
            .active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let _ = sender.send(true);
        }
    }
    pub fn state(&self) -> Value {
        json!({"protocol_version":1,"available":self.executable.is_some(),"active_run_id":self.active.lock().ok().and_then(|a|a.as_ref().map(|a|a.0)),"limits":workspace::Kind::Analyst.limits()})
    }
    pub fn cancel(&self, id: &Value) -> Result<bool> {
        let id = validation::integer(id, "Analyst run ID", 1, validation::MAX_SAFE_INTEGER)?;
        let active = self
            .active
            .lock()
            .map_err(|_| Error::new(500, "Analyst runner is unavailable"))?;
        let (_, sender) = active
            .as_ref()
            .filter(|(run, _)| *run == id)
            .ok_or_else(|| Error::bad("The selected analyst run is no longer active"))?;
        sender
            .send(true)
            .map_err(|_| Error::bad("The selected analyst run is no longer active"))?;
        Ok(true)
    }
    /// Runs until the script settles, the researcher cancels it, or its
    /// request goes away; there is no deadline. `selected` is the stored
    /// record and verified bytes of the artifact `run` names.
    pub async fn run(&self, run: Run, selected: Option<(Value, Vec<u8>)>) -> Result<Value> {
        if let Some((artifact, _)) = &selected {
            run.admit(artifact)?;
        }
        let Run {
            mut request,
            selected: reference,
            ..
        } = run;
        let bytes = match selected {
            Some((artifact, bytes)) => {
                let mut metadata = serde_json::Map::new();
                for field in SELECTED_FIELDS {
                    if !artifact[field].is_null() {
                        metadata.insert(field.into(), artifact[field].clone());
                    }
                }
                metadata.insert("byte_size".into(), json!(bytes.len()));
                request["evidence"]["selected_artifact"] = Value::Object(metadata);
                bytes
            }
            None if reference.is_some() => {
                return Err(Error::bad("The selected artifact was not read"));
            }
            None => Vec::new(),
        };
        let executable = self.executable.as_ref().ok_or_else(|| {
            Error::new(
                503,
                "Local analyst execution requires the native runner or Node.js 22 or newer",
            )
            .with_code(Code::DependencyUnavailable)
        })?;
        let (sender, mut receiver) = watch::channel(false);
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| Error::new(500, "Analyst runner is unavailable"))?;
            if active.is_some() {
                return Err(Error::conflict(
                    "Another local analyst script is already running",
                ));
            }
            *active = Some((request["run_id"].as_u64().unwrap(), sender));
        }
        let active = Active(self);
        let mut command = Command::new(executable);
        if !self.native {
            command
                .args([
                    "--permission",
                    &format!("--allow-fs-read={}", self.directory.display()),
                    "--disable-proto=throw",
                    "--no-addons",
                ])
                .arg(self.directory.join("analyst_runner_node.js"));
        }
        command
            .arg(self.directory.join("analyst_runner_core.js"))
            .current_dir(std::env::temp_dir())
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TZ", "UTC");
        #[cfg(unix)]
        {
            command.process_group(0);
            unsafe {
                command.pre_exec(|| {
                    // No CPU or memory limit: a run lasts until it settles
                    // or is cancelled, and holds what its evidence needs.
                    for (resource, limit) in [
                        (libc::RLIMIT_CORE, 0),
                        (libc::RLIMIT_FSIZE, 0),
                        (libc::RLIMIT_NOFILE, 32),
                    ] {
                        let limit = libc::rlimit {
                            rlim_cur: limit,
                            rlim_max: limit,
                        };
                        if libc::setrlimit(resource, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
        let started = Instant::now();
        // Runner input v2: one JSON line, then the selected artifact's bytes.
        // The line is encoded while the runner reads it and the request is
        // freed once it is, and the bytes are freed once written, so neither
        // the evidence snapshot nor the artifact is held while the script
        // runs, and the snapshot is never held both parsed and encoded.
        let identity = json!({"run_id":request["run_id"],"script_id":request["script_id"],"library_generation":request["library_generation"]});
        let (mut writer, line) = worker::ChunkWriter::new();
        let encoder = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            use std::io::Write;
            serde_json::to_writer(&mut writer, &request)?;
            writer.write_all(b"\n")?;
            writer.flush()
        });
        let result = worker::run_cancel(
            &mut command,
            vec![line, worker::Input::Owned(bytes)],
            None,
            None,
            Some(&mut receiver),
        )
        .await;
        // The runner stopping early fails the encoder; a result is only
        // trusted when its whole input was written.
        let encoded = matches!(encoder.await, Ok(Ok(())));
        // The run is over once its worker returns; a later cancel finds no
        // active run instead of reporting a request nothing will observe.
        drop(active);
        match result {
            Err(e) if e.reason.code == Code::Cancelled => Ok(failure(
                &identity,
                "cancelled",
                "Analyst script cancelled",
                started.elapsed().as_millis() as u64,
            )),
            Err(e) => Err(e),
            Ok(_) if !encoded => Err(Error::new(500, "Analyst runner input was not written")),
            Ok(output) => {
                let mut result: Value = serde_json::from_slice(&output.bytes).map_err(|_| {
                    Error::protocol(if output.stderr.is_empty() {
                        "Analyst runner returned malformed output".into()
                    } else {
                        String::from_utf8_lossy(&output.stderr).trim().to_owned()
                    })
                })?;
                validate_result(&result, &identity)?;
                annotate_failure(&mut result);
                Ok(result)
            }
        }
    }
}
fn normalize(mut value: Value, workspace: &Value) -> Result<(Value, Option<(String, String)>)> {
    validation::fields(
        &value,
        &[
            "action",
            "protocol_version",
            "run_id",
            "script_id",
            "library_generation",
            "source",
            "variables",
            "evidence",
            "confirmed",
            "confirmed_sensitive",
        ],
        "Analyst run",
    )?;
    if value["protocol_version"] != 2 {
        return Err(Error::bad(
            "Analyst runs use protocol 2, which names the selected artifact by artifact_id and sha256",
        ));
    }
    if value["action"] != "run_local_analyst_script"
        || value["confirmed"] != true
        || !value["confirmed_sensitive"].is_boolean()
    {
        return Err(Error::bad(
            "Confirm local analyst script execution before running",
        ));
    }
    let run = validation::integer(
        &value["run_id"],
        "Analyst run ID",
        1,
        validation::MAX_SAFE_INTEGER,
    )?;
    let script = validation::integer(
        &value["script_id"],
        "Analyst script ID",
        1,
        validation::MAX_SAFE_INTEGER,
    )?;
    let generation = validation::integer(
        &value["library_generation"],
        "Analyst generation",
        0,
        validation::MAX_SAFE_INTEGER,
    )?;
    let source = validation::text(&value["source"], "Analyst source", usize::MAX, false, true)?;
    if source.trim().is_empty() || source.chars().any(|c| c < ' ' && !"\t\n\r".contains(c)) {
        return Err(Error::bad("Analyst source is empty or contains controls"));
    }
    let variables = workspace::variables(&value["variables"], true)?;
    let evidence = &value["evidence"];
    validation::fields(
        evidence,
        &[
            "events",
            "artifacts",
            "trace_edges",
            "signal_profiles",
            "vm_analysis",
            "selected_artifact",
            "summary",
        ],
        "Analyst evidence",
    )?;
    for key in ["events", "artifacts", "trace_edges", "signal_profiles"] {
        if !evidence[key].is_array() {
            return Err(Error::bad(format!("Analyst {key} must be a list")));
        }
    }
    if !evidence["vm_analysis"].is_null() && !evidence["vm_analysis"].is_object()
        || !evidence["summary"].is_object()
    {
        return Err(Error::bad("Analyst evidence snapshot is invalid"));
    }
    let selected = &evidence["selected_artifact"];
    let reference = if selected.is_null() {
        None
    } else {
        validation::fields(
            selected,
            &["artifact_id", "sha256"],
            "Analyst selected artifact",
        )?;
        let id = validation::text(
            &selected["artifact_id"],
            "Selected artifact ID",
            64,
            false,
            false,
        )?;
        let sha256 = validation::text(
            &selected["sha256"],
            "Selected artifact SHA-256",
            64,
            false,
            false,
        )?;
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::bad("Selected artifact SHA-256 is invalid"));
        }
        Some((id.to_owned(), sha256.to_owned()))
    };
    if workspace["generation"] != generation {
        return Err(Error::conflict(
            "Analyst workspace changed; refresh before running the saved script",
        )
        .with_reason(Reason::stale(
            generation,
            workspace["generation"].as_u64().unwrap(),
        )));
    }
    if !workspace["files"].as_array().is_some_and(|a| {
        a.iter().any(|f| {
            f["id"] == script
                && f["kind"] == "analyst-script"
                && f["language"] == "javascript"
                && f["content"] == source
        })
    }) {
        return Err(Error::conflict(
            "Only the current saved JavaScript analyst script can execute",
        ));
    }
    // Built by moving the source and snapshot in: `json!` would serialize
    // them, a deep copy of the whole snapshot.
    let mut request = serde_json::Map::new();
    request.insert("protocol_version".into(), json!(2));
    request.insert("run_id".into(), json!(run));
    request.insert("script_id".into(), json!(script));
    request.insert("library_generation".into(), json!(generation));
    request.insert("source".into(), value["source"].take());
    request.insert("variables".into(), variables);
    request.insert("evidence".into(), value["evidence"].take());
    Ok((Value::Object(request), reference))
}
fn validate_result(value: &Value, request: &Value) -> Result<()> {
    validation::fields(
        value,
        &[
            "protocol_version",
            "run_id",
            "script_id",
            "library_generation",
            "ok",
            "outcome",
            "result_type",
            "result_text",
            "result_truncated",
            "logs",
            "logs_truncated",
            "duration_ms",
            "error",
        ],
        "Analyst result",
    )
    .map_err(|e| Error::protocol(e.message))?;
    if value["protocol_version"] != 1
        || ["run_id", "script_id", "library_generation"]
            .iter()
            .any(|k| value[k] != request[k])
        || !["completed", "failed", "cancelled"].contains(&value["outcome"].as_str().unwrap_or(""))
        || value["ok"].as_bool() != Some(value["outcome"] == "completed")
        || !value["result_truncated"].is_boolean()
        || !value["logs_truncated"].is_boolean()
        || !value["duration_ms"].is_u64()
    {
        return Err(Error::protocol(
            "Analyst runner returned invalid result state or correlation identifiers",
        ));
    }
    for (key, max) in [
        ("result_type", 64),
        ("result_text", usize::MAX),
        ("error", usize::MAX),
    ] {
        validation::text(&value[key], key, max, true, true)
            .map_err(|e| Error::protocol(e.message))?;
    }
    if (value["ok"] == true) == !value["error"].as_str().unwrap().is_empty() {
        return Err(Error::protocol(
            "Analyst runner returned inconsistent error state",
        ));
    }
    let logs = value["logs"]
        .as_array()
        .ok_or_else(|| Error::protocol("Analyst runner returned malformed logs"))?;
    for log in logs {
        validation::fields(log, &["level", "text"], "Analyst log")
            .map_err(|e| Error::protocol(e.message))?;
        if !["log", "info", "warn", "error"].contains(&log["level"].as_str().unwrap_or("")) {
            return Err(Error::protocol(
                "Analyst runner returned an invalid log level",
            ));
        }
        validation::text(&log["text"], "Analyst log", usize::MAX, true, true)
            .map_err(|e| Error::protocol(e.message))?;
    }
    Ok(())
}
fn failure(request: &Value, outcome: &str, message: &str, duration: u64) -> Value {
    let mut result = json!({"protocol_version":1,"run_id":request["run_id"],"script_id":request["script_id"],"library_generation":request["library_generation"],"ok":false,"outcome":outcome,"result_type":"error","result_text":"","result_truncated":false,"logs":[],"logs_truncated":false,"duration_ms":duration,"error":message});
    annotate_failure(&mut result);
    result
}
fn annotate_failure(value: &mut Value) {
    let code = match value["outcome"].as_str() {
        Some("cancelled") => Code::Cancelled,
        Some("failed") => Code::ApplicationFailed,
        _ => return,
    };
    Reason::at(code, Phase::Worker).annotate(value);
}
