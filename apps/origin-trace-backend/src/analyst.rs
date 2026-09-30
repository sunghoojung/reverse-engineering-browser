use crate::{
    config::Options,
    error::{Error, Result},
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
    pub async fn run(&self, value: &Value, workspace: &Value) -> Result<Value> {
        let request = normalize(value, workspace)?;
        let executable = self.executable.as_ref().ok_or_else(|| {
            Error::new(
                503,
                "Local analyst execution requires the native runner or Node.js 22 or newer",
            )
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
        let _active = Active(self);
        let mut command = Command::new(executable);
        if !self.native {
            command
                .args([
                    "--permission",
                    &format!("--allow-fs-read={}", self.directory.display()),
                    "--max-old-space-size=64",
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
                    for (resource, limit) in [
                        (libc::RLIMIT_CORE, 0),
                        (libc::RLIMIT_CPU, 3),
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
        let encoded = serde_json::to_vec(&request)?;
        let result = worker::run_cancel(
            &mut command,
            &encoded,
            128 * 1024,
            Duration::from_millis(2500),
            Some(&mut receiver),
        )
        .await;
        match result {
            Err(e) if e.status == 499 => Ok(failure(
                &request,
                "cancelled",
                "Analyst script cancelled",
                started.elapsed().as_millis() as u64,
            )),
            Err(e) if e.status == 408 => Ok(failure(
                &request,
                "timed_out",
                "Analyst script exceeded the 2 second execution limit",
                started.elapsed().as_millis() as u64,
            )),
            Err(e) => Err(e),
            Ok(output) => {
                let result: Value = serde_json::from_slice(&output.bytes).map_err(|_| {
                    Error::protocol(if output.stderr.is_empty() {
                        "Analyst runner returned malformed output".into()
                    } else {
                        validation::truncate(String::from_utf8_lossy(&output.stderr).trim(), 512)
                    })
                })?;
                validate_result(&result, &request)?;
                Ok(result)
            }
        }
    }
}
fn normalize(value: &Value, workspace: &Value) -> Result<Value> {
    validation::fields(
        value,
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
    if value["action"] != "run_local_analyst_script"
        || value["protocol_version"] != 1
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
    let source = validation::text(&value["source"], "Analyst source", 32768, false, true)?;
    if source.trim().is_empty() || source.chars().any(|c| c < ' ' && !"\t\n\r".contains(c)) {
        return Err(Error::bad("Analyst source is empty or contains controls"));
    }
    let variables = workspace::variables(&value["variables"], 128, 16384, true)?;
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
    for (key, max) in [
        ("events", 500),
        ("artifacts", 500),
        ("trace_edges", 1000),
        ("signal_profiles", 256),
    ] {
        if !evidence[key].as_array().is_some_and(|a| a.len() <= max) {
            return Err(Error::bad(format!(
                "Analyst {key} are invalid or oversized"
            )));
        }
    }
    if !evidence["vm_analysis"].is_null() && !evidence["vm_analysis"].is_object()
        || !evidence["summary"].is_object()
    {
        return Err(Error::bad("Analyst evidence snapshot is invalid"));
    }
    let selected = &evidence["selected_artifact"];
    if !selected.is_null() {
        if !selected.is_object() {
            return Err(Error::bad("Analyst selected artifact snapshot is invalid"));
        }
        validation::text(
            &selected["content"],
            "Analyst selected artifact",
            65536,
            true,
            true,
        )?;
        if selected["sensitive"] == true && value["confirmed_sensitive"] != true {
            return Err(Error::bad(
                "Confirm inclusion of sensitive selected artifact bytes before running",
            ));
        }
    }
    bounded_json(evidence, 0, &mut 0)?;
    if serde_json::to_vec(evidence)?.len() > 768 * 1024 {
        return Err(Error::bad("Analyst evidence snapshot exceeds 768 KiB"));
    }
    let request = json!({"protocol_version":1,"run_id":run,"script_id":script,"library_generation":generation,"source":source,"variables":variables,"evidence":evidence});
    if serde_json::to_vec(&request)?.len() > 800 * 1024 {
        return Err(Error::bad("Analyst runner input is oversized"));
    }
    if workspace["generation"] != generation {
        return Err(Error::conflict(
            "Analyst workspace changed; refresh before running the saved script",
        ));
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
    Ok(request)
}
fn bounded_json(value: &Value, depth: usize, count: &mut usize) -> Result<()> {
    *count += 1;
    if depth > 16 || *count > 50000 {
        return Err(Error::bad(
            "Analyst evidence exceeds its nesting or entry limit",
        ));
    }
    match value {
        Value::Array(a) => {
            for v in a {
                bounded_json(v, depth + 1, count)?;
            }
        }
        Value::Object(o) => {
            for (key, v) in o {
                if key.len() > 256 {
                    return Err(Error::bad("Analyst evidence contains an invalid key"));
                }
                bounded_json(v, depth + 1, count)?;
            }
        }
        _ => (),
    }
    Ok(())
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
        || !["completed", "failed", "cancelled", "timed_out"]
            .contains(&value["outcome"].as_str().unwrap_or(""))
        || value["ok"].as_bool() != Some(value["outcome"] == "completed")
        || !value["result_truncated"].is_boolean()
        || !value["logs_truncated"].is_boolean()
        || !value["duration_ms"].as_u64().is_some_and(|n| n <= 7000)
    {
        return Err(Error::protocol(
            "Analyst runner returned invalid result state or correlation identifiers",
        ));
    }
    for (key, max) in [("result_type", 64), ("result_text", 32768), ("error", 512)] {
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
        .filter(|a| a.len() <= 64)
        .ok_or_else(|| Error::protocol("Analyst runner returned too many logs"))?;
    for log in logs {
        validation::fields(log, &["level", "text"], "Analyst log")
            .map_err(|e| Error::protocol(e.message))?;
        if !["log", "info", "warn", "error"].contains(&log["level"].as_str().unwrap_or("")) {
            return Err(Error::protocol(
                "Analyst runner returned an invalid log level",
            ));
        }
        validation::text(&log["text"], "Analyst log", 1024, true, true)
            .map_err(|e| Error::protocol(e.message))?;
    }
    Ok(())
}
fn failure(request: &Value, outcome: &str, message: &str, duration: u64) -> Value {
    json!({"protocol_version":1,"run_id":request["run_id"],"script_id":request["script_id"],"library_generation":request["library_generation"],"ok":false,"outcome":outcome,"result_type":"error","result_text":"","result_truncated":false,"logs":[],"logs_truncated":false,"duration_ms":duration.min(7000),"error":validation::truncate(message,512)})
}
