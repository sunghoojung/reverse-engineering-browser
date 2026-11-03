//! Starts a live capture session for `reb-api session start` and the MCP
//! `start_live_session` tool. It runs the same launcher as `make live` and the
//! packaged app, detached from the caller, with named capture options in place
//! of environment variables. Every capture switch is off unless requested, so
//! a session never inherits a switch from the caller's shell.
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const READY_LINE: &str = "Origin Trace live session ";
const FAILURE_LINE: &str = "REB_LIVE_SESSION_FAILURE: ";
const POLL: Duration = Duration::from_millis(200);

/// Capture options named after the launcher's environment switches.
#[derive(Clone, Debug, Default)]
pub struct StartOptions {
    pub url: Option<String>,
    pub wasm_dispatch: bool,
    pub wasm_call_indirect: bool,
    pub guest_adapter: Option<PathBuf>,
    pub js_dispatch_sites: Option<PathBuf>,
    pub quiet: bool,
    pub category_mask: Option<u32>,
    pub duration_seconds: Option<u32>,
    pub localhost_only: bool,
    pub canvas_images: bool,
    pub confirm_sensitive_capture: bool,
    pub publish_canonical_endpoint: bool,
    pub brave_binary: Option<PathBuf>,
    pub timeout_seconds: Option<u64>,
    /// CLI only: where session directories are created.
    pub sessions_root: Option<PathBuf>,
}

impl StartOptions {
    /// Reads options already checked against the `LiveSessionStart` schema.
    pub fn from_json(value: &Value) -> Self {
        let flag = |key: &str| value[key].as_bool().unwrap_or(false);
        let path = |key: &str| value[key].as_str().map(PathBuf::from);
        Self {
            url: value["url"].as_str().map(str::to_owned),
            wasm_dispatch: flag("wasm_dispatch"),
            wasm_call_indirect: flag("wasm_call_indirect"),
            guest_adapter: path("guest_adapter"),
            js_dispatch_sites: path("js_dispatch_sites"),
            quiet: flag("quiet"),
            category_mask: value["category_mask"].as_u64().map(|n| n as u32),
            duration_seconds: value["duration_seconds"].as_u64().map(|n| n as u32),
            localhost_only: flag("localhost_only"),
            canvas_images: flag("canvas_images"),
            confirm_sensitive_capture: flag("confirm_sensitive_capture"),
            publish_canonical_endpoint: flag("publish_canonical_endpoint"),
            brave_binary: path("brave_binary"),
            timeout_seconds: value["timeout_seconds"].as_u64(),
            sessions_root: None,
        }
    }

    /// Cross-field rules a JSON Schema cannot state clearly. The launcher
    /// checks the same rules again and remains the authority.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(url) = &self.url {
            let parsed = url::Url::parse(url).map_err(|_| "url must be an HTTP or HTTPS URL")?;
            if !["http", "https"].contains(&parsed.scheme())
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err("url must be HTTP or HTTPS without embedded credentials".into());
            }
        }
        for (name, path) in [
            ("guest_adapter", &self.guest_adapter),
            ("js_dispatch_sites", &self.js_dispatch_sites),
            ("brave_binary", &self.brave_binary),
            ("sessions_root", &self.sessions_root),
        ] {
            if path.as_ref().is_some_and(|path| !path.is_absolute()) {
                return Err(format!("{name} must be an absolute path"));
            }
        }
        if self.guest_adapter.is_some() && !self.wasm_dispatch {
            return Err("guest_adapter requires wasm_dispatch".into());
        }
        if self.canvas_images && !self.confirm_sensitive_capture {
            return Err(
                "canvas_images stores page content and requires confirm_sensitive_capture".into(),
            );
        }
        if self
            .category_mask
            .is_some_and(|mask| !(1..=4095).contains(&mask))
        {
            return Err("category_mask must be between 1 and 4095".into());
        }
        if self
            .duration_seconds
            .is_some_and(|seconds| !(60..=3600).contains(&seconds))
        {
            return Err("duration_seconds must be between 60 and 3600".into());
        }
        if self
            .timeout_seconds
            .is_some_and(|seconds| !(10..=600).contains(&seconds))
        {
            return Err("timeout_seconds must be between 10 and 600".into());
        }
        Ok(())
    }

    /// The options the session actually ran with, defaults included.
    pub fn effective(&self) -> Value {
        let mut value = json!({
            "wasm_dispatch": self.wasm_dispatch,
            "wasm_call_indirect": self.wasm_call_indirect,
            "quiet": self.quiet,
            "category_mask": self.category_mask.unwrap_or(4095),
            "duration_seconds": self.duration_seconds.unwrap_or(3600),
            "localhost_only": self.localhost_only,
            "canvas_images": self.canvas_images,
            "publish_canonical_endpoint": self.publish_canonical_endpoint,
            "timeout_seconds": self.timeout(),
        });
        for (key, path) in [
            ("guest_adapter", &self.guest_adapter),
            ("js_dispatch_sites", &self.js_dispatch_sites),
            ("brave_binary", &self.brave_binary),
        ] {
            if let Some(path) = path {
                value[key] = json!(path.display().to_string());
            }
        }
        if let Some(url) = &self.url {
            value["url"] = json!(url);
        }
        if self.confirm_sensitive_capture {
            value["confirm_sensitive_capture"] = json!(true);
        }
        value
    }

    fn timeout(&self) -> u64 {
        self.timeout_seconds.unwrap_or(180)
    }
}

/// A ready session. Paths are for local callers; the MCP tool omits them.
#[derive(Debug)]
pub struct Started {
    pub session_id: String,
    pub session_dir: PathBuf,
    pub endpoint: String,
    pub endpoint_file: PathBuf,
    pub instance_id: String,
    pub log_file: PathBuf,
    pub canonical_endpoint: bool,
    pub url_opened: Option<bool>,
    pub url_error: Option<String>,
    /// Whether a stored record followed the opened page. Null without a url.
    pub capture_observed: Option<bool>,
}

impl Started {
    pub fn document(&self, options: &StartOptions, paths: bool) -> Value {
        let mut value = json!({
            "session_id": self.session_id,
            "endpoint": self.endpoint,
            "instance_id": self.instance_id,
            "canonical_endpoint": self.canonical_endpoint,
            "options": options.effective(),
            "url_opened": self.url_opened,
            "capture_observed": self.capture_observed,
        });
        if let Some(error) = &self.url_error {
            value["url_error"] = json!(error);
        }
        if paths {
            value["session_dir"] = json!(self.session_dir.display().to_string());
            value["endpoint_file"] = json!(self.endpoint_file.display().to_string());
            value["log_file"] = json!(self.log_file.display().to_string());
        }
        value
    }
}

/// The launcher and helper set that belong with this `reb-api` build.
struct Kit {
    script: PathBuf,
    env: Vec<(&'static str, PathBuf)>,
    sessions_root: PathBuf,
    brave: Option<PathBuf>,
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is required to start a live session".into())
}

fn kit() -> Result<Kit, String> {
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|error| format!("Cannot locate this reb-api build: {error}"))?;
    let directory = executable
        .parent()
        .ok_or("Cannot locate this reb-api build")?;
    if let Some(script) = std::env::var_os("REB_LIVE_SESSION_SCRIPT") {
        let root = std::env::var_os("REB_LIVE_SESSION_ROOT")
            .map(PathBuf::from)
            .ok_or("REB_LIVE_SESSION_SCRIPT also needs REB_LIVE_SESSION_ROOT")?;
        return Ok(Kit {
            script: PathBuf::from(script),
            env: Vec::new(),
            sessions_root: root,
            brave: None,
        });
    }
    // Packaged: <App>.app/Contents/MacOS/OriginTraceAPI beside the helpers.
    let resources = directory.join("../Resources/run-live-session.sh");
    if directory.ends_with("Contents/MacOS") && resources.is_file() {
        let bundle = directory
            .parent()
            .and_then(Path::parent)
            .ok_or("Cannot locate the Origin Trace app bundle")?
            .to_path_buf();
        let support = home()?.join("Library/Application Support/Origin Trace");
        let helper = |name: &str| directory.join(name);
        let sibling = bundle
            .parent()
            .map(|parent| {
                parent
                    .join("Brave Browser Development.app/Contents/MacOS/Brave Browser Development")
            })
            .filter(|path| path.is_file());
        return Ok(Kit {
            script: resources,
            env: vec![
                ("REB_BROKER_BINARY", helper("OriginTraceEventBroker")),
                (
                    "REB_ARTIFACT_RECEIVER_BINARY",
                    helper("OriginTraceArtifactReceiver"),
                ),
                (
                    "REB_HEAP_SNAPSHOT_BINARY",
                    helper("OriginTraceHeapSnapshot"),
                ),
                ("REB_DECODER_BINARY", helper("OriginTraceDecoder")),
                ("REB_DEOBFUSCATOR_WORKER", helper("OriginTraceDeobfuscator")),
                ("REB_ORIGIN_TRACE_BACKEND", helper("OriginTraceBackend")),
                ("REB_VM_ANALYZER", helper("OriginTraceVMAnalyzer")),
                ("REB_ORIGIN_TRACE_APP", bundle),
                (
                    "REB_API_COLLECTION_STORE",
                    support.join("api-collection-v1.json"),
                ),
                (
                    "REB_LOCAL_ANALYST_STORE",
                    support.join("local-analyst-workspace-v1.json"),
                ),
                (
                    "REB_BRAVE_CACHE_ROOT",
                    home()?.join("Library/Caches/Origin Trace/sessions/live"),
                ),
            ],
            sessions_root: support.join("sessions/live"),
            brave: sibling,
        });
    }
    // Checkout: apps/origin-trace-backend/target/<profile>/reb-api.
    for ancestor in directory.ancestors().take(6) {
        let script = ancestor.join("scripts/run-live-session.sh");
        if script.is_file() && ancestor.join("AGENTS.md").is_file() {
            return Ok(Kit {
                script,
                env: Vec::new(),
                sessions_root: ancestor.join("build/sessions/live"),
                brave: None,
            });
        }
    }
    Err("No run-live-session.sh belongs with this reb-api build. Use the reb-api inside Origin Trace.app or a checkout build, or set REB_LIVE_SESSION_SCRIPT.".into())
}

fn private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("Cannot create {}: {error}", path.display()))
}

/// Waits for a launcher that is already exiting, such as after its failure
/// line, so its own cleanup can finish.
fn exited(child: &mut Child, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Stops a launcher that has not reported a ready session. Its own trap stops
/// the browser and every helper it started. If it does not exit, its whole
/// process group, which holds those helpers, is killed.
fn stop(child: &mut Child) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    if exited(child, Duration::from_secs(10)) {
        return;
    }
    unsafe {
        libc::killpg(child.id() as i32, libc::SIGKILL);
    }
    let _ = child.wait();
}

fn failure(log: &str) -> Option<String> {
    log.lines()
        .rev()
        .find_map(|line| line.split_once(FAILURE_LINE).map(|(_, cause)| cause))
        .map(|cause| cause.chars().take(1000).collect())
}

fn ready(log: &str) -> Option<String> {
    log.lines().find_map(|line| {
        let id = line.strip_prefix(READY_LINE)?.trim();
        (!id.is_empty() && id.len() <= 20 && id.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| id.to_owned())
    })
}

/// Waits for `/api/health` to report a live capture with a connected broker,
/// and returns its process-lifetime instance identity.
async fn live_instance(client: &reqwest::Client, endpoint: &str) -> Option<String> {
    let health: Value = client
        .get(format!("{endpoint}/api/health"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    (health["status"] == "ok"
        && health["capture_mode"] == "live"
        && health["broker_connected"] == true)
        .then(|| health["instance_id"].as_str().map(str::to_owned))
        .flatten()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id.bytes().all(|byte| byte.is_ascii_digit() || byte == b':')
        })
}

/// Opens the first page. The ready line can come a moment before the browser
/// holds its profile, so a not-yet-running browser is retried briefly.
/// Returns whether capture recorded anything after the page opened.
async fn open_url(
    client: &reqwest::Client,
    endpoint: &str,
    instance: &str,
    url: &str,
) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let response = client
            .post(format!("{endpoint}/api/session/actions"))
            .header("x-reb-expected-instance", instance)
            .timeout(Duration::from_secs(30))
            .json(&json!({"action": "open_url", "url": url}))
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let body: Value = response.json().await.unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            return Ok(body["capture_observed"] == true);
        }
        if status == 409 && body["code"] == "target_unavailable" && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        }
        return Err(format!(
            "HTTP {status}: {}",
            body["error"]
                .as_str()
                .unwrap_or("the capture browser did not open the URL")
                .chars()
                .take(500)
                .collect::<String>()
        ));
    }
}

pub async fn launch(options: &StartOptions) -> Result<Started, String> {
    options.validate()?;
    let kit = kit()?;
    let home = home()?;
    let nonce = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        std::process::id()
    );
    let agent = home
        .join(".config/origin-trace/agent-sessions")
        .join(&nonce);
    private_directory(&agent)?;
    // An explicit root wins, then the operator's REB_LIVE_SESSION_ROOT, as
    // for make live, then the build's own default.
    let sessions_root = options
        .sessions_root
        .clone()
        .or_else(|| std::env::var_os("REB_LIVE_SESSION_ROOT").map(PathBuf::from))
        .unwrap_or(kit.sessions_root);
    private_directory(&sessions_root)?;
    let log_file = agent.join("launch.log");
    let log = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&log_file)
            .map_err(|error| format!("Cannot create the launch log: {error}"))?
    };
    let active_endpoint = if options.publish_canonical_endpoint {
        home.join(".config/origin-trace/reb-api.endpoint")
    } else {
        agent.join("active.endpoint")
    };
    let brave = options
        .brave_binary
        .clone()
        .or_else(|| std::env::var_os("REB_BRAVE_BINARY").map(PathBuf::from))
        .or(kit.brave);
    let mut command = Command::new("/bin/bash");
    command.arg(&kit.script);
    // The packaged app's embedded handshake and any inherited capture switch
    // must not leak into a session whose options were named explicitly.
    for name in [
        "REB_EMBEDDED_SESSION",
        "REB_SESSION_HANDSHAKE",
        "REB_SESSION_OWNER_PID",
        "REB_BRAVE_PROFILE",
        "REB_NATIVE_WASM_GUEST_ADAPTER",
        "REB_NATIVE_JS_DISPATCH_SITES",
        "REB_BRAVE_BINARY",
    ] {
        command.env_remove(name);
    }
    for (name, path) in &kit.env {
        command.env(name, path);
    }
    let switch = |on: bool| if on { "1" } else { "0" };
    command
        .env("REB_LIVE_SESSION_ROOT", &sessions_root)
        .env("REB_ACTIVE_ENDPOINT_FILE", &active_endpoint)
        .env("REB_NATIVE_WASM_DISPATCH", switch(options.wasm_dispatch))
        .env(
            "REB_NATIVE_WASM_CALL_INDIRECT",
            switch(options.wasm_call_indirect),
        )
        .env("REB_NATIVE_QUIET_MODE", switch(options.quiet))
        .env("REB_CAPTURE_CANVAS_IMAGES", switch(options.canvas_images))
        // Request paths, queries and bodies are sensitive and not a named
        // option, so an inherited switch never turns them on here.
        .env("REB_CAPTURE_REQUEST_CONTENT", "0")
        // Document-start Console scripts run researcher code in new matching
        // documents. The browser-session permission is not a named option, so
        // an inherited switch never grants it to an agent-started capture.
        .env("REB_CONSOLE_DOCUMENT_START", "0")
        .env("REB_LOCALHOST_ONLY", switch(options.localhost_only))
        // An agent cannot answer a macOS Keychain prompt, so agent sessions use
        // a prompt-free isolated profile. Do not save passwords in it.
        .env("REB_USE_SYSTEM_KEYCHAIN", "0")
        .env(
            "REB_CAPTURE_CATEGORY_MASK",
            options.category_mask.unwrap_or(4095).to_string(),
        )
        .env(
            "REB_CAPTURE_DURATION_SECONDS",
            options.duration_seconds.unwrap_or(3600).to_string(),
        );
    if let Some(path) = &options.guest_adapter {
        command.env("REB_NATIVE_WASM_GUEST_ADAPTER", path);
    }
    if let Some(path) = &options.js_dispatch_sites {
        command.env("REB_NATIVE_JS_DISPATCH_SITES", path);
    }
    if let Some(path) = &brave {
        command.env("REB_BRAVE_BINARY", path);
    }
    let output = log
        .try_clone()
        .map_err(|error| format!("Cannot share the launch log: {error}"))?;
    // Everything that can fail is prepared before the launcher starts, so an
    // early error never leaves an unwatched session running.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| error.to_string())?;
    let mut read = std::fs::File::open(&log_file).map_err(|error| error.to_string())?;
    {
        use std::os::unix::process::CommandExt;
        // Its own process group keeps the session alive when the caller's
        // terminal or MCP client sends a signal to its group.
        command.process_group(0);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(log)
        .spawn()
        .map_err(|error| format!("Cannot run {}: {error}", kit.script.display()))?;
    let deadline = Instant::now() + Duration::from_secs(options.timeout());
    let mut bytes = Vec::new();
    let mut ready_id = None;
    let started = loop {
        let _ = read.read_to_end(&mut bytes);
        let text = String::from_utf8_lossy(&bytes);
        if let Some(cause) = failure(&text) {
            // The launcher is already exiting; let its cleanup finish first.
            if !exited(&mut child, Duration::from_secs(15)) {
                stop(&mut child);
            }
            return Err(format!("The live session did not start: {cause}"));
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "The live-session launcher exited ({status}) before capture was ready."
            ));
        }
        if ready_id.is_none() {
            ready_id = ready(&text);
        }
        if let Some(id) = &ready_id {
            let session_dir = sessions_root.join(id);
            let endpoint_file = session_dir.join("research-ui.endpoint");
            if let Ok(endpoint) = std::fs::read_to_string(&endpoint_file) {
                let endpoint = endpoint.trim().to_owned();
                if let Some(instance_id) = live_instance(&client, &endpoint).await {
                    break Started {
                        session_id: id.clone(),
                        session_dir,
                        endpoint,
                        endpoint_file,
                        instance_id,
                        log_file: log_file.clone(),
                        canonical_endpoint: options.publish_canonical_endpoint,
                        url_opened: None,
                        url_error: None,
                        capture_observed: None,
                    };
                }
            }
        }
        if Instant::now() >= deadline {
            stop(&mut child);
            return Err(format!(
                "The live session was not ready within {} seconds and was stopped.",
                options.timeout()
            ));
        }
        tokio::time::sleep(POLL).await;
    };
    // The session outlives this call; reap the launcher when it ends.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    let mut started = started;
    if let Some(url) = &options.url {
        match open_url(&client, &started.endpoint, &started.instance_id, url).await {
            Ok(observed) => {
                started.url_opened = Some(true);
                started.capture_observed = Some(observed);
            }
            Err(error) => {
                started.url_opened = Some(false);
                started.url_error = Some(error);
            }
        }
    }
    Ok(started)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_reject_unsafe_or_incomplete_combinations() {
        let ok =
            StartOptions::from_json(&json!({"url":"https://example.test/","wasm_dispatch":true}));
        assert!(ok.validate().is_ok());
        for (value, message) in [
            (json!({"url":"file:///etc/passwd"}), "HTTP"),
            (
                json!({"url":"https://user:pw@example.test/"}),
                "credentials",
            ),
            (
                json!({"guest_adapter":"/tmp/a.json"}),
                "requires wasm_dispatch",
            ),
            (
                json!({"guest_adapter":"a.json","wasm_dispatch":true}),
                "absolute",
            ),
            (json!({"canvas_images":true}), "confirm_sensitive_capture"),
            (json!({"category_mask":0}), "category_mask"),
            (json!({"duration_seconds":7200}), "duration_seconds"),
        ] {
            let error = StartOptions::from_json(&value).validate().unwrap_err();
            assert!(error.contains(message), "{value}: {error}");
        }
        let effective = StartOptions::from_json(&json!({"quiet":true})).effective();
        assert_eq!(effective["wasm_dispatch"], false);
        assert_eq!(effective["category_mask"], 4095);
        assert_eq!(effective["timeout_seconds"], 180);
        assert!(effective.get("url").is_none());
    }

    #[test]
    fn launcher_output_names_the_session_or_its_failure() {
        let log = "noise\nOrigin Trace live session 1234\nEvidence store: x\n";
        assert_eq!(ready(log).as_deref(), Some("1234"));
        assert_eq!(ready("Origin Trace live session ../x\n"), None);
        assert_eq!(
            failure("a\nREB_LIVE_SESSION_FAILURE: Brave is missing\n").as_deref(),
            Some("Brave is missing")
        );
        assert_eq!(failure(log), None);
    }
}
