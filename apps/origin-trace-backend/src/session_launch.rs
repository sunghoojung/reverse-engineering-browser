//! Starts a live capture session for `reb-api session start` and the MCP
//! `start_live_session` tool. It runs the same launcher as `make live` and the
//! packaged app, detached from the caller, with named capture options in place
//! of environment variables. Every capture switch is off unless requested, so
//! a session never inherits a switch from the caller's shell.
use crate::js_invocation_sites;
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
    /// At most this many retained samples of each function, on each stream.
    pub wasm_samples_per_function: Option<u32>,
    /// At most this many retained call_indirect samples of each call site.
    pub wasm_samples_per_indirect_site: Option<u32>,
    /// Function indexes to admit. Empty admits every function not denied.
    pub wasm_function_allow: Vec<u32>,
    /// Function indexes to exclude. A denied index is excluded even if allowed.
    pub wasm_function_deny: Vec<u32>,
    /// Lowercase SHA-256 digests. Empty admits every module.
    pub wasm_module_allowlist: Vec<String>,
    /// Set when a budget field was present but not the documented shape.
    pub wasm_budget_malformed: bool,
    pub guest_adapter: Option<PathBuf>,
    pub js_dispatch_sites: Option<PathBuf>,
    pub quiet: bool,
    pub category_mask: Option<u32>,
    pub duration_seconds: Option<u32>,
    pub localhost_only: bool,
    pub canvas_images: bool,
    /// Retain request paths, queries and bounded bodies, request and response
    /// headers including Cookie, Set-Cookie and Authorization, each request's
    /// cookies, and response bodies. Sensitive.
    pub request_content: bool,
    /// MiB of unique request bodies and targets a content session retains.
    pub request_content_budget_mib: Option<u32>,
    /// Record the JavaScript and Wasm stack that started each renderer request.
    pub request_stacks: bool,
    /// Permit document-start Console scripts in this capture browser. Arming
    /// one stays a separate confirmed Console action.
    pub document_start: bool,
    /// A site file the agent wrote, armed from a private copy.
    pub js_invocation_sites: Option<PathBuf>,
    /// The agent's own saved site set, never the researcher's.
    pub js_invocation_saved_sites: bool,
    /// Hash settled values of armed calls. Sensitive; needs sites.
    pub js_invocation_digests: bool,
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
        let mut wasm_budget_malformed = false;
        let cap = |key: &str, malformed: &mut bool| match &value[key] {
            Value::Null => None,
            Value::Number(number) => match number.as_u64() {
                Some(number) if number <= u64::from(u32::MAX) => Some(number as u32),
                _ => {
                    *malformed = true;
                    None
                }
            },
            _ => {
                *malformed = true;
                None
            }
        };
        let indexes = |key: &str, malformed: &mut bool| match &value[key] {
            Value::Null => Vec::new(),
            Value::Array(items) => items
                .iter()
                .filter_map(|item| match item.as_u64() {
                    Some(number) if number < 16_777_216 => Some(number as u32),
                    _ => {
                        *malformed = true;
                        None
                    }
                })
                .collect(),
            _ => {
                *malformed = true;
                Vec::new()
            }
        };
        let digests = |key: &str, malformed: &mut bool| match &value[key] {
            Value::Null => Vec::new(),
            Value::Array(items) => items
                .iter()
                .map(|item| match item.as_str() {
                    Some(text)
                        if text.len() == 64
                            && text.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                    {
                        text.to_ascii_lowercase()
                    }
                    _ => {
                        *malformed = true;
                        String::new()
                    }
                })
                .collect(),
            _ => {
                *malformed = true;
                Vec::new()
            }
        };
        Self {
            url: value["url"].as_str().map(str::to_owned),
            wasm_dispatch: flag("wasm_dispatch"),
            wasm_call_indirect: flag("wasm_call_indirect"),
            wasm_samples_per_function: cap("wasm_samples_per_function", &mut wasm_budget_malformed),
            wasm_samples_per_indirect_site: cap(
                "wasm_samples_per_indirect_site",
                &mut wasm_budget_malformed,
            ),
            wasm_function_allow: indexes("wasm_function_allow", &mut wasm_budget_malformed),
            wasm_function_deny: indexes("wasm_function_deny", &mut wasm_budget_malformed),
            wasm_module_allowlist: digests("wasm_module_allowlist", &mut wasm_budget_malformed),
            wasm_budget_malformed,
            guest_adapter: path("guest_adapter"),
            js_dispatch_sites: path("js_dispatch_sites"),
            quiet: flag("quiet"),
            category_mask: value["category_mask"].as_u64().map(|n| n as u32),
            duration_seconds: value["duration_seconds"].as_u64().map(|n| n as u32),
            localhost_only: flag("localhost_only"),
            canvas_images: flag("canvas_images"),
            request_content: flag("request_content"),
            request_content_budget_mib: value["request_content_budget_mib"]
                .as_u64()
                .map(|n| n.min(u64::from(u32::MAX)) as u32),
            request_stacks: flag("request_stacks"),
            document_start: flag("document_start"),
            js_invocation_sites: path("js_invocation_sites"),
            js_invocation_saved_sites: flag("js_invocation_saved_sites"),
            js_invocation_digests: flag("js_invocation_digests"),
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
            ("js_invocation_sites", &self.js_invocation_sites),
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
        if self.wasm_budget_malformed {
            return Err("Wasm sample budget options must be integers, function indexes below 16777216, and 64-character hex module digests".into());
        }
        let wasm_budget = self.wasm_samples_per_function.is_some()
            || self.wasm_samples_per_indirect_site.is_some()
            || !self.wasm_function_allow.is_empty()
            || !self.wasm_function_deny.is_empty()
            || !self.wasm_module_allowlist.is_empty();
        if wasm_budget && !(self.wasm_dispatch || self.wasm_call_indirect) {
            return Err(
                "Wasm sample budget options require wasm_dispatch or wasm_call_indirect".into(),
            );
        }
        if self
            .wasm_samples_per_function
            .is_some_and(|limit| !(1..=16).contains(&limit))
        {
            return Err("wasm_samples_per_function must be from 1 to 16".into());
        }
        if self
            .wasm_samples_per_indirect_site
            .is_some_and(|limit| !(1..=16).contains(&limit))
        {
            return Err("wasm_samples_per_indirect_site must be from 1 to 16".into());
        }
        for (name, indexes) in [
            ("wasm_function_allow", &self.wasm_function_allow),
            ("wasm_function_deny", &self.wasm_function_deny),
        ] {
            if indexes.len() > 32 || indexes.iter().any(|index| *index >= 16_777_216) {
                return Err(format!(
                    "{name} accepts at most 32 function indexes, each below 16777216"
                ));
            }
            if indexes.len()
                != indexes
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            {
                return Err(format!("{name} indexes must be unique"));
            }
        }
        let digests = self
            .wasm_module_allowlist
            .iter()
            .map(|digest| digest.to_ascii_lowercase())
            .collect::<Vec<_>>();
        if digests.len() > 8
            || digests.iter().any(|digest| {
                digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
            || digests.len()
                != digests
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
        {
            return Err(
                "wasm_module_allowlist accepts at most 8 unique 64-character hex digests".into(),
            );
        }
        if self.canvas_images && !self.confirm_sensitive_capture {
            return Err(
                "canvas_images stores page content and requires confirm_sensitive_capture".into(),
            );
        }
        if self.request_content && !self.confirm_sensitive_capture {
            return Err("request_content retains request paths, queries and bodies, headers including Cookie, Set-Cookie and Authorization, each request's cookies, and response bodies, and requires confirm_sensitive_capture".into());
        }
        if let Some(budget) = self.request_content_budget_mib {
            if !self.request_content {
                return Err("request_content_budget_mib requires request_content".into());
            }
            if !(1..=4096).contains(&budget) {
                return Err("request_content_budget_mib must be from 1 to 4096".into());
            }
        }
        if self.js_invocation_sites.is_some() && self.js_invocation_saved_sites {
            return Err("Name js_invocation_sites or js_invocation_saved_sites, not both".into());
        }
        let invocation = self.js_invocation_sites.is_some() || self.js_invocation_saved_sites;
        if self.js_invocation_digests && !invocation {
            return Err(
                "js_invocation_digests requires js_invocation_sites or js_invocation_saved_sites"
                    .into(),
            );
        }
        if self.js_invocation_digests && !self.confirm_sensitive_capture {
            return Err("js_invocation_digests hashes settled call values and requires confirm_sensitive_capture".into());
        }
        if self
            .category_mask
            .is_some_and(|mask| !(1..=4095).contains(&mask))
        {
            return Err("category_mask must be between 1 and 4095".into());
        }
        // The launcher refuses the same masks; naming the option here says
        // which one to change.
        let mask = self.category_mask.unwrap_or(4095);
        if self.request_content && mask & 1280 != 1280 {
            return Err("request_content needs Network and Artifact category bits (256 and 1024) in category_mask".into());
        }
        if self.request_stacks && mask & 1280 != 1280 {
            return Err("request_stacks needs Network and Artifact category bits (256 and 1024) in category_mask".into());
        }
        if invocation && mask & 512 == 0 {
            return Err(
                "JavaScript invocation sites need the VM category bit (512) in category_mask"
                    .into(),
            );
        }
        if wasm_budget && mask & (512 | 1024) != (512 | 1024) {
            return Err("Wasm sample budget options need the VM and Artifact category bits (512 and 1024) in category_mask".into());
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
            "wasm_samples_per_function": self.wasm_samples_per_function,
            "wasm_samples_per_indirect_site": self.wasm_samples_per_indirect_site,
            "wasm_function_allow": self.wasm_function_allow,
            "wasm_function_deny": self.wasm_function_deny,
            "wasm_module_allowlist": self.wasm_module_allowlist,
            "quiet": self.quiet,
            "category_mask": self.category_mask.unwrap_or(4095),
            "duration_seconds": self.duration_seconds.unwrap_or(3600),
            "localhost_only": self.localhost_only,
            "canvas_images": self.canvas_images,
            "request_content": self.request_content,
            "request_content_budget_mib": self.request_content.then(|| self.request_content_budget_mib.unwrap_or(256)),
            "request_stacks": self.request_stacks,
            "document_start": self.document_start,
            "js_invocation_saved_sites": self.js_invocation_saved_sites,
            "js_invocation_digests": self.js_invocation_digests,
            "publish_canonical_endpoint": self.publish_canonical_endpoint,
            "timeout_seconds": self.timeout(),
        });
        for (key, path) in [
            ("guest_adapter", &self.guest_adapter),
            ("js_dispatch_sites", &self.js_dispatch_sites),
            ("js_invocation_sites", &self.js_invocation_sites),
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
    /// How many invocation sites this session armed, when it armed any.
    pub js_invocation_sites_armed: Option<usize>,
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
        if let Some(count) = self.js_invocation_sites_armed {
            value["js_invocation_sites_armed"] = json!(count);
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

/// Launcher refusals name its environment switches. An agent sets named
/// options instead, so the switch's option is named beside the cause.
fn with_option_names(cause: &str) -> String {
    let names = [
        ("REB_CAPTURE_REQUEST_CONTENT", "request_content"),
        (
            "REB_REQUEST_CONTENT_BUDGET_MIB",
            "request_content_budget_mib",
        ),
        ("REB_NATIVE_REQUEST_STACKS", "request_stacks"),
        ("REB_CONSOLE_DOCUMENT_START", "document_start"),
        (
            "REB_NATIVE_JS_INVOCATION_SITES",
            "js_invocation_sites or js_invocation_saved_sites",
        ),
        ("REB_NATIVE_JS_INVOCATION_DIGESTS", "js_invocation_digests"),
        ("REB_NATIVE_JS_DISPATCH_SITES", "js_dispatch_sites"),
        ("REB_NATIVE_WASM_GUEST_ADAPTER", "guest_adapter"),
        ("REB_NATIVE_WASM_DISPATCH", "wasm_dispatch"),
        ("REB_NATIVE_WASM_CALL_INDIRECT", "wasm_call_indirect"),
        (
            "REB_NATIVE_WASM_SAMPLES_PER_FUNCTION",
            "wasm_samples_per_function",
        ),
        (
            "REB_NATIVE_WASM_SAMPLES_PER_INDIRECT_SITE",
            "wasm_samples_per_indirect_site",
        ),
        ("REB_NATIVE_WASM_FUNCTION_ALLOW", "wasm_function_allow"),
        ("REB_NATIVE_WASM_FUNCTION_DENY", "wasm_function_deny"),
        ("REB_NATIVE_WASM_MODULE_ALLOWLIST", "wasm_module_allowlist"),
        ("REB_NATIVE_QUIET_MODE", "quiet"),
        ("REB_CAPTURE_CANVAS_IMAGES", "canvas_images"),
        ("REB_CAPTURE_CATEGORY_MASK", "category_mask"),
        ("REB_BRAVE_BINARY", "brave_binary"),
    ];
    let named = names
        .iter()
        .filter(|(switch, _)| {
            cause.match_indices(switch).any(|(at, _)| {
                !cause[at + switch.len()..]
                    .starts_with(|c: char| c == '_' || c.is_ascii_uppercase())
            })
        })
        .map(|(switch, option)| format!("{switch} is the option {option}"))
        .collect::<Vec<_>>();
    if named.is_empty() {
        cause.to_owned()
    } else {
        format!("{cause} (For this start: {}.)", named.join("; "))
    }
}

/// The agent's saved invocation sites, shared by the sessions agents start
/// under this HOME and never the app's own set. Sites saved with
/// `js_invocation_site_action` in one agent session arm the next one started
/// with `js_invocation_saved_sites`.
pub fn agent_site_store(home: &Path) -> PathBuf {
    home.join(".config/origin-trace/agent-sessions/js-invocation-sites-v1.json")
}

/// One lowercase digest per line. Brave reads this file; an empty list is not
/// written, which leaves every module admissible.
fn wasm_module_allowlist_file(
    options: &StartOptions,
    agent: &Path,
) -> Result<Option<PathBuf>, String> {
    if options.wasm_module_allowlist.is_empty() {
        return Ok(None);
    }
    let path = agent.join("wasm-module-allowlist");
    let text = options
        .wasm_module_allowlist
        .iter()
        .map(|digest| format!("{}\n", digest.to_ascii_lowercase()))
        .collect::<String>();
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(text.as_bytes())
        })
        .map_err(|error| format!("Cannot write the Wasm module allowlist: {error}"))?;
    Ok(Some(path))
}

/// The site file this session arms, as a private copy nothing changes while
/// it runs: the browser rereads the file it was given and refuses a session
/// whose file changed. Returns the copy and how many sites it names.
fn invocation_sites(
    options: &StartOptions,
    home: &Path,
    agent: &Path,
) -> Result<Option<(PathBuf, usize)>, String> {
    let sites = if options.js_invocation_saved_sites {
        let store = agent_site_store(home);
        let saved = js_invocation_sites::Store::new(store)
            .load()
            .map_err(|error| {
                format!(
                    "The agent's saved invocation sites cannot be read: {}",
                    error.message
                )
            })?;
        if saved.is_empty() {
            return Err("js_invocation_saved_sites names the agent's saved set, which is empty. In an agent session, resolve a function with resolve_js_invocation_site and save it with js_invocation_site_action add; it arms in the next session started with js_invocation_saved_sites.".into());
        }
        saved.into_iter().map(|saved| saved.site).collect()
    } else if let Some(path) = &options.js_invocation_sites {
        let bytes = std::fs::read(path)
            .map_err(|error| format!("js_invocation_sites cannot be read: {error}"))?;
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(js_invocation_sites::parse_sites_file)
            .ok_or("js_invocation_sites is not a native-js-invocation-sites-v1 file: canonical JSON naming 1 to 8 distinct function-entry sites in at most 4096 bytes. resolve_js_invocation_site returns exact site entries.")?
    } else {
        return Ok(None);
    };
    let text = js_invocation_sites::sites_file(&sites)
        .map_err(|_| "The invocation site set cannot be written as a site file")?;
    let copy = agent.join("js-invocation-sites.json");
    crate::durable::write_private(&copy, text.as_bytes()).map_err(|error| {
        format!(
            "Cannot write the session's invocation site file: {}",
            error.message
        )
    })?;
    Ok(Some((copy, sites.len())))
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
    let armed_sites = invocation_sites(options, &home, &agent).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&agent);
    })?;
    let module_allowlist = wasm_module_allowlist_file(options, &agent).inspect_err(|_| {
        let _ = std::fs::remove_dir_all(&agent);
    })?;
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
    {
        // The named options lead the log, so what this session was asked for
        // is visible beside what the launcher reports it passed to Brave.
        use std::io::Write;
        let mut named = options.effective();
        if let Some((_, count)) = &armed_sites {
            named["js_invocation_site_count"] = json!(count);
        }
        writeln!(&log, "Agent session options: {named}")
            .map_err(|error| format!("Cannot write the launch log: {error}"))?;
    }
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
        "REB_NATIVE_WASM_SAMPLES_PER_FUNCTION",
        "REB_NATIVE_WASM_SAMPLES_PER_INDIRECT_SITE",
        "REB_NATIVE_WASM_FUNCTION_ALLOW",
        "REB_NATIVE_WASM_FUNCTION_DENY",
        "REB_NATIVE_WASM_MODULE_ALLOWLIST",
        "REB_NATIVE_JS_DISPATCH_SITES",
        "REB_REQUEST_CONTENT_BUDGET_MIB",
        "REB_RESPONSE_BODY_BUDGET_MIB",
        "REB_CAPTURE_RESPONSE_MEDIA",
        // Invocation sites arm only from a named option, never from the
        // researcher's file or saved set. A named set is strict: a Brave
        // without invocation capture refuses the start instead of dropping it.
        "REB_NATIVE_JS_INVOCATION_SITES",
        "REB_NATIVE_JS_INVOCATION_IF_SUPPORTED",
        "REB_NATIVE_REQUEST_STACKS",
        "REB_NATIVE_REQUEST_STACKS_IF_SUPPORTED",
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
        // The app's saved invocation sites arm its next capture, so agent
        // sessions keep their own saved set and never change the researcher's.
        .env("REB_JS_INVOCATION_SITE_STORE", agent_site_store(&home))
        .env("REB_NATIVE_WASM_DISPATCH", switch(options.wasm_dispatch))
        .env(
            "REB_NATIVE_WASM_CALL_INDIRECT",
            switch(options.wasm_call_indirect),
        )
        .env("REB_NATIVE_QUIET_MODE", switch(options.quiet))
        .env("REB_CAPTURE_CANVAS_IMAGES", switch(options.canvas_images))
        // Request paths, queries and bodies are sensitive: on only when the
        // start names request_content, never from an inherited switch.
        .env(
            "REB_CAPTURE_REQUEST_CONTENT",
            switch(options.request_content),
        )
        // Strict, like named invocation sites: a Brave without the flag refuses.
        .env("REB_NATIVE_REQUEST_STACKS", switch(options.request_stacks))
        // Browser-internal and extension evidence are debugging opt-ins, never inherited.
        .env("REB_CAPTURE_BROWSER_INTERNAL", "0")
        .env("REB_CAPTURE_EXTENSION_TRAFFIC", "0")
        // Document-start Console scripts run code in new matching documents.
        // The browser-session permission comes only from document_start, never
        // from an inherited switch, and it arms nothing by itself.
        .env("REB_CONSOLE_DOCUMENT_START", switch(options.document_start))
        // Settled-value digests are sensitive capture and need named sites.
        .env(
            "REB_NATIVE_JS_INVOCATION_DIGESTS",
            switch(options.js_invocation_digests),
        )
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
    if let Some(budget) = options.request_content_budget_mib {
        command.env("REB_REQUEST_CONTENT_BUDGET_MIB", budget.to_string());
    }
    if let Some(path) = &options.guest_adapter {
        command.env("REB_NATIVE_WASM_GUEST_ADAPTER", path);
    }
    if let Some(limit) = options.wasm_samples_per_function {
        command.env("REB_NATIVE_WASM_SAMPLES_PER_FUNCTION", limit.to_string());
    }
    if let Some(limit) = options.wasm_samples_per_indirect_site {
        command.env(
            "REB_NATIVE_WASM_SAMPLES_PER_INDIRECT_SITE",
            limit.to_string(),
        );
    }
    if !options.wasm_function_allow.is_empty() {
        command.env(
            "REB_NATIVE_WASM_FUNCTION_ALLOW",
            options
                .wasm_function_allow
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if !options.wasm_function_deny.is_empty() {
        command.env(
            "REB_NATIVE_WASM_FUNCTION_DENY",
            options
                .wasm_function_deny
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(path) = &module_allowlist {
        command.env("REB_NATIVE_WASM_MODULE_ALLOWLIST", path);
    }
    if let Some(path) = &options.js_dispatch_sites {
        command.env("REB_NATIVE_JS_DISPATCH_SITES", path);
    }
    if let Some((path, _)) = &armed_sites {
        command.env("REB_NATIVE_JS_INVOCATION_SITES", path);
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
            return Err(format!(
                "The live session did not start: {}",
                with_option_names(&cause)
            ));
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
                        js_invocation_sites_armed: armed_sites.as_ref().map(|(_, count)| *count),
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
            (json!({"request_content":true}), "confirm_sensitive_capture"),
            (
                json!({"request_content":true,"confirm_sensitive_capture":true,"category_mask":1024}),
                "256 and 1024",
            ),
            (
                json!({"request_content_budget_mib":64}),
                "requires request_content",
            ),
            (
                json!({"request_content":true,"confirm_sensitive_capture":true,"request_content_budget_mib":4097}),
                "from 1 to 4096",
            ),
            (
                json!({"request_stacks":true,"category_mask":256}),
                "request_stacks needs Network and Artifact",
            ),
            (
                json!({"js_invocation_saved_sites":true,"category_mask":1024}),
                "VM category",
            ),
            (
                json!({"js_invocation_digests":true,"confirm_sensitive_capture":true}),
                "requires js_invocation_sites",
            ),
            (
                json!({"js_invocation_digests":true,"js_invocation_saved_sites":true}),
                "confirm_sensitive_capture",
            ),
            (
                json!({"js_invocation_sites":"/tmp/s.json","js_invocation_saved_sites":true}),
                "not both",
            ),
            (json!({"js_invocation_sites":"s.json"}), "absolute"),
            (
                json!({"wasm_samples_per_function":2}),
                "require wasm_dispatch",
            ),
            (
                json!({"wasm_samples_per_function":0,"wasm_dispatch":true}),
                "from 1 to 16",
            ),
            (
                json!({"wasm_function_allow":[1,1],"wasm_dispatch":true}),
                "unique",
            ),
            (
                json!({"wasm_function_allow":[16777216],"wasm_dispatch":true}),
                "16777216",
            ),
            (
                json!({"wasm_module_allowlist":["abcd"],"wasm_call_indirect":true}),
                "64-character",
            ),
            (
                json!({"wasm_samples_per_function":2,"wasm_dispatch":true,"category_mask":512}),
                "Artifact category",
            ),
        ] {
            let error = StartOptions::from_json(&value).validate().unwrap_err();
            assert!(error.contains(message), "{value}: {error}");
        }
        let effective = StartOptions::from_json(&json!({"quiet":true})).effective();
        assert_eq!(effective["wasm_dispatch"], false);
        assert!(effective["wasm_samples_per_function"].is_null());
        assert!(effective["wasm_samples_per_indirect_site"].is_null());
        assert_eq!(effective["wasm_function_allow"], json!([]));
        assert_eq!(effective["wasm_function_deny"], json!([]));
        assert_eq!(effective["wasm_module_allowlist"], json!([]));
        assert_eq!(effective["category_mask"], 4095);
        assert_eq!(effective["timeout_seconds"], 180);
        assert!(effective["request_content_budget_mib"].is_null());
        assert!(effective.get("url").is_none());
        // Every switch an agent can name is shown, off unless named.
        for key in [
            "request_content",
            "request_stacks",
            "document_start",
            "js_invocation_saved_sites",
            "js_invocation_digests",
        ] {
            assert_eq!(effective[key], false, "{key}");
        }
        let content = |extra: Value| {
            let mut value = json!({"request_content":true,"confirm_sensitive_capture":true});
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let options = StartOptions::from_json(&value);
            assert!(options.validate().is_ok(), "{value}");
            options.effective()["request_content_budget_mib"].clone()
        };
        assert_eq!(content(json!({})), 256, "the launcher default is shown");
        assert_eq!(content(json!({"request_content_budget_mib":64})), 64);
        let named = StartOptions::from_json(&json!({"document_start":true,
            "js_invocation_sites":"/tmp/s.json","js_invocation_digests":true,
            "confirm_sensitive_capture":true}));
        assert!(named.validate().is_ok());
        let effective = named.effective();
        assert_eq!(effective["document_start"], true);
        assert_eq!(effective["js_invocation_sites"], "/tmp/s.json");
        assert_eq!(effective["js_invocation_digests"], true);
        let budget = StartOptions::from_json(&json!({
            "wasm_dispatch": true,
            "wasm_samples_per_function": 2,
            "wasm_function_allow": [1, 2],
            "wasm_module_allowlist": ["AA"],
        }));
        assert!(budget.validate().is_err());
        let digest = "ab".repeat(32);
        let budget = StartOptions::from_json(&json!({
            "wasm_call_indirect": true,
            "wasm_samples_per_indirect_site": 1,
            "wasm_function_deny": [4],
            "wasm_module_allowlist": [digest],
        }));
        assert!(
            budget.validate().is_ok(),
            "{}",
            budget.validate().unwrap_err()
        );
        let effective = budget.effective();
        assert_eq!(effective["wasm_samples_per_indirect_site"], 1);
        assert_eq!(effective["wasm_function_deny"], json!([4]));
        assert_eq!(effective["wasm_module_allowlist"][0], digest);
    }

    #[test]
    fn launcher_refusals_name_the_option_to_change() {
        let cause = "Brave does not define --reb-js-invocation-capture (from REB_NATIVE_JS_INVOCATION_SITES); turn it off with unset REB_NATIVE_JS_INVOCATION_SITES.";
        let named = with_option_names(cause);
        assert!(named.starts_with(cause));
        assert!(named.ends_with(
            "(For this start: REB_NATIVE_JS_INVOCATION_SITES is the option js_invocation_sites or js_invocation_saved_sites.)"
        ));
        // A longer switch that starts with a known one is not mistaken for it.
        assert_eq!(
            with_option_names("REB_NATIVE_WASM_DISPATCH_EXTRA is unknown"),
            "REB_NATIVE_WASM_DISPATCH_EXTRA is unknown"
        );
        assert_eq!(with_option_names("Brave is missing"), "Brave is missing");
        assert!(
            with_option_names("turn that capture off with REB_NATIVE_REQUEST_STACKS=0.").ends_with(
                "(For this start: REB_NATIVE_REQUEST_STACKS is the option request_stacks.)"
            )
        );
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
