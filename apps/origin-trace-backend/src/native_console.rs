use crate::{
    config::Options,
    error::{Error, Result},
    validation, worker,
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};

const MAGIC: u32 = 0x43424552;
const SOURCE_LIMIT: usize = 8192;
const TEXT_LIMIT: usize = 8192;
const TARGET_LIMIT: usize = 64;
const TARGET_SIZE: usize = 920;
const RUNTIME_LIMIT: usize = 65536;

// Own both process groups, including Chromium descendants. kill_on_drop alone
// stops only the immediate process and can leave renderer/profile owners alive.
struct OwnedProcess {
    child: Child,
    group: i32,
}
impl OwnedProcess {
    fn spawn(command: &mut Command) -> Result<Self> {
        let child = command
            .kill_on_drop(true)
            .process_group(0)
            .spawn()
            .map_err(|_| Error::new(503, "Native console process could not start"))?;
        let group = i32::try_from(
            child
                .id()
                .ok_or_else(|| Error::new(503, "Native process ID unavailable"))?,
        )
        .map_err(|_| Error::new(503, "Native process ID is out of range"))?;
        Ok(Self { child, group })
    }
    async fn stop(&mut self) {
        unsafe {
            libc::kill(-self.group, libc::SIGKILL);
        }
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        self.group = 0;
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if self.group > 0 {
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
        }
    }
}

struct Session {
    id: String,
    bridge: OwnedProcess,
    browser: OwnedProcess,
    input: ChildStdin,
    output: ChildStdout,
    _directory: TempDir,
    next_request: u64,
    poisoned: bool,
    started: Instant,
}
impl Session {
    async fn stop(mut self) {
        self.bridge.stop().await;
        self.browser.stop().await;
    }
    async fn exchange(&mut self, operation: u16, target: u64, source: &str) -> Result<Value> {
        // If the HTTP future is cancelled mid-exchange, the session stays
        // poisoned. Never retry an expression or reuse an ambiguous pipe.
        self.poisoned = true;
        let id = self.next_request;
        self.next_request = id
            .checked_add(1)
            .ok_or_else(|| Error::conflict("Native request IDs exhausted"))?;
        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&2u16.to_le_bytes());
        header[6..8].copy_from_slice(&operation.to_le_bytes());
        header[8..16].copy_from_slice(&id.to_le_bytes());
        header[16..24].copy_from_slice(&target.to_le_bytes());
        header[24..28].copy_from_slice(&(source.len() as u32).to_le_bytes());
        let timeout = if id == 1 { 35 } else { 6 };
        let result = tokio::time::timeout(Duration::from_secs(timeout), async {
            self.input.write_all(&header).await?;
            self.input.write_all(source.as_bytes()).await?;
            self.input.flush().await?;
            let mut response = [0u8; 32];
            self.output.read_exact(&mut response).await?;
            let parsed = ResponseHeader::parse(&response, id, operation)?;
            let mut payload = vec![0; parsed.bytes];
            self.output.read_exact(&mut payload).await?;
            let mut value = parsed.value(&payload, &self.id)?;
            if parsed.kind == 11 { value["request_id"] = json!(id.to_string()); }
            Ok(value)
        }).await.map_err(|_| Error::new(408, "Native console timed out; execution may have occurred. Restart the session"))?
          .map_err(|e: Error| Error::new(e.status, if e.status == 500 { "Native browser or console disconnected; rebuild Brave with native console support".to_owned() } else { e.message }))?;
        self.poisoned = false;
        Ok(result)
    }
}

struct ResponseHeader {
    status: u16,
    kind: u16,
    truncated: bool,
    count: usize,
    bytes: usize,
}
impl ResponseHeader {
    fn parse(bytes: &[u8; 32], request: u64, operation: u16) -> Result<Self> {
        let u16_at = |i| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
        let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let parsed = Self {
            status: u16_at(6),
            kind: u16_at(16),
            truncated: u16_at(18) != 0,
            count: u32_at(20) as usize,
            bytes: u32_at(24) as usize,
        };
        if u32_at(0) != MAGIC
            || u16_at(4) != 2
            || u64::from_le_bytes(bytes[8..16].try_into().unwrap()) != request
            || u32_at(28) != 0
            || parsed.status > 6
            || parsed.kind > 11
            || (parsed.kind == 11 && operation != 3)
            || (operation == 3 && parsed.status == 0 && parsed.kind != 11)
            || u16_at(18) > 1
            || (parsed.kind == 10
                && (operation != 1
                    || parsed.status != 0
                    || parsed.count > TARGET_LIMIT
                    || parsed.bytes != parsed.count * TARGET_SIZE))
            || (parsed.kind != 10
                && (parsed.count != 0
                    || parsed.bytes
                        > if parsed.kind == 11 {
                            RUNTIME_LIMIT
                        } else {
                            TEXT_LIMIT
                        }
                    || (operation == 1 && parsed.status == 0)))
        {
            return Err(Error::protocol(
                "Native console returned a malformed record",
            ));
        }
        if operation == 1 && parsed.kind != 10 {
            return Err(Error::conflict(
                "Native document listing failed; restart the session",
            ));
        }
        if parsed.status == 6 || (parsed.status == 5 && parsed.bytes == 0) {
            return Err(Error::conflict(
                "Native session retired; restart it. Execution may have occurred",
            ));
        }
        Ok(parsed)
    }
    fn value(&self, payload: &[u8], session: &str) -> Result<Value> {
        if self.kind == 10 {
            let mut targets = Vec::with_capacity(self.count);
            let mut ids = std::collections::BTreeSet::new();
            for record in payload.as_chunks::<TARGET_SIZE>().0 {
                let id = u64::from_le_bytes(record[..8].try_into().unwrap());
                let size = u16::from_le_bytes(record[8..10].try_into().unwrap()) as usize;
                let flags = u16::from_le_bytes(record[10..12].try_into().unwrap());
                if id == 0
                    || size > 256
                    || flags > 3
                    || record[916..920] != [0; 4]
                    || record[12..16] != [0; 4]
                    || !ids.insert(id)
                {
                    return Err(Error::protocol("Native target listing is malformed"));
                }
                let origin = std::str::from_utf8(&record[16..16 + size])
                    .map_err(|_| Error::protocol("Native origin is not UTF-8"))?;
                let label_size = u16::from_le_bytes(record[272..274].try_into().unwrap()) as usize;
                let url_size = u16::from_le_bytes(record[274..276].try_into().unwrap()) as usize;
                if label_size > 128 || url_size > 512 {
                    return Err(Error::protocol("Native context metadata is oversized"));
                }
                let label = std::str::from_utf8(&record[276..276 + label_size])
                    .map_err(|_| Error::protocol("Native label is not UTF-8"))?;
                let url = std::str::from_utf8(&record[404..404 + url_size])
                    .map_err(|_| Error::protocol("Native URL is not UTF-8"))?;
                targets.push(json!({"id":id.to_string(),"origin":origin,"label":label,"url":url,"main_frame":flags & 2 != 0,"truncated":flags & 1 != 0}));
            }
            return Ok(
                json!({"contract_version":2,"session_id":session,"state":"ready","targets":targets,"truncated":self.truncated}),
            );
        }
        if self.kind == 11 {
            let runtime: Value = serde_json::from_slice(payload)
                .map_err(|_| Error::protocol("Native runtime result is not JSON"))?;
            if !runtime.is_object() || self.status != 0 {
                return Err(Error::protocol("Invalid runtime envelope"));
            }
            return Ok(
                json!({"contract_version":2,"session_id":session,"state":"ready","runtime":runtime}),
            );
        }
        let types = [
            "undefined",
            "null",
            "boolean",
            "number",
            "string",
            "bigint",
            "symbol",
            "function",
            "object",
            "promise",
        ];
        let statuses = [
            "ok",
            "malformed",
            "stale_target",
            "forbidden",
            "exception",
            "timeout",
            "disconnected",
        ];
        let text = std::str::from_utf8(payload)
            .map_err(|_| Error::protocol("Native result is not UTF-8"))?;
        Ok(
            json!({"contract_version":2,"session_id":session,"state":"ready","status":statuses[self.status as usize],
            "type":types[self.kind as usize],"text":text,"truncated":self.truncated}),
        )
    }
}

pub struct NativeConsole {
    helper: PathBuf,
    browser: Option<PathBuf>,
    session: Mutex<Option<Session>>,
}
impl NativeConsole {
    pub fn new(options: &Options) -> Self {
        Self {
            helper: options.worker(
                &options.native_console,
                "OriginTraceNativeConsole",
                "build/reb-console",
            ),
            browser: options.brave_binary.clone(),
            session: Mutex::new(None),
        }
    }
    fn available(&self) -> bool {
        worker::executable(&self.helper)
            && self.browser.as_ref().is_some_and(|p| worker::executable(p))
    }
    pub async fn state(&self) -> Value {
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.as_mut()
            && (session.poisoned
                || session.started.elapsed() >= Duration::from_secs(3600)
                || session.browser.child.try_wait().ok().flatten().is_some()
                || session.bridge.child.try_wait().ok().flatten().is_some())
        {
            guard.take().unwrap().stop().await;
        }
        let id = guard.as_ref().map(|s| s.id.as_str());
        json!({"contract_version":2,"available":self.available(),"state":if id.is_some() {"ready"} else {"idle"},
            "session_id":id,"message":if self.available() {"Native console uses a separate disposable browser profile"} else {"Configure a rebuilt custom Brave executable using REB_BRAVE_BINARY"}})
    }
    pub async fn stop(&self) {
        if let Some(session) = self.session.lock().await.take() {
            session.stop().await;
        }
    }
    pub async fn action(&self, request: &Value) -> Result<Value> {
        let mut guard = self
            .session
            .try_lock()
            .map_err(|_| Error::conflict("Another native console action is running"))?;
        let action = request["action"].as_str().unwrap_or("");
        if action == "start" {
            validation::fields(request, &["action", "url"], "Native console start")?;
            if guard.is_some() {
                return Err(Error::conflict(
                    "Stop the current native session before starting another",
                ));
            }
            if !self.available() {
                return Err(Error::new(
                    503,
                    "Native console requires its bundled helper and a rebuilt custom Brave executable",
                ));
            }
            let address = validation::text(&request["url"], "Console URL", 4096, false, false)?;
            let url =
                url::Url::parse(address).map_err(|_| Error::bad("Provide an HTTP or HTTPS URL"))?;
            if !["http", "https"].contains(&url.scheme())
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err(Error::bad(
                    "Console URL must use HTTP or HTTPS without embedded credentials",
                ));
            }
            let mut session = self.launch(url.as_str()).await?;
            let result = session.exchange(1, 0, "").await;
            if result.is_ok() {
                *guard = Some(session);
            } else {
                session.stop().await;
            }
            return result;
        }
        if action != "start" && !(action == "stop" && request["session_id"].is_null()) {
            validation::canonical(&request["session_id"], 64, true, "Console session")?;
        }
        if action == "stop" {
            validation::fields(request, &["action", "session_id"], "Native console stop")?;
            if let Some(session) = guard.as_ref()
                && request["session_id"] != session.id
            {
                return Err(Error::conflict("Native console session changed"));
            }
            if let Some(session) = guard.take() {
                session.stop().await;
            }
            return Ok(json!({"contract_version":2,"state":"idle","session_id":null}));
        }
        let allowed = if action == "targets" {
            vec!["action", "session_id"]
        } else if action == "runtime" {
            vec!["action", "session_id", "target_id", "command"]
        } else if action == "evaluate" {
            vec!["action", "session_id", "target_id", "source"]
        } else {
            return Err(Error::bad("Native console action is invalid"));
        };
        validation::fields(request, &allowed, "Native console action")?;
        let session = guard
            .as_mut()
            .ok_or_else(|| Error::conflict("Start a native console session first"))?;
        if request["session_id"] != session.id {
            return Err(Error::conflict("Native console session changed"));
        }
        if session.poisoned
            || session.started.elapsed() >= Duration::from_secs(3600)
            || session.browser.child.try_wait()?.is_some()
        {
            guard.take().unwrap().stop().await;
            return Err(Error::conflict(
                "Native console session ended; start another session",
            ));
        }
        let runtime_source;
        let (operation, target, source) = if action == "targets" {
            (1, 0, "")
        } else if action == "runtime" {
            validate_command(&request["command"])?;
            runtime_source = serde_json::to_string(&request["command"])?;
            if runtime_source.len() > RUNTIME_LIMIT {
                return Err(Error::bad("Runtime command exceeds 65536 bytes"));
            }
            (
                3,
                validation::canonical(&request["target_id"], 64, true, "Console target")?,
                runtime_source.as_str(),
            )
        } else {
            let source =
                validation::text(&request["source"], "JavaScript", SOURCE_LIMIT, false, true)?;
            if source.is_empty() || source.contains('\0') {
                return Err(Error::bad(
                    "JavaScript must be nonempty and contain no NUL bytes",
                ));
            }
            let target = validation::canonical(&request["target_id"], 64, true, "Console target")?;
            (2, target, source)
        };
        let result = session.exchange(operation, target, source).await;
        if result.is_err() {
            guard.take().unwrap().stop().await;
        }
        result
    }
    async fn launch(&self, address: &str) -> Result<Session> {
        let directory = tempfile::Builder::new()
            .prefix("reb-console.")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let mut random = [0u8; 40];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token = directory.path().join("token");
        let mut token_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token)?;
        token_file.write_all(format!("{}\n", hex::encode(&random[..32])).as_bytes())?;
        let id = u64::from_le_bytes(random[32..].try_into().unwrap())
            .max(1)
            .to_string();
        let socket = directory.path().join("console.sock");
        let mut helper = Command::new(&self.helper);
        helper
            .args(["--bridge", "--socket"])
            .arg(&socket)
            .arg("--token-file")
            .arg(&token)
            .arg("--session")
            .arg(&id)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut bridge = OwnedProcess::spawn(&mut helper)?;
        let input = bridge
            .child
            .stdin
            .take()
            .ok_or_else(|| Error::new(503, "Native console input unavailable"))?;
        let output = bridge
            .child
            .stdout
            .take()
            .ok_or_else(|| Error::new(503, "Native console output unavailable"))?;
        let mut browser = Command::new(self.browser.as_ref().unwrap());
        browser
            .arg(format!(
                "--user-data-dir={}",
                directory.path().join("profile").display()
            ))
            .args([
                "--no-first-run",
                "--no-default-browser-check",
                "--password-store=basic",
                "--use-mock-keychain",
                "--reb-native-console",
            ])
            .arg(format!("--reb-native-console-socket={}", socket.display()))
            .arg(format!(
                "--reb-native-console-token-file={}",
                token.display()
            ))
            .arg(format!("--reb-native-console-session-id={id}"))
            .arg(address)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let browser = OwnedProcess::spawn(&mut browser)?;
        Ok(Session {
            id,
            bridge,
            browser,
            input,
            output,
            _directory: directory,
            next_request: 1,
            poisoned: false,
            started: Instant::now(),
        })
    }
}

// Runtime inspection commands have exact fields. Source is only accepted by
// explicit evaluation; completion never receives an executable expression.
fn validate_command(command: &Value) -> Result<()> {
    let operation = command["operation"].as_str().unwrap_or("");
    let fields: &[&str] = match operation {
        "evaluate" => &["operation", "source"],
        "inspect" => &["operation", "handle", "offset"],
        "complete" => &["operation", "path", "prefix"],
        "await" | "release" | "store" | "cancel" | "source" | "listeners" | "monitor"
        | "unmonitor" => &["operation", "handle"],
        "poll" | "clear" | "last" | "traffic" => &["operation"],
        _ => return Err(Error::bad("Invalid runtime operation")),
    };
    validation::fields(command, fields, "Runtime command")?;
    if operation == "evaluate" {
        let source = validation::text(&command["source"], "JavaScript", SOURCE_LIMIT, false, true)?;
        if source.is_empty() || source.contains('\0') {
            return Err(Error::bad("JavaScript must be nonempty without NUL"));
        }
    }
    if fields.contains(&"handle") {
        validation::canonical(&command["handle"], 64, true, "Value handle")?;
    }
    if operation == "inspect" && !command["offset"].as_u64().is_some_and(|n| n <= 65536) {
        return Err(Error::bad("Property offset must be 0 to 65536"));
    }
    if operation == "complete" {
        let path = command["path"]
            .as_array()
            .ok_or_else(|| Error::bad("Completion path must be an array"))?;
        if path.len() > 8 {
            return Err(Error::bad("Completion path has more than 8 components"));
        }
        for key in path {
            validation::text(key, "Completion component", 128, false, false)?;
        }
        validation::text(&command["prefix"], "Completion prefix", 128, true, false)?;
    }
    Ok(())
}
