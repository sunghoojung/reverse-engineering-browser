use crate::{
    config::Options,
    error::{Cause, Code, Error, Reason, Result},
    validation, worker,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::CString,
    io::{Read, Write},
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
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
const DOCUMENT_START_SCRIPT_LIMIT: usize = 4;
const DOCUMENT_START_SOURCE_LIMIT: usize = 4096;
const DOCUMENT_START_TOTAL_SOURCE_LIMIT: usize = 8192;
const DOCUMENT_START_RULE_LIMIT: usize = 256;

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
            .map_err(|_| {
                Error::new(503, "Native console process could not start")
                    .with_code(Code::DependencyUnavailable)
            })?;
        let group = i32::try_from(
            child
                .id()
                .ok_or_else(|| Error::new(503, "Native process ID unavailable"))?,
        )
        .map_err(|_| Error::new(503, "Native process ID is out of range"))?;
        Ok(Self { child, group })
    }
    async fn stop(&mut self) {
        if self.group > 0 {
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
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

enum ConsoleDir {
    Disposable(TempDir),
    // Only the short transport directory is owned here. The capture keeps its
    // binding file and evidence directory when this console is retired.
    Live(TempDir),
}

struct Session {
    id: String,
    // Public nonsecret generation, separate from the private authentication token.
    binding_id: String,
    bridge: OwnedProcess,
    // None when this bridge is bound to the capture browser. Stop must not kill it.
    browser: Option<OwnedProcess>,
    input: ChildStdin,
    output: ChildStdout,
    directory: ConsoleDir,
    next_request: u64,
    poisoned: bool,
    started: Instant,
    live: bool,
    live_target: Option<u64>,
    native_targets: BTreeSet<u64>,
    accessed_targets: BTreeSet<u64>,
    // The browser advertises document-start support on its target listing. An
    // older browser leaves it clear, so operation 4 is never sent to a browser
    // that would reject it and retire this working session.
    document_start: bool,
    // The browser may hold an armed set. Raised before an arm is sent, because
    // an ambiguous failure can still have armed it, and lowered only by a
    // browser reply that lists no script. A live binding outlives each Console
    // connection, so Stop must not hand it back while this is set.
    document_start_armed: bool,
}
impl Session {
    async fn stop(mut self) {
        match &self.directory {
            ConsoleDir::Disposable(directory) => {
                let _ = directory.path();
            }
            ConsoleDir::Live(directory) => {
                let _ = directory.path();
            }
        }
        self.bridge.stop().await;
        if let Some(browser) = self.browser.as_mut() {
            browser.stop().await;
        }
    }
    async fn list_live(&mut self) -> Result<Value> {
        // The authenticated capture browser is the only document authority.
        // URLs, titles and debugger target IDs are never execution identities.
        let mut listing = self.exchange(1, 0, "").await?;
        self.native_targets = listing["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|target| target["id"].as_str()?.parse().ok())
            .collect();
        if self
            .live_target
            .is_some_and(|target| !self.native_targets.contains(&target))
        {
            self.live_target = None;
        }
        listing["document_source"] = json!("live_capture");
        listing["binding_id"] = json!(self.binding_id);
        listing["selected_target_id"] = self
            .live_target
            .map(|target| json!(target.to_string()))
            .unwrap_or(Value::Null);
        Ok(listing)
    }
    async fn release_live_values(&mut self) -> Result<()> {
        // Clear only documents used by this console connection. Stale native
        // IDs fail closed; never find a replacement document for cleanup.
        for target in self.accessed_targets.clone() {
            let result = self.exchange(3, target, r#"{"operation":"clear"}"#).await?;
            if result["runtime"]["status"] != "ok" && result["status"] != "stale_target" {
                return Err(Error::conflict(
                    "Live value cleanup was not confirmed; restart the capture binding",
                ));
            }
        }
        self.accessed_targets.clear();
        Ok(())
    }
    // The browser clears its registry only when it is told to or when this wire
    // connection ends. A live Stop keeps the connection for the next Console
    // connection, so it clears explicitly and requires the browser to confirm
    // that nothing is armed.
    async fn clear_document_start(&mut self) -> Result<()> {
        match self.exchange(4, 0, r#"{"operation":"clear"}"#).await {
            Ok(result)
                if result["document_start"]["status"] == "ok" && !self.document_start_armed =>
            {
                Ok(())
            }
            Ok(_) => Err(Error::conflict(DOCUMENT_START_UNCONFIRMED)),
            Err(error) => {
                Err(Error::conflict(DOCUMENT_START_UNCONFIRMED).with_reason(error.reason))
            }
        }
    }
    async fn exchange(&mut self, operation: u16, target: u64, source: &str) -> Result<Value> {
        // If the HTTP future is cancelled mid-exchange, the session stays
        // poisoned. Never retry an expression or reuse an ambiguous pipe.
        self.poisoned = true;
        let id = self.next_request;
        self.next_request = id.checked_add(1).ok_or_else(|| {
            Error::conflict("Native request IDs exhausted").with_code(Code::ResourceLimit)
        })?;
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
        }).await.map_err(|_| Error::new(408, "Native console timed out; execution may have occurred. Restart the session").with_reason(Reason::uncertain(Cause::Timeout)))?
          .map_err(|mut e: Error| {
              if e.status == 500 { e.message = "Native browser or console disconnected; rebuild Brave with native console support".to_owned(); }
              if e.reason.code != Code::CommandOutcomeUnknown {
                  let cause = if e.reason.code == Code::ProtocolError { Cause::InvalidReply } else { Cause::TransportFailure };
                  e = e.with_reason(Reason::uncertain(cause));
              }
              e
          })?;
        self.poisoned = false;
        if operation == 1 {
            self.document_start = result["document_start_supported"] == json!(true);
        }
        // Every document-start reply, including a refusal, lists what is armed.
        if operation == 4
            && let Some(scripts) = result["document_start"]["scripts"].as_array()
        {
            self.document_start_armed = !scripts.is_empty();
        }
        Ok(result)
    }
}

struct ResponseHeader {
    status: u16,
    kind: u16,
    truncated: bool,
    document_start: bool,
    count: usize,
    bytes: usize,
}
impl ResponseHeader {
    fn parse(bytes: &[u8; 32], request: u64, operation: u16) -> Result<Self> {
        let u16_at = |i| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
        let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let flags = u16_at(18);
        let parsed = Self {
            status: u16_at(6),
            kind: u16_at(16),
            truncated: flags & 1 != 0,
            document_start: flags & 2 != 0,
            count: u32_at(20) as usize,
            bytes: u32_at(24) as usize,
        };
        if u32_at(0) != MAGIC
            || u16_at(4) != 2
            || u64::from_le_bytes(bytes[8..16].try_into().unwrap()) != request
            || u32_at(28) != 0
            || parsed.status > 6
            || parsed.kind > 12
            || (parsed.kind == 11 && operation != 3)
            || (parsed.kind == 12 && operation != 4)
            || (operation == 3 && parsed.status == 0 && parsed.kind != 11)
            || (operation == 4 && parsed.status == 0 && parsed.kind != 12)
            || flags > 3
            // The capability bit is listing-only, so a command reply can never
            // smuggle in a claim that this browser supports the experiment.
            || (parsed.document_start && parsed.kind != 10)
            || (parsed.kind == 10
                && (operation != 1
                    || parsed.status != 0
                    || parsed.count > TARGET_LIMIT
                    || parsed.bytes != parsed.count * TARGET_SIZE))
            || (parsed.kind != 10
                && (parsed.count != 0
                    || parsed.bytes
                        > if parsed.kind == 11 || parsed.kind == 12 {
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
            )
            .with_reason(Reason::uncertain(if parsed.status == 5 {
                Cause::Timeout
            } else {
                Cause::Disconnected
            })));
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
                json!({"contract_version":2,"session_id":session,"state":"ready","targets":targets,"truncated":self.truncated,
                    "document_start_supported":self.document_start}),
            );
        }
        if self.kind == 11 {
            let runtime: Value = serde_json::from_slice(payload)
                .map_err(|_| Error::protocol("Native runtime result is not JSON"))?;
            if !runtime.is_object() || self.status != 0 {
                return Err(Error::protocol("Invalid runtime envelope"));
            }
            let failed = matches!(
                runtime["status"].as_str(),
                Some("error" | "exception" | "rejected")
            );
            let mut result = json!({"contract_version":2,"session_id":session,"state":"ready","runtime":runtime});
            if failed {
                Reason::new(Code::ApplicationFailed).annotate(&mut result);
            }
            return Ok(result);
        }
        if self.kind == 12 {
            let document_start: Value = serde_json::from_slice(payload)
                .map_err(|_| Error::protocol("Native document-start result is not JSON"))?;
            if !document_start.is_object() || self.status != 0 {
                return Err(Error::protocol("Invalid document-start envelope"));
            }
            let failed = document_start["status"] != json!("ok");
            let mut result = json!({"contract_version":3,"session_id":session,"state":"ready","document_start":document_start});
            if failed {
                Reason::new(Code::ApplicationFailed).annotate(&mut result);
            }
            return Ok(result);
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
        let mut result = json!({"contract_version":2,"session_id":session,"state":"ready","status":statuses[self.status as usize],
            "type":types[self.kind as usize],"text":text,"truncated":self.truncated});
        let reason = match self.status {
            1 => Some(Reason::new(Code::InvalidRequest)),
            2 => Some(Reason::new(Code::TargetUnavailable)),
            3 => Some(Reason::new(Code::StateConflict)),
            4 => Some(Reason::new(Code::ApplicationFailed)),
            5 => Some(Reason::uncertain(Cause::Timeout)),
            6 => Some(Reason::uncertain(Cause::Disconnected)),
            _ => None,
        };
        if let Some(reason) = reason {
            reason.annotate(&mut result);
        }
        Ok(result)
    }
}

pub struct NativeConsole {
    helper: PathBuf,
    browser: Option<PathBuf>,
    // Lock order: `session`, then `live_bridge`.
    session: Mutex<Option<Session>>,
    live_bridge: Mutex<Option<Session>>,
    live_directory: Option<PathBuf>,
    // A live binding that may have held an armed set ended without the browser
    // confirming the set was cleared. Reads report that instead of an idle
    // experiment until the capture, and with it this backend, is restarted.
    document_start_unconfirmed: AtomicBool,
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
            live_bridge: Mutex::new(None),
            live_directory: options.native_console_live_directory.clone(),
            document_start_unconfirmed: AtomicBool::new(false),
        }
    }
    // Ending a live binding closes its wire connection, and the browser drops
    // the armed set once it notices. That is not a confirmed clear, so it is
    // recorded rather than reported as an idle experiment.
    async fn retire(&self, session: Session) {
        if session.live && session.document_start_armed {
            self.document_start_unconfirmed
                .store(true, Ordering::Relaxed);
        }
        session.stop().await;
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
                || session
                    .browser
                    .as_mut()
                    .is_some_and(|browser| browser.child.try_wait().ok().flatten().is_some())
                || session.bridge.child.try_wait().ok().flatten().is_some())
        {
            self.retire(guard.take().unwrap()).await;
        }
        if guard.as_ref().is_some_and(|session| !session.live) || self.live_directory.is_none() {
            let id = guard.as_ref().map(|session| session.id.as_str());
            return json!({"contract_version":2,"available":self.available(),"state":if id.is_some() {"ready"} else {"idle"},
                "session_id":id,"message":if self.available() {"Native console uses a separate disposable browser profile"} else {"Configure a rebuilt custom Brave executable using REB_BRAVE_BINARY"}});
        }
        let mut armed = self.live_bridge.lock().await;
        let connected = guard.is_some();
        let owner = if connected { &mut *guard } else { &mut *armed };
        if let Some(session) = owner.as_mut() {
            if !session.poisoned
                && session.started.elapsed() < Duration::from_secs(3600)
                && session.bridge.child.try_wait().ok().flatten().is_none()
                && let Ok(mut listing) = session.list_live().await
            {
                listing["available"] = json!(self.available());
                listing["live_available"] = json!(true);
                listing["message"] = json!(LIVE_CAPTURE_MESSAGE);
                if !connected {
                    listing["state"] = json!("idle");
                    listing["session_id"] = Value::Null;
                }
                return listing;
            }
            self.retire(owner.take().unwrap()).await;
        }
        // A vanished or unavailable binding never changes the execution mode.
        // Recover by restarting the capture, not by launching another browser.
        json!({"contract_version":2,"available":self.available(),"live_available":false,"state":"idle","session_id":null,
            "document_source":"live_capture","targets":[],"truncated":false,
            "message":"Live capture console binding unavailable. Rebuild the matching browser and backend, then restart the capture. No second browser profile was launched."})
    }
    // Read-only. It never arms, clears, drains, launches, evaluates, or retires
    // a session, including an expired or poisoned one: retirement stays with
    // the explicit actions so a read can never destroy a researcher's context.
    pub async fn document_start(&self, after: u64) -> Result<Value> {
        let mut guard = self
            .session
            .try_lock()
            .map_err(|_| Error::conflict("Another native console action is running"))?;
        let Some(session) = guard.as_mut() else {
            if self.document_start_unconfirmed.load(Ordering::Relaxed) {
                return Ok(
                    json!({"contract_version":3,"available":self.available(),"state":"idle","session_id":null,
                    "document_start":{"status":"unconfirmed","permitted":false,"scripts":[],
                        "message":DOCUMENT_START_UNCONFIRMED},
                    "limits":document_start_limits(),"unsupported":document_start_unsupported()}),
                );
            }
            return Ok(
                json!({"contract_version":3,"available":self.available(),"state":"idle","session_id":null,
                "document_start":{"status":"idle","permitted":false,"scripts":[],
                    "message":"Connect the Console with document-start scripts enabled, then arm a rule."},
                "limits":document_start_limits(),"unsupported":document_start_unsupported()}),
            );
        };
        let ended = if let Some(browser) = session.browser.as_mut() {
            browser.child.try_wait().ok().flatten().is_some()
        } else {
            session.bridge.child.try_wait().ok().flatten().is_some()
        };
        if session.poisoned || session.started.elapsed() >= Duration::from_secs(3600) || ended {
            // A live binding's armed set lives in the capture browser, which
            // keeps it while the connection is open and confirms nothing when
            // the connection ends, so neither case may read as gone.
            let (status, message) = if !session.live || !session.document_start_armed {
                (
                    "error",
                    "This Console session ended. Start another session; armed scripts and their output are gone.",
                )
            } else if ended {
                ("unconfirmed", DOCUMENT_START_UNCONFIRMED)
            } else {
                ("unconfirmed", DOCUMENT_START_LIVE_RETIRE)
            };
            return Ok(
                json!({"contract_version":3,"available":self.available(),"state":"ready","session_id":session.id,
                "document_start":{"status":status,"permitted":false,"scripts":[],"message":message},
                "limits":document_start_limits(),"unsupported":document_start_unsupported()}),
            );
        }
        if !session.document_start {
            let mut result = document_start_unavailable(&session.id);
            result["available"] = json!(self.available());
            result["limits"] = document_start_limits();
            result["unsupported"] = document_start_unsupported();
            return Ok(result);
        }
        let command = json!({"operation":"state","after":after.to_string()});
        let mut result = session
            .exchange(4, 0, &serde_json::to_string(&command)?)
            .await?;
        result["available"] = json!(self.available());
        result["limits"] = document_start_limits();
        result["unsupported"] = document_start_unsupported();
        Ok(result)
    }
    pub async fn stop(&self) {
        if let Some(session) = self.session.lock().await.take() {
            session.stop().await;
        }
        if let Some(session) = self.live_bridge.lock().await.take() {
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
            // The experiment opt-in is optional so an existing caller that never
            // asks for it keeps working unchanged.
            let allowed: &[&str] = if request.get("document_start").is_some() {
                &["action", "url", "document_start"]
            } else {
                &["action", "url"]
            };
            validation::fields(request, allowed, "Native console start")?;
            if guard.is_some() {
                return Err(Error::conflict(
                    "Stop the current native session before starting another",
                ));
            }
            if !self.available() {
                return Err(Error::new(
                    503,
                    "Native console requires its bundled helper and a rebuilt custom Brave executable",
                ).with_code(Code::DependencyUnavailable));
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
            // Permitting document-start scripts is a launch-time decision for
            // this disposable browser. The switch alone arms nothing, and a
            // session started without it can never arm.
            let document_start = match request.get("document_start") {
                None => false,
                Some(Value::Bool(value)) => *value,
                Some(_) => {
                    return Err(Error::bad(
                        "document_start must be true or false on a native console start",
                    ));
                }
            };
            let mut session = self.launch(url.as_str(), document_start).await?;
            let result = session.exchange(1, 0, "").await;
            if result.is_ok() {
                *guard = Some(session);
            } else {
                self.retire(session).await;
            }
            return result;
        }
        if action == "connect_live" {
            validation::fields(
                request,
                &["action", "target_id", "binding_id", "confirm_live"],
                "Native console live connect",
            )?;
            if guard.is_some() {
                return Err(Error::conflict(
                    "Stop the current native session before starting another",
                ));
            }
            if request["confirm_live"] != true {
                return Err(Error::bad(
                    "Confirm that commands can change the specifically selected captured document",
                ));
            }
            let selected =
                validation::canonical(&request["target_id"], 64, true, "Console target")?;
            let binding =
                validation::canonical(&request["binding_id"], 64, true, "Console binding")?;
            let (session, result) = bind_live(&self.live_bridge, selected, binding).await?;
            *guard = Some(session);
            return Ok(result);
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
            if let Some(mut session) = guard.take() {
                let bridge_alive = session.bridge.child.try_wait().ok().flatten().is_none();
                if session.live && !session.poisoned && bridge_alive {
                    if let Err(error) = session.release_live_values().await {
                        self.retire(session).await;
                        return Err(error);
                    }
                    // The capture browser keeps an armed set for as long as this
                    // wire connection stays open, so the binding is handed back
                    // only after the browser confirms it holds no script.
                    if session.document_start_armed
                        && let Err(error) = session.clear_document_start().await
                    {
                        self.retire(session).await;
                        return Err(error);
                    }
                    session.live_target = None;
                    let mut armed = self.live_bridge.lock().await;
                    if let Some(previous) = armed.replace(session) {
                        previous.stop().await;
                    }
                } else {
                    let unconfirmed = session.live && session.document_start_armed;
                    self.retire(session).await;
                    if unconfirmed {
                        return Err(Error::conflict(DOCUMENT_START_UNCONFIRMED));
                    }
                }
            }
            return Ok(json!({"contract_version":2,"state":"idle","session_id":null}));
        }
        let allowed = if action == "targets" {
            vec!["action", "session_id"]
        } else if action == "runtime" {
            vec!["action", "session_id", "target_id", "command"]
        } else if action == "evaluate" {
            vec!["action", "session_id", "target_id", "source"]
        } else if action == "arm_document_start" {
            vec!["action", "session_id", "scripts", "confirm_document_start"]
        } else if action == "clear_document_start" {
            vec!["action", "session_id"]
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
        let ended = if let Some(browser) = session.browser.as_mut() {
            browser.child.try_wait()?.is_some()
        } else {
            session.bridge.child.try_wait()?.is_some()
        };
        if session.poisoned || session.started.elapsed() >= Duration::from_secs(3600) || ended {
            self.retire(guard.take().unwrap()).await;
            return Err(Error::conflict(
                "Native console session ended; start another session",
            ));
        }
        if action == "targets" && session.live {
            let result = session.list_live().await;
            if result.is_err() {
                self.retire(guard.take().unwrap()).await;
            }
            return result;
        }
        let runtime_source;
        let document_start_source;
        let (operation, target, source) = if action == "targets" {
            (1, 0, "")
        } else if action == "arm_document_start" || action == "clear_document_start" {
            if !session.document_start {
                if action == "clear_document_start" {
                    // Nothing can be armed in a session that never permitted
                    // the experiment, so report that instead of sending an
                    // operation this browser would reject.
                    return Ok(document_start_unavailable(&session.id));
                }
                return Err(Error::new(503, DOCUMENT_START_UNAVAILABLE)
                    .with_code(Code::DependencyUnavailable));
            }
            document_start_source = if action == "clear_document_start" {
                r#"{"operation":"clear"}"#.to_owned()
            } else {
                if request["confirm_document_start"] != true {
                    return Err(Error::bad(
                        "Confirm that armed snippets run automatically in every new matching document",
                    ));
                }
                let scripts = validate_document_start(&request["scripts"])?;
                session.document_start_armed = true;
                serde_json::to_string(&json!({"operation":"arm","scripts":scripts}))?
            };
            if document_start_source.len() > RUNTIME_LIMIT {
                return Err(Error::bad("Document-start command exceeds 65536 bytes"));
            }
            (4, 0, document_start_source.as_str())
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
        if session.live && operation != 1 && operation != 4 {
            // Reject unknown ownership before any request. Refreshing may remove
            // the exact ID but must never translate it to a replacement document.
            if session.live_target != Some(target) || !session.native_targets.contains(&target) {
                return Ok(stale_document(&session.id));
            }
            if let Err(error) = session.list_live().await {
                self.retire(guard.take().unwrap()).await;
                return Err(error);
            }
            if !session.native_targets.contains(&target) {
                return Ok(stale_document(&session.id));
            }
            session.accessed_targets.insert(target);
        }
        let result = session.exchange(operation, target, source).await;
        if session.live
            && result
                .as_ref()
                .is_ok_and(|value| value["status"] == "stale_target")
        {
            session.live_target = None;
        }
        if result.is_err() {
            self.retire(guard.take().unwrap()).await;
        }
        result
    }
    pub async fn arm_live_bridge(&self) {
        let Some(directory) = self.live_directory.clone() else {
            return;
        };
        if !private_directory(&directory) || !worker::executable(&self.helper) {
            if private_directory(&directory) {
                write_absent(&directory);
            }
            return;
        }
        let _ = std::fs::remove_file(directory.join("binding.absent"));
        // Capture paths can exceed sockaddr_un.sun_path, especially beneath
        // macOS Application Support. Publish the binding there, but keep the
        // authenticated socket and token in a short, privately owned directory.
        let transport = match tempfile::Builder::new()
            .prefix("reb-console-live.")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
        {
            Ok(directory) => directory,
            Err(_) => {
                write_absent(&directory);
                return;
            }
        };
        let bridge = match self.spawn_bridge(transport.path()).await {
            Ok(bridge) => bridge,
            Err(_) => {
                write_absent(&directory);
                return;
            }
        };
        if !wait_for_socket(&bridge.socket).await || write_binding(&directory, &bridge).is_err() {
            bridge.stop().await;
            write_absent(&directory);
            return;
        }
        *self.live_bridge.lock().await = Some(bridge.session(ConsoleDir::Live(transport), true));
    }
    async fn launch(&self, address: &str, document_start: bool) -> Result<Session> {
        let directory = tempfile::Builder::new()
            .prefix("reb-console.")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")?;
        let bridge = self.spawn_bridge(directory.path()).await?;
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
            .arg(format!(
                "--reb-native-console-socket={}",
                bridge.socket.display()
            ))
            .arg(format!(
                "--reb-native-console-token-file={}",
                bridge.token.display()
            ))
            .arg(format!("--reb-native-console-session-id={}", bridge.id));
        if document_start {
            browser.arg("--reb-native-console-document-start");
        }
        browser
            .arg(address)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let browser = OwnedProcess::spawn(&mut browser)?;
        let mut session = bridge.session(ConsoleDir::Disposable(directory), false);
        session.browser = Some(browser);
        Ok(session)
    }
    async fn spawn_bridge(&self, directory: &Path) -> Result<BridgeProcess> {
        let mut random = [0u8; 40];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token = directory.join("token");
        let mut token_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token)?;
        token_file.write_all(format!("{}\n", hex::encode(&random[..32])).as_bytes())?;
        let id = u64::from_le_bytes(random[32..].try_into().unwrap())
            .max(1)
            .to_string();
        let socket = directory.join("console.sock");
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
        Ok(BridgeProcess {
            id,
            bridge,
            input,
            output,
            socket,
            token,
        })
    }
}

struct BridgeProcess {
    id: String,
    bridge: OwnedProcess,
    input: ChildStdin,
    output: ChildStdout,
    socket: PathBuf,
    token: PathBuf,
}
impl BridgeProcess {
    fn session(self, directory: ConsoleDir, live: bool) -> Session {
        Session {
            binding_id: self.id.clone(),
            id: self.id,
            bridge: self.bridge,
            browser: None,
            input: self.input,
            output: self.output,
            directory,
            next_request: 1,
            poisoned: false,
            started: Instant::now(),
            live,
            live_target: None,
            native_targets: BTreeSet::new(),
            accessed_targets: BTreeSet::new(),
            document_start: false,
            document_start_armed: false,
        }
    }
    async fn stop(mut self) {
        self.bridge.stop().await;
    }
}

const DOCUMENT_START_UNCONFIRMED: &str = "The capture browser did not confirm that it cleared the armed document-start scripts. \
     The Console binding was ended, so the browser drops them once it notices; until then new matching \
     documents can still run them. Restart the capture before relying on documents running nothing.";

const DOCUMENT_START_LIVE_RETIRE: &str = "This Console connection failed while document-start scripts may be armed. \
     They stay in the capture browser until the connection ends; Stop ends it.";

const DOCUMENT_START_UNAVAILABLE: &str = "Document-start Console scripts are not available in this session. Rebuild the pinned browser, \
     then start a disposable Console session with document_start enabled, or relaunch the live \
     capture with REB_CONSOLE_DOCUMENT_START=1. Nothing is relaunched automatically.";

// Stated rather than silently skipped. These contexts are never reached by an
// armed snippet, whatever a rule declares, so a researcher or agent can tell
// "my rule did not match" from "this context is out of scope entirely".
fn document_start_unsupported() -> Value {
    json!([
        {"context":"dedicated_worker","reason":"The injector observes documents only; no worker scope is reached."},
        {"context":"shared_worker","reason":"The injector observes documents only; no worker scope is reached."},
        {"context":"service_worker","reason":"The injector observes documents only; no worker scope is reached."},
        {"context":"worklet","reason":"The injector observes documents only; no worklet scope is reached."},
        {"context":"isolated_world","reason":"Injection is page main world only; no isolated or extension world is used."},
        {"context":"non_http_document","reason":"A rule names an exact http or https origin, so about:blank, the initial empty document, data URLs and internal browser pages never match."},
        {"context":"other_profile","reason":"Only documents in the Console's own bound profile are eligible."},
        {"context":"already_open_document","reason":"Injection happens at document creation. A document open when the set was armed is never retroactively injected; reload it."},
    ])
}

fn document_start_limits() -> Value {
    json!({
        "scripts": DOCUMENT_START_SCRIPT_LIMIT,
        "source_bytes": DOCUMENT_START_SOURCE_LIMIT,
        "total_source_bytes": DOCUMENT_START_TOTAL_SOURCE_LIMIT,
        "rule_bytes": DOCUMENT_START_RULE_LIMIT,
        "report_bytes": 512,
        "records_per_document": 64,
        "retained_records": 128,
        "records_per_read": 32,
        "execution_millis": 50,
    })
}

fn document_start_unavailable(session: &str) -> Value {
    json!({"contract_version":3,"state":"ready","session_id":session,
        "document_start":{"status":"unavailable","permitted":false,"scripts":[],
            "message":DOCUMENT_START_UNAVAILABLE}})
}

// The browser revalidates every field and owns the rule grammar. These checks
// refuse an obviously wrong declaration before it reaches the wire, so a
// researcher sees which field is wrong instead of one opaque refusal.
fn validate_document_start(scripts: &Value) -> Result<Value> {
    let list = scripts
        .as_array()
        .ok_or_else(|| Error::bad("Document-start scripts must be an array"))?;
    if list.is_empty() || list.len() > DOCUMENT_START_SCRIPT_LIMIT {
        return Err(Error::bad(format!(
            "Arm 1 to {DOCUMENT_START_SCRIPT_LIMIT} document-start scripts"
        ))
        .with_code(Code::ResourceLimit));
    }
    let mut normalized = Vec::with_capacity(list.len());
    let mut total = 0usize;
    for script in list {
        let fields: Vec<&str> = if script.get("path_prefix").is_some() {
            vec!["frame", "origin", "path_prefix", "source"]
        } else {
            vec!["frame", "origin", "source"]
        };
        validation::fields(script, &fields, "Document-start script")?;
        let origin = validation::text(
            &script["origin"],
            "Document-start origin",
            DOCUMENT_START_RULE_LIMIT,
            false,
            false,
        )?;
        // One exact serialized origin: no pattern, wildcard, host suffix, path,
        // credentials, trailing slash, or uppercase host.
        let host = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .filter(|host| !host.is_empty())
            .ok_or_else(|| {
                Error::bad("Document-start origin must be an exact http:// or https:// origin")
            })?;
        if host.contains('/')
            || host.contains('@')
            || host.contains('?')
            || host.contains('#')
            || host.contains('*')
            || host != host.to_lowercase()
        {
            return Err(Error::bad(
                "Document-start origin takes no path, credentials, wildcard or uppercase host",
            ));
        }
        let frame = script["frame"].as_str().unwrap_or("");
        if frame != "top" && frame != "child" {
            return Err(Error::bad(
                "A document-start rule matches frame \"top\" or \"child\"; request both as two rules",
            ));
        }
        let prefix = match script.get("path_prefix") {
            Some(value) => Some(validation::text(
                value,
                "Document-start path prefix",
                DOCUMENT_START_RULE_LIMIT,
                false,
                false,
            )?),
            None => None,
        };
        if let Some(prefix) = prefix
            && (!prefix.starts_with('/') || prefix.contains('?') || prefix.contains('#'))
        {
            return Err(Error::bad(
                "A document-start path prefix is a literal path starting with / and carries no query or fragment",
            ));
        }
        let source = validation::text(
            &script["source"],
            "Document-start snippet",
            DOCUMENT_START_SOURCE_LIMIT,
            false,
            true,
        )?;
        if source.is_empty() || source.contains('\0') {
            return Err(Error::bad(
                "A document-start snippet must be nonempty and contain no NUL bytes",
            ));
        }
        total += source.len();
        if total > DOCUMENT_START_TOTAL_SOURCE_LIMIT {
            return Err(Error::bad(format!(
                "Document-start snippets exceed {DOCUMENT_START_TOTAL_SOURCE_LIMIT} total source bytes"
            ))
            .with_code(Code::ResourceLimit));
        }
        let mut entry = json!({"origin":origin,"frame":frame,"source":source});
        if let Some(prefix) = prefix {
            entry["path_prefix"] = json!(prefix);
        }
        normalized.push(entry);
    }
    Ok(Value::Array(normalized))
}

const LIVE_CAPTURE_MESSAGE: &str =
    "These documents come from the live capture. A second browser profile is not opened.";

async fn bind_live(
    live_bridge: &Mutex<Option<Session>>,
    selected: u64,
    binding: u64,
) -> Result<(Session, Value)> {
    let mut armed = live_bridge.lock().await;
    let session = armed.as_mut().ok_or_else(|| Error::conflict(
        "The live capture has no native console binding. Restart the capture; a second browser profile was not launched.",
    ))?;
    if session.binding_id != binding.to_string() {
        return Err(Error::conflict(
            "Live capture binding changed; select and authorize a current document",
        ));
    }
    if session.poisoned
        || session.started.elapsed() >= Duration::from_secs(3600)
        || session.bridge.child.try_wait()?.is_some()
    {
        armed.take().unwrap().stop().await;
        return Err(Error::conflict(
            "Live console binding ended; restart the capture",
        ));
    }
    let mut listing = match session.list_live().await {
        Ok(listing) => listing,
        Err(error) => {
            armed.take().unwrap().stop().await;
            return Err(error);
        }
    };
    if !session.native_targets.contains(&selected) {
        return Err(Error::conflict(
            "Selected live document changed; explicitly select a current document",
        ));
    }
    // HTTP connections get a fresh identity, independently of the existing
    // authenticated wire connection. Requests and handles from before Stop
    // cannot become valid again after reconnecting to the capture browser.
    let mut random = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let next = u64::from_le_bytes(random).max(1).to_string();
    if next == session.id {
        return Err(Error::conflict("Console identity collision; connect again"));
    }
    session.id = next;
    session.live_target = Some(selected);
    listing["session_id"] = json!(session.id);
    listing["selected_target_id"] = json!(selected.to_string());
    Ok((armed.take().unwrap(), listing))
}

fn stale_document(session: &str) -> Value {
    let mut result = json!({
        "contract_version": 2,
        "session_id": session,
        "state": "ready",
        "status": "stale_target",
        "type": "undefined",
        "text": "Selected document changed. Explicitly select a current live document.",
        "truncated": false,
    });
    Reason::new(Code::TargetUnavailable).annotate(&mut result);
    result
}

fn private_directory(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return false;
    }
    let Ok(path) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    let mut info = unsafe { std::mem::zeroed::<libc::stat>() };
    unsafe { libc::lstat(path.as_ptr(), &mut info) == 0 && info.st_uid == libc::geteuid() }
}

fn write_absent(directory: &Path) {
    let path = directory.join("binding.absent");
    if path.exists() {
        return;
    }
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
}

fn write_binding(directory: &Path, bridge: &BridgeProcess) -> Result<()> {
    let temporary = directory.join(format!("binding.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(
        format!(
            "{}\n{}\n{}\n",
            bridge.id,
            bridge.socket.display(),
            bridge.token.display()
        )
        .as_bytes(),
    )?;
    file.sync_all()?;
    std::fs::rename(temporary, directory.join("binding"))?;
    Ok(())
}

async fn wait_for_socket(path: &Path) -> bool {
    for _ in 0..100 {
        if std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn wire_status_reasons_preserve_native_application_text() {
        for (status, code) in [
            (1, "invalid_request"),
            (2, "target_unavailable"),
            (3, "state_conflict"),
            (4, "application_failed"),
            (5, "command_outcome_unknown"),
        ] {
            let header = ResponseHeader {
                status,
                kind: 0,
                truncated: false,
                document_start: false,
                count: 0,
                bytes: 0,
            };
            let result = header.value(b"synthetic private value", "1").unwrap();
            assert_eq!(result["text"], "synthetic private value");
            assert_eq!(result["code"], code);
            assert!(!result["details"].to_string().contains("private"));
            if status == 5 {
                assert_eq!(
                    result["details"],
                    json!({"phase":"command_exchange","cause":"timeout"})
                );
            }
        }
        let header = ResponseHeader {
            status: 0,
            kind: 0,
            truncated: false,
            document_start: false,
            count: 0,
            bytes: 0,
        };
        let result = header.value(b"success", "1").unwrap();
        assert!(result.get("code").is_none());
        assert!(result.get("details").is_none());
    }
    #[test]
    fn runtime_failure_details_do_not_copy_runtime_content() {
        let header = ResponseHeader {
            status: 0,
            kind: 11,
            truncated: false,
            document_start: false,
            count: 0,
            bytes: 0,
        };
        let payload = br#"{"status":"exception","text":"synthetic private text","stack":[]}"#;
        let result = header.value(payload, "1").unwrap();
        assert_eq!(
            result["runtime"],
            serde_json::from_slice::<Value>(payload).unwrap()
        );
        assert_eq!(result["code"], "application_failed");
        assert_eq!(result["details"], json!({}));
    }
    #[test]
    fn document_start_rules_refuse_anything_that_could_widen_their_scope() {
        let rule = |extra: Value| {
            let mut script =
                json!({"origin":"https://fixture.test","frame":"top","source":"report('x');"});
            for (key, value) in extra.as_object().unwrap() {
                if value.is_null() {
                    script.as_object_mut().unwrap().remove(key);
                } else {
                    script[key] = value.clone();
                }
            }
            validate_document_start(&json!([script]))
        };
        assert!(rule(json!({})).is_ok());
        assert!(rule(json!({"path_prefix":"/lab/"})).is_ok());
        assert!(rule(json!({"frame":"child"})).is_ok());
        for refused in [
            json!({"origin":"fixture.test"}),
            json!({"origin":"ftp://fixture.test"}),
            json!({"origin":"https://fixture.test/"}),
            json!({"origin":"https://Fixture.test"}),
            json!({"origin":"https://*.fixture.test"}),
            json!({"origin":"https://user:secret@fixture.test"}),
            json!({"origin":"https://fixture.test/path"}),
            json!({"origin":"https://fixture.test?a=b"}),
            json!({"origin":"https://"}),
            json!({"frame":"any"}),
            json!({"frame":Value::Null}),
            json!({"path_prefix":"lab"}),
            json!({"path_prefix":"/lab?a=b"}),
            json!({"path_prefix":"/lab#a"}),
            json!({"source":""}),
            json!({"source":Value::Null}),
            json!({"origin":Value::Null}),
            json!({"unexpected":"field"}),
        ] {
            assert!(rule(refused.clone()).is_err(), "{refused}");
        }
        // Bounds: script count, per-snippet source and the whole set's source.
        let script = json!({"origin":"https://fixture.test","frame":"top","source":"report('x');"});
        assert!(validate_document_start(&json!([])).is_err());
        assert!(validate_document_start(&json!([script, script, script, script, script])).is_err());
        assert!(validate_document_start(&json!(script)).is_err());
        let long = json!({"origin":"https://fixture.test","frame":"top","source":"a".repeat(DOCUMENT_START_SOURCE_LIMIT)});
        assert!(validate_document_start(&json!([long])).is_ok());
        assert!(validate_document_start(&json!([long, long, long])).is_err());
        let oversized = json!({"origin":"https://fixture.test","frame":"top","source":"a".repeat(DOCUMENT_START_SOURCE_LIMIT + 1)});
        assert!(validate_document_start(&json!([oversized])).is_err());
        // The normalized command keeps exactly the declared rule.
        let armed = validate_document_start(&json!([{"origin":"http://127.0.0.1:8080","frame":"child","path_prefix":"/lab/","source":"report(1);"}])).unwrap();
        assert_eq!(
            armed,
            json!([{"origin":"http://127.0.0.1:8080","frame":"child","path_prefix":"/lab/","source":"report(1);"}])
        );
    }

    #[test]
    fn document_start_states_match_their_published_contract() {
        let armed = json!({
            "contract_version": 3, "available": true, "state": "ready", "session_id": "12",
            "limits": document_start_limits(), "unsupported": document_start_unsupported(),
            "document_start": {
                "status": "ok", "permitted": true, "generation": "2", "renderer_processes": 2,
                "pending_renderer_processes": 0,
                "scripts": [{"script_id":"1","rule":{"origin":"https://fixture.test","frame":"top","path_prefix":"/lab/"},
                    "source_bytes": 24, "digest": "0123456789abcdef", "records": 3,
                    "injected_documents": 1, "refused": 0}],
                "output": {"records":[{"sequence":"3","record":"report","provenance":"console-document-start-script",
                    "script_id":"1","document_id":"7","frame_id":"99","top_frame":true,"time":1.0,
                    "truncated":false,"text":"kinds=string:12"}],
                    "next_sequence":"4","oldest_sequence":"1","retained":3,"dropped":0,
                    "unattributed":0,"stale":0},
            },
        });
        crate::validation::schema("NativeConsoleDocumentStart", &armed, 500).unwrap();
        let mut unavailable = document_start_unavailable("12");
        unavailable["available"] = json!(false);
        unavailable["limits"] = document_start_limits();
        unavailable["unsupported"] = document_start_unsupported();
        crate::validation::schema("NativeConsoleDocumentStart", &unavailable, 500).unwrap();
        crate::validation::schema(
            "NativeConsoleDocumentStartResult",
            &document_start_unavailable("12"),
            500,
        )
        .unwrap();
        // Provenance is fixed: output can never be labeled as capture evidence.
        let mut forged = armed.clone();
        forged["document_start"]["output"]["records"][0]["provenance"] = json!("native-capture");
        assert!(crate::validation::schema("NativeConsoleDocumentStart", &forged, 500).is_err());
    }

    #[tokio::test]
    async fn document_start_reads_never_start_or_retire_a_session() {
        let options = Options::try_parse_from(["origin-trace-backend"]).unwrap();
        let console = NativeConsole::new(&options);
        let state = console.document_start(0).await.unwrap();
        assert_eq!(state["state"], "idle");
        assert_eq!(state["session_id"], Value::Null);
        assert_eq!(state["document_start"]["permitted"], json!(false));
        assert_eq!(state["document_start"]["scripts"], json!([]));
        // Out-of-scope contexts are always stated, even with no session.
        assert!(
            state["unsupported"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["context"] == "service_worker")
        );
        crate::validation::schema("NativeConsoleDocumentStart", &state, 500).unwrap();
        // Reading twice cannot launch a browser or change the reported state.
        assert_eq!(console.document_start(0).await.unwrap(), state);
        assert!(console.session.lock().await.is_none());
    }

    #[tokio::test]
    async fn connect_live_does_not_launch_a_browser_when_the_capture_has_no_binding() {
        let directory = tempfile::tempdir().unwrap();
        let options = Options::try_parse_from([
            "origin-trace-backend",
            "--native-console-live-directory",
            directory.path().to_str().unwrap(),
        ])
        .unwrap();
        let console = NativeConsole::new(&options);
        let state = console.state().await;
        assert_eq!(state["state"], "idle");
        assert_eq!(state["document_source"], "live_capture");
        assert_eq!(state["available"], false);
        assert_eq!(state["targets"], json!([]));
        let error = console
            .action(&json!({"action":"connect_live","binding_id":"42","target_id":"12","confirm_live":true}))
            .await
            .unwrap_err();
        assert_eq!(error.status, 409);
        assert!(
            error
                .message
                .contains("second browser profile was not launched")
        );
        assert!(console.session.lock().await.is_none());
    }
    // A scripted pipe peer tests backend dispatch, not Blink/V8 behavior.
    async fn live_fixture() -> (NativeConsole, TempDir) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("targets.json"),
            r#"[
            {"id":11,"url":"https://same.test/page"},
            {"id":22,"url":"https://same.test/page"}
        ]"#,
        )
        .unwrap();
        let script = r#"
import json, pathlib, struct, sys
root = pathlib.Path(sys.argv[1])
request = struct.Struct('<IHHQQII')
response = struct.Struct('<IHHQHHIII')
target_record = struct.Struct('<QHHI256sHH128s512sI')
while True:
    header = sys.stdin.buffer.read(32)
    if not header:
        break
    magic, version, operation, sequence, target, size, reserved = request.unpack(header)
    source = sys.stdin.buffer.read(size).decode()
    with (root / 'requests.jsonl').open('a') as log:
        log.write(json.dumps({'operation':operation,'target':target,'source':source}) + '\n')
    count, kind, flags = 0, 11, 0
    if operation == 1:
        documents = json.loads((root / 'targets.json').read_text())
        records = []
        for item in documents:
            origin = b'https://same.test'
            label = b'Identical page'
            url = item['url'].encode()[:512]
            records.append(target_record.pack(item['id'],len(origin),2,0,origin,len(label),len(url),label,url,0))
        payload, count, kind = b''.join(records), len(records), 10
        # The capture browser advertises the experiment only when launched with it.
        flags = 2 if (root / 'document-start').exists() else 0
    elif operation == 4:
        # A synthetic registry that outlives Console connections, like the
        # capture browser's. clear-refused keeps the set, as a failed clear would.
        command = json.loads(source)
        armed = root / 'armed.json'
        scripts = json.loads(armed.read_text()) if armed.exists() else []
        status = 'ok'
        if command['operation'] == 'arm':
            scripts = [{'script_id':str(index + 1),'rule':{'origin':script['origin'],'frame':script['frame']},
                        'source_bytes':len(script['source']),'digest':'0123456789abcdef','records':0,
                        'injected_documents':0,'refused':0} for index, script in enumerate(command['scripts'])]
        elif command['operation'] == 'clear':
            if (root / 'clear-refused').exists():
                status = 'error'
            else:
                scripts = []
        armed.write_text(json.dumps(scripts))
        payload, kind = json.dumps({'status':status,'contract_version':3,'permitted':True,'generation':'1',
            'scripts':scripts,'renderer_processes':1,'pending_renderer_processes':0}).encode(), 12
    else:
        payload = json.dumps({'status':'ok','value':{'type':'object','text':str(target),'handle':'7','truncated':False}}).encode()
    sys.stdout.buffer.write(response.pack(magic,version,0,sequence,kind,flags,count,len(payload),0) + payload)
    sys.stdout.buffer.flush()
"#;
        let mut command = Command::new("python3");
        command
            .args(["-u", "-c", script])
            .arg(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut bridge = OwnedProcess::spawn(&mut command).unwrap();
        let input = bridge.child.stdin.take().unwrap();
        let output = bridge.child.stdout.take().unwrap();
        let session = Session {
            id: "42".into(),
            binding_id: "42".into(),
            bridge,
            browser: None,
            input,
            output,
            directory: ConsoleDir::Live(tempfile::tempdir().unwrap()),
            next_request: 1,
            poisoned: false,
            started: Instant::now(),
            live: true,
            live_target: None,
            native_targets: BTreeSet::new(),
            accessed_targets: BTreeSet::new(),
            document_start: false,
            document_start_armed: false,
        };
        let mut options = Options::try_parse_from(["origin-trace-backend"]).unwrap();
        options.native_console_live_directory = Some(directory.path().into());
        let console = NativeConsole::new(&options);
        *console.live_bridge.lock().await = Some(session);
        (console, directory)
    }
    fn requests(directory: &TempDir) -> Vec<Value> {
        std::fs::read_to_string(directory.path().join("requests.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    async fn connect_fixture(console: &NativeConsole, target: &str) -> String {
        console
            .action(&json!({"action":"connect_live","binding_id":"42","target_id":target,"confirm_live":true}))
            .await
            .unwrap()["session_id"]
            .as_str()
            .unwrap()
            .into()
    }
    #[tokio::test]
    async fn live_exact_ids_ignore_duplicate_urls_and_truncated_metadata() {
        let (console, directory) = live_fixture().await;
        let long_url = format!("https://same.test/{}", "a".repeat(600));
        std::fs::write(
            directory.path().join("targets.json"),
            json!([
                {"id":11,"url":format!("{long_url}first")},
                {"id":22,"url":format!("{long_url}second")}
            ])
            .to_string(),
        )
        .unwrap();
        let state = console.state().await;
        assert_eq!(state["targets"][0]["url"], state["targets"][1]["url"]);
        assert_eq!(state["targets"][0]["id"], "11");
        assert_eq!(state["targets"][1]["id"], "22");
        let before = requests(&directory).len();
        for confirmation in [json!(false), Value::Null] {
            let error = console
                .action(
                    &json!({"action":"connect_live","binding_id":"42","target_id":"22","confirm_live":confirmation}),
                )
                .await
                .unwrap_err();
            assert_eq!(error.status, 400);
        }
        assert_eq!(
            requests(&directory).len(),
            before,
            "unconfirmed connection must not dispatch"
        );
        let identity = connect_fixture(&console, "22").await;
        let connected = console.state().await;
        assert_eq!(connected["selected_target_id"], "22");
        let before = requests(&directory).len();
        let wrong = console.action(&json!({"action":"runtime","session_id":identity,"target_id":"11","command":{"operation":"evaluate","source":"location.href"}})).await.unwrap();
        assert_eq!(wrong["status"], "stale_target");
        assert_eq!(
            requests(&directory).len(),
            before,
            "another eligible tab is not authorized"
        );
        let result = console.action(&json!({"action":"runtime","session_id":identity,"target_id":"22","command":{"operation":"evaluate","source":"location.href"}})).await.unwrap();
        assert_eq!(result["runtime"]["value"]["text"], "22");
        assert_eq!(requests(&directory).last().unwrap()["target"], 22);
        let refreshed = console
            .action(&json!({"action":"targets","session_id":identity}))
            .await
            .unwrap();
        assert_eq!(refreshed["selected_target_id"], "22");
        console.stop().await;
    }
    #[tokio::test]
    async fn live_replaced_binding_rejects_reused_document_id_before_dispatch() {
        let (console, directory) = live_fixture().await;
        assert_eq!(console.state().await["binding_id"], "42");
        console
            .live_bridge
            .lock()
            .await
            .as_mut()
            .unwrap()
            .binding_id = "99".into();
        let before = requests(&directory).len();
        let error = console.action(&json!({"action":"connect_live","binding_id":"42","target_id":"22","confirm_live":true})).await.unwrap_err();
        assert_eq!(error.status, 409);
        assert_eq!(requests(&directory).len(), before);
        assert!(console.session.lock().await.is_none());
        let state = console.state().await;
        assert_eq!(state["binding_id"], "99");
        assert_eq!(state["targets"][1]["id"], "22");
        console.stop().await;
    }

    #[tokio::test]
    async fn live_navigation_reload_close_revoke_authorization_without_dispatch() {
        for replacement in [
            json!([{"id":33,"url":"https://same.test/other"}]),
            json!([{"id":33,"url":"https://same.test/page"}]),
            json!([]),
        ] {
            let (console, directory) = live_fixture().await;
            let identity = connect_fixture(&console, "22").await;
            std::fs::write(
                directory.path().join("targets.json"),
                replacement.to_string(),
            )
            .unwrap();
            let before = requests(&directory).len();
            let result = console.action(&json!({"action":"runtime","session_id":identity,"target_id":"22","command":{"operation":"inspect","handle":"7","offset":0}})).await.unwrap();
            assert_eq!(result["status"], "stale_target");
            let after = requests(&directory);
            assert_eq!(after.len(), before + 1);
            assert_eq!(
                after.last().unwrap()["operation"],
                1,
                "no runtime dispatched after document invalidation"
            );
            // Even a faulty peer reintroducing the old number cannot revive consent.
            std::fs::write(
                directory.path().join("targets.json"),
                r#"[{"id":22,"url":"https://same.test/page"}]"#,
            )
            .unwrap();
            let result = console.action(&json!({"action":"evaluate","session_id":identity,"target_id":"22","source":"location.href"})).await.unwrap();
            assert_eq!(result["status"], "stale_target");
            assert_eq!(requests(&directory).len(), after.len());
            console.stop().await;
        }
    }
    #[tokio::test]
    async fn live_reconnect_clears_values_rotates_identity_and_rejects_stale_handles() {
        let (console, directory) = live_fixture().await;
        let first = connect_fixture(&console, "22").await;
        console.action(&json!({"action":"runtime","session_id":first,"target_id":"22","command":{"operation":"evaluate","source":"({a:1})"}})).await.unwrap();
        console
            .action(&json!({"action":"stop","session_id":first}))
            .await
            .unwrap();
        let last = requests(&directory).pop().unwrap();
        assert_eq!(last["target"], 22);
        assert_eq!(last["source"], r#"{"operation":"clear"}"#);
        assert!(
            console
                .live_bridge
                .lock()
                .await
                .as_ref()
                .unwrap()
                .browser
                .is_none()
        );
        let second = connect_fixture(&console, "11").await;
        assert_ne!(first, second);
        let before = requests(&directory).len();
        let error = console.action(&json!({"action":"runtime","session_id":first,"target_id":"22","command":{"operation":"inspect","handle":"7","offset":0}})).await.unwrap_err();
        assert_eq!(error.status, 409);
        assert_eq!(requests(&directory).len(), before);
        // Binding loss stays live/unavailable and cannot spawn or bind a replacement.
        console
            .session
            .lock()
            .await
            .as_mut()
            .unwrap()
            .bridge
            .stop()
            .await;
        let state = console.state().await;
        assert_eq!(state["document_source"], "live_capture");
        assert_eq!(state["live_available"], false);
        assert_eq!(state["targets"], json!([]));
        assert!(
            console
                .action(&json!({"action":"connect_live","binding_id":"42","target_id":"11","confirm_live":true}))
                .await
                .is_err()
        );
        assert_eq!(requests(&directory).len(), before);
        console.stop().await;
    }
    async fn arm_fixture(console: &NativeConsole, directory: &TempDir) -> String {
        std::fs::write(directory.path().join("document-start"), "").unwrap();
        let identity = connect_fixture(console, "22").await;
        let armed = console
            .action(&json!({"action":"arm_document_start","session_id":identity,"confirm_document_start":true,
                "scripts":[{"origin":"https://same.test","frame":"top","source":"report(1);"}]}))
            .await
            .unwrap();
        assert_eq!(armed["document_start"]["scripts"][0]["script_id"], "1");
        identity
    }
    #[tokio::test]
    async fn live_stop_clears_armed_document_start_scripts_before_reporting_idle() {
        let (console, directory) = live_fixture().await;
        let identity = arm_fixture(&console, &directory).await;
        let stopped = console
            .action(&json!({"action":"stop","session_id":identity}))
            .await
            .unwrap();
        assert_eq!(stopped["state"], "idle");
        // The capture browser keeps its registry across Console connections,
        // so Stop itself must have cleared it before reporting idle.
        let last = requests(&directory).pop().unwrap();
        assert_eq!(last["operation"], 4);
        assert_eq!(last["source"], r#"{"operation":"clear"}"#);
        let idle = console.document_start(0).await.unwrap();
        assert_eq!(idle["document_start"]["status"], "idle");
        crate::validation::schema("NativeConsoleDocumentStart", &idle, 500).unwrap();
        let second = connect_fixture(&console, "22").await;
        let state = console.document_start(0).await.unwrap();
        assert_eq!(state["session_id"], second);
        assert_eq!(state["document_start"]["scripts"], json!([]));
        // Nothing armed means nothing to clear: Stop sends no extra request.
        let before = requests(&directory).len();
        console
            .action(&json!({"action":"stop","session_id":second}))
            .await
            .unwrap();
        assert!(
            requests(&directory)[before..]
                .iter()
                .all(|request| request["operation"] != 4)
        );
        console.stop().await;
    }
    #[tokio::test]
    async fn live_stop_reports_an_unconfirmed_clear_instead_of_idle() {
        let (console, directory) = live_fixture().await;
        let identity = arm_fixture(&console, &directory).await;
        std::fs::write(directory.path().join("clear-refused"), "").unwrap();
        let error = console
            .action(&json!({"action":"stop","session_id":identity}))
            .await
            .unwrap_err();
        assert_eq!(error.status, 409);
        assert!(
            error.message.contains("did not confirm"),
            "{}",
            error.message
        );
        // The binding is ended rather than handed back with a set still armed.
        assert!(console.live_bridge.lock().await.is_none());
        let state = console.document_start(0).await.unwrap();
        assert_eq!(state["state"], "idle");
        assert_eq!(state["document_start"]["status"], "unconfirmed");
        assert!(
            state["document_start"]["message"]
                .as_str()
                .unwrap()
                .contains("Restart the capture")
        );
        crate::validation::schema("NativeConsoleDocumentStart", &state, 500).unwrap();
        assert_eq!(console.state().await["live_available"], false);
        console.stop().await;
    }
    #[tokio::test]
    async fn live_stop_of_a_failed_connection_never_reports_an_armed_set_gone() {
        let (console, directory) = live_fixture().await;
        let identity = arm_fixture(&console, &directory).await;
        console.session.lock().await.as_mut().unwrap().poisoned = true;
        let state = console.document_start(0).await.unwrap();
        assert_eq!(state["document_start"]["status"], "unconfirmed");
        crate::validation::schema("NativeConsoleDocumentStart", &state, 500).unwrap();
        let before = requests(&directory).len();
        let error = console
            .action(&json!({"action":"stop","session_id":identity}))
            .await
            .unwrap_err();
        assert_eq!(error.status, 409);
        // A failed connection is never reused to send the clear.
        assert_eq!(requests(&directory).len(), before);
        assert_eq!(
            console.document_start(0).await.unwrap()["document_start"]["status"],
            "unconfirmed"
        );
        console.stop().await;
    }
    #[test]
    fn retired_session_does_not_claim_the_command_had_no_effect() {
        for (status, cause) in [(5u16, "timeout"), (6, "disconnected")] {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&MAGIC.to_le_bytes());
            bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
            bytes[6..8].copy_from_slice(&status.to_le_bytes());
            bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
            let error = ResponseHeader::parse(&bytes, 1, 2).err().unwrap();
            assert_eq!(error.status, 409);
            assert_eq!(error.reason.code, Code::CommandOutcomeUnknown);
            assert_eq!(
                serde_json::to_value(error).unwrap()["details"],
                json!({"phase":"command_exchange","cause":cause})
            );
        }
    }
}
