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
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};

const MAGIC: u32 = 0x43424552;
// Wire version 3 added Stop (operation 5) and the stopped status (7). Version
// 4 drops every command, reply and listing bound and makes target records
// variable length (common/native_console_protocol.h).
const VERSION: u16 = 4;
// The one bound left is the record format's own: a header names its payload
// with 32 bits, so a command or a reply is at most this many bytes. Every
// source, value, message and listing below it crosses whole.
const RECORD_LIMIT: usize = u32::MAX as usize;
// A target record's fixed part. Its origin, label and URL bytes follow it.
const TARGET_HEADER: usize = 24;
// A reply that drains a queue stops adding records past this many bytes and
// says that more remain (kNativeConsolePageBytes). It is a page, not a limit.
const PAGE_BYTES: usize = 8 * 1024 * 1024;
// What the browser keeps of document-start output for a reader that stops
// reading (kNativeConsoleDocumentStartRetainedBytes).
const DOCUMENT_START_RETAINED_BYTES: usize = 64 * 1024 * 1024;
// A record being transferred must keep moving; however large, it fails only
// when it stalls this long. Longer than the bridge's own two-second stall, so
// the hop nearer the browser reports a stall first.
const TRANSFER_STALL: Duration = Duration::from_secs(10);
// Chromium refuses a URL longer than this (url::kMaxURLChars), so a Console
// URL can be any URL the browser can open.
const URL_LIMIT: usize = 2 * 1024 * 1024;

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
    // Shared with `interrupt`, which writes a Stop while an action holds the
    // session for a running command.
    input: Arc<Mutex<ChildStdin>>,
    output: ChildStdout,
    directory: ConsoleDir,
    next_request: u64,
    poisoned: bool,
    live: bool,
    live_target: Option<u64>,
    // The selected document that a listing or the browser reported gone. It
    // stays reported until the next connect_live or Stop, so a caller can tell
    // "my document went stale" from "nothing was ever selected".
    stale_target: Option<u64>,
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
    // The document and rules the renderer last confirmed armed through `watch`.
    watch: Option<(u64, Value)>,
    // The scope the browser confirmed it keeps for later documents, and the
    // document it was armed from. It outlives that document's navigation, so
    // Stop clears it through an `unwatch` even when the document is gone
    // (protocol/native-debugger-observation-v1.md).
    kept: Option<(u64, Value)>,
    // The last live listing, which a state read reports while a command runs.
    listing: Value,
}
// A command the renderer runs until it returns or is stopped. Registered while
// the session's input is locked to send it, so a Stop written under the same
// lock can name only this command or the one just answered, which the bridge
// and browser ignore; never a later command.
struct Running {
    session_id: String,
    request_id: u64,
    input: Arc<Mutex<ChildStdin>>,
    stopping: bool,
    // What a state read reports until the command returns.
    state: Value,
}
#[derive(Default)]
struct RunningSlot {
    running: std::sync::Mutex<Option<Running>>,
    // Wakes a state read that waits for the session, because the action
    // holding it has started a command that may run for a long time.
    registered: tokio::sync::Notify,
}
impl RunningSlot {
    fn state(&self) -> Option<Value> {
        let running = self.running.lock().unwrap();
        let running = running.as_ref()?;
        let mut state = running.state.clone();
        state["command"] = json!({"status":if running.stopping {"stopping"} else {"running"},
            "request_id":running.request_id.to_string()});
        Some(state)
    }
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
    // Why this session can no longer be used, decided without an exchange.
    // An unreadable process status counts as ended.
    fn ended(&mut self) -> Option<&'static str> {
        let exited = |process: &mut OwnedProcess| !matches!(process.child.try_wait(), Ok(None));
        if self.poisoned {
            Some(LOST_EXCHANGE)
        } else if exited(&mut self.bridge) || self.browser.as_mut().is_some_and(exited) {
            Some(LOST_EXITED)
        } else {
            None
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
        // Navigation disarms the renderer's rules with the document.
        if self
            .watch
            .as_ref()
            .is_some_and(|(armed, _)| !self.native_targets.contains(armed))
        {
            self.watch = None;
        }
        if let Some(target) = self
            .live_target
            .filter(|target| !self.native_targets.contains(target))
        {
            self.live_target = None;
            self.stale_target = Some(target);
        }
        listing["document_source"] = json!("live_capture");
        listing["binding_id"] = json!(self.binding_id);
        listing["selected_target_id"] = self
            .live_target
            .map(|target| json!(target.to_string()))
            .unwrap_or(Value::Null);
        listing["selection"] = self.selection();
        self.listing = listing.clone();
        Ok(listing)
    }
    fn selection(&self) -> Value {
        match (self.live_target, self.stale_target) {
            (Some(target), _) => json!({"status":"selected","target_id":target.to_string()}),
            (None, Some(target)) => json!({"status":"stale","target_id":target.to_string(),
                "message":stale_message(target)}),
            (None, None) => json!({"status":"none"}),
        }
    }
    async fn release_live_values(&mut self) -> Result<()> {
        // Watch rules outlive a listing's agent rebind, so Stop disarms them.
        // The browser forgets a kept scope on any unwatch, even one whose
        // document is gone, so the document it was armed from serves.
        let armed = self.watch.take().map(|(target, _)| target);
        let kept = self.kept.take().map(|(target, _)| target);
        if let Some(target) = armed.or(kept) {
            let result = self
                .exchange(3, target, r#"{"operation":"unwatch"}"#)
                .await?;
            if result["runtime"]["status"] != "ok" && result["status"] != "stale_target" {
                return Err(Error::conflict(
                    "Watch rules were not confirmed disarmed; restart the capture binding",
                ));
            }
        }
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
        self.exchange_running(operation, target, source, None).await
    }
    // Commands (operations 2 and 3) run in the page until they return or are
    // stopped, so their answer is awaited for as long, and `running` registers
    // them for `interrupt`. Listings and document-start operations are browser
    // work, so their answer must start within a short deadline. Either way a
    // record of any size moves for as long as it keeps moving.
    async fn exchange_running(
        &mut self,
        operation: u16,
        target: u64,
        source: &str,
        running: Option<(&RunningSlot, Value)>,
    ) -> Result<Value> {
        // If the HTTP future is cancelled mid-exchange, the session stays
        // poisoned. Never retry an expression or reuse an ambiguous pipe.
        self.poisoned = true;
        let id = self.next_request;
        self.next_request = id.checked_add(1).ok_or_else(|| {
            Error::conflict("Native request IDs exhausted").with_code(Code::ResourceLimit)
        })?;
        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&operation.to_le_bytes());
        header[8..16].copy_from_slice(&id.to_le_bytes());
        header[16..24].copy_from_slice(&target.to_le_bytes());
        header[24..28].copy_from_slice(&(source.len() as u32).to_le_bytes());
        let answer = running
            .is_none()
            .then(|| answer_deadline(id == 1, source.len()));
        let (session_id, shared) = (self.id.clone(), self.input.clone());
        let result = async {
            let mut input = shared.lock().await;
            if let Some((slot, state)) = running {
                *slot.running.lock().unwrap() = Some(Running {
                    session_id,
                    request_id: id,
                    input: shared.clone(),
                    stopping: false,
                    state,
                });
                slot.registered.notify_waiters();
            }
            write_moving(&mut input, &header).await?;
            write_moving(&mut input, source.as_bytes()).await?;
            stalled(input.flush()).await??;
            drop(input);
            let mut response = [0u8; 32];
            match answer {
                Some(deadline) => tokio::time::timeout(deadline, self.output.read_exact(&mut response))
                    .await
                    .map_err(|_| timed_out())??,
                None => self.output.read_exact(&mut response).await?,
            };
            let parsed = ResponseHeader::parse(&response, id, operation)?;
            let payload = read_moving(&mut self.output, parsed.bytes).await?;
            let mut value = parsed.value(&payload, &self.id)?;
            if parsed.kind == 11 { value["request_id"] = json!(id.to_string()); }
            Ok(value)
        }.await
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

// How long browser work may take to start answering. The first listing waits
// for the browser's own start. The browser receives and parses the whole
// command before it answers, across two more processes than the HTTP body, so
// the deadline grows by a second per 4 MiB of it: a document-start set is
// never refused for its size, only a browser that stops answering is.
fn answer_deadline(first: bool, command_bytes: usize) -> Duration {
    Duration::from_secs(if first { 35 } else { 6 } + (command_bytes >> 22) as u64)
}

fn timed_out() -> Error {
    Error::new(
        408,
        "Native console timed out; execution may have occurred. Restart the session",
    )
    .with_reason(Reason::uncertain(Cause::Timeout))
}

// One step of a transfer, failed only when it makes no progress for
// TRANSFER_STALL.
async fn stalled<T>(step: impl std::future::Future<Output = T>) -> Result<T> {
    tokio::time::timeout(TRANSFER_STALL, step)
        .await
        .map_err(|_| timed_out())
}

async fn write_moving(input: &mut ChildStdin, bytes: &[u8]) -> Result<()> {
    for chunk in bytes.chunks(1 << 20) {
        stalled(input.write_all(chunk)).await??;
    }
    Ok(())
}

// Reads a `bytes`-long payload. The buffer grows with the bytes that actually
// arrived, so a header's length alone allocates nothing.
async fn read_moving(output: &mut ChildStdout, bytes: usize) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    while payload.len() < bytes {
        let mut filled = payload.len();
        payload.resize(bytes.min((filled * 2).max(1 << 20)), 0);
        while filled < payload.len() {
            let count = stalled(output.read(&mut payload[filled..])).await??;
            if count == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            filled += count;
        }
    }
    Ok(payload)
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
            || u16_at(4) != VERSION
            || u64::from_le_bytes(bytes[8..16].try_into().unwrap()) != request
            || u32_at(28) != 0
            || parsed.status > 7
            || parsed.kind > 12
            || (parsed.kind == 11 && operation != 3)
            || (parsed.kind == 12 && operation != 4)
            || (operation == 3 && parsed.status == 0 && parsed.kind != 11)
            || (operation == 4 && parsed.status == 0 && parsed.kind != 12)
            || flags > 3
            // Both flags describe a listing, so a command reply can never
            // smuggle in a claim that this browser supports the experiment,
            // and nothing else is ever cut to fit a record.
            || (flags != 0 && parsed.kind != 10)
            // Each target's own lengths are checked as it is read; the count
            // can only be as large as the fixed parts the payload has room for.
            || (parsed.kind == 10
                && (operation != 1
                    || parsed.status != 0
                    || parsed.count * TARGET_HEADER > parsed.bytes))
            || (parsed.kind != 10 && (parsed.count != 0 || (operation == 1 && parsed.status == 0)))
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
        // An empty timeout or disconnect record is the browser retiring this
        // wire connection. With text, either is one command's outcome, such as
        // a renderer that went away mid-command; the connection stays usable
        // and `value` reports the outcome as unknown.
        if parsed.bytes == 0 && (parsed.status == 5 || parsed.status == 6) {
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
            // Each target is its fixed part followed by its whole origin, label
            // and URL (NativeConsoleTarget), however long.
            let malformed = || Error::protocol("Native target listing is malformed");
            let mut targets = Vec::with_capacity(self.count);
            let mut ids = std::collections::BTreeSet::new();
            let mut offset = 0;
            for _ in 0..self.count {
                let record = payload
                    .get(offset..offset + TARGET_HEADER)
                    .ok_or_else(malformed)?;
                let id = u64::from_le_bytes(record[..8].try_into().unwrap());
                let size =
                    |at: usize| u32::from_le_bytes(record[at..at + 4].try_into().unwrap()) as usize;
                let (origin_size, label_size, url_size) = (size(8), size(12), size(16));
                let flags = u16::from_le_bytes(record[20..22].try_into().unwrap());
                if id == 0 || flags & !2 != 0 || record[22..24] != [0; 2] || !ids.insert(id) {
                    return Err(malformed());
                }
                offset += TARGET_HEADER;
                let mut text = |size: usize, what: &str| -> Result<&str> {
                    let bytes = payload.get(offset..offset + size).ok_or_else(malformed)?;
                    offset += size;
                    std::str::from_utf8(bytes)
                        .map_err(|_| Error::protocol(format!("Native {what} is not UTF-8")))
                };
                let origin = text(origin_size, "origin")?;
                let label = text(label_size, "label")?;
                let url = text(url_size, "URL")?;
                targets.push(json!({"id":id.to_string(),"origin":origin,"label":label,"url":url,"main_frame":flags & 2 != 0}));
            }
            if offset != payload.len() {
                return Err(malformed());
            }
            annotate_frames(&mut targets);
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
            let mut result = json!({"contract_version":4,"session_id":session,"state":"ready","document_start":document_start});
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
            "stopped",
        ];
        let text = std::str::from_utf8(payload)
            .map_err(|_| Error::protocol("Native result is not UTF-8"))?;
        let mut result = json!({"contract_version":2,"session_id":session,"state":"ready","status":statuses[self.status as usize],
            "type":types[self.kind as usize],"text":text});
        let reason = match self.status {
            1 => Some(Reason::new(Code::InvalidRequest)),
            2 => Some(Reason::new(Code::TargetUnavailable)),
            3 => Some(Reason::new(Code::StateConflict)),
            4 => Some(Reason::new(Code::ApplicationFailed)),
            5 => Some(Reason::uncertain(Cause::Timeout)),
            6 => Some(Reason::uncertain(Cause::Disconnected)),
            7 => Some(Reason::new(Code::Cancelled)),
            _ => None,
        };
        if let Some(reason) = reason {
            reason.annotate(&mut result);
        }
        Ok(result)
    }
}

pub struct NativeConsole {
    // Every operation runs to completion on its own task. An HTTP client that
    // disconnects mid-exchange would otherwise abandon a half-written request
    // or an unread reply, leaving the pipe ambiguous, and for a live capture
    // that ends the one binding its browser connects.
    inner: Arc<Inner>,
}
impl NativeConsole {
    pub fn new(options: &Options) -> Self {
        Self {
            inner: Arc::new(Inner::new(options)),
        }
    }
    pub async fn state(&self) -> Value {
        let inner = self.inner.clone();
        detach(async move { inner.state().await })
            .await
            .unwrap_or_else(|error| {
                json!({"contract_version":2,"available":false,"state":"idle","session_id":null,"message":error.message})
            })
    }
    /// The confirmed watch rules as `armed` and the scope the browser keeps
    /// as `kept`, each null when there is none, or `None` while an action
    /// holds the session. Never exchanges with the browser.
    pub fn watch(&self) -> Option<Value> {
        let guard = self.inner.session.try_lock().ok()?;
        let Some(session) = guard.as_ref() else {
            return Some(json!({"armed": null, "kept": null}));
        };
        let armed = session.watch.as_ref().map(|(target, rules)| {
            json!({"session_id": session.id, "target_id": target.to_string(), "rules": rules})
        });
        let kept = session.kept.as_ref().map(|(target, kept)| {
            let mut kept = kept.clone();
            kept["session_id"] = json!(session.id);
            kept["target_id"] = json!(target.to_string());
            kept
        });
        Some(json!({"armed": armed, "kept": kept}))
    }
    pub async fn document_start(&self, after: u64) -> Result<Value> {
        let inner = self.inner.clone();
        detach(async move { inner.document_start(after).await }).await?
    }
    pub async fn action(&self, request: &Value) -> Result<Value> {
        let (inner, request) = (self.inner.clone(), request.clone());
        detach(async move { inner.action(&request).await }).await?
    }
    pub async fn stop(&self) {
        self.inner.stop().await;
    }
    pub async fn arm_live_bridge(&self) {
        self.inner.arm_live_bridge().await;
    }
}

async fn detach<T: Send + 'static>(work: impl Future<Output = T> + Send + 'static) -> Result<T> {
    tokio::spawn(work)
        .await
        .map_err(|_| Error::new(500, "Native console task ended unexpectedly"))
}

// The live capture's Console binding. The capture browser connects to its
// bridge once, at launch, and the bridge accepts one connection, so a lost
// binding cannot be re-armed: it stays lost until the capture restarts. A loss
// is entered only through `Inner::lose`, which records why for state reads.
enum LiveBridge {
    // No binding was published for this capture.
    Absent,
    // Published. The handshake task owns the bridge until the capture browser
    // answers its first document listing.
    Connecting,
    // Answered and idle, ready for `connect_live`.
    Ready(Box<Session>),
    // Lent to the Console connection in `Inner::session`. A Stop that confirms
    // its cleanup hands it back as `Ready`.
    Connected,
    // Ended. The reason completes `lost_message`.
    Lost(&'static str),
}
impl LiveBridge {
    fn name(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Connecting => "connecting",
            Self::Ready(_) => "ready",
            Self::Connected => "connected",
            Self::Lost(_) => "lost",
        }
    }
}

struct Inner {
    helper: PathBuf,
    browser: Option<PathBuf>,
    // Lock order: `action`, `session`, then `live`. An action holds `action`
    // throughout, so a second action is refused rather than queued; reads take
    // only `session`, so a read never makes an action fail.
    action: Mutex<()>,
    session: Mutex<Option<Session>>,
    live: Mutex<LiveBridge>,
    live_directory: Option<PathBuf>,
    handshake: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
    // A live binding that may have held an armed set ended without the browser
    // confirming the set was cleared. Reads report that instead of an idle
    // experiment until the capture, and with it this backend, is restarted.
    document_start_unconfirmed: AtomicBool,
    // The capture launcher passed Brave the document-start permission. A live
    // browser that still lists no support then lacks the overlay, which is a
    // different next step from a capture started without the permission.
    live_document_start_permitted: bool,
    running: RunningSlot,
}
impl Inner {
    fn new(options: &Options) -> Self {
        Self {
            helper: options.worker(
                &options.native_console,
                "OriginTraceNativeConsole",
                "build/reb-console",
            ),
            browser: options.brave_binary.clone(),
            action: Mutex::new(()),
            session: Mutex::new(None),
            live: Mutex::new(LiveBridge::Absent),
            live_directory: options.native_console_live_directory.clone(),
            handshake: std::sync::Mutex::new(None),
            document_start_unconfirmed: AtomicBool::new(false),
            live_document_start_permitted: options.session_document_start,
            running: RunningSlot::default(),
        }
    }
    fn unavailable_message(&self, session: &Session) -> &'static str {
        if session.live && self.live_document_start_permitted {
            DOCUMENT_START_BROWSER_UNSUPPORTED
        } else {
            DOCUMENT_START_UNAVAILABLE
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
    // A session that can no longer be used. A live one takes its binding with
    // it, because the capture browser never connects another.
    async fn end(&self, session: Session, why: &'static str) {
        if session.live {
            let mut live = self.live.lock().await;
            self.lose(&mut live, Some(session), why).await;
        } else {
            self.retire(session).await;
        }
    }
    async fn lose(&self, live: &mut LiveBridge, session: Option<Session>, why: &'static str) {
        if let LiveBridge::Ready(ready) = std::mem::replace(live, LiveBridge::Lost(why)) {
            self.retire(*ready).await;
        }
        if let Some(session) = session {
            self.retire(session).await;
        }
    }
    fn available(&self) -> bool {
        worker::executable(&self.helper)
            && self.browser.as_ref().is_some_and(|p| worker::executable(p))
    }
    // The session, once a short action or read holding it is done. A command
    // runs until it returns, so while one runs this returns its state instead
    // of waiting.
    async fn session(
        &self,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, Option<Session>>, Value> {
        loop {
            let registered = self.running.registered.notified();
            tokio::pin!(registered);
            registered.as_mut().enable();
            if let Some(state) = self.running.state() {
                return Err(state);
            }
            tokio::select! {
                guard = self.session.lock() => return Ok(guard),
                () = &mut registered => {}
            }
        }
    }
    async fn state(&self) -> Value {
        let mut guard = match self.session().await {
            Ok(guard) => guard,
            Err(running) => return running,
        };
        if let Some(why) = guard.as_mut().and_then(Session::ended) {
            // Records an end that already happened; a usable session is never
            // ended by a read.
            self.end(guard.take().unwrap(), why).await;
        }
        if guard.as_ref().is_some_and(|session| !session.live) || self.live_directory.is_none() {
            let id = guard.as_ref().map(|session| session.id.as_str());
            return json!({"contract_version":2,"available":self.available(),"state":if id.is_some() {"ready"} else {"idle"},
                "session_id":id,"message":if self.available() {"Native console uses a separate disposable browser profile"} else {"Configure a rebuilt custom Brave executable using REB_BRAVE_BINARY"}});
        }
        // Listing again is how a connected reader sees its selected document
        // go stale. A failed listing leaves an ambiguous pipe, so it ends the
        // binding with that reason rather than being retried.
        if let Some(session) = guard.as_mut() {
            match session.list_live().await {
                Ok(mut listing) => {
                    listing["available"] = json!(self.available());
                    listing["live_available"] = json!(true);
                    listing["binding_state"] = json!("connected");
                    listing["message"] = json!(LIVE_CAPTURE_MESSAGE);
                    return listing;
                }
                Err(_) => self.end(guard.take().unwrap(), LOST_EXCHANGE).await,
            }
        }
        let mut live = self.live.lock().await;
        drop(guard);
        // Discovery before any connection: the idle bridge is the only source
        // of live documents. A failed listing leaves an ambiguous pipe.
        let listed = match &mut *live {
            LiveBridge::Ready(session) => Some(match session.ended() {
                Some(why) => Err(why),
                None => session.list_live().await.map_err(|_| LOST_EXCHANGE),
            }),
            _ => None,
        };
        match listed {
            Some(Ok(mut listing)) => {
                listing["available"] = json!(self.available());
                listing["live_available"] = json!(true);
                listing["binding_state"] = json!("ready");
                listing["message"] = json!(LIVE_CAPTURE_MESSAGE);
                listing["state"] = json!("idle");
                listing["session_id"] = Value::Null;
                return listing;
            }
            Some(Err(why)) => self.lose(&mut live, None, why).await,
            None => {}
        }
        // A vanished or unavailable binding never changes the execution mode.
        // Recover by restarting the capture, not by launching another browser.
        let message = match &*live {
            LiveBridge::Connecting => LIVE_CONNECTING.to_owned(),
            LiveBridge::Lost(why) => lost_message(why),
            _ => LIVE_UNAVAILABLE.to_owned(),
        };
        json!({"contract_version":2,"available":self.available(),"live_available":false,"state":"idle","session_id":null,
            "document_source":"live_capture","binding_state":live.name(),"targets":[],"truncated":false,"message":message})
    }
    // Read-only. It never arms, clears, drains, launches, evaluates, or retires
    // a session, including a poisoned one: retirement stays with
    // the explicit actions so a read can never destroy a researcher's context.
    async fn document_start(&self, after: u64) -> Result<Value> {
        let mut guard = self.session().await.map_err(|_| {
            Error::conflict(
                "A Console command is running; read document-start output once it returns or is stopped",
            )
        })?;
        let Some(session) = guard.as_mut() else {
            if self.document_start_unconfirmed.load(Ordering::Relaxed) {
                return Ok(
                    json!({"contract_version":4,"available":self.available(),"state":"idle","session_id":null,
                    "document_start":{"status":"unconfirmed","permitted":false,"scripts":[],
                        "message":DOCUMENT_START_UNCONFIRMED},
                    "limits":document_start_limits(),"unsupported":document_start_unsupported()}),
                );
            }
            return Ok(
                json!({"contract_version":4,"available":self.available(),"state":"idle","session_id":null,
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
        if session.poisoned || ended {
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
                json!({"contract_version":4,"available":self.available(),"state":"ready","session_id":session.id,
                "document_start":{"status":status,"permitted":false,"scripts":[],"message":message},
                "limits":document_start_limits(),"unsupported":document_start_unsupported()}),
            );
        }
        if !session.document_start {
            let mut result =
                document_start_unavailable(&session.id, self.unavailable_message(session));
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
    async fn stop(&self) {
        let handshake = self.handshake.lock().unwrap().take();
        if let Some(handshake) = handshake {
            handshake.abort();
        }
        // A running command holds the session until it returns. Stop it, and
        // wait no longer than the browser's own Stop deadline: processes left
        // with the action are killed when it is dropped at exit.
        let _ = self.stop_running(None).await;
        if let Ok(mut guard) =
            tokio::time::timeout(Duration::from_secs(10), self.session.lock()).await
            && let Some(session) = guard.take()
        {
            session.stop().await;
        }
        let mut live = self.live.lock().await;
        if !matches!(*live, LiveBridge::Absent)
            && let LiveBridge::Ready(session) =
                std::mem::replace(&mut *live, LiveBridge::Lost(LOST_STOPPED))
        {
            session.stop().await;
        }
    }
    // What a state read reports while `session` runs a command, the same as
    // it would report between commands.
    fn running_state(&self, session: &Session) -> Value {
        if !session.live || self.live_directory.is_none() {
            return json!({"contract_version":2,"available":self.available(),"state":"ready",
                "session_id":session.id,"message":"Native console uses a separate disposable browser profile"});
        }
        let mut state = session.listing.clone();
        state["available"] = json!(self.available());
        state["live_available"] = json!(true);
        state["binding_state"] = json!("connected");
        state["message"] = json!(LIVE_CAPTURE_MESSAGE);
        state
    }
    // Stops the command another action is running, without waiting for that
    // action. The renderer ends the command at its next interrupt check and
    // answers it as `stopped`; changes it already made stay.
    async fn interrupt(&self, request: &Value) -> Result<Value> {
        validation::fields(
            request,
            &["action", "session_id"],
            "Native console interrupt",
        )?;
        validation::canonical(&request["session_id"], 64, true, "Console session")?;
        let answer = |command: &str| {
            json!({"contract_version":2,"state":"ready","session_id":request["session_id"],
                "command":command})
        };
        if self.stop_running(Some(&request["session_id"])).await? {
            return Ok(answer("stopping"));
        }
        // Nothing runs for this session. A free session still checks the
        // identity, like every other action.
        if let Ok(guard) = self.session.try_lock()
            && guard
                .as_ref()
                .is_none_or(|session| request["session_id"] != session.id)
        {
            return Err(Error::conflict(SESSION_CHANGED));
        }
        Ok(answer("none"))
    }
    // Sends Stop to the running command, of `session_id` when one is named.
    // False when no such command runs.
    async fn stop_running(&self, session_id: Option<&Value>) -> Result<bool> {
        let running = {
            let running = self.running.running.lock().unwrap();
            running
                .as_ref()
                .filter(|running| session_id.is_none_or(|id| *id == running.session_id))
                .map(|running| (running.input.clone(), running.request_id))
        };
        let Some((input, request_id)) = running else {
            return Ok(false);
        };
        let mut input = input.lock().await;
        // Under the input lock no later command can be sent, so the Stop names
        // the running command or the one just answered, which is ignored.
        {
            let mut running = self.running.running.lock().unwrap();
            match running.as_mut() {
                Some(running) if running.request_id == request_id => running.stopping = true,
                _ => return Ok(false),
            }
        }
        let mut header = [0u8; 32];
        header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&5u16.to_le_bytes());
        header[8..16].copy_from_slice(&request_id.to_le_bytes());
        tokio::time::timeout(Duration::from_secs(5), async {
            input.write_all(&header).await?;
            input.flush().await
        })
        .await
        .map_err(|_| Error::new(503, "Native console did not accept the Stop"))?
        .map_err(|_| Error::new(503, "Native console disconnected before the Stop"))?;
        Ok(true)
    }
    async fn action(&self, request: &Value) -> Result<Value> {
        let action = request["action"].as_str().unwrap_or("");
        // A Stop never waits for the command it stops.
        if action == "interrupt" {
            return self.interrupt(request).await;
        }
        let _action = self
            .action
            .try_lock()
            .map_err(|_| Error::conflict("Another native console action is running"))?;
        // Only a read can hold the session here, and briefly: no command runs
        // without this action.
        let mut guard = self.session.lock().await;
        if action == "start" {
            // The experiment opt-in is optional so an existing caller that never
            // asks for it keeps working unchanged.
            let allowed: &[&str] = if request.get("document_start").is_some() {
                &["action", "url", "document_start"]
            } else {
                &["action", "url"]
            };
            validation::fields(request, allowed, "Native console start")?;
            if let Some(open) = guard.as_ref() {
                return Err(Error::conflict(already_open(open)));
            }
            if !self.available() {
                return Err(Error::new(
                    503,
                    "Native console requires its bundled helper and a rebuilt custom Brave executable",
                ).with_code(Code::DependencyUnavailable));
            }
            let address =
                validation::text(&request["url"], "Console URL", URL_LIMIT, false, false)?;
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
            if let Some(open) = guard.as_ref() {
                return Err(Error::conflict(already_open(open)));
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
            let (session, result) = self.bind_live(selected, binding).await?;
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
                return Err(Error::conflict(SESSION_CHANGED));
            }
            if let Some(mut session) = guard.take() {
                let ended = session.ended();
                if session.live && ended.is_none() {
                    if let Err(error) = session.release_live_values().await {
                        self.end(session, LOST_CLEANUP).await;
                        return Err(error);
                    }
                    // The capture browser keeps an armed set for as long as this
                    // wire connection stays open, so the binding is handed back
                    // only after the browser confirms it holds no script.
                    if session.document_start_armed
                        && let Err(error) = session.clear_document_start().await
                    {
                        self.end(session, LOST_DOCUMENT_START).await;
                        return Err(error);
                    }
                    session.live_target = None;
                    session.stale_target = None;
                    let mut live = self.live.lock().await;
                    if matches!(*live, LiveBridge::Connected) {
                        *live = LiveBridge::Ready(Box::new(session));
                    } else {
                        self.retire(session).await;
                    }
                } else if let Some(why) = ended.filter(|_| session.live) {
                    let unconfirmed = session.document_start_armed;
                    self.end(session, why).await;
                    if unconfirmed {
                        return Err(Error::conflict(DOCUMENT_START_UNCONFIRMED));
                    }
                } else {
                    self.retire(session).await;
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
        } else if action == "arm_document_start" || action == "add_document_start" {
            vec!["action", "session_id", "scripts", "confirm_document_start"]
        } else if action == "remove_document_start" {
            vec!["action", "session_id", "script_ids"]
        } else if action == "clear_document_start" {
            vec!["action", "session_id"]
        } else {
            return Err(Error::bad("Native console action is invalid"));
        };
        validation::fields(request, &allowed, "Native console action")?;
        let session = guard.as_mut().ok_or_else(|| {
            Error::conflict(if self.live_directory.is_some() {
                "Start a native console session first: read get_native_console for binding_id and a target id, then send connect_live with confirm_live true. No command was sent."
            } else {
                "Start a native console session first: send start with an authorized URL. No command was sent."
            })
        })?;
        if request["session_id"] != session.id {
            return Err(Error::conflict(SESSION_CHANGED));
        }
        if let Some(why) = session.ended() {
            self.end(guard.take().unwrap(), why).await;
            return Err(Error::conflict(
                "Native console session ended; start another session",
            ));
        }
        if action == "targets" && session.live {
            let result = session.list_live().await;
            if result.is_err() {
                self.end(guard.take().unwrap(), LOST_EXCHANGE).await;
            }
            return result;
        }
        let runtime_source;
        let document_start_source;
        let (operation, target, source) = if action == "targets" {
            (1, 0, "")
        } else if action.ends_with("_document_start") {
            if !session.document_start {
                if action == "clear_document_start" {
                    // Nothing can be armed in a session that never permitted
                    // the experiment, so report that instead of sending an
                    // operation this browser would reject.
                    return Ok(document_start_unavailable(
                        &session.id,
                        self.unavailable_message(session),
                    ));
                }
                return Err(Error::new(503, self.unavailable_message(session))
                    .with_code(Code::DependencyUnavailable));
            }
            document_start_source = if action == "clear_document_start" {
                r#"{"operation":"clear"}"#.to_owned()
            } else if action == "remove_document_start" {
                let ids = validate_script_ids(&request["script_ids"])?;
                serde_json::to_string(&json!({"operation":"remove","script_ids":ids}))?
            } else {
                if request["confirm_document_start"] != true {
                    return Err(Error::bad(
                        "Confirm that armed snippets run automatically in every new matching document",
                    ));
                }
                let scripts = validate_document_start(&request["scripts"])?;
                session.document_start_armed = true;
                let operation = if action == "arm_document_start" {
                    "arm"
                } else {
                    "add"
                };
                serde_json::to_string(&json!({"operation":operation,"scripts":scripts}))?
            };
            if document_start_source.len() > RECORD_LIMIT {
                return Err(Error::bad(
                    "Document-start command exceeds the 4 GiB a Console record can name as JSON; send its scripts in several add_document_start actions",
                )
                .with_code(Code::ResourceLimit));
            }
            (4, 0, document_start_source.as_str())
        } else if action == "runtime" {
            validate_command(&request["command"])?;
            runtime_source = serde_json::to_string(&request["command"])?;
            if runtime_source.len() > RECORD_LIMIT {
                return Err(Error::bad(
                    "Runtime command exceeds the 4 GiB a Console record can name as JSON",
                )
                .with_code(Code::ResourceLimit));
            }
            (
                3,
                validation::canonical(&request["target_id"], 64, true, "Console target")?,
                runtime_source.as_str(),
            )
        } else {
            let source =
                validation::text(&request["source"], "JavaScript", RECORD_LIMIT, false, true)?;
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
            if session.live_target != Some(target) {
                return Ok(not_selected(session, target));
            }
            if !session.native_targets.contains(&target) {
                session.live_target = None;
                session.stale_target = Some(target);
                return Ok(stale_document(&session.id, target));
            }
            if let Err(error) = session.list_live().await {
                self.end(guard.take().unwrap(), LOST_EXCHANGE).await;
                return Err(error);
            }
            if !session.native_targets.contains(&target) {
                return Ok(stale_document(&session.id, target));
            }
            session.accessed_targets.insert(target);
        }
        let mut result = if operation == 2 || operation == 3 {
            let state = self.running_state(session);
            let result = session
                .exchange_running(operation, target, source, Some((&self.running, state)))
                .await;
            *self.running.running.lock().unwrap() = None;
            result
        } else {
            session.exchange(operation, target, source).await
        };
        if session.live
            && let Ok(value) = result.as_mut()
            && value["status"] == "stale_target"
        {
            session.live_target = None;
            session.stale_target = Some(target);
            value["text"] = json!(stale_message(target));
        }
        let watch = request["command"]["operation"].as_str();
        if operation == 3 && matches!(watch, Some("watch" | "unwatch")) {
            // A refused watch leaves nothing armed (renderer/native_console_runtime.cc).
            let confirmed = result
                .as_ref()
                .ok()
                .filter(|value| watch == Some("watch") && value["runtime"]["status"] == "ok");
            session.watch = confirmed.map(|_| (target, request["command"]["rules"].clone()));
            // The browser replaces or clears its kept scope on every confirmed
            // watch and forgets it on any unwatch it receives; a refused watch
            // leaves it as it was.
            if watch == Some("unwatch") && result.is_ok() {
                session.kept = None;
            } else if let Some(value) = confirmed {
                session.kept = kept_scope(&value["runtime"]["kept"], &request["command"]["rules"])
                    .map(|kept| (target, kept));
            }
        } else if session.watch.as_ref().map(|(armed, _)| *armed) == session.stale_target {
            session.watch = None;
        }
        if result.is_err() {
            self.end(guard.take().unwrap(), LOST_EXCHANGE).await;
        }
        result
    }
    async fn arm_live_bridge(self: &Arc<Self>) {
        let Some(directory) = self.live_directory.clone() else {
            return;
        };
        if !private_directory(&directory) {
            return;
        }
        // Exactly one marker describes this arm, even in a reused directory,
        // so the launcher never reads an earlier backend's binding.
        let _ = std::fs::remove_file(directory.join("binding"));
        let _ = std::fs::remove_file(directory.join("binding.absent"));
        if !worker::executable(&self.helper) {
            write_absent(&directory);
            return;
        }
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
        self.handshake(bridge.session(ConsoleDir::Live(transport), true))
            .await;
    }
    // The capture browser launches only after it reads the binding, so its
    // first answer can take as long as browser startup. That wait happens here,
    // never in a state read or an action.
    async fn handshake(self: &Arc<Self>, mut session: Session) {
        *self.live.lock().await = LiveBridge::Connecting;
        let inner = self.clone();
        let task = tokio::spawn(async move {
            let listed = session.list_live().await;
            let mut live = inner.live.lock().await;
            if !matches!(*live, LiveBridge::Connecting) {
                session.stop().await;
            } else if listed.is_ok() {
                *live = LiveBridge::Ready(Box::new(session));
            } else {
                inner.lose(&mut live, Some(session), LOST_HANDSHAKE).await;
            }
        });
        *self.handshake.lock().unwrap() = Some(task.abort_handle());
    }
    async fn bind_live(&self, selected: u64, binding: u64) -> Result<(Session, Value)> {
        let mut live = self.live.lock().await;
        let session = match &mut *live {
            LiveBridge::Ready(session) => session,
            LiveBridge::Connecting => return Err(Error::conflict(LIVE_CONNECTING)),
            LiveBridge::Lost(why) => return Err(Error::conflict(lost_message(why))),
            LiveBridge::Absent | LiveBridge::Connected => {
                return Err(Error::conflict(
                    "The live capture has no native console binding. Restart the capture; a second browser profile was not launched.",
                ));
            }
        };
        if session.binding_id != binding.to_string() {
            return Err(Error::conflict(
                "Live capture binding changed; select and authorize a current document. Read get_native_console for the current binding_id.",
            ));
        }
        if let Some(why) = session.ended() {
            self.lose(&mut live, None, why).await;
            return Err(Error::conflict(lost_message(why)));
        }
        let mut listing = match session.list_live().await {
            Ok(listing) => listing,
            Err(error) => {
                self.lose(&mut live, None, LOST_EXCHANGE).await;
                return Err(error);
            }
        };
        if !session.native_targets.contains(&selected) {
            return Err(Error::conflict(format!(
                "Selected live document changed; explicitly select a current document. Document {selected} is not in the current listing: it was replaced or closed. Read get_native_console and pick a current id."
            )));
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
        session.stale_target = None;
        listing["session_id"] = json!(session.id);
        listing["selected_target_id"] = json!(selected.to_string());
        listing["selection"] = session.selection();
        let LiveBridge::Ready(session) = std::mem::replace(&mut *live, LiveBridge::Connected)
        else {
            unreachable!("the binding was ready above");
        };
        Ok((*session, listing))
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
            input: Arc::new(Mutex::new(self.input)),
            output: self.output,
            directory,
            next_request: 1,
            poisoned: false,
            live,
            live_target: None,
            stale_target: None,
            native_targets: BTreeSet::new(),
            accessed_targets: BTreeSet::new(),
            document_start: false,
            document_start_armed: false,
            watch: None,
            kept: None,
            listing: Value::Null,
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

const DOCUMENT_START_UNAVAILABLE: &str = "Document-start Console scripts are not available in this session, which started without \
     the permission. Start a disposable Console session with document_start enabled, or a new live session with \
     Allow document-start Console scripts in Advanced options of New Live Session… (an agent session: \
     start_live_session, unless document_start is false). Nothing is relaunched automatically.";

const DOCUMENT_START_BROWSER_UNSUPPORTED: &str = "This capture was started with the document-start permission, but its browser \
     does not advertise document-start support: it was built without the Native Console v3 overlay. Use a Brave \
     built from this checkout's pinned revisions. Nothing is relaunched automatically.";

const SESSION_CHANGED: &str = "Native console session changed: session_id does not name the open Console connection. \
     Read get_native_console for the current session_id. No command was sent.";

fn already_open(open: &Session) -> String {
    if open.live {
        format!(
            "A live Console connection is already open (session_id {}, document {}). To use another document, send stop with that session_id, then connect_live with the new target_id.",
            open.id,
            open.live_target
                .map(|target| target.to_string())
                .unwrap_or_else(|| "none".into())
        )
    } else {
        format!(
            "A disposable Console session is already open (session_id {}). Send stop with that session_id first.",
            open.id
        )
    }
}

/// Derived from the listing alone. The browser's target record carries no
/// parent frame and no renderer process, so a child frame is compared with
/// every listed top-level document; when they disagree the relation is
/// undetermined rather than guessed. Under Chromium's full site isolation a
/// cross-site child runs in its own renderer process, an out-of-process frame.
fn annotate_frames(targets: &mut [Value]) {
    let tops = targets
        .iter()
        .filter(|target| target["main_frame"] == true)
        .filter_map(|target| target["origin"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    for target in targets.iter_mut() {
        if target["main_frame"] == true {
            target["frame"] = json!("top");
            continue;
        }
        target["frame"] = json!("child");
        let origin = target["origin"].as_str().unwrap_or_default().to_owned();
        let mut relations = tops.iter().map(|top| frame_relation(&origin, top));
        let relation = match relations.next() {
            Some(first) if relations.all(|other| other == first) => first,
            _ => "undetermined",
        };
        target["top_relation"] = json!(relation);
        target["out_of_process"] = match relation {
            "cross_site" => json!(true),
            "same_origin" => json!(false),
            // Same-site frames normally share a process, but an
            // Origin-Agent-Cluster header can still isolate one.
            _ => Value::Null,
        };
    }
}

/// Schemeful same-site without the public suffix list: equal hosts, or equal
/// IP addresses, are same-site; a different scheme, an IP against a name, or
/// names whose last two labels differ are cross-site, because a registrable
/// domain always spans at least two labels. Two names that share their last
/// two labels need the list (`a.example.com` and `b.example.com` are
/// same-site, `a.github.io` and `b.github.io` are not), so they stay
/// undetermined. An opaque or non-HTTP origin is undetermined.
fn frame_relation(child: &str, top: &str) -> &'static str {
    let parse = |origin: &str| {
        url::Url::parse(origin)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https") && url.host().is_some())
    };
    let (Some(child_url), Some(top_url)) = (parse(child), parse(top)) else {
        return "undetermined";
    };
    if child == top {
        return "same_origin";
    }
    if child_url.scheme() != top_url.scheme() {
        return "cross_site";
    }
    match (child_url.host().unwrap(), top_url.host().unwrap()) {
        (url::Host::Domain(a), url::Host::Domain(b)) => {
            fn suffix(host: &str) -> Vec<&str> {
                host.rsplitn(3, '.').take(2).collect()
            }
            if a == b {
                "same_site"
            } else if suffix(a) != suffix(b) {
                "cross_site"
            } else {
                "undetermined"
            }
        }
        (url::Host::Domain(_), _) | (_, url::Host::Domain(_)) => "cross_site",
        (a, b) if a == b => "same_site",
        _ => "cross_site",
    }
}

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

// The record format's own bound, the page size reads use, and what the
// browser keeps for a reader that stops reading. Nothing counts scripts,
// snippet, rule or report bytes, records per document or execution time: a
// snippet runs until it returns, and removing it, clearing or replacing the
// set, or ending the session stops it.
fn document_start_limits() -> Value {
    json!({
        "record_bytes": RECORD_LIMIT,
        "page_bytes": PAGE_BYTES,
        "retained_bytes": DOCUMENT_START_RETAINED_BYTES,
    })
}

fn document_start_unavailable(session: &str, message: &str) -> Value {
    json!({"contract_version":4,"state":"ready","session_id":session,
        "document_start":{"status":"unavailable","permitted":false,"scripts":[],
            "message":message}})
}

// The browser revalidates every field and owns the rule grammar. These checks
// refuse an obviously wrong declaration before it reaches the wire, so a
// researcher sees which field is wrong instead of one opaque refusal.
fn validate_document_start(scripts: &Value) -> Result<Value> {
    let list = scripts
        .as_array()
        .ok_or_else(|| Error::bad("Document-start scripts must be an array"))?;
    if list.is_empty() {
        return Err(Error::bad("Arm at least one document-start script"));
    }
    let mut normalized = Vec::with_capacity(list.len());
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
            RECORD_LIMIT,
            false,
            false,
        )?;
        if !document_start_origin(origin) {
            return Err(Error::bad(
                "A document-start origin is one exact http:// or https:// origin as the browser serializes it: \
                 a lowercase host name, an IPv4 address or a canonical bracketed IPv6 address, and a port only \
                 when it is not the scheme's default. No path, credentials, wildcard or trailing slash.",
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
                RECORD_LIMIT,
                false,
                false,
            )?),
            None => None,
        };
        if let Some(prefix) = prefix
            && !document_start_path(prefix)
        {
            return Err(Error::bad(
                "A document-start path prefix is a literal printable-ASCII path starting with / and carries no query or fragment",
            ));
        }
        let source = validation::text(
            &script["source"],
            "Document-start snippet",
            RECORD_LIMIT,
            false,
            true,
        )?;
        if source.is_empty() || source.contains('\0') {
            return Err(Error::bad(
                "A document-start snippet must be nonempty and contain no NUL bytes",
            ));
        }
        let mut entry = json!({"origin":origin,"frame":frame,"source":source});
        if let Some(prefix) = prefix {
            entry["path_prefix"] = json!(prefix);
        }
        normalized.push(entry);
    }
    Ok(Value::Array(normalized))
}

// The armed ids to remove, as the browser lists them: decimal strings, each
// once.
fn validate_script_ids(ids: &Value) -> Result<Value> {
    let list = ids
        .as_array()
        .ok_or_else(|| Error::bad("script_ids must be an array of armed script ids"))?;
    if list.is_empty() {
        return Err(Error::bad("Name at least one armed script id to remove"));
    }
    let mut seen = BTreeSet::new();
    for id in list {
        let id = validation::canonical(id, 64, true, "Document-start script id")?;
        if !seen.insert(id) {
            return Err(Error::bad("Each script id is named once"));
        }
    }
    Ok(ids.clone())
}

// The browser's rule, IsValidNativeConsoleDocumentStartOrigin in
// common/native_console_document_start.h, ported line for line. Both test
// suites run tools/fixtures/console-document-start/rule-origins.txt, so an
// origin the backend admits is one the browser admits and one a document's
// url::Origin serialization can equal.
fn document_start_origin(origin: &str) -> bool {
    let (host, default_port) = if let Some(host) = origin.strip_prefix("http://") {
        (host, 80)
    } else if let Some(host) = origin.strip_prefix("https://") {
        (host, 443)
    } else {
        return false;
    };
    if host.is_empty() {
        return false;
    }
    let port = if let Some(literal) = host.strip_prefix('[') {
        let Some(close) = literal.find(']') else {
            return false;
        };
        if !canonical_ipv6(&literal[..close]) {
            return false;
        }
        match &literal[close + 1..] {
            "" => None,
            rest => match rest.strip_prefix(':') {
                Some(port) => Some(port),
                None => return false,
            },
        }
    } else {
        let (name, port) = match host.split_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        };
        if name.is_empty()
            || name.starts_with(['.', '-'])
            || name.ends_with(['.', '-'])
            || name.contains("..")
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
            })
            || !canonical_host_name(name)
        {
            return false;
        }
        port
    };
    let Some(port) = port else {
        return true;
    };
    if port.is_empty()
        || port.len() > 5
        || port.starts_with('0')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    // Serialize omits the scheme's default port, so spelling it never matches.
    port.parse::<u32>()
        .is_ok_and(|value| value <= 65535 && value != default_port)
}

// url::CanonicalizeIPv6Address output: lowercase hex groups without leading
// zeros, "::" for the first longest run of two or more zero groups, and no
// embedded IPv4. Any other spelling of the same address is refused.
fn canonical_ipv6(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut pieces = [0u16; 8];
    let mut count = 0;
    let mut compress = None;
    let mut index = 0;
    if text.starts_with("::") {
        compress = Some(0);
        index = 2;
    }
    while index < bytes.len() {
        if count == pieces.len() {
            return false;
        }
        let (mut value, mut digits) = (0u32, 0);
        while index < bytes.len() && digits < 5 {
            let digit = match bytes[index] {
                byte @ b'0'..=b'9' => byte - b'0',
                byte @ b'a'..=b'f' => byte - b'a' + 10,
                _ => break,
            };
            value = value * 16 + u32::from(digit);
            index += 1;
            digits += 1;
        }
        if digits == 0 || digits > 4 {
            return false;
        }
        pieces[count] = value as u16;
        count += 1;
        if index == bytes.len() {
            break;
        }
        if bytes[index] != b':' {
            return false;
        }
        index += 1;
        if index == bytes.len() {
            return false;
        }
        if bytes[index] == b':' {
            if compress.is_some() {
                return false;
            }
            compress = Some(count);
            index += 1;
        }
    }
    match compress {
        None if count != pieces.len() => return false,
        Some(_) if count >= pieces.len() => return false,
        Some(at) => {
            let gap = 8 - (count - at);
            pieces.copy_within(at..count, gap);
            pieces[at..gap].fill(0);
        }
        None => {}
    }
    let (mut best, mut best_length) = (pieces.len(), 1);
    let mut start = 0;
    while start < pieces.len() {
        if pieces[start] != 0 {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < pieces.len() && pieces[end] == 0 {
            end += 1;
        }
        if end - start > best_length {
            (best, best_length) = (start, end - start);
        }
        start = end;
    }
    let mut canonical = String::with_capacity(39);
    let mut piece = 0;
    while piece < pieces.len() {
        if piece == best {
            canonical.push_str(if piece == 0 { "::" } else { ":" });
            piece += best_length;
            continue;
        }
        canonical.push_str(&format!("{:x}", pieces[piece]));
        piece += 1;
        if piece < pieces.len() {
            canonical.push(':');
        }
    }
    canonical == text
}

// A host whose last label is a number serializes as four decimal octets.
fn canonical_host_name(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or(host);
    let numeric = !last.is_empty()
        && match last.strip_prefix("0x") {
            Some(hex) => hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            None => last.bytes().all(|byte| byte.is_ascii_digit()),
        };
    if !numeric {
        return true;
    }
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && !(octet.len() > 1 && octet.starts_with('0'))
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

// IsValidNativeConsoleDocumentStartPath for a declared prefix. An explicit
// empty prefix is refused before this, so a rule never shows a prefix it lacks.
fn document_start_path(path: &str) -> bool {
    path.starts_with('/')
        && path
            .bytes()
            .all(|byte| (0x21..0x7f).contains(&byte) && byte != b'?' && byte != b'#')
}

const LIVE_CAPTURE_MESSAGE: &str =
    "These documents come from the live capture. A second browser profile is not opened.";

const LIVE_CONNECTING: &str = "Waiting for the capture browser to connect its Console binding. \
     Its documents appear here once it answers. No second browser profile is opened.";

const LIVE_UNAVAILABLE: &str = "Live capture console binding unavailable. Rebuild the matching browser and backend, \
     then restart the capture. No second browser profile was launched.";

// Why a live binding ended, completing `lost_message`.
const LOST_EXCHANGE: &str =
    "a native exchange failed or timed out, and an ambiguous pipe is never reused";
const LOST_HANDSHAKE: &str = "the capture browser did not answer its first document listing";
const LOST_EXITED: &str = "its bridge process exited";
const LOST_CLEANUP: &str = "live value cleanup was not confirmed";
const LOST_DOCUMENT_START: &str =
    "the capture browser did not confirm clearing document-start scripts";
const LOST_STOPPED: &str = "the backend stopped";

fn lost_message(why: &str) -> String {
    format!(
        "The live capture's Console binding ended: {why}. The capture browser connects its binding once, \
         so restart the capture to use the live Console again. No second browser profile was launched."
    )
}

fn stale_message(target: u64) -> String {
    format!(
        "Selected document changed: document {target} was replaced or closed (navigation, reload or frame removal), which ended its authorization. Read get_native_console for current ids, then send stop and connect_live with the new document's id. Nothing was run."
    )
}

fn stale_document(session: &str, target: u64) -> Value {
    let mut result = json!({
        "contract_version": 2,
        "session_id": session,
        "state": "ready",
        "status": "stale_target",
        "type": "undefined",
        "text": stale_message(target),
    });
    Reason::new(Code::TargetUnavailable).annotate(&mut result);
    result
}

// A live connection runs commands only in the one document connect_live
// selected. Another id is refused before the wire, never remapped.
fn not_selected(session: &Session, target: u64) -> Value {
    if session.live_target.is_none()
        && let Some(stale) = session.stale_target
    {
        return stale_document(&session.id, stale);
    }
    let mut result = json!({
        "contract_version": 2,
        "session_id": session.id,
        "state": "ready",
        "status": "stale_target",
        "type": "undefined",
        "text": format!(
            "Selected document changed: document {target} is not the document this connection selected ({}). Live commands run only in the connect_live document; to use {target}, send stop, then connect_live with target_id {target}. Nothing was run.",
            session.live_target.map(|id| id.to_string()).unwrap_or_else(|| "none".into())
        ),
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

// What the browser said it keeps, with the rules it keeps: the confirmed set
// without its DOM rules, which name one document's nodes.
fn kept_scope(kept: &Value, rules: &Value) -> Option<Value> {
    let origin = kept["origin"].as_str()?;
    let frame = kept["frame"]
        .as_str()
        .filter(|frame| ["top", "child"].contains(frame))?;
    let mut rules = rules.clone();
    rules.as_object_mut()?.remove("dom");
    Some(json!({"origin": origin, "frame": frame, "rules": rules}))
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
        "poll" | "clear" | "last" | "traffic" | "unwatch" => &["operation"],
        "watch" if command.get("keep").is_some() => &["operation", "rules", "keep"],
        "watch" => &["operation", "rules"],
        _ => return Err(Error::bad("Invalid runtime operation")),
    };
    validation::fields(command, fields, "Runtime command")?;
    if operation == "watch" {
        crate::debugger_watch::validate(&command["rules"])?;
        if command.get("keep").is_some_and(|keep| !keep.is_boolean()) {
            return Err(Error::bad("keep must be true or false"));
        }
    }
    if operation == "evaluate" {
        let source = validation::text(&command["source"], "JavaScript", RECORD_LIMIT, false, true)?;
        if source.is_empty() || source.contains('\0') {
            return Err(Error::bad("JavaScript must be nonempty without NUL"));
        }
    }
    if fields.contains(&"handle") {
        validation::canonical(&command["handle"], 64, true, "Value handle")?;
    }
    // Any member position an array or typed array can have, up to 2^53 - 1,
    // which a JSON number holds exactly.
    if operation == "inspect"
        && !command["offset"]
            .as_u64()
            .is_some_and(|n| n <= 9_007_199_254_740_991)
    {
        return Err(Error::bad("Property offset must be 0 to 2^53 - 1"));
    }
    if operation == "complete" {
        let path = command["path"]
            .as_array()
            .ok_or_else(|| Error::bad("Completion path must be an array"))?;
        for key in path {
            validation::text(key, "Completion component", RECORD_LIMIT, false, false)?;
        }
        validation::text(
            &command["prefix"],
            "Completion prefix",
            RECORD_LIMIT,
            true,
            false,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn browser_work_deadline_grows_with_the_command() {
        assert_eq!(answer_deadline(true, 0), Duration::from_secs(35));
        assert_eq!(answer_deadline(false, 0), Duration::from_secs(6));
        assert_eq!(
            answer_deadline(false, (4 << 20) - 1),
            Duration::from_secs(6)
        );
        assert_eq!(answer_deadline(false, 64 << 20), Duration::from_secs(22));
        // A command at the record bound still has time to be read and parsed.
        assert_eq!(
            answer_deadline(false, u32::MAX as usize),
            Duration::from_secs(6 + 1023)
        );
    }

    #[test]
    fn frames_name_their_kind_and_relation_to_the_top_document() {
        for (child, top, relation) in [
            (
                "http://localhost:8001",
                "http://localhost:8001",
                "same_origin",
            ),
            (
                "http://localhost:8002",
                "http://localhost:8001",
                "same_site",
            ),
            (
                "http://127.0.0.1:8003",
                "http://localhost:8001",
                "cross_site",
            ),
            (
                "http://127.0.0.1:8003",
                "http://127.0.0.1:8001",
                "same_site",
            ),
            ("http://10.0.0.1", "http://127.0.0.1", "cross_site"),
            (
                "https://localhost:8001",
                "http://localhost:8001",
                "cross_site",
            ),
            (
                "https://assets.widget.test",
                "https://shop.example",
                "cross_site",
            ),
            (
                "https://a.example.com",
                "https://b.example.com",
                "undetermined",
            ),
            ("https://a.github.io", "https://b.github.io", "undetermined"),
            ("http://[::1]:8002", "http://[::1]:8001", "same_site"),
            ("null", "null", "undetermined"),
            ("null", "http://localhost:8001", "undetermined"),
        ] {
            assert_eq!(frame_relation(child, top), relation, "{child} in {top}");
        }
        let target = |id: &str, origin: &str, top: bool| json!({"id":id,"origin":origin,"label":"","url":"","main_frame":top});
        let mut listing = vec![
            target("1", "http://localhost:8001", true),
            target("2", "http://localhost:8002", false),
            target("3", "http://127.0.0.1:8003", false),
            target("4", "http://localhost:8001", false),
        ];
        annotate_frames(&mut listing);
        assert_eq!(listing[0]["frame"], "top");
        assert!(listing[0].get("top_relation").is_none());
        assert_eq!(
            (&listing[1]["top_relation"], &listing[1]["out_of_process"]),
            (&json!("same_site"), &Value::Null)
        );
        assert_eq!(
            (&listing[2]["top_relation"], &listing[2]["out_of_process"]),
            (&json!("cross_site"), &json!(true))
        );
        assert_eq!(
            (&listing[3]["top_relation"], &listing[3]["out_of_process"]),
            (&json!("same_origin"), &json!(false))
        );
        // Two tabs whose top documents disagree leave a child undetermined:
        // the listing has no parent link to choose between them.
        listing.push(target("5", "http://127.0.0.1:8003", true));
        annotate_frames(&mut listing);
        assert_eq!(listing[2]["top_relation"], "undetermined");
        assert_eq!(listing[2]["out_of_process"], Value::Null);
        // No top document listed: nothing to compare with.
        let mut orphan = vec![target("6", "http://127.0.0.1:8003", false)];
        annotate_frames(&mut orphan);
        assert_eq!(orphan[0]["top_relation"], "undetermined");
    }

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
        // No script count or snippet budget: an empty set is refused, but many
        // scripts and a large snippet are armed, and only the 4 GiB a record
        // names applies (checked where the command is serialized).
        let script = json!({"origin":"https://fixture.test","frame":"top","source":"report('x');"});
        assert!(validate_document_start(&json!([])).is_err());
        assert!(validate_document_start(&json!(script)).is_err());
        let many: Vec<Value> = (0..1000).map(|_| script.clone()).collect();
        assert_eq!(
            validate_document_start(&json!(many))
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1000
        );
        let long = json!({"origin":"https://fixture.test","frame":"top","source":"a".repeat(80 * 1024 * 1024)});
        assert!(validate_document_start(&json!([long, long])).is_ok());
        // Neither an origin nor a path prefix has a length bound.
        let host = format!("https://{}.test", "a".repeat(4096));
        let prefix = format!("/{}", "p".repeat(1024 * 1024));
        assert!(
            validate_document_start(
                &json!([{"origin":host,"frame":"top","path_prefix":prefix,"source":"report(1);"}])
            )
            .is_ok()
        );
        assert_eq!(
            validate_script_ids(&json!(["1", "20"])).unwrap(),
            json!(["1", "20"])
        );
        for refused in [
            json!([]),
            json!(["1", "1"]),
            json!(["01"]),
            json!([1]),
            json!("1"),
        ] {
            assert!(validate_script_ids(&refused).is_err(), "{refused}");
        }
        // The normalized command keeps exactly the declared rule.
        let armed = validate_document_start(&json!([{"origin":"http://127.0.0.1:8080","frame":"child","path_prefix":"/lab/","source":"report(1);"}])).unwrap();
        assert_eq!(
            armed,
            json!([{"origin":"http://127.0.0.1:8080","frame":"child","path_prefix":"/lab/","source":"report(1);"}])
        );
    }

    #[test]
    fn document_start_origins_match_the_browser_rule_case_for_case() {
        // The browser's offline check runs these same lines, so the backend
        // accepts and refuses exactly the origins the browser does.
        let cases = include_str!("../../../tools/fixtures/console-document-start/rule-origins.txt");
        let (mut accepted, mut refused) = (0, 0);
        for line in cases
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let (verdict, origin) = line.split_once(' ').unwrap();
            let rule = json!([{"origin":origin,"frame":"top","source":"report(1);"}]);
            match verdict {
                "accept" => {
                    assert!(document_start_origin(origin), "accepted: {origin}");
                    assert!(validate_document_start(&rule).is_ok(), "accepted: {origin}");
                    accepted += 1;
                }
                "refuse" => {
                    assert!(!document_start_origin(origin), "refused: {origin}");
                    assert!(validate_document_start(&rule).is_err(), "refused: {origin}");
                    refused += 1;
                }
                _ => panic!("unknown verdict: {line}"),
            }
        }
        assert!(
            accepted >= 20 && refused >= 60,
            "every shared origin case was read"
        );
        assert!(!document_start_origin(""));
        for path in ["/a/b-c_1.html", "/"] {
            assert!(document_start_path(path), "{path}");
        }
        for path in [
            "a",
            "../a",
            "/a?b",
            "/a#b",
            "/a b",
            "/a\u{7f}",
            "/a\n",
            "/caf\u{e9}",
        ] {
            assert!(!document_start_path(path), "{path:?}");
        }
        let long = format!("/{}", "a".repeat(1024 * 1024));
        assert!(document_start_path(&long));
    }

    #[test]
    fn document_start_states_match_their_published_contract() {
        let armed = json!({
            "contract_version": 4, "available": true, "state": "ready", "session_id": "12",
            "limits": document_start_limits(), "unsupported": document_start_unsupported(),
            "document_start": {
                "status": "ok", "permitted": true, "generation": "2", "renderer_processes": 2,
                "pending_renderer_processes": 1,
                "scripts": [{"script_id":"1","rule":{"origin":"https://fixture.test","frame":"top","path_prefix":"/lab/"},
                    "source_bytes": 24, "digest": "0123456789abcdef", "records": 3,
                    "injected_documents": 1, "refused": 0}],
                "output": {"records":[{"sequence":"3","record":"report","provenance":"console-document-start-script",
                    "script_id":"1","document_id":"7","frame_id":"99","top_frame":true,"time":1.0,
                    "text":"kinds=string:12"}],
                    "more":false,"next_sequence":"4","oldest_sequence":"1","retained":3,"retained_bytes":1120,
                    "dropped":0,"unattributed":0,"stale":0},
            },
        });
        crate::validation::schema("NativeConsoleDocumentStart", &armed, 500).unwrap();
        let mut unavailable = document_start_unavailable("12", DOCUMENT_START_UNAVAILABLE);
        unavailable["available"] = json!(false);
        unavailable["limits"] = document_start_limits();
        unavailable["unsupported"] = document_start_unsupported();
        crate::validation::schema("NativeConsoleDocumentStart", &unavailable, 500).unwrap();
        crate::validation::schema(
            "NativeConsoleDocumentStartResult",
            &document_start_unavailable("12", DOCUMENT_START_BROWSER_UNSUPPORTED),
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
        assert!(console.inner.session.lock().await.is_none());
    }

    #[tokio::test]
    async fn connect_live_does_not_launch_a_browser_when_the_capture_has_no_binding() {
        let directory = tempfile::tempdir().unwrap();
        let mut options = Options::try_parse_from([
            "origin-trace-backend",
            "--native-console-live-directory",
            directory.path().to_str().unwrap(),
        ])
        .unwrap();
        // --brave-binary also reads REB_BRAVE_BINARY, which a developer who runs
        // live checks has set; this case is a backend with no browser.
        options.brave_binary = None;
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
        assert!(console.inner.session.lock().await.is_none());
    }
    // A scripted pipe peer tests backend dispatch, not Blink/V8 behavior.
    async fn live_fixture() -> (NativeConsole, TempDir) {
        let (session, directory) = live_peer();
        let mut options = Options::try_parse_from(["origin-trace-backend"]).unwrap();
        options.native_console_live_directory = Some(directory.path().into());
        let console = NativeConsole::new(&options);
        console.inner.handshake(session).await;
        settle(&console).await;
        (console, directory)
    }
    fn live_peer() -> (Session, TempDir) {
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
import json, pathlib, struct, sys, time
root = pathlib.Path(sys.argv[1])
request = struct.Struct('<IHHQQII')
response = struct.Struct('<IHHQHHIII')
target_header = struct.Struct('<QIIIHH')
while True:
    header = sys.stdin.buffer.read(32)
    if not header:
        break
    magic, version, operation, sequence, target, size, reserved = request.unpack(header)
    source = sys.stdin.buffer.read(size).decode()
    with (root / 'requests.jsonl').open('a') as log:
        log.write(json.dumps({'operation':operation,'target':target,'source':source}) + '\n')
    count, kind, flags, wire_status = 0, 11, 0, 0
    # A slow browser answer, to hold an exchange open.
    delay = root / ('slow-listing' if operation == 1 else 'slow-command')
    if delay.exists():
        time.sleep(float(delay.read_text() or '1'))
    # A command that runs until the owner's Stop names it, as the bridge
    # forwards one while the command is in flight.
    stopped = operation in (2, 3) and (root / 'endless-command').exists()
    if stopped:
        stop = request.unpack(sys.stdin.buffer.read(32))
        with (root / 'requests.jsonl').open('a') as log:
            log.write(json.dumps({'operation':stop[2],'target':stop[4],'source':'','request':stop[3]}) + '\n')
        assert stop[2] == 5 and stop[3] == sequence and stop[4] == 0 and stop[5] == 0
        payload, kind, wire_status = b'Stopped; changes are not rolled back', 0, 7
    elif operation == 1:
        documents = json.loads((root / 'targets.json').read_text())
        records = []
        for item in documents:
            origin = b'https://same.test'
            label = b'Identical page'
            url = item['url'].encode()
            records.append(target_header.pack(item['id'],len(origin),len(label),len(url),2,0) + origin + label + url)
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
        if command['operation'] in ('arm', 'add'):
            first = 1 + max([int(script['script_id']) for script in scripts], default=0)
            added = [{'script_id':str(first + index),'rule':{'origin':script['origin'],'frame':script['frame']},
                      'source_bytes':len(script['source']),'digest':'0123456789abcdef','records':0,
                      'injected_documents':0,'refused':0} for index, script in enumerate(command['scripts'])]
            scripts = added if command['operation'] == 'arm' else scripts + added
        elif command['operation'] == 'remove':
            scripts = [script for script in scripts if script['script_id'] not in command['script_ids']]
        elif command['operation'] == 'clear':
            if (root / 'clear-refused').exists():
                status = 'error'
            else:
                scripts = []
        armed.write_text(json.dumps(scripts))
        payload, kind = json.dumps({'status':status,'contract_version':4,'permitted':True,'generation':'1',
            'scripts':scripts,'renderer_processes':1,'pending_renderer_processes':0}).encode(), 12
    elif '__renderer_gone__' in source:
        # The browser's per-command reply when the selected renderer's pipe drops.
        payload, kind, wire_status = b'Renderer disconnected', 0, 6
    else:
        reply = {'status':'ok','value':{'type':'object','text':str(target),'handle':'7'}}
        # The browser says what a confirmed watch keeps, from the document's own origin.
        command = json.loads(source) if operation == 3 else {}
        if command.get('operation') == 'watch' and command.get('keep'):
            reply['kept'] = {'origin':'https://same.test','frame':'top'}
        payload = json.dumps(reply).encode()
    sys.stdout.buffer.write(response.pack(magic,version,wire_status,sequence,kind,flags,count,len(payload),0) + payload)
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
            input: Arc::new(Mutex::new(input)),
            output,
            directory: ConsoleDir::Live(tempfile::tempdir().unwrap()),
            next_request: 1,
            poisoned: false,
            live: true,
            live_target: None,
            stale_target: None,
            native_targets: BTreeSet::new(),
            accessed_targets: BTreeSet::new(),
            document_start: false,
            document_start_armed: false,
            watch: None,
            kept: None,
            listing: Value::Null,
        };
        (session, directory)
    }
    async fn settle(console: &NativeConsole) {
        while matches!(*console.inner.live.lock().await, LiveBridge::Connecting) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn binding(console: &NativeConsole) -> &'static str {
        match console.inner.live.try_lock().as_deref() {
            Ok(LiveBridge::Ready(_)) => "ready",
            Ok(live) => live.name(),
            Err(_) => "locked",
        }
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
    async fn live_exact_ids_ignore_duplicate_urls_and_keep_metadata_whole() {
        let (console, directory) = live_fixture().await;
        let long_url = format!("https://same.test/{}", "a".repeat(1024 * 1024));
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
        assert_eq!(state["targets"][0]["url"], format!("{long_url}first"));
        assert_eq!(state["targets"][1]["url"], format!("{long_url}second"));
        assert_eq!(state["truncated"], false);
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
        if let LiveBridge::Ready(session) = &mut *console.inner.live.lock().await {
            session.binding_id = "99".into();
        }
        let before = requests(&directory).len();
        let error = console.action(&json!({"action":"connect_live","binding_id":"42","target_id":"22","confirm_live":true})).await.unwrap_err();
        assert_eq!(error.status, 409);
        assert_eq!(requests(&directory).len(), before);
        assert!(console.inner.session.lock().await.is_none());
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
    async fn live_selection_goes_stale_visibly_and_refusals_name_the_next_step() {
        let (console, directory) = live_fixture().await;
        let identity = connect_fixture(&console, "22").await;
        let listing = console.state().await;
        assert_eq!(
            listing["selection"],
            json!({"status":"selected","target_id":"22"})
        );
        // Another listed document is refused before the wire, not remapped.
        let before = requests(&directory).len();
        let other = console
            .action(
                &json!({"action":"evaluate","session_id":identity,"target_id":"11","source":"1"}),
            )
            .await
            .unwrap();
        assert_eq!(other["status"], "stale_target");
        assert!(
            other["text"]
                .as_str()
                .unwrap()
                .contains("connect_live with target_id 11")
        );
        assert_eq!(requests(&directory).len(), before);
        let busy = console
            .action(&json!({"action":"connect_live","binding_id":"42","target_id":"11","confirm_live":true}))
            .await
            .unwrap_err();
        assert!(busy.message.contains(&identity) && busy.message.contains("send stop"));
        // A navigation replaces document 22; the listing says so until stop.
        std::fs::write(
            directory.path().join("targets.json"),
            r#"[{"id":11,"url":"https://same.test/page"},{"id":33,"url":"https://same.test/page"}]"#,
        )
        .unwrap();
        let stale = console.state().await;
        assert!(stale["selected_target_id"].is_null());
        assert_eq!(stale["selection"]["status"], "stale");
        assert_eq!(stale["selection"]["target_id"], "22");
        let refused = console
            .action(
                &json!({"action":"evaluate","session_id":identity,"target_id":"22","source":"1"}),
            )
            .await
            .unwrap();
        assert!(
            refused["text"]
                .as_str()
                .unwrap()
                .contains("replaced or closed")
        );
        console
            .action(&json!({"action":"stop","session_id":identity}))
            .await
            .unwrap();
        assert_eq!(console.state().await["selection"], json!({"status":"none"}));
        // A session without the browser-session permission and a browser that
        // lacks the overlay are different next steps.
        let identity = connect_fixture(&console, "33").await;
        let arm = json!({"action":"arm_document_start","session_id":identity,"confirm_document_start":true,
            "scripts":[{"origin":"https://same.test","frame":"child","source":"report(1);"}]});
        let missing = console.action(&arm).await.unwrap_err();
        assert_eq!(missing.status, 503);
        assert!(
            missing
                .message
                .contains("Allow document-start Console scripts")
        );
        assert!(missing.message.contains("disposable Console session"));
        let mut console = console;
        Arc::get_mut(&mut console.inner)
            .expect("no task holds the console")
            .live_document_start_permitted = true;
        let unsupported = console.action(&arm).await.unwrap_err();
        assert!(
            unsupported
                .message
                .contains("without the Native Console v3 overlay")
        );
        let read = console.document_start(0).await.unwrap();
        assert_eq!(read["document_start"]["status"], "unavailable");
        assert!(
            read["document_start"]["message"]
                .as_str()
                .unwrap()
                .contains("without the Native Console v3 overlay")
        );
        console.stop().await;
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
        assert!(matches!(
            &*console.inner.live.lock().await,
            LiveBridge::Ready(session) if session.browser.is_none()
        ));
        let second = connect_fixture(&console, "11").await;
        assert_ne!(first, second);
        let before = requests(&directory).len();
        let error = console.action(&json!({"action":"runtime","session_id":first,"target_id":"22","command":{"operation":"inspect","handle":"7","offset":0}})).await.unwrap_err();
        assert_eq!(error.status, 409);
        assert_eq!(requests(&directory).len(), before);
        // Binding loss stays live/unavailable and cannot spawn or bind a replacement.
        console
            .inner
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
        assert_eq!(state["binding_state"], "lost");
        assert!(state["message"].as_str().unwrap().contains(LOST_EXITED));
        assert_eq!(state["targets"], json!([]));
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
        assert!(
            console
                .action(&json!({"action":"connect_live","binding_id":"42","target_id":"11","confirm_live":true}))
                .await
                .is_err()
        );
        assert_eq!(requests(&directory).len(), before);
        console.stop().await;
    }
    #[tokio::test]
    async fn live_watch_is_tracked_disarmed_on_stop_and_cleared_by_navigation() {
        let (console, directory) = live_fixture().await;
        let identity = connect_fixture(&console, "22").await;
        let rules = json!({"events":["click"],"exceptions":"uncaught"});
        let watch = |session: &str, operation: &str| {
            let mut command = json!({"operation": operation});
            if operation == "watch" {
                command["rules"] = rules.clone();
            }
            json!({"action":"runtime","session_id":session,"target_id":"22","command":command})
        };
        let none = json!({"armed": null, "kept": null});
        console.action(&watch(&identity, "watch")).await.unwrap();
        assert_eq!(
            console.watch().unwrap(),
            json!({"armed":{"session_id":identity,"target_id":"22","rules":rules},"kept":null})
        );
        console.action(&watch(&identity, "unwatch")).await.unwrap();
        assert_eq!(console.watch().unwrap(), none);
        console.action(&watch(&identity, "watch")).await.unwrap();
        console
            .action(&json!({"action":"stop","session_id":identity}))
            .await
            .unwrap();
        let sent: Vec<Value> = requests(&directory)
            .into_iter()
            .map(|request| request["source"].clone())
            .collect();
        let unwatch = sent.iter().rposition(|s| s == r#"{"operation":"unwatch"}"#);
        let clear = sent.iter().rposition(|s| s == r#"{"operation":"clear"}"#);
        assert!(unwatch.unwrap() < clear.unwrap(), "{sent:?}");
        assert_eq!(console.watch().unwrap(), none);

        // A kept scope: the browser names the document's origin and frame
        // kind, and the backend keeps the rules without their DOM rules.
        let second = connect_fixture(&console, "22").await;
        let mut keep = watch(&second, "watch");
        keep["command"]["keep"] = json!(true);
        keep["command"]["rules"]["dom"] = json!([{"handle":"7","removal":true}]);
        console.action(&keep).await.unwrap();
        let kept = json!({"origin":"https://same.test","frame":"top","rules":rules,
            "session_id":second,"target_id":"22"});
        assert_eq!(console.watch().unwrap()["kept"], kept);
        let mut refused = keep.clone();
        refused["command"]["keep"] = json!("yes");
        assert!(console.action(&refused).await.is_err());
        // Navigation ends the document's own arm; the scope stays, and Stop
        // still forgets it through that document.
        std::fs::write(
            directory.path().join("targets.json"),
            r#"[{"id":11,"url":"https://same.test/page"}]"#,
        )
        .unwrap();
        console.state().await;
        assert_eq!(console.watch().unwrap()["armed"], Value::Null);
        assert_eq!(console.watch().unwrap()["kept"], kept);
        let before = requests(&directory).len();
        console
            .action(&json!({"action":"stop","session_id":second}))
            .await
            .unwrap();
        let after = requests(&directory);
        assert!(
            after[before..]
                .iter()
                .any(|request| request["source"] == r#"{"operation":"unwatch"}"#
                    && request["target"] == 22),
            "{after:?}"
        );
        assert_eq!(console.watch().unwrap(), none);

        // A watch without keep on the same document clears the scope.
        let third = connect_fixture(&console, "11").await;
        let mut keep = watch(&third, "watch");
        keep["target_id"] = json!("11");
        keep["command"]["keep"] = json!(true);
        console.action(&keep).await.unwrap();
        assert_eq!(console.watch().unwrap()["kept"]["target_id"], "11");
        keep["command"].as_object_mut().unwrap().remove("keep");
        console.action(&keep).await.unwrap();
        assert_eq!(console.watch().unwrap()["kept"], Value::Null);
        assert_eq!(console.watch().unwrap()["armed"]["target_id"], "11");
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
    async fn live_add_and_remove_change_the_armed_set_without_replacing_it() {
        let (console, directory) = live_fixture().await;
        let identity = arm_fixture(&console, &directory).await;
        let ids = |result: &Value| {
            result["document_start"]["scripts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|script| script["script_id"].clone())
                .collect::<Vec<_>>()
        };
        let added = console
            .action(&json!({"action":"add_document_start","session_id":identity,"confirm_document_start":true,
                "scripts":[{"origin":"https://same.test","frame":"child","source":"report(2);"}]}))
            .await
            .unwrap();
        crate::validation::schema("NativeConsoleDocumentStartResult", &added, 500).unwrap();
        assert_eq!(ids(&added), [json!("1"), json!("2")]);
        let sent = requests(&directory).pop().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(sent["source"].as_str().unwrap()).unwrap()["operation"],
            "add"
        );
        // An add runs snippets as an arm does, so it needs the same
        // confirmation, and a malformed removal sends nothing.
        let before = requests(&directory).len();
        let error = console
            .action(&json!({"action":"add_document_start","session_id":identity,
                "scripts":[{"origin":"https://same.test","frame":"top","source":"report(3);"}]}))
            .await
            .unwrap_err();
        assert_eq!(error.status, 400);
        for script_ids in [
            json!([]),
            json!(["1", "1"]),
            json!(["01"]),
            json!([1]),
            json!("1"),
        ] {
            let error = console
                .action(&json!({"action":"remove_document_start","session_id":identity,"script_ids":script_ids}))
                .await
                .unwrap_err();
            assert_eq!(error.status, 400, "{script_ids}");
        }
        assert_eq!(requests(&directory).len(), before);
        let removed = console
            .action(
                &json!({"action":"remove_document_start","session_id":identity,"script_ids":["1"]}),
            )
            .await
            .unwrap();
        crate::validation::schema("NativeConsoleDocumentStartResult", &removed, 500).unwrap();
        assert_eq!(ids(&removed), [json!("2")]);
        assert_eq!(
            requests(&directory).pop().unwrap()["source"],
            r#"{"operation":"remove","script_ids":["1"]}"#
        );
        console.stop().await;
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
        assert_eq!(binding(&console), "lost");
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
        console
            .inner
            .session
            .lock()
            .await
            .as_mut()
            .unwrap()
            .poisoned = true;
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
    #[tokio::test]
    async fn a_renderer_that_goes_away_mid_command_does_not_end_the_live_binding() {
        let (console, directory) = live_fixture().await;
        let identity = connect_fixture(&console, "22").await;
        let gone = console
            .action(
                &json!({"action":"runtime","session_id":identity,"target_id":"22",
            "command":{"operation":"evaluate","source":"__renderer_gone__"}}),
            )
            .await
            .unwrap();
        assert_eq!(gone["status"], "disconnected");
        assert_eq!(gone["code"], "command_outcome_unknown");
        assert_eq!(gone["text"], "Renderer disconnected");
        let evaluations = |directory: &TempDir| {
            requests(directory)
                .iter()
                .filter(|request| request["operation"] == 3)
                .count()
        };
        assert_eq!(
            evaluations(&directory),
            1,
            "an unknown outcome is never retried"
        );
        let state = console.state().await;
        assert_eq!(state["session_id"], identity);
        assert_eq!(state["binding_state"], "connected");
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
        let next = console
            .action(
                &json!({"action":"runtime","session_id":identity,"target_id":"22",
            "command":{"operation":"evaluate","source":"1"}}),
            )
            .await
            .unwrap();
        assert_eq!(next["runtime"]["status"], "ok");
        console
            .action(&json!({"action":"stop","session_id":identity}))
            .await
            .unwrap();
        assert_eq!(binding(&console), "ready");
        console.stop().await;
    }
    #[tokio::test]
    async fn interrupt_stops_a_running_command_without_waiting_for_its_action() {
        let (console, directory) = live_fixture().await;
        let identity = connect_fixture(&console, "22").await;
        let interrupt = json!({"action":"interrupt","session_id":identity});
        // With nothing running, nothing is sent.
        let idle = console.action(&interrupt).await.unwrap();
        assert_eq!(idle["command"], "none");
        crate::validation::schema("NativeConsoleInterrupt", &idle, 500).unwrap();
        let stale = console
            .action(&json!({"action":"interrupt","session_id":"9"}))
            .await
            .unwrap_err();
        assert_eq!(stale.status, 409);
        std::fs::write(directory.path().join("endless-command"), "").unwrap();
        let inner = console.inner.clone();
        let evaluate = json!({"action":"runtime","session_id":identity,"target_id":"22",
            "command":{"operation":"evaluate","source":"for (;;);"}});
        let running = tokio::spawn(async move { inner.action(&evaluate).await });
        let state = loop {
            let state = console.state().await;
            if state.get("command").is_some() {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(state["command"]["status"], "running");
        assert_eq!(state["binding_state"], "connected");
        assert_eq!(state["selected_target_id"], "22");
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
        let request = state["command"]["request_id"].as_str().unwrap().to_owned();
        // Another action is refused while the command holds the session.
        let busy = console
            .action(&json!({"action":"targets","session_id":identity}))
            .await
            .unwrap_err();
        assert_eq!(busy.status, 409);
        let sent = console.action(&interrupt).await.unwrap();
        assert_eq!(sent["command"], "stopping");
        crate::validation::schema("NativeConsoleInterrupt", &sent, 500).unwrap();
        let stopped = running.await.unwrap().unwrap();
        assert_eq!(stopped["status"], "stopped");
        assert_eq!(stopped["code"], "cancelled");
        crate::validation::schema("NativeConsoleEvaluation", &stopped, 500).unwrap();
        let stop = requests(&directory)
            .into_iter()
            .find(|request| request["operation"] == 5)
            .unwrap();
        assert_eq!(stop["request"].to_string(), request);
        assert!(console.state().await.get("command").is_none());
        // The session stays usable after a stopped command.
        std::fs::remove_file(directory.path().join("endless-command")).unwrap();
        let next = console
            .action(
                &json!({"action":"runtime","session_id":identity,"target_id":"22",
                "command":{"operation":"evaluate","source":"1"}}),
            )
            .await
            .unwrap();
        assert_eq!(next["runtime"]["status"], "ok");
        console.stop().await;
    }
    #[tokio::test]
    async fn a_client_that_disconnects_mid_command_does_not_end_the_live_binding() {
        let (console, directory) = live_fixture().await;
        let identity = connect_fixture(&console, "22").await;
        std::fs::write(directory.path().join("slow-command"), "0.4").unwrap();
        let evaluate = json!({"action":"runtime","session_id":identity,"target_id":"22",
            "command":{"operation":"evaluate","source":"1"}});
        // The HTTP future is dropped while the browser is still answering.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), console.action(&evaluate))
                .await
                .is_err()
        );
        std::fs::remove_file(directory.path().join("slow-command")).unwrap();
        // The command finishes on its own. A read reports it while it runs
        // rather than waiting for it.
        let state = console.state().await;
        assert_eq!(state["state"], "ready");
        assert_eq!(state["session_id"], identity);
        assert_eq!(state["binding_state"], "connected");
        assert_eq!(state["command"]["status"], "running");
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
        while console.state().await.get("command").is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let before = requests(&directory).len();
        let next = console.action(&evaluate).await.unwrap();
        assert_eq!(next["runtime"]["status"], "ok");
        assert_eq!(
            requests(&directory)[before..]
                .iter()
                .filter(|request| request["operation"] == 3)
                .count(),
            1
        );
        console.stop().await;
    }
    #[tokio::test]
    async fn state_reads_wait_for_actions_instead_of_failing_them() {
        let (console, directory) = live_fixture().await;
        let console = Arc::new(console);
        std::fs::write(directory.path().join("slow-listing"), "0.3").unwrap();
        let reader = console.clone();
        let read = tokio::spawn(async move { reader.state().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Connecting waits for the read's listing instead of failing.
        let identity = connect_fixture(&console, "22").await;
        assert_eq!(read.await.unwrap()["binding_state"], "ready");
        std::fs::remove_file(directory.path().join("slow-listing")).unwrap();
        // A connected read lists once, so the selection it reports is current.
        let before = requests(&directory).len();
        let state = console.state().await;
        assert_eq!(state["binding_state"], "connected");
        assert_eq!(state["selected_target_id"], "22");
        assert_eq!(state["targets"][1]["id"], "22");
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
        let listed = &requests(&directory)[before..];
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["operation"], 1);
        // A read during a running command waits for it and leaves it alone.
        std::fs::write(directory.path().join("slow-command"), "0.3").unwrap();
        let actor = console.clone();
        let command = tokio::spawn(async move {
            actor
                .action(
                    &json!({"action":"runtime","session_id":identity,"target_id":"22",
                "command":{"operation":"evaluate","source":"1"}}),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(console.state().await["binding_state"], "connected");
        assert_eq!(command.await.unwrap().unwrap()["runtime"]["status"], "ok");
        console.stop().await;
    }
    #[tokio::test]
    async fn the_first_browser_answer_waits_in_the_handshake_and_a_failed_one_is_reported() {
        let (session, directory) = live_peer();
        std::fs::write(directory.path().join("slow-listing"), "0.4").unwrap();
        let mut options = Options::try_parse_from(["origin-trace-backend"]).unwrap();
        options.native_console_live_directory = Some(directory.path().into());
        let console = NativeConsole::new(&options);
        console.inner.handshake(session).await;
        let started = std::time::Instant::now();
        let state = console.state().await;
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "a read never waits for the browser"
        );
        assert_eq!(state["binding_state"], "connecting");
        assert_eq!(state["live_available"], false);
        assert!(
            state["message"]
                .as_str()
                .unwrap()
                .contains("Waiting for the capture browser")
        );
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
        let error = console
            .action(&json!({"action":"connect_live","binding_id":"42","target_id":"22","confirm_live":true}))
            .await
            .unwrap_err();
        assert_eq!(error.status, 409);
        std::fs::remove_file(directory.path().join("slow-listing")).unwrap();
        settle(&console).await;
        let state = console.state().await;
        assert_eq!(state["binding_state"], "ready");
        assert_eq!(state["targets"][1]["id"], "22");
        console.stop().await;
        assert_eq!(console.state().await["binding_state"], "lost");

        // A bridge that never answers is reported lost, with why.
        let (mut session, directory) = live_peer();
        session.bridge.stop().await;
        let mut options = Options::try_parse_from(["origin-trace-backend"]).unwrap();
        options.native_console_live_directory = Some(directory.path().into());
        let console = NativeConsole::new(&options);
        console.inner.handshake(session).await;
        settle(&console).await;
        let state = console.state().await;
        assert_eq!(state["binding_state"], "lost");
        let message = state["message"].as_str().unwrap();
        assert!(message.contains(LOST_HANDSHAKE), "{message}");
        assert!(message.contains("restart the capture"), "{message}");
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
        let error = console
            .action(&json!({"action":"connect_live","binding_id":"42","target_id":"22","confirm_live":true}))
            .await
            .unwrap_err();
        assert!(error.message.contains(LOST_HANDSHAKE), "{}", error.message);
    }
    #[tokio::test]
    async fn arming_in_a_reused_directory_leaves_exactly_one_marker() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            directory.path().join("binding"),
            "1\n/tmp/earlier/console.sock\n/tmp/earlier/token\n",
        )
        .unwrap();
        let options = Options::try_parse_from([
            "origin-trace-backend",
            "--native-console",
            "/nonexistent/reb-console",
            "--native-console-live-directory",
            directory.path().to_str().unwrap(),
        ])
        .unwrap();
        let console = NativeConsole::new(&options);
        console.arm_live_bridge().await;
        assert!(!directory.path().join("binding").exists());
        assert!(directory.path().join("binding.absent").is_file());
        let state = console.state().await;
        assert_eq!(state["binding_state"], "absent");
        crate::validation::schema("NativeConsoleState", &state, 500).unwrap();
    }
    #[test]
    fn retired_session_does_not_claim_the_command_had_no_effect() {
        for (status, cause) in [(5u16, "timeout"), (6, "disconnected")] {
            let mut bytes = [0; 32];
            bytes[..4].copy_from_slice(&MAGIC.to_le_bytes());
            bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
            bytes[6..8].copy_from_slice(&status.to_le_bytes());
            bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
            let error = ResponseHeader::parse(&bytes, 1, 2).err().unwrap();
            assert_eq!(error.status, 409);
            assert_eq!(error.reason.code, Code::CommandOutcomeUnknown);
            assert_eq!(
                serde_json::to_value(error).unwrap()["details"],
                json!({"phase":"command_exchange","cause":cause})
            );
            // With text it is one command's unknown outcome, and the
            // connection stays usable.
            bytes[24..28].copy_from_slice(&21u32.to_le_bytes());
            let parsed = ResponseHeader::parse(&bytes, 1, 2).unwrap();
            let result = parsed.value(b"Renderer disconnected", "1").unwrap();
            assert_eq!(result["code"], "command_outcome_unknown");
            assert_eq!(result["details"]["cause"], cause);
        }
    }
}
