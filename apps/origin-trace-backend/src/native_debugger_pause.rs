//! The pausing debugger's command socket, protocol/native-debugger-pause-v1.md.
//!
//! The HTTP routes speak a bounded private socket to the browser. This module
//! also holds the contract peer the tests drive: a deterministic fixture page
//! that really pauses, steps and resumes, so the backend, the projection and
//! the interface are exercised against the exact contract. No Brave build
//! serves the real peer yet, so without a socket the state is `unsupported`
//! and every action is refused before anything is sent.

use crate::{
    error::{Cause, Code, Error, Reason, Result},
    validation,
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub const LEASE_LIMIT_MS: u64 = 60_000;
/// The request-stack bounds, so one reader fits a pause stack and a request
/// stack: 1,024 synchronous frames and 32 async frames, indices 0 to 1,055.
pub const FRAME_LIMIT: usize = 1_024;
pub const ASYNC_FRAME_LIMIT: usize = 32;
pub const SCOPE_LIMIT: usize = 8;
pub const BREAKPOINT_LIMIT: usize = 64;
/// The notice a state read and every action result carry while a document is
/// selected, in the same words the browser and the interface use.
const ACTIVE_INDICATION: &str = "Debugger active (detectable)";
pub const VALUE_TEXT_BYTES: usize = 2_048;
pub const NAME_BYTES: usize = 128;
pub const PROPERTY_PAGE: usize = 64;
pub const PROPERTY_LIMIT: usize = 4_096;
pub const OBJECT_LIMIT: usize = 1_024;

const MAGIC: u32 = 0x4442_4552;
const VERSION: u16 = 1;
const REQUEST_HEADER: usize = 48;
const RESPONSE_HEADER: usize = 32;
const MAX_REQUEST_PAYLOAD: usize = 16_384;
const MAX_RESPONSE_PAYLOAD: usize = 1_048_576;

const OP_STATE: u16 = 1;
const OP_SELECT_DOCUMENT: u16 = 2;
const OP_RELEASE_DOCUMENT: u16 = 3;
const OP_SET_BREAKPOINT: u16 = 4;
const OP_REMOVE_BREAKPOINT: u16 = 5;
const OP_PAUSE_ON_EXCEPTIONS: u16 = 6;
const OP_PAUSE: u16 = 7;
const OP_RESUME: u16 = 8;
const OP_STEP_OVER: u16 = 9;
const OP_STEP_INTO: u16 = 10;
const OP_STEP_OUT: u16 = 11;
const OP_RELEASE_LEASE: u16 = 12;
const OP_EVALUATE_ON_FRAME: u16 = 13;
const OP_GET_PROPERTIES: u16 = 14;

/// Action name to operation code. The peer echoes the action and the backend
/// refuses a reply that names another, so a routing mistake cannot look like
/// a different command's success.
fn operation(action: &str) -> Option<u16> {
    Some(match action {
        "select_document" => OP_SELECT_DOCUMENT,
        "release_document" => OP_RELEASE_DOCUMENT,
        "set_breakpoint" => OP_SET_BREAKPOINT,
        "remove_breakpoint" => OP_REMOVE_BREAKPOINT,
        "pause_on_exceptions" => OP_PAUSE_ON_EXCEPTIONS,
        "pause" => OP_PAUSE,
        "resume" => OP_RESUME,
        "step_over" => OP_STEP_OVER,
        "step_into" => OP_STEP_INTO,
        "step_out" => OP_STEP_OUT,
        "release_lease" => OP_RELEASE_LEASE,
        "evaluate_on_frame" => OP_EVALUATE_ON_FRAME,
        "get_properties" => OP_GET_PROPERTIES,
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    Malformed,
    StaleDocument,
    NotAuthorized,
    NotPaused,
    StaleLease,
    UnknownBreakpoint,
    UnknownObject,
    Limit,
    InvalidInput,
    EvaluationError,
    Unsupported,
    Busy,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Malformed => "malformed",
            Self::StaleDocument => "stale_document",
            Self::NotAuthorized => "not_authorized",
            Self::NotPaused => "not_paused",
            Self::StaleLease => "stale_lease",
            Self::UnknownBreakpoint => "unknown_breakpoint",
            Self::UnknownObject => "unknown_object",
            Self::Limit => "limit",
            Self::InvalidInput => "invalid_input",
            Self::EvaluationError => "evaluation_error",
            Self::Unsupported => "unsupported",
            Self::Busy => "busy",
        }
    }
    fn code(self) -> u16 {
        match self {
            Self::Ok => 0,
            Self::Malformed => 1,
            Self::StaleDocument => 2,
            Self::NotAuthorized => 3,
            Self::NotPaused => 4,
            Self::StaleLease => 5,
            Self::UnknownBreakpoint => 6,
            Self::UnknownObject => 7,
            Self::Limit => 8,
            Self::InvalidInput => 9,
            Self::EvaluationError => 10,
            Self::Unsupported => 11,
            Self::Busy => 12,
        }
    }
    fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            0 => Self::Ok,
            1 => Self::Malformed,
            2 => Self::StaleDocument,
            3 => Self::NotAuthorized,
            4 => Self::NotPaused,
            5 => Self::StaleLease,
            6 => Self::UnknownBreakpoint,
            7 => Self::UnknownObject,
            8 => Self::Limit,
            9 => Self::InvalidInput,
            10 => Self::EvaluationError,
            11 => Self::Unsupported,
            12 => Self::Busy,
            _ => return None,
        })
    }
}

/// The pausing half of `NativeDebuggerState` when no peer can answer. The
/// phase 1 fields are merged over this by `native_debugger::state`.
fn unsupported_state(reason: &str) -> Value {
    json!({
        "availability": "unsupported",
        "reason": reason,
        "active_indication": Value::Null,
        "quiet_mode": Value::Null,
        "document": Value::Null,
        "last_clear": Value::Null,
        "exceptions": "none",
        "breakpoints": [],
        "lease": Value::Null,
        "paused": false,
        "pause": Value::Null,
    })
}

#[derive(Clone)]
pub struct NativeDebuggerPause {
    socket: Option<PathBuf>,
}

impl NativeDebuggerPause {
    pub fn new(socket: Option<PathBuf>) -> Self {
        Self { socket }
    }

    /// The pausing fields of the debugger state. One `state` command, which
    /// never pauses, steps, resumes or renews a lease.
    pub fn state(&self) -> Value {
        let Some(socket) = &self.socket else {
            return unsupported_state("browser_debugger_unsupported");
        };
        match exchange(socket, OP_STATE, 0, 0, &[]) {
            Ok(reply) => match available_state(reply) {
                Some(value) => value,
                None => unsupported_state("peer_unavailable"),
            },
            Err(_) => unsupported_state("peer_unavailable"),
        }
    }

    /// One command. Every refusal before the socket write says plainly that
    /// nothing was sent; an interrupted exchange says the outcome is unknown
    /// and is never retried.
    pub fn action(&self, value: &Value) -> Result<Value> {
        let action = value["action"].as_str().unwrap_or_default();
        let Some(op) = operation(action) else {
            return Err(Error::bad("Native debugger action is invalid"));
        };
        let Some(socket) = &self.socket else {
            return Err(Error::new(
                503,
                "No Brave build serves the native debugger. Nothing was sent; no page paused, stepped or resumed.",
            )
            .with_code(Code::DependencyUnavailable));
        };
        let target = validation::canonical(&value["target_id"], 64, true, "Target ID")?;
        let lease = match value.get("lease_id") {
            Some(id) => validation::canonical(id, 64, true, "Lease ID")?,
            None => 0,
        };
        let payload = serde_json::to_vec(value).map_err(|_| Error::bad("Action is not JSON"))?;
        if payload.len() > MAX_REQUEST_PAYLOAD {
            return Err(Error::bad("Native debugger action is too large"));
        }
        let reply = exchange(socket, op, target, lease, &payload)?;
        let body = reply.body;
        if body["action"] != action {
            return Err(uncertain(
                Cause::InvalidReply,
                "The native debugger peer reply did not match the action. Whether the command ran is unknown.",
            ));
        }
        if body["status"] != reply.status.as_str()
            || body["paused"] != json!(reply.paused)
            || body["resumed"] != json!(reply.resumed)
        {
            return Err(uncertain(
                Cause::InvalidReply,
                "The native debugger peer reply disagreed with its header. Whether the command ran is unknown.",
            ));
        }
        // A reply this contract does not define is a peer that cannot be
        // read, like one whose body disagrees with its header: the client
        // gets that named outcome and the validator's own words, not a 500
        // that reads as a fault in this backend.
        if let Err(invalid) = validation::schema("NativeDebuggerActionResult", &body, 500) {
            return Err(uncertain(
                Cause::InvalidReply,
                &format!(
                    "The native debugger peer reply does not match this contract: {}. \
                     Whether the command ran is unknown.",
                    invalid.message
                ),
            ));
        }
        Ok(body)
    }
}

/// A `state` reply must not claim it changed anything, and it must carry the
/// pausing fields. Anything else is a peer that cannot be read, not an idle
/// debugger with no breakpoints.
fn available_state(reply: Reply) -> Option<Value> {
    if reply.status != Status::Ok || reply.resumed {
        return None;
    }
    let mut body = reply.body;
    let object = body.as_object_mut()?;
    if object.get("paused")? != &json!(reply.paused) {
        return None;
    }
    object.insert("availability".into(), json!("available"));
    object.insert("reason".into(), Value::Null);
    for field in [
        "active_indication",
        "quiet_mode",
        "document",
        "last_clear",
        "exceptions",
        "breakpoints",
        "lease",
        "pause",
    ] {
        object.get(field)?;
    }
    object.retain(|key, _| {
        [
            "availability",
            "reason",
            "active_indication",
            "quiet_mode",
            "document",
            "last_clear",
            "exceptions",
            "breakpoints",
            "lease",
            "paused",
            "pause",
        ]
        .contains(&key.as_str())
    });
    Some(body)
}

fn unavailable(message: &str) -> Error {
    Error::new(503, message).with_code(Code::DependencyUnavailable)
}

fn uncertain(cause: Cause, message: &str) -> Error {
    let status = if matches!(cause, Cause::Timeout) {
        408
    } else {
        422
    };
    Error::new(status, message).with_reason(Reason::uncertain(cause))
}

struct Reply {
    status: Status,
    paused: bool,
    resumed: bool,
    body: Value,
}

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

fn exchange(socket: &Path, op: u16, target: u64, lease: u64, payload: &[u8]) -> Result<Reply> {
    trusted_socket(socket)?;
    let mut stream = UnixStream::connect(socket).map_err(|_| {
        unavailable(
            "The native debugger peer is not available. Nothing was sent; no page paused, stepped or resumed.",
        )
    })?;
    silence_sigpipe(&stream);
    let timed = stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(2))));
    timed.map_err(|_| unavailable("The native debugger peer could not be timed."))?;
    let id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let mut request = Vec::with_capacity(REQUEST_HEADER + payload.len());
    request.extend_from_slice(&MAGIC.to_le_bytes());
    request.extend_from_slice(&VERSION.to_le_bytes());
    request.extend_from_slice(&op.to_le_bytes());
    request.extend_from_slice(&id.to_le_bytes());
    request.extend_from_slice(&target.to_le_bytes());
    // The document generation is the target id itself, so these eight bytes
    // stay zero rather than carrying a second identity the two sides could
    // disagree about.
    request.extend_from_slice(&0u64.to_le_bytes());
    request.extend_from_slice(&lease.to_le_bytes());
    let length = u32::try_from(payload.len())
        .map_err(|_| Error::bad("Native debugger action is too large"))?;
    request.extend_from_slice(&length.to_le_bytes());
    request.extend_from_slice(&0u32.to_le_bytes());
    request.extend_from_slice(payload);
    write_all(&mut stream, &request).map_err(|_| {
        uncertain(
            Cause::Disconnected,
            "The native debugger peer disconnected after the command was sent. Whether it ran is unknown.",
        )
    })?;
    let mut header = [0u8; RESPONSE_HEADER];
    stream.read_exact(&mut header).map_err(|error| {
        let cause = if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            Cause::Timeout
        } else {
            Cause::Disconnected
        };
        uncertain(
            cause,
            "The native debugger peer did not finish its reply. Whether the command ran is unknown.",
        )
    })?;
    let malformed = || {
        uncertain(
            Cause::InvalidReply,
            "The native debugger peer reply was malformed. Whether the command ran is unknown.",
        )
    };
    let response = decode_response(&header).ok_or_else(malformed)?;
    if response.id != id {
        return Err(malformed());
    }
    let mut body = vec![0u8; response.payload_len];
    if response.payload_len > 0 {
        stream.read_exact(&mut body).map_err(|_| {
            uncertain(
                Cause::Disconnected,
                "The native debugger peer reply was truncated. Whether the command ran is unknown.",
            )
        })?;
    }
    if response.status == Status::Malformed {
        return Err(uncertain(
            Cause::InvalidReply,
            "The native debugger peer rejected the command framing. Nothing it had already done changed.",
        ));
    }
    let body: Value = serde_json::from_slice(&body).map_err(|_| {
        uncertain(
            Cause::InvalidReply,
            "The native debugger peer reply was not JSON. Whether the command ran is unknown.",
        )
    })?;
    if !body.is_object() {
        return Err(malformed());
    }
    Ok(Reply {
        status: response.status,
        paused: response.paused,
        resumed: response.resumed,
        body,
    })
}

struct ResponseHeader {
    id: u64,
    status: Status,
    paused: bool,
    resumed: bool,
    payload_len: usize,
}

fn decode_response(bytes: &[u8; RESPONSE_HEADER]) -> Option<ResponseHeader> {
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
    let status = Status::from_code(u16::from_le_bytes(bytes[6..8].try_into().ok()?))?;
    let id = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let paused = match bytes[16] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let flags = u16::from_le_bytes(bytes[18..20].try_into().ok()?);
    let payload_len = u32::from_le_bytes(bytes[20..24].try_into().ok()?) as usize;
    let tail = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
    if magic != MAGIC
        || version != VERSION
        || id == 0
        || bytes[17] != 0
        || flags > 1
        || tail != 0
        || payload_len > MAX_RESPONSE_PAYLOAD
    {
        return None;
    }
    Some(ResponseHeader {
        id,
        status,
        paused,
        resumed: flags == 1,
        payload_len,
    })
}

fn write_all(stream: &mut UnixStream, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    stream.write_all(bytes)?;
    stream.flush()
}

fn silence_sigpipe(stream: &UnixStream) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let one: libc::c_int = 1;
        // SAFETY: a live socket descriptor and a correctly sized option value.
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                std::ptr::from_ref(&one).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let _ = stream;
}

/// Same checks as the live Wasm socket: a user-only socket in a user-only
/// directory, neither of them a symlink.
fn trusted_socket(path: &Path) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let parent = path
        .parent()
        .ok_or_else(|| unavailable("The native debugger socket is not in a private directory."))?;
    let directory = std::fs::symlink_metadata(parent)
        .map_err(|_| unavailable("The native debugger socket is not available."))?;
    let socket = std::fs::symlink_metadata(path)
        .map_err(|_| unavailable("The native debugger socket is not available."))?;
    if !directory.is_dir()
        || directory.uid() != uid
        || directory.permissions().mode() & 0o077 != 0
        || socket.file_type().is_symlink()
        || !socket.file_type().is_socket()
        || socket.uid() != uid
        || socket.permissions().mode() & 0o777 != 0o600
    {
        return Err(unavailable(
            "The native debugger socket is not a private user socket. Nothing was sent.",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Contract peer
// ---------------------------------------------------------------------------
//
// A deterministic fixture document that really pauses, steps and resumes, so
// every status and bound in the contract is exercised without a browser. It
// is not a JavaScript engine: it runs the fixed program below over a tiny
// expression evaluator, which is enough to make a conditional breakpoint, a
// scope read and a step mean what they mean in the contract.

pub const FIXTURE_TARGET: u64 = 22;
pub const FIXTURE_CHILD_TARGET: u64 = 23;
pub const FIXTURE_SCRIPT_ID: u32 = 11;
pub const FIXTURE_SOURCE: &str = "\
function add(a, b) {
  return a + b;
}
function collect(items) {
  let total = 0;
  for (const item of items) {
    total = add(total, item);
  }
  return total;
}
collect([1, 2, 3]);
";

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Undefined,
    Int(i64),
    Str(String),
    Arr(Vec<i64>),
}

impl Val {
    fn kind(&self) -> &'static str {
        match self {
            Self::Undefined => "undefined",
            Self::Int(_) => "number",
            Self::Str(_) => "string",
            Self::Arr(_) => "object",
        }
    }
    fn text(&self) -> String {
        match self {
            Self::Undefined => "undefined".into(),
            Self::Int(value) => value.to_string(),
            Self::Str(value) => format!("\"{value}\""),
            Self::Arr(values) => {
                let inner: Vec<String> = values.iter().take(8).map(i64::to_string).collect();
                let more = if values.len() > 8 { ", ..." } else { "" };
                format!("Array({}) [{}{more}]", values.len(), inner.join(", "))
            }
        }
    }
    fn truthy(&self) -> bool {
        match self {
            Self::Undefined => false,
            Self::Int(value) => *value != 0,
            Self::Str(value) => !value.is_empty(),
            Self::Arr(_) => true,
        }
    }
}

enum Inst {
    /// `name = <expr>` at this line.
    Set {
        line: u32,
        name: &'static str,
        expr: &'static str,
    },
    /// Resets the hidden cursor of a `for of` loop.
    IterInit {
        line: u32,
        cursor: &'static str,
    },
    /// Binds the next element or jumps past the loop.
    IterNext {
        line: u32,
        cursor: &'static str,
        list: &'static str,
        var: &'static str,
        exit: usize,
    },
    Jump {
        target: usize,
    },
    Call {
        line: u32,
        function: usize,
        args: &'static [&'static str],
        result: &'static str,
    },
    Return {
        line: u32,
        expr: &'static str,
    },
}

impl Inst {
    fn line(&self) -> u32 {
        match self {
            Self::Set { line, .. }
            | Self::IterInit { line, .. }
            | Self::IterNext { line, .. }
            | Self::Call { line, .. }
            | Self::Return { line, .. } => *line,
            // A loop's back edge is not a statement boundary of its own.
            Self::Jump { .. } => 0,
        }
    }
}

struct Function {
    name: &'static str,
    params: &'static [&'static str],
    code: &'static [Inst],
}

const ADD: usize = 0;
const COLLECT: usize = 1;
const MAIN: usize = 2;

static PROGRAM: [Function; 3] = [
    Function {
        name: "add",
        params: &["a", "b"],
        code: &[Inst::Return {
            line: 2,
            expr: "a + b",
        }],
    },
    Function {
        name: "collect",
        params: &["items"],
        code: &[
            Inst::Set {
                line: 5,
                name: "total",
                expr: "0",
            },
            Inst::IterInit {
                line: 6,
                cursor: "#cursor",
            },
            Inst::IterNext {
                line: 6,
                cursor: "#cursor",
                list: "items",
                var: "item",
                exit: 5,
            },
            Inst::Call {
                line: 7,
                function: ADD,
                args: &["total", "item"],
                result: "total",
            },
            Inst::Jump { target: 2 },
            Inst::Return {
                line: 9,
                expr: "total",
            },
        ],
    },
    Function {
        name: "(anonymous)",
        params: &[],
        code: &[
            Inst::Call {
                line: 11,
                function: COLLECT,
                args: &["items"],
                result: "result",
            },
            Inst::Return {
                line: 11,
                expr: "result",
            },
        ],
    },
];

struct StackFrame {
    function: usize,
    pc: usize,
    env: BTreeMap<String, Val>,
}

/// The breakpoint kinds a V8 inspector session can serve. The DevTools XHR,
/// event listener, DOM and CSP breakpoints belong to Blink's DOMDebugger
/// domain, which an inspector session does not dispatch, so this contract
/// does not claim them; phase 1 records all four without pausing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BreakpointKind {
    Line,
    Conditional,
    Logpoint,
}

impl BreakpointKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Line => "line",
            Self::Conditional => "conditional",
            Self::Logpoint => "logpoint",
        }
    }
}

struct Breakpoint {
    id: u64,
    kind: BreakpointKind,
    script_id: u32,
    line: u32,
    column: u32,
    condition: Option<String>,
    log_message: Option<String>,
    hits: u64,
}

impl Breakpoint {
    fn value(&self) -> Value {
        let mut row = Map::new();
        row.insert("breakpoint_id".into(), json!(self.id.to_string()));
        row.insert("kind".into(), json!(self.kind.as_str()));
        row.insert("hits".into(), json!(self.hits));
        // V8 binds a script breakpoint when it sets it, so a set breakpoint
        // of this contract's kinds is resolved.
        row.insert("resolved".into(), json!(true));
        row.insert("script_id".into(), json!(self.script_id));
        row.insert("line".into(), json!(self.line));
        row.insert("column".into(), json!(self.column));
        row.insert("condition_set".into(), json!(self.condition.is_some()));
        row.insert("logpoint".into(), json!(self.log_message.is_some()));
        Value::Object(row)
    }
}

struct Object {
    properties: Vec<(String, Val, Option<u64>)>,
}

struct Pause {
    reason: &'static str,
    breakpoint_id: u64,
    lease: u64,
    /// Innermost first, as the contract numbers them.
    frames: Vec<Value>,
    objects: BTreeMap<u64, Object>,
}

struct Lease {
    id: u64,
    state: &'static str,
    started: Instant,
    /// The deadline in force when the pause began, so a lease reports the
    /// same remaining time after the limit is changed for a test.
    limit_ms: u64,
}

impl Lease {
    fn value(&self) -> Value {
        let remaining = if self.state == "active" {
            self.limit_ms
                .saturating_sub(self.started.elapsed().as_millis() as u64)
        } else {
            0
        };
        json!({"lease_id": self.id.to_string(), "state": self.state,
            "expires_in_ms": remaining})
    }
}

/// One document generation. A navigation retires an id and hands out a new
/// one, which is the only identity a command can name; the Console's own id
/// space works the same way, so the two never disagree.
struct Document {
    id: u64,
    child: bool,
}

pub struct Engine {
    documents: Vec<Document>,
    next_document: u64,
    quiet_mode: bool,
    /// The one authorized document, by id.
    authorized: Option<u64>,
    last_clear: Option<&'static str>,
    exceptions: &'static str,
    breakpoints: Vec<Breakpoint>,
    next_breakpoint: u64,
    next_lease: u64,
    lease: Option<Lease>,
    lease_limit_ms: u64,
    pause: Option<Pause>,
    stack: Vec<StackFrame>,
    globals: BTreeMap<String, Val>,
    pause_on_next: bool,
    /// Set by a step command; the next boundary at or above this depth pauses.
    step: Option<(&'static str, usize)>,
    /// A resume or step has been answered and the page runs again on the next
    /// tick, never inside the command. The browser behaves the same way: the
    /// inspector unwinds the nested loop after the command returns, so a step
    /// reply cannot carry the pause it lands on.
    running: bool,
    finished: bool,
    logpoints: Vec<String>,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        let mut globals = BTreeMap::new();
        globals.insert("table".into(), Val::Arr((0..200).collect()));
        globals.insert("origin".into(), Val::Str("https://fixture.test".into()));
        Self {
            documents: vec![
                Document {
                    id: FIXTURE_TARGET,
                    child: false,
                },
                Document {
                    id: FIXTURE_CHILD_TARGET,
                    child: true,
                },
            ],
            next_document: FIXTURE_CHILD_TARGET + 1,
            quiet_mode: true,
            authorized: None,
            last_clear: None,
            exceptions: "none",
            breakpoints: Vec::new(),
            next_breakpoint: 1,
            next_lease: 1,
            lease: None,
            lease_limit_ms: LEASE_LIMIT_MS,
            pause: None,
            stack: Vec::new(),
            globals,
            pause_on_next: false,
            step: None,
            running: false,
            finished: false,
            logpoints: Vec::new(),
        }
    }

    /// The top document's current generation.
    pub fn target(&self) -> u64 {
        self.documents[0].id
    }
    /// A same-process iframe of it. Selecting one is ordinary: the inspector
    /// session belongs to the local root either way.
    pub fn child_target(&self) -> u64 {
        self.documents[1].id
    }
    /// The only test hook over the contract's 60 second deadline, so a test
    /// can watch the browser's own timer resume a page nobody is holding.
    pub fn set_lease_limit_ms(&mut self, limit: u64) {
        self.lease_limit_ms = limit.min(LEASE_LIMIT_MS);
    }
    pub fn is_paused(&self) -> bool {
        self.pause.is_some()
    }
    pub fn lease_id(&self) -> Option<u64> {
        self.lease.as_ref().map(|lease| lease.id)
    }
    pub fn logpoints(&self) -> &[String] {
        &self.logpoints
    }
    /// True once the fixture program ran to the end, so a test can tell a
    /// resume that finished the page from one that paused again.
    pub fn finished(&self) -> bool {
        self.finished
    }
    /// A page's own `debugger;` only pauses when the browser is not in quiet
    /// mode; the fixture starts quiet, as the packaged app does.
    pub fn set_quiet_mode(&mut self, quiet: bool) {
        self.quiet_mode = quiet;
    }

    /// The authorized document navigates: the renderer drops its session,
    /// every breakpoint it set, and the pause. The new generation is the only
    /// one a later command can name.
    pub fn navigate(&mut self) {
        let authorized = self.authorized;
        for document in &mut self.documents {
            document.id = self.next_document;
            self.next_document += 1;
        }
        if authorized.is_some() {
            self.clear("navigated");
        }
    }

    /// The authorized document is stored into the back-forward cache. The
    /// authorization ends the same way a navigation ends it, because the
    /// document stopped running, but the id is not retired: a restored
    /// document keeps the id it had, so selecting it again can succeed.
    pub fn store_in_back_forward_cache(&mut self) {
        if self.authorized.is_some() {
            self.clear("navigated");
        }
    }

    /// The authorized frame is detached. The document is gone with it, so its
    /// id names nothing afterwards and the authorization ended `navigated`:
    /// the document went away, this peer's connection did not.
    pub fn detach_child(&mut self) {
        let child = self.documents.iter().position(|document| document.child);
        if let Some(index) = child {
            let id = self.documents[index].id;
            self.documents.remove(index);
            if self.authorized == Some(id) {
                self.clear("navigated");
            }
        }
    }

    /// The browser's own deadline fires. The page runs again and the lease
    /// says why, which is what the interface shows.
    pub fn expire_lease(&mut self) {
        if self.pause.is_none() {
            return;
        }
        self.resume_execution();
        if let Some(lease) = &mut self.lease {
            lease.state = "expired";
        }
    }

    /// The deadline the browser holds, enforced with no client in sight. The
    /// peer's own thread calls this, so nothing a client does or stops doing
    /// can keep a page paused past it.
    pub fn enforce_lease(&mut self) -> bool {
        let overdue = self.pause.is_some()
            && self.lease.as_ref().is_some_and(|lease| {
                lease.state == "active"
                    && lease.started.elapsed().as_millis() as u64 >= lease.limit_ms
            });
        if overdue {
            self.expire_lease();
        }
        overdue
    }

    /// One command by action name, for a caller outside this module: the
    /// operation codes and the socket framing stay private. Returns the
    /// status as this contract names it.
    pub fn command_by_action(&mut self, target: u64, lease: u64, body: &Value) -> &'static str {
        let Some(op) = operation(body["action"].as_str().unwrap_or_default()) else {
            return Status::Malformed.as_str();
        };
        self.command(op, target, lease, body).status.as_str()
    }

    /// Runs the page on once a resume or a step has been answered. The
    /// browser's nested loop unwinds after the reply the same way.
    pub fn pump(&mut self) -> bool {
        if !self.running || self.pause.is_some() {
            return false;
        }
        self.running = false;
        let running = self
            .stack
            .last()
            .is_some_and(|frame| PROGRAM[frame.function].code.get(frame.pc).is_some());
        if !running {
            // A synthetic handler frame has no program to continue into.
            self.stack.clear();
            self.finished = true;
            self.step = None;
            return true;
        }
        self.execute();
        self.advance();
        true
    }

    fn clear(&mut self, reason: &'static str) {
        self.authorized = None;
        self.breakpoints.clear();
        self.pause = None;
        self.stack.clear();
        self.step = None;
        self.pause_on_next = false;
        self.running = false;
        self.finished = false;
        self.exceptions = "none";
        if let Some(lease) = &mut self.lease
            && lease.state == "active"
        {
            lease.state = "released";
        }
        self.last_clear = Some(reason);
    }

    /// Runs the fixture document from the top until it pauses or finishes.
    pub fn run(&mut self) {
        if self.pause.is_some() {
            return;
        }
        let mut env = BTreeMap::new();
        env.insert("items".into(), Val::Arr(vec![1, 2, 3]));
        self.stack = vec![StackFrame {
            function: MAIN,
            pc: 0,
            env,
        }];
        self.finished = false;
        self.advance();
    }

    /// One throw in the page. It pauses only in the mode the researcher set.
    pub fn throw(&mut self, caught: bool) -> bool {
        if self.pause.is_some()
            || self.exceptions == "none"
            || (self.exceptions == "uncaught" && caught)
        {
            return false;
        }
        self.pause_synthetic("exception", 0, "handleError", 7);
        true
    }

    /// A `debugger;` statement the page runs. Quiet mode swallows it.
    pub fn debugger_statement(&mut self) -> bool {
        if self.quiet_mode || self.pause.is_some() {
            return false;
        }
        self.pause_synthetic("debugger_statement", 0, "collect", 7);
        true
    }

    /// A pause with one handler frame, for a stop the fixture program did
    /// not reach itself. The frame carries a local scope so a scope read and
    /// a watch expression work the same way they do at a line breakpoint.
    fn pause_synthetic(
        &mut self,
        reason: &'static str,
        breakpoint_id: u64,
        function: &'static str,
        line: u32,
    ) {
        let mut env = BTreeMap::new();
        env.insert("handled".into(), Val::Int(1));
        self.stack = vec![StackFrame {
            function: COLLECT,
            pc: usize::MAX,
            env,
        }];
        self.finished = false;
        self.enter_pause(reason, breakpoint_id, Some((function, line)));
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

impl Engine {
    /// Runs instructions until a breakpoint, a step target or the end. A
    /// boundary is checked before the instruction at the current program
    /// counter runs, so a pause reports the statement that has not run yet.
    fn advance(&mut self) {
        // The fixture is finite; the bound only keeps a programming mistake
        // in this peer from hanging a test.
        for _ in 0..100_000 {
            let Some(frame) = self.stack.last() else {
                self.finished = true;
                return;
            };
            let depth = self.stack.len();
            let code = PROGRAM[frame.function].code;
            let Some(inst) = code.get(frame.pc) else {
                self.pop_frame(Val::Undefined);
                continue;
            };
            let line = inst.line();
            if line != 0 && self.should_pause(line, depth) {
                return;
            }
            self.execute();
        }
        self.finished = true;
        self.stack.clear();
    }

    /// Decides the boundary before an instruction. A logpoint records its
    /// message and lets the page run, as DevTools does.
    fn should_pause(&mut self, line: u32, depth: usize) -> bool {
        if self.pause_on_next {
            self.pause_on_next = false;
            self.enter_pause("pause", 0, None);
            return true;
        }
        if let Some(index) = self.matching_breakpoint(line) {
            let id = self.breakpoints[index].id;
            if let Some(message) = self.breakpoints[index].log_message.clone() {
                // A logpoint never pauses, so it never counts a hit: a hit
                // is a stop, the only thing either side can observe. The
                // message is one literal console.log argument, as the browser
                // sends it; nothing in it is interpolated.
                self.logpoints
                    .push(validation::truncate(&message, VALUE_TEXT_BYTES));
            } else {
                self.breakpoints[index].hits += 1;
                self.enter_pause("breakpoint", id, None);
                return true;
            }
        }
        match self.step {
            Some(("into", _)) => {
                self.step = None;
                self.enter_pause("step", 0, None);
                true
            }
            Some(("over", target)) if depth <= target => {
                self.step = None;
                self.enter_pause("step", 0, None);
                true
            }
            Some(("out", target)) if depth < target => {
                self.step = None;
                self.enter_pause("step", 0, None);
                true
            }
            _ => false,
        }
    }

    fn matching_breakpoint(&mut self, line: u32) -> Option<usize> {
        let candidates: Vec<usize> = self
            .breakpoints
            .iter()
            .enumerate()
            .filter(|(_, breakpoint)| {
                matches!(
                    breakpoint.kind,
                    BreakpointKind::Line | BreakpointKind::Conditional | BreakpointKind::Logpoint
                ) && breakpoint.script_id == FIXTURE_SCRIPT_ID
                    && breakpoint.line == line
            })
            .map(|(index, _)| index)
            .collect();
        for index in candidates {
            let condition = self.breakpoints[index].condition.clone();
            // A condition that throws does not pause, as in DevTools.
            let hit = match condition {
                None => true,
                Some(source) => self
                    .evaluate_in_frame(0, &source, false)
                    .is_ok_and(|value| value.truthy()),
            };
            if hit {
                return Some(index);
            }
        }
        None
    }

    fn execute(&mut self) {
        let Some(frame) = self.stack.last() else {
            return;
        };
        let function = frame.function;
        let pc = frame.pc;
        match &PROGRAM[function].code[pc] {
            Inst::Set { name, expr, .. } => {
                let value = self
                    .eval(expr, self.stack.len() - 1)
                    .unwrap_or(Val::Undefined);
                let frame = self.stack.last_mut().expect("frame checked above");
                frame.env.insert((*name).into(), value);
                frame.pc += 1;
            }
            Inst::IterInit { cursor, .. } => {
                let frame = self.stack.last_mut().expect("frame checked above");
                frame.env.insert((*cursor).into(), Val::Int(0));
                frame.pc += 1;
            }
            Inst::IterNext {
                cursor,
                list,
                var,
                exit,
                ..
            } => {
                let index = match self.lookup(cursor, self.stack.len() - 1) {
                    Some(Val::Int(index)) => index,
                    _ => 0,
                };
                let items = match self.lookup(list, self.stack.len() - 1) {
                    Some(Val::Arr(items)) => items,
                    _ => Vec::new(),
                };
                let frame = self.stack.last_mut().expect("frame checked above");
                match items.get(usize::try_from(index).unwrap_or(usize::MAX)) {
                    Some(item) => {
                        frame.env.insert((*var).into(), Val::Int(*item));
                        frame.env.insert((*cursor).into(), Val::Int(index + 1));
                        frame.pc += 1;
                    }
                    None => {
                        frame.env.remove(*var);
                        frame.pc = *exit;
                    }
                }
            }
            Inst::Jump { target } => {
                self.stack.last_mut().expect("frame checked above").pc = *target;
            }
            Inst::Call {
                function: callee,
                args,
                ..
            } => {
                let depth = self.stack.len() - 1;
                let values: Vec<Val> = args
                    .iter()
                    .map(|name| self.lookup(name, depth).unwrap_or(Val::Undefined))
                    .collect();
                let mut env = BTreeMap::new();
                for (name, value) in PROGRAM[*callee].params.iter().zip(values) {
                    env.insert((*name).into(), value);
                }
                self.stack.push(StackFrame {
                    function: *callee,
                    pc: 0,
                    env,
                });
            }
            Inst::Return { expr, .. } => {
                let value = self
                    .eval(expr, self.stack.len() - 1)
                    .unwrap_or(Val::Undefined);
                self.pop_frame(value);
            }
        }
    }

    fn pop_frame(&mut self, value: Val) {
        self.stack.pop();
        let Some(caller) = self.stack.last() else {
            return;
        };
        let function = caller.function;
        let pc = caller.pc;
        if let Some(Inst::Call { result, .. }) = PROGRAM[function].code.get(pc) {
            let name = (*result).into();
            let caller = self.stack.last_mut().expect("caller checked above");
            caller.env.insert(name, value);
            caller.pc += 1;
        }
    }

    fn lookup(&self, name: &str, depth: usize) -> Option<Val> {
        self.stack
            .get(depth)
            .and_then(|frame| frame.env.get(name))
            .or_else(|| self.globals.get(name))
            .cloned()
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------
//
// Enough of JavaScript for a breakpoint condition, a watch expression and a
// logpoint: literals, identifiers, `.length`, one index, one assignment, and
// left-associative binary operators with no precedence. The contract says so,
// and a watch the fixture cannot parse is an `invalid_input`, never a guess.

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Ident(String),
    Int(i64),
    Str(String),
    Op(&'static str),
}

fn tokenize(source: &str) -> std::result::Result<Vec<Token>, String> {
    const OPERATORS: [&str; 11] = ["===", "!==", "<=", ">=", "=", "<", ">", "+", "-", "*", "."];
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte.is_ascii_whitespace() {
            at += 1;
        } else if byte.is_ascii_digit() {
            let start = at;
            while at < bytes.len() && bytes[at].is_ascii_digit() {
                at += 1;
            }
            let text = &source[start..at];
            tokens.push(Token::Int(
                text.parse()
                    .map_err(|_| "number is out of range".to_owned())?,
            ));
        } else if byte == b'_' || byte == b'$' || byte.is_ascii_alphabetic() {
            let start = at;
            while at < bytes.len()
                && (bytes[at] == b'_' || bytes[at] == b'$' || bytes[at].is_ascii_alphanumeric())
            {
                at += 1;
            }
            tokens.push(Token::Ident(source[start..at].to_owned()));
        } else if byte == b'"' || byte == b'\'' {
            let quote = byte;
            at += 1;
            let start = at;
            while at < bytes.len() && bytes[at] != quote {
                at += 1;
            }
            if at >= bytes.len() {
                return Err("string is not closed".into());
            }
            tokens.push(Token::Str(source[start..at].to_owned()));
            at += 1;
        } else if byte == b'[' || byte == b']' {
            tokens.push(Token::Op(if byte == b'[' { "[" } else { "]" }));
            at += 1;
        } else if let Some(operator) = OPERATORS
            .iter()
            .find(|operator| source[at..].starts_with(**operator))
        {
            tokens.push(Token::Op(operator));
            at += operator.len();
        } else {
            return Err(format!("unexpected character at byte {at}"));
        }
        if tokens.len() > 128 {
            return Err("expression is too long".into());
        }
    }
    if tokens.is_empty() {
        return Err("expression is empty".into());
    }
    Ok(tokens)
}

fn apply(operator: &str, left: &Val, right: &Val) -> std::result::Result<Val, String> {
    let equal = left == right;
    Ok(match (operator, left, right) {
        ("===", _, _) => Val::Int(i64::from(equal)),
        ("!==", _, _) => Val::Int(i64::from(!equal)),
        ("+", Val::Str(left), right) => Val::Str(format!("{left}{}", plain(right))),
        ("+", left, Val::Str(right)) => Val::Str(format!("{}{right}", plain(left))),
        ("+", Val::Int(left), Val::Int(right)) => Val::Int(left.saturating_add(*right)),
        ("-", Val::Int(left), Val::Int(right)) => Val::Int(left.saturating_sub(*right)),
        ("*", Val::Int(left), Val::Int(right)) => Val::Int(left.saturating_mul(*right)),
        ("<", Val::Int(left), Val::Int(right)) => Val::Int(i64::from(left < right)),
        (">", Val::Int(left), Val::Int(right)) => Val::Int(i64::from(left > right)),
        ("<=", Val::Int(left), Val::Int(right)) => Val::Int(i64::from(left <= right)),
        (">=", Val::Int(left), Val::Int(right)) => Val::Int(i64::from(left >= right)),
        _ => return Err(format!("{operator} is not defined for these values")),
    })
}

fn plain(value: &Val) -> String {
    match value {
        Val::Str(text) => text.clone(),
        other => other.text(),
    }
}

impl Engine {
    /// `index` counts from the innermost frame, as the contract numbers them.
    fn evaluate_in_frame(
        &mut self,
        index: usize,
        source: &str,
        allow_assignment: bool,
    ) -> std::result::Result<Val, String> {
        if self.stack.is_empty() {
            return Err("no frame is paused".into());
        }
        let depth = self
            .stack
            .len()
            .checked_sub(index + 1)
            .ok_or_else(|| "frame index is past the stack".to_owned())?;
        let tokens = tokenize(source)?;
        if allow_assignment
            && tokens.len() > 2
            && matches!(tokens[1], Token::Op("="))
            && let Token::Ident(name) = &tokens[0]
        {
            let value = self.evaluate_tokens(&tokens[2..], depth)?;
            let name = name.clone();
            if self.stack[depth].env.contains_key(&name) || !self.globals.contains_key(&name) {
                self.stack[depth].env.insert(name, value.clone());
            } else {
                self.globals.insert(name, value.clone());
            }
            return Ok(value);
        }
        self.evaluate_tokens(&tokens, depth)
    }

    fn eval(&self, source: &str, depth: usize) -> std::result::Result<Val, String> {
        self.evaluate_tokens(&tokenize(source)?, depth)
    }

    fn evaluate_tokens(&self, tokens: &[Token], depth: usize) -> std::result::Result<Val, String> {
        let (mut value, mut at) = self.primary(tokens, 0, depth)?;
        while at < tokens.len() {
            let Token::Op(operator) = tokens[at] else {
                return Err("expected an operator".into());
            };
            if operator == "=" || operator == "." || operator == "[" || operator == "]" {
                return Err("expected an operator".into());
            }
            let (right, next) = self.primary(tokens, at + 1, depth)?;
            value = apply(operator, &value, &right)?;
            at = next;
        }
        Ok(value)
    }

    fn primary(
        &self,
        tokens: &[Token],
        at: usize,
        depth: usize,
    ) -> std::result::Result<(Val, usize), String> {
        match tokens.get(at) {
            Some(Token::Int(value)) => Ok((Val::Int(*value), at + 1)),
            Some(Token::Str(value)) => Ok((Val::Str(value.clone()), at + 1)),
            Some(Token::Ident(name)) => {
                let base = self
                    .lookup(name, depth)
                    .ok_or_else(|| format!("{name} is not defined"))?;
                match (tokens.get(at + 1), tokens.get(at + 2)) {
                    (Some(Token::Op(".")), Some(Token::Ident(member))) if member == "length" => {
                        let length = match &base {
                            Val::Arr(items) => items.len(),
                            Val::Str(text) => text.chars().count(),
                            _ => return Err(format!("{name} has no length")),
                        };
                        Ok((Val::Int(length as i64), at + 3))
                    }
                    (Some(Token::Op("[")), Some(Token::Int(index))) => {
                        if tokens.get(at + 3) != Some(&Token::Op("]")) {
                            return Err("index is not closed".into());
                        }
                        let Val::Arr(items) = &base else {
                            return Err(format!("{name} is not indexable"));
                        };
                        let item = usize::try_from(*index)
                            .ok()
                            .and_then(|index| items.get(index))
                            .copied();
                        Ok((item.map_or(Val::Undefined, Val::Int), at + 4))
                    }
                    _ => Ok((base, at + 1)),
                }
            }
            _ => Err("expected a value".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Pause views
// ---------------------------------------------------------------------------

impl Engine {
    fn enter_pause(
        &mut self,
        reason: &'static str,
        breakpoint_id: u64,
        synthetic: Option<(&'static str, u32)>,
    ) {
        let lease = self.next_lease;
        self.next_lease += 1;
        // The lease starts here, at the pause, not when a client first asks.
        self.lease = Some(Lease {
            id: lease,
            state: "active",
            started: Instant::now(),
            limit_ms: self.lease_limit_ms,
        });
        let (frames, objects) = self.build_pause(synthetic);
        self.pause = Some(Pause {
            reason,
            breakpoint_id,
            lease,
            frames,
            objects,
        });
    }

    fn build_pause(
        &self,
        synthetic: Option<(&'static str, u32)>,
    ) -> (Vec<Value>, BTreeMap<u64, Object>) {
        let mut objects: BTreeMap<u64, Object> = BTreeMap::new();
        let mut next_id = 1u64;
        let global_id = next_id;
        next_id += 1;
        let global = self.object_of(&self.globals, &mut next_id, &mut objects);
        objects.insert(global_id, global);

        let mut frames = Vec::new();
        for frame in self.stack.iter().rev() {
            // Both bounds are the contract's: a deeper stack is truncated and
            // said to be, and a frame past the live-object bound gets no
            // scope rather than an id the peer could not answer for.
            if frames.len() >= FRAME_LIMIT || objects.len() >= OBJECT_LIMIT {
                break;
            }
            let local_id = next_id;
            next_id += 1;
            let local = self.object_of(&frame.env, &mut next_id, &mut objects);
            objects.insert(local_id, local);
            let function = PROGRAM[frame.function].name;
            let (name, line) = match (frames.is_empty(), synthetic) {
                (true, Some((name, line))) => (name, line),
                _ => (
                    function,
                    PROGRAM[frame.function]
                        .code
                        .get(frame.pc)
                        .map_or(0, Inst::line),
                ),
            };
            frames.push(json!({
                "index": frames.len(),
                "function_name": validation::truncate(name, NAME_BYTES),
                "script_id": FIXTURE_SCRIPT_ID,
                "line": line,
                "column": 2,
                "this_object_id": Value::Null,
                "scopes": [
                    {"type": "local", "name": validation::truncate(function, NAME_BYTES),
                     "object_id": local_id.to_string()},
                    {"type": "global", "object_id": global_id.to_string()},
                ],
            }));
        }
        (frames, objects)
    }

    /// One scope or array as a property list. An array property gets its own
    /// id so the interface can expand it; nothing deeper is allocated, which
    /// keeps the live-object count inside the contract's bound.
    fn object_of(
        &self,
        env: &BTreeMap<String, Val>,
        next_id: &mut u64,
        objects: &mut BTreeMap<u64, Object>,
    ) -> Object {
        let mut properties = Vec::new();
        for (name, value) in env {
            // Hidden loop cursors are this peer's bookkeeping, not page state.
            if name.starts_with('#') || properties.len() >= PROPERTY_LIMIT {
                continue;
            }
            let child = match value {
                Val::Arr(items) if objects.len() < OBJECT_LIMIT => {
                    let id = *next_id;
                    *next_id += 1;
                    let mut rows: Vec<(String, Val, Option<u64>)> = items
                        .iter()
                        .take(PROPERTY_LIMIT - 1)
                        .enumerate()
                        .map(|(index, item)| (index.to_string(), Val::Int(*item), None))
                        .collect();
                    rows.push(("length".into(), Val::Int(items.len() as i64), None));
                    objects.insert(id, Object { properties: rows });
                    Some(id)
                }
                _ => None,
            };
            properties.push((name.clone(), value.clone(), child));
        }
        Object { properties }
    }

    fn pause_value(&self) -> Value {
        let Some(pause) = &self.pause else {
            return Value::Null;
        };
        json!({
            "reason": pause.reason,
            "breakpoint_id": (pause.breakpoint_id != 0)
                .then(|| pause.breakpoint_id.to_string()),
            "lease_id": pause.lease.to_string(),
            "frames_recorded": pause.frames.len(),
            "async_frames": 0,
            "frames_truncated": self.stack.len() > FRAME_LIMIT,
            // This fixture's stack is small enough to always fit the reply
            // bound; the browser leaves the frames out of a deep pause and
            // says so here.
            "frames_omitted": false,
            "frames": pause.frames,
        })
    }

    pub fn state_value(&self) -> Value {
        json!({
            // The page can always tell, so the state says so wherever it is on.
            "active_indication": self.authorized.map(|_| ACTIVE_INDICATION),
            "quiet_mode": self.quiet_mode,
            "document": self.authorized.and_then(|id| {
                self.documents.iter().find(|document| document.id == id).map(|document| {
                    json!({"target_id": id.to_string(),
                        "frame": if document.child { "child" } else { "top" }})
                })
            }),
            "last_clear": self.last_clear,
            "exceptions": self.exceptions,
            "breakpoints": self.breakpoints.iter().map(Breakpoint::value)
                .collect::<Vec<Value>>(),
            "lease": self.lease.as_ref().map(Lease::value),
            "paused": self.pause.is_some(),
            "pause": self.pause_value(),
        })
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

struct Outcome {
    status: Status,
    resumed: bool,
    breakpoint: Value,
    value: Value,
    properties: Value,
}

impl Outcome {
    fn new(status: Status) -> Self {
        Self {
            status,
            resumed: false,
            breakpoint: Value::Null,
            value: Value::Null,
            properties: Value::Null,
        }
    }
    fn ok() -> Self {
        Self::new(Status::Ok)
    }
}

impl Engine {
    /// One command from the socket. `target` and `lease` come from the frame
    /// header; `body` is the action object the backend validated.
    ///
    /// The order of the two identity guards is the contract's: a document
    /// that no longer exists is `stale_document` whatever this connection
    /// selected, and only a document that still exists can be reported as
    /// not authorized. Looking a target up has no side effect, so this order
    /// costs nothing and answers the more specific thing.
    fn command(&mut self, op: u16, target: u64, lease: u64, body: &Value) -> Outcome {
        if !self.documents.iter().any(|document| document.id == target) {
            return Outcome::new(Status::StaleDocument);
        }
        if op != OP_SELECT_DOCUMENT && self.authorized != Some(target) {
            return Outcome::new(Status::NotAuthorized);
        }
        let needs_pause = matches!(
            op,
            OP_RESUME
                | OP_STEP_OVER
                | OP_STEP_INTO
                | OP_STEP_OUT
                | OP_RELEASE_LEASE
                | OP_EVALUATE_ON_FRAME
                | OP_GET_PROPERTIES
        );
        if needs_pause {
            let Some(pause) = &self.pause else {
                return Outcome::new(Status::NotPaused);
            };
            if pause.lease != lease {
                return Outcome::new(Status::StaleLease);
            }
        }
        let confirmed = body["confirm_pause"] == json!(true);
        match op {
            OP_SELECT_DOCUMENT => {
                if !confirmed {
                    return Outcome::new(Status::InvalidInput);
                }
                // Selecting a second document replaces the first, which is
                // resumed and fully disarmed before this one is armed. The
                // reply is the new selection's own state, which is what a
                // fresh session in the browser answers: nothing paused, no
                // lease, and `resumed` false. That the previous document was
                // let go is read from `last_clear`.
                // Selecting the document that is already selected is not a
                // replacement: the authorization, its breakpoints, the pause
                // and its lease all survive, and the reply describes that
                // session.
                if self.authorized == Some(target) {
                    return Outcome::ok();
                }
                if self.authorized.is_some() {
                    self.clear("replaced");
                }
                self.authorized = Some(target);
                // A fresh session: no lease, nothing ended. `last_clear`
                // describes the authorization being read, and this one has
                // not ended.
                self.lease = None;
                self.last_clear = None;
                Outcome::ok()
            }
            OP_RELEASE_DOCUMENT => {
                let was_paused = self.pause.is_some();
                self.clear("released");
                let mut outcome = Outcome::ok();
                outcome.resumed = was_paused;
                outcome
            }
            OP_SET_BREAKPOINT => {
                if !confirmed {
                    return Outcome::new(Status::InvalidInput);
                }
                self.add_breakpoint(body)
            }
            OP_REMOVE_BREAKPOINT => {
                let id = body["breakpoint_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                match self
                    .breakpoints
                    .iter()
                    .position(|breakpoint| breakpoint.id.to_string() == id)
                {
                    Some(index) => {
                        // The row is gone; the reply says only that it was
                        // removed, which is what the browser answers.
                        self.breakpoints.remove(index);
                        Outcome::ok()
                    }
                    None => Outcome::new(Status::UnknownBreakpoint),
                }
            }
            OP_PAUSE_ON_EXCEPTIONS => {
                if !confirmed {
                    return Outcome::new(Status::InvalidInput);
                }
                self.exceptions = match body["mode"].as_str() {
                    Some("uncaught") => "uncaught",
                    Some("all") => "all",
                    _ => "none",
                };
                Outcome::ok()
            }
            OP_PAUSE => {
                if !confirmed {
                    return Outcome::new(Status::InvalidInput);
                }
                self.pause_on_next = self.pause.is_none();
                Outcome::ok()
            }
            OP_RESUME => {
                self.resume_execution();
                let mut outcome = Outcome::ok();
                outcome.resumed = true;
                outcome
            }
            OP_STEP_OVER | OP_STEP_INTO | OP_STEP_OUT => {
                let depth = self.stack.len();
                self.step = Some(match op {
                    OP_STEP_INTO => ("into", 0),
                    OP_STEP_OUT => ("out", depth),
                    _ => ("over", depth),
                });
                self.resume_execution();
                let mut outcome = Outcome::ok();
                outcome.resumed = true;
                outcome
            }
            OP_RELEASE_LEASE => {
                self.pause = None;
                self.stack.clear();
                self.finished = true;
                self.step = None;
                if let Some(lease) = &mut self.lease {
                    lease.state = "released";
                }
                let mut outcome = Outcome::ok();
                outcome.resumed = true;
                outcome
            }
            OP_EVALUATE_ON_FRAME => self.evaluate_command(body),
            OP_GET_PROPERTIES => self.properties_command(body),
            _ => Outcome::new(Status::Malformed),
        }
    }

    fn add_breakpoint(&mut self, body: &Value) -> Outcome {
        if self.breakpoints.len() >= BREAKPOINT_LIMIT {
            return Outcome::new(Status::Limit);
        }
        let text = |field: &str| body[field].as_str().map(str::to_owned);
        let number = |field: &str| u32::try_from(body[field].as_u64().unwrap_or_default()).ok();
        let kind = if body.get("log_message").is_some() {
            BreakpointKind::Logpoint
        } else if body.get("condition").is_some() {
            BreakpointKind::Conditional
        } else {
            BreakpointKind::Line
        };
        // V8 takes any condition string and a condition it cannot evaluate
        // simply does not stop the page, so no condition is refused here
        // either. `should_pause` treats one this fixture cannot tokenize as
        // false, which is the same observable behaviour.
        let id = self.next_breakpoint;
        self.next_breakpoint += 1;
        let breakpoint = Breakpoint {
            id,
            kind,
            script_id: number("script_id").unwrap_or_default(),
            line: number("line").unwrap_or_default(),
            column: number("column").unwrap_or_default(),
            condition: text("condition"),
            log_message: text("log_message"),
            hits: 0,
        };
        let mut outcome = Outcome::ok();
        outcome.breakpoint = breakpoint.value();
        self.breakpoints.push(breakpoint);
        outcome
    }

    /// Answers the command now and lets the page run on the next tick, which
    /// is why a step reply says the page resumed and carries no new pause.
    fn resume_execution(&mut self) {
        self.pause = None;
        if let Some(lease) = &mut self.lease
            && lease.state == "active"
        {
            lease.state = "released";
        }
        self.running = true;
    }

    fn evaluate_command(&mut self, body: &Value) -> Outcome {
        let index = usize::try_from(body["call_frame_index"].as_u64().unwrap_or_default())
            .unwrap_or(usize::MAX);
        let frames = self.pause.as_ref().map_or(0, |pause| pause.frames.len());
        if index >= frames {
            return Outcome::new(Status::Limit);
        }
        let expression = body["expression"].as_str().unwrap_or_default().to_owned();
        let result = self.evaluate_in_frame(index, &expression, true);
        // An assignment changes the page, so the frames and scope objects are
        // rebuilt before the next read of them.
        if let Some(pause) = self.pause.take() {
            let (new_frames, objects) = self.build_pause(None);
            self.pause = Some(Pause {
                frames: new_frames,
                objects,
                ..pause
            });
        }
        let mut outcome = Outcome::ok();
        match result {
            Ok(value) => {
                let text = value.text();
                outcome.value = json!({
                    "kind": value.kind(),
                    "text": validation::truncate(&text, VALUE_TEXT_BYTES),
                    "truncated": text.len() > VALUE_TEXT_BYTES,
                    "object_id": Value::Null,
                    "threw": false,
                });
            }
            Err(message) => {
                outcome.status = Status::EvaluationError;
                outcome.value = json!({
                    "kind": "error",
                    "text": validation::truncate(&message, VALUE_TEXT_BYTES),
                    "truncated": false,
                    "object_id": Value::Null,
                    "threw": true,
                });
            }
        }
        outcome
    }

    fn properties_command(&mut self, body: &Value) -> Outcome {
        let id: u64 = body["object_id"]
            .as_str()
            .and_then(|id| id.parse().ok())
            .unwrap_or_default();
        let offset =
            usize::try_from(body["offset"].as_u64().unwrap_or_default()).unwrap_or(usize::MAX);
        let Some(pause) = &self.pause else {
            return Outcome::new(Status::NotPaused);
        };
        let Some(object) = pause.objects.get(&id) else {
            return Outcome::new(Status::UnknownObject);
        };
        let total = object.properties.len();
        let page: Vec<Value> = object
            .properties
            .iter()
            .skip(offset)
            .take(PROPERTY_PAGE)
            .map(|(name, value, child)| {
                let text = value.text();
                json!({
                    "name": validation::truncate(name, NAME_BYTES),
                    "kind": value.kind(),
                    "text": validation::truncate(&text, VALUE_TEXT_BYTES),
                    "truncated": text.len() > VALUE_TEXT_BYTES,
                    "object_id": child.map(|id| id.to_string()),
                })
            })
            .collect();
        let next = offset.saturating_add(page.len());
        let mut outcome = Outcome::ok();
        outcome.properties = json!({
            "object_id": id.to_string(),
            "offset": offset.min(total),
            "next_offset": (next < total).then(|| next.to_string()),
            "total": total,
            "items": page,
        });
        outcome
    }
}

// ---------------------------------------------------------------------------
// Peer server
// ---------------------------------------------------------------------------

/// The contract peer. One request and one reply per connection, with the same
/// private-socket permissions a browser peer must publish.
pub struct Peer {
    socket: PathBuf,
    engine: Arc<Mutex<Engine>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// The browser's own clock: it runs the page on after a resume and
    /// expires a lease whether or not any client is still there.
    clock: Option<JoinHandle<()>>,
    _directory: tempfile::TempDir,
}

impl Peer {
    pub fn spawn(engine: Engine) -> std::io::Result<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("native-debugger.sock");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let engine = Arc::new(Mutex::new(engine));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_engine = Arc::clone(&engine);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = std::thread::Builder::new()
            .name("native-debugger-peer".into())
            .spawn(move || serve(listener, thread_shutdown, thread_engine))?;
        let clock_engine = Arc::clone(&engine);
        let clock_shutdown = Arc::clone(&shutdown);
        let clock = std::thread::Builder::new()
            .name("native-debugger-clock".into())
            .spawn(move || {
                while !clock_shutdown.load(Ordering::SeqCst) {
                    {
                        let mut engine = clock_engine
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        engine.pump();
                        engine.enforce_lease();
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            })?;
        Ok(Self {
            socket,
            engine,
            shutdown,
            thread: Some(thread),
            clock: Some(clock),
            _directory: directory,
        })
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn with_engine<T>(&self, body: impl FnOnce(&mut Engine) -> T) -> T {
        let mut engine = self
            .engine
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        body(&mut engine)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(clock) = self.clock.take() {
            let _ = clock.join();
        }
    }
}

fn serve(listener: UnixListener, shutdown: Arc<AtomicBool>, engine: Arc<Mutex<Engine>>) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok((stream, _)) = listener.accept() else {
            break;
        };
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let _ = handle_connection(stream, &engine);
    }
}

struct RequestHeader {
    operation: u16,
    id: u64,
    target: u64,
    lease: u64,
    payload_len: usize,
}

fn decode_request(bytes: &[u8; REQUEST_HEADER]) -> Option<RequestHeader> {
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
    let operation = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
    let id = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let payload_len = u32::from_le_bytes(bytes[40..44].try_into().ok()?) as usize;
    let tail = u32::from_le_bytes(bytes[44..48].try_into().ok()?);
    let reserved = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
    if magic != MAGIC
        || version != VERSION
        || id == 0
        || tail != 0
        || reserved != 0
        || operation == 0
        || operation > OP_GET_PROPERTIES
        || payload_len > MAX_REQUEST_PAYLOAD
    {
        return None;
    }
    Some(RequestHeader {
        operation,
        id,
        target: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
        lease: u64::from_le_bytes(bytes[32..40].try_into().ok()?),
        payload_len,
    })
}

fn encode_reply(id: u64, status: Status, paused: bool, resumed: bool, body: &[u8]) -> Vec<u8> {
    let mut reply = Vec::with_capacity(RESPONSE_HEADER + body.len());
    reply.extend_from_slice(&MAGIC.to_le_bytes());
    reply.extend_from_slice(&VERSION.to_le_bytes());
    reply.extend_from_slice(&status.code().to_le_bytes());
    reply.extend_from_slice(&id.to_le_bytes());
    reply.push(u8::from(paused));
    reply.push(0);
    reply.extend_from_slice(&u16::from(resumed).to_le_bytes());
    reply.extend_from_slice(&(body.len() as u32).to_le_bytes());
    reply.extend_from_slice(&0u64.to_le_bytes());
    reply.extend_from_slice(body);
    reply
}

fn handle_connection(mut stream: UnixStream, engine: &Mutex<Engine>) -> std::io::Result<()> {
    silence_sigpipe(&stream);
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    if !same_user(&stream) {
        return Ok(());
    }
    let mut header = [0u8; REQUEST_HEADER];
    stream.read_exact(&mut header)?;
    let Some(request) = decode_request(&header) else {
        return write_all(
            &mut stream,
            &encode_reply(1, Status::Malformed, false, false, b"{}"),
        );
    };
    let mut payload = vec![0u8; request.payload_len];
    if request.payload_len > 0 {
        stream.read_exact(&mut payload)?;
    }
    let body: Value = if payload.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&payload).unwrap_or(Value::Null)
    };
    let mut engine = engine.lock().unwrap_or_else(|error| error.into_inner());
    if request.operation == OP_STATE {
        let mut state = engine.state_value();
        if let Some(object) = state.as_object_mut() {
            object.insert("action".into(), json!("state"));
            object.insert("status".into(), json!(Status::Ok.as_str()));
            object.insert("resumed".into(), json!(false));
        }
        let paused = engine.is_paused();
        let encoded = serde_json::to_vec(&state).unwrap_or_default();
        return write_all(
            &mut stream,
            &encode_reply(request.id, Status::Ok, paused, false, &encoded),
        );
    }
    let Some(action) = body["action"].as_str().map(str::to_owned) else {
        return write_all(
            &mut stream,
            &encode_reply(
                request.id,
                Status::Malformed,
                engine.is_paused(),
                false,
                b"{}",
            ),
        );
    };
    if operation(&action) != Some(request.operation) {
        return write_all(
            &mut stream,
            &encode_reply(
                request.id,
                Status::Malformed,
                engine.is_paused(),
                false,
                b"{}",
            ),
        );
    }
    let outcome = engine.command(request.operation, request.target, request.lease, &body);
    let paused = engine.is_paused();
    let reply = json!({
        "action": action,
        "status": outcome.status.as_str(),
        "active_indication": if engine.authorized.is_some() {
            json!(ACTIVE_INDICATION)
        } else {
            Value::Null
        },
        "paused": paused,
        "resumed": outcome.resumed,
        "lease": engine.lease.as_ref().map(Lease::value),
        // No command reply carries a pause: a step cannot know the next one,
        // and the current one is read from the state. The browser answers the
        // same way.
        "pause": Value::Null,
        "breakpoint": outcome.breakpoint,
        "value": outcome.value,
        "properties": outcome.properties,
    });
    let encoded = serde_json::to_vec(&reply).unwrap_or_default();
    write_all(
        &mut stream,
        &encode_reply(
            request.id,
            outcome.status,
            paused,
            outcome.resumed,
            &encoded,
        ),
    )
}

fn same_user(stream: &UnixStream) -> bool {
    peer_uid(stream) == Some(unsafe { libc::getuid() })
}

/// The same peer check the live Wasm socket makes, with the same platform
/// split: Linux reads SO_PEERCRED, the BSDs read getpeereid, and anything
/// else refuses rather than guessing.
fn peer_uid(stream: &UnixStream) -> Option<libc::uid_t> {
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
        // SAFETY: a live socket descriptor and correctly sized out parameters.
        let ok = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::from_mut(&mut cred).cast(),
                &mut len,
            )
        };
        (ok == 0).then_some(cred.uid)
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: a live socket descriptor and two owned out parameters.
        let ok = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        let _ = gid;
        (ok == 0).then_some(uid)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    )))]
    {
        let _ = fd;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorized() -> Engine {
        let mut engine = Engine::new();
        let outcome = engine.command(
            OP_SELECT_DOCUMENT,
            FIXTURE_TARGET,
            0,
            &json!({"action": "select_document", "confirm_pause": true}),
        );
        assert_eq!(outcome.status, Status::Ok);
        engine
    }

    fn run(engine: &mut Engine, op: u16, lease: u64, body: Value) -> Outcome {
        let target = engine.target();
        engine.command(op, target, lease, &body)
    }

    /// Runs the page on the way the peer's clock does, so a test sees what a
    /// client sees: the reply first, then the next pause.
    fn settle(engine: &mut Engine) {
        for _ in 0..64 {
            if !engine.pump() {
                break;
            }
        }
    }

    fn conditional(engine: &mut Engine, condition: &str) -> u64 {
        let outcome = run(
            engine,
            OP_SET_BREAKPOINT,
            0,
            json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID, "line": 7,
                "column": 4, "condition": condition, "confirm_pause": true}),
        );
        assert_eq!(outcome.status, Status::Ok);
        outcome.breakpoint["breakpoint_id"]
            .as_str()
            .and_then(|id| id.parse().ok())
            .expect("a set breakpoint has an id")
    }

    /// The names a frame's local scope holds, so a test reads a scope the way
    /// the interface does rather than reaching into the engine.
    fn locals(engine: &mut Engine, frame: usize) -> Vec<(String, String)> {
        let lease = engine.lease_id().expect("a pause holds a lease");
        let id = engine.pause.as_ref().expect("paused").frames[frame]["scopes"][0]["object_id"]
            .as_str()
            .expect("a local scope has an object id")
            .to_owned();
        let outcome = run(
            engine,
            OP_GET_PROPERTIES,
            lease,
            json!({"action": "get_properties", "object_id": id, "offset": 0}),
        );
        assert_eq!(outcome.status, Status::Ok);
        outcome.properties["items"]
            .as_array()
            .expect("a page of properties")
            .iter()
            .map(|item| {
                (
                    item["name"].as_str().unwrap_or_default().to_owned(),
                    item["text"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn an_unarmed_fixture_runs_to_the_end() {
        let mut engine = authorized();
        engine.run();
        assert!(engine.finished() && !engine.is_paused());
        assert_eq!(engine.state_value()["pause"], Value::Null);
        assert_eq!(engine.state_value()["lease"], Value::Null);
    }

    #[test]
    fn a_conditional_breakpoint_pauses_on_its_iteration_only() {
        let mut engine = authorized();
        let id = conditional(&mut engine, "item === 2");
        engine.run();
        assert!(engine.is_paused());
        let state = engine.state_value();
        assert_eq!(state["pause"]["reason"], "breakpoint");
        assert_eq!(state["pause"]["breakpoint_id"], id.to_string());
        assert_eq!(state["pause"]["frames"][0]["function_name"], "collect");
        assert_eq!(state["pause"]["frames"][0]["line"], 7);
        assert_eq!(state["pause"]["frames"][1]["function_name"], "(anonymous)");
        assert_eq!(state["pause"]["frames_recorded"], 2);
        assert_eq!(state["lease"]["state"], "active");
        // A hit is a pause, as in DevTools: the condition was evaluated on
        // every iteration and matched once. total is 1 after the first.
        assert_eq!(state["breakpoints"][0]["hits"], 1);
        let scope = locals(&mut engine, 0);
        assert!(scope.contains(&("item".into(), "2".into())));
        assert!(scope.contains(&("total".into(), "1".into())));
        assert!(
            !scope.iter().any(|(name, _)| name.starts_with('#')),
            "the peer's loop cursor is not page state"
        );
    }

    #[test]
    fn a_condition_that_cannot_be_evaluated_never_pauses() {
        let mut engine = authorized();
        conditional(&mut engine, "missing === 2");
        engine.run();
        assert!(engine.finished() && !engine.is_paused());
    }

    #[test]
    fn a_logpoint_records_its_message_and_leaves_the_page_running() {
        let mut engine = authorized();
        run(
            &mut engine,
            OP_SET_BREAKPOINT,
            0,
            json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID, "line": 7,
                "column": 4, "log_message": "item {item} total {total}", "confirm_pause": true}),
        );
        engine.run();
        settle(&mut engine);
        assert!(engine.finished() && !engine.is_paused());
        // One literal console.log argument each time, as the browser sends
        // it: this contract interpolates nothing into a logpoint message.
        assert_eq!(engine.logpoints(), ["item {item} total {total}"; 3]);
        assert_eq!(engine.state_value()["breakpoints"][0]["hits"], 0);
    }

    #[test]
    fn stepping_walks_into_out_of_and_over_a_call() {
        let mut engine = authorized();
        conditional(&mut engine, "item === 2");
        engine.run();
        let lease = engine.lease_id().expect("a pause holds a lease");

        let outcome = run(
            &mut engine,
            OP_STEP_INTO,
            lease,
            json!({"action": "step_into"}),
        );
        // The reply says the page resumed and carries no pause: the next one
        // is a later fact, read from the state once the page has run.
        assert!(outcome.resumed && !engine.is_paused());
        settle(&mut engine);
        let state = engine.state_value();
        assert_eq!(state["pause"]["reason"], "step");
        assert_eq!(state["pause"]["frames"][0]["function_name"], "add");
        assert_eq!(state["pause"]["frames"][0]["line"], 2);
        assert_eq!(state["pause"]["frames_recorded"], 3);
        assert_ne!(
            state["lease"]["lease_id"],
            lease.to_string(),
            "a step takes a fresh lease"
        );
        assert_eq!(
            locals(&mut engine, 0),
            [
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "2".to_owned())
            ]
        );

        let lease = engine.lease_id().expect("the step paused again");
        run(
            &mut engine,
            OP_STEP_OUT,
            lease,
            json!({"action": "step_out"}),
        );
        settle(&mut engine);
        let state = engine.state_value();
        assert_eq!(state["pause"]["frames"][0]["function_name"], "collect");
        assert_eq!(
            state["pause"]["frames"][0]["line"], 6,
            "the call returned to the loop"
        );
        assert_eq!(state["pause"]["frames_recorded"], 2);

        // Stepping over never enters add: the loop header, the call, the next
        // header, then the return, all in the one frame.
        let mut lines = Vec::new();
        for _ in 0..3 {
            let lease = engine.lease_id().expect("the step paused again");
            run(
                &mut engine,
                OP_STEP_OVER,
                lease,
                json!({"action": "step_over"}),
            );
            settle(&mut engine);
            let state = engine.state_value();
            assert_eq!(state["pause"]["frames_recorded"], 2);
            lines.push(
                state["pause"]["frames"][0]["line"]
                    .as_u64()
                    .unwrap_or_default(),
            );
        }
        assert_eq!(lines, [7, 6, 9]);

        let lease = engine.lease_id().expect("the step paused again");
        let outcome = run(&mut engine, OP_RESUME, lease, json!({"action": "resume"}));
        assert!(outcome.resumed && !engine.is_paused());
        settle(&mut engine);
        assert!(engine.finished());
        assert_eq!(engine.state_value()["lease"]["state"], "released");
    }

    #[test]
    fn a_stale_lease_is_refused_and_never_applied_to_the_next_pause() {
        let mut engine = authorized();
        // An unconditional line breakpoint in the loop pauses three times.
        run(
            &mut engine,
            OP_SET_BREAKPOINT,
            0,
            json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID, "line": 7,
                "column": 4, "confirm_pause": true}),
        );
        engine.run();
        let first = engine.lease_id().expect("a pause holds a lease");
        run(&mut engine, OP_RESUME, first, json!({"action": "resume"}));
        settle(&mut engine);
        assert!(engine.is_paused(), "the next iteration pauses again");
        let outcome = run(&mut engine, OP_RESUME, first, json!({"action": "resume"}));
        assert_eq!(outcome.status, Status::StaleLease);
        assert!(engine.is_paused(), "the second pause was not resumed");
    }

    #[test]
    fn evaluating_on_a_frame_reads_and_writes_the_paused_page() {
        let mut engine = authorized();
        conditional(&mut engine, "item === 2");
        engine.run();
        let lease = engine.lease_id().expect("a pause holds a lease");
        let read = run(
            &mut engine,
            OP_EVALUATE_ON_FRAME,
            lease,
            json!({"action": "evaluate_on_frame", "call_frame_index": 0,
                "expression": "total + item"}),
        );
        assert_eq!(read.status, Status::Ok);
        assert_eq!(read.value["text"], "3");
        assert_eq!(read.value["threw"], false);

        let write = run(
            &mut engine,
            OP_EVALUATE_ON_FRAME,
            lease,
            json!({"action": "evaluate_on_frame", "call_frame_index": 0,
                "expression": "total = 40"}),
        );
        assert_eq!(write.status, Status::Ok);
        assert!(locals(&mut engine, 0).contains(&("total".into(), "40".into())));

        let threw = run(
            &mut engine,
            OP_EVALUATE_ON_FRAME,
            lease,
            json!({"action": "evaluate_on_frame", "call_frame_index": 0,
                "expression": "nope.length"}),
        );
        assert_eq!(threw.status, Status::EvaluationError);
        assert_eq!(threw.value["threw"], true);
        assert!(
            threw.value["text"]
                .as_str()
                .unwrap_or_default()
                .contains("not defined")
        );

        let past = run(
            &mut engine,
            OP_EVALUATE_ON_FRAME,
            lease,
            json!({"action": "evaluate_on_frame", "call_frame_index": 9,
                "expression": "total"}),
        );
        assert_eq!(past.status, Status::Limit);

        // The page really changed: the sum carries the written value on.
        let outcome = run(&mut engine, OP_RESUME, lease, json!({"action": "resume"}));
        assert!(outcome.resumed);
    }

    #[test]
    fn properties_page_and_stop() {
        let mut engine = authorized();
        conditional(&mut engine, "item === 2");
        engine.run();
        let lease = engine.lease_id().expect("a pause holds a lease");
        let global = engine.pause.as_ref().expect("paused").frames[0]["scopes"][1]["object_id"]
            .as_str()
            .expect("a global scope has an object id")
            .to_owned();
        let page = run(
            &mut engine,
            OP_GET_PROPERTIES,
            lease,
            json!({"action": "get_properties", "object_id": global, "offset": 0}),
        );
        let table = page.properties["items"]
            .as_array()
            .expect("a page")
            .iter()
            .find(|item| item["name"] == "table")
            .and_then(|item| item["object_id"].as_str())
            .expect("an array property can be expanded")
            .to_owned();

        let first = run(
            &mut engine,
            OP_GET_PROPERTIES,
            lease,
            json!({"action": "get_properties", "object_id": table, "offset": 0}),
        );
        assert_eq!(first.properties["total"], 201);
        assert_eq!(
            first.properties["items"].as_array().expect("a page").len(),
            PROPERTY_PAGE
        );
        assert_eq!(first.properties["next_offset"], "64");

        let last = run(
            &mut engine,
            OP_GET_PROPERTIES,
            lease,
            json!({"action": "get_properties", "object_id": table, "offset": 192}),
        );
        assert_eq!(last.properties["next_offset"], Value::Null);
        assert_eq!(
            last.properties["items"].as_array().expect("a page").len(),
            9
        );

        let unknown = run(
            &mut engine,
            OP_GET_PROPERTIES,
            lease,
            json!({"action": "get_properties", "object_id": "99999", "offset": 0}),
        );
        assert_eq!(unknown.status, Status::UnknownObject);
    }

    #[test]
    fn navigation_clears_the_authorization_and_retires_the_generation() {
        let mut engine = authorized();
        conditional(&mut engine, "item === 2");
        engine.run();
        let lease = engine.lease_id().expect("a pause holds a lease");
        let retired = engine.target();
        engine.navigate();
        assert!(!engine.is_paused());
        let state = engine.state_value();
        assert_eq!(state["document"], Value::Null);
        assert_eq!(state["active_indication"], Value::Null);
        assert_eq!(state["last_clear"], "navigated");
        assert_eq!(state["breakpoints"].as_array().expect("a list").len(), 0);
        assert_eq!(state["lease"]["state"], "released");
        assert_ne!(engine.target(), retired);

        // The retired generation is gone, whatever the command.
        for op in [OP_RESUME, OP_SELECT_DOCUMENT] {
            let outcome = engine.command(
                op,
                retired,
                lease,
                &json!({"action": "resume", "confirm_pause": true}),
            );
            assert_eq!(outcome.status, Status::StaleDocument, "op {op}");
        }
        // The current generation exists but nothing selected it.
        let current = engine.target();
        let outcome = engine.command(OP_RESUME, current, lease, &json!({"action": "resume"}));
        assert_eq!(outcome.status, Status::NotAuthorized);
    }

    #[test]
    fn an_expired_lease_resumes_the_page_and_says_so() {
        let mut engine = authorized();
        conditional(&mut engine, "item === 2");
        engine.run();
        let lease = engine.lease_id().expect("a pause holds a lease");
        engine.expire_lease();
        assert!(!engine.is_paused());
        let state = engine.state_value();
        assert_eq!(state["lease"]["state"], "expired");
        assert_eq!(state["lease"]["expires_in_ms"], 0);
        assert_eq!(state["pause"], Value::Null);
        assert_eq!(state["document"]["target_id"], FIXTURE_TARGET.to_string());
        assert_eq!(state["active_indication"], "Debugger active (detectable)");
        let outcome = run(&mut engine, OP_RESUME, lease, json!({"action": "resume"}));
        assert_eq!(outcome.status, Status::NotPaused);
        // The page runs on from where it stopped rather than being abandoned.
        settle(&mut engine);
        assert!(engine.finished());
    }

    /// The deadline belongs to the browser: a pause no client ever asks about
    /// is still resumed, and the lease says the browser did it.
    #[test]
    fn a_pause_nobody_observes_is_resumed_by_the_deadline() {
        let peer = Peer::spawn(Engine::new()).expect("the contract peer starts");
        peer.with_engine(|engine| {
            engine.set_lease_limit_ms(40);
        });
        let pause = NativeDebuggerPause::new(Some(peer.socket().to_path_buf()));
        pause
            .action(
                &json!({"action": "select_document", "target_id": FIXTURE_TARGET.to_string(),
                "confirm_pause": true}),
            )
            .expect("the peer answered");
        pause
            .action(
                &json!({"action": "set_breakpoint", "target_id": FIXTURE_TARGET.to_string(),
                "script_id": FIXTURE_SCRIPT_ID, "line": 7, "column": 4,
                "condition": "item === 2", "confirm_pause": true}),
            )
            .expect("the peer answered");
        // The page runs and stops with nobody holding the pause.
        peer.with_engine(|engine| engine.run());
        assert!(peer.with_engine(|engine| engine.is_paused()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while peer.with_engine(|engine| engine.is_paused()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !peer.with_engine(|engine| engine.is_paused()),
            "the browser's own clock resumed the page"
        );
        let state = pause.state();
        assert_eq!(state["lease"]["state"], "expired");
        assert_eq!(state["paused"], false);
    }

    /// Losing the socket is not a way to keep a page paused: the deadline is
    /// the browser's and it runs whether or not anything can reach it.
    #[test]
    fn a_pause_outlives_the_client_only_until_the_deadline() {
        let peer = Peer::spawn(Engine::new()).expect("the contract peer starts");
        peer.with_engine(|engine| {
            engine.set_lease_limit_ms(40);
            engine.command(
                OP_SELECT_DOCUMENT,
                FIXTURE_TARGET,
                0,
                &json!({"action": "select_document", "confirm_pause": true}),
            );
            engine.command(
                OP_SET_BREAKPOINT,
                FIXTURE_TARGET,
                0,
                &json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID, "line": 7,
                    "column": 4, "condition": "item === 2", "confirm_pause": true}),
            );
            engine.run();
        });
        assert!(peer.with_engine(|engine| engine.is_paused()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while peer.with_engine(|engine| engine.is_paused()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!peer.with_engine(|engine| engine.is_paused()));
        assert!(peer.with_engine(|engine| engine.state_value()["lease"]["state"] == "expired"));
    }

    /// A same-process iframe is an ordinary selection: the inspector session
    /// belongs to the local root either way.
    #[test]
    fn a_same_process_iframe_can_be_selected() {
        let mut engine = Engine::new();
        let child = engine.child_target();
        let outcome = engine.command(
            OP_SELECT_DOCUMENT,
            child,
            0,
            &json!({"action": "select_document", "confirm_pause": true}),
        );
        assert_eq!(outcome.status, Status::Ok);
        let state = engine.state_value();
        assert_eq!(state["document"]["target_id"], child.to_string());
        assert_eq!(state["document"]["frame"], "child");
        assert_eq!(state["active_indication"], "Debugger active (detectable)");
        // The top document is a current document that nothing selected.
        let top = engine.target();
        let outcome = engine.command(
            OP_PAUSE,
            top,
            0,
            &json!({"action": "pause",
            "confirm_pause": true}),
        );
        assert_eq!(outcome.status, Status::NotAuthorized);
    }

    /// Replacing a selection resumes and disarms the one it replaced; the old
    /// document is never left paused with nothing able to reach it.
    #[test]
    fn replacing_a_selection_while_paused_resumes_and_disarms_the_old_one() {
        let mut engine = authorized();
        conditional(&mut engine, "item === 2");
        engine.run();
        assert!(engine.is_paused());
        let child = engine.child_target();
        let outcome = engine.command(
            OP_SELECT_DOCUMENT,
            child,
            0,
            &json!({"action": "select_document", "confirm_pause": true}),
        );
        assert_eq!(outcome.status, Status::Ok);
        // The reply is the new selection's own state, which is what a fresh
        // session in the browser answers. That the replaced document was let
        // go is visible in the state below, not in this reply.
        assert!(!outcome.resumed);
        assert!(
            !engine.is_paused(),
            "the replaced document is not left paused"
        );
        let state = engine.state_value();
        assert_eq!(state["document"]["target_id"], child.to_string());
        assert_eq!(state["breakpoints"], json!([]), "nothing stays armed");
        assert_eq!(state["lease"], Value::Null, "the new selection holds none");
        assert_eq!(
            state["last_clear"],
            Value::Null,
            "the new selection is clean"
        );
    }

    #[test]
    fn exceptions_pause_only_in_the_mode_the_researcher_set() {
        let mut engine = authorized();
        assert!(!engine.throw(false));
        run(
            &mut engine,
            OP_PAUSE_ON_EXCEPTIONS,
            0,
            json!({"action": "pause_on_exceptions", "mode": "uncaught", "confirm_pause": true}),
        );
        assert!(
            !engine.throw(true),
            "a caught throw does not pause in uncaught mode"
        );
        assert!(engine.throw(false));
        assert_eq!(engine.state_value()["pause"]["reason"], "exception");
        let lease = engine.lease_id().expect("a pause holds a lease");
        run(
            &mut engine,
            OP_RELEASE_LEASE,
            lease,
            json!({"action": "release_lease"}),
        );
        run(
            &mut engine,
            OP_PAUSE_ON_EXCEPTIONS,
            0,
            json!({"action": "pause_on_exceptions", "mode": "all", "confirm_pause": true}),
        );
        assert!(engine.throw(true));
    }

    #[test]
    fn quiet_mode_swallows_the_pages_own_debugger_statement() {
        let mut engine = authorized();
        assert!(engine.state_value()["quiet_mode"] == json!(true));
        assert!(!engine.debugger_statement(), "quiet mode ignores it");
        engine.set_quiet_mode(false);
        assert!(engine.debugger_statement());
        assert_eq!(
            engine.state_value()["pause"]["reason"],
            "debugger_statement"
        );
    }

    #[test]
    fn the_breakpoint_bound_and_the_unconfirmed_and_unauthorized_paths() {
        let mut engine = Engine::new();
        let refused = run(
            &mut engine,
            OP_PAUSE,
            0,
            json!({"action": "pause",
            "confirm_pause": true}),
        );
        assert_eq!(refused.status, Status::NotAuthorized);
        let mut engine = authorized();
        let unconfirmed = run(
            &mut engine,
            OP_SET_BREAKPOINT,
            0,
            json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID, "line": 7,
                "column": 4}),
        );
        assert_eq!(unconfirmed.status, Status::InvalidInput);
        for index in 0..BREAKPOINT_LIMIT {
            let outcome = run(
                &mut engine,
                OP_SET_BREAKPOINT,
                0,
                json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID,
                    "line": index + 1, "column": 0, "confirm_pause": true}),
            );
            assert_eq!(outcome.status, Status::Ok);
        }
        let over = run(
            &mut engine,
            OP_SET_BREAKPOINT,
            0,
            json!({"action": "set_breakpoint", "script_id": FIXTURE_SCRIPT_ID, "line": 99,
                "column": 0, "confirm_pause": true}),
        );
        assert_eq!(over.status, Status::Limit);
        let unknown = run(
            &mut engine,
            OP_REMOVE_BREAKPOINT,
            0,
            json!({"action": "remove_breakpoint", "breakpoint_id": "9999"}),
        );
        assert_eq!(unknown.status, Status::UnknownBreakpoint);
    }

    #[test]
    fn the_pause_button_stops_at_the_next_statement() {
        let mut engine = authorized();
        run(
            &mut engine,
            OP_PAUSE,
            0,
            json!({"action": "pause", "confirm_pause": true}),
        );
        engine.run();
        assert_eq!(engine.state_value()["pause"]["reason"], "pause");
        assert_eq!(engine.state_value()["pause"]["frames"][0]["line"], 11);
    }

    #[test]
    fn without_a_socket_the_state_is_unsupported_and_nothing_is_sent() {
        let pause = NativeDebuggerPause::new(None);
        let state = pause.state();
        assert_eq!(state["availability"], "unsupported");
        assert_eq!(state["reason"], "browser_debugger_unsupported");
        assert_eq!(state["document"], Value::Null);
        assert_eq!(state["pause"], Value::Null);
        let error = pause
            .action(&json!({"action": "resume", "target_id": "22",
                "lease_id": "1"}))
            .unwrap_err();
        assert_eq!(error.status, 503);
        assert!(error.message.contains("no page paused, stepped or resumed"));
    }

    #[test]
    fn a_missing_peer_is_unavailable_not_an_idle_debugger() {
        let directory = tempfile::tempdir().expect("a private directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private");
        let socket = directory.path().join("absent.sock");
        let pause = NativeDebuggerPause::new(Some(socket));
        let state = pause.state();
        assert_eq!(state["availability"], "unsupported");
        assert_eq!(state["reason"], "peer_unavailable");
        assert_eq!(state["breakpoints"], json!([]));
        let error = pause
            .action(&json!({"action": "resume", "target_id": "22",
                "lease_id": "1"}))
            .unwrap_err();
        assert_eq!(error.status, 503);
    }

    #[test]
    fn a_world_readable_socket_is_refused_before_anything_is_sent() {
        let peer = Peer::spawn(Engine::new()).expect("the contract peer starts");
        std::fs::set_permissions(peer.socket(), std::fs::Permissions::from_mode(0o666))
            .expect("relax the socket");
        let pause = NativeDebuggerPause::new(Some(peer.socket().to_path_buf()));
        assert_eq!(pause.state()["reason"], "peer_unavailable");
        let error = pause
            .action(&json!({"action": "resume", "target_id": "22",
                "lease_id": "1"}))
            .unwrap_err();
        assert_eq!(error.status, 503);
        assert!(error.message.contains("private user socket"));
    }

    #[test]
    fn the_socket_round_trip_matches_the_engine() {
        let peer = Peer::spawn(Engine::new()).expect("the contract peer starts");
        let pause = NativeDebuggerPause::new(Some(peer.socket().to_path_buf()));
        let state = pause.state();
        assert_eq!(state["availability"], "available");
        assert_eq!(state["reason"], Value::Null);
        assert_eq!(state["document"], Value::Null);

        let select = pause
            .action(&json!({"action": "select_document", "target_id": "22", "confirm_pause": true}))
            .expect("the peer answered");
        assert_eq!(select["status"], "ok");
        assert_eq!(select["paused"], false);
        assert_eq!(select["resumed"], false);
        assert_eq!(select["pause"], Value::Null);

        pause
            .action(&json!({"action": "set_breakpoint", "target_id": "22",
                "script_id": FIXTURE_SCRIPT_ID, "line": 7, "column": 4,
                "condition": "item === 2", "confirm_pause": true}))
            .expect("the peer answered");
        peer.with_engine(|engine| engine.run());
        let state = pause.state();
        assert_eq!(state["paused"], true);
        assert_eq!(state["pause"]["frames"][0]["function_name"], "collect");
        let lease = state["lease"]["lease_id"]
            .as_str()
            .expect("a lease")
            .to_owned();

        let stale = pause
            .action(&json!({"action": "resume", "target_id": "99", "lease_id": lease}))
            .expect("the peer answered");
        assert_eq!(stale["status"], "stale_document");
        assert_eq!(stale["paused"], true);

        let resumed = pause
            .action(&json!({"action": "resume", "target_id": "22",
                "lease_id": lease}))
            .expect("the peer answered");
        assert_eq!(resumed["status"], "ok");
        assert_eq!(resumed["resumed"], true);
        assert_eq!(resumed["paused"], false);
        // The page runs on after the reply, on the peer's own clock.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !peer.with_engine(|engine| engine.finished()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(peer.with_engine(|engine| engine.finished()));
    }

    /// The peer's own framing guard: a header it cannot decode, an operation
    /// past the socket's range, and a body whose action is not the operation.
    #[test]
    fn the_peer_refuses_a_frame_it_cannot_decode() {
        use std::io::Write;
        let peer = Peer::spawn(Engine::new()).expect("the contract peer starts");
        let frame = |magic: u32, version: u16, op: u16, id: u64, body: &[u8]| {
            let mut request = Vec::new();
            request.extend_from_slice(&magic.to_le_bytes());
            request.extend_from_slice(&version.to_le_bytes());
            request.extend_from_slice(&op.to_le_bytes());
            request.extend_from_slice(&id.to_le_bytes());
            request.extend_from_slice(&FIXTURE_TARGET.to_le_bytes());
            request.extend_from_slice(&0u64.to_le_bytes());
            request.extend_from_slice(&0u64.to_le_bytes());
            request.extend_from_slice(&(body.len() as u32).to_le_bytes());
            request.extend_from_slice(&0u32.to_le_bytes());
            request.extend_from_slice(body);
            request
        };
        let exchange_raw = |request: Vec<u8>| {
            let mut stream = UnixStream::connect(peer.socket()).expect("connect");
            stream.write_all(&request).expect("write");
            let mut header = [0u8; RESPONSE_HEADER];
            stream
                .read_exact(&mut header)
                .expect("the peer always answers");
            decode_response(&header).expect("a decodable reply").status
        };
        let good = br#"{"action":"select_document","confirm_pause":true}"#;
        assert_eq!(
            exchange_raw(frame(0x4142_4344, VERSION, OP_SELECT_DOCUMENT, 1, good)),
            Status::Malformed,
            "another protocol's magic"
        );
        assert_eq!(
            exchange_raw(frame(MAGIC, 2, OP_SELECT_DOCUMENT, 2, good)),
            Status::Malformed,
            "a version this peer does not speak"
        );
        assert_eq!(
            exchange_raw(frame(MAGIC, VERSION, 19, 3, good)),
            Status::Malformed,
            "expire_lease never crosses the socket"
        );
        assert_eq!(
            exchange_raw(frame(MAGIC, VERSION, OP_SELECT_DOCUMENT, 0, good)),
            Status::Malformed,
            "a zero request id"
        );
        let mut reserved = frame(MAGIC, VERSION, OP_SELECT_DOCUMENT, 6, good);
        reserved[24] = 3;
        assert_eq!(
            exchange_raw(reserved),
            Status::Malformed,
            "a second identity in the reserved slot"
        );
        assert_eq!(
            exchange_raw(frame(MAGIC, VERSION, OP_RESUME, 4, good)),
            Status::Malformed,
            "a body whose action is not the operation"
        );
        assert_eq!(
            exchange_raw(frame(MAGIC, VERSION, OP_SELECT_DOCUMENT, 5, b"not json")),
            Status::Malformed,
            "a body that is not JSON"
        );
        // None of that selected anything.
        assert!(!peer.with_engine(|engine| engine.state_value()["document"] != Value::Null));
    }

    #[test]
    fn a_reply_that_disagrees_with_its_header_is_not_a_result() {
        let directory = tempfile::tempdir().expect("a private directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private");
        let socket = directory.path().join("liar.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("private socket");
        // Four replies, in the order the asserts below ask for them.
        let bodies: Vec<Vec<u8>> = vec![
            serde_json::to_vec(
                &json!({"action": "step_over", "status": "ok", "paused": true,
                "resumed": false, "lease": Value::Null, "pause": Value::Null,
                "breakpoint": Value::Null, "value": Value::Null, "properties": Value::Null}),
            )
            .expect("json"),
            serde_json::to_vec(&json!({"action": "resume", "status": "not_paused",
                "paused": true, "resumed": false, "lease": Value::Null, "pause": Value::Null,
                "breakpoint": Value::Null, "value": Value::Null, "properties": Value::Null}))
            .expect("json"),
            b"{ not json".to_vec(),
            serde_json::to_vec(&json!({"action": "resume", "status": "ok", "paused": true,
                "resumed": false, "lease": Value::Null, "pause": Value::Null,
                "breakpoint": Value::Null, "value": "a string", "properties": Value::Null}))
            .expect("json"),
        ];
        let server = std::thread::spawn(move || {
            for body in bodies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut header = [0u8; REQUEST_HEADER];
                if stream.read_exact(&mut header).is_err() {
                    return;
                }
                let request = decode_request(&header).expect("the client frames correctly");
                let mut payload = vec![0u8; request.payload_len];
                let _ = stream.read_exact(&mut payload);
                let _ = write_all(
                    &mut stream,
                    &encode_reply(request.id, Status::Ok, true, false, &body),
                );
            }
        });
        let pause = NativeDebuggerPause::new(Some(socket));
        let command = json!({"action": "resume", "target_id": "22",
            "lease_id": "1"});
        let wrong_action = pause.action(&command).unwrap_err();
        assert_eq!(wrong_action.status, 422);
        assert!(wrong_action.message.contains("did not match the action"));
        let wrong_status = pause.action(&command).unwrap_err();
        assert_eq!(wrong_status.status, 422);
        assert!(wrong_status.message.contains("disagreed with its header"));
        let not_json = pause.action(&command).unwrap_err();
        assert_eq!(not_json.status, 422);
        assert!(not_json.message.contains("was not JSON"));
        // A reply this contract does not define is the peer's fault, not this
        // backend's: the client is told the outcome is unknown and what was
        // wrong with the reply.
        let off_contract = pause.action(&command).unwrap_err();
        assert_eq!(off_contract.status, 422);
        assert!(
            off_contract
                .message
                .contains("does not match this contract")
                && off_contract.message.contains("NativeDebuggerActionResult"),
            "{}",
            off_contract.message
        );
        assert_eq!(off_contract.reason.code, Code::CommandOutcomeUnknown);
        server.join().expect("the stand-in peer finishes");
    }
}
