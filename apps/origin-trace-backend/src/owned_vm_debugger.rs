//! One cooperative, repository-owned fixture. The cached public view is never a
//! command channel. In particular, inspecting or exporting it cannot dispatch.
use crate::{
    error::{Cause, Code, Error, Reason, Result},
    worker,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    future::Future,
    io::Read,
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{Mutex, mpsc, oneshot, watch},
    task::JoinHandle,
};

const SCHEMA: &str = "reb-owned-vm-debug-session-v1";
const MAGIC: u32 = 0x314d5652;
const BODY_LIMIT: usize = 2048;
const REPLY_LIMIT: usize = 32768;
const VIEW_LIMIT: usize = 1024 * 1024;
const STDERR_LIMIT: u64 = 8192;
const RUN_INTERVAL: Duration = Duration::from_millis(250);
const LIFETIME: Duration = Duration::from_secs(60);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);
const START_TIMEOUT: Duration = Duration::from_secs(5);
const PCS: [u64; 10] = [0, 1, 2, 3, 4, 5, 6, 8, 10, 10];

type Exchange = Pin<Box<dyn Future<Output = Result<NativeReply>> + Send>>;
type Disposal<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// A JSON string, never a JSON number, including for the smallest counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Decimal(pub u64);
impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.is_empty()
            || s.len() > 20
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("expected canonical uint64 string"));
        }
        s.parse().map(Decimal).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Fixture {
    Register,
    Stack,
}
impl Fixture {
    fn name(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Stack => "stack",
        }
    }
    fn program(self) -> &'static str {
        match self {
            Self::Register => "owned-register-v1",
            Self::Stack => "owned-stack-v1",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    Observed,
    Inferred,
    Unknown,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuestValue {
    pub bits: Decimal,
    pub evidence: Evidence,
}
impl GuestValue {
    fn valid(&self) -> bool {
        self.evidence != Evidence::Unknown || self.bits.0 == 0
    }
    fn unknown() -> Self {
        Self {
            bits: Decimal(0),
            evidence: Evidence::Unknown,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryCell {
    pub guest_address: Decimal,
    pub value: GuestValue,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub pc: Decimal,
    pub pc_evidence: Evidence,
    pub partial: bool,
    pub halted: bool,
    pub registers: Vec<GuestValue>,
    pub stack: Vec<GuestValue>,
    pub memory: Vec<MemoryCell>,
}
impl Snapshot {
    fn initial(fixture: Fixture) -> Self {
        Self {
            pc: Decimal(0),
            pc_evidence: Evidence::Observed,
            partial: false,
            halted: false,
            registers: if fixture == Fixture::Register {
                vec![GuestValue::unknown(); 3]
            } else {
                vec![]
            },
            stack: vec![],
            memory: vec![],
        }
    }
    fn valid_at(&self, fixture: Fixture, count: u64) -> bool {
        const STACK_COUNTS: [usize; 10] = [0, 1, 2, 1, 0, 1, 1, 1, 1, 1];
        count <= 9
            && self.valid(fixture)
            && self.stack.len()
                == (if fixture == Fixture::Stack {
                    STACK_COUNTS[count as usize]
                } else {
                    0
                })
            && self.memory.len() == usize::from(count >= 4)
            && self.memory.iter().all(|cell| cell.guest_address.0 == 16)
    }
    fn valid(&self, fixture: Fixture) -> bool {
        let mut addresses = BTreeSet::new();
        self.pc.0 <= 10
            && (self.pc_evidence != Evidence::Unknown || self.pc.0 == 0)
            && self.registers.len() == (if fixture == Fixture::Register { 3 } else { 0 })
            && self.stack.len() <= (if fixture == Fixture::Stack { 8 } else { 0 })
            && self.memory.len() <= 8
            && self
                .registers
                .iter()
                .chain(self.stack.iter())
                .all(GuestValue::valid)
            && self
                .memory
                .iter()
                .all(|c| c.value.valid() && addresses.insert(c.guest_address))
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    Immediate,
    Register,
    Stack,
    Memory,
}
impl Location {
    fn valid(self, index: Decimal) -> bool {
        match self {
            Self::Immediate => index.0 == 0,
            Self::Register | Self::Stack => index.0 < 8,
            Self::Memory => true,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operand {
    pub location: Location,
    pub index: Decimal,
    pub value: GuestValue,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub access: Access,
    pub location: Location,
    pub index: Decimal,
    pub value: GuestValue,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub sequence: Decimal,
    pub tick: Decimal,
    pub opcode: u32,
    pub opcode_evidence: Evidence,
    pub partial: bool,
    pub operands: Vec<Operand>,
    pub effects: Vec<Effect>,
    pub before: Snapshot,
    pub after: Snapshot,
}
impl Record {
    fn valid(&self, fixture: Fixture) -> bool {
        self.sequence.0 > 0
            && self.tick.0 > 0
            && self.opcode <= 8
            && (self.opcode_evidence != Evidence::Unknown || self.opcode == 0)
            && self.operands.len() <= 4
            && self.effects.len() <= 8
            && self.before.valid(fixture)
            && self.after.valid(fixture)
            && self
                .operands
                .iter()
                .all(|o| o.location.valid(o.index) && o.value.valid())
            && self.effects.iter().all(|e| {
                e.location != Location::Immediate && e.location.valid(e.index) && e.value.valid()
            })
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecorderStats {
    pub attempted: Decimal,
    pub recorded: Decimal,
    pub full: Decimal,
    pub malformed: Decimal,
    pub wrong_document: Decimal,
    pub stale_generation: Decimal,
    pub exhausted: Decimal,
    pub expired: Decimal,
    pub partial: Decimal,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RecorderResult {
    Recorded,
    Disabled,
    StaleGeneration,
    WrongDocument,
    Expired,
    Malformed,
    Full,
    Exhausted,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum NativeState {
    Paused,
    Halted,
    Expired,
    Stopped,
    Failed,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeView {
    schema: String,
    fixture: Fixture,
    program_id: String,
    fixture_revision: u32,
    session_id: Decimal,
    document_id: Decimal,
    invocation_id: Decimal,
    run_generation: Decimal,
    state: NativeState,
    executed_count: Decimal,
    retained_count: Decimal,
    snapshot: Snapshot,
    transition: Option<Record>,
    recorder_result: Option<RecorderResult>,
    stats: RecorderStats,
    tick_units: String,
}
#[derive(Clone, Debug)]
struct NativeReply {
    status: u16,
    view: NativeView,
}
#[derive(Clone, Copy, Debug)]
struct WireRequest {
    id: u64,
    generation: u64,
    count: u64,
    operation: u16,
}
#[derive(Clone, Debug)]
struct SpawnSpec {
    fixture: Fixture,
    session: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Run,
    Pause,
    Step,
    Stop,
    Reset,
    Close,
}
impl Action {
    fn urgent(self) -> bool {
        matches!(self, Self::Pause | Self::Stop | Self::Reset | Self::Close)
    }
}
/// Intentionally not flattened: serde detects duplicate keys before a Value can
/// erase them. Per-action field presence is checked in parse(), below.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub action: Action,
    pub command_id: String,
    pub fixture: Option<Fixture>,
    pub backend_instance_id: Option<String>,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
    pub run_generation: Option<Decimal>,
    pub expected_control_revision: Option<Decimal>,
    pub expected_executed_count: Option<Decimal>,
}
impl ControlRequest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > BODY_LIMIT {
            return Err(Error::bad("VM control body exceeds 2 KiB"));
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| Error::bad("Invalid VM control request"))?;
        let has_scope = request.backend_instance_id.is_some()
            && request.session_id.is_some()
            && request.run_id.is_some()
            && request.run_generation.is_some();
        let no_scope = request.backend_instance_id.is_none()
            && request.session_id.is_none()
            && request.run_id.is_none()
            && request.run_generation.is_none();
        if !identifier(&request.command_id)
            || request.command_id.len() > 64
            || request
                .backend_instance_id
                .iter()
                .chain(request.session_id.iter())
                .chain(request.run_id.iter())
                .any(|s| !identifier(s))
            || if request.action == Action::Create {
                request.fixture.is_none() || !no_scope
            } else {
                request.fixture.is_some() || !has_scope
            }
            || request.expected_control_revision.is_some()
                != matches!(request.action, Action::Run | Action::Step)
            || request.expected_executed_count.is_some() != (request.action == Action::Step)
        {
            return Err(Error::bad(
                "VM action fields do not match the selected action",
            ));
        }
        // An explicit null is not an omitted field in this strict command API.
        let object: serde_json::Map<String, Value> =
            serde_json::from_slice(bytes).map_err(|_| Error::bad("Invalid VM control request"))?;
        if object.values().any(Value::is_null) {
            return Err(Error::bad("VM control fields cannot be null"));
        }
        Ok(request)
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSelector {
    pub backend_instance_id: String,
    pub session_id: String,
    pub run_id: String,
    pub run_generation: Decimal,
}
impl TraceSelector {
    pub fn parse(query: &str) -> Result<Self> {
        if query.is_empty() || query.len() > 1024 {
            return Err(Error::bad("Exact VM trace selection is required"));
        }
        let mut fields = serde_json::Map::new();
        for pair in query.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| Error::bad("Invalid VM trace selection"))?;
            let key = decode_query(key)?;
            let value = decode_query(value)?;
            if fields.insert(key, Value::String(value)).is_some() {
                return Err(Error::bad("Duplicate VM trace selector"));
            }
        }
        let selected: Self = serde_json::from_value(Value::Object(fields))
            .map_err(|_| Error::bad("Invalid exact VM trace selection"))?;
        if !identifier(&selected.backend_instance_id)
            || !identifier(&selected.session_id)
            || !identifier(&selected.run_id)
        {
            return Err(Error::bad("Invalid exact VM trace identity"));
        }
        Ok(selected)
    }
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn decode_query(input: &str) -> Result<String> {
    let mut output = Vec::new();
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        output.push(match b {
            b'+' => b' ',
            b'%' => {
                let high = bytes.next().and_then(|v| (v as char).to_digit(16));
                let low = bytes.next().and_then(|v| (v as char).to_digit(16));
                match (high, low) {
                    (Some(h), Some(l)) => ((h << 4) | l) as u8,
                    _ => return Err(Error::bad("Invalid VM selector encoding")),
                }
            }
            _ => b,
        });
    }
    String::from_utf8(output).map_err(|_| Error::bad("VM selector is not UTF-8"))
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Starting,
    Paused,
    Running,
    Pausing,
    Stepping,
    Stopping,
    Halted,
    Stopped,
    Expired,
    Failed,
}
impl State {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Halted | Self::Stopped | Self::Expired | Self::Failed
        )
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ack {
    Pending,
    Completed,
    Rejected,
    OutcomeUnknown,
}
#[derive(Clone, Debug, Serialize)]
pub struct LastCommand {
    pub command_id: String,
    pub action: Action,
    pub ack: Ack,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Diagnostics {
    pub stderr_bytes: Decimal,
    pub stderr_truncated: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecorderView {
    pub session_id: Decimal,
    pub document_id: Decimal,
    pub invocation_id: Decimal,
    pub generation: Decimal,
    pub stats: RecorderStats,
}
#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    pub backend_instance_id: String,
    pub session_id: String,
    pub run_id: String,
    pub run_generation: Decimal,
    pub provider: &'static str,
    pub target_kind: &'static str,
    pub fixture: Fixture,
    pub program_id: &'static str,
    pub fixture_revision: u32,
    pub program_sha256: String,
    pub program_manifest_scope: &'static str,
    pub build_id: Option<String>,
    pub build_id_scope: &'static str,
    pub pc_units: &'static str,
    pub value_semantics: &'static str,
    pub tick_units: &'static str,
    pub state: State,
    pub control_revision: Decimal,
    pub snapshot_revision: Decimal,
    pub executed_count: Decimal,
    pub retained_count: Decimal,
    pub execution_state_known: bool,
    pub termination_reason: Option<&'static str>,
    pub initial_snapshot: Option<Snapshot>,
    pub current_snapshot: Option<Snapshot>,
    pub records: Vec<Record>,
    pub recorder: RecorderView,
    pub last_command: Option<LastCommand>,
    pub diagnostics: Diagnostics,
    pub disposal_failed: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct PublicView {
    pub schema: &'static str,
    pub available: bool,
    pub unavailable_reason: Option<&'static str>,
    pub backend_instance_id: String,
    pub session: Option<SessionView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack: Option<Ack>,
}

trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}
struct MonotonicClock(tokio::time::Instant);
impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}
trait NativeChild: Send {
    fn exchange(&self, request: WireRequest) -> Exchange;
    fn dispose(&mut self) -> Disposal<'_>;
    fn diagnostics(&self) -> Diagnostics;
}
trait Factory: Send + Sync {
    fn available(&self) -> bool;
    fn spawn(&self, spec: &SpawnSpec) -> Result<(Box<dyn NativeChild>, String)>;
}
struct ProcessFactory {
    path: PathBuf,
}
struct Pipe {
    input: tokio::process::ChildStdin,
    output: tokio::process::ChildStdout,
}
#[derive(Default)]
struct CapturedDiagnostics {
    view: Diagnostics,
    retained: Vec<u8>,
}
struct ProcessChild {
    child: Child,
    group: i32,
    pipe: Arc<Mutex<Pipe>>,
    diagnostics: Arc<StdMutex<CapturedDiagnostics>>,
    stderr: JoinHandle<()>,
}
impl Factory for ProcessFactory {
    fn available(&self) -> bool {
        worker::executable(&self.path)
    }
    fn spawn(&self, spec: &SpawnSpec) -> Result<(Box<dyn NativeChild>, String)> {
        if !self.available() {
            return Err(dependency());
        }
        let mut file = std::fs::File::open(&self.path).map_err(|_| dependency())?;
        let before = file.metadata().map_err(|_| dependency())?;
        if before.len() > 64 * 1024 * 1024 {
            return Err(Error::new(503, "Configured VM helper exceeds 64 MiB")
                .with_code(Code::ResourceLimit));
        }
        let mut hash = Sha256::new();
        let mut total = 0u64;
        let mut chunk = [0u8; 32768];
        loop {
            let n = file.read(&mut chunk).map_err(|_| dependency())?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > 64 * 1024 * 1024 {
                return Err(dependency());
            }
            hash.update(&chunk[..n]);
        }
        let after = file.metadata().map_err(|_| dependency())?;
        let admission = self.path.metadata().map_err(|_| dependency())?;
        if total != before.len() || !same_file(&before, &after) || !same_file(&before, &admission) {
            return Err(dependency());
        }
        let build = hex::encode(hash.finalize());
        let mut command = Command::new(&self.path);
        command
            .args([
                "--control-owned-fixture-v1",
                "--fixture",
                spec.fixture.name(),
                "--session-id",
            ])
            .arg(spec.session.to_string())
            .args(["--document-id", "1", "--invocation-id"])
            .arg(spec.generation.to_string())
            .arg("--run-generation")
            .arg(spec.generation.to_string())
            .args(["--lifetime-ms", "60000"])
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
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
        let mut child = command.spawn().map_err(|_| dependency())?;
        let group = i32::try_from(child.id().ok_or_else(dependency)?).map_err(|_| dependency())?;
        let input = child.stdin.take().ok_or_else(dependency)?;
        let output = child.stdout.take().ok_or_else(dependency)?;
        let mut stderr = child.stderr.take().ok_or_else(dependency)?;
        let diagnostics = Arc::new(StdMutex::new(CapturedDiagnostics::default()));
        let captured = diagnostics.clone();
        let task = tokio::spawn(async move {
            // Drain all bytes so stderr cannot block stdout. No raw diagnostics
            // escape this owner; only a capped byte count and truncation flag do.
            let mut buffer = [0u8; 1024];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut state = captured.lock().unwrap();
                        let count = state.view.stderr_bytes.0.saturating_add(n as u64);
                        let retain = n.min(STDERR_LIMIT as usize - state.retained.len());
                        state.retained.extend_from_slice(&buffer[..retain]);
                        state.view.stderr_truncated |= count > STDERR_LIMIT;
                        state.view.stderr_bytes = Decimal(count.min(STDERR_LIMIT));
                    }
                }
            }
        });
        Ok((
            Box::new(ProcessChild {
                child,
                group,
                pipe: Arc::new(Mutex::new(Pipe { input, output })),
                diagnostics,
                stderr: task,
            }),
            build,
        ))
    }
}
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}
fn dependency() -> Error {
    Error::new(
        503,
        "Owned VM helper is unavailable or changed during admission",
    )
    .with_code(Code::DependencyUnavailable)
}
fn uncertain(cause: Cause) -> Error {
    Error::new(
        502,
        "Owned VM instruction outcome is unknown; reset the selected run",
    )
    .with_reason(Reason::uncertain(cause))
}
fn busy() -> Error {
    Error::conflict("Owned VM control is busy; inspect state before another command")
}
impl NativeChild for ProcessChild {
    fn exchange(&self, request: WireRequest) -> Exchange {
        let pipe = self.pipe.clone();
        Box::pin(async move {
            let duration = if request.operation == 0 {
                START_TIMEOUT
            } else {
                EXCHANGE_TIMEOUT
            };
            tokio::time::timeout(duration, async {
                let mut pipe = pipe.lock().await;
                if request.operation != 0 {
                    let mut header = [0u8; 40];
                    header[0..4].copy_from_slice(&MAGIC.to_le_bytes());
                    header[4..6].copy_from_slice(&1u16.to_le_bytes());
                    header[6..8].copy_from_slice(&request.operation.to_le_bytes());
                    header[8..16].copy_from_slice(&request.id.to_le_bytes());
                    header[16..24].copy_from_slice(&request.generation.to_le_bytes());
                    header[24..32].copy_from_slice(&request.count.to_le_bytes());
                    pipe.input
                        .write_all(&header)
                        .await
                        .map_err(|_| uncertain(Cause::TransportFailure))?;
                    pipe.input
                        .flush()
                        .await
                        .map_err(|_| uncertain(Cause::TransportFailure))?;
                }
                let mut header = [0u8; 24];
                pipe.output
                    .read_exact(&mut header)
                    .await
                    .map_err(|_| uncertain(Cause::Disconnected))?;
                let (status, bytes) = parse_header(&header, request.id)?;
                let mut payload = vec![0; bytes];
                pipe.output
                    .read_exact(&mut payload)
                    .await
                    .map_err(|_| uncertain(Cause::Disconnected))?;
                require_nullable_fields(&payload)?;
                let view: NativeView =
                    serde_json::from_slice(&payload).map_err(|_| uncertain(Cause::InvalidReply))?;
                Ok(NativeReply { status, view })
            })
            .await
            .map_err(|_| uncertain(Cause::Timeout))?
        })
    }
    fn dispose(&mut self) -> Disposal<'_> {
        Box::pin(async move {
            if self.group == 0 {
                return Ok(());
            }
            // Signal only the group created by this owner. Keep ownership after
            // a failed reap: a replacement cannot start while it is unresolved.
            #[cfg(unix)]
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
            let _ = self.child.start_kill();
            tokio::time::timeout(EXCHANGE_TIMEOUT, self.child.wait())
                .await
                .map_err(|_| {
                    Error::new(503, "Owned VM helper could not be reaped")
                        .with_code(Code::ResourceLimit)
                })?
                .map_err(|_| {
                    Error::new(503, "Owned VM helper disposal failed")
                        .with_code(Code::ApplicationFailed)
                })?;
            self.group = 0;
            // Once the exact group is gone, allow its last buffered diagnostics
            // to drain. A stuck inherited pipe still cannot delay disposal.
            if tokio::time::timeout(Duration::from_millis(100), &mut self.stderr)
                .await
                .is_err()
            {
                self.diagnostics.lock().unwrap().view.stderr_truncated = true;
                self.stderr.abort();
            }
            Ok(())
        })
    }
    fn diagnostics(&self) -> Diagnostics {
        self.diagnostics.lock().unwrap().view.clone()
    }
}
impl Drop for ProcessChild {
    fn drop(&mut self) {
        if self.group > 0 {
            #[cfg(unix)]
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
        }
        self.stderr.abort();
    }
}
fn require_nullable_fields(payload: &[u8]) -> Result<()> {
    // Option fields in a derived struct accept absent keys. Check presence
    // separately, without converting the input used by the strict typed parser:
    // duplicate fields are still rejected from the original bytes below.
    let fields: std::collections::BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(payload).map_err(|_| uncertain(Cause::InvalidReply))?;
    if !fields.contains_key("transition") || !fields.contains_key("recorder_result") {
        return Err(uncertain(Cause::InvalidReply));
    }
    Ok(())
}
fn parse_header(bytes: &[u8; 24], request: u64) -> Result<(u16, usize)> {
    let u16_at = |i| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
    let u32_at = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    let status = u16_at(6);
    let length = u32_at(16) as usize;
    if u32_at(0) != MAGIC
        || u16_at(4) != 1
        || status > 9
        || u64::from_le_bytes(bytes[8..16].try_into().unwrap()) != request
        || u32_at(20) != 0
        || length == 0
        || length > REPLY_LIMIT
    {
        return Err(uncertain(Cause::InvalidReply));
    }
    Ok((status, length))
}

struct Envelope {
    request: ControlRequest,
    reply: oneshot::Sender<Result<Value>>,
}
struct Runtime {
    view: SessionView,
    spec: SpawnSpec,
    created: Duration,
    last_clock: Duration,
    next_tick: Option<Duration>,
    next_request: u64,
    identity_active: bool,
    expiry_pending: bool,
}
struct Owner {
    factory: Arc<dyn Factory>,
    clock: Arc<dyn Clock>,
    instance: String,
    normal: mpsc::Receiver<Envelope>,
    urgent: mpsc::Receiver<Envelope>,
    shutdown: watch::Receiver<bool>,
    published: watch::Sender<PublicView>,
    session: Option<Runtime>,
    child: Option<Box<dyn NativeChild>>,
    exchange: Option<Exchange>,
    pending: Option<Envelope>,
    pause: Option<Envelope>,
    next_session: u64,
    next_generation: u64,
}
/// One actor and eight queued messages total: seven ordinary slots and one
/// reserved quiescing slot. Pending controls do not hold a mutex around native
/// I/O. A Pause accepted during I/O is acknowledged only after that I/O settles.
pub struct OwnedVmDebugger {
    normal: mpsc::Sender<Envelope>,
    urgent: mpsc::Sender<Envelope>,
    published: watch::Receiver<PublicView>,
    shutdown: watch::Sender<bool>,
    owner: Mutex<Option<JoinHandle<Result<()>>>>,
}
impl OwnedVmDebugger {
    pub fn new(helper: PathBuf) -> Self {
        let mut nonce = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut nonce))
            .expect("Operating system random source");
        Self::with_factory(
            Arc::new(ProcessFactory { path: helper }),
            Arc::new(MonotonicClock(tokio::time::Instant::now())),
            hex::encode(nonce),
        )
    }
    fn with_factory(factory: Arc<dyn Factory>, clock: Arc<dyn Clock>, instance: String) -> Self {
        let (normal_tx, normal) = mpsc::channel(7);
        let (urgent_tx, urgent) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let available = factory.available();
        let (published, receiver) = watch::channel(PublicView {
            schema: SCHEMA,
            available,
            unavailable_reason: if available {
                None
            } else {
                Some("owned_vm_helper_unavailable")
            },
            backend_instance_id: instance.clone(),
            session: None,
            command_id: None,
            ack: None,
        });
        let owner = Owner {
            factory,
            clock,
            instance,
            normal,
            urgent,
            shutdown,
            published,
            session: None,
            child: None,
            exchange: None,
            pending: None,
            pause: None,
            next_session: 1,
            next_generation: 1,
        };
        Self {
            normal: normal_tx,
            urgent: urgent_tx,
            published: receiver,
            shutdown: shutdown_tx,
            owner: Mutex::new(Some(tokio::spawn(owner.run()))),
        }
    }
    pub async fn state(&self) -> Result<Value> {
        bounded_value(&self.published.borrow().clone())
    }
    pub async fn action_bytes(&self, bytes: &[u8]) -> Result<Value> {
        let request = ControlRequest::parse(bytes)?;
        let (reply, receive) = oneshot::channel();
        let urgent = request.action.urgent();
        let message = Envelope { request, reply };
        let sender = if urgent { &self.urgent } else { &self.normal };
        sender.try_send(message).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                Error::new(409, "Owned VM control mailbox is full").with_code(Code::ResourceLimit)
            }
            mpsc::error::TrySendError::Closed(_) => {
                Error::new(503, "Owned VM owner has stopped").with_code(Code::DependencyUnavailable)
            }
        })?;
        // Cancellation drops only this receiver. Before admission, the owner
        // skips it; after admission, the owner completes or retires independently.
        receive.await.map_err(|_| {
            Error::new(503, "Owned VM owner stopped before replying")
                .with_reason(Reason::uncertain(Cause::Disconnected))
        })?
    }
    pub async fn trace(&self, query: &str) -> Result<Value> {
        let selected = TraceSelector::parse(query)?;
        let view = self.published.borrow().clone();
        let current = view
            .session
            .as_ref()
            .ok_or_else(|| Error::conflict("No owned VM run is selected"))?;
        if current.backend_instance_id != selected.backend_instance_id
            || current.session_id != selected.session_id
            || current.run_id != selected.run_id
            || current.run_generation != selected.run_generation
        {
            return Err(Error::conflict("Owned VM trace selection is stale")
                .with_code(Code::StaleGeneration));
        }
        bounded_value(&view)
    }
    pub async fn stop(&self) -> Result<()> {
        let _ = self.shutdown.send(true);
        if let Some(owner) = self.owner.lock().await.take() {
            owner.await.map_err(|_| {
                Error::new(503, "Owned VM owner stopped unexpectedly")
                    .with_code(Code::ApplicationFailed)
            })??;
        }
        Ok(())
    }
}
impl Drop for OwnedVmDebugger {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}
fn bounded_value(view: &PublicView) -> Result<Value> {
    let bytes = serde_json::to_vec(view)?;
    if bytes.len() > VIEW_LIMIT {
        return Err(Error::new(422, "Owned VM view exceeds 1 MiB").with_code(Code::ResourceLimit));
    }
    serde_json::from_slice(&bytes).map_err(Error::from)
}
impl Owner {
    fn snapshot(&self) -> PublicView {
        let available = self.factory.available();
        PublicView {
            schema: SCHEMA,
            available,
            unavailable_reason: if available {
                None
            } else {
                Some("owned_vm_helper_unavailable")
            },
            backend_instance_id: self.instance.clone(),
            session: self.session.as_ref().map(|s| s.view.clone()),
            command_id: None,
            ack: None,
        }
    }
    fn publish(&mut self) {
        if let (Some(child), Some(session)) = (&self.child, &mut self.session) {
            session.view.diagnostics = child.diagnostics();
        }
        self.published.send_replace(self.snapshot());
    }
    fn answer(&self, message: Envelope, ack: Ack) {
        let mut view = self.snapshot();
        view.command_id = Some(message.request.command_id);
        view.ack = Some(ack);
        let result = bounded_value(&view).map(|mut value| {
            if ack == Ack::OutcomeUnknown {
                Reason::uncertain(Cause::Disconnected).annotate(&mut value);
            }
            value
        });
        let _ = message.reply.send(result);
    }
    fn reject(message: Envelope, error: Error) {
        let _ = message.reply.send(Err(error));
    }
    fn stamp(&mut self, request: &ControlRequest, ack: Ack) {
        if let Some(session) = &mut self.session {
            session.view.last_command = Some(LastCommand {
                command_id: request.command_id.clone(),
                action: request.action,
                ack,
            });
        }
    }
    fn advance_control(&mut self) -> Result<()> {
        let revision = &mut self.session.as_mut().unwrap().view.control_revision.0;
        *revision = revision.checked_add(1).ok_or_else(|| {
            Error::conflict("Owned VM control revisions exhausted").with_code(Code::ResourceLimit)
        })?;
        Ok(())
    }
    fn scope_matches(&self, request: &ControlRequest) -> bool {
        self.session.as_ref().is_some_and(|s| {
            s.identity_active
                && request.backend_instance_id.as_ref() == Some(&s.view.backend_instance_id)
                && request.session_id.as_ref() == Some(&s.view.session_id)
                && request.run_id.as_ref() == Some(&s.view.run_id)
                && request.run_generation == Some(s.view.run_generation)
        })
    }
    async fn run(mut self) -> Result<()> {
        enum Event {
            Shutdown,
            Urgent(Envelope),
            Normal(Envelope),
            Reply(Box<Result<NativeReply>>),
            Timer,
            NormalClosed,
            UrgentClosed,
        }
        let mut normal_open = true;
        let mut urgent_open = true;
        loop {
            // This is the independent lease timer, not a consequence of a
            // stale command. A flood of rejected controls cannot renew a lease.
            self.check_time().await;
            let delay = self.next_delay();
            let event = tokio::select! {
                biased;
                _ = self.shutdown.changed() => Event::Shutdown,
                // Poll the existing exchange (including its timeout) even under
                // a flood of urgent rejections. Settling this one instruction
                // cannot dispatch another; urgent controls still precede ticks.
                result = async { self.exchange.as_mut().unwrap().await }, if self.exchange.is_some() => Event::Reply(Box::new(result)),
                message = self.urgent.recv(), if urgent_open => match message { Some(m) => Event::Urgent(m), None => Event::UrgentClosed },
                _ = async {
                    // Already-due deadlines are ready without registering a new
                    // zero-duration timer behind an always-ready command queue.
                    if !delay.is_zero() { tokio::time::sleep(delay).await; }
                }, if self.session.as_ref().is_some_and(|s| !s.view.state.terminal()) => Event::Timer,
                message = self.normal.recv(), if normal_open => match message { Some(m) => Event::Normal(m), None => Event::NormalClosed },
            };
            match event {
                Event::Shutdown => {
                    self.exchange = None;
                    self.reject_waiters(uncertain(Cause::Disconnected));
                    return self.dispose().await;
                }
                Event::Urgent(message) | Event::Normal(message) => self.handle(message).await,
                Event::Reply(result) => {
                    self.exchange = None;
                    self.complete(*result).await;
                }
                Event::Timer => self.tick().await,
                Event::NormalClosed => normal_open = false,
                Event::UrgentClosed => urgent_open = false,
            }
        }
    }
    fn next_delay(&self) -> Duration {
        let Some(session) = &self.session else {
            return LIFETIME;
        };
        let now = self.clock.now();
        let deadline = session.created.saturating_add(LIFETIME);
        let next = if session.expiry_pending {
            None
        } else {
            Some(deadline)
        };
        let next = match (next, session.next_tick) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        next.map_or(LIFETIME, |at| at.saturating_sub(now))
    }
    async fn handle(&mut self, message: Envelope) {
        if message.reply.is_closed() {
            return;
        }
        if message.request.action == Action::Create {
            if self.session.is_some() || self.child.is_some() {
                Self::reject(
                    message,
                    Error::conflict(
                        "An owned VM session already exists; reset or close it explicitly",
                    ),
                );
                return;
            }
            if self.next_session == u64::MAX {
                Self::reject(
                    message,
                    Error::conflict("Owned VM session IDs exhausted")
                        .with_code(Code::ResourceLimit),
                );
                return;
            }
            let id = self.next_session;
            self.next_session += 1;
            self.start(message, id).await;
            return;
        }
        // Identity is checked before time, counters, or any replacement state.
        if !self.scope_matches(&message.request) {
            Self::reject(
                message,
                Error::conflict("Owned VM run identity is stale").with_code(Code::StaleGeneration),
            );
            return;
        }
        self.check_time().await;
        let state = self.session.as_ref().unwrap().view.state;
        let action = message.request.action;
        if matches!(action, Action::Run | Action::Step) {
            let view = &self.session.as_ref().unwrap().view;
            if self.exchange.is_some() || state != State::Paused {
                Self::reject(message, busy());
                return;
            }
            if message.request.expected_control_revision != Some(view.control_revision)
                || (action == Action::Step
                    && message.request.expected_executed_count != Some(view.executed_count))
            {
                Self::reject(
                    message,
                    Error::conflict("Owned VM control precondition changed")
                        .with_code(Code::StaleGeneration),
                );
                return;
            }
        }
        if action == Action::Pause && self.pause.is_some() {
            Self::reject(message, busy());
            return;
        }
        if let Err(error) = self.advance_control() {
            let unknown = self.exchange.is_some()
                && self
                    .session
                    .as_ref()
                    .unwrap()
                    .view
                    .initial_snapshot
                    .is_some();
            self.retire(State::Failed, "resource_limit", unknown).await;
            self.reject_waiters(if unknown {
                uncertain(Cause::Disconnected)
            } else {
                error.clone()
            });
            self.publish();
            Self::reject(message, error);
            return;
        }
        self.stamp(&message.request, Ack::Pending);
        match action {
            Action::Run => {
                let now = self.clock.now();
                let session = self.session.as_mut().unwrap();
                session.view.state = State::Running;
                session.next_tick = Some(now.saturating_add(RUN_INTERVAL));
                self.stamp(&message.request, Ack::Completed);
                self.publish();
                self.answer(message, Ack::Completed);
            }
            Action::Step => {
                self.session.as_mut().unwrap().view.state = State::Stepping;
                self.pending = Some(message);
                if let Err(error) = self.dispatch() {
                    self.retire(State::Failed, "resource_limit", false).await;
                    if let Some(message) = self.pending.take() {
                        Self::reject(message, error);
                    }
                }
                self.publish();
            }
            Action::Pause => {
                self.session.as_mut().unwrap().next_tick = None;
                if self.exchange.is_some() {
                    self.session.as_mut().unwrap().view.state = State::Pausing;
                    self.pause = Some(message);
                } else {
                    if !state.terminal() {
                        self.session.as_mut().unwrap().view.state = State::Paused;
                    }
                    self.stamp(&message.request, Ack::Completed);
                    self.publish();
                    self.answer(message, Ack::Completed);
                    return;
                }
                self.publish();
            }
            Action::Stop | Action::Close | Action::Reset => {
                let uncertain_step = self.exchange.is_some()
                    && self
                        .session
                        .as_ref()
                        .unwrap()
                        .view
                        .initial_snapshot
                        .is_some();
                let session_id = self.session.as_ref().unwrap().spec.session;
                let fixture = self.session.as_ref().unwrap().spec.fixture;
                let session = self.session.as_mut().unwrap();
                session.identity_active = action != Action::Reset && action != Action::Close;
                session.view.state = State::Stopping;
                session.next_tick = None;
                if uncertain_step {
                    session.view.execution_state_known = false;
                }
                self.exchange = None;
                self.reject_waiters(if uncertain_step {
                    uncertain(Cause::Disconnected)
                } else {
                    busy()
                });
                self.publish();
                if let Err(error) = self.dispose().await {
                    self.session.as_mut().unwrap().view.state = State::Failed;
                    self.session.as_mut().unwrap().view.termination_reason =
                        Some("disposal_failed");
                    self.stamp(&message.request, Ack::Rejected);
                    self.publish();
                    Self::reject(message, error);
                    return;
                }
                if action == Action::Reset {
                    let mut message = message;
                    message.request.fixture = Some(fixture);
                    self.start(message, session_id).await;
                } else if action == Action::Close {
                    self.session = None;
                    self.publish();
                    self.answer(
                        message,
                        if uncertain_step {
                            Ack::OutcomeUnknown
                        } else {
                            Ack::Completed
                        },
                    );
                } else {
                    let session = self.session.as_mut().unwrap();
                    session.view.state = State::Stopped;
                    session.view.termination_reason = Some("stopped");
                    let ack = if uncertain_step {
                        Ack::OutcomeUnknown
                    } else {
                        Ack::Completed
                    };
                    self.stamp(&message.request, ack);
                    self.publish();
                    self.answer(message, ack);
                }
            }
            Action::Create => unreachable!(),
        }
    }
    async fn start(&mut self, message: Envelope, session_id: u64) {
        if self.child.is_some() {
            Self::reject(
                message,
                Error::conflict("Previous VM helper has not been reaped"),
            );
            return;
        }
        let generation = self.next_generation;
        let Some(next_generation) = generation.checked_add(1) else {
            if let Some(session) = &mut self.session {
                session.view.state = State::Failed;
                session.view.termination_reason = Some("resource_limit");
            }
            self.publish();
            Self::reject(
                message,
                Error::conflict("Owned VM generations exhausted").with_code(Code::ResourceLimit),
            );
            return;
        };
        self.next_generation = next_generation;
        let fixture = message.request.fixture.unwrap();
        let spec = SpawnSpec {
            fixture,
            session: session_id,
            generation,
        };
        let now = self.clock.now();
        let program_sha256 = hex::encode(Sha256::digest(include_bytes!(
            "../../../protocol/owned-vm-programs-v1.json"
        )));
        let view = SessionView {
            backend_instance_id: self.instance.clone(),
            session_id: format!("session-{session_id}"),
            run_id: format!("run-{generation}"),
            run_generation: Decimal(generation),
            provider: "live-owned-native-fixture",
            target_kind: "owned_fixture",
            fixture,
            program_id: fixture.program(),
            fixture_revision: 1,
            program_sha256,
            program_manifest_scope: "declared-two-program-manifest-sha256",
            build_id: None,
            build_id_scope: "configured-helper-file-sha256",
            pc_units: "instruction-index",
            value_semantics: "unsigned-64-bit-bits",
            tick_units: "monotonic-nanoseconds",
            state: State::Starting,
            control_revision: Decimal(1),
            snapshot_revision: Decimal(0),
            executed_count: Decimal(0),
            retained_count: Decimal(0),
            execution_state_known: false,
            termination_reason: None,
            initial_snapshot: None,
            current_snapshot: None,
            records: vec![],
            recorder: RecorderView {
                session_id: Decimal(session_id),
                document_id: Decimal(1),
                invocation_id: Decimal(generation),
                generation: Decimal(1),
                stats: RecorderStats::default(),
            },
            last_command: Some(LastCommand {
                command_id: message.request.command_id.clone(),
                action: message.request.action,
                ack: Ack::Pending,
            }),
            diagnostics: Diagnostics::default(),
            disposal_failed: false,
        };
        self.session = Some(Runtime {
            view,
            spec: spec.clone(),
            created: now,
            last_clock: now,
            next_tick: None,
            next_request: 1,
            identity_active: true,
            expiry_pending: false,
        });
        self.publish();
        match self.factory.spawn(&spec) {
            Ok((child, build)) => {
                self.session.as_mut().unwrap().view.build_id = Some(build);
                self.exchange = Some(child.exchange(WireRequest {
                    id: 0,
                    generation,
                    count: 0,
                    operation: 0,
                }));
                self.child = Some(child);
                self.pending = Some(message);
                self.publish();
            }
            Err(error) => {
                self.session.as_mut().unwrap().view.state = State::Failed;
                self.session.as_mut().unwrap().view.termination_reason =
                    Some("dependency_unavailable");
                self.stamp(&message.request, Ack::Rejected);
                self.publish();
                Self::reject(message, error);
            }
        }
    }
    fn dispatch(&mut self) -> Result<()> {
        if self.exchange.is_some() {
            return Err(busy());
        }
        let session = self.session.as_mut().unwrap();
        if session.view.executed_count.0 >= 16 {
            return Err(Error::conflict("Owned VM dispatch budget exhausted")
                .with_code(Code::ResourceLimit));
        }
        let id = session.next_request;
        session.next_request = id.checked_add(1).ok_or_else(|| {
            Error::conflict("Owned VM request IDs exhausted").with_code(Code::ResourceLimit)
        })?;
        session.next_tick = None;
        let child = self.child.as_ref().ok_or_else(dependency)?;
        self.exchange = Some(child.exchange(WireRequest {
            id,
            generation: session.spec.generation,
            count: session.view.executed_count.0,
            operation: 2,
        }));
        Ok(())
    }
    async fn tick(&mut self) {
        self.check_time().await;
        let now = self.clock.now();
        let eligible = self.session.as_ref().is_some_and(|s| {
            s.view.state == State::Running
                && !s.expiry_pending
                && s.next_tick.is_some_and(|at| at <= now)
        });
        if eligible && self.exchange.is_none() {
            if let Err(error) = self.dispatch() {
                self.retire(State::Failed, "resource_limit", false).await;
                self.reject_waiters(error);
            }
            self.publish();
        }
    }
    async fn check_time(&mut self) {
        let now = self.clock.now();
        let Some(session) = &mut self.session else {
            return;
        };
        if session.view.state.terminal() || session.expiry_pending {
            return;
        }
        if now < session.last_clock {
            let unknown = self.exchange.is_some();
            self.retire(State::Failed, "clock_rollback", unknown).await;
            self.reject_waiters(if unknown {
                uncertain(Cause::Timeout)
            } else {
                Error::conflict("Owned VM clock moved backwards")
            });
            self.publish();
            return;
        }
        session.last_clock = now;
        if now >= session.created.saturating_add(LIFETIME) {
            session.expiry_pending = true;
            session.next_tick = None;
            if self.exchange.is_some() {
                session.view.state = State::Stopping;
                self.publish();
            } else {
                self.retire(State::Expired, "expired", false).await;
                self.publish();
            }
        }
    }
    fn reject_waiters(&mut self, error: Error) {
        if let Some(message) = self.pending.take() {
            Self::reject(message, error.clone());
        }
        if let Some(message) = self.pause.take() {
            Self::reject(message, error);
        }
    }
    async fn dispose(&mut self) -> Result<()> {
        if let Some(child) = &mut self.child {
            if let Some(session) = &mut self.session {
                session.view.diagnostics = child.diagnostics();
            }
            if let Err(error) = child.dispose().await {
                if let Some(session) = &mut self.session {
                    session.view.disposal_failed = true;
                }
                return Err(error);
            }
            if let Some(session) = &mut self.session {
                session.view.diagnostics = child.diagnostics();
            }
        }
        self.child = None;
        if let Some(session) = &mut self.session {
            session.view.disposal_failed = false;
        }
        Ok(())
    }
    async fn retire(&mut self, state: State, reason: &'static str, unknown: bool) {
        self.exchange = None;
        if let Some(session) = &mut self.session {
            session.next_tick = None;
            session.view.state = state;
            // Retired revisions never wrap or become usable again.
            if let Some(revision) = session.view.control_revision.0.checked_add(1) {
                session.view.control_revision = Decimal(revision);
            }
            session.view.termination_reason = Some(reason);
            if unknown {
                session.view.execution_state_known = false;
            }
            if let Some(command) = &mut session.view.last_command {
                command.ack = if unknown {
                    Ack::OutcomeUnknown
                } else {
                    Ack::Rejected
                };
            }
        }
        if self.dispose().await.is_err()
            && let Some(session) = &mut self.session
        {
            session.view.state = State::Failed;
            session.view.termination_reason = Some("disposal_failed");
        }
    }
    async fn complete(&mut self, result: Result<NativeReply>) {
        let initializing = self
            .session
            .as_ref()
            .is_some_and(|s| s.view.initial_snapshot.is_none());
        let reply = result.and_then(|reply| {
            validate_native(self.session.as_ref().unwrap(), &reply, initializing)?;
            Ok(reply)
        });
        let reply = match reply {
            Ok(reply) => reply,
            Err(mut error) => {
                if initializing {
                    error = Error::new(503, "Owned VM helper initialization failed")
                        .with_code(Code::DependencyUnavailable);
                }
                let expired = self.session.as_ref().is_some_and(|s| s.expiry_pending);
                self.retire(
                    if expired {
                        State::Expired
                    } else {
                        State::Failed
                    },
                    if expired { "expired" } else { "helper_failure" },
                    !initializing,
                )
                .await;
                self.reject_waiters(error);
                self.publish();
                return;
            }
        };
        if reply.status != 0 {
            let expired = reply.status == 5;
            self.retire(
                if expired {
                    State::Expired
                } else {
                    State::Failed
                },
                if expired {
                    "expired"
                } else {
                    "native_rejection"
                },
                false,
            )
            .await;
            let error = Error::new(
                if expired { 410 } else { 409 },
                "Owned VM helper refused this instruction before dispatch",
            )
            .with_code(if expired {
                Code::Timeout
            } else {
                Code::StateConflict
            });
            self.reject_waiters(error);
            self.publish();
            return;
        }
        let now = self.clock.now();
        let session = self.session.as_mut().unwrap();
        let Some(revision) = session.view.snapshot_revision.0.checked_add(1) else {
            self.retire(State::Failed, "resource_limit", !initializing)
                .await;
            self.reject_waiters(
                Error::conflict("Owned VM snapshot revisions exhausted")
                    .with_code(Code::ResourceLimit),
            );
            self.publish();
            return;
        };
        session.view.snapshot_revision = Decimal(revision);
        if initializing {
            session.view.initial_snapshot = Some(reply.view.snapshot.clone());
        }
        session.view.current_snapshot = Some(reply.view.snapshot);
        session.view.executed_count = reply.view.executed_count;
        session.view.retained_count = reply.view.retained_count;
        session.view.recorder.stats = reply.view.stats;
        if let Some(record) = reply.view.transition {
            session.view.records.push(record);
        }
        session.view.execution_state_known = true;
        let halted = reply.view.state == NativeState::Halted;
        let expired = session.expiry_pending || now >= session.created.saturating_add(LIFETIME);
        let paused = initializing || session.view.state != State::Running || self.pause.is_some();
        session.view.state = if expired {
            State::Expired
        } else if halted {
            State::Halted
        } else if paused {
            State::Paused
        } else {
            State::Running
        };
        if expired || halted {
            session.next_tick = None;
            session.view.termination_reason = Some(if expired { "expired" } else { "halt" });
        } else if !paused {
            session.next_tick = Some(now.saturating_add(RUN_INTERVAL));
        }
        if (paused || halted || expired) && self.advance_control().is_err() {
            self.retire(State::Failed, "resource_limit", false).await;
            self.reject_waiters(
                Error::conflict("Owned VM control revisions exhausted")
                    .with_code(Code::ResourceLimit),
            );
            self.publish();
            return;
        }
        if (expired || halted)
            && let Err(error) = self.dispose().await
        {
            let session = self.session.as_mut().unwrap();
            session.view.state = State::Failed;
            session.view.termination_reason = Some("disposal_failed");
            self.reject_waiters(error);
            self.publish();
            return;
        }
        // Deliver each stable acknowledgment with the same confirmed state. A
        // Pause which raced HALT sees halted, never a fictitious paused cursor.
        let pending = self.pending.take();
        let pause = self.pause.take();
        if let Some(message) = &pending {
            self.stamp(&message.request, Ack::Completed);
        }
        if let Some(message) = &pause {
            self.stamp(&message.request, Ack::Completed);
        }
        self.publish();
        if let Some(message) = pending {
            self.answer(message, Ack::Completed);
        }
        if let Some(message) = pause {
            self.answer(message, Ack::Completed);
        }
    }
}
fn validate_native(session: &Runtime, reply: &NativeReply, initial: bool) -> Result<()> {
    let v = &reply.view;
    let old = &session.view;
    let malformed = || uncertain(Cause::InvalidReply);
    if v.schema != "reb-owned-vm-helper-v1"
        || v.fixture != session.spec.fixture
        || v.program_id != session.spec.fixture.program()
        || v.fixture_revision != 1
        || v.session_id.0 != session.spec.session
        || v.document_id.0 != 1
        || v.invocation_id.0 != session.spec.generation
        || v.run_generation.0 != session.spec.generation
        || v.tick_units != "monotonic-nanoseconds"
        || !v.snapshot.valid_at(v.fixture, v.executed_count.0)
        || v.executed_count.0 > 9
        || v.retained_count.0 > 64
        || v.retained_count != v.stats.recorded
        || v.stats.recorded.0 > v.executed_count.0
        || v.stats.partial.0 > v.stats.recorded.0
        || v.stats.attempted.0 > v.executed_count.0
        || v.stats
            .recorded
            .0
            .checked_add(v.stats.full.0)
            .and_then(|n| n.checked_add(v.stats.malformed.0))
            != Some(v.stats.attempted.0)
        || v.snapshot.pc.0 != PCS[v.executed_count.0 as usize]
        || v.snapshot.halted != (v.executed_count.0 == 9)
    {
        return Err(malformed());
    }
    if initial {
        if reply.status != 0
            || v.state != NativeState::Paused
            || v.executed_count.0 != 0
            || v.retained_count.0 != 0
            || v.transition.is_some()
            || v.recorder_result.is_some()
            || v.stats != RecorderStats::default()
            || v.snapshot != Snapshot::initial(v.fixture)
        {
            return Err(malformed());
        }
        return Ok(());
    }
    if reply.status != 0 {
        // The only admitted post-handshake operation is execute_one. A close
        // response is never its acknowledgment, and halted must be real HALT.
        if reply.status == 9 || (reply.status == 6 && !v.snapshot.halted) {
            return Err(malformed());
        }
        if v.executed_count != old.executed_count
            || old.current_snapshot.as_ref() != Some(&v.snapshot)
            || v.retained_count != old.retained_count
            || v.state
                != (match reply.status {
                    1 | 7 | 8 => NativeState::Failed,
                    5 => NativeState::Expired,
                    6 => NativeState::Halted,
                    9 => NativeState::Stopped,
                    _ => {
                        if v.snapshot.halted {
                            NativeState::Halted
                        } else {
                            NativeState::Paused
                        }
                    }
                })
            || v.transition.is_some()
            || v.recorder_result.is_some()
            || v.stats != old.recorder.stats
        {
            return Err(malformed());
        }
        return Ok(());
    }
    if v.executed_count.0 != old.executed_count.0.checked_add(1).ok_or_else(malformed)?
        || v.state
            != (if v.snapshot.halted {
                NativeState::Halted
            } else {
                NativeState::Paused
            })
    {
        return Err(malformed());
    }
    let previous = &old.recorder.stats;
    for (a, b) in [
        (v.stats.attempted, previous.attempted),
        (v.stats.recorded, previous.recorded),
        (v.stats.full, previous.full),
        (v.stats.malformed, previous.malformed),
        (v.stats.wrong_document, previous.wrong_document),
        (v.stats.stale_generation, previous.stale_generation),
        (v.stats.exhausted, previous.exhausted),
        (v.stats.expired, previous.expired),
        (v.stats.partial, previous.partial),
    ] {
        if a < b || a.0 - b.0 > 1 {
            return Err(malformed());
        }
    }
    let mut expected_stats = previous.clone();
    let increment = |value: &mut Decimal| -> Result<()> {
        value.0 = value.0.checked_add(1).ok_or_else(malformed)?;
        Ok(())
    };
    match v.recorder_result {
        Some(RecorderResult::Recorded) => {
            increment(&mut expected_stats.attempted)?;
            increment(&mut expected_stats.recorded)?;
            if v.transition
                .as_ref()
                .is_some_and(|r| r.partial || r.before.partial || r.after.partial)
            {
                increment(&mut expected_stats.partial)?;
            }
        }
        Some(RecorderResult::Full) => {
            increment(&mut expected_stats.attempted)?;
            increment(&mut expected_stats.full)?;
        }
        Some(RecorderResult::Malformed) => {
            increment(&mut expected_stats.attempted)?;
            increment(&mut expected_stats.malformed)?;
        }
        Some(RecorderResult::WrongDocument) => increment(&mut expected_stats.wrong_document)?,
        Some(RecorderResult::StaleGeneration) => increment(&mut expected_stats.stale_generation)?,
        Some(RecorderResult::Expired) => increment(&mut expected_stats.expired)?,
        Some(RecorderResult::Exhausted) => increment(&mut expected_stats.exhausted)?,
        Some(RecorderResult::Disabled) => (),
        None => return Err(malformed()),
    }
    if expected_stats != v.stats {
        return Err(malformed());
    }
    match (&v.transition, v.recorder_result) {
        (Some(record), Some(RecorderResult::Recorded)) => {
            if !record.valid(v.fixture)
                || old.records.len() >= 64
                || record.after != v.snapshot
                || old.current_snapshot.as_ref() != Some(&record.before)
                || record.sequence != v.stats.attempted
                || v.retained_count.0 != old.retained_count.0 + 1
                || v.stats.attempted.0 != previous.attempted.0 + 1
                || old
                    .records
                    .last()
                    .is_some_and(|r| r.sequence >= record.sequence || r.tick > record.tick)
            {
                return Err(malformed());
            }
        }
        (None, Some(result)) if result != RecorderResult::Recorded => {
            if v.retained_count != old.retained_count {
                return Err(malformed());
            }
        }
        _ => return Err(malformed()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    #[derive(Default)]
    struct ManualClock(AtomicU64);
    impl ManualClock {
        fn set(&self, millis: u64) {
            self.0.store(millis, Ordering::SeqCst);
        }
    }
    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::SeqCst))
        }
    }
    #[derive(Default)]
    struct Ledger {
        requests: StdMutex<Vec<WireRequest>>,
        live: AtomicUsize,
        spawned: AtomicUsize,
        reaped: AtomicUsize,
        refuse_reap: AtomicBool,
    }
    struct FakeFactory(Arc<Ledger>);
    struct FakeChild {
        ledger: Arc<Ledger>,
        reaped: bool,
    }
    impl Factory for FakeFactory {
        fn available(&self) -> bool {
            true
        }
        fn spawn(&self, _: &SpawnSpec) -> Result<(Box<dyn NativeChild>, String)> {
            assert_eq!(
                self.0.live.fetch_add(1, Ordering::SeqCst),
                0,
                "second live helper"
            );
            self.0.spawned.fetch_add(1, Ordering::SeqCst);
            Ok((
                Box::new(FakeChild {
                    ledger: self.0.clone(),
                    reaped: false,
                }),
                "a".repeat(64),
            ))
        }
    }
    impl NativeChild for FakeChild {
        fn exchange(&self, request: WireRequest) -> Exchange {
            self.ledger.requests.lock().unwrap().push(request);
            // Explicit reply barrier. Tests release it through complete(); no
            // sleep, scheduler race, or generated native output is the oracle.
            Box::pin(std::future::pending())
        }
        fn dispose(&mut self) -> Disposal<'_> {
            Box::pin(async move {
                if self.ledger.refuse_reap.load(Ordering::SeqCst) {
                    return Err(Error::new(503, "Synthetic reap failure")
                        .with_code(Code::ApplicationFailed));
                }
                if !self.reaped {
                    self.reaped = true;
                    self.ledger.reaped.fetch_add(1, Ordering::SeqCst);
                    self.ledger.live.fetch_sub(1, Ordering::SeqCst);
                }
                Ok(())
            })
        }
        fn diagnostics(&self) -> Diagnostics {
            Diagnostics::default()
        }
    }
    struct Harness {
        owner: Owner,
        clock: Arc<ManualClock>,
        ledger: Arc<Ledger>,
        _normal: mpsc::Sender<Envelope>,
        _urgent: mpsc::Sender<Envelope>,
        _shutdown: watch::Sender<bool>,
    }
    impl Harness {
        fn new() -> Self {
            let clock = Arc::new(ManualClock::default());
            let ledger = Arc::new(Ledger::default());
            let (normal_tx, normal) = mpsc::channel(7);
            let (urgent_tx, urgent) = mpsc::channel(1);
            let (shutdown_tx, shutdown) = watch::channel(false);
            let (published, _) = watch::channel(PublicView {
                schema: SCHEMA,
                available: true,
                unavailable_reason: None,
                backend_instance_id: "test-instance".into(),
                session: None,
                command_id: None,
                ack: None,
            });
            Self {
                owner: Owner {
                    factory: Arc::new(FakeFactory(ledger.clone())),
                    clock: clock.clone(),
                    instance: "test-instance".into(),
                    normal,
                    urgent,
                    shutdown,
                    published,
                    session: None,
                    child: None,
                    exchange: None,
                    pending: None,
                    pause: None,
                    next_session: 1,
                    next_generation: 1,
                },
                clock,
                ledger,
                _normal: normal_tx,
                _urgent: urgent_tx,
                _shutdown: shutdown_tx,
            }
        }
        fn request(&self, action: Action, command: &str) -> ControlRequest {
            let mut value = json!({"action":action,"command_id":command});
            if action == Action::Create {
                value["fixture"] = json!("register");
            } else {
                let view = &self.owner.session.as_ref().unwrap().view;
                for key in [
                    "backend_instance_id",
                    "session_id",
                    "run_id",
                    "run_generation",
                ] {
                    value[key] = serde_json::to_value(view).unwrap()[key].clone();
                }
                if matches!(action, Action::Run | Action::Step) {
                    value["expected_control_revision"] = json!(view.control_revision);
                }
                if action == Action::Step {
                    value["expected_executed_count"] = json!(view.executed_count);
                }
            }
            ControlRequest::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
        }
        async fn submit(
            &mut self,
            action: Action,
            command: &str,
        ) -> oneshot::Receiver<Result<Value>> {
            let (message, receive) = envelope(self.request(action, command));
            self.owner.handle(message).await;
            receive
        }
        async fn create(&mut self) {
            let mut receive = self.submit(Action::Create, "create").await;
            assert!(matches!(
                receive.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            self.finish(0).await;
            assert_eq!(
                receive.await.unwrap().unwrap()["session"]["state"],
                "paused"
            );
        }
        async fn finish(&mut self, count: u64) {
            self.owner.exchange = None;
            let spec = &self.owner.session.as_ref().unwrap().spec;
            self.owner.complete(Ok(golden_reply(spec, count))).await;
        }
        fn dispatches(&self) -> usize {
            self.ledger
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.operation == 2)
                .count()
        }
        fn view(&self) -> &SessionView {
            &self.owner.session.as_ref().unwrap().view
        }
    }
    fn envelope(request: ControlRequest) -> (Envelope, oneshot::Receiver<Result<Value>>) {
        let (reply, receive) = oneshot::channel();
        (Envelope { request, reply }, receive)
    }
    fn observed(bits: u64) -> GuestValue {
        GuestValue {
            bits: Decimal(bits),
            evidence: Evidence::Observed,
        }
    }
    // Independent fixed expected states, not a call into either interpreter.
    fn golden_snapshot(fixture: Fixture, count: u64) -> Snapshot {
        let mut state = Snapshot::initial(fixture);
        state.pc = Decimal(PCS[count as usize]);
        state.halted = count == 9;
        if fixture == Fixture::Register {
            if count >= 1 {
                state.registers[0] = observed(if count >= 3 { 12 } else { 7 });
            }
            if count >= 2 {
                state.registers[1] = observed(5);
            }
            if count >= 5 {
                state.registers[2] = observed(12);
            }
        } else {
            state.stack = match count {
                0 | 4 => vec![],
                1 => vec![observed(7)],
                2 => vec![observed(7), observed(5)],
                _ => vec![observed(12)],
            };
        }
        if count >= 4 {
            state.memory = vec![MemoryCell {
                guest_address: Decimal(16),
                value: observed(12),
            }];
        }
        state
    }
    fn golden_record(fixture: Fixture, count: u64) -> Record {
        let slot = if fixture == Fixture::Register {
            Location::Register
        } else {
            Location::Stack
        };
        let operand = |location, index, bits| Operand {
            location,
            index: Decimal(index),
            value: observed(bits),
        };
        let effect = |access, location, index, value| Effect {
            access,
            location,
            index: Decimal(index),
            value,
        };
        let mut operands = vec![];
        let mut effects = vec![];
        match count {
            1 | 2 => {
                let bits = if count == 1 { 7 } else { 5 };
                operands.push(operand(Location::Immediate, 0, bits));
                effects.push(effect(Access::Write, slot, count - 1, observed(bits)));
            }
            3 => {
                operands = vec![operand(slot, 0, 7), operand(slot, 1, 5)];
                effects = vec![
                    effect(Access::Read, slot, 0, observed(7)),
                    effect(Access::Read, slot, 1, observed(5)),
                    effect(Access::Write, slot, 0, observed(12)),
                ];
                if fixture == Fixture::Stack {
                    effects.push(effect(Access::Write, slot, 1, GuestValue::unknown()));
                }
            }
            4 => {
                operands.push(operand(slot, 0, 12));
                effects = vec![
                    effect(Access::Read, slot, 0, observed(12)),
                    effect(Access::Write, Location::Memory, 16, observed(12)),
                ];
                if fixture == Fixture::Stack {
                    effects.push(effect(Access::Write, slot, 0, GuestValue::unknown()));
                }
            }
            5 => {
                operands.push(operand(Location::Memory, 16, 12));
                effects = vec![
                    effect(Access::Read, Location::Memory, 16, observed(12)),
                    effect(
                        Access::Write,
                        slot,
                        if fixture == Fixture::Register { 2 } else { 0 },
                        observed(12),
                    ),
                ];
            }
            6 | 8 => {
                let index = if fixture == Fixture::Register { 2 } else { 0 };
                operands = vec![
                    operand(slot, index, 12),
                    operand(Location::Immediate, 0, 10),
                ];
                effects.push(effect(Access::Read, slot, index, observed(12)));
            }
            7 => operands.push(operand(Location::Immediate, 0, 8)),
            9 => (),
            _ => panic!("invalid golden instruction"),
        }
        Record {
            sequence: Decimal(count),
            tick: Decimal(count),
            opcode: [1, 1, 2, 3, 4, 5, 6, 7, 8][count as usize - 1],
            opcode_evidence: Evidence::Observed,
            partial: false,
            operands,
            effects,
            before: golden_snapshot(fixture, count - 1),
            after: golden_snapshot(fixture, count),
        }
    }
    fn golden_reply(spec: &SpawnSpec, count: u64) -> NativeReply {
        NativeReply {
            status: 0,
            view: NativeView {
                schema: "reb-owned-vm-helper-v1".into(),
                fixture: spec.fixture,
                program_id: spec.fixture.program().into(),
                fixture_revision: 1,
                session_id: Decimal(spec.session),
                document_id: Decimal(1),
                invocation_id: Decimal(spec.generation),
                run_generation: Decimal(spec.generation),
                state: if count == 9 {
                    NativeState::Halted
                } else {
                    NativeState::Paused
                },
                executed_count: Decimal(count),
                retained_count: Decimal(count),
                snapshot: golden_snapshot(spec.fixture, count),
                transition: if count == 0 {
                    None
                } else {
                    Some(golden_record(spec.fixture, count))
                },
                recorder_result: if count == 0 {
                    None
                } else {
                    Some(RecorderResult::Recorded)
                },
                stats: RecorderStats {
                    attempted: Decimal(count),
                    recorded: Decimal(count),
                    ..RecorderStats::default()
                },
                tick_units: "monotonic-nanoseconds".into(),
            },
        }
    }
    #[test]
    fn decimal_and_control_decoding_are_strict_and_lossless() {
        for valid in ["0", "1", "9007199254740993", "18446744073709551615"] {
            let n: Decimal = serde_json::from_value(json!(valid)).unwrap();
            assert_eq!(serde_json::to_value(n).unwrap(), json!(valid));
        }
        for invalid in [
            json!(0),
            json!(""),
            json!("00"),
            json!("01"),
            json!("+1"),
            json!("-1"),
            json!(" 1"),
            json!("1e3"),
            json!("18446744073709551616"),
        ] {
            assert!(serde_json::from_value::<Decimal>(invalid).is_err());
        }
        assert!(
            ControlRequest::parse(br#"{"action":"create","command_id":"a","fixture":"register"}"#)
                .is_ok()
        );
        for invalid in [
            br#"{"action":"create","command_id":"a","fixture":"register","fixture":"stack"}"#.as_slice(),
            br#"{"action":"create","command_id":"a","fixture":"register","script":"1+1"}"#,
            br#"{"action":"create","command_id":"a","fixture":"register","run_generation":null}"#,
            br#"{"action":"create","command_id":"a","fixture":"register","expected_executed_count":"0"}"#,
            br#"{"action":"step","command_id":"a"}"#,
            br#"{"action":"create","command_id":"a","fixture":"external"}"#,
        ] { assert!(ControlRequest::parse(invalid).is_err()); }
        assert!(ControlRequest::parse(&vec![b' '; BODY_LIMIT + 1]).is_err());
    }
    #[test]
    fn independent_checked_in_goldens_match_the_rust_test_oracle() {
        let goldens: Value = serde_json::from_str(include_str!(
            "../../../tools/fixtures/owned-vm-golden-transitions-v1.json"
        ))
        .unwrap();
        for fixture in [Fixture::Register, Fixture::Stack] {
            let expected = &goldens[fixture.name()];
            assert_eq!(
                expected["initial"],
                serde_json::to_value(golden_snapshot(fixture, 0)).unwrap()
            );
            for count in 1..=9 {
                let mut record = expected["transitions"][count as usize - 1].clone();
                record["tick"] = json!(count.to_string());
                assert_eq!(
                    record,
                    serde_json::to_value(golden_record(fixture, count)).unwrap()
                );
            }
        }
    }
    #[test]
    fn selectors_and_response_header_fail_closed() {
        let query = "backend_instance_id=b&session_id=s&run_id=r&run_generation=1";
        assert!(TraceSelector::parse(query).is_ok());
        for invalid in [
            format!("{query}&run_id=r"),
            format!("{query}&extra=x"),
            query.replace("run_id=r", "run_id=%FF"),
            query.replace("run_id=r", "run_id=%"),
            query.replace("run_generation=1", "run_generation=01"),
        ] {
            assert!(TraceSelector::parse(&invalid).is_err());
        }
        let mut header = [0u8; 24];
        header[..4].copy_from_slice(&MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&1u16.to_le_bytes());
        header[8..16].copy_from_slice(&99u64.to_le_bytes());
        header[16..20].copy_from_slice(&(REPLY_LIMIT as u32).to_le_bytes());
        assert_eq!(parse_header(&header, 99).unwrap(), (0, REPLY_LIMIT));
        assert!(parse_header(&header, 98).is_err());
        for offset in [0, 4, 6, 20] {
            let mut wrong = header;
            wrong[offset] = 255;
            assert!(parse_header(&wrong, 99).is_err());
        }
        header[16..20].copy_from_slice(&((REPLY_LIMIT + 1) as u32).to_le_bytes());
        assert!(parse_header(&header, 99).is_err());
    }
    #[test]
    fn native_codec_rejects_unknown_duplicate_or_impossible_data() {
        assert!(require_nullable_fields(br#"{}"#).is_err());
        assert!(require_nullable_fields(br#"{"transition":null}"#).is_err());
        assert!(require_nullable_fields(br#"{"recorder_result":null}"#).is_err());
        assert!(require_nullable_fields(br#"{"transition":null,"recorder_result":null}"#).is_ok());
        let snapshot = serde_json::to_string(&Snapshot::initial(Fixture::Register)).unwrap();
        assert!(
            serde_json::from_str::<Snapshot>(
                &snapshot.replace("\"pc\":\"0\"", "\"pc\":\"0\",\"pc\":\"1\"")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Snapshot>(
                &snapshot.replace("\"pc\":", "\"unexpected\":0,\"pc\":")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Snapshot>(&snapshot.replace("observed", "confirmed")).is_err()
        );
        let mut s = Snapshot::initial(Fixture::Register);
        s.registers[0].bits = Decimal(u64::MAX);
        assert!(!s.valid(Fixture::Register));
        s.registers[0].evidence = Evidence::Observed;
        assert!(s.valid(Fixture::Register));
        assert_eq!(
            serde_json::to_value(&s).unwrap()["registers"][0]["bits"],
            "18446744073709551615"
        );
        s.memory = vec![
            MemoryCell {
                guest_address: Decimal(16),
                value: observed(1)
            };
            2
        ];
        assert!(!s.valid(Fixture::Register));
        let mut impossible = golden_snapshot(Fixture::Stack, 1);
        impossible.stack.resize(8, observed(7));
        assert!(!impossible.valid_at(Fixture::Stack, 1));
        impossible = golden_snapshot(Fixture::Stack, 1);
        impossible.memory.push(MemoryCell {
            guest_address: Decimal(16),
            value: observed(12),
        });
        assert!(!impossible.valid_at(Fixture::Stack, 1));
        let mut r = golden_record(Fixture::Register, 1);
        r.effects[0].location = Location::Immediate;
        assert!(!r.valid(Fixture::Register));
        r = golden_record(Fixture::Register, 1);
        r.operands.resize(5, r.operands[0].clone());
        assert!(!r.valid(Fixture::Register));
    }
    #[tokio::test]
    async fn public_views_match_openapi_including_starting_and_uncertain_outcomes() {
        let mut h = Harness::new();
        let validate =
            |value: &Value| crate::validation::schema("OwnedVmDebuggerState", value, 500).unwrap();
        validate(&serde_json::to_value(h.owner.snapshot()).unwrap());
        let create = h.submit(Action::Create, "create").await;
        let mut starting = serde_json::to_value(h.owner.snapshot()).unwrap();
        starting["session"]["build_id"] = Value::Null;
        assert!(starting["session"]["initial_snapshot"].is_null());
        assert!(starting["session"]["current_snapshot"].is_null());
        validate(&starting);
        h.finish(0).await;
        validate(&create.await.unwrap().unwrap());
        for action in ["run", "pause", "step", "stop", "reset", "close"] {
            let request = public_request(
                &serde_json::to_value(h.owner.snapshot()).unwrap(),
                action,
                action,
            );
            crate::validation::schema("OwnedVmDebuggerAction", &request, 400).unwrap();
            ControlRequest::parse(&serde_json::to_vec(&request).unwrap()).unwrap();
        }
        let step = h.submit(Action::Step, "step").await;
        let stopped = h.submit(Action::Stop, "stop").await.await.unwrap().unwrap();
        validate(&stopped);
        assert_eq!(stopped["code"], "command_outcome_unknown");
        assert!(step.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn missing_helper_get_is_inert_and_explicit_create_reports_dependency() {
        let root = tempfile::tempdir().unwrap();
        let debugger = OwnedVmDebugger::new(root.path().join("not-built"));
        let first = debugger.state().await.unwrap();
        assert_eq!(first["available"], false);
        assert!(first["session"].is_null());
        for _ in 0..5 {
            assert_eq!(debugger.state().await.unwrap(), first);
        }
        let error = debugger
            .action_bytes(br#"{"action":"create","command_id":"create","fixture":"stack"}"#)
            .await
            .unwrap_err();
        assert_eq!(error.reason.code, Code::DependencyUnavailable);
        assert_eq!(
            debugger.state().await.unwrap()["session"]["state"],
            "failed"
        );
        debugger.stop().await.unwrap();
    }
    #[tokio::test]
    async fn native_status_contradictions_are_uncertain_not_safe_rejections() {
        let mut h = Harness::new();
        h.create().await;
        for (status, state) in [
            (5, NativeState::Paused),
            (6, NativeState::Halted),
            (9, NativeState::Stopped),
        ] {
            let mut reply = golden_reply(&h.owner.session.as_ref().unwrap().spec, 0);
            reply.status = status;
            reply.view.state = state;
            assert_eq!(
                validate_native(h.owner.session.as_ref().unwrap(), &reply, false)
                    .unwrap_err()
                    .reason
                    .code,
                Code::CommandOutcomeUnknown
            );
        }
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn initial_pause_gets_and_run_ticks_never_catch_up() {
        let mut h = Harness::new();
        h.create().await;
        let before = serde_json::to_value(h.owner.snapshot()).unwrap();
        for _ in 0..20 {
            assert_eq!(serde_json::to_value(h.owner.snapshot()).unwrap(), before);
        }
        h.clock.set(10_000);
        h.owner.tick().await;
        assert_eq!(h.dispatches(), 0);
        assert_eq!(
            h.submit(Action::Run, "run").await.await.unwrap().unwrap()["session"]["executed_count"],
            "0"
        );
        h.clock.set(20_000);
        h.owner.tick().await;
        assert_eq!(h.dispatches(), 1);
        for _ in 0..10 {
            h.owner.tick().await;
        }
        assert_eq!(h.dispatches(), 1);
        h.finish(1).await;
        h.owner.tick().await;
        assert_eq!(h.dispatches(), 1);
        h.clock.set(20_249);
        h.owner.tick().await;
        assert_eq!(h.dispatches(), 1);
        h.clock.set(20_250);
        h.owner.tick().await;
        assert_eq!(h.dispatches(), 2);
        h.owner.exchange = None;
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn pause_before_tick_and_during_step_acknowledges_quiescence() {
        let mut h = Harness::new();
        h.create().await;
        h.submit(Action::Run, "run").await.await.unwrap().unwrap();
        h.submit(Action::Pause, "pause-first")
            .await
            .await
            .unwrap()
            .unwrap();
        h.clock.set(1000);
        h.owner.tick().await;
        assert_eq!(h.dispatches(), 0);
        let mut step = h.submit(Action::Step, "step").await;
        let mut pause = h.submit(Action::Pause, "pause-during").await;
        assert_eq!(h.view().state, State::Pausing);
        assert!(matches!(
            step.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            pause.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        h.finish(1).await;
        assert_eq!(
            step.await.unwrap().unwrap()["session"]["executed_count"],
            "1"
        );
        let paused = pause.await.unwrap().unwrap();
        assert_eq!(paused["session"]["state"], "paused");
        let snapshot = h.view().current_snapshot.clone();
        h.clock.set(5000);
        h.owner.tick().await;
        assert_eq!(h.dispatches(), 1);
        assert_eq!(h.view().current_snapshot, snapshot);
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn duplicate_execution_guards_and_reserved_mailbox_are_bounded() {
        let mut h = Harness::new();
        h.create().await;
        let request = h.request(Action::Step, "duplicate");
        let (first, first_result) = envelope(request.clone());
        h.owner.handle(first).await;
        let (second, second_result) = envelope(request.clone());
        h.owner.handle(second).await;
        assert!(second_result.await.unwrap().is_err());
        assert_eq!(h.dispatches(), 1);
        h.finish(1).await;
        first_result.await.unwrap().unwrap();
        let (third, third_result) = envelope(request);
        h.owner.handle(third).await;
        assert_eq!(
            third_result.await.unwrap().unwrap_err().reason.code,
            Code::StaleGeneration
        );
        for i in 0..7 {
            let (message, _) = envelope(h.request(Action::Run, &format!("queued-{i}")));
            assert!(h._normal.try_send(message).is_ok());
        }
        let (full, _) = envelope(h.request(Action::Run, "full"));
        assert!(h._normal.try_send(full).is_err());
        let (pause, _) = envelope(h.request(Action::Pause, "reserved"));
        assert!(h._urgent.try_send(pause).is_ok());
        let (full, _) = envelope(h.request(Action::Pause, "full-reserved"));
        assert!(h._urgent.try_send(full).is_err());
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn stopped_inflight_instruction_is_unknown_and_reaped_before_reset() {
        let mut h = Harness::new();
        h.create().await;
        let step = h.submit(Action::Step, "step").await;
        let stopped = h.submit(Action::Stop, "stop").await.await.unwrap().unwrap();
        assert_eq!(stopped["ack"], "outcome_unknown");
        assert_eq!(stopped["code"], "command_outcome_unknown");
        assert_eq!(stopped["session"]["state"], "stopped");
        assert_eq!(stopped["session"]["execution_state_known"], false);
        assert_eq!(
            step.await.unwrap().unwrap_err().reason.code,
            Code::CommandOutcomeUnknown
        );
        assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
        let stale = h.request(Action::Pause, "stale");
        let reset = h.submit(Action::Reset, "reset").await;
        assert_eq!(h.ledger.spawned.load(Ordering::SeqCst), 2);
        assert_eq!(h.view().run_generation, Decimal(2));
        let (old, old_result) = envelope(stale);
        h.owner.handle(old).await;
        assert_eq!(
            old_result.await.unwrap().unwrap_err().reason.code,
            Code::StaleGeneration
        );
        h.finish(0).await;
        let result = reset.await.unwrap().unwrap();
        assert_eq!(result["session"]["executed_count"], "0");
        assert!(h.view().records.is_empty());
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn reset_drops_old_exchange_and_old_controls_cannot_touch_replacement() {
        let mut h = Harness::new();
        h.create().await;
        let old = h.request(Action::Stop, "old-stop");
        let step = h.submit(Action::Step, "step").await;
        let reset = h.submit(Action::Reset, "reset").await;
        assert!(step.await.unwrap().is_err());
        assert_eq!(h.ledger.reaped.load(Ordering::SeqCst), 1);
        h.finish(0).await;
        reset.await.unwrap().unwrap();
        let before = h.view().control_revision;
        h.clock.set(59_999);
        let (message, receive) = envelope(old);
        h.owner.handle(message).await;
        assert_eq!(
            receive.await.unwrap().unwrap_err().reason.code,
            Code::StaleGeneration
        );
        assert_eq!(h.view().control_revision, before);
        assert_eq!(h.view().state, State::Paused);
        assert_eq!(h.view().executed_count, Decimal(0));
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn expiration_is_exact_includes_pauses_and_finishes_one_admitted_instruction() {
        let mut h = Harness::new();
        h.create().await;
        h.clock.set(59_999);
        h.owner.check_time().await;
        assert_eq!(h.view().state, State::Paused);
        h.clock.set(60_000);
        h.owner.check_time().await;
        assert_eq!(h.view().state, State::Expired);
        assert_eq!(h.dispatches(), 0);
        assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
        let mut h = Harness::new();
        h.create().await;
        h.clock.set(59_999);
        let step = h.submit(Action::Step, "last-step").await;
        h.clock.set(60_000);
        h.owner.check_time().await;
        assert_eq!(h.view().state, State::Stopping);
        h.finish(1).await;
        let result = step.await.unwrap().unwrap();
        assert_eq!(result["session"]["state"], "expired");
        assert_eq!(result["session"]["executed_count"], "1");
        assert_eq!(result["session"]["execution_state_known"], true);
        assert_eq!(h.dispatches(), 1);
        assert_eq!(h.view().recorder.stats.expired, Decimal(0));
    }
    #[tokio::test]
    async fn cancellation_before_admission_is_inert_after_admission_is_not_rollback() {
        let mut h = Harness::new();
        h.create().await;
        let request = h.request(Action::Step, "cancelled");
        let (message, receive) = envelope(request);
        drop(receive);
        h.owner.handle(message).await;
        assert_eq!(h.dispatches(), 0);
        let receive = h.submit(Action::Step, "admitted").await;
        drop(receive);
        h.finish(1).await;
        assert_eq!(h.dispatches(), 1);
        assert_eq!(h.view().executed_count, Decimal(1));
        assert_eq!(h.view().last_command.as_ref().unwrap().ack, Ack::Completed);
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn malformed_reply_retires_without_retry_and_preserves_confirmed_evidence() {
        let mut h = Harness::new();
        h.create().await;
        let step = h.submit(Action::Step, "step").await;
        h.finish(2).await;
        assert_eq!(
            step.await.unwrap().unwrap_err().reason.code,
            Code::CommandOutcomeUnknown
        );
        assert_eq!(h.view().state, State::Failed);
        assert!(!h.view().execution_state_known);
        assert_eq!(h.view().executed_count, Decimal(0));
        assert_eq!(h.dispatches(), 1);
        assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
        assert!(
            h.submit(Action::Step, "retry")
                .await
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(h.dispatches(), 1);
    }
    #[tokio::test]
    async fn recorder_loss_keeps_live_state_known_and_does_not_join_history() {
        let mut h = Harness::new();
        h.create().await;
        let first = h.submit(Action::Step, "one").await;
        h.finish(1).await;
        first.await.unwrap().unwrap();
        let second = h.submit(Action::Step, "two").await;
        let mut reply = golden_reply(&h.owner.session.as_ref().unwrap().spec, 2);
        reply.view.retained_count = Decimal(1);
        reply.view.stats.recorded = Decimal(1);
        reply.view.stats.full = Decimal(1);
        reply.view.transition = None;
        reply.view.recorder_result = Some(RecorderResult::Full);
        h.owner.exchange = None;
        h.owner.complete(Ok(reply)).await;
        second.await.unwrap().unwrap();
        assert_eq!(h.view().executed_count, Decimal(2));
        assert_eq!(h.view().records.len(), 1);
        assert!(h.view().execution_state_known);
        assert_eq!(
            h.view().current_snapshot,
            Some(golden_snapshot(Fixture::Register, 2))
        );
        h.owner.dispose().await.unwrap();
    }
    #[tokio::test]
    async fn disposal_failure_blocks_replacement_and_counter_exhaustion_never_dispatches() {
        let mut h = Harness::new();
        h.create().await;
        h.ledger.refuse_reap.store(true, Ordering::SeqCst);
        assert!(h.submit(Action::Stop, "stop").await.await.unwrap().is_err());
        assert!(h.view().disposal_failed);
        assert!(
            h.submit(Action::Reset, "reset")
                .await
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(h.ledger.spawned.load(Ordering::SeqCst), 1);
        h.ledger.refuse_reap.store(false, Ordering::SeqCst);
        h.owner.dispose().await.unwrap();
        let mut h = Harness::new();
        h.create().await;
        h.owner.session.as_mut().unwrap().next_request = u64::MAX;
        assert!(
            h.submit(Action::Step, "overflow")
                .await
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(h.dispatches(), 0);
        assert_eq!(h.view().state, State::Failed);
    }
    // These tests run the actual select loop with all competing events already
    // queued. Reply/admission probes inspect the competing response channel at
    // the linearization point, so executor wake order cannot hide a regression.
    type QueuedResult = Arc<StdMutex<Option<oneshot::Receiver<Result<Value>>>>>;
    struct AdmissionOrderChild {
        child: Box<dyn NativeChild>,
        normal_result: QueuedResult,
        admitted: StdMutex<Option<oneshot::Sender<()>>>,
    }
    impl NativeChild for AdmissionOrderChild {
        fn exchange(&self, request: WireRequest) -> Exchange {
            if request.operation == 2 {
                assert!(
                    matches!(
                        self.normal_result
                            .lock()
                            .unwrap()
                            .as_mut()
                            .unwrap()
                            .try_recv(),
                        Err(oneshot::error::TryRecvError::Empty)
                    ),
                    "normal queue won before an already-due tick"
                );
                self.admitted
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
            }
            self.child.exchange(request)
        }
        fn dispose(&mut self) -> Disposal<'_> {
            self.child.dispose()
        }
        fn diagnostics(&self) -> Diagnostics {
            self.child.diagnostics()
        }
    }
    #[tokio::test]
    async fn owner_loop_settles_ready_reply_and_timeout_before_rejected_urgent_queue() {
        for timed_out in [false, true] {
            let mut h = Harness::new();
            h.create().await;
            let step = h.submit(Action::Step, "step").await;
            let mut stale = h.request(Action::Pause, "stale-urgent");
            stale.backend_instance_id = Some("previous-backend".into());
            let (message, receive) = envelope(stale);
            let urgent_result: QueuedResult = Arc::new(StdMutex::new(Some(receive)));
            assert!(h._urgent.try_send(message).is_ok());
            let observation = urgent_result.clone();
            let reply = golden_reply(&h.owner.session.as_ref().unwrap().spec, 1);
            h.owner.exchange = Some(Box::pin(async move {
                assert!(
                    matches!(
                        observation.lock().unwrap().as_mut().unwrap().try_recv(),
                        Err(oneshot::error::TryRecvError::Empty)
                    ),
                    "urgent rejection starved a ready exchange"
                );
                if timed_out {
                    Err(uncertain(Cause::Timeout))
                } else {
                    Ok(reply)
                }
            }));
            let task = tokio::spawn(h.owner.run());
            // Timeout is only a deadlock guard. The test oracle is the channel
            // state checked inside the ready exchange before any await/yield.
            let settled = tokio::time::timeout(Duration::from_secs(5), step)
                .await
                .unwrap()
                .unwrap();
            if timed_out {
                assert_eq!(
                    settled.unwrap_err().reason.code,
                    Code::CommandOutcomeUnknown
                );
            } else {
                assert_eq!(settled.unwrap()["session"]["executed_count"], "1");
            }
            let receive = urgent_result.lock().unwrap().take().unwrap();
            assert_eq!(
                receive.await.unwrap().unwrap_err().reason.code,
                Code::StaleGeneration
            );
            h._shutdown.send(true).unwrap();
            task.await.unwrap().unwrap();
            assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
            assert_eq!(
                h.ledger
                    .requests
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|r| r.operation == 2)
                    .count(),
                1
            );
        }
    }
    #[tokio::test]
    async fn owner_loop_admits_due_tick_before_saturated_normal_queue() {
        let mut h = Harness::new();
        h.create().await;
        h.submit(Action::Run, "run").await.await.unwrap().unwrap();
        h.clock.set(250);
        let (first, receive) = envelope(h.request(Action::Run, "queued-first"));
        let normal_result: QueuedResult = Arc::new(StdMutex::new(Some(receive)));
        assert!(h._normal.try_send(first).is_ok());
        let mut rest = Vec::new();
        for i in 0..6 {
            let (message, receive) = envelope(h.request(Action::Run, &format!("queued-{i}")));
            assert!(h._normal.try_send(message).is_ok());
            rest.push(receive);
        }
        let (admitted, admission) = oneshot::channel();
        let child = h.owner.child.take().unwrap();
        h.owner.child = Some(Box::new(AdmissionOrderChild {
            child,
            normal_result: normal_result.clone(),
            admitted: StdMutex::new(Some(admitted)),
        }));
        let task = tokio::spawn(h.owner.run());
        tokio::time::timeout(Duration::from_secs(5), admission)
            .await
            .unwrap()
            .unwrap();
        let receive = normal_result.lock().unwrap().take().unwrap();
        assert!(receive.await.unwrap().is_err());
        for receive in rest {
            assert!(receive.await.unwrap().is_err());
        }
        h._shutdown.send(true).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
        assert_eq!(
            h.ledger
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.operation == 2)
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn owner_loop_admits_pause_before_an_already_due_tick() {
        let mut h = Harness::new();
        h.create().await;
        h.submit(Action::Run, "run").await.await.unwrap().unwrap();
        h.clock.set(250);
        let (pause, receive) = envelope(h.request(Action::Pause, "pause-before-tick"));
        assert!(h._urgent.try_send(pause).is_ok());
        let task = tokio::spawn(h.owner.run());
        let paused = tokio::time::timeout(Duration::from_secs(5), receive)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(paused["session"]["state"], "paused");
        assert_eq!(paused["session"]["executed_count"], "0");
        assert_eq!(
            h.ledger
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.operation == 2)
                .count(),
            0
        );
        h._shutdown.send(true).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn revision_exhaustion_during_blocked_step_preserves_uncertainty() {
        let mut h = Harness::new();
        h.create().await;
        let step = h.submit(Action::Step, "inflight").await;
        h.owner.session.as_mut().unwrap().view.control_revision = Decimal(u64::MAX);
        assert!(
            h.submit(Action::Pause, "overflow-pause")
                .await
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(
            step.await.unwrap().unwrap_err().reason.code,
            Code::CommandOutcomeUnknown
        );
        assert!(!h.view().execution_state_known);
        assert_eq!(h.view().state, State::Failed);
        assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
        assert_eq!(h.dispatches(), 1);
        assert_eq!(h.view().control_revision, Decimal(u64::MAX));
    }
    #[tokio::test]
    async fn halt_pause_and_clock_rollback_fail_closed() {
        let mut h = Harness::new();
        h.create().await;
        for count in 1..9 {
            let result = h.submit(Action::Step, &format!("step-{count}")).await;
            h.finish(count).await;
            result.await.unwrap().unwrap();
        }
        let halt = h.submit(Action::Step, "halt").await;
        let pause = h.submit(Action::Pause, "pause-halt").await;
        h.finish(9).await;
        halt.await.unwrap().unwrap();
        assert_eq!(pause.await.unwrap().unwrap()["session"]["state"], "halted");
        assert_eq!(h.view().executed_count, Decimal(9));
        assert_eq!(h.ledger.live.load(Ordering::SeqCst), 0);
        assert!(
            h.submit(Action::Run, "run-halted")
                .await
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(h.dispatches(), 9);
        let mut h = Harness::new();
        h.create().await;
        h.clock.set(100);
        h.owner.check_time().await;
        h.clock.set(99);
        h.owner.check_time().await;
        assert_eq!(h.view().state, State::Failed);
        assert_eq!(h.view().termination_reason, Some("clock_rollback"));
        assert_eq!(h.dispatches(), 0);
    }
    #[tokio::test]
    #[ignore = "requires REB_OWNED_VM_TEST_HELPER pointing to the built native helper"]
    async fn owned_vm_real_helper_control_and_independent_goldens() {
        let path = PathBuf::from(
            std::env::var_os("REB_OWNED_VM_TEST_HELPER").expect("Set REB_OWNED_VM_TEST_HELPER"),
        );
        let debugger = OwnedVmDebugger::new(path);
        for fixture in [Fixture::Register, Fixture::Stack] {
            let mut view = debugger
                .action_bytes(
                    &serde_json::to_vec(
                        &json!({"action":"create","command_id":"create","fixture":fixture}),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(view["session"]["state"], "paused");
            assert_eq!(view["session"]["executed_count"], "0");
            assert_eq!(
                view["session"]["initial_snapshot"],
                serde_json::to_value(golden_snapshot(fixture, 0)).unwrap()
            );
            for count in 1..=9 {
                let request = public_request(&view, "step", &format!("step-{count}"));
                view = debugger
                    .action_bytes(&serde_json::to_vec(&request).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    view["session"]["current_snapshot"],
                    serde_json::to_value(golden_snapshot(fixture, count)).unwrap()
                );
                let mut observed_record = view["session"]["records"][count as usize - 1].clone();
                observed_record["tick"] = json!(count.to_string());
                assert_eq!(
                    observed_record,
                    serde_json::to_value(golden_record(fixture, count)).unwrap()
                );
            }
            assert_eq!(view["session"]["state"], "halted");
            let reset = public_request(&view, "reset", "reset");
            view = debugger
                .action_bytes(&serde_json::to_vec(&reset).unwrap())
                .await
                .unwrap();
            assert_eq!(view["session"]["executed_count"], "0");
            let run = public_request(&view, "run", "run");
            view = debugger
                .action_bytes(&serde_json::to_vec(&run).unwrap())
                .await
                .unwrap();
            assert_eq!(view["session"]["executed_count"], "0");
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    view = debugger.state().await.unwrap();
                    if view["session"]["executed_count"]
                        .as_str()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap()
                        >= 2
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let pause = public_request(&view, "pause", "pause");
            view = debugger
                .action_bytes(&serde_json::to_vec(&pause).unwrap())
                .await
                .unwrap();
            assert_eq!(view["session"]["state"], "paused");
            let paused = view["session"]["current_snapshot"].clone();
            let count = view["session"]["executed_count"].clone();
            tokio::time::sleep(Duration::from_millis(600)).await;
            let inert = debugger.state().await.unwrap();
            assert_eq!(inert["session"]["current_snapshot"], paused);
            assert_eq!(inert["session"]["executed_count"], count);
            let step = public_request(&view, "step", "after-pause");
            view = debugger
                .action_bytes(&serde_json::to_vec(&step).unwrap())
                .await
                .unwrap();
            let close = public_request(&view, "close", "close");
            assert!(
                debugger
                    .action_bytes(&serde_json::to_vec(&close).unwrap())
                    .await
                    .unwrap()["session"]
                    .is_null()
            );
        }
        debugger.stop().await.unwrap();
    }
    fn public_request(view: &Value, action: &str, command: &str) -> Value {
        let mut value = json!({"action":action,"command_id":command});
        for key in [
            "backend_instance_id",
            "session_id",
            "run_id",
            "run_generation",
        ] {
            value[key] = view["session"][key].clone();
        }
        if matches!(action, "run" | "step") {
            value["expected_control_revision"] = view["session"]["control_revision"].clone();
        }
        if action == "step" {
            value["expected_executed_count"] = view["session"]["executed_count"].clone();
        }
        value
    }
}
