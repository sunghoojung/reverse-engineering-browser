//! One session's flow graph (protocol/flow-graph-v1.md): every walked stack the
//! store holds, folded into one graph of functions grouped by realm.
//!
//! Request, navigation and async-task scheduling stacks, and the walked stacks
//! of script cookie writes, name their frames by digest. Each distinct stack is
//! decoded once however often it repeats, each retained script is read once for
//! every frame that names it, and its positions are resolved in one pass. Two
//! adjacent synchronous frames are a call edge. A change of realm between them
//! is a frame boundary (a same-process iframe), a change between JavaScript and
//! Wasm a language boundary, and a call into an `eval` or `new Function` script
//! a dynamic one. Task segments link the stack that scheduled a task to that
//! task's first frame, so a `postMessage` into an iframe is one edge between
//! realms. Nothing is inferred: a frame without a resolvable identity stays a
//! node with a reason, and a cut chain, an omitted run or a budget is reported,
//! never bridged.
use crate::{
    error::{Error, Result},
    event_window, evidence, request_cookies, request_index,
    request_stack::{self, Frame, Identity, Record, Segment},
    store_scan::{self, Scanned, Stopped, Stores},
};
use axum::body::Bytes;
use hex::FromHex;
use regex::bytes::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const SCHEMA: &str = "flow-graph-v1";
/// A pathological store is a visible cut rather than an endless request.
const SCAN_DEADLINE: Duration = Duration::from_secs(30);
const CANCELLED: &str = "The flow graph request was cancelled";
/// Distinct stacks decoded. A stack is one digest however often it repeats, and
/// each renderer sends at most 1,024 request and 1,024 scheduling stacks per
/// configuration; past this the rest are counted, not drawn.
const MAX_STACKS: usize = 16_384;
const MAX_NODES: usize = 32_768;
const MAX_EDGES: usize = 131_072;
/// Edge and node references kept for path highlighting, about 8 MiB of JSON.
const MAX_PATH_REFS: usize = 1 << 20;
const MAX_IDENTITIES: usize = 1 << 18;
/// Request labels (`METHOD host`) waiting for their stack record.
const MAX_REQUEST_LABELS: usize = 1 << 18;
/// Distinct `METHOD host` texts; a session talks to far fewer hosts.
const MAX_LABEL_TEXTS: usize = 1 << 16;
/// Retained source read for names and positions, once per digest. One source
/// is held at a time, so this bounds work, not memory.
const MAX_SOURCE_BYTES: usize = 1 << 30;
/// Renderer request IDs kept on paths, for finding a selected request's path.
const MAX_REQUEST_REFS: usize = 1 << 17;
/// Call sites kept per edge, enough to show that one call is many.
const MAX_SITES: usize = 8;
const TYPES: [&str; 6] = [
    "request_initiator_stack",
    "navigation_initiator_stack",
    "async_task_stack",
    "script_cookie",
    "script_identity",
    "request_initiated",
];

/// The last answer and the store snapshot it describes.
#[derive(Default)]
pub struct Cache(Mutex<Option<(String, Bytes)>>);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Sink {
    Request(String),
    Navigation(&'static str),
    Cookie(&'static str),
}

impl Sink {
    fn kind(&self) -> &'static str {
        match self {
            Sink::Request(_) => "request",
            Sink::Navigation(_) => "navigation",
            Sink::Cookie(_) => "cookie_write",
        }
    }
    fn label(&self) -> String {
        match self {
            Sink::Request(label) => label.clone(),
            Sink::Navigation(kind) => kind.replace('_', " "),
            Sink::Cookie(api) => (*api).to_owned(),
        }
    }
}

/// How a digest's artifact is decoded: against its record, as a scheduling
/// stack of a known depth, or by its own header.
#[derive(Clone)]
enum Shape {
    Record(Record),
    Scheduling(u32),
    Alone,
}

/// Where a frame's script ID is read: its renderer process and isolate key
/// (zero for the document main thread, else the worker's context ID).
/// Script IDs are unique only per isolate (protocol/native-network-v3.md).
type Where = (u32, u64);

/// A scheduling stack's frames, shared by every stack whose chain names it,
/// and where this stack reads them.
type SegmentFrames = (Arc<Vec<Frame>>, Where);
/// A scheduling stack decoded once per digest: its frames and, for a version
/// 3 artifact, its own scope. Without one, each stack reads the frames in its
/// own process: identical version 1 or 2 bytes from two renderers name
/// different scripts.
type DecodedSegment = Option<(Arc<Vec<Frame>>, Option<request_stack::ScriptScope>)>;

/// One distinct walked stack and every record that named it.
struct Walk {
    process: u32,
    isolate: u64,
    digest: [u8; 32],
    shape: Shape,
    innermost: Frame,
    /// Records naming it whose state says the frames were not retained.
    unretained: bool,
    /// An `async_task_stack` whose walk stopped at 256 frames.
    bounded: bool,
    occurrences: u64,
    sinks: BTreeMap<Sink, u64>,
    schedules: BTreeMap<&'static str, u64>,
    frame_votes: BTreeMap<u64, u64>,
    tabs: BTreeSet<u64>,
    /// Renderer request IDs whose stack this is, so a selected request can
    /// find its path.
    requests: Vec<u64>,
}

#[derive(Default)]
struct Scan {
    identities: HashMap<Where, HashMap<u32, Identity>>,
    identity_count: usize,
    identities_dropped: u64,
    labels: HashMap<(u32, u64), u32>,
    label_ids: HashMap<String, u32>,
    label_text: Vec<String>,
    labels_dropped: bool,
    walks: Vec<Walk>,
    by_digest: HashMap<(Where, [u8; 32]), usize>,
    stacks_over_budget: u64,
    records: BTreeMap<&'static str, u64>,
    not_walked: BTreeMap<&'static str, u64>,
    request_refs: usize,
    request_refs_dropped: u64,
    /// Stack records from builds before the stack scope (request stack
    /// versions 1 and 2, `async_task_stack` version 1), and from builds with
    /// it: what the graph cannot show depends on which it read.
    unscoped_records: bool,
    scoped_records: bool,
}

/// An identifier field of a record, 0 unless it is a canonical unsigned integer.
fn number(event: &Value, key: &str) -> u64 {
    event_window::unsigned(&event[key]).unwrap_or(0)
}

impl Scan {
    fn walk(
        &mut self,
        event: &Value,
        isolate: u64,
        digest: [u8; 32],
        shape: Shape,
        innermost: Frame,
    ) -> Option<&mut Walk> {
        let process = number(event, "process_id") as u32;
        let index = match self.by_digest.get(&((process, isolate), digest)) {
            Some(index) => *index,
            None if self.walks.len() < MAX_STACKS => {
                self.walks.push(Walk {
                    process,
                    isolate,
                    digest,
                    shape,
                    innermost,
                    unretained: false,
                    bounded: false,
                    occurrences: 0,
                    sinks: BTreeMap::new(),
                    schedules: BTreeMap::new(),
                    frame_votes: BTreeMap::new(),
                    tabs: BTreeSet::new(),
                    requests: Vec::new(),
                });
                self.by_digest
                    .insert(((process, isolate), digest), self.walks.len() - 1);
                self.walks.len() - 1
            }
            None => {
                self.stacks_over_budget += 1;
                return None;
            }
        };
        let walk = &mut self.walks[index];
        walk.occurrences += 1;
        *walk
            .frame_votes
            .entry(number(event, "frame_id"))
            .or_default() += 1;
        let tab = number(event, "tab_id");
        if tab != 0 && walk.tabs.len() < 64 {
            walk.tabs.insert(tab);
        }
        Some(walk)
    }

    /// Folds in one record of the session; false when its decoder refuses it.
    fn record(&mut self, event: &Value) -> bool {
        let Some(&kind) = event["type"]
            .as_str()
            .and_then(|kind| TYPES.iter().find(|t| **t == kind))
        else {
            return false;
        };
        let Some(bytes) = request_stack::payload(event) else {
            return false;
        };
        *self.records.entry(kind).or_default() += 1;
        match kind {
            "script_identity" => self.identity(event, &bytes),
            "request_initiated" => {
                self.request_label(event, &bytes);
                true
            }
            "request_initiator_stack" => self.request_stack(event, &bytes),
            "navigation_initiator_stack" => self.navigation_stack(event, &bytes),
            "async_task_stack" => self.scheduling_stack(event, &bytes),
            _ => self.cookie_write(event),
        }
    }

    fn identity(&mut self, event: &Value, bytes: &[u8]) -> bool {
        let Some((isolate, script, identity)) = request_stack::decode_identity(bytes) else {
            return false;
        };
        let process = number(event, "process_id") as u32;
        let table = self.identities.entry((process, isolate)).or_default();
        if !table.contains_key(&script) && self.identity_count == MAX_IDENTITIES {
            self.identities_dropped += 1;
        } else {
            self.identity_count += usize::from(table.insert(script, identity).is_none());
        }
        true
    }

    /// Keeps a request's `METHOD host` for the stack record that follows it.
    fn request_label(&mut self, event: &Value, bytes: &[u8]) {
        let text = request_index::payload_text(bytes);
        let Some((method, host)) = request_index::network_target(&text, "request_initiated") else {
            return;
        };
        if self.labels.len() == MAX_REQUEST_LABELS {
            // Stacks follow their request closely; forgetting old
            // labels costs only a host on a very old stack.
            self.labels.clear();
            self.labels_dropped = true;
        }
        let label = match method {
            Some(method) => format!("{method} {host}"),
            None => host,
        };
        let id = match self.label_ids.get(&label) {
            Some(id) => *id,
            None if self.label_text.len() < MAX_LABEL_TEXTS => {
                self.label_text.push(label.clone());
                self.label_ids
                    .insert(label, (self.label_text.len() - 1) as u32);
                (self.label_text.len() - 1) as u32
            }
            None => {
                self.labels_dropped = true;
                return;
            }
        };
        let process = number(event, "process_id") as u32;
        self.labels
            .insert((process, number(event, "request_id")), id);
    }

    fn request_stack(&mut self, event: &Value, bytes: &[u8]) -> bool {
        let Some(record) = request_stack::decode_record(bytes) else {
            return false;
        };
        self.note_version(bytes[0] == 3);
        if matches!(record.state, 2 | 3 | 6) {
            let reason = match record.state {
                2 => "no_script",
                3 => "unsupported_thread",
                _ => "not_walked_thread_limit",
            };
            *self.not_walked.entry(reason).or_default() += 1;
            return true;
        }
        let (process, request) = (
            number(event, "process_id") as u32,
            number(event, "request_id"),
        );
        let label = self.labels.get(&(process, request)).map_or_else(
            || "request".to_owned(),
            |id| self.label_text[*id as usize].clone(),
        );
        let room = self.request_refs < MAX_REQUEST_REFS;
        let (digest, innermost, unretained) = (record.digest, record.innermost, record.state != 1);
        let isolate = record.scope.isolate_key;
        let kept = match self.walk(event, isolate, digest, Shape::Record(record), innermost) {
            Some(walk) => {
                walk.unretained |= unretained;
                *walk.sinks.entry(Sink::Request(label)).or_default() += 1;
                if room {
                    walk.requests.push(request);
                }
                room
            }
            None => false,
        };
        if kept {
            self.request_refs += 1;
        } else {
            self.request_refs_dropped += 1;
        }
        true
    }

    fn navigation_stack(&mut self, event: &Value, bytes: &[u8]) -> bool {
        let Some((record, kind, _target)) = request_stack::decode_navigation(bytes) else {
            return false;
        };
        let (digest, innermost, unretained) = (record.digest, record.innermost, record.state != 1);
        if let Some(walk) = self.walk(event, 0, digest, Shape::Record(record), innermost) {
            walk.unretained |= unretained;
            *walk.sinks.entry(Sink::Navigation(kind)).or_default() += 1;
        }
        true
    }

    fn note_version(&mut self, scoped: bool) {
        if scoped {
            self.scoped_records = true;
        } else {
            self.unscoped_records = true;
        }
    }

    fn scheduling_stack(&mut self, event: &Value, bytes: &[u8]) -> bool {
        let Some((task, recorded, digest, innermost, isolate)) = decode_scheduling(bytes) else {
            return false;
        };
        self.note_version(bytes[0] == 2);
        let bounded = bytes[5] & 1 != 0;
        let shape = Shape::Scheduling(recorded);
        if let Some(walk) = self.walk(event, isolate, digest, shape, innermost) {
            walk.bounded |= bounded;
            *walk.schedules.entry(task).or_default() += 1;
        }
        true
    }

    fn cookie_write(&mut self, event: &Value) -> bool {
        let Some(script) = request_cookies::decode_script(event) else {
            return false;
        };
        // Only a write walks the stack (flags bits 1 and 2); a read keeps one
        // frame.
        // A service worker's write is read in the worker's isolate; a record
        // that names no isolate records no frame to read.
        if let (true, Some(scope)) = (
            matches!(script.api, 1 | 3 | 6) && script.flags & 0x06 == 0x06,
            script.scope,
        ) {
            let api = request_cookies::APIS[usize::from(script.api)];
            let innermost = Frame::read(&script.frame);
            let isolate = scope.isolate_key;
            if let Some(walk) = self.walk(event, isolate, script.stack, Shape::Alone, innermost) {
                *walk.sinks.entry(Sink::Cookie(api)).or_default() += 1;
            }
        }
        true
    }
}

/// The one field read from a candidate line whose bytes do not name the
/// session the way the broker writes it.
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    session_id: Value,
}

/// Whether a candidate line can be one of the session's records, decided
/// before the line is parsed in full. The compact bytes the broker writes
/// answer at once. Any other line reads `session_id` alone, which still checks
/// that the whole line is JSON; a line that fails goes on to the full parse, so
/// malformed lines are counted as before.
fn may_be_session(line: &[u8], needle: &Regex, session: u64) -> bool {
    needle.is_match(line)
        || serde_json::from_slice::<Envelope>(line).map_or(true, |envelope| {
            event_window::unsigned(&envelope.session_id) == Some(session)
        })
}

/// The `async_task_stack` payload: task kind, recorded depth, digest, the
/// innermost frame and the isolate key, or None for a malformed record.
/// Version 2 adds message kinds 10 to 12, promise registrations (kind 9, at
/// most 32 frames, its call at byte 6) and the stack scope at bytes 80-95.
fn decode_scheduling(bytes: &[u8]) -> Option<(&'static str, u32, [u8; 32], Frame, u64)> {
    if bytes.len() != 128
        || !matches!(bytes[..4], [1 | 2, 0, 128, 0])
        || bytes[5] & !1 != 0
        || bytes[7] != 0
        || bytes[20..32].iter().any(|b| *b != 0)
    {
        return None;
    }
    let scoped = bytes[0] == 2;
    let (kind, registration) = (bytes[4], bytes[6]);
    let limit = if kind == 9 { 32 } else { 256 };
    let kinds = if kind == 9 {
        scoped && (1..=4).contains(&registration)
    } else {
        registration == 0 && (1..=if scoped { 12 } else { 8 }).contains(&kind)
    };
    let isolate = if scoped {
        if bytes[96..].iter().any(|b| *b != 0) {
            return None;
        }
        request_stack::Scope::read(&bytes[80..96])?.isolate_key
    } else if bytes[80..].iter().any(|b| *b != 0) {
        return None;
    } else {
        0
    };
    let recorded = request_stack::u32_at(bytes, 8);
    let digest: [u8; 32] = bytes[32..64].try_into().unwrap();
    let innermost = Frame::read(&bytes[64..80]);
    (kinds
        && (1..=limit).contains(&recorded)
        && (bytes[5] & 1 == 0 || recorded == limit)
        && digest.iter().any(|b| *b != 0))
    .then(|| {
        (
            request_stack::task_kind(kind),
            recorded,
            digest,
            innermost,
            isolate,
        )
    })
}

/// A decoded stack: synchronous frames innermost first, the await chain, and
/// each task segment with its scheduling frames when they were retained.
struct Decoded {
    sync: Vec<Frame>,
    omitted: u32,
    asyncs: Vec<Frame>,
    /// Many stacks share one scheduling stack, so its frames are shared. They
    /// are read where their own artifact says they were walked: a message
    /// carries segments from another thread or process.
    segments: Vec<(Segment, Option<SegmentFrames>)>,
    /// Record flags bit 2, bit 3 and bit 4.
    asyncs_truncated: bool,
    chain_cut: bool,
    chain_truncated: bool,
    /// A scheduling stack whose walk stopped at 256 frames: its outermost
    /// recorded frame is not the first frame of its task.
    bounded: bool,
    retained: bool,
}

/// Function identity: the same code in the same realm is one node however many
/// script IDs compiled it (an eval of one string, an inline script twice).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Code {
    Sha([u8; 32]),
    Script(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum NodeKey {
    Function {
        process: u32,
        isolate: u64,
        realm: u64,
        code: Code,
        wasm: bool,
        function: u32,
    },
    Sink {
        context: usize,
        sink: Sink,
    },
}

/// A node as it is built. `detail` holds what describes its function or sink;
/// the rest is written when the answer is.
struct Node {
    key: NodeKey,
    context: usize,
    kind: &'static str,
    detail: Value,
    /// Tasks the function scheduled, from `async_task_stack` records.
    schedules: BTreeMap<&'static str, u64>,
    chain_cut: bool,
    hits: u64,
    entries: u64,
    leaves: u64,
}

impl Node {
    fn json(self, id: usize) -> Value {
        let mut value = self.detail;
        value["id"] = json!(id);
        value["kind"] = json!(self.kind);
        value["context"] = json!(self.context);
        value["hits"] = json!(self.hits);
        value["entries"] = json!(self.entries);
        value["leaves"] = json!(self.leaves);
        if !self.schedules.is_empty() {
            value["schedules"] = json!(self.schedules);
        }
        if self.chain_cut {
            value["chain_cut"] = json!(true);
        }
        value
    }
}

/// An edge's identity: from, to, kind and, for a task edge, the task kind.
type EdgeKey = (usize, usize, &'static str, Option<&'static str>);

struct Edge {
    from: usize,
    to: usize,
    kind: &'static str,
    task: Option<&'static str>,
    crosses: Vec<&'static str>,
    count: u64,
    stacks: u64,
    sites: BTreeSet<(u64, u64)>,
    /// Details that can differ between the stacks that share this edge.
    via: BTreeSet<&'static str>,
    labels: BTreeSet<&'static str>,
    omitted: Option<u32>,
}

impl Edge {
    fn json(self) -> Value {
        let sites: Vec<Value> = self
            .sites
            .iter()
            .map(|&(line, column)| {
                if line == 0 {
                    json!({"module_offset": column})
                } else {
                    json!({"line": line, "column": column})
                }
            })
            .collect();
        let mut value = json!({
            "from": self.from,
            "to": self.to,
            "kind": self.kind,
            "crosses": self.crosses,
            "count": self.count,
            "stacks": self.stacks,
            "sites": sites,
        });
        if let Some(task) = self.task {
            value["task"] = json!(task);
        }
        if !self.via.is_empty() {
            value["via"] = json!(self.via);
        }
        if !self.labels.is_empty() {
            value["label"] = json!(self.labels.into_iter().collect::<Vec<_>>().join(" / "));
        }
        if let Some(omitted) = self.omitted {
            value["omitted"] = json!(omitted);
        }
        value
    }
}

/// What one stack says about an edge beyond its endpoints.
#[derive(Default)]
struct Detail {
    site: Option<(u64, u64)>,
    via: Vec<&'static str>,
    label: Option<&'static str>,
    omitted: Option<u32>,
}

/// One stack being added: its process, how many records it stands for, and
/// the edges it has walked.
struct Visit {
    at: Where,
    weight: u64,
    path: BTreeSet<usize>,
}

/// What one script's retained bytes resolved: positions and names by offset.
#[derive(Default)]
struct Resolved {
    artifact_id: Value,
    url: Value,
    lines: HashMap<u32, (u64, u64)>,
    names: HashMap<u32, String>,
    reason: Option<&'static str>,
}

struct Context {
    process: u32,
    isolate: u64,
    realm: u64,
    frame_votes: BTreeMap<u64, u64>,
    tabs: BTreeSet<u64>,
    origins: BTreeMap<String, u64>,
    kinds: BTreeMap<&'static str, u64>,
}

impl Context {
    fn json(&self, id: usize) -> Value {
        let mut origins: Vec<(&String, &u64)> = self.origins.iter().collect();
        origins.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let mut frames: Vec<(&u64, &u64)> = self
            .frame_votes
            .iter()
            .filter(|(frame, _)| **frame != 0)
            .collect();
        frames.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        json!({
            "id": id,
            "process_id": self.process,
            "isolate_key": (self.isolate != 0).then(|| format!("{:016x}", self.isolate)),
            "execution_context_id": (self.realm != 0).then(|| self.realm.to_string()),
            "origin": origins.first().map(|(origin, _)| origin),
            "origins": origins.iter().take(8).map(|(origin, functions)| json!({"origin": origin, "functions": functions})).collect::<Vec<_>>(),
            "frame_ids": frames.iter().take(8).map(|(frame, stacks)| json!({"frame_id": frame.to_string(), "stacks": stacks})).collect::<Vec<_>>(),
            "tab_ids": self.tabs.iter().take(16).collect::<Vec<_>>(),
            "counts": self.kinds,
        })
    }
}

struct Builder<'a> {
    scan: &'a Scan,
    resolved: &'a HashMap<[u8; 32], Resolved>,
    contexts: Vec<Context>,
    context_index: HashMap<(Where, u64), usize>,
    nodes: Vec<Node>,
    node_index: HashMap<NodeKey, usize>,
    edges: Vec<Edge>,
    edge_index: HashMap<EdgeKey, usize>,
    paths: Vec<Value>,
    path_refs: usize,
    nodes_cut: u64,
    edges_cut: u64,
    paths_cut: u64,
}

fn origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    match parsed.origin() {
        url::Origin::Tuple(..) => Some(parsed.origin().ascii_serialization()),
        url::Origin::Opaque(_) => Some(format!("{}:", parsed.scheme())),
    }
}

fn combinator(frame: &Frame) -> &'static str {
    match frame.combinator {
        1 => "Promise.all",
        2 => "Promise.allSettled",
        _ => "Promise.any",
    }
}

/// Whether a node's code is Wasm (true) or JavaScript (false); None for a sink.
fn language(kind: &str) -> Option<bool> {
    match kind {
        "wasm" => Some(true),
        "javascript" | "eval" => Some(false),
        _ => None,
    }
}

impl<'a> Builder<'a> {
    fn new(scan: &'a Scan, resolved: &'a HashMap<[u8; 32], Resolved>) -> Self {
        Self {
            scan,
            resolved,
            contexts: Vec::new(),
            context_index: HashMap::new(),
            nodes: Vec::new(),
            node_index: HashMap::new(),
            edges: Vec::new(),
            edge_index: HashMap::new(),
            paths: Vec::new(),
            path_refs: 0,
            nodes_cut: 0,
            edges_cut: 0,
            paths_cut: 0,
        }
    }

    fn identity(&self, at: Where, script: u32) -> Option<&'a Identity> {
        self.scan.identities.get(&at)?.get(&script)
    }

    fn context(&mut self, at: Where, realm: u64) -> usize {
        *self.context_index.entry((at, realm)).or_insert_with(|| {
            self.contexts.push(Context {
                process: at.0,
                isolate: at.1,
                realm,
                frame_votes: BTreeMap::new(),
                tabs: BTreeSet::new(),
                origins: BTreeMap::new(),
                kinds: BTreeMap::new(),
            });
            self.contexts.len() - 1
        })
    }

    /// The node for `key`, added with the context, kind and detail `describe`
    /// gives when it is new, or None past the node budget.
    fn node(
        &mut self,
        key: NodeKey,
        describe: impl FnOnce(&mut Self) -> (usize, &'static str, Value),
    ) -> Option<usize> {
        if let Some(&index) = self.node_index.get(&key) {
            return Some(index);
        }
        if self.nodes.len() == MAX_NODES {
            self.nodes_cut += 1;
            return None;
        }
        let (context, kind, detail) = describe(self);
        *self.contexts[context].kinds.entry(kind).or_default() += 1;
        self.node_index.insert(key.clone(), self.nodes.len());
        self.nodes.push(Node {
            key,
            context,
            kind,
            detail,
            schedules: BTreeMap::new(),
            chain_cut: false,
            hits: 0,
            entries: 0,
            leaves: 0,
        });
        Some(self.nodes.len() - 1)
    }

    /// The node for one frame, or None past the node budget. Combinator frames
    /// are labels on the await edge, never nodes.
    fn function(&mut self, at: Where, frame: &Frame) -> Option<usize> {
        let identity = self.identity(at, frame.script_id);
        let realm = identity.map_or(0, |identity| identity.realm);
        let wasm = frame.kind == 2;
        let top_level = !wasm && frame.flags & 2 != 0;
        let key = NodeKey::Function {
            process: at.0,
            isolate: at.1,
            realm,
            code: identity
                .and_then(|identity| identity.sha256)
                .map_or(Code::Script(frame.script_id), Code::Sha),
            wasm,
            function: if top_level { u32::MAX } else { frame.detail },
        };
        self.node(key, |builder| {
            let context = builder.context(at, realm);
            let kind = if wasm {
                "wasm"
            } else if identity.is_some_and(|identity| identity.eval) {
                "eval"
            } else {
                "javascript"
            };
            let detail = builder.function_detail(context, frame, identity, top_level);
            (context, kind, detail)
        })
    }

    /// Where a function node's frame is and what it is called, or why its
    /// source does not say.
    fn function_detail(
        &mut self,
        context: usize,
        frame: &Frame,
        identity: Option<&'a Identity>,
        top_level: bool,
    ) -> Value {
        let mut detail = json!({"script_id": frame.script_id, "status": "unresolved"});
        let sources = self.resolved;
        let source = request_stack::find_source(identity, |_, sha| sources.get(sha));
        let reason = match source {
            Ok((_, resolved)) => resolved.reason,
            Err(reason) => Some(reason),
        };
        if let Ok((_, resolved)) = source {
            detail["artifact_id"] = resolved.artifact_id.clone();
            detail["url"] = resolved.url.clone();
            if let Some(origin) = resolved.url.as_str().and_then(origin) {
                *self.contexts[context].origins.entry(origin).or_default() += 1;
            }
        }
        let usable = source.ok().filter(|_| reason.is_none());
        if frame.kind == 2 {
            detail["function_index"] = json!(frame.detail);
            if let Ok((_, resolved)) = source
                && let Some(name) = resolved.names.get(&frame.detail)
            {
                detail["name"] = json!(name);
            }
            if usable.is_some() {
                detail["status"] = json!("resolved");
            }
        } else {
            let at = (!top_level).then_some(frame.detail);
            detail["top_level"] = json!(top_level);
            detail["function_position"] = json!(at);
            if let Some((identity, resolved)) = usable {
                detail["status"] = json!("resolved");
                if let Some(&(line, column)) = at.and_then(|at| resolved.lines.get(&at)) {
                    // Sources numbers the artifact itself; line and column
                    // add the script's start in its document.
                    let (document_line, document_column) = identity.document_position(line, column);
                    detail["artifact_line"] = json!(line);
                    detail["artifact_column"] = json!(column);
                    detail["line"] = json!(document_line);
                    detail["column"] = json!(document_column);
                } else if top_level {
                    let (line, column) = identity.document_position(1, 1);
                    detail["line"] = json!(line);
                    detail["column"] = json!(column);
                } else {
                    detail["status"] = json!("unresolved");
                    detail["reason"] = json!("position_outside_source");
                }
                if let Some(name) = at.and_then(|at| resolved.names.get(&at)) {
                    detail["name"] = json!(name);
                }
            }
        }
        if let Some(reason) = reason {
            detail["reason"] = json!(reason);
        }
        detail
    }

    fn sink(&mut self, context: usize, sink: &Sink) -> Option<usize> {
        let key = NodeKey::Sink {
            context,
            sink: sink.clone(),
        };
        self.node(key, |_| {
            let detail = json!({"name": sink.label(), "status": "resolved"});
            (context, sink.kind(), detail)
        })
    }

    /// The call position inside the caller, as a one-based line and column.
    fn site(&self, at: Where, caller: &Frame) -> Option<(u64, u64)> {
        if caller.kind == 2 {
            return Some((0, u64::from(caller.position)));
        }
        let identity = self.identity(at, caller.script_id);
        let (identity, resolved) =
            request_stack::find_source(identity, |_, sha| self.resolved.get(sha)).ok()?;
        let &(line, column) = resolved.lines.get(&caller.position)?;
        Some(identity.document_position(line, column))
    }

    /// What an edge between two nodes crosses: realms, languages, or into eval
    /// code from other code.
    fn crosses(&self, from: usize, to: usize) -> Vec<&'static str> {
        let (a, b) = (&self.nodes[from], &self.nodes[to]);
        let realm = |node: &Node| self.contexts[node.context].realm;
        let mut crosses = Vec::new();
        if a.context != b.context && realm(a) != 0 && realm(b) != 0 {
            crosses.push("frame");
        }
        if let (Some(x), Some(y)) = (language(a.kind), language(b.kind))
            && x != y
        {
            crosses.push("language");
        }
        if b.kind == "eval" && !(a.kind == "eval" && same_code(&a.key, &b.key)) {
            crosses.push("dynamic");
        }
        crosses
    }

    /// Adds one stack's use of an edge. A stack that walks an edge twice (a
    /// recursion, two segments naming one scheduling stack) counts once.
    fn edge(&mut self, key: EdgeKey, weight: u64, detail: Detail, path: &mut BTreeSet<usize>) {
        let index = match self.edge_index.get(&key) {
            Some(&index) => index,
            None if self.edges.len() == MAX_EDGES => {
                self.edges_cut += 1;
                return;
            }
            None => {
                let (from, to, kind, task) = key;
                let crosses = self.crosses(from, to);
                self.edges.push(Edge {
                    from,
                    to,
                    kind,
                    task,
                    crosses,
                    count: 0,
                    stacks: 0,
                    sites: BTreeSet::new(),
                    via: BTreeSet::new(),
                    labels: BTreeSet::new(),
                    omitted: None,
                });
                self.edge_index.insert(key, self.edges.len() - 1);
                self.edges.len() - 1
            }
        };
        let edge = &mut self.edges[index];
        if path.insert(index) {
            edge.count += weight;
            edge.stacks += 1;
        }
        if let Some(site) = detail.site
            && edge.sites.len() < MAX_SITES
        {
            edge.sites.insert(site);
        }
        edge.via.extend(detail.via);
        edge.labels.extend(detail.label);
        edge.omitted = edge.omitted.max(detail.omitted);
    }

    /// Call edges of one synchronous run, innermost first; returns its nodes.
    fn run(
        &mut self,
        visit: &mut Visit,
        at: Where,
        frames: &[Frame],
        omitted_after: Option<(usize, u32)>,
    ) -> Vec<Option<usize>> {
        let nodes: Vec<Option<usize>> = frames
            .iter()
            .map(|frame| self.function(at, frame))
            .collect();
        for (index, pair) in nodes.windows(2).enumerate() {
            let &[Some(callee), Some(caller)] = pair else {
                continue;
            };
            let (kind, detail) = match omitted_after {
                Some((at, omitted)) if at == index => (
                    "omitted",
                    Detail {
                        omitted: Some(omitted),
                        ..Detail::default()
                    },
                ),
                _ => (
                    "call",
                    Detail {
                        site: self.site(at, &frames[index + 1]),
                        ..Detail::default()
                    },
                ),
            };
            self.edge(
                (caller, callee, kind, None),
                visit.weight,
                detail,
                &mut visit.path,
            );
        }
        nodes
    }

    fn add(&mut self, walk: &Walk, decoded: &Decoded) {
        let mut visit = Visit {
            at: (walk.process, walk.isolate),
            weight: walk.occurrences,
            path: BTreeSet::new(),
        };
        // A stack deeper than 1,024 keeps the innermost and outermost 512.
        let omitted_after = (decoded.omitted != 0).then_some((511, decoded.omitted));
        let own = visit.at;
        let sync = self.run(&mut visit, own, &decoded.sync, omitted_after);
        let innermost = sync.first().copied().flatten();
        let outermost = sync.last().copied().flatten();
        // A walk that stopped at 256 frames did not reach its task's first frame.
        let mut cut_at = outermost.filter(|_| decoded.retained && decoded.bounded);
        let first = self.await_chain(&mut visit, decoded, outermost, &mut cut_at);
        let entry = self.task_chain(&mut visit, decoded, first, &mut cut_at);
        if let Some(at) = cut_at {
            self.nodes[at].chain_cut = true;
        }
        let sinks = match innermost {
            Some(innermost) => self.innermost_records(&mut visit, walk, innermost),
            None => Vec::new(),
        };
        // Each node of this stack counts its occurrences once.
        let members: BTreeSet<usize> = sync
            .iter()
            .flatten()
            .copied()
            .chain(
                visit
                    .path
                    .iter()
                    .flat_map(|&edge| [self.edges[edge].from, self.edges[edge].to]),
            )
            .filter(|node| !sinks.contains(node))
            .collect();
        for &node in &members {
            self.nodes[node].hits += visit.weight;
        }
        if let Some(innermost) = innermost {
            self.nodes[innermost].leaves += visit.weight;
        }
        // Only a known first frame is an entry; an undecoded or cut stack names none.
        if let Some(entry) = entry {
            self.nodes[entry].entries += visit.weight;
        }
        self.keep_path(walk, decoded.retained, visit.path, members, sinks);
    }

    /// The await chain, each async frame awaited by the next. Returns the
    /// frame that began this task: the last awaiter, else the outermost
    /// synchronous frame. None when it is not known, so no task edge enters a
    /// frame that was not its task's first.
    fn await_chain(
        &mut self,
        visit: &mut Visit,
        decoded: &Decoded,
        outermost: Option<usize>,
        cut_at: &mut Option<usize>,
    ) -> Option<usize> {
        let mut first = outermost.filter(|_| decoded.retained && !decoded.bounded);
        let mut target = outermost;
        let mut label = None;
        for frame in &decoded.asyncs {
            if frame.kind == 4 {
                label = Some(combinator(frame));
                continue;
            }
            // A node past the budget is a gap, never bridged.
            let node = self.function(visit.at, frame)?;
            if let Some(to) = target {
                let detail = Detail {
                    site: self.site(visit.at, frame),
                    label: label.take(),
                    ..Detail::default()
                };
                self.edge(
                    (node, to, "await", None),
                    visit.weight,
                    detail,
                    &mut visit.path,
                );
            }
            target = Some(node);
            first = first.map(|_| node);
        }
        if decoded.asyncs_truncated {
            // The await chain continues past 32 frames: its first awaiter is unknown.
            *cut_at = cut_at.or(target);
            return None;
        }
        first
    }

    /// The task chain, nearest first: a segment's innermost frame scheduled
    /// the task whose first frame is the target, which starts as this task's
    /// first frame. Returns the first frame of the earliest task reached.
    fn task_chain(
        &mut self,
        visit: &mut Visit,
        decoded: &Decoded,
        first: Option<usize>,
        cut_at: &mut Option<usize>,
    ) -> Option<usize> {
        let mut target = first;
        let mut via: Vec<&'static str> = Vec::new();
        let mut cut = decoded.chain_cut || decoded.chain_truncated;
        for (segment, frames) in &decoded.segments {
            let Some(to) = target else {
                break;
            };
            let task = request_stack::task_kind(segment.kind);
            match frames {
                Some((frames, at)) if !frames.is_empty() => {
                    let nodes = self.run(visit, *at, frames, None);
                    if let Some(from) = nodes[0] {
                        let detail = Detail {
                            site: self.site(*at, &frames[0]),
                            via: std::mem::take(&mut via),
                            ..Detail::default()
                        };
                        let key = (from, to, "task", Some(task));
                        self.edge(key, visit.weight, detail, &mut visit.path);
                    } else {
                        // The scheduling frame is past the node budget.
                        *cut_at = cut_at.or(target);
                    }
                    let outer = nodes.last().copied().flatten();
                    if segment.flags & 1 != 0 || nodes[0].is_none() || outer.is_none() {
                        // The walk stopped at 256 frames, or a node is past the
                        // budget: that task's first frame is not known.
                        *cut_at = cut_at.or(outer).or(nodes[0]);
                        return None;
                    }
                    target = outer;
                }
                _ if segment.kind == 9 => via.push(task),
                _ => {
                    cut = true;
                    break;
                }
            }
        }
        if let Some(at) = target
            && (cut || !via.is_empty())
        {
            *cut_at = cut_at.or(Some(at));
        }
        target
    }

    /// What the records naming this stack say about its innermost frame: an
    /// edge to each sink they reached, the tasks it scheduled, and the frames
    /// and tabs of its realm. Returns the sink nodes.
    fn innermost_records(
        &mut self,
        visit: &mut Visit,
        walk: &Walk,
        innermost: usize,
    ) -> Vec<usize> {
        let context = self.nodes[innermost].context;
        let mut sinks = Vec::new();
        for (sink, &count) in &walk.sinks {
            if let Some(node) = self.sink(context, sink) {
                let key = (innermost, node, sink.kind(), None);
                self.edge(key, count, Detail::default(), &mut visit.path);
                self.nodes[node].hits += count;
                sinks.push(node);
            }
        }
        let schedules = &mut self.nodes[innermost].schedules;
        for (task, count) in &walk.schedules {
            *schedules.entry(task).or_default() += count;
        }
        let context = &mut self.contexts[context];
        for (frame, votes) in &walk.frame_votes {
            *context.frame_votes.entry(*frame).or_default() += votes;
        }
        context.tabs.extend(&walk.tabs);
        sinks
    }

    /// Keeps the stack's path for highlighting, within the path budget.
    fn keep_path(
        &mut self,
        walk: &Walk,
        retained: bool,
        edges: BTreeSet<usize>,
        members: BTreeSet<usize>,
        sinks: Vec<usize>,
    ) {
        let refs = edges.len() + members.len() + sinks.len();
        if self.path_refs + refs > MAX_PATH_REFS {
            self.paths_cut += 1;
            return;
        }
        self.path_refs += refs;
        let nodes: Vec<usize> = members.into_iter().chain(sinks).collect();
        self.paths.push(json!({
            "process_id": walk.process,
            "digest": hex::encode(walk.digest),
            "occurrences": walk.occurrences,
            "retained": retained,
            "requests": walk.requests.iter().map(u64::to_string).collect::<Vec<_>>(),
            "nodes": nodes,
            "edges": edges,
        }));
    }
}

fn same_code(a: &NodeKey, b: &NodeKey) -> bool {
    match (a, b) {
        (
            NodeKey::Function {
                process: p,
                code: c,
                ..
            },
            NodeKey::Function {
                process: q,
                code: d,
                ..
            },
        ) => p == q && c == d,
        _ => false,
    }
}

/// One walk's own artifact, decoded: recorded depth, omitted run, record
/// flags, frames (innermost first) and task segments.
type Main = (u32, u32, u8, Vec<Frame>, Vec<Segment>);

fn decode_main(
    walk: &Walk,
    stacks: &HashMap<[u8; 32], Value>,
    read: &dyn Fn(&Value, usize) -> Option<Vec<u8>>,
) -> std::result::Result<Main, &'static str> {
    let content = stacks
        .get(&walk.digest)
        .and_then(|artifact| read(artifact, request_stack::MAX_ARTIFACT));
    let decoded = content.as_deref().and_then(|content| match &walk.shape {
        Shape::Record(record) => request_stack::decode_artifact(content, record, walk.process).map(
            |(frames, segments)| {
                (
                    record.recorded,
                    record.omitted,
                    record.flags,
                    frames,
                    segments,
                )
            },
        ),
        Shape::Scheduling(recorded) => request_stack::decode_segment_artifact(content, *recorded)
            .map(|(frames, _)| (*recorded, 0, 0, frames, Vec::new())),
        Shape::Alone => {
            request_stack::decode_artifact_alone(content).map(|(record, frames, segments)| {
                (
                    record.recorded,
                    record.omitted,
                    record.flags,
                    frames,
                    segments,
                )
            })
        }
    });
    decoded.ok_or(if walk.unretained {
        "frames_not_retained"
    } else if content.is_none() {
        "stack_artifact_missing"
    } else {
        "stack_artifact_malformed"
    })
}

/// Completes a decoded walk with its task segments' scheduling frames. Many
/// requests share one scheduling stack, so each is decoded once.
fn decode(
    walk: &Walk,
    main: std::result::Result<Main, &'static str>,
    stacks: &HashMap<[u8; 32], Value>,
    read: &dyn Fn(&Value, usize) -> Option<Vec<u8>>,
    segments_seen: &mut HashMap<[u8; 32], DecodedSegment>,
    missing: &mut BTreeMap<&'static str, u64>,
) -> Decoded {
    let (recorded, omitted, flags, mut frames, segments) = match main {
        Ok(main) => main,
        Err(reason) => {
            *missing.entry(reason).or_default() += 1;
            return Decoded {
                sync: vec![walk.innermost],
                omitted: 0,
                asyncs: Vec::new(),
                segments: Vec::new(),
                asyncs_truncated: false,
                chain_cut: false,
                chain_truncated: false,
                bounded: walk.bounded,
                retained: false,
            };
        }
    };
    let asyncs = frames.split_off(recorded as usize);
    let segments = segments
        .into_iter()
        .map(|segment| {
            if segment.kind == 9 || segment.state != 1 {
                return (segment, None);
            }
            let frames = segments_seen
                .entry(segment.digest)
                .or_insert_with(|| {
                    stacks
                        .get(&segment.digest)
                        .and_then(|artifact| read(artifact, request_stack::MAX_ARTIFACT))
                        .and_then(|content| {
                            request_stack::decode_segment_artifact(&content, segment.recorded)
                        })
                        .map(|(frames, scope)| (Arc::new(frames), scope))
                })
                .clone()
                // A version 1 or 2 artifact is this walk's own document.
                .map(|(frames, scope)| {
                    let at = scope.map_or((walk.process, 0), |(process, scope)| {
                        (process, scope.isolate_key)
                    });
                    (frames, at)
                });
            if frames.is_none() {
                *missing.entry("segment_not_retained").or_default() += 1;
            }
            (segment, frames)
        })
        .collect();
    Decoded {
        sync: frames,
        omitted,
        asyncs,
        segments,
        asyncs_truncated: flags & 0x04 != 0,
        chain_cut: flags & 0x08 != 0,
        chain_truncated: flags & 0x10 != 0,
        bounded: walk.bounded,
        retained: true,
    }
}

/// Sources left unread, by why.
#[derive(Default)]
struct SourceCuts {
    budget: u64,
    deadline: u64,
}

/// Positions and names for every offset any frame names in one retained
/// script or module, reading its bytes once.
fn resolve_sources(
    wanted: &BTreeMap<[u8; 32], (bool, BTreeSet<u32>)>,
    sources: &HashMap<[u8; 32], Value>,
    read: &dyn Fn(&Value, usize) -> Option<Vec<u8>>,
    deadline: Instant,
    budget: &mut usize,
    cuts: &mut SourceCuts,
) -> HashMap<[u8; 32], Resolved> {
    let mut out = HashMap::new();
    for (sha, (wasm, offsets)) in wanted {
        let Some(artifact) = sources.get(sha) else {
            continue;
        };
        let mut resolved = Resolved {
            artifact_id: artifact["artifact_id"].clone(),
            url: artifact["url"].clone(),
            ..Resolved::default()
        };
        let size = artifact["byte_size"].as_u64().unwrap_or(0) as usize;
        if Instant::now() >= deadline {
            resolved.reason = Some("source_deadline");
            cuts.deadline += 1;
            out.insert(*sha, resolved);
            continue;
        }
        if size > *budget {
            resolved.reason = Some("source_budget");
            cuts.budget += 1;
            out.insert(*sha, resolved);
            continue;
        }
        match read(artifact, request_stack::MAX_SOURCE) {
            None => resolved.reason = Some("source_artifact_unreadable"),
            Some(bytes) => {
                *budget = budget.saturating_sub(bytes.len());
                if *wasm {
                    resolved.names = request_stack::wasm_names(&bytes)
                        .into_iter()
                        .filter(|(index, _)| offsets.contains(index))
                        .collect();
                } else {
                    match String::from_utf8(bytes) {
                        Err(_) => resolved.reason = Some("source_not_utf8"),
                        Ok(text) => {
                            for (offset, (byte, line, column)) in
                                request_stack::positions(&text, offsets)
                            {
                                resolved.lines.insert(offset, (line, column));
                                if let Some(name) = request_stack::function_name(&text, byte) {
                                    resolved.names.insert(offset, name);
                                }
                            }
                        }
                    }
                }
            }
        }
        out.insert(*sha, resolved);
    }
    out
}

fn snapshot_key(stores: &Stores, session: u64, end: u64) -> String {
    let manifest =
        std::fs::metadata(stores.artifacts.join("manifest.jsonl")).map_or(0, |meta| meta.len());
    format!("{session}:{end}:{manifest}")
}

/// The session's flow graph as JSON, answered from the cache while the stores
/// have not changed.
pub fn run(stores: &Stores, session: u64, cache: &Cache, cancel: &AtomicBool) -> Result<Bytes> {
    let end = store_scan::complete_end(&stores.events)?;
    let key = snapshot_key(stores, session, end);
    if let Some((cached, bytes)) = cache.0.lock().unwrap().as_ref()
        && *cached == key
    {
        return Ok(bytes.clone());
    }
    let (graph, cacheable) = build(stores, session, end, cancel)?;
    let bytes = Bytes::from(
        serde_json::to_vec(&graph).map_err(|_| Error::new(500, "Flow graph encoding failed"))?,
    );
    // A scan cut by its deadline is answered but not kept: the next request
    // reads again instead of repeating the partial graph.
    *cache.0.lock().unwrap() = cacheable.then(|| (key, bytes.clone()));
    Ok(bytes)
}

/// Every record of the session the flow graph reads, in one forward pass.
fn scan_events(
    path: &Path,
    session: u64,
    end: u64,
    reader: &store_scan::Reader,
) -> Result<(Scan, Scanned)> {
    let filter = |pattern: &str| {
        Regex::new(pattern).map_err(|_| Error::new(500, "Flow graph filter failed"))
    };
    let prefilter = filter(&format!(r#""type":"(?:{})""#, TYPES.join("|")))?;
    let needle = filter(&store_scan::field_pattern("session_id", session))?;
    let mut scan = Scan::default();
    let scanned = reader.lines(path, 0, end, Some(&prefilter), &mut |_, line| {
        if !may_be_session(line, &needle, session) {
            return Some(true);
        }
        let event = serde_json::from_slice::<Value>(line).ok()?;
        // A record the decoders refuse is counted as malformed.
        (!store_scan::same_session(&event, session) || scan.record(&event)).then_some(true)
    })?;
    Ok((scan, scanned))
}

/// The session's stack, script and module artifacts the walks name, by
/// SHA-256.
struct Artifacts<'a> {
    root: &'a Path,
    session: String,
    stacks: HashMap<[u8; 32], Value>,
    sources: HashMap<[u8; 32], Value>,
}

impl<'a> Artifacts<'a> {
    fn new(root: &'a Path, session: u64) -> Self {
        Self {
            root,
            session: session.to_string(),
            stacks: HashMap::new(),
            sources: HashMap::new(),
        }
    }

    /// One manifest pass for the artifacts whose hex SHA-256 is wanted.
    fn select(&mut self, wanted: &HashSet<String>) -> Result<()> {
        let selected = evidence::select_artifacts(self.root, |a| {
            a["session_id"].as_str() == Some(self.session.as_str())
                && matches!(a["kind"].as_str(), Some("stack" | "javascript" | "wasm"))
                && a["sha256"].as_str().is_some_and(|sha| wanted.contains(sha))
        })?;
        for artifact in selected {
            let Some(sha) = artifact["sha256"]
                .as_str()
                .and_then(|sha| <[u8; 32]>::from_hex(sha).ok())
            else {
                continue;
            };
            // Later manifest records are newer and win, as stack resolution reads them.
            if artifact["kind"] == "stack" {
                self.stacks.insert(sha, artifact);
            } else {
                self.sources.insert(sha, artifact);
            }
        }
        Ok(())
    }

    fn read(&self, artifact: &Value, limit: usize) -> Option<Vec<u8>> {
        evidence::content(self.root, artifact, limit).ok()
    }
}

/// Every walk decoded, with its task segments' scheduling stacks, and the
/// count of walks and segments left unresolved by why.
fn decode_walks(
    scan: &Scan,
    artifacts: &mut Artifacts,
) -> Result<(Vec<Decoded>, BTreeMap<&'static str, u64>)> {
    let mut wanted: HashSet<String> = scan
        .walks
        .iter()
        .map(|walk| hex::encode(walk.digest))
        .collect();
    for table in scan.identities.values() {
        wanted.extend(
            table
                .values()
                .filter_map(|identity| identity.sha256.map(hex::encode)),
        );
    }
    artifacts.select(&wanted)?;
    let read = |artifact: &Value, limit: usize| artifacts.read(artifact, limit);
    let mains: Vec<_> = scan
        .walks
        .iter()
        .map(|walk| decode_main(walk, &artifacts.stacks, &read))
        .collect();
    // Task segments can name scheduling stacks that no record here describes.
    let segment_digests: HashSet<String> = mains
        .iter()
        .flatten()
        .flat_map(|(_, _, _, _, segments)| segments.iter())
        .filter(|segment| segment.kind != 9 && segment.state == 1)
        .filter(|segment| !artifacts.stacks.contains_key(&segment.digest))
        .map(|segment| hex::encode(segment.digest))
        .collect();
    if !segment_digests.is_empty() {
        artifacts.select(&segment_digests)?;
    }
    let read = |artifact: &Value, limit: usize| artifacts.read(artifact, limit);
    let mut missing = BTreeMap::new();
    let mut segments_seen = HashMap::new();
    let decoded = scan
        .walks
        .iter()
        .zip(mains)
        .map(|(walk, main)| {
            decode(
                walk,
                main,
                &artifacts.stacks,
                &read,
                &mut segments_seen,
                &mut missing,
            )
        })
        .collect();
    Ok((decoded, missing))
}

/// Every offset each retained script is asked for, gathered before any read.
fn source_offsets(scan: &Scan, decoded: &[Decoded]) -> BTreeMap<[u8; 32], (bool, BTreeSet<u32>)> {
    let mut offsets: BTreeMap<[u8; 32], (bool, BTreeSet<u32>)> = BTreeMap::new();
    for (walk, decoded) in scan.walks.iter().zip(decoded) {
        let own: Where = (walk.process, walk.isolate);
        let frames = decoded
            .sync
            .iter()
            .chain(&decoded.asyncs)
            .map(|frame| (own, frame))
            .chain(
                decoded
                    .segments
                    .iter()
                    .filter_map(|(_, frames)| frames.as_ref())
                    .flat_map(|(frames, at)| frames.iter().map(move |frame| (*at, frame))),
            );
        for (at, frame) in frames.filter(|(_, frame)| frame.script_id != 0) {
            let Some(sha) = scan
                .identities
                .get(&at)
                .and_then(|t| t.get(&frame.script_id))
                .and_then(|i| i.sha256)
            else {
                continue;
            };
            let entry = offsets
                .entry(sha)
                .or_insert_with(|| (frame.kind == 2, BTreeSet::new()));
            if frame.kind == 2 {
                entry.1.insert(frame.detail);
            } else {
                entry.1.insert(frame.position);
                entry.1.insert(frame.detail);
            }
        }
    }
    offsets
}

/// What the read records cannot contain. Records from before the stack scope
/// walked the document main thread only and carried no message callers;
/// later ones walk workers and carry messages across threads and processes.
fn not_shown(scan: &Scan) -> Vec<&'static str> {
    const UNSCOPED: [&str; 3] = [
        "worker and worklet stacks (stacks are walked on the document main thread only)",
        "MessagePort and worker messages",
        "cross-process frames (an out-of-process iframe is another renderer; only its own stacks \
         appear)",
    ];
    const SCOPED: [&str; 3] = [
        "worklet stacks (worklets have no stack tables), and stacks of a worker past the \
         renderer's 32 stack tables",
        "ServiceWorker.postMessage and Client.postMessage, and window.postMessage to or from \
         another process",
        "frames of another renderer process: its stacks are their own realms, joined to this \
         page's only by MessagePort, BroadcastChannel and worker message task edges",
    ];
    const MIXED: [&str; 3] = [
        "in records from builds before request stack version 3: worker stacks, and MessagePort \
         and worker messages",
        "worklet stacks (worklets have no stack tables), and stacks of a worker past the \
         renderer's 32 stack tables",
        "ServiceWorker.postMessage and Client.postMessage, and window.postMessage to or from \
         another process",
    ];
    let mut out: Vec<&'static str> = match (scan.unscoped_records, scan.scoped_records) {
        (true, false) => UNSCOPED.to_vec(),
        (true, true) => MIXED
            .iter()
            .copied()
            .chain(std::iter::once(SCOPED[2]))
            .collect(),
        _ => SCOPED.to_vec(),
    };
    out.insert(
        out.len() - 1,
        "calls that never reached a recorded request, navigation, task or cookie write",
    );
    out
}

/// The graph, and whether it may be cached: an answer the deadline cut is not.
fn build(stores: &Stores, session: u64, end: u64, cancel: &AtomicBool) -> Result<(Value, bool)> {
    let started = Instant::now();
    let deadline = started + SCAN_DEADLINE;
    let reader = store_scan::Reader {
        cancel,
        deadline,
        cancelled: CANCELLED,
    };
    let (scan, scanned) = scan_events(&stores.events, session, end, &reader)?;
    let mut artifacts = Artifacts::new(&stores.artifacts, session);
    let (decoded, missing) = decode_walks(&scan, &mut artifacts)?;
    let (mut source_budget, mut source_cuts) = (MAX_SOURCE_BYTES, SourceCuts::default());
    let resolved = resolve_sources(
        &source_offsets(&scan, &decoded),
        &artifacts.sources,
        &|artifact, limit| artifacts.read(artifact, limit),
        deadline,
        &mut source_budget,
        &mut source_cuts,
    );

    let mut builder = Builder::new(&scan, &resolved);
    for (walk, decoded) in scan.walks.iter().zip(&decoded) {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::new(499, CANCELLED));
        }
        builder.add(walk, decoded);
    }

    let deadline_cut = scanned.stopped == Stopped::Deadline;
    // Complete means nothing was cut: no deadline, no budget and no table
    // that forgot entries.
    let complete = !deadline_cut
        && scan.stacks_over_budget == 0
        && builder.nodes_cut == 0
        && builder.edges_cut == 0
        && builder.paths_cut == 0
        && scan.identities_dropped == 0
        && !scan.labels_dropped
        && scan.request_refs_dropped == 0
        && source_cuts.budget == 0
        && source_cuts.deadline == 0;
    let contexts: Vec<Value> = builder
        .contexts
        .iter()
        .enumerate()
        .map(|(id, context)| context.json(id))
        .collect();
    let nodes: Vec<Value> = builder
        .nodes
        .into_iter()
        .enumerate()
        .map(|(id, node)| node.json(id))
        .collect();
    let edges: Vec<Value> = builder.edges.into_iter().map(Edge::json).collect();
    let graph = json!({
        "schema": SCHEMA,
        "session_id": session.to_string(),
        "evidence": "observed",
        "complete": complete,
        "coverage": {
            "stopped": if deadline_cut { "deadline" } else { "end" },
            "scanned_bytes": scanned.position.to_string(),
            "store_end": end.to_string(),
            "malformed_records": scanned.malformed,
            "elapsed_ms": started.elapsed().as_millis() as u64,
        },
        "stacks": {
            "records": scan.records,
            "occurrences": scan.walks.iter().map(|walk| walk.occurrences).sum::<u64>(),
            "distinct": scan.walks.len(),
            "decoded": decoded.iter().filter(|d| d.retained).count(),
            "not_walked": scan.not_walked,
            "unresolved": missing,
            "over_budget": scan.stacks_over_budget,
        },
        "truncated": {
            "nodes": builder.nodes_cut,
            "edges": builder.edges_cut,
            "paths": builder.paths_cut,
            "identities": scan.identities_dropped,
            "request_labels": scan.labels_dropped,
            "request_ids": scan.request_refs_dropped,
            "source_budget": source_cuts.budget,
            "source_deadline": source_cuts.deadline,
        },
        "limits": {
            "stacks": MAX_STACKS,
            "nodes": MAX_NODES,
            "edges": MAX_EDGES,
            "path_refs": MAX_PATH_REFS,
            "request_refs": MAX_REQUEST_REFS,
            "source_bytes": MAX_SOURCE_BYTES,
            "scan_deadline_ms": SCAN_DEADLINE.as_millis() as u64,
        },
        "not_shown": not_shown(&scan),
        "contexts": contexts,
        "nodes": nodes,
        "edges": edges,
        "paths": builder.paths,
    });
    Ok((graph, !deadline_cut && source_cuts.deadline == 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_stack::tests::{frame, identity_bytes, segment, stack_artifact};
    use sha2::{Digest, Sha256};
    use std::io::Write;

    fn request_record(
        digest: &[u8],
        innermost: &[u8],
        recorded: u32,
        segments: u16,
        wasm: u32,
    ) -> Vec<u8> {
        let mut p = vec![2, 0, 128, 0, 1, 0];
        p.extend(segments.to_le_bytes());
        for value in [recorded, recorded, 0] {
            p.extend(value.to_le_bytes());
        }
        p.extend(0u16.to_le_bytes());
        p.extend(segments.to_le_bytes());
        p.extend(wasm.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        p.extend(digest);
        p.extend(innermost);
        p.resize(128, 0);
        p
    }

    fn scheduling_record(kind: u8, recorded: u32, digest: &[u8], innermost: &[u8]) -> Vec<u8> {
        let mut p = vec![1, 0, 128, 0, kind, 0, 0, 0];
        p.extend(recorded.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        p.resize(32, 0);
        p.extend(digest);
        p.extend(innermost);
        p.resize(128, 0);
        p
    }

    struct Fixture {
        root: tempfile::TempDir,
        events: Vec<Value>,
        artifacts: Vec<Value>,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join("artifacts/blobs")).unwrap();
            Self {
                root,
                events: Vec::new(),
                artifacts: Vec::new(),
            }
        }
        fn event(&mut self, kind: &str, process: u64, request: u64, frame: u64, payload: &[u8]) {
            let sequence = self.events.len() as u64 + 1;
            self.events.push(json!({"protocol_version":3,"session_id":"9","sequence_number":sequence.to_string(),
                "monotonic_time_ns":sequence.to_string(),"navigation_id":"0","frame_id":frame.to_string(),"artifact_id":"0",
                "parent_event_id":"0","request_id":request.to_string(),"process_id":process,"thread_id":1,"tab_id":5,
                "category":"network","type":kind,"flags":0,"payload_encoding":"hex","payload":hex::encode(payload),
                "payload_size":payload.len(),"payload_truncated":false}));
        }
        fn text_event(&mut self, kind: &str, process: u64, request: u64, text: &str) {
            self.event(kind, process, request, 1, text.as_bytes());
        }
        fn artifact(&mut self, kind: &str, url: &str, bytes: &[u8]) -> String {
            let sha = hex::encode(Sha256::digest(bytes));
            std::fs::write(
                self.root.path().join(format!("artifacts/blobs/{sha}.bin")),
                bytes,
            )
            .unwrap();
            let id = self.artifacts.len() + 1;
            self.artifacts.push(json!({"protocol_version": 1, "artifact_id": id.to_string(), "session_id": "9",
                "navigation_id": "0", "frame_id": "0", "parent_artifact_id": "0", "creator_event_id": "1", "kind": kind,
                "execution_context_id": "99", "capture_origin": match kind {
                    "stack" => "request_stack",
                    "wasm" => "webassembly_module",
                    _ => "stack_script",
                },
                "url": url, "mime_type": "application/octet-stream", "sensitive": false, "sha256": sha,
                "byte_size": bytes.len(), "content_path": format!("blobs/{sha}.bin")}));
            sha
        }
        fn stores(&self) -> Stores {
            let events = self.root.path().join("events.jsonl");
            let mut file = std::fs::File::create(&events).unwrap();
            for event in &self.events {
                writeln!(file, "{event}").unwrap();
            }
            let mut manifest =
                std::fs::File::create(self.root.path().join("artifacts/manifest.jsonl")).unwrap();
            for artifact in &self.artifacts {
                writeln!(manifest, "{artifact}").unwrap();
            }
            Stores {
                events,
                artifacts: self.root.path().join("artifacts"),
            }
        }
    }

    /// Every answer must match the published contract.
    fn assert_contract(value: &Value) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/openapi.json");
        let spec: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let document = json!({"$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/components/schemas/FlowGraph", "components": spec["components"]});
        let validator = jsonschema::validator_for(&document).unwrap();
        if let Err(error) = validator.validate(value) {
            panic!("flow graph contract: {error}");
        }
    }

    fn answer(stores: &Stores, session: u64, cache: &Cache) -> (Bytes, Value) {
        let bytes = run(stores, session, cache, &AtomicBool::new(false)).unwrap();
        let value = serde_json::from_slice(&bytes).unwrap();
        assert_contract(&value);
        (bytes, value)
    }

    fn graph(fixture: &Fixture) -> Value {
        answer(&fixture.stores(), 9, &Cache::default()).1
    }

    fn node<'a>(graph: &'a Value, name: &str) -> &'a Value {
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["name"] == name)
            .unwrap_or_else(|| panic!("no node {name}"))
    }

    fn edge<'a>(graph: &'a Value, from: &str, to: &str) -> &'a Value {
        let (from, to) = (&node(graph, from)["id"], &node(graph, to)["id"]);
        graph["edges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|edge| edge["from"] == *from && edge["to"] == *to)
            .unwrap_or_else(|| panic!("no edge"))
    }

    /// A top page posts a message into a same-process iframe, whose handler
    /// calls an eval'd helper and a Wasm export, and the Wasm import fetches.
    fn iframe_wasm_fixture() -> Fixture {
        let mut f = Fixture::new();
        let top = "function boot() {\n  frames[0].postMessage('go', '*');\n}\nboot();\n";
        let inner = "function onMessage() {\n  helper();\n  exports.run();\n}\nfunction send() {\n  fetch('/beacon', {method: 'POST'});\n}\n";
        let dynamic = "function helper() { return 1; }";
        let module = wat::parse_str(
            r#"(module (import "env" "send" (func $send)) (func $run (export "run") call $send))"#,
        )
        .unwrap();
        f.artifact("javascript", "https://top.test/app.js", top.as_bytes());
        f.artifact(
            "javascript",
            "https://frame.test/inner.js",
            inner.as_bytes(),
        );
        f.artifact("javascript", "https://frame.test/", dynamic.as_bytes());
        f.artifact("wasm", "https://frame.test/m.wasm", &module);
        let at = |text: &str, needle: &str| text.find(needle).unwrap() as u32;
        // Scheduling stack in the top realm: boot -> postMessage, from top level.
        let scheduling = [
            frame(1, 0, 10, at(top, "frames[0]"), at(top, "() {")),
            frame(1, 2, 10, at(top, "boot();"), 0),
        ];
        let scheduling_artifact = stack_artifact(1, &scheduling, &[], &[]);
        let scheduling_sha = f.artifact("stack", "reb-stack:x", &scheduling_artifact);
        let scheduling_digest = hex::decode(&scheduling_sha).unwrap();
        // The request stack in the iframe realm, innermost first:
        // send <- wasm run <- onMessage (the posted task).
        let request = [
            frame(1, 0, 20, at(inner, "fetch"), at(inner, "() {\n  fetch")),
            frame(2, 0, 30, 0x2c, 1),
            frame(
                1,
                0,
                20,
                at(inner, "exports.run"),
                at(inner, "() {\n  helper"),
            ),
        ];
        let request_artifact =
            stack_artifact(2, &request, &[], &[segment(5, 1, 2, &scheduling_digest)]);
        let request_sha = f.artifact("stack", "reb-stack:y", &request_artifact);
        let request_digest = hex::decode(&request_sha).unwrap();
        // A second, cookie-free request through the eval'd helper.
        let helper = [
            frame(1, 0, 40, 9, 15),
            frame(
                1,
                0,
                20,
                at(inner, "helper();"),
                at(inner, "() {\n  helper"),
            ),
        ];
        let helper_artifact = stack_artifact(2, &helper, &[], &[]);
        let helper_sha = f.artifact("stack", "reb-stack:z", &helper_artifact);
        let helper_digest = hex::decode(&helper_sha).unwrap();
        for (script, realm, kind, flags, bytes) in [
            (10u32, 99u64, 1u8, 2u8, top.as_bytes().to_vec()),
            (20, 100, 1, 2, inner.as_bytes().to_vec()),
            (40, 100, 1, 3, dynamic.as_bytes().to_vec()),
            (30, 100, 2, 0, module.clone()),
        ] {
            f.event(
                "script_identity",
                41,
                0,
                7,
                &identity_bytes(kind, flags, script, (0, 0), realm, &bytes),
            );
        }
        f.event(
            "async_task_stack",
            41,
            0,
            6,
            &scheduling_record(5, 2, &scheduling_digest, &scheduling[0]),
        );
        for request_id in [70, 71] {
            f.text_event("request_initiated", 41, request_id, "POST frame.test");
            f.event(
                "request_initiator_stack",
                41,
                request_id,
                7,
                &request_record(&request_digest, &request[0], 3, 1, 1),
            );
        }
        f.text_event("request_initiated", 41, 72, "GET frame.test");
        f.event(
            "request_initiator_stack",
            41,
            72,
            7,
            &request_record(&helper_digest, &helper[0], 2, 0, 0),
        );
        f
    }

    #[test]
    fn one_graph_crosses_realms_languages_and_dynamic_code() {
        let g = graph(&iframe_wasm_fixture());
        assert_eq!(g["schema"], SCHEMA);
        assert_eq!(g["complete"], true, "{}", g["truncated"]);
        assert_eq!(g["stacks"]["distinct"], 3);
        assert_eq!(g["stacks"]["occurrences"], 4);
        let contexts = g["contexts"].as_array().unwrap();
        assert_eq!(contexts.len(), 2, "one lane per realm");
        let lane = |name: &str| &contexts[node(&g, name)["context"].as_u64().unwrap() as usize];
        assert_eq!(lane("boot")["origin"], "https://top.test");
        assert_eq!(lane("onMessage")["origin"], "https://frame.test");
        assert_eq!(lane("onMessage")["frame_ids"][0]["frame_id"], "7");
        assert_eq!(node(&g, "run")["kind"], "wasm");
        assert_eq!(node(&g, "helper")["kind"], "eval");
        assert_eq!(node(&g, "onMessage")["line"], 1);
        assert_eq!(node(&g, "send")["line"], 5);
        assert_eq!(
            (
                node(&g, "send")["artifact_line"].as_u64(),
                node(&g, "send")["artifact_column"].as_u64()
            ),
            (Some(5), Some(14))
        );

        // postMessage from the top realm into the iframe is one task edge.
        let task = edge(&g, "boot", "onMessage");
        assert_eq!(
            (task["kind"].as_str(), task["task"].as_str()),
            (Some("task"), Some("post_message"))
        );
        assert_eq!(task["crosses"], json!(["frame"]));
        assert_eq!(task["count"], 2, "two requests rode the same posted task");
        assert_eq!(edge(&g, "onMessage", "run")["crosses"], json!(["language"]));
        assert_eq!(edge(&g, "run", "send")["crosses"], json!(["language"]));
        assert_eq!(edge(&g, "run", "send")["sites"][0]["module_offset"], 0x2c);
        assert_eq!(
            edge(&g, "onMessage", "helper")["crosses"],
            json!(["dynamic"])
        );
        assert_eq!(edge(&g, "onMessage", "run")["sites"][0]["line"], 3);
        // The top-level frame scheduled boot's call.
        let top = g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["top_level"] == true)
            .unwrap();
        assert_eq!(top["context"], node(&g, "boot")["context"]);

        let sink = node(&g, "POST frame.test");
        assert_eq!(
            (sink["kind"].as_str(), sink["hits"].as_u64()),
            (Some("request"), Some(2))
        );
        assert_eq!(edge(&g, "send", "POST frame.test")["count"], 2);
        assert_eq!(
            node(&g, "onMessage")["hits"],
            3,
            "each stack counts a node once"
        );
        assert_eq!(node(&g, "onMessage")["schedules"], Value::Null);
        assert_eq!(node(&g, "boot")["schedules"]["post_message"], 1);
        // Paths name exactly the edges each stack walked.
        let paths = g["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 3);
        let request_path = paths.iter().find(|p| p["occurrences"] == 2).unwrap();
        assert_eq!(request_path["requests"], json!(["70", "71"]));
        let path_edges: BTreeSet<u64> = request_path["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_u64().unwrap())
            .collect();
        assert!(path_edges.contains(&task_index(&g, "boot", "onMessage")));
        assert!(!path_edges.contains(&task_index(&g, "onMessage", "helper")));
    }

    fn task_index(g: &Value, from: &str, to: &str) -> u64 {
        let wanted = edge(g, from, to);
        g["edges"]
            .as_array()
            .unwrap()
            .iter()
            .position(|e| e == wanted)
            .unwrap() as u64
    }

    #[test]
    fn missing_bytes_stay_visible_and_never_bridge() {
        let mut f = iframe_wasm_fixture();
        // Drop the scheduling stack and the inner script: the task edge goes,
        // inner frames keep their identity and a reason.
        f.artifacts
            .retain(|a| a["url"] != "reb-stack:x" && a["url"] != "https://frame.test/inner.js");
        let g = graph(&f);
        assert_eq!(g["stacks"]["unresolved"]["stack_artifact_missing"], 1);
        assert_eq!(
            g["stacks"]["unresolved"]["segment_not_retained"], 1,
            "two requests share one decoded stack"
        );
        let unresolved: Vec<&Value> = g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["reason"] == "source_artifact_missing")
            .collect();
        assert_eq!(
            unresolved.len(),
            2,
            "onMessage and send keep their identities"
        );
        assert!(
            g["edges"]
                .as_array()
                .unwrap()
                .iter()
                .all(|e| e["kind"] != "task")
        );
        let entry = unresolved
            .iter()
            .find(|n| n["chain_cut"] == true)
            .expect("the cut task entry is marked");
        assert_eq!(entry["kind"], "javascript");
    }

    #[test]
    fn repeated_stacks_are_decoded_once_and_the_answer_is_cached() {
        let mut f = iframe_wasm_fixture();
        let digest = {
            let stack = f
                .events
                .iter()
                .find(|e| e["type"] == "request_initiator_stack")
                .unwrap();
            stack["payload"].clone()
        };
        for request in 100..400u64 {
            let mut copy = f
                .events
                .iter()
                .find(|e| e["type"] == "request_initiator_stack")
                .unwrap()
                .clone();
            copy["request_id"] = json!(request.to_string());
            copy["payload"] = digest.clone();
            f.events.push(copy);
        }
        let stores = f.stores();
        let cache = Cache::default();
        let (bytes, first) = answer(&stores, 9, &cache);
        assert_eq!(first["stacks"]["distinct"], 3);
        assert_eq!(first["stacks"]["occurrences"], 304);
        assert_eq!(edge(&first, "boot", "onMessage")["count"], 302);
        let (again, _) = answer(&stores, 9, &cache);
        assert_eq!(
            bytes.as_ptr(),
            again.as_ptr(),
            "an unchanged store answers from the cache"
        );
        // Another session in the same store is not this one.
        let (_, other) = answer(&stores, 8, &cache);
        assert_eq!(other["nodes"], json!([]));
    }

    #[test]
    fn malformed_and_unwalked_records_are_counted() {
        let mut f = iframe_wasm_fixture();
        f.event("request_initiator_stack", 41, 80, 7, &[0; 128]);
        f.event("script_cookie", 41, 0, 7, &[0; 128]);
        let mut no_script = vec![2, 0, 128, 0, 2, 0, 0, 0];
        no_script.resize(128, 0);
        f.event("request_initiator_stack", 41, 81, 7, &no_script);
        f.events.push(json!({"session_id": "9", "type": "async_task_stack", "payload_encoding": "hex", "payload": "zz"}));
        let g = graph(&f);
        assert_eq!(g["coverage"]["malformed_records"], 3);
        assert_eq!(g["stacks"]["not_walked"]["no_script"], 1);
        assert_eq!(g["stacks"]["distinct"], 3);
    }

    fn async_record(
        digest: &[u8],
        innermost: &[u8],
        recorded: u32,
        asyncs: u16,
        segments: u16,
    ) -> Vec<u8> {
        let mut p = request_record(digest, innermost, recorded, segments, 0);
        p[20..22].copy_from_slice(&asyncs.to_le_bytes());
        p[22..24].copy_from_slice(&(asyncs + segments).to_le_bytes());
        p
    }

    #[test]
    fn task_edges_enter_only_a_known_first_frame_and_count_each_stack_once() {
        let mut f = Fixture::new();
        let text = "async function a() {\n  await b();\n}\nfunction b() {\n  fetch('/x');\n}\nfunction x() {\n  setTimeout(a);\n}\nfunction r() {\n  r();\n}\nfunction g() {\n  r();\n}\n";
        let at = |needle: &str| text.find(needle).unwrap() as u32;
        let start = |name: &str| at(&format!("function {name}(")) + 9 + name.len() as u32;
        f.artifact("javascript", "https://top.test/app.js", text.as_bytes());
        f.event(
            "script_identity",
            41,
            0,
            7,
            &identity_bytes(1, 2, 50, (0, 0), 99, text.as_bytes()),
        );
        let b = frame(1, 0, 50, at("fetch"), start("b"));
        let x = frame(1, 0, 50, at("setTimeout"), start("x"));
        let scheduler = stack_artifact(1, std::slice::from_ref(&x), &[], &[]);
        let scheduler = hex::decode(f.artifact("stack", "reb-stack:x", &scheduler)).unwrap();
        // 1. `setTimeout(a)` ran `a`, which awaited `b`: the task enters `a`.
        let awaited = frame(3, 0, 50, at("await b"), start("a"));
        let one = stack_artifact(
            2,
            std::slice::from_ref(&b),
            std::slice::from_ref(&awaited),
            &[segment(1, 1, 1, &scheduler)],
        );
        let one = hex::decode(f.artifact("stack", "reb-stack:1", &one)).unwrap();
        f.event(
            "request_initiator_stack",
            41,
            70,
            7,
            &async_record(&one, &b, 1, 1, 1),
        );
        // 2. The timer was scheduled by a walk that stopped at 256 frames (`r`
        //    recursing), itself posted by `g`: no task edge enters that walk.
        let mut deep = vec![x.clone()];
        deep.extend(std::iter::repeat_n(
            frame(1, 0, 50, at("  r();"), start("r")),
            255,
        ));
        let deep = hex::decode(f.artifact(
            "stack",
            "reb-stack:deep",
            &stack_artifact(1, &deep, &[], &[]),
        ))
        .unwrap();
        let g = frame(1, 0, 50, at("  r();\n}\n"), start("g"));
        let poster = hex::decode(f.artifact(
            "stack",
            "reb-stack:g",
            &stack_artifact(1, std::slice::from_ref(&g), &[], &[]),
        ))
        .unwrap();
        let mut bounded = segment(1, 1, 256, &deep);
        bounded[2] = 1;
        let two = stack_artifact(
            2,
            std::slice::from_ref(&b),
            &[],
            &[bounded, segment(5, 1, 1, &poster)],
        );
        let two = hex::decode(f.artifact("stack", "reb-stack:2", &two)).unwrap();
        f.event(
            "request_initiator_stack",
            41,
            71,
            7,
            &request_record(&two, &b, 1, 2, 0),
        );
        // 3. A microtask hop before the same timer: the shared edge keeps it.
        let microtask = segment(9, 6, 0, &[0; 32]);
        let three = stack_artifact(
            2,
            std::slice::from_ref(&b),
            &[],
            &[microtask, segment(1, 1, 1, &scheduler)],
        );
        let three = hex::decode(f.artifact("stack", "reb-stack:3", &three)).unwrap();
        f.event(
            "request_initiator_stack",
            41,
            72,
            7,
            &request_record(&three, &b, 1, 2, 0),
        );
        // 4. A stack whose artifact is missing names no entry.
        f.event(
            "request_initiator_stack",
            41,
            73,
            7,
            &request_record(&[7; 32], &b, 1, 0, 0),
        );
        let graph = graph(&f);
        let id = |name: &str| node(&graph, name)["id"].clone();
        let edges = graph["edges"].as_array().unwrap();
        let between = |from: &str, to: &str| {
            edges
                .iter()
                .filter(|e| e["from"] == id(from) && e["to"] == id(to))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            between("x", "a").len(),
            1,
            "the timer ran the awaiting function"
        );
        assert_eq!(between("a", "b")[0]["kind"], "await");
        let timer = between("x", "b");
        assert_eq!(timer.len(), 1);
        assert_eq!(
            (timer[0]["count"].as_u64(), timer[0]["via"].clone()),
            (Some(2), json!(["microtask"])),
            "stacks 2 and 3 share the edge; the hop is kept"
        );
        // The chain stops at the cut: the poster past it is neither linked nor
        // drawn on this path (its own async_task_stack record would draw it).
        assert!(
            graph["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|n| n["name"] != "g"),
            "nothing enters a walk that stopped at 256 frames"
        );
        assert_eq!(node(&graph, "r")["chain_cut"], true);
        let recursion = &between("r", "r")[0];
        assert_eq!(
            (recursion["stacks"].as_u64(), recursion["count"].as_u64()),
            (Some(1), Some(1)),
            "one stack walking r -> r 254 times counts once"
        );
        assert_eq!(
            node(&graph, "x")["entries"],
            2,
            "stacks 1 and 3 began in x's task"
        );
        assert_eq!(
            (
                node(&graph, "b")["entries"].as_u64(),
                node(&graph, "a")["entries"].as_u64()
            ),
            (Some(0), Some(0))
        );
        assert_eq!(graph["stacks"]["unresolved"]["stack_artifact_missing"], 1);
    }

    /// Two renderers (two tabs of one site) record byte-identical version 1
    /// scheduling stacks, whose script 50 is a different script in each.
    /// Each request is drawn as scheduled in its own process: one decode of
    /// the shared bytes never carries the first stack's process to the next.
    #[test]
    fn identical_older_segments_resolve_in_each_stack_own_process() {
        let mut f = Fixture::new();
        let first = "function go() {\n  fetch('/a');\n}\nfunction a1() {\n  setTimeout(go);\n}\n";
        let second = "function go() {\n  fetch('/b');\n}\nfunction b1() {\n  setTimeout(go);\n}\n";
        let at = |needle: &str| first.find(needle).unwrap() as u32;
        let start = |name: &str| at(&format!("function {name}(")) + 9 + name.len() as u32;
        for (process, text) in [(41, first), (42, second)] {
            f.artifact("javascript", "https://top.test/app.js", text.as_bytes());
            f.event(
                "script_identity",
                process,
                0,
                7,
                &identity_bytes(1, 2, 50, (0, 0), 99, text.as_bytes()),
            );
        }
        let go = frame(1, 0, 50, at("fetch"), start("go"));
        let timer = frame(1, 0, 50, at("setTimeout"), start("a1"));
        let scheduler = stack_artifact(1, std::slice::from_ref(&timer), &[], &[]);
        let scheduler = hex::decode(f.artifact("stack", "reb-stack:t", &scheduler)).unwrap();
        let stack = stack_artifact(
            2,
            std::slice::from_ref(&go),
            &[],
            &[segment(1, 1, 1, &scheduler)],
        );
        let stack = hex::decode(f.artifact("stack", "reb-stack:go", &stack)).unwrap();
        for process in [41, 42] {
            f.event(
                "request_initiator_stack",
                process,
                70,
                7,
                &request_record(&stack, &go, 1, 1, 0),
            );
        }
        let g = graph(&f);
        let nodes = g["nodes"].as_array().unwrap();
        let contexts = g["contexts"].as_array().unwrap();
        let at_process = |name: &str, process: u64| {
            nodes
                .iter()
                .find(|node| {
                    node["name"] == name
                        && contexts[node["context"].as_u64().unwrap() as usize]["process_id"]
                            == process
                })
                .unwrap_or_else(|| panic!("no node {name} in process {process}"))["id"]
                .clone()
        };
        let task =
            |from: &Value, to: &Value| {
                g["edges"].as_array().unwrap().iter().any(|edge| {
                    edge["from"] == *from && edge["to"] == *to && edge["kind"] == "task"
                })
            };
        let (go41, go42) = (at_process("go", 41), at_process("go", 42));
        let (a1, b1) = (at_process("a1", 41), at_process("b1", 42));
        assert!(task(&a1, &go41) && task(&b1, &go42), "{}", g["edges"]);
        assert!(
            !task(&a1, &go42),
            "no edge between processes that never interacted"
        );
        // Only records from before the stack scope: what they could not hold.
        assert_eq!(
            g["not_shown"][0],
            "worker and worklet stacks (stacks are walked on the document main thread only)"
        );
        assert_eq!(g["not_shown"][1], "MessagePort and worker messages");
    }

    #[test]
    fn worker_stacks_resolve_in_their_own_isolate() {
        use crate::request_stack::tests::scoped_artifact;
        let mut f = Fixture::new();
        // Script 7 is a different script in the page and in the worker.
        let page = "function post() {\n  port.postMessage(1);\n}\n";
        let worker = "let n = 0;\nfunction inWorker() {\n  fetch('/w');\n}\n";
        let at = |text: &str, needle: &str| text.find(needle).unwrap() as u32;
        let post = frame(1, 0, 7, at(page, "port"), at(page, "() {"));
        let work = frame(1, 0, 7, at(worker, "fetch"), at(worker, "() {"));
        f.artifact("javascript", "https://app.test/page.js", page.as_bytes());
        f.artifact(
            "javascript",
            "https://app.test/worker.js",
            worker.as_bytes(),
        );
        let mut worker_identity = identity_bytes(1, 0x02, 7, (0, 0), 98, worker.as_bytes());
        worker_identity[0] = 2;
        worker_identity[72] = 2;
        worker_identity[80..88].copy_from_slice(&0x77u64.to_le_bytes());
        f.event(
            "script_identity",
            41,
            0,
            7,
            &identity_bytes(1, 0x02, 7, (0, 0), 99, page.as_bytes()),
        );
        f.event("script_identity", 41, 0, 0x77, &worker_identity);
        // The page posted to a port; the worker's request ran in its handler.
        let posted = scoped_artifact(41, 1, 0, std::slice::from_ref(&post), &[], 0);
        f.artifact("stack", "reb-stack:posted", &posted);
        let carried = segment(10, 1, 1, &Sha256::digest(&posted));
        let stack = scoped_artifact(41, 2, 0x77, std::slice::from_ref(&work), &[carried], 0);
        f.artifact("stack", "reb-stack:worker", &stack);
        let mut record = request_record(&Sha256::digest(&stack), &work, 1, 1, 0);
        record[0] = 3;
        record[80] = 2;
        record[88..96].copy_from_slice(&0x77u64.to_le_bytes());
        f.event("request_initiator_stack", 41, 90, 0x77, &record);
        // A worker past the renderer's table limit is counted, never walked.
        let mut limited = vec![3, 0, 128, 0, 6, 0];
        limited.resize(128, 0);
        limited[80] = 2;
        limited[88..96].copy_from_slice(&0x78u64.to_le_bytes());
        f.event("request_initiator_stack", 41, 91, 0x78, &limited);
        let g = graph(&f);
        assert_eq!(g["complete"], true, "{}", g["truncated"]);
        // Named from the worker's source: the page's script 7 has no such function.
        assert_eq!(node(&g, "inWorker")["line"], 2);
        assert_eq!(node(&g, "post")["line"], 1);
        let contexts = g["contexts"].as_array().unwrap();
        let lane = |name: &str| &contexts[node(&g, name)["context"].as_u64().unwrap() as usize];
        assert_eq!(lane("inWorker")["isolate_key"], "0000000000000077");
        assert_eq!(lane("post")["isolate_key"], Value::Null);
        let task = edge(&g, "post", "inWorker");
        assert_eq!(
            (task["kind"].as_str(), task["task"].as_str()),
            (Some("task"), Some("message_port"))
        );
        assert_eq!(g["stacks"]["not_walked"]["not_walked_thread_limit"], 1);
        // Scoped records walk workers and carry messages across processes.
        let not_shown = g["not_shown"].to_string();
        assert!(
            not_shown.contains("worklet stacks (worklets have no stack tables)")
                && not_shown.contains("joined to this page's only by MessagePort")
                && !not_shown.contains("MessagePort and worker messages"),
            "{not_shown}"
        );
    }

    #[test]
    fn an_empty_store_is_an_empty_complete_graph() {
        let f = Fixture::new();
        let g = graph(&f);
        assert_eq!(
            (
                g["nodes"].as_array().unwrap().len(),
                g["complete"].as_bool()
            ),
            (0, Some(true))
        );
    }
}
