//! The graph as it is built: realms, function and sink nodes, and edges, each
//! kept once by identity, and every walk's plan, the nodes and edges it walks.
//! A plan is made once per walk and its weight is added along it; a record
//! that names the walk again only adds that weight along the same plan. A walk
//! whose inputs change (its stack artifact or a scheduling stack arrives, an
//! identity it looked for arrives, a later record says its frames were not
//! retained or its walk was bounded) has its plan taken back out and made
//! again. Counts are exact under that: every count a plan adds it takes back.
//! What stacks say about an edge (call sites, microtask hops, labels, the
//! omitted run) is a union that only grows, since a walk's frames never change:
//! a plan made again names the same details on every edge it keeps.
use super::{
    FxMap,
    records::{Counts, Delta, Identity, IdentityKey, NO_SHA, Scan, Shape, Sink, Walk, Where, add},
};
use crate::request_stack::{self, Frame, Segment};
use std::{collections::BTreeMap, sync::Arc};

/// A scheduling stack's frames, shared by every stack whose chain names it,
/// and where this stack reads them.
pub(super) type SegmentFrames = (Arc<Vec<Frame>>, Where);
/// A scheduling stack read once per digest and depth: its frames and, for a
/// version 3 artifact, its own scope, or why it was not decoded. Without a
/// scope, each stack reads the frames in its own process: identical version 1
/// or 2 bytes from two renderers name different scripts.
pub(super) type SegmentRead =
    std::result::Result<(Arc<Vec<Frame>>, Option<request_stack::ScriptScope>), &'static str>;

/// A scheduling stack's artifact, decoded, or why it was not.
pub(super) fn read_segment(content: crate::error::Result<&[u8]>, recorded: u32) -> SegmentRead {
    let content = content.map_err(|_| "stack_artifact_missing")?;
    request_stack::decode_segment_artifact(content, recorded)
        .map(|(frames, scope)| (Arc::new(frames), scope))
        .ok_or("stack_artifact_malformed")
}

/// A decoded stack: synchronous frames innermost first, the await chain, and
/// each task segment with its scheduling frames when they were retained.
pub(super) struct Decoded {
    pub sync: Vec<Frame>,
    pub omitted: u32,
    pub asyncs: Vec<Frame>,
    /// Many stacks share one scheduling stack, so its frames are shared. They
    /// are read where their own artifact says they were walked: a message
    /// carries segments from another thread or process.
    pub segments: Vec<(Segment, Option<SegmentFrames>)>,
    /// Record flags bit 2, bit 3 and bit 4.
    pub asyncs_truncated: bool,
    pub chain_cut: bool,
    pub chain_truncated: bool,
    /// A scheduling stack whose walk stopped at 256 frames: its outermost
    /// recorded frame is not the first frame of its task.
    pub bounded: bool,
    pub retained: bool,
    /// Why the stack's own frames are unknown, when they are.
    pub reason: Option<&'static str>,
    /// Retained scheduling stacks that were not read.
    pub segments_missing: u32,
}

/// One walk's own artifact, decoded: recorded depth, omitted run, record
/// flags, frames (innermost first) and task segments.
pub(super) type Main = (u32, u32, u8, Vec<Frame>, Vec<Segment>);

/// A walk's own artifact decoded against its record or its own header. A
/// scheduling stack is read as a segment instead (`scheduling_main`).
pub(super) fn decode_main(
    walk: &Walk,
    content: Option<&[u8]>,
) -> std::result::Result<Main, &'static str> {
    let decoded = content.and_then(|content| match &walk.shape {
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
        // Read as a segment instead, by `scheduling_main`.
        Shape::Scheduling(_) => None,
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

/// A scheduling stack's walk, from its artifact read as a segment, so a stack
/// that is both a walk and a segment of other chains is decoded once. None
/// when the artifact lookup does not hold it.
pub(super) fn scheduling_main(
    recorded: u32,
    read: Option<&SegmentRead>,
) -> std::result::Result<Main, &'static str> {
    match read {
        Some(Ok((frames, _))) => Ok((recorded, 0, 0, frames.to_vec(), Vec::new())),
        Some(Err(reason)) => Err(reason),
        None => Err("stack_artifact_missing"),
    }
}

/// Completes a decoded walk with its task segments' scheduling frames, each
/// read once per digest and depth.
pub(super) fn decode(
    walk: &Walk,
    main: std::result::Result<Main, &'static str>,
    segments_by_digest: &FxMap<([u8; 32], u32), SegmentRead>,
) -> Decoded {
    let (recorded, omitted, flags, mut frames, segments) = match main {
        Ok(main) => main,
        Err(reason) => {
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
                reason: Some(reason),
                segments_missing: 0,
            };
        }
    };
    let asyncs = frames.split_off(recorded as usize);
    let mut segments_missing = 0;
    let segments = segments
        .into_iter()
        .map(|segment| {
            // States 7 and 8 end the chain; 4 and 5 cut it; 6 is a frameless
            // microtask hop. State 1 names the scheduling stack.
            if segment.state != 1 {
                return (segment, None);
            }
            let frames = segments_by_digest
                .get(&(segment.digest, segment.recorded))
                .and_then(|read| read.as_ref().ok())
                .cloned()
                // A version 1 or 2 artifact is this walk's own document.
                .map(|(frames, scope)| {
                    let at = scope.map_or((walk.process, 0), |(process, scope)| {
                        (process, scope.isolate_key)
                    });
                    (frames, at)
                });
            segments_missing += u32::from(frames.is_none());
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
        reason: None,
        segments_missing,
    }
}

/// Function identity: the same code in the same realm is one node however many
/// script IDs compiled it (an eval of one string, an inline script twice).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Code {
    Sha(u32),
    Script(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct NodeKey {
    at: Where,
    realm: u64,
    code: Code,
    wasm: bool,
    /// The function position or index; `u32::MAX` for top-level script code.
    function: u32,
}

/// The frame fields a node is found by, before its identity is looked up.
type FrameKey = (Where, u32, u32, bool);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NodeKind {
    Javascript,
    Eval,
    Wasm,
    Request,
    Navigation,
    CookieWrite,
}

impl NodeKind {
    pub fn name(self) -> &'static str {
        match self {
            NodeKind::Javascript => "javascript",
            NodeKind::Eval => "eval",
            NodeKind::Wasm => "wasm",
            NodeKind::Request => "request",
            NodeKind::Navigation => "navigation",
            NodeKind::CookieWrite => "cookie_write",
        }
    }
    /// Whether the code is Wasm (true) or JavaScript (false); None for a sink.
    fn language(self) -> Option<bool> {
        match self {
            NodeKind::Wasm => Some(true),
            NodeKind::Javascript | NodeKind::Eval => Some(false),
            _ => None,
        }
    }
}

/// What a function node's first frame said about it.
pub(super) struct Function {
    pub script_id: u32,
    /// The function position (JavaScript) or index (Wasm).
    pub detail: u32,
    pub top_level: bool,
    pub code: Code,
    pub identity: Option<Identity>,
}

pub(super) struct Node {
    pub context: u32,
    pub kind: NodeKind,
    /// None for a sink, which names `sink`.
    pub function: Option<Function>,
    pub sink: u32,
    pub hits: u64,
    /// Distinct stacks that walk it.
    pub stacks: u64,
    pub entries: u64,
    pub leaves: u64,
    /// Tasks the function scheduled, from `async_task_stack` records.
    pub schedules: Counts<u8>,
    /// Walks whose chain is cut here.
    pub chain_cut: u64,
    /// Why chains end here uncut, by segment state and task kind: no script
    /// scheduled the task, or its message origin was rejected.
    pub chain_ends: Counts<(u8, u8)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum EdgeKind {
    Call,
    Omitted,
    Await,
    Task,
    Request,
    Navigation,
    CookieWrite,
}

impl EdgeKind {
    pub fn name(self) -> &'static str {
        match self {
            EdgeKind::Call => "call",
            EdgeKind::Omitted => "omitted",
            EdgeKind::Await => "await",
            EdgeKind::Task => "task",
            EdgeKind::Request => "request",
            EdgeKind::Navigation => "navigation",
            EdgeKind::CookieWrite => "cookie_write",
        }
    }
}

/// An edge's identity: from, to, kind and, for a task edge, the task kind.
type EdgeKey = (u32, u32, EdgeKind, u8);

/// A call position before its source is read: the caller's script and where
/// that script starts in its document, or a Wasm module offset (`NO_SHA`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Site {
    pub sha: u32,
    pub start_line: u32,
    pub start_column: u32,
    pub position: u32,
}

pub(super) const CROSSES_FRAME: u8 = 1;
pub(super) const CROSSES_LANGUAGE: u8 = 2;
pub(super) const CROSSES_DYNAMIC: u8 = 4;

pub(super) struct Edge {
    pub from: u32,
    pub to: u32,
    pub kind: EdgeKind,
    /// The task kind of a task edge (`request_stack::task_kind`), else 0.
    pub task: u8,
    pub crosses: u8,
    pub count: u64,
    pub stacks: u64,
    /// Every distinct call site, sorted.
    pub sites: Vec<Site>,
    /// Microtask hops, one bit per task kind.
    pub via: u16,
    /// Combinators (bits 0-2) and promise registrations (bits 3-6).
    pub labels: u8,
    pub omitted: u32,
}

pub(super) struct Context {
    pub process: u32,
    pub isolate: u64,
    pub realm: u64,
    /// Records by frame ID and by tab ID, of the walks whose innermost frame
    /// is in this realm.
    pub frames: BTreeMap<u64, u64>,
    pub tabs: BTreeMap<u64, u64>,
}

/// The offsets of one source that frames asked for since it was last read.
#[derive(Default)]
pub(super) struct Wanted {
    pub wasm: bool,
    pub positions: Vec<u32>,
    pub names: Vec<u32>,
}

/// What one stack walks.
#[derive(Default)]
pub(super) struct Plan {
    /// Function nodes, sorted.
    pub members: Box<[u32]>,
    /// Edges other than to sinks, sorted.
    pub edges: Box<[u32]>,
    /// Each sink its records reached: the sink, its node and the edge to it.
    pub sinks: Vec<(u32, u32, u32)>,
    pub innermost: Option<u32>,
    /// The first frame of the earliest task reached, when it is known.
    pub entry: Option<u32>,
    pub cut: Option<u32>,
    /// Where the chain ends uncut: the node, the segment state and task kind.
    pub end: Option<(u32, u8, u8)>,
    pub reason: Option<&'static str>,
    pub segments_missing: u32,
    pub retained: bool,
}

/// What one stack says about an edge beyond its endpoints.
#[derive(Default)]
struct Detail {
    site: Option<Site>,
    via: u16,
    labels: u8,
    omitted: u32,
}

/// The walk being planned: where its own frames are read, the edges it has
/// walked, and identities it looked for and did not find.
struct Planning<'a> {
    at: Where,
    path: Vec<u32>,
    missing: &'a mut Vec<IdentityKey>,
}

#[derive(Default)]
pub(super) struct Graph {
    pub contexts: Vec<Context>,
    context_index: FxMap<(Where, u64), u32>,
    pub nodes: Vec<Node>,
    node_index: FxMap<NodeKey, u32>,
    /// The node each frame shape resolved to, and whether its identity was
    /// missing; cleared when identities arrive.
    frames: FxMap<FrameKey, (u32, bool)>,
    sink_nodes: FxMap<(u32, u32), u32>,
    pub edges: Vec<Edge>,
    edge_index: FxMap<EdgeKey, u32>,
    pub wanted: FxMap<u32, Wanted>,
    /// Walks and segments left unresolved, by why.
    pub unresolved: BTreeMap<&'static str, u64>,
    pub decoded: u64,
    pub occurrences: u64,
    pub planned: u64,
}

fn combinator(frame: &Frame) -> u8 {
    1 << (frame.combinator.clamp(1, 3) - 1)
}

fn registration(registration: u8) -> u8 {
    1 << (registration.clamp(1, 4) + 2)
}

/// The label of each bit of `Edge::labels`, as the Initiator tab names them.
pub(super) const LABELS: [&str; 7] = [
    "Promise.all",
    "Promise.allSettled",
    "Promise.any",
    "Promise.then",
    "Promise.catch",
    "Promise.finally",
    "await",
];

fn subtract<K: PartialEq>(counts: &mut Counts<K>, key: K, by: u64) {
    if let Some(at) = counts.iter().position(|(k, _)| *k == key) {
        counts[at].1 -= by;
        if counts[at].1 == 0 {
            counts.swap_remove(at);
        }
    }
}

fn take_map(map: &mut BTreeMap<u64, u64>, key: u64, by: u64) {
    if let Some(count) = map.get_mut(&key) {
        *count -= by;
        if *count == 0 {
            map.remove(&key);
        }
    }
}

impl Graph {
    /// Forgets which node each frame shape resolved to, after identities a
    /// lookup missed have arrived.
    pub fn identities_arrived(&mut self) {
        self.frames.clear();
    }

    fn context(&mut self, at: Where, realm: u64) -> u32 {
        *self.context_index.entry((at, realm)).or_insert_with(|| {
            self.contexts.push(Context {
                process: at.0,
                isolate: at.1,
                realm,
                frames: BTreeMap::new(),
                tabs: BTreeMap::new(),
            });
            self.contexts.len() as u32 - 1
        })
    }

    /// The node for one frame. Combinator frames are labels on the await
    /// edge, never nodes.
    fn function(&mut self, scan: &Scan, at: Where, frame: &Frame, p: &mut Planning) -> u32 {
        let wasm = frame.kind == 2;
        let top_level = !wasm && frame.flags & 2 != 0;
        let function = if top_level { u32::MAX } else { frame.detail };
        let shape = (at, frame.script_id, function, wasm);
        let identity_key = (at.0, at.1, frame.script_id);
        if let Some(&(node, missing)) = self.frames.get(&shape) {
            if missing {
                p.missing.push(identity_key);
            }
            return node;
        }
        let identity = scan.identities.get(&identity_key).copied();
        if identity.is_none() {
            p.missing.push(identity_key);
        }
        let realm = identity.map_or(0, |identity| identity.realm);
        let code = match identity {
            Some(identity) if identity.sha != NO_SHA => Code::Sha(identity.sha),
            _ => Code::Script(frame.script_id),
        };
        let key = NodeKey {
            at,
            realm,
            code,
            wasm,
            function,
        };
        let node = match self.node_index.get(&key) {
            Some(&node) => node,
            None => {
                let context = self.context(at, realm);
                let kind = if wasm {
                    NodeKind::Wasm
                } else if identity.is_some_and(|identity| identity.eval) {
                    NodeKind::Eval
                } else {
                    NodeKind::Javascript
                };
                // Top-level code asks for no offset, yet its source's record
                // still says where it is.
                if let Some(identity) = identity.filter(|identity| identity.sha != NO_SHA) {
                    let wanted = self.wanted.entry(identity.sha).or_default();
                    wanted.wasm = wasm;
                    if !top_level {
                        wanted.names.push(frame.detail);
                        if !wasm {
                            wanted.positions.push(frame.detail);
                        }
                    }
                }
                let node = self.nodes.len() as u32;
                self.nodes.push(Node {
                    context,
                    kind,
                    function: Some(Function {
                        script_id: frame.script_id,
                        detail: frame.detail,
                        top_level,
                        code,
                        identity,
                    }),
                    sink: 0,
                    hits: 0,
                    stacks: 0,
                    entries: 0,
                    leaves: 0,
                    schedules: Vec::new(),
                    chain_cut: 0,
                    chain_ends: Vec::new(),
                });
                self.node_index.insert(key, node);
                node
            }
        };
        self.frames.insert(shape, (node, identity.is_none()));
        node
    }

    fn sink_node(&mut self, context: u32, sink: u32, scan: &Scan) -> u32 {
        *self.sink_nodes.entry((context, sink)).or_insert_with(|| {
            let kind = match scan.sinks.get(sink) {
                Sink::Request(_) => NodeKind::Request,
                Sink::Navigation(_) => NodeKind::Navigation,
                Sink::Cookie(_) => NodeKind::CookieWrite,
            };
            self.nodes.push(Node {
                context,
                kind,
                function: None,
                sink,
                hits: 0,
                stacks: 0,
                entries: 0,
                leaves: 0,
                schedules: Vec::new(),
                chain_cut: 0,
                chain_ends: Vec::new(),
            });
            self.nodes.len() as u32 - 1
        })
    }

    /// The call position inside the caller.
    fn site(&mut self, scan: &Scan, at: Where, caller: &Frame) -> Option<Site> {
        if caller.kind == 2 {
            return Some(Site {
                sha: NO_SHA,
                start_line: 0,
                start_column: 0,
                position: caller.position,
            });
        }
        let identity = scan.identities.get(&(at.0, at.1, caller.script_id))?;
        (identity.sha != NO_SHA).then_some(Site {
            sha: identity.sha,
            start_line: identity.start_line,
            start_column: identity.start_column,
            position: caller.position,
        })
    }

    /// What an edge between two nodes crosses: realms, languages, or into
    /// eval code from other code.
    fn crosses(&self, from: u32, to: u32) -> u8 {
        let (a, b) = (&self.nodes[from as usize], &self.nodes[to as usize]);
        let realm = |node: &Node| self.contexts[node.context as usize].realm;
        let mut crosses = 0;
        if a.context != b.context && realm(a) != 0 && realm(b) != 0 {
            crosses |= CROSSES_FRAME;
        }
        if let (Some(x), Some(y)) = (a.kind.language(), b.kind.language())
            && x != y
        {
            crosses |= CROSSES_LANGUAGE;
        }
        let same_code = match (&a.function, &b.function) {
            (Some(x), Some(y)) => {
                self.contexts[a.context as usize].process
                    == self.contexts[b.context as usize].process
                    && x.code == y.code
            }
            _ => false,
        };
        if b.kind == NodeKind::Eval && !(a.kind == NodeKind::Eval && same_code) {
            crosses |= CROSSES_DYNAMIC;
        }
        crosses
    }

    fn edge_of(&mut self, key: EdgeKey) -> u32 {
        if let Some(&edge) = self.edge_index.get(&key) {
            return edge;
        }
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
            sites: Vec::new(),
            via: 0,
            labels: 0,
            omitted: 0,
        });
        let edge = self.edges.len() as u32 - 1;
        self.edge_index.insert(key, edge);
        edge
    }

    /// One stack's use of an edge and what it says about it.
    fn edge(&mut self, key: EdgeKey, detail: Detail, p: &mut Planning) {
        let index = self.edge_of(key);
        p.path.push(index);
        let edge = &mut self.edges[index as usize];
        edge.via |= detail.via;
        edge.labels |= detail.labels;
        edge.omitted = edge.omitted.max(detail.omitted);
        if let Some(site) = detail.site
            && let Err(at) = edge.sites.binary_search(&site)
        {
            edge.sites.insert(at, site);
            if site.sha != NO_SHA {
                self.wanted
                    .entry(site.sha)
                    .or_default()
                    .positions
                    .push(site.position);
            }
        }
    }

    /// Call edges of one synchronous run, innermost first; returns its nodes.
    fn run(
        &mut self,
        scan: &Scan,
        at: Where,
        frames: &[Frame],
        omitted_after: Option<(usize, u32)>,
        p: &mut Planning,
    ) -> Vec<u32> {
        let nodes: Vec<u32> = frames
            .iter()
            .map(|frame| self.function(scan, at, frame, p))
            .collect();
        for (index, pair) in nodes.windows(2).enumerate() {
            let &[callee, caller] = pair else {
                continue;
            };
            let (kind, detail) = match omitted_after {
                Some((after, omitted)) if after == index => (
                    EdgeKind::Omitted,
                    Detail {
                        omitted,
                        ..Detail::default()
                    },
                ),
                _ => (
                    EdgeKind::Call,
                    Detail {
                        site: self.site(scan, at, &frames[index + 1]),
                        ..Detail::default()
                    },
                ),
            };
            self.edge((caller, callee, kind, 0), detail, p);
        }
        nodes
    }

    /// The plan of one decoded walk. Identities it looked for and did not
    /// find are added to `missing`.
    pub fn plan(
        &mut self,
        scan: &Scan,
        walk: &Walk,
        decoded: &Decoded,
        missing: &mut Vec<IdentityKey>,
    ) -> Plan {
        let mut p = Planning {
            at: (walk.process, walk.isolate),
            path: Vec::new(),
            missing,
        };
        // A stack deeper than 1,024 keeps the innermost and outermost 512.
        let omitted_after = (decoded.omitted != 0).then_some((511, decoded.omitted));
        let own = p.at;
        let sync = self.run(scan, own, &decoded.sync, omitted_after, &mut p);
        let innermost = sync.first().copied();
        let outermost = sync.last().copied();
        // A walk that stopped at 256 frames did not reach its task's first frame.
        let mut cut = outermost.filter(|_| decoded.retained && decoded.bounded);
        let first = self.await_chain(scan, &mut p, decoded, outermost, &mut cut);
        let mut end = None;
        let entry = self.task_chain(scan, &mut p, decoded, first, &mut cut, &mut end);
        let mut members = sync;
        for &edge in &p.path {
            let edge = &self.edges[edge as usize];
            members.push(edge.from);
            members.push(edge.to);
        }
        members.sort_unstable();
        members.dedup();
        let mut edges = p.path;
        edges.sort_unstable();
        edges.dedup();
        Plan {
            members: members.into(),
            edges: edges.into(),
            sinks: Vec::new(),
            innermost,
            entry,
            cut,
            end,
            reason: decoded.reason,
            segments_missing: decoded.segments_missing,
            retained: decoded.retained,
        }
    }

    /// The await chain, each async frame awaited by the next. Returns the
    /// frame that began this task: the last awaiter, else the outermost
    /// synchronous frame. None when it is not known, so no task edge enters a
    /// frame that was not its task's first.
    fn await_chain(
        &mut self,
        scan: &Scan,
        p: &mut Planning,
        decoded: &Decoded,
        outermost: Option<u32>,
        cut: &mut Option<u32>,
    ) -> Option<u32> {
        let mut first = outermost.filter(|_| decoded.retained && !decoded.bounded);
        let mut target = outermost;
        let mut label = 0;
        for frame in &decoded.asyncs {
            if frame.kind == 4 {
                label = combinator(frame);
                continue;
            }
            let at = p.at;
            let node = self.function(scan, at, frame, p);
            if let Some(to) = target {
                let detail = Detail {
                    site: self.site(scan, at, frame),
                    labels: std::mem::take(&mut label),
                    ..Detail::default()
                };
                self.edge((node, to, EdgeKind::Await, 0), detail, p);
            }
            target = Some(node);
            first = first.map(|_| node);
        }
        if decoded.asyncs_truncated {
            // The await chain continues past 32 frames: its first awaiter is unknown.
            *cut = cut.or(target);
            return None;
        }
        first
    }

    /// The task chain, nearest first: a segment's innermost frame scheduled
    /// the task whose first frame is the target, which starts as this task's
    /// first frame. Returns the first frame of the earliest task reached.
    fn task_chain(
        &mut self,
        scan: &Scan,
        p: &mut Planning,
        decoded: &Decoded,
        first: Option<u32>,
        cut_at: &mut Option<u32>,
        end: &mut Option<(u32, u8, u8)>,
    ) -> Option<u32> {
        let mut target = first;
        let mut via = 0u16;
        let mut cut = decoded.chain_cut || decoded.chain_truncated;
        for (segment, frames) in &decoded.segments {
            let Some(to) = target else {
                break;
            };
            match frames {
                Some((frames, at)) if !frames.is_empty() => {
                    let nodes = self.run(scan, *at, frames, None, p);
                    // A microtask's segment carries the stack that registered
                    // its reaction: the call is the label.
                    let detail = Detail {
                        site: self.site(scan, *at, &frames[0]),
                        via: std::mem::take(&mut via),
                        labels: if segment.kind == 9 {
                            registration(segment.registration)
                        } else {
                            0
                        },
                        ..Detail::default()
                    };
                    self.edge((nodes[0], to, EdgeKind::Task, segment.kind), detail, p);
                    let outer = *nodes.last().unwrap();
                    if segment.flags & 1 != 0 {
                        // The walk stopped at 256 frames: that task's first
                        // frame is not known.
                        *cut_at = cut_at.or(Some(outer));
                        return None;
                    }
                    target = Some(outer);
                }
                // A microtask hop that recorded no registration.
                _ if segment.kind == 9 && segment.state == 6 => via |= 1 << segment.kind,
                _ if segment.ends_chain() => {
                    // No script scheduled this task (the browser, the parser
                    // or a native callback queued it), or its message origin
                    // was rejected: the chain ends with that reason, uncut.
                    // After a frameless microtask hop the frames that
                    // registered the reaction are unknown, so it is a cut.
                    if via == 0 {
                        *end = Some((to, segment.state, segment.kind));
                    } else {
                        cut = true;
                    }
                    break;
                }
                _ => {
                    cut = true;
                    break;
                }
            }
        }
        if let Some(at) = target
            && (cut || via != 0)
        {
            *cut_at = cut_at.or(Some(at));
        }
        target
    }

    fn sink_edge(&mut self, innermost: u32, sink: u32, scan: &Scan) -> (u32, u32) {
        let context = self.nodes[innermost as usize].context;
        let node = self.sink_node(context, sink, scan);
        let kind = match scan.sinks.get(sink) {
            Sink::Request(_) => EdgeKind::Request,
            Sink::Navigation(_) => EdgeKind::Navigation,
            Sink::Cookie(_) => EdgeKind::CookieWrite,
        };
        (node, self.edge_of((innermost, node, kind, 0)))
    }

    /// Adds a walk's whole counts along its plan, and the sinks it reached.
    pub fn attach(&mut self, plan: &mut Plan, walk: &Walk, scan: &Scan) {
        let weight = walk.occurrences;
        for &node in &plan.members {
            let node = &mut self.nodes[node as usize];
            node.hits += weight;
            node.stacks += 1;
        }
        for &edge in &plan.edges {
            let edge = &mut self.edges[edge as usize];
            edge.count += weight;
            edge.stacks += 1;
        }
        if let Some(innermost) = plan.innermost {
            self.nodes[innermost as usize].leaves += weight;
            for &(task, count) in &walk.schedules {
                add(&mut self.nodes[innermost as usize].schedules, task, count);
            }
            let context = &mut self.contexts[self.nodes[innermost as usize].context as usize];
            for &(frame, count) in &walk.frames {
                *context.frames.entry(frame).or_default() += count;
            }
            for &(tab, count) in &walk.tabs {
                *context.tabs.entry(tab).or_default() += count;
            }
            for &(sink, count) in &walk.sinks {
                let (node, edge) = self.sink_edge(innermost, sink, scan);
                let edge_at = &mut self.edges[edge as usize];
                edge_at.count += count;
                edge_at.stacks += 1;
                self.nodes[node as usize].hits += count;
                self.nodes[node as usize].stacks += 1;
                plan.sinks.push((sink, node, edge));
            }
        }
        if let Some(entry) = plan.entry {
            self.nodes[entry as usize].entries += weight;
        }
        if let Some(cut) = plan.cut {
            self.nodes[cut as usize].chain_cut += 1;
        }
        if let Some((node, state, task)) = plan.end {
            add(
                &mut self.nodes[node as usize].chain_ends,
                (state, task),
                weight,
            );
        }
        if let Some(reason) = plan.reason {
            *self.unresolved.entry(reason).or_default() += 1;
        }
        if plan.segments_missing != 0 {
            *self.unresolved.entry("segment_not_retained").or_default() +=
                u64::from(plan.segments_missing);
        }
        self.decoded += u64::from(plan.retained);
        self.occurrences += weight;
        self.planned += 1;
    }

    /// Takes back everything `attach` and later `weigh` calls added for this
    /// walk, whose counts are now its whole counts.
    pub fn detach(&mut self, plan: &Plan, walk: &Walk) {
        let weight = walk.occurrences;
        for &node in &plan.members {
            let node = &mut self.nodes[node as usize];
            node.hits -= weight;
            node.stacks -= 1;
        }
        for &edge in &plan.edges {
            let edge = &mut self.edges[edge as usize];
            edge.count -= weight;
            edge.stacks -= 1;
        }
        if let Some(innermost) = plan.innermost {
            self.nodes[innermost as usize].leaves -= weight;
            for &(task, count) in &walk.schedules {
                subtract(&mut self.nodes[innermost as usize].schedules, task, count);
            }
            let context = &mut self.contexts[self.nodes[innermost as usize].context as usize];
            for &(frame, count) in &walk.frames {
                take_map(&mut context.frames, frame, count);
            }
            for &(tab, count) in &walk.tabs {
                take_map(&mut context.tabs, tab, count);
            }
            for &(sink, node, edge) in &plan.sinks {
                let count = walk
                    .sinks
                    .iter()
                    .find(|(s, _)| *s == sink)
                    .map_or(0, |(_, count)| *count);
                let edge = &mut self.edges[edge as usize];
                edge.count -= count;
                edge.stacks -= 1;
                self.nodes[node as usize].hits -= count;
                self.nodes[node as usize].stacks -= 1;
            }
        }
        if let Some(entry) = plan.entry {
            self.nodes[entry as usize].entries -= weight;
        }
        if let Some(cut) = plan.cut {
            self.nodes[cut as usize].chain_cut -= 1;
        }
        if let Some((node, state, task)) = plan.end {
            subtract(
                &mut self.nodes[node as usize].chain_ends,
                (state, task),
                weight,
            );
        }
        if let Some(reason) = plan.reason
            && let Some(count) = self.unresolved.get_mut(reason)
        {
            *count -= 1;
            if *count == 0 {
                self.unresolved.remove(reason);
            }
        }
        if plan.segments_missing != 0
            && let Some(count) = self.unresolved.get_mut("segment_not_retained")
        {
            *count -= u64::from(plan.segments_missing);
            if *count == 0 {
                self.unresolved.remove("segment_not_retained");
            }
        }
        self.decoded -= u64::from(plan.retained);
        self.occurrences -= weight;
        self.planned -= 1;
    }

    /// Adds what a walk's records added since its plan last took its counts.
    pub fn weigh(&mut self, plan: &mut Plan, delta: &Delta, scan: &Scan) {
        let weight = delta.occurrences;
        for &node in &plan.members {
            self.nodes[node as usize].hits += weight;
        }
        for &edge in &plan.edges {
            self.edges[edge as usize].count += weight;
        }
        if let Some(innermost) = plan.innermost {
            self.nodes[innermost as usize].leaves += weight;
            for &(task, count) in &delta.schedules {
                add(&mut self.nodes[innermost as usize].schedules, task, count);
            }
            let context = &mut self.contexts[self.nodes[innermost as usize].context as usize];
            for &(frame, count) in &delta.frames {
                *context.frames.entry(frame).or_default() += count;
            }
            for &(tab, count) in &delta.tabs {
                *context.tabs.entry(tab).or_default() += count;
            }
            for &(sink, count) in &delta.sinks {
                let (node, edge) = match plan.sinks.iter().find(|(s, _, _)| *s == sink) {
                    Some(&(_, node, edge)) => (node, edge),
                    None => {
                        let (node, edge) = self.sink_edge(innermost, sink, scan);
                        self.edges[edge as usize].stacks += 1;
                        self.nodes[node as usize].stacks += 1;
                        plan.sinks.push((sink, node, edge));
                        (node, edge)
                    }
                };
                self.edges[edge as usize].count += count;
                self.nodes[node as usize].hits += count;
            }
        }
        if let Some(entry) = plan.entry {
            self.nodes[entry as usize].entries += weight;
        }
        if let Some((node, state, task)) = plan.end {
            add(
                &mut self.nodes[node as usize].chain_ends,
                (state, task),
                weight,
            );
        }
        self.occurrences += weight;
    }
}
