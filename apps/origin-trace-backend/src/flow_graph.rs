//! One session's flow graph (protocol/flow-graph-v2.md): every walked stack the
//! store holds, folded into one graph of functions grouped by realm.
//!
//! Request, navigation and async-task scheduling stacks, and the walked stacks
//! of script cookie writes, name their frames by digest. Two adjacent
//! synchronous frames are a call edge. A change of realm between them is a
//! frame boundary (a same-process iframe), a change between JavaScript and
//! Wasm a language boundary, and a call into an `eval` or `new Function`
//! script a dynamic one. Task segments link the stack that scheduled a task to
//! that task's first frame, so a `postMessage` into an iframe is one edge
//! between realms. Nothing is inferred: a frame without a resolvable identity
//! stays a node with a reason, and a cut chain or an omitted run is reported,
//! never bridged.
//!
//! The fold is kept per session and only ever moves forward. The event index
//! names the session's records (`event_index::Indexes::flow_rows`), so a
//! refresh reads only the records appended since the last one, of this
//! session alone. Each distinct stack is decoded once, when it first appears;
//! a stack seen again adds its weight along the plan it already has
//! (`build`). Stack, script and module artifacts are found by SHA-256 in the
//! artifact lookup and read in parallel, every read verified. Each source is
//! read again only when frames ask it for offsets it has not resolved. One
//! build runs per session at a time; a request that arrives during one waits
//! for it and answers from its result.
mod answer;
mod build;
mod records;
#[cfg(test)]
mod tests;

use crate::{
    artifact_lookup::{self, Content},
    error::{Error, Result},
    event_index::Indexes,
    evidence::Blobs,
    request_stack,
    wasm_names::Names,
};
use axum::body::Bytes;
use build::{Graph, Plan, SegmentRead};
use records::{IdentityKey, Scan, Shape};
use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub const SCHEMA: &str = "flow-graph-v2";
pub const PATHS_SCHEMA: &str = "flow-graph-paths-v1";
const CANCELLED: &str = "The flow graph request was cancelled";
/// The record types the flow graph folds; the event index marks them so a
/// session's are read without its other records.
pub(crate) const TYPES: [&str; 6] = [
    "request_initiator_stack",
    "navigation_initiator_stack",
    "async_task_stack",
    "script_cookie",
    "script_identity",
    "request_initiated",
];
/// Index rows read at a time; a batch is folded, decoded and planned before
/// the next is read, so a cancelled build keeps what it finished.
const BATCH_ROWS: usize = 1 << 16;
/// How long a request lets the event and artifact indexes catch up before it
/// reads them; the background indexer keeps them within a second of the
/// stores.
const INDEX_SLICE: Duration = Duration::from_millis(100);
/// How long one request folds before it answers with what it has. This cuts
/// nothing: the answer says how far it reached (`coverage.caught_up`), the
/// fold keeps its place, and the next request goes on from there.
const PROGRESS: Duration = Duration::from_secs(10);
/// Sessions whose fold is kept between requests. A session dropped from this
/// cache is folded again from its first record when it is next asked for.
const SESSIONS: usize = 4;

pub(crate) type FxMap<K, V> = HashMap<K, V, foldhash::fast::RandomState>;
pub(crate) type FxSet<K> = std::collections::HashSet<K, foldhash::fast::RandomState>;

/// Values interned as dense IDs, in first-seen order.
pub(crate) struct Interner<K> {
    items: Vec<K>,
    index: FxMap<K, u32>,
}

impl<K> Default for Interner<K> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            index: FxMap::default(),
        }
    }
}

impl<K: Clone + Eq + Hash> Interner<K> {
    pub fn intern(&mut self, key: K) -> u32 {
        if let Some(&id) = self.index.get(&key) {
            return id;
        }
        let id = self.items.len() as u32;
        self.items.push(key.clone());
        self.index.insert(key, id);
        id
    }
    pub fn find<Q: ?Sized + Hash + Eq>(&self, key: &Q) -> Option<u32>
    where
        K: Borrow<Q>,
    {
        self.index.get(key).copied()
    }
    pub fn get(&self, id: u32) -> &K {
        &self.items[id as usize]
    }
}

/// The stores a fold reads.
#[derive(Clone)]
pub struct Inputs {
    pub store: PathBuf,
    pub artifacts: PathBuf,
    pub indexes: Arc<Mutex<Indexes>>,
}

/// Every kept session's fold. Each session has its own lock, so builds of
/// two sessions run side by side and two requests for one share its build.
#[derive(Default)]
pub struct Graphs {
    sessions: Mutex<Vec<(u64, Slot)>>,
}

/// One session's fold, None until it is first asked for or after a reset.
type Slot = Arc<Mutex<Option<State>>>;

impl Graphs {
    fn slot(&self, session: u64) -> Slot {
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(at) = sessions.iter().position(|(id, _)| *id == session) {
            let entry = sessions.remove(at);
            let slot = entry.1.clone();
            sessions.push(entry);
            return slot;
        }
        let slot = Arc::new(Mutex::new(None));
        sessions.push((session, slot.clone()));
        if sessions.len() > SESSIONS {
            sessions.remove(0);
        }
        slot
    }
}

/// Generations are unique in this process and across its restarts, so a
/// client never mistakes another build's node and edge IDs for its own.
fn next_generation() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    static BOOT: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_micros() as u64)
    });
    format!("{:x}-{}", *BOOT, NEXT.fetch_add(1, Ordering::Relaxed))
}

/// A retained script or module's manifest record, and what its bytes resolved.
#[derive(Default)]
pub(crate) struct Source {
    /// From the artifact lookup, once it holds the digest.
    row: Option<SourceRow>,
    /// The manifest bytes the lookup covered when it last missed the digest.
    missed_at: Option<u64>,
    wasm: bool,
    /// Offsets asked for: positions of functions and call sites, and the
    /// function starts whose names are read.
    positions: FxSet<u32>,
    names_asked: FxSet<u32>,
    /// Offsets asked for since the bytes were last read.
    stale: bool,
    lines: FxMap<u32, (u64, u64)>,
    names: FxMap<u32, Box<str>>,
    reason: Option<&'static str>,
}

struct SourceRow {
    artifact_id: String,
    url: String,
    byte_size: u64,
}

/// One session's fold.
pub(crate) struct State {
    session: u64,
    events_epoch: String,
    artifacts_epoch: Option<String>,
    /// Records starting before this have been folded.
    folded_to: u64,
    /// Where the event index stood when the session's records last ran out:
    /// every record of the session before it is folded.
    covered_to: u64,
    store_end: u64,
    caught_up: bool,
    store_damage: Option<String>,
    scan: Scan,
    graph: Graph,
    plans: Vec<Option<Plan>>,
    /// Walks to plan, first or again.
    queue: Vec<u32>,
    queued: Vec<bool>,
    /// Stack artifact sizes by digest, from the artifact lookup.
    stacks: FxMap<[u8; 32], u64>,
    /// Scheduling stacks read, by digest and depth.
    segments: FxMap<([u8; 32], u32), SegmentRead>,
    /// Stack digests the lookup did not hold, and the walks waiting on each.
    missing_stacks: FxMap<[u8; 32], Vec<u32>>,
    /// Identities a plan looked for and did not find, and the walks waiting.
    waiting: FxMap<IdentityKey, Vec<u32>>,
    sources: FxMap<u32, Source>,
    /// Manifest bytes the lookup covered when the missing digests were last
    /// asked for again.
    artifacts_indexed_to: u64,
    artifacts_caught_up: bool,
    generation: String,
    changed: bool,
    body: Option<answer::Body>,
}

impl State {
    fn new(session: u64) -> Self {
        Self {
            session,
            events_epoch: String::new(),
            artifacts_epoch: None,
            folded_to: 0,
            covered_to: 0,
            store_end: 0,
            caught_up: false,
            store_damage: None,
            scan: Scan::default(),
            graph: Graph::default(),
            plans: Vec::new(),
            queue: Vec::new(),
            queued: Vec::new(),
            stacks: FxMap::default(),
            segments: FxMap::default(),
            missing_stacks: FxMap::default(),
            waiting: FxMap::default(),
            sources: FxMap::default(),
            artifacts_indexed_to: 0,
            artifacts_caught_up: true,
            generation: next_generation(),
            changed: false,
            body: None,
        }
    }

    fn enqueue(&mut self, walk: u32) {
        let at = walk as usize;
        if self.queued.len() <= at {
            self.queued.resize(at + 1, false);
            self.plans.resize_with(at + 1, || None);
        }
        if !self.queued[at] {
            self.queued[at] = true;
            self.queue.push(walk);
        }
    }

    /// Folds what the stores gained since the last refresh, for at most
    /// `PROGRESS` of reading, and resolves every source offset the graph
    /// asks for. Returns false when the stores were replaced, so the fold
    /// must start again.
    fn refresh(&mut self, inputs: &Inputs, cancel: &AtomicBool) -> Result<bool> {
        let started = Instant::now();
        let blobs = Blobs::open(&inputs.artifacts)?;
        let probe = artifact_lookup::by_digest(
            &inputs.artifacts,
            self.session,
            Content::Stack,
            &[],
            Instant::now() + INDEX_SLICE,
        )?;
        match &self.artifacts_epoch {
            Some(epoch) if *epoch != probe.epoch => return Ok(false),
            _ => self.artifacts_epoch = Some(probe.epoch.clone()),
        }
        self.artifacts_caught_up = probe.caught_up;
        let mut store = None;
        let mut first = true;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::new(499, CANCELLED));
            }
            let deadline = if first {
                Instant::now() + INDEX_SLICE
            } else {
                Instant::now()
            };
            first = false;
            let rows = inputs
                .indexes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .flow_rows(self.session, self.folded_to, BATCH_ROWS, deadline)?;
            let Some(rows) = rows else {
                self.caught_up = true;
                break;
            };
            if self.events_epoch.is_empty() {
                self.events_epoch = rows.position.epoch.clone();
            } else if self.events_epoch != rows.position.epoch {
                return Ok(false);
            }
            self.store_damage = rows.damage.map(|error| error.message);
            self.store_end = rows.position.file_end;
            if let Some(&(_, end)) = rows.rows.last() {
                let file = match &mut store {
                    Some(file) => file,
                    None => store.insert(crate::evidence::regular_file(&inputs.store)?),
                };
                read_rows(file, &rows.rows, |line| {
                    self.scan.line(line, self.session);
                })?;
                self.folded_to = end;
                self.apply(inputs, blobs.as_ref(), cancel)?;
            }
            if rows.rows.len() < BATCH_ROWS {
                self.covered_to = rows.position.indexed_to;
                self.caught_up = rows.position.caught_up(crate::event_index::RECORD_BYTES as u64);
                break;
            }
            if started.elapsed() >= PROGRESS {
                self.caught_up = false;
                break;
            }
        }
        // Artifacts the lookup did not hold may have arrived since.
        if probe.indexed_to > self.artifacts_indexed_to {
            self.artifacts_indexed_to = probe.indexed_to;
            self.missing_arrived(inputs)?;
        }
        self.apply(inputs, blobs.as_ref(), cancel)?;
        self.resolve_sources(inputs, blobs.as_ref(), cancel)?;
        Ok(true)
    }

    /// Asks the artifact lookup again for every stack digest it did not hold,
    /// and plans again the walks that waited on one it holds now.
    fn missing_arrived(&mut self, inputs: &Inputs) -> Result<()> {
        if self.missing_stacks.is_empty() {
            return Ok(());
        }
        let digests: Vec<[u8; 32]> = self.missing_stacks.keys().copied().collect();
        let found = artifact_lookup::by_digest(
            &inputs.artifacts,
            self.session,
            Content::Stack,
            &digests,
            Instant::now(),
        )?;
        for (digest, row) in found.found {
            self.stacks
                .insert(digest, row["byte_size"].as_u64().unwrap_or(0));
            for walk in self.missing_stacks.remove(&digest).unwrap_or_default() {
                self.enqueue(walk);
            }
        }
        Ok(())
    }

    /// The sizes of stack artifacts the lookup holds, asked for once each.
    fn stack_sizes(&mut self, inputs: &Inputs, digests: Vec<[u8; 32]>) -> Result<()> {
        let unknown: Vec<[u8; 32]> = digests
            .into_iter()
            .filter(|digest| {
                !self.stacks.contains_key(digest) && !self.missing_stacks.contains_key(digest)
            })
            .collect::<FxSet<_>>()
            .into_iter()
            .collect();
        if unknown.is_empty() {
            return Ok(());
        }
        let found = artifact_lookup::by_digest(
            &inputs.artifacts,
            self.session,
            Content::Stack,
            &unknown,
            Instant::now(),
        )?;
        for (digest, row) in found.found {
            self.stacks
                .insert(digest, row["byte_size"].as_u64().unwrap_or(0));
        }
        Ok(())
    }

    /// Plans every queued walk and adds what touched walks gained. Walks are
    /// decoded in chunks: their artifacts and the scheduling stacks they
    /// name are read in parallel, then planned in order.
    fn apply(&mut self, inputs: &Inputs, blobs: Option<&Blobs>, cancel: &AtomicBool) -> Result<()> {
        for walk in std::mem::take(&mut self.scan.new_walks) {
            self.enqueue(walk);
        }
        for walk in std::mem::take(&mut self.scan.changed_walks) {
            self.enqueue(walk);
        }
        if std::mem::take(&mut self.scan.identity_changed) {
            // An identity a plan already used changed: every plan may name
            // other nodes now, so the graph is planned again from the walks.
            self.graph = Graph::default();
            self.waiting.clear();
            self.scan.arrived.clear();
            for plan in &mut self.plans {
                *plan = None;
            }
            for walk in &mut self.scan.walks {
                walk.pending = None;
            }
            self.scan.touched.clear();
            for walk in 0..self.scan.walks.len() as u32 {
                self.enqueue(walk);
            }
            self.changed = true;
        } else {
            let arrived = std::mem::take(&mut self.scan.arrived);
            let mut any = false;
            for key in arrived {
                if let Some(walks) = self.waiting.remove(&key) {
                    any = true;
                    for walk in walks {
                        self.enqueue(walk);
                    }
                }
            }
            if any {
                self.graph.identities_arrived();
            }
        }
        const CHUNK: usize = 1 << 14;
        while !self.queue.is_empty() {
            let take = self.queue.len().min(CHUNK);
            let chunk: Vec<u32> = self.queue.drain(..take).collect();
            self.plan_chunk(inputs, blobs, &chunk, cancel)?;
        }
        for walk in std::mem::take(&mut self.scan.touched) {
            let walk = walk as usize;
            let Some(delta) = self.scan.walks[walk].pending.take() else {
                continue;
            };
            if let Some(plan) = self.plans.get_mut(walk).and_then(Option::as_mut) {
                self.graph.weigh(plan, &delta, &self.scan);
                self.changed = true;
            }
        }
        Ok(())
    }

    fn plan_chunk(
        &mut self,
        inputs: &Inputs,
        blobs: Option<&Blobs>,
        chunk: &[u32],
        cancel: &AtomicBool,
    ) -> Result<()> {
        let digests = chunk
            .iter()
            .map(|&walk| self.scan.walks[walk as usize].digest)
            .collect();
        self.stack_sizes(inputs, digests)?;
        // A scheduling stack is read as a segment, once per digest and depth,
        // so one that is also a segment of other chains is decoded once.
        let scheduling = chunk
            .iter()
            .filter_map(|&walk| {
                let walk = &self.scan.walks[walk as usize];
                match walk.shape {
                    Shape::Scheduling(recorded) => Some((walk.digest, recorded)),
                    _ => None,
                }
            })
            .collect();
        self.read_segments(blobs, scheduling, chunk, cancel)?;
        let (stacks, walks) = (&self.stacks, &self.scan.walks);
        let mains: Vec<_> = match blobs {
            Some(blobs) => blobs.read_all(
                chunk,
                |walk| {
                    let walk = &walks[*walk as usize];
                    if matches!(walk.shape, Shape::Scheduling(_)) {
                        return None;
                    }
                    stacks
                        .get(&walk.digest)
                        .map(|size| (walk.digest, *size, request_stack::MAX_ARTIFACT))
                },
                |walk, content| build::decode_main(&walks[*walk as usize], content.ok()),
                cancel,
            ),
            None => std::iter::repeat_with(|| None).take(chunk.len()).collect(),
        };
        if cancel.load(Ordering::Relaxed) {
            self.queue.extend_from_slice(chunk);
            return Err(Error::new(499, CANCELLED));
        }
        let segments = &self.segments;
        let mains: Vec<_> = chunk
            .iter()
            .zip(mains)
            .map(|(&walk, main)| {
                let walk = &walks[walk as usize];
                match walk.shape {
                    Shape::Scheduling(recorded) => {
                        build::scheduling_main(recorded, segments.get(&(walk.digest, recorded)))
                    }
                    _ => main.unwrap_or_else(|| build::decode_main(walk, None)),
                }
            })
            .collect();
        // Task segments can name scheduling stacks that no record here
        // describes.
        let named: Vec<([u8; 32], u32)> = mains
            .iter()
            .flatten()
            .flat_map(|(_, _, _, _, segments)| segments.iter())
            .filter(|segment| segment.state == 1)
            .map(|segment| (segment.digest, segment.recorded))
            .collect();
        self.stack_sizes(inputs, named.iter().map(|(digest, _)| *digest).collect())?;
        self.read_segments(blobs, named, chunk, cancel)?;
        for (at, (&walk, main)) in chunk.iter().zip(mains).enumerate() {
            if at % 1024 == 0 && cancel.load(Ordering::Relaxed) {
                self.queue.extend_from_slice(&chunk[at..]);
                return Err(Error::new(499, CANCELLED));
            }
            let index = walk as usize;
            let digest = self.scan.walks[index].digest;
            let missing_stack = main.is_err() && !self.stacks.contains_key(&digest);
            let segment_digests: Vec<[u8; 32]> = main
                .as_ref()
                .map(|(_, _, _, _, segments)| {
                    segments
                        .iter()
                        .filter(|segment| {
                            segment.state == 1 && !self.stacks.contains_key(&segment.digest)
                        })
                        .map(|segment| segment.digest)
                        .collect()
                })
                .unwrap_or_default();
            let decoded = build::decode(&self.scan.walks[index], main, &self.segments);
            if let Some(mut old) = self.plans[index].take() {
                if let Some(delta) = self.scan.walks[index].pending.take() {
                    self.graph.weigh(&mut old, &delta, &self.scan);
                }
                self.graph.detach(&old, &self.scan.walks[index]);
            }
            self.scan.walks[index].pending = None;
            let mut missing = Vec::new();
            let mut plan =
                self.graph
                    .plan(&self.scan, &self.scan.walks[index], &decoded, &mut missing);
            self.graph
                .attach(&mut plan, &self.scan.walks[index], &self.scan);
            self.plans[index] = Some(plan);
            self.queued[index] = false;
            self.changed = true;
            missing.sort_unstable();
            missing.dedup();
            for key in missing {
                self.waiting.entry(key).or_default().push(walk);
            }
            if missing_stack {
                self.missing_stacks.entry(digest).or_default().push(walk);
            }
            for digest in segment_digests {
                self.missing_stacks.entry(digest).or_default().push(walk);
            }
        }
        Ok(())
    }

    /// Reads the scheduling stacks not read yet whose artifacts the lookup
    /// holds, in parallel, keeping each by digest and depth: stacks are
    /// immutable, so a stack planned again reads none of them again.
    fn read_segments(
        &mut self,
        blobs: Option<&Blobs>,
        keys: Vec<([u8; 32], u32)>,
        chunk: &[u32],
        cancel: &AtomicBool,
    ) -> Result<()> {
        let Some(blobs) = blobs else {
            return Ok(());
        };
        let keys: Vec<([u8; 32], u32)> = keys
            .into_iter()
            .filter(|key| !self.segments.contains_key(key) && self.stacks.contains_key(&key.0))
            .collect::<FxSet<_>>()
            .into_iter()
            .collect();
        let stacks = &self.stacks;
        let read = blobs.read_all(
            &keys,
            |(digest, _)| {
                stacks
                    .get(digest)
                    .map(|size| (*digest, *size, request_stack::MAX_ARTIFACT))
            },
            |(_, recorded), content| build::read_segment(content, *recorded),
            cancel,
        );
        for (key, read) in keys.into_iter().zip(read) {
            if let Some(read) = read {
                self.segments.insert(key, read);
            }
        }
        if cancel.load(Ordering::Relaxed) {
            self.queue.extend_from_slice(chunk);
            return Err(Error::new(499, CANCELLED));
        }
        Ok(())
    }

    /// Reads every source frames asked for offsets it has not resolved, once,
    /// and resolves all its asked offsets in one pass.
    fn resolve_sources(
        &mut self,
        inputs: &Inputs,
        blobs: Option<&Blobs>,
        cancel: &AtomicBool,
    ) -> Result<()> {
        for (sha, wanted) in std::mem::take(&mut self.graph.wanted) {
            let source = self.sources.entry(sha).or_default();
            source.wasm = wanted.wasm;
            for offset in wanted.positions {
                source.stale |= source.positions.insert(offset);
            }
            for offset in wanted.names {
                source.stale |= source.names_asked.insert(offset);
            }
        }
        // Rows the lookup did not hold when last asked, asked again once it
        // has grown.
        let lookup: Vec<u32> = self
            .sources
            .iter()
            .filter(|(_, source)| {
                source.row.is_none()
                    && source
                        .missed_at
                        .is_none_or(|at| at < self.artifacts_indexed_to)
            })
            .map(|(sha, _)| *sha)
            .collect();
        if !lookup.is_empty() {
            let digests: Vec<[u8; 32]> =
                lookup.iter().map(|sha| *self.scan.shas.get(*sha)).collect();
            let found = artifact_lookup::by_digest(
                &inputs.artifacts,
                self.session,
                Content::Source,
                &digests,
                Instant::now(),
            )?;
            let mut rows: FxMap<[u8; 32], serde_json::Value> = found.found.into_iter().collect();
            for sha in lookup {
                let source = self.sources.get_mut(&sha).unwrap();
                match rows.remove(self.scan.shas.get(sha)) {
                    Some(row) => {
                        source.row = Some(SourceRow {
                            artifact_id: row["artifact_id"].as_str().unwrap_or("").to_owned(),
                            url: row["url"].as_str().unwrap_or("").to_owned(),
                            byte_size: row["byte_size"].as_u64().unwrap_or(0),
                        });
                        source.stale = true;
                        self.changed = true;
                    }
                    None => source.missed_at = Some(found.indexed_to),
                }
            }
        }
        let stale: Vec<u32> = self
            .sources
            .iter()
            .filter(|(_, source)| source.stale && source.row.is_some())
            .map(|(sha, _)| *sha)
            .collect();
        let Some(blobs) = blobs else {
            return Ok(());
        };
        let shas = &self.scan.shas;
        let sources = &self.sources;
        let resolved = blobs.read_all(
            &stale,
            |sha| {
                sources[sha]
                    .row
                    .as_ref()
                    .map(|row| (*shas.get(*sha), row.byte_size, request_stack::MAX_SOURCE))
            },
            |sha, bytes| resolve(&sources[sha], bytes),
            cancel,
        );
        for (sha, resolved) in stale.into_iter().zip(resolved) {
            let Some((lines, names, reason)) = resolved else {
                continue;
            };
            let source = self.sources.get_mut(&sha).unwrap();
            (source.lines, source.names, source.reason) = (lines, names, reason);
            source.stale = false;
            self.changed = true;
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::new(499, CANCELLED));
        }
        Ok(())
    }
}

type Resolved = (
    FxMap<u32, (u64, u64)>,
    FxMap<u32, Box<str>>,
    Option<&'static str>,
);

/// Positions and names for every offset asked of one script or module.
fn resolve(source: &Source, bytes: Result<&[u8]>) -> Resolved {
    let (mut lines, mut names) = (FxMap::default(), FxMap::default());
    let Ok(bytes) = bytes else {
        return (lines, names, Some("source_artifact_unreadable"));
    };
    if source.wasm {
        for (index, name) in request_stack::wasm_names(bytes) {
            if source.names_asked.contains(&index) {
                names.insert(index, name.into_boxed_str());
            }
        }
        return (lines, names, None);
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return (lines, names, Some("source_not_utf8"));
    };
    let offsets: std::collections::BTreeSet<u32> = source
        .positions
        .iter()
        .chain(&source.names_asked)
        .copied()
        .collect();
    for (offset, (byte, line, column)) in request_stack::positions(text, &offsets) {
        if source.positions.contains(&offset) {
            lines.insert(offset, (line, column));
        }
        if source.names_asked.contains(&offset)
            && let Some(name) = request_stack::function_name(text, byte)
        {
            names.insert(offset, name.into_boxed_str());
        }
    }
    (lines, names, None)
}

/// Reads index rows from the store, joining rows that lie close together into
/// one read, and hands each record line to `line`.
fn read_rows(
    file: &mut std::fs::File,
    rows: &[(u64, u64)],
    mut line: impl FnMut(&[u8]),
) -> Result<()> {
    /// Rows this close are read together, skipping what lies between them.
    const GAP: u64 = 64 * 1024;
    const SPAN: u64 = 8 * 1024 * 1024;
    let mut at = 0;
    while at < rows.len() {
        let start = rows[at].0;
        let mut last = at;
        while last + 1 < rows.len()
            && rows[last + 1].0.saturating_sub(rows[last].1) <= GAP
            && rows[last + 1].1 - start <= SPAN
        {
            last += 1;
        }
        let bytes = crate::index_db::read_range(file, start, rows[last].1)?;
        for &(row_start, row_end) in &rows[at..=last] {
            let record = &bytes[(row_start - start) as usize..(row_end - start) as usize];
            line(record.trim_ascii_end());
        }
        at = last + 1;
    }
    Ok(())
}

/// Brings the session's fold up to the stores, starting it again when the
/// stores were replaced, and runs `then` on it.
fn with_state<T>(
    graphs: &Graphs,
    inputs: &Inputs,
    session: u64,
    cancel: &AtomicBool,
    refresh: bool,
    then: impl FnOnce(&mut State) -> Result<T>,
) -> Result<T> {
    let slot = graphs.slot(session);
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() || refresh {
        loop {
            let state = guard.get_or_insert_with(|| State::new(session));
            if state.refresh(inputs, cancel)? {
                break;
            }
            *guard = None;
        }
        let state = guard.as_mut().unwrap();
        if std::mem::take(&mut state.changed) {
            state.generation = next_generation();
            state.body = None;
        }
    }
    then(guard.as_mut().unwrap())
}

/// Nodes and edges a graph page holds unless it asks for another number. A
/// page is a run of slices of the generation's encoding, so any number is
/// cheap to send; the default keeps one answer to a few megabytes.
pub const GRAPH_PAGE: usize = 1 << 16;

/// Which graph a request reads and which page of it: the generation an
/// earlier answer named, or None for the graph folded up to the stores; the
/// first item; and how many items the page holds.
pub struct Page<'a> {
    pub generation: Option<&'a str>,
    pub cursor: u32,
    pub limit: usize,
}

/// One page of the session's flow graph as JSON. A request without a
/// generation folds up to the stores first and answers the first page it
/// asks for; a request that names the generation an earlier page came from
/// answers from that fold without moving it, so a client pages through one
/// graph while the stores grow, or is told that graph is gone.
pub fn graph(
    graphs: &Graphs,
    inputs: &Inputs,
    session: u64,
    page: Page,
    cancel: &AtomicBool,
    names: &Arc<Names>,
) -> Result<Vec<Bytes>> {
    let started = Instant::now();
    let refresh = page.generation.is_none();
    with_state(graphs, inputs, session, cancel, refresh, |state| {
        same_generation(state, page.generation)?;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        answer::graph(state, names, elapsed_ms, page.cursor, page.limit)
    })
}

fn same_generation(state: &State, generation: Option<&str>) -> Result<()> {
    match generation {
        Some(generation) if generation != state.generation => Err(Error::new(
            409,
            "The flow graph changed since that answer; ask for the graph again",
        )),
        _ => Ok(()),
    }
}

/// Stacks a paths page lists unless it asks for another number, and at most.
pub const PATHS_PAGE: usize = 64;
pub const PATHS_PAGE_MAX: usize = 1024;

/// A stack digest as 64 lowercase hex digits.
pub fn digest(text: &str) -> Result<[u8; 32]> {
    use hex::FromHex;
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(Error::bad("digest must be 64 lowercase hex digits"));
    }
    <[u8; 32]>::from_hex(text).map_err(|_| Error::bad("digest must be 64 lowercase hex digits"))
}

/// Which stacks a paths request asks for.
pub enum PathQuery {
    Node(u32),
    Request {
        process: u32,
        request: u64,
    },
    Digest {
        digest: [u8; 32],
        process: Option<u32>,
    },
}

/// One page of the stacks that walk a node, made a request, or have a
/// digest, in the graph generation the client holds. A session never asked
/// for is folded first; a fold that moved on since the client's answer is a
/// conflict, so IDs never point into another graph.
pub fn paths(
    graphs: &Graphs,
    inputs: &Inputs,
    session: u64,
    page: Page,
    query: &PathQuery,
    cancel: &AtomicBool,
) -> Result<Bytes> {
    with_state(graphs, inputs, session, cancel, false, |state| {
        same_generation(state, page.generation)?;
        answer::paths(state, query, page.cursor as usize, page.limit)
    })
}
