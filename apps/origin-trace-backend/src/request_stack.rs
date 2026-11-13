//! Request and navigation initiator stacks (protocol/native-network-v3.md).
//! Decodes the stack record, its frames artifact, the async task segments it
//! names and the script identities, and resolves each frame only through
//! retained bytes: an unresolved frame keeps its raw identity and a reason.
use crate::{
    error::Result,
    event_query::{self, EventFilter},
    evidence,
    request_index::RequestIndex,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};
use tokio::sync::Mutex;

const SYNC_LIMIT: u32 = 1024;
const ASYNC_LIMIT: u32 = 32;
const TASK_LIMIT: u32 = 32;
const TASK_FRAME_LIMIT: u32 = 256;
const REGISTRATION_FRAME_LIMIT: u32 = 32;
const HEADER: usize = 32;
/// A version 3 stack artifact appends the scope to the header.
const SCOPED_HEADER: usize = 48;
const FRAME: usize = 16;
const SEGMENT: usize = 48;
pub(crate) const MAX_ARTIFACT: usize =
    SCOPED_HEADER + FRAME * (SYNC_LIMIT + ASYNC_LIMIT) as usize + SEGMENT * TASK_LIMIT as usize;
pub(crate) const MAX_SOURCE: usize = 16 * 1024 * 1024;
const IDENTITY_SCAN: usize = 4096;
/// Version 1 records captured no task-attributed callers.
const ASYNC_NOT_SHOWN_V1: [&str; 4] = [
    "timers",
    "event listeners",
    "promise.then callbacks",
    "message handlers",
];
/// Version 2 records predate message origins.
const ASYNC_NOT_SHOWN_V2: [&str; 1] = ["MessagePort and worker messages"];
/// Version 3: callers no record carries, stated with every version 3 stack.
const ASYNC_NOT_SHOWN: [&str; 5] = [
    "ServiceWorker.postMessage and Client.postMessage",
    "window.postMessage to or from another process",
    "MessagePort.postMessage from a worklet, which has no stack tables",
    "the task a promise reaction in a worker continues: Blink tracks task attribution only on the \
     document main thread",
    "promise reactions a builtin registered (Promise.all, race, any, allSettled and the like): V8 \
     tags them for neither DevTools nor REB",
];

/// The isolate a stack's script IDs belong to: script IDs are unique only
/// within one isolate. Version 1 and 2 stacks are the document main thread's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Scope {
    pub(crate) thread: u8,
    pub(crate) isolate_key: u64,
}

impl Scope {
    pub const DOCUMENT: Self = Self {
        thread: 1,
        isolate_key: 0,
    };
    /// A `script_cookie` record's isolate: version 2 byte 6 and, for a worker,
    /// the record's frame_id, which is the worker's context ID. None when the
    /// thread was not named, so no frame of it can be read.
    pub fn of_cookie(thread: u8, frame_id: u64) -> Option<Self> {
        match thread {
            1 => Some(Self::DOCUMENT),
            2..=4 if frame_id != 0 => Some(Self {
                thread,
                isolate_key: frame_id,
            }),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        self.thread_name()
    }
    /// A request index row's thread and isolate key; a pre-scope row is the document's.
    fn of_row(thread: u64, isolate_key: u64) -> Self {
        match u8::try_from(thread) {
            Ok(thread @ 2..=4) if isolate_key != 0 => Self {
                thread,
                isolate_key,
            },
            _ => Self::DOCUMENT,
        }
    }
    /// A 16-byte stack scope: thread 1 to 4, zero reserved, key zero only for 1.
    pub(crate) fn read(bytes: &[u8]) -> Option<Self> {
        let scope = Self {
            thread: bytes[0],
            isolate_key: u64_at(bytes, 8),
        };
        let valid = bytes[1..8].iter().all(|b| *b == 0)
            && if scope.thread == 1 {
                scope.isolate_key == 0
            } else {
                (2..=4).contains(&scope.thread) && scope.isolate_key != 0
            };
        valid.then_some(scope)
    }
    fn thread_name(self) -> &'static str {
        match self.thread {
            1 => "document",
            2 => "dedicated_worker",
            3 => "shared_worker",
            _ => "service_worker",
        }
    }
    fn to_json(self) -> Value {
        json!({"thread": self.thread_name(),
            "isolate_key": (self.isolate_key != 0).then(|| format!("{:016x}", self.isolate_key))})
    }
}

/// Where a frame's script ID is read: renderer OS process and isolate.
pub(crate) type ScriptScope = (u32, Scope);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub(crate) kind: u8,
    pub(crate) flags: u8,
    pub(crate) combinator: u16,
    pub(crate) script_id: u32,
    pub(crate) position: u32,
    pub(crate) detail: u32,
}

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

impl Frame {
    pub(crate) fn read(bytes: &[u8]) -> Self {
        Self {
            kind: bytes[0],
            flags: bytes[1],
            combinator: u16_at(bytes, 2),
            script_id: u32_at(bytes, 4),
            position: u32_at(bytes, 8),
            detail: u32_at(bytes, 12),
        }
    }
    /// The frame rules of include/reb/request_stack.hpp.
    fn valid(&self, is_async: bool) -> bool {
        match self.kind {
            1 => !is_async && self.script_id != 0 && self.combinator == 0 && self.flags & !3 == 0,
            2 => !is_async && self.script_id != 0 && self.combinator == 0 && self.flags == 0,
            3 => is_async && self.script_id != 0 && self.combinator == 0 && self.flags & !2 == 0,
            4 => {
                is_async
                    && self.script_id == 0
                    && (1..=3).contains(&self.combinator)
                    && self.flags == 0
                    && self.detail == 0
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub(crate) kind: u8,
    pub(crate) state: u8,
    pub(crate) flags: u8,
    pub(crate) registration: u8,
    pub(crate) recorded: u32,
    pub(crate) digest: [u8; 32],
}

impl Segment {
    /// The task segment rules of include/reb/request_stack.hpp for a version
    /// 2 or 3 artifact.
    fn read(bytes: &[u8], version: u16) -> Option<Self> {
        let segment = Self {
            kind: bytes[0],
            state: bytes[1],
            flags: bytes[2],
            registration: bytes[3],
            recorded: u32_at(bytes, 4),
            digest: bytes[16..48].try_into().unwrap(),
        };
        let scoped = version == 3;
        // Bit 1: a version 3 not_recorded microtask recorded with promise stacks on.
        let known = if scoped && segment.kind == 9 { 3 } else { 1 };
        let reserved = bytes[8..16].iter().all(|b| *b == 0) && segment.flags & !known == 0;
        let empty =
            segment.flags == 0 && segment.recorded == 0 && segment.digest.iter().all(|b| *b == 0);
        let frames = |limit: u32| {
            matches!(segment.state, 1 | 4 | 5)
                && (1..=limit).contains(&segment.recorded)
                && (segment.flags & 1 == 0 || segment.recorded == limit)
                && segment.digest.iter().any(|b| *b != 0)
        };
        let shape = if segment.kind == 9 {
            if segment.state == 6 {
                segment.registration == 0
                    && segment.flags & !2 == 0
                    && segment.recorded == 0
                    && segment.digest.iter().all(|b| *b == 0)
            } else {
                scoped
                    && (1..=4).contains(&segment.registration)
                    && segment.flags & 2 == 0
                    && frames(REGISTRATION_FRAME_LIMIT)
            }
        } else if segment.registration != 0
            || !(1..=if scoped { 12 } else { 8 }).contains(&segment.kind)
        {
            false
        } else if segment.state == 7 {
            scoped && empty
        } else if segment.state == 8 {
            // A received message whose origin was rejected: kinds 10 to 12.
            scoped && empty && segment.kind >= 10
        } else {
            frames(TASK_FRAME_LIMIT)
        };
        (reserved && shape).then_some(segment)
    }
    fn has_frames(&self) -> bool {
        self.digest.iter().any(|b| *b != 0)
    }
    /// No script was running, or the message's origin was rejected: the chain ends here.
    fn ends_chain(&self) -> bool {
        matches!(self.state, 7 | 8)
    }
}

/// The decoded `request_initiator_stack` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    version: u16,
    pub(crate) scope: Scope,
    task_segments: u32,
    pub(crate) state: u8,
    pub(crate) flags: u8,
    pub(crate) total: u32,
    pub(crate) recorded: u32,
    pub(crate) omitted: u32,
    async_frames: u32,
    async_segments: u32,
    wasm_frames: u32,
    scripts: u32,
    pub(crate) digest: [u8; 32],
    pub(crate) innermost: Frame,
}

pub fn decode_record(payload: &[u8]) -> Option<Record> {
    if payload.len() != 128 || !matches!(payload[..4], [1..=3, 0, 128, 0]) {
        return None;
    }
    let scoped = payload[0] == 3;
    let tasks = payload[0] != 1;
    let known = if tasks { 0x1f } else { 0x0f };
    if payload[if scoped { 96 } else { 80 }..]
        .iter()
        .any(|b| *b != 0)
        || payload[5] & !known != 0
        || (!tasks && payload[6..8] != [0, 0])
    {
        return None;
    }
    // Version 3: a thread with no worker or document isolate names no scope.
    let scope = match (scoped, payload[4]) {
        (false, _) => Scope::DOCUMENT,
        (true, 3) => payload[80..96]
            .iter()
            .all(|b| *b == 0)
            .then_some(Scope::default())?,
        (true, _) => Scope::read(&payload[80..96])?,
    };
    let record = Record {
        version: u16::from(payload[0]),
        scope,
        task_segments: u32::from(u16_at(payload, 6)),
        state: payload[4],
        flags: payload[5],
        total: u32_at(payload, 8),
        recorded: u32_at(payload, 12),
        omitted: u32_at(payload, 16),
        async_frames: u32::from(u16_at(payload, 20)),
        async_segments: u32::from(u16_at(payload, 22)),
        wasm_frames: u32_at(payload, 24),
        scripts: u32_at(payload, 28),
        digest: payload[32..64].try_into().unwrap(),
        innermost: Frame::read(&payload[64..80]),
    };
    let frames = u64::from(record.recorded) + u64::from(record.async_frames);
    let unwalked = || {
        record.flags & !(if tasks { 0 } else { 0x08 }) == 0
            && record.task_segments == 0
            && payload[8..80].iter().all(|b| *b == 0)
    };
    let chain = if tasks {
        record.task_segments <= TASK_LIMIT
            && record.async_segments == record.async_frames + record.task_segments
            && (record.flags & 0x10 == 0 || record.task_segments == TASK_LIMIT)
    } else {
        record.async_segments <= record.async_frames
    };
    let valid = match record.state {
        // 6, version 3: a worker past the renderer's stack table limit.
        2 | 3 => unwalked(),
        6 if scoped => unwalked(),
        1 | 4 | 5 => {
            (1..=SYNC_LIMIT).contains(&record.recorded)
                && u64::from(record.recorded) + u64::from(record.omitted) == u64::from(record.total)
                && (record.omitted != 0) == (record.flags & 0x02 != 0)
                && (record.omitted == 0 || record.recorded == SYNC_LIMIT)
                && record.async_frames <= ASYNC_LIMIT
                && chain
                && (record.flags & 0x04 == 0 || record.async_frames == ASYNC_LIMIT)
                && (record.flags & 0x01 == 0 || record.state == 1)
                && u64::from(record.wasm_frames) <= frames
                && u64::from(record.scripts) <= frames
                && record.digest.iter().any(|b| *b != 0)
                && record.innermost.valid(false)
        }
        _ => false,
    };
    valid.then_some(record)
}

/// A version 3 artifact's scope: renderer process, thread and isolate key.
fn artifact_scope(content: &[u8]) -> Option<ScriptScope> {
    let process = u32_at(content, 32);
    let scope = Scope::read(&[&content[36..37], &[0u8; 7][..], &content[40..48]].concat())?;
    (process != 0 && content[37..40].iter().all(|b| *b == 0)).then_some((process, scope))
}

/// Frames and task chain of a stack artifact that agrees with its record.
/// A version 3 artifact names the same process and isolate as the record.
pub fn decode_artifact(
    content: &[u8],
    record: &Record,
    process_id: u32,
) -> Option<(Vec<Frame>, Vec<Segment>)> {
    if content.len() < HEADER || content.len() > MAX_ARTIFACT || u32_at(content, 0) != 0x4b53_4252 {
        return None;
    }
    let version = u16_at(content, 4);
    // Navigation stacks keep record version 2 and, from the scoped producer,
    // a version 3 artifact.
    let expected = match record.version {
        1 => version == 1,
        2 => matches!(version, 2 | 3),
        _ => version == 3,
    };
    let header = if version == 3 { SCOPED_HEADER } else { HEADER };
    if !expected
        || content.len() < header
        || (version == 3 && artifact_scope(content) != Some((process_id, record.scope)))
    {
        return None;
    }
    let count = (u64::from(record.recorded) + u64::from(record.async_frames)) as usize;
    let header_flags = if record.version != 1 { 0x1e } else { 0x06 };
    if u16_at(content, 6) as usize != header
        || u16_at(content, 8) as usize != FRAME
        || u16_at(content, 10) != u16::from(record.flags & header_flags)
        || u32_at(content, 12) != record.total
        || u32_at(content, 16) != record.recorded
        || u32_at(content, 20) != record.omitted
        || u32::from(u16_at(content, 24)) != record.async_frames
        || u32::from(u16_at(content, 26)) != record.async_segments
        || u32::from(u16_at(content, 28)) != record.task_segments
        || u16_at(content, 30) != 0
        || content.len() != header + FRAME * count + SEGMENT * record.task_segments as usize
    {
        return None;
    }
    let chain = header + FRAME * count;
    let frames: Vec<Frame> = content[header..chain]
        .as_chunks::<FRAME>()
        .0
        .iter()
        .map(|chunk| Frame::read(chunk))
        .collect();
    let segments: Option<Vec<Segment>> = content[chain..]
        .as_chunks::<SEGMENT>()
        .0
        .iter()
        .map(|chunk| Segment::read(chunk, version))
        .collect();
    // A segment scheduled with no script, or received with a rejected origin,
    // ends the chain, neither cut nor truncated.
    let terminal = segments.as_ref().is_some_and(|segments| {
        segments
            .iter()
            .position(Segment::ends_chain)
            .is_none_or(|at| at + 1 == segments.len() && record.flags & 0x18 == 0)
    });
    let valid = terminal
        && frames
            .iter()
            .enumerate()
            .all(|(i, frame)| frame.valid(i >= record.recorded as usize))
        && frames.first() == Some(&record.innermost);
    valid
        .then_some(())
        .and(segments)
        .map(|segments| (frames, segments))
}

/// The record a stack artifact's own header states, before its frames are
/// checked against it.
fn header_record(content: &[u8], innermost: Frame) -> Option<Record> {
    // Read alone, a version 1 or 2 artifact is the document main thread's.
    (content.len() >= HEADER).then(|| Record {
        version: u16_at(content, 4),
        scope: Scope::DOCUMENT,
        task_segments: u32::from(u16_at(content, 28)),
        state: 1,
        flags: content[10],
        total: u32_at(content, 12),
        recorded: u32_at(content, 16),
        omitted: u32_at(content, 20),
        async_frames: u32::from(u16_at(content, 24)),
        async_segments: u32::from(u16_at(content, 26)),
        wasm_frames: 0,
        scripts: 0,
        digest: [0; 32],
        innermost,
    })
}

/// A stack artifact read by its own header, for a digest that no stack record
/// describes here (a `script_cookie` write's walk). The header is checked
/// against the frames exactly as a record's would be.
pub(crate) fn decode_artifact_alone(content: &[u8]) -> Option<(Record, Vec<Frame>, Vec<Segment>)> {
    if content.len() < HEADER + FRAME || content[11] != 0 {
        return None;
    }
    let record = header_record(content, Frame::read(&content[HEADER..HEADER + FRAME]))?;
    let bounded = matches!(record.version, 1 | 2)
        && (1..=SYNC_LIMIT).contains(&record.recorded)
        && record.async_frames <= ASYNC_LIMIT
        && record.task_segments <= TASK_LIMIT
        && u64::from(record.recorded) + u64::from(record.omitted) == u64::from(record.total);
    let (frames, segments) = bounded
        .then(|| decode_artifact(content, &record, 0))
        .flatten()?;
    Some((record, frames, segments))
}

/// A scheduling stack's frames and, for a version 3 artifact, where its
/// script IDs are read. A version 1 artifact is the document main thread's.
pub(crate) fn decode_segment_artifact(
    content: &[u8],
    recorded: u32,
) -> Option<(Vec<Frame>, Option<ScriptScope>)> {
    let count = recorded as usize;
    let version = if content.len() >= HEADER {
        u16_at(content, 4)
    } else {
        0
    };
    let header = if version == 3 { SCOPED_HEADER } else { HEADER };
    let shape = content.len() == header + FRAME * count
        && u32_at(content, 0) == 0x4b53_4252
        && matches!(version, 1 | 3)
        && u16_at(content, 6) as usize == header
        && u16_at(content, 8) as usize == FRAME
        && u16_at(content, 10) == 0
        && u32_at(content, 12) == recorded
        && u32_at(content, 16) == recorded
        && content[20..32].iter().all(|b| *b == 0);
    let scope = if version == 3 && shape {
        Some(artifact_scope(content)?)
    } else {
        None
    };
    let frames: Vec<Frame> = content
        .get(header..)
        .filter(|_| shape)?
        .as_chunks::<FRAME>()
        .0
        .iter()
        .map(|chunk| Frame::read(chunk))
        .collect();
    frames
        .iter()
        .all(|frame| frame.valid(false))
        .then_some((frames, scope))
}

/// The segment digests a version 2 or 3 artifact names, before it is validated.
fn segment_digests(content: &[u8]) -> Vec<String> {
    let version = if content.len() >= HEADER {
        u16_at(content, 4)
    } else {
        0
    };
    let header = match version {
        2 => HEADER,
        3 => SCOPED_HEADER,
        _ => return Vec::new(),
    };
    let frames = u32_at(content, 16) as usize + usize::from(u16_at(content, 24));
    let start = header + FRAME * frames;
    content
        .get(start..)
        .unwrap_or_default()
        .as_chunks::<SEGMENT>()
        .0
        .iter()
        .filter(|chunk| chunk[16..48].iter().any(|b| *b != 0))
        .map(|chunk| hex::encode(&chunk[16..48]))
        .collect()
}

/// Script IDs are read per renderer process and isolate.
pub type IdentityKey = (u32, u64, u32);

/// The newest `script_identity` per script ID, from one process's records.
#[derive(Clone, Debug)]
pub struct Identity {
    pub(crate) wasm: bool,
    pub(crate) eval: bool,
    pub(crate) retained: bool,
    pub(crate) start_line: u32,
    pub(crate) start_column: u32,
    /// The execution context ID of the script's realm: one per document,
    /// so a stack that changes realm crossed a frame boundary.
    pub(crate) realm: u64,
    pub(crate) sha256: Option<[u8; 32]>,
}

impl Identity {
    /// A one-based line and column of the script's artifact as a position in
    /// its document: the script's start line is added, and its start column
    /// only on its first line.
    pub(crate) fn document_position(&self, line: u64, column: u64) -> (u64, u64) {
        let column = if line == 1 {
            u64::from(self.start_column) + column
        } else {
            column
        };
        (u64::from(self.start_line) + line, column)
    }
}

/// The retained source of a frame's script, which `find` looks up by the
/// script's identity and digest, or the first reason there is none.
pub(crate) fn find_source<'a, T>(
    identity: Option<&'a Identity>,
    find: impl FnOnce(&'a Identity, &[u8; 32]) -> Option<T>,
) -> std::result::Result<(&'a Identity, T), &'static str> {
    let identity = identity.ok_or("script_identity_missing")?;
    let sha = identity.sha256.as_ref().ok_or("source_unavailable")?;
    let found = find(identity, sha).ok_or(if identity.wasm || identity.retained {
        "source_artifact_missing"
    } else {
        "source_not_retained"
    })?;
    Ok((identity, found))
}

/// A script identity's isolate key (zero on the document main thread), its
/// script ID and what it says about the source. Version 2 names the isolate.
pub fn decode_identity(payload: &[u8]) -> Option<(u64, u32, Identity)> {
    if payload.len() != 128
        || !matches!(payload[..4], [1 | 2, 0, 128, 0])
        || payload[6..8] != [0, 0]
        || payload[20..24] != [0; 4]
    {
        return None;
    }
    let scope = if payload[0] == 2 {
        if payload[88..].iter().any(|b| *b != 0) {
            return None;
        }
        Scope::read(&payload[72..88])?
    } else {
        if payload[72..].iter().any(|b| *b != 0) {
            return None;
        }
        Scope::DOCUMENT
    };
    let (kind, flags) = (payload[4], payload[5]);
    let script = u32_at(payload, 8);
    let length = u64_at(payload, 32);
    let digest = &payload[40..72];
    let retention = flags & 0x1e;
    let shape = script != 0
        && u64_at(payload, 24) != 0
        && flags & !0x1f == 0
        && retention & retention.wrapping_sub(1) == 0
        && matches!(kind, 1 | 2)
        && (kind != 2 || flags & !0x0c == 0)
        && (kind != 1 || retention != 0);
    let digested = match retention {
        0x08 => length == 0 && digest.iter().all(|b| *b == 0),
        0x04 => length > MAX_SOURCE as u64 && digest.iter().all(|b| *b == 0),
        _ => length != 0 && length <= MAX_SOURCE as u64 && digest.iter().any(|b| *b != 0),
    };
    (shape && digested).then(|| {
        (
            scope.isolate_key,
            script,
            Identity {
                wasm: kind == 2,
                eval: flags & 0x01 != 0,
                retained: flags & 0x02 != 0,
                start_line: u32_at(payload, 12),
                start_column: u32_at(payload, 16),
                realm: u64_at(payload, 24),
                sha256: matches!(retention, 0x00 | 0x02 | 0x10).then(|| digest.try_into().unwrap()),
            },
        )
    })
}

/// One-based LF lines and UTF-16 columns of sorted UTF-16 offsets in text, as
/// Sources numbers them, with each offset's UTF-8 byte position.
pub(crate) fn positions(text: &str, offsets: &BTreeSet<u32>) -> HashMap<u32, (usize, u64, u64)> {
    let mut out = HashMap::new();
    let mut wanted = offsets.iter().copied().peekable();
    let (mut unit, mut line, mut column) = (0u64, 1u64, 1u64);
    for (byte, ch) in text
        .char_indices()
        .chain(std::iter::once((text.len(), '\0')))
    {
        while let Some(&next) = wanted.peek() {
            if u64::from(next) < unit {
                wanted.next();
            } else if u64::from(next) == unit {
                out.insert(next, (byte, line, column));
                wanted.next();
            } else {
                break;
            }
        }
        if byte == text.len() || wanted.peek().is_none() {
            break;
        }
        unit += ch.len_utf16() as u64;
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += ch.len_utf16() as u64;
        }
    }
    out
}

fn identifier_end(bytes: &[u8], mut end: usize) -> Option<(usize, usize)> {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && ident(bytes[start - 1]) {
        start -= 1;
    }
    (start < end && !bytes[start].is_ascii_digit()).then_some((start, end))
}

/// The name the source gives the function starting at byte `start`: the
/// declaration or method name, or the binding an anonymous function or arrow
/// is assigned to. None for an anonymous function.
pub(crate) fn function_name(text: &str, start: usize) -> Option<String> {
    let bytes = text.as_bytes();
    let mut cursor = start.min(bytes.len());
    if let Some((name_start, name_end)) = identifier_end(bytes, cursor) {
        let name = &text[name_start..name_end];
        let before = identifier_end(bytes, name_start).map(|(s, e)| &text[s..e]);
        let keyword = [
            "function", "async", "get", "set", "static", "if", "for", "while", "switch", "catch",
            "return", "with",
        ];
        if !keyword.contains(&name) {
            return Some(match before {
                Some("get" | "set") => format!("{} {name}", before.unwrap()),
                _ => name.to_owned(),
            });
        }
        if name != "function" && name != "async" {
            return None;
        }
        cursor = name_start;
        if name == "function"
            && let Some((s, e)) = identifier_end(bytes, cursor)
            && &text[s..e] == "async"
        {
            cursor = s;
        }
    }
    // `x = function`, `x: (a) =>`, `this.x = function`.
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    let operator = *bytes.get(cursor.checked_sub(1)?)?;
    if operator != b'=' && operator != b':' {
        return None;
    }
    if operator == b'=' && cursor >= 2 && matches!(bytes[cursor - 2], b'=' | b'!' | b'<' | b'>') {
        return None;
    }
    let mut end = cursor - 1;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end > 0 && matches!(bytes[end - 1], b'"' | b'\'') {
        let quote = bytes[end - 1];
        let open = text[..end - 1].rfind(quote as char)?;
        return Some(text[open + 1..end - 1].to_owned());
    }
    let (mut chain_start, chain_end) = identifier_end(bytes, end)?;
    while chain_start > 0 && bytes[chain_start - 1] == b'.' {
        match identifier_end(bytes, chain_start - 1) {
            Some((s, _)) => chain_start = s,
            None => break,
        }
    }
    Some(text[chain_start..chain_end].to_owned())
}

pub(crate) fn wasm_names(bytes: &[u8]) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        let Ok(wasmparser::Payload::CustomSection(section)) = payload else {
            continue;
        };
        if let wasmparser::KnownCustom::Name(reader) = section.as_known() {
            for name in reader.into_iter().flatten() {
                if let wasmparser::Name::Function(map) = name {
                    for naming in map.into_iter().flatten() {
                        names.insert(naming.index, naming.name.to_owned());
                    }
                }
            }
        }
    }
    names
}

fn unresolved(reason: &str) -> Value {
    json!({"status": "unresolved", "reason": reason})
}

fn frame_kind(frame: &Frame) -> &'static str {
    match (frame.kind, frame.combinator) {
        (1, _) => "javascript",
        (2, _) => "wasm",
        (3, _) => "await",
        (_, 1) => "promise_all",
        (_, 2) => "promise_all_settled",
        _ => "promise_any",
    }
}

struct Source {
    artifact_id: Value,
    url: Value,
    text: Option<String>,
    names: HashMap<u32, String>,
    positions: HashMap<u32, (usize, u64, u64)>,
}

/// The retained bytes a script identity's digest names, or why there are none.
/// The newest artifact of this session that matches.
fn newest<'a>(
    artifacts: &'a [Value],
    session: &str,
    matches: impl Fn(&Value) -> bool,
) -> Option<&'a Value> {
    artifacts
        .iter()
        .rev()
        .find(|a| a["session_id"].as_str() == Some(session) && matches(a))
}

fn load_source(
    identity: Option<&Identity>,
    offsets: &BTreeSet<u32>,
    artifacts: &[Value],
    session: &str,
    read: &dyn Fn(&Value, usize) -> Result<Vec<u8>>,
) -> std::result::Result<Source, &'static str> {
    let (identity, artifact) = find_source(identity, |identity, sha| {
        let kind = if identity.wasm { "wasm" } else { "javascript" };
        let sha = hex::encode(sha);
        newest(artifacts, session, |a| {
            a["kind"] == kind && a["sha256"] == sha.as_str()
        })
    })?;
    let bytes = read(artifact, MAX_SOURCE).map_err(|_| "source_artifact_unreadable")?;
    let mut source = Source {
        artifact_id: artifact["artifact_id"].clone(),
        url: artifact["url"].clone(),
        text: None,
        names: HashMap::new(),
        positions: HashMap::new(),
    };
    if identity.wasm {
        source.names = wasm_names(&bytes);
    } else {
        let text = String::from_utf8(bytes).map_err(|_| "source_not_utf8")?;
        source.positions = positions(&text, offsets);
        source.text = Some(text);
    }
    Ok(source)
}

fn state_name(state: u8) -> &'static str {
    match state {
        1 => "captured",
        2 => "no_script",
        3 => "unsupported_thread",
        4 => "not_retained_artifact_unavailable",
        5 => "not_retained_budget",
        _ => "not_walked_thread_limit",
    }
}

/// A record state with no walk, so no digest, frames or segments.
fn unwalked_state(state: u8) -> bool {
    matches!(state, 2 | 3 | 6)
}

/// A record's summary without its frames: state, depth, digest and innermost frame.
pub fn summary(record: &Record) -> Value {
    let walked = !unwalked_state(record.state);
    let f = &record.innermost;
    json!({
        "state": state_name(record.state),
        "total_depth": record.total,
        "recorded": record.recorded,
        "async_frames": record.async_frames,
        "digest": walked.then(|| hex::encode(record.digest)),
        "innermost": walked.then(|| json!({"kind": f.kind, "script_id": f.script_id,
            "position": f.position, "detail": f.detail})),
    })
}

pub(crate) fn task_kind(kind: u8) -> &'static str {
    match kind {
        1 => "set_timeout",
        2 => "set_interval",
        3 => "request_animation_frame",
        4 => "request_idle_callback",
        5 => "post_message",
        6 => "xhr_send",
        7 => "post_task",
        8 => "event",
        9 => "microtask",
        10 => "message_port",
        11 => "broadcast_channel",
        _ => "worker_message",
    }
}

fn segment_state(state: u8) -> &'static str {
    match state {
        1 => "captured",
        4 => "not_retained_artifact_unavailable",
        5 => "not_retained_budget",
        7 => "no_script",
        8 => "origin_rejected",
        _ => "not_recorded",
    }
}

/// The call that registered a microtask's promise reaction, when recorded.
fn registration_name(registration: u8) -> Option<&'static str> {
    match registration {
        1 => Some("then"),
        2 => Some("catch"),
        3 => Some("finally"),
        4 => Some("await"),
        _ => None,
    }
}

type Sources = HashMap<IdentityKey, std::result::Result<Source, &'static str>>;

fn identity_key(scope: ScriptScope, script: u32) -> IdentityKey {
    (scope.0, scope.1.isolate_key, script)
}

/// Each script's retained source, loaded once for every frame that names it.
fn load_sources<'a>(
    frames: impl Iterator<Item = (ScriptScope, &'a Frame)>,
    identities: &HashMap<IdentityKey, Identity>,
    artifacts: &[Value],
    session: &str,
    read: &dyn Fn(&Value, usize) -> Result<Vec<u8>>,
) -> Sources {
    let mut by_script: BTreeMap<IdentityKey, BTreeSet<u32>> = BTreeMap::new();
    for (scope, frame) in frames.filter(|(_, f)| f.script_id != 0) {
        let offsets = by_script
            .entry(identity_key(scope, frame.script_id))
            .or_default();
        if matches!(frame.kind, 1 | 3) {
            offsets.insert(frame.position);
            offsets.insert(frame.detail);
        }
    }
    by_script
        .into_iter()
        .map(|(script, offsets)| {
            let source = load_source(identities.get(&script), &offsets, artifacts, session, read);
            (script, source)
        })
        .collect()
}

fn frame_value(
    index: usize,
    frame: &Frame,
    is_async: bool,
    scope: ScriptScope,
    sources: &Sources,
    identities: &HashMap<IdentityKey, Identity>,
) -> Value {
    let key = identity_key(scope, frame.script_id);
    let mut value = json!({
        "index": index,
        "kind": frame_kind(frame),
        "async": is_async,
        "script_id": frame.script_id,
    });
    if frame.kind == 4 {
        value["promise_index"] = json!(frame.position);
        value["resolution"] = json!({"status": "builtin"});
        return value;
    }
    let source = sources.get(&key);
    if frame.kind == 2 {
        value["function_index"] = json!(frame.detail);
        value["module_offset"] = json!(frame.position);
        // The module digest is the function's identity across sessions;
        // researcher names join to it.
        if let Some(sha) = identities.get(&key).and_then(|identity| identity.sha256) {
            value["module_sha256"] = json!(hex::encode(sha));
        }
        value["resolution"] = match source {
            Some(Ok(source)) => json!({
                "status": "resolved",
                "artifact_id": source.artifact_id,
                "url": source.url,
                "function_name": source.names.get(&frame.detail),
            }),
            Some(Err(reason)) => unresolved(reason),
            None => unresolved("script_identity_missing"),
        };
        return value;
    }
    value["position"] = json!(frame.position);
    value["function_position"] = json!(frame.detail);
    value["constructor"] = json!(frame.flags & 1 != 0);
    value["top_level"] = json!(frame.flags & 2 != 0);
    let identity = identities.get(&key);
    value["eval"] = json!(identity.is_some_and(|i| i.eval));
    value["resolution"] = match source {
        Some(Ok(source)) => match (
            source.positions.get(&frame.position),
            source.text.as_deref(),
            identity,
        ) {
            (Some(&(_, line, column)), Some(text), Some(identity)) => {
                let name = (frame.flags & 2 == 0)
                    .then(|| source.positions.get(&frame.detail))
                    .flatten()
                    .and_then(|&(byte, _, _)| function_name(text, byte));
                let (document_line, document_column) = identity.document_position(line, column);
                json!({
                    "status": "resolved",
                    "artifact_id": source.artifact_id,
                    "url": source.url,
                    "artifact_line": line,
                    "artifact_column": column,
                    "line": document_line,
                    "column": document_column,
                    "function_name": name,
                })
            }
            _ => unresolved("position_outside_source"),
        },
        Some(Err(reason)) => unresolved(reason),
        None => unresolved("script_identity_missing"),
    };
    value
}

/// The stack document for one decoded record. `read` returns verified
/// artifact bytes up to a limit.
pub fn resolve(
    stack_event: &Value,
    record: &Record,
    identities: &HashMap<IdentityKey, Identity>,
    artifacts: &[Value],
    read: &dyn Fn(&Value, usize) -> Result<Vec<u8>>,
) -> Value {
    let state = state_name(record.state);
    let session = stack_event["session_id"].as_str().unwrap_or("");
    let digest = hex::encode(record.digest);
    let tasks = record.version != 1;
    let process = stack_event["process_id"].as_u64().unwrap_or(0) as u32;
    let own: ScriptScope = (process, record.scope);
    let mut document = json!({
        "status": "recorded",
        "request": {
            "session_id": stack_event["session_id"],
            "process_id": stack_event["process_id"],
            "request_id": stack_event["request_id"],
            "frame_id": stack_event["frame_id"],
            "sequence_number": stack_event["sequence_number"],
            "parent_event_id": stack_event["parent_event_id"],
        },
        "state": state,
        "total_depth": record.total,
        "recorded": record.recorded,
        "omitted": record.omitted,
        "omitted_after_index": (record.omitted != 0).then_some(SYNC_LIMIT / 2 - 1),
        "async_frames": record.async_frames,
        "async_segments": record.async_segments,
        "async_truncated": record.flags & 0x04 != 0,
        "task_chain_cut": tasks && record.flags & 0x08 != 0,
        "task_chain_truncated": record.flags & 0x10 != 0,
        "async_callers_not_shown": match record.version {
            1 => &ASYNC_NOT_SHOWN_V1[..],
            2 => &ASYNC_NOT_SHOWN_V2[..],
            _ => &ASYNC_NOT_SHOWN[..],
        },
        "scope": (record.scope.thread != 0).then(|| record.scope.to_json()),
        "wasm_frames": record.wasm_frames,
        "digest": (!unwalked_state(record.state)).then_some(&digest),
        "frames_retained": false,
        "frames": [],
        "task_segments": [],
    });
    if unwalked_state(record.state) {
        return document;
    }
    let decoded = newest(artifacts, session, |a| {
        a["kind"] == "stack" && a["sha256"] == digest.as_str()
    })
    .and_then(|artifact| read(artifact, MAX_ARTIFACT).ok())
    .and_then(|content| decode_artifact(&content, record, process));
    document["frames_retained"] = json!(decoded.is_some());
    let (frames, segments) = decoded.unwrap_or_else(|| (vec![record.innermost], Vec::new()));
    // A segment's frames are read where its own artifact says they were walked:
    // a message carries segments from another thread or process.
    let segment_frames: Vec<Option<(Vec<Frame>, ScriptScope)>> = segments
        .iter()
        .map(|segment| {
            let sha = hex::encode(segment.digest);
            segment
                .has_frames()
                .then(|| {
                    newest(artifacts, session, |a| {
                        a["kind"] == "stack" && a["sha256"] == sha.as_str()
                    })
                })
                .flatten()
                .and_then(|artifact| read(artifact, MAX_ARTIFACT).ok())
                .and_then(|content| decode_segment_artifact(&content, segment.recorded))
                .map(|(frames, scope)| (frames, scope.unwrap_or((process, Scope::DOCUMENT))))
        })
        .collect();
    let sources = load_sources(
        frames.iter().map(|frame| (own, frame)).chain(
            segment_frames
                .iter()
                .flatten()
                .flat_map(|(frames, scope)| frames.iter().map(move |frame| (*scope, frame))),
        ),
        identities,
        artifacts,
        session,
        read,
    );
    document["frames"] = frames
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            frame_value(
                index,
                frame,
                index >= record.recorded as usize,
                own,
                &sources,
                identities,
            )
        })
        .collect();
    document["task_segments"] = segments
        .iter()
        .zip(&segment_frames)
        .enumerate()
        .map(|(index, (segment, frames))| {
            let scope = frames.as_ref().map(|(_, scope)| *scope);
            json!({
                "index": index,
                "kind": task_kind(segment.kind),
                "state": segment_state(segment.state),
                "registration": registration_name(segment.registration),
                "recorded": segment.recorded,
                "bounded": segment.flags & 1 != 0,
                // A not_recorded microtask: whether promise stacks were on.
                "promise_stacks_on": (segment.kind == 9).then_some(segment.flags & 2 != 0),
                "digest": segment.has_frames().then(|| hex::encode(segment.digest)),
                "frames_retained": frames.is_some(),
                "scope": scope.map(|(segment_process, segment_scope)| {
                    let mut value = segment_scope.to_json();
                    value["process_id"] = json!(segment_process);
                    value["elsewhere"] = json!((segment_process, segment_scope) != own);
                    value["other_process"] = json!(segment_process != process);
                    value
                }),
                "frames": frames.as_ref().map(|(frames, scope)| frames.iter().enumerate()
                    .map(|(i, frame)| frame_value(i, frame, false, *scope, &sources, identities))
                    .collect::<Vec<_>>()).unwrap_or_default(),
            })
        })
        .collect();
    document
}

/// A `script_cookie` call's walked stack by digest, else its innermost frame
/// alone, read in the given isolate.
pub fn resolve_call(
    event: &Value,
    scope: Scope,
    innermost: &[u8; FRAME],
    digest: Option<[u8; 32]>,
    identities: &HashMap<IdentityKey, Identity>,
    artifacts: &[Value],
    read: &dyn Fn(&Value, usize) -> Result<Vec<u8>>,
) -> Value {
    let mut record = Record {
        version: 1,
        scope,
        task_segments: 0,
        state: 1,
        flags: 0x08,
        total: 1,
        recorded: 1,
        omitted: 0,
        async_frames: 0,
        async_segments: 0,
        wasm_frames: 0,
        scripts: 0,
        digest: digest.unwrap_or_default(),
        innermost: Frame::read(innermost),
    };
    let session = event["session_id"].as_str().unwrap_or("");
    let header = digest
        .and_then(|digest| {
            let sha = hex::encode(digest);
            newest(artifacts, session, |a| {
                a["kind"] == "stack" && a["sha256"] == sha.as_str()
            })
        })
        .and_then(|artifact| read(artifact, MAX_ARTIFACT).ok())
        .and_then(|content| header_record(&content, record.innermost));
    if let Some(header) = header {
        record.flags |= header.flags & 0x06;
        record.total = header.total;
        record.recorded = header.recorded;
        record.omitted = header.omitted;
        record.async_frames = header.async_frames;
        record.async_segments = header.async_segments;
    }
    let mut document = resolve(event, &record, identities, artifacts, read);
    if digest.is_none() {
        document["digest"] = Value::Null;
    }
    document
}

/// Resolves `get_requests` rows' innermost frames, keeping settled outcomes (protocol/request-index-v1.md).
#[derive(Default)]
pub struct InitiatorFrames(HashMap<String, Value>);

impl InitiatorFrames {
    const KEPT: usize = 4096;
    const NEW_PER_ANSWER: usize = 64;

    /// False when rows were left unresolved for a later answer.
    pub fn resolve(&mut self, document: &mut Value, artifacts_root: &Path) -> bool {
        self.resolve_with(document, artifacts_root, |wanted| {
            evidence::select_artifacts(artifacts_root, |a| {
                matches!(a["kind"].as_str(), Some("javascript" | "wasm"))
                    && a["sha256"].as_str().is_some_and(|sha| wanted.contains(sha))
            })
            .unwrap_or_default()
        })
    }

    fn resolve_with(
        &mut self,
        document: &mut Value,
        artifacts_root: &Path,
        manifest: impl FnOnce(&BTreeSet<String>) -> Vec<Value>,
    ) -> bool {
        let mut manifest = Some(manifest);
        let Some(rows) = document["requests"].as_array_mut() else {
            return true;
        };
        let wanted: BTreeSet<String> = rows
            .iter()
            .filter_map(|row| {
                let identity = hex::decode(row["initiator_frame"]["identity"].as_str()?).ok()?;
                decode_identity(&identity)?.2.sha256.map(hex::encode)
            })
            .collect();
        let mut deferred = false;
        let mut artifacts: Option<Vec<Value>> = None;
        let sources = std::cell::RefCell::new(HashMap::<String, Vec<u8>>::new());
        let read = |artifact: &Value, limit: usize| -> Result<Vec<u8>> {
            let key = artifact["sha256"].as_str().unwrap_or("").to_owned();
            if let Some(bytes) = sources.borrow().get(&key) {
                return Ok(bytes.clone());
            }
            let bytes = evidence::content(artifacts_root, artifact, limit)?;
            let mut kept = sources.borrow_mut();
            if kept.values().map(Vec::len).sum::<usize>() + bytes.len() <= 4 * MAX_SOURCE {
                kept.insert(key, bytes.clone());
            }
            Ok(bytes)
        };
        let mut fresh = 0;
        for row in rows {
            let raw = row["initiator_frame"].take();
            let (Some(frame), Some(session)) = (
                raw["frame"]
                    .as_str()
                    .and_then(|hex| hex::decode(hex).ok())
                    .and_then(|bytes| <[u8; FRAME]>::try_from(bytes).ok()),
                raw["session_id"].as_str(),
            ) else {
                continue;
            };
            let key = format!(
                "{session}:{}:{}:{}",
                raw["process_id"], raw["isolate_key"], raw["frame"]
            );
            if let Some(kept) = self.0.get(&key) {
                row["initiator_frame"] = kept.clone();
                continue;
            }
            if fresh == Self::NEW_PER_ANSWER {
                deferred = true;
                continue;
            }
            fresh += 1;
            let process = raw["process_id"].as_u64().unwrap_or(0) as u32;
            let scope = Scope::of_row(
                raw["thread"].as_u64().unwrap_or(0),
                raw["isolate_key"]
                    .as_str()
                    .and_then(|key| key.parse().ok())
                    .unwrap_or(0),
            );
            let identities: HashMap<IdentityKey, Identity> = raw["identity"]
                .as_str()
                .and_then(|hex| hex::decode(hex).ok())
                .and_then(|bytes| decode_identity(&bytes))
                .map(|(isolate, script, identity)| ((process, isolate, script), identity))
                .into_iter()
                .collect();
            let artifacts = artifacts
                .get_or_insert_with(|| manifest.take().map_or_else(Vec::new, |f| f(&wanted)));
            let event = json!({"session_id": session, "process_id": raw["process_id"]});
            let mut stack =
                resolve_call(&event, scope, &frame, None, &identities, artifacts, &read);
            let resolution = stack["frames"][0]["resolution"].take();
            let pending = matches!(
                resolution["reason"].as_str(),
                Some("script_identity_missing" | "source_artifact_missing")
            );
            if !pending {
                if self.0.len() == Self::KEPT {
                    self.0.clear();
                }
                self.0.insert(key, resolution.clone());
            }
            row["initiator_frame"] = resolution;
        }
        !deferred
    }
}

/// A stored record's payload bytes; stored payloads are hex.
pub(crate) fn payload(event: &Value) -> Option<Vec<u8>> {
    (event["payload_encoding"] == "hex")
        .then(|| hex::decode(event["payload"].as_str()?).ok())
        .flatten()
}

/// Bytes 80-127 of a `navigation_initiator_stack`: its kind and target frame.
pub(crate) fn decode_navigation(payload: &[u8]) -> Option<(Record, &'static str, u64)> {
    if payload.len() != 128
        || payload[0] != 2
        || !matches!(payload[4], 1 | 4 | 5)
        || payload[81..88].iter().any(|b| *b != 0)
        || payload[96..].iter().any(|b| *b != 0)
    {
        return None;
    }
    let kind = match payload[80] {
        1 => "location",
        2 => "form_submission",
        3 => "window_open",
        4 => "other_script",
        _ => return None,
    };
    let target = u64_at(payload, 88);
    let mut stack = payload.to_vec();
    stack[80..].fill(0);
    (target != 0)
        .then(|| decode_record(&stack))
        .flatten()
        .map(|record| (record, kind, target))
}

/// Decodes `RequestIndex::identities` payloads. A malformed one is left out,
/// like a malformed identity record in a store scan.
pub(crate) fn decode_indexed_identities(
    process: u32,
    payloads: &crate::request_index::IdentityPayloads,
) -> HashMap<IdentityKey, Identity> {
    payloads
        .values()
        .filter_map(|payload| {
            let (isolate, script, identity) = decode_identity(&hex::decode(payload).ok()?)?;
            Some(((process, isolate, script), identity))
        })
        .collect()
}

/// Every frame's script identity, and whether an identity absent from them is
/// absent from the store. The index keeps the whole session's identities, so
/// the store is scanned only while the index cannot answer for all of them.
fn stored_identities(
    store: &Path,
    requests: &Mutex<RequestIndex>,
    stack: &Value,
    process_id: u64,
) -> Result<(HashMap<IdentityKey, Identity>, bool)> {
    let session = stack["session_id"].as_str();
    let mut identities = HashMap::new();
    let mut known = false;
    if let Some(session) = session {
        let (indexed, exhaustive) = requests
            .blocking_lock()
            .identities(session, process_id as u32)?;
        known = exhaustive;
        identities = decode_indexed_identities(process_id as u32, &indexed);
    }
    if !known {
        let mut ids = vec![("process_id", process_id)];
        if let Some(session) = session.and_then(|session| session.parse().ok()) {
            ids.push(("session_id", session));
        }
        let filter = EventFilter::exact(&["script_identity"], ids);
        let detail = event_query::read_request_records(store, None, IDENTITY_SCAN, &filter)?;
        known = detail.coverage.complete();
        for event in &detail.records {
            if let Some((isolate, script, identity)) =
                payload(event).as_deref().and_then(decode_identity)
            {
                identities.insert((process_id as u32, isolate, script), identity);
            }
        }
    }
    Ok((identities, known))
}

/// A frame whose identity was not found cannot claim that it was never
/// recorded when the identities were not all read.
pub(crate) fn mark_identities_outside_scan(document: &mut Value) {
    let mark = |frames: Option<&mut Vec<Value>>| {
        for frame in frames.into_iter().flatten() {
            if frame["resolution"]["reason"] == "script_identity_missing" {
                frame["resolution"]["reason"] = json!("script_identity_outside_scan");
            }
        }
    };
    mark(document["frames"].as_array_mut());
    if let Some(segments) = document["task_segments"].as_array_mut() {
        for segment in segments {
            mark(segment["frames"].as_array_mut());
        }
    }
}

/// The stack document, and `site` resolved alone through the same
/// identities: a debugger observation's listener, callback or throw site,
/// which can name a script while the stack itself holds none.
fn resolve_stored(
    store: &Path,
    artifacts_root: &Path,
    requests: &Mutex<RequestIndex>,
    stack: &Value,
    record: &Record,
    process_id: u64,
    site: Option<&[u8; FRAME]>,
) -> Result<(Value, Option<Value>)> {
    let (mut identities, mut known) = if !unwalked_state(record.state) || site.is_some() {
        stored_identities(store, requests, stack, process_id)?
    } else {
        (HashMap::new(), true)
    };
    let mut wanted: BTreeSet<String> = identities
        .values()
        .filter_map(|identity| identity.sha256.map(hex::encode))
        .collect();
    let digest = hex::encode(record.digest);
    wanted.insert(digest.clone());
    let stack_session = stack["session_id"].as_str();
    let select = |wanted: &BTreeSet<String>| {
        evidence::select_artifacts(artifacts_root, |a| {
            a["session_id"].as_str() == stack_session
                && matches!(a["kind"].as_str(), Some("stack" | "javascript" | "wasm"))
                && a["sha256"].as_str().is_some_and(|sha| wanted.contains(sha))
        })
    };
    let mut artifacts = select(&wanted)?;
    let root = artifacts_root.to_path_buf();
    let read = move |artifact: &Value, limit: usize| evidence::content(&root, artifact, limit);
    // The task chain names its scheduling stacks by digest.
    if record.version != 1
        && record.task_segments != 0
        && let Some(content) = newest(&artifacts, stack_session.unwrap_or(""), |a| {
            a["kind"] == "stack" && a["sha256"] == digest.as_str()
        })
        .and_then(|artifact| read(artifact, MAX_ARTIFACT).ok())
    {
        let segments: BTreeSet<String> = segment_digests(&content)
            .into_iter()
            .filter(|sha| !wanted.contains(sha))
            .collect();
        if !segments.is_empty() {
            let selected = select(&segments)?;
            // A segment a message carried from another renderer reads its
            // script IDs in that renderer: load its identities and sources too.
            let others: BTreeSet<u32> = selected
                .iter()
                .filter_map(|artifact| read(artifact, MAX_ARTIFACT).ok())
                .filter(|content| content.len() >= SCOPED_HEADER && u16_at(content, 4) == 3)
                .filter_map(|content| artifact_scope(&content))
                .map(|(process, _)| process)
                .filter(|process| u64::from(*process) != process_id)
                .collect();
            artifacts.extend(selected);
            let mut sources = BTreeSet::new();
            for other in others {
                let (found, complete) = stored_identities(store, requests, stack, other.into())?;
                known &= complete;
                sources.extend(
                    found
                        .values()
                        .filter_map(|identity| identity.sha256.map(hex::encode))
                        .filter(|sha| !wanted.contains(sha)),
                );
                identities.extend(found);
            }
            if !sources.is_empty() {
                artifacts.extend(select(&sources)?);
            }
        }
    }
    let mut document = resolve(stack, record, &identities, &artifacts, &read);
    let site = site.map(|site| {
        let mut alone = resolve_call(
            stack,
            record.scope,
            site,
            None,
            &identities,
            &artifacts,
            &read,
        );
        if !known {
            mark_identities_outside_scan(&mut alone);
        }
        alone["frames"][0].take()
    });
    if !known {
        mark_identities_outside_scan(&mut document);
    }
    Ok((document, site))
}

fn absent_status(coverage: event_query::Coverage) -> &'static str {
    if coverage.complete() {
        "not_recorded"
    } else {
        "outside_scan"
    }
}

/// Reads the newest stack record of one renderer request and resolves it. The
/// index names the request's bytes, so newer traffic does not hide its stack.
pub fn document(
    store: &Path,
    artifacts_root: &Path,
    requests: &Mutex<RequestIndex>,
    session_id: Option<u64>,
    process_id: u64,
    request_id: u64,
) -> Result<Value> {
    let session = session_id.map(|session| session.to_string());
    let range = requests.blocking_lock().member_range(
        session.as_deref(),
        Some(process_id as u32),
        &request_id.to_string(),
    )?;
    let mut ids = vec![("process_id", process_id), ("request_id", request_id)];
    if let Some(session) = session_id {
        ids.push(("session_id", session));
    }
    let filter = EventFilter::exact(&["request_initiator_stack"], ids);
    let detail = event_query::read_newest_record(store, range, &filter)?;
    let coverage = detail.coverage;
    let Some(stack) = detail.records.into_iter().next_back() else {
        // Only an index that has not reached the end can later name these bytes;
        // otherwise another read would scan the same range to the same answer.
        let index_behind = match range {
            Some(range) => !range.indexed,
            None => !requests.blocking_lock().is_caught_up(),
        };
        return Ok(json!({
            "status": absent_status(coverage),
            "request": {"process_id": process_id, "request_id": request_id.to_string()},
            "coverage": coverage.to_json(),
            "index_behind": index_behind,
        }));
    };
    let Some(record) = payload(&stack).as_deref().and_then(decode_record) else {
        return Ok(json!({"status": "malformed", "request": {
            "session_id": stack["session_id"], "process_id": stack["process_id"],
            "request_id": stack["request_id"], "sequence_number": stack["sequence_number"]},
            "coverage": coverage.to_json()}));
    };
    let (mut document, _) = resolve_stored(
        store,
        artifacts_root,
        requests,
        &stack,
        &record,
        process_id,
        None,
    )?;
    document["coverage"] = coverage.to_json();
    Ok(document)
}

/// The `navigation_initiator_stack` a browser `navigation_initiator_link` names.
pub fn navigation_document(
    store: &Path,
    artifacts_root: &Path,
    requests: &Mutex<RequestIndex>,
    session_id: Option<u64>,
    process_id: u64,
    sequence: u64,
) -> Result<Value> {
    let mut ids = vec![("process_id", process_id), ("sequence_number", sequence)];
    if let Some(session) = session_id {
        ids.push(("session_id", session));
    }
    let filter = EventFilter::exact(&["navigation_initiator_stack"], ids);
    // Navigation stacks have no row, so only the newest bytes are read.
    let detail = event_query::read_newest_record(store, None, &filter)?;
    let coverage = detail.coverage;
    let Some(stack) = detail.records.into_iter().next_back() else {
        return Ok(json!({
            "status": absent_status(coverage),
            "request": {"process_id": process_id, "sequence_number": sequence.to_string()},
            "coverage": coverage.to_json(),
        }));
    };
    let Some((record, kind, target)) = payload(&stack).as_deref().and_then(decode_navigation)
    else {
        return Ok(json!({"status": "malformed", "request": {
            "session_id": stack["session_id"], "process_id": stack["process_id"],
            "sequence_number": stack["sequence_number"]},
            "coverage": coverage.to_json()}));
    };
    let (mut document, _) = resolve_stored(
        store,
        artifacts_root,
        requests,
        &stack,
        &record,
        process_id,
        None,
    )?;
    document["navigation"] = json!({"kind": kind, "target_frame_id": target.to_string()});
    document["coverage"] = coverage.to_json();
    Ok(document)
}

/// Payload bytes of a debugger observation's own frame: the listener, the
/// timer callback or the throw site (protocol/native-debugger-observation-v1.md).
fn observation_site(kind: &str, payload: &[u8]) -> Option<[u8; FRAME]> {
    let at = match kind {
        "listener_dispatch" | "exception_observation" => 84,
        "timer_observation" => 92,
        _ => return None,
    };
    let site: [u8; FRAME] = payload[at..at + FRAME].try_into().ok()?;
    site.iter().any(|b| *b != 0).then_some(site)
}

/// One debugger observation record (types 40 to 45) of a renderer: its stack
/// resolved like a request's and its own frame resolved alone.
pub fn observation_document(
    store: &Path,
    artifacts_root: &Path,
    requests: &Mutex<RequestIndex>,
    session_id: Option<u64>,
    process_id: u64,
    sequence: u64,
) -> Result<Value> {
    let mut ids = vec![("process_id", process_id), ("sequence_number", sequence)];
    if let Some(session) = session_id {
        ids.push(("session_id", session));
    }
    let filter = EventFilter::exact(&crate::debugger_observation::TYPES, ids);
    // Observations have no row, so only the newest bytes are read.
    let detail = event_query::read_newest_record(store, None, &filter)?;
    let coverage = detail.coverage;
    let Some(event) = detail.records.into_iter().next_back() else {
        return Ok(json!({
            "status": absent_status(coverage),
            "request": {"process_id": process_id, "sequence_number": sequence.to_string()},
            "coverage": coverage.to_json(),
        }));
    };
    let decoded = crate::debugger_observation::decode(&event);
    let mut stack = payload(&event).unwrap_or_default();
    let site = decoded
        .as_ref()
        .and_then(|_| observation_site(event["type"].as_str().unwrap_or(""), &stack));
    let record = decoded.as_ref().and_then(|_| {
        stack[80..].fill(0);
        decode_record(&stack)
    });
    let (Some(observation), Some(record)) = (decoded, record) else {
        return Ok(json!({"status": "malformed", "request": {
            "session_id": event["session_id"], "process_id": event["process_id"],
            "sequence_number": event["sequence_number"]},
            "coverage": coverage.to_json()}));
    };
    let (mut document, site) = resolve_stored(
        store,
        artifacts_root,
        requests,
        &event,
        &record,
        process_id,
        site.as_ref(),
    )?;
    document["observation"] = json!({"type": observation["type"], "detail": observation["detail"],
        "site": site});
    document["coverage"] = coverage.to_json();
    Ok(document)
}

/// Distinct scripts one event page reads to resolve its sites. Each is one
/// source read and one walk over it for every site it holds, up to 16 MiB;
/// the number of sites in a script costs nothing more.
pub const PAGE_SOURCES: usize = 4;

/// An observation's own frame before a read resolves it: its raw identity and
/// why this read did not. `eval` comes from the script identity, so it is
/// absent rather than guessed.
fn deferred_site(site: &[u8; FRAME], reason: &str) -> Value {
    let frame = Frame::read(site);
    let mut value = frame_value(
        0,
        &frame,
        false,
        (0, Scope::DOCUMENT),
        &HashMap::new(),
        &HashMap::new(),
    );
    if let Some(object) = value.as_object_mut() {
        object.remove("eval");
    }
    value["resolution"] = json!({"status": "deferred", "reason": reason});
    value
}

/// For one decoded observation record (types 40 to 45): its own frame (the
/// listener, the timer callback or the throw site) as `site`, raw until
/// `ObservationSites` resolves it and null when the record names none, and the
/// exact `get_request_stack` arguments that read its whole stack.
pub(crate) fn observation_reads(event: &Value) -> (Value, Value) {
    let kind = event["type"].as_str().unwrap_or("");
    let site = payload(event)
        .and_then(|payload| observation_site(kind, &payload))
        .map_or(Value::Null, |site| deferred_site(&site, "source_limit"));
    let sequence = event["sequence_number"].as_str().unwrap_or("0");
    let process = event["process_id"].as_u64().unwrap_or(0);
    let session = event["session_id"].as_str().unwrap_or("0");
    let read = (process != 0 && sequence != "0" && session != "0").then(
        || json!({"session_id": session, "process_id": process, "observation_sequence": sequence}),
    );
    (site, read.unwrap_or(Value::Null))
}

/// What one page's site resolution read. A page whose sites are all settled,
/// or pending with nothing they depend on changed, reads none of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SiteWork {
    /// Sources read and walked, one per script.
    pub source_walks: usize,
    /// Manifest lines parsed: only those appended since the last read.
    pub manifest_lines: usize,
    /// Renderers whose script identities were read from the request index.
    pub identity_reads: usize,
}

/// Which file kept answers were read from: its device and inode, a digest of
/// its first bytes and a digest of the bytes before its length then, as the
/// request index anchors its folded offset. A file replaced under the same
/// name, or rewritten in place with the same beginning, is told from one that
/// only grew.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileMark {
    device: u64,
    inode: u64,
    length: u64,
    head: usize,
    head_digest: [u8; 32],
    tail: usize,
    tail_digest: [u8; 32],
}

const MARK_HEAD: usize = 4096;

impl FileMark {
    /// The file now, and whether it is the same file as `before`, grown or not.
    fn read(path: &Path, before: Option<&FileMark>) -> std::io::Result<(FileMark, bool)> {
        use sha2::{Digest, Sha256};
        use std::io::{Read, Seek, SeekFrom};
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        let digest = |bytes: &[u8]| -> [u8; 32] { Sha256::digest(bytes).into() };
        let mut file = match evidence::regular_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let empty = FileMark {
                    device: 0,
                    inode: 0,
                    length: 0,
                    head: 0,
                    head_digest: digest(&[]),
                    tail: 0,
                    tail_digest: digest(&[]),
                };
                let same = before.is_none_or(|before| before.length == 0);
                return Ok((empty, same));
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        #[cfg(unix)]
        let (device, inode) = (metadata.dev(), metadata.ino());
        #[cfg(not(unix))]
        let (device, inode) = (0, 0);
        let length = metadata.len();
        let mut range = |at: u64, count: usize| -> std::io::Result<Vec<u8>> {
            let mut bytes = vec![0u8; count];
            file.seek(SeekFrom::Start(at))?;
            file.read_exact(&mut bytes)?;
            Ok(bytes)
        };
        let head = range(0, length.min(MARK_HEAD as u64) as usize)?;
        let tail_count = length.min(MARK_HEAD as u64) as usize;
        let tail = range(length - tail_count as u64, tail_count)?;
        let same = match before {
            None => true,
            // Nothing was read from an empty file, so any file now is it grown.
            Some(before) if before.length == 0 => true,
            Some(before) => {
                before.device == device
                    && before.inode == inode
                    && before.length <= length
                    && before.head <= head.len()
                    && digest(&head[..before.head]) == before.head_digest
                    && digest(&range(before.length - before.tail as u64, before.tail)?)
                        == before.tail_digest
            }
        };
        let mark = FileMark {
            device,
            inode,
            length,
            head: head.len(),
            head_digest: digest(&head),
            tail: tail.len(),
            tail_digest: digest(&tail),
        };
        Ok((mark, same))
    }
}

/// The artifact manifest's identity for a page's tag: the file, its length
/// and both anchors, so a manifest replaced by one of the same length is a
/// different tag.
pub fn manifest_tag(artifacts_root: &Path) -> String {
    match FileMark::read(&artifacts_root.join("manifest.jsonl"), None) {
        Ok((mark, _)) => format!(
            "{}-{}-{}-{}-{}",
            mark.device,
            mark.inode,
            mark.length,
            hex::encode(&mark.head_digest[..8]),
            hex::encode(&mark.tail_digest[..8])
        ),
        Err(error) => format!("unreadable-{:?}", error.kind()),
    }
}

/// What a pending site depends on, as it was when the site was read: the
/// manifest bytes parsed and the request index's epoch and folded offset.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    manifest: u64,
    index: Option<(String, u64)>,
}

struct Kept {
    site: Value,
    /// None once settled; else the state a re-read waits for a change from.
    pending: Option<Stamp>,
}

/// The manifest's JavaScript and Wasm artifacts by session, kind and digest,
/// newest last as `newest` reads them, built from the appended lines alone.
struct ManifestArtifact {
    id: String,
    url: Value,
    size: u64,
    path: String,
}

#[derive(Default)]
struct ManifestDigests {
    mark: Option<FileMark>,
    offset: u64,
    ids: std::collections::HashSet<String>,
    newest: HashMap<(String, String, String), ManifestArtifact>,
}

impl ManifestDigests {
    fn apply(&mut self, records: Vec<Value>) -> Result<()> {
        for record in records {
            let id = record["artifact_id"].as_str().unwrap_or("").to_owned();
            if !self.ids.insert(id.clone()) {
                return Err(crate::error::Error::new(
                    500,
                    "The artifact manifest contains a duplicate artifact ID",
                ));
            }
            let kind = record["kind"].as_str().unwrap_or("");
            if !matches!(kind, "javascript" | "wasm") {
                continue;
            }
            self.newest.insert(
                (
                    record["session_id"].as_str().unwrap_or("").to_owned(),
                    kind.to_owned(),
                    record["sha256"].as_str().unwrap_or("").to_owned(),
                ),
                ManifestArtifact {
                    id,
                    url: record["url"].clone(),
                    size: record["byte_size"].as_u64().unwrap_or(0),
                    path: record["content_path"].as_str().unwrap_or("").to_owned(),
                },
            );
        }
        Ok(())
    }

    /// Applies the lines one read parsed from `from` to `offset`, unless
    /// another read already moved past `from`, and returns the offset the
    /// digests now cover.
    fn take(&mut self, from: u64, records: Vec<Value>, offset: u64, mark: FileMark) -> Result<u64> {
        if from == 0 {
            *self = Self::default();
        }
        if self.offset == from {
            self.apply(records)?;
            self.offset = offset;
            self.mark = Some(mark);
        }
        Ok(self.offset)
    }

    fn artifact(&self, session: &str, kind: &str, sha: &str) -> Option<Value> {
        let found = self
            .newest
            .get(&(session.to_owned(), kind.to_owned(), sha.to_owned()))?;
        Some(
            json!({"artifact_id": found.id, "session_id": session, "kind": kind,
            "url": found.url, "sha256": sha, "byte_size": found.size, "content_path": found.path}),
        )
    }
}

fn files_moved() -> crate::error::Error {
    crate::error::Error::new(
        409,
        "The event store or artifact manifest was replaced while its sites were read",
    )
}

#[cfg(test)]
thread_local! {
    /// Runs once between a read's manifest read and its publish, as a second
    /// read interleaving there would.
    static AFTER_MANIFEST_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Observation sites resolved once and kept, as `InitiatorFrames` keeps
/// initiator frames. A settled site is a fact of retained bytes. A pending one
/// (its identity or source not seen yet) is kept with the manifest bytes its
/// lookups covered and the index position it was read at, and read again only
/// once either moved. The
/// manifest is read incrementally from where the last read stopped. All of it
/// belongs to one event store and one manifest: either not being the same
/// file grown drops everything, before any kept answer is used.
#[derive(Default)]
pub struct ObservationSites {
    store: Option<FileMark>,
    kept: HashMap<String, Kept>,
    manifest: ManifestDigests,
    generation: u64,
    /// Counts the times everything was dropped. A read that began before a
    /// drop publishes nothing and shows nothing it read.
    clears: u64,
}

struct Wanted {
    key: String,
    session: String,
    process: u32,
    frame: Frame,
    events: Vec<usize>,
}

impl ObservationSites {
    const KEPT: usize = 4096;

    /// Changes whenever a kept answer does, so a tag that covers it tells a
    /// page whose sites resolved since from one that did not.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Drops every kept answer, as clearing the capture drops the stores.
    pub fn clear(&mut self) {
        *self = Self {
            generation: self.generation + 1,
            clears: self.clears + 1,
            ..Self::default()
        };
    }

    /// Decodes every observation of one page and resolves its sites, newest
    /// first when `newest_first` (a backward page). The lock is taken only to
    /// read and publish kept answers: identities, the manifest and sources
    /// are read without it. A failed identity or manifest read, or a store
    /// or manifest another read found replaced meanwhile, leaves each
    /// unsettled site raw with reason `site_read_failed`; it never costs the
    /// records themselves.
    pub fn annotate(
        sites: &std::sync::Mutex<ObservationSites>,
        store: &Path,
        artifacts_root: &Path,
        requests: &Mutex<RequestIndex>,
        events: &mut [Value],
        newest_first: bool,
    ) -> SiteWork {
        crate::debugger_observation::annotate(events);
        let mut work = SiteWork::default();
        if Self::resolve(
            sites,
            store,
            artifacts_root,
            requests,
            events,
            newest_first,
            &mut work,
        )
        .is_err()
        {
            for event in events.iter_mut() {
                let site = &mut event["debugger_observation"]["site"];
                if site["resolution"]["status"] == "deferred" {
                    site["resolution"]["reason"] = json!("site_read_failed");
                }
            }
        }
        work
    }

    fn lock(sites: &std::sync::Mutex<ObservationSites>) -> std::sync::MutexGuard<'_, Self> {
        sites
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn resolve(
        sites: &std::sync::Mutex<ObservationSites>,
        store: &Path,
        artifacts_root: &Path,
        requests: &Mutex<RequestIndex>,
        events: &mut [Value],
        newest_first: bool,
        work: &mut SiteWork,
    ) -> Result<()> {
        let manifest_path = artifacts_root.join("manifest.jsonl");
        // The index's position without waiting for it: while it is busy a
        // pending site is served as it was and read again next time.
        let index_now = requests.try_lock().ok().and_then(|index| index.position());
        let order: Vec<usize> = if newest_first {
            (0..events.len()).rev().collect()
        } else {
            (0..events.len()).collect()
        };
        let mut wanted: Vec<Wanted> = Vec::new();
        let (manifest_mark, manifest_offset, clears) = {
            // Both files are checked before any kept answer is used: a site
            // is a fact of this event store and of these artifacts.
            let (store_before, manifest_before) = {
                let this = Self::lock(sites);
                (this.store.clone(), this.manifest.mark.clone())
            };
            let (mark, same) = FileMark::read(store, store_before.as_ref())?;
            let (manifest_mark, manifest_same) =
                FileMark::read(&manifest_path, manifest_before.as_ref())?;
            let manifest_length = manifest_mark.length;
            let mut this = Self::lock(sites);
            if !same || !manifest_same {
                // Not the store or the manifest these answers came from.
                this.clear();
            }
            this.store = Some(mark.clone());
            for at in order {
                let event = &mut events[at];
                if event["debugger_observation"]["site"].is_null() {
                    continue;
                }
                let kind = event["type"].as_str().unwrap_or("");
                let Some(site) =
                    payload(event).and_then(|payload| observation_site(kind, &payload))
                else {
                    continue;
                };
                let (session, process) = (
                    event["session_id"].as_str().unwrap_or("").to_owned(),
                    event["process_id"].as_u64().unwrap_or(0) as u32,
                );
                let key = format!("{session}:{process}:{}", hex::encode(site));
                let reusable = this.kept.get(&key).filter(|kept| match &kept.pending {
                    None => true,
                    Some(stamp) => {
                        stamp.manifest == manifest_length
                            && (index_now.is_none() || stamp.index == index_now)
                    }
                });
                if let Some(kept) = reusable {
                    event["debugger_observation"]["site"] = kept.site.clone();
                } else if let Some(same) = wanted.iter_mut().find(|w| w.key == key) {
                    same.events.push(at);
                } else {
                    wanted.push(Wanted {
                        key,
                        session,
                        process,
                        frame: Frame::read(&site),
                        events: vec![at],
                    });
                }
            }
            (manifest_mark, this.manifest.offset, this.clears)
        };
        if wanted.is_empty() {
            return Ok(());
        }
        // Identities once per renderer, from the request index alone: a
        // 64 MiB store scan per read is not paid for an identity the index
        // does not hold. Reading them refreshes the index.
        let mut identities = HashMap::new();
        let mut complete: HashMap<(String, u32), bool> = HashMap::new();
        for want in &wanted {
            let renderer = (want.session.clone(), want.process);
            if complete.contains_key(&renderer) {
                continue;
            }
            work.identity_reads += 1;
            let (indexed, exhaustive) = requests
                .blocking_lock()
                .identities(&want.session, want.process)?;
            identities.extend(decode_indexed_identities(want.process, &indexed));
            complete.insert(renderer, exhaustive);
        }
        let index_read = requests.blocking_lock().position();
        // The manifest lines appended since the last read, read without the lock.
        let start = manifest_offset;
        // A manifest rewritten past its first bytes no longer has a line
        // boundary where the last read stopped: read it again from the start.
        let (from, records, offset) = match evidence::manifest_from(artifacts_root, start) {
            Ok((records, offset)) => (start, records, offset),
            Err(_) if start > 0 => {
                let (records, offset) = evidence::manifest_from(artifacts_root, 0)?;
                (0, records, offset)
            }
            Err(error) => return Err(error),
        };
        work.manifest_lines = records.len();
        // The lines parsed belong to the manifest whose kept answers were
        // used, and the mark kept for the next read anchors what was parsed.
        let (manifest_mark, still) = FileMark::read(&manifest_path, Some(&manifest_mark))?;
        if !still {
            return Err(files_moved());
        }
        // The scripts whose sources are read, in the page's order, at most
        // PAGE_SOURCES; a site of a later script stays raw with source_limit.
        let scope = |want: &Wanted| (want.process, Scope::DOCUMENT);
        let mut scripts: Vec<IdentityKey> = Vec::new();
        let mut limited = BTreeSet::new();
        for (at, want) in wanted.iter().enumerate() {
            let key = identity_key(scope(want), want.frame.script_id);
            let reads = identities.get(&key).is_some_and(|i| i.sha256.is_some());
            if !reads || scripts.contains(&key) {
                continue;
            }
            if scripts.len() == PAGE_SOURCES {
                limited.insert(at);
            } else {
                scripts.push(key);
            }
        }
        #[cfg(test)]
        if let Some(hook) = AFTER_MANIFEST_READ.with(|hook| hook.borrow_mut().take()) {
            hook();
        }
        let (artifacts, parsed_to): (Vec<Value>, u64) = {
            let mut this = Self::lock(sites);
            if this.clears != clears {
                return Err(files_moved());
            }
            let parsed_to = this.manifest.take(from, records, offset, manifest_mark)?;
            let sessions: BTreeSet<&str> =
                wanted.iter().map(|want| want.session.as_str()).collect();
            let mut found = Vec::new();
            for key in &scripts {
                let Some(identity) = identities.get(key) else {
                    continue;
                };
                let (kind, sha) = (
                    if identity.wasm { "wasm" } else { "javascript" },
                    identity.sha256.map(hex::encode).unwrap_or_default(),
                );
                for session in &sessions {
                    found.extend(this.manifest.artifact(session, kind, &sha));
                }
            }
            (found, parsed_to)
        };
        let walks = std::cell::Cell::new(0usize);
        let read = |artifact: &Value, limit: usize| -> Result<Vec<u8>> {
            walks.set(walks.get() + 1);
            evidence::content(artifacts_root, artifact, limit)
        };
        // One pass per session over every site's script: each source is read
        // and walked once, for all of its sites' offsets, as resolve() does for
        // the frames of one stack.
        // A pending outcome waits on what the shared digests parsed, which
        // another read may have left short of this read's own offset.
        let stamp = Stamp {
            manifest: parsed_to,
            index: index_read,
        };
        let mut results: Vec<(usize, Value, bool)> = Vec::new();
        let sessions: BTreeSet<String> = wanted.iter().map(|want| want.session.clone()).collect();
        for session in &sessions {
            let frames: Vec<(ScriptScope, &Frame)> = wanted
                .iter()
                .enumerate()
                .filter(|(at, want)| want.session == *session && !limited.contains(at))
                .map(|(_, want)| (scope(want), &want.frame))
                .collect();
            let sources = load_sources(frames.into_iter(), &identities, &artifacts, session, &read);
            for (at, want) in wanted.iter().enumerate() {
                if want.session != *session || limited.contains(&at) {
                    continue;
                }
                let mut site =
                    frame_value(0, &want.frame, false, scope(want), &sources, &identities);
                if site["resolution"]["reason"] == "script_identity_missing"
                    && !complete[&(want.session.clone(), want.process)]
                {
                    site["resolution"]["reason"] = json!("script_identity_outside_scan");
                }
                let pending = matches!(
                    site["resolution"]["reason"].as_str(),
                    Some(
                        "script_identity_missing"
                            | "script_identity_outside_scan"
                            | "source_artifact_missing"
                    )
                );
                results.push((at, site, pending));
            }
        }
        work.source_walks = walks.get();
        let mut this = Self::lock(sites);
        // Read from a store or manifest another read has since found
        // replaced: nothing of it is shown or kept.
        if this.clears != clears {
            return Err(files_moved());
        }
        for (at, site, pending) in results {
            let want = &wanted[at];
            for &event in &want.events {
                events[event]["debugger_observation"]["site"] = site.clone();
            }
            let changed = this
                .kept
                .get(&want.key)
                .is_none_or(|kept| kept.site != site);
            if this.kept.len() >= Self::KEPT && !this.kept.contains_key(&want.key) {
                this.kept.clear();
                this.generation += 1;
            }
            this.kept.insert(
                want.key.clone(),
                Kept {
                    site,
                    pending: pending.then(|| stamp.clone()),
                },
            );
            if changed {
                this.generation += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// One 16-byte frame of a stack artifact or record.
    pub(crate) fn frame(kind: u8, flags: u8, script: u32, position: u32, detail: u32) -> Vec<u8> {
        let mut bytes = vec![kind, flags, 0, 0];
        for value in [script, position, detail] {
            bytes.extend(value.to_le_bytes());
        }
        bytes
    }

    /// A stack artifact: synchronous frames innermost first, then the await
    /// chain and the task segments.
    pub(crate) fn stack_artifact(
        version: u16,
        sync: &[Vec<u8>],
        asyncs: &[Vec<u8>],
        segments: &[Vec<u8>],
    ) -> Vec<u8> {
        let recorded = sync.len() as u32;
        let mut a = 0x4b53_4252u32.to_le_bytes().to_vec();
        a.extend(version.to_le_bytes());
        a.extend([32, 0, 16, 0, 0, 0]);
        for value in [recorded, recorded, 0] {
            a.extend(value.to_le_bytes());
        }
        for value in [
            asyncs.len(),
            asyncs.len() + segments.len(),
            segments.len(),
            0,
        ] {
            a.extend((value as u16).to_le_bytes());
        }
        for part in sync.iter().chain(asyncs).chain(segments) {
            a.extend(part);
        }
        a
    }

    /// One 48-byte task segment of a version 2 stack artifact.
    pub(crate) fn segment(kind: u8, state: u8, recorded: u32, digest: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, state, 0, 0];
        bytes.extend(recorded.to_le_bytes());
        bytes.extend([0; 8]);
        bytes.extend(digest);
        bytes
    }

    /// A `script_identity` payload whose digest is that of `text`.
    pub(crate) fn identity_bytes(
        kind: u8,
        flags: u8,
        script: u32,
        (line, column): (u32, u32),
        realm: u64,
        text: &[u8],
    ) -> Vec<u8> {
        let mut p = vec![1, 0, 128, 0, kind, flags, 0, 0];
        for value in [script, line, column, 0] {
            p.extend(value.to_le_bytes());
        }
        p.extend(realm.to_le_bytes());
        p.extend((text.len() as u64).to_le_bytes());
        p.extend(Sha256::digest(text));
        p.resize(128, 0);
        p
    }

    fn record_bytes(
        state: u8,
        total: u32,
        recorded: u32,
        asyncs: u16,
        digest: [u8; 32],
    ) -> Vec<u8> {
        let mut p = vec![1, 0, 128, 0, state, 0x08, 0, 0];
        let omitted = total - recorded;
        if omitted != 0 {
            p[5] |= 0x02;
        }
        for value in [total, recorded, omitted] {
            p.extend(value.to_le_bytes());
        }
        p.extend(asyncs.to_le_bytes());
        p.extend(asyncs.to_le_bytes());
        p.extend(0u32.to_le_bytes());
        p.extend(1u32.to_le_bytes());
        p.extend(digest);
        p.extend(frame(1, 0, 7, 30, 21));
        p.resize(128, 0);
        p
    }
    fn artifact(id: &str, kind: &str, bytes: &[u8]) -> Value {
        json!({"artifact_id": id, "session_id": "9", "kind": kind,
            "url": format!("https://app.example.test/{id}.js"), "sha256": hex::encode(Sha256::digest(bytes))})
    }

    #[test]
    fn initiator_frames_resolve_alone_and_keep_settled_outcomes() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("blobs")).unwrap();
        let source = "let a = 1;\nfunction load() {\n  fetch('/x');\n}\n";
        let hash = hex::encode(Sha256::digest(source));
        std::fs::write(root.path().join(format!("blobs/{hash}.bin")), source).unwrap();
        let mut script = artifact("21", "javascript", source.as_bytes());
        script["byte_size"] = json!(source.len());
        script["content_path"] = json!(format!("blobs/{hash}.bin"));
        let at = source.find("fetch").unwrap() as u32;
        let start = source.find("() {").unwrap() as u32;
        let raw = |identity: Option<Vec<u8>>| {
            json!({"session_id": "9", "process_id": 41, "frame": hex::encode(frame(1, 0, 7, at, start)),
                "identity": identity.map(hex::encode)})
        };
        let mut document = json!({"requests": [
            {"initiator_frame": raw(Some(identity_bytes(1, 0x02, 7, (0, 0), 99, source.as_bytes())))},
            {"initiator_frame": Value::Null},
        ]});
        let mut frames = InitiatorFrames::default();
        assert!(frames.resolve_with(&mut document, root.path(), |_| vec![script.clone()]));
        let resolved = &document["requests"][0]["initiator_frame"];
        assert_eq!(
            (&resolved["status"], &resolved["line"], &resolved["column"]),
            (&json!("resolved"), &json!(3), &json!(3))
        );
        assert_eq!(resolved["function_name"], "load");
        assert_eq!(document["requests"][1]["initiator_frame"], Value::Null);
        // The kept outcome answers without the manifest; a missing identity is retried.
        let mut again = json!({"requests": [{"initiator_frame": raw(None)}]});
        frames.resolve_with(&mut again, root.path(), |_| Vec::new());
        assert_eq!(again["requests"][0]["initiator_frame"], *resolved);
        let mut missing = json!({"requests": [{"initiator_frame": raw(None)}]});
        missing["requests"][0]["initiator_frame"]["frame"] =
            json!(hex::encode(frame(1, 0, 8, 1, 0)));
        frames.resolve_with(&mut missing, root.path(), |_| Vec::new());
        assert_eq!(
            missing["requests"][0]["initiator_frame"]["reason"],
            "script_identity_missing"
        );
        assert_eq!(frames.0.len(), 1);
    }

    /// A store where one request and its renderer records are followed by
    /// more than one scan budget of newer traffic.
    fn store_with_newer_traffic(records: &[(u64, u64, &str, Vec<u8>)]) -> tempfile::TempDir {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let mut file = std::fs::File::create(root.path().join("events.jsonl")).unwrap();
        let mut sequence = 0u64;
        let mut write = |file: &mut std::fs::File,
                         process: u64,
                         request: u64,
                         kind: &str,
                         category: &str,
                         payload: &[u8],
                         pad: usize| {
            sequence += 1;
            let mut event = json!({"protocol_version":3,"session_id":"9",
                "sequence_number":sequence.to_string(),"monotonic_time_ns":sequence.to_string(),
                "navigation_id":"0","frame_id":"1","artifact_id":"0","parent_event_id":"0",
                "request_id":request.to_string(),"process_id":process,"thread_id":1,"tab_id":0,
                "category":category,"type":kind,"flags":0,"status_code":0,"error_code":0,
                "encoded_data_length":"0","decoded_body_length":"0","resource_type":0,
                "initiator_process_id":0,"initiator_request_id":0,"payload_encoding":"hex",
                "payload":hex::encode(payload),"payload_size":payload.len(),"payload_truncated":false});
            if pad != 0 {
                event["pad"] = json!("x".repeat(pad));
            }
            let mut line = event.to_string().into_bytes();
            line.push(b'\n');
            file.write_all(&line).unwrap();
            line.len() as u64
        };
        for (process, request, kind, payload) in records {
            write(&mut file, *process, *request, kind, "network", payload, 0);
        }
        let mut written = 0;
        while written <= event_query::SCAN_BYTES + (1 << 20) {
            written += write(&mut file, 1000, 0, "api_call", "wasm", &[], 3000);
        }
        root
    }

    fn caught_up(index: &Mutex<RequestIndex>) {
        for _ in 0..4 {
            index.blocking_lock().refresh().unwrap();
        }
    }

    #[test]
    fn a_stack_behind_newer_traffic_is_read_from_its_requests_bytes() {
        let stack = vec![1, 0, 128, 0, 2, 0, 0, 0]
            .into_iter()
            .chain(std::iter::repeat_n(0, 120))
            .collect::<Vec<u8>>();
        let root = store_with_newer_traffic(&[
            (42, 5, "request_initiated", Vec::new()),
            (42, 5, "request_initiator_stack", stack),
            (42, 6, "request_initiated", Vec::new()),
        ]);
        let store = root.path().join("events.jsonl");
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let index = Mutex::new(RequestIndex::new(&store));
        caught_up(&index);
        let read = |request| document(&store, &artifacts, &index, Some(9), 42, request).unwrap();

        let recorded = read(5);
        assert_eq!(recorded["status"], "recorded", "{recorded}");
        assert_eq!(recorded["coverage"]["scope"], "request_range");
        assert_eq!(recorded["coverage"]["complete"], true);

        // Its own bytes were read, so this absence is a fact.
        let absent = read(6);
        assert_eq!(absent["status"], "not_recorded", "{absent}");
        assert_eq!(absent["coverage"]["scope"], "request_range");

        // No row names this request and the store outgrows the scan.
        let unknown = read(7);
        assert_eq!(unknown["status"], "outside_scan", "{unknown}");
        assert_eq!(unknown["coverage"]["scope"], "bounded_range");
        assert_eq!(unknown["coverage"]["complete"], false);
        assert_eq!(unknown["coverage"]["budget_exhausted"], true);
    }

    /// Compiled script capture (protocol/native-compiled-scripts-v1.md) keeps
    /// inline text as `compiled_script` and eval text as `dynamic_javascript`.
    /// They hash the same UTF-8 source as the script identity, so a stored
    /// frame resolves to them when the walk kept no `stack_script` copy.
    #[test]
    fn stored_frames_resolve_to_compiled_script_sources() {
        use std::io::Write;
        let inline = "function send() {\n  return fetch('/a');\n}\nsend();\n";
        let evaled = "send()";
        let wrapped = "function wrap() { return send(); }\n";
        let frames = vec![
            frame(
                1,
                0,
                7,
                inline.find("fetch").unwrap() as u32,
                inline.find("() {").unwrap() as u32,
            ),
            frame(1, 0, 8, 0, 0),
            frame(
                1,
                0,
                9,
                wrapped.find("send").unwrap() as u32,
                wrapped.find("() {").unwrap() as u32,
            ),
        ];
        let stack = stack_artifact(1, &frames, &[], &[]);
        let mut record = record_bytes(1, 3, 3, 0, Sha256::digest(&stack).into());
        record[64..80].copy_from_slice(&frames[0]);

        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let mut events = std::fs::File::create(&store).unwrap();
        for (sequence, request, kind, payload) in [
            // Not retained by the walk (budget), eval and not retained, retained.
            (
                1,
                0,
                "script_identity",
                identity_bytes(1, 0x10, 7, (4, 0), 99, inline.as_bytes()),
            ),
            (
                2,
                0,
                "script_identity",
                identity_bytes(1, 0x11, 8, (0, 0), 99, evaled.as_bytes()),
            ),
            (
                3,
                0,
                "script_identity",
                identity_bytes(1, 0x02, 9, (0, 0), 99, wrapped.as_bytes()),
            ),
            (4, 5, "request_initiated", Vec::new()),
            (5, 5, "request_initiator_stack", record),
        ] {
            let event = json!({"protocol_version":3,"session_id":"9",
                "sequence_number":sequence.to_string(),"monotonic_time_ns":sequence.to_string(),
                "navigation_id":"0","frame_id":"1","artifact_id":"0","parent_event_id":"0",
                "request_id":request.to_string(),"process_id":42,"thread_id":1,"tab_id":0,
                "category":"network","type":kind,"flags":0,"status_code":0,"error_code":0,
                "encoded_data_length":"0","decoded_body_length":"0","resource_type":0,
                "initiator_process_id":0,"initiator_request_id":0,"payload_encoding":"hex",
                "payload":hex::encode(&payload),"payload_size":payload.len(),"payload_truncated":false});
            writeln!(events, "{event}").unwrap();
        }

        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(artifacts.join("blobs")).unwrap();
        let mut manifest = String::new();
        for (id, kind, origin, creator, bytes) in [
            ("1", "stack", "request_stack", "5", stack.as_slice()),
            (
                "2",
                "javascript",
                "compiled_script",
                "21",
                inline.as_bytes(),
            ),
            (
                "3",
                "javascript",
                "dynamic_javascript",
                "22",
                evaled.as_bytes(),
            ),
            ("4", "javascript", "stack_script", "5", wrapped.as_bytes()),
            (
                "5",
                "javascript",
                "compiled_script",
                "23",
                wrapped.as_bytes(),
            ),
        ] {
            let sha = hex::encode(Sha256::digest(bytes));
            std::fs::write(artifacts.join(format!("blobs/{sha}.bin")), bytes).unwrap();
            let mime = if kind == "stack" {
                "application/x-reb-stack"
            } else {
                "text/javascript"
            };
            let entry = json!({"protocol_version":1,"artifact_id":id,"session_id":"9",
                "navigation_id":"0","frame_id":"1","parent_artifact_id":"0","creator_event_id":creator,
                "execution_context_id":"99","capture_origin":origin,"kind":kind,
                "url":format!("https://app.example.test/{id}.js"),"mime_type":mime,
                "byte_size":bytes.len(),"sha256":sha,"sensitive":false,
                "content_path":format!("blobs/{sha}.bin")});
            manifest.push_str(&format!("{entry}\n"));
        }
        std::fs::write(artifacts.join("manifest.jsonl"), manifest).unwrap();

        let index = Mutex::new(RequestIndex::new(&store));
        caught_up(&index);
        let doc = document(&store, &artifacts, &index, Some(9), 42, 5).unwrap();
        assert_eq!(doc["frames_retained"], true, "{doc}");
        let f = &doc["frames"];
        let inline_frame = &f[0]["resolution"];
        assert_eq!(inline_frame["status"], "resolved", "{doc}");
        assert_eq!(inline_frame["artifact_id"], "2");
        assert_eq!(inline_frame["function_name"], "send");
        assert_eq!(inline_frame["artifact_line"], 2);
        assert_eq!(
            inline_frame["line"], 6,
            "the document line adds the start line"
        );
        assert_eq!(f[1]["eval"], true);
        assert_eq!(f[1]["resolution"]["status"], "resolved", "{doc}");
        assert_eq!(f[1]["resolution"]["artifact_id"], "3");
        // The same bytes under two origins: the newest is shown.
        assert_eq!(f[2]["resolution"]["artifact_id"], "5", "{doc}");
        assert_eq!(f[2]["resolution"]["function_name"], "wrap");
    }

    #[test]
    fn observation_sites_resolve_when_the_stack_holds_no_script() {
        use std::io::Write;
        let source = "let n = 0;\ndocument.body.onclick = function onTap(event) {\n  n += 1;\n};\n";
        let start = source.find("(event)").unwrap() as u32;
        let listener = |site: &[u8]| {
            let mut tail = vec![0, 1, 1, 0];
            tail.extend_from_slice(site);
            tail.push(5);
            tail.extend_from_slice(b"click");
            tail
        };
        let observation = |tail: &[u8]| {
            let mut payload = vec![1, 0, 128, 0, 2, 0x08, 0, 0];
            payload.resize(80, 0);
            payload.extend_from_slice(tail);
            payload.resize(128, 0);
            payload
        };
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let mut events = std::fs::File::create(&store).unwrap();
        for (sequence, category, kind, payload) in [
            (
                1,
                "network",
                "script_identity",
                identity_bytes(1, 0x10, 7, (0, 0), 99, source.as_bytes()),
            ),
            (
                2,
                "runtime",
                "listener_dispatch",
                observation(&listener(&frame(1, 0, 7, start, start))),
            ),
            (3, "network", "request_watch_match", observation(&[0, 1])),
            // A listener record whose event type is cut is refused.
            (
                4,
                "runtime",
                "listener_dispatch",
                observation(&[0, 1, 1, 0]),
            ),
        ] {
            let event = json!({"protocol_version":3,"session_id":"9",
                "sequence_number":sequence.to_string(),"monotonic_time_ns":sequence.to_string(),
                "navigation_id":"0","frame_id":"1","artifact_id":"0","parent_event_id":"0",
                "request_id":"0","process_id":42,"thread_id":1,"tab_id":0,
                "category":category,"type":kind,"flags":0,"payload_encoding":"hex",
                "payload":hex::encode(&payload),"payload_size":payload.len(),"payload_truncated":false});
            writeln!(events, "{event}").unwrap();
        }
        // Nine more scripts whose sources are digested but not retained.
        for script in 20..29u32 {
            let text = format!("// script {script}\n");
            let payload = identity_bytes(1, 0x10, script, (0, 0), 99, text.as_bytes());
            let event = json!({"protocol_version":3,"session_id":"9",
                "sequence_number":(script + 100).to_string(),"monotonic_time_ns":"1",
                "navigation_id":"0","frame_id":"1","artifact_id":"0","parent_event_id":"0",
                "request_id":"0","process_id":42,"thread_id":1,"tab_id":0,
                "category":"network","type":"script_identity","flags":0,"payload_encoding":"hex",
                "payload":hex::encode(&payload),"payload_size":payload.len(),"payload_truncated":false});
            writeln!(events, "{event}").unwrap();
        }
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(artifacts.join("blobs")).unwrap();
        let sha = hex::encode(Sha256::digest(source));
        std::fs::write(artifacts.join(format!("blobs/{sha}.bin")), source).unwrap();
        let entry = json!({"protocol_version":1,"artifact_id":"2","session_id":"9",
            "navigation_id":"0","frame_id":"1","parent_artifact_id":"0","creator_event_id":"1",
            "execution_context_id":"99","capture_origin":"compiled_script","kind":"javascript",
            "url":"https://app.example.test/app.js","mime_type":"text/javascript",
            "byte_size":source.len(),"sha256":sha,"sensitive":false,
            "content_path":format!("blobs/{sha}.bin")});
        std::fs::write(artifacts.join("manifest.jsonl"), format!("{entry}\n")).unwrap();
        let index = Mutex::new(RequestIndex::new(&store));
        caught_up(&index);
        let read = |sequence| {
            observation_document(&store, &artifacts, &index, Some(9), 42, sequence).unwrap()
        };

        let tap = read(2);
        assert_eq!(tap["status"], "recorded", "{tap}");
        assert_eq!(tap["state"], "no_script");
        assert_eq!(tap["frames"], json!([]));
        assert_eq!(tap["observation"]["type"], "listener_dispatch");
        assert_eq!(tap["observation"]["detail"]["event_type"], "click");
        let site = &tap["observation"]["site"]["resolution"];
        assert_eq!(site["status"], "resolved", "{tap}");
        assert_eq!(site["artifact_id"], "2");
        assert_eq!(site["artifact_line"], 2);
        assert_eq!(site["function_name"], "onTap");
        assert_eq!(tap["request"]["sequence_number"], "2");

        let matched = read(3);
        assert_eq!(matched["observation"]["type"], "request_watch_match");
        assert_eq!(matched["observation"]["site"], Value::Null);
        assert_eq!(read(4)["status"], "malformed");
        // A request stack is never answered as an observation.
        assert_eq!(read(1)["status"], "not_recorded");
        assert_eq!(read(9)["status"], "not_recorded");

        // The same records on an event page, as get_events and wait_for_events
        // return them: the object get_native_debugger lists, plus the site
        // resolved by the same frame resolution, and the stack's read.
        let raw: Vec<Value> = std::fs::read_to_string(&store)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let sites = std::sync::Mutex::new(ObservationSites::default());
        let annotate =
            |sites: &std::sync::Mutex<ObservationSites>, page: &mut [Value], newest: bool| {
                ObservationSites::annotate(sites, &store, &artifacts, &index, page, newest)
            };
        let fresh = || std::sync::Mutex::new(ObservationSites::default());
        let mut page = raw.clone();
        let work = annotate(&sites, &mut page, false);
        let decoded = &page[1]["debugger_observation"];
        let listed = crate::debugger_observation::decode(&page[1]).unwrap();
        for (key, value) in listed.as_object().unwrap() {
            assert_eq!(decoded[key], *value, "{key}");
        }
        assert_eq!(decoded["status"], "decoded");
        assert_eq!(
            decoded["site"], tap["observation"]["site"],
            "one resolver for both reads"
        );
        let site = &decoded["site"]["resolution"];
        assert_eq!(
            (&site["url"], &site["line"], &site["column"]),
            (
                &json!("https://app.example.test/app.js"),
                &json!(2),
                &json!(source.lines().nth(1).unwrap().find("(event)").unwrap() + 1)
            )
        );
        // stack_read is exactly the read's arguments; the operation is beside it.
        assert_eq!(
            decoded["stack_read"],
            json!({"session_id": "9", "process_id": 42, "observation_sequence": "2"})
        );
        assert_eq!(decoded["stack_read_operation"], "get_request_stack");
        assert_eq!(page[2]["debugger_observation"]["site"], Value::Null);
        assert_eq!(
            page[3]["debugger_observation"],
            json!({"status": "invalid"})
        );
        assert!(page[0].get("debugger_observation").is_none());
        for annotation in [&page[1], &page[2], &page[3]] {
            crate::validation::schema(
                "DebuggerObservationDecode",
                &annotation["debugger_observation"],
                500,
            )
            .unwrap();
        }
        assert_eq!(
            work,
            SiteWork {
                source_walks: 1,
                manifest_lines: 1,
                identity_reads: 1
            }
        );
        // A settled site is kept: the same page again reads nothing.
        let mut again = raw.clone();
        let work = annotate(&sites, &mut again, false);
        assert_eq!(
            work,
            SiteWork::default(),
            "a settled page reads no source, manifest or identity"
        );
        assert_eq!(
            again[1]["debugger_observation"],
            page[1]["debugger_observation"]
        );

        // Many sites in one script cost one walk over its source: the work is
        // per script, not per site. A position past the source keeps a reason.
        let record = |script: u32, position: u32, sequence: u32| {
            let mut event = raw[1].clone();
            let payload = observation(&listener(&frame(1, 0, script, position, position)));
            event["payload"] = json!(hex::encode(&payload));
            event["sequence_number"] = json!(sequence.to_string());
            event
        };
        let mut many: Vec<Value> = (0..200u32)
            .map(|n| record(7, start + n, 1000 + n))
            .collect();
        let work = annotate(&fresh(), &mut many, false);
        assert_eq!(work.source_walks, 1, "{work:?}");
        let status = |event: &Value| event["debugger_observation"]["site"]["resolution"].clone();
        assert_eq!(status(&many[0])["status"], "resolved");
        assert_eq!(
            status(&many[199]),
            json!({"status": "unresolved", "reason": "position_outside_source"})
        );
        assert!(
            many.iter()
                .all(|event| status(event)["status"] != "deferred"),
            "no site is left for a later read"
        );

        // A page whose sites name more scripts than one read loads keeps the
        // rest raw with source_limit, newest first on a backward page: the
        // oldest record's script is the one left.
        let mut scripts: Vec<Value> = (20..29u32)
            .map(|script| record(script, 1, 2000 + script))
            .collect();
        let work = annotate(&fresh(), &mut scripts, true);
        assert_eq!(work.source_walks, 0, "no source of these is retained");
        let left = PAGE_SOURCES..scripts.len();
        for (at, event) in scripts.iter().rev().enumerate() {
            let expected = if left.contains(&at) {
                json!({"status": "deferred", "reason": "source_limit"})
            } else {
                json!({"status": "unresolved", "reason": "source_not_retained"})
            };
            assert_eq!(status(event), expected, "newest first: {at}");
        }
        assert_eq!(scripts[0]["debugger_observation"]["site"]["script_id"], 20);
        crate::validation::schema(
            "DebuggerObservationDecode",
            &scripts[0]["debugger_observation"],
            500,
        )
        .unwrap();
        // Forward, the newest are left instead.
        let mut forward: Vec<Value> = (20..29u32)
            .map(|script| record(script, 1, 2000 + script))
            .collect();
        annotate(&fresh(), &mut forward, false);
        assert_eq!(status(&forward[0])["reason"], "source_not_retained");
        assert_eq!(status(&forward[8])["reason"], "source_limit");

        // An unreadable manifest leaves the records and names why; nothing
        // unsettled is kept, so the next read tries again.
        std::fs::write(artifacts.join("manifest.jsonl"), "not json\n").unwrap();
        let mut failed = raw[..2].to_vec();
        let failing = fresh();
        annotate(&failing, &mut failed, false);
        assert_eq!(
            status(&failed[1]),
            json!({"status": "deferred", "reason": "site_read_failed"})
        );
        assert_eq!(
            failed[1]["debugger_observation"]["detail"]["event_type"],
            "click"
        );
        assert!(failing.lock().unwrap().kept.is_empty());
    }

    /// A listener record of renderer 42 naming `script` at `start`.
    fn listener_record(sequence: u64, script: u32, start: u32) -> Value {
        let mut payload = vec![1, 0, 128, 0, 2, 0x08, 0, 0];
        payload.resize(80, 0);
        payload.extend([0, 1, 1, 0]);
        payload.extend(frame(1, 0, script, start, start));
        payload.push(5);
        payload.extend(b"click");
        payload.resize(128, 0);
        store_event(sequence, "runtime", "listener_dispatch", &payload)
    }

    fn store_event(sequence: u64, category: &str, kind: &str, payload: &[u8]) -> Value {
        json!({"protocol_version":3,"session_id":"9",
            "sequence_number":sequence.to_string(),"monotonic_time_ns":sequence.to_string(),
            "navigation_id":"0","frame_id":"1","artifact_id":"0","parent_event_id":"0",
            "request_id":"0","process_id":42,"thread_id":1,"tab_id":0,
            "category":category,"type":kind,"flags":0,"payload_encoding":"hex",
            "payload":hex::encode(payload),"payload_size":payload.len(),"payload_truncated":false})
    }

    fn write_store(path: &Path, events: &[Value]) {
        let text: String = events.iter().map(|event| format!("{event}\n")).collect();
        std::fs::write(path, text).unwrap();
    }

    /// A compiled-script artifact line for `source`, its blob written.
    fn source_artifact(artifacts: &Path, id: &str, url: &str, source: &str) -> String {
        let sha = hex::encode(Sha256::digest(source));
        std::fs::create_dir_all(artifacts.join("blobs")).unwrap();
        std::fs::write(artifacts.join(format!("blobs/{sha}.bin")), source).unwrap();
        format!(
            "{}\n",
            json!({"protocol_version":1,"artifact_id":id,"session_id":"9","navigation_id":"0",
            "frame_id":"1","parent_artifact_id":"0","creator_event_id":"1","execution_context_id":"99",
            "capture_origin":"compiled_script","kind":"javascript","url":url,"mime_type":"text/javascript",
            "byte_size":source.len(),"sha256":sha,"sensitive":false,"content_path":format!("blobs/{sha}.bin")})
        )
    }

    fn append(path: &Path, text: &str) {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }

    /// Review round 2, A: a site whose source has not landed is kept with
    /// what it waits for. Read again while nothing moved, it costs nothing;
    /// an appended manifest costs its new lines only.
    #[test]
    fn pending_sites_are_read_again_only_after_the_manifest_or_index_moves() {
        let root = tempfile::tempdir().unwrap();
        let (store, artifacts) = (
            root.path().join("events.jsonl"),
            root.path().join("artifacts"),
        );
        let source = "document.body.onclick = function onTap(event) {\n  return 1;\n};\n";
        let start = source.find("(event)").unwrap() as u32;
        write_store(
            &store,
            &[
                store_event(
                    1,
                    "network",
                    "script_identity",
                    &identity_bytes(1, 0x02, 7, (0, 0), 99, source.as_bytes()),
                ),
                listener_record(2, 7, start),
            ],
        );
        let manifest = artifacts.join("manifest.jsonl");
        for n in 0..50 {
            append(
                &manifest,
                &source_artifact(
                    &artifacts,
                    &format!("{}", 500 + n),
                    "https://cdn.test/other.js",
                    &format!("// other {n}\n"),
                ),
            );
        }
        let index = Mutex::new(RequestIndex::new(&store));
        caught_up(&index);
        let sites = std::sync::Mutex::new(ObservationSites::default());
        let read = || {
            let mut page = vec![listener_record(2, 7, start)];
            let work =
                ObservationSites::annotate(&sites, &store, &artifacts, &index, &mut page, true);
            (
                work,
                page[0]["debugger_observation"]["site"]["resolution"].clone(),
            )
        };
        let (work, site) = read();
        assert_eq!(
            site,
            json!({"status": "unresolved", "reason": "source_artifact_missing"})
        );
        assert_eq!(
            work,
            SiteWork {
                source_walks: 0,
                manifest_lines: 50,
                identity_reads: 1
            }
        );
        for _ in 0..3 {
            let (work, again) = read();
            assert_eq!(
                work,
                SiteWork::default(),
                "nothing moved: no manifest parse, no identity read"
            );
            assert_eq!(again, site);
        }
        // Another artifact lands: only that line is parsed.
        append(
            &manifest,
            &source_artifact(&artifacts, "600", "https://cdn.test/late.js", "// late\n"),
        );
        let (work, still) = read();
        assert_eq!(
            work,
            SiteWork {
                source_walks: 0,
                manifest_lines: 1,
                identity_reads: 1
            }
        );
        assert_eq!(still, site);
        assert_eq!(read().0, SiteWork::default());
        // The source lands: its line, then its one walk, settles the site.
        append(
            &manifest,
            &source_artifact(&artifacts, "601", "https://app.test/app.js", source),
        );
        let (work, resolved) = read();
        assert_eq!(
            work,
            SiteWork {
                source_walks: 1,
                manifest_lines: 1,
                identity_reads: 1
            }
        );
        assert_eq!(
            (&resolved["status"], &resolved["function_name"]),
            (&json!("resolved"), &json!("onTap"))
        );
        assert_eq!(read().0, SiteWork::default(), "settled");
    }

    /// Review round 2, A: past the index's identity cap, a site whose identity
    /// it does not hold is answered from the index alone, never by a 64 MiB
    /// store scan per read, and kept until the index moves.
    #[test]
    fn an_identity_past_the_index_cap_costs_no_store_scan() {
        let root = tempfile::tempdir().unwrap();
        let (store, artifacts) = (
            root.path().join("events.jsonl"),
            root.path().join("artifacts"),
        );
        let mut events: Vec<Value> = (0..16_400u32)
            .map(|n| {
                let mut payload = vec![1, 0, 128, 0, 1, 0x08, 0, 0];
                for value in [1000 + n, 0, 0, 0] {
                    payload.extend(value.to_le_bytes());
                }
                payload.extend(99u64.to_le_bytes());
                payload.resize(128, 0);
                store_event(u64::from(n) + 1, "network", "script_identity", &payload)
            })
            .collect();
        events.push(listener_record(20_000, 7, 100));
        write_store(&store, &events);
        std::fs::create_dir_all(&artifacts).unwrap();
        let index = Mutex::new(RequestIndex::new(&store));
        caught_up(&index);
        let sites = std::sync::Mutex::new(ObservationSites::default());
        let read = || {
            let mut page = vec![listener_record(20_000, 7, 100)];
            let work =
                ObservationSites::annotate(&sites, &store, &artifacts, &index, &mut page, true);
            (
                work,
                page[0]["debugger_observation"]["site"]["resolution"].clone(),
            )
        };
        let started = std::time::Instant::now();
        let (work, site) = read();
        assert_eq!(
            site,
            json!({"status": "unresolved", "reason": "script_identity_outside_scan"})
        );
        assert_eq!(
            work,
            SiteWork {
                source_walks: 0,
                manifest_lines: 0,
                identity_reads: 1
            }
        );
        assert_eq!(
            read().0,
            SiteWork::default(),
            "kept while the index has not moved"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(60));
    }

    /// Review round 2, B: a store replaced under the same name (same session,
    /// renderer and script IDs, other sources) drops every kept site before
    /// any is used, so a page never presents the old function as resolved.
    #[test]
    fn a_replaced_store_drops_kept_sites_before_any_is_used() {
        let root = tempfile::tempdir().unwrap();
        let (store, artifacts) = (
            root.path().join("events.jsonl"),
            root.path().join("artifacts"),
        );
        let manifest = artifacts.join("manifest.jsonl");
        let version = |name: &str, script: u32| {
            format!("document.body.onclick = function {name}(event) {{ return {script}; }};\n")
        };
        let (a, b) = (version("handlerA", 7), version("renameBB", 7));
        let start = a.find("(event)").unwrap() as u32;
        assert_eq!(start, b.find("(event)").unwrap() as u32);
        let records = |source: &str| {
            vec![
                store_event(
                    1,
                    "network",
                    "script_identity",
                    &identity_bytes(1, 0x02, 7, (0, 0), 99, source.as_bytes()),
                ),
                listener_record(2, 7, start),
                listener_record(3, 7, start + 1),
            ]
        };
        write_store(&store, &records(&a));
        append(
            &manifest,
            &source_artifact(&artifacts, "360", "https://app.test/bundle0.js?v=1", &a),
        );
        let index = Mutex::new(RequestIndex::new(&store));
        caught_up(&index);
        let sites = std::sync::Mutex::new(ObservationSites::default());
        let read = |page: &mut Vec<Value>| {
            ObservationSites::annotate(&sites, &store, &artifacts, &index, page, true);
            page.iter()
                .map(|e| e["debugger_observation"]["site"]["resolution"].clone())
                .collect::<Vec<_>>()
        };
        let first = read(&mut vec![listener_record(2, 7, start)]);
        assert_eq!(
            (&first[0]["function_name"], &first[0]["artifact_id"]),
            (&json!("handlerA"), &json!("360"))
        );
        // Store B is written over the same file; its source lands as artifact 900.
        write_store(&store, &records(&b));
        append(
            &manifest,
            &source_artifact(&artifacts, "900", "https://app.test/bundle0.js?v=2", &b),
        );
        // A page whose only site is kept, then one with a kept and a new site.
        for mut page in [
            vec![listener_record(2, 7, start)],
            vec![
                listener_record(2, 7, start),
                listener_record(3, 7, start + 1),
            ],
        ] {
            let sites = read(&mut page);
            assert_eq!(sites[0]["function_name"], "renameBB", "{}", sites[0]);
            for site in sites {
                assert_eq!(
                    (&site["artifact_id"], &site["url"]),
                    (&json!("900"), &json!("https://app.test/bundle0.js?v=2")),
                    "{site}"
                );
            }
        }
        let direct = observation_document(&store, &artifacts, &index, Some(9), 42, 2).unwrap();
        assert_eq!(
            direct["observation"]["site"]["resolution"]["function_name"],
            "renameBB"
        );
    }

    /// One listener on script 7 and the source it names, as two stores whose
    /// sources differ only in the function's name.
    struct TwoStores {
        root: tempfile::TempDir,
        store: std::path::PathBuf,
        artifacts: std::path::PathBuf,
        a: String,
        b: String,
        start: u32,
    }

    impl TwoStores {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let (store, artifacts) = (
                root.path().join("events.jsonl"),
                root.path().join("artifacts"),
            );
            let version = |name: &str| {
                format!("document.body.onclick = function {name}(event) {{ return 7; }};\n")
            };
            let (a, b) = (version("handlerA"), version("renameBB"));
            let start = a.find("(event)").unwrap() as u32;
            Self {
                root,
                store,
                artifacts,
                a,
                b,
                start,
            }
        }

        /// Twelve listeners of another script first, so the identity record
        /// lies past the first 4 KiB, then the listener and its identity.
        fn records(&self, source: &str) -> Vec<Value> {
            let mut records: Vec<Value> = (1..=12).map(|n| listener_record(n, 8, 0)).collect();
            records.push(listener_record(13, 7, self.start));
            records.push(store_event(
                14,
                "network",
                "script_identity",
                &identity_bytes(1, 0x02, 7, (0, 0), 99, source.as_bytes()),
            ));
            records
        }

        fn site(
            &self,
            sites: &std::sync::Mutex<ObservationSites>,
            index: &Mutex<RequestIndex>,
        ) -> Value {
            let mut page = vec![listener_record(13, 7, self.start)];
            ObservationSites::annotate(sites, &self.store, &self.artifacts, index, &mut page, true);
            page[0]["debugger_observation"]["site"]["resolution"].clone()
        }
    }

    fn named(site: &Value) -> (Value, Value, Value) {
        (
            site["function_name"].clone(),
            site["artifact_id"].clone(),
            site["url"].clone(),
        )
    }

    /// Review round 3, 1: a store rewritten in place with the same length,
    /// inode and first 4 KiB, its identity record later in the file naming
    /// other bytes, drops the kept site: the mark anchors the bytes before
    /// the length last read as well as the first ones.
    #[test]
    fn a_store_rewritten_past_its_first_bytes_drops_kept_sites() {
        let two = TwoStores::new();
        write_store(&two.store, &two.records(&two.a));
        append(
            &two.artifacts.join("manifest.jsonl"),
            &source_artifact(
                &two.artifacts,
                "360",
                "https://app.test/bundle0.js?v=1",
                &two.a,
            ),
        );
        let index = Mutex::new(RequestIndex::new(&two.store));
        caught_up(&index);
        let sites = std::sync::Mutex::new(ObservationSites::default());
        assert_eq!(
            named(&two.site(&sites, &index)),
            (
                json!("handlerA"),
                json!("360"),
                json!("https://app.test/bundle0.js?v=1")
            )
        );
        let (before, after) = (
            std::fs::read(&two.store).unwrap(),
            two.records(&two.b)
                .iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>(),
        );
        assert_eq!(before.len(), after.len());
        assert_eq!(before[..MARK_HEAD], after.as_bytes()[..MARK_HEAD]);
        let inode = std::fs::metadata(&two.store).map(|m| std::os::unix::fs::MetadataExt::ino(&m));
        std::fs::write(&two.store, &after).unwrap();
        assert_eq!(
            inode.unwrap(),
            std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&two.store).unwrap())
        );
        append(
            &two.artifacts.join("manifest.jsonl"),
            &source_artifact(
                &two.artifacts,
                "900",
                "https://app.test/bundle0.js?v=2",
                &two.b,
            ),
        );
        assert_eq!(
            named(&two.site(&sites, &index)),
            (
                json!("renameBB"),
                json!("900"),
                json!("https://app.test/bundle0.js?v=2")
            )
        );
    }

    /// Review round 3, 2: a settled site is a fact of the artifacts it was
    /// read from too. An artifacts directory replaced by one that names the
    /// same bytes under another ID and URL, or no longer holds them, drops
    /// the kept site before it is used, and the manifest's tag changes even
    /// when its length does not.
    #[test]
    fn a_replaced_manifest_drops_kept_sites_before_any_is_used() {
        let two = TwoStores::new();
        write_store(&two.store, &two.records(&two.a));
        let index = Mutex::new(RequestIndex::new(&two.store));
        caught_up(&index);
        let replace = |id: &str, url: &str, source: &str| {
            let old = two.root.path().join("artifacts.old");
            let _ = std::fs::remove_dir_all(&old);
            if two.artifacts.exists() {
                std::fs::rename(&two.artifacts, &old).unwrap();
            }
            let line = source_artifact(&two.artifacts, id, url, source);
            append(&two.artifacts.join("manifest.jsonl"), &line);
        };
        let first = || replace("360", "https://app.test/bundle0.js?v=1", &two.a);
        // Same bytes, another artifact ID and URL of the same lengths.
        first();
        let sites = std::sync::Mutex::new(ObservationSites::default());
        assert_eq!(named(&two.site(&sites, &index)).1, json!("360"));
        let tag = manifest_tag(&two.artifacts);
        replace("900", "https://app.test/bundle0.js?v=2", &two.a);
        assert_ne!(manifest_tag(&two.artifacts), tag);
        assert_eq!(
            named(&two.site(&sites, &index)),
            (
                json!("handlerA"),
                json!("900"),
                json!("https://app.test/bundle0.js?v=2")
            )
        );
        // The same bytes no longer retained: another script's source only.
        first();
        let sites = std::sync::Mutex::new(ObservationSites::default());
        assert_eq!(named(&two.site(&sites, &index)).1, json!("360"));
        replace("900", "https://app.test/bundle0.js?v=2", &two.b);
        assert_eq!(
            two.site(&sites, &index),
            json!({"status": "unresolved", "reason": "source_artifact_missing"})
        );
    }

    /// Review round 3, 4: when another read applied fewer manifest lines than
    /// this one parsed, the pending outcome waits on the lines its lookups
    /// covered, so the next read parses the rest and finds the source.
    #[test]
    fn a_pending_site_waits_on_the_manifest_lines_its_lookups_covered() {
        let two = TwoStores::new();
        write_store(&two.store, &two.records(&two.a));
        let manifest = two.artifacts.join("manifest.jsonl");
        append(
            &manifest,
            &source_artifact(
                &two.artifacts,
                "500",
                "https://cdn.test/other.js",
                "// other\n",
            ),
        );
        let index = std::sync::Arc::new(Mutex::new(RequestIndex::new(&two.store)));
        caught_up(&index);
        let sites = std::sync::Arc::new(std::sync::Mutex::new(ObservationSites::default()));
        let missing = json!({"status": "unresolved", "reason": "source_artifact_missing"});
        assert_eq!(two.site(&sites, &index), missing);
        let parsed = std::fs::metadata(&manifest).unwrap().len();
        append(
            &manifest,
            &source_artifact(
                &two.artifacts,
                "501",
                "https://cdn.test/late.js",
                "// late\n",
            ),
        );
        let shorter = std::fs::metadata(&manifest).unwrap().len();
        append(
            &manifest,
            &source_artifact(&two.artifacts, "601", "https://app.test/app.js", &two.a),
        );
        // A second read that parsed only the next line applies it first.
        let (other, root) = (sites.clone(), two.artifacts.clone());
        AFTER_MANIFEST_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let (mut records, _) = evidence::manifest_from(&root, parsed).unwrap();
                records.truncate(1);
                let mark = FileMark::read(&root.join("manifest.jsonl"), None)
                    .unwrap()
                    .0;
                let mut other = other.lock().unwrap();
                assert_eq!(
                    other.manifest.take(parsed, records, shorter, mark).unwrap(),
                    shorter
                );
            }));
        });
        assert_eq!(two.site(&sites, &index), missing);
        assert!(AFTER_MANIFEST_READ.with(|hook| hook.borrow().is_none()));
        let site = two.site(&sites, &index);
        assert_eq!(
            named(&site),
            (
                json!("handlerA"),
                json!("601"),
                json!("https://app.test/app.js")
            ),
            "{site}"
        );
    }

    /// Review round 3, 6: a store another read finds replaced while this one
    /// reads fails this read's sites as `site_read_failed`, none published.
    /// A store another read finds only grown costs nothing.
    #[test]
    fn a_store_replaced_mid_read_fails_its_sites_and_one_grown_does_not() {
        for replaced in [true, false] {
            let two = TwoStores::new();
            write_store(&two.store, &two.records(&two.a));
            append(
                &two.artifacts.join("manifest.jsonl"),
                &source_artifact(
                    &two.artifacts,
                    "360",
                    "https://app.test/bundle0.js?v=1",
                    &two.a,
                ),
            );
            let index = std::sync::Arc::new(Mutex::new(RequestIndex::new(&two.store)));
            caught_up(&index);
            let sites = std::sync::Arc::new(std::sync::Mutex::new(ObservationSites::default()));
            let (other, other_index) = (sites.clone(), index.clone());
            let (store, artifacts, b_records) = (
                two.store.clone(),
                two.artifacts.clone(),
                two.records(&two.b),
            );
            AFTER_MANIFEST_READ.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    if replaced {
                        let next = store.with_extension("next");
                        write_store(&next, &b_records);
                        std::fs::rename(&next, &store).unwrap();
                    } else {
                        append(&store, &format!("{}\n", listener_record(15, 8, 0)));
                    }
                    let mut page = vec![listener_record(15, 8, 0)];
                    ObservationSites::annotate(
                        &other,
                        &store,
                        &artifacts,
                        &other_index,
                        &mut page,
                        true,
                    );
                }));
            });
            let site = two.site(&sites, &index);
            if replaced {
                assert_eq!(
                    site,
                    json!({"status": "deferred", "reason": "site_read_failed"}),
                    "{site}"
                );
                // Only the other read's site, from the new store, is kept.
                let kept = &sites.lock().unwrap().kept;
                assert!(
                    kept.values()
                        .all(|kept| kept.site["resolution"]["function_name"].is_null())
                );
            } else {
                assert_eq!(named(&site).0, json!("handlerA"), "{site}");
            }
        }
    }

    #[test]
    fn an_identity_outside_the_scan_is_not_reported_as_missing() {
        let identity = identity_bytes(1, 0x02, 7, (1, 1), 99, b"x");
        let root = store_with_newer_traffic(&[
            (42, 0, "script_identity", identity),
            (42, 5, "request_initiated", Vec::new()),
        ]);
        let store = root.path().join("events.jsonl");
        let stack = json!({"session_id": "9"});

        // Before the index reaches the end, a miss is not reported as a fact.
        let behind = Mutex::new(RequestIndex::new(&store));
        let (found, known) = stored_identities(&store, &behind, &stack, 43).unwrap();
        assert!(found.is_empty());
        assert!(!known);

        // The caught-up index holds every identity of the session.
        let index = Mutex::new(RequestIndex::new(&store));
        caught_up(&index);
        let (found, known) = stored_identities(&store, &index, &stack, 42).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found.contains_key(&(42, 0, 7)));
        assert!(known);

        let mut document = json!({
            "frames": [{"resolution": {"reason": "script_identity_missing"}},
                {"resolution": {"reason": "source_unavailable"}}],
            "task_segments": [{"frames": [{"resolution": {"reason": "script_identity_missing"}}]}],
        });
        mark_identities_outside_scan(&mut document);
        assert_eq!(
            document["frames"][0]["resolution"]["reason"],
            "script_identity_outside_scan"
        );
        assert_eq!(
            document["frames"][1]["resolution"]["reason"],
            "source_unavailable"
        );
        assert_eq!(
            document["task_segments"][0]["frames"][0]["resolution"]["reason"],
            "script_identity_outside_scan"
        );
    }

    #[test]
    fn frame_counts_past_their_limits_are_rejected_without_overflow() {
        assert!(decode_record(&record_bytes(1, u32::MAX, u32::MAX, 1, [1; 32])).is_none());
    }

    #[test]
    fn frames_resolve_through_identities_and_retained_sources() {
        let inline = "<x>\nfunction send(body) {\n  return fetch('/a', body);\n}\nconst run = () => send(1);\n";
        let send_at = inline.find('(').unwrap() as u32;
        let fetch_at = inline.find("fetch").unwrap() as u32;
        let run_at = inline.find("() =>").unwrap() as u32;
        let call_at = inline.rfind("send").unwrap() as u32;
        let evaled = "eval_target()";
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        // A name section naming function 3 "$encrypt".
        let names = [vec![1u8], vec![10, 1, 3, 7], b"encrypt".to_vec()].concat();
        let custom = [vec![4u8], b"name".to_vec(), names].concat();
        wasm.push(0);
        wasm.push(custom.len() as u8);
        wasm.extend(custom);
        let frames = vec![
            frame(1, 0, 7, fetch_at, send_at),
            frame(2, 0, 30, 0x2a1, 3),
            frame(1, 0, 8, 0, 0),
            frame(1, 0, 7, call_at, run_at),
            frame(1, 0, 40, 5, 0),
            frame(3, 0, 7, call_at, run_at),
            vec![4, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
        ];
        let stack = stack_artifact(1, &frames[..5], &frames[5..], &[]);
        let digest: [u8; 32] = Sha256::digest(&stack).into();
        let mut bytes = record_bytes(1, 5, 5, 2, digest);
        bytes[64..80].copy_from_slice(&frames[0]);
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        let record = decode_record(&bytes).expect("valid record");
        let mut deeper = stack.clone();
        deeper[12] = 6;
        assert!(
            decode_artifact(&deeper, &record, 4).is_none(),
            "depth must agree"
        );
        let mut identities = HashMap::new();
        for (script, payload) in [
            (
                7,
                identity_bytes(1, 0x02, 7, (10, 4), 99, inline.as_bytes()),
            ),
            (8, identity_bytes(1, 0x03, 8, (0, 0), 99, evaled.as_bytes())),
            (30, identity_bytes(2, 0, 30, (0, 0), 99, &wasm)),
            (40, identity_bytes(1, 0x11, 40, (0, 0), 99, b"not retained")),
        ] {
            let (isolate, id, identity) = decode_identity(&payload).expect("identity");
            assert_eq!((isolate, id), (0, script));
            identities.insert((4, isolate, id), identity);
        }
        let artifacts = vec![
            artifact("1", "stack", &stack),
            artifact("2", "javascript", inline.as_bytes()),
            artifact("3", "javascript", evaled.as_bytes()),
            artifact("4", "wasm", &wasm),
        ];
        let contents: HashMap<String, Vec<u8>> = [
            ("1", stack.clone()),
            ("2", inline.as_bytes().to_vec()),
            ("3", evaled.as_bytes().to_vec()),
            ("4", wasm.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let read =
            |a: &Value, _limit: usize| Ok(contents[a["artifact_id"].as_str().unwrap()].clone());
        let event = json!({"session_id": "9", "process_id": 4, "request_id": "3",
            "frame_id": "5", "sequence_number": "12", "parent_event_id": "11"});
        let doc = resolve(&event, &record, &identities, &artifacts, &read);
        assert_eq!(doc["state"], "captured");
        assert_eq!(doc["frames_retained"], true);
        let f = &doc["frames"];
        assert_eq!(f[0]["resolution"]["function_name"], "send");
        assert_eq!(f[0]["resolution"]["artifact_line"], 3);
        assert_eq!(f[0]["resolution"]["artifact_column"], 10);
        assert_eq!(
            f[0]["resolution"]["line"], 13,
            "document line adds the start line"
        );
        assert_eq!(f[1]["kind"], "wasm");
        assert_eq!(f[1]["resolution"]["function_name"], "encrypt");
        assert_eq!(f[1]["module_offset"], 0x2a1);
        assert_eq!(f[2]["eval"], true);
        assert_eq!(f[2]["resolution"]["artifact_id"], "3");
        assert_eq!(f[2]["resolution"]["column"], 1);
        assert_eq!(f[3]["resolution"]["function_name"], "run");
        assert_eq!(f[4]["eval"], true, "a Metadata only eval frame says why");
        assert_eq!(f[4]["resolution"]["reason"], "source_not_retained");
        assert_eq!(f[5]["kind"], "await");
        assert_eq!(f[5]["async"], true);
        assert_eq!(f[6]["kind"], "promise_all");
        assert_eq!(doc["async_callers_not_shown"][0], "timers");

        // Without the frames artifact only the innermost frame is known.
        let doc = resolve(&event, &record, &identities, &artifacts[1..], &read);
        assert_eq!(doc["frames_retained"], false);
        assert_eq!(doc["frames"].as_array().unwrap().len(), 1);
        // Without identities nothing is guessed.
        let doc = resolve(&event, &record, &HashMap::new(), &artifacts, &read);
        assert_eq!(
            doc["frames"][0]["resolution"]["reason"],
            "script_identity_missing"
        );
    }

    #[test]
    fn task_chains_resolve_each_scheduling_stack() {
        let source =
            "function schedule() {\n  setTimeout(send, 5);\n}\nfunction send() { fetch('/b'); }\n";
        let at = |text: &str| source.find(text).unwrap() as u32;
        let schedule = frame(1, 0, 7, at("setTimeout"), at("() {"));
        let timer = stack_artifact(1, std::slice::from_ref(&schedule), &[], &[]);
        let timer_digest: [u8; 32] = Sha256::digest(&timer).into();
        let send = frame(1, 0, 7, at("fetch"), at("() { fetch"));
        let mut stack = stack_artifact(
            2,
            std::slice::from_ref(&send),
            &[],
            &[segment(1, 1, 1, &timer_digest), segment(9, 6, 0, &[0; 32])],
        );
        // The task chain was cut.
        stack[10] = 0x08;
        let digest: [u8; 32] = Sha256::digest(&stack).into();
        let mut bytes = record_bytes(1, 1, 1, 0, digest);
        bytes[0] = 2;
        bytes[5] = 0x08;
        bytes[6..8].copy_from_slice(&2u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&2u16.to_le_bytes());
        bytes[64..80].copy_from_slice(&send);
        let record = decode_record(&bytes).expect("version 2 record");
        let mut v1 = bytes.clone();
        v1[0] = 1;
        assert!(decode_record(&v1).is_none(), "version 1 has no task chain");
        let (_, _, identity) =
            decode_identity(&identity_bytes(1, 0x02, 7, (0, 0), 99, source.as_bytes())).unwrap();
        let identities = HashMap::from([((4, 0, 7), identity)]);
        let artifacts = vec![
            artifact("1", "stack", &stack),
            artifact("2", "stack", &timer),
            artifact("3", "javascript", source.as_bytes()),
        ];
        assert_eq!(segment_digests(&stack), vec![hex::encode(timer_digest)]);
        let contents: HashMap<&str, Vec<u8>> = HashMap::from([
            ("1", stack.clone()),
            ("2", timer.clone()),
            ("3", source.as_bytes().to_vec()),
        ]);
        let read =
            |a: &Value, _limit: usize| Ok(contents[a["artifact_id"].as_str().unwrap()].clone());
        let event = json!({"session_id": "9", "process_id": 4, "request_id": "3",
            "frame_id": "5", "sequence_number": "12", "parent_event_id": "11"});
        let doc = resolve(&event, &record, &identities, &artifacts, &read);
        let chain = &doc["task_segments"];
        assert_eq!(doc["frames"][0]["resolution"]["function_name"], "send");
        assert_eq!(
            (&chain[0]["kind"], &chain[0]["frames_retained"]),
            (&json!("set_timeout"), &json!(true))
        );
        assert_eq!(
            chain[0]["frames"][0]["resolution"]["function_name"],
            "schedule"
        );
        assert_eq!(chain[0]["frames"][0]["resolution"]["line"], 2);
        assert_eq!(
            (&chain[1]["kind"], &chain[1]["state"]),
            (&json!("microtask"), &json!("not_recorded"))
        );
        assert_eq!(doc["task_chain_cut"], true);
        assert_eq!(
            doc["async_callers_not_shown"],
            json!(["MessagePort and worker messages"])
        );
        // A scheduling stack that was not retained keeps its kind, never frames.
        let doc = resolve(
            &event,
            &record,
            &identities,
            &[artifacts[0].clone(), artifacts[2].clone()],
            &read,
        );
        assert_eq!(doc["task_segments"][0]["frames_retained"], false);
        assert_eq!(doc["task_segments"][0]["frames"], json!([]));

        // A navigation record is the same stack plus its kind and target frame.
        let mut navigation = bytes.clone();
        navigation[80] = 3;
        navigation[88..96].copy_from_slice(&0x5151u64.to_le_bytes());
        let (decoded, kind, target) = decode_navigation(&navigation).expect("navigation");
        assert_eq!((decoded, kind, target), (record, "window_open", 0x5151));
        for (byte, value) in [(80, 0u8), (80, 5), (84, 1), (100, 1), (0, 1), (4, 2)] {
            let mut bad = navigation.clone();
            bad[byte] = value;
            assert!(decode_navigation(&bad).is_none(), "navigation byte {byte}");
        }
        let mut no_target = navigation.clone();
        no_target[88..96].fill(0);
        assert!(decode_navigation(&no_target).is_none());
    }

    /// A version 3 artifact: the scoped header, the frames, then the segments.
    pub(crate) fn scoped_artifact(
        process: u32,
        thread: u8,
        key: u64,
        frames: &[Vec<u8>],
        segments: &[Vec<u8>],
        flags: u8,
    ) -> Vec<u8> {
        let recorded = frames.len() as u32;
        let mut a = 0x4b53_4252u32.to_le_bytes().to_vec();
        a.extend([3, 0, 48, 0, 16, 0, flags, 0]);
        a.extend([recorded, recorded, 0].iter().flat_map(|v| v.to_le_bytes()));
        let chain = segments.len() as u16;
        a.extend([0u16, chain, chain, 0].iter().flat_map(|v| v.to_le_bytes()));
        a.extend(process.to_le_bytes());
        a.extend([thread, 0, 0, 0]);
        a.extend(key.to_le_bytes());
        for part in frames.iter().chain(segments) {
            a.extend(part);
        }
        a
    }
    fn segment_bytes(
        kind: u8,
        state: u8,
        registration: u8,
        recorded: u32,
        digest: [u8; 32],
    ) -> Vec<u8> {
        let mut bytes = vec![kind, state, 0, registration];
        bytes.extend(recorded.to_le_bytes());
        bytes.extend([0; 8]);
        bytes.extend(digest);
        bytes
    }

    #[test]
    fn worker_and_message_segments_resolve_in_their_own_scope() {
        // Script 7 is a different script in each isolate.
        let worker_source = "function work() {\n  fetch('/w');\n}\n";
        let page_source = "function post() {\n  port.postMessage(1);\n}\n";
        let at = |text: &str, needle: &str| text.find(needle).unwrap() as u32;
        let work = frame(
            1,
            0,
            7,
            at(worker_source, "fetch"),
            at(worker_source, "() {"),
        );
        let post = frame(1, 0, 7, at(page_source, "port"), at(page_source, "() {"));
        let then = frame(1, 0, 7, at(worker_source, "work"), 0);
        // The posting stack, walked in the page's renderer (process 5).
        let posted = scoped_artifact(5, 1, 0, std::slice::from_ref(&post), &[], 0);
        let posted_digest: [u8; 32] = Sha256::digest(&posted).into();
        // A .then registration walked in the worker.
        let registered = scoped_artifact(4, 2, 0x77, std::slice::from_ref(&then), &[], 0);
        let registered_digest: [u8; 32] = Sha256::digest(&registered).into();
        let segments = [
            segment_bytes(9, 1, 1, 1, registered_digest),
            segment_bytes(10, 1, 0, 1, posted_digest),
            segment_bytes(8, 7, 0, 0, [0; 32]),
        ];
        let stack = scoped_artifact(4, 2, 0x77, std::slice::from_ref(&work), &segments, 0);
        let digest: [u8; 32] = Sha256::digest(&stack).into();
        let mut bytes = record_bytes(1, 1, 1, 0, digest);
        bytes[0] = 3;
        bytes[5] = 0;
        bytes[6..8].copy_from_slice(&3u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&3u16.to_le_bytes());
        bytes[64..80].copy_from_slice(&work);
        bytes[80] = 2;
        bytes[88..96].copy_from_slice(&0x77u64.to_le_bytes());
        let record = decode_record(&bytes).expect("version 3 record");
        assert_eq!(
            record.scope,
            Scope {
                thread: 2,
                isolate_key: 0x77
            }
        );
        for (byte, value) in [(80, 0u8), (80, 5), (84, 1), (100, 1)] {
            let mut bad = bytes.clone();
            bad[byte] = value;
            assert!(decode_record(&bad).is_none(), "scope byte {byte}");
        }
        let mut document_key = bytes.clone();
        document_key[80] = 1;
        assert!(
            decode_record(&document_key).is_none(),
            "the main thread has no key"
        );
        let mut worker_identity = identity_bytes(1, 0x02, 7, (0, 0), 99, worker_source.as_bytes());
        worker_identity[0] = 2;
        worker_identity[72] = 2;
        worker_identity[80..88].copy_from_slice(&0x77u64.to_le_bytes());
        let (isolate, script, worker) = decode_identity(&worker_identity).unwrap();
        assert_eq!((isolate, script), (0x77, 7));
        let (_, _, page) = decode_identity(&identity_bytes(
            1,
            0x02,
            7,
            (0, 0),
            99,
            page_source.as_bytes(),
        ))
        .unwrap();
        let identities = HashMap::from([((4, 0x77, 7), worker), ((5, 0, 7), page)]);
        let artifacts = vec![
            artifact("1", "stack", &stack),
            artifact("2", "stack", &posted),
            artifact("3", "stack", &registered),
            artifact("4", "javascript", worker_source.as_bytes()),
            artifact("5", "javascript", page_source.as_bytes()),
        ];
        let contents: HashMap<&str, Vec<u8>> = HashMap::from([
            ("1", stack.clone()),
            ("2", posted.clone()),
            ("3", registered.clone()),
            ("4", worker_source.as_bytes().to_vec()),
            ("5", page_source.as_bytes().to_vec()),
        ]);
        let read =
            |a: &Value, _limit: usize| Ok(contents[a["artifact_id"].as_str().unwrap()].clone());
        let event = json!({"session_id": "9", "process_id": 4, "request_id": "3",
            "frame_id": "119", "sequence_number": "12", "parent_event_id": "11"});
        assert_eq!(
            segment_digests(&stack),
            vec![hex::encode(registered_digest), hex::encode(posted_digest)]
        );
        let doc = resolve(&event, &record, &identities, &artifacts, &read);
        assert_eq!(
            doc["scope"],
            json!({"thread": "dedicated_worker", "isolate_key": "0000000000000077"})
        );
        assert_eq!(doc["frames"][0]["resolution"]["function_name"], "work");
        let chain = &doc["task_segments"];
        assert_eq!(
            (
                &chain[0]["kind"],
                &chain[0]["registration"],
                &chain[0]["state"]
            ),
            (&json!("microtask"), &json!("then"), &json!("captured"))
        );
        assert_eq!(chain[0]["scope"]["elsewhere"], false);
        assert_eq!(chain[0]["frames"][0]["resolution"]["line"], 1);
        assert_eq!(chain[1]["kind"], "message_port");
        assert_eq!(
            (
                &chain[1]["scope"]["thread"],
                &chain[1]["scope"]["process_id"],
                &chain[1]["scope"]["other_process"]
            ),
            (&json!("document"), &json!(5), &json!(true))
        );
        assert_eq!(chain[1]["frames"][0]["resolution"]["function_name"], "post");
        assert_eq!(
            (&chain[2]["kind"], &chain[2]["state"], &chain[2]["digest"]),
            (&json!("event"), &json!("no_script"), &Value::Null)
        );
        assert_eq!(doc["task_chain_cut"], false);
        assert_eq!(doc["async_callers_not_shown"], json!(ASYNC_NOT_SHOWN));
        assert!(
            ASYNC_NOT_SHOWN.iter().any(|line| line.contains("worklet"))
                && ASYNC_NOT_SHOWN
                    .iter()
                    .any(|line| line.contains("promise reaction in a worker"))
                && ASYNC_NOT_SHOWN.iter().any(|line| line.contains("builtin")),
            "version 3 states what it cannot show"
        );
        // An artifact naming another isolate does not belong to this record.
        let foreign = scoped_artifact(4, 2, 0x78, std::slice::from_ref(&work), &segments, 0);
        assert!(decode_artifact(&foreign, &record, 4).is_none());
        assert!(decode_artifact(&stack, &record, 5).is_none());
        // A no-script segment ends the chain: it is last and not cut there.
        let early = scoped_artifact(
            4,
            2,
            0x77,
            std::slice::from_ref(&work),
            &[segments[2].clone(), segments[1].clone()],
            0,
        );
        let mut early_bytes = bytes.clone();
        early_bytes[6..8].copy_from_slice(&2u16.to_le_bytes());
        early_bytes[22..24].copy_from_slice(&2u16.to_le_bytes());
        let early_record = decode_record(&early_bytes).unwrap();
        assert!(decode_artifact(&early, &early_record, 4).is_none());
        // A registration keeps at most 32 frames and names its call.
        assert!(Segment::read(&segment_bytes(9, 1, 0, 1, [1; 32]), 3).is_none());
        assert!(Segment::read(&segment_bytes(9, 1, 1, 33, [1; 32]), 3).is_none());
        assert!(Segment::read(&segment_bytes(9, 1, 1, 1, [1; 32]), 2).is_none());
        assert!(Segment::read(&segment_bytes(13, 1, 0, 1, [1; 32]), 3).is_none());
        assert!(Segment::read(&segment_bytes(10, 1, 0, 1, [1; 32]), 2).is_none());
        // A worker request with no script on its stack keeps its scope.
        let mut loader = vec![3, 0, 128, 0, 2, 0];
        loader.resize(128, 0);
        loader[80] = 3;
        loader[88..96].copy_from_slice(&0x79u64.to_le_bytes());
        assert_eq!(decode_record(&loader).unwrap().scope.thread, 3);
        let mut pool = vec![3, 0, 128, 0, 3, 0];
        pool.resize(128, 0);
        assert_eq!(decode_record(&pool).unwrap().scope, Scope::default());
        pool[80] = 2;
        assert!(
            decode_record(&pool).is_none(),
            "unsupported_thread names no isolate"
        );

        // A worker past the renderer's table limit: its scope, nothing walked.
        let mut limited = loader.clone();
        limited[4] = 6;
        let limited_record = decode_record(&limited).expect("thread-limit record");
        let limited_doc = resolve(&event, &limited_record, &identities, &artifacts, &read);
        assert_eq!(
            (
                &limited_doc["state"],
                &limited_doc["digest"],
                &limited_doc["frames"],
                &limited_doc["scope"]["thread"]
            ),
            (
                &json!("not_walked_thread_limit"),
                &Value::Null,
                &json!([]),
                &json!("shared_worker")
            )
        );
        assert_eq!(summary(&limited_record)["digest"], Value::Null);
        let mut unscoped = limited.clone();
        unscoped[80..96].fill(0);
        assert!(decode_record(&unscoped).is_none(), "it names its worker");
        let mut version_2 = unscoped.clone();
        version_2[0] = 2;
        assert!(decode_record(&version_2).is_none(), "only version 3 has it");

        // A received message whose origin was rejected ends the chain at a
        // segment of the receiving kind, and nothing follows it.
        let rejected = segment_bytes(11, 8, 0, 0, [0; 32]);
        assert!(Segment::read(&rejected, 3).is_some());
        assert!(Segment::read(&rejected, 2).is_none());
        assert!(Segment::read(&segment_bytes(1, 8, 0, 0, [0; 32]), 3).is_none());
        assert!(Segment::read(&segment_bytes(11, 8, 0, 1, [1; 32]), 3).is_none());
        let chain_of = |segments: &[Vec<u8>], flags: u8| {
            let artifact =
                scoped_artifact(4, 2, 0x77, std::slice::from_ref(&work), segments, flags);
            let mut bytes = bytes.clone();
            let count = segments.len() as u16;
            bytes[5] = flags;
            bytes[6..8].copy_from_slice(&count.to_le_bytes());
            bytes[22..24].copy_from_slice(&count.to_le_bytes());
            bytes[32..64].copy_from_slice(&Sha256::digest(&artifact));
            (artifact, decode_record(&bytes).unwrap())
        };
        let (ended, ended_record) = chain_of(&[segments[1].clone(), rejected.clone()], 0);
        let (_, decoded) =
            decode_artifact(&ended, &ended_record, 4).expect("ends at the rejection");
        assert_eq!(segment_state(decoded[1].state), "origin_rejected");
        let (after, after_record) = chain_of(&[rejected.clone(), segments[1].clone()], 0);
        assert!(decode_artifact(&after, &after_record, 4).is_none());
        let (cut, cut_record) = chain_of(std::slice::from_ref(&rejected), 0x08);
        assert!(decode_artifact(&cut, &cut_record, 4).is_none());

        // A microtask with nothing remembered says whether promise stacks were on.
        let mut remembered_none = segment_bytes(9, 6, 0, 0, [0; 32]);
        remembered_none[2] = 2;
        assert!(Segment::read(&remembered_none, 3).is_some());
        assert!(Segment::read(&remembered_none, 2).is_none());
        let mut captured_on = segments[0].clone();
        captured_on[2] = 2;
        assert!(Segment::read(&captured_on, 3).is_none());
        let mut port_on = segments[1].clone();
        port_on[2] = 2;
        assert!(Segment::read(&port_on, 3).is_none());
        let (flagged, flagged_record) =
            chain_of(&[remembered_none, segment_bytes(9, 6, 0, 0, [0; 32])], 0);
        let flagged_artifacts = vec![artifact("6", "stack", &flagged)];
        let flagged_read = |_: &Value, _limit: usize| Ok(flagged.clone());
        let flagged_doc = resolve(
            &event,
            &flagged_record,
            &identities,
            &flagged_artifacts,
            &flagged_read,
        );
        assert_eq!(
            (
                &flagged_doc["task_segments"][0]["promise_stacks_on"],
                &flagged_doc["task_segments"][1]["promise_stacks_on"]
            ),
            (&json!(true), &json!(false))
        );
    }

    #[test]
    fn records_follow_the_shared_rules() {
        let digest = [7u8; 32];
        assert!(decode_record(&record_bytes(1, 150, 150, 0, digest)).is_some());
        let deep = record_bytes(1, 5000, 1024, 0, digest);
        let record = decode_record(&deep).unwrap();
        assert_eq!((record.recorded, record.omitted), (1024, 3976));
        let parser = [vec![1, 0, 128, 0, 2, 8], vec![0; 122]].concat();
        assert!(decode_record(&parser).is_some());
        for (at, value) in [(4, 9u8), (5, 0x18), (100, 1), (32, 0)] {
            let mut bad = record_bytes(1, 150, 150, 0, digest);
            if at == 32 {
                bad[32..64].fill(0);
            } else {
                bad[at] = value;
            }
            assert!(decode_record(&bad).is_none(), "byte {at}");
        }
        let mut bad = record_bytes(1, 160, 150, 0, digest);
        bad[5] &= !0x02;
        assert!(decode_record(&bad).is_none(), "omitted below the bound");
    }

    #[test]
    fn names_come_from_the_source_at_the_function_start() {
        let cases = [
            ("function alpha(a) {}", "(", Some("alpha")),
            ("obj.beta = function (a) {}", "(", Some("obj.beta")),
            ("const gamma = async (a) => a", "(", Some("gamma")),
            ("x = { delta(a) {} }", "(", Some("delta")),
            ("class A { get epsilon() {} }", "(", Some("get epsilon")),
            ("x = { 'zeta': function() {} }", "(", Some("zeta")),
            ("[1].map(function (a) {})", "(a", None),
            ("if (a == function () {}) {}", "() {}", None),
        ];
        for (text, anchor, expected) in cases {
            let at = text.rfind(anchor).unwrap();
            assert_eq!(function_name(text, at).as_deref(), expected, "{text}");
        }
    }

    #[test]
    fn positions_count_utf16_columns_and_lf_lines() {
        let text = "a😀b\nc";
        let wanted: BTreeSet<u32> = [0, 3, 4, 5, 6, 9].into_iter().collect();
        let got = positions(text, &wanted);
        assert_eq!(got[&3], (5, 1, 4));
        assert_eq!(got[&5], (7, 2, 1));
        assert_eq!(got[&6], (8, 2, 2));
        assert!(!got.contains_key(&9));
    }
}
