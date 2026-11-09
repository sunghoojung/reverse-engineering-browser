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
const HEADER: usize = 32;
const FRAME: usize = 16;
const SEGMENT: usize = 48;
const MAX_ARTIFACT: usize =
    HEADER + FRAME * (SYNC_LIMIT + ASYNC_LIMIT) as usize + SEGMENT * TASK_LIMIT as usize;
const MAX_SOURCE: usize = 16 * 1024 * 1024;
const IDENTITY_SCAN: usize = 4096;
/// Version 1 records captured no task-attributed callers.
const ASYNC_NOT_SHOWN_V1: [&str; 4] = [
    "timers",
    "event listeners",
    "promise.then callbacks",
    "message handlers",
];
const ASYNC_NOT_SHOWN: [&str; 1] = ["MessagePort and worker messages"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    kind: u8,
    flags: u8,
    combinator: u16,
    script_id: u32,
    position: u32,
    detail: u32,
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
    fn read(bytes: &[u8]) -> Self {
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
    kind: u8,
    state: u8,
    flags: u8,
    recorded: u32,
    digest: [u8; 32],
}

impl Segment {
    fn read(bytes: &[u8]) -> Option<Self> {
        let segment = Self {
            kind: bytes[0],
            state: bytes[1],
            flags: bytes[2],
            recorded: u32_at(bytes, 4),
            digest: bytes[16..48].try_into().unwrap(),
        };
        let reserved = bytes[3] == 0 && bytes[8..16].iter().all(|b| *b == 0);
        let shape = if segment.kind == 9 {
            segment.state == 6
                && segment.flags == 0
                && segment.recorded == 0
                && segment.digest.iter().all(|b| *b == 0)
        } else {
            (1..=8).contains(&segment.kind)
                && matches!(segment.state, 1 | 4 | 5)
                && segment.flags & !1 == 0
                && (1..=TASK_FRAME_LIMIT).contains(&segment.recorded)
                && (segment.flags & 1 == 0 || segment.recorded == TASK_FRAME_LIMIT)
                && segment.digest.iter().any(|b| *b != 0)
        };
        (reserved && shape).then_some(segment)
    }
}

/// The decoded `request_initiator_stack` payload.
#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    version: u16,
    task_segments: u32,
    state: u8,
    flags: u8,
    total: u32,
    recorded: u32,
    omitted: u32,
    async_frames: u32,
    async_segments: u32,
    wasm_frames: u32,
    scripts: u32,
    digest: [u8; 32],
    innermost: Frame,
}

pub fn decode_record(payload: &[u8]) -> Option<Record> {
    if payload.len() != 128 || !matches!(payload[..4], [1 | 2, 0, 128, 0]) {
        return None;
    }
    let tasks = payload[0] == 2;
    let known = if tasks { 0x1f } else { 0x0f };
    if payload[80..].iter().any(|b| *b != 0)
        || payload[5] & !known != 0
        || (!tasks && payload[6..8] != [0, 0])
    {
        return None;
    }
    let record = Record {
        version: u16::from(payload[0]),
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
    let chain = if tasks {
        record.task_segments <= TASK_LIMIT
            && record.async_segments == record.async_frames + record.task_segments
            && (record.flags & 0x10 == 0 || record.task_segments == TASK_LIMIT)
    } else {
        record.async_segments <= record.async_frames
    };
    let valid = match record.state {
        2 | 3 => {
            record.flags & !(if tasks { 0 } else { 0x08 }) == 0
                && record.task_segments == 0
                && payload[8..80].iter().all(|b| *b == 0)
        }
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

/// Frames and task chain of a stack artifact that agrees with its record.
pub fn decode_artifact(content: &[u8], record: &Record) -> Option<(Vec<Frame>, Vec<Segment>)> {
    if content.len() < HEADER || content.len() > MAX_ARTIFACT || u32_at(content, 0) != 0x4b53_4252 {
        return None;
    }
    let count = (u64::from(record.recorded) + u64::from(record.async_frames)) as usize;
    let header_flags = if record.version == 2 { 0x1e } else { 0x06 };
    if u16_at(content, 4) != record.version
        || u16_at(content, 6) as usize != HEADER
        || u16_at(content, 8) as usize != FRAME
        || u16_at(content, 10) != u16::from(record.flags & header_flags)
        || u32_at(content, 12) != record.total
        || u32_at(content, 16) != record.recorded
        || u32_at(content, 20) != record.omitted
        || u32::from(u16_at(content, 24)) != record.async_frames
        || u32::from(u16_at(content, 26)) != record.async_segments
        || u32::from(u16_at(content, 28)) != record.task_segments
        || u16_at(content, 30) != 0
        || content.len() != HEADER + FRAME * count + SEGMENT * record.task_segments as usize
    {
        return None;
    }
    let chain = HEADER + FRAME * count;
    let frames: Vec<Frame> = content[HEADER..chain]
        .as_chunks::<FRAME>()
        .0
        .iter()
        .map(|chunk| Frame::read(chunk))
        .collect();
    let segments: Option<Vec<Segment>> = content[chain..]
        .as_chunks::<SEGMENT>()
        .0
        .iter()
        .map(|chunk| Segment::read(chunk))
        .collect();
    let valid = frames
        .iter()
        .enumerate()
        .all(|(i, frame)| frame.valid(i >= record.recorded as usize))
        && frames.first() == Some(&record.innermost);
    valid
        .then_some(())
        .and(segments)
        .map(|segments| (frames, segments))
}

fn decode_segment_artifact(content: &[u8], recorded: u32) -> Option<Vec<Frame>> {
    let count = recorded as usize;
    let shape = content.len() == HEADER + FRAME * count
        && u32_at(content, 0) == 0x4b53_4252
        && u16_at(content, 4) == 1
        && u16_at(content, 6) as usize == HEADER
        && u16_at(content, 8) as usize == FRAME
        && u16_at(content, 10) == 0
        && u32_at(content, 12) == recorded
        && u32_at(content, 16) == recorded
        && content[20..32].iter().all(|b| *b == 0);
    let frames: Vec<Frame> = content
        .get(HEADER..)
        .filter(|_| shape)?
        .as_chunks::<FRAME>()
        .0
        .iter()
        .map(|chunk| Frame::read(chunk))
        .collect();
    frames
        .iter()
        .all(|frame| frame.valid(false))
        .then_some(frames)
}

/// The segment digests a version 2 artifact names, before it is validated.
fn segment_digests(content: &[u8]) -> Vec<String> {
    if content.len() < HEADER || u16_at(content, 4) != 2 {
        return Vec::new();
    }
    let frames = u32_at(content, 16) as usize + usize::from(u16_at(content, 24));
    let start = HEADER + FRAME * frames;
    content
        .get(start..)
        .unwrap_or_default()
        .as_chunks::<SEGMENT>()
        .0
        .iter()
        .filter(|chunk| chunk[0] != 9)
        .map(|chunk| hex::encode(&chunk[16..48]))
        .collect()
}

/// The newest `script_identity` per script ID, from one process's records.
#[derive(Clone, Debug)]
pub struct Identity {
    wasm: bool,
    eval: bool,
    retained: bool,
    start_line: u32,
    start_column: u32,
    sha256: Option<String>,
}

pub fn decode_identity(payload: &[u8]) -> Option<(u32, Identity)> {
    if payload.len() != 128
        || payload[..4] != [1, 0, 128, 0]
        || payload[6..8] != [0, 0]
        || payload[20..24] != [0; 4]
        || payload[72..].iter().any(|b| *b != 0)
    {
        return None;
    }
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
            script,
            Identity {
                wasm: kind == 2,
                eval: flags & 0x01 != 0,
                retained: flags & 0x02 != 0,
                start_line: u32_at(payload, 12),
                start_column: u32_at(payload, 16),
                sha256: matches!(retention, 0x00 | 0x02 | 0x10).then(|| hex::encode(digest)),
            },
        )
    })
}

/// One-based LF lines and UTF-16 columns of sorted UTF-16 offsets in text, as
/// Sources numbers them, with each offset's UTF-8 byte position.
fn positions(text: &str, offsets: &BTreeSet<u32>) -> HashMap<u32, (usize, u64, u64)> {
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
fn function_name(text: &str, start: usize) -> Option<String> {
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

fn wasm_names(bytes: &[u8]) -> HashMap<u32, String> {
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
    let identity = identity.ok_or("script_identity_missing")?;
    let sha = identity.sha256.as_deref().ok_or("source_unavailable")?;
    let kind = if identity.wasm { "wasm" } else { "javascript" };
    let artifact = newest(artifacts, session, |a| {
        a["kind"] == kind && a["sha256"] == sha
    })
    .ok_or(if identity.wasm || identity.retained {
        "source_artifact_missing"
    } else {
        "source_not_retained"
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
        _ => "not_retained_budget",
    }
}

/// A record's summary without its frames: state, depth, digest and innermost frame.
pub fn summary(record: &Record) -> Value {
    let walked = record.state != 2 && record.state != 3;
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

fn task_kind(kind: u8) -> &'static str {
    match kind {
        1 => "set_timeout",
        2 => "set_interval",
        3 => "request_animation_frame",
        4 => "request_idle_callback",
        5 => "post_message",
        6 => "xhr_send",
        7 => "post_task",
        8 => "event",
        _ => "microtask",
    }
}

fn segment_state(state: u8) -> &'static str {
    match state {
        1 => "captured",
        4 => "not_retained_artifact_unavailable",
        5 => "not_retained_budget",
        _ => "not_recorded",
    }
}

type Sources = HashMap<u32, std::result::Result<Source, &'static str>>;

/// Each script's retained source, loaded once for every frame that names it.
fn load_sources<'a>(
    frames: impl Iterator<Item = &'a Frame>,
    identities: &HashMap<u32, Identity>,
    artifacts: &[Value],
    session: &str,
    read: &dyn Fn(&Value, usize) -> Result<Vec<u8>>,
) -> Sources {
    let mut by_script: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for frame in frames.filter(|f| f.script_id != 0) {
        let offsets = by_script.entry(frame.script_id).or_default();
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
    sources: &Sources,
    identities: &HashMap<u32, Identity>,
) -> Value {
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
    let source = sources.get(&frame.script_id);
    if frame.kind == 2 {
        value["function_index"] = json!(frame.detail);
        value["module_offset"] = json!(frame.position);
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
    let identity = identities.get(&frame.script_id);
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
                json!({
                    "status": "resolved",
                    "artifact_id": source.artifact_id,
                    "url": source.url,
                    "artifact_line": line,
                    "artifact_column": column,
                    "line": u64::from(identity.start_line) + line,
                    "column": if line == 1 {
                        u64::from(identity.start_column) + column
                    } else {
                        column
                    },
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
    identities: &HashMap<u32, Identity>,
    artifacts: &[Value],
    read: &dyn Fn(&Value, usize) -> Result<Vec<u8>>,
) -> Value {
    let state = state_name(record.state);
    let session = stack_event["session_id"].as_str().unwrap_or("");
    let digest = hex::encode(record.digest);
    let tasks = record.version == 2;
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
        "async_callers_not_shown": if tasks { &ASYNC_NOT_SHOWN[..] } else { &ASYNC_NOT_SHOWN_V1[..] },
        "wasm_frames": record.wasm_frames,
        "digest": (record.state != 2 && record.state != 3).then_some(&digest),
        "frames_retained": false,
        "frames": [],
        "task_segments": [],
    });
    if record.state == 2 || record.state == 3 {
        return document;
    }
    let decoded = newest(artifacts, session, |a| {
        a["kind"] == "stack" && a["sha256"] == digest.as_str()
    })
    .and_then(|artifact| read(artifact, MAX_ARTIFACT).ok())
    .and_then(|content| decode_artifact(&content, record));
    document["frames_retained"] = json!(decoded.is_some());
    let (frames, segments) = decoded.unwrap_or_else(|| (vec![record.innermost], Vec::new()));
    let segment_frames: Vec<Option<Vec<Frame>>> = segments
        .iter()
        .map(|segment| {
            let sha = hex::encode(segment.digest);
            (segment.kind != 9)
                .then(|| {
                    newest(artifacts, session, |a| {
                        a["kind"] == "stack" && a["sha256"] == sha.as_str()
                    })
                })
                .flatten()
                .and_then(|artifact| read(artifact, MAX_ARTIFACT).ok())
                .and_then(|content| decode_segment_artifact(&content, segment.recorded))
        })
        .collect();
    let sources = load_sources(
        frames
            .iter()
            .chain(segment_frames.iter().flatten().flatten()),
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
            json!({
                "index": index,
                "kind": task_kind(segment.kind),
                "state": segment_state(segment.state),
                "recorded": segment.recorded,
                "bounded": segment.flags & 1 != 0,
                "digest": (segment.kind != 9).then(|| hex::encode(segment.digest)),
                "frames_retained": frames.is_some(),
                "frames": frames.as_deref().unwrap_or_default().iter().enumerate()
                    .map(|(i, frame)| frame_value(i, frame, false, &sources, identities))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    document
}

/// A `script_cookie` call's walked stack by digest, else its innermost frame alone.
pub fn resolve_call(
    event: &Value,
    innermost: &[u8; FRAME],
    digest: Option<[u8; 32]>,
    identities: &HashMap<u32, Identity>,
    artifacts: &[Value],
    read: &dyn Fn(&Value, usize) -> Result<Vec<u8>>,
) -> Value {
    let mut record = Record {
        version: 1,
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
        .filter(|content| content.len() >= HEADER);
    if let Some(content) = header {
        record.flags |= content[10] & 0x06;
        record.total = u32_at(&content, 12);
        record.recorded = u32_at(&content, 16);
        record.omitted = u32_at(&content, 20);
        record.async_frames = u32::from(u16_at(&content, 24));
        record.async_segments = u32::from(u16_at(&content, 26));
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
                decode_identity(&identity)?.1.sha256
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
            let key = format!("{session}:{}:{}", raw["process_id"], raw["frame"]);
            if let Some(kept) = self.0.get(&key) {
                row["initiator_frame"] = kept.clone();
                continue;
            }
            if fresh == Self::NEW_PER_ANSWER {
                deferred = true;
                continue;
            }
            fresh += 1;
            let identities: HashMap<u32, Identity> = raw["identity"]
                .as_str()
                .and_then(|hex| hex::decode(hex).ok())
                .and_then(|bytes| decode_identity(&bytes))
                .into_iter()
                .collect();
            let artifacts = artifacts
                .get_or_insert_with(|| manifest.take().map_or_else(Vec::new, |f| f(&wanted)));
            let event = json!({"session_id": session, "process_id": raw["process_id"]});
            let mut stack = resolve_call(&event, &frame, None, &identities, artifacts, &read);
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

fn payload(event: &Value) -> Option<Vec<u8>> {
    hex::decode(event["payload"].as_str()?).ok()
}

/// Bytes 80-127 of a `navigation_initiator_stack`: its kind and target frame.
fn decode_navigation(payload: &[u8]) -> Option<(Record, &'static str, u64)> {
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
pub(crate) fn decode_indexed_identities(payloads: &HashMap<u32, String>) -> HashMap<u32, Identity> {
    payloads
        .values()
        .filter_map(|payload| decode_identity(&hex::decode(payload).ok()?))
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
) -> Result<(HashMap<u32, Identity>, bool)> {
    let session = stack["session_id"].as_str();
    let mut identities = HashMap::new();
    let mut known = false;
    if let Some(session) = session {
        let (indexed, exhaustive) = requests
            .blocking_lock()
            .identities(session, process_id as u32)?;
        known = exhaustive;
        identities = decode_indexed_identities(&indexed);
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
            if let Some((script, identity)) = payload(event).as_deref().and_then(decode_identity) {
                identities.insert(script, identity);
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

fn resolve_stored(
    store: &Path,
    artifacts_root: &Path,
    requests: &Mutex<RequestIndex>,
    stack: &Value,
    record: &Record,
    process_id: u64,
) -> Result<Value> {
    let (identities, known) = if record.state != 2 && record.state != 3 {
        stored_identities(store, requests, stack, process_id)?
    } else {
        (HashMap::new(), true)
    };
    let mut wanted: BTreeSet<String> = identities
        .values()
        .filter_map(|identity| identity.sha256.clone())
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
    if record.version == 2
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
            artifacts.extend(select(&segments)?);
        }
    }
    let mut document = resolve(stack, record, &identities, &artifacts, &read);
    if !known {
        mark_identities_outside_scan(&mut document);
    }
    Ok(document)
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
    let mut document =
        resolve_stored(store, artifacts_root, requests, &stack, &record, process_id)?;
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
    let mut document =
        resolve_stored(store, artifacts_root, requests, &stack, &record, process_id)?;
    document["navigation"] = json!({"kind": kind, "target_frame_id": target.to_string()});
    document["coverage"] = coverage.to_json();
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn frame(kind: u8, script: u32, position: u32, detail: u32) -> Vec<u8> {
        let mut bytes = vec![kind, 0, 0, 0];
        for value in [script, position, detail] {
            bytes.extend(value.to_le_bytes());
        }
        bytes
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
        p.extend(frame(1, 7, 30, 21));
        p.resize(128, 0);
        p
    }
    fn artifact_bytes(total: u32, frames: &[Vec<u8>], asyncs: u16) -> Vec<u8> {
        let recorded = frames.len() as u32 - u32::from(asyncs);
        let mut a = 0x4b53_4252u32.to_le_bytes().to_vec();
        a.extend([1, 0, 32, 0, 16, 0]);
        a.extend(if total > recorded { [2u8, 0] } else { [0, 0] });
        for value in [total, recorded, total - recorded] {
            a.extend(value.to_le_bytes());
        }
        a.extend(asyncs.to_le_bytes());
        a.extend(asyncs.to_le_bytes());
        a.extend(0u32.to_le_bytes());
        for f in frames {
            a.extend(f);
        }
        a
    }
    fn identity_bytes(
        kind: u8,
        flags: u8,
        script: u32,
        line: u32,
        column: u32,
        text: &[u8],
    ) -> Vec<u8> {
        let mut p = vec![1, 0, 128, 0, kind, flags, 0, 0];
        for value in [script, line, column, 0] {
            p.extend(value.to_le_bytes());
        }
        p.extend(99u64.to_le_bytes());
        p.extend((text.len() as u64).to_le_bytes());
        p.extend(Sha256::digest(text));
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
            json!({"session_id": "9", "process_id": 41, "frame": hex::encode(frame(1, 7, at, start)),
                "identity": identity.map(hex::encode)})
        };
        let mut document = json!({"requests": [
            {"initiator_frame": raw(Some(identity_bytes(1, 0x02, 7, 0, 0, source.as_bytes())))},
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
        missing["requests"][0]["initiator_frame"]["frame"] = json!(hex::encode(frame(1, 8, 1, 0)));
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

    #[test]
    fn an_identity_outside_the_scan_is_not_reported_as_missing() {
        let identity = identity_bytes(1, 0x02, 7, 1, 1, b"x");
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
        assert!(found.contains_key(&7));
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
            frame(1, 7, fetch_at, send_at),
            frame(2, 30, 0x2a1, 3),
            frame(1, 8, 0, 0),
            frame(1, 7, call_at, run_at),
            frame(1, 40, 5, 0),
            frame(3, 7, call_at, run_at),
            vec![4, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
        ];
        let stack = artifact_bytes(6, &frames, 2);
        let digest: [u8; 32] = Sha256::digest(&stack).into();
        let mut bytes = record_bytes(1, 5, 5, 2, digest);
        bytes[64..80].copy_from_slice(&frames[0]);
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        let record = decode_record(&bytes).expect("valid record");
        assert!(
            decode_artifact(&stack, &record).is_none(),
            "depth must agree"
        );
        let stack = artifact_bytes(5, &frames, 2);
        let digest: [u8; 32] = Sha256::digest(&stack).into();
        bytes[32..64].copy_from_slice(&digest);
        let record = decode_record(&bytes).expect("valid record");
        let mut identities = HashMap::new();
        for (script, payload) in [
            (7, identity_bytes(1, 0x02, 7, 10, 4, inline.as_bytes())),
            (8, identity_bytes(1, 0x03, 8, 0, 0, evaled.as_bytes())),
            (30, identity_bytes(2, 0, 30, 0, 0, &wasm)),
            (40, identity_bytes(1, 0x10, 40, 0, 0, b"not retained")),
        ] {
            let (id, identity) = decode_identity(&payload).expect("identity");
            assert_eq!(id, script);
            identities.insert(id, identity);
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
        let schedule = frame(1, 7, at("setTimeout"), at("() {"));
        let mut timer = 0x4b53_4252u32.to_le_bytes().to_vec();
        timer.extend([1, 0, 32, 0, 16, 0, 0, 0]);
        timer.extend([1u32, 1, 0].iter().flat_map(|v| v.to_le_bytes()));
        timer.extend([0; 8]);
        timer.extend(&schedule);
        let timer_digest: [u8; 32] = Sha256::digest(&timer).into();
        let send = frame(1, 7, at("fetch"), at("() { fetch"));
        let segment = |kind: u8, state: u8, recorded: u32, digest: [u8; 32]| {
            let mut bytes = vec![kind, state, 0, 0];
            bytes.extend(recorded.to_le_bytes());
            bytes.extend([0; 8]);
            bytes.extend(digest);
            bytes
        };
        let mut stack = 0x4b53_4252u32.to_le_bytes().to_vec();
        stack.extend([2, 0, 32, 0, 16, 0, 0x08, 0]);
        stack.extend([1u32, 1, 0].iter().flat_map(|v| v.to_le_bytes()));
        stack.extend([0, 0, 2, 0, 2, 0, 0, 0]);
        stack.extend(&send);
        stack.extend(segment(1, 1, 1, timer_digest));
        stack.extend(segment(9, 6, 0, [0; 32]));
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
        let (_, identity) =
            decode_identity(&identity_bytes(1, 0x02, 7, 0, 0, source.as_bytes())).unwrap();
        let identities = HashMap::from([(7, identity)]);
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
