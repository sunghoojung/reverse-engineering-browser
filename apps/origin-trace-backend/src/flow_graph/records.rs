//! The records the flow graph folds, each read once in store order: typed
//! fields borrowed from the line, the payload decoded into one reused buffer.
//! Distinct stacks become walks; every record that names a walk again only
//! adds to its counts, and the counts it adds since the graph last took them
//! are kept as the walk's pending delta.
use super::{FxMap, Interner, TYPES};
use crate::{
    event_window, request_cookies, request_index,
    request_stack::{self, Frame, Record},
};
use serde::{
    Deserialize, Deserializer,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use std::{borrow::Cow, collections::BTreeMap};

/// An identifier field as `event_window::unsigned` reads it: a JSON number,
/// or a canonical decimal string; None for anything else.
#[derive(Clone, Copy, Default)]
struct Unsigned(Option<u64>);

impl<'de> Deserialize<'de> for Unsigned {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = Unsigned;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("any JSON value")
            }
            fn visit_u64<E>(self, value: u64) -> Result<Unsigned, E> {
                Ok(Unsigned(Some(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Unsigned, E> {
                Ok(Unsigned(u64::try_from(value).ok()))
            }
            fn visit_f64<E>(self, _: f64) -> Result<Unsigned, E> {
                Ok(Unsigned(None))
            }
            fn visit_bool<E>(self, _: bool) -> Result<Unsigned, E> {
                Ok(Unsigned(None))
            }
            fn visit_unit<E>(self) -> Result<Unsigned, E> {
                Ok(Unsigned(None))
            }
            fn visit_str<E>(self, text: &str) -> Result<Unsigned, E> {
                Ok(Unsigned(event_window::unsigned_text(text)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unsigned, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Unsigned(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unsigned, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Unsigned(None))
            }
        }
        deserializer.deserialize_any(Any)
    }
}

impl Unsigned {
    fn or_zero(self) -> u64 {
        self.0.unwrap_or(0)
    }
}

/// The fields of a record the fold reads; the rest of the line is skipped.
#[derive(Deserialize)]
struct Line<'a> {
    #[serde(rename = "type", borrow, default)]
    kind: Option<Cow<'a, str>>,
    #[serde(default)]
    session_id: Unsigned,
    #[serde(default)]
    process_id: Unsigned,
    #[serde(default)]
    request_id: Unsigned,
    #[serde(default)]
    frame_id: Unsigned,
    #[serde(default)]
    tab_id: Unsigned,
    #[serde(borrow, default)]
    payload_encoding: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    payload: Option<Cow<'a, str>>,
}

/// What a sink is: a request's `METHOD host` (an interned text), a script
/// navigation's kind, or a cookie write's API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Sink {
    Request(u32),
    Navigation(&'static str),
    Cookie(&'static str),
}

/// How a digest's artifact is decoded: against its record, as a scheduling
/// stack of a known depth, or by its own header.
#[derive(Clone)]
pub(super) enum Shape {
    Record(Box<Record>),
    Scheduling(u32),
    Alone,
}

/// Where a frame's script ID is read: its renderer process and isolate key
/// (zero for the document main thread, else the worker's context ID).
/// Script IDs are unique only per isolate (protocol/native-network-v3.md).
pub(super) type Where = (u32, u64);
pub(super) type IdentityKey = (u32, u64, u32);

/// A `script_identity`, compact: its source digest interned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub realm: u64,
    /// The interned SHA-256 of the retained source, or `NO_SHA`.
    pub sha: u32,
    pub start_line: u32,
    pub start_column: u32,
    pub wasm: bool,
    pub eval: bool,
    pub retained: bool,
}

pub(super) const NO_SHA: u32 = u32::MAX;

impl Identity {
    /// A one-based line and column of the script's artifact as a position in
    /// its document (`request_stack::Identity::document_position`).
    pub fn document_position(&self, line: u64, column: u64) -> (u64, u64) {
        document_position(self.start_line, self.start_column, line, column)
    }
}

/// A position in a script's artifact as one in its document, for a script
/// that starts at `start_line` and `start_column` (zero-based) there.
pub(super) fn document_position(
    start_line: u32,
    start_column: u32,
    line: u64,
    column: u64,
) -> (u64, u64) {
    let column = if line == 1 {
        u64::from(start_column) + column
    } else {
        column
    };
    (u64::from(start_line) + line, column)
}

/// Counts a walk's records add, by key, in first-seen order.
pub(super) type Counts<K> = Vec<(K, u64)>;

pub(super) fn add<K: PartialEq>(counts: &mut Counts<K>, key: K, by: u64) {
    match counts.iter_mut().find(|(k, _)| *k == key) {
        Some((_, count)) => *count += by,
        None => counts.push((key, by)),
    }
}

/// What a walk's records added since the graph last took its counts.
#[derive(Default)]
pub(super) struct Delta {
    pub occurrences: u64,
    pub sinks: Counts<u32>,
    pub schedules: Counts<u8>,
    pub frames: Counts<u64>,
    pub tabs: Counts<u64>,
}

/// One distinct walked stack and every record that named it.
pub(super) struct Walk {
    pub process: u32,
    pub isolate: u64,
    pub digest: [u8; 32],
    pub shape: Shape,
    pub innermost: Frame,
    /// Records naming it whose state says the frames were not retained.
    pub unretained: bool,
    /// An `async_task_stack` whose walk stopped at 256 frames.
    pub bounded: bool,
    pub occurrences: u64,
    /// Interned sinks and how many records reached each.
    pub sinks: Counts<u32>,
    /// Task kinds (`request_stack::task_kind`) its scheduling records name.
    pub schedules: Counts<u8>,
    pub frames: Counts<u64>,
    pub tabs: Counts<u64>,
    /// Renderer request IDs whose stack this is, every one of them, so a
    /// selected request finds its path.
    pub requests: Vec<u64>,
    pub pending: Option<Box<Delta>>,
}

/// Every record of the session folded so far.
#[derive(Default)]
pub(super) struct Scan {
    /// The newest identity per process, isolate and script.
    pub identities: FxMap<IdentityKey, Identity>,
    pub shas: Interner<[u8; 32]>,
    /// `METHOD host` of each request whose stack record has not arrived yet.
    labels: FxMap<(u32, u64), u32>,
    pub label_text: Interner<String>,
    pub sinks: Interner<Sink>,
    pub walks: Vec<Walk>,
    by_digest: FxMap<(Where, [u8; 32]), u32>,
    pub records: BTreeMap<&'static str, u64>,
    pub not_walked: BTreeMap<&'static str, u64>,
    pub malformed: u64,
    /// Stack records from builds before the stack scope (request stack
    /// versions 1 and 2, `async_task_stack` version 1), and from builds with
    /// it: what the graph cannot show depends on which it read.
    pub unscoped_records: bool,
    pub scoped_records: bool,
    /// Walks whose records added counts since the graph last took them.
    pub touched: Vec<u32>,
    /// Walks first seen since the graph last planned.
    pub new_walks: Vec<u32>,
    /// Walks whose plan depends on something a record changed.
    pub changed_walks: Vec<u32>,
    /// Identity keys that got an identity, and whether one that was already
    /// known changed.
    pub arrived: Vec<IdentityKey>,
    pub identity_changed: bool,
    payload: Vec<u8>,
}

/// The `async_task_stack` payload: task kind, recorded depth, digest, the
/// innermost frame and the isolate key, or None for a malformed record.
/// Version 2 adds message kinds 10 to 12, promise registrations (kind 9, at
/// most 32 frames, its call at byte 6) and the stack scope at bytes 80-95.
fn decode_scheduling(bytes: &[u8]) -> Option<(u8, u32, [u8; 32], Frame, u64)> {
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
    .then_some((kind, recorded, digest, innermost, isolate))
}

/// The common fields of a record a walk is counted from.
struct Seen {
    process: u32,
    request: u64,
    frame: u64,
    tab: u64,
}

impl Scan {
    /// Folds one record line of the session; one the decoders refuse, or
    /// whose line is not a record, is counted as malformed.
    pub fn line(&mut self, line: &[u8], session: u64) {
        if !self.fold(line, session) {
            self.malformed += 1;
        }
    }

    fn fold(&mut self, line: &[u8], session: u64) -> bool {
        let Ok(record) = serde_json::from_slice::<Line>(line) else {
            return false;
        };
        // The event index names the session by its reference; a record whose
        // session field reads otherwise is not this session's.
        if record.session_id.or_zero() != session {
            return true;
        }
        let Some(&kind) = record
            .kind
            .as_deref()
            .and_then(|kind| TYPES.iter().find(|t| **t == kind))
        else {
            return false;
        };
        let (Some("hex"), Some(payload)) = (record.payload_encoding.as_deref(), &record.payload)
        else {
            return false;
        };
        let mut bytes = std::mem::take(&mut self.payload);
        bytes.resize(payload.len() / 2, 0);
        let decoded = hex::decode_to_slice(payload.as_bytes(), &mut bytes[..]).is_ok();
        let seen = Seen {
            process: record.process_id.or_zero() as u32,
            request: record.request_id.or_zero(),
            frame: record.frame_id.or_zero(),
            tab: record.tab_id.or_zero(),
        };
        let folded = decoded && {
            *self.records.entry(kind).or_default() += 1;
            match kind {
                "script_identity" => self.identity(&seen, &bytes),
                "request_initiated" => {
                    self.request_label(&seen, &bytes);
                    true
                }
                "request_initiator_stack" => self.request_stack(&seen, &bytes),
                "navigation_initiator_stack" => self.navigation_stack(&seen, &bytes),
                "async_task_stack" => self.scheduling_stack(&seen, &bytes),
                _ => self.cookie_write(&seen, line),
            }
        };
        self.payload = bytes;
        folded
    }

    fn identity(&mut self, seen: &Seen, bytes: &[u8]) -> bool {
        let Some((isolate, script, identity)) = request_stack::decode_identity(bytes) else {
            return false;
        };
        let identity = Identity {
            realm: identity.realm,
            sha: identity.sha256.map_or(NO_SHA, |sha| self.shas.intern(sha)),
            start_line: identity.start_line,
            start_column: identity.start_column,
            wasm: identity.wasm,
            eval: identity.eval,
            retained: identity.retained,
        };
        let key = (seen.process, isolate, script);
        match self.identities.insert(key, identity) {
            None => self.arrived.push(key),
            Some(before) if before != identity => self.identity_changed = true,
            Some(_) => {}
        }
        true
    }

    /// Keeps a request's `METHOD host` until the stack record that follows it.
    fn request_label(&mut self, seen: &Seen, bytes: &[u8]) {
        let text = request_index::payload_text(bytes);
        let Some((method, host)) = request_index::network_target(&text, "request_initiated") else {
            return;
        };
        let label = match method {
            Some(method) => format!("{method} {host}"),
            None => host,
        };
        let id = self.label_text.intern(label);
        self.labels.insert((seen.process, seen.request), id);
    }

    fn note_version(&mut self, scoped: bool) {
        if scoped {
            self.scoped_records = true;
        } else {
            self.unscoped_records = true;
        }
    }

    /// The walk for this stack, counted once more for this record.
    fn walk(
        &mut self,
        seen: &Seen,
        isolate: u64,
        digest: [u8; 32],
        shape: impl FnOnce() -> Shape,
        innermost: Frame,
    ) -> &mut Walk {
        let key = ((seen.process, isolate), digest);
        let index = match self.by_digest.get(&key) {
            Some(&index) => index,
            None => {
                let index = self.walks.len() as u32;
                self.walks.push(Walk {
                    process: seen.process,
                    isolate,
                    digest,
                    shape: shape(),
                    innermost,
                    unretained: false,
                    bounded: false,
                    occurrences: 0,
                    sinks: Vec::new(),
                    schedules: Vec::new(),
                    frames: Vec::new(),
                    tabs: Vec::new(),
                    requests: Vec::new(),
                    pending: None,
                });
                self.by_digest.insert(key, index);
                self.new_walks.push(index);
                index
            }
        };
        let walk = &mut self.walks[index as usize];
        let pending = walk.pending.get_or_insert_with(|| {
            self.touched.push(index);
            Box::default()
        });
        walk.occurrences += 1;
        pending.occurrences += 1;
        add(&mut walk.frames, seen.frame, 1);
        add(&mut pending.frames, seen.frame, 1);
        if seen.tab != 0 {
            add(&mut walk.tabs, seen.tab, 1);
            add(&mut pending.tabs, seen.tab, 1);
        }
        walk
    }

    fn reach(walk: &mut Walk, sink: u32) {
        add(&mut walk.sinks, sink, 1);
        add(&mut walk.pending.as_mut().unwrap().sinks, sink, 1);
    }

    /// Marks a walk whose plan a record changed: the shape it is decoded by
    /// is the first record's, but whether its frames were retained and
    /// whether its walk was bounded are every record's.
    fn changed(&mut self, index: u32) {
        self.changed_walks.push(index);
    }

    fn request_stack(&mut self, seen: &Seen, bytes: &[u8]) -> bool {
        let Some(record) = request_stack::decode_record(bytes) else {
            return false;
        };
        self.note_version(bytes[0] == 3);
        // The label waits only for this record, whatever its state.
        let label = self.labels.remove(&(seen.process, seen.request));
        if matches!(record.state, 2 | 3 | 6) {
            let reason = match record.state {
                2 => "no_script",
                3 => "unsupported_thread",
                _ => "not_walked_thread_limit",
            };
            *self.not_walked.entry(reason).or_default() += 1;
            return true;
        }
        let label = label.unwrap_or_else(|| match self.label_text.find("request") {
            Some(id) => id,
            None => self.label_text.intern("request".to_owned()),
        });
        let sink = self.sinks.intern(Sink::Request(label));
        let (digest, innermost, unretained) = (record.digest, record.innermost, record.state != 1);
        let isolate = record.scope.isolate_key;
        let walk = self.walk(
            seen,
            isolate,
            digest,
            || Shape::Record(Box::new(record)),
            innermost,
        );
        let flipped = unretained && !walk.unretained;
        walk.unretained |= unretained;
        Self::reach(walk, sink);
        walk.requests.push(seen.request);
        if flipped {
            let index = self.by_digest[&((seen.process, isolate), digest)];
            self.changed(index);
        }
        true
    }

    fn navigation_stack(&mut self, seen: &Seen, bytes: &[u8]) -> bool {
        let Some((record, kind, _target)) = request_stack::decode_navigation(bytes) else {
            return false;
        };
        let sink = self.sinks.intern(Sink::Navigation(kind));
        let (digest, innermost, unretained) = (record.digest, record.innermost, record.state != 1);
        let walk = self.walk(
            seen,
            0,
            digest,
            || Shape::Record(Box::new(record)),
            innermost,
        );
        let flipped = unretained && !walk.unretained;
        walk.unretained |= unretained;
        Self::reach(walk, sink);
        if flipped {
            let index = self.by_digest[&((seen.process, 0), digest)];
            self.changed(index);
        }
        true
    }

    fn scheduling_stack(&mut self, seen: &Seen, bytes: &[u8]) -> bool {
        let Some((task, recorded, digest, innermost, isolate)) = decode_scheduling(bytes) else {
            return false;
        };
        self.note_version(bytes[0] == 2);
        let bounded = bytes[5] & 1 != 0;
        let walk = self.walk(
            seen,
            isolate,
            digest,
            || Shape::Scheduling(recorded),
            innermost,
        );
        let flipped = bounded && !walk.bounded;
        walk.bounded |= bounded;
        add(&mut walk.schedules, task, 1);
        add(&mut walk.pending.as_mut().unwrap().schedules, task, 1);
        if flipped {
            let index = self.by_digest[&((seen.process, isolate), digest)];
            self.changed(index);
        }
        true
    }

    /// A cookie write is checked by the rules `get_cookie_provenance`
    /// applies, which read the whole record.
    fn cookie_write(&mut self, seen: &Seen, line: &[u8]) -> bool {
        let Some(script) = serde_json::from_slice(line)
            .ok()
            .and_then(|event| request_cookies::decode_script(&event))
        else {
            return false;
        };
        // Only a write walks the stack (flags bits 1 and 2); a read keeps one
        // frame. A service worker's write is read in the worker's isolate; a
        // record that names no isolate records no frame to read.
        if let (true, Some(scope)) = (
            matches!(script.api, 1 | 3 | 6) && script.flags & 0x06 == 0x06,
            script.scope,
        ) {
            let api = request_cookies::APIS[usize::from(script.api)];
            let sink = self.sinks.intern(Sink::Cookie(api));
            let innermost = Frame::read(&script.frame);
            let walk = self.walk(
                seen,
                scope.isolate_key,
                script.stack,
                || Shape::Alone,
                innermost,
            );
            Self::reach(walk, sink);
        }
        true
    }
}
