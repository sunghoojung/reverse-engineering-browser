//! Filtered, cursor-paged reads of append-only JSONL evidence.
//!
//! The polling window in `event_window` answers "what is newest" for the UI.
//! These reads answer an agent's narrower question, such as "the Wasm samples
//! of one frame", without moving the whole tail. There is no cache: each
//! request reads at most one scan budget of complete, newline-terminated
//! records from an explicit byte cursor. A record still being written is not
//! returned until its newline arrives, so a cursor never splits a record.
//! Stored records are not rewritten; a filter only selects them. Responses add
//! `wasm_observation` beside the hex payload of native Wasm dispatch and
//! call_indirect events, and `wasm_overflow` beside an overflow identity.
//! That decode reads the payload only.
use crate::{
    app::{Query, validate_event},
    error::{Code, Error, Result},
    event_window::{self, NamedGap},
    evidence,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub const SCAN_BYTES: u64 = event_window::SCAN_BYTES as u64;
pub const EVENT_RECORD_BYTES: usize = 4096;
const CHUNK: usize = 64 * 1024;
const MAX_LIST: usize = 16;
const MAX_NAME: usize = 64;

/// Identity fields an event filter can match exactly. Values are compared as
/// unsigned integers, whether the record stores a decimal string or a number.
pub const EVENT_ID_FIELDS: [&str; 8] = [
    "session_id",
    "navigation_id",
    "frame_id",
    "tab_id",
    "process_id",
    "artifact_id",
    "request_id",
    "parent_event_id",
];

/// Where a page starts. Offsets are record boundaries in the store this
/// backend reads; they are not portable between stores or after a clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cursor {
    /// Newest complete records, reading backward from the last newline.
    Tail,
    /// Oldest records that start at or after this boundary, reading forward.
    After(u64),
    /// Newest records that end at or before this boundary, reading backward.
    Before(u64),
}

/// One page of matching records and the byte scope that produced it.
pub struct Page {
    pub records: Vec<Value>,
    /// Half-open byte scope of every record read, matched or not.
    pub scan_start: u64,
    pub scan_end: u64,
    /// File length when the read started.
    pub store_end: u64,
    /// Reading stopped because `limit` records matched.
    pub limited: bool,
    /// Reading stopped because the byte budget ran out.
    pub exhausted: bool,
}
impl Page {
    fn empty(cursor: u64, store_end: u64) -> Self {
        Self {
            records: Vec::new(),
            scan_start: cursor,
            scan_end: cursor,
            store_end,
            limited: false,
            exhausted: false,
        }
    }
    /// Paging fields shared by every filtered read.
    pub fn paging(&self, direction: &str, limit: usize) -> Value {
        json!({
            "direction": direction,
            "limit": limit,
            "returned": self.records.len(),
            "store_end": self.store_end.to_string(),
            "next_after": self.scan_end.to_string(),
            "next_before": (self.scan_start > 0).then(|| self.scan_start.to_string()),
            "limited": self.limited,
            "budget_exhausted": self.exhausted,
        })
    }
    pub fn scope(&self) -> &'static str {
        if self.scan_start == 0 && self.scan_end == self.store_end {
            "store"
        } else {
            "bounded_range"
        }
    }
}

/// Gap accounting with the same rules as the polling window, applied to the
/// records a filtered read actually scanned.
#[derive(Default)]
pub struct Tally {
    streams: HashMap<(u64, u64), (u64, u64, HashSet<u64>)>,
    queue_drops: u64,
    queue_drops_saturated: bool,
    named_gaps: Vec<NamedGap>,
}
impl Tally {
    pub fn record(&mut self, event: &Value) -> Result<()> {
        let session =
            event_window::unsigned(&event["session_id"]).ok_or_else(event_window::malformed)?;
        let process =
            event_window::unsigned(&event["process_id"]).ok_or_else(event_window::malformed)?;
        let sequence = event_window::unsigned(&event["sequence_number"])
            .ok_or_else(event_window::malformed)?;
        let stream = self
            .streams
            .entry((session, process))
            .or_insert_with(|| (sequence, sequence, HashSet::new()));
        stream.0 = stream.0.min(sequence);
        stream.1 = stream.1.max(sequence);
        stream.2.insert(sequence);
        if event["type"] != "gap" {
            return Ok(());
        }
        event_window::add(
            &mut self.queue_drops,
            &mut self.queue_drops_saturated,
            event_window::drop_weight(event),
        );
        if let Some(named) = event_window::named_gap(event) {
            let (category, reason) = *named;
            if let Some(gap) = self
                .named_gaps
                .iter_mut()
                .find(|gap| gap.category == category && gap.reason == reason)
            {
                gap.count += 1;
            } else if self.named_gaps.len() < event_window::MAX_NAMED_GAPS {
                self.named_gaps.push(NamedGap {
                    category,
                    reason,
                    count: 1,
                });
            }
        }
        Ok(())
    }
    pub fn named_gaps(&self) -> &[NamedGap] {
        &self.named_gaps
    }
    pub fn queue_drops(&self) -> (u64, bool) {
        (self.queue_drops, self.queue_drops_saturated)
    }
    /// Absent sequence IDs inside each stream's observed bounds.
    pub fn sequence_gaps(&self) -> (u64, bool) {
        let mut total = 0;
        let mut saturated = false;
        for (low, high, seen) in self.streams.values() {
            event_window::add(
                &mut total,
                &mut saturated,
                high - low - (seen.len() as u64 - 1),
            );
        }
        (total, saturated)
    }
    /// The gap fields of the `Events` document.
    pub fn write(&self, document: &mut Value) {
        let (gaps, gaps_saturated) = self.sequence_gaps();
        document["sequence_gaps"] = json!(gaps.to_string());
        document["sequence_gaps_saturated"] = json!(gaps_saturated);
        document["queue_drops"] = json!(self.queue_drops.to_string());
        document["queue_drops_saturated"] = json!(self.queue_drops_saturated);
        document["named_gaps"] = Value::Array(
            self.named_gaps
                .iter()
                .map(|gap| {
                    json!({"category": gap.category, "reason": gap.reason,
                        "count": gap.count.to_string()})
                })
                .collect(),
        );
    }
}

/// Comma-separated lowercase identifiers, at most 16. The same rule covers
/// event types, event categories and artifact kinds.
pub fn names(text: &str, label: &str) -> Result<Vec<String>> {
    let values = text.split(',').map(str::to_owned).collect::<Vec<_>>();
    if values.len() > MAX_LIST
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > MAX_NAME
                || !value.as_bytes()[0].is_ascii_lowercase()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(Error::bad(format!(
            "{label} must list 1 to {MAX_LIST} lowercase names separated by commas"
        )));
    }
    Ok(values)
}

/// Exact-match selection over stored event fields.
#[derive(Default)]
pub struct EventFilter {
    types: Vec<String>,
    categories: Vec<String>,
    ids: Vec<(&'static str, u64)>,
    since_ns: Option<u64>,
    until_ns: Option<u64>,
}
impl EventFilter {
    pub fn matches(&self, event: &Value) -> bool {
        let named = |names: &[String], value: &Value| {
            names.is_empty()
                || value
                    .as_str()
                    .is_some_and(|text| names.iter().any(|n| n == text))
        };
        let time = event_window::unsigned(&event["monotonic_time_ns"]);
        named(&self.types, &event["type"])
            && named(&self.categories, &event["category"])
            && self
                .ids
                .iter()
                .all(|(field, value)| event_window::unsigned(&event[*field]) == Some(*value))
            && self
                .since_ns
                .is_none_or(|since| time.is_some_and(|time| time >= since))
            && self
                .until_ns
                .is_none_or(|until| time.is_some_and(|time| time < until))
    }
    pub fn echo(&self) -> Value {
        let mut object = Map::new();
        if !self.types.is_empty() {
            object.insert("type".into(), json!(self.types));
        }
        if !self.categories.is_empty() {
            object.insert("category".into(), json!(self.categories));
        }
        for (field, value) in &self.ids {
            object.insert((*field).into(), json!(value.to_string()));
        }
        if let Some(since) = self.since_ns {
            object.insert("since_ns".into(), json!(since.to_string()));
        }
        if let Some(until) = self.until_ns {
            object.insert("until_ns".into(), json!(until.to_string()));
        }
        Value::Object(object)
    }
}

/// Filter and cursor keys accepted by the filtered event routes.
pub const EVENT_QUERY_KEYS: [&str; 14] = [
    "type",
    "category",
    "session_id",
    "navigation_id",
    "frame_id",
    "tab_id",
    "process_id",
    "artifact_id",
    "request_id",
    "parent_event_id",
    "since_ns",
    "until_ns",
    "after",
    "before",
];

pub fn event_filter(q: &Query) -> Result<EventFilter> {
    let mut filter = EventFilter::default();
    if let Some(text) = q.one("type")? {
        filter.types = names(text, "type")?;
    }
    if let Some(text) = q.one("category")? {
        filter.categories = names(text, "category")?;
    }
    for field in EVENT_ID_FIELDS {
        if q.one(field)?.is_some() {
            filter.ids.push((field, q.number(field, None, 64, false)?));
        }
    }
    if q.one("since_ns")?.is_some() {
        filter.since_ns = Some(q.number("since_ns", None, 64, false)?);
    }
    if q.one("until_ns")?.is_some() {
        filter.until_ns = Some(q.number("until_ns", None, 64, false)?);
    }
    Ok(filter)
}

/// `after` or `before`, never both. `None` means the newest records.
pub fn cursor(q: &Query) -> Result<Cursor> {
    match (q.one("after")?, q.one("before")?) {
        (Some(_), Some(_)) => Err(Error::bad("Pass after or before, not both")),
        (Some(_), None) => Ok(Cursor::After(q.number("after", None, 64, false)?)),
        (None, Some(_)) => Ok(Cursor::Before(q.number("before", None, 64, false)?)),
        (None, None) => Ok(Cursor::Tail),
    }
}

/// Reads one page of records from a JSONL store. `visit` parses, validates and
/// accounts for each record and returns it when the filter selects it.
pub fn read_page(
    path: &Path,
    cursor: Cursor,
    limit: usize,
    budget: u64,
    max_record: usize,
    mut visit: impl FnMut(&[u8]) -> Result<Option<Value>>,
) -> Result<Page> {
    let mut file = match evidence::regular_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return match cursor {
                Cursor::Tail | Cursor::After(0) | Cursor::Before(0) => Ok(Page::empty(0, 0)),
                _ => Err(cursor_error()),
            };
        }
        Err(error) => return Err(error.into()),
    };
    let length = file.metadata()?.len();
    let mut records = Vec::new();
    let mut limited = false;
    let mut select = |line: &[u8]| -> Result<bool> {
        if let Some(record) = visit(line)? {
            records.push(record);
            if records.len() >= limit {
                limited = true;
                return Ok(false);
            }
        }
        Ok(true)
    };
    let page = match cursor {
        Cursor::After(from) => {
            require_boundary(&mut file, length, from)?;
            let (end, exhausted) =
                forward(&mut file, length, from, budget, max_record, &mut select)?;
            Page {
                records: Vec::new(),
                scan_start: from,
                scan_end: end,
                store_end: length,
                limited: false,
                exhausted,
            }
        }
        Cursor::Tail | Cursor::Before(_) => {
            let to = match cursor {
                Cursor::Before(to) => {
                    require_boundary(&mut file, length, to)?;
                    to
                }
                _ => last_boundary(&mut file, length, max_record)?,
            };
            let (start, exhausted) = backward(&mut file, to, budget, max_record, &mut select)?;
            Page {
                records: Vec::new(),
                scan_start: start,
                scan_end: to,
                store_end: length,
                limited: false,
                exhausted,
            }
        }
    };
    if matches!(cursor, Cursor::Tail | Cursor::Before(_)) {
        records.reverse();
    }
    Ok(Page {
        records,
        limited,
        ..page
    })
}

fn cursor_error() -> Error {
    Error::bad(
        "The cursor is not a record boundary in this evidence store. Start again without a cursor.",
    )
}

fn require_boundary(file: &mut File, length: u64, offset: u64) -> Result<()> {
    if offset > length {
        return Err(cursor_error());
    }
    if offset == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(offset - 1))?;
    let mut byte = [0];
    file.read_exact(&mut byte)?;
    if byte[0] != b'\n' {
        return Err(cursor_error());
    }
    Ok(())
}

/// The position after the last newline. A trailing record without one is
/// still being written and is left for a later read.
fn last_boundary(file: &mut File, length: u64, max_record: usize) -> Result<u64> {
    let window = length.min(max_record as u64 + 1);
    file.seek(SeekFrom::Start(length - window))?;
    let mut tail = vec![0; window as usize];
    file.read_exact(&mut tail)?;
    match tail.iter().rposition(|byte| *byte == b'\n') {
        Some(index) => Ok(length - window + index as u64 + 1),
        None if window == length => Ok(0),
        None => Err(oversized()),
    }
}

fn oversized() -> Error {
    Error::new(500, "The evidence store contains an oversized record")
}

fn whitespace(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

/// Visits complete records in `[from, from + budget)` in file order. Returns
/// the end of the last record read and whether the budget stopped it.
fn forward(
    file: &mut File,
    length: u64,
    from: u64,
    budget: u64,
    max_record: usize,
    visit: &mut impl FnMut(&[u8]) -> Result<bool>,
) -> Result<(u64, bool)> {
    let limit = length.min(from.saturating_add(budget));
    let mut position = from;
    let mut read = from;
    let mut buffer = Vec::new();
    let mut consumed = 0usize;
    file.seek(SeekFrom::Start(from))?;
    loop {
        while let Some(newline) = buffer[consumed..].iter().position(|byte| *byte == b'\n') {
            let line = &buffer[consumed..consumed + newline];
            if line.len() > max_record {
                return Err(oversized());
            }
            let more = whitespace(line) || visit(line)?;
            position += newline as u64 + 1;
            consumed += newline + 1;
            if !more {
                return Ok((position, false));
            }
        }
        if buffer.len() - consumed > max_record {
            return Err(oversized());
        }
        if read >= limit {
            // At the end of the file, unterminated bytes are a record still
            // being written. Before it, the budget stopped the read.
            return Ok((position, limit < length));
        }
        buffer.drain(..consumed);
        consumed = 0;
        let size = (limit - read).min(CHUNK as u64) as usize;
        let start = buffer.len();
        buffer.resize(start + size, 0);
        file.read_exact(&mut buffer[start..])?;
        read += size as u64;
    }
}

/// Visits complete records ending at or before `to`, newest first, while their
/// bytes fit in `budget`. Returns the start of the oldest record read and
/// whether the budget stopped it. `to` must be a record boundary.
fn backward(
    file: &mut File,
    to: u64,
    budget: u64,
    max_record: usize,
    visit: &mut impl FnMut(&[u8]) -> Result<bool>,
) -> Result<(u64, bool)> {
    // `buffer` holds the file bytes `[position, end)`; `end` is the boundary
    // after the next record to visit.
    let mut position = to;
    let mut end = to;
    let mut buffer: Vec<u8> = Vec::new();
    while end > 0 {
        // The byte before `end` is this record's newline once it is buffered.
        let body = (end - position) as usize;
        let found = if body == 0 {
            None
        } else {
            buffer[..body - 1].iter().rposition(|byte| *byte == b'\n')
        };
        let start = match found {
            Some(index) => position + index as u64 + 1,
            None if position == 0 => 0,
            None => {
                if body > max_record + 1 {
                    return Err(oversized());
                }
                let size = position.min(CHUNK as u64) as usize;
                position -= size as u64;
                let mut chunk = vec![0; size];
                file.seek(SeekFrom::Start(position))?;
                file.read_exact(&mut chunk)?;
                chunk.extend_from_slice(&buffer);
                buffer = chunk;
                continue;
            }
        };
        if to - start > budget {
            return Ok((end, true));
        }
        let from = (start - position) as usize;
        let line = &buffer[from..from + (end - start) as usize - 1];
        if line.len() > max_record {
            return Err(oversized());
        }
        let more = whitespace(line) || visit(line)?;
        end = start;
        buffer.truncate(from);
        if !more {
            break;
        }
    }
    Ok((end, false))
}

/// Parses and validates one stored event, counts it, and returns it when the
/// filter selects it.
pub fn event_visitor<'a>(
    filter: &'a EventFilter,
    tally: &'a mut Tally,
) -> impl FnMut(&[u8]) -> Result<Option<Value>> + 'a {
    move |line| {
        let event: Value = serde_json::from_slice(line).map_err(|_| event_window::malformed())?;
        validate_event(&event)?;
        tally.record(&event)?;
        Ok(filter.matches(&event).then_some(event))
    }
}

/// A filtered event page in the `Events` document shape. The polling-only
/// network window is empty here: select network records with `category`.
pub fn events_document(
    page: &Page,
    tally: &Tally,
    filter: &EventFilter,
    cursor: Cursor,
    limit: usize,
) -> Value {
    let direction = if matches!(cursor, Cursor::After(_)) {
        "forward"
    } else {
        "backward"
    };
    let mut query = page.paging(direction, limit);
    query["filters"] = filter.echo();
    let mut document = json!({
        "count": page.records.len(),
        "event_window": {
            "scope": page.scope(),
            "scan_start": page.scan_start.to_string(),
            "scan_end": page.scan_end.to_string(),
            "scan_limit": event_window::SCAN_BYTES,
            "events_limited": page.limited,
            "network_events_limited": false
        },
        "query": query,
        "network_events": [],
    });
    tally.write(&mut document);
    let mut events = page.records.clone();
    crate::vm_opcode::annotate_wasm_observations(&mut events);
    document["events"] = Value::Array(events);
    document
}

/// The waiting read stops at this many concurrent callers rather than queue.
pub const MAX_WAITERS: usize = 8;
pub const MAX_WAIT_MS: u64 = 60_000;

pub fn wait_timeout(q: &Query) -> Result<u64> {
    let timeout = q.number("timeout_ms", Some("10000"), 64, true)?;
    if timeout > MAX_WAIT_MS {
        return Err(Error::bad(format!(
            "timeout_ms must be between 1 and {MAX_WAIT_MS}"
        )));
    }
    Ok(timeout)
}

pub fn waiters_full() -> Error {
    Error::new(503, "Too many waiting event reads; retry explicitly").with_code(Code::ResourceLimit)
}

/// Where a wait without `after` begins: the end of the complete records now,
/// so only records written after the call are returned.
pub fn current_boundary(path: &Path) -> Result<u64> {
    let mut file = match evidence::regular_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(0);
    }
    last_boundary(&mut file, length, EVENT_RECORD_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn event(sequence: u64, kind: &str, frame: u64) -> Value {
        json!({"protocol_version":3,"session_id":"1","sequence_number":sequence.to_string(),
            "monotonic_time_ns":(sequence * 10).to_string(),"navigation_id":"1",
            "frame_id":frame.to_string(),"artifact_id":"0","request_id":"0","process_id":7,
            "tab_id":3,"category":"wasm","type":kind,"payload_encoding":"hex","payload":"",
            "payload_size":0})
    }
    fn store(events: &[Value]) -> (tempfile::TempDir, std::path::PathBuf, Vec<u64>) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for event in events {
            serde_json::to_writer(&mut bytes, event).unwrap();
            bytes.push(b'\n');
            ends.push(bytes.len() as u64);
        }
        fs::write(&path, &bytes).unwrap();
        (root, path, ends)
    }
    fn sequences(page: &Page) -> Vec<u64> {
        page.records
            .iter()
            .map(|event| event_window::unsigned(&event["sequence_number"]).unwrap())
            .collect()
    }
    fn query(path: &Path, filter: &EventFilter, cursor: Cursor, limit: usize, budget: u64) -> Page {
        let mut tally = Tally::default();
        read_page(
            path,
            cursor,
            limit,
            budget,
            EVENT_RECORD_BYTES,
            event_visitor(filter, &mut tally),
        )
        .unwrap()
    }

    #[test]
    fn pages_cover_every_match_once_in_both_directions() {
        let events: Vec<_> = (1..=20)
            .map(|n| {
                event(
                    n,
                    if n % 3 == 0 {
                        "module_compiled"
                    } else {
                        "api_call"
                    },
                    n % 2,
                )
            })
            .collect();
        let (_root, path, ends) = store(&events);
        let filter = EventFilter {
            types: vec!["module_compiled".into()],
            ..Default::default()
        };
        let tail = query(&path, &filter, Cursor::Tail, 2, SCAN_BYTES);
        assert_eq!(sequences(&tail), vec![15, 18]);
        assert!(tail.limited);
        assert_eq!(tail.scan_end, *ends.last().unwrap());
        assert_eq!(tail.scan_start, ends[13]);
        let older = query(
            &path,
            &filter,
            Cursor::Before(tail.scan_start),
            2,
            SCAN_BYTES,
        );
        assert_eq!(sequences(&older), vec![9, 12]);
        let oldest = query(
            &path,
            &filter,
            Cursor::Before(older.scan_start),
            2,
            SCAN_BYTES,
        );
        assert_eq!(sequences(&oldest), vec![3, 6]);
        let none = query(
            &path,
            &filter,
            Cursor::Before(oldest.scan_start),
            2,
            SCAN_BYTES,
        );
        assert!(none.records.is_empty() && !none.limited);
        assert_eq!(none.scan_start, 0);
        let forward = query(&path, &filter, Cursor::After(0), 4, SCAN_BYTES);
        assert_eq!(sequences(&forward), vec![3, 6, 9, 12]);
        assert_eq!(forward.scan_end, ends[11]);
        let rest = query(
            &path,
            &filter,
            Cursor::After(forward.scan_end),
            4,
            SCAN_BYTES,
        );
        assert_eq!(sequences(&rest), vec![15, 18]);
        assert!(!rest.limited);
        assert_eq!(rest.scan_end, rest.store_end);
    }

    #[test]
    fn identity_time_and_category_filters_select_exact_records() {
        let events: Vec<_> = (1..=10).map(|n| event(n, "api_call", n % 2)).collect();
        let (_root, path, _) = store(&events);
        let filter = EventFilter {
            categories: vec!["wasm".into()],
            ids: vec![("frame_id", 1), ("tab_id", 3)],
            since_ns: Some(30),
            until_ns: Some(80),
            ..Default::default()
        };
        assert_eq!(
            sequences(&query(&path, &filter, Cursor::Tail, 100, SCAN_BYTES)),
            vec![3, 5, 7]
        );
        let other = EventFilter {
            ids: vec![("process_id", 8)],
            ..Default::default()
        };
        assert!(
            query(&path, &other, Cursor::Tail, 100, SCAN_BYTES)
                .records
                .is_empty()
        );
    }

    #[test]
    fn budget_stops_at_a_boundary_and_the_next_page_continues() {
        let events: Vec<_> = (1..=6).map(|n| event(n, "api_call", 1)).collect();
        let (_root, path, ends) = store(&events);
        let size = ends[0];
        let all = EventFilter::default();
        let first = query(&path, &all, Cursor::After(0), 100, size * 2 + 1);
        assert_eq!(sequences(&first), vec![1, 2]);
        assert!(first.exhausted && !first.limited);
        let next = query(&path, &all, Cursor::After(first.scan_end), 100, SCAN_BYTES);
        assert_eq!(sequences(&next), vec![3, 4, 5, 6]);
        let tail = query(&path, &all, Cursor::Tail, 100, size * 2 + 1);
        assert_eq!(sequences(&tail), vec![5, 6]);
        assert!(tail.exhausted);
    }

    #[test]
    fn cursors_must_name_record_boundaries_and_partial_tails_wait() {
        let events: Vec<_> = (1..=3).map(|n| event(n, "api_call", 1)).collect();
        let (_root, path, ends) = store(&events);
        let mut tally = Tally::default();
        let filter = EventFilter::default();
        for cursor in [
            Cursor::After(1),
            Cursor::Before(ends[0] + 1),
            Cursor::After(ends[2] + 1),
        ] {
            let error = read_page(
                &path,
                cursor,
                10,
                SCAN_BYTES,
                EVENT_RECORD_BYTES,
                event_visitor(&filter, &mut tally),
            )
            .err()
            .unwrap();
            assert_eq!(error.status, 400, "{cursor:?}");
        }
        let mut partial = fs::read(&path).unwrap();
        partial.extend_from_slice(br#"{"protocol_version":3,"session"#);
        fs::write(&path, &partial).unwrap();
        let tail = query(&path, &filter, Cursor::Tail, 10, SCAN_BYTES);
        assert_eq!(sequences(&tail), vec![1, 2, 3]);
        assert_eq!(tail.scan_end, ends[2]);
        let forward = query(&path, &filter, Cursor::After(ends[1]), 10, SCAN_BYTES);
        assert_eq!(sequences(&forward), vec![3]);
        assert_eq!(forward.scan_end, ends[2]);
        assert!(!forward.exhausted);
        assert_eq!(current_boundary(&path).unwrap(), ends[2]);
    }

    #[test]
    fn tally_counts_named_gaps_drops_and_sequence_holes_in_scope() {
        let mut events: Vec<_> = [1, 2, 5].iter().map(|n| event(*n, "api_call", 1)).collect();
        let mut gap = event(6, "gap", 1);
        gap["category"] = json!("vm");
        gap["payload"] = json!(hex::encode("native_guest_sample_limit"));
        gap["payload_size"] = json!(25);
        events.push(gap);
        let (_root, path, _) = store(&events);
        let mut tally = Tally::default();
        let filter = EventFilter {
            types: vec!["module_compiled".into()],
            ..Default::default()
        };
        let page = read_page(
            &path,
            Cursor::Tail,
            10,
            SCAN_BYTES,
            EVENT_RECORD_BYTES,
            event_visitor(&filter, &mut tally),
        )
        .unwrap();
        assert!(page.records.is_empty());
        assert_eq!(tally.sequence_gaps(), (2, false));
        assert_eq!(tally.queue_drops(), (1, false));
        assert_eq!(tally.named_gaps()[0].reason, "native_guest_sample_limit");
    }

    #[test]
    fn names_reject_empty_uppercase_and_oversized_lists() {
        assert_eq!(
            names("gap,api_call", "type").unwrap(),
            vec!["gap", "api_call"]
        );
        let long = vec!["a"; 17].join(",");
        for bad in ["", "Gap", "gap,", "1gap", "gap-call", long.as_str()] {
            assert!(names(bad, "type").is_err(), "{bad}");
        }
    }
}
