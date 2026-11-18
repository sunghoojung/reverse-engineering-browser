//! Identity indexes of the event store and the origin trace edge store
//! (`index_db`), so Origin Trace walks back through a session of any length
//! by identity instead of loading its newest records. The event index maps
//! `(session, process, sequence)` and request IDs to record byte ranges and
//! keeps each stream's queue-drop markers; the edge index maps an edge's
//! source event to its record. Records are read back from the stores, so the
//! indexes hold identifiers and offsets only.
//!
//! A trace refuses a damaged store as it always refused a damaged window: the
//! first oversized, malformed or duplicate record is kept as the index's damage
//! and every trace over that store returns it.
use crate::{
    error::{Error, Result},
    index_db::{self, Indexed, Position, SqlResult},
    origin_trace::{self, Reference},
};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};

pub const EVENTS_SUFFIX: &str = ".events-v1";
pub const EDGES_SUFFIX: &str = ".edges-v1";
const EVENTS_FORMAT: &str = "reb-event-index-v1";
const EDGES_FORMAT: &str = "reb-edge-index-v1";
/// The largest event or edge record a trace reads.
pub const RECORD_BYTES: usize = 4096;
/// Bytes folded per call, so a reader never waits on the index for long.
const FOLD_BYTES: u64 = 64 * 1024 * 1024;
/// How long a trace read may spend bringing its indexes up to the stores.
pub const TRACE_DEADLINE: Duration = Duration::from_secs(5);
/// `kind` of an indexed event: another type, or a `js_invocation_settle`,
/// which value flow reads by renderer stream.
const OTHER: i64 = 0;
const SETTLE: i64 = 1;
const EVENT_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS events(start INTEGER PRIMARY KEY, end INTEGER NOT NULL,
        session INTEGER NOT NULL, process INTEGER NOT NULL, sequence INTEGER NOT NULL,
        request INTEGER NOT NULL, kind INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS events_identity ON events(session, process, sequence);
    CREATE INDEX IF NOT EXISTS events_request ON events(request) WHERE request != 0;
    CREATE INDEX IF NOT EXISTS events_settles ON events(session, process) WHERE kind = 1;
    CREATE TABLE IF NOT EXISTS markers(session INTEGER NOT NULL, process INTEGER NOT NULL,
        count INTEGER NOT NULL, PRIMARY KEY(session, process)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS damage(id INTEGER PRIMARY KEY CHECK (id = 0),
        status INTEGER NOT NULL, message TEXT NOT NULL);";
const EDGE_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS edges(start INTEGER PRIMARY KEY, end INTEGER NOT NULL,
        session INTEGER NOT NULL, process INTEGER NOT NULL, sequence INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS edges_source ON edges(session, process, sequence);
    CREATE TABLE IF NOT EXISTS damage(id INTEGER PRIMARY KEY CHECK (id = 0),
        status INTEGER NOT NULL, message TEXT NOT NULL);";

/// What one event record is to a trace.
enum Event {
    Record(Reference, Value),
    /// A queue-drop marker of this stream.
    Marker(String, u32),
    /// A named capture-limit gap, which no trace reads.
    Ignored,
}

/// Reads one event line as the trace reads it. Gap markers share the last
/// event's identity and never stand for it: a queue-drop marker counts for
/// its stream, and a named capture-limit gap is a sampling limit, not a loss.
fn event(line: &[u8]) -> Result<Event> {
    if line.len() > RECORD_BYTES {
        return Err(Error::new(
            500,
            "The evidence store contains an oversized event",
        ));
    }
    let event: Value = serde_json::from_slice(line)
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| Error::new(500, "The evidence store contains a malformed event"))?;
    let reference = origin_trace::reference(&event)?;
    if event["type"] != "gap" {
        return Ok(Event::Record(reference, event));
    }
    Ok(match origin_trace::drop_marker(&event)? {
        Some((session, process, _)) => Event::Marker(session, process),
        None => Event::Ignored,
    })
}

/// Reads one edge line, validated, by its source.
fn edge(line: &[u8]) -> Result<(Reference, Value)> {
    if line.len() > RECORD_BYTES {
        return Err(Error::new(
            500,
            "The evidence store contains an oversized origin trace edge",
        ));
    }
    let edge: Value = serde_json::from_slice(line)
        .ok()
        .filter(Value::is_object)
        .ok_or_else(|| {
            Error::new(
                500,
                "The evidence store contains a malformed origin trace edge",
            )
        })?;
    Ok((origin_trace::validate_edge(&edge)?, edge))
}

fn number(value: &str) -> i64 {
    index_db::key(value.parse().unwrap_or(0))
}

fn damage(transaction: &rusqlite::Transaction<'_>, error: &Error) -> Result<()> {
    transaction
        .prepare_cached("INSERT OR IGNORE INTO damage(id, status, message) VALUES (0, ?1, ?2)")
        .sql()?
        .execute(params![error.status, error.message])
        .sql()?;
    Ok(())
}

fn fold_event(
    transaction: &rusqlite::Transaction<'_>,
    line: &[u8],
    start: u64,
    end: u64,
) -> Result<()> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let (reference, event) = match event(line) {
        Ok(Event::Record(reference, event)) => (reference, event),
        Ok(Event::Marker(session, process)) => {
            transaction
                .prepare_cached(
                    "INSERT INTO markers(session, process, count) VALUES (?1, ?2, 1)
                     ON CONFLICT(session, process) DO UPDATE SET count = count + 1",
                )
                .sql()?
                .execute(params![number(&session), i64::from(process)])
                .sql()?;
            return Ok(());
        }
        Ok(Event::Ignored) => return Ok(()),
        Err(error) => return damage(transaction, &error),
    };
    let identity = params![
        number(&reference.0),
        i64::from(reference.1),
        number(&reference.2)
    ];
    let duplicate = transaction
        .prepare_cached(
            "SELECT 1 FROM events WHERE session = ?1 AND process = ?2 AND sequence = ?3",
        )
        .sql()?
        .exists(identity)
        .sql()?;
    if duplicate {
        return damage(transaction, &duplicate_event());
    }
    let request = event["request_id"].as_str().map_or(0, number);
    let kind = if event["type"] == "js_invocation_settle" {
        SETTLE
    } else {
        OTHER
    };
    transaction
        .prepare_cached(
            "INSERT INTO events(start, end, session, process, sequence, request, kind)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .sql()?
        .execute(params![
            start as i64,
            end as i64,
            number(&reference.0),
            i64::from(reference.1),
            number(&reference.2),
            request,
            kind
        ])
        .sql()?;
    Ok(())
}

fn fold_edge(
    transaction: &rusqlite::Transaction<'_>,
    line: &[u8],
    start: u64,
    end: u64,
) -> Result<()> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let (source, _) = match edge(line) {
        Ok(edge) => edge,
        Err(error) => return damage(transaction, &error),
    };
    transaction
        .prepare_cached(
            "INSERT INTO edges(start, end, session, process, sequence) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .sql()?
        .execute(params![
            start as i64,
            end as i64,
            number(&source.0),
            i64::from(source.1),
            number(&source.2)
        ])
        .sql()?;
    Ok(())
}

fn duplicate_event() -> Error {
    Error::bad("Origin trace input contains a duplicate event reference")
}

type FoldLine = fn(&rusqlite::Transaction<'_>, &[u8], u64, u64) -> Result<()>;

/// One store and its identity index.
struct StoreIndex {
    index: Indexed,
    fold: FoldLine,
    oversized: &'static str,
}

impl StoreIndex {
    /// Folds appended records until caught up or past `deadline`. Returns the
    /// store and where the index stands, or None when there is no store.
    fn refresh(&mut self, deadline: Instant) -> Result<Option<(File, Position)>> {
        let Some((mut file, mut position)) = self.index.open()? else {
            return Ok(None);
        };
        while !position.caught_up(0) && Instant::now() < deadline {
            let before = position.indexed_to;
            position = self.index.sidecar().fold(
                &mut file,
                &position,
                FOLD_BYTES,
                deadline,
                RECORD_BYTES,
                self.oversized,
                &mut self.fold,
            )?;
            if position.indexed_to == before {
                break;
            }
        }
        Ok(Some((file, position)))
    }

    /// The first damaged record the index has folded, as the error a trace returns.
    fn damage(&mut self) -> Result<Option<Error>> {
        let damage: Option<(u16, String)> = self
            .index
            .sidecar()
            .connection()
            .query_row(
                "SELECT status, message FROM damage WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .sql()?;
        Ok(damage.map(|(status, message)| Error::new(status, message)))
    }

    fn records(
        &mut self,
        file: &mut File,
        sql: &str,
        parameters: impl rusqlite::Params,
    ) -> Result<Vec<Value>> {
        let ranges: Vec<(i64, i64)> = self
            .index
            .sidecar()
            .connection()
            .prepare_cached(sql)
            .sql()?
            .query_map(parameters, |row| Ok((row.get(0)?, row.get(1)?)))
            .sql()?
            .collect::<rusqlite::Result<_>>()
            .sql()?;
        ranges
            .into_iter()
            .map(|(start, end)| {
                serde_json::from_slice(&index_db::record(file, start, end)?)
                    .map_err(|_| Error::new(500, "An indexed evidence record changed"))
            })
            .collect()
    }
}

fn indexing(position: &Position) -> Error {
    Error::new(
        503,
        format!(
            "Origin Trace is still indexing the evidence stores ({} of {} MiB). Try again shortly.",
            position.indexed_to >> 20,
            position.file_end.div_ceil(1 << 20)
        ),
    )
}

/// The unterminated last line of a store, when it is a whole record. A writer
/// appends the newline last, so a line that parses as one object is complete;
/// anything shorter is a write in progress and is not read yet.
fn tail(file: &mut File, position: &Position) -> Result<Option<Vec<u8>>> {
    if position.indexed_to >= position.file_end || !position.caught_up(RECORD_BYTES as u64) {
        return Ok(None);
    }
    let bytes = index_db::read_range(file, position.indexed_to, position.file_end)?;
    if bytes.contains(&b'\n') {
        return Err(indexing(position));
    }
    let complete = serde_json::from_slice::<Value>(&bytes).is_ok_and(|value| value.is_object());
    Ok(complete.then_some(bytes))
}

/// The event and edge indexes of one session's stores.
pub struct Indexes {
    events: StoreIndex,
    edges: StoreIndex,
}

impl Indexes {
    pub fn new(store: &Path, trace_store: &Path) -> Self {
        Self {
            events: StoreIndex {
                index: Indexed::new(store, EVENTS_SUFFIX, EVENTS_FORMAT, EVENT_SCHEMA),
                fold: fold_event,
                oversized: "The evidence store contains an oversized event",
            },
            edges: StoreIndex {
                index: Indexed::new(trace_store, EDGES_SUFFIX, EDGES_FORMAT, EDGE_SCHEMA),
                fold: fold_edge,
                oversized: "The evidence store contains an oversized origin trace edge",
            },
        }
    }

    /// Folds appended records into both indexes until `deadline`.
    pub fn catch_up(&mut self, deadline: Instant) -> Result<()> {
        self.events.refresh(deadline)?;
        self.edges.refresh(deadline)?;
        Ok(())
    }

    /// Removes both indexes, before a capture clear empties their stores.
    pub fn discard(&mut self) -> Result<()> {
        self.events.index.discard()?;
        self.edges.index.discard()
    }

    /// The whole stores as one trace reads them, once both indexes are caught
    /// up. A trace over a partial index could end at a predecessor it has not
    /// reached yet, so a store still being indexed past `deadline` is refused
    /// with how far it got rather than traced.
    pub fn trace<'a>(
        &'a mut self,
        artifacts: &'a Path,
        deadline: Instant,
    ) -> Result<StoredEvidence<'a>> {
        let mut opened = Vec::new();
        for index in [&mut self.events, &mut self.edges] {
            let Some((mut file, position)) = index.refresh(deadline)? else {
                opened.push(None);
                continue;
            };
            if !position.caught_up(RECORD_BYTES as u64) {
                return Err(indexing(&position));
            }
            if let Some(error) = index.damage()? {
                return Err(error);
            }
            let tail = tail(&mut file, &position)?;
            opened.push(Some((file, tail)));
        }
        let mut opened = opened.into_iter();
        let (events, event_tail) = opened.next().flatten().unzip();
        let (edges, edge_tail) = opened.next().flatten().unzip();
        let mut evidence = StoredEvidence {
            indexes: self,
            events,
            edges,
            artifacts,
            event_tail: None,
            marker_tail: None,
            edge_tail: None,
        };
        match event_tail.flatten().map(|line| event(&line)).transpose()? {
            Some(Event::Record(reference, record)) => {
                if evidence.indexed_event(&reference)?.is_some() {
                    return Err(duplicate_event());
                }
                evidence.event_tail = Some((reference, record));
            }
            Some(Event::Marker(session, process)) => {
                evidence.marker_tail = Some((session, process))
            }
            Some(Event::Ignored) | None => {}
        }
        evidence.edge_tail = edge_tail.flatten().map(|line| edge(&line)).transpose()?;
        Ok(evidence)
    }
}

/// The whole stores of a session, read by identity through their indexes.
pub struct StoredEvidence<'a> {
    indexes: &'a mut Indexes,
    events: Option<File>,
    edges: Option<File>,
    artifacts: &'a Path,
    /// The stores' unterminated last records, which the indexes have not folded.
    event_tail: Option<(Reference, Value)>,
    marker_tail: Option<(String, u32)>,
    edge_tail: Option<(Reference, Value)>,
}

impl StoredEvidence<'_> {
    fn indexed_event(&mut self, reference: &Reference) -> Result<Option<Value>> {
        let Some(file) = self.events.as_mut() else {
            return Ok(None);
        };
        // Folding refuses a second record with one identity, so there is at most one.
        Ok(self
            .indexes
            .events
            .records(
                file,
                "SELECT start, end FROM events WHERE session = ?1 AND process = ?2 AND sequence = ?3",
                params![number(&reference.0), i64::from(reference.1), number(&reference.2)],
            )?
            .pop())
    }

    fn tail_event(&self, keep: impl Fn(&Reference, &Value) -> bool) -> Option<Value> {
        self.event_tail
            .as_ref()
            .filter(|(reference, event)| keep(reference, event))
            .map(|(_, event)| event.clone())
    }
}

impl origin_trace::Evidence for StoredEvidence<'_> {
    fn request_events(&mut self, request_id: &str) -> Result<Vec<Value>> {
        let mut events = match (self.events.as_mut(), request_id.parse::<u64>()) {
            // `request != 0` lets SQLite use the partial index, which a bound
            // parameter alone never implies.
            (Some(file), Ok(request @ 1..)) => self.indexes.events.records(
                file,
                "SELECT start, end FROM events WHERE request = ?1 AND request != 0 ORDER BY start",
                [index_db::key(request)],
            )?,
            _ => Vec::new(),
        };
        events.extend(self.tail_event(|_, event| event["request_id"] == request_id));
        Ok(events)
    }
    fn event(&mut self, reference: &Reference) -> Result<Option<Value>> {
        Ok(match self.indexed_event(reference)? {
            Some(event) => Some(event),
            None => self.tail_event(|tail, _| tail == reference),
        })
    }
    fn edges_from(&mut self, reference: &Reference) -> Result<Vec<Value>> {
        let mut edges = match self.edges.as_mut() {
            Some(file) => self.indexes.edges.records(
                file,
                "SELECT start, end FROM edges WHERE session = ?1 AND process = ?2 AND sequence = ?3 ORDER BY start",
                params![number(&reference.0), i64::from(reference.1), number(&reference.2)],
            )?,
            None => Vec::new(),
        };
        edges.extend(
            self.edge_tail
                .as_ref()
                .filter(|(source, _)| source == reference)
                .map(|(_, edge)| edge.clone()),
        );
        Ok(edges)
    }
    fn settles(&mut self, session: &str, process: u32) -> Result<Vec<Value>> {
        let mut settles = match self.events.as_mut() {
            Some(file) => self.indexes.events.records(
                file,
                "SELECT start, end FROM events WHERE session = ?1 AND process = ?2 AND kind = 1 ORDER BY start",
                params![number(session), i64::from(process)],
            )?,
            None => Vec::new(),
        };
        settles.extend(self.tail_event(|(s, p, _), event| {
            s == session && *p == process && event["type"] == "js_invocation_settle"
        }));
        Ok(settles)
    }
    fn drop_markers(&mut self, session: &str, process: u32) -> Result<u64> {
        let indexed: Option<i64> = match self.events {
            Some(_) => self
                .indexes
                .events
                .index
                .sidecar()
                .connection()
                .query_row(
                    "SELECT count FROM markers WHERE session = ?1 AND process = ?2",
                    params![number(session), i64::from(process)],
                    |row| row.get(0),
                )
                .optional()
                .sql()?,
            None => None,
        };
        let tail = self
            .marker_tail
            .as_ref()
            .is_some_and(|(s, p)| s == session && *p == process);
        Ok(indexed.unwrap_or(0) as u64 + u64::from(tail))
    }
    fn artifact(&mut self, id: &str) -> Result<Option<Value>> {
        match crate::evidence::find_artifact(self.artifacts, id) {
            Ok(artifact) => Ok(Some(artifact)),
            Err(error) if error.status == 404 => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin_trace::{RequestBodies, Retained, check_selectors, trace};
    use serde_json::json;

    fn write(path: &Path, rows: &[Value], terminated: bool) {
        let mut text = rows
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        if terminated && !rows.is_empty() {
            text.push('\n');
        }
        std::fs::write(path, text).unwrap();
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    type Query = (String, Option<String>, Option<u32>, Option<String>);

    fn query(case: &Value) -> Query {
        let query = &case["query"];
        let text = |key: &str| {
            query.get(key).map(|value| {
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned)
            })
        };
        (
            text("request_id").unwrap(),
            text("session_id"),
            query
                .get("root_process_id")
                .and_then(Value::as_u64)
                .map(|n| n as u32),
            text("root_sequence_number"),
        )
    }

    fn run(
        evidence: Result<impl origin_trace::Evidence>,
        bodies: &RequestBodies,
        query: &Query,
    ) -> Result<Value> {
        let (request, session, process, sequence) = query;
        check_selectors(request, session.as_deref(), *process, sequence.as_deref())?;
        trace(
            &mut evidence?,
            bodies,
            request,
            session.as_deref(),
            *process,
            sequence.as_deref(),
        )
    }

    /// Every shared case traces the same through the indexed stores as through
    /// slices, refusals included, with the last records terminated or not.
    #[test]
    fn shared_cases_trace_the_same_through_the_stores() {
        let root = tempfile::tempdir().unwrap();
        let (events_path, edges_path) = (
            root.path().join("events.jsonl"),
            root.path().join("trace.jsonl"),
        );
        let mut cases = 0;
        for fixture in [
            include_str!("../assets/origin-trace-gap-cases.json"),
            include_str!("../assets/origin-trace-invocation-cases.json"),
        ] {
            let fixture: Value = serde_json::from_str(fixture).unwrap();
            for case in fixture["cases"].as_array().unwrap() {
                let name = case["name"].as_str().unwrap();
                let pick = |kind: &str| -> Vec<Value> {
                    case[kind]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|key| fixture[kind][key.as_str().unwrap()].clone())
                        .collect()
                };
                let (events, edges) = (pick("events"), pick("edges"));
                let mut bodies = RequestBodies::new();
                for body in case["bodies"].as_array().into_iter().flatten() {
                    let body = &fixture["bodies"][body.as_str().unwrap()];
                    let parts: Vec<&str> = body["event"].as_str().unwrap().split(':').collect();
                    bodies.insert(
                        (parts[0].into(), parts[1].parse().unwrap(), parts[2].into()),
                        hex::decode(body["hex"].as_str().unwrap()).unwrap(),
                    );
                }
                let query = query(case);
                let sliced = run(Retained::new(&events, &edges, &[]), &bodies, &query);
                for terminated in [true, false] {
                    write(&events_path, &events, terminated);
                    write(&edges_path, &edges, terminated);
                    let mut indexes = Indexes::new(&events_path, &edges_path);
                    let stored = run(indexes.trace(root.path(), far()), &bodies, &query);
                    match (&stored, &sliced) {
                        (Ok(stored), Ok(sliced)) => assert_eq!(stored, sliced, "{name}"),
                        (Err(stored), Err(sliced)) => {
                            assert_eq!(
                                (stored.status, &stored.message),
                                (sliced.status, &sliced.message),
                                "{name}"
                            )
                        }
                        _ => panic!("{name}: stores {stored:?}, slices {sliced:?}"),
                    }
                    indexes.discard().unwrap();
                }
                cases += 1;
            }
        }
        assert!(cases > 50);
    }

    fn network(sequence: u64, request: u64, kind: &str) -> Value {
        json!({"protocol_version":3,"session_id":"7","sequence_number":sequence.to_string(),
            "monotonic_time_ns":(sequence * 10).to_string(),"process_id":42,"thread_id":0,"tab_id":0,
            "navigation_id":"0","frame_id":"0","artifact_id":"0","parent_event_id":"0",
            "request_id":request.to_string(),"payload_truncated":false,"category":"network",
            "type":kind,"payload_size":10,"payload_encoding":"hex","payload":hex::encode("GET a.test")})
    }

    fn parent(from: u64, to: u64, request: u64) -> Value {
        json!({"protocol_version":1,"session_id":"7","from_process_id":42,
            "from_sequence_number":from.to_string(),"to_process_id":42,
            "to_sequence_number":to.to_string(),"relation":"parent_event",
            "confidence":"observed","request_id":request.to_string(),"artifact_id":"0"})
    }

    fn steps(indexes: &mut Indexes, root: &Path, request: u64) -> Vec<String> {
        let mut evidence = indexes.trace(root, far()).unwrap();
        let document =
            origin_trace::build(&mut evidence, &request.to_string(), None, None, None, root)
                .unwrap();
        document["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| {
                step["event"]["sequence_number"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    /// The oldest request of a long store traces whole, appends are read on
    /// the next trace, and a rewritten store is reindexed rather than misread.
    #[test]
    fn the_oldest_request_of_a_long_store_traces_and_the_index_follows_the_store() {
        let root = tempfile::tempdir().unwrap();
        let (events_path, edges_path) = (
            root.path().join("events.jsonl"),
            root.path().join("trace.jsonl"),
        );
        let mut events = vec![
            network(1, 0, "runtime_read"),
            network(2, 1, "request_started"),
        ];
        events[0]["category"] = json!("runtime");
        events.extend((3..40_003).map(|sequence| network(sequence, sequence, "request_started")));
        write(&events_path, &events, true);
        write(&edges_path, &[parent(2, 1, 1)], true);
        let mut indexes = Indexes::new(&events_path, &edges_path);
        assert_eq!(steps(&mut indexes, root.path(), 1), ["2", "1"]);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&events_path)
            .unwrap();
        std::io::Write::write_all(
            &mut file,
            format!("{}\n", network(40_003, 50_000, "request_started")).as_bytes(),
        )
        .unwrap();
        assert_eq!(steps(&mut indexes, root.path(), 50_000), ["40003"]);

        write(&events_path, &[network(9, 1, "request_started")], true);
        assert_eq!(steps(&mut indexes, root.path(), 1), ["9"]);
        assert!(steps(&mut indexes, root.path(), 50_000).is_empty());

        indexes.discard().unwrap();
        for suffix in [EVENTS_SUFFIX, EDGES_SUFFIX] {
            assert!(!root.path().join(format!("events.jsonl{suffix}")).exists());
            assert!(!root.path().join(format!("trace.jsonl{suffix}")).exists());
        }
    }

    /// Past its deadline a trace refuses with how far indexing got and keeps
    /// that progress; damage folded once refuses every later trace.
    #[test]
    fn an_unindexed_store_is_refused_and_damage_is_kept() {
        let root = tempfile::tempdir().unwrap();
        let (events_path, edges_path) = (
            root.path().join("events.jsonl"),
            root.path().join("trace.jsonl"),
        );
        let events: Vec<Value> = (1..20_000)
            .map(|sequence| network(sequence, sequence, "request_started"))
            .collect();
        write(&events_path, &events, true);
        let mut indexes = Indexes::new(&events_path, &edges_path);
        let refused = indexes.trace(root.path(), Instant::now()).err().unwrap();
        assert_eq!(refused.status, 503);
        assert!(
            refused.message.contains("still indexing"),
            "{}",
            refused.message
        );
        assert_eq!(steps(&mut indexes, root.path(), 7), ["7"]);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&events_path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"{not json\n").unwrap();
        std::io::Write::write_all(
            &mut file,
            format!("{}\n", network(30_000, 30_000, "request_started")).as_bytes(),
        )
        .unwrap();
        for _ in 0..2 {
            let damaged = indexes.trace(root.path(), far()).err().unwrap();
            assert_eq!(
                (damaged.status, damaged.message.as_str()),
                (500, "The evidence store contains a malformed event")
            );
        }
        let mut reopened = Indexes::new(&events_path, &edges_path);
        assert_eq!(
            reopened.trace(root.path(), far()).err().unwrap().status,
            500
        );
    }
}
