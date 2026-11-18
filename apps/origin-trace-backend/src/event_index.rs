//! Identity indexes of the event store and the origin trace edge store
//! (`index_db`), so Origin Trace walks back through a session of any length
//! by identity instead of loading its newest records. The event index maps
//! `(session, process, sequence)` and request IDs to record byte ranges and
//! keeps each stream's queue-drop markers; the edge index maps an edge's
//! source event to its record. Records are read back from the stores, so the
//! indexes hold identifiers and offsets only. The event index also keeps the
//! whole store's gap totals (sequence gaps per stream, queue drops, named
//! capture-limit gaps and unreadable lines) with the rules of the polling
//! window, so `/api/events` counts every record instead of its newest bytes,
//! and the session summary's counts (`session_summary::Fold`), so a summary
//! covers the whole store by reading a few rows.
//!
//! A trace refuses a damaged store as it always refused a damaged window: the
//! first oversized, malformed or duplicate record is kept as the index's damage
//! and every trace over that store returns it.
//!
//! A third index maps each request root of the signal store to its newest
//! request signal profile, so Traffic's Signals finds a profile of any age.
use crate::{
    error::{Error, Result},
    event_window::{self, NamedGap},
    index_db::{self, Indexed, Position, SqlResult},
    origin_trace::{self, Reference},
    session_summary,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::Value;
use std::{
    collections::{HashMap, hash_map::Entry},
    fs::File,
    path::Path,
    time::{Duration, Instant},
};

pub const EVENTS_SUFFIX: &str = ".events-v1";
pub const EDGES_SUFFIX: &str = ".edges-v1";
pub const PROFILES_SUFFIX: &str = ".profiles-v1";
/// The second layout adds the gap totals, the third the summary's counts,
/// the fourth the debugger threads, the fifth the flow graph's record kind.
const EVENTS_FORMAT: &str = "reb-event-index-v1/5";
const EDGES_FORMAT: &str = "reb-edge-index-v1";
const PROFILES_FORMAT: &str = "reb-signal-profile-index-v1";
/// The largest event or edge record a trace reads.
pub const RECORD_BYTES: usize = 4096;
/// The largest request signal profile record: 8 KiB of profile with room
/// for the broker's encoding.
const PROFILE_BYTES: usize = 16384;
/// Bytes folded per call, so a reader never waits on the index for long.
const FOLD_BYTES: u64 = 64 * 1024 * 1024;
/// How long a trace read may spend bringing its indexes up to the stores.
pub const TRACE_DEADLINE: Duration = Duration::from_secs(5);
/// `kind` of an indexed event: another type, a `js_invocation_settle`, which
/// value flow reads by renderer stream, or one of the record types the flow
/// graph folds (`flow_graph::TYPES`), which it reads by session.
const OTHER: i64 = 0;
const SETTLE: i64 = 1;
const FLOW: i64 = 2;
pub(crate) const EVENT_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS events(start INTEGER PRIMARY KEY, end INTEGER NOT NULL,
        session INTEGER NOT NULL, process INTEGER NOT NULL, sequence INTEGER NOT NULL,
        request INTEGER NOT NULL, kind INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS events_identity ON events(session, process, sequence);
    CREATE INDEX IF NOT EXISTS events_request ON events(request) WHERE request != 0;
    CREATE INDEX IF NOT EXISTS events_settles ON events(session, process) WHERE kind = 1;
    CREATE INDEX IF NOT EXISTS events_flow ON events(session, start) WHERE kind = 2;
    CREATE TABLE IF NOT EXISTS markers(session INTEGER NOT NULL, process INTEGER NOT NULL,
        count INTEGER NOT NULL, PRIMARY KEY(session, process)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS damage(id INTEGER PRIMARY KEY CHECK (id = 0),
        status INTEGER NOT NULL, message TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS gap_sequences(session INTEGER NOT NULL, process INTEGER NOT NULL,
        sequence INTEGER NOT NULL, PRIMARY KEY(session, process, sequence)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS streams(session INTEGER NOT NULL, process INTEGER NOT NULL,
        low INTEGER NOT NULL, high INTEGER NOT NULL, seen INTEGER NOT NULL,
        PRIMARY KEY(session, process)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS named_gaps(ordinal INTEGER PRIMARY KEY, category TEXT NOT NULL,
        reason TEXT NOT NULL, count INTEGER NOT NULL, UNIQUE(category, reason));
    CREATE TABLE IF NOT EXISTS totals(id INTEGER PRIMARY KEY CHECK (id = 0),
        drops INTEGER NOT NULL, drops_saturated INTEGER NOT NULL, malformed INTEGER NOT NULL,
        events INTEGER NOT NULL DEFAULT 0, first_ns INTEGER, last_ns INTEGER);
    INSERT OR IGNORE INTO totals(id, drops, drops_saturated, malformed) VALUES (0, 0, 0, 0);
    -- The session summary's counts (session_summary::Fold). Identifiers keep
    -- their bits (`index_db::key`); times are below 2^63.
    CREATE TABLE IF NOT EXISTS summary_types(category TEXT NOT NULL, type TEXT NOT NULL,
        count INTEGER NOT NULL, PRIMARY KEY(category, type)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS summary_sessions(session INTEGER PRIMARY KEY, count INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS summary_frames(id INTEGER PRIMARY KEY, session INTEGER NOT NULL,
        tab INTEGER NOT NULL, navigation INTEGER NOT NULL, frame INTEGER NOT NULL,
        count INTEGER NOT NULL, first_ns INTEGER NOT NULL, last_ns INTEGER NOT NULL,
        UNIQUE(session, tab, navigation, frame));
    CREATE INDEX IF NOT EXISTS summary_frames_busiest ON summary_frames(count);
    CREATE TABLE IF NOT EXISTS summary_frame_types(frame INTEGER NOT NULL, type TEXT NOT NULL,
        count INTEGER NOT NULL, PRIMARY KEY(frame, type)) WITHOUT ROWID;
    -- Cumulative counts a producer repeats in each record, the newest kept:
    -- kind 0 is a capture exclusion of `class`, 1 unattributed header blocks
    -- and 2 unattributed cookie lists.
    CREATE TABLE IF NOT EXISTS summary_newest(kind INTEGER NOT NULL, session INTEGER NOT NULL,
        process INTEGER NOT NULL, class INTEGER NOT NULL, count INTEGER NOT NULL,
        PRIMARY KEY(kind, session, process, class)) WITHOUT ROWID;
    -- Content refusals by category and reason; category `artifact` holds the
    -- artifact_capture_failed reasons.
    CREATE TABLE IF NOT EXISTS summary_refusals(category TEXT NOT NULL, reason TEXT NOT NULL,
        count INTEGER NOT NULL, PRIMARY KEY(category, reason)) WITHOUT ROWID;
    -- Counts kept as rows change: `tab_rows`, `tab_extension_rows`,
    -- `unresolved:<reason>` and `missing:<reason>`.
    CREATE TABLE IF NOT EXISTS summary_counts(name TEXT PRIMARY KEY, count INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS summary_drops(session INTEGER NOT NULL, time INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS summary_drops_time ON summary_drops(session, time);
    -- Each browser request's header hops and lifecycle, and why its final
    -- block is missing, or null.
    CREATE TABLE IF NOT EXISTS summary_headers(session INTEGER NOT NULL, process INTEGER NOT NULL,
        request INTEGER NOT NULL, provisional INTEGER NOT NULL, network INTEGER NOT NULL,
        lifecycle INTEGER NOT NULL, first_ns INTEGER NOT NULL, last_ns INTEGER NOT NULL, reason TEXT,
        PRIMARY KEY(session, process, request)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS summary_headers_unsure ON summary_headers(session, last_ns)
        WHERE reason = 'not_reported';
    -- Each request row's tab facts (request_tabs), in first-seen order, and
    -- why it has no tab, or null.
    CREATE TABLE IF NOT EXISTS summary_tabs(ordinal INTEGER PRIMARY KEY, browser INTEGER NOT NULL,
        session INTEGER NOT NULL, process INTEGER NOT NULL, high INTEGER NOT NULL,
        low INTEGER NOT NULL, request INTEGER NOT NULL, linked INTEGER NOT NULL,
        extension INTEGER NOT NULL, process_id INTEGER NOT NULL, request_id INTEGER NOT NULL,
        renderer_kind INTEGER, renderer_frame INTEGER NOT NULL, browser_kind INTEGER, reason TEXT,
        UNIQUE(browser, session, process, high, low, request));
    CREATE INDEX IF NOT EXISTS summary_tabs_unresolved ON summary_tabs(ordinal)
        WHERE reason IS NOT NULL;
    -- Debugger threads (protocol/native-debugger-observation-v1.md): the
    -- native frame of every valid observation record, every
    -- debugger_observation_budget gap, and the worker of every request a
    -- worker started (loader kind 17 to 19), each with its newest record.
    CREATE TABLE IF NOT EXISTS observed_frames(session INTEGER NOT NULL, process INTEGER NOT NULL,
        frame INTEGER NOT NULL, records INTEGER NOT NULL, last_sequence INTEGER NOT NULL,
        last_start INTEGER NOT NULL, PRIMARY KEY(session, process, frame)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS observation_budget_gaps(start INTEGER PRIMARY KEY,
        session INTEGER NOT NULL, process INTEGER NOT NULL, frame INTEGER NOT NULL,
        sequence INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS workers(process INTEGER NOT NULL, context INTEGER NOT NULL,
        session INTEGER NOT NULL, kind INTEGER NOT NULL, requests INTEGER NOT NULL,
        last_sequence INTEGER NOT NULL, last_start INTEGER NOT NULL,
        PRIMARY KEY(process, context)) WITHOUT ROWID;";
const EDGE_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS edges(start INTEGER PRIMARY KEY, end INTEGER NOT NULL,
        session INTEGER NOT NULL, process INTEGER NOT NULL, sequence INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS edges_source ON edges(session, process, sequence);
    CREATE TABLE IF NOT EXISTS damage(id INTEGER PRIMARY KEY CHECK (id = 0),
        status INTEGER NOT NULL, message TEXT NOT NULL);";

// A profile is immutable once written; a later record for the same root
// replaces it, as the newest record did when the store was read backward.
const PROFILE_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS profiles(session TEXT NOT NULL, request TEXT NOT NULL,
        process INTEGER NOT NULL, sequence TEXT NOT NULL, start INTEGER NOT NULL,
        end INTEGER NOT NULL, PRIMARY KEY(session, request, process, sequence)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS damage(id INTEGER PRIMARY KEY CHECK (id = 0),
        status INTEGER NOT NULL, message TEXT NOT NULL);";

/// The exact request root a signal profile is selected by.
pub struct ProfileKey<'a> {
    pub session: &'a str,
    pub request: &'a str,
    pub process: u64,
    pub sequence: &'a str,
}

/// What one event record is to a trace.
enum Event {
    Record(Reference, Value),
    /// A gap marker, which shares the last event's identity: a queue-drop
    /// marker of its stream when `drop` names one, else a named capture-limit
    /// gap, which no trace reads.
    Gap {
        reference: Reference,
        event: Value,
        /// A marker the trace cannot read is damage to the trace, yet still
        /// a gap record to the totals, as it is to the polling window.
        drop: Result<Option<(String, u32)>>,
    },
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
    let drop = origin_trace::drop_marker(&event)
        .map(|marker| marker.map(|(session, process, _)| (session, process)));
    Ok(Event::Gap {
        reference,
        event,
        drop,
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

/// One stream's sequence bounds and how many distinct sequences it holds.
#[derive(Clone, Copy)]
struct Stream {
    low: u64,
    high: u64,
    seen: u64,
}

/// Folds event lines into identity rows, the gap totals and the summary's
/// counts. Totals change in memory during one fold and are written back in
/// `finish`, so they commit with the position they describe; `begin` drops
/// what a failed fold left.
#[derive(Default)]
struct EventFold {
    streams: HashMap<(i64, i64), Stream>,
    named: Vec<((String, String), u64)>,
    drops: u64,
    drops_saturated: bool,
    malformed: u64,
    summary: session_summary::Fold,
}

impl EventFold {
    fn stream(&mut self, transaction: &Transaction<'_>, key: (i64, i64)) -> Result<&mut Stream> {
        Ok(match self.streams.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let stored = transaction
                    .prepare_cached(
                        "SELECT low, high, seen FROM streams WHERE session = ?1 AND process = ?2",
                    )
                    .sql()?
                    .query_row(params![key.0, key.1], |row| {
                        Ok(Stream {
                            low: row.get::<_, i64>(0)? as u64,
                            high: row.get::<_, i64>(1)? as u64,
                            seen: row.get::<_, i64>(2)? as u64,
                        })
                    })
                    .optional()
                    .sql()?;
                entry.insert(stored.unwrap_or(Stream {
                    low: u64::MAX,
                    high: 0,
                    seen: 0,
                }))
            }
        })
    }

    /// Counts one sequence of a stream as the window does: bounds widen, and
    /// a sequence no earlier record of the stream held is one more seen.
    fn sequence(
        &mut self,
        transaction: &Transaction<'_>,
        reference: &Reference,
        fresh: bool,
    ) -> Result<()> {
        let key = (number(&reference.0), i64::from(reference.1));
        let sequence = number(&reference.2) as u64;
        let stream = self.stream(transaction, key)?;
        stream.low = stream.low.min(sequence);
        stream.high = stream.high.max(sequence);
        stream.seen += u64::from(fresh);
        Ok(())
    }

    fn gap(
        &mut self,
        transaction: &Transaction<'_>,
        reference: &Reference,
        event: &Value,
    ) -> Result<()> {
        let identity = params![
            number(&reference.0),
            i64::from(reference.1),
            number(&reference.2)
        ];
        // A marker shares the last event's identity, so it is seldom a new sequence.
        let known = transaction
            .prepare_cached(
                "SELECT 1 FROM events WHERE session = ?1 AND process = ?2 AND sequence = ?3",
            )
            .sql()?
            .exists(identity)
            .sql()?;
        let fresh = !known
            && transaction
                .prepare_cached(
                    "INSERT OR IGNORE INTO gap_sequences(session, process, sequence) VALUES (?1, ?2, ?3)",
                )
                .sql()?
                .execute(identity)
                .sql()?
                == 1;
        self.sequence(transaction, reference, fresh)?;
        event_window::add(
            &mut self.drops,
            &mut self.drops_saturated,
            event_window::drop_weight(event),
        );
        if let Some(named) = event_window::named_gap(event) {
            match self.named.iter_mut().find(|(pair, _)| *pair == *named) {
                Some((_, count)) => *count += 1,
                None => self.named.push((*named, 1)),
            }
        }
        Ok(())
    }

    fn record(
        &mut self,
        transaction: &Transaction<'_>,
        reference: &Reference,
        event: &Value,
        start: u64,
        end: u64,
        counted: bool,
    ) -> Result<()> {
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
            if counted {
                self.sequence(transaction, reference, false)?;
            }
            return damage(transaction, &duplicate_event());
        }
        if counted {
            let after_marker = transaction
                .prepare_cached(
                    "SELECT 1 FROM gap_sequences WHERE session = ?1 AND process = ?2 AND sequence = ?3",
                )
                .sql()?
                .exists(identity)
                .sql()?;
            self.sequence(transaction, reference, !after_marker)?;
        }
        let request = event["request_id"].as_str().map_or(0, number);
        let kind = match event["type"].as_str() {
            Some("js_invocation_settle") => SETTLE,
            Some(kind) if crate::flow_graph::TYPES.contains(&kind) => FLOW,
            _ => OTHER,
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
}

fn identifier(value: &Value) -> i64 {
    value.as_str().map_or(0, number)
}

/// A valid debugger observation counts for its native frame, and a request a
/// worker started counts for that worker; each keeps its newest record.
fn thread_record(transaction: &Transaction<'_>, event: &Value, start: u64) -> Result<()> {
    let kind = event["type"].as_str().unwrap_or("");
    let (session, process) = (
        identifier(&event["session_id"]),
        event["process_id"].as_i64().unwrap_or(0),
    );
    let sequence = identifier(&event["sequence_number"]);
    if crate::debugger_observation::TYPES.contains(&kind) {
        if crate::debugger_observation::decode(event).is_none() {
            return Ok(());
        }
        transaction
            .prepare_cached(
                "INSERT INTO observed_frames(session, process, frame, records, last_sequence, last_start)
                 VALUES (?1, ?2, ?3, 1, ?4, ?5)
                 ON CONFLICT(session, process, frame) DO UPDATE SET records = records + 1,
                     last_sequence = excluded.last_sequence, last_start = excluded.last_start",
            )
            .sql()?
            .execute(params![session, process, identifier(&event["frame_id"]), sequence, start as i64])
            .sql()?;
    } else if kind == "request_initiated"
        && let Some(worker @ 17..=19) = event["loader_kind"].as_i64()
    {
        transaction
            .prepare_cached(
                "INSERT INTO workers(process, context, session, kind, requests, last_sequence, last_start)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)
                 ON CONFLICT(process, context) DO UPDATE SET session = excluded.session,
                     kind = excluded.kind, requests = requests + 1,
                     last_sequence = excluded.last_sequence, last_start = excluded.last_start",
            )
            .sql()?
            .execute(params![process, identifier(&event["frame_id"]), session, worker, sequence, start as i64])
            .sql()?;
    }
    Ok(())
}

/// A renderer that ran out of its observation budget leaves one named gap.
fn budget_gap(transaction: &Transaction<'_>, event: &Value, start: u64) -> Result<()> {
    if event_window::named_gap(event).is_some_and(|named| {
        named.0 == "runtime" && named.1 == crate::debugger_observation::BUDGET_REASON
    }) {
        transaction
            .prepare_cached(
                "INSERT INTO observation_budget_gaps(start, session, process, frame, sequence)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .sql()?
            .execute(params![
                start as i64,
                identifier(&event["session_id"]),
                event["process_id"].as_i64().unwrap_or(0),
                identifier(&event["frame_id"]),
                identifier(&event["sequence_number"])
            ])
            .sql()?;
    }
    Ok(())
}

impl index_db::Fold for EventFold {
    fn begin(&mut self) {
        *self = Self::default();
    }

    fn line(
        &mut self,
        transaction: &Transaction<'_>,
        line: &[u8],
        start: u64,
        end: u64,
    ) -> Result<()> {
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        // The totals skip what the polling window skips: a line that is not a
        // valid event counts as unreadable, though a trace still reads it.
        let counted = |event: &Value| crate::app::validate_event(event).is_ok();
        match event(line) {
            Ok(Event::Record(reference, event)) => {
                let counted = counted(&event);
                self.malformed += u64::from(!counted);
                if counted {
                    self.summary.record(&event);
                    thread_record(transaction, &event, start)?;
                }
                self.record(transaction, &reference, &event, start, end, counted)
            }
            Ok(Event::Gap {
                reference,
                event,
                drop,
            }) => {
                if counted(&event) {
                    self.summary.record(&event);
                    self.gap(transaction, &reference, &event)?;
                    budget_gap(transaction, &event, start)?;
                } else {
                    self.malformed += 1;
                }
                match drop {
                    Ok(Some((session, process))) => {
                        transaction
                            .prepare_cached(
                                "INSERT INTO markers(session, process, count) VALUES (?1, ?2, 1)
                                 ON CONFLICT(session, process) DO UPDATE SET count = count + 1",
                            )
                            .sql()?
                            .execute(params![number(&session), i64::from(process)])
                            .sql()?;
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(error) => damage(transaction, &error),
                }
            }
            Err(error) => {
                self.malformed += 1;
                damage(transaction, &error)
            }
        }
    }

    fn finish(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        for ((session, process), stream) in self.streams.drain() {
            transaction
                .prepare_cached(
                    "INSERT OR REPLACE INTO streams(session, process, low, high, seen)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .sql()?
                .execute(params![
                    session,
                    process,
                    stream.low as i64,
                    stream.high as i64,
                    stream.seen as i64
                ])
                .sql()?;
        }
        // New pairs take the next ordinal, so the table keeps first-seen order.
        for ((category, reason), count) in self.named.drain(..) {
            transaction
                .prepare_cached(
                    "INSERT INTO named_gaps(category, reason, count) VALUES (?1, ?2, ?3)
                     ON CONFLICT(category, reason) DO UPDATE SET count = count + excluded.count",
                )
                .sql()?
                .execute(params![category, reason, count as i64])
                .sql()?;
        }
        let (drops, saturated, malformed): (i64, bool, i64) = transaction
            .query_row(
                "SELECT drops, drops_saturated, malformed FROM totals WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .sql()?;
        let (mut drops, mut saturated) = (drops as u64, saturated);
        event_window::add(&mut drops, &mut saturated, self.drops);
        transaction
            .execute(
                "UPDATE totals SET drops = ?1, drops_saturated = ?2, malformed = ?3 WHERE id = 0",
                params![
                    drops as i64,
                    saturated || self.drops_saturated,
                    (malformed as u64).saturating_add(self.malformed) as i64
                ],
            )
            .sql()?;
        self.summary.write(transaction)?;
        *self = Self::default();
        Ok(())
    }
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

fn malformed_profile() -> Error {
    Error::new(
        500,
        "The evidence store contains a malformed request signal profile",
    )
}

/// Indexes one profile by its request root. A damaged line stops every
/// lookup, as it did when the newest profiles were read and validated whole.
fn fold_profile(
    transaction: &rusqlite::Transaction<'_>,
    line: &[u8],
    start: u64,
    end: u64,
) -> Result<()> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    if line.len() > PROFILE_BYTES {
        return damage(
            transaction,
            &Error::new(
                500,
                "The evidence store contains an oversized request signal profile",
            ),
        );
    }
    let Ok(profile) = serde_json::from_slice::<Value>(line) else {
        return damage(transaction, &malformed_profile());
    };
    let root = &profile["root_event"];
    let (Some(session), Some(request), Some(process), Some(sequence)) = (
        profile["session_id"].as_str(),
        profile["request_id"].as_str(),
        root["process_id"].as_u64(),
        root["sequence_number"].as_str(),
    ) else {
        return damage(transaction, &malformed_profile());
    };
    transaction
        .prepare_cached(
            "INSERT OR REPLACE INTO profiles(session, request, process, sequence, start, end)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .sql()?
        .execute(params![
            session,
            request,
            index_db::key(process),
            sequence,
            start as i64,
            end as i64
        ])
        .sql()?;
    Ok(())
}

fn duplicate_event() -> Error {
    Error::bad("Origin trace input contains a duplicate event reference")
}

/// One store and its identity index.
struct StoreIndex {
    index: Indexed,
    fold: Box<dyn index_db::Fold + Send>,
    oversized: &'static str,
    /// The longest unterminated tail that can still become a record.
    max_line: usize,
}

impl StoreIndex {
    /// Folds appended records until caught up or past `deadline`. Returns the
    /// store and where the index stands, or None when there is no store.
    fn refresh(&mut self, deadline: Instant) -> Result<Option<(File, Position)>> {
        let Some((mut file, mut position)) = self.index.open()? else {
            return Ok(None);
        };
        while !position.caught_up() && Instant::now() < deadline {
            let before = position.indexed_to;
            position = self.index.sidecar().fold(
                &mut file,
                &position,
                FOLD_BYTES,
                deadline,
                self.max_line,
                self.oversized,
                self.fold.as_mut(),
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
    if position.indexed_to >= position.file_end || !position.caught_up() {
        return Ok(None);
    }
    let bytes = index_db::read_range(file, position.indexed_to, position.file_end)?;
    if bytes.contains(&b'\n') {
        return Err(indexing(position));
    }
    let complete = serde_json::from_slice::<Value>(&bytes).is_ok_and(|value| value.is_object());
    Ok(complete.then_some(bytes))
}

/// How long a record lookup folds appended records before it answers from
/// where the index stands; the background indexer keeps it within a second
/// of the store.
pub const LOCATE_DEADLINE: Duration = Duration::from_secs(1);

/// Where one record sits: its byte range when the indexed prefix holds it,
/// and how far that prefix reaches. Absent from a caught-up index is absent
/// from the store, but for an unterminated record still being written.
pub struct Located {
    pub range: Option<(u64, u64)>,
    pub indexed_to: u64,
    pub store_end: u64,
    pub caught_up: bool,
}

/// The whole event store's gap totals, with the polling window's rules.
#[derive(Debug, PartialEq)]
pub struct Totals {
    /// The store bytes they cover, from its start: every terminated record.
    pub indexed_to: u64,
    pub sequence_gaps: u64,
    pub sequence_gaps_saturated: bool,
    pub queue_drops: u64,
    pub queue_drops_saturated: bool,
    /// In first-seen order.
    pub named_gaps: Vec<NamedGap>,
    pub malformed_lines: u64,
}

/// The gap totals of the indexed prefix `position` names.
pub fn totals(connection: &Connection, position: &Position) -> Result<Totals> {
    let mut sequence_gaps = 0;
    let mut sequence_gaps_saturated = false;
    let streams = connection
        .prepare_cached("SELECT low, high, seen FROM streams")
        .sql()?
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
            ))
        })
        .sql()?
        .collect::<rusqlite::Result<Vec<_>>>()
        .sql()?;
    for (low, high, seen) in streams {
        // `seen` distinct sequences lie in [low, high], so this never underflows.
        event_window::add(
            &mut sequence_gaps,
            &mut sequence_gaps_saturated,
            high - low - (seen - 1),
        );
    }
    let named_gaps = connection
        .prepare_cached("SELECT category, reason, count FROM named_gaps ORDER BY ordinal")
        .sql()?
        .query_map([], |row| {
            Ok(NamedGap {
                category: row.get(0)?,
                reason: row.get(1)?,
                count: row.get::<_, i64>(2)? as u64,
            })
        })
        .sql()?
        .collect::<rusqlite::Result<Vec<_>>>()
        .sql()?;
    let (queue_drops, queue_drops_saturated, malformed_lines) = connection
        .query_row(
            "SELECT drops, drops_saturated, malformed FROM totals WHERE id = 0",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, bool>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            },
        )
        .sql()?;
    Ok(Totals {
        indexed_to: position.indexed_to,
        sequence_gaps,
        sequence_gaps_saturated,
        queue_drops,
        queue_drops_saturated,
        named_gaps,
        malformed_lines,
    })
}

/// The event index as the session summary reads it.
pub struct SummaryIndex<'a> {
    pub position: Position,
    /// Why the index cannot read past `position`, when it cannot.
    pub stopped: Option<Error>,
    pub connection: &'a Connection,
}

/// One session's flow graph records as the event index holds them.
pub struct FlowRows {
    /// Where the index stands; every row starts below `indexed_to`.
    pub position: Position,
    /// Byte ranges `[start, end)` of the records, the newline included.
    pub rows: Vec<(u64, u64)>,
    /// The first record the index refused, which no row stands for.
    pub damage: Option<Error>,
}

/// The event and edge indexes of one session's stores.
pub struct Indexes {
    events: StoreIndex,
    edges: StoreIndex,
    profiles: StoreIndex,
}

impl Indexes {
    pub fn new(store: &Path, trace_store: &Path, signal_store: &Path) -> Self {
        Self {
            events: StoreIndex {
                index: Indexed::new(store, EVENTS_SUFFIX, EVENTS_FORMAT, EVENT_SCHEMA),
                fold: Box::<EventFold>::default(),
                oversized: "The evidence store contains an oversized event",
                max_line: RECORD_BYTES,
            },
            edges: StoreIndex {
                index: Indexed::new(trace_store, EDGES_SUFFIX, EDGES_FORMAT, EDGE_SCHEMA),
                fold: Box::new(fold_edge),
                oversized: "The evidence store contains an oversized origin trace edge",
                max_line: RECORD_BYTES,
            },
            profiles: StoreIndex {
                index: Indexed::new(
                    signal_store,
                    PROFILES_SUFFIX,
                    PROFILES_FORMAT,
                    PROFILE_SCHEMA,
                ),
                fold: Box::new(fold_profile),
                oversized: "The evidence store contains an oversized request signal profile",
                max_line: PROFILE_BYTES,
            },
        }
    }

    /// Folds appended records into every index until `deadline`. One store's
    /// failure does not stop the others from catching up.
    pub fn catch_up(&mut self, deadline: Instant) -> Result<()> {
        let events = self.events.refresh(deadline);
        let edges = self.edges.refresh(deadline);
        let profiles = self.profiles.refresh(deadline);
        events.and(edges).and(profiles).map(|_| ())
    }

    /// The newest request signal profile of one request root, from a signal
    /// store of any length; None when no indexed profile has that root. A
    /// root the index has not reached yet past `deadline` is refused with how
    /// far it got, since its profile may sit in the unindexed bytes.
    pub fn signal_profile(&mut self, key: &ProfileKey, deadline: Instant) -> Result<Option<Value>> {
        let Some((mut file, position)) = self.profiles.refresh(deadline)? else {
            return Ok(None);
        };
        if let Some(error) = self.profiles.damage()? {
            return Err(error);
        }
        let range: Option<(i64, i64)> = self
            .profiles
            .index
            .sidecar()
            .connection()
            .prepare_cached(
                "SELECT start, end FROM profiles
                 WHERE session = ?1 AND request = ?2 AND process = ?3 AND sequence = ?4",
            )
            .sql()?
            .query_row(
                params![
                    key.session,
                    key.request,
                    index_db::key(key.process),
                    key.sequence
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .sql()?;
        let Some((start, end)) = range else {
            if !position.caught_up() {
                return Err(Error::new(
                    503,
                    format!(
                        "The request signal profiles are still being indexed ({} of {} MiB). Try again shortly.",
                        position.indexed_to >> 20,
                        position.file_end.div_ceil(1 << 20)
                    ),
                ));
            }
            return Ok(None);
        };
        let bytes = index_db::record(&mut file, start, end)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| malformed_profile())
    }

    /// The event store's gap totals once its index has caught up, folding
    /// until `deadline`. None while the index is behind, so a caller reports
    /// the window's counts rather than a part of the store as all of it, and
    /// when there is no store.
    pub fn event_totals(&mut self, deadline: Instant) -> Result<Option<Totals>> {
        let Some((_, position)) = self.events.refresh(deadline)? else {
            return Ok(None);
        };
        if !position.caught_up() {
            return Ok(None);
        }
        totals(self.events.index.sidecar().connection(), &position).map(Some)
    }

    /// Where the record `(session, process, sequence)` sits in an event store
    /// of any length, folding until `deadline`; None when there is no store.
    /// With no session, each session with a stream of `process` is looked up.
    /// A line the index cannot fold stops it there, and the answer says so.
    pub fn locate(
        &mut self,
        session: Option<u64>,
        process: u32,
        sequence: u64,
        deadline: Instant,
    ) -> Result<Option<Located>> {
        let (position, stopped) = match self.events.refresh(deadline) {
            Ok(None) => return Ok(None),
            Ok(Some((_, position))) => (position, false),
            Err(_) => match self.events.index.open()? {
                Some((_, position)) => (position, true),
                None => return Ok(None),
            },
        };
        let connection = self.events.index.sidecar().connection();
        let sessions: Vec<i64> = match session {
            Some(session) => vec![index_db::key(session)],
            None => connection
                .prepare_cached("SELECT session FROM streams WHERE process = ?1")
                .sql()?
                .query_map([i64::from(process)], |row| row.get(0))
                .sql()?
                .collect::<rusqlite::Result<_>>()
                .sql()?,
        };
        let mut range = None;
        for session in sessions {
            range = connection
                .prepare_cached(
                    "SELECT start, end FROM events WHERE session = ?1 AND process = ?2 AND sequence = ?3",
                )
                .sql()?
                .query_row(
                    params![session, i64::from(process), index_db::key(sequence)],
                    |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
                )
                .optional()
                .sql()?;
            if range.is_some() {
                break;
            }
        }
        Ok(Some(Located {
            range,
            indexed_to: position.indexed_to,
            store_end: position.file_end,
            caught_up: !stopped && position.caught_up(),
        }))
    }

    /// The event index brought up to the store until `deadline`, for the
    /// session summary and the debugger threads, and where it stands; None
    /// when there is no store.
    /// Its counts and gap totals describe the same indexed prefix. A record
    /// the index cannot read stops it there, with that error beside it.
    pub fn summary_index(&mut self, deadline: Instant) -> Result<Option<SummaryIndex<'_>>> {
        let (position, stopped) = match self.events.refresh(deadline) {
            Ok(None) => return Ok(None),
            Ok(Some((_, position))) => (position, None),
            Err(error) => match self.events.index.open()? {
                Some((_, position)) => (position, Some(error)),
                None => return Ok(None),
            },
        };
        Ok(Some(SummaryIndex {
            position,
            stopped,
            connection: self.events.index.sidecar().connection(),
        }))
    }

    /// The flow graph's records of `session` that start at or after `from`,
    /// at most `limit` of them in store order, from the event index brought
    /// up to the store until `deadline`; None when there is no store.
    pub fn flow_rows(
        &mut self,
        session: u64,
        from: u64,
        limit: usize,
        deadline: Instant,
    ) -> Result<Option<FlowRows>> {
        let Some((_, position)) = self.events.refresh(deadline)? else {
            return Ok(None);
        };
        let damage = self.events.damage()?;
        // `kind = 2` lets SQLite use the partial index, which a bound
        // parameter alone never implies.
        let rows = self
            .events
            .index
            .sidecar()
            .connection()
            .prepare_cached(
                "SELECT start, end FROM events WHERE session = ?1 AND kind = 2 AND start >= ?2
                 ORDER BY start LIMIT ?3",
            )
            .sql()?
            .query_map(
                params![
                    index_db::key(session),
                    from as i64,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
            )
            .sql()?
            .collect::<rusqlite::Result<_>>()
            .sql()?;
        Ok(Some(FlowRows {
            position,
            rows,
            damage,
        }))
    }

    /// Removes every index, before a capture clear empties their stores.
    pub fn discard(&mut self) -> Result<()> {
        self.events.index.discard()?;
        self.edges.index.discard()?;
        self.profiles.index.discard()
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
            if !position.caught_up() {
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
            Some(Event::Gap { drop, .. }) => evidence.marker_tail = drop?,
            None => {}
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
                    let mut indexes = Indexes::new(
                        &events_path,
                        &edges_path,
                        &root.path().join("signals.jsonl"),
                    );
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
        let mut indexes = Indexes::new(
            &events_path,
            &edges_path,
            &root.path().join("signals.jsonl"),
        );
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
        let mut indexes = Indexes::new(
            &events_path,
            &edges_path,
            &root.path().join("signals.jsonl"),
        );
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
        let mut reopened = Indexes::new(
            &events_path,
            &edges_path,
            &root.path().join("signals.jsonl"),
        );
        assert_eq!(
            reopened.trace(root.path(), far()).err().unwrap().status,
            500
        );
    }

    /// The index's totals are the polling window's counts over the same whole
    /// store, folded in several passes: sequence gaps per stream (a marker's
    /// fresh sequence counts once, a duplicate never), queue drops with named
    /// weights, every named pair in first-seen order and unreadable lines.
    #[test]
    fn gap_totals_match_the_window_over_the_whole_store() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let event = |process: u64, sequence: u64, kind: &str, payload: &str| {
            json!({"protocol_version":3,"session_id":"1","sequence_number":sequence.to_string(),
                "monotonic_time_ns":"1","navigation_id":"1","frame_id":"1","artifact_id":"0",
                "request_id":"1","process_id":process,"category":"vm","type":kind,
                "payload_encoding":"hex","payload":hex::encode(payload),"payload_size":payload.len()})
        };
        let mut rows = vec![
            event(7, 1, "api_call", ""),
            event(7, 2, "api_call", ""),
            event(7, 2, "gap", "3"),
            event(7, 6, "api_call", ""),
            // A marker with a sequence of its own, and the record that repeats it.
            event(7, 9, "gap", "native_reason_a"),
            event(7, 9, "api_call", ""),
            event(8, 40, "api_call", ""),
            event(8, 40, "api_call", ""),
            event(8, 45, "gap", "native_reason_b"),
            event(8, 46, "gap", "native_reason_a"),
        ];
        rows.extend((0..300u64).map(|n| event(9, 2 * n + 1, "api_call", "")));
        let mut text = String::new();
        for (index, row) in rows.iter().enumerate() {
            text.push_str(&row.to_string());
            text.push('\n');
            if index == 3 {
                text.push_str("{\"not\":\"an event\"}\n");
            }
        }
        std::fs::write(&store, &text).unwrap();
        let mut indexes = Indexes::new(
            &store,
            &root.path().join("trace.jsonl"),
            &root.path().join("signals.jsonl"),
        );
        // A store the index has not folded yet has no totals.
        assert_eq!(indexes.event_totals(Instant::now()).unwrap(), None);
        let totals = indexes.event_totals(far()).unwrap().unwrap();
        let window = crate::event_window::EventWindowCache::default()
            .read(&store, 1, crate::app::validate_event, None)
            .unwrap();
        assert_eq!(window.coverage["scope"], "store");
        assert_eq!(
            (totals.sequence_gaps, totals.sequence_gaps_saturated),
            (window.sequence_gaps, window.sequence_gaps_saturated)
        );
        assert_eq!(totals.sequence_gaps, 3 + 1 + 5 + 299, "{totals:?}");
        assert_eq!(
            (totals.queue_drops, totals.queue_drops_saturated),
            (window.queue_drops, window.queue_drops_saturated)
        );
        assert_eq!(totals.queue_drops, 6);
        assert_eq!(totals.named_gaps, window.named_gaps);
        assert_eq!(totals.named_gaps[0].reason, "native_reason_a");
        assert_eq!(totals.named_gaps[0].count, 2);
        assert_eq!(totals.malformed_lines, 1);
        assert_eq!(totals.indexed_to, text.len() as u64);
        // Appended records fold into the same totals.
        let mut more = std::fs::OpenOptions::new()
            .append(true)
            .open(&store)
            .unwrap();
        use std::io::Write;
        writeln!(more, "{}", event(7, 12, "api_call", "")).unwrap();
        let grown = indexes.event_totals(far()).unwrap().unwrap();
        assert_eq!(grown.sequence_gaps, totals.sequence_gaps + 2);
        let window = crate::event_window::EventWindowCache::default()
            .read(&store, 1, crate::app::validate_event, None)
            .unwrap();
        assert_eq!(grown.sequence_gaps, window.sequence_gaps);
    }
}
