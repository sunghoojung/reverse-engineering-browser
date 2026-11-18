//! Phase 1 debugger records, protocol/native-debugger-observation-v1.md.

use std::{
    path::Path,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use crate::{
    error::Result,
    event_index::Indexes,
    event_query::{self, Cursor, EventFilter},
    index_db::SqlResult,
    request_stack::{self, u16_at, u32_at},
};

pub const TYPES: [&str; 6] = [
    "request_watch_match",
    "listener_dispatch",
    "timer_observation",
    "csp_violation",
    "exception_observation",
    "dom_mutation",
];
pub const RECENT: usize = 32;
/// The most records one filtered read returns.
pub const PAGE: usize = 256;
pub(crate) const BUDGET_REASON: &str = "debugger_observation_budget";

const TARGETS: [&str; 5] = ["element", "document", "window", "node", "other"];
const EXCEPTIONS: [&str; 3] = ["uncaught", "caught", "unhandled_rejection"];
const MUTATIONS: [&str; 3] = ["attribute", "subtree", "removal"];
// network::mojom::CSPDirectiveName at the Chromium pin.
const DIRECTIVES: [&str; 30] = [
    "unknown",
    "base-uri",
    "block-all-mixed-content",
    "child-src",
    "connect-src",
    "default-src",
    "fenced-frame-src",
    "font-src",
    "form-action",
    "frame-ancestors",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "report-to",
    "report-uri",
    "require-trusted-types-for",
    "sandbox",
    "script-src",
    "script-src-v2",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "treat-as-public-address",
    "trusted-types",
    "upgrade-insecure-requests",
    "worker-src",
];

/// A kind 1 frame, or null for an all-zero one.
fn frame(bytes: &[u8]) -> Option<Value> {
    if bytes.iter().all(|b| *b == 0) {
        return Some(Value::Null);
    }
    let script_id = u32_at(bytes, 4);
    (bytes[0] == 1 && script_id != 0 && u16_at(bytes, 2) == 0 && bytes[1] & !3 == 0).then(|| {
        json!({"script_id": script_id, "position": u32_at(bytes, 8),
            "function_start": u32_at(bytes, 12)})
    })
}

/// Printable ASCII of `length` bytes followed by zeros, as the core requires.
fn name(field: &[u8], length: u8, required: bool) -> Option<String> {
    let length = usize::from(length);
    let (text, rest) = field.split_at_checked(length)?;
    (!(required && text.is_empty())
        && text.iter().all(|b| (0x21..0x7f).contains(b))
        && rest.iter().all(|b| *b == 0))
    .then(|| String::from_utf8_lossy(text).into_owned())
}

fn detail(kind: &str, t: &[u8]) -> Option<Value> {
    let zero = |range: std::ops::Range<usize>| t[range].iter().all(|b| *b == 0);
    Some(match kind {
        "request_watch_match" if t[0] < 8 && t[1] & !1 == 0 && zero(2..48) => {
            json!({"rule": t[0], "method_matched": t[1] == 1})
        }
        "listener_dispatch" if t[0] < 16 && (1..=5).contains(&t[1]) => json!({
            "rule": t[0],
            "target": TARGETS[usize::from(t[1] - 1)],
            "node_type": u16_at(t, 2),
            "listener": frame(&t[4..20])?,
            "event_type": name(&t[21..48], t[20], true)?,
        }),
        "timer_observation"
            if (1..=2).contains(&t[0])
                && (1..=2).contains(&t[1])
                && t[2] & !1 == 0
                && t[3] == 0
                && zero(28..48) =>
        {
            json!({
                "phase": if t[0] == 1 { "scheduled" } else { "fired" },
                "kind": if t[1] == 1 { "timeout" } else { "interval" },
                "string_callback": t[2] == 1,
                "timer_id": u32_at(t, 4),
                "delay_ms": u32_at(t, 8),
                "callback": frame(&t[12..28])?,
            })
        }
        "csp_violation" if (1..=2).contains(&t[1]) => json!({
            "directive": DIRECTIVES.get(usize::from(t[0])).copied().unwrap_or("unknown"),
            "directive_value": t[0],
            "disposition": if t[1] == 1 { "enforce" } else { "report" },
            "blocked_host": name(&t[3..48], t[2], false)?,
        }),
        "exception_observation" if (1..=3).contains(&t[0]) && zero(1..4) && zero(20..48) => json!({
            "kind": EXCEPTIONS[usize::from(t[0] - 1)],
            "site": frame(&t[4..20])?,
        }),
        "dom_mutation" if (1..=3).contains(&t[0]) && t[1] < 4 && (t[0] == 1 || t[4] == 0) => {
            json!({
                "kind": MUTATIONS[usize::from(t[0] - 1)],
                "node_slot": t[1],
                "node_type": u16_at(t, 2),
                "attribute": name(&t[5..37], t[4], t[0] == 1).filter(|_| zero(37..48))?,
            })
        }
        _ => return None,
    })
}

/// One decoded record, or None for anything the core would refuse.
pub fn decode(event: &Value) -> Option<Value> {
    let kind = event["type"].as_str().filter(|kind| TYPES.contains(kind))?;
    if event["payload_truncated"] == true {
        return None;
    }
    let mut payload = hex::decode(event["payload"].as_str()?).ok()?;
    if payload.len() != 128 {
        return None;
    }
    let detail = detail(kind, &payload[80..])?;
    if payload[..2] != [1, 0] {
        return None;
    }
    payload[80..].fill(0);
    let stack = request_stack::decode_record(&payload)?;
    Some(json!({
        "type": kind,
        "session_id": event["session_id"],
        "process_id": event["process_id"],
        "frame_id": event["frame_id"],
        "sequence_number": event["sequence_number"],
        "parent_event_id": event["parent_event_id"],
        "request_id": event["request_id"],
        "monotonic_time_ns": event["monotonic_time_ns"],
        "stack": request_stack::summary(&stack),
        "detail": detail,
    }))
}

/// Puts `debugger_observation` beside the payload of each record of types 40
/// to 45 on a filtered or waiting event page: the object `get_native_debugger`
/// lists for it, its own frame as `site` (raw here, resolved by
/// `request_stack::ObservationSites`, which calls this), and the exact
/// arguments of the `get_request_stack` read of its stack as `stack_read`,
/// with that operation's name beside them. A record the core would refuse is
/// `{status: invalid}` with no fields.
pub(crate) fn annotate(events: &mut [Value]) {
    for event in events {
        if !event["type"]
            .as_str()
            .is_some_and(|kind| TYPES.contains(&kind))
        {
            continue;
        }
        let annotation = match decode(event) {
            Some(mut decoded) => {
                let (site, stack_read) = request_stack::observation_reads(event);
                decoded["status"] = json!("decoded");
                decoded["site"] = site;
                decoded["stack_read_operation"] = json!("get_request_stack");
                decoded["stack_read"] = stack_read;
                decoded
            }
            None => json!({"status": "invalid"}),
        };
        if let Some(object) = event.as_object_mut() {
            object.insert("debugger_observation".to_owned(), annotation);
        }
    }
}

/// One native frame's records, matched exactly on all three identities.
#[derive(Clone, Copy)]
pub struct Thread {
    pub session: u64,
    pub process: u64,
    pub frame: u64,
}

/// Which records a read returns: one type or all six, one frame or every
/// frame, and the newest records ending at or before `before`.
pub struct Query {
    pub kind: Option<&'static str>,
    pub thread: Option<Thread>,
    pub before: Option<u64>,
    pub limit: usize,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            kind: None,
            thread: None,
            before: None,
            limit: RECENT,
        }
    }
}

pub struct Recent {
    pub records: Vec<Value>,
    pub malformed: usize,
    /// The query echoed with the read's byte scope, as `get_events` pages.
    pub query: Value,
}

fn echo(page: &event_query::Page, query: &Query, returned: usize) -> Value {
    let mut echo = page.paging("backward", query.limit);
    echo["returned"] = json!(returned);
    echo["scope"] = json!(page.scope());
    echo["type"] = json!(query.kind);
    echo["thread"] = query.thread.map_or(Value::Null, |thread| {
        json!({"session_id": thread.session.to_string(), "process_id": thread.process,
            "frame_id": thread.frame.to_string()})
    });
    echo
}

/// How long a debugger read folds appended records before it lists threads
/// from where the event index stands; the background indexer keeps the
/// index within a second of the store.
const THREADS_FOLD: Duration = Duration::from_millis(100);

/// The whole store's debugger threads from the event index, newest first:
/// the native frame of every valid observation record (the identity a thread
/// scope filters by), every worker that started a request (`request_initiated`
/// loader kinds 17 to 19, protocol/native-network-v3.md), every observation
/// budget gap, and what the index covered.
pub struct Threads {
    pub observed: Vec<Value>,
    pub workers: Vec<Value>,
    pub budget_gaps: Vec<Value>,
    pub coverage: Value,
}

pub fn threads(indexes: &Mutex<Indexes>) -> Result<Threads> {
    let mut indexes = indexes.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(index) = indexes.summary_index(Instant::now() + THREADS_FOLD)? else {
        return Ok(Threads {
            observed: Vec::new(),
            workers: Vec::new(),
            budget_gaps: Vec::new(),
            coverage: event_query::Coverage::located(0, 0, true, 0).to_json(),
        });
    };
    let text = |key: i64| (key as u64).to_string();
    let rows = |sql: &str, row: &dyn Fn(&rusqlite::Row<'_>) -> rusqlite::Result<Value>| {
        index
            .connection
            .prepare_cached(sql)
            .sql()?
            .query_map([], |found| row(found))
            .sql()?
            .collect::<rusqlite::Result<Vec<_>>>()
            .sql()
    };
    let observed = rows(
        "SELECT session, process, frame, last_sequence, records FROM observed_frames
         ORDER BY last_start DESC",
        &|row| {
            Ok(
                json!({"session_id": text(row.get(0)?), "process_id": row.get::<_, i64>(1)?,
                "frame_id": text(row.get(2)?), "last_sequence": text(row.get(3)?),
                "records": row.get::<_, i64>(4)?}),
            )
        },
    )?;
    let workers = rows(
        "SELECT kind, session, process, context, last_sequence, requests FROM workers
         ORDER BY last_start DESC",
        &|row| {
            let kind = match row.get::<_, i64>(0)? {
                17 => "dedicated_worker",
                18 => "shared_worker",
                _ => "service_worker",
            };
            Ok(json!({"kind": kind, "session_id": text(row.get(1)?),
                "process_id": row.get::<_, i64>(2)?, "context_id": text(row.get(3)?),
                "last_sequence": text(row.get(4)?), "requests": row.get::<_, i64>(5)?}))
        },
    )?;
    let budget_gaps = rows(
        "SELECT session, process, frame, sequence FROM observation_budget_gaps
         ORDER BY start DESC",
        &|row| {
            Ok(
                json!({"session_id": text(row.get(0)?), "process_id": row.get::<_, i64>(1)?,
                "frame_id": text(row.get(2)?), "sequence_number": text(row.get(3)?)}),
            )
        },
    )?;
    let caught_up = index.stopped.is_none() && index.position.caught_up();
    let coverage = event_query::Coverage::located(
        index.position.indexed_to,
        index.position.file_end,
        caught_up,
        0,
    );
    Ok(Threads {
        observed,
        workers,
        budget_gaps,
        coverage: coverage.to_json(),
    })
}

/// The newest matching records first; a record the core would refuse is
/// counted, not shown.
pub fn recent(store: &Path, query: &Query) -> Result<Recent> {
    let types = query.kind.map_or(TYPES.to_vec(), |kind| vec![kind]);
    let ids = query.thread.map_or_else(Vec::new, |thread| {
        vec![
            ("session_id", thread.session),
            ("process_id", thread.process),
            ("frame_id", thread.frame),
        ]
    });
    let filter = EventFilter::exact(&types, ids);
    let cursor = query.before.map_or(Cursor::Tail, Cursor::Before);
    let (page, damaged) =
        event_query::read_tolerant(store, cursor, query.limit, event_query::SCAN_BYTES, &filter)?;
    let decoded: Vec<Value> = page.records.iter().rev().filter_map(decode).collect();
    Ok(Recent {
        malformed: page.records.len() - decoded.len() + damaged as usize,
        records: decoded,
        query: echo(&page, query, page.records.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, tail: &[u8]) -> Value {
        let mut payload = vec![1, 0, 128, 0, 2, 0x08, 0, 0];
        payload.resize(80, 0);
        payload.extend_from_slice(tail);
        payload.resize(128, 0);
        json!({"type": kind, "category": "runtime", "session_id": "1", "process_id": 2,
            "frame_id": "9", "sequence_number": "5", "parent_event_id": "0",
            "request_id": 0, "payload": hex::encode(payload)})
    }

    #[test]
    fn each_type_decodes_and_malformed_tails_are_refused() {
        let mut listener = vec![
            0, 1, 1, 0, 1, 0, 0, 0, 10, 0, 0, 0, 40, 0, 0, 0, 40, 0, 0, 0, 5,
        ];
        listener.extend_from_slice(b"click");
        let decoded = decode(&record("listener_dispatch", &listener)).unwrap();
        assert_eq!(decoded["detail"]["event_type"], "click");
        assert_eq!(decoded["detail"]["listener"]["script_id"], 10);
        assert_eq!(decoded["stack"]["state"], "no_script");

        let mut csp = vec![19, 2, 16];
        csp.extend_from_slice(b"cdn.example.test");
        let csp = decode(&record("csp_violation", &csp)).unwrap();
        assert_eq!(csp["detail"]["directive"], "script-src");
        assert_eq!(csp["detail"]["disposition"], "report");
        assert_eq!(csp["detail"]["blocked_host"], "cdn.example.test");

        let timer = decode(&record("timer_observation", &[2, 2, 1, 0, 77])).unwrap();
        assert_eq!(timer["detail"]["phase"], "fired");
        assert_eq!(timer["detail"]["timer_id"], 77);
        assert_eq!(timer["detail"]["callback"], Value::Null);

        let thrown = decode(&record("exception_observation", &[3])).unwrap();
        assert_eq!(thrown["detail"]["kind"], "unhandled_rejection");

        let mut attribute = vec![1, 0, 1, 0, 5];
        attribute.extend_from_slice(b"class");
        let mutation = decode(&record("dom_mutation", &attribute)).unwrap();
        assert_eq!(mutation["detail"]["attribute"], "class");
        assert!(decode(&record("request_watch_match", &[1, 1])).is_some());

        for (kind, tail) in [
            ("listener_dispatch", vec![0, 1, 1, 0]),
            ("listener_dispatch", vec![16, 1]),
            ("timer_observation", vec![3, 1]),
            ("exception_observation", vec![4]),
            ("dom_mutation", vec![1, 0, 1, 0, 0]),
            ("dom_mutation", vec![2, 0, 1, 0, 1, b'x']),
            ("csp_violation", vec![19, 1, 1, b' ']),
            ("request_watch_match", vec![8]),
            ("request_initiated", vec![]),
        ] {
            assert!(decode(&record(kind, &tail)).is_none(), "{kind} {tail:?}");
        }
        let mut cut = record("exception_observation", &[1]);
        cut["payload_truncated"] = json!(true);
        assert!(decode(&cut).is_none());
    }
}
