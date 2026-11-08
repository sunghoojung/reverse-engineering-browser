//! Phase 1 debugger records, protocol/native-debugger-observation-v1.md.

use std::path::Path;

use serde_json::{Value, json};

use crate::{
    error::Result,
    event_query::{self, Cursor, EventFilter},
    request_stack,
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
const WORKER_SCAN: usize = 2048;
const WORKERS: usize = 64;

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

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

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

fn tail(store: &Path, types: &[&str], limit: usize) -> Result<Vec<Value>> {
    let filter = EventFilter::exact(types, Vec::new());
    let mut tally = event_query::Tally::default();
    Ok(event_query::read_page(
        store,
        Cursor::Tail,
        limit,
        event_query::SCAN_BYTES,
        event_query::EVENT_RECORD_BYTES,
        event_query::event_visitor(&filter, &mut tally),
    )?
    .records)
}

/// The newest records first; a record the core would refuse is counted, not shown.
pub fn recent(store: &Path) -> Result<(Vec<Value>, usize)> {
    let events = tail(store, &TYPES, RECENT)?;
    let decoded: Vec<Value> = events.iter().rev().filter_map(decode).collect();
    let malformed = events.len() - decoded.len();
    Ok((decoded, malformed))
}

/// Workers the renderer saw start requests, from `request_initiated` loader
/// kinds 17 to 19 (protocol/native-network-v3.md).
pub fn workers(store: &Path) -> Result<Vec<Value>> {
    let mut found: Vec<Value> = Vec::new();
    for event in tail(store, &["request_initiated"], WORKER_SCAN)?
        .iter()
        .rev()
    {
        let kind = match event["loader_kind"].as_u64() {
            Some(17) => "dedicated_worker",
            Some(18) => "shared_worker",
            Some(19) => "service_worker",
            _ => continue,
        };
        let same = |worker: &&mut Value| {
            worker["process_id"] == event["process_id"] && worker["context_id"] == event["frame_id"]
        };
        if let Some(worker) = found.iter_mut().find(same) {
            worker["requests"] = json!(worker["requests"].as_u64().unwrap_or(0) + 1);
        } else if found.len() < WORKERS {
            found.push(json!({"kind": kind, "session_id": event["session_id"],
                "process_id": event["process_id"], "context_id": event["frame_id"],
                "last_sequence": event["sequence_number"], "requests": 1}));
        }
    }
    Ok(found)
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
