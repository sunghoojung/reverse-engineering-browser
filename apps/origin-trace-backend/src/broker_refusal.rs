//! Broker refusal records (protocol/broker-refusal-v1.md): what the broker
//! stores in place of a record it refused at validation, so that loss is
//! evidence rather than a count on the broker's stop line. Every rule here
//! mirrors `IsValidBrokerRefusal` in src/capture/event.cpp and the Python and
//! JavaScript readers; a record any of them refuses is neither decoded nor
//! counted.
use crate::event_window::unsigned;
use serde_json::{Value, json};

pub const TYPE: &str = "broker_refusal";
/// The broker's own stream (`kBrokerProcessId`), which a refusal takes when
/// the refused header cannot name the refused record's place.
pub const BROKER_PROCESS: u64 = 0xffff_ffff;
const PAYLOAD_BYTES: usize = 128;
/// Bytes from here to the end of the payload are zero.
const USED_BYTES: usize = 56;
const HEADER_BYTES: u64 = 144;
const PROTOCOL_VERSION: u64 = 3;
/// Reasons 1 to 10, in the order the broker's checks run.
pub const REASONS: [&str; 10] = [
    "protocol_version",
    "header_size",
    "process_id",
    "payload_size",
    "reserved",
    "category",
    "type",
    "flags",
    "network_class",
    "typed_payload",
];
const PROCESS_ID: usize = 3;
const PAYLOAD_SIZE: usize = 4;
const CATEGORY: usize = 6;
/// Store names of categories 0 to 12.
const CATEGORIES: [&str; 13] = [
    "unknown",
    "canvas",
    "webgl",
    "web_audio",
    "navigator",
    "permissions",
    "storage",
    "webrtc",
    "wasm",
    "network",
    "vm",
    "artifact",
    "runtime",
];

/// Refusals in one category for one reason, in first-seen order.
#[derive(Clone, Debug, PartialEq)]
pub struct RefusalCount {
    pub category: String,
    pub reason: &'static str,
    pub count: u64,
}

/// Adds one refusal to `counts`. There are at most 13 categories and 10
/// reasons, so a scan is cheaper than a map.
pub fn count(counts: &mut Vec<RefusalCount>, category: &str, reason: &'static str, add: u64) {
    match counts
        .iter_mut()
        .find(|known| known.reason == reason && known.category == category)
    {
        Some(known) => known.count = known.count.saturating_add(add),
        None => counts.push(RefusalCount {
            category: category.to_owned(),
            reason,
            count: add,
        }),
    }
}

/// The `broker_refusals` field of `Events` and the session summary.
pub fn counts_json(counts: &[RefusalCount]) -> Value {
    Value::Array(
        counts
            .iter()
            .map(|refusal| {
                json!({"category": refusal.category, "reason": refusal.reason,
                    "count": refusal.count.to_string()})
            })
            .collect(),
    )
}

struct Refusal {
    reason: &'static str,
    broker_stream: bool,
    payload: [u8; PAYLOAD_BYTES],
}

fn le(payload: &[u8], at: usize, size: usize) -> u64 {
    payload[at..at + size]
        .iter()
        .rev()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

fn zero(event: &Value, key: &str) -> bool {
    unsigned(&event[key]) == Some(0)
}

fn decode_record(event: &Value) -> Option<Refusal> {
    if event["type"] != TYPE
        || event["protocol_version"].as_u64() != Some(PROTOCOL_VERSION)
        || event["payload_size"].as_u64() != Some(PAYLOAD_BYTES as u64)
        || event["payload_encoding"] != "hex"
        || event["payload_truncated"] != false
        || event["flags"].as_u64() != Some(0)
        || event
            .get("scheme_class")
            .is_some_and(|v| v.as_u64() != Some(0))
        || event
            .get("loader_kind")
            .is_some_and(|v| v.as_u64() != Some(0))
        || ![
            "browser_context_id_high",
            "browser_context_id_low",
            "encoded_data_length",
            "decoded_body_length",
            "status_code",
            "error_code",
            "resource_type",
            "initiator_request_id",
            "initiator_process_id",
        ]
        .iter()
        .all(|key| zero(event, key))
    {
        return None;
    }
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    let payload: [u8; PAYLOAD_BYTES] = bytes.try_into().ok()?;
    let field = |at, size| le(&payload, at, size);
    let reason = field(4, 2) as usize;
    let identity = field(6, 2);
    if field(0, 2) != 1
        || field(2, 2) != PAYLOAD_BYTES as u64
        || !(1..=REASONS.len()).contains(&reason)
        || payload[USED_BYTES..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let raw_category = field(12, 2) as usize;
    let category = CATEGORIES.get(raw_category).copied().unwrap_or("unknown");
    if event["category"] != category {
        return None;
    }
    // Each check before the reason passed and the reason's own failed; the
    // later checks are not compared, as the refused bytes are not kept.
    let holds = |check: usize, passed: bool| {
        if reason == check {
            !passed
        } else {
            reason < check || passed
        }
    };
    let received = field(24, 8);
    if !holds(1, field(8, 2) == PROTOCOL_VERSION)
        || !holds(2, field(10, 2) == HEADER_BYTES)
        || !holds(PROCESS_ID, field(48, 4) != BROKER_PROCESS)
        || !holds(PAYLOAD_SIZE, field(16, 4) <= PAYLOAD_BYTES as u64)
        || !holds(CATEGORY, category != "unknown")
    {
        return None;
    }
    let broker_stream = reason <= PROCESS_ID;
    let header = |key: &str| unsigned(&event[key]);
    let placed = if broker_stream {
        identity == 2
            && header("process_id") == Some(BROKER_PROCESS)
            && header("thread_id") == Some(0)
            && header("sequence_number").is_some_and(|sequence| sequence != 0)
            && header("monotonic_time_ns") == Some(received)
            && [
                "tab_id",
                "navigation_id",
                "frame_id",
                "artifact_id",
                "parent_event_id",
                "request_id",
            ]
            .iter()
            .all(|key| header(key) == Some(0))
    } else {
        identity == 1
            && header("process_id") == Some(field(48, 4))
            && header("thread_id") == Some(field(52, 4))
            && header("sequence_number") == Some(field(32, 8))
            && header("monotonic_time_ns") == Some(field(40, 8))
    };
    placed.then_some(Refusal {
        reason: REASONS[reason - 1],
        broker_stream,
        payload,
    })
}

/// The category and reason of a well-formed refusal, which the counts use.
pub fn reason(event: &Value) -> Option<(&str, &'static str)> {
    let refusal = decode_record(event)?;
    Some((event["category"].as_str()?, refusal.reason))
}

/// The decoded `broker_refusal` object of a refusal record, or
/// `{"status": "invalid"}` when its fields do not form one.
pub fn decode(event: &Value) -> Option<Value> {
    if event["type"] != TYPE {
        return None;
    }
    let Some(refusal) = decode_record(event) else {
        return Some(json!({"status": "invalid"}));
    };
    let field = |at, size| le(&refusal.payload, at, size);
    Some(json!({
        "status": "decoded",
        "reason": refusal.reason,
        "identity": if refusal.broker_stream { "broker" } else { "refused" },
        "received_monotonic_time_ns": field(24, 8).to_string(),
        "refused": {
            "protocol_version": field(8, 2),
            "header_size": field(10, 2),
            "category": field(12, 2),
            "type": field(14, 2),
            "payload_size": field(16, 4),
            "flags": field(20, 2),
            "scheme_class": field(22, 1),
            "loader_kind": field(23, 1),
            "sequence_number": field(32, 8).to_string(),
            "monotonic_time_ns": field(40, 8).to_string(),
            "process_id": field(48, 4),
            "thread_id": field(52, 4),
        },
    }))
}

/// Puts the decoded refusal beside each refusal record's payload.
pub(crate) fn annotate(events: &mut [Value]) {
    for event in events {
        if let Some(decoded) = decode(event)
            && let Some(object) = event.as_object_mut()
        {
            object.insert("broker_refusal".to_owned(), decoded);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A stored refusal as the broker writes it, from `reason` (1 to 10).
    pub(crate) fn record(sequence: u64, reason: usize, category: &str) -> Value {
        let raw_category = CATEGORIES
            .iter()
            .position(|name| *name == category)
            .map_or(999, |index| index as u64);
        let broker_stream = reason <= PROCESS_ID;
        let mut payload = [0u8; PAYLOAD_BYTES];
        let mut put = |at: usize, size: usize, value: u64| {
            payload[at..at + size].copy_from_slice(&value.to_le_bytes()[..size]);
        };
        put(0, 2, 1);
        put(2, 2, 128);
        put(4, 2, reason as u64);
        put(6, 2, if broker_stream { 2 } else { 1 });
        put(8, 2, if reason == 1 { 2 } else { 3 });
        put(10, 2, if reason == 2 { 100 } else { 144 });
        put(
            12,
            2,
            if reason == CATEGORY {
                999
            } else {
                raw_category
            },
        );
        put(14, 2, 1);
        put(16, 4, if reason == PAYLOAD_SIZE { 129 } else { 0 });
        put(24, 8, 500);
        put(32, 8, sequence);
        put(40, 8, sequence * 10);
        put(
            48,
            4,
            if reason == PROCESS_ID {
                BROKER_PROCESS
            } else {
                7
            },
        );
        put(52, 4, 1);
        let (process, thread, header_sequence, time) = if broker_stream {
            (BROKER_PROCESS, 0, 1, 500)
        } else {
            (7, 1, sequence, sequence * 10)
        };
        json!({"protocol_version":3,"session_id":"1","sequence_number":header_sequence.to_string(),
            "monotonic_time_ns":time.to_string(),"process_id":process,"thread_id":thread,"tab_id":0,
            "navigation_id":"0","frame_id":"0","artifact_id":"0","parent_event_id":"0","request_id":"0",
            "browser_context_id_high":"0","browser_context_id_low":"0","encoded_data_length":"0",
            "decoded_body_length":"0","status_code":0,"error_code":0,"resource_type":0,"flags":0,
            "initiator_request_id":0,"initiator_process_id":0,"payload_truncated":false,
            "category": if reason == CATEGORY { "unknown" } else { category },
            "type":"broker_refusal","payload_size":128,"payload_encoding":"hex",
            "payload":hex::encode(payload)})
    }

    #[test]
    fn every_reason_decodes_with_its_identity() {
        for reason in 1..=REASONS.len() {
            let event = record(5, reason, "canvas");
            let decoded = decode(&event).unwrap();
            assert_eq!(decoded["status"], "decoded", "{reason}");
            assert_eq!(decoded["reason"], REASONS[reason - 1]);
            let broker = reason <= PROCESS_ID;
            assert_eq!(
                decoded["identity"],
                if broker { "broker" } else { "refused" }
            );
            assert_eq!(decoded["refused"]["sequence_number"], "5");
            assert_eq!(decoded["received_monotonic_time_ns"], "500");
            let category = if reason == CATEGORY {
                "unknown"
            } else {
                "canvas"
            };
            assert_eq!(super::reason(&event), Some((category, REASONS[reason - 1])));
        }
    }

    #[test]
    fn a_refusal_whose_fields_disagree_is_invalid() {
        let valid = record(5, 5, "canvas");
        let payload = hex::decode(valid["payload"].as_str().unwrap()).unwrap();
        let with = |at: usize, value: u8| {
            let mut changed = payload.clone();
            changed[at] = value;
            let mut event = valid.clone();
            event["payload"] = json!(hex::encode(changed));
            event
        };
        let cases = [
            // Reason 0 and 11 name no check.
            with(4, 0),
            with(4, 11),
            // A refused-stream reason with the broker's identity.
            with(6, 2),
            // A payload version or size the reader does not know.
            with(0, 2),
            with(2, 64),
            // The protocol version passed, so reason 1 cannot be it.
            with(4, 1),
            // A trailing byte.
            with(127, 1),
            // The header's sequence is not the payload's.
            with(32, 6),
        ];
        for (index, event) in cases.iter().enumerate() {
            assert_eq!(
                decode(event).unwrap(),
                json!({"status": "invalid"}),
                "{index}"
            );
            assert_eq!(reason(event), None);
        }
        let mut header = valid.clone();
        header["category"] = json!("webgl");
        assert_eq!(reason(&header), None, "the category is the refused one");
        let mut header = valid.clone();
        header["status_code"] = json!(200);
        assert_eq!(reason(&header), None, "network fields stay zero");
        let mut broker = record(5, 1, "canvas");
        broker["thread_id"] = json!(3);
        assert_eq!(reason(&broker), None, "the broker's stream has no thread");
        assert_eq!(decode(&json!({"type": "api_call"})), None);
    }

    #[test]
    fn counts_keep_first_seen_order() {
        let mut counts = Vec::new();
        count(&mut counts, "canvas", "reserved", 1);
        count(&mut counts, "unknown", "category", 1);
        count(&mut counts, "canvas", "reserved", 2);
        assert_eq!(
            counts_json(&counts),
            json!([
                {"category": "canvas", "reason": "reserved", "count": "3"},
                {"category": "unknown", "reason": "category", "count": "1"}
            ])
        );
    }
}
