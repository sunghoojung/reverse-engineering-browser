//! Native JavaScript invocation records, the Wasm invocation context and the
//! exact value search behind `invocation_value_flow`. Every rule here mirrors
//! protocol/native-js-invocation-v1.md and the C++, Python and JavaScript
//! readers; a record any of them refuses is never read as evidence.
use crate::evidence;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Base of the 64-bit polynomial rolling hash, `h = h * base + byte`.
pub const ROLLING_BASE: u64 = 0x0000_0100_0000_01b3;
/// Encoded bytes a settle digest may cover.
pub const DIGEST_BYTE_LIMIT: u32 = 1 << 20;
/// Bytes hashed by one value search; a body over it is reported unsearched.
pub const SEARCH_BYTE_LIMIT: usize = 16 << 20;

pub fn rolling_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |hash, byte| {
        hash.wrapping_mul(ROLLING_BASE)
            .wrapping_add(u64::from(*byte))
    })
}

/// State 2 (inside) carries a nonzero ID; every other state carries none.
pub fn context_valid(state: u8, id: u32) -> bool {
    state <= 3 && (state == 2) == (id != 0)
}

/// The invocation context of a Wasm consumer payload. `new_version` stores it
/// at `offset`; every earlier version reserved those bytes, so it reads as
/// `(0, 0)`, not observed. `None` for any inconsistency.
pub fn wasm_context(payload: &[u8], new_version: u8, offset: usize) -> Option<(u8, u32)> {
    let state = payload[offset];
    let id = u32::from_le_bytes(payload[offset + 4..offset + 8].try_into().ok()?);
    let padded = payload[offset + 1..offset + 4].iter().all(|b| *b == 0);
    (padded && context_valid(state, id) && (payload[0] >= new_version || (state == 0 && id == 0)))
        .then_some((state, id))
}

/// The row field VM Lab shows for a Wasm record: absent when the record did
/// not observe a context, so older workspaces keep their exact shape.
pub fn context_row(state: u8, id: u32) -> Option<Value> {
    let name = match state {
        1 => "none",
        2 => "inside",
        3 => "unknown",
        _ => return None,
    };
    Some(json!({"state":name,"invocation_id":id.to_string()}))
}

fn le16(p: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([p[at], p[at + 1]])
}
fn le32(p: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(p[at..at + 4].try_into().expect("fixed payload"))
}
fn le64(p: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(p[at..at + 8].try_into().expect("fixed payload"))
}

/// The 128-byte payload of an invocation record whose envelope is valid.
fn payload(event: &Value, kind: &str) -> Option<Vec<u8>> {
    let canonical = |key: &str, nonzero| evidence::canonical(&event[key], 64, nonzero);
    if event["type"] != kind
        || event["category"] != "vm"
        || event["protocol_version"] != 3
        || event["flags"] != 0
        || event["payload_truncated"] != false
        || event["payload_size"] != 128
        || event["payload_encoding"] != "hex"
        || !["session_id", "sequence_number", "monotonic_time_ns"]
            .iter()
            .all(|key| canonical(key, true))
        || !["artifact_id", "parent_event_id", "navigation_id"]
            .iter()
            .all(|key| event[*key] == "0")
        || !canonical("frame_id", false)
        || !canonical("request_id", false)
        || ["process_id", "thread_id"].iter().any(|key| {
            event[*key]
                .as_u64()
                .is_none_or(|v| v == 0 || v > u64::from(u32::MAX))
        })
    {
        return None;
    }
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    (bytes.len() == 128 && le16(&bytes, 0) == 1 && le16(&bytes, 2) == 128).then_some(bytes)
}

fn kind_valid(kind: u8, low32: u32) -> bool {
    (1..=14).contains(&kind)
        && match kind {
            1 => true,
            7 => low32 <= 1,
            _ => low32 == 0,
        }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Start {
    pub site_slot: u8,
    pub invocation_id: u32,
    pub parent_invocation_id: u32,
    pub parent_unknown: bool,
    pub argument_count: u16,
    pub script_id: u32,
    pub anchor_offset: u32,
    pub site_sample_index: u16,
    pub sample_index: u16,
    pub source_sha256: [u8; 32],
    pub document_id: u64,
}

pub fn start(event: &Value) -> Option<Start> {
    let p = payload(event, "js_invocation_start")?;
    if event["frame_id"] == "0" || event["request_id"] != "0" {
        return None;
    }
    let (slot, flags, argc) = (p[4], p[5], le16(&p, 6));
    let (id, parent) = (le32(&p, 20), le32(&p, 24));
    if slot >= 8
        || flags & !0x03 != 0
        || le32(&p, 8) == 0
        || le32(&p, 16) == 0
        || le32(&p, 12) >= le32(&p, 16)
        || id == 0
        || le16(&p, 28) >= 64
        || le16(&p, 30) >= 256
        || le64(&p, 104) == 0
        || p[112..].iter().any(|b| *b != 0)
        || (parent != 0 && (parent >= id || flags & 0x01 != 0))
        || (flags & 0x02 != 0) != (argc > 8)
    {
        return None;
    }
    for index in 0..8 {
        let (kind, low32) = (p[32 + index], le32(&p, 40 + 4 * index));
        let valid = if index < usize::from(argc) {
            kind_valid(kind, low32)
        } else {
            kind == 0 && low32 == 0
        };
        if !valid {
            return None;
        }
    }
    Some(Start {
        site_slot: slot,
        invocation_id: id,
        parent_invocation_id: parent,
        parent_unknown: flags & 0x01 != 0,
        argument_count: argc,
        script_id: le32(&p, 8),
        anchor_offset: le32(&p, 12),
        site_sample_index: le16(&p, 28),
        sample_index: le16(&p, 30),
        source_sha256: p[72..104].try_into().ok()?,
        document_id: le64(&p, 104),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest32 {
    pub sha256: [u8; 32],
    pub rolling: u64,
    pub byte_length: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settle {
    pub site_slot: u8,
    pub invocation_id: u32,
    pub fulfilled: bool,
    /// 1 synchronous return, 2 synchronous throw, 3 the caller's promise.
    pub via: u8,
    pub value_kind: u8,
    pub value_length: u32,
    pub digest_state: u8,
    pub digest: Option<Digest32>,
    pub document_id: u64,
}

pub fn settle(event: &Value) -> Option<Settle> {
    let p = payload(event, "js_invocation_settle")?;
    if event["frame_id"] == "0" || event["request_id"] != "0" {
        return None;
    }
    let (slot, outcome, via, kind) = (p[4], p[5], p[6], p[7]);
    let (length, state, encoding, flags) = (le32(&p, 12), p[16], p[17], p[18]);
    let (byte_length, rolling) = (le32(&p, 20), le64(&p, 24));
    let (fulfilled, rejected) = (outcome == 1, outcome == 2);
    let string = kind == 3;
    let bytes = kind == 12 || kind == 13;
    if slot >= 8
        || !(fulfilled || rejected)
        || !(1..=14).contains(&kind)
        || le32(&p, 8) == 0
        || le64(&p, 64) == 0
        || p[19] != 0
        || flags & !0x01 != 0
        || p[72..].iter().any(|b| *b != 0)
        || !((via == 1 && fulfilled) || (via == 2 && rejected) || via == 3)
        || (length != 0 && !(string || bytes || kind == 11))
    {
        return None;
    }
    let digest = if state == 1 {
        let valid = fulfilled
            && byte_length <= DIGEST_BYTE_LIMIT
            && ((string && encoding == 1) || (bytes && encoding == 2))
            && (string || flags & 0x01 == 0)
            && (!string || byte_length >= length)
            && (!bytes || byte_length == length)
            && (byte_length != 0 || rolling == 0);
        if !valid {
            return None;
        }
        Some(Digest32 {
            sha256: p[32..64].try_into().ok()?,
            rolling,
            byte_length,
        })
    } else {
        let clean = encoding == 0
            && byte_length == 0
            && rolling == 0
            && flags == 0
            && p[32..64].iter().all(|b| *b == 0);
        let consistent = match state {
            0 => true,
            2 => !(fulfilled && (string || bytes)),
            3 => fulfilled && (string || bytes),
            4 => fulfilled && bytes,
            _ => false,
        };
        if !clean || !consistent {
            return None;
        }
        None
    };
    Some(Settle {
        site_slot: slot,
        invocation_id: le32(&p, 8),
        fulfilled,
        via,
        value_kind: kind,
        value_length: length,
        digest_state: state,
        digest,
        document_id: le64(&p, 64),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub inside: bool,
    pub invocation_id: u32,
}

pub fn request(event: &Value) -> Option<Request> {
    let p = payload(event, "js_invocation_request")?;
    let request_id = evidence::canonical(&event["request_id"], 64, true)
        .then(|| event["request_id"].as_str()?.parse::<u64>().ok())
        .flatten()?;
    let (state, id) = (p[4], le32(&p, 8));
    ((state == 2 || state == 3)
        && request_id <= u64::from(u32::MAX)
        && context_valid(state, id)
        && le16(&p, 12) < 256
        && p[5..8].iter().all(|b| *b == 0)
        && le16(&p, 14) == 0
        && p[16..].iter().all(|b| *b == 0))
    .then_some(Request {
        inside: state == 2,
        invocation_id: id,
    })
}

/// API names of value kinds 1 to 14 in wire order. The first nine are the
/// JavaScript dispatch selector names; 13 is a typed array or `DataView`.
const VALUE_KINDS: [&str; 14] = [
    "integer",
    "number",
    "string",
    "symbol",
    "undefined",
    "null",
    "boolean",
    "bigint",
    "object",
    "function",
    "array",
    "array_buffer",
    "array_buffer_view",
    "promise",
];
/// Settle `via` 1 to 3, named as the shipped viewer names them.
const VIA: [&str; 3] = ["sync_return", "sync_throw", "promise"];
/// Settle digest states 0 to 4.
const DIGEST_STATES: [&str; 5] = [
    "not_requested",
    "present",
    "not_digestible",
    "too_large",
    "unavailable",
];

/// The `js_invocation` object `get_events` puts beside the hex payload of an
/// invocation record; `None` for every other type. A record the parser refuses
/// is `{status: invalid}` with no fields, never a partial row. A settle names
/// only its digest state: the digest is sensitive capture that only the
/// value-flow join reads, and the API never decodes it.
pub fn query(event: &Value) -> Option<Value> {
    let decoded = match event["type"].as_str()? {
        "js_invocation_start" => start(event).map(|s| {
            json!({"status":"decoded","kind":"start","site_slot":s.site_slot,
                "invocation_id":s.invocation_id,"parent_invocation_id":s.parent_invocation_id,
                "parent_unknown":s.parent_unknown,"argument_count":s.argument_count,
                "script_id":s.script_id,"anchor_offset":s.anchor_offset,
                "source_sha256":hex::encode(s.source_sha256),
                "site_sample_index":s.site_sample_index,"sample_index":s.sample_index,
                "document_id":s.document_id.to_string()})
        }),
        "js_invocation_settle" => settle(event).and_then(|s| {
            let name = |names: &[&'static str], index: usize| names.get(index).copied();
            Some(
                json!({"status":"decoded","kind":"settle","site_slot":s.site_slot,
                "invocation_id":s.invocation_id,"fulfilled":s.fulfilled,
                "via":name(&VIA, usize::from(s.via).checked_sub(1)?)?,
                "value_kind":name(&VALUE_KINDS, usize::from(s.value_kind).checked_sub(1)?)?,
                "value_length":s.value_length,
                "digest_state":name(&DIGEST_STATES, usize::from(s.digest_state))?,
                "document_id":s.document_id.to_string()}),
            )
        }),
        "js_invocation_request" => request(event).map(|r| {
            json!({"status":"decoded","kind":"request","inside":r.inside,
                "invocation_id":r.invocation_id,"request_id":event["request_id"]})
        }),
        _ => return None,
    };
    Some(decoded.unwrap_or_else(|| json!({"status":"invalid"})))
}

/// Puts `js_invocation` beside the payload of each invocation record and
/// leaves every other event, and every stored field, as it is.
pub(crate) fn annotate(events: &mut [Value]) {
    for event in events {
        if let Some(decoded) = query(event)
            && let Some(object) = event.as_object_mut()
        {
            object.insert("js_invocation".to_owned(), decoded);
        }
    }
}

/// Whether the exact digested bytes occur in `body`. The rolling hash selects
/// candidate windows in one pass and SHA-256 alone confirms each; the window
/// length is the stated encoded length, so a shorter or longer occurrence of
/// the same text never matches. `None` when the search would exceed its byte
/// bound and was not run.
pub fn body_contains(body: &[u8], digest: &Digest32) -> Option<bool> {
    let length = digest.byte_length as usize;
    if length == 0 || length > body.len() {
        return Some(false);
    }
    let mut power = 1u64;
    for _ in 1..length {
        power = power.wrapping_mul(ROLLING_BASE);
    }
    let mut hash = rolling_hash(&body[..length]);
    let mut hashed = 0usize;
    for start in 0..=body.len() - length {
        if start > 0 {
            let out = u64::from(body[start - 1]);
            let incoming = u64::from(body[start + length - 1]);
            hash = hash
                .wrapping_sub(out.wrapping_mul(power))
                .wrapping_mul(ROLLING_BASE)
                .wrapping_add(incoming);
        }
        if hash == digest.rolling {
            hashed += length;
            if hashed > SEARCH_BYTE_LIMIT {
                return None;
            }
            if Sha256::digest(&body[start..start + length]).as_slice() == digest.sha256 {
                return Some(true);
            }
        }
    }
    Some(false)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn event(kind: &str, seq: u64, request: u64, payload: &[u8; 128]) -> Value {
        json!({"protocol_version":3,"session_id":"9","sequence_number":seq.to_string(),
            "monotonic_time_ns":seq.to_string(),"process_id":4,"thread_id":5,"tab_id":0,
            "navigation_id":"0","frame_id":if kind == "js_invocation_request" {"0"} else {"6"},
            "artifact_id":"0","parent_event_id":"0","request_id":request.to_string(),
            "browser_context_id_high":"0","browser_context_id_low":"0",
            "encoded_data_length":"0","decoded_body_length":"0","status_code":0,"error_code":0,
            "resource_type":0,"flags":0,"initiator_request_id":0,"initiator_process_id":0,
            "category":"vm","type":kind,"payload_size":128,"payload_encoding":"hex",
            "payload_truncated":false,"payload":hex::encode(payload)})
    }

    pub(crate) fn start_payload(id: u32, parent: u32) -> [u8; 128] {
        let mut p = [0u8; 128];
        p[0] = 1;
        p[2] = 128;
        p[6] = 2;
        p[8..12].copy_from_slice(&17u32.to_le_bytes());
        p[12..16].copy_from_slice(&41u32.to_le_bytes());
        p[16..20].copy_from_slice(&900u32.to_le_bytes());
        p[20..24].copy_from_slice(&id.to_le_bytes());
        p[24..28].copy_from_slice(&parent.to_le_bytes());
        p[32] = 3;
        p[33] = 9;
        p[72] = 0x5a;
        p[104..112].copy_from_slice(&7u64.to_le_bytes());
        p
    }

    pub(crate) fn settle_payload(id: u32, value: Option<&[u8]>) -> [u8; 128] {
        let mut p = [0u8; 128];
        p[0] = 1;
        p[2] = 128;
        p[5] = 1;
        p[6] = 3;
        p[7] = 3;
        p[8..12].copy_from_slice(&id.to_le_bytes());
        if let Some(value) = value {
            p[12..16].copy_from_slice(&(value.len() as u32).to_le_bytes());
            p[16] = 1;
            p[17] = 1;
            p[20..24].copy_from_slice(&(value.len() as u32).to_le_bytes());
            p[24..32].copy_from_slice(&rolling_hash(value).to_le_bytes());
            p[32..64].copy_from_slice(&Sha256::digest(value));
        }
        p[64..72].copy_from_slice(&7u64.to_le_bytes());
        p
    }

    pub(crate) fn request_payload(state: u8, id: u32) -> [u8; 128] {
        let mut p = [0u8; 128];
        p[0] = 1;
        p[2] = 128;
        p[4] = state;
        p[8..12].copy_from_slice(&id.to_le_bytes());
        p
    }

    #[test]
    fn rolling_hash_matches_the_shared_reference() {
        assert_eq!(rolling_hash(b"abc"), 0x014a_0800_0118_b972);
        assert_eq!(rolling_hash(b"token"), 0x407e_4fc9_3226_7c09);
        assert_eq!(rolling_hash(b""), 0);
    }

    #[test]
    fn records_follow_every_contract_rule() {
        let s = start(&event("js_invocation_start", 1, 0, &start_payload(5, 2))).unwrap();
        assert_eq!((s.invocation_id, s.parent_invocation_id), (5, 2));
        assert!(start(&event("js_invocation_start", 1, 0, &start_payload(5, 5))).is_none());
        let mut truncated = start_payload(5, 0);
        truncated[6] = 9;
        assert!(start(&event("js_invocation_start", 1, 0, &truncated)).is_none());
        truncated[5] = 0x02;
        assert!(start(&event("js_invocation_start", 1, 0, &truncated)).is_none());
        let mut no_document = start_payload(5, 0);
        no_document[104] = 0;
        assert!(start(&event("js_invocation_start", 1, 0, &no_document)).is_none());

        let value = settle(&event(
            "js_invocation_settle",
            2,
            0,
            &settle_payload(5, Some(b"tok")),
        ));
        assert_eq!(value.unwrap().digest.unwrap().byte_length, 3);
        let mut lossy_bytes = settle_payload(5, Some(b"tok"));
        lossy_bytes[7] = 12;
        lossy_bytes[17] = 2;
        lossy_bytes[18] = 1;
        assert!(settle(&event("js_invocation_settle", 2, 0, &lossy_bytes)).is_none());
        let plain = settle(&event(
            "js_invocation_settle",
            2,
            0,
            &settle_payload(5, None),
        ));
        assert!(plain.unwrap().digest.is_none());
        let mut kept = settle_payload(5, None);
        kept[40] = 1;
        assert!(settle(&event("js_invocation_settle", 2, 0, &kept)).is_none());

        assert_eq!(
            request(&event(
                "js_invocation_request",
                3,
                31,
                &request_payload(2, 5)
            )),
            Some(Request {
                inside: true,
                invocation_id: 5
            })
        );
        assert!(
            request(&event(
                "js_invocation_request",
                3,
                31,
                &request_payload(1, 0)
            ))
            .is_none()
        );
        assert!(
            request(&event(
                "js_invocation_request",
                3,
                31,
                &request_payload(3, 5)
            ))
            .is_none()
        );
        assert!(
            request(&event(
                "js_invocation_request",
                3,
                0,
                &request_payload(2, 5)
            ))
            .is_none()
        );
    }

    #[test]
    fn query_objects_name_each_record_and_refuse_without_fields() {
        let invalid = json!({"status":"invalid"});
        let start_event = event("js_invocation_start", 1, 0, &start_payload(5, 2));
        assert_eq!(
            query(&start_event),
            Some(
                json!({"status":"decoded","kind":"start","site_slot":0,"invocation_id":5,
                "parent_invocation_id":2,"parent_unknown":false,"argument_count":2,
                "script_id":17,"anchor_offset":41,
                "source_sha256":format!("5a{}", "00".repeat(31)),
                "site_sample_index":0,"sample_index":0,"document_id":"7"})
            )
        );
        // Parent unknown: no parent ID, and a parent ID beside the flag is refused.
        let mut unknown = start_payload(5, 0);
        unknown[5] = 0x01;
        unknown[4] = 3;
        unknown[28] = 12;
        unknown[30] = 40;
        let decoded = query(&event("js_invocation_start", 1, 0, &unknown)).unwrap();
        assert_eq!(
            (
                &decoded["parent_unknown"],
                &decoded["parent_invocation_id"],
                &decoded["site_slot"],
                &decoded["site_sample_index"],
                &decoded["sample_index"]
            ),
            (&json!(true), &json!(0), &json!(3), &json!(12), &json!(40))
        );
        let mut both = start_payload(5, 2);
        both[5] = 0x01;
        assert_eq!(
            query(&event("js_invocation_start", 1, 0, &both)),
            Some(invalid.clone())
        );

        let present = query(&event(
            "js_invocation_settle",
            2,
            0,
            &settle_payload(5, Some(b"tok")),
        ))
        .unwrap();
        assert_eq!(
            present,
            json!({"status":"decoded","kind":"settle","site_slot":0,"invocation_id":5,
                "fulfilled":true,"via":"promise","value_kind":"string","value_length":3,
                "digest_state":"present","document_id":"7"})
        );
        // The digest is never decoded into the object, under any name.
        let text = present.to_string();
        let sha = hex::encode(Sha256::digest(b"tok"));
        assert!(!text.contains(&sha) && !text.contains("sha256") && !text.contains("rolling"));
        let mut thrown = settle_payload(5, None);
        (thrown[5], thrown[6], thrown[7]) = (2, 2, 13);
        let thrown = query(&event("js_invocation_settle", 2, 0, &thrown)).unwrap();
        assert_eq!(
            (
                &thrown["fulfilled"],
                &thrown["via"],
                &thrown["value_kind"],
                &thrown["digest_state"]
            ),
            (
                &json!(false),
                &json!("sync_throw"),
                &json!("array_buffer_view"),
                &json!("not_requested")
            )
        );

        assert_eq!(
            query(&event(
                "js_invocation_request",
                3,
                31,
                &request_payload(2, 5)
            )),
            Some(json!({"status":"decoded","kind":"request","inside":true,
                "invocation_id":5,"request_id":"31"}))
        );
        let outside = query(&event(
            "js_invocation_request",
            3,
            31,
            &request_payload(3, 0),
        ))
        .unwrap();
        assert_eq!(
            (&outside["inside"], &outside["invocation_id"]),
            (&json!(false), &json!(0))
        );

        // Every refusal is the same one-field object.
        let mut refused = Vec::new();
        let mut truncated = start_event.clone();
        truncated["payload_truncated"] = json!(true);
        refused.push(truncated);
        let mut short = start_event.clone();
        short["payload"] = json!(hex::encode(&start_payload(5, 2)[..127]));
        short["payload_size"] = json!(127);
        refused.push(short);
        for (field, value) in [
            ("protocol_version", json!(2)),
            ("flags", json!(1)),
            ("category", json!("network")),
            ("payload_encoding", json!("utf8")),
            ("navigation_id", json!("4")),
        ] {
            let mut wrong = start_event.clone();
            wrong[field] = value;
            refused.push(wrong);
        }
        // Another record's payload under this type, and a version this reader does not know.
        let mut wrong_type = event("js_invocation_settle", 2, 0, &start_payload(5, 2));
        refused.push(wrong_type.clone());
        wrong_type["type"] = json!("js_invocation_request");
        wrong_type["request_id"] = json!("31");
        refused.push(wrong_type);
        let mut version = start_payload(5, 2);
        version[0] = 2;
        refused.push(event("js_invocation_start", 1, 0, &version));
        refused.push(event("js_invocation_request", 3, 0, &request_payload(2, 5)));
        for record in &refused {
            assert_eq!(query(record), Some(invalid.clone()), "{record}");
        }

        let mut other = start_event.clone();
        other["type"] = json!("module_compiled");
        let mut events = vec![start_event.clone(), refused[0].clone(), other];
        annotate(&mut events);
        assert_eq!(events[0]["js_invocation"]["kind"], "start");
        assert_eq!(events[0]["payload"], start_event["payload"]);
        assert_eq!(events[1]["js_invocation"], invalid);
        assert_eq!(events[1]["js_invocation"].as_object().unwrap().len(), 1);
        assert!(events[2].get("js_invocation").is_none());
    }

    #[test]
    fn wasm_context_reads_each_version() {
        let mut p = [0u8; 128];
        p[0] = 1;
        assert_eq!(wasm_context(&p, 2, 24), Some((0, 0)));
        p[24] = 2;
        p[28] = 3;
        assert_eq!(
            wasm_context(&p, 2, 24),
            None,
            "version 1 reserved the context"
        );
        p[0] = 2;
        assert_eq!(wasm_context(&p, 2, 24), Some((2, 3)));
        p[25] = 1;
        assert_eq!(wasm_context(&p, 2, 24), None);
        p[25] = 0;
        p[28] = 0;
        assert_eq!(wasm_context(&p, 2, 24), None, "inside without an ID");
        assert_eq!(context_row(0, 0), None);
        assert_eq!(
            context_row(2, 3),
            Some(json!({"state":"inside","invocation_id":"3"}))
        );
    }

    #[test]
    fn value_search_needs_the_exact_stated_bytes() {
        let token = b"P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9";
        let digest = settle(&event(
            "js_invocation_settle",
            2,
            0,
            &settle_payload(5, Some(token)),
        ))
        .unwrap()
        .digest
        .unwrap();
        let mut body = b"v=1&n=".to_vec();
        body.extend_from_slice(token);
        body.extend_from_slice(b"&c=x");
        assert_eq!(body_contains(&body, &digest), Some(true));
        assert_eq!(body_contains(token, &digest), Some(true));
        // One byte short, transformed or absent: no match, never a guess.
        assert_eq!(body_contains(&token[1..], &digest), Some(false));
        let escaped: Vec<u8> = token
            .iter()
            .flat_map(|b| {
                if *b == b'_' {
                    b"%5F".to_vec()
                } else {
                    vec![*b]
                }
            })
            .collect();
        assert_eq!(body_contains(&escaped, &digest), Some(false));
        assert_eq!(body_contains(b"", &digest), Some(false));
        // A rolling-hash collision alone never confirms a match.
        let forged = Digest32 {
            sha256: [0; 32],
            ..digest
        };
        assert_eq!(body_contains(&body, &forged), Some(false));
    }
}
