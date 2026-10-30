//! Native JavaScript dispatch observations: one record per admitted dispatch
//! at an armed `switch` or `t[k](...)` site. A record names its site by the
//! script text V8 compiled, never by artifact ID or URL, so it joins the
//! workspace artifact only when that artifact decodes to the same text.
use crate::vm::dispatch_shape::{Role, Roles};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Sites one site file can arm, as in `protocol/native-js-dispatch-v1.md`.
pub(crate) const SITE_LIMIT: usize = 8;
/// Refused interpreter-candidate sites listed by the arming export.
const MAX_REFUSED: usize = 64;

/// The text V8 compiles for an artifact: strict UTF-8 without one leading
/// U+FEFF, which Blink's decoder strips. Offsets into it are UTF-16 code
/// units; artifact offsets add back the mark's three bytes.
pub(crate) struct SourceKey {
    pub bom: usize,
    pub length: u32,
    pub sha256: [u8; 32],
}

pub(crate) fn source_key(bytes: &[u8]) -> Option<SourceKey> {
    let text = std::str::from_utf8(bytes).ok()?;
    let bom = if text.starts_with('\u{feff}') { 3 } else { 0 };
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 1024];
    let mut used = 0;
    for unit in text[bom..].encode_utf16() {
        buffer[used..used + 2].copy_from_slice(&unit.to_le_bytes());
        used += 2;
        length += 1;
        if used == buffer.len() {
            hasher.update(&buffer[..used]);
            used = 0;
        }
    }
    hasher.update(&buffer[..used]);
    Some(SourceKey {
        bom,
        length: u32::try_from(length).ok()?,
        sha256: hasher.finalize().into(),
    })
}

/// Artifact byte offsets of UTF-16 positions in the compiled text. A
/// position inside a surrogate pair, or past the end, has no byte offset.
fn utf8_offsets(text: &str, bom: usize, positions: &[u32]) -> Vec<Option<usize>> {
    let mut order = (0..positions.len()).collect::<Vec<_>>();
    order.sort_by_key(|&index| positions[index]);
    let mut output = vec![None; positions.len()];
    let mut next = order.into_iter().peekable();
    let mut unit = 0u64;
    for (byte, character) in text[bom..].char_indices() {
        while let Some(&index) = next.peek() {
            let position = u64::from(positions[index]);
            if position > unit {
                break;
            }
            if position == unit {
                output[index] = Some(bom + byte);
            }
            next.next();
        }
        unit += character.len_utf16() as u64;
    }
    for index in next {
        if u64::from(positions[index]) == unit {
            output[index] = Some(text.len());
        }
    }
    output
}

/// UTF-16 positions in the compiled text of artifact byte offsets at
/// character boundaries after the byte-order mark.
fn utf16_offsets(text: &str, bom: usize, offsets: &[usize]) -> Vec<Option<u32>> {
    let mut order = (0..offsets.len()).collect::<Vec<_>>();
    order.sort_by_key(|&index| offsets[index]);
    let mut output = vec![None; offsets.len()];
    let mut next = order.into_iter().peekable();
    let mut unit = 0u64;
    for (byte, character) in text[bom..].char_indices() {
        while let Some(&index) = next.peek() {
            let offset = offsets[index];
            if offset > bom + byte {
                break;
            }
            if offset == bom + byte {
                output[index] = u32::try_from(unit).ok();
            }
            next.next();
        }
        unit += character.len_utf16() as u64;
    }
    output
}

const SELECTOR_KINDS: [&str; 9] = [
    "integer",
    "number",
    "string",
    "symbol",
    "undefined",
    "null",
    "boolean",
    "bigint",
    "object",
];

/// One decoded payload, before its offsets are mapped to artifact bytes.
struct Payload {
    shape: &'static str,
    kind: &'static str,
    slot: u8,
    flags: u8,
    script: u32,
    anchor: u32,
    length: u32,
    selector: u32,
    handler: Option<(u32, u32, u32)>,
    activation: u32,
    parent: u32,
    site_sample: u16,
    sample: u16,
    sha256: [u8; 32],
}

const NEW_ACTIVATION: u8 = 1;
const PARENT_UNKNOWN: u8 = 2;
const PARENT_TRUNCATED: u8 = 4;
const HANDLER_SPAN: u8 = 8;

/// The payload table of `protocol/native-js-dispatch-v1.md`, rule by rule.
fn payload(bytes: &[u8]) -> Option<Payload> {
    let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed"));
    if bytes.len() != 128
        || u16_at(0) != 1
        || u16_at(2) != 128
        || bytes[80..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let shape = match bytes[4] {
        1 => "switch",
        2 => "indexed-call",
        _ => return None,
    };
    let kind = *SELECTOR_KINDS.get(usize::from(bytes[5]).checked_sub(1)?)?;
    let (slot, flags) = (bytes[6], bytes[7]);
    let (script, anchor, length, selector) = (u32_at(8), u32_at(12), u32_at(16), u32_at(20));
    let (handler_script, start, end) = (u32_at(24), u32_at(28), u32_at(32));
    let (activation, parent) = (u32_at(36), u32_at(40));
    let (site_sample, sample) = (u16_at(44), u16_at(46));
    let handler = if flags & HANDLER_SPAN != 0 {
        if shape != "indexed-call" || handler_script == 0 || start >= end {
            return None;
        }
        Some((handler_script, start, end))
    } else if handler_script != 0 || start != 0 || end != 0 {
        return None;
    } else {
        None
    };
    if usize::from(slot) >= SITE_LIMIT
        || flags & !0x0f != 0
        || script == 0
        || length == 0
        || anchor >= length
        || activation == 0
        || site_sample >= 64
        || sample >= 256
        || (kind == "boolean" && selector > 1)
        || (!matches!(kind, "integer" | "boolean") && selector != 0)
        || (parent != 0
            && (parent >= activation || flags & (PARENT_UNKNOWN | PARENT_TRUNCATED) != 0))
    {
        return None;
    }
    Some(Payload {
        shape,
        kind,
        slot,
        flags,
        script,
        anchor,
        length,
        selector,
        handler,
        activation,
        parent,
        site_sample,
        sample,
        sha256: bytes[48..80].try_into().expect("fixed"),
    })
}

/// The envelope rules: a renderer record with full identity and no
/// artifact, navigation, request or parent event.
fn envelope(event: &Value) -> bool {
    let canonical = |key: &str| crate::evidence::canonical(&event[key], 64, true);
    let zero = |key: &str| event.get(key).is_none_or(|value| value == "0");
    event["category"] == "vm"
        && event["type"] == "js_dispatch_observation"
        && event["protocol_version"] == 3
        && event["payload_size"] == 128
        && event["payload_encoding"] == "hex"
        && event["payload_truncated"] == false
        && event["flags"] == 0
        && [
            "session_id",
            "sequence_number",
            "monotonic_time_ns",
            "frame_id",
        ]
        .iter()
        .all(|key| canonical(key))
        && ["process_id", "thread_id"].iter().all(|key| {
            event[*key]
                .as_u64()
                .is_some_and(|value| value != 0 && value <= u64::from(u32::MAX))
        })
        && [
            "artifact_id",
            "navigation_id",
            "parent_event_id",
            "request_id",
        ]
        .iter()
        .all(|key| zero(key))
}

fn decode(event: &Value) -> Option<Payload> {
    if !envelope(event) {
        return None;
    }
    payload(&hex::decode(event["payload"].as_str().filter(|text| text.len() == 256)?).ok()?)
}

/// The probe key of a valid record, for counting records whose script text
/// no analyzed artifact has. Scoped like the workspace join.
pub(crate) fn event_key(event: &Value) -> Option<(String, String, [u8; 32], u32)> {
    let payload = decode(event)?;
    Some((
        event["session_id"].as_str()?.to_owned(),
        event["frame_id"].as_str()?.to_owned(),
        payload.sha256,
        payload.length,
    ))
}

#[derive(Default)]
pub(super) struct Observations {
    pub rows: Vec<Value>,
    pub count: u64,
    /// Malformed records, and records of this text whose positions do not
    /// fall on its UTF-16 boundaries.
    pub invalid: u64,
}

/// Records of this artifact's text in its session and frame. Records of
/// other text belong to other artifacts and are not counted here.
pub(super) fn collect(artifact: &Value, bytes: &[u8], events: &[Value]) -> Observations {
    let mut output = Observations::default();
    if artifact["kind"] != "javascript"
        || !events
            .iter()
            .any(|event| event["type"] == "js_dispatch_observation")
    {
        return output;
    }
    let Some(key) = source_key(bytes) else {
        return output;
    };
    let text = std::str::from_utf8(bytes).expect("source_key checked UTF-8");
    let mut decoded = Vec::new();
    for event in events
        .iter()
        .filter(|event| event["type"] == "js_dispatch_observation")
    {
        if event["session_id"] != artifact["session_id"]
            || event["frame_id"] != artifact["frame_id"]
        {
            continue;
        }
        let Some(payload) = decode(event) else {
            // A malformed record is counted where its key names this text.
            output.invalid += u64::from(
                hex::decode(event["payload"].as_str().unwrap_or(""))
                    .ok()
                    .and_then(|bytes| bytes.get(48..80).map(|digest| digest == key.sha256))
                    .unwrap_or(false),
            );
            continue;
        };
        if payload.sha256 != key.sha256 || payload.length != key.length {
            continue;
        }
        decoded.push((event, payload));
    }
    let mut positions = Vec::with_capacity(decoded.len() * 3);
    for (_, payload) in &decoded {
        positions.push(payload.anchor);
        let (start, end) = payload
            .handler
            .filter(|handler| handler.0 == payload.script)
            .map_or((0, 0), |handler| (handler.1, handler.2));
        positions.extend([start, end]);
    }
    let offsets = utf8_offsets(text, key.bom, &positions);
    for (index, (event, payload)) in decoded.into_iter().enumerate() {
        let (Some(anchor), start, end) = (
            offsets[index * 3],
            offsets[index * 3 + 1],
            offsets[index * 3 + 2],
        ) else {
            output.invalid += 1;
            continue;
        };
        let handler = match payload.handler {
            None => Value::Null,
            Some((script, from, to)) if script == payload.script => match (start, end) {
                (Some(start), Some(end)) => json!({"script_id":script,"start":from,"end":to,
                    "byte_offset":start,"byte_size":end - start}),
                _ => {
                    output.invalid += 1;
                    continue;
                }
            },
            Some((script, from, to)) => {
                json!({"script_id":script,"start":from,"end":to,"byte_offset":null,"byte_size":null})
            }
        };
        output.count += 1;
        if output.rows.len() >= super::MAX_SAMPLES {
            continue;
        }
        output.rows.push(json!({
            "event": super::event_reference(event),
            "monotonic_time_ns": event["monotonic_time_ns"],
            "thread_id": event["thread_id"],
            "shape": payload.shape,
            "site_slot": payload.slot,
            "script_id": payload.script,
            "anchor_offset": anchor,
            "selector_kind": payload.kind,
            "selector": (payload.kind == "integer").then_some(payload.selector),
            "selector_bits": payload.selector,
            "handler": handler,
            "activation_id": payload.activation,
            "parent_activation_id": (payload.parent != 0).then_some(payload.parent),
            "new_activation": payload.flags & NEW_ACTIVATION != 0,
            "parent_unknown": payload.flags & PARENT_UNKNOWN != 0,
            "parent_search_truncated": payload.flags & PARENT_TRUNCATED != 0,
            "site_sample_index": payload.site_sample,
            "sample_index": payload.sample,
        }));
    }
    output
}

/// Renderer losses named by `native_js_dispatch_*` gaps in one session.
#[derive(Clone)]
pub(crate) struct Gap {
    pub session_id: String,
    pub reason: String,
}

/// A vm gap whose payload text is a native JavaScript dispatch loss reason.
pub(crate) fn gap(event: &Value) -> Option<Gap> {
    if event["category"] != "vm" || event["type"] != "gap" {
        return None;
    }
    let payload = hex::decode(event["payload"].as_str()?).ok()?;
    let reason = std::str::from_utf8(&payload).ok()?;
    let known = matches!(
        reason,
        "native_js_dispatch_budget_incomplete"
            | "native_js_dispatch_site_budget_incomplete"
            | "native_js_dispatch_transport_unavailable"
            | "native_js_dispatch_input_unavailable"
    ) || reason
        .strip_prefix("native_js_dispatch_site_")
        .and_then(|rest| rest.strip_suffix("_compiled_before_arming"))
        .is_some_and(|slot| matches!(slot, "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7"));
    known.then(|| Gap {
        session_id: event["session_id"].as_str().unwrap_or("").to_owned(),
        reason: reason.to_owned(),
    })
}

/// The workspace omission for this session's native JavaScript losses.
pub(super) fn gap_omission(artifact: &Value, gaps: &[Gap]) -> Option<Value> {
    let mut reasons = std::collections::BTreeMap::<&str, u64>::new();
    for gap in gaps
        .iter()
        .filter(|gap| artifact["session_id"].as_str() == Some(gap.session_id.as_str()))
    {
        *reasons.entry(&gap.reason).or_default() += 1;
    }
    if reasons.is_empty() {
        return None;
    }
    let mut detail = reasons
        .iter()
        .map(|(reason, count)| format!("{reason} x{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    detail.insert_str(0, "Native JavaScript dispatch capture reported losses: ");
    if detail.len() > 240 {
        let mut end = 236;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
        detail.push_str(" ...");
    }
    Some(json!({"reason":"native-js-dispatch-incomplete","detail":detail}))
}

/// The site file for this artifact's interpreter-candidate `switch` and
/// `indexed call` sites, with every refused candidate and its reason.
pub(super) fn arming(artifact: &Value, bytes: &[u8], roles: &Roles) -> Option<Value> {
    let candidates = roles
        .js_sites()
        .iter()
        .filter(|site| site.role == Role::InterpreterCandidate)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }
    let key = source_key(bytes);
    let anchors = match (&key, std::str::from_utf8(bytes)) {
        (Some(key), Ok(text)) => utf16_offsets(
            text,
            key.bom,
            &candidates
                .iter()
                .map(|site| site.anchor.unwrap_or(usize::MAX))
                .collect::<Vec<_>>(),
        ),
        _ => vec![None; candidates.len()],
    };
    let mut sites = Vec::new();
    let mut refused = Vec::new();
    for (site, anchor) in candidates.iter().zip(anchors) {
        let reason = match (&key, site.shape(), site.anchor, anchor) {
            (None, ..) => Some("js-dispatch-source-not-utf8"),
            (_, None, ..) => Some(crate::vm::dispatch_shape::javascript::ANCHOR_UNOBSERVABLE),
            (_, Some(_), None, _) => Some(
                site.refusal
                    .as_deref()
                    .unwrap_or(crate::vm::dispatch_shape::javascript::ANCHOR_UNRESOLVED),
            ),
            (_, Some(_), Some(_), None) => {
                Some(crate::vm::dispatch_shape::javascript::ANCHOR_UNRESOLVED)
            }
            _ if sites.len() >= SITE_LIMIT => Some("js-dispatch-site-limit"),
            _ => None,
        };
        let key = key.as_ref();
        match (reason, key, anchor) {
            (None, Some(key), Some(anchor)) => sites.push(json!({
                "anchor_offset": anchor,
                "artifact_id": artifact["artifact_id"],
                "artifact_sha256": artifact["sha256"],
                "byte_offset": site.byte_offset,
                "shape": site.shape().expect("armable shape"),
                "source_length": key.length,
                "source_sha256": hex::encode(key.sha256),
            })),
            (reason, ..) => refused.push(json!({
                "byte_offset": site.byte_offset,
                "instruction": site.instruction,
                "reason": reason.unwrap_or(crate::vm::dispatch_shape::javascript::ANCHOR_UNRESOLVED),
            })),
        }
    }
    let omitted = refused.len().saturating_sub(MAX_REFUSED);
    refused.truncate(MAX_REFUSED);
    // base::JSONWriter writes sorted keys without whitespace; serde_json
    // maps are sorted, so the compact rendering is the canonical file.
    let file = (!sites.is_empty())
        .then(|| serde_json::to_string(&json!({"sites":sites,"version":1})).expect("JSON"));
    Some(json!({
        "version": 1,
        "source_sha256": key.as_ref().map(|key| hex::encode(key.sha256)),
        "source_length": key.as_ref().map(|key| key.length),
        "sites": sites,
        "refused": refused,
        "omitted_refused_count": omitted,
        "file": file,
    }))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    #[test]
    fn source_key_strips_one_mark_and_hashes_utf16() {
        let text = "\u{feff}a\u{3a9}\u{1d535}";
        let key = source_key(text.as_bytes()).unwrap();
        assert_eq!((key.bom, key.length), (3, 4));
        let mut units = Vec::new();
        for unit in "a\u{3a9}\u{1d535}".encode_utf16() {
            units.extend(unit.to_le_bytes());
        }
        assert_eq!(key.sha256.as_slice(), Sha256::digest(&units).as_slice());
        // Only the first mark is the byte-order mark.
        assert_eq!(source_key("\u{feff}\u{feff}".as_bytes()).unwrap().length, 1);
        assert!(source_key(&[0xff, 0xfe]).is_none());
        // A large text crosses the hashing buffer exactly.
        let long = "x".repeat(1537);
        let mut units = Vec::new();
        for unit in long.encode_utf16() {
            units.extend(unit.to_le_bytes());
        }
        assert_eq!(
            source_key(long.as_bytes()).unwrap().sha256.as_slice(),
            Sha256::digest(&units).as_slice()
        );
    }

    #[test]
    fn utf16_positions_map_to_artifact_bytes_and_back() {
        let text = "\u{feff}a\u{3a9}\u{1d535}b";
        // a=0, Omega=1, the astral letter covers 2 and 3, b=4, end=5.
        let mapped = utf8_offsets(text, 3, &[4, 0, 1, 2, 3, 5, 6]);
        assert_eq!(
            mapped,
            vec![Some(10), Some(3), Some(4), Some(6), None, Some(11), None]
        );
        assert_eq!(
            utf16_offsets(text, 3, &[10, 3, 4, 6, 7, 0]),
            vec![Some(4), Some(0), Some(1), Some(2), None, None]
        );
    }

    fn put(bytes: &mut [u8], at: usize, value: u32, width: usize) {
        bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    /// A valid `switch` record at `anchor` of `source`.
    pub(crate) fn record(source: &str, anchor: u32, selector: u32) -> [u8; 128] {
        let key = source_key(source.as_bytes()).unwrap();
        let mut bytes = [0u8; 128];
        bytes[..4].copy_from_slice(&[1, 0, 128, 0]);
        bytes[4] = 1;
        bytes[5] = 1;
        put(&mut bytes, 8, 9, 4);
        put(&mut bytes, 12, anchor, 4);
        put(&mut bytes, 16, key.length, 4);
        put(&mut bytes, 20, selector, 4);
        put(&mut bytes, 36, 1, 4);
        bytes[48..80].copy_from_slice(&key.sha256);
        bytes
    }

    pub(crate) fn event(sequence: u64, payload: &[u8; 128]) -> Value {
        json!({"protocol_version":3,"session_id":"1","sequence_number":sequence.to_string(),
            "process_id":1,"thread_id":1,"monotonic_time_ns":sequence.to_string(),"tab_id":0,
            "navigation_id":"0","frame_id":"1","artifact_id":"0","parent_event_id":"0",
            "request_id":"0","flags":0,"payload_size":128,"payload_encoding":"hex",
            "payload_truncated":false,"category":"vm","type":"js_dispatch_observation",
            "payload":hex::encode(payload)})
    }

    #[test]
    fn payload_rules_match_the_contract_table() {
        let source = "switch (x) {}";
        let base = record(source, 0, 7);
        assert!(payload(&base).is_some());
        let mutate = |change: &dyn Fn(&mut [u8; 128])| {
            let mut bytes = base;
            change(&mut bytes);
            payload(&bytes).is_some()
        };
        type Mutation<'a> = (&'a str, &'a dyn Fn(&mut [u8; 128]));
        let rejected: [Mutation<'_>; 16] = [
            ("version", &|b| b[0] = 2),
            ("size", &|b| b[2] = 127),
            ("shape", &|b| b[4] = 3),
            ("kind", &|b| b[5] = 10),
            ("slot", &|b| b[6] = 8),
            ("flags", &|b| b[7] = 16),
            ("script", &|b| put(b, 8, 0, 4)),
            ("anchor", &|b| put(b, 12, 13, 4)),
            ("non-integer bits", &|b| b[5] = 3),
            ("boolean bits", &|b| {
                b[5] = 7;
                put(b, 20, 2, 4);
            }),
            ("switch handler", &|b| {
                b[7] = HANDLER_SPAN;
                put(b, 24, 9, 4);
                put(b, 28, 1, 4);
                put(b, 32, 2, 4);
            }),
            ("handler without flag", &|b| put(b, 24, 9, 4)),
            ("parent order", &|b| put(b, 40, 1, 4)),
            ("site sample", &|b| put(b, 44, 64, 2)),
            ("sample", &|b| put(b, 46, 256, 2)),
            ("reserved", &|b| b[127] = 1),
        ];
        for (name, change) in rejected {
            assert!(!mutate(change), "{name}");
        }
        assert!(mutate(&|b| {
            b[5] = 7;
            put(b, 20, 1, 4);
        }));
        assert!(mutate(&|b| {
            put(b, 36, 2, 4);
            put(b, 40, 1, 4);
        }));
        assert!(!mutate(&|b| {
            put(b, 36, 2, 4);
            put(b, 40, 1, 4);
            b[7] = PARENT_UNKNOWN;
        }));
        let indexed = |start: u32, end: u32, script: u32| {
            let mut bytes = base;
            bytes[4] = 2;
            bytes[7] = HANDLER_SPAN;
            put(&mut bytes, 24, script, 4);
            put(&mut bytes, 28, start, 4);
            put(&mut bytes, 32, end, 4);
            payload(&bytes).is_some()
        };
        assert!(indexed(1, 2, 9) && !indexed(2, 2, 9) && !indexed(1, 2, 0));
    }

    #[test]
    fn records_join_only_this_text_in_its_session_and_frame() {
        let source = "\u{feff}// \u{3a9}\nswitch (x) {}";
        let artifact = json!({"kind":"javascript","artifact_id":"5","sha256":"00","session_id":"1","frame_id":"1"});
        let anchor = "// \u{3a9}\n".encode_utf16().count() as u32;
        let good = event(1, &record(source, anchor, 7));
        let output = collect(&artifact, source.as_bytes(), std::slice::from_ref(&good));
        assert_eq!((output.count, output.invalid), (1, 0));
        let row = &output.rows[0];
        assert_eq!(row["anchor_offset"], source.find("switch").unwrap());
        assert_eq!(row["selector"], 7);
        assert_eq!(row["handler"], Value::Null);
        assert_eq!(row["parent_activation_id"], Value::Null);
        // Another session or frame is another capture, and other text is
        // another artifact's record: neither is counted here.
        for (key, value) in [("session_id", "2"), ("frame_id", "2")] {
            let mut other = good.clone();
            other[key] = json!(value);
            let output = collect(&artifact, source.as_bytes(), &[other]);
            assert_eq!((output.count, output.invalid), (0, 0), "{key}");
        }
        let other = event(2, &record("switch (y) {}", 0, 7));
        assert_eq!(collect(&artifact, source.as_bytes(), &[other]).count, 0);
        // A malformed record of this text is counted as invalid.
        for (key, value) in [
            ("artifact_id", json!("3")),
            ("navigation_id", json!("3")),
            ("parent_event_id", json!("3")),
            ("flags", json!(1)),
            ("payload_truncated", json!(true)),
            ("thread_id", json!(0)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            let output = collect(&artifact, source.as_bytes(), &[bad]);
            assert_eq!((output.count, output.invalid), (0, 1), "{key}");
        }
        let mut reserved = record(source, anchor, 7);
        reserved[100] = 1;
        let output = collect(&artifact, source.as_bytes(), &[event(3, &reserved)]);
        assert_eq!((output.count, output.invalid), (0, 1));
        // A position inside a surrogate pair is not a site of this text.
        let astral = "\u{1d535}switch (x) {}";
        let output = collect(
            &artifact,
            astral.as_bytes(),
            &[event(4, &record(astral, 1, 0))],
        );
        assert_eq!((output.count, output.invalid), (0, 1));
    }

    fn export(source: &str) -> Value {
        let roles = crate::vm::dispatch_roles("javascript", source.as_bytes()).unwrap();
        let artifact =
            json!({"artifact_id":"7","sha256":hex::encode(Sha256::digest(source.as_bytes()))});
        arming(&artifact, source.as_bytes(), &roles).expect("interpreter candidates")
    }

    #[test]
    fn arming_export_writes_the_canonical_site_file_and_refuses_unobservable_shapes() {
        // Nine owned switch interpreters: eight are armed, the ninth is the limit.
        let loops = (0..9)
            .map(|n| format!("function r{n}(c){{var p=0;while(p<c.length){{switch(c[p++]){{case 0:p+=1;break;case 1:p+=2;break;}}}}}}\n"))
            .collect::<String>();
        let source = format!("\u{feff}// \u{3a9}\n{loops}");
        let arming = export(&source);
        let sites = arming["sites"].as_array().unwrap();
        assert_eq!(sites.len(), 8);
        let key = source_key(source.as_bytes()).unwrap();
        for (n, site) in sites.iter().enumerate() {
            let byte = source.match_indices("switch").nth(n).unwrap().0;
            assert_eq!(site["byte_offset"], byte);
            // The anchor is a UTF-16 position after the byte-order mark.
            assert_eq!(
                site["anchor_offset"],
                source[3..byte].encode_utf16().count()
            );
            assert_eq!(site["shape"], "switch");
            assert_eq!(site["source_length"], key.length);
            assert_eq!(site["source_sha256"], hex::encode(key.sha256));
            assert_eq!(site["artifact_id"], "7");
        }
        assert_eq!(
            arming["refused"],
            json!([{"byte_offset":source.match_indices("switch").nth(8).unwrap().0,"instruction":"switch","reason":"js-dispatch-site-limit"}])
        );
        // Exact compact JSON with sorted keys, as base::JSONWriter writes it.
        let file = arming["file"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed, json!({"sites":sites,"version":1}));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), file);
        assert!(file.starts_with("{\"sites\":[{\"anchor_offset\":"));
        assert!(file.ends_with("}],\"version\":1}"));

        // Shapes the probe cannot observe are refused with their reason.
        let shapes = "function a(c,t){var p=0;while(p<c.length){const h=t[c[p++]];h(p);}}\n\
            function l(c){var p=0;while(p<c.length){var o=c[p++];if(o===0){p+=1}else if(o===1){p+=2}else if(o===2){p+=3}}}\n\
            function o(c,t){var p=0;while(p<c.length){t[c[p++]]?.(p);}}\n\
            function k(c,t){var p=0;while(p<c.length){t /* [ */ [c[p++]](p);}}";
        let arming = export(shapes);
        let refused = arming["refused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["instruction"].as_str().unwrap(),
                    row["reason"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert!(
            refused.contains(&("aliased call", "js-dispatch-shape-unobservable")),
            "{refused:?}"
        );
        assert!(
            refused.contains(&("if ladder", "js-dispatch-shape-unobservable")),
            "{refused:?}"
        );
        assert!(
            refused.contains(&("indexed call", "js-dispatch-shape-unobservable")),
            "{refused:?}"
        );
        // A comment holding `[` before the real bracket is skipped.
        let armed = arming["sites"].as_array().unwrap();
        assert_eq!(armed.len(), 1, "{arming:#}");
        assert_eq!(
            armed[0]["anchor_offset"],
            shapes.rfind("[c[p++]](p)").unwrap()
        );
        assert_eq!(armed[0]["shape"], "indexed-call");
    }

    #[test]
    fn member_bracket_skips_only_trivia_between_object_and_key() {
        use crate::vm::dispatch_shape::javascript::member_bracket;
        let at = |text: &str| member_bracket(text, 1, text.len());
        assert_eq!(at("t[k]"), Some(1));
        assert_eq!(at("t /* [ */ \n // x\n [k"), Some(18));
        assert_eq!(at("t) ?.[k"), Some(5));
        assert_eq!(at("t\u{a0}\u{feff}[k"), Some(6));
        assert_eq!(at("t . [k"), None);
        assert_eq!(at("t /* open"), None);
        assert_eq!(at("t\n"), None);
    }

    const FIXTURE: &[u8] =
        include_bytes!("../../../tools/fixtures/native-js-dispatch/two-level-vm.js");
    const GOLDEN_VALID: [&str; 6] = [
        "default",
        "indexed",
        "nested",
        "string-selector",
        "parent-unknown",
        "wide-identities",
    ];

    fn golden(exe: &str, case: &str) -> Value {
        let process = std::process::Command::new(exe)
            .args(["--case", case])
            .output()
            .expect("run C++ producer");
        assert!(
            process.status.success(),
            "C++ case {case}: {}",
            String::from_utf8_lossy(&process.stderr)
        );
        serde_json::from_slice(&process.stdout).expect("EventToJson output")
    }

    fn golden_artifact(root: &std::path::Path, event: &Value) -> Value {
        let hash = hex::encode(Sha256::digest(FIXTURE));
        std::fs::create_dir_all(root.join("blobs")).unwrap();
        std::fs::write(root.join(format!("blobs/{hash}.bin")), FIXTURE).unwrap();
        json!({"protocol_version":1,"artifact_id":"5","parent_artifact_id":"0","creator_event_id":"0",
            "execution_context_id":"1","capture_origin":"unknown","kind":"javascript",
            "url":"fixture://native-js-dispatch/two-level-vm.js","mime_type":"text/javascript",
            "byte_size":FIXTURE.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin"),
            "session_id":event["session_id"],"navigation_id":"0","frame_id":event["frame_id"]})
    }

    #[test]
    #[ignore = "requires actual C++ producer; make check supplies REB_NATIVE_JS_GOLDEN"]
    fn native_js_cpp_golden() {
        let exe = std::env::var("REB_NATIVE_JS_GOLDEN").expect("actual C++ producer required");
        let key = source_key(FIXTURE).unwrap();
        for case in GOLDEN_VALID.iter().chain(&[
            "reserved",
            "version",
            "size",
            "truncated",
            "shape",
            "kind",
            "slot",
            "flags",
            "parent-order",
            "handler-without-flag",
            "switch-handler",
            "non-integer-bits",
            "sample-index",
            "site-sample-index",
            "anchor",
            "boolean-bits",
            "activation",
            "script",
            "source-length",
            "parent-flags",
            "handler-order",
            "handler-script",
            "envelope-version",
            "envelope-flags",
            "identity",
            "artifact",
            "parent-event",
            "navigation",
            "request",
            "big-endian",
        ]) {
            let event = golden(&exe, case);
            let artifact = json!({"kind":"javascript","session_id":event["session_id"],"frame_id":event["frame_id"]});
            let output = collect(&artifact, FIXTURE, std::slice::from_ref(&event));
            let valid = GOLDEN_VALID.contains(case);
            assert_eq!(output.count, u64::from(valid), "C++ case {case}");
            assert_eq!(event_key(&event).is_some(), valid, "C++ case {case}");
            if valid {
                assert_eq!(
                    event_key(&event).unwrap().2,
                    key.sha256,
                    "fixture key {case}"
                );
            }
        }
        // The product path: the owned fixture, every valid record but the
        // wide-identity one, through the store, workspace and schema.
        let root = tempfile::tempdir().unwrap();
        let events = GOLDEN_VALID[..5]
            .iter()
            .map(|case| golden(&exe, case))
            .collect::<Vec<_>>();
        let manifest = golden_artifact(root.path(), &events[0]);
        std::fs::write(root.path().join("manifest.jsonl"), format!("{manifest}\n")).unwrap();
        let path = root.path().join("events.jsonl");
        std::fs::write(
            &path,
            events
                .iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>(),
        )
        .unwrap();
        crate::vm::store(root.path(), &path).unwrap();
        let document: Value = serde_json::from_slice(
            &std::fs::read(root.path().join("analysis/vm-opcode-workspace-v2.json")).unwrap(),
        )
        .unwrap();
        let workspace = &document["workspaces"][0];
        assert_eq!(workspace["runtime"], "javascript", "{document:#}");
        assert_eq!(workspace["native_js_observation_count"], 5);
        let claims = workspace["observed_claims"].as_array().unwrap();
        assert!(claims.iter().all(|claim| claim["stream"] == "native-js"));
        assert_eq!(claims.len(), 4, "{claims:#?}");
        let nested = workspace["nested_guests"].as_array().unwrap();
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0]["outer"]["activation_id"], 1);
        assert_eq!(nested[0]["inner"]["activation_id"], 2);
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-opcode-workspace-v2.schema.json"
        ))
        .unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&document)
            .unwrap();
        if let Ok(path) = std::env::var("REB_NATIVE_JS_WORKSPACE_OUTPUT") {
            std::fs::write(path, serde_json::to_vec(&document).unwrap()).unwrap();
        }
        super::super::export_golden_evidence(root.path(), "REB_NATIVE_JS_EVIDENCE_OUTPUT");
    }

    #[test]
    fn loss_gaps_are_recognized_by_exact_reason() {
        let gap_event = |reason: &str| json!({"category":"vm","type":"gap","session_id":"1","payload":hex::encode(reason)});
        for reason in [
            "native_js_dispatch_budget_incomplete",
            "native_js_dispatch_site_budget_incomplete",
            "native_js_dispatch_transport_unavailable",
            "native_js_dispatch_input_unavailable",
            "native_js_dispatch_site_7_compiled_before_arming",
        ] {
            assert_eq!(gap(&gap_event(reason)).unwrap().reason, reason);
        }
        for reason in [
            "native_js_dispatch_site_8_compiled_before_arming",
            "native_js_dispatch_other",
            "native_wasm_dispatch_budget_incomplete",
        ] {
            assert!(gap(&gap_event(reason)).is_none(), "{reason}");
        }
        let artifact = json!({"session_id":"1"});
        let gaps = [
            gap(&gap_event("native_js_dispatch_budget_incomplete")).unwrap(),
            gap(&gap_event("native_js_dispatch_budget_incomplete")).unwrap(),
        ];
        let omission = gap_omission(&artifact, &gaps).unwrap();
        assert_eq!(omission["reason"], "native-js-dispatch-incomplete");
        assert!(
            omission["detail"]
                .as_str()
                .unwrap()
                .contains("native_js_dispatch_budget_incomplete x2")
        );
        assert!(gap_omission(&json!({"session_id":"2"}), &gaps).is_none());
    }
}
