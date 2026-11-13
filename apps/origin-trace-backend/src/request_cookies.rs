//! Cookies ("Cookies" in protocol/native-network-v3.md): one request's sent
//! and received cookie lists per hop for `get_request_cookies`, and everything
//! that touched one cookie name for `get_cookie_provenance`. Records are
//! validated again here and lists are read only after a size and SHA-256
//! check. Values are withheld with their length and SHA-256, like credential
//! headers; a script write links to a sent cookie by equal value digests.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::event_window;
use crate::evidence;
use crate::request_headers::{
    Drops, STATES, child_payload, le, lifecycle_of, provisional_hops, qualified, span_of,
};
use crate::request_stack;

const LIST_LIMIT: usize = 2 * 1024 * 1024;
const NAME_PREFIX: usize = 24;
const PROVENANCE_LISTS: usize = 256;
/// Distinct script positions resolved to source per provenance answer.
const PROVENANCE_STACKS: usize = 64;
const EXCLUSIONS: [&str; 30] = [
    "unknown_error",
    "http_only",
    "secure_only",
    "domain_mismatch",
    "not_on_path",
    "samesite_strict",
    "samesite_lax",
    "samesite_unspecified_treated_as_lax",
    "samesite_none_insecure",
    "user_preferences",
    "failure_to_store",
    "noncookieable_scheme",
    "overwrite_secure",
    "overwrite_http_only",
    "invalid_domain",
    "invalid_prefix",
    "invalid_partitioned",
    "name_value_pair_exceeds_max_size",
    "attribute_value_exceeds_max_size",
    "domain_non_ascii",
    "third_party_blocked_within_first_party_set",
    "port_mismatch",
    "scheme_mismatch",
    "shadowing_domain",
    "disallowed_character",
    "third_party_phaseout",
    "no_cookie_content",
    "anonymous_context",
    "invalid_path",
    "ambiguous_serialization",
];
const WARNINGS: [&str; 17] = [
    "samesite_unspecified_cross_site_context",
    "samesite_none_insecure",
    "samesite_unspecified_lax_allow_unsafe",
    "strict_lax_downgrade_strict_samesite",
    "strict_cross_downgrade_strict_samesite",
    "strict_cross_downgrade_lax_samesite",
    "lax_cross_downgrade_strict_samesite",
    "lax_cross_downgrade_lax_samesite",
    "secure_access_granted_non_cryptographic",
    "cross_site_redirect_downgrade_changes_inclusion",
    "attribute_value_exceeds_max_size",
    "domain_non_ascii",
    "port_mismatch",
    "scheme_mismatch",
    "tentatively_allowing_secure_source_scheme",
    "shadowing_domain",
    "third_party_phaseout",
];
const SAME_SITE: [&str; 5] = ["", "Unspecified", "None", "Lax", "Strict"];
const PRIORITY: [&str; 4] = ["", "Low", "Medium", "High"];
const EFFECTIVE: [&str; 6] = [
    "",
    "None",
    "Lax",
    "Strict",
    "Lax-allowing-unsafe",
    "Undefined",
];
pub(crate) const APIS: [&str; 7] = [
    "",
    "document.cookie set",
    "document.cookie get",
    "cookieStore.set",
    "cookieStore.get",
    "cookieStore.getAll",
    "cookieStore.delete",
];

struct List {
    sent: bool,
    state: u8,
    count: u32,
    blocked: u32,
    length: u32,
    hop: u32,
    unattributed: u32,
    digest: [u8; 32],
}

/// The C++ core's rules for the cookie_list record, envelope included.
fn decode_list(event: &Value) -> Option<List> {
    let bytes = child_payload(event, "cookie_list")?;
    let list = List {
        sent: bytes[4] == 1,
        state: bytes[5],
        count: le(&bytes[8..12]) as u32,
        blocked: le(&bytes[12..16]) as u32,
        length: le(&bytes[16..20]) as u32,
        hop: le(&bytes[20..24]) as u32,
        unattributed: le(&bytes[24..28]) as u32,
        digest: bytes[32..64].try_into().ok()?,
    };
    let zero = |slice: &[u8]| slice.iter().all(|byte| *byte == 0);
    let empty = list.state == 3;
    let limited = list.state == 4;
    let valid = matches!(bytes[4], 1 | 2)
        && (1..=8).contains(&list.state)
        && zero(&bytes[6..8])
        && zero(&bytes[28..32])
        && zero(&bytes[64..])
        && list.blocked <= list.count
        && (list.count == 0) == empty
        && (list.length == 0) == empty
        && (empty || u64::from(list.length) >= 16 + 64 * u64::from(list.count))
        && limited == (list.length as usize > LIST_LIMIT)
        && zero(&list.digest) == limited
        && (event["artifact_id"] != "0") == matches!(list.state, 1 | 2);
    valid.then_some(list)
}

struct Cookie {
    exclusions: u64,
    warnings: u64,
    expiry: i64,
    flags: u8,
    same_site: u8,
    priority: u8,
    effective: u8,
    scheme: u8,
    port: i32,
    strings: [Vec<u8>; 6],
}

/// The list artifact, exactly: header, `count` cookies and nothing after.
fn parse_list(bytes: &[u8], sent: bool, count: u32) -> Option<Vec<Cookie>> {
    if bytes.len() < 16
        || &bytes[0..4] != b"RBCK"
        || le(&bytes[4..6]) != 1
        || bytes[6] != if sent { 1 } else { 2 }
        || bytes[7] != 0
        || le(&bytes[8..12]) != u64::from(count)
        || le(&bytes[12..16]) != 0
    {
        return None;
    }
    let mut offset = 16usize;
    let mut cookies = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let fixed = bytes.get(offset..offset + 64)?;
        if fixed[29..32].iter().any(|byte| *byte != 0) || le(&fixed[60..64]) != 0 {
            return None;
        }
        let mut text = offset + 64;
        let mut strings: [Vec<u8>; 6] = Default::default();
        for (index, string) in strings.iter_mut().enumerate() {
            let length = le(&fixed[36 + 4 * index..40 + 4 * index]) as usize;
            *string = bytes.get(text..text.checked_add(length)?)?.to_vec();
            text += length;
        }
        let cookie = Cookie {
            exclusions: le(&fixed[0..8]),
            warnings: le(&fixed[8..16]),
            expiry: le(&fixed[16..24]) as i64,
            flags: fixed[24],
            same_site: fixed[25],
            priority: fixed[26],
            effective: fixed[27],
            scheme: fixed[28],
            port: le(&fixed[32..36]) as u32 as i32,
            strings,
        };
        let parsed = cookie.flags & 1 != 0;
        let shape = if parsed {
            cookie.flags & !0x3f == 0
                && (1..=4).contains(&cookie.same_site)
                && (1..=3).contains(&cookie.priority)
                && (1..=5).contains(&cookie.effective)
                && cookie.scheme <= 2
        } else {
            !sent
                && cookie.flags == 0
                && cookie.same_site == 0
                && cookie.priority == 0
                && cookie.effective == 0
                && cookie.scheme == 0
                && cookie.port == 0
                && cookie.expiry == 0
                && cookie.strings[..5].iter().all(Vec::is_empty)
        };
        if !shape || (sent && !cookie.strings[5].is_empty()) {
            return None;
        }
        cookies.push(cookie);
        offset = text;
    }
    (offset == bytes.len()).then_some(cookies)
}

fn reasons(bits: u64, names: &[&str]) -> Vec<String> {
    (0..64)
        .filter(|bit| bits & (1u64 << bit) != 0)
        .map(|bit| {
            names
                .get(bit)
                .map_or_else(|| format!("bit_{bit}"), |name| (*name).to_owned())
        })
        .collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn describe_cookie(cookie: &Cookie) -> Value {
    let [name, value, domain, path, partition, line] = &cookie.strings;
    let parsed = cookie.flags & 1 != 0;
    let mut out = json!({
        "parsed": parsed,
        "blocked": cookie.exclusions != 0,
        "exclusion_reasons": reasons(cookie.exclusions, &EXCLUSIONS),
        "warning_reasons": reasons(cookie.warnings, &WARNINGS),
    });
    if !line.is_empty() {
        out["line_withheld"] = json!(true);
        out["line_bytes"] = json!(line.len());
    }
    if !parsed {
        return out;
    }
    out["name"] = json!(text(name));
    out["value_withheld"] = json!(true);
    out["value_bytes"] = json!(value.len());
    out["value_sha256"] = json!(hex::encode(Sha256::digest(value)));
    out["size"] = json!(name.len() + value.len());
    out["domain"] = json!(text(domain));
    out["path"] = json!(text(path));
    out["expires_ms"] = if cookie.expiry == 0 {
        Value::Null
    } else {
        json!(cookie.expiry)
    };
    out["http_only"] = json!(cookie.flags & 2 != 0);
    out["secure"] = json!(cookie.flags & 4 != 0);
    out["same_site"] = json!(SAME_SITE[cookie.same_site as usize]);
    out["effective_same_site"] = json!(EFFECTIVE[cookie.effective as usize]);
    out["priority"] = json!(PRIORITY[cookie.priority as usize]);
    out["partition_key"] = if cookie.flags & 8 != 0 {
        json!({"top_level_site": text(partition), "cross_site_ancestor": cookie.flags & 16 != 0})
    } else {
        Value::Null
    };
    out["domain_cookie"] = json!(cookie.flags & 32 != 0);
    out["source_scheme"] = json!(["unset", "non_secure", "secure"][cookie.scheme as usize]);
    out["source_port"] = json!(cookie.port);
    out
}

/// A valid cookie list record's state and unattributed count.
pub(crate) fn list_facts(event: &Value) -> Option<(u8, u32)> {
    decode_list(event).map(|list| (list.state, list.unattributed))
}

/// The verified cookies of a retained list, or the reason none are shown.
fn read_list(
    event: &Value,
    list: &List,
    artifacts: &[Value],
    root: &Path,
) -> Result<Vec<Cookie>, &'static str> {
    // A created list names this record; a shared one an earlier record's.
    let mut matching = artifacts.iter().filter(|artifact| {
        artifact["artifact_id"] == event["artifact_id"]
            && artifact["session_id"] == event["session_id"]
            && artifact["kind"] == "cookie_list"
            && artifact["capture_origin"] == "network_request"
            && (list.state == 2 || artifact["creator_event_id"] == event["sequence_number"])
    });
    let artifact = match (matching.next(), matching.next()) {
        (Some(artifact), None) => artifact,
        _ => return Err("missing"),
    };
    match evidence::content(root, artifact, LIST_LIMIT) {
        Ok(bytes)
            if bytes.len() == list.length as usize
                && Sha256::digest(&bytes).as_slice() == list.digest =>
        {
            parse_list(&bytes, list.sent, list.count).ok_or("malformed")
        }
        Ok(_) => Err("mismatch"),
        Err(_) => Err("unreadable"),
    }
}

fn describe_list(event: &Value, list: &List, artifacts: &[Value], root: &Path) -> Value {
    let mut value = json!({
        "sequence_number": event["sequence_number"],
        "parent_event_id": event["parent_event_id"],
        "state": STATES[list.state as usize],
        "cookie_count": list.count,
        "blocked_count": list.blocked,
        "list_bytes": list.length,
        "sha256": if list.state == 4 { Value::Null } else { json!(hex::encode(list.digest)) },
        "artifact_id": event["artifact_id"],
        "unattributed_lists": list.unattributed,
    });
    if matches!(list.state, 1 | 2) {
        match read_list(event, list, artifacts, root) {
            Ok(cookies) => {
                value["artifact"] = json!("verified");
                value["cookies"] = json!(cookies.iter().map(describe_cookie).collect::<Vec<_>>());
            }
            Err(reason) => value["artifact"] = json!(reason),
        }
    }
    value
}

fn sequence(event: &Value) -> u64 {
    event["sequence_number"]
        .as_str()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0)
}

fn hop_starts(events: &[Value], session: &str) -> HashMap<(u64, String), String> {
    events
        .iter()
        .filter(|event| {
            event["session_id"] == session
                && event["category"] == "network"
                && matches!(
                    event["type"].as_str(),
                    Some("request_started" | "request_redirected")
                )
        })
        .filter_map(|event| {
            Some((
                (
                    event["process_id"].as_u64()?,
                    event["sequence_number"].as_str()?.to_owned(),
                ),
                event["request_id"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

fn parent_key(event: &Value) -> (u64, String) {
    (
        event["process_id"].as_u64().unwrap_or(0),
        event["parent_event_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    )
}

/// Cookie lists of `request_id` in `session_id`, grouped by hop. `drops` are
/// the session's, which say whether a list may have been lost.
pub fn build(
    events: &[Value],
    drops: &Drops,
    artifacts: &[Value],
    root: &Path,
    session: &str,
    request: &str,
) -> Value {
    let starts = hop_starts(events, session);
    let mut hops: BTreeMap<u32, (Vec<Value>, Vec<Value>)> = BTreeMap::new();
    let mut malformed = Vec::new();
    let mut unattached = 0usize;
    let mut records: Vec<&Value> = events
        .iter()
        .filter(|event| {
            event["session_id"] == session
                && event["request_id"] == request
                && event["category"] == "network"
                && event["type"] == "cookie_list"
        })
        .collect();
    records.sort_by_key(|event| sequence(event));
    for event in records {
        if starts.get(&parent_key(event)).map(String::as_str) != Some(request) {
            unattached += 1;
            continue;
        }
        let Some(list) = decode_list(event) else {
            malformed.push(event["sequence_number"].clone());
            continue;
        };
        let described = describe_list(event, &list, artifacts, root);
        let entry = hops.entry(list.hop).or_default();
        if list.sent {
            entry.0.push(described);
        } else {
            entry.1.push(described);
        }
    }
    // A content session records a provisional block for every hop; a hop
    // the network never reported has no list, and says why.
    let (provisional, process) = provisional_hops(events, session, request);
    let lifecycle = lifecycle_of(events, session, request, process);
    let dropped = span_of(events, session, request, process)
        .is_some_and(|(first, last)| drops.during(first, last, lifecycle.ended));
    let last = provisional.iter().next_back().copied();
    for hop in &provisional {
        hops.entry(*hop).or_default();
    }
    // A sent list comes with the raw request, so a later hop's list means the
    // factory observed and tracked the request.
    let sent_hops: BTreeSet<u32> = hops
        .iter()
        .filter(|(_, (sent, _))| !sent.is_empty())
        .map(|(hop, _)| *hop)
        .collect();
    let hops: Vec<Value> = hops
        .into_iter()
        .map(|(hop, (sent, received))| {
            let counted = provisional.contains(&hop);
            let later_reported = sent_hops.range(hop + 1..).next().is_some();
            let sent_missing = if counted && sent.is_empty() {
                json!(qualified(
                    lifecycle.missing_reason(Some(hop) == last, later_reported),
                    dropped
                ))
            } else {
                Value::Null
            };
            let received_missing = if counted && !sent.is_empty() && received.is_empty() {
                json!(qualified(
                    lifecycle.missing_received_reason(Some(hop) == last),
                    dropped
                ))
            } else {
                Value::Null
            };
            json!({"hop": hop, "sent": sent, "received": received,
                "sent_missing": sent_missing, "received_missing": received_missing})
        })
        .collect();
    json!({
        "session_id": session,
        "request_id": request,
        "hops": hops,
        "malformed_records": malformed,
        "unattached_records": unattached,
    })
}

pub(crate) struct Script {
    pub(crate) api: u8,
    pub(crate) flags: u8,
    count: u32,
    name_length: u32,
    value_length: u32,
    string_length: u32,
    pub(crate) frame: [u8; 16],
    pub(crate) stack: [u8; 32],
    value: [u8; 32],
    prefix: [u8; NAME_PREFIX],
    /// The isolate its frame and stack are read in: version 1 is the
    /// document's; version 2 names it. None when version 2 names no thread.
    pub(crate) scope: Option<request_stack::Scope>,
    /// A `document.cookie` read of the whole jar, with no name: every version
    /// 1 and 2 read, and a version 3 read record (flag bit 4).
    read_record: bool,
    /// A version 3 read record's names that no name record counts.
    unrecorded_names: u32,
}

/// The C++ core's rules for the renderer's script_cookie record.
pub(crate) fn decode_script(event: &Value) -> Option<Script> {
    if event["type"] != "script_cookie"
        || event["protocol_version"] != 3
        || event["category"] != "network"
        || event["flags"] != 0
        || event["payload_truncated"] != false
        || event["payload_size"] != 128
        || event["payload_encoding"] != "hex"
        || [
            "parent_event_id",
            "request_id",
            "artifact_id",
            "navigation_id",
            "encoded_data_length",
            "decoded_body_length",
        ]
        .iter()
        .any(|key| event[*key] != "0")
        || event["status_code"] != 0
        || event["error_code"] != 0
        || event["resource_type"] != 0
    {
        return None;
    }
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    if bytes.len() != 128 || le(&bytes[2..4]) != 128 {
        return None;
    }
    let version = le(&bytes[0..2]);
    if !matches!(version, 1..=3) {
        return None;
    }
    let frame_id = event["frame_id"].as_str()?.parse::<u64>().ok()?;
    // Version 2 byte 6: 0 (no thread named) or a stack thread, 2 to 4 only
    // with the worker's context ID as frame_id.
    let thread = bytes[6];
    let scope = if version == 1 {
        Some(request_stack::Scope::DOCUMENT)
    } else {
        request_stack::Scope::of_cookie(thread, frame_id)
    };
    let scoped = if version == 1 {
        thread == 0
    } else {
        thread == 0 || scope.is_some()
    };
    // Version 3: a document.cookie read is a nameless read record (bit 4),
    // whose offset 16 counts unrecorded names, or one name it returned.
    let flagged_read = bytes[5] & 16 != 0;
    let script = Script {
        api: bytes[4],
        flags: bytes[5],
        count: le(&bytes[8..12]) as u32,
        name_length: le(&bytes[12..16]) as u32,
        value_length: if flagged_read {
            0
        } else {
            le(&bytes[16..20]) as u32
        },
        string_length: le(&bytes[20..24]) as u32,
        frame: bytes[24..40].try_into().ok()?,
        stack: bytes[40..72].try_into().ok()?,
        value: bytes[72..104].try_into().ok()?,
        prefix: bytes[104..128].try_into().ok()?,
        scope,
        read_record: bytes[4] == 2 && (version < 3 || flagged_read),
        unrecorded_names: if flagged_read {
            le(&bytes[16..20]) as u32
        } else {
            0
        },
    };
    let zero = |slice: &[u8]| slice.iter().all(|byte| *byte == 0);
    let write = matches!(script.api, 1 | 3 | 6);
    let truncated = script.name_length as usize > NAME_PREFIX;
    let frame = &script.frame;
    let framed = matches!(frame[0], 1 | 2)
        && le(&frame[4..8]) != 0
        && le(&frame[2..4]) == 0
        && frame[1] & !3 == 0;
    let recorded = script.flags & 2 != 0;
    let stacked = script.flags & 4 != 0;
    let flag_mask = if version == 3 { 0x1f } else { 0x0f };
    let reads_shaped = if flagged_read {
        script.api == 2 && script.name_length == 0
    } else {
        version < 3
            || script.api != 2
            || (script.flags & 8 == 0 && script.string_length >= script.name_length)
    };
    let valid = (1..=6).contains(&script.api)
        && script.flags & !flag_mask == 0
        && reads_shaped
        && scoped
        && bytes[7] == 0
        && (script.scope.is_some() || !recorded)
        && script.count != 0
        && truncated == (script.flags & 1 != 0)
        && (truncated || zero(&script.prefix[script.name_length as usize..]))
        && if write {
            script.count == 1 && !zero(&script.value) && script.flags & 8 == 0
        } else {
            script.value_length == 0 && zero(&script.value)
        }
        && match script.api {
            1 => {
                u64::from(script.string_length)
                    >= u64::from(script.name_length) + u64::from(script.value_length)
            }
            2 => true,
            _ => script.string_length == 0,
        }
        && if recorded { framed } else { zero(frame) }
        && stacked != zero(&script.stack)
        && (!stacked || recorded);
    valid.then_some(script)
}

fn names_match(script: &Script, name: &[u8]) -> bool {
    script.name_length as usize == name.len()
        && script.prefix[..name.len().min(NAME_PREFIX)] == name[..name.len().min(NAME_PREFIX)]
}

fn describe_script(event: &Value, script: &Script) -> Value {
    let frame = &script.frame;
    json!({
        "sequence_number": event["sequence_number"],
        "process_id": event["process_id"],
        "frame_id": event["frame_id"],
        "tab_id": event["tab_id"],
        "monotonic_time_ns": event["monotonic_time_ns"],
        "api": APIS[script.api as usize],
        "count": script.count,
        "name_prefix_only": script.flags & 1 != 0,
        "value_bytes": script.value_length,
        "value_sha256": if matches!(script.api, 1 | 3 | 6) { json!(hex::encode(script.value)) } else { Value::Null },
        "string_bytes": script.string_length,
        "table_full": script.flags & 8 != 0,
        "read_record": script.read_record,
        "unrecorded_names": script.unrecorded_names,
        "script_frame": if script.flags & 2 != 0 {
            json!({"kind": if frame[0] == 2 { "wasm" } else { "javascript" },
                "constructor": frame[1] & 1 != 0, "script_id": le(&frame[4..8]),
                "position": le(&frame[8..12])})
        } else {
            Value::Null
        },
        "stack_digest": if script.flags & 4 != 0 { json!(hex::encode(script.stack)) } else { Value::Null },
        "thread": script.scope.map(|scope| scope.name()),
        "stack": Value::Null,
    })
}

/// A renderer's script identities outside the records `provenance` read, and
/// whether an identity absent from them is absent from the store.
pub type IndexedIdentities = (
    HashMap<request_stack::IdentityKey, request_stack::Identity>,
    bool,
);

/// Everything in `events` that touched cookie `name` in `session_id`.
pub fn provenance(
    events: &[Value],
    drops: &Drops,
    artifacts: &[Value],
    root: &Path,
    session: &str,
    name: &str,
    indexed_identities: &dyn Fn(u64) -> IndexedIdentities,
) -> Value {
    let wanted = name.as_bytes();
    let starts = hop_starts(events, session);
    let mut set_by = Vec::new();
    let mut sent_with = Vec::new();
    let mut scripts = Vec::new();
    let mut malformed = Vec::new();
    let mut lists: HashMap<String, Option<Vec<Cookie>>> = HashMap::new();
    let mut unread = BTreeSet::new();
    let mut identities: HashMap<u64, HashMap<request_stack::IdentityKey, request_stack::Identity>> =
        HashMap::new();
    for event in events
        .iter()
        .filter(|event| event["session_id"] == session && event["type"] == "script_identity")
    {
        let decoded = event["payload"]
            .as_str()
            .and_then(|payload| hex::decode(payload).ok())
            .and_then(|bytes| request_stack::decode_identity(&bytes));
        if let (Some((isolate, script, identity)), Some(process)) =
            (decoded, event["process_id"].as_u64())
        {
            identities
                .entry(process)
                .or_default()
                .insert((process as u32, isolate, script), identity);
        }
    }
    let mut known_identities: HashMap<u64, bool> = HashMap::new();
    let no_identities = HashMap::new();
    let read = |artifact: &Value, limit: usize| evidence::content(root, artifact, limit);
    let mut stacks: HashMap<(u64, request_stack::Scope, [u8; 16], [u8; 32]), Value> =
        HashMap::new();
    let mut stacks_unresolved = 0u64;
    // document.cookie reads that returned the jar without naming each cookie
    // in it: they may include this name, so `script` is then not complete.
    let mut whole_jar_reads = 0u64;
    let mut unrecorded_reads = 0u64;
    let mut unrecorded_names = 0u64;
    // cookieStore.get or getAll with no name reads every cookie it can, and
    // a record a full queue dropped may have named this one.
    let mut unnamed_store_reads = 0u64;
    let records_dropped;
    let mut ordered: Vec<&Value> = events
        .iter()
        .filter(|event| event["session_id"] == session && event["category"] == "network")
        .collect();
    ordered.sort_by_key(|event| {
        event["monotonic_time_ns"]
            .as_str()
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(0)
    });
    // A full queue may have dropped a record that named this cookie: a gap of
    // any category, since a renderer's gap takes the category of the last
    // record drained before it, at or after the oldest record read.
    let oldest = ordered
        .first()
        .and_then(|event| event_window::unsigned(&event["monotonic_time_ns"]))
        .unwrap_or(0);
    for event in ordered {
        match event["type"].as_str() {
            Some("script_cookie") => match decode_script(event) {
                Some(script) if script.read_record => {
                    if script.flags & 16 == 0 {
                        whole_jar_reads += u64::from(script.count);
                    } else if script.unrecorded_names != 0 {
                        unrecorded_reads += u64::from(script.count);
                        unrecorded_names += u64::from(script.unrecorded_names);
                    }
                }
                Some(script)
                    if names_match(&script, wanted)
                        || (matches!(script.api, 4 | 5) && script.name_length == 0) =>
                {
                    if matches!(script.api, 4 | 5) && script.name_length == 0 {
                        unnamed_store_reads += u64::from(script.count);
                        if !names_match(&script, wanted) {
                            continue;
                        }
                    }
                    let mut item = describe_script(event, &script);
                    if let (true, Some(scope)) = (script.flags & 2 != 0, script.scope) {
                        let process = event["process_id"].as_u64().unwrap_or(0);
                        let key = (process, scope, script.frame, script.stack);
                        if let Some(stack) = stacks.get(&key) {
                            item["stack"] = stack.clone();
                        } else if stacks.len() < PROVENANCE_STACKS {
                            // The newest records need not hold this renderer's
                            // identities; the index has the whole session's.
                            let known = *known_identities.entry(process).or_insert_with(|| {
                                let (indexed, exhaustive) = indexed_identities(process);
                                let table = identities.entry(process).or_default();
                                for (key, identity) in indexed {
                                    table.entry(key).or_insert(identity);
                                }
                                exhaustive
                            });
                            let mut stack = request_stack::resolve_call(
                                event,
                                scope,
                                &script.frame,
                                (script.flags & 4 != 0).then_some(script.stack),
                                identities.get(&process).unwrap_or(&no_identities),
                                artifacts,
                                &read,
                            );
                            if !known {
                                request_stack::mark_identities_outside_scan(&mut stack);
                            }
                            item["stack"] = stack.clone();
                            stacks.insert(key, stack);
                        } else {
                            stacks_unresolved += 1;
                        }
                    }
                    scripts.push(item)
                }
                Some(_) => {}
                None => malformed.push(event["sequence_number"].clone()),
            },
            Some("cookie_list") => {
                let Some(list) = decode_list(event) else {
                    malformed.push(event["sequence_number"].clone());
                    continue;
                };
                let Some(request) = starts.get(&parent_key(event)) else {
                    continue;
                };
                if !matches!(list.state, 1 | 2) {
                    continue;
                }
                let key = event["artifact_id"].as_str().unwrap_or("0").to_owned();
                if !lists.contains_key(&key) {
                    if lists.len() >= PROVENANCE_LISTS {
                        unread.insert(key);
                        continue;
                    }
                    let read = read_list(event, &list, artifacts, root).ok();
                    lists.insert(key.clone(), read);
                }
                let Some(Some(cookies)) = lists.get(&key) else {
                    continue;
                };
                for cookie in cookies.iter().filter(|cookie| {
                    cookie.flags & 1 != 0 && cookie.strings[0].as_slice() == wanted
                }) {
                    let mut item = describe_cookie(cookie);
                    item["request_id"] = json!(request);
                    item["hop"] = json!(list.hop);
                    item["sequence_number"] = event["sequence_number"].clone();
                    item["monotonic_time_ns"] = event["monotonic_time_ns"].clone();
                    if list.sent {
                        sent_with.push(item);
                    } else {
                        set_by.push(item);
                    }
                }
            }
            _ => {}
        }
    }
    records_dropped = drops.between(oldest, None);
    // A sent value equal to a script write's value names that write.
    for item in &mut sent_with {
        let written: Vec<Value> = scripts
            .iter()
            .filter(|script| script["value_sha256"] == item["value_sha256"])
            .map(|script| json!({"process_id": script["process_id"], "sequence_number": script["sequence_number"]}))
            .collect();
        item["written_by_script"] = json!(written);
    }
    json!({
        "session_id": session,
        "name": name,
        "set_by": set_by,
        "script": scripts,
        "sent_with": sent_with,
        "lists_read": lists.len(),
        "lists_unread": unread.len(),
        "stacks_unresolved": stacks_unresolved,
        "read_coverage": {
            "complete": whole_jar_reads == 0
                && unrecorded_reads == 0
                && unnamed_store_reads == 0
                && records_dropped == 0,
            "whole_jar_reads": whole_jar_reads,
            "reads_with_unrecorded_names": unrecorded_reads,
            "unrecorded_names": unrecorded_names,
            "unnamed_store_reads": unnamed_store_reads,
            "records_dropped": records_dropped,
        },
        "malformed_records": malformed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_index(_process: u64) -> IndexedIdentities {
        (HashMap::new(), true)
    }

    fn record(kind: &str, sequence: u64, parent: u64, payload: &[u8], artifact: &str) -> Value {
        json!({"protocol_version":3,"session_id":"7","sequence_number":sequence.to_string(),
            "monotonic_time_ns":sequence.to_string(),"process_id":42,"thread_id":1,"tab_id":0,
            "navigation_id":"0","frame_id":"0","artifact_id":artifact,
            "parent_event_id":parent.to_string(),"request_id":if parent == 0 { "0" } else { "17" },
            "browser_context_id_high":"0","browser_context_id_low":"0","encoded_data_length":"0",
            "decoded_body_length":"0","status_code":0,"error_code":0,"resource_type":0,"flags":0,
            "initiator_request_id":0,"initiator_process_id":0,"payload_truncated":false,
            "category":"network","type":kind,"payload_size":128,"payload_encoding":"hex",
            "payload":hex::encode(payload)})
    }

    fn entry(out: &mut Vec<u8>, exclusions: u64, flags: u8, strings: [&[u8]; 6]) {
        let mut fixed = [0u8; 64];
        fixed[0..8].copy_from_slice(&exclusions.to_le_bytes());
        fixed[16..24].copy_from_slice(&1_700_000_000_000i64.to_le_bytes());
        fixed[24] = flags;
        if flags & 1 != 0 {
            fixed[25] = 3;
            fixed[26] = 2;
            fixed[27] = 2;
            fixed[28] = 2;
            fixed[32..36].copy_from_slice(&443i32.to_le_bytes());
        } else {
            fixed[16..24].fill(0);
        }
        for (index, string) in strings.iter().enumerate() {
            fixed[36 + 4 * index..40 + 4 * index]
                .copy_from_slice(&(string.len() as u32).to_le_bytes());
        }
        out.extend_from_slice(&fixed);
        for string in strings {
            out.extend_from_slice(string);
        }
    }

    fn list(sent: bool, cookies: &[(u64, u8, [&[u8]; 6])]) -> Vec<u8> {
        let mut out = b"RBCK".to_vec();
        out.extend_from_slice(&[1, 0, if sent { 1 } else { 2 }, 0]);
        out.extend_from_slice(&(cookies.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        for (exclusions, flags, strings) in cookies {
            entry(&mut out, *exclusions, *flags, *strings);
        }
        out
    }

    fn list_payload(
        sent: bool,
        state: u8,
        bytes: &[u8],
        count: u32,
        blocked: u32,
        hop: u32,
    ) -> Vec<u8> {
        let mut out = vec![0u8; 128];
        out[0] = 1;
        out[2] = 128;
        out[4] = if sent { 1 } else { 2 };
        out[5] = state;
        out[8..12].copy_from_slice(&count.to_le_bytes());
        out[12..16].copy_from_slice(&blocked.to_le_bytes());
        out[16..20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        out[20..24].copy_from_slice(&hop.to_le_bytes());
        out[32..64].copy_from_slice(&Sha256::digest(bytes));
        out
    }

    fn script_payload(api: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 128];
        out[0] = 1;
        out[2] = 128;
        out[4] = api;
        out[5] = 2;
        out[8] = 1;
        out[12..16].copy_from_slice(&(name.len() as u32).to_le_bytes());
        out[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        out[20..24].copy_from_slice(&((name.len() + value.len() + 1) as u32).to_le_bytes());
        out[24] = 1;
        out[28..32].copy_from_slice(&77u32.to_le_bytes());
        out[32..36].copy_from_slice(&1234u32.to_le_bytes());
        out[72..104].copy_from_slice(&Sha256::digest(value));
        out[104..104 + name.len()].copy_from_slice(name);
        out
    }

    #[test]
    fn hops_provenance_and_withheld_values() {
        let root = std::env::temp_dir().join(format!("reb-request-cookies-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("blobs")).unwrap();
        let partition = b"https://top.test";
        let sent = list(
            true,
            &[
                (
                    0,
                    0x3f,
                    [b"_abck", b"token-1", b".echo.test", b"/", partition, b""],
                ),
                (
                    32,
                    1,
                    [b"pref", b"dark", b"echo.test", b"/settings", b"", b""],
                ),
            ],
        );
        let received = list(
            false,
            &[
                (
                    256,
                    0x07,
                    [
                        b"_abck",
                        b"token-0",
                        b"echo.test",
                        b"/",
                        b"",
                        b"_abck=token-0; Secure",
                    ],
                ),
                (1 << 24, 0, [b"", b"", b"", b"", b"", b"bad\x01=1"]),
            ],
        );
        let mut artifacts = Vec::new();
        for (id, creator, bytes) in [("8", "12", &sent), ("9", "13", &received)] {
            let hash = hex::encode(Sha256::digest(bytes));
            std::fs::write(root.join(format!("blobs/{hash}.bin")), bytes).unwrap();
            artifacts.push(json!({"artifact_id":id,"session_id":"7","kind":"cookie_list",
                "capture_origin":"network_request","creator_event_id":creator,"byte_size":bytes.len(),
                "sha256":hash,"content_path":format!("blobs/{hash}.bin")}));
        }
        let start = json!({"session_id":"7","request_id":"17","category":"network",
            "type":"request_started","process_id":42,"sequence_number":"11","monotonic_time_ns":"11"});
        let mut events = vec![
            start,
            record(
                "script_cookie",
                5,
                0,
                &script_payload(1, b"_abck", b"token-1"),
                "0",
            ),
            record(
                "cookie_list",
                12,
                11,
                &list_payload(true, 1, &sent, 2, 1, 0),
                "8",
            ),
            record(
                "cookie_list",
                13,
                11,
                &list_payload(false, 1, &received, 2, 2, 0),
                "9",
            ),
            record(
                "cookie_list",
                14,
                9,
                &list_payload(true, 3, b"", 0, 0, 0),
                "0",
            ),
            record(
                "cookie_list",
                15,
                11,
                &list_payload(true, 1, &sent, 2, 3, 0),
                "8",
            ),
        ];
        events[1]["frame_id"] = json!("99");
        let result = build(&events, &Drops::default(), &artifacts, &root, "7", "17");
        assert_eq!(result["unattached_records"], 1);
        assert_eq!(result["malformed_records"], json!(["15"]));
        let hop = &result["hops"][0];
        assert_eq!(hop["sent"][0]["artifact"], "verified");
        let first = &hop["sent"][0]["cookies"][0];
        assert_eq!(first["name"], "_abck");
        assert_eq!(first["value_withheld"], true);
        assert_eq!(first["value_bytes"], 7);
        assert_eq!(first["same_site"], "Lax");
        assert_eq!(first["partition_key"]["top_level_site"], "https://top.test");
        assert_eq!(first["partition_key"]["cross_site_ancestor"], true);
        assert_eq!(first["expires_ms"], 1_700_000_000_000i64);
        assert_eq!(
            hop["sent"][0]["cookies"][1]["exclusion_reasons"],
            json!(["samesite_strict"])
        );
        let unparsed = &hop["received"][0]["cookies"][1];
        assert_eq!(unparsed["parsed"], false);
        assert_eq!(
            unparsed["exclusion_reasons"],
            json!(["disallowed_character"])
        );
        assert_eq!(unparsed["line_bytes"], 6);
        assert!(!result.to_string().contains("token-"));
        assert_eq!(hop["sent_missing"], Value::Null);
        assert_eq!(hop["received_missing"], Value::Null);
        // A content session's hop with only a provisional block has no list,
        // and says why; so does a sent list without a received one.
        let mut provisional = vec![0u8; 128];
        provisional[0] = 1;
        provisional[2] = 128;
        provisional[4] = 1;
        provisional[5] = 3;
        provisional[6] = 4;
        provisional[16] = 1;
        provisional[48..80].fill(0x5a);
        let mut hops = events.clone();
        hops.push(json!({"session_id":"7","request_id":"17","category":"network",
            "type":"request_redirected","process_id":42,"sequence_number":"20","monotonic_time_ns":"20"}));
        hops.push(record("request_headers", 21, 20, &provisional, "0"));
        provisional[16] = 0;
        hops.push(record("request_headers", 22, 11, &provisional, "0"));
        hops.push(json!({"session_id":"7","request_id":"17","category":"network",
            "type":"request_failed","process_id":42,"sequence_number":"23","monotonic_time_ns":"23","flags":0}));
        let missing = build(&hops, &Drops::default(), &artifacts, &root, "7", "17");
        assert_eq!(missing["hops"][1]["hop"], 1);
        assert_eq!(missing["hops"][1]["sent_missing"], "failed");
        assert_eq!(missing["hops"][1]["received_missing"], Value::Null);
        assert_eq!(missing["hops"][0]["sent_missing"], Value::Null);
        // A sent list without a received one has its own reason, and a hop
        // before one with a sent list sent nothing.
        let mut sent_only: Vec<Value> = hops
            .iter()
            .filter(|event| event["sequence_number"] != "13")
            .cloned()
            .collect();
        sent_only.push(record(
            "cookie_list",
            24,
            20,
            &list_payload(true, 3, b"", 0, 0, 1),
            "0",
        ));
        let received = build(&sent_only, &Drops::default(), &artifacts, &root, "7", "17");
        assert_eq!(received["hops"][0]["received_missing"], "no_raw_response");
        // A drop while it ran makes the absent response list unsure.
        let gap = json!({"session_id":"7","type":"gap","category":"canvas","process_id":42,
            "sequence_number":"40","monotonic_time_ns":"12","payload":hex::encode("1"),
            "payload_truncated":false});
        let lossy = build(
            &sent_only,
            &Drops::of(&[gap], "7"),
            &artifacts,
            &root,
            "7",
            "17",
        );
        assert_eq!(lossy["hops"][0]["received_missing"], "record_dropped");
        assert_eq!(lossy["hops"][1]["received_missing"], "failed");
        assert_eq!(received["hops"][1]["sent_missing"], Value::Null);
        assert_eq!(received["hops"][1]["received_missing"], "failed");

        let origin = provenance(
            &events,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(
            origin["set_by"][0]["exclusion_reasons"],
            json!(["samesite_none_insecure"])
        );
        assert_eq!(origin["script"][0]["api"], "document.cookie set");
        assert_eq!(origin["script"][0]["frame_id"], "99");
        assert_eq!(origin["script"][0]["script_frame"]["script_id"], 77);
        assert_eq!(origin["script"][0]["script_frame"]["position"], 1234);
        assert_eq!(origin["sent_with"][0]["request_id"], "17");
        assert_eq!(
            origin["sent_with"][0]["written_by_script"],
            json!([{"process_id": 42, "sequence_number": "5"}])
        );
        assert_eq!(origin["lists_read"], 2);
        assert!(!origin.to_string().contains("token-"));
        let none = provenance(
            &events,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "pref",
            &no_index,
        );
        assert_eq!(none["sent_with"][0]["blocked"], true);
        assert_eq!(none["script"], json!([]));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A `document.cookie` read: version 3 with `name`, else the whole jar.
    fn read_payload(
        version: u8,
        name: &[u8],
        read_record: bool,
        count: u32,
        unrecorded: u32,
    ) -> Vec<u8> {
        let mut out = script_payload(2, name, b"");
        out[0] = version;
        out[6] = if version >= 2 { 1 } else { 0 };
        out[5] = 2 | if read_record { 16 } else { 0 };
        out[8..12].copy_from_slice(&count.to_le_bytes());
        out[16..20].copy_from_slice(&unrecorded.to_le_bytes());
        out[20..24].copy_from_slice(&40u32.to_le_bytes());
        out[72..104].fill(0);
        out
    }

    #[test]
    fn document_cookie_reads_join_provenance_by_name() {
        let root = std::env::temp_dir().join(format!("reb-cookie-reads-{}", std::process::id()));
        let events = vec![
            record(
                "script_cookie",
                5,
                0,
                &read_payload(3, b"_abck", false, 4, 0),
                "0",
            ),
            record(
                "script_cookie",
                6,
                0,
                &read_payload(3, b"pref", false, 1, 0),
                "0",
            ),
            record(
                "script_cookie",
                7,
                0,
                &read_payload(3, b"", true, 2, 3),
                "0",
            ),
            record(
                "script_cookie",
                8,
                0,
                &read_payload(3, b"", true, 1, 0),
                "0",
            ),
            record(
                "script_cookie",
                9,
                0,
                &read_payload(2, b"", false, 5, 0),
                "0",
            ),
        ];
        let origin = provenance(
            &events,
            &Drops::default(),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(origin["malformed_records"], json!([]));
        assert_eq!(origin["script"].as_array().unwrap().len(), 1);
        let read = &origin["script"][0];
        assert_eq!(read["api"], "document.cookie get");
        assert_eq!(read["count"], 4);
        assert_eq!(read["read_record"], false);
        assert_eq!(read["script_frame"]["position"], 1234);
        assert_eq!(read["value_sha256"], Value::Null);
        assert_eq!(
            origin["read_coverage"],
            json!({"complete": false, "whole_jar_reads": 5, "reads_with_unrecorded_names": 2,
                "unrecorded_names": 3, "unnamed_store_reads": 0, "records_dropped": 0})
        );
        // Only reads that named every cookie leave the coverage complete.
        let named = provenance(
            &events[..2],
            &Drops::default(),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(named["read_coverage"]["complete"], true);
        // cookieStore.getAll() and get({url}) name no cookie, so they may have
        // read this one; a dropped record may have named it.
        let mut unnamed = events[..2].to_vec();
        let mut store = script_payload(5, b"", b"");
        store[5] = 2;
        store[8..12].copy_from_slice(&3u32.to_le_bytes());
        store[16..24].fill(0);
        store[72..104].fill(0);
        unnamed.push(record("script_cookie", 10, 0, &store, "0"));
        let coverage = provenance(
            &unnamed,
            &Drops::default(),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(coverage["malformed_records"], json!([]));
        assert_eq!(coverage["read_coverage"]["unnamed_store_reads"], 3);
        assert_eq!(coverage["read_coverage"]["complete"], false);
        assert_eq!(coverage["script"].as_array().unwrap().len(), 1);
        // ...and the empty name still lists it, as its own read.
        let empty = provenance(&unnamed, &Drops::default(), &[], &root, "7", "", &no_index);
        assert_eq!(empty["script"].as_array().unwrap().len(), 1);
        // A full queue may have dropped a record that named it, in a gap of any
        // category: a renderer's gap takes the category of the last record it
        // drained, here a canvas one. A gap before the oldest record read is
        // outside the window, and a named gap is a reason, not a loss.
        let gap = |sequence: u64, time: &str, category: &str, payload: &str| {
            let mut gap = record("gap", sequence, 0, b"", "0");
            gap["category"] = json!(category);
            gap["monotonic_time_ns"] = json!(time);
            gap["payload"] = json!(hex::encode(payload));
            gap["payload_size"] = json!(payload.len());
            gap
        };
        let window = &events[..2];
        let lost = provenance(
            window,
            &Drops::of(&[gap(11, "6", "canvas", "2")], "7"),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(lost["read_coverage"]["records_dropped"], 2);
        assert_eq!(lost["read_coverage"]["complete"], false);
        let older = provenance(
            window,
            &Drops::of(&[gap(11, "4", "canvas", "2")], "7"),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(older["read_coverage"]["complete"], true);
        let reason = gap(11, "6", "network", "service_worker_end_lost");
        let kept = provenance(
            window,
            &Drops::of(&[reason], "7"),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(kept["read_coverage"]["complete"], true);
        let mut other = gap(11, "6", "canvas", "2");
        other["session_id"] = json!("8");
        let elsewhere = provenance(
            window,
            &Drops::of(&[other], "7"),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(elsewhere["read_coverage"]["complete"], true);
        // Unrecorded names add up across read records.
        let mut twice = events[..2].to_vec();
        twice.push(record(
            "script_cookie",
            12,
            0,
            &read_payload(3, b"", true, 1, 3),
            "0",
        ));
        twice.push(record(
            "script_cookie",
            13,
            0,
            &read_payload(3, b"", true, 1, 2),
            "0",
        ));
        let summed = provenance(
            &twice,
            &Drops::default(),
            &[],
            &root,
            "7",
            "_abck",
            &no_index,
        );
        assert_eq!(summed["read_coverage"]["reads_with_unrecorded_names"], 2);
        assert_eq!(summed["read_coverage"]["unrecorded_names"], 5);
        // A read record has no name, and a name read is never recorded alone.
        assert!(
            decode_script(&record(
                "script_cookie",
                5,
                0,
                &read_payload(3, b"a", true, 1, 0),
                "0"
            ))
            .is_none()
        );
        let mut full = read_payload(3, b"a", false, 1, 0);
        full[5] |= 8;
        assert!(decode_script(&record("script_cookie", 5, 0, &full, "0")).is_none());
        let mut unrecorded = read_payload(3, b"a", false, 1, 0);
        unrecorded[16] = 1;
        assert!(decode_script(&record("script_cookie", 5, 0, &unrecorded, "0")).is_none());
        let mut legacy_flag = read_payload(2, b"", true, 1, 0);
        legacy_flag[16] = 0;
        assert!(decode_script(&record("script_cookie", 5, 0, &legacy_flag, "0")).is_none());
    }

    #[test]
    fn script_writes_resolve_their_walked_stack() {
        let root = std::env::temp_dir().join(format!("reb-cookie-stacks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("blobs")).unwrap();
        let source = "let a = 1;\nfunction setSid() {\n  document.cookie = 'sid=1';\n}\n";
        let position = source.find("document").unwrap() as u32;
        let start = source.find("() {").unwrap() as u32;
        let mut frame = vec![1u8, 0, 0, 0];
        for value in [77u32, position, start] {
            frame.extend(value.to_le_bytes());
        }
        let mut walked = 0x4b53_4252u32.to_le_bytes().to_vec();
        walked.extend([1, 0, 32, 0, 16, 0, 0, 0]);
        walked.extend(1u32.to_le_bytes());
        walked.extend(1u32.to_le_bytes());
        walked.extend([0; 12]);
        walked.extend(&frame);
        let mut artifacts = Vec::new();
        for (id, kind, bytes) in [
            ("20", "stack", walked.as_slice()),
            ("21", "javascript", source.as_bytes()),
        ] {
            let hash = hex::encode(Sha256::digest(bytes));
            std::fs::write(root.join(format!("blobs/{hash}.bin")), bytes).unwrap();
            artifacts.push(
                json!({"artifact_id":id,"session_id":"7","kind":kind,"url":"https://app.test/a.js",
                "byte_size":bytes.len(),"sha256":hash,"content_path":format!("blobs/{hash}.bin")}),
            );
        }
        let mut write = script_payload(1, b"sid", b"1");
        write[5] = 2 | 4;
        write[24..40].copy_from_slice(&frame);
        write[40..72].copy_from_slice(&Sha256::digest(&walked));
        let mut identity = vec![0u8; 128];
        identity[0] = 1;
        identity[2] = 128;
        identity[4] = 1;
        identity[5] = 2;
        identity[8..12].copy_from_slice(&77u32.to_le_bytes());
        identity[24..32].copy_from_slice(&9u64.to_le_bytes());
        identity[32..40].copy_from_slice(&(source.len() as u64).to_le_bytes());
        identity[40..72].copy_from_slice(&Sha256::digest(source));
        let mut events = vec![
            record("script_cookie", 5, 0, &write, "0"),
            record("script_identity", 6, 5, &identity, "0"),
        ];
        events[1]["request_id"] = json!("0");
        let origin = provenance(
            &events,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "sid",
            &no_index,
        );
        let stack = &origin["script"][0]["stack"];
        let digest = hex::encode(Sha256::digest(&walked));
        assert_eq!(
            (stack["frames_retained"].as_bool(), stack["digest"].as_str()),
            (Some(true), Some(digest.as_str()))
        );
        let resolution = &stack["frames"][0]["resolution"];
        assert_eq!(
            (
                &resolution["status"],
                &resolution["line"],
                &resolution["column"],
                &resolution["function_name"]
            ),
            (&json!("resolved"), &json!(3), &json!(3), &json!("setSid"))
        );
        // Without a digest the one-frame position still resolves.
        events[0] = record(
            "script_cookie",
            5,
            0,
            &{
                let mut one = write.clone();
                one[5] = 2;
                one[40..72].fill(0);
                one
            },
            "0",
        );
        let origin = provenance(
            &events,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "sid",
            &no_index,
        );
        let stack = &origin["script"][0]["stack"];
        assert_eq!(
            (stack["digest"].clone(), stack["frames_retained"].clone()),
            (Value::Null, json!(false))
        );
        assert_eq!(stack["frames"][0]["resolution"]["line"], 3);
        assert_eq!(origin["stacks_unresolved"], 0);
        // With no identity in the records read, the index answers for it.
        let without = vec![events[0].clone()];
        let resolution_of =
            |origin: &Value| origin["script"][0]["stack"]["frames"][0]["resolution"].clone();
        let from_index = |process: u64| -> IndexedIdentities {
            (
                HashMap::from([{
                    let (isolate, script, identity) =
                        request_stack::decode_identity(&identity).unwrap();
                    ((process as u32, isolate, script), identity)
                }]),
                false,
            )
        };
        let found = provenance(
            &without,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "sid",
            &from_index,
        );
        assert_eq!(resolution_of(&found)["status"], "resolved");
        // An index that cannot answer for every identity leaves it unknown.
        let unknown = provenance(
            &without,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "sid",
            &|_| (HashMap::new(), false),
        );
        assert_eq!(
            resolution_of(&unknown)["reason"],
            "script_identity_outside_scan"
        );
        // Only a whole-store answer can say it is missing.
        let missing = provenance(
            &without,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "sid",
            &no_index,
        );
        assert_eq!(resolution_of(&missing)["reason"], "script_identity_missing");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn service_worker_cookie_writes_resolve_in_the_workers_isolate() {
        let root = std::env::temp_dir().join(format!("reb-cookie-worker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("blobs")).unwrap();
        // Script 77 is a different script in each isolate.
        let page = "function onPage() {\n  document.cookie = 'sid=1';\n}\n";
        let worker = "let n = 0;\nfunction inWorker() {\n  cookieStore.set('sid', '1');\n}\n";
        let position = worker.find("cookieStore").unwrap() as u32;
        let mut artifacts = Vec::new();
        for (id, source) in [("31", page), ("32", worker)] {
            let hash = hex::encode(Sha256::digest(source));
            std::fs::write(root.join(format!("blobs/{hash}.bin")), source).unwrap();
            artifacts.push(
                json!({"artifact_id":id,"session_id":"7","kind":"javascript","url":"https://app.test/a.js",
                "byte_size":source.len(),"sha256":hash,"content_path":format!("blobs/{hash}.bin")}),
            );
        }
        let identity = |source: &str, thread: u8, key: u64| {
            let mut bytes = vec![0u8; 128];
            bytes[0] = 2;
            bytes[2] = 128;
            bytes[4] = 1;
            bytes[5] = 2;
            bytes[8..12].copy_from_slice(&77u32.to_le_bytes());
            bytes[24..32].copy_from_slice(&9u64.to_le_bytes());
            bytes[32..40].copy_from_slice(&(source.len() as u64).to_le_bytes());
            bytes[40..72].copy_from_slice(&Sha256::digest(source));
            bytes[72] = thread;
            bytes[80..88].copy_from_slice(&key.to_le_bytes());
            bytes
        };
        let mut write = script_payload(3, b"sid", b"1");
        write[0] = 2;
        write[6] = 4;
        write[20..24].fill(0);
        write[32..36].copy_from_slice(&position.to_le_bytes());
        let start = worker.find("() {").unwrap() as u32;
        write[36..40].copy_from_slice(&start.to_le_bytes());
        let mut events = vec![
            record("script_cookie", 5, 0, &write, "0"),
            record("script_identity", 6, 0, &identity(page, 1, 0), "0"),
            record("script_identity", 7, 0, &identity(worker, 4, 0x5157), "0"),
        ];
        events[0]["frame_id"] = json!(0x5157u64.to_string());
        let origin = provenance(
            &events,
            &Drops::default(),
            &artifacts,
            &root,
            "7",
            "sid",
            &no_index,
        );
        let script = &origin["script"][0];
        assert_eq!(script["thread"], "service_worker");
        let resolution = &script["stack"]["frames"][0]["resolution"];
        assert_eq!(
            (
                &resolution["status"],
                &resolution["function_name"],
                &resolution["line"]
            ),
            (&json!("resolved"), &json!("inWorker"), &json!(3)),
            "{resolution}"
        );
        // A worker's record without its context ID names no isolate.
        events[0]["frame_id"] = json!("0");
        assert!(decode_script(&events[0]).is_none());
        // Version 2 that names no thread records no frame; with a frame it is refused.
        let mut unnamed = script_payload(3, b"sid", b"1");
        unnamed[0] = 2;
        unnamed[20..24].fill(0);
        assert!(decode_script(&record("script_cookie", 5, 0, &unnamed, "0")).is_none());
        unnamed[5] = 0;
        unnamed[24..40].fill(0);
        let bare = decode_script(&record("script_cookie", 5, 0, &unnamed, "0")).unwrap();
        assert!(bare.scope.is_none());
        // Version 1 records, written before the thread byte, are the document's.
        let mut legacy = write.clone();
        legacy[0] = 1;
        assert!(decode_script(&record("script_cookie", 5, 0, &legacy, "0")).is_none());
        legacy[6] = 0;
        assert_eq!(
            decode_script(&record("script_cookie", 5, 0, &legacy, "0"))
                .unwrap()
                .scope,
            Some(request_stack::Scope::DOCUMENT)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lists_and_scripts_reject_what_the_core_rejects() {
        let sent = list(true, &[(0, 1, [b"a", b"b", b"", b"", b"", b""])]);
        assert!(parse_list(&sent, true, 1).is_some());
        assert!(parse_list(&sent, false, 1).is_none());
        assert!(parse_list(&sent, true, 2).is_none());
        assert!(parse_list(&sent[..sent.len() - 1], true, 1).is_none());
        let line = list(true, &[(0, 1, [b"a", b"b", b"", b"", b"", b"a=b"])]);
        assert!(
            parse_list(&line, true, 1).is_none(),
            "sent cookies carry no line"
        );
        let mut payload = script_payload(2, b"sid", b"");
        payload[72..104].fill(0);
        assert!(decode_script(&record("script_cookie", 3, 0, &payload, "0")).is_some());
        payload[8] = 0;
        assert!(decode_script(&record("script_cookie", 3, 0, &payload, "0")).is_none());
        let write = script_payload(1, b"sid", b"v");
        assert!(decode_script(&record("script_cookie", 3, 0, &write, "0")).is_some());
        let mut parented = record("script_cookie", 3, 0, &write, "0");
        parented["parent_event_id"] = json!("2");
        assert!(decode_script(&parented).is_none());
    }
}
