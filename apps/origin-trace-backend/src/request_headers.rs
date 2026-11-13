//! One request's header blocks per hop (protocol/native-network-v3.md), for
//! `get_request_headers`. Records are validated again here and joined only to
//! an exact lifecycle parent of the request. Values of headers named as
//! credentials stay in the binary artifact, which MCP never inlines, like
//! request bodies. Withholding goes by name: a value under any other name, such
//! as a `Location` query, is returned as captured.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::event_window;
use crate::evidence;

const BLOCK_LIMIT: usize = 320 * 1024;
/// Substrings that mark a header name as a credential even inside a compound
/// such as `X-AuthToken`, `AccessToken` or `X-Amzn-Remapped-Set-Cookie`. Each is
/// long or distinctive enough that an ordinary name does not contain it.
const CREDENTIAL_ROOTS: [&str; 15] = [
    "token",
    "secret",
    "passw",
    "passphrase",
    "csrf",
    "xsrf",
    "cookie",
    "bearer",
    "credential",
    "sessionid",
    "sessid",
    "signature",
    "authoriz",
    "authentication",
    "oauth",
];
/// Words too short to match as substrings. Whole words only, so `:authority`
/// and `Author` stay readable. A word ending in `key` is matched separately.
const CREDENTIAL_WORDS: [&str; 6] = ["auth", "jwt", "otp", "pwd", "session", "wsse"];
/// Standard names that a credential rule would catch, whose values are not
/// credentials: a WebSocket nonce, a retry key, CORS's literal `true`, and pins.
const READABLE_NAMES: [&str; 5] = [
    "sec-websocket-key",
    "idempotency-key",
    "access-control-allow-credentials",
    "public-key-pins",
    "public-key-pins-report-only",
];
const SOURCES: [&str; 4] = ["", "browser", "network", "early_hints"];
pub(crate) const STATES: [&str; 9] = [
    "",
    "captured",
    "captured_shared",
    "empty",
    "not_captured_block_limit",
    "not_captured_artifact_unavailable",
    "not_captured_transfer_refused",
    "not_captured_session_budget",
    "not_captured_url",
];
// net::ReferrerPolicy + 1, as Fetch policy names.
const POLICIES: [&str; 9] = [
    "",
    "no-referrer-when-downgrade",
    "strict-origin-when-cross-origin",
    "origin-when-cross-origin",
    "unsafe-url",
    "origin",
    "same-origin",
    "strict-origin",
    "no-referrer",
];

/// Why a hop of a content session's request has no `network` request block,
/// from the request's own browser lifecycle records ("Missing final blocks"
/// in protocol/native-network-v3.md), in the order they are decided.
pub(crate) const MISSING_REASONS: [(&str, &str); 9] = [
    (
        "in_progress",
        "the request has not ended, so the network service may still report what it sent",
    ),
    (
        "download",
        "downloads load through the browser's own factory, which has no DevTools observer at the pinned Chromium",
    ),
    (
        "service_worker",
        "a service worker answered it, so no request reached the network",
    ),
    (
        "from_cache",
        "the HTTP cache answered it without sending a request, so there are no sent headers or cookies",
    ),
    (
        "failed",
        "it failed before the network service reported the headers it sent",
    ),
    (
        "redirect_not_sent",
        "nothing was sent for this redirect hop: it was an internal redirect, such as an HSTS upgrade, or one the HTTP cache answered, while a later hop of the request reported what it sent",
    ),
    (
        "not_reported",
        "the network service reported no sent headers for this hop: its factory had no DevTools observer, or the block arrived for a request the capture no longer tracked",
    ),
    (
        "record_dropped",
        "a full queue dropped records while this request ran, so its block or list may have been lost",
    ),
    // A hop with a sent cookie list and no received one.
    (
        "no_raw_response",
        "the network service reported what was sent for this hop but no response headers: no response arrived, or it arrived after the capture stopped tracking the request",
    ),
];

/// What one request's browser records say about how it ended.
#[derive(Default)]
pub(crate) struct Lifecycle {
    pub(crate) ended: bool,
    pub(crate) failed: bool,
    pub(crate) responded: bool,
    pub(crate) from_cache: bool,
    pub(crate) from_service_worker: bool,
    pub(crate) download: bool,
}

impl Lifecycle {
    /// Folds one lifecycle record of the request into what is known.
    pub(crate) fn record(&mut self, event: &Value) {
        let flags = event["flags"].as_u64().unwrap_or(0);
        match event["type"].as_str() {
            Some("request_started") => self.download |= event["loader_kind"] == 2,
            Some("response_started") => {
                self.responded = true;
                self.from_cache |= flags & 2 != 0;
                self.from_service_worker |= flags & 4 != 0;
            }
            Some("request_completed" | "response_completed") => self.ended = true,
            Some("request_failed") => {
                self.ended = true;
                self.failed = true;
            }
            _ => {}
        }
    }

    /// The reason a hop without a `network` block has none; `last` is whether
    /// it is the request's final hop, the one its response belongs to, and
    /// `later_reported` whether a later hop of the request has a block.
    pub(crate) fn missing_reason(&self, last: bool, later_reported: bool) -> &'static str {
        if last && !self.ended {
            "in_progress"
        } else if self.download {
            "download"
        } else if !last && later_reported {
            // The factory observes and tracks this request, so nothing was sent.
            "redirect_not_sent"
        } else if last && self.from_service_worker {
            "service_worker"
        } else if last && self.from_cache {
            "from_cache"
        } else if last && self.failed && !self.responded {
            "failed"
        } else {
            "not_reported"
        }
    }
}

impl Lifecycle {
    /// The reason a hop with a sent cookie list has no received one: the
    /// network service reports it with the response headers.
    pub(crate) fn missing_received_reason(&self, last: bool) -> &'static str {
        if last && !self.ended {
            "in_progress"
        } else if last && self.failed && !self.responded {
            "failed"
        } else {
            "no_raw_response"
        }
    }
}

/// The hops of `request` with a provisional (`browser`) request block, which
/// a content session records for every hop, and its browser process.
pub(crate) fn provisional_hops(
    events: &[Value],
    session: &str,
    request: &str,
) -> (BTreeSet<u32>, Option<u64>) {
    let mut hops = BTreeSet::new();
    let mut process = None;
    for event in events.iter().filter(|event| {
        event["session_id"] == session
            && event["request_id"] == request
            && event["category"] == "network"
            && event["type"] == "request_headers"
    }) {
        if let Some(block) = decode(event).filter(|block| block.source == 1) {
            hops.insert(block.hop);
            process.get_or_insert(event["process_id"].as_u64().unwrap_or(0));
        }
    }
    (hops, process)
}

/// How long after a request's last record a drop of one of its records can
/// still be reported: the browser's writer reports drops on its next wake, at
/// most 250 ms later, then sends its batch.
pub(crate) const DROP_REPORT_SLACK_NS: u64 = 1_000_000_000;

/// The session's records lost to full queues, by the time of the gap that
/// reported them, from gap records of any category and process.
#[derive(Default)]
pub(crate) struct Drops(Vec<(u64, u64)>);

impl Drops {
    /// From (gap time, records dropped) pairs of one session.
    pub(crate) fn new(mut drops: Vec<(u64, u64)>) -> Self {
        drops.sort_unstable();
        Self(drops)
    }
    #[cfg(test)]
    pub(crate) fn of(gaps: &[Value], session: &str) -> Self {
        let mut drops: Vec<(u64, u64)> = gaps
            .iter()
            .filter(|gap| gap["session_id"] == session)
            .filter_map(|gap| {
                let count = event_window::dropped_records(gap);
                let time = event_window::unsigned(&gap["monotonic_time_ns"])?;
                (count > 0).then_some((time, count))
            })
            .collect();
        drops.sort_unstable();
        Self(drops)
    }
    /// Records lost at or after `from`, and at or before `to` when given.
    pub(crate) fn between(&self, from: u64, to: Option<u64>) -> u64 {
        self.0
            .iter()
            .filter(|(time, _)| *time >= from && to.is_none_or(|to| *time <= to))
            .fold(0u64, |sum, (_, count)| sum.saturating_add(*count))
    }
    /// Whether a record of a request spanning `first` to `last` may have been
    /// lost: a drop while it ran, or reported just after; any later one while
    /// it has not ended.
    pub(crate) fn during(&self, first: u64, last: u64, ended: bool) -> bool {
        self.between(
            first,
            ended.then(|| last.saturating_add(DROP_REPORT_SLACK_NS)),
        ) > 0
    }
}

/// A reason inferred from a block's absence, which a dropped record makes
/// unsure; a reason from a record that is there (cache, service worker,
/// download, failure, still open) stands.
pub(crate) fn qualified(reason: &'static str, dropped: bool) -> &'static str {
    if dropped
        && matches!(
            reason,
            "redirect_not_sent" | "not_reported" | "no_raw_response"
        )
    {
        "record_dropped"
    } else {
        reason
    }
}

pub(crate) fn missing_meaning(reason: &str) -> &'static str {
    MISSING_REASONS
        .iter()
        .find(|(code, _)| *code == reason)
        .map_or("", |(_, meaning)| meaning)
}

struct Block {
    response: bool,
    source: u8,
    state: u8,
    policy: u8,
    family: u8,
    count: u32,
    length: u32,
    hop: u32,
    status: u16,
    port: u16,
    address: [u8; 16],
    unattributed: u32,
    digest: [u8; 32],
}

pub(crate) fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

/// The 128-byte payload of a `kind` child record of a lifecycle record, after
/// the C++ core's envelope rules (native-network-v2.md and v3).
pub(crate) fn child_payload(event: &Value, kind: &str) -> Option<Vec<u8>> {
    if event["type"] != kind
        || event["protocol_version"] != 3
        || event["category"] != "network"
        || event["flags"] != 0
        || event["payload_truncated"] != false
        || event["payload_size"] != 128
        || event["payload_encoding"] != "hex"
        || event["navigation_id"] != "0"
        || event["status_code"] != 0
        || event["error_code"] != 0
        || event["encoded_data_length"] != "0"
        || event["decoded_body_length"] != "0"
        || event["resource_type"] != 0
    {
        return None;
    }
    let sequence: u64 = event["sequence_number"].as_str()?.parse().ok()?;
    let parent: u64 = event["parent_event_id"].as_str()?.parse().ok()?;
    if parent == 0 || parent >= sequence {
        return None;
    }
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    (bytes.len() == 128 && le(&bytes[0..2]) == 1 && le(&bytes[2..4]) == 128).then_some(bytes)
}

/// The C++ core's rules for the record, envelope included.
fn decode(event: &Value) -> Option<Block> {
    let response = event["type"] == "response_headers";
    let bytes = child_payload(
        event,
        if response {
            "response_headers"
        } else {
            "request_headers"
        },
    )?;
    let block = Block {
        response,
        source: bytes[4],
        state: bytes[5],
        policy: bytes[6],
        family: bytes[7],
        count: le(&bytes[8..12]) as u32,
        length: le(&bytes[12..16]) as u32,
        hop: le(&bytes[16..20]) as u32,
        status: le(&bytes[20..22]) as u16,
        port: le(&bytes[22..24]) as u16,
        address: bytes[24..40].try_into().ok()?,
        unattributed: le(&bytes[40..44]) as u32,
        digest: bytes[48..80].try_into().ok()?,
    };
    let zero = |slice: &[u8]| slice.iter().all(|byte| *byte == 0);
    let addressed = block.family != 0;
    let shape = if response {
        block.policy == 0
            && if block.source == 1 {
                block.status <= 999 && (block.status == 0 || block.status >= 100)
            } else {
                block.source == 3 && block.status == 103 && !addressed
            }
    } else {
        block.status == 0
            && !addressed
            && if block.source == 1 {
                (1..=8).contains(&block.policy)
            } else {
                block.source == 2 && block.policy == 0
            }
    };
    let empty = block.state == 3;
    let limited = block.state == 4;
    let valid = shape
        && (1..=8).contains(&block.state)
        && zero(&bytes[44..48])
        && zero(&bytes[80..])
        && matches!(block.family, 0 | 4 | 6)
        && (addressed || (block.port == 0 && zero(&block.address)))
        && (block.family != 4 || zero(&block.address[4..]))
        && (block.count == 0) == empty
        && (block.length == 0) == empty
        && u64::from(block.length) >= 5 * u64::from(block.count)
        && limited == (block.length as usize > BLOCK_LIMIT)
        && zero(&block.digest) == limited
        && (event["artifact_id"] != "0") == matches!(block.state, 1 | 2);
    valid.then_some(block)
}

/// A valid header record's direction, source, state, hop and unattributed
/// count, for counts that read no block.
pub(crate) struct BlockFacts {
    pub(crate) response: bool,
    pub(crate) source: u8,
    pub(crate) state: u8,
    pub(crate) hop: u32,
    pub(crate) unattributed: u32,
}

pub(crate) fn block_facts(event: &Value) -> Option<BlockFacts> {
    decode(event).map(|block| BlockFacts {
        response: block.response,
        source: block.source,
        state: block.state,
        hop: block.hop,
        unattributed: block.unattributed,
    })
}

/// `name: value` CRLF lines, split at the first colon after the first byte.
fn parse(bytes: &[u8], count: u32) -> Option<Vec<(String, String)>> {
    let text = bytes.strip_suffix(b"\n")?;
    let mut lines = Vec::new();
    for line in text.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r")?;
        let colon = line.iter().skip(1).position(|byte| *byte == b':')? + 1;
        if line.get(colon + 1) != Some(&b' ') {
            return None;
        }
        lines.push((
            String::from_utf8_lossy(&line[..colon]).into_owned(),
            String::from_utf8_lossy(&line[colon + 2..]).into_owned(),
        ));
    }
    (lines.len() == count as usize).then_some(lines)
}

fn address(block: &Block) -> Value {
    match block.family {
        4 => json!(format!(
            "{}.{}.{}.{}",
            block.address[0], block.address[1], block.address[2], block.address[3]
        )),
        6 => json!(format!("[{}]", std::net::Ipv6Addr::from(block.address))),
        _ => Value::Null,
    }
}

/// Whether a header's value is withheld. Decided from the name alone. A
/// false match only keeps a value out of JSON; the binary artifact still has it.
fn credential_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if READABLE_NAMES.contains(&name.as_str()) {
        return false;
    }
    CREDENTIAL_ROOTS.iter().any(|root| name.contains(root))
        || name
            .split(['-', '_', ':'])
            .filter(|word| !word.is_empty())
            .any(|word| CREDENTIAL_WORDS.contains(&word) || word.ends_with("key"))
}

fn headers(lines: Vec<(String, String)>) -> Vec<Value> {
    lines
        .into_iter()
        .map(|(name, value)| {
            if credential_name(&name) {
                json!({"name": name, "value_withheld": true, "value_bytes": value.len()})
            } else {
                json!({"name": name, "value": value})
            }
        })
        .collect()
}

fn describe(event: &Value, block: &Block, artifacts: &[Value], root: &Path) -> Value {
    let kind = if block.response {
        "response_headers"
    } else {
        "request_headers"
    };
    let digest = hex::encode(block.digest);
    let mut value = json!({
        "sequence_number": event["sequence_number"],
        "parent_event_id": event["parent_event_id"],
        "source": SOURCES[block.source as usize],
        "state": STATES[block.state as usize],
        "header_count": block.count,
        "block_bytes": block.length,
        "sha256": if block.state == 4 { Value::Null } else { json!(digest) },
        "artifact_id": event["artifact_id"],
        "unattributed_blocks": block.unattributed,
    });
    if block.response {
        value["status_code"] = json!(block.status);
        value["remote_address"] = address(block);
        value["remote_port"] = json!(block.port);
    } else {
        value["referrer_policy"] = if block.policy == 0 {
            Value::Null
        } else {
            json!(POLICIES[block.policy as usize])
        };
    }
    if !matches!(block.state, 1 | 2) {
        return value;
    }
    // A created block names this record; a shared one an earlier record's.
    let mut matching = artifacts.iter().filter(|artifact| {
        artifact["artifact_id"] == event["artifact_id"]
            && artifact["session_id"] == event["session_id"]
            && artifact["kind"] == kind
            && artifact["capture_origin"] == "network_request"
            && (block.state == 2 || artifact["creator_event_id"] == event["sequence_number"])
    });
    let artifact = match (matching.next(), matching.next()) {
        (Some(artifact), None) => artifact,
        _ => {
            value["artifact"] = json!("missing");
            return value;
        }
    };
    match evidence::content(root, artifact, BLOCK_LIMIT) {
        Ok(bytes)
            if bytes.len() == block.length as usize
                && Sha256::digest(&bytes).as_slice() == block.digest =>
        {
            match parse(&bytes, block.count) {
                Some(lines) => {
                    value["artifact"] = json!("verified");
                    value["headers"] = json!(headers(lines));
                }
                None => value["artifact"] = json!("malformed"),
            }
        }
        Ok(_) => value["artifact"] = json!("mismatch"),
        Err(_) => value["artifact"] = json!("unreadable"),
    }
    value
}

/// The first and last record times of `request` in its browser `process`.
pub(crate) fn span_of(
    events: &[Value],
    session: &str,
    request: &str,
    process: Option<u64>,
) -> Option<(u64, u64)> {
    let process = process?;
    let times = events
        .iter()
        .filter(|event| {
            event["session_id"] == session
                && event["request_id"] == request
                && event["process_id"].as_u64() == Some(process)
        })
        .filter_map(|event| event_window::unsigned(&event["monotonic_time_ns"]));
    times.fold(None, |span, time| match span {
        None => Some((time, time)),
        Some((first, last)) => Some((first.min(time), last.max(time))),
    })
}

/// The lifecycle of `request` as its browser `process` recorded it.
pub(crate) fn lifecycle_of(
    events: &[Value],
    session: &str,
    request: &str,
    process: Option<u64>,
) -> Lifecycle {
    let mut lifecycle = Lifecycle::default();
    let Some(process) = process else {
        return lifecycle;
    };
    for event in events.iter().filter(|event| {
        event["session_id"] == session
            && event["request_id"] == request
            && event["category"] == "network"
            && event["process_id"].as_u64() == Some(process)
    }) {
        lifecycle.record(event);
    }
    lifecycle
}

/// Header blocks of `request_id` in `session_id`, grouped by hop. `drops` are
/// the session's, which say whether a block may have been lost.
pub fn build(
    events: &[Value],
    drops: &Drops,
    artifacts: &[Value],
    root: &Path,
    session: &str,
    request: &str,
) -> Value {
    let ours = |event: &Value| {
        event["session_id"] == session
            && event["request_id"] == request
            && event["category"] == "network"
    };
    let parents: BTreeSet<(u64, String)> = events
        .iter()
        .filter(|event| {
            ours(event)
                && matches!(
                    event["type"].as_str(),
                    Some("request_started" | "request_redirected" | "response_started")
                )
        })
        .filter_map(|event| {
            Some((
                event["process_id"].as_u64()?,
                event["sequence_number"].as_str()?.to_owned(),
            ))
        })
        .collect();
    let mut hops: BTreeMap<u32, (Vec<Value>, Vec<Value>)> = BTreeMap::new();
    let mut malformed = Vec::new();
    let mut unattached = 0usize;
    let mut sources: BTreeMap<u32, (bool, bool)> = BTreeMap::new();
    let mut browser_process = None;
    let mut records: Vec<&Value> = events
        .iter()
        .filter(|event| {
            ours(event)
                && matches!(
                    event["type"].as_str(),
                    Some("request_headers" | "response_headers")
                )
        })
        .collect();
    records.sort_by_key(|event| {
        event["sequence_number"]
            .as_str()
            .and_then(|text| text.parse::<u64>().ok())
    });
    for event in records {
        let parent = (
            event["process_id"].as_u64().unwrap_or(0),
            event["parent_event_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        );
        if !parents.contains(&parent) {
            unattached += 1;
            continue;
        }
        let Some(block) = decode(event) else {
            malformed.push(event["sequence_number"].clone());
            continue;
        };
        let described = describe(event, &block, artifacts, root);
        let entry = hops.entry(block.hop).or_default();
        if block.response {
            entry.1.push(described);
        } else {
            let seen = sources.entry(block.hop).or_default();
            if block.source == 1 {
                seen.0 = true;
                browser_process.get_or_insert(parent.0);
            } else {
                seen.1 = true;
            }
            entry.0.push(described);
        }
    }
    let lifecycle = lifecycle_of(events, session, request, browser_process);
    let dropped = span_of(events, session, request, browser_process)
        .is_some_and(|(first, last)| drops.during(first, last, lifecycle.ended));
    let last = sources.keys().next_back().copied();
    let hops: Vec<Value> = hops
        .into_iter()
        .map(|(hop, (request, response))| {
            let provisional =
                !request.is_empty() && request.iter().all(|block| block["source"] == "browser");
            // A content session's hop that the network never reported.
            let later_reported = sources.range(hop + 1..).any(|(_, seen)| seen.1);
            let missing = match sources.get(&hop) {
                Some((true, false)) => json!(qualified(
                    lifecycle.missing_reason(Some(hop) == last, later_reported),
                    dropped
                )),
                _ => Value::Null,
            };
            json!({"hop": hop, "provisional": provisional, "network_block_missing": missing,
                "request": request, "response": response})
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, sequence: u64, parent: u64, payload: [u8; 128], artifact: &str) -> Value {
        json!({"protocol_version":3,"session_id":"7","sequence_number":sequence.to_string(),
            "monotonic_time_ns":"1","process_id":42,"thread_id":1,"tab_id":0,"navigation_id":"0",
            "frame_id":"0","artifact_id":artifact,"parent_event_id":parent.to_string(),"request_id":"17",
            "browser_context_id_high":"0","browser_context_id_low":"0","encoded_data_length":"0",
            "decoded_body_length":"0","status_code":0,"error_code":0,"resource_type":0,"flags":0,
            "initiator_request_id":0,"initiator_process_id":0,"payload_truncated":false,
            "category":"network","type":kind,"payload_size":128,"payload_encoding":"hex",
            "payload":hex::encode(payload)})
    }

    fn payload(
        source: u8,
        state: u8,
        policy: u8,
        block: &[u8],
        hop: u32,
        status: u16,
    ) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0] = 1;
        out[2] = 128;
        out[4] = source;
        out[5] = state;
        out[6] = policy;
        out[8..12]
            .copy_from_slice(&(block.iter().filter(|b| **b == b'\n').count() as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(block.len() as u32).to_le_bytes());
        out[16..20].copy_from_slice(&hop.to_le_bytes());
        out[20..22].copy_from_slice(&status.to_le_bytes());
        out[48..80].copy_from_slice(&Sha256::digest(block));
        out
    }

    #[test]
    fn hops_join_exact_parents_and_withhold_credentials() {
        let root = std::env::temp_dir().join(format!("reb-request-headers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("blobs")).unwrap();
        let sent = b"Accept: */*\r\nCookie: sid=secret\r\n";
        let got = b"Set-Cookie: a=b\r\nLocation: /next\r\n";
        let mut artifacts = Vec::new();
        for (id, creator, kind, bytes) in [
            ("5", "12", "request_headers", &sent[..]),
            ("6", "21", "response_headers", &got[..]),
        ] {
            let hash = hex::encode(Sha256::digest(bytes));
            std::fs::write(root.join(format!("blobs/{hash}.bin")), bytes).unwrap();
            artifacts.push(json!({"artifact_id":id,"session_id":"7","kind":kind,
                "capture_origin":"network_request","creator_event_id":creator,"byte_size":bytes.len(),
                "sha256":hash,"content_path":format!("blobs/{hash}.bin")}));
        }
        let start = json!({"session_id":"7","request_id":"17","category":"network",
            "type":"request_started","process_id":42,"sequence_number":"11"});
        let redirect = json!({"session_id":"7","request_id":"17","category":"network",
            "type":"request_redirected","process_id":42,"sequence_number":"20"});
        let events = vec![
            start,
            record("request_headers", 12, 11, payload(1, 1, 4, sent, 0, 0), "5"),
            redirect,
            record(
                "response_headers",
                21,
                20,
                payload(1, 1, 0, got, 0, 302),
                "6",
            ),
            record("request_headers", 22, 20, payload(1, 2, 4, sent, 1, 0), "5"),
            record("request_headers", 23, 9, payload(2, 3, 0, b"", 0, 0), "0"),
            record("request_headers", 24, 20, payload(1, 1, 0, sent, 1, 0), "5"),
        ];
        let result = build(&events, &Drops::default(), &artifacts, &root, "7", "17");
        assert_eq!(result["unattached_records"], 1);
        assert_eq!(result["malformed_records"], json!(["24"]));
        let hop0 = &result["hops"][0];
        assert_eq!(hop0["provisional"], true);
        assert_eq!(hop0["request"][0]["referrer_policy"], "unsafe-url");
        assert_eq!(hop0["request"][0]["artifact"], "verified");
        assert_eq!(
            hop0["request"][0]["headers"],
            json!([{"name":"Accept","value":"*/*"},
                {"name":"Cookie","value_withheld":true,"value_bytes":10}])
        );
        assert_eq!(hop0["response"][0]["status_code"], 302);
        assert_eq!(hop0["response"][0]["headers"][0]["value_withheld"], true);
        assert_eq!(hop0["response"][0]["headers"][1]["value"], "/next");
        let hop1 = &result["hops"][1];
        assert_eq!(hop1["request"][0]["state"], "captured_shared");
        assert_eq!(hop1["request"][0]["artifact"], "verified");
        assert!(!result.to_string().contains("secret"));
        // Hops the network never reported say why, from the request's records.
        assert_eq!(hop0["network_block_missing"], "not_reported");
        assert_eq!(hop1["network_block_missing"], "in_progress");
        let mut ended = events.clone();
        ended.push(
            json!({"session_id":"7","request_id":"17","category":"network",
            "type":"response_started","process_id":42,"sequence_number":"30","flags":2}),
        );
        ended.push(
            json!({"session_id":"7","request_id":"17","category":"network",
            "type":"request_completed","process_id":42,"sequence_number":"31","flags":0}),
        );
        // Another process's records of the same ID are not this request's.
        ended.push(
            json!({"session_id":"7","request_id":"17","category":"network",
            "type":"request_failed","process_id":43,"sequence_number":"32","flags":0}),
        );
        let cached = build(&ended, &Drops::default(), &artifacts, &root, "7", "17");
        assert_eq!(cached["hops"][1]["network_block_missing"], "from_cache");
        assert_eq!(cached["hops"][0]["network_block_missing"], "not_reported");
        let lifecycle = |kinds: &[(&str, u64)], loader: u64| {
            let mut life = Lifecycle::default();
            life.record(&json!({"type":"request_started","loader_kind":loader,"flags":0}));
            for (kind, flags) in kinds {
                life.record(&json!({"type":kind,"flags":flags}));
            }
            life
        };
        assert_eq!(
            lifecycle(&[("request_failed", 0)], 3).missing_reason(true, false),
            "failed"
        );
        assert_eq!(
            lifecycle(&[("response_started", 0), ("request_failed", 0)], 3)
                .missing_reason(true, false),
            "not_reported"
        );
        assert_eq!(
            lifecycle(&[("response_started", 4), ("request_completed", 0)], 3)
                .missing_reason(true, false),
            "service_worker"
        );
        assert_eq!(
            lifecycle(&[("request_completed", 0)], 2).missing_reason(true, false),
            "download"
        );
        // A service worker answered from its cache: no request reached the network.
        assert_eq!(
            lifecycle(&[("response_started", 6), ("request_completed", 0)], 3)
                .missing_reason(true, false),
            "service_worker"
        );
        // An earlier hop of a request whose later hop was reported sent nothing.
        let finished = lifecycle(&[("response_started", 0), ("request_completed", 0)], 3);
        assert_eq!(finished.missing_reason(false, true), "redirect_not_sent");
        assert_eq!(finished.missing_reason(false, false), "not_reported");
        assert_eq!(finished.missing_received_reason(true), "no_raw_response");
        let mut redirected = events.clone();
        redirected.push(record(
            "request_headers",
            25,
            20,
            payload(2, 3, 0, b"", 1, 0),
            "0",
        ));
        let reported = build(&redirected, &Drops::default(), &artifacts, &root, "7", "17");
        assert_eq!(
            reported["hops"][0]["network_block_missing"],
            "redirect_not_sent"
        );
        assert_eq!(reported["hops"][1]["network_block_missing"], Value::Null);
        // A full queue dropping records while the request ran, in a gap of any
        // category, makes a reason drawn from an absence unsure; a reason from
        // a record that is there stands. An ended request ignores drops past
        // the report slack.
        let gap = |time: u64, category: &str| {
            json!({"session_id":"7","type":"gap","category":category,"process_id":42,
                "sequence_number":"40","monotonic_time_ns":time.to_string(),
                "payload":hex::encode("3"),"payload_truncated":false})
        };
        let lossy = build(
            &redirected,
            &Drops::of(&[gap(1, "canvas")], "7"),
            &artifacts,
            &root,
            "7",
            "17",
        );
        assert_eq!(lossy["hops"][0]["network_block_missing"], "record_dropped");
        let cached_lossy = build(
            &ended,
            &Drops::of(&[gap(500_000_001, "network")], "7"),
            &artifacts,
            &root,
            "7",
            "17",
        );
        assert_eq!(
            cached_lossy["hops"][0]["network_block_missing"],
            "record_dropped"
        );
        assert_eq!(
            cached_lossy["hops"][1]["network_block_missing"],
            "from_cache"
        );
        let late = build(
            &ended,
            &Drops::of(&[gap(2_000_000_001, "network")], "7"),
            &artifacts,
            &root,
            "7",
            "17",
        );
        assert_eq!(late["hops"][0]["network_block_missing"], "not_reported");
        assert!(
            MISSING_REASONS
                .iter()
                .all(|(code, _)| !missing_meaning(code).is_empty())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn credential_names_are_withheld_and_ordinary_names_stay_readable() {
        for name in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Api-Key",
            "api-key",
            "apikey",
            "X-Goog-Api-Key",
            "X-Auth-Token",
            "X-Access-Token",
            "X-Amz-Security-Token",
            "X-CSRF-Token",
            "X-XSRF-TOKEN",
            "X-CSRFToken",
            "RequestVerificationToken",
            "Authentication",
            "X-Session-Id",
            "X-Client-Secret",
            "Ocp-Apim-Subscription-Key",
            "X-Functions-Key",
            "X-RapidAPI-Key",
            "X-AuthToken",
            "X-AccessToken",
            "AccessToken",
            "IdToken",
            "X-SessionToken",
            "X-ApiToken",
            "X-App-Key",
            "X-Access-Key",
            "X-Client-Key",
            "X-Subscription-Key",
            "X-AppKey",
            "X-Cookie",
            "X-Original-Cookie",
            "X-Amzn-Remapped-Set-Cookie",
            "X-Signature",
            "X-WSSE",
        ] {
            assert!(credential_name(name), "{name}");
        }
        for name in [
            ":authority",
            ":path",
            "Accept",
            "User-Agent",
            "Location",
            "Referer",
            "WWW-Authenticate",
            "Sec-WebSocket-Key",
            "Idempotency-Key",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Authority",
            "Author",
            "Keep-Alive",
            "X-Request-Id",
            "X-Forwarded-For",
            "Sec-Fetch-Mode",
            "Sec-CH-UA",
            "Accept-Language",
            "Access-Control-Allow-Credentials",
            "Public-Key-Pins",
        ] {
            assert!(!credential_name(name), "{name}");
        }
        let shown = headers(vec![
            ("X-Api-Key".into(), "secret-value".into()),
            ("Accept".into(), "*/*".into()),
        ]);
        assert_eq!(
            shown,
            vec![
                json!({"name": "X-Api-Key", "value_withheld": true, "value_bytes": 12}),
                json!({"name": "Accept", "value": "*/*"})
            ]
        );
    }

    #[test]
    fn parse_rejects_blocks_that_disagree_with_their_record() {
        assert_eq!(
            parse(b":path: /a?b=c\r\nx: y: z\r\n", 2),
            Some(vec![
                (":path".into(), "/a?b=c".into()),
                ("x".into(), "y: z".into())
            ])
        );
        assert!(parse(b"a: b\r\n", 2).is_none());
        assert!(parse(b"a: b", 1).is_none());
        assert!(parse(b"a:b\r\n", 1).is_none());
    }
}
