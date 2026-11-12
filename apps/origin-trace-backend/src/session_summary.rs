//! One bounded read that answers "did this capture work?": event counts by
//! type and frame, artifact digests, gap reasons and capture state, with a
//! short list of checks that name what looks wrong. It is counts, identifiers
//! and origin labels only; it never includes payloads, source or bodies.
use crate::{
    app::validate_event,
    artifact_query::{self, MANIFEST_RECORD_BYTES},
    error::Result,
    event_query::{self, Cursor, EVENT_RECORD_BYTES, SCAN_BYTES, Tally},
    event_window, request_cookies,
    request_headers::{self, Lifecycle},
    request_tabs::RequestTabs,
    session_context,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

const FRAMES: usize = 32;
const TRACKED_FRAMES: usize = 4096;
const FRAME_TYPES: usize = 8;
const SESSIONS: usize = 16;
const ARTIFACTS: usize = 32;
const REFUSAL_REASONS: usize = 32;
/// Browser requests followed for a final header block, as many as the
/// request index holds; the rest are counted as untracked.
const HEADER_REQUESTS: usize = if cfg!(test) { 16 } else { 131_072 };

/// Live state the backend knows outside the stores.
pub struct CaptureState<'a> {
    pub instance_id: &'a str,
    pub capture_mode: &'a str,
    pub broker_connected: bool,
    pub capture_stopped: bool,
    pub artifact_receiver_configured: bool,
    pub artifact_receiver_connected: bool,
}

#[derive(Default)]
struct Frame {
    count: u64,
    first: u64,
    last: u64,
    types: BTreeMap<String, u64>,
}

#[derive(Default)]
struct EventCounts {
    total: u64,
    first: Option<u64>,
    last: Option<u64>,
    by_type: BTreeMap<(String, String), u64>,
    sessions: BTreeMap<u64, u64>,
    frames: HashMap<(u64, u64, u64, u64), Frame>,
    untracked_frame_events: u64,
}
impl EventCounts {
    fn record(&mut self, event: &Value) {
        let number = |key: &str| event_window::unsigned(&event[key]).unwrap_or(0);
        let time = number("monotonic_time_ns");
        let kind = event["type"].as_str().unwrap_or("").to_owned();
        self.total += 1;
        self.first = Some(self.first.map_or(time, |first| first.min(time)));
        self.last = Some(self.last.map_or(time, |last| last.max(time)));
        *self
            .by_type
            .entry((
                event["category"].as_str().unwrap_or("").to_owned(),
                kind.clone(),
            ))
            .or_default() += 1;
        *self.sessions.entry(number("session_id")).or_default() += 1;
        let key = (
            number("session_id"),
            number("tab_id"),
            number("navigation_id"),
            number("frame_id"),
        );
        if !self.frames.contains_key(&key) && self.frames.len() >= TRACKED_FRAMES {
            self.untracked_frame_events += 1;
            return;
        }
        let frame = self.frames.entry(key).or_insert_with(|| Frame {
            first: time,
            last: time,
            ..Default::default()
        });
        frame.count += 1;
        frame.first = frame.first.min(time);
        frame.last = frame.last.max(time);
        *frame.types.entry(kind).or_default() += 1;
    }
    fn count(&self, kind: &str) -> u64 {
        self.by_type
            .iter()
            .filter(|((_, name), _)| name == kind)
            .map(|(_, count)| count)
            .sum()
    }
    fn document(&self, page: &event_query::Page, tally: &Tally) -> Value {
        let mut by_type = self
            .by_type
            .iter()
            .map(|((category, kind), count)| (category, kind, *count))
            .collect::<Vec<_>>();
        by_type.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| (a.0, a.1).cmp(&(b.0, b.1))));
        let mut frames = self.frames.iter().collect::<Vec<_>>();
        frames.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
        let mut sessions = self.sessions.iter().collect::<Vec<_>>();
        sessions.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let mut document = json!({
            "scope": page.scope(),
            "scan_start": page.scan_start.to_string(),
            "scan_end": page.scan_end.to_string(),
            "scan_limit": SCAN_BYTES,
            "budget_exhausted": page.exhausted,
            "total": self.total.to_string(),
            "first_time_ns": self.first.map(|time| time.to_string()),
            "last_time_ns": self.last.map(|time| time.to_string()),
            "by_type": by_type.iter().map(|(category, kind, count)| json!({
                "category": category, "type": kind, "count": count.to_string()
            })).collect::<Vec<_>>(),
            "sessions": sessions.iter().take(SESSIONS).map(|(session, count)| json!({
                "session_id": session.to_string(), "count": count.to_string()
            })).collect::<Vec<_>>(),
            "sessions_omitted": sessions.len().saturating_sub(SESSIONS),
            "frames": frames.iter().take(FRAMES).map(|((session, tab, navigation, frame), stats)| {
                let mut types = stats.types.iter().collect::<Vec<_>>();
                types.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                json!({
                    "session_id": session.to_string(),
                    "tab_id": tab,
                    "navigation_id": navigation.to_string(),
                    "frame_id": frame.to_string(),
                    "count": stats.count.to_string(),
                    "first_time_ns": stats.first.to_string(),
                    "last_time_ns": stats.last.to_string(),
                    "types": types.iter().take(FRAME_TYPES).map(|(kind, count)| json!({
                        "type": kind, "count": count.to_string()
                    })).collect::<Vec<_>>(),
                    "types_omitted": types.len().saturating_sub(FRAME_TYPES),
                })
            }).collect::<Vec<_>>(),
            "frames_omitted": frames.len().saturating_sub(FRAMES),
            "untracked_frame_events": self.untracked_frame_events.to_string(),
        });
        tally.write(&mut document);
        document
    }
}

/// Every capture refusal by its native reason: artifact_capture_failed
/// payloads, and request content a content session did not retain.
#[derive(Default)]
struct Refusals {
    failures: BTreeMap<String, u64>,
    content: BTreeMap<(&'static str, &'static str), u64>,
}
impl Refusals {
    fn record(&mut self, event: &Value) {
        let payload = || {
            event["payload"]
                .as_str()
                .and_then(|text| hex::decode(text).ok())
        };
        match (event["category"].as_str(), event["type"].as_str()) {
            (_, Some("artifact_capture_failed")) => {
                let reason = payload()
                    .filter(|bytes| {
                        !bytes.is_empty()
                            && bytes.len() <= 64
                            && bytes
                                .iter()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
                    })
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_else(|| "unrecognized".into());
                let key = if self.failures.len() < REFUSAL_REASONS
                    || self.failures.contains_key(&reason)
                {
                    reason
                } else {
                    "other".into()
                };
                *self.failures.entry(key).or_default() += 1;
            }
            (Some("network"), Some("request_body")) => {
                if let Some(reason) = payload()
                    .filter(|b| b.len() == 128)
                    .and_then(|b| body_refusal(b[5]))
                {
                    *self.content.entry(("request_body", reason)).or_default() += 1;
                }
            }
            (Some("network"), Some("request_target")) => {
                if let Some(reason) = payload()
                    .filter(|b| b.len() == 128 && b[0] == 2)
                    .and_then(|b| target_refusal(b[9]))
                {
                    *self.content.entry(("request_target", reason)).or_default() += 1;
                }
            }
            (Some("network"), Some(kind @ ("request_headers" | "response_headers"))) => {
                if let Some(reason) = request_headers::block_facts(event)
                    .and_then(|facts| header_refusal(facts.state))
                {
                    let kind = if kind == "request_headers" {
                        "request_headers"
                    } else {
                        "response_headers"
                    };
                    *self.content.entry((kind, reason)).or_default() += 1;
                }
            }
            (Some("network"), Some("cookie_list")) => {
                if let Some(reason) =
                    request_cookies::list_facts(event).and_then(|(state, _)| header_refusal(state))
                {
                    *self.content.entry(("cookie_list", reason)).or_default() += 1;
                }
            }
            (Some("network"), Some("response_body")) => {
                if let Some(reason) = payload()
                    .filter(|b| b.len() == 128 && (b[0] == 1 || b[0] == 2))
                    .and_then(|b| response_refusal(b[4]))
                {
                    *self.content.entry(("response_body", reason)).or_default() += 1;
                }
            }
            _ => {}
        }
    }
}

/// Header block and cookie list states that retained no bytes (native-network-v3.md).
fn header_refusal(state: u8) -> Option<&'static str> {
    Some(match state {
        4 => "not_captured_block_limit",
        5 => "not_captured_artifact_unavailable",
        6 => "not_captured_transfer_refused",
        7 => "not_captured_session_budget",
        8 => "not_captured_url",
        _ => return None,
    })
}

/// One browser request's header blocks and how it ended.
#[derive(Default)]
struct RequestHeaderFacts {
    /// Hops (bit n for hop n) with a provisional or a `network` request block.
    provisional: u64,
    network: u64,
    lifecycle: Lifecycle,
}

/// Header blocks and cookie lists no row shows, and the requests of content
/// sessions that ended without a `network` request block, with the reason
/// ("Missing final blocks" in protocol/native-network-v3.md).
#[derive(Default)]
struct HeaderCoverage {
    /// The newest unattributed count per producer: each record carries its
    /// configuration's count so far.
    unattributed_blocks: BTreeMap<(u64, u64), u64>,
    unattributed_lists: BTreeMap<(u64, u64), u64>,
    requests: HashMap<(u64, u64, u64), RequestHeaderFacts>,
    untracked: u64,
}
impl HeaderCoverage {
    fn record(&mut self, event: &Value) {
        if event["category"] != "network" {
            return;
        }
        let number = |key: &str| event_window::unsigned(&event[key]).unwrap_or(0);
        let producer = (number("session_id"), number("process_id"));
        let key = (producer.0, producer.1, number("request_id"));
        match event["type"].as_str() {
            Some("request_headers" | "response_headers") => {
                let Some(facts) = request_headers::block_facts(event) else {
                    return;
                };
                let newest = self.unattributed_blocks.entry(producer).or_default();
                *newest = (*newest).max(u64::from(facts.unattributed));
                if facts.response || facts.hop >= 64 {
                    return;
                }
                if let Some(request) = self.request(key, true) {
                    if facts.source == 1 {
                        request.provisional |= 1 << facts.hop;
                    } else {
                        request.network |= 1 << facts.hop;
                    }
                }
            }
            Some("cookie_list") => {
                if let Some((_, unattributed)) = request_cookies::list_facts(event) {
                    let newest = self.unattributed_lists.entry(producer).or_default();
                    *newest = (*newest).max(u64::from(unattributed));
                }
            }
            // Browser lifecycle records; a renderer row has no header block.
            Some(
                "request_started" | "response_started" | "request_completed" | "response_completed"
                | "request_failed",
            ) if event["browser_context_id_high"].as_str().unwrap_or("0") != "0"
                || event["browser_context_id_low"].as_str().unwrap_or("0") != "0" =>
            {
                if let Some(request) = self.request(key, false) {
                    request.lifecycle.record(event);
                }
            }
            _ => {}
        }
    }
    /// The request's facts. Only a header record past the bound is counted
    /// as untracked: a request with no header record has no final block to
    /// miss, as in a metadata-only session, whose lifecycle records are simply
    /// not followed then.
    fn request(&mut self, key: (u64, u64, u64), header: bool) -> Option<&mut RequestHeaderFacts> {
        if key.2 == 0 {
            return None;
        }
        if !self.requests.contains_key(&key) && self.requests.len() >= HEADER_REQUESTS {
            self.untracked += u64::from(header);
            return None;
        }
        Some(self.requests.entry(key).or_default())
    }
    /// Requests that ended without a `network` block on their final hop.
    fn missing(&self) -> BTreeMap<&'static str, u64> {
        let mut missing = BTreeMap::new();
        for request in self.requests.values() {
            if request.provisional == 0 {
                continue;
            }
            let last = 63 - request.provisional.leading_zeros();
            if request.network & (1 << last) != 0 {
                continue;
            }
            let reason = request.lifecycle.missing_reason(true, false);
            if reason != "in_progress" {
                *missing.entry(reason).or_default() += 1;
            }
        }
        missing
    }
}

fn missing_check(reason: &str, count: u64) -> Value {
    // A request that failed, or that the cache, a service worker or a
    // download answered, has no final headers by design; the rest are gaps.
    let severity = if reason == "not_reported" {
        "warning"
    } else {
        "info"
    };
    let mut item = check(
        "final_headers_missing",
        severity,
        format!(
            "{count} {} of a content session ended with only provisional headers and no cookie lists: {}.",
            if count == 1 { "request" } else { "requests" },
            request_headers::missing_meaning(reason)
        ),
    );
    item["reason"] = json!(reason);
    item["count"] = json!(count.to_string());
    item
}

/// request_body states that keep less than the whole body (native-network-v2.md).
fn body_refusal(state: u8) -> Option<&'static str> {
    Some(match state {
        5 => "captured_truncated",
        6 => "not_captured_body_kind",
        7 => "not_captured_artifact_unavailable",
        8 => "not_captured_transfer_refused",
        9 => "not_captured_url",
        10 => "not_captured_session_budget",
        11 => "not_captured_credential_form",
        12 => "not_captured_read_incomplete",
        _ => return None,
    })
}

/// Version 2 request_target retention states that did not retain the full target.
fn target_refusal(retention: u8) -> Option<&'static str> {
    Some(match retention {
        2 => "not_retained_artifact_unavailable",
        3 => "not_retained_transfer_refused",
        4 => "not_retained_session_budget",
        5 => "not_retained_url",
        _ => return None,
    })
}

/// response_body states a capture limit or policy caused (native-network-v3.md).
fn response_refusal(state: u8) -> Option<&'static str> {
    Some(match state {
        2 => "captured_truncated",
        9 => "not_captured_type",
        10 => "not_captured_artifact_unavailable",
        11 => "not_captured_transfer_refused",
        12 => "not_captured_session_budget",
        _ => return None,
    })
}

fn content_meaning(category: &str, reason: &str, count: u64) -> String {
    let what = match category {
        "request_body" => "request bodies",
        "response_body" => "response bodies",
        "request_headers" => "request header blocks",
        "response_headers" => "response header blocks",
        "cookie_list" => "cookie lists",
        _ => "full request targets",
    };
    let headers = matches!(
        category,
        "request_headers" | "response_headers" | "cookie_list"
    );
    let why = match reason {
        "not_captured_block_limit" if category == "cookie_list" => {
            "were longer than the 2 MiB list limit, so only their counts and size are recorded"
        }
        "not_captured_block_limit" => {
            "were longer than the 320 KiB block limit, so only their header count and size are recorded"
        }
        "not_captured_session_budget" if headers => {
            "arrived after the configuration retained 64 MiB of header blocks and cookie lists. Start a new session for a fresh budget"
        }
        "not_captured_url" if headers => {
            "had no HTTP(S) URL, a URL longer than 8 KiB, or a hop the capture no longer tracked"
        }
        "captured_truncated" => "were longer than 16 MiB, so only their first 16 MiB is retained",
        "not_captured_type" => {
            "were images, audio, video or fonts that page elements load, which are kept only with REB_CAPTURE_RESPONSE_MEDIA=1"
        }
        "not_captured_session_budget" if category == "response_body" => {
            "arrived after the session's response body byte budget was used. Start a new session, or raise REB_RESPONSE_BODY_BUDGET_MIB"
        }
        "not_captured_body_kind" => {
            "had a part the browser does not read, so they are described but not read"
        }
        "not_captured_read_incomplete" => {
            "had a file, blob or stream part that changed, failed or was cancelled before it was read whole"
        }
        "not_captured_credential_form" => {
            "were password form posts, which keep neither bytes nor a digest"
        }
        "not_captured_url" | "not_retained_url" => {
            "had no HTTP(S) or WebSocket origin, or exceeded Chromium's URL limit"
        }
        "not_captured_session_budget" | "not_retained_session_budget" => {
            "arrived after the session's request-content byte budget was used. Start a new session, or raise REB_REQUEST_CONTENT_BUDGET_MIB"
        }
        "not_captured_artifact_unavailable" | "not_retained_artifact_unavailable" => {
            "had no artifact channel: the Artifact category was off or the receiver was disconnected"
        }
        _ => "were refused by the bounded in-flight memory pool or artifact queue",
    };
    format!("{count} {what} {why}.")
}

#[derive(Default)]
struct ArtifactCounts {
    total: u64,
    by_kind: BTreeMap<String, u64>,
    items: Vec<Value>,
}
impl ArtifactCounts {
    fn record(&mut self, artifact: &Value) {
        self.total += 1;
        *self
            .by_kind
            .entry(artifact["kind"].as_str().unwrap_or("").to_owned())
            .or_default() += 1;
        // The manifest is read newest first.
        if self.items.len() < ARTIFACTS {
            let mut item = json!({});
            for key in [
                "artifact_id",
                "kind",
                "session_id",
                "navigation_id",
                "frame_id",
                "capture_origin",
                "byte_size",
                "sha256",
            ] {
                item[key] = artifact[key].clone();
            }
            item["url_label"] = session_context::url_label(&artifact["url"]);
            self.items.push(item);
        }
    }
}

/// Browser-internal evidence the capture counted instead of recording
/// (protocol/native-network-v3.md). Each record is one producer's cumulative
/// count for one class, so the newest count per producer is summed.
#[derive(Default)]
struct Exclusions(BTreeMap<(u64, u64, u8), u64>);
impl Exclusions {
    fn record(&mut self, event: &Value) {
        if event["category"] != "network" || event["type"] != "capture_exclusion" {
            return;
        }
        let Some(payload) = event["payload"].as_str().and_then(|p| hex::decode(p).ok()) else {
            return;
        };
        if payload.len() != 16 || payload[..4] != [1, 0, 16, 0] || payload[5..8] != [0, 0, 0] {
            return;
        }
        let count = u64::from_le_bytes(payload[8..16].try_into().unwrap());
        if exclusion_class(payload[4]).is_none() || count == 0 {
            return;
        }
        let key = (
            event_window::unsigned(&event["session_id"]).unwrap_or(0),
            event["initiator_process_id"].as_u64().unwrap_or(0),
            payload[4],
        );
        let newest = self.0.entry(key).or_default();
        *newest = (*newest).max(count);
    }
    fn totals(&self) -> BTreeMap<u8, u64> {
        let mut totals = BTreeMap::new();
        for ((_, _, class), count) in &self.0 {
            let total: &mut u64 = totals.entry(*class).or_default();
            *total = total.saturating_add(*count);
        }
        totals
    }
}

fn exclusion_class(code: u8) -> Option<(&'static str, &'static str)> {
    Some(match code {
        16 => ("chrome", "requests"),
        17 => ("chrome_untrusted", "requests"),
        18 => ("brave", "requests"),
        19 => ("devtools", "requests"),
        20 => ("chrome_search", "requests"),
        64 => ("webui_renderer", "renderer_processes"),
        65 => ("extension_worker", "requests"),
        66 => ("devtools_load", "requests"),
        67 => ("webui_request", "requests"),
        68 => ("service_worker_no_page", "requests"),
        69 => ("browser_prefetch", "requests"),
        70 => ("memory_cache_reuse", "reuses"),
        71 => ("non_ordinary_page_reuse", "reuses"),
        _ => return None,
    })
}

fn check(code: &str, severity: &str, message: impl Into<String>) -> Value {
    json!({"code": code, "severity": severity, "message": message.into()})
}

/// Plain-language meaning of a producer gap reason, from its shape. The reason
/// itself stays in the check, so an unfamiliar one is never hidden.
fn gap_meaning(reason: &str) -> &'static str {
    if reason == "service_worker_page_decision_unshared" {
        "A service-worker request's class 68 answer was evicted before its other half asked, so that half decided alone: the request may have one half recorded without the other, as a row without a tab, or one half left out. The count is the evicted answers (protocol/native-network-v3.md)."
    } else if reason.contains("filtered") {
        "A sample policy excluded these observations before a sample slot was taken. Retained observations are unchanged."
    } else if reason.contains("limit_or_invalid") || reason.contains("module_invalid") {
        "The record was malformed or outside a structural bound, so it was refused before a sample slot was taken."
    } else if reason.contains("budget") || reason.contains("limit") || reason.contains("capped") {
        "A sampling budget or limit was reached, so later occurrences were not sampled. Sample fewer sites, or start a new session for a fresh budget."
    } else if reason.contains("unavailable") || reason.contains("lost") {
        "A capture stage was unavailable, so these observations were not recorded."
    } else if reason.contains("unresolved")
        || reason.contains("mismatch")
        || reason.contains("omitted")
        || reason.contains("unbound")
    {
        "Linkage for these observations could not be established, so they are recorded without it."
    } else if reason.contains("unsupported") || reason.contains("left_liftoff") {
        "This execution was outside document Liftoff code, so it was named and not sampled."
    } else {
        "The capture refused or dropped these observations for this reason."
    }
}

pub fn build(store: &Path, artifacts: &Path, state: &CaptureState<'_>) -> Result<Value> {
    let mut events = EventCounts::default();
    let mut exclusions = Exclusions::default();
    let mut request_tabs = RequestTabs::default();
    let mut refusals = Refusals::default();
    let mut header_coverage = HeaderCoverage::default();
    let mut tally = Tally::default();
    let event_page = event_query::read_page(
        store,
        Cursor::Tail,
        usize::MAX,
        SCAN_BYTES,
        EVENT_RECORD_BYTES,
        |line| {
            let event: Value =
                serde_json::from_slice(line).map_err(|_| event_window::malformed())?;
            validate_event(&event)?;
            tally.record(&event)?;
            events.record(&event);
            exclusions.record(&event);
            request_tabs.record(&event);
            refusals.record(&event);
            header_coverage.record(&event);
            Ok(None)
        },
    )?;
    let mut stored = ArtifactCounts::default();
    let mut seen = HashSet::new();
    let artifact_page = event_query::read_page(
        &artifacts.join("manifest.jsonl"),
        Cursor::Tail,
        usize::MAX,
        SCAN_BYTES,
        MANIFEST_RECORD_BYTES,
        artifact_query::visitor(&mut seen, |artifact| {
            stored.record(artifact);
            false
        }),
    )?;
    let mut checks = Vec::new();
    let live = state.capture_mode == "live";
    if !live {
        checks.push(check(
            "capture_not_live",
            "info",
            format!(
                "This backend is not a live capture (capture_mode={}). It reports stored evidence only.",
                state.capture_mode
            ),
        ));
    } else if state.capture_stopped {
        checks.push(check(
            "capture_stopped",
            "info",
            "Native capture was stopped; no new events will arrive in this session.",
        ));
    } else if !state.broker_connected {
        checks.push(check(
            "broker_disconnected",
            "warning",
            "The native capture broker is not connected; no new events will arrive.",
        ));
    }
    if state.artifact_receiver_configured && !state.artifact_receiver_connected && live {
        checks.push(check(
            "artifact_receiver_disconnected",
            "warning",
            "The artifact receiver is not connected; new scripts and Wasm modules are not being stored.",
        ));
    }
    if events.total == 0 {
        checks.push(check(
            "no_events",
            "warning",
            "No events are stored yet. Open a page in the capture browser, then wait for events.",
        ));
    }
    let compiled = events.count("module_compiled");
    if compiled > 0 && !stored.by_kind.contains_key("wasm") {
        checks.push(check(
            "wasm_without_artifacts",
            "warning",
            format!(
                "{compiled} Wasm module_compiled events but no stored Wasm artifact. Check the artifact receiver and that the capture category mask includes Artifact (1024)."
            ),
        ));
    }
    for (reason, count) in &refusals.failures {
        let mut item = check(
            "artifact_capture_failed",
            "warning",
            format!("{count} artifact captures failed ({reason}); those bytes are not stored."),
        );
        item["reason"] = json!(reason);
        item["count"] = json!(count.to_string());
        checks.push(item);
    }
    for ((category, reason), count) in &refusals.content {
        let mut item = check(
            "request_content_not_retained",
            "warning",
            content_meaning(category, reason, *count),
        );
        item["category"] = json!(category);
        item["reason"] = json!(reason);
        item["count"] = json!(count.to_string());
        checks.push(item);
    }
    let blocks: u64 = header_coverage.unattributed_blocks.values().sum();
    let lists: u64 = header_coverage.unattributed_lists.values().sum();
    if blocks > 0 || lists > 0 {
        let mut item = check(
            "network_headers_unattributed",
            "warning",
            format!(
                "{blocks} network header blocks and {lists} cookie lists arrived for requests the capture no longer tracked (ended, or past 4,096 in flight), so they are on no row."
            ),
        );
        item["blocks"] = json!(blocks.to_string());
        item["lists"] = json!(lists.to_string());
        checks.push(item);
    }
    for (reason, count) in header_coverage.missing() {
        checks.push(missing_check(reason, count));
    }
    if header_coverage.untracked > 0 {
        let mut item = check(
            "final_headers_untracked",
            "info",
            format!(
                "{} header records belong to requests past the {HEADER_REQUESTS} this summary follows, so whether those requests have final headers is not counted.",
                header_coverage.untracked
            ),
        );
        item["count"] = json!(header_coverage.untracked.to_string());
        checks.push(item);
    }
    let (drops, _) = tally.queue_drops();
    let named: u64 = tally.named_gaps().iter().map(|gap| gap.count).sum();
    if drops > named {
        checks.push(check(
            "queue_drops",
            "warning",
            format!(
                "{} events were dropped by a full queue and are missing from this store.",
                drops - named
            ),
        ));
    }
    let (holes, _) = tally.sequence_gaps();
    if holes > 0 {
        checks.push(check(
            "sequence_gaps",
            "warning",
            format!("{holes} sequence numbers are absent inside the scanned events."),
        ));
    }
    for gap in tally.named_gaps() {
        let mut item = check("named_gap", "warning", gap_meaning(&gap.reason));
        item["category"] = json!(gap.category);
        item["reason"] = json!(gap.reason);
        item["count"] = json!(gap.count.to_string());
        checks.push(item);
    }
    // A context with no parent document (a shared storage worklet) is not
    // linked by design, so it is a warning; every other reason is a capture bug.
    let mut reasons = request_tabs.unresolved_reasons();
    let no_document = reasons.remove("no_document").unwrap_or(0);
    let unresolved: u64 = reasons.values().sum();
    if unresolved > 0 {
        let reasons = reasons
            .iter()
            .map(|(reason, count)| format!("{reason} {count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut item = check(
            "network_tab_unresolved",
            "error",
            format!(
                "{unresolved} requests have no tab ({reasons}). This is a capture bug, not a property of the page; request_tabs lists them by process and request id, with their reason, for get_events."
            ),
        );
        item["count"] = json!(unresolved.to_string());
        checks.insert(0, item);
    }
    if no_document > 0 {
        let mut item = check(
            "network_tab_no_document",
            "warning",
            format!(
                "{no_document} requests come from a context with no parent document, a shared storage worklet, which the renderer cannot name a tab for. The capture does not link them; request_tabs lists them with reason no_document."
            ),
        );
        item["count"] = json!(no_document.to_string());
        checks.push(item);
    }
    let excluded = exclusions.totals();
    let no_tab: u64 = [65, 66, 68, 69]
        .iter()
        .filter_map(|class| excluded.get(class))
        .fold(0, |sum, count| sum.saturating_add(*count));
    if no_tab > 0 {
        let count = |class: u8| excluded.get(&class).copied().unwrap_or(0);
        let mut item = check(
            "no_tab_traffic_excluded",
            "info",
            format!(
                "{no_tab} requests no tab caused were not recorded (extension workers {}, DevTools loads {}, service workers no page used {}, browser prefetches with no page {}). These are named exclusions, not gaps.",
                count(65),
                count(66),
                count(68),
                count(69)
            ),
        );
        item["count"] = json!(no_tab.to_string());
        checks.push(item);
    }
    if let Some(&reuses) = excluded.get(&70) {
        let mut item = check(
            "memory_cache_reuse_not_recorded",
            "info",
            format!(
                "{reuses} memory-cache reuses were counted, not recorded: each renderer records at most 4,096 per capture configuration. This is a named exclusion, not a gap. Reuses in pages that are not ordinary (an SVG image's own document or a page popup), which no tab owns, are counted apart as non_ordinary_page_reuse."
            ),
        );
        item["count"] = json!(reuses.to_string());
        checks.push(item);
    }
    // Internal-scheme loads and the requests WebUI renderers sent through the proxy.
    let internal_request = |class: u8| class < 64 || class == 67;
    let requests: u64 = excluded
        .iter()
        .filter(|(class, _)| internal_request(**class))
        .fold(0, |sum, (_, count)| sum.saturating_add(*count));
    let renderers = excluded.get(&64).copied().unwrap_or(0);
    if requests > 0 || renderers > 0 {
        let by_class = excluded
            .iter()
            .filter(|(class, _)| internal_request(**class))
            .map(|(class, count)| format!("{} {count}", exclusion_class(*class).unwrap().0))
            .collect::<Vec<_>>()
            .join(", ");
        let mut parts = Vec::new();
        if requests > 0 {
            parts.push(format!(
                "{requests} browser-internal requests were not recorded ({by_class})"
            ));
        }
        if renderers > 0 {
            parts.push(format!(
                "{renderers} WebUI renderer processes were not admitted"
            ));
        }
        let mut item = check(
            "browser_internal_excluded",
            "info",
            format!(
                "{}. These are named exclusions, not gaps; set REB_CAPTURE_BROWSER_INTERNAL=1 to record them.",
                parts.join("; ")
            ),
        );
        item["count"] = json!(requests.to_string());
        checks.push(item);
    }
    if event_page.exhausted {
        checks.push(check(
            "bounded_scope",
            "info",
            "Only the newest 64 MiB of events were summarized. Page older events with get_events before.",
        ));
    }
    Ok(json!({
        "protocol_version": 1,
        "instance_id": state.instance_id,
        "capture_mode": state.capture_mode,
        "live_admission": session_context::live_admission(state.capture_mode, state.broker_connected),
        "broker_connected": state.broker_connected,
        "capture_stopped": state.capture_stopped,
        "artifact_receiver_configured": state.artifact_receiver_configured,
        "artifact_receiver_connected": state.artifact_receiver_connected,
        "events": events.document(&event_page, &tally),
        "request_tabs": request_tabs.document(),
        "exclusions": excluded.iter().map(|(class, count)| {
            let (name, unit) = exclusion_class(*class).unwrap();
            json!({"class": name, "unit": unit, "count": count.to_string()})
        }).collect::<Vec<_>>(),
        "artifacts": {
            "scope": artifact_page.scope(),
            "budget_exhausted": artifact_page.exhausted,
            "total": stored.total.to_string(),
            "by_kind": stored.by_kind.iter().map(|(kind, count)| (kind.clone(), json!(count.to_string()))).collect::<serde_json::Map<_, _>>(),
            "items": stored.items,
            "items_omitted": stored.total.saturating_sub(stored.items.len() as u64).to_string(),
        },
        "checks": checks,
    }))
}

/// What each request's response body case of the request index means
/// (protocol/native-network-v3.md "Bodies the proxy never sees").
fn body_case_meaning(case: &str) -> &'static str {
    match case {
        "captured" => "retained in full",
        "captured_truncated" => "retained up to the 16 MiB capture limit",
        "partial" => "still arriving; the newest snapshot is retained",
        "aborted" => "the network failed mid-body; what arrived is retained",
        "cancelled" => "the page or browser stopped reading; what arrived is retained",
        "empty" => "the body had no bytes",
        "not_modified" => "HTTP 304: the server sent no body",
        "redirected" => {
            "redirected, then ended with no other response; Chromium discards redirect bodies"
        }
        "not_captured_type" => {
            "images, audio, video or fonts that page elements load, kept only with REB_CAPTURE_RESPONSE_MEDIA=1"
        }
        "not_captured_artifact_unavailable" => {
            "no artifact channel: the Artifact category was off or the receiver was disconnected"
        }
        "not_captured_transfer_refused" => {
            "refused by the bounded in-flight memory pool or artifact queue"
        }
        "not_captured_session_budget" => "arrived after the response body budget was used",
        "malformed" => "the response body record is malformed",
        "source_artifact" => "a script or Wasm response, retained as a source artifact",
        "no_record" => {
            "the browser saw a response but no body record is indexed: not a content capture session, or still arriving"
        }
        "memory_cache" => "reused from Blink's memory cache: no request was made",
        "service_worker" => {
            "answered by a service worker in the renderer, which the browser proxy never sees"
        }
        "failed_before_response" => "failed before any response",
        "cancelled_before_response" => "cancelled before any response",
        "interrupted" => "observation ended before the outcome was known",
        "end_lost" => {
            "a service worker ended it, but its start slot was reused, so its outcome was not recorded"
        }
        "pending" => "no response or end yet",
        "renderer_answered" => {
            "answered in the renderer without a URL loader (data:, blob: and other local schemes)"
        }
        _ => "ended with no response record",
    }
}

/// The summary's ETag key: capture state, artifact manifest and the request
/// index's progress, since the body case counts change as the index reads an
/// unchanged store.
pub fn etag_key(state: &str, manifest: &str, progress: &str) -> String {
    format!("summary:{state}:{manifest}:index:{progress}")
}

/// Every request's response body case, counted from the request index's rows,
/// and a check naming the bodies the browser proxy can never see. An index
/// that cannot answer leaves the counts unavailable, with its reason.
pub fn add_response_bodies(summary: &mut Value, counts: std::result::Result<Value, String>) {
    let counts = match counts {
        Ok(counts) => counts,
        Err(reason) => {
            summary["response_bodies"] = json!({"available": false, "reason": reason,
                "complete": false, "requests": "0", "unindexed_records": "0",
                "snapshots_withheld": "0", "cases": []});
            return;
        }
    };
    let count = |case: &str| {
        counts["cases"][case]
            .as_str()
            .and_then(|count| count.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let cases = counts["cases"]
        .as_object()
        .map(|cases| {
            cases
                .iter()
                .map(|(case, value)| json!({"case": case, "count": value, "meaning": body_case_meaning(case)}))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let (worker, reused, local) = (
        count("service_worker"),
        count("memory_cache"),
        count("renderer_answered"),
    );
    summary["response_bodies"] = json!({
        "available": true, "reason": null,
        "complete": counts["complete"], "requests": counts["requests"],
        "unindexed_records": counts["unindexed_records"],
        "snapshots_withheld": counts["snapshots_withheld"].as_str().unwrap_or("0"), "cases": cases,
    });
    let withheld = counts["snapshots_withheld"]
        .as_str()
        .and_then(|count| count.parse::<u64>().ok())
        .unwrap_or(0);
    if withheld > 0 {
        let mut item = check(
            "response_snapshots_withheld",
            "info",
            format!(
                "{withheld} response bodies had a snapshot withheld while they arrived: their own snapshot allowance, the session's snapshot quarter of the response body budget, or the budget was used, so their newest snapshot is older than the schedule would make it. Raise REB_RESPONSE_BODY_BUDGET_MIB for a new session."
            ),
        );
        item["count"] = json!(withheld.to_string());
        if let Some(checks) = summary["checks"].as_array_mut() {
            checks.push(item);
        }
    }
    if worker + reused + local > 0 {
        let mut item = check(
            "response_bodies_not_observed",
            "info",
            format!(
                "{} responses never reached the browser proxy, so their bodies are not retained under their own request: {worker} served by a service worker, {reused} reused from the memory cache and {local} answered in the renderer. Traffic links a reuse to the request whose response it reused, and a service worker answer to the worker's own fetch of the same URL, when those were retained.",
                worker + reused + local
            ),
        );
        item["count"] = json!((worker + reused + local).to_string());
        if let Some(checks) = summary["checks"].as_array_mut() {
            checks.push(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_body_cases_are_counted_with_their_meaning() {
        let mut summary = json!({"checks": []});
        add_response_bodies(
            &mut summary,
            Ok(
                json!({"complete": true, "requests": "6", "unindexed_records": "0", "snapshots_withheld": "3",
                "cases": {"captured": "2", "memory_cache": "1", "service_worker": "2", "renderer_answered": "1"}}),
            ),
        );
        assert_eq!(summary["response_bodies"]["available"], true);
        assert_eq!(summary["response_bodies"]["snapshots_withheld"], "3");
        let withheld = summary["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["code"] == "response_snapshots_withheld")
            .unwrap();
        assert_eq!(withheld["count"], "3");
        let cases = summary["response_bodies"]["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 4);
        let worker = cases
            .iter()
            .find(|case| case["case"] == "service_worker")
            .unwrap();
        assert_eq!(worker["count"], "2");
        assert!(worker["meaning"].as_str().unwrap().contains("never sees"));
        let check = summary["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["code"] == "response_bodies_not_observed")
            .unwrap();
        assert_eq!(check["count"], "4");
        assert!(
            check["message"]
                .as_str()
                .unwrap()
                .contains("2 served by a service worker, 1 reused")
        );
        assert!(
            check["message"]
                .as_str()
                .unwrap()
                .starts_with("4 responses never reached")
        );
        let mut quiet = json!({"checks": []});
        add_response_bodies(
            &mut quiet,
            Ok(
                json!({"complete": true, "requests": "2", "unindexed_records": "0", "cases": {"captured": "2"}}),
            ),
        );
        assert!(quiet["checks"].as_array().unwrap().is_empty());
        // An index that cannot answer leaves the counts unavailable, never the summary.
        let mut failed = json!({"checks": []});
        add_response_bodies(&mut failed, Err("The request index is unreadable".into()));
        assert_eq!(failed["response_bodies"]["available"], false);
        assert_eq!(
            failed["response_bodies"]["reason"],
            "The request index is unreadable"
        );
        assert_eq!(failed["response_bodies"]["cases"], json!([]));
        // The tag changes as the index reads an unchanged store.
        assert_ne!(
            etag_key("live", "m1", "4096"),
            etag_key("live", "m1", "caught-up")
        );
    }

    #[test]
    fn filtered_wasm_gap_is_a_policy_exclusion() {
        let filtered = gap_meaning("native_wasm_dispatch_browser_filtered");
        assert!(filtered.contains("excluded"));
        assert!(!filtered.contains("sampling budget"));
        assert!(gap_meaning("native_wasm_dispatch_function_budget_incomplete").contains("budget"));
        let malformed = gap_meaning("native_wasm_dispatch_limit_or_invalid");
        assert!(malformed.contains("malformed"));
        assert!(!malformed.contains("sampling budget"));
        assert!(gap_meaning("native_guest_sample_limit").contains("budget"));
    }

    fn event(sequence: u64, category: &str, kind: &str, frame: u64, payload: &str) -> Value {
        json!({"protocol_version":3,"session_id":"9","sequence_number":sequence.to_string(),
            "monotonic_time_ns":(sequence * 10).to_string(),"navigation_id":"2",
            "frame_id":frame.to_string(),"artifact_id":"0","request_id":"0","process_id":7,
            "tab_id":4,"category":category,"type":kind,"payload_encoding":"hex",
            "payload":hex::encode(payload),"payload_size":payload.len()})
    }

    #[test]
    fn summary_counts_frames_gaps_and_names_what_went_wrong() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let mut lines = Vec::new();
        for (sequence, category, kind, frame, payload) in [
            (1, "wasm", "module_compiled", 5, ""),
            (2, "vm", "wasm_dispatch_observation", 5, ""),
            (3, "vm", "wasm_dispatch_observation", 5, ""),
            (5, "vm", "gap", 5, "native_wasm_dispatch_budget_incomplete"),
            (6, "canvas", "api_call", 6, ""),
        ] {
            lines.push(event(sequence, category, kind, frame, payload).to_string());
        }
        std::fs::write(&store, lines.join("\n") + "\n").unwrap();
        let state = CaptureState {
            instance_id: "1:2",
            capture_mode: "live",
            broker_connected: true,
            capture_stopped: false,
            artifact_receiver_configured: true,
            artifact_receiver_connected: true,
        };
        let summary = build(&store, &artifacts, &state).unwrap();
        let events = &summary["events"];
        assert_eq!(events["total"], "5");
        assert_eq!(events["by_type"][0]["type"], "wasm_dispatch_observation");
        assert_eq!(events["by_type"][0]["count"], "2");
        assert_eq!(events["frames"][0]["frame_id"], "5");
        assert_eq!(events["frames"][0]["count"], "4");
        assert_eq!(events["frames"][0]["tab_id"], 4);
        assert_eq!(events["sequence_gaps"], "1");
        assert_eq!(summary["live_admission"], "ready");
        let codes = summary["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| check["code"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec!["wasm_without_artifacts", "sequence_gaps", "named_gap"]
        );
        let gap = &summary["checks"][2];
        assert_eq!(gap["reason"], "native_wasm_dispatch_budget_incomplete");
        assert!(gap["message"].as_str().unwrap().contains("budget"));
        assert_eq!(summary["artifacts"]["total"], "0");
        let text = summary.to_string();
        assert!(!text.contains(&hex::encode("native_wasm")));
    }

    /// A `request_headers` (or `response_headers`) record of request 17 + n.
    fn header(
        sequence: u64,
        parent: u64,
        request: u64,
        response: bool,
        source: u8,
        state: u8,
        hop: u32,
        unattributed: u32,
    ) -> Value {
        let mut payload = vec![0u8; 128];
        payload[0] = 1;
        payload[2] = 128;
        payload[4] = source;
        payload[5] = state;
        payload[6] = if !response && source == 1 { 4 } else { 0 };
        let (count, length): (u32, u32) = match state {
            3 => (0, 0),
            4 => (1, 400 * 1024),
            _ => (1, 10),
        };
        payload[8..12].copy_from_slice(&count.to_le_bytes());
        payload[12..16].copy_from_slice(&length.to_le_bytes());
        payload[16..20].copy_from_slice(&hop.to_le_bytes());
        if response {
            payload[20..22].copy_from_slice(&200u16.to_le_bytes());
        }
        payload[40..44].copy_from_slice(&unattributed.to_le_bytes());
        if state != 4 {
            payload[48..80].fill(0x5a);
        }
        let kind = if response {
            "response_headers"
        } else {
            "request_headers"
        };
        let mut event = lifecycle(sequence, kind, request);
        event["payload"] = json!(hex::encode(&payload));
        event["payload_size"] = json!(128);
        event["parent_event_id"] = json!(parent.to_string());
        event["artifact_id"] = json!("0");
        event["status_code"] = json!(0);
        event
    }

    /// A browser lifecycle record of `request`.
    fn lifecycle(sequence: u64, kind: &str, request: u64) -> Value {
        let mut event = event(sequence, "network", kind, 3, "");
        event["request_id"] = json!(request.to_string());
        event["process_id"] = json!(1);
        event["navigation_id"] = json!("0");
        event["browser_context_id_high"] = json!("5");
        event["browser_context_id_low"] = json!("6");
        for key in [
            "parent_event_id",
            "encoded_data_length",
            "decoded_body_length",
        ] {
            event[key] = json!("0");
        }
        for key in ["status_code", "error_code", "resource_type", "flags"] {
            event[key] = json!(0);
        }
        event["payload_truncated"] = json!(false);
        event
    }

    #[test]
    fn untracked_final_blocks_are_counted_only_for_header_records() {
        let summarize = |events: Vec<Value>| {
            let root = tempfile::tempdir().unwrap();
            let store = root.path().join("events.jsonl");
            let artifacts = root.path().join("artifacts");
            std::fs::create_dir_all(&artifacts).unwrap();
            let lines: Vec<String> = events.iter().map(Value::to_string).collect();
            std::fs::write(&store, lines.join("\n") + "\n").unwrap();
            let state = CaptureState {
                instance_id: "1:2",
                capture_mode: "live",
                broker_connected: true,
                capture_stopped: false,
                artifact_receiver_configured: false,
                artifact_receiver_connected: false,
            };
            build(&store, &artifacts, &state).unwrap()["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|check| check["code"] == "final_headers_untracked")
                .cloned()
                .collect::<Vec<_>>()
        };
        // A metadata-only session past the bound has no final block to miss.
        let mut sequence = 0;
        let mut metadata = Vec::new();
        for request in 1..=HEADER_REQUESTS as u64 + 4 {
            for kind in ["request_started", "response_started", "request_completed"] {
                sequence += 1;
                metadata.push(lifecycle(sequence, kind, request));
            }
        }
        assert_eq!(summarize(metadata), Vec::<Value>::new());
        // A content session's header records past it are counted.
        let mut content = Vec::new();
        let mut sequence = 0;
        for request in 1..=HEADER_REQUESTS as u64 + 4 {
            sequence += 1;
            let start = sequence;
            content.push(lifecycle(start, "request_started", request));
            sequence += 1;
            content.push(header(sequence, start, request, false, 1, 3, 0, 0));
        }
        let untracked = summarize(content);
        assert_eq!(untracked.len(), 1);
        assert_eq!(untracked[0]["count"], "4");
    }

    #[test]
    fn header_refusals_and_missing_final_blocks_are_counted_with_reasons() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let mut sequence = 0;
        let mut next = || {
            sequence += 1;
            sequence
        };
        let mut events = Vec::new();
        // One request per case: request 1 has its final block; 2 came from the
        // cache; 3 failed before sending; 4 is a download; 5 is still open; 6
        // was answered without a block nobody explains; 7 redirected, and only
        // its first hop has a network block.
        for request in 1..=7u64 {
            let start = next();
            let mut started = lifecycle(start, "request_started", request);
            if request == 4 {
                started["loader_kind"] = json!(2);
            }
            events.push(started);
            events.push(header(next(), start, request, false, 1, 3, 0, 0));
            if matches!(request, 1 | 7) {
                events.push(header(next(), start, request, false, 2, 3, 0, 0));
            }
            if request == 7 {
                let redirect = next();
                events.push(lifecycle(redirect, "request_redirected", request));
                events.push(header(next(), redirect, request, false, 1, 3, 1, 0));
            }
            if request == 3 {
                events.push(lifecycle(next(), "request_failed", request));
                continue;
            }
            if request == 5 {
                continue;
            }
            let mut response = lifecycle(next(), "response_started", request);
            if request == 2 {
                response["flags"] = json!(2);
            }
            events.push(response);
            events.push(lifecycle(next(), "request_completed", request));
        }
        // Blocks and lists not retained, with their reasons, and late blocks.
        let start = next();
        events.push(lifecycle(start, "request_started", 8));
        events.push(header(next(), start, 8, false, 1, 7, 0, 2));
        events.push(header(next(), start, 8, true, 1, 4, 0, 3));
        let mut list = vec![0u8; 128];
        list[0] = 1;
        list[2] = 128;
        list[4] = 1;
        list[5] = 6;
        list[8] = 1;
        list[16] = 80;
        list[24] = 4;
        list[32..64].fill(0x5a);
        let mut cookie = lifecycle(next(), "cookie_list", 8);
        cookie["payload"] = json!(hex::encode(&list));
        cookie["payload_size"] = json!(128);
        cookie["parent_event_id"] = json!(start.to_string());
        cookie["artifact_id"] = json!("0");
        events.push(cookie);
        let lines: Vec<String> = events.iter().map(Value::to_string).collect();
        std::fs::write(&store, lines.join("\n") + "\n").unwrap();
        let state = CaptureState {
            instance_id: "1:2",
            capture_mode: "live",
            broker_connected: true,
            capture_stopped: false,
            artifact_receiver_configured: false,
            artifact_receiver_connected: false,
        };
        let summary = build(&store, &artifacts, &state).unwrap();
        let checks = summary["checks"].as_array().unwrap();
        let find = |code: &str| {
            checks
                .iter()
                .filter(|check| check["code"] == code)
                .map(|check| {
                    (
                        check["reason"].as_str().unwrap_or("").to_owned(),
                        check.clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let missing = find("final_headers_missing");
        assert_eq!(
            missing.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["download", "failed", "from_cache", "not_reported"]
        );
        for reason in ["download", "failed", "from_cache"] {
            assert_eq!(missing[reason]["count"], "1");
            assert_eq!(missing[reason]["severity"], "info");
        }
        // Request 6 and request 7's final hop: the gaps nobody explains.
        assert_eq!(missing["not_reported"]["count"], "2");
        assert_eq!(missing["not_reported"]["severity"], "warning");
        assert!(
            missing["from_cache"]["message"]
                .as_str()
                .unwrap()
                .contains("HTTP cache")
        );
        let refused = checks
            .iter()
            .filter(|check| check["code"] == "request_content_not_retained")
            .map(|check| {
                (
                    check["category"].as_str().unwrap().to_owned(),
                    check["reason"].as_str().unwrap().to_owned(),
                    check["count"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            refused,
            vec![
                (
                    "cookie_list".into(),
                    "not_captured_transfer_refused".into(),
                    "1".into()
                ),
                (
                    "request_headers".into(),
                    "not_captured_session_budget".into(),
                    "1".into()
                ),
                (
                    "response_headers".into(),
                    "not_captured_block_limit".into(),
                    "1".into()
                ),
            ]
        );
        let late = &find("network_headers_unattributed")[""];
        assert_eq!(late["blocks"], "3");
        assert_eq!(late["lists"], "4");
        assert!(find("final_headers_untracked").is_empty());
    }

    #[test]
    fn scope_gaps_are_named_incompleteness_not_drops() {
        for reason in [
            "native_wasm_dispatch_worker_unsupported",
            "native_wasm_dispatch_worklet_unsupported",
            "native_wasm_indirect_jitless_unsupported",
            "native_wasm_dispatch_left_liftoff",
        ] {
            let meaning = gap_meaning(reason);
            assert!(meaning.contains("not sampled"), "{reason}: {meaning}");
            assert!(!meaning.contains("dropped"), "{reason}: {meaning}");
        }
        assert!(gap_meaning("native_wasm_dispatch_budget_incomplete").contains("budget"));
    }

    #[test]
    fn unshared_service_worker_decisions_have_their_own_meaning() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let lines = [1, 2].map(|sequence| {
            event(
                sequence,
                "network",
                "gap",
                0,
                "service_worker_page_decision_unshared",
            )
            .to_string()
        });
        std::fs::write(&store, lines.join("\n") + "\n").unwrap();
        let state = CaptureState {
            instance_id: "1:2",
            capture_mode: "live",
            broker_connected: true,
            capture_stopped: false,
            artifact_receiver_configured: false,
            artifact_receiver_connected: false,
        };
        let summary = build(&store, &artifacts, &state).unwrap();
        let gap = summary["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["code"] == "named_gap")
            .unwrap();
        assert_eq!(gap["reason"], "service_worker_page_decision_unshared");
        assert_eq!(gap["count"], "2");
        let message = gap["message"].as_str().unwrap();
        assert!(
            message.contains("evicted") && !message.contains("refused or dropped"),
            "{message}"
        );
    }

    fn exclusion(sequence: u64, producer: u32, class: u8, count: u64) -> Value {
        let mut payload = vec![1, 0, 16, 0, class, 0, 0, 0];
        payload.extend(count.to_le_bytes());
        let mut event = event(sequence, "network", "capture_exclusion", 0, "");
        event["payload"] = json!(hex::encode(&payload));
        event["payload_size"] = json!(16);
        event["initiator_process_id"] = json!(producer);
        event["frame_id"] = json!("0");
        event["tab_id"] = json!(0);
        event
    }

    #[test]
    fn browser_internal_exclusions_are_named_counts_not_gaps() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let mut lines = [
            exclusion(1, 40, 16, 3),
            exclusion(2, 40, 16, 5),
            exclusion(3, 41, 16, 2),
            exclusion(4, 41, 19, 1),
            exclusion(5, 0, 64, 1),
            exclusion(6, 0, 64, 2),
            exclusion(8, 41, 65, 2),
            exclusion(9, 0, 66, 1),
            exclusion(11, 0, 67, 3),
            exclusion(12, 41, 70, 4),
            exclusion(13, 41, 70, 9),
            exclusion(14, 41, 71, 2),
            exclusion(15, 41, 68, 2),
            exclusion(16, 0, 68, 1),
            exclusion(17, 0, 69, 4),
        ]
        .map(|event| event.to_string())
        .to_vec();
        let mut orphan = event(10, "network", "request_started", 0, "GET example.test");
        orphan["tab_id"] = json!(0);
        orphan["request_id"] = json!("77");
        orphan["browser_context_id_high"] = json!("3");
        orphan["browser_context_id_low"] = json!("4");
        lines.push(orphan.to_string());
        // A shared storage worklet's fetch: unresolved by design, a warning.
        let mut worklet = event(1, "network", "request_initiated", 0, "GET example.test");
        worklet["process_id"] = json!(31);
        worklet["request_id"] = json!("5");
        worklet["frame_id"] = json!("9");
        worklet["loader_kind"] = json!(20);
        worklet["tab_id"] = json!(0);
        lines.push(worklet.to_string());
        let mut dirty = exclusion(7, 42, 16, 9);
        let mut bytes = hex::decode(dirty["payload"].as_str().unwrap()).unwrap();
        bytes[5] = 1;
        dirty["payload"] = json!(hex::encode(bytes));
        lines.push(dirty.to_string());
        std::fs::write(&store, lines.join("\n") + "\n").unwrap();
        let state = CaptureState {
            instance_id: "1:2",
            capture_mode: "live",
            broker_connected: true,
            capture_stopped: false,
            artifact_receiver_configured: false,
            artifact_receiver_connected: false,
        };
        let summary = build(&store, &artifacts, &state).unwrap();
        assert_eq!(
            summary["exclusions"],
            json!([
                {"class": "chrome", "unit": "requests", "count": "7"},
                {"class": "devtools", "unit": "requests", "count": "1"},
                {"class": "webui_renderer", "unit": "renderer_processes", "count": "2"},
                {"class": "extension_worker", "unit": "requests", "count": "2"},
                {"class": "devtools_load", "unit": "requests", "count": "1"},
                {"class": "webui_request", "unit": "requests", "count": "3"},
                {"class": "service_worker_no_page", "unit": "requests", "count": "3"},
                {"class": "browser_prefetch", "unit": "requests", "count": "4"},
                {"class": "memory_cache_reuse", "unit": "reuses", "count": "9"},
                {"class": "non_ordinary_page_reuse", "unit": "reuses", "count": "2"},
            ])
        );
        let reuses = summary["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["code"] == "memory_cache_reuse_not_recorded")
            .unwrap();
        assert_eq!(reuses["severity"], "info");
        // Reuses in pages no tab owns are not the budget's overflow.
        assert_eq!(reuses["count"], "9");
        let checks = summary["checks"].as_array().unwrap();
        assert_eq!(checks[0]["code"], "network_tab_unresolved");
        assert_eq!(checks[0]["severity"], "error");
        assert_eq!(
            summary["request_tabs"]["unresolved_requests"],
            json!([
                {"process_id": 31, "request_id": "5", "reason": "no_document"},
                {"process_id": 7, "request_id": "77", "reason": "no_loader_kind"}
            ])
        );
        assert!(
            checks[0]["message"]
                .as_str()
                .unwrap()
                .starts_with("1 requests have no tab (no_loader_kind 1).")
        );
        assert_eq!(checks[0]["count"], "1");
        let no_document = checks
            .iter()
            .find(|check| check["code"] == "network_tab_no_document")
            .unwrap();
        assert_eq!(
            (
                no_document["severity"].as_str(),
                no_document["count"].as_str()
            ),
            (Some("warning"), Some("1"))
        );
        assert_eq!(
            summary["request_tabs"]["unresolved_reasons"],
            json!({"no_document": "1", "no_loader_kind": "1"})
        );
        let no_tab = checks
            .iter()
            .find(|check| check["code"] == "no_tab_traffic_excluded")
            .unwrap();
        assert_eq!(no_tab["count"], "10");
        assert!(no_tab["message"].as_str().unwrap().contains(
            "(extension workers 2, DevTools loads 1, service workers no page used 3, browser prefetches with no page 4)"
        ));
        assert_eq!(summary["events"]["sequence_gaps"], "0");
        let checks = summary["checks"].as_array().unwrap();
        assert!(checks.iter().all(|check| check["code"] != "named_gap"));
        let excluded = checks
            .iter()
            .find(|check| check["code"] == "browser_internal_excluded")
            .unwrap();
        assert_eq!(excluded["severity"], "info");
        assert_eq!(excluded["count"], "11");
        let message = excluded["message"].as_str().unwrap();
        assert!(message.contains(
            "11 browser-internal requests were not recorded (chrome 7, devtools 1, webui_request 3)"
        ));
        assert!(message.contains("2 WebUI renderer processes were not admitted"));
    }

    #[test]
    fn an_empty_idle_store_explains_itself() {
        let root = tempfile::tempdir().unwrap();
        let state = CaptureState {
            instance_id: "1:2",
            capture_mode: "idle",
            broker_connected: false,
            capture_stopped: false,
            artifact_receiver_configured: false,
            artifact_receiver_connected: false,
        };
        let summary = build(
            &root.path().join("events.jsonl"),
            &root.path().join("artifacts"),
            &state,
        )
        .unwrap();
        assert_eq!(summary["events"]["total"], "0");
        assert_eq!(summary["events"]["scope"], "store");
        assert_eq!(summary["checks"][0]["code"], "capture_not_live");
        assert_eq!(summary["checks"][1]["code"], "no_events");
    }
}
