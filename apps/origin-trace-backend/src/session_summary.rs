//! One bounded read that answers "did this capture work?": event counts by
//! type and frame, artifact digests, gap reasons and capture state, with a
//! short list of checks that name what looks wrong. It is counts, identifiers
//! and origin labels only; it never includes payloads, source or bodies.
use crate::{
    app::validate_event,
    artifact_query::{self, MANIFEST_RECORD_BYTES},
    error::Result,
    event_query::{self, Cursor, EVENT_RECORD_BYTES, SCAN_BYTES, Tally},
    event_window,
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
            (Some("network"), Some("response_body")) => {
                if let Some(reason) = payload()
                    .filter(|b| b.len() == 128 && b[0] == 1)
                    .and_then(|b| response_refusal(b[4]))
                {
                    *self.content.entry(("response_body", reason)).or_default() += 1;
                }
            }
            _ => {}
        }
    }
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
        _ => "full request targets",
    };
    let why = match reason {
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
        // 68 and 69 belong to another part of the contract.
        70 => ("memory_cache_reuse", "reuses"),
        _ => return None,
    })
}

fn check(code: &str, severity: &str, message: impl Into<String>) -> Value {
    json!({"code": code, "severity": severity, "message": message.into()})
}

/// Plain-language meaning of a producer gap reason, from its shape. The reason
/// itself stays in the check, so an unfamiliar one is never hidden.
fn gap_meaning(reason: &str) -> &'static str {
    if reason.contains("filtered") {
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
    let unresolved = request_tabs.unresolved();
    if unresolved > 0 {
        let mut item = check(
            "network_tab_unresolved",
            "error",
            format!(
                "{unresolved} requests have no tab. This is a capture bug, not a property of the page; request_tabs lists them by process and request id for get_events."
            ),
        );
        item["count"] = json!(unresolved.to_string());
        checks.insert(0, item);
    }
    let excluded = exclusions.totals();
    let no_tab: u64 = [65, 66]
        .iter()
        .filter_map(|class| excluded.get(class))
        .fold(0, |sum, count| sum.saturating_add(*count));
    if no_tab > 0 {
        let mut item = check(
            "no_tab_traffic_excluded",
            "info",
            format!(
                "{no_tab} requests no tab caused were not recorded (extension workers {}, DevTools loads {}). These are named exclusions, not gaps.",
                excluded.get(&65).copied().unwrap_or(0),
                excluded.get(&66).copied().unwrap_or(0)
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
                "{reuses} memory-cache reuses were counted, not recorded: each renderer records at most 4,096 per capture configuration, and none in a page that is not ordinary (an SVG image's own document or a page popup). This is a named exclusion, not a gap."
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

#[cfg(test)]
mod tests {
    use super::*;

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
        ]
        .map(|event| event.to_string())
        .to_vec();
        let mut orphan = event(10, "network", "request_started", 0, "GET example.test");
        orphan["tab_id"] = json!(0);
        orphan["request_id"] = json!("77");
        orphan["browser_context_id_high"] = json!("3");
        orphan["browser_context_id_low"] = json!("4");
        lines.push(orphan.to_string());
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
                {"class": "memory_cache_reuse", "unit": "reuses", "count": "9"},
            ])
        );
        let reuses = summary["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["code"] == "memory_cache_reuse_not_recorded")
            .unwrap();
        assert_eq!(reuses["severity"], "info");
        assert_eq!(reuses["count"], "9");
        let checks = summary["checks"].as_array().unwrap();
        assert_eq!(checks[0]["code"], "network_tab_unresolved");
        assert_eq!(checks[0]["severity"], "error");
        assert_eq!(
            summary["request_tabs"]["unresolved_requests"],
            json!([{"process_id": 7, "request_id": "77"}])
        );
        let no_tab = checks
            .iter()
            .find(|check| check["code"] == "no_tab_traffic_excluded")
            .unwrap();
        assert_eq!(no_tab["count"], "3");
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
