//! One read that answers "did this capture work?" for the whole session:
//! event counts by type and frame, artifact digests, gap reasons and capture
//! state, with a short list of checks that name what looks wrong. The counts
//! are folded as records arrive, into the event index (`event_index`, with
//! `Fold`) and the artifact lookup index, so a session of any length is
//! summarized from a few rows. It is counts, identifiers and origin labels
//! only; it never includes payloads, source or bodies.
use crate::{
    artifact_lookup,
    error::Result,
    event_index::{self, Indexes, Totals},
    event_window,
    index_db::{self, Position, SqlResult},
    request_cookies,
    request_headers::{self, DROP_REPORT_SLACK_NS, Lifecycle},
    request_tabs::{self, RequestTabs},
    session_context,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    time::{Duration, Instant},
};

/// What the answer lists; each list says how many it leaves out.
const FRAMES: usize = 32;
const FRAME_TYPES: usize = 8;
const SESSIONS: usize = 16;
const ARTIFACTS: usize = 32;
const REFUSAL_REASONS: usize = 32;
/// How long a summary folds appended records before it answers from what
/// is indexed. The background indexer folds the rest, and the answer says
/// how far it got.
pub const FOLD: Duration = Duration::from_secs(1);

/// Live state the backend knows outside the stores.
pub struct CaptureState<'a> {
    pub instance_id: &'a str,
    pub capture_mode: &'a str,
    pub broker_connected: bool,
    pub capture_stopped: bool,
    pub artifact_receiver_configured: bool,
    pub artifact_receiver_connected: bool,
    /// `session_context::content_limits`: the budgets this session runs with,
    /// or null when unknown or without request content.
    pub content_limits: Value,
}

/// A content session's two byte budgets: which refusals and which retained
/// artifact kinds each one counts (native-network-v2.md, native-network-v3.md).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Budget {
    RequestContent,
    ResponseBody,
}
impl Budget {
    fn of_refusal(category: &str, reason: &str) -> Option<Self> {
        // Header blocks and cookie lists have their own fixed 64 MiB budget,
        // which no start panel control sets, so they are not named here.
        match (category, reason) {
            ("response_body", "not_captured_session_budget") => Some(Self::ResponseBody),
            ("request_body", "not_captured_session_budget")
            | ("request_target", "not_retained_session_budget") => Some(Self::RequestContent),
            _ => None,
        }
    }
    fn of_kind(kind: &str) -> Option<Self> {
        match kind {
            "request_body" | "request_target" => Some(Self::RequestContent),
            "response_body" => Some(Self::ResponseBody),
            _ => None,
        }
    }
    /// The start option, as content_limits and start_live_session name it.
    fn option(self) -> &'static str {
        match self {
            Self::RequestContent => "request_content_budget_mib",
            Self::ResponseBody => "response_body_budget_mib",
        }
    }
    /// The start panel control that sets it.
    fn control(self) -> &'static str {
        match self {
            Self::RequestContent => "Request content budget",
            Self::ResponseBody => "Response body budget",
        }
    }
    fn contents(self) -> &'static str {
        match self {
            Self::RequestContent => "request bodies and full targets",
            Self::ResponseBody => "response bodies",
        }
    }
}

/// The start option of the budget an artifact kind is charged to; the
/// artifact lookup index sums each budget's unique bytes under it.
pub(crate) fn budget_of_kind(kind: &str) -> Option<&'static str> {
    Budget::of_kind(kind).map(Budget::option)
}

/// A stored time or identifier for SQL: times stay below 2^63, and
/// identifiers keep their bits (`index_db::key`).
fn clamp(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Adds `delta` to one of the summary's kept counts.
pub(crate) fn bump(transaction: &Transaction<'_>, name: &str, delta: i64) -> Result<()> {
    if delta != 0 {
        transaction
            .prepare_cached(
                "INSERT INTO summary_counts(name, count) VALUES (?1, ?2)
                 ON CONFLICT(name) DO UPDATE SET count = count + excluded.count",
            )
            .sql()?
            .execute(params![name, delta])
            .sql()?;
    }
    Ok(())
}

/// The kept counts whose names start with `prefix`, by the rest of the name.
pub(crate) fn counts_named(connection: &Connection, prefix: &str) -> Result<BTreeMap<String, u64>> {
    // `;` follows `:` in byte order, so the range is every name with the prefix.
    let end = format!("{};", prefix.trim_end_matches(':'));
    connection
        .prepare_cached(
            "SELECT name, count FROM summary_counts WHERE name > ?1 AND name < ?2 AND count > 0",
        )
        .sql()?
        .query_map(params![prefix, end], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })
        .sql()?
        .map(|row| {
            row.map(|(name, count)| (name[prefix.len()..].to_owned(), count))
                .sql()
        })
        .collect()
}

pub(crate) fn count_named(connection: &Connection, name: &str) -> Result<u64> {
    Ok(connection
        .prepare_cached("SELECT count FROM summary_counts WHERE name = ?1")
        .sql()?
        .query_row([name], |row| row.get::<_, i64>(0))
        .optional()
        .sql()?
        .map_or(0, |count| count as u64))
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
}

#[derive(Default)]
struct Frame {
    count: u64,
    first: u64,
    last: u64,
    types: HashMap<String, u64>,
}

/// One fold's events by type, session and frame, added to the stored counts
/// in `write`.
#[derive(Default)]
struct EventCounts {
    total: u64,
    first: Option<u64>,
    last: Option<u64>,
    by_type: HashMap<(String, String), u64>,
    sessions: HashMap<u64, u64>,
    frames: HashMap<(u64, u64, u64, u64), Frame>,
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

    fn write(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        let (Some(first), Some(last)) = (self.first, self.last) else {
            return Ok(());
        };
        transaction
            .prepare_cached(
                "UPDATE totals SET events = events + ?1,
                    first_ns = min(coalesce(first_ns, ?2), ?2), last_ns = max(coalesce(last_ns, ?3), ?3)
                 WHERE id = 0",
            )
            .sql()?
            .execute(params![clamp(self.total), clamp(first), clamp(last)])
            .sql()?;
        for ((category, kind), count) in self.by_type.drain() {
            transaction
                .prepare_cached(
                    "INSERT INTO summary_types(category, type, count) VALUES (?1, ?2, ?3)
                     ON CONFLICT(category, type) DO UPDATE SET count = count + excluded.count",
                )
                .sql()?
                .execute(params![category, kind, clamp(count)])
                .sql()?;
        }
        for (session, count) in self.sessions.drain() {
            transaction
                .prepare_cached(
                    "INSERT INTO summary_sessions(session, count) VALUES (?1, ?2)
                     ON CONFLICT(session) DO UPDATE SET count = count + excluded.count",
                )
                .sql()?
                .execute(params![index_db::key(session), clamp(count)])
                .sql()?;
        }
        for ((session, tab, navigation, frame), stats) in self.frames.drain() {
            let id: i64 = transaction
                .prepare_cached(
                    "INSERT INTO summary_frames(session, tab, navigation, frame, count, first_ns, last_ns)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(session, tab, navigation, frame) DO UPDATE SET
                        count = count + excluded.count, first_ns = min(first_ns, excluded.first_ns),
                        last_ns = max(last_ns, excluded.last_ns)
                     RETURNING id",
                )
                .sql()?
                .query_row(
                    params![
                        index_db::key(session),
                        index_db::key(tab),
                        index_db::key(navigation),
                        index_db::key(frame),
                        clamp(stats.count),
                        clamp(stats.first),
                        clamp(stats.last)
                    ],
                    |row| row.get(0),
                )
                .sql()?;
            for (kind, count) in stats.types {
                transaction
                    .prepare_cached(
                        "INSERT INTO summary_frame_types(frame, type, count) VALUES (?1, ?2, ?3)
                         ON CONFLICT(frame, type) DO UPDATE SET count = count + excluded.count",
                    )
                    .sql()?
                    .execute(params![id, kind, clamp(count)])
                    .sql()?;
            }
        }
        Ok(())
    }
}

/// Every capture refusal by its native reason: artifact_capture_failed
/// payloads, and request content a content session did not retain.
#[derive(Default)]
struct Refusals {
    failures: HashMap<String, u64>,
    content: HashMap<(&'static str, &'static str), u64>,
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
                *self.failures.entry(reason).or_default() += 1;
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
    fn write(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        let failures = self
            .failures
            .drain()
            .map(|(reason, count)| ("artifact", reason, count));
        let content = self
            .content
            .drain()
            .map(|((category, reason), count)| (category, reason.to_owned(), count));
        for (category, reason, count) in failures.chain(content) {
            transaction
                .prepare_cached(
                    "INSERT INTO summary_refusals(category, reason, count) VALUES (?1, ?2, ?3)
                     ON CONFLICT(category, reason) DO UPDATE SET count = count + excluded.count",
                )
                .sql()?
                .execute(params![category, reason, clamp(count)])
                .sql()?;
        }
        Ok(())
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
    /// The first and last times of its records.
    span: Option<(u64, u64)>,
}

/// Header blocks and cookie lists no row shows, and the requests of content
/// sessions that ended without a `network` request block, with the reason
/// ("Missing final blocks" in protocol/native-network-v3.md). One fold's
/// facts are merged into each request's stored row in `write`.
#[derive(Default)]
struct HeaderCoverage {
    /// The newest unattributed count per producer: each record carries its
    /// configuration's count so far.
    unattributed_blocks: HashMap<(u64, u64), u64>,
    unattributed_lists: HashMap<(u64, u64), u64>,
    requests: HashMap<(u64, u64, u64), RequestHeaderFacts>,
    /// Gap times of every category, by session: a dropped block makes an
    /// absent one unsure.
    drops: Vec<(u64, u64)>,
}
impl HeaderCoverage {
    fn record(&mut self, event: &Value) {
        let number = |key: &str| event_window::unsigned(&event[key]).unwrap_or(0);
        if event_window::dropped_records(event) > 0 {
            self.drops
                .push((number("session_id"), number("monotonic_time_ns")));
        }
        let producer = (number("session_id"), number("process_id"));
        let key = (producer.0, producer.1, number("request_id"));
        let time = number("monotonic_time_ns");
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
                if let Some(request) = self.request(key) {
                    request.widen(time);
                    if facts.source == 1 {
                        request.provisional |= 1 << facts.hop;
                    } else {
                        request.network |= 1 << facts.hop;
                    }
                }
            }
            _ if event["category"] != "network" => {}
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
                if let Some(request) = self.request(key) {
                    request.widen(time);
                    request.lifecycle.record(event);
                }
            }
            _ => {}
        }
    }
    fn request(&mut self, key: (u64, u64, u64)) -> Option<&mut RequestHeaderFacts> {
        (key.2 != 0).then(|| self.requests.entry(key).or_default())
    }

    fn write(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        for (kind, newest) in [
            (1, &mut self.unattributed_blocks),
            (2, &mut self.unattributed_lists),
        ] {
            for ((session, process), count) in newest.drain() {
                write_newest(transaction, kind, session, process, 0, count)?;
            }
        }
        for (session, time) in &self.drops {
            transaction
                .prepare_cached("INSERT INTO summary_drops(session, time) VALUES (?1, ?2)")
                .sql()?
                .execute(params![index_db::key(*session), clamp(*time)])
                .sql()?;
        }
        // Each request this fold saw, merged with its stored row; its reason
        // is decided with every drop so far, this fold's included.
        for ((session, process, request), facts) in self.requests.drain() {
            let key = params![
                index_db::key(session),
                index_db::key(process),
                index_db::key(request)
            ];
            let stored = transaction
                .prepare_cached(
                    "SELECT provisional, network, lifecycle, first_ns, last_ns, reason
                     FROM summary_headers WHERE session = ?1 AND process = ?2 AND request = ?3",
                )
                .sql()?
                .query_row(key, |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)? as u64,
                        row.get::<_, i64>(4)? as u64,
                        row.get::<_, Option<String>>(5)?,
                    ))
                })
                .optional()
                .sql()?;
            let (mut first, mut last) = facts.span.unwrap_or_default();
            let mut merged = facts;
            let mut before = None;
            if let Some((provisional, network, lifecycle, stored_first, stored_last, reason)) =
                stored
            {
                merged.provisional |= provisional;
                merged.network |= network;
                merged.lifecycle = lifecycle_of(lifecycle_bits(&merged.lifecycle) | lifecycle);
                first = first.min(stored_first);
                last = last.max(stored_last);
                before = reason;
            }
            let reason = missing_reason(transaction, session, &merged, first, last)?;
            if before.as_deref() != reason {
                if let Some(before) = &before {
                    bump(transaction, &format!("missing:{before}"), -1)?;
                }
                if let Some(reason) = reason {
                    bump(transaction, &format!("missing:{reason}"), 1)?;
                }
            }
            transaction
                .prepare_cached(
                    "INSERT OR REPLACE INTO summary_headers(session, process, request, provisional,
                        network, lifecycle, first_ns, last_ns, reason)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .sql()?
                .execute(params![
                    index_db::key(session),
                    index_db::key(process),
                    index_db::key(request),
                    merged.provisional as i64,
                    merged.network as i64,
                    lifecycle_bits(&merged.lifecycle),
                    clamp(first),
                    clamp(last),
                    reason
                ])
                .sql()?;
        }
        // A drop also makes unsure the ended requests written by earlier
        // folds that it overlaps.
        for (session, time) in self.drops.drain(..) {
            let unsure = transaction
                .prepare_cached(
                    "UPDATE summary_headers SET reason = 'record_dropped'
                     WHERE session = ?1 AND reason = 'not_reported' AND last_ns >= ?2 AND first_ns <= ?3",
                )
                .sql()?
                .execute(params![
                    index_db::key(session),
                    clamp(time.saturating_sub(DROP_REPORT_SLACK_NS)),
                    clamp(time)
                ])
                .sql()? as i64;
            bump(transaction, "missing:not_reported", -unsure)?;
            bump(transaction, "missing:record_dropped", unsure)?;
        }
        Ok(())
    }
}

impl RequestHeaderFacts {
    fn widen(&mut self, time: u64) {
        self.span = Some(self.span.map_or((time, time), |(first, last)| {
            (first.min(time), last.max(time))
        }));
    }
}

/// Why a request ended without a `network` block on its final hop, or None
/// when it has one, has no header block, or is still open.
fn missing_reason(
    transaction: &Transaction<'_>,
    session: u64,
    request: &RequestHeaderFacts,
    first: u64,
    last: u64,
) -> Result<Option<&'static str>> {
    if request.provisional == 0 {
        return Ok(None);
    }
    let hop = 63 - request.provisional.leading_zeros();
    if request.network & (1 << hop) != 0 {
        return Ok(None);
    }
    let reason = request.lifecycle.missing_reason(true, false);
    if reason == "in_progress" {
        return Ok(None);
    }
    // Only a reason inferred from the block's absence can be made unsure,
    // and an ended request only by a drop reported within the slack.
    let dropped = request_headers::qualified(reason, true) != reason
        && transaction
            .prepare_cached(
                "SELECT 1 FROM summary_drops WHERE session = ?1 AND time >= ?2 AND time <= ?3",
            )
            .sql()?
            .exists(params![
                index_db::key(session),
                clamp(first),
                clamp(last.saturating_add(DROP_REPORT_SLACK_NS))
            ])
            .sql()?;
    Ok(Some(request_headers::qualified(reason, dropped)))
}

fn lifecycle_bits(lifecycle: &Lifecycle) -> i64 {
    [
        lifecycle.ended,
        lifecycle.failed,
        lifecycle.responded,
        lifecycle.from_cache,
        lifecycle.from_service_worker,
        lifecycle.download,
    ]
    .iter()
    .enumerate()
    .fold(0, |bits, (bit, set)| bits | (i64::from(*set) << bit))
}

fn lifecycle_of(bits: i64) -> Lifecycle {
    let set = |bit: u32| bits & (1 << bit) != 0;
    Lifecycle {
        ended: set(0),
        failed: set(1),
        responded: set(2),
        from_cache: set(3),
        from_service_worker: set(4),
        download: set(5),
    }
}

/// Keeps the larger of a producer's stored and newest cumulative count.
fn write_newest(
    transaction: &Transaction<'_>,
    kind: i64,
    session: u64,
    process: u64,
    class: u8,
    count: u64,
) -> Result<()> {
    transaction
        .prepare_cached(
            "INSERT INTO summary_newest(kind, session, process, class, count) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(kind, session, process, class) DO UPDATE SET count = max(count, excluded.count)",
        )
        .sql()?
        .execute(params![
            kind,
            index_db::key(session),
            index_db::key(process),
            class,
            clamp(count)
        ])
        .sql()?;
    Ok(())
}

fn missing_check(reason: &str, count: u64) -> Value {
    // A request that failed, or that the cache, a service worker or a
    // download answered, has no final headers by design; the rest are gaps.
    let severity = if matches!(reason, "not_reported" | "record_dropped") {
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

/// A budget refusal names the budget in force, what this session retained
/// against it, and the remedy: the start panel control, or the start option,
/// for the next session.
fn budget_meaning(
    budget: Budget,
    what: &str,
    count: u64,
    budget_mib: &Value,
    retained: u64,
    complete: bool,
) -> String {
    let size = budget_mib
        .as_u64()
        .map(|value| format!("{value} MiB "))
        .unwrap_or_default();
    format!(
        "{count} {what} arrived after this session's {size}{} was used; {}{} of unique {} are retained. Raise {} in the start panel (New Live Session…) for the next session; an agent's start_live_session sets {}.",
        budget.control().to_ascii_lowercase(),
        if complete { "" } else { "at least " },
        mib(retained),
        budget.contents(),
        budget.control(),
        budget.option(),
    )
}

fn content_noun(category: &str) -> &'static str {
    match category {
        "request_body" => "request bodies",
        "response_body" => "response bodies",
        "request_headers" => "request header blocks",
        "response_headers" => "response header blocks",
        "cookie_list" => "cookie lists",
        _ => "full request targets",
    }
}

fn content_meaning(category: &str, reason: &str, count: u64) -> String {
    let what = content_noun(category);
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
            "were images, audio, video or fonts that page elements load, which are kept only when Capture media and fonts is on in the start panel (New Live Session…) for the next session, or an agent's start_live_session sets response_media"
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
        "not_captured_artifact_unavailable" | "not_retained_artifact_unavailable" => {
            "had no artifact channel: the Artifact category was off or the receiver was disconnected"
        }
        _ => "were refused by the bounded in-flight memory pool or artifact queue",
    };
    format!("{count} {what} {why}.")
}

/// Browser-internal evidence the capture counted instead of recording
/// (protocol/native-network-v3.md). Each record is one producer's cumulative
/// count for one class, so the newest count per producer is summed.
#[derive(Default)]
struct Exclusions(HashMap<(u64, u64, u8), u64>);
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
    fn write(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        for ((session, process, class), count) in self.0.drain() {
            write_newest(transaction, 0, session, process, class, count)?;
        }
        Ok(())
    }
}

/// The summary's part of the event index fold: each valid record's counts,
/// merged into the stored ones when the fold commits.
#[derive(Default)]
pub(crate) struct Fold {
    events: EventCounts,
    exclusions: Exclusions,
    request_tabs: RequestTabs,
    refusals: Refusals,
    header_coverage: HeaderCoverage,
}
impl Fold {
    pub(crate) fn record(&mut self, event: &Value) {
        self.events.record(event);
        self.exclusions.record(event);
        self.request_tabs.record(event);
        self.refusals.record(event);
        self.header_coverage.record(event);
    }

    pub(crate) fn write(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        self.events.write(transaction)?;
        self.exclusions.write(transaction)?;
        self.request_tabs.write(transaction)?;
        self.refusals.write(transaction)?;
        self.header_coverage.write(transaction)
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

/// The stored counts the answer lists, read at one position of the index.
struct Stored {
    totals: Totals,
    total: u64,
    first: Option<u64>,
    last: Option<u64>,
    by_type: Vec<(String, String, u64)>,
    sessions: Vec<(u64, u64)>,
    sessions_total: u64,
    frames: Vec<Value>,
    frames_total: u64,
    exclusions: BTreeMap<u8, u64>,
    /// artifact_capture_failed reasons, most frequent first.
    failures: Vec<(String, u64)>,
    content: Vec<(String, String, u64)>,
    unattributed_blocks: u64,
    unattributed_lists: u64,
    missing: BTreeMap<String, u64>,
    request_tabs: Value,
    unresolved: BTreeMap<String, u64>,
}

impl Stored {
    fn empty() -> Self {
        Self {
            totals: Totals {
                indexed_to: 0,
                sequence_gaps: 0,
                sequence_gaps_saturated: false,
                queue_drops: 0,
                queue_drops_saturated: false,
                named_gaps: Vec::new(),
                malformed_lines: 0,
            },
            total: 0,
            first: None,
            last: None,
            by_type: Vec::new(),
            sessions: Vec::new(),
            sessions_total: 0,
            frames: Vec::new(),
            frames_total: 0,
            exclusions: BTreeMap::new(),
            failures: Vec::new(),
            content: Vec::new(),
            unattributed_blocks: 0,
            unattributed_lists: 0,
            missing: BTreeMap::new(),
            request_tabs: request_tabs::empty_document(),
            unresolved: BTreeMap::new(),
        }
    }

    fn read(connection: &Connection, position: &Position) -> Result<Self> {
        let rows = |sql: &str| -> Result<Vec<(String, String, u64)>> {
            connection
                .prepare_cached(sql)
                .sql()?
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? as u64))
                })
                .sql()?
                .map(|row| row.sql())
                .collect()
        };
        let number = |sql: &str| -> Result<u64> {
            Ok(connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .sql()? as u64)
        };
        let (total, first, last) = connection
            .query_row(
                "SELECT events, first_ns, last_ns FROM totals WHERE id = 0",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u64,
                        row.get::<_, Option<i64>>(1)?.map(|time| time as u64),
                        row.get::<_, Option<i64>>(2)?.map(|time| time as u64),
                    ))
                },
            )
            .sql()?;
        let sessions = connection
            .prepare_cached(&format!(
                "SELECT session, count FROM summary_sessions ORDER BY count DESC, session LIMIT {SESSIONS}"
            ))
            .sql()?
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
            })
            .sql()?
            .map(|row| row.sql())
            .collect::<Result<Vec<_>>>()?;
        let busiest = connection
            .prepare_cached(&format!(
                "SELECT id, session, tab, navigation, frame, count, first_ns, last_ns FROM summary_frames
                 ORDER BY count DESC, session, tab, navigation, frame LIMIT {FRAMES}"
            ))
            .sql()?
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    [1, 2, 3, 4, 5, 6, 7].map(|column| row.get::<_, i64>(column).map(|v| v as u64)),
                ))
            })
            .sql()?
            .map(|row| row.sql())
            .collect::<Result<Vec<_>>>()?;
        let mut frames = Vec::new();
        for (id, columns) in busiest {
            let [session, tab, navigation, frame, count, first, last] =
                columns.map(|value| value.unwrap_or(0));
            let types = connection
                .prepare_cached(&format!(
                    "SELECT type, count FROM summary_frame_types WHERE frame = ?1
                     ORDER BY count DESC, type LIMIT {FRAME_TYPES}"
                ))
                .sql()?
                .query_map([id], |row| {
                    Ok(json!({"type": row.get::<_, String>(0)?,
                        "count": (row.get::<_, i64>(1)? as u64).to_string()}))
                })
                .sql()?
                .map(|row| row.sql())
                .collect::<Result<Vec<_>>>()?;
            let kinds: i64 = connection
                .prepare_cached("SELECT count(*) FROM summary_frame_types WHERE frame = ?1")
                .sql()?
                .query_row([id], |row| row.get(0))
                .sql()?;
            frames.push(json!({
                "session_id": session.to_string(),
                "tab_id": tab,
                "navigation_id": navigation.to_string(),
                "frame_id": frame.to_string(),
                "count": count.to_string(),
                "first_time_ns": first.to_string(),
                "last_time_ns": last.to_string(),
                "types_omitted": (kinds as usize).saturating_sub(types.len()),
                "types": types,
            }));
        }
        let mut exclusions = BTreeMap::new();
        let (mut unattributed_blocks, mut unattributed_lists) = (0u64, 0u64);
        let newest = connection
            .prepare_cached("SELECT kind, class, count FROM summary_newest")
            .sql()?
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u8>(1)?,
                    row.get::<_, i64>(2)? as u64,
                ))
            })
            .sql()?
            .map(|row| row.sql())
            .collect::<Result<Vec<_>>>()?;
        for (kind, class, count) in newest {
            let total = match kind {
                0 => exclusions.entry(class).or_default(),
                1 => &mut unattributed_blocks,
                _ => &mut unattributed_lists,
            };
            *total = total.saturating_add(count);
        }
        let refusals =
            rows("SELECT category, reason, count FROM summary_refusals ORDER BY category, reason")?;
        let mut failures = refusals
            .iter()
            .filter(|(category, ..)| category == "artifact")
            .map(|(_, reason, count)| (reason.clone(), *count))
            .collect::<Vec<_>>();
        failures.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let unresolved = counts_named(connection, "unresolved:")?;
        Ok(Self {
            totals: event_index::totals(connection, position)?,
            total,
            first,
            last,
            by_type: rows(
                "SELECT category, type, count FROM summary_types ORDER BY count DESC, category, type",
            )?,
            sessions,
            sessions_total: number("SELECT count(*) FROM summary_sessions")?,
            frames,
            frames_total: number("SELECT count(*) FROM summary_frames")?,
            exclusions,
            failures,
            content: refusals
                .into_iter()
                .filter(|(category, ..)| category != "artifact")
                .collect(),
            unattributed_blocks,
            unattributed_lists,
            missing: counts_named(connection, "missing:")?,
            request_tabs: request_tabs::document(connection, &unresolved)?,
            unresolved,
        })
    }

    fn count(&self, kind: &str) -> u64 {
        self.by_type
            .iter()
            .filter(|(_, name, _)| name == kind)
            .map(|(_, _, count)| count)
            .sum()
    }

    fn events_document(&self, position: &Position, scope: &str) -> Value {
        let totals = &self.totals;
        json!({
            "scope": scope,
            "scan_start": "0",
            "scan_end": position.indexed_to.to_string(),
            "store_end": position.file_end.to_string(),
            "total": self.total.to_string(),
            "first_time_ns": self.first.map(|time| time.to_string()),
            "last_time_ns": self.last.map(|time| time.to_string()),
            "by_type": self.by_type.iter().map(|(category, kind, count)| json!({
                "category": category, "type": kind, "count": count.to_string()
            })).collect::<Vec<_>>(),
            "sessions": self.sessions.iter().map(|(session, count)| json!({
                "session_id": session.to_string(), "count": count.to_string()
            })).collect::<Vec<_>>(),
            "sessions_omitted": (self.sessions_total as usize).saturating_sub(self.sessions.len()),
            "frames": self.frames,
            "frames_omitted": (self.frames_total as usize).saturating_sub(self.frames.len()),
            "malformed_lines": totals.malformed_lines.to_string(),
            "sequence_gaps": totals.sequence_gaps.to_string(),
            "sequence_gaps_saturated": totals.sequence_gaps_saturated,
            "queue_drops": totals.queue_drops.to_string(),
            "queue_drops_saturated": totals.queue_drops_saturated,
            "named_gaps": totals.named_gaps.iter().map(|gap| json!({
                "category": gap.category, "reason": gap.reason, "count": gap.count.to_string()
            })).collect::<Vec<_>>(),
        })
    }
}

/// The summary of the whole session, from the event index and the artifact
/// lookup index, each first brought up to its store until `deadline`. A store
/// still being indexed is summarized as far as its index reaches, which the
/// answer's scopes and a `summary_indexing` check say.
pub fn build(
    indexes: &mut Indexes,
    artifacts: &Path,
    state: &CaptureState<'_>,
    deadline: Instant,
) -> Result<Value> {
    let manifest = artifact_lookup::summary(artifacts, ARTIFACTS, deadline)?;
    let (position, stopped, stored) = match indexes.summary_index(deadline)? {
        Some(index) => {
            let stored = Stored::read(index.connection, &index.position)?;
            (index.position, index.stopped, stored)
        }
        None => (
            Position {
                epoch: String::new(),
                indexed_to: 0,
                file_end: 0,
                reopened: false,
            },
            None,
            Stored::empty(),
        ),
    };
    let events_scope = if stopped.is_some() {
        "stopped"
    } else if position.caught_up(event_index::RECORD_BYTES as u64) {
        "store"
    } else {
        "indexing"
    };
    let retained = |budget: Budget| {
        manifest
            .retained
            .iter()
            .find(|(option, _)| option == budget.option())
            .map_or(0, |(_, bytes)| *bytes)
    };
    let has_kind = |kind: &str| manifest.by_kind.iter().any(|(name, _)| name == kind);
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
    if stored.total == 0 {
        checks.push(check(
            "no_events",
            "warning",
            "No events are stored yet. Open a page in the capture browser, then wait for events.",
        ));
    }
    let compiled = stored.count("module_compiled");
    if compiled > 0 && !has_kind("wasm") {
        checks.push(check(
            "wasm_without_artifacts",
            "warning",
            format!(
                "{compiled} Wasm module_compiled events but no stored Wasm artifact. Check the artifact receiver and that the capture category mask includes Artifact (1024)."
            ),
        ));
    }
    // The most frequent reasons each have a check, in name order; the rest
    // share one, which says how many reasons it holds.
    let mut failures = stored
        .failures
        .iter()
        .take(REFUSAL_REASONS)
        .collect::<Vec<_>>();
    failures.sort_by(|a, b| a.0.cmp(&b.0));
    for (reason, count) in failures {
        let mut item = check(
            "artifact_capture_failed",
            "warning",
            format!("{count} artifact captures failed ({reason}); those bytes are not stored."),
        );
        item["reason"] = json!(reason);
        item["count"] = json!(count.to_string());
        checks.push(item);
    }
    let rest = &stored.failures[stored.failures.len().min(REFUSAL_REASONS)..];
    if !rest.is_empty() {
        let count = rest
            .iter()
            .fold(0u64, |sum, (_, count)| sum.saturating_add(*count));
        let mut item = check(
            "artifact_capture_failed",
            "warning",
            format!(
                "{count} artifact captures failed for {} less frequent reasons; those bytes are not stored.",
                rest.len()
            ),
        );
        item["reason"] = json!("other");
        item["count"] = json!(count.to_string());
        checks.push(item);
    }
    for (category, reason, count) in &stored.content {
        let budget = Budget::of_refusal(category, reason);
        let message = match budget {
            Some(budget) => budget_meaning(
                budget,
                content_noun(category),
                *count,
                &state.content_limits[budget.option()],
                retained(budget),
                manifest.complete,
            ),
            None => content_meaning(category, reason, *count),
        };
        let mut item = check("request_content_not_retained", "warning", message);
        item["category"] = json!(category);
        item["reason"] = json!(reason);
        item["count"] = json!(count.to_string());
        // The budget in force (null when this backend does not know it) and
        // the unique bytes retained against it in the indexed manifest.
        if let Some(budget) = budget {
            item["budget_mib"] = state.content_limits[budget.option()].clone();
            item["retained_bytes"] = json!(retained(budget).to_string());
            item["retained_complete"] = json!(manifest.complete);
        }
        checks.push(item);
    }
    let (blocks, lists) = (stored.unattributed_blocks, stored.unattributed_lists);
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
    for (reason, count) in &stored.missing {
        checks.push(missing_check(reason, *count));
    }
    let totals = &stored.totals;
    let drops = totals.queue_drops;
    let named: u64 = totals.named_gaps.iter().map(|gap| gap.count).sum();
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
    let holes = totals.sequence_gaps;
    if holes > 0 {
        checks.push(check(
            "sequence_gaps",
            "warning",
            format!("{holes} sequence numbers are absent inside the stored events."),
        ));
    }
    for gap in &totals.named_gaps {
        let mut item = check("named_gap", "warning", gap_meaning(&gap.reason));
        item["category"] = json!(gap.category);
        item["reason"] = json!(gap.reason);
        item["count"] = json!(gap.count.to_string());
        checks.push(item);
    }
    // A context with no parent document (a shared storage worklet) is not
    // linked by design, so it is a warning; every other reason is a capture bug.
    let mut reasons = stored.unresolved.clone();
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
    let excluded = &stored.exclusions;
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
    if totals.malformed_lines > 0 {
        let mut item = check(
            "malformed_lines",
            "warning",
            format!(
                "{} stored lines are not valid events, so no count here includes them.",
                totals.malformed_lines
            ),
        );
        item["count"] = json!(totals.malformed_lines.to_string());
        checks.push(item);
    }
    // A record the index cannot read stops its counts for good: what follows
    // it is in none of them.
    let unreadable = |code: &str, error: &str, store: &str, to: u64, end: u64| {
        check(
            code,
            "error",
            format!(
                "{}, so these counts cover the first {} of the {store}'s {} and nothing after it.",
                error.trim_end_matches('.'),
                mib(to),
                mib(end)
            ),
        )
    };
    if let Some(error) = &stopped {
        checks.push(unreadable(
            "events_unreadable",
            &error.message,
            "event store",
            position.indexed_to,
            position.file_end,
        ));
    }
    if let Some(error) = &manifest.stopped {
        checks.push(unreadable(
            "artifact_manifest_unreadable",
            error,
            "artifact manifest",
            manifest.indexed_to,
            manifest.file_end,
        ));
    }
    if let Some(damage) = &manifest.damage {
        checks.push(check(
            "artifact_manifest_damaged",
            "warning",
            format!(
                "{}. That record is in no count here, and reading an artifact by ID fails until the manifest is replaced.",
                damage.trim_end_matches('.')
            ),
        ));
    }
    let mut indexing = Vec::new();
    if events_scope == "indexing" {
        indexing.push(format!(
            "the events up to {} of {}",
            mib(position.indexed_to),
            mib(position.file_end)
        ));
    }
    if !manifest.complete && manifest.stopped.is_none() {
        indexing.push(format!(
            "the artifact manifest up to {} of {}",
            mib(manifest.indexed_to),
            mib(manifest.file_end)
        ));
    }
    if !indexing.is_empty() {
        checks.push(check(
            "summary_indexing",
            "info",
            format!(
                "The backend is still indexing this session, so these counts cover {}. Read the summary again shortly.",
                indexing.join(" and ")
            ),
        ));
    }
    let items = manifest
        .newest
        .iter()
        .map(|artifact| {
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
            item
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "protocol_version": 2,
        "instance_id": state.instance_id,
        "capture_mode": state.capture_mode,
        "live_admission": session_context::live_admission(state.capture_mode, state.broker_connected),
        "broker_connected": state.broker_connected,
        "capture_stopped": state.capture_stopped,
        "artifact_receiver_configured": state.artifact_receiver_configured,
        "artifact_receiver_connected": state.artifact_receiver_connected,
        "events": stored.events_document(&position, events_scope),
        "request_tabs": stored.request_tabs,
        "exclusions": excluded.iter().map(|(class, count)| {
            let (name, unit) = exclusion_class(*class).unwrap();
            json!({"class": name, "unit": unit, "count": count.to_string()})
        }).collect::<Vec<_>>(),
        "artifacts": {
            "scope": if manifest.stopped.is_some() { "stopped" } else if manifest.complete { "store" } else { "indexing" },
            "scan_end": manifest.indexed_to.to_string(),
            "store_end": manifest.file_end.to_string(),
            "total": manifest.total.to_string(),
            "by_kind": manifest.by_kind.iter().map(|(kind, count)| (kind.clone(), json!(count.to_string()))).collect::<serde_json::Map<_, _>>(),
            "items_omitted": manifest.total.saturating_sub(items.len() as u64).to_string(),
            "items": items,
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
            "images, audio, video or fonts that page elements load, kept only when Capture media and fonts is on in the start panel (New Live Session…), or an agent's start_live_session sets response_media"
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

/// Every request's response body case, counted from the request index's rows,
/// and a check naming the bodies the browser proxy can never see. An index
/// that cannot answer leaves the counts unavailable, with its reason.
pub fn add_response_bodies(summary: &mut Value, counts: std::result::Result<Value, String>) {
    let counts = match counts {
        Ok(counts) => counts,
        Err(reason) => {
            summary["response_bodies"] = json!({"available": false, "reason": reason,
                "complete": false, "requests": "0",
                "snapshots_withheld": "0", "earlier_snapshots": "0", "cases": []});
            return;
        }
    };
    let count = |case: &str| {
        counts["cases"][case]
            .as_str()
            .and_then(|count| count.parse::<u64>().ok())
            .unwrap_or(0)
    };
    // A refused or malformed body may still name an earlier snapshot the
    // receiver holds, which Traffic opens; each case says how many do.
    let earlier = |case: &str| {
        counts["earlier_snapshots"][case]
            .as_str()
            .and_then(|count| count.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let cases = counts["cases"]
        .as_object()
        .map(|cases| {
            cases
                .iter()
                .map(|(case, value)| json!({"case": case, "count": value,
                    "earlier_snapshots": earlier(case).to_string(), "meaning": body_case_meaning(case)}))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let earlier_total = counts["earlier_snapshots"]
        .as_object()
        .map(|cases| {
            cases
                .values()
                .filter_map(|count| count.as_str()?.parse::<u64>().ok())
                .sum::<u64>()
        })
        .unwrap_or(0);
    let (worker, reused, local) = (
        count("service_worker"),
        count("memory_cache"),
        count("renderer_answered"),
    );
    summary["response_bodies"] = json!({
        "available": true, "reason": null,
        "complete": counts["complete"], "requests": counts["requests"],
        "snapshots_withheld": counts["snapshots_withheld"].as_str().unwrap_or("0"),
        "earlier_snapshots": earlier_total.to_string(), "cases": cases,
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
                "{withheld} response bodies had a snapshot withheld while they arrived: their own snapshot allowance, the session's snapshot quarter of the response body budget, or the budget was used, so their newest snapshot is older than the schedule would make it. Raise Response body budget in the start panel (New Live Session…) for the next session; an agent's start_live_session sets response_body_budget_mib."
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

    /// The summary of a store, from its event index on disk beside it.
    fn summarize(store: &Path, artifacts: &Path, state: &CaptureState<'_>) -> Value {
        let mut indexes = Indexes::new(store, &store.with_file_name("origin-trace.jsonl"));
        build(
            &mut indexes,
            artifacts,
            state,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap()
    }

    #[test]
    fn response_body_cases_are_counted_with_their_meaning() {
        let mut summary = json!({"checks": []});
        add_response_bodies(
            &mut summary,
            Ok(
                json!({"complete": true, "requests": "8", "snapshots_withheld": "3",
                "cases": {"captured": "2", "memory_cache": "1", "service_worker": "2", "renderer_answered": "1",
                    "not_captured_session_budget": "2"},
                "earlier_snapshots": {"not_captured_session_budget": "1"}}),
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
        // A remedy names the start panel's control, never an environment
        // variable a person using the packaged app cannot set.
        let remedy = withheld["message"].as_str().unwrap();
        assert!(
            remedy.contains("Raise Response body budget in the start panel"),
            "{remedy}"
        );
        assert!(!remedy.contains("REB_"), "{remedy}");
        let media = body_case_meaning("not_captured_type");
        assert!(media.contains("Capture media and fonts"), "{media}");
        assert!(!media.contains("REB_"), "{media}");
        let cases = summary["response_bodies"]["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 5);
        // A refused body that keeps an earlier snapshot is counted as such.
        assert_eq!(summary["response_bodies"]["earlier_snapshots"], "1");
        let refused = cases
            .iter()
            .find(|case| case["case"] == "not_captured_session_budget")
            .unwrap();
        assert_eq!(refused["earlier_snapshots"], "1");
        assert_eq!(cases[0]["earlier_snapshots"], "0");
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
            Ok(json!({"complete": true, "requests": "2", "cases": {"captured": "2"}})),
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
            content_limits: Value::Null,
        };
        let summary = summarize(&store, &artifacts, &state);
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
    #[allow(clippy::too_many_arguments)] // one per field of the record under test
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
    fn a_drop_while_a_request_ran_makes_its_missing_block_unsure() {
        let summarize = |with_gap: bool| {
            let root = tempfile::tempdir().unwrap();
            let store = root.path().join("events.jsonl");
            let artifacts = root.path().join("artifacts");
            std::fs::create_dir_all(&artifacts).unwrap();
            let mut events = vec![
                lifecycle(1, "request_started", 1),
                header(2, 1, 1, false, 1, 3, 0, 0),
                lifecycle(4, "response_started", 1),
                lifecycle(5, "request_completed", 1),
            ];
            if with_gap {
                // A renderer's drop gap takes the category of its last record.
                let mut gap = event(3, "canvas", "gap", 3, "2");
                gap["process_id"] = json!(9);
                events.push(gap);
            }
            let lines: Vec<String> = events.iter().map(Value::to_string).collect();
            std::fs::write(&store, lines.join("\n") + "\n").unwrap();
            let state = CaptureState {
                instance_id: "1:2",
                capture_mode: "live",
                broker_connected: true,
                capture_stopped: false,
                artifact_receiver_configured: false,
                artifact_receiver_connected: false,
                content_limits: Value::Null,
            };
            summarize(&store, &artifacts, &state)["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|check| check["code"] == "final_headers_missing")
                .map(|check| (check["reason"].clone(), check["severity"].clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            summarize(false),
            vec![(json!("not_reported"), json!("warning"))]
        );
        assert_eq!(
            summarize(true),
            vec![(json!("record_dropped"), json!("warning"))]
        );
    }

    #[test]
    fn every_request_is_followed_across_folds_and_a_later_drop_reaches_earlier_ones() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let state = CaptureState {
            instance_id: "1:2",
            capture_mode: "live",
            broker_connected: true,
            capture_stopped: false,
            artifact_receiver_configured: false,
            artifact_receiver_connected: false,
            content_limits: Value::Null,
        };
        let append = |events: &[Value]| {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&store)
                .unwrap();
            for event in events {
                std::io::Write::write_all(&mut file, format!("{event}\n").as_bytes()).unwrap();
            }
        };
        let missing = |summary: &Value| {
            summary["checks"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|check| check["code"] == "final_headers_missing")
                .map(|check| {
                    (
                        check["reason"].as_str().unwrap().to_owned(),
                        check["count"].as_str().unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>()
        };
        // A metadata-only session has no final block to miss, however long.
        let mut sequence = 0;
        let mut metadata = Vec::new();
        for request in 1..=40 {
            for kind in ["request_started", "response_started", "request_completed"] {
                sequence += 1;
                metadata.push(lifecycle(sequence, kind, request));
            }
        }
        append(&metadata);
        let summary = summarize(&store, &artifacts, &state);
        assert!(missing(&summary).is_empty());
        assert_eq!(summary["events"]["scope"], "store");
        assert_eq!(summary["protocol_version"], 2);
        // Every content request is followed; none is past a bound.
        let mut content = Vec::new();
        let mut starts = Vec::new();
        for request in 41..=80 {
            sequence += 1;
            let start = sequence;
            starts.push(start * 10);
            content.push(lifecycle(start, "request_started", request));
            sequence += 1;
            content.push(header(sequence, start, request, false, 1, 3, 0, 0));
            sequence += 1;
            content.push(lifecycle(sequence, "request_completed", request));
        }
        append(&content);
        let summary = summarize(&store, &artifacts, &state);
        assert_eq!(
            missing(&summary),
            vec![("not_reported".to_owned(), "40".to_owned())]
        );
        // A drop folded later, timed while the first twenty ran, makes their
        // absent blocks unsure; the rest started after it.
        let mut gap = event(sequence + 1, "canvas", "gap", 3, "2");
        gap["process_id"] = json!(9);
        gap["monotonic_time_ns"] = json!((starts[19] + 5).to_string());
        append(&[gap]);
        let summary = summarize(&store, &artifacts, &state);
        assert_eq!(
            missing(&summary),
            vec![
                ("not_reported".to_owned(), "20".to_owned()),
                ("record_dropped".to_owned(), "20".to_owned())
            ]
        );
        // The same store folded at once agrees.
        let whole = tempfile::tempdir().unwrap();
        let copy = whole.path().join("events.jsonl");
        std::fs::copy(&store, &copy).unwrap();
        assert_eq!(
            missing(&summarize(&copy, &artifacts, &state)),
            missing(&summary)
        );
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
            content_limits: Value::Null,
        };
        let summary = summarize(&store, &artifacts, &state);
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
    }

    #[test]
    fn budget_refusals_name_the_budget_what_it_holds_and_the_control() {
        let root = tempfile::tempdir().unwrap();
        let store = root.path().join("events.jsonl");
        let artifacts = root.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let child = |sequence: u64, kind: &str, set: &dyn Fn(&mut Vec<u8>)| {
            let mut payload = vec![0u8; 128];
            set(&mut payload);
            let mut event = event(sequence, "network", kind, 5, "");
            event["payload"] = json!(hex::encode(&payload));
            event["payload_size"] = json!(128);
            event.to_string()
        };
        let lines = [
            child(1, "response_body", &|p| {
                p[0] = 1;
                p[4] = 12;
            }),
            child(2, "response_body", &|p| {
                p[0] = 1;
                p[4] = 12;
            }),
            child(3, "response_body", &|p| {
                p[0] = 1;
                p[4] = 9;
            }),
            child(4, "request_body", &|p| p[5] = 10),
            child(5, "request_target", &|p| {
                p[0] = 2;
                p[9] = 4;
            }),
            // A header block past its own fixed budget, which no start panel
            // control sets.
            header(6, 1, 0, false, 1, 7, 0, 0).to_string(),
        ];
        std::fs::write(&store, lines.join("\n") + "\n").unwrap();
        // Two distinct response bodies and a repeat of one, one request body
        // and one full target: the repeat is stored once and counted once.
        let row = |id: u64, kind: &str, digest: char, size: u64| {
            let hash = digest.to_string().repeat(64);
            json!({"protocol_version":1,"artifact_id":id.to_string(),"session_id":"9","navigation_id":"0",
                "frame_id":"5","parent_artifact_id":"0","creator_event_id":"1","execution_context_id":"0",
                "capture_origin":if kind == "response_body" {"network_response"} else {"network_request"},
                "kind":kind,"url":"https://owned.example/x","mime_type":"application/json",
                "byte_size":size,"sha256":hash,"sensitive":true,"content_path":format!("blobs/{hash}.bin")})
            .to_string()
        };
        let manifest = [
            row(1, "response_body", 'a', 3 * 1_048_576),
            row(2, "response_body", 'b', 1_048_576),
            row(3, "response_body", 'a', 3 * 1_048_576),
            row(4, "request_body", 'c', 524_288),
            row(5, "request_target", 'd', 524_288),
        ];
        std::fs::write(artifacts.join("manifest.jsonl"), manifest.join("\n") + "\n").unwrap();
        let summarize = |content_limits: Value| {
            let state = CaptureState {
                instance_id: "1:2",
                capture_mode: "live",
                broker_connected: true,
                capture_stopped: false,
                artifact_receiver_configured: true,
                artifact_receiver_connected: true,
                content_limits,
            };
            summarize(&store, &artifacts, &state)
        };
        // Different budgets, so a check that reports the other one fails.
        let summary = summarize(json!({"version":1,"request_content_budget_mib":3,
            "response_body_budget_mib":8,"response_media":false}));
        let find = |summary: &Value, category: &str, reason: &str| {
            summary["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|check| check["category"] == category && check["reason"] == reason)
                .cloned()
                .unwrap()
        };
        let response = find(&summary, "response_body", "not_captured_session_budget");
        assert_eq!(response["count"], "2");
        assert_eq!(response["budget_mib"], 8);
        assert_eq!(response["retained_bytes"], (4 * 1_048_576).to_string());
        assert_eq!(response["retained_complete"], true);
        assert_eq!(
            response["message"],
            "2 response bodies arrived after this session's 8 MiB response body budget was used; 4.0 MiB of unique response bodies are retained. Raise Response body budget in the start panel (New Live Session…) for the next session; an agent's start_live_session sets response_body_budget_mib."
        );
        // Request bodies and full targets share the request content budget.
        for (category, reason, noun) in [
            (
                "request_body",
                "not_captured_session_budget",
                "request bodies",
            ),
            (
                "request_target",
                "not_retained_session_budget",
                "full request targets",
            ),
        ] {
            let check = find(&summary, category, reason);
            assert_eq!(check["budget_mib"], 3, "{category}");
            assert_eq!(check["retained_bytes"], "1048576", "{category}");
            let message = check["message"].as_str().unwrap();
            assert!(message.starts_with(&format!("1 {noun} arrived after this session's 3 MiB request content budget was used; 1.0 MiB of unique request bodies and full targets are retained.")), "{message}");
            assert!(message.contains("Raise Request content budget in the start panel (New Live Session…) for the next session"), "{message}");
            assert!(message.contains("request_content_budget_mib"), "{message}");
            assert!(!message.contains("REB_"), "{message}");
        }
        let headers = find(&summary, "request_headers", "not_captured_session_budget");
        assert!(headers.get("budget_mib").is_none(), "{headers}");
        assert!(headers.get("retained_bytes").is_none(), "{headers}");
        assert!(
            headers["message"]
                .as_str()
                .unwrap()
                .contains("64 MiB of header blocks"),
            "{headers}"
        );
        let media = find(&summary, "response_body", "not_captured_type");
        assert!(
            media.get("budget_mib").is_none(),
            "media is not a budget refusal"
        );
        let media = media["message"].as_str().unwrap();
        assert!(media.contains("Capture media and fonts is on in the start panel (New Live Session…) for the next session"), "{media}");
        assert!(
            media.contains("response_media") && !media.contains("REB_"),
            "{media}"
        );
        // A backend that does not know the budget says so rather than guessing.
        let unknown = find(
            &summarize(Value::Null),
            "response_body",
            "not_captured_session_budget",
        );
        assert!(unknown["budget_mib"].is_null());
        assert_eq!(unknown["retained_bytes"], (4 * 1_048_576).to_string());
        assert!(
            unknown["message"]
                .as_str()
                .unwrap()
                .contains("after this session's response body budget was used; 4.0 MiB")
        );
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
            content_limits: Value::Null,
        };
        let summary = summarize(&store, &artifacts, &state);
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
            content_limits: Value::Null,
        };
        let summary = summarize(&store, &artifacts, &state);
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
            content_limits: Value::Null,
        };
        let summary = summarize(
            &root.path().join("events.jsonl"),
            &root.path().join("artifacts"),
            &state,
        );
        assert_eq!(summary["events"]["total"], "0");
        assert_eq!(summary["events"]["scope"], "store");
        assert_eq!(summary["checks"][0]["code"], "capture_not_live");
        assert_eq!(summary["checks"][1]["code"], "no_events");
    }
}
