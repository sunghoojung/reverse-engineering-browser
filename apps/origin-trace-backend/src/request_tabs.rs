//! Whether each request row has a tab (protocol/native-network-v3.md "Request
//! owners and tabs"). Rows join records the way Traffic does; a row is linked
//! when any record has a tab or a request_tab_link or request_extension_link
//! names it. An unlinked row is a capture error, reported with a reason taken
//! from its own records. Identifiers only.
use crate::event_window;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};

const TRACKED_ROWS: usize = 262_144;
const SAMPLES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Row {
    Renderer(u64, u64, u64),
    Browser(u64, u64, u64, u64, u64),
}

struct State {
    linked: bool,
    extension: bool,
    order: usize,
    process_id: u64,
    request_id: u64,
    /// The renderer request_initiated's loader kind and whether it had a frame.
    renderer: Option<(u64, bool)>,
    /// Set by a browser request_started: its newest nonzero loader kind, else 0.
    browser: Option<u64>,
}

/// Why a row has no tab (protocol/native-network-v3.md "Unresolved requests"),
/// from its renderer start's loader kind and frame and its browser start's
/// loader kind. The request index names its rows with the same rule.
pub(crate) fn unresolved_reason(
    renderer: Option<(u64, bool)>,
    browser: Option<u64>,
) -> &'static str {
    match (renderer, browser) {
        (Some((0, _)), _) => "no_loader_kind",
        (Some((17..=19, _)), _) => "worker",
        (Some((20, _)), _) => "no_document",
        (Some((_, false)), _) => "no_frame",
        (Some(_), _) => "document_frame",
        (None, None) => "no_start",
        (None, Some(0)) => "no_loader_kind",
        (None, Some(_)) => "browser_factory",
    }
}

fn reason(state: &State) -> &'static str {
    unresolved_reason(state.renderer, state.browser)
}

/// One lifecycle record's part in its row.
struct Record {
    process_id: u64,
    request_id: u64,
    renderer: Option<(u64, bool)>,
    browser: Option<u64>,
}

#[derive(Default)]
pub(crate) struct RequestTabs {
    rows: HashMap<Row, State>,
    untracked: u64,
}

fn lifecycle(kind: &str) -> bool {
    matches!(
        kind,
        "request_initiated"
            | "request_started"
            | "request_redirected"
            | "response_started"
            | "response_completed"
            | "request_completed"
            | "request_failed"
            | "memory_cache_reuse"
    )
}

// A link needs its fixed payload; the validator already checked the rest.
fn link_payload(event: &Value, extension: bool) -> bool {
    event["payload"]
        .as_str()
        .and_then(|payload| hex::decode(payload).ok())
        .is_some_and(|bytes| {
            if extension {
                bytes.len() == 40
                    && bytes[..4] == [1, 0, 40, 0]
                    && matches!(bytes[4], 4 | 6 | 17..=19)
            } else {
                bytes.len() == 24 && bytes[..4] == [1, 0, 24, 0] && (1..=5).contains(&bytes[4])
            }
        })
}

impl RequestTabs {
    pub(crate) fn record(&mut self, event: &Value) {
        if event["protocol_version"] != 3 || event["category"] != "network" {
            return;
        }
        let number = |key: &str| event_window::unsigned(&event[key]).unwrap_or(0);
        let kind = event["type"].as_str().unwrap_or("");
        let session = number("session_id");
        if kind == "request_tab_link" || kind == "request_extension_link" {
            let extension = kind == "request_extension_link";
            if !link_payload(event, extension) {
                return;
            }
            // A renderer record by its process and request id, else a browser record.
            let row = if number("initiator_process_id") != 0 {
                Row::Renderer(
                    session,
                    number("initiator_process_id"),
                    number("initiator_request_id"),
                )
            } else {
                Row::Browser(
                    session,
                    number("process_id"),
                    number("browser_context_id_high"),
                    number("browser_context_id_low"),
                    number("request_id"),
                )
            };
            if !matches!(row, Row::Renderer(_, _, 0) | Row::Browser(_, _, _, _, 0)) {
                self.note(row, true, extension, None);
            }
            return;
        }
        if !lifecycle(kind) {
            return;
        }
        let row = if kind == "request_initiated" || kind == "memory_cache_reuse" {
            Row::Renderer(session, number("process_id"), number("request_id"))
        } else if number("initiator_process_id") != 0 {
            Row::Renderer(
                session,
                number("initiator_process_id"),
                number("initiator_request_id"),
            )
        } else if number("browser_context_id_high") == 0 && number("browser_context_id_low") == 0 {
            Row::Renderer(session, number("process_id"), number("request_id"))
        } else {
            Row::Browser(
                session,
                number("process_id"),
                number("browser_context_id_high"),
                number("browser_context_id_low"),
                number("request_id"),
            )
        };
        if matches!(row, Row::Renderer(_, _, 0) | Row::Browser(_, _, _, _, 0)) {
            return;
        }
        let loader_kind = number("loader_kind");
        let record = Record {
            process_id: number("process_id"),
            request_id: number("request_id"),
            // A memory-cache reuse names its owner as request_initiated does.
            renderer: matches!(kind, "request_initiated" | "memory_cache_reuse")
                .then(|| (loader_kind, number("frame_id") != 0)),
            browser: (kind == "request_started").then_some(loader_kind),
        };
        self.note(row, number("tab_id") != 0, false, Some(record));
    }

    fn note(&mut self, row: Row, linked: bool, extension: bool, record: Option<Record>) {
        if !self.rows.contains_key(&row) && self.rows.len() >= TRACKED_ROWS {
            self.untracked += 1;
            return;
        }
        let order = self.rows.len();
        let state = self.rows.entry(row).or_insert(State {
            linked: false,
            extension: false,
            order,
            process_id: 0,
            request_id: 0,
            renderer: None,
            browser: None,
        });
        state.linked |= linked;
        state.extension |= extension;
        let Some(record) = record else {
            return;
        };
        if state.process_id == 0 {
            (state.process_id, state.request_id) = (record.process_id, record.request_id);
        }
        state.renderer = state.renderer.or(record.renderer);
        if let Some(kind) = record.browser {
            state.browser = Some(if kind == 0 {
                state.browser.unwrap_or(0)
            } else {
                kind
            });
        }
    }

    /// A link alone is not a row: only rows with a lifecycle record count.
    fn rows(&self) -> impl Iterator<Item = &State> {
        self.rows.values().filter(|state| state.process_id != 0)
    }

    /// Unresolved rows by reason.
    pub(crate) fn unresolved_reasons(&self) -> BTreeMap<&'static str, u64> {
        let mut reasons = BTreeMap::new();
        for state in self.rows().filter(|state| !state.linked) {
            *reasons.entry(reason(state)).or_default() += 1;
        }
        reasons
    }

    pub(crate) fn document(&self) -> Value {
        let mut unresolved = self
            .rows()
            .filter(|state| !state.linked)
            .collect::<Vec<_>>();
        unresolved.sort_by_key(|state| state.order);
        json!({
            "rows": self.rows().count().to_string(),
            "extension_rows": self.rows().filter(|state| state.extension).count().to_string(),
            "unresolved": unresolved.len().to_string(),
            "unresolved_reasons": self.unresolved_reasons().into_iter()
                .map(|(reason, count)| (reason.to_owned(), json!(count.to_string())))
                .collect::<serde_json::Map<_, _>>(),
            "unresolved_requests": unresolved.iter().take(SAMPLES).map(|state| json!({
                "process_id": state.process_id,
                "request_id": state.request_id.to_string(),
                "reason": reason(state),
            })).collect::<Vec<_>>(),
            "unresolved_omitted": unresolved.len().saturating_sub(SAMPLES).to_string(),
            "untracked_records": self.untracked.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, process: u64, request: u64, tab: u64, fields: Value) -> Value {
        let mut event = json!({
            "protocol_version": 3, "category": "network", "type": kind, "session_id": "1",
            "process_id": process, "request_id": request.to_string(), "tab_id": tab,
            "initiator_process_id": 0, "initiator_request_id": 0,
            "browser_context_id_high": "0", "browser_context_id_low": "0", "payload": "",
        });
        for (key, value) in fields.as_object().unwrap() {
            event[key] = value.clone();
        }
        event
    }

    #[test]
    fn rows_join_like_traffic_and_unlinked_rows_are_errors() {
        let mut tabs = RequestTabs::default();
        // A worker start, its browser record and its link: one linked row.
        tabs.record(&record("request_initiated", 31, 5, 0, json!({})));
        tabs.record(&record(
            "request_started",
            2,
            900,
            0,
            json!({
            "initiator_process_id": 31, "initiator_request_id": 5,
            "browser_context_id_high": "3", "browser_context_id_low": "4"}),
        ));
        tabs.record(&record(
            "request_tab_link",
            2,
            0,
            0,
            json!({
            "initiator_process_id": 31, "initiator_request_id": 5,
            "payload": "010018000300000003000000000000000200000000000000"}),
        ));
        // A document request with a tab.
        tabs.record(&record(
            "request_started",
            2,
            901,
            4,
            json!({
            "browser_context_id_high": "3", "browser_context_id_low": "4"}),
        ));
        // A service-worker script fetch the browser could not link.
        tabs.record(&record(
            "request_started",
            2,
            902,
            0,
            json!({
            "browser_context_id_high": "3", "browser_context_id_low": "4", "loader_kind": 6}),
        ));
        tabs.record(&record(
            "request_completed",
            2,
            902,
            0,
            json!({
            "browser_context_id_high": "3", "browser_context_id_low": "4"}),
        ));
        // A service-worker update check linked to its version's clients and an
        // extension's service-worker script: browser records linked by request id.
        let context = json!({"browser_context_id_high": "3", "browser_context_id_low": "4"});
        for request in [904, 905] {
            tabs.record(&record("request_started", 2, request, 0, context.clone()));
        }
        let mut link = context.clone();
        link["payload"] = json!("010018000400000004000000000000000200000000000000");
        tabs.record(&record("request_tab_link", 2, 904, 0, link));
        let mut link = context.clone();
        link["payload"] = json!(format!("0100280006000000{}", "61".repeat(32)));
        tabs.record(&record("request_extension_link", 2, 905, 0, link));
        // A malformed link names nothing.
        tabs.record(&record(
            "request_initiated",
            31,
            6,
            0,
            json!({"loader_kind": 17}),
        ));
        tabs.record(&record(
            "request_tab_link",
            2,
            0,
            0,
            json!({
            "initiator_process_id": 31, "initiator_request_id": 6, "payload": "00"}),
        ));
        // A memory-cache reuse is its own row: one on its frame's tab, one in a
        // worker its link names, one with neither.
        tabs.record(&record("memory_cache_reuse", 31, 7, 4, json!({})));
        tabs.record(&record("memory_cache_reuse", 31, 8, 0, json!({})));
        tabs.record(&record(
            "request_tab_link",
            2,
            0,
            0,
            json!({
            "initiator_process_id": 31, "initiator_request_id": 8,
            "payload": "010018000100000003000000000000000100000000000000"}),
        ));
        tabs.record(&record("memory_cache_reuse", 31, 9, 0, json!({})));
        // Pre-v3 evidence has no tab field to judge.
        let mut old = record("request_started", 2, 903, 0, json!({}));
        old["protocol_version"] = json!(2);
        tabs.record(&old);
        // A registrant link (kind 5) names its row like the others.
        tabs.record(&record(
            "request_initiated",
            31,
            10,
            0,
            json!({"loader_kind": 19}),
        ));
        tabs.record(&record(
            "request_tab_link",
            2,
            0,
            0,
            json!({
            "initiator_process_id": 31, "initiator_request_id": 10,
            "payload": "010018000500000003000000000000000100000000000000"}),
        ));
        let document = tabs.document();
        assert_eq!(document["unresolved"], "3");
        assert_eq!(document["rows"], "10");
        assert_eq!(document["extension_rows"], "1");
        assert_eq!(
            document["unresolved_requests"],
            json!([
                {"process_id": 2, "request_id": "902", "reason": "browser_factory"},
                {"process_id": 31, "request_id": "6", "reason": "worker"},
                {"process_id": 31, "request_id": "9", "reason": "no_loader_kind"}
            ])
        );
        assert_eq!(
            document["unresolved_reasons"],
            json!({"browser_factory": "1", "no_loader_kind": "1", "worker": "1"})
        );
    }

    #[test]
    fn unresolved_rows_name_why_from_their_own_records() {
        let mut tabs = RequestTabs::default();
        let renderer =
            |request: u64, fields: Value| record("request_initiated", 31, request, 0, fields);
        tabs.record(&renderer(1, json!({"loader_kind": 16, "frame_id": "77"})));
        tabs.record(&renderer(2, json!({"loader_kind": 22, "frame_id": "78"})));
        tabs.record(&renderer(3, json!({"loader_kind": 20, "frame_id": "79"})));
        tabs.record(&renderer(4, json!({"loader_kind": 21, "frame_id": "0"})));
        tabs.record(&renderer(5, json!({"loader_kind": 18, "frame_id": "80"})));
        tabs.record(&renderer(6, json!({"frame_id": "81"})));
        // The renderer record decides, even when a browser record with a loader kind joins it.
        tabs.record(&record(
            "request_started",
            2,
            900,
            0,
            json!({
            "initiator_process_id": 31, "initiator_request_id": 5,
            "browser_context_id_high": "3", "browser_context_id_low": "4", "loader_kind": 7}),
        ));
        // Only a completion: the start was dropped, outside the scan or past the exclusion ring.
        tabs.record(&record("request_completed", 31, 8, 0, json!({})));
        // A memory-cache reuse names its owner as a start does.
        tabs.record(&record(
            "memory_cache_reuse",
            31,
            9,
            0,
            json!({"loader_kind": 16, "frame_id": "83"}),
        ));
        // A worklet record whose frame the browser knew is no error.
        tabs.record(&renderer(
            7,
            json!({"loader_kind": 22, "frame_id": "82", "tab_id": 4}),
        ));
        let reasons = tabs
            .rows
            .values()
            .filter(|state| !state.linked)
            .map(|state| (state.request_id, reason(state)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            reasons,
            BTreeMap::from([
                (1, "document_frame"),
                (2, "document_frame"),
                (3, "no_document"),
                (4, "no_frame"),
                (5, "worker"),
                (6, "no_loader_kind"),
                (8, "no_start"),
                (9, "document_frame"),
            ])
        );
        assert_eq!(
            tabs.document()["unresolved_reasons"],
            json!({"document_frame": "3", "no_document": "1", "no_frame": "1",
                   "no_loader_kind": "1", "no_start": "1", "worker": "1"})
        );
    }
}
