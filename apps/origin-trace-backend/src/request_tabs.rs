//! Whether each request row has a tab (protocol/native-network-v3.md "Request
//! owners and tabs"). Rows join records the way Traffic does; a row is linked
//! when any record has a tab or a request_tab_link names it. An unlinked row
//! is a capture error. Identifiers only.
use crate::event_window;
use serde_json::{Value, json};
use std::collections::HashMap;

const TRACKED_ROWS: usize = 262_144;
const SAMPLES: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Row {
    Renderer(u64, u64, u64),
    Browser(u64, u64, u64, u64, u64),
}

struct State {
    linked: bool,
    order: usize,
    process_id: u64,
    request_id: u64,
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
    )
}

// A link needs its fixed payload; the validator already checked the rest.
fn link_payload(event: &Value) -> bool {
    event["payload"]
        .as_str()
        .and_then(|payload| hex::decode(payload).ok())
        .is_some_and(|bytes| {
            bytes.len() == 24 && bytes[..4] == [1, 0, 24, 0] && (1..=4).contains(&bytes[4])
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
        if kind == "request_tab_link" {
            if link_payload(event) && number("initiator_process_id") != 0 {
                let row = Row::Renderer(
                    session,
                    number("initiator_process_id"),
                    number("initiator_request_id"),
                );
                self.note(row, true, 0, 0);
            }
            return;
        }
        if !lifecycle(kind) {
            return;
        }
        let row = if kind == "request_initiated" {
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
        self.note(
            row,
            number("tab_id") != 0,
            number("process_id"),
            number("request_id"),
        );
    }

    fn note(&mut self, row: Row, linked: bool, process_id: u64, request_id: u64) {
        let order = self.rows.len();
        if let Some(state) = self.rows.get_mut(&row) {
            state.linked |= linked;
            if state.process_id == 0 {
                (state.process_id, state.request_id) = (process_id, request_id);
            }
        } else if self.rows.len() >= TRACKED_ROWS {
            self.untracked += 1;
        } else {
            self.rows.insert(
                row,
                State {
                    linked,
                    order,
                    process_id,
                    request_id,
                },
            );
        }
    }

    /// A link alone is not a row: only rows with a lifecycle record count.
    fn rows(&self) -> impl Iterator<Item = &State> {
        self.rows.values().filter(|state| state.process_id != 0)
    }

    pub(crate) fn unresolved(&self) -> u64 {
        self.rows().filter(|state| !state.linked).count() as u64
    }

    pub(crate) fn document(&self) -> Value {
        let mut unresolved = self
            .rows()
            .filter(|state| !state.linked)
            .collect::<Vec<_>>();
        unresolved.sort_by_key(|state| state.order);
        json!({
            "rows": self.rows().count().to_string(),
            "unresolved": unresolved.len().to_string(),
            "unresolved_requests": unresolved.iter().take(SAMPLES).map(|state| json!({
                "process_id": state.process_id,
                "request_id": state.request_id.to_string(),
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
            "browser_context_id_high": "3", "browser_context_id_low": "4"}),
        ));
        tabs.record(&record(
            "request_completed",
            2,
            902,
            0,
            json!({
            "browser_context_id_high": "3", "browser_context_id_low": "4"}),
        ));
        // A malformed link names nothing.
        tabs.record(&record("request_initiated", 31, 6, 0, json!({})));
        tabs.record(&record(
            "request_tab_link",
            2,
            0,
            0,
            json!({
            "initiator_process_id": 31, "initiator_request_id": 6, "payload": "00"}),
        ));
        // Pre-v3 evidence has no tab field to judge.
        let mut old = record("request_started", 2, 903, 0, json!({}));
        old["protocol_version"] = json!(2);
        tabs.record(&old);
        assert_eq!(tabs.unresolved(), 2);
        let document = tabs.document();
        assert_eq!(document["rows"], "4");
        assert_eq!(
            document["unresolved_requests"],
            json!([{"process_id": 2, "request_id": "902"}, {"process_id": 31, "request_id": "6"}])
        );
    }
}
