//! Status-only ExtraInfo correlation. Owner IDs include connection/session
//! generation; no response metadata is borrowed from a terminal handoff owner.
use serde_json::{Value, json};
use std::collections::BTreeMap;

const LIMIT: usize = 2048;
#[derive(Default)]
struct Evidence {
    starts: usize,
    extras: usize,
    responses: usize,
    redirected: bool,
    status: Option<u64>,
}
#[derive(Default)]
pub(super) struct StatusEvidence {
    entries: BTreeMap<(String, String), Evidence>,
    saturated: bool,
}
impl StatusEvidence {
    pub(super) fn observe(&mut self, state: &mut Value, owner: &str, method: &str, p: &Value) {
        let Some(id) = p["requestId"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 4096)
        else {
            return;
        };
        let key = (owner.to_owned(), id.to_owned());
        if !self.entries.contains_key(&key) && self.entries.len() >= LIMIT {
            self.saturated = true;
            state["network"]["capture_status"]["status_extra_info_overflow"] = json!(true);
        }
        if !self.saturated {
            let evidence = self.entries.entry(key.clone()).or_default();
            match method {
                "Network.requestWillBeSent" => {
                    evidence.starts = evidence.starts.saturating_add(1);
                    evidence.redirected |= p.get("redirectResponse").is_some();
                }
                "Network.responseReceived" => {
                    evidence.responses = evidence.responses.saturating_add(1);
                }
                "Network.responseReceivedExtraInfo" => {
                    evidence.extras = evidence.extras.saturating_add(1);
                    evidence.status = p["statusCode"]
                        .as_u64()
                        .filter(|status| (100..=599).contains(status));
                }
                _ => (),
            }
        }
        let complete = !self.saturated && state["network"]["dropped"].as_u64() == Some(0);
        let wire = self.entries.get(&key).and_then(|evidence| {
            (complete
                && evidence.starts == 1
                && evidence.extras == 1
                && evidence.responses <= 1
                && !evidence.redirected)
                .then_some(evidence.status)
                .flatten()
        });
        let response_seen = self
            .entries
            .get(&key)
            .is_some_and(|evidence| evidence.responses > 0);
        for row in state["network"]["requests"]
            .as_array_mut()
            .into_iter()
            .flatten()
        {
            if complete && (row["capture_owner"] != owner || row["protocol_request_id"] != id) {
                continue;
            }
            // Once retention is incomplete, remove every speculative fallback.
            // Tombstones are never evicted: later ID reuse cannot become unique.
            let row_wire = if complete { wire } else { None };
            row["wire_status"] = row_wire.map_or(Value::Null, |status| json!(status));
            if row["status_source"] == "response-received-extra-info" {
                row["status"] = Value::Null;
                row["status_source"] = json!("unavailable");
            }
            if !response_seen
                && row["status_source"] == "unavailable"
                && let Some(status) = row_wire.filter(|status| *status != 304)
            {
                // A wire 304 alone cannot establish the effective cached status.
                row["status"] = json!(status);
                row["status_source"] = json!("response-received-extra-info");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> Value {
        json!({"network":{"dropped":0,"requests":[]}})
    }
    fn row(owner: &str) -> Value {
        json!({"capture_owner":owner,"protocol_request_id":"r","status":null,"status_source":"unavailable","wire_status":null})
    }
    fn start(e: &mut StatusEvidence, s: &mut Value, owner: &str) {
        e.observe(
            s,
            owner,
            "Network.requestWillBeSent",
            &json!({"requestId":"r"}),
        );
        s["network"]["requests"]
            .as_array_mut()
            .unwrap()
            .push(row(owner));
        e.observe(s, owner, "reconcile", &json!({"requestId":"r"}));
    }
    fn extra(e: &mut StatusEvidence, s: &mut Value, owner: &str, status: Value) {
        e.observe(
            s,
            owner,
            "Network.responseReceivedExtraInfo",
            &json!({"requestId":"r","statusCode":status}),
        );
    }
    #[test]
    fn extra_before_start_and_after_terminal_use_exact_namespace() {
        let mut e = StatusEvidence::default();
        let mut s = state();
        extra(&mut e, &mut s, "old", json!(201));
        start(&mut e, &mut s, "new");
        assert!(s["network"]["requests"][0]["status"].is_null());
        start(&mut e, &mut s, "old");
        assert_eq!(s["network"]["requests"][1]["status"], 201);
        s["network"]["requests"][0]["state"] = json!("complete");
        extra(&mut e, &mut s, "new", json!(202));
        assert_eq!(s["network"]["requests"][0]["status"], 202);
        assert_eq!(
            s["network"]["requests"][0]["status_source"],
            "response-received-extra-info"
        );
    }
    #[test]
    fn response_before_request_or_malformed_response_blocks_fallback() {
        for before_start in [false, true] {
            let mut e = StatusEvidence::default();
            let mut s = state();
            if !before_start {
                start(&mut e, &mut s, "o");
            }
            e.observe(
                &mut s,
                "o",
                "Network.responseReceived",
                &json!({"requestId":"r","response":null}),
            );
            if before_start {
                start(&mut e, &mut s, "o");
            }
            extra(&mut e, &mut s, "o", json!(200));
            assert!(s["network"]["requests"][0]["status"].is_null());
            assert_eq!(s["network"]["requests"][0]["wire_status"], 200);
        }
    }
    #[test]
    fn response_and_cached_status_are_authoritative() {
        let mut e = StatusEvidence::default();
        let mut s = state();
        start(&mut e, &mut s, "o");
        extra(&mut e, &mut s, "o", json!(304));
        assert!(s["network"]["requests"][0]["status"].is_null());
        assert_eq!(s["network"]["requests"][0]["wire_status"], 304);
        s["network"]["requests"][0]["status"] = json!(200);
        s["network"]["requests"][0]["status_source"] = json!("response-received");
        e.observe(&mut s, "o", "reconcile", &json!({"requestId":"r"}));
        assert_eq!(s["network"]["requests"][0]["status"], 200);
        extra(&mut e, &mut s, "o", json!(304));
        assert_eq!(s["network"]["requests"][0]["status"], 200);
        assert!(s["network"]["requests"][0]["wire_status"].is_null());
    }
    #[test]
    fn duplicates_redirects_reuse_and_malformed_values_refuse_or_retract() {
        for invalid in [
            Value::Null,
            json!(0),
            json!(600),
            json!(200.5),
            json!("200"),
        ] {
            let mut e = StatusEvidence::default();
            let mut s = state();
            start(&mut e, &mut s, "o");
            extra(&mut e, &mut s, "o", invalid);
            assert!(s["network"]["requests"][0]["status"].is_null());
        }
        for method in [
            "Network.responseReceivedExtraInfo",
            "Network.requestWillBeSent",
        ] {
            let mut e = StatusEvidence::default();
            let mut s = state();
            start(&mut e, &mut s, "o");
            extra(&mut e, &mut s, "o", json!(200));
            assert_eq!(s["network"]["requests"][0]["status"], 200);
            e.observe(
                &mut s,
                "o",
                method,
                &json!({"requestId":"r","statusCode":200}),
            );
            assert!(s["network"]["requests"][0]["status"].is_null());
        }
        let mut e = StatusEvidence::default();
        let mut s = state();
        s["network"]["requests"] = json!([row("o")]);
        e.observe(
            &mut s,
            "o",
            "Network.requestWillBeSent",
            &json!({"requestId":"r","redirectResponse":{}}),
        );
        extra(&mut e, &mut s, "o", json!(200));
        assert!(s["network"]["requests"][0]["status"].is_null());
    }
    #[test]
    fn lost_history_and_tombstone_saturation_retract_all_fallbacks() {
        for overflow in [false, true] {
            let mut e = StatusEvidence::default();
            let mut s = state();
            start(&mut e, &mut s, "o");
            extra(&mut e, &mut s, "o", json!(200));
            if overflow {
                for n in 0..LIMIT {
                    e.observe(
                        &mut s,
                        "o",
                        "Network.requestWillBeSent",
                        &json!({"requestId":format!("id{n}")}),
                    );
                }
                assert!(e.saturated);
            } else {
                s["network"]["dropped"] = json!(1);
                e.observe(&mut s, "o", "reconcile", &json!({"requestId":"r"}));
            }
            assert!(s["network"]["requests"][0]["status"].is_null());
            assert!(s["network"]["requests"][0]["wire_status"].is_null());
        }
    }
}
