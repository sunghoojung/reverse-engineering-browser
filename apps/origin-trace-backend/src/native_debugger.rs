//! Native debugger surface, docs/product/native-debugger-v1.md. Phase 1
//! threads, watch rules and observations are served here; every pausing field
//! belongs to the peer of protocol/native-debugger-pause-v1.md. No Brave build
//! serves that peer, so it reports `unsupported` and every action is refused
//! before anything is sent.

use std::path::Path;

use serde_json::{Value, json};

use crate::debugger_observation;
use crate::error::Result;
use crate::native_debugger_pause::NativeDebuggerPause;
use crate::validation;

pub const LEASE_LIMIT_MS: u64 = 60_000;

/// `console` is the Console listing; `watch` is None while a Console action
/// holds the session. `query` selects which observation records are listed,
/// and `pause` owns every pausing field.
pub fn state(
    store: &Path,
    console: &Value,
    watch: Option<Value>,
    query: &debugger_observation::Query,
    pause: &NativeDebuggerPause,
) -> Result<Value> {
    let scan = debugger_observation::scan(store)?;
    let recent = debugger_observation::recent(store, query, &scan)?;
    let (observed, budget_gaps) = scan.observed();
    let frames: Vec<Value> = console["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|target| {
            json!({"target_id": target["id"], "label": target["label"],
                "origin": target["origin"], "frame": target["frame"],
                "out_of_process": target.get("out_of_process").cloned().unwrap_or(json!(false))})
        })
        .collect();
    let watch = match watch {
        None => json!({"state": "busy", "armed": null}),
        Some(Value::Null) => json!({"state": "none", "armed": null}),
        Some(armed) => json!({"state": "armed", "armed": armed}),
    };
    let mut value = json!({
        "contract_version": 1,
        "experiment_flag": "--reb-native-debugger",
        "policy": "approved",
        "detectable": true,
        "lease_limit_ms": LEASE_LIMIT_MS,
        "threads": {
            "console": console["binding_state"].as_str().or(console["state"].as_str()).unwrap_or("idle"),
            "frames": frames,
            "workers": debugger_observation::workers(store)?,
            "observed": observed,
        },
        "watch": watch,
        "observations": recent.records,
        "observations_malformed": recent.malformed,
        "observations_query": recent.query,
        "observation_budget_gaps": budget_gaps,
    });
    // The peer owns every pausing field, so an unreadable peer cannot leave a
    // stale document, breakpoint or lease behind in this view.
    let Value::Object(pausing) = pause.state() else {
        unreachable!("the pausing half is always an object");
    };
    for (key, field) in pausing {
        value[key] = field;
    }
    validation::schema("NativeDebuggerState", &value, 500)?;
    Ok(value)
}

pub fn action(value: &Value, pause: &NativeDebuggerPause) -> Result<Value> {
    validation::schema("NativeDebuggerAction", value, 400)?;
    pause.action(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_unsupported_and_actions_send_nothing() {
        let store = tempfile::tempdir().unwrap();
        let path = store.path().join("events.jsonl");
        let line = |kind: &str, category: &str, sequence: u64, frame: &str, payload: &[u8]| {
            json!({"protocol_version":3,"category":category,"type":kind,"session_id":"1",
                "sequence_number":sequence.to_string(),"monotonic_time_ns":"1","navigation_id":"0",
                "frame_id":frame,"artifact_id":"0","request_id":"0","parent_event_id":"0","process_id":2,
                "payload_encoding":"hex","payload":hex::encode(payload),"payload_size":payload.len(),
                "loader_kind":17})
            .to_string()
        };
        let mut thrown = vec![1, 0, 128, 0, 2, 8];
        thrown.resize(80, 0);
        thrown.push(1);
        thrown.resize(128, 0);
        let mut refused = thrown.clone();
        refused[80] = 9;
        let mut timer = thrown.clone();
        timer[80..84].copy_from_slice(&[1, 1, 0, 0]);
        let lines = [
            line("request_initiated", "network", 1, "77", &[]),
            line("exception_observation", "runtime", 2, "9", &thrown),
            line("exception_observation", "runtime", 3, "9", &refused),
            line("request_initiated", "network", 4, "77", &[]),
            line("timer_observation", "runtime", 5, "10", &timer),
            line("gap", "runtime", 6, "10", b"debugger_observation_budget"),
            line(
                "gap",
                "vm",
                7,
                "10",
                b"native_wasm_dispatch_budget_incomplete",
            ),
        ];
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let console = json!({"state":"ready","binding_state":"connected","targets":[
            {"id":"22","label":"top #22","origin":"https://a.test","frame":"top","main_frame":true},
            {"id":"23","label":"frame #23","origin":"https://b.test","frame":"child","out_of_process":true}]});
        let every = debugger_observation::Query::default();
        let pause = NativeDebuggerPause::new(None);
        let current = state(&path, &console, Some(Value::Null), &every, &pause).unwrap();
        assert_eq!(current["availability"], "unsupported");
        assert_eq!(current["lease"], Value::Null);
        assert_eq!(current["threads"]["frames"][1]["out_of_process"], true);
        assert_eq!(current["watch"]["state"], "none");
        assert_eq!(current["observations"][0]["detail"]["phase"], "scheduled");
        assert_eq!(current["observations"][1]["detail"]["kind"], "uncaught");
        assert_eq!(current["observations"].as_array().unwrap().len(), 2);
        assert_eq!(current["observations_malformed"], 1);
        assert_eq!(current["observations_query"]["scope"], "store");
        assert_eq!(current["observations_query"]["next_before"], Value::Null);
        assert_eq!(current["threads"]["workers"][0]["kind"], "dedicated_worker");
        assert_eq!(current["threads"]["workers"][0]["requests"], 2);
        // Native frames newest first, counted from decodable records only.
        let observed = &current["threads"]["observed"];
        assert_eq!(observed[0]["frame_id"], "10");
        assert_eq!(observed[1]["frame_id"], "9");
        assert_eq!(observed[1]["records"], 1);
        assert_eq!(observed[1]["last_sequence"], "2");
        // Only the debugger's own budget gap, not another category's.
        let gaps = current["observation_budget_gaps"].as_array().unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0]["sequence_number"], "6");

        // One type, one exact frame, and a cursor that pages older records.
        let query = |kind, frame: Option<u64>, before, limit| debugger_observation::Query {
            kind,
            thread: frame.map(|frame| debugger_observation::Thread {
                session: 1,
                process: 2,
                frame,
            }),
            before,
            limit,
        };
        let read = |query| state(&path, &console, Some(Value::Null), &query, &pause).unwrap();
        let exceptions = read(query(Some("exception_observation"), None, None, 32));
        assert_eq!(exceptions["observations"].as_array().unwrap().len(), 1);
        assert_eq!(
            exceptions["observations_query"]["type"],
            "exception_observation"
        );
        let framed = read(query(None, Some(10), None, 32));
        assert_eq!(framed["observations"].as_array().unwrap().len(), 1);
        assert_eq!(framed["observations_query"]["thread"]["frame_id"], "10");
        assert_eq!(
            read(query(None, Some(11), None, 32))["observations"],
            json!([])
        );
        let newest = read(query(None, None, None, 1));
        assert_eq!(newest["observations"][0]["sequence_number"], "5");
        let older = newest["observations_query"]["next_before"]
            .as_str()
            .unwrap();
        let page = read(query(None, None, Some(older.parse().unwrap()), 1));
        assert_eq!(
            page["observations"],
            json!([]),
            "the next older record is refused"
        );
        assert_eq!(page["observations_malformed"], 1);
        let busy = state(&path, &json!({}), None, &every, &pause).unwrap();
        assert_eq!(busy["watch"]["state"], "busy");
        assert_eq!(busy["threads"]["console"], "idle");
        let error = action(&json!({"action":"resume","target_id":"22","lease_id":"1"}), &pause)
            .unwrap_err();
        assert_eq!(error.status, 503, "no peer is configured");
        assert!(action(&json!({"action":"resume"}), &pause).unwrap_err().status == 400);
        assert!(
            action(
                &json!({"action":"set_breakpoint","target_id":"22",
                "script_id":7,"line":1,"column":0}),
                &pause
            )
            .unwrap_err()
            .status
                == 400,
            "a breakpoint needs confirm_pause"
        );
    }
}
