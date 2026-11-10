//! Native debugger surface, docs/product/native-debugger-v1.md. Phase 1
//! threads, watch rules and observations are served; no Brave build serves the
//! pausing peer yet, so it is `unsupported` and every action is refused before
//! anything is sent.

use std::path::Path;

use serde_json::{Value, json};

use crate::debugger_observation;
use crate::error::{Code, Error, Result};
use crate::validation;

pub const LEASE_LIMIT_MS: u64 = 60_000;

/// `console` is the Console listing; `watch` is None while a Console action
/// holds the session.
pub fn state(store: &Path, console: &Value, watch: Option<Value>) -> Result<Value> {
    let (observations, malformed) = debugger_observation::recent(store)?;
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
    let value = json!({
        "contract_version": 1,
        "availability": "unsupported",
        "reason": "browser_debugger_unsupported",
        "experiment_flag": "--reb-native-debugger",
        "policy": "proposed_pending_approval",
        "detectable": true,
        "lease_limit_ms": LEASE_LIMIT_MS,
        "lease": Value::Null,
        "paused": false,
        "breakpoints": [],
        "threads": {
            "console": console["binding_state"].as_str().or(console["state"].as_str()).unwrap_or("idle"),
            "frames": frames,
            "workers": debugger_observation::workers(store)?,
        },
        "watch": watch,
        "observations": observations,
        "observations_malformed": malformed,
    });
    validation::schema("NativeDebuggerState", &value, 500)?;
    Ok(value)
}

pub fn action(value: &Value) -> Result<Value> {
    validation::schema("NativeDebuggerAction", value, 400)?;
    Err(Error::new(
        503,
        "No Brave build serves the native debugger. Nothing was sent; no page paused, stepped or resumed.",
    )
    .with_code(Code::DependencyUnavailable))
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
        std::fs::write(
            &path,
            [
                line("request_initiated", "network", 1, "77", &[]),
                line("exception_observation", "runtime", 2, "9", &thrown),
                line("exception_observation", "runtime", 3, "9", &refused),
                line("request_initiated", "network", 4, "77", &[]),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let console = json!({"state":"ready","binding_state":"connected","targets":[
            {"id":"22","label":"top #22","origin":"https://a.test","frame":"top","main_frame":true},
            {"id":"23","label":"frame #23","origin":"https://b.test","frame":"child","out_of_process":true}]});
        let current = state(&path, &console, Some(Value::Null)).unwrap();
        assert_eq!(current["availability"], "unsupported");
        assert_eq!(current["lease"], Value::Null);
        assert_eq!(current["threads"]["frames"][1]["out_of_process"], true);
        assert_eq!(current["watch"]["state"], "none");
        assert_eq!(current["observations"][0]["detail"]["kind"], "uncaught");
        assert_eq!(current["observations"].as_array().unwrap().len(), 1);
        assert_eq!(current["observations_malformed"], 1);
        assert_eq!(current["threads"]["workers"][0]["kind"], "dedicated_worker");
        assert_eq!(current["threads"]["workers"][0]["requests"], 2);
        let busy = state(&path, &json!({}), None).unwrap();
        assert_eq!(busy["watch"]["state"], "busy");
        assert_eq!(busy["threads"]["console"], "idle");
        let error = action(
            &json!({"action":"resume","target_id":"22","document_epoch":"3","lease_id":"1"}),
        )
        .unwrap_err();
        assert_eq!(error.status, 503);
        assert!(action(&json!({"action":"resume"})).unwrap_err().status == 400);
        assert!(
            action(
                &json!({"action":"set_breakpoint","target_id":"22","document_epoch":"3",
                "script_id":7,"line":1,"column":0})
            )
            .unwrap_err()
            .status
                == 400,
            "a breakpoint needs confirm_pause"
        );
    }
}
