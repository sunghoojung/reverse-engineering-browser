//! Pausing native debugger surface, docs/product/native-debugger-v1.md.
//! No Brave build serves the peer yet, so state is `unsupported` and every
//! action is refused before anything is sent.

use serde_json::{Value, json};

use crate::error::{Code, Error, Result};
use crate::validation;

pub const LEASE_LIMIT_MS: u64 = 60_000;

pub fn state() -> Result<Value> {
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
        let current = state().unwrap();
        assert_eq!(current["availability"], "unsupported");
        assert_eq!(current["lease"], Value::Null);
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
