//! Read-only compatibility state for historical capture consumers.
//! No browser connection, transport process, injected script or CDP command exists.
mod api_catalog;
mod network_request;
use crate::{
    config::Options,
    error::{Code, Error, Result},
};
pub(crate) use network_request::NetworkRequestSelection;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

pub struct Debugger {
    state: Mutex<Value>,
}
impl Debugger {
    pub fn new(_options: &Options) -> Arc<Self> {
        let mut state: Value =
            serde_json::from_str(include_str!("../../assets/debugger-empty.json"))
                .expect("Historical capture state");
        state["state"] = json!("unavailable");
        state["error"] = json!("CDP support has been removed. Native-only capture is available.");
        state["network"]["capture_enabled"] = json!(false);
        state["network"]["capture_epoch"] = json!(0);
        state["network"]["instance_id"] = json!(format!(
            "{}:{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Arc::new(Self {
            state: Mutex::new(state),
        })
    }
    pub fn snapshot(&self) -> Value {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn instance_id(&self) -> Value {
        self.state.lock().unwrap_or_else(|e| e.into_inner())["network"]["instance_id"].clone()
    }
    pub fn session_context(&self) -> Value {
        crate::session_context::debugger(&self.snapshot())
    }
    pub async fn stop(&self) {}
    pub async fn source(&self, _id: &str) -> Result<Value> {
        Err(removed())
    }
    #[cfg(test)]
    pub async fn action(&self, _request: &Value) -> Result<Value> {
        Err(removed())
    }
    #[cfg(test)]
    fn update(&self, edit: impl FnOnce(&mut Value)) {
        edit(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
    }
}
pub fn removed() -> Error {
    Error::new(
        410,
        "CDP functionality was removed; this operation has no native replacement.",
    )
    .with_code(Code::DebuggerUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[tokio::test]
    async fn browser_actions_are_removed_and_cannot_start_transport() {
        let state = Debugger::new(&Options::parse_from(["test"]));
        assert_eq!(state.snapshot()["state"], "unavailable");
        assert_eq!(state.snapshot()["network"]["capture_enabled"], false);
        for action in ["connect", "evaluate", "resume", "network", "wasm-live"] {
            assert!(state.action(&json!({"action":action})).await.is_err());
        }
        assert!(state.source("1").await.is_err());
    }
}
