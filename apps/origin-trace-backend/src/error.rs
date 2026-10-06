use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;

/// Stable reasons are assigned where the failure is known, never from prose.
/// Unspecified deliberately preserves uncertainty in unmigrated legacy paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    Unspecified,
    InvalidRequest,
    StateConflict,
    ProtocolError,
    StaleGeneration,
    TargetUnavailable,
    DependencyUnavailable,
    ResourceLimit,
    Timeout,
    Cancelled,
    CommandOutcomeUnknown,
    ApplicationFailed,
}
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    RequestBody,
    Worker,
    CommandExchange,
}
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    Timeout,
    Disconnected,
    TransportFailure,
    InvalidReply,
}
// No arbitrary strings, identifiers, JSON, or diagnostics can enter details.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Details {
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<Phase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cause: Option<Cause>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_generation: Option<u64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Reason {
    pub code: Code,
    details: Details,
}
impl Reason {
    pub fn new(code: Code) -> Self {
        Self {
            code,
            details: Details::default(),
        }
    }
    pub fn at(code: Code, phase: Phase) -> Self {
        Self {
            code,
            details: Details {
                phase: Some(phase),
                ..Details::default()
            },
        }
    }
    pub fn uncertain(cause: Cause) -> Self {
        Self {
            code: Code::CommandOutcomeUnknown,
            details: Details {
                phase: Some(Phase::CommandExchange),
                cause: Some(cause),
                ..Details::default()
            },
        }
    }
    pub fn stale(expected: u64, current: u64) -> Self {
        Self {
            code: Code::StaleGeneration,
            details: Details {
                expected_generation: Some(expected),
                current_generation: Some(current),
                ..Details::default()
            },
        }
    }
    /// Add the same bounded reason to an existing application failure envelope.
    /// Keep that envelope's human text, outcome and HTTP transport unchanged.
    pub fn annotate(self, value: &mut Value) {
        value["code"] = serde_json::to_value(self.code).expect("error code");
        value["details"] = serde_json::to_value(self.details).expect("error details");
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Error {
    #[serde(skip)]
    pub status: u16,
    #[serde(rename = "error")]
    pub message: String,
    #[serde(flatten)]
    pub reason: Reason,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            reason: Reason::new(Code::Unspecified),
        }
    }
    pub fn with_code(mut self, code: Code) -> Self {
        self.reason = Reason::new(code);
        self
    }
    pub fn with_reason(mut self, reason: Reason) -> Self {
        self.reason = reason;
        self
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(400, message).with_code(Code::InvalidRequest)
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(409, message).with_code(Code::StateConflict)
    }
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(422, message).with_code(Code::ProtocolError)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(500, error.to_string())
    }
}
impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::bad(error.to_string())
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(self),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reason_codes_match_the_embedded_offline_contract() {
        let codes = [
            Code::Unspecified,
            Code::InvalidRequest,
            Code::StateConflict,
            Code::ProtocolError,
            Code::StaleGeneration,
            Code::TargetUnavailable,
            Code::DependencyUnavailable,
            Code::ResourceLimit,
            Code::Timeout,
            Code::Cancelled,
            Code::CommandOutcomeUnknown,
            Code::ApplicationFailed,
        ];
        assert_eq!(
            serde_json::to_value(codes).unwrap(),
            crate::validation::SPEC["components"]["schemas"]["ErrorCode"]["enum"]
        );
    }
    #[test]
    fn legacy_text_and_status_do_not_classify_reasons() {
        let error = Error::new(408, "secret: cancelled stale target timed out");
        assert_eq!(error.status, 408);
        assert_eq!(
            error.to_string(),
            "secret: cancelled stale target timed out"
        );
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({
                "error":"secret: cancelled stale target timed out", "code":"unspecified", "details":{}
            })
        );
    }
    #[test]
    fn details_are_bounded_and_separate_from_human_text() {
        let error =
            Error::conflict("private diagnostic").with_reason(Reason::uncertain(Cause::Timeout));
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(
            value["details"],
            json!({"phase":"command_exchange","cause":"timeout"})
        );
        assert_eq!(value["code"], "command_outcome_unknown");
        assert!(value.get("retryable").is_none());
        assert!(!value["details"].to_string().contains("private"));
    }
}
