use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_BODY_BYTES: usize = 128 * 1024;
const MAX_POINTER_BYTES: usize = 256;
const MAX_VALUE_BYTES: usize = 4 * 1024;

#[derive(Deserialize)]
pub(crate) struct Request {
    pub(crate) operation: String,
    pub(crate) body: String,
    pub(crate) pointer: String,
}

#[derive(Serialize)]
pub(crate) struct Response {
    schema: &'static str,
    status: &'static str,
    value: Option<String>,
}

fn response(status: &'static str, value: Option<String>) -> Response {
    Response {
        schema: "reb-request-field-v1",
        status,
        value,
    }
}

pub(crate) fn extract(request: Request) -> Response {
    if request.operation != "request_field" {
        return response("invalid_request", None);
    }
    if request.body.len() > MAX_BODY_BYTES {
        return response("body_too_large", None);
    }
    if request.pointer.is_empty()
        || request.pointer.len() > MAX_POINTER_BYTES
        || !request.pointer.starts_with('/')
        || request.pointer.split('/').skip(1).any(|part| {
            let mut chars = part.chars();
            while let Some(character) = chars.next() {
                if character == '~' && !matches!(chars.next(), Some('0' | '1')) {
                    return true;
                }
            }
            false
        })
    {
        return response("invalid_pointer", None);
    }
    let Ok(document) = serde_json::from_str::<Value>(&request.body) else {
        return response("invalid_json", None);
    };
    let Some(value) = document.pointer(&request.pointer) else {
        return response("missing", None);
    };
    let Ok(serialized) = serde_json::to_string(value) else {
        return response("invalid_json", None);
    };
    if serialized.len() > MAX_VALUE_BYTES {
        return response("value_too_large", None);
    }
    response("available", Some(serialized))
}

#[cfg(test)]
mod tests {
    use super::{Request, extract};

    fn field(body: &str, pointer: &str) -> super::Response {
        extract(Request {
            operation: "request_field".into(),
            body: body.into(),
            pointer: pointer.into(),
        })
    }

    #[test]
    fn extracts_escaped_pointer_and_distinguishes_missing_from_null() {
        let found = field(r#"{"a/b":{"~key":null}}"#, "/a~1b/~0key");
        assert_eq!(found.status, "available");
        assert_eq!(found.value.as_deref(), Some("null"));
        assert_eq!(field(r#"{"a":1}"#, "/absent").status, "missing");
    }

    #[test]
    fn fails_closed_on_malformed_or_excessive_input() {
        assert_eq!(field("{", "/a").status, "invalid_json");
        assert_eq!(field("{}", "/a~2b").status, "invalid_pointer");
        assert_eq!(field("{}", "a").status, "invalid_pointer");
        assert_eq!(
            field(&"x".repeat(128 * 1024 + 1), "/a").status,
            "body_too_large"
        );
        let oversized = format!(r#"{{"a":"{}"}}"#, "x".repeat(4 * 1024));
        assert_eq!(field(&oversized, "/a").status, "value_too_large");
    }
}
