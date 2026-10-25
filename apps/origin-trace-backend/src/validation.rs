use crate::error::{Error, Reason, Result};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, LazyLock, Mutex},
};

pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
pub static SPEC: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../protocol/openapi.json"))
        .expect("versioned OpenAPI document")
});
static VALIDATORS: LazyLock<Mutex<BTreeMap<String, Arc<jsonschema::Validator>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
pub fn schema(name: &str, value: &Value, status: u16) -> Result<()> {
    let validator = {
        let mut validators = VALIDATORS
            .lock()
            .map_err(|_| Error::new(500, "Contract validator is unavailable"))?;
        if let Some(validator) = validators.get(name) {
            validator.clone()
        } else {
            if SPEC["components"]["schemas"].get(name).is_none() {
                return Err(Error::new(500, format!("Unknown contract: {name}")));
            }
            let document = json!({"$ref":format!("#/components/schemas/{name}"),"components":SPEC["components"]});
            let validator = Arc::new(
                jsonschema::validator_for(&document).map_err(|e| Error::new(500, e.to_string()))?,
            );
            validators.insert(name.into(), validator.clone());
            validator
        }
    };
    validator.validate(value).map_err(|e| {
        if status == 400
            && let Some(guidance) =
                crate::action_guidance::action_guidance(&SPEC["components"]["schemas"][name], value)
        {
            return Error::bad(format!(
                "{name} action body is invalid; see allowed_actions and missing_fields"
            ))
            .with_reason(Reason::action(guidance));
        }
        Error::new(status, format!("{name} contract is invalid: {e}"))
    })
}
/// Admission metadata lives beside each action contract so extensions cannot
/// silently inherit a different target prerequisite from a dispatcher list.
pub fn requires_live_target(action: &str) -> bool {
    SPEC["components"]["schemas"]["DebuggerAction"]["oneOf"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|variant| variant["properties"]["action"]["const"] == action)
        .is_none_or(|variant| variant["x-reb-requires-live-target"] != false)
}

pub fn fields(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::bad(format!("{label} must be an object")))?;
    let keys: BTreeSet<_> = object.keys().map(String::as_str).collect();
    if keys != expected.iter().copied().collect() {
        return Err(Error::bad(format!("{label} shape is invalid")));
    }
    Ok(())
}
pub fn integer(value: &Value, label: &str, minimum: u64, maximum: u64) -> Result<u64> {
    value
        .as_u64()
        .filter(|n| *n >= minimum && *n <= maximum)
        .ok_or_else(|| Error::bad(format!("{label} is invalid")))
}
pub fn canonical(value: &Value, bits: u32, nonzero: bool, label: &str) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or_else(|| Error::bad(format!("{label} must be a canonical unsigned integer")))?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::bad(format!(
            "{label} must be a canonical unsigned integer"
        )));
    }
    let n = text
        .parse::<u64>()
        .map_err(|_| Error::bad(format!("{label} exceeds its integer range")))?;
    if (bits == 32 && n > u64::from(u32::MAX)) || (nonzero && n == 0) {
        return Err(Error::bad(format!("{label} is outside its range")));
    }
    Ok(n)
}
pub fn text<'a>(
    value: &'a Value,
    label: &str,
    max: usize,
    empty: bool,
    controls: bool,
) -> Result<&'a str> {
    let text = value
        .as_str()
        .ok_or_else(|| Error::bad(format!("{label} must be text")))?;
    if (!empty && text.is_empty())
        || text.len() > max
        || (!controls && text.chars().any(char::is_control))
    {
        return Err(Error::bad(format!(
            "{label} is empty, oversized, or contains controls"
        )));
    }
    Ok(text)
}
pub fn truncate(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].into()
}
pub fn variable_name(name: &str) -> bool {
    let mut chars = name.bytes();
    chars
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && chars.all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(MAX_SAFE_INTEGER)) as u64
}
