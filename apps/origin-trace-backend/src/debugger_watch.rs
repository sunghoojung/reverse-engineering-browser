//! Rules for the Console `watch` command, protocol/native-debugger-observation-v1.md.

use serde_json::Value;

use crate::error::{Error, Result};
use crate::validation;

const REQUEST_RULES: usize = 8;
const EVENT_RULES: usize = 16;
const DOM_NODES: usize = 4;
const URL_BYTES: usize = 256;
const EVENT_BYTES: usize = 27;

fn keys(value: &Value, allowed: &[&str], required: &[&str], label: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::bad(format!("{label} must be an object")))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !object.contains_key(*key))
    {
        return Err(Error::bad(format!("{label} shape is invalid")));
    }
    Ok(())
}

fn list<'a>(value: &'a Value, limit: usize, label: &str) -> Result<&'a [Value]> {
    match value {
        Value::Null => Ok(&[]),
        Value::Array(items) if items.len() <= limit => Ok(items),
        _ => Err(Error::bad(format!(
            "{label} must be a list of at most {limit}"
        ))),
    }
}

fn flag(value: &Value, label: &str) -> Result<()> {
    if value.is_null() || value.is_boolean() {
        Ok(())
    } else {
        Err(Error::bad(format!("{label} must be true or false")))
    }
}

/// Refuses any rule set the renderer could not hold exactly.
pub fn validate(rules: &Value) -> Result<()> {
    keys(
        rules,
        &["requests", "events", "timers", "csp", "exceptions", "dom"],
        &[],
        "Watch rules",
    )?;
    for rule in list(&rules["requests"], REQUEST_RULES, "Request rules")? {
        keys(
            rule,
            &["url_contains", "method"],
            &["url_contains"],
            "Request rule",
        )?;
        validation::text(
            &rule["url_contains"],
            "url_contains",
            URL_BYTES,
            false,
            false,
        )?;
        if let Some(method) = rule.get("method")
            && !method.as_str().is_some_and(|m| {
                (1..=16).contains(&m.len()) && m.bytes().all(|b| b.is_ascii_uppercase())
            })
        {
            return Err(Error::bad(
                "Request rule method must be 1 to 16 uppercase letters",
            ));
        }
    }
    let events = list(&rules["events"], EVENT_RULES, "Event rules")?;
    for (index, name) in events.iter().enumerate() {
        let valid = name.as_str().is_some_and(|n| {
            (1..=EVENT_BYTES).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_graphic())
        });
        if !valid || events[..index].contains(name) {
            return Err(Error::bad(
                "Event rules are 1 to 27 printable ASCII bytes, each once",
            ));
        }
    }
    flag(&rules["timers"], "timers")?;
    flag(&rules["csp"], "csp")?;
    if !(rules["exceptions"].is_null()
        || ["off", "uncaught", "all"].contains(&rules["exceptions"].as_str().unwrap_or("")))
    {
        return Err(Error::bad("exceptions must be off, uncaught or all"));
    }
    for node in list(&rules["dom"], DOM_NODES, "DOM rules")? {
        keys(
            node,
            &["handle", "attributes", "subtree", "removal"],
            &["handle"],
            "DOM rule",
        )?;
        validation::canonical(&node["handle"], 64, true, "DOM rule handle")?;
        for field in ["attributes", "subtree", "removal"] {
            flag(&node[field], field)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bounded_rules_pass_and_anything_wider_is_refused() {
        validate(
            &json!({"requests":[{"url_contains":"/api/x","method":"POST"}],
            "events":["click"],"timers":true,"csp":true,"exceptions":"uncaught",
            "dom":[{"handle":"7","attributes":true}]}),
        )
        .unwrap();
        validate(&json!({})).unwrap();
        for rules in [
            json!({"requests":[{"url_contains":""}]}),
            json!({"requests":[{"url_contains":"x","method":"post"}]}),
            json!({"requests":[{"url_contains":"x","regex":".*"}]}),
            json!({"requests": vec![json!({"url_contains":"x"}); 9]}),
            json!({"events":["click","click"]}),
            json!({"events":["cl ick"]}),
            json!({"events":["x".repeat(28)]}),
            json!({"exceptions":"caught"}),
            json!({"dom":[{"handle":"0"}]}),
            json!({"dom": vec![json!({"handle":"1"}); 5]}),
            json!({"selector":"#login"}),
        ] {
            assert!(validate(&rules).is_err(), "{rules}");
        }
    }
}
