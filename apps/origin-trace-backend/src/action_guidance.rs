//! Request guidance contains only names from the versioned contract, never
//! rejected values or validator diagnostics that may contain submitted secrets.
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct ActionGuidance {
    allowed_actions: Vec<String>,
    missing_fields: Vec<String>,
}

pub fn action_guidance(schema: &Value, request: &Value) -> Option<ActionGuidance> {
    let variants = schema.get("oneOf")?.as_array()?;
    let mut allowed = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let action = request.get("action").and_then(Value::as_str);
    for variant in variants {
        let name = variant["properties"]["action"]["const"].as_str()?;
        allowed.insert(name.to_owned());
        if action == Some(name)
            && let Some(required) = variant["required"].as_array()
        {
            for field in required.iter().filter_map(Value::as_str) {
                if request.get(field).is_none() {
                    missing.insert(field.to_owned());
                }
            }
        }
    }
    if request.get("action").is_none() {
        missing.insert("action".to_owned());
    }
    Some(ActionGuidance {
        allowed_actions: allowed.into_iter().collect(),
        missing_fields: missing.into_iter().collect(),
    })
}

/// HTTP errors are untrusted. Accept guidance names only if they occur in the
/// embedded contract; syntactically valid identifiers alone are not an allowlist.
pub fn valid_details(spec: &Value, details: &Value) -> bool {
    let mut actions = BTreeSet::new();
    let mut fields = BTreeSet::new();
    for schema in spec["components"]["schemas"]
        .as_object()
        .into_iter()
        .flat_map(|s| s.values())
    {
        for variant in schema["oneOf"].as_array().into_iter().flatten() {
            if let Some(action) = variant["properties"]["action"]["const"].as_str() {
                actions.insert(action);
                fields.extend(
                    variant["required"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str),
                );
            }
        }
    }
    [("allowed_actions", actions), ("missing_fields", fields)]
        .iter()
        .all(|(key, names)| {
            details.get(key).is_none_or(|value| {
                value.as_array().is_some_and(|items| {
                    items
                        .iter()
                        .all(|item| item.as_str().is_some_and(|name| names.contains(name)))
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn contract_guidance_and_live_metadata_stay_explicit_and_bounded() {
        let spec = &crate::validation::SPEC;
        let schema = serde_json::json!({"$ref":"#/components/schemas/ErrorDetails","components":spec["components"]});
        let validator = jsonschema::validator_for(&schema).unwrap();
        for request in spec["components"]["schemas"].as_object().unwrap().values() {
            if let Some(guidance) = action_guidance(request, &serde_json::json!({})) {
                let details = serde_json::to_value(guidance).unwrap();
                assert!(validator.is_valid(&details), "{details}");
                assert!(valid_details(spec, &details));
            }
        }
        for variant in spec["components"]["schemas"]["DebuggerAction"]["oneOf"]
            .as_array()
            .unwrap()
        {
            assert!(
                variant["x-reb-requires-live-target"].is_boolean(),
                "Every action must declare live target admission"
            );
        }
        assert!(crate::validation::requires_live_target("pause"));
        assert!(!crate::validation::requires_live_target("clear_console"));
        assert!(crate::validation::requires_live_target("unknown"));
    }
    #[test]
    fn guidance_never_echoes_rejected_values() {
        let schema = &crate::validation::SPEC["components"]["schemas"]["DebuggerAction"];
        let guidance = action_guidance(
            schema,
            &json!({"action":"secret_canary", "credential":"secret_canary"}),
        )
        .unwrap();
        assert!(guidance.allowed_actions.contains(&"pause".to_owned()));
        assert!(
            !serde_json::to_string(&guidance)
                .unwrap()
                .contains("secret_canary")
        );
        let guidance = action_guidance(schema, &json!({"action":"add_watch"})).unwrap();
        assert_eq!(guidance.missing_fields, ["expression"]);
        assert!(!valid_details(
            &crate::validation::SPEC,
            &json!({"allowed_actions":["secret_canary"]})
        ));
        assert!(valid_details(
            &crate::validation::SPEC,
            &serde_json::to_value(guidance).unwrap()
        ));
    }
}
