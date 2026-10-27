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

#[cfg(test)]
mod tests {
    use super::SPEC;
    use serde_json::Value;
    use std::{collections::BTreeSet, path::Path};

    fn walk<'a>(value: &'a Value, visit: &mut impl FnMut(&str, &'a Value)) {
        match value {
            Value::Object(map) => {
                for (key, item) in map {
                    visit(key, item);
                    walk(item, visit);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, visit)),
            _ => {}
        }
    }
    fn schema_refs(value: &Value) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        walk(value, &mut |key, item| {
            if let (Some(name), "$ref") = (
                item.as_str()
                    .and_then(|r| r.strip_prefix("#/components/schemas/")),
                key,
            ) {
                let name = name.split('/').next().unwrap_or(name);
                names.insert(name.replace("~1", "/").replace("~0", "~"));
            }
        });
        names
    }
    fn rust_sources(dir: &Path, out: &mut String) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push_str(&std::fs::read_to_string(path).unwrap());
            }
        }
    }

    // A deleted implementation must take its contract with it. Every source
    // citation resolves, and every component schema is reachable from a
    // route or from a `validation::schema("Name", ...)` call in the backend.
    #[test]
    fn contract_sources_exist_and_every_schema_is_reachable() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut missing = Vec::new();
        walk(&SPEC, &mut |key, item| {
            let paths: Vec<&str> = match key {
                "x-source" => match item {
                    Value::String(path) => vec![path],
                    Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
                    _ => vec![],
                },
                "sources" => item
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|source| source["path"].as_str())
                    .collect(),
                _ => vec![],
            };
            for path in paths {
                let file = path.split('#').next().unwrap_or(path);
                if !root.join(file).exists() {
                    missing.push(path.to_owned());
                }
            }
        });
        assert!(missing.is_empty(), "missing contract sources: {missing:?}");

        let schemas = SPEC["components"]["schemas"].as_object().unwrap();
        let mut code = String::new();
        rust_sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut code,
        );
        let mut reachable: BTreeSet<String> = schemas
            .keys()
            .filter(|name| code.contains(&format!("schema(\"{name}\"")))
            .cloned()
            .collect();
        let mut roots = SPEC.clone();
        roots["components"]
            .as_object_mut()
            .unwrap()
            .remove("schemas");
        reachable.extend(schema_refs(&roots));
        let mut frontier: Vec<String> = reachable.iter().cloned().collect();
        while let Some(name) = frontier.pop() {
            for next in schema_refs(&schemas[&name]) {
                if reachable.insert(next.clone()) {
                    frontier.push(next);
                }
            }
        }
        let unknown: Vec<_> = reachable
            .iter()
            .filter(|n| !schemas.contains_key(*n))
            .collect();
        assert!(
            unknown.is_empty(),
            "unresolved schema references: {unknown:?}"
        );
        let unreachable: Vec<_> = schemas.keys().filter(|n| !reachable.contains(*n)).collect();
        assert!(
            unreachable.is_empty(),
            "unreferenced schemas: {unreachable:?}"
        );
    }
}
