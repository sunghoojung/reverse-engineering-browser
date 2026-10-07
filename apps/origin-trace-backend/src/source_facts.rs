//! Verified immutable-source adapter. Worker-local IDs never identify another artifact.
use crate::{
    error::{Error, Result},
    evidence, validation,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const FACT_TABLES: [&str; 5] = ["scopes", "bindings", "callables", "regions", "operations"];

pub fn load(root: &Path, session: &str, id: &str) -> Result<(String, Value)> {
    let artifact = evidence::find_artifact(root, id)?;
    if artifact["session_id"] != session {
        return Err(Error::new(
            404,
            "Artifact not found in the requested session",
        ));
    }
    if artifact["kind"] != "javascript" {
        return Err(Error::bad("Artifact is not JavaScript"));
    }
    // Read and hash the entire immutable blob before interpreting even one byte.
    let bytes = evidence::content(root, &artifact, MAX_SOURCE_BYTES)?;
    let source = String::from_utf8(bytes)
        .map_err(|_| Error::bad("Artifact is not valid UTF-8 JavaScript"))?;
    Ok((source, evidence::public_artifact(&artifact)))
}

fn invalid() -> Error {
    // Do not forward worker diagnostics or schema errors containing source values.
    Error::new(
        502,
        "JavaScript source facts worker returned an invalid response",
    )
}

fn valid_range(source: &str, value: &Value) -> bool {
    let start = value["start"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok());
    let end = value["end"].as_u64().and_then(|n| usize::try_from(n).ok());
    matches!((start, end), (Some(start), Some(end)) if start <= end
        && end <= source.len() && source.is_char_boundary(start)
        && source.is_char_boundary(end))
}

fn valid_ranges(source: &str, value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "range" || key.ends_with("_range") {
                // Optional expression ranges (for example `return;`) are null.
                // Required top-level ranges are already checked by the schema.
                value.is_null() || valid_range(source, value)
            } else if key.ends_with("_ranges") {
                value
                    .as_array()
                    .is_some_and(|items| items.iter().all(|v| valid_range(source, v)))
            } else {
                valid_ranges(source, value)
            }
        }),
        Value::Array(items) => items.iter().all(|value| valid_ranges(source, value)),
        _ => true,
    }
}

fn valid_targets(value: &Value, bindings: &BTreeSet<u64>, callables: &BTreeSet<u64>) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "binding_ids" {
                value.as_array().is_some_and(|ids| {
                    ids.iter()
                        .all(|id| id.as_u64().is_some_and(|id| bindings.contains(&id)))
                })
            } else if key == "callable_id" {
                value.as_u64().is_some_and(|id| callables.contains(&id))
            } else {
                valid_targets(value, bindings, callables)
            }
        }),
        Value::Array(items) => items
            .iter()
            .all(|value| valid_targets(value, bindings, callables)),
        _ => true,
    }
}

pub fn validate(source: &str, response: &Value) -> Result<()> {
    validation::schema("JavaScriptSourceFactsWorker", response, 502).map_err(|_| invalid())?;
    if response["source_bytes"].as_u64() != Some(source.len() as u64)
        || !valid_ranges(source, response)
        || response["ok"].as_bool() != Some(response["coverage"]["status"] != "unavailable")
        || (response["coverage"]["truncated"] == true
            && response["coverage"]["status"] == "complete")
    {
        return Err(invalid());
    }
    let mut tables = Vec::new();
    let mut count = 0;
    for table in FACT_TABLES {
        let rows = response[table].as_array().ok_or_else(invalid)?;
        count += rows.len();
        let ids = rows
            .iter()
            .map(|row| row["id"].as_u64().unwrap())
            .collect::<BTreeSet<_>>();
        if ids.len() != rows.len() {
            return Err(invalid());
        }
        tables.push(ids);
    }
    if count > 16384 || (response["coverage"]["status"] == "unavailable" && count != 0) {
        return Err(invalid());
    }
    for (table, field, target, nullable) in [
        ("scopes", "parent_id", 0, true),
        ("bindings", "scope_id", 0, false),
        ("callables", "scope_id", 0, false),
        ("regions", "parent_id", 3, true),
        ("regions", "callable_id", 2, true),
        ("operations", "region_id", 3, false),
    ] {
        for row in response[table].as_array().unwrap() {
            if !(nullable && row[field].is_null())
                && !row[field]
                    .as_u64()
                    .is_some_and(|id| tables[target].contains(&id))
            {
                return Err(invalid());
            }
        }
    }
    // A valid ID alone does not make a valid ownership graph. Parents precede
    // children, enclose their byte ranges, and consume one unique local slot.
    let encloses = |outer: &Value, inner: &Value| {
        outer["start"].as_u64() <= inner["start"].as_u64()
            && outer["end"].as_u64() >= inner["end"].as_u64()
    };
    let mut graph_tables = Vec::new();
    for table in ["scopes", "regions"] {
        let mut prior = BTreeMap::<u64, &Value>::new();
        let mut roots = 0;
        for row in response[table].as_array().unwrap() {
            if let Some(parent) = row["parent_id"].as_u64() {
                if !prior
                    .get(&parent)
                    .is_some_and(|parent| encloses(&parent["range"], &row["range"]))
                {
                    return Err(invalid());
                }
            } else {
                roots += 1;
                if row["kind"] != "program"
                    || row["range"]["start"] != 0
                    || row["range"]["end"] != source.len()
                {
                    return Err(invalid());
                }
            }
            prior.insert(row["id"].as_u64().unwrap(), row);
        }
        if roots != usize::from(!prior.is_empty()) {
            return Err(invalid());
        }
        graph_tables.push(prior);
    }
    if count != 0 && (graph_tables[0].is_empty() || graph_tables[1].is_empty()) {
        return Err(invalid());
    }
    for table in ["bindings", "callables"] {
        for row in response[table].as_array().unwrap() {
            let scope = graph_tables[0][&row["scope_id"].as_u64().unwrap()];
            if !encloses(&scope["range"], &row["range"])
                || (table == "callables" && !encloses(&row["range"], &row["body_range"]))
            {
                return Err(invalid());
            }
        }
    }
    let mut slots = BTreeSet::new();
    for region in response["regions"].as_array().unwrap() {
        if let Some(parent) = region["parent_id"].as_u64() {
            if !slots.insert((parent, region["entry_order"].as_u64().unwrap())) {
                return Err(invalid());
            }
        } else if region["entry_order"] != 0 || !region["callable_id"].is_null() {
            return Err(invalid());
        }
    }
    for operation in response["operations"].as_array().unwrap() {
        let owner = operation["region_id"].as_u64().unwrap();
        if !slots.insert((owner, operation["order"].as_u64().unwrap()))
            || !encloses(&graph_tables[1][&owner]["range"], &operation["range"])
        {
            return Err(invalid());
        }
    }
    if response["coverage"]["status"] == "complete"
        && (!response["coverage"]["frontiers"]
            .as_array()
            .unwrap()
            .is_empty()
            || !response["coverage"]["diagnostics"]
                .as_array()
                .unwrap()
                .is_empty())
    {
        return Err(invalid());
    }
    if !valid_targets(&response["operations"], &tables[1], &tables[2]) {
        return Err(invalid());
    }
    Ok(())
}
