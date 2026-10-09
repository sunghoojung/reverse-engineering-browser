//! Pure, bounded evidence projection. Equality never establishes value flow.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_FRAMES: usize = 16;
const MAX_CANDIDATES: usize = 32;
// The debugger retains at most 5000 scripts across page and worker targets.
const MAX_SCRIPT_CATALOG: usize = 5000;
const WINDOW_MS: u64 = 5000;

fn bounded(value: &Value, limit: usize) -> Option<&str> {
    value.as_str().filter(|text| text.len() <= limit)
}

fn preview(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn string_digest(value: &Value) -> Value {
    bounded(value, 4096).map_or(Value::Null, |text| {
        json!(format!("{:x}", Sha256::digest(text.as_bytes())))
    })
}

fn source_url(value: &Value) -> String {
    preview(value.as_str().unwrap_or(""), 8192).to_owned()
}

fn coordinate(value: &Value) -> bool {
    value.as_u64().is_some_and(|n| n <= i32::MAX as u64)
}

fn call_sites(request: &Value) -> Result<Value, &'static str> {
    let target = bounded(&request["target_id"], 4096).ok_or("Invalid target")?;
    let stack = &request["initiator"]["stack"];
    let Some(frames) = stack["callFrames"].as_array() else {
        return Ok(json!({"sites": [], "gaps": ["initiator_unavailable"]}));
    };
    let catalog = request["scripts"].as_object();
    if catalog.is_some_and(|scripts| scripts.len() > MAX_SCRIPT_CATALOG) {
        return Err("Script catalog exceeds limit");
    }
    let mut sites = Vec::new();
    let mut gaps = BTreeSet::new();
    for frame in frames.iter().take(MAX_FRAMES) {
        let Some(script) = bounded(&frame["scriptId"], 4096).filter(|id| !id.is_empty()) else {
            gaps.insert("malformed_call_site");
            continue;
        };
        if !coordinate(&frame["lineNumber"]) || !coordinate(&frame["columnNumber"]) {
            gaps.insert("malformed_call_site");
            continue;
        }
        let public = catalog.and_then(|scripts| {
            scripts.values().find(|item| {
                item["target_id"].as_str().unwrap_or(target) == target
                    && item["cdp_script_id"]
                        .as_str()
                        .or(item["script_id"].as_str())
                        == Some(script)
            })
        });
        sites.push(json!({
            "script_id": public.and_then(|item| bounded(&item["script_id"], 4096)).filter(|id| !id.is_empty()).unwrap_or(script),
            "source_hash": public.and_then(|item| bounded(&item["hash"], 256)),
            "target_id": target, "source": source_url(&frame["url"]),
            "source_truncated": frame["url"].as_str().is_some_and(|value| value.len() > 8192),
            "function": preview(frame["functionName"].as_str().unwrap_or(""), 256),
            "line": frame["lineNumber"], "column": frame["columnNumber"]
        }));
    }
    if frames.len() > MAX_FRAMES {
        gaps.insert("call_site_limit");
    }
    if !stack["parent"].is_null() || !stack["parentId"].is_null() {
        gaps.insert("async_parent_unresolved");
    }
    Ok(json!({"sites":sites, "gaps":gaps}))
}

fn snapshot(request: &Value) -> Result<Value, &'static str> {
    let hits = request["hits"].as_array().ok_or("Invalid hits")?;
    if hits.len() > 512 {
        return Err("Hit retention exceeds limit");
    }
    let target = bounded(&request["target_id"], 4096).ok_or("Invalid target")?;
    let time = request["occurred_at_ms"].as_u64().ok_or("Invalid time")?;
    let eligible = hits
        .iter()
        .filter(|hit| {
            hit["target_id"] == target
                && hit["occurred_at_ms"]
                    .as_u64()
                    .and_then(|occurred| time.checked_sub(occurred))
                    .is_some_and(|age| age <= WINDOW_MS)
        })
        .collect::<Vec<_>>();
    let limited = eligible.len() > MAX_CANDIDATES;
    let start = eligible.len().saturating_sub(MAX_CANDIDATES);
    Ok(json!({"hits": eligible[start..], "limited":limited}))
}

fn build(request: &Value) -> Result<Value, &'static str> {
    let hits = request["hits"].as_array().ok_or("Invalid hits")?;
    if hits.len() > MAX_CANDIDATES {
        return Err("Candidate limit exceeded");
    }
    let sites = request["call_sites"]["sites"]
        .as_array()
        .ok_or("Invalid call sites")?;
    if sites.len() > MAX_FRAMES {
        return Err("Call site limit exceeded");
    }
    for site in sites {
        if !coordinate(&site["line"])
            || !coordinate(&site["column"])
            || !bounded(&site["script_id"], 4096).is_some_and(|id| !id.is_empty())
            || bounded(&site["target_id"], 4096).is_none()
            || bounded(&site["function"], 256).is_none()
            || bounded(&site["source"], 8192).is_none()
            || (!site["source_hash"].is_null() && bounded(&site["source_hash"], 256).is_none())
        {
            return Err("Invalid call site");
        }
    }
    let digest = bounded(&request["selected_digest"], 64).filter(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    });
    let mut candidates = Vec::new();
    for hit in hits {
        if !matches!(
            hit["operation"].as_str(),
            Some("observed" | "return_overridden")
        ) || !hit["error"].is_null()
        {
            continue;
        }
        if !coordinate(&hit["line"])
            || !coordinate(&hit["column"])
            || !hit["id"]
                .as_u64()
                .is_some_and(|id| (1..=9007199254740991).contains(&id))
            || !matches!(hit["category"].as_str(), Some("entry" | "return"))
        {
            return Err("Invalid hit identity");
        }
        for (field, max) in [
            ("target_id", 4096),
            ("script_id", 4096),
            ("source", 8192),
            ("function", 256),
        ] {
            if bounded(&hit[field], max).is_none() {
                return Err("Invalid hit location");
            }
        }
        if !hit["source_hash"].is_null() && bounded(&hit["source_hash"], 256).is_none() {
            return Err("Invalid source hash");
        }
        let equal = |remote: &Value| digest.is_some() && remote["string_sha256"].as_str() == digest;
        let mut labels = Vec::new();
        for field in ["original_return", "replacement_return"] {
            if equal(&hit[field]) {
                labels.push(field.to_owned());
            }
        }
        let bindings = hit["bindings"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        if bindings.len() > 32 {
            return Err("Binding limit exceeded");
        }
        for binding in bindings {
            if binding["accessor"] != true && equal(&binding["value"]) {
                labels.push(
                    bounded(&binding["name"], 256)
                        .ok_or("Invalid binding name")?
                        .to_owned(),
                );
            }
        }
        if !labels.is_empty() {
            candidates.push(json!({"hit_id":hit["id"], "target_id":hit["target_id"],
                "script_id":hit["script_id"], "source_hash":hit["source_hash"], "source":source_url(&hit["source"]), "source_truncated":hit["source_truncated"] == true || hit["source"].as_str().is_some_and(|value| value.len() > 8192),
                "function":hit["function"], "line":hit["line"], "column":hit["column"],
                "phase":hit["category"], "operation":hit["operation"], "matched_values":labels,
                "confidence":"correlated"}));
        }
    }
    let mut gaps = BTreeSet::from([
        "value_flow_unobserved",
        "transforms_unobserved",
        "async_worker_wasm_flow_unobserved",
    ]);
    let input_gaps = request["call_sites"]["gaps"]
        .as_array()
        .ok_or("Invalid gaps")?;
    if input_gaps.len() > 4 {
        return Err("Gap limit exceeded");
    }
    for gap in input_gaps {
        let gap = gap.as_str().ok_or("Invalid gap")?;
        if !matches!(
            gap,
            "initiator_unavailable"
                | "malformed_call_site"
                | "call_site_limit"
                | "async_parent_unresolved"
        ) {
            return Err("Unknown gap");
        }
        gaps.insert(gap);
    }
    if digest.is_none() {
        gaps.insert("complete_string_unavailable");
    }
    if candidates.is_empty() {
        gaps.insert("no_matching_runtime_value");
    }
    if request["limited"] == true {
        gaps.insert("candidate_hit_limit");
    }
    Ok(
        json!({"protocol_version":1, "call_sites":sites, "candidates":candidates,
        "gaps":gaps, "window_ms":WINDOW_MS}),
    )
}

pub(crate) fn catalog(state: &Value) -> Value {
    let mut scripts = serde_json::Map::new();
    for script in state["scripts"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_SCRIPT_CATALOG)
    {
        let Some(id) = script["script_id"].as_str() else {
            continue;
        };
        let mut script = script.clone();
        if script["target_id"].is_null() {
            script["target_id"] = state["target"]["id"].clone();
        }
        scripts.insert(id.to_owned(), script);
    }
    Value::Object(scripts)
}

pub(crate) fn project(request: &Value) -> Result<Value, &'static str> {
    match request["operation"].as_str() {
        Some("string_digest") => {
            let value = if request["serialized"] == true {
                request["value"]
                    .as_str()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .unwrap_or(Value::Null)
            } else {
                request["value"].clone()
            };
            Ok(string_digest(&value))
        }
        Some("call_sites") => call_sites(request),
        Some("snapshot") => snapshot(request),
        Some("build") => build(request),
        _ => Err("Unknown provenance operation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hit(id: u64, target: &str, time: u64) -> Value {
        json!({"id":id,"target_id":target,"occurred_at_ms":time,"script_id":"s","source_hash":"hash", "source":"http://a.test/code.js","function":"f","line":0,"column":1,"category":"return","operation":"observed","error":null,"original_return":{"string_sha256":string_digest(&json!("x"))},"bindings":[]})
    }
    #[test]
    fn digest_is_utf8_bounded_and_primitive_only() {
        assert_eq!(
            string_digest(&json!("x")),
            json!("2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881")
        );
        assert!(!string_digest(&json!("🙂".repeat(1024))).is_null());
        assert!(string_digest(&json!("🙂".repeat(1025))).is_null());
        assert!(string_digest(&json!({"value":"x"})).is_null());
        assert_eq!(
            project(&json!({"operation":"string_digest","serialized":true,"value":"\"x\""}))
                .unwrap(),
            string_digest(&json!("x"))
        );
        assert_eq!(
            project(&json!({"operation":"string_digest","serialized":true,"value":"{\"x\":1}"}))
                .unwrap(),
            Value::Null
        );
    }
    #[test]
    fn sites_preserve_raw_urls_and_report_limits_and_invalid_coordinates() {
        let frame = json!({"scriptId":"s","url":"https://user:secret@a.test/code.js?token=private#secret","functionName":"f","lineNumber":0,"columnNumber":1});
        let mut frames = vec![frame; 17];
        frames[0]["lineNumber"] = json!(true);
        let sites=call_sites(&json!({"target_id":"t","initiator":{"stack":{"callFrames":frames,"parentId":{"id":"async"}}}})).unwrap();
        assert_eq!(sites["sites"].as_array().unwrap().len(), 15);
        assert_eq!(
            sites["sites"][0]["source"],
            "https://user:secret@a.test/code.js?token=private#secret"
        );
        assert_eq!(
            sites["gaps"],
            json!([
                "async_parent_unresolved",
                "call_site_limit",
                "malformed_call_site"
            ])
        );
    }
    #[test]
    fn source_prefix_flags_match_the_public_optional_contract() {
        let frame = json!({"scriptId":"s","url":"雪".repeat(3000),"functionName":"f","lineNumber":0,"columnNumber":1});
        let sites =
            call_sites(&json!({"target_id":"t","initiator":{"stack":{"callFrames":[frame]}}}))
                .unwrap();
        let site = &sites["sites"][0];
        assert_eq!(site["source_truncated"], true);
        assert_eq!(site["source"].as_str().unwrap().len(), 8190);
        let spec: Value =
            serde_json::from_str(include_str!("../../../protocol/openapi.json")).unwrap();
        jsonschema::validator_for(&spec["components"]["schemas"]["FieldCallSite"])
            .unwrap()
            .validate(site)
            .unwrap();
        let mut raw_hit = hit(1, "t", 1000);
        raw_hit["source"] = json!("raw-prefix");
        raw_hit["source_truncated"] = json!(true);
        let output = build(&json!({"selected_digest":string_digest(&json!("x")),"hits":[raw_hit],"call_sites":{"sites":[],"gaps":[]},"limited":false})).unwrap();
        let candidate = &output["candidates"][0];
        assert_eq!(candidate["source_truncated"], true);
        jsonschema::validator_for(&spec["components"]["schemas"]["FieldProvenanceCandidate"])
            .unwrap()
            .validate(candidate)
            .unwrap();
        assert_eq!(
            source_url(&json!("data:text/javascript,synthetic?token#fragment")),
            "data:text/javascript,synthetic?token#fragment"
        );
    }

    #[test]
    fn snapshot_rejects_cross_target_future_and_expired_hits_and_reports_eviction() {
        let mut hits = (1..=40).map(|id| hit(id, "t", 1000)).collect::<Vec<_>>();
        hits.extend([hit(41, "other", 1000), hit(42, "t", 7000), hit(43, "t", 0)]);
        let selected =
            snapshot(&json!({"hits":hits,"target_id":"t","occurred_at_ms":6000})).unwrap();
        assert_eq!(selected["hits"].as_array().unwrap().len(), 32);
        assert_eq!(selected["hits"][0]["id"], 9);
        assert_eq!(selected["limited"], true);
    }
    #[test]
    fn replacement_matches_remain_correlated_and_accessors_are_excluded() {
        let mut hit = hit(1, "t", 1000);
        hit["operation"] = json!("return_overridden");
        hit["source"] = json!("https://user:secret@a.test/code.js?token=private#secret");
        hit["replacement_return"] = hit["original_return"].take();
        hit["bindings"] =
            json!([{"name":"accessor","accessor":true,"value":hit["replacement_return"]}]);
        let output=build(&json!({"selected_digest":string_digest(&json!("x")),"hits":[hit],"call_sites":{"sites":[],"gaps":[]},"limited":false})).unwrap();
        assert_eq!(
            output["candidates"][0]["matched_values"],
            json!(["replacement_return"])
        );
        assert_eq!(output["candidates"][0]["confidence"], "correlated");
        assert_eq!(
            output["candidates"][0]["source"],
            "https://user:secret@a.test/code.js?token=private#secret"
        );
        assert!(
            output["gaps"]
                .as_array()
                .unwrap()
                .contains(&json!("value_flow_unobserved"))
        );
    }
    #[test]
    fn malformed_projection_does_not_invent_evidence() {
        assert!(project(&json!({"operation":"invent"})).is_err());
        assert!(
            snapshot(&json!({"hits":vec![Value::Null;513],"target_id":"t","occurred_at_ms":1}))
                .is_err()
        );
        assert!(build(&json!({"hits":[],"call_sites":{"sites":[],"gaps":["proven"]}})).is_err());
        assert!(
            build(&json!({"hits":[],"call_sites":{"sites":[{"line":true}],"gaps":[]}})).is_err()
        );
    }
}
