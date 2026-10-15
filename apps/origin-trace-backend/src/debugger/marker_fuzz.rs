// Optional, fail-closed per-case guard for the explicitly armed CLI workflow.
// Aggregate scheduling/byte budgets are owned by that runner, not this API.
use super::requests;
use crate::{
    error::{Error, Result},
    validation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn hash(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn identity(s: &Value, g: &Value) -> bool {
    s["network"]["instance_id"] == g["instance_id"]
        && s["target"]["id"] == g["target_id"]
        && s["request_interception"]["target_id"] == g["target_id"]
        && s["request_interception"]["experiment_id"] == g["experiment_id"]
        && s["repeater"]["session_id"] == g["session_id"]
}
pub(super) fn scope(s: &Value, g: &Value, now: u64) -> Result<()> {
    if !identity(s, g)
        || !["running", "paused"].contains(&s["state"].as_str().unwrap_or(""))
        || s["request_interception"]["state"] != "ready"
        || s["request_interception"]["rule"]["mode"] != "continue"
        || !g["expires_at_ms"]
            .as_u64()
            .is_some_and(|v| v > now && v <= now.saturating_add(60000))
    {
        return Err(Error::conflict(
            "Marker case scope changed or its deadline expired",
        ));
    }
    Ok(())
}
pub(super) fn admit(s: &Value, guard: &Value, execution: u64, now: u64) -> bool {
    scope(s, guard, now).is_ok()
        && s["repeater"]["active_execution"]["execution_id"] == execution
        && s["repeater"]["active_execution"]["marker_fuzz"] == *guard
        && s["repeater"]["active_execution"]["cancel_requested"] != true
}
pub(super) fn literal(r: &Value, s: &Value, now: u64) -> Result<Value> {
    let g = &r["marker_fuzz"];
    validation::fields(
        g,
        &[
            "version",
            "plan_sha256",
            "case_index",
            "case_count",
            "instance_id",
            "target_id",
            "experiment_id",
            "session_id",
            "exact_origin",
            "exact_method",
            "request_sha256",
            "expires_at_ms",
        ],
        "Marker case guard",
    )?;
    validation::text(
        &g["instance_id"],
        "Marker backend instance",
        128,
        false,
        false,
    )?;
    validation::text(&g["target_id"], "Marker target", 4096, false, false)?;
    for key in ["experiment_id", "session_id"] {
        validation::integer(&g[key], "Marker identity", 1, validation::MAX_SAFE_INTEGER)?;
    }
    let count = validation::integer(&g["case_count"], "Marker case count", 1, 16)?;
    validation::integer(&g["case_index"], "Marker case index", 0, count - 1)?;
    let timeout = validation::integer(&r["timeout_ms"], "Marker timeout", 100, 5000)?;
    if g["version"] != 1
        || !hash(&g["plan_sha256"])
        || !hash(&g["request_sha256"])
        || !r["collection_request_id"].is_null()
    {
        return Err(Error::bad("Marker case identity is invalid"));
    }
    scope(s, g, now)?;
    // Reuse the same credential/body/header validators, but never expand variables.
    let mut resolved = requests::request(r)?;
    let address = resolved["url"].as_str().unwrap();
    let parsed = requests::url(address)?;
    if r["url"] != resolved["url"]
        || r["method"] != resolved["method"]
        || r["body"] != resolved["body"]
        || parsed.as_str() != address
        || !address.bytes().all(|b| (33..=126).contains(&b))
        || address.contains('#')
        || g["exact_origin"] != parsed.origin().ascii_serialization()
        || g["exact_method"] != resolved["method"]
        || !["GET", "HEAD", "POST"].contains(&resolved["method"].as_str().unwrap())
    {
        return Err(Error::bad(
            "Marker case must retain its exact canonical origin and method",
        ));
    }
    let headers = r["headers"]
        .as_object()
        .ok_or_else(|| Error::bad("Marker headers must be explicit"))?;
    if headers.iter().any(|(name, value)| {
        !((name == "accept" && value == "*/*")
            || (name == "content-type" && value == "text/plain; charset=utf-8"))
    }) {
        return Err(Error::bad(
            "Marker case headers must use the credential-free safelist",
        ));
    }
    let body = resolved["body"].as_str().unwrap();
    let size = address.len()
        + resolved["method"].as_str().unwrap().len()
        + body.len()
        + headers
            .iter()
            .map(|(name, value)| name.len() + value.as_str().unwrap().len())
            .sum::<usize>();
    let original =
        json!({"url":r["url"],"method":r["method"],"headers":r["headers"],"body":r["body"]});
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&original).unwrap()));
    if size > 8192 || g["request_sha256"] != digest {
        return Err(Error::bad(
            "Marker request differs from its reviewed digest or exceeds 8 KiB",
        ));
    }
    let remaining = g["expires_at_ms"].as_u64().unwrap().saturating_sub(now);
    if remaining < 100 {
        return Err(Error::conflict("Marker deadline is too close to dispatch"));
    }
    resolved["timeout_ms"] = json!(timeout.min(remaining));
    resolved["collection_request_id"] = Value::Null;
    Ok(resolved)
}
pub(super) fn cancellation(s: &Value, expected: &Value) -> Result<()> {
    validation::fields(
        expected,
        &[
            "instance_id",
            "target_id",
            "experiment_id",
            "session_id",
            "execution_id",
            "plan_sha256",
            "case_index",
        ],
        "Expected marker execution",
    )?;
    let active = &s["repeater"]["active_execution"];
    if !identity(s, expected)
        || active["execution_id"] != expected["execution_id"]
        || ["instance_id", "target_id", "experiment_id", "session_id"]
            .iter()
            .any(|key| active["marker_fuzz"][*key] != expected[*key])
        || active["marker_fuzz"]["plan_sha256"] != expected["plan_sha256"]
        || active["marker_fuzz"]["case_index"] != expected["case_index"]
        || !hash(&expected["plan_sha256"])
        || expected["execution_id"].as_u64().is_none_or(|id| id == 0)
    {
        return Err(Error::conflict(
            "Expected marker execution is no longer active; nothing was cancelled",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        let mut r = json!({"url":"http://127.0.0.1:8000/echo?q=%E9%9B%AA", "method":"POST", "headers":{"content-type":"text/plain; charset=utf-8"}, "body":"{{literal}}雪", "timeout_ms":1000});
        let h = hex::encode(Sha256::digest(serde_json::to_vec(&json!({"url":r["url"],"method":r["method"],"headers":r["headers"],"body":r["body"]})).unwrap()));
        r["marker_fuzz"] = json!({"version":1,"plan_sha256":"a".repeat(64),"case_index":0,"case_count":2,"instance_id":"backend-one","target_id":"owned","experiment_id":3,"session_id":3,"exact_origin":"http://127.0.0.1:8000","exact_method":"POST","request_sha256":h,"expires_at_ms":2000});
        let s = json!({"network":{"instance_id":"backend-one"},"state":"running","target":{"id":"owned"},"request_interception":{"instance_id":"backend-one","target_id":"owned","experiment_id":3,"state":"ready","rule":{"mode":"continue"}},"repeater":{"session_id":3,"active_execution":{"execution_id":4,"marker_fuzz":r["marker_fuzz"]}}});
        (r, s)
    }
    #[test]
    fn literal_scope_and_bounds_are_fail_closed() {
        let (r, s) = fixture();
        assert_eq!(literal(&r, &s, 1000).unwrap()["body"], "{{literal}}雪");
        for (key, value) in [
            ("instance_id", json!("backend-two")),
            ("target_id", json!("new")),
            ("session_id", json!(4)),
            ("experiment_id", json!(4)),
            ("exact_origin", json!("http://127.0.0.1:9000")),
            ("exact_method", json!("GET")),
            ("expires_at_ms", json!(1000)),
            ("request_sha256", json!("b".repeat(64))),
            ("case_count", json!(17)),
        ] {
            let mut changed = r.clone();
            changed["marker_fuzz"][key] = value;
            assert!(literal(&changed, &s, 1000).is_err(), "{key}");
        }
        for headers in [
            json!({"authorization":"synthetic"}),
            json!({"cookie":"synthetic"}),
            json!({"x-token":"synthetic"}),
            json!({"accept":"text/html"}),
        ] {
            let mut changed = r.clone();
            changed["headers"] = headers;
            assert!(literal(&changed, &s, 1000).is_err());
        }
        for url in [
            "http://user@127.0.0.1:8000/",
            "http://127.0.0.1:8000/#",
            "http://127.0.0.1:8000/#fragment",
        ] {
            let mut changed = r.clone();
            changed["url"] = json!(url);
            assert!(literal(&changed, &s, 1000).is_err());
        }
        let mut changed = r.clone();
        changed["body"] = json!("x".repeat(8193));
        assert!(literal(&changed, &s, 1000).is_err());
        let mut changed = r.clone();
        changed["method"] = json!("GET");
        assert!(literal(&changed, &s, 1000).is_err());
        let mut changed = s.clone();
        changed["request_interception"]["rule"]["mode"] = json!("rewrite");
        assert!(literal(&r, &changed, 1000).is_err());
    }
    #[test]
    fn cancel_compares_entire_execution_tuple() {
        let (_, s) = fixture();
        let expected = json!({"instance_id":"backend-one","target_id":"owned","experiment_id":3,"session_id":3,"execution_id":4,"plan_sha256":"a".repeat(64),"case_index":0});
        assert!(cancellation(&s, &expected).is_ok());
        for (key, value) in [
            ("instance_id", json!("backend-two")),
            ("target_id", json!("new")),
            ("experiment_id", json!(4)),
            ("session_id", json!(4)),
            ("execution_id", json!(5)),
            ("plan_sha256", json!("b".repeat(64))),
            ("case_index", json!(1)),
        ] {
            let mut changed = expected.clone();
            changed[key] = value;
            assert!(cancellation(&s, &changed).is_err(), "{key}");
        }
    }
}
