//! Read-only comparison of two strictly validated, supplied metadata packages.
//! Full declared scoped keys align metadata, never capture ownership or behavior.
use crate::{
    error::{Code, Error, Result},
    evidence_package,
};
use serde::Deserialize;
use serde_json::{Value, json, value::RawValue};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

pub const MAX_REQUEST_BYTES: usize = 2 * evidence_package::MAX_BYTES + 4096;
pub const MAX_RESULT_BYTES: usize = 512 * 1024;
pub const MAX_ROWS: usize =
    2 * (evidence_package::MAX_EVENTS + evidence_package::MAX_ARTIFACTS) + 5;
pub const MAX_PAGE_SIZE: usize = 100;
pub const PROFILE: &str = "reb-declared-metadata-v1";
const FACETS: [&str; 7] = [
    "artifacts",
    "coverage",
    "events",
    "gaps",
    "provenance",
    "relationships",
    "selection",
];
const LIMITATIONS: [&str; 8] = [
    "untrusted_input",
    "authenticity_not_established",
    "artifact_bytes_not_present_not_reverified",
    "capture_configuration_unknown",
    "observer_regime_unknown",
    "historical_epochs_unknown",
    "behavioral_equivalence_not_established",
    "timing_equivalence_not_established",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    #[serde(borrow)]
    left: &'a RawValue,
    #[serde(borrow)]
    right: &'a RawValue,
    #[serde(borrow)]
    normalization_profile: &'a RawValue,
    #[serde(borrow)]
    facets: &'a RawValue,
    #[serde(default, borrow, deserialize_with = "optional_raw")]
    offset: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "optional_raw")]
    limit: Option<&'a RawValue>,
}
fn optional_raw<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<&'de RawValue>, D::Error> {
    <&'de RawValue>::deserialize(deserializer).map(Some)
}
struct Request<'a> {
    left: &'a [u8],
    right: &'a [u8],
    facets: BTreeSet<String>,
    offset: usize,
    limit: usize,
}
fn invalid() -> Error {
    Error::bad("Invalid evidence comparison request")
}
fn exhausted() -> Error {
    Error::new(400, "Evidence comparison resource limit exceeded").with_code(Code::ResourceLimit)
}
fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::new(408, "Evidence comparison deadline exceeded").with_code(Code::Timeout))
    } else {
        Ok(())
    }
}
// RawValue borrows the original package tokens. Before serde scans them, bound
// nesting without interpreting keys, allocating strings, or erasing duplicates.
fn framing(raw: &[u8]) -> Result<()> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(exhausted());
    }
    let (mut depth, mut quoted, mut escape) = (0usize, false, false);
    for byte in raw {
        if quoted {
            if !escape && *byte == b'"' {
                quoted = false;
            }
            escape = !escape && *byte == b'\\';
        } else {
            match byte {
                b'"' => {
                    quoted = true;
                    escape = false;
                }
                b'[' | b'{' => {
                    depth += 1;
                    if depth > evidence_package::MAX_DEPTH + 1 {
                        return Err(exhausted());
                    }
                }
                b']' | b'}' => {
                    depth = depth.saturating_sub(1);
                }
                _ => (),
            }
        }
    }
    Ok(())
}
fn request(raw: &[u8]) -> Result<Request<'_>> {
    framing(raw)?;
    let envelope: Envelope<'_> = serde_json::from_slice(raw).map_err(|_| invalid())?;
    if envelope.left.get().len() > evidence_package::MAX_BYTES
        || envelope.right.get().len() > evidence_package::MAX_BYTES
    {
        return Err(exhausted());
    }
    if envelope.normalization_profile.get().len() > 128 || envelope.facets.get().len() > 512 {
        return Err(invalid());
    }
    let profile: String =
        serde_json::from_str(envelope.normalization_profile.get()).map_err(|_| invalid())?;
    if profile != PROFILE {
        return Err(Error::bad(
            "Unsupported evidence comparison normalization profile",
        ));
    }
    let facets: Vec<String> = serde_json::from_str(envelope.facets.get()).map_err(|_| invalid())?;
    let unique: BTreeSet<String> = facets.iter().cloned().collect();
    if facets.is_empty()
        || facets.len() > FACETS.len()
        || unique.len() != facets.len()
        || facets.iter().any(|f| !FACETS.contains(&f.as_str()))
    {
        return Err(invalid());
    }
    let number = |raw: Option<&RawValue>, default: usize| -> Result<usize> {
        match raw {
            None => Ok(default),
            Some(v) if v.get().len() <= 5 => serde_json::from_str(v.get()).map_err(|_| invalid()),
            _ => Err(invalid()),
        }
    };
    let offset = number(envelope.offset, 0)?;
    let limit = number(envelope.limit, 50)?;
    if offset > MAX_ROWS || limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(invalid());
    }
    Ok(Request {
        left: envelope.left.get().as_bytes(),
        right: envelope.right.get().as_bytes(),
        facets: unique,
        offset,
        limit,
    })
}
/// CLI preflight validates both original byte streams without materializing JSON
/// and reserializing it. This keeps duplicate and original-size rejection intact.
pub fn preflight(raw: &[u8]) -> Result<()> {
    let request = request(raw)?;
    evidence_package::parse_bytes(request.left).map_err(|e| Error::bad(e.to_string()))?;
    evidence_package::parse_bytes(request.right).map_err(|e| Error::bad(e.to_string()))?;
    Ok(())
}
fn digest(domain: &[u8], value: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    // Every value here is constructed from fixed fields and bounded validated input.
    hash.update(serde_json::to_vec(value).expect("serializable comparison value"));
    hex::encode(hash.finalize())
}
fn reference(package: &Value, facet: &str, key: Option<&Value>) -> Value {
    json!({"package_id":package["package_id"],"facet":facet,"key":key})
}
fn key(value: &Value) -> String {
    serde_json::to_string(value).expect("validated key")
}
fn local_key(value: &Value) -> String {
    let mut value = value.clone();
    value
        .as_object_mut()
        .expect("validated key")
        .remove("session_id");
    key(&value)
}
fn summarize(value: &Value) -> Value {
    match value {
        Value::Object(v) => json!({"kind":"object","count":v.len()}),
        Value::Array(v) => json!({"kind":"array","count":v.len()}),
        _ => json!({"kind":"scalar","value":value}),
    }
}
fn differences(left: &Value, right: &Value) -> (Vec<Value>, usize) {
    let mut result = Vec::new();
    if let (Some(left), Some(right)) = (left.as_object(), right.as_object()) {
        let fields: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
        for field in fields {
            if left.get(field) != right.get(field) {
                result.push(json!({"field":field,"left":summarize(left.get(field).unwrap_or(&Value::Null)),"right":summarize(right.get(field).unwrap_or(&Value::Null))}));
            }
        }
    } else if left != right {
        result.push(
            json!({"field":"selected_facet","left":summarize(left),"right":summarize(right)}),
        );
    }
    let omitted = result.len().saturating_sub(12);
    result.truncate(12);
    (result, omitted)
}
fn row(
    facet: &str,
    left_package: &Value,
    right_package: &Value,
    left: Option<&Value>,
    right: Option<&Value>,
    ambiguous: usize,
) -> Value {
    let records = facet == "events" || facet == "artifacts";
    let left_ref = left.map(|v| reference(left_package, facet, records.then_some(&v["key"])));
    let right_ref = right.map(|v| reference(right_package, facet, records.then_some(&v["key"])));
    let (status, alignment) = match (left, right) {
        (Some(a), Some(b)) => (
            if a == b {
                "equal_declared_metadata"
            } else {
                "changed_declared_metadata"
            },
            if records {
                "declared_scoped_key"
            } else {
                "selected_facet"
            },
        ),
        (Some(_), None) => (
            "left_only",
            if ambiguous > 0 {
                "ambiguous_cross_scope"
            } else {
                "unmatched"
            },
        ),
        _ => (
            "right_only",
            if ambiguous > 0 {
                "ambiguous_cross_scope"
            } else {
                "unmatched"
            },
        ),
    };
    let (diffs, omitted) = if let (Some(a), Some(b)) = (left, right) {
        differences(a, b)
    } else {
        (vec![], 0)
    };
    let declared_hash_match = if facet == "artifacts" {
        match (left, right) {
            (Some(a), Some(b)) => {
                json!(a["sha256"] == b["sha256"] && a["byte_size"] == b["byte_size"])
            }
            _ => Value::Null,
        }
    } else {
        Value::Null
    };
    let id = digest(
        b"REB\0evidence-comparison-row\0v1\0",
        &json!([PROFILE, facet, left_ref, right_ref]),
    );
    json!({"row_id":format!("reb-comparison-row-v1:sha256:{id}"),"facet":facet,"status":status,"alignment":alignment,"left":left_ref,"right":right_ref,"cross_scope_candidates":ambiguous,"differences":diffs,"differences_omitted":omitted,"declared_content_hash_match":declared_hash_match})
}
/// No configured stores, filesystem, URL resolution, helper or network access.
pub fn compare_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    compare_bytes_at(raw, Instant::now() + Duration::from_secs(10))
}
pub(crate) fn compare_bytes_at(raw: &[u8], deadline: Instant) -> Result<Vec<u8>> {
    check(deadline)?;
    let request = request(raw)?;
    let left = evidence_package::validated_normalized_bytes(request.left)?;
    check(deadline)?;
    let right = evidence_package::validated_normalized_bytes(request.right)?;
    check(deadline)?;
    let comparison_id = format!(
        "reb-comparison-v1:sha256:{}",
        digest(
            b"REB\0evidence-comparison\0v1\0",
            &json!([
                PROFILE,
                left["package_id"],
                right["package_id"],
                request.facets
            ])
        )
    );
    let mut page = Vec::new();
    let mut total = 0usize;
    let mut counts = BTreeMap::from([
        ("equal_declared_metadata", 0usize),
        ("changed_declared_metadata", 0),
        ("left_only", 0),
        ("right_only", 0),
        ("ambiguous_cross_scope", 0),
    ]);
    let mut emit = |row: Value| {
        *counts
            .get_mut(row["status"].as_str().expect("fixed status"))
            .unwrap() += 1;
        if row["alignment"] == "ambiguous_cross_scope" {
            *counts.get_mut("ambiguous_cross_scope").unwrap() += 1;
        }
        if total >= request.offset && page.len() < request.limit {
            page.push(row);
        }
        total += 1;
    };
    for facet in &request.facets {
        check(deadline)?;
        if facet == "events" || facet == "artifacts" {
            fn index<'a>(p: &'a Value, facet: &str) -> BTreeMap<String, &'a Value> {
                p["records"][facet]
                    .as_array()
                    .expect("validated records")
                    .iter()
                    .map(|v| (key(&v["key"]), v))
                    .collect()
            }
            let a = index(&left, facet);
            let b = index(&right, facet);
            let local = |m: &BTreeMap<String, &Value>| {
                let mut counts = BTreeMap::<String, usize>::new();
                for v in m.values() {
                    *counts.entry(local_key(&v["key"])).or_default() += 1;
                }
                counts
            };
            let a_local = local(&a);
            let b_local = local(&b);
            let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for key in keys {
                check(deadline)?;
                let av = a.get(key).copied();
                let bv = b.get(key).copied();
                let candidates = match (av, bv) {
                    (Some(v), None) => *b_local.get(&local_key(&v["key"])).unwrap_or(&0),
                    (None, Some(v)) => *a_local.get(&local_key(&v["key"])).unwrap_or(&0),
                    _ => 0,
                };
                emit(row(facet, &left, &right, av, bv, candidates));
            }
        } else {
            emit(row(
                facet,
                &left,
                &right,
                Some(&left[facet]),
                Some(&right[facet]),
                0,
            ));
        }
    }
    check(deadline)?;
    let next =
        (request.offset.saturating_add(page.len()) < total).then_some(request.offset + page.len());
    let result = json!({"protocol_version":1,"comparison_id":comparison_id,"normalization_profile":PROFILE,"left_package_id":left["package_id"],"right_package_id":right["package_id"],"facets":request.facets,"package_metadata_equal":left["package_id"] == right["package_id"],"selected_metadata_equal":(total > 0).then_some(counts["changed_declared_metadata"] == 0 && counts["left_only"] == 0 && counts["right_only"] == 0),"comparability":{"observer_regime":"unknown","capture_coverage":"unknown_or_partial","behavior":"not_established","timing":"not_established"},"limitations":LIMITATIONS,"coverage":{"left":left["coverage"],"right":right["coverage"]},"counts":counts,"page":{"offset":request.offset,"limit":request.limit,"total":total,"next_offset":next},"rows":page});
    serialize_result(&result, deadline)
}
fn serialize_result(result: &Value, deadline: Instant) -> Result<Vec<u8>> {
    struct Output {
        bytes: Vec<u8>,
        deadline: Instant,
    }
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len().saturating_add(bytes.len()) > MAX_RESULT_BYTES
                || Instant::now() >= self.deadline
            {
                return Err(std::io::Error::other("Comparison output bound"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Output {
        bytes: Vec::new(),
        deadline,
    };
    serde_json::to_writer(&mut output, result)
        .map_err(|_| check(deadline).err().unwrap_or_else(exhausted))?;
    let bytes = output.bytes;
    check(deadline)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialization_deadline_keeps_timeout_and_byte_exhaustion_keeps_resource_limit() {
        // Exercise the writer failure mapping directly, beyond the comparison's
        // preflight deadline guard. No successful partial output escapes.
        let timeout = serialize_result(&json!(null), Instant::now()).unwrap_err();
        assert_eq!(timeout.status, 408);
        assert_eq!(serde_json::to_value(timeout).unwrap()["code"], "timeout");
        let oversized = json!("x".repeat(MAX_RESULT_BYTES));
        let limit =
            serialize_result(&oversized, Instant::now() + Duration::from_secs(10)).unwrap_err();
        assert_eq!(limit.status, 400);
        assert_eq!(
            serde_json::to_value(limit).unwrap()["code"],
            "resource_limit"
        );
    }
    fn golden() -> Value {
        serde_json::from_slice(include_bytes!("../assets/evidence-packages/golden-v1.json"))
            .unwrap()
    }
    fn rehash(p: &mut Value) {
        p["package_id"] = json!(evidence_package::package_id(p).unwrap());
    }
    fn body(a: &Value, b: &Value) -> Value {
        json!({"left":a,"right":b,"normalization_profile":PROFILE,"facets":FACETS})
    }
    fn run(v: &Value) -> Value {
        serde_json::from_slice(&compare_bytes(&serde_json::to_vec(v).unwrap()).unwrap()).unwrap()
    }
    #[test]
    fn equal_metadata_keeps_unknown_observer_capture_and_bytes() {
        let p = golden();
        let r = run(&body(&p, &p));
        assert_eq!(r["package_metadata_equal"], true);
        assert_eq!(r["selected_metadata_equal"], true);
        assert_eq!(r["comparability"]["observer_regime"], "unknown");
        assert_eq!(r["counts"]["equal_declared_metadata"], 11);
        assert!(
            r["limitations"]
                .as_array()
                .unwrap()
                .contains(&json!("artifact_bytes_not_present_not_reverified"))
        );
    }
    #[test]
    fn reordered_sets_keep_result_identity_and_changed_scalar_is_reported() {
        let a = golden();
        let mut b = a.clone();
        b["records"]["events"].as_array_mut().unwrap().reverse();
        b["relationships"].as_array_mut().unwrap().reverse();
        assert_eq!(run(&body(&a, &a)), run(&body(&a, &b)));
        b["records"]["events"][0]["monotonic_time_ns"] = json!("11");
        rehash(&mut b);
        let r = run(&body(&a, &b));
        assert_eq!(r["counts"]["changed_declared_metadata"], 1);
        assert_eq!(r["selected_metadata_equal"], false);
        assert!(
            r["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["differences"][0]["field"] == "monotonic_time_ns")
        );
    }
    #[test]
    fn cross_session_coincidences_are_not_aligned() {
        let a = golden();
        let raw = serde_json::to_string(&a)
            .unwrap()
            .replace("\"session_id\":\"7\"", "\"session_id\":\"17\"")
            .replace("\"session_id\":\"8\"", "\"session_id\":\"18\"");
        let mut b: Value = serde_json::from_str(&raw).unwrap();
        rehash(&mut b);
        let r = run(&body(&a, &b));
        assert_eq!(r["counts"]["left_only"], 6);
        assert_eq!(r["counts"]["right_only"], 6);
        assert_eq!(r["counts"]["ambiguous_cross_scope"], 12);
        assert!(
            r["rows"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["facet"] == "events")
                .all(|v| v["alignment"] == "ambiguous_cross_scope")
        );
    }
    #[test]
    fn pages_and_facets_are_deterministic_and_bounded() {
        let p = golden();
        let mut q = body(&p, &p);
        q["limit"] = json!(2);
        let first = run(&q);
        q["offset"] = json!(2);
        let second = run(&q);
        assert_eq!(first["comparison_id"], second["comparison_id"]);
        assert_ne!(first["rows"][0]["row_id"], second["rows"][0]["row_id"]);
        assert_eq!(first["page"]["next_offset"], 2);
        assert_eq!(second["rows"].as_array().unwrap().len(), 2);
        q["facets"] = json!(["events"]);
        assert_ne!(run(&q)["comparison_id"], first["comparison_id"]);
        q["limit"] = json!(101);
        assert!(compare_bytes(&serde_json::to_vec(&q).unwrap()).is_err());
    }
    #[test]
    fn malformed_unsupported_duplicate_secret_and_oversized_originals_fail() {
        let p = golden();
        let q = body(&p, &p);
        let raw = serde_json::to_string(&q).unwrap();
        let duplicate = raw.replacen(
            "\"process_id\":42",
            "\"process_id\":42,\"process_id\":42",
            1,
        );
        assert!(compare_bytes(duplicate.as_bytes()).is_err());
        assert!(preflight(duplicate.as_bytes()).is_err());
        for mutation in [json!(2), json!(null)] {
            let mut q = q.clone();
            q["left"]["protocol_version"] = mutation;
            assert!(compare_bytes(&serde_json::to_vec(&q).unwrap()).is_err());
        }
        let mut q = q.clone();
        q["left"]["PRIVATE_CANARY"] = json!("SECRET");
        rehash(&mut q["left"]);
        let err = compare_bytes(&serde_json::to_vec(&q).unwrap()).unwrap_err();
        assert!(!format!("{err:?}").contains("SECRET"));
        let oversized = format!(
            "{{\"left\":{{{}\"x\":1}},\"right\":{},\"normalization_profile\":\"{}\",\"facets\":[\"events\"]}}",
            " ".repeat(evidence_package::MAX_BYTES),
            p,
            PROFILE
        );
        assert!(compare_bytes(oversized.as_bytes()).is_err());
        assert!(compare_bytes_at(raw.as_bytes(), Instant::now()).is_err());
    }
    fn sized_package(events: usize, artifacts: usize, session: &str) -> Value {
        let mut p = golden();
        let event = p["records"]["events"][0].clone();
        let artifact = p["records"]["artifacts"][0].clone();
        p["records"]["events"] = json!(
            (0..events)
                .map(|i| {
                    let mut e = event.clone();
                    e["key"]["session_id"] = json!(session);
                    e["key"]["sequence_number"] = json!((i + 1).to_string());
                    e["artifact_id"] = json!("0");
                    e
                })
                .collect::<Vec<_>>()
        );
        p["records"]["artifacts"] = json!(
            (0..artifacts)
                .map(|i| {
                    let mut a = artifact.clone();
                    a["key"]["session_id"] = json!(session);
                    a["key"]["artifact_id"] = json!((i + 1).to_string());
                    a["creator_event_id"] = json!("0");
                    a
                })
                .collect::<Vec<_>>()
        );
        p["relationships"] = json!([]);
        p["gaps"] = json!([]);
        for section in ["events", "artifacts"] {
            p["selection"][section] = json!(
                p["records"][section]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v["key"].clone())
                    .collect::<Vec<_>>()
            );
            let n = p["records"][section].as_array().unwrap().len();
            p["coverage"][section]["selected_count"] = json!(n);
            p["coverage"][section]["selection_state"] =
                json!(if n == 0 { "not_requested" } else { "complete" });
            p["coverage"][section]["source_scan"] =
                json!(if n == 0 { "not_read" } else { "complete" });
            p["coverage"][section]["limitations"] = json!([
                "capture_configuration_unknown",
                "metadata_only",
                "origin_scope_unknown",
                "producer_build_unknown"
            ]);
        }
        if events + artifacts == 0 {
            p["coverage"]["selection"] = json!("empty");
            p["provenance"]["consistency"] = json!("empty_selection");
        }
        rehash(&mut p);
        p
    }
    #[test]
    fn maximal_records_preserve_page_budget_and_ambiguous_candidates() {
        let a = sized_package(MAX_EVENTS_FOR_TEST, 64, "7");
        let b = sized_package(MAX_EVENTS_FOR_TEST, 64, "77");
        let mut q = body(&a, &b);
        q["limit"] = json!(100);
        let r = run(&q);
        assert_eq!(r["page"]["total"], MAX_ROWS);
        assert_eq!(r["counts"]["ambiguous_cross_scope"], 2176);
        assert_eq!(r["rows"].as_array().unwrap().len(), 100);
        assert!(serde_json::to_vec(&r).unwrap().len() < MAX_RESULT_BYTES);
        q["offset"] = json!(MAX_ROWS);
        let end = run(&q);
        assert_eq!(end["rows"], json!([]));
        assert_eq!(end["page"]["next_offset"], Value::Null);
    }
    const MAX_EVENTS_FOR_TEST: usize = evidence_package::MAX_EVENTS;
    #[test]
    fn absent_records_are_never_unchanged_evidence() {
        let a = sized_package(0, 0, "7");
        let mut q = body(&a, &a);
        q["facets"] = json!(["events", "artifacts"]);
        let r = run(&q);
        assert_eq!(r["selected_metadata_equal"], Value::Null);
        assert_eq!(r["page"]["total"], 0);
        q["right"] = sized_package(1, 0, "7");
        let r = run(&q);
        assert_eq!(r["selected_metadata_equal"], false);
        assert_eq!(r["counts"]["right_only"], 1);
    }
    #[test]
    fn observed_changes_survive_partial_coverage_without_equivalence() {
        let mut a = sized_package(1, 0, "7");
        a["gaps"] = json!([{"kind":"queue_drop_marker","session_id":"7","process_id":42,"anchor_sequence":"1","monotonic_time_ns":"10","reported_dropped_count":"2","count_state":"reported","occurrences":1}]);
        a["coverage"]["events"]["capture_state"] = json!("partial");
        a["coverage"]["events"]["limitations"]
            .as_array_mut()
            .unwrap()
            .push(json!("capture_gap"));
        rehash(&mut a);
        let mut b = a.clone();
        b["records"]["events"][0]["monotonic_time_ns"] = json!("11");
        rehash(&mut b);
        let r = run(&body(&a, &b));
        assert_eq!(r["counts"]["changed_declared_metadata"], 1);
        assert_eq!(r["coverage"]["left"]["events"]["capture_state"], "partial");
        assert_eq!(r["comparability"]["behavior"], "not_established");
    }
    #[test]
    fn descriptor_hash_matches_do_not_hide_changed_descriptor_or_verify_bytes() {
        let a = sized_package(0, 1, "7");
        let mut b = a.clone();
        b["records"]["artifacts"][0]["kind"] = json!("wasm");
        rehash(&mut b);
        let r = run(&body(&a, &b));
        let row = &r["rows"][0];
        assert_eq!(row["declared_content_hash_match"], true);
        assert_eq!(row["status"], "changed_declared_metadata");
        assert_eq!(row["differences"][0]["field"], "kind");
        let a = sized_package(1, 0, "7");
        let mut b = a.clone();
        b["records"]["events"][0]["key"]["process_id"] = json!(43);
        b["selection"]["events"][0]["process_id"] = json!(43);
        rehash(&mut b);
        let r = run(&body(&a, &b));
        assert_eq!(r["counts"]["ambiguous_cross_scope"], 0);
        assert_eq!(r["counts"]["left_only"], 1);
        assert_eq!(r["counts"]["right_only"], 1);
    }
    #[test]
    fn changed_field_details_are_bounded_without_hiding_omissions() {
        let a: Value = (0..40)
            .map(|i| (format!("field_{i:02}"), json!(0)))
            .collect::<serde_json::Map<_, _>>()
            .into();
        let b: Value = (0..40)
            .map(|i| (format!("field_{i:02}"), json!(1)))
            .collect::<serde_json::Map<_, _>>()
            .into();
        let (details, omitted) = differences(&a, &b);
        assert_eq!(details.len(), 12);
        assert_eq!(omitted, 28);
        assert_eq!(details[0]["field"], "field_00");
        assert_eq!(details[11]["field"], "field_11");
    }
    #[test]
    fn captured_synthetic_golden_response_remains_exact() {
        let p = golden();
        let r = run(&body(&p, &p));
        let expected: Value = serde_json::from_slice(include_bytes!(
            "../assets/evidence-packages/comparison-equal-v1.json"
        ))
        .unwrap();
        assert_eq!(r, expected);
    }
}
