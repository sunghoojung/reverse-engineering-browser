//! Metadata-only package identity, inert validation, and explicitly selected
//! cooperative stopped-store export. Validation has no source-store access.
use crate::error::{Error, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::LazyLock,
    time::{Duration, Instant},
};

pub const MAX_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NODES: usize = 200_000;
pub const MAX_DEPTH: usize = 32;
pub const MAX_STRING_BYTES: usize = 4096;
pub const MAX_EVENTS: usize = 1024;
pub const MAX_ARTIFACTS: usize = 64;
pub const MAX_RELATIONSHIPS: usize = 4096;
pub const MAX_GAPS: usize = 4096;
pub const SERIALIZATION_PROFILE: &str = "reb-json-semantic-v1";
pub const REDACTION_PROFILE: &str = "reb-metadata-only-v1";
pub const SEMANTICS_PROFILE: &str = "reb-api-marker-v1";
const DOMAIN: &[u8] = b"REB\0evidence-package\0v1\0";
const ID_PREFIX: &str = "reb-package-v1:sha256:";
const BASE_LIMITATIONS: [&str; 4] = [
    "capture_configuration_unknown",
    "metadata_only",
    "origin_scope_unknown",
    "producer_build_unknown",
];
pub const EXCLUDED_SECTIONS: [&str; 6] = [
    "analysis_documents",
    "artifact_bytes",
    "debugger_network",
    "hook_values",
    "signal_profiles",
    "trace_edges",
];
// Source: chromium/0002-record-web-audio-function-calls.patch and
// patches/0004-observe-native-web-audio-readbacks.patch. Legacy producer builds
// are unknown: all entries mean marker observed, never successful completion.
pub const AUDIO_OPERATIONS: [&str; 12] = [
    "AnalyserNode.getFloatFrequencyData",
    "AnalyserNode.getByteFrequencyData",
    "AnalyserNode.getFloatTimeDomainData",
    "AnalyserNode.getByteTimeDomainData",
    "AudioBuffer.getChannelData",
    "AudioBuffer.copyFromChannel",
    "BaseAudioContext.createDynamicsCompressor",
    "BaseAudioContext.createAnalyser",
    "BaseAudioContext.createOscillator",
    "AudioNode.connect",
    "AudioScheduledSourceNode.start",
    "OfflineAudioContext.startRendering",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Malformed,
    NonObject,
    DuplicateKey,
    ResourceLimit,
    InvalidNumber,
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "The package body is malformed JSON",
            Self::NonObject => "The package body must be an object",
            Self::DuplicateKey => "The package contains a duplicate JSON key",
            Self::ResourceLimit => "The package exceeds a resource limit",
            Self::InvalidNumber => "The package contains an unsupported number",
        })
    }
}
impl std::error::Error for ParseError {}

struct Budget {
    deadline: Instant,
}
impl Budget {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(2),
        }
    }
    fn check(&self) -> std::result::Result<(), ParseError> {
        if Instant::now() >= self.deadline {
            Err(ParseError::ResourceLimit)
        } else {
            Ok(())
        }
    }
}
struct Parser<'a> {
    budget: &'a Budget,
    nodes: usize,
    fault: Option<ParseError>,
}
impl Parser<'_> {
    fn fail<E: de::Error>(&mut self, fault: ParseError) -> E {
        self.fault = Some(fault);
        E::custom("Invalid bounded package JSON")
    }
    fn node<E: de::Error>(&mut self, depth: usize) -> std::result::Result<(), E> {
        if depth > MAX_DEPTH || self.nodes >= MAX_NODES || self.budget.check().is_err() {
            return Err(self.fail(ParseError::ResourceLimit));
        }
        self.nodes += 1;
        Ok(())
    }
    fn string<E: de::Error>(&mut self, value: &str) -> std::result::Result<(), E> {
        if value.len() > MAX_STRING_BYTES {
            Err(self.fail(ParseError::ResourceLimit))
        } else {
            Ok(())
        }
    }
}
struct Seed<'a, 'b> {
    parser: &'a mut Parser<'b>,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_, '_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        self.parser.node(self.depth)?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_, '_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded metadata JSON")
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(json!(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(json!(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(json!(v))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Value, E> {
        Err(self.parser.fail(ParseError::InvalidNumber))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        self.parser.string(v)?;
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        self.parser.string(&v)?;
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            parser: self.parser,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.parser.node(self.depth + 1)?;
            self.parser.string(&key)?;
            if values.contains_key(&key) {
                return Err(self.parser.fail(ParseError::DuplicateKey));
            }
            let value = map.next_value_seed(Seed {
                parser: self.parser,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
fn parse(raw: &[u8], budget: &Budget) -> std::result::Result<Value, ParseError> {
    if raw.len() > MAX_BYTES {
        return Err(ParseError::ResourceLimit);
    }
    budget.check()?;
    // A decoded 4096-byte string needs at most six JSON source bytes per byte.
    // Bound serde's temporary string/key allocation before it decodes a token.
    let (mut in_string, mut escaped, mut length) = (false, false, 0usize);
    for chunk in raw.chunks(64 * 1024) {
        budget.check()?;
        for byte in chunk {
            if in_string {
                if !escaped && *byte == b'"' {
                    in_string = false;
                    continue;
                }
                length += 1;
                if length > 6 * MAX_STRING_BYTES {
                    return Err(ParseError::ResourceLimit);
                }
                escaped = !escaped && *byte == b'\\';
            } else if *byte == b'"' {
                in_string = true;
                escaped = false;
                length = 0;
            }
        }
    }
    let mut parser = Parser {
        budget,
        nodes: 0,
        fault: None,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = Seed {
        parser: &mut parser,
        depth: 1,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| parser.fault.unwrap_or(ParseError::Malformed))?;
    deserializer.end().map_err(|_| ParseError::Malformed)?;
    budget.check()?;
    if !value.is_object() {
        return Err(ParseError::NonObject);
    }
    Ok(value)
}
/// Shared by the raw HTTP path and CLI. Never erase duplicate keys into Value.
pub fn parse_bytes(raw: &[u8]) -> std::result::Result<Value, ParseError> {
    parse(raw, &Budget::new())
}

static SCHEMA: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../protocol/evidence-package-v1.schema.json"
    ))
    .expect("package schema JSON");
    jsonschema::validator_for(&schema).expect("local package schema")
});
struct Report {
    value: Value,
}
impl Report {
    fn new() -> Self {
        Self {
            value: json!({"protocol_version":1,"status":"invalid","package_id":null,
            "checks":{"structure":"not_run","semantic_digest":"not_run","references":"not_run","metadata_profile":"not_run"},
            "origin":"untrusted_input","authenticity":"not_established","artifact_bytes":"not_present_not_reverified",
            "issues":[],"issues_truncated":false}),
        }
    }
    fn issue(&mut self, code: &'static str, section: &'static str, index: Option<usize>) {
        let issues = self.value["issues"].as_array_mut().unwrap();
        if issues.len() < 64 {
            issues.push(json!({"code":code,"section":section,"index":index.filter(|i| *i < 4096)}));
        } else {
            self.value["issues_truncated"] = json!(true);
        }
    }
    fn check(&mut self, name: &str, passed: bool) {
        self.value["checks"][name] = json!(if passed { "passed" } else { "failed" });
    }
    fn count(&self) -> usize {
        self.value["issues"].as_array().unwrap().len()
    }
}
fn location(path: &str) -> (&'static str, Option<usize>) {
    let mut parts = path.split('/').skip(1);
    let first = parts.next().unwrap_or("");
    let section = match first {
        "selection" => "selection",
        "coverage" => "coverage",
        "relationships" => "relationships",
        "gaps" => "gaps",
        "records" => match parts.next() {
            Some("events") => "events",
            Some("artifacts") => "artifacts",
            _ => "package",
        },
        _ => "package",
    };
    (
        section,
        parts
            .next()
            .and_then(|p| p.parse::<usize>().ok())
            .filter(|i| *i < 4096),
    )
}
fn forbidden(error: &jsonschema::ValidationError<'_>) -> bool {
    use jsonschema::error::ValidationErrorKind as K;
    match &error.kind {
        K::AdditionalProperties { .. } | K::UnevaluatedProperties { .. } => true,
        K::AnyOf { context } | K::OneOfNotValid { context } | K::OneOfMultipleValid { context } => {
            context
                .iter()
                .filter(|errors| {
                    !errors.iter().any(|error| {
                        matches!(error.kind, K::Constant { .. })
                            && matches!(
                                error.instance_path.as_str().rsplit('/').next(),
                                Some("kind" | "relation" | "from_kind" | "to_kind")
                            )
                    })
                })
                .flatten()
                .any(forbidden)
        }
        _ => false,
    }
}
fn unsigned(value: &Value, nonzero: bool) -> Option<u64> {
    let s = value.as_str()?;
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse::<u64>().ok().filter(|n| !nonzero || *n != 0)
}
fn signed(value: &Value) -> Option<i64> {
    let s = value.as_str()?;
    let n = s.parse::<i64>().ok()?;
    (n.to_string() == s).then_some(n)
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Key {
    Event(u64, u32, u64),
    Artifact(u64, u64),
}
fn key(kind: &str, value: &Value) -> Option<Key> {
    let session = unsigned(&value["session_id"], true)?;
    match kind {
        "event" => Some(Key::Event(
            session,
            u32::try_from(value["process_id"].as_u64()?)
                .ok()
                .filter(|v| *v != 0)?,
            unsigned(&value["sequence_number"], true)?,
        )),
        "artifact" => Some(Key::Artifact(
            session,
            unsigned(&value["artifact_id"], true)?,
        )),
        _ => None,
    }
}
fn array<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    value[name].as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn records<'a>(package: &'a Value, section: &str) -> &'a [Value] {
    array(&package["records"], section)
}

fn identities<'a>(
    package: &'a Value,
    report: &mut Report,
    budget: &Budget,
) -> std::result::Result<BTreeMap<Key, &'a Value>, ParseError> {
    let mut all = BTreeMap::new();
    for (section, kind) in [("events", "event"), ("artifacts", "artifact")] {
        let mut selected = BTreeSet::new();
        for (i, value) in array(&package["selection"], section).iter().enumerate() {
            budget.check()?;
            match key(kind, value) {
                None => report.issue("invalid_identifier", "selection", Some(i)),
                Some(k) if !selected.insert(k) => {
                    report.issue("duplicate_identity", "selection", Some(i))
                }
                _ => (),
            }
        }
        let mut present = BTreeSet::new();
        for (i, value) in records(package, section).iter().enumerate() {
            budget.check()?;
            let Some(k) = key(kind, &value["key"]) else {
                report.issue("invalid_identifier", section, Some(i));
                continue;
            };
            present.insert(k);
            if let Some(old) = all.insert(k, value) {
                report.issue(
                    if old == value {
                        "duplicate_identity"
                    } else {
                        "conflicting_identity"
                    },
                    section,
                    Some(i),
                );
            }
            let unsigned_fields: &[&str] = if kind == "event" {
                &[
                    "monotonic_time_ns",
                    "navigation_id",
                    "frame_id",
                    "artifact_id",
                    "parent_event_id",
                    "request_id",
                    "browser_context_id_high",
                    "browser_context_id_low",
                ]
            } else {
                &[
                    "navigation_id",
                    "frame_id",
                    "parent_artifact_id",
                    "creator_event_id",
                    "execution_context_id",
                    "byte_size",
                ]
            };
            for field in unsigned_fields {
                if !value[field].is_null() && unsigned(&value[field], false).is_none() {
                    report.issue("invalid_identifier", section, Some(i));
                }
            }
            for field in ["encoded_data_length", "decoded_body_length"] {
                if kind == "event" && !value[field].is_null() && signed(&value[field]).is_none() {
                    report.issue("invalid_identifier", section, Some(i));
                }
            }
            if kind == "event" {
                let operation = value["operation"].as_str();
                if operation.is_some_and(|op| !AUDIO_OPERATIONS.contains(&op))
                    || (operation.is_some()
                        && (value["category"] != "web_audio"
                            || value["type"] != "api_call"
                            || value["payload_truncated"] != false))
                    || (operation
                        .is_some_and(|op| value["payload_size"].as_u64() != Some(op.len() as u64)))
                    || (value["flags"].as_u64().is_some_and(|flags| {
                        value["payload_truncated"]
                            .as_bool()
                            .is_some_and(|truncated| truncated != (flags & 1 != 0))
                    }))
                {
                    report.issue("invalid_shape", section, Some(i));
                    report.check("metadata_profile", false);
                }
            } else {
                let kind = value["kind"].as_str().unwrap_or("");
                let origin = value["capture_origin"].as_str().unwrap_or("");
                let context = unsigned(&value["execution_context_id"], false);
                if value["sensitive"].as_bool()
                    != Some(matches!(kind, "response_body" | "canvas_data_url"))
                    || (value["execution_context_id"].is_null() && origin != "unknown")
                    || (origin == "dynamic_javascript"
                        && (kind != "javascript" || context.is_none_or(|id| id == 0)))
                    || (origin.starts_with("webassembly_")
                        && (kind != "wasm" || context.is_none_or(|id| id == 0)))
                    || (origin == "canvas_to_data_url"
                        && (kind != "canvas_data_url" || context != Some(0)))
                    || unsigned(&value["byte_size"], false).is_some_and(|n| n > 16 * 1024 * 1024)
                {
                    report.issue("invalid_shape", section, Some(i));
                    report.check("metadata_profile", false);
                }
            }
        }
        if selected != present {
            report.issue("selection_mismatch", "selection", None);
        }
    }
    Ok(all)
}

fn references(
    package: &Value,
    all: &BTreeMap<Key, &Value>,
    report: &mut Report,
    budget: &Budget,
) -> std::result::Result<(), ParseError> {
    let mut expected = BTreeMap::new();
    for (k, value) in all {
        match *k {
            Key::Event(session, process, _) => {
                if let Some(id) = unsigned(&value["parent_event_id"], true) {
                    expected.insert((*k, "parent_event"), Some(Key::Event(session, process, id)));
                }
                if let Some(id) = unsigned(&value["artifact_id"], true) {
                    expected.insert((*k, "event_artifact"), Some(Key::Artifact(session, id)));
                }
            }
            Key::Artifact(session, _) => {
                if let Some(id) = unsigned(&value["parent_artifact_id"], true) {
                    expected.insert((*k, "parent_artifact"), Some(Key::Artifact(session, id)));
                }
                if unsigned(&value["creator_event_id"], true).is_some() {
                    expected.insert((*k, "artifact_creator"), None);
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    let mut parents = BTreeMap::new();
    // Retained-source presence belongs to the scoped target, not to an edge.
    // Unknown/not-inspected references make no presence claim.
    let mut existence: BTreeMap<Key, bool> = all.keys().map(|k| (*k, true)).collect();
    let mut expected_gaps = BTreeSet::new();
    for (i, relation) in array(package, "relationships").iter().enumerate() {
        budget.check()?;
        let from_kind = relation["from_kind"].as_str().unwrap();
        let to_kind = relation["to_kind"].as_str().unwrap();
        let Some(from) = key(from_kind, &relation["from_key"]) else {
            report.issue("invalid_identifier", "relationships", Some(i));
            continue;
        };
        let to = if relation["to_key"].is_null() {
            None
        } else {
            key(to_kind, &relation["to_key"])
        };
        if !relation["to_key"].is_null() && to.is_none() {
            report.issue("invalid_identifier", "relationships", Some(i));
            continue;
        }
        let name = relation["relation"].as_str().unwrap();
        if !seen.insert((from, name)) {
            report.issue("duplicate_identity", "relationships", Some(i));
        }
        if expected.get(&(from, name)) != Some(&to) {
            report.issue("invalid_reference_state", "relationships", Some(i));
            continue;
        }
        let resolution = relation["resolution"].as_str().unwrap();
        let requested = !records(
            package,
            if to_kind == "event" {
                "events"
            } else {
                "artifacts"
            },
        )
        .is_empty();
        let included = to.is_some_and(|k| all.contains_key(&k));
        let valid = match resolution {
            "included" => included,
            "outside_selection" | "missing_in_retained_source" => {
                requested && !included && to.is_some()
            }
            "not_inspected" => !requested && to.is_some(),
            "insufficient_identity" => name == "artifact_creator" && to.is_none(),
            _ => false,
        };
        if !valid {
            report.issue(
                if resolution == "included" {
                    "missing_reference"
                } else {
                    "invalid_reference_state"
                },
                "relationships",
                Some(i),
            );
        }
        if valid
            && matches!(
                resolution,
                "included" | "outside_selection" | "missing_in_retained_source"
            )
            && let Some(to) = to
        {
            let present = resolution != "missing_in_retained_source";
            if existence
                .insert(to, present)
                .is_some_and(|old| old != present)
            {
                report.issue("invalid_reference_state", "relationships", Some(i));
            }
        }
        if name == "artifact_creator" && resolution != "insufficient_identity" {
            report.issue("invalid_reference_state", "relationships", Some(i));
        }
        if resolution == "included"
            && matches!(name, "parent_event" | "parent_artifact")
            && let Some(to) = to
        {
            parents.insert(from, to);
        }
        if resolution == "missing_in_retained_source" {
            let mut gap = relation.clone();
            gap.as_object_mut().unwrap().remove("resolution");
            gap["kind"] = json!("missing_reference");
            expected_gaps.insert(serde_json::to_vec(&gap).unwrap());
        }
        if resolution == "insufficient_identity"
            && let Some(artifact) = all.get(&from)
        {
            expected_gaps.insert(serde_json::to_vec(&json!({"kind":"creator_identity_incomplete","artifact_key":relation["from_key"],"creator_event_id":artifact["creator_event_id"]})).unwrap());
        }
    }
    for entry in expected.keys() {
        if !seen.contains(entry) {
            report.issue("missing_reference", "relationships", None);
        }
    }
    // Parent relations have at most one outgoing edge. Global completed nodes
    // prevent quadratic walks; the current path detects cycles iteratively.
    let mut completed = BTreeSet::new();
    for start in parents.keys() {
        budget.check()?;
        let mut current = *start;
        let mut path = BTreeSet::new();
        while !completed.contains(&current) {
            budget.check()?;
            if !path.insert(current) {
                report.issue("forbidden_cycle", "relationships", None);
                break;
            }
            let Some(next) = parents.get(&current) else {
                break;
            };
            current = *next;
        }
        completed.extend(path);
    }
    let mut actual_gaps = BTreeSet::new();
    let mut unique = BTreeSet::new();
    let mut windows = BTreeMap::<(u64, u32), (u64, u64)>::new();
    for k in all.keys() {
        if let Key::Event(session, process, sequence) = *k {
            let window = windows
                .entry((session, process))
                .or_insert((sequence, sequence));
            window.0 = window.0.min(sequence);
            window.1 = window.1.max(sequence);
        }
    }
    let mut holes = BTreeMap::<(u64, u32), Vec<(u64, u64)>>::new();
    for (i, gap) in array(package, "gaps").iter().enumerate() {
        budget.check()?;
        let kind = gap["kind"].as_str().unwrap();
        let mut identity = gap.clone();
        if kind == "queue_drop_marker" {
            identity.as_object_mut().unwrap().remove("occurrences");
        }
        if !unique.insert(serde_json::to_vec(&identity).unwrap()) {
            report.issue("duplicate_identity", "gaps", Some(i));
        }
        match kind {
            "missing_reference" | "creator_identity_incomplete" => {
                actual_gaps.insert(serde_json::to_vec(gap).unwrap());
            }
            "queue_drop_marker" | "sequence_discontinuity" => {
                let stream = unsigned(&gap["session_id"], true).zip(
                    gap["process_id"]
                        .as_u64()
                        .and_then(|p| u32::try_from(p).ok()),
                );
                let window = stream.and_then(|s| windows.get(&s));
                if kind == "queue_drop_marker" {
                    let anchor = unsigned(&gap["anchor_sequence"], true);
                    let count = unsigned(&gap["reported_dropped_count"], false);
                    if window
                        .zip(anchor)
                        .is_none_or(|((min, max), n)| n < *min || n > *max)
                        || unsigned(&gap["monotonic_time_ns"], false).is_none()
                        || ((gap["count_state"] == "reported") != count.is_some())
                        || (gap["count_state"] == "count_unknown"
                            && !gap["reported_dropped_count"].is_null())
                    {
                        report.issue("invalid_coverage", "gaps", Some(i));
                    }
                } else {
                    let range = unsigned(&gap["first_missing_sequence"], true)
                        .zip(unsigned(&gap["last_missing_sequence"], true));
                    if window.zip(range).is_none_or(|((min, max), (first, last))| {
                        first > last || first <= *min || last >= *max
                    }) {
                        report.issue("invalid_coverage", "gaps", Some(i));
                    } else if let (Some(stream), Some((first, last))) = (stream, range) {
                        // A discontinuity is between adjacent retained events.
                        // The strict selected-window bounds make this arithmetic safe.
                        for sequence in [first - 1, last + 1] {
                            if existence.insert(Key::Event(stream.0, stream.1, sequence), true)
                                == Some(false)
                            {
                                report.issue("invalid_coverage", "gaps", Some(i));
                            }
                        }
                        holes.entry(stream).or_default().push((first, last));
                    }
                }
            }
            _ => unreachable!("closed schema"),
        }
    }
    let present: BTreeSet<_> = existence
        .iter()
        .filter_map(|(k, present)| present.then_some(*k))
        .collect();
    for (stream, ranges) in &mut holes {
        budget.check()?;
        ranges.sort_unstable();
        if ranges.windows(2).any(|w| w[0].1 >= w[1].0) {
            report.issue("invalid_coverage", "gaps", None);
        }
        for (first, last) in ranges {
            budget.check()?;
            if present
                .range(
                    Key::Event(stream.0, stream.1, *first)..=Key::Event(stream.0, stream.1, *last),
                )
                .next()
                .is_some()
            {
                report.issue("invalid_coverage", "gaps", None);
            }
        }
    }
    if actual_gaps != expected_gaps {
        report.issue("missing_reference", "gaps", None);
    }
    Ok(())
}
fn coverage_observations(
    package: &Value,
    section: &str,
    kind: &str,
    budget: &Budget,
) -> std::result::Result<(BTreeSet<&'static str>, bool), ParseError> {
    let values = records(package, section);
    let mut limitations: BTreeSet<&str> = BASE_LIMITATIONS.into_iter().collect();
    for relation in array(package, "relationships") {
        budget.check()?;
        if relation["from_kind"] == kind {
            match relation["resolution"].as_str().unwrap() {
                "outside_selection" => {
                    limitations.insert("reference_outside_selection");
                }
                "missing_in_retained_source" => {
                    limitations.insert("reference_missing");
                }
                "not_inspected" => {
                    limitations.insert("reference_not_inspected");
                }
                "insufficient_identity" => {
                    limitations.insert("creator_identity_incomplete");
                }
                _ => (),
            }
        }
    }
    let mut partial = false;
    if kind == "event" {
        if values.iter().any(|v| {
            v["payload_truncated"] == true
                || v["flags"].as_u64().is_some_and(|flags| flags & 1 != 0)
        }) {
            limitations.insert("payload_was_truncated");
        }
        for gap in array(package, "gaps") {
            budget.check()?;
            match gap["kind"].as_str() {
                Some("queue_drop_marker") => {
                    limitations.insert("capture_gap");
                    partial = true;
                }
                Some("sequence_discontinuity") => {
                    limitations.insert("sequence_discontinuity");
                    partial = true;
                }
                _ => (),
            }
        }
    }
    Ok((limitations, partial))
}
fn coverage(
    package: &Value,
    report: &mut Report,
    budget: &Budget,
) -> std::result::Result<(), ParseError> {
    let empty = records(package, "events").is_empty() && records(package, "artifacts").is_empty();
    if package["coverage"]["selection"] != if empty { "empty" } else { "complete" }
        || package["provenance"]["consistency"]
            != if empty {
                "empty_selection"
            } else {
                "cooperative_stopped_store_v1"
            }
    {
        report.issue("invalid_coverage", "coverage", None);
    }
    let excluded: BTreeSet<_> = array(&package["coverage"], "excluded_sections")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if excluded != EXCLUDED_SECTIONS.into_iter().collect() {
        report.issue("invalid_coverage", "coverage", None);
    }
    for (section, kind) in [("events", "event"), ("artifacts", "artifact")] {
        budget.check()?;
        let values = records(package, section);
        let requested = !values.is_empty();
        let (limitations, partial) = coverage_observations(package, section, kind, budget)?;
        let c = &package["coverage"][section];
        let supplied: BTreeSet<_> = array(c, "limitations")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if c["selected_count"].as_u64() != Some(values.len() as u64)
            || c["selection_state"]
                != if requested {
                    "complete"
                } else {
                    "not_requested"
                }
            || c["source_scan"] != if requested { "complete" } else { "not_read" }
            || c["capture_state"] != if partial { "partial" } else { "unknown" }
            || supplied != limitations
        {
            report.issue("invalid_coverage", "coverage", None);
        }
    }
    Ok(())
}

fn normalized(package: &Value, budget: &Budget) -> std::result::Result<Value, ParseError> {
    let mut value = package.clone();
    value
        .as_object_mut()
        .ok_or(ParseError::NonObject)?
        .remove("package_id");
    for (section, kind) in [("events", "event"), ("artifacts", "artifact")] {
        budget.check()?;
        for (container, is_record) in [("selection", false), ("records", true)] {
            let values = value[container][section]
                .as_array_mut()
                .ok_or(ParseError::Malformed)?;
            // Validate every sort key before sort; never use fallback identities.
            let mut keyed = Vec::with_capacity(values.len());
            for item in values.drain(..) {
                budget.check()?;
                let k = key(kind, if is_record { &item["key"] } else { &item })
                    .ok_or(ParseError::Malformed)?;
                keyed.push((k, item));
            }
            keyed.sort_by_key(|entry| entry.0);
            values.extend(keyed.into_iter().map(|entry| entry.1));
        }
        value["coverage"][section]["limitations"]
            .as_array_mut()
            .ok_or(ParseError::Malformed)?
            .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    }
    value["coverage"]["excluded_sections"]
        .as_array_mut()
        .ok_or(ParseError::Malformed)?
        .sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    for section in ["relationships", "gaps"] {
        let values = value[section].as_array_mut().ok_or(ParseError::Malformed)?;
        let mut keyed = Vec::with_capacity(values.len());
        for item in values.drain(..) {
            budget.check()?;
            keyed.push((
                serde_json::to_vec(&item).map_err(|_| ParseError::Malformed)?,
                item,
            ));
        }
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        values.extend(keyed.into_iter().map(|entry| entry.1));
    }
    Ok(value)
}
struct BoundedWriter<'a> {
    bytes: Vec<u8>,
    budget: &'a Budget,
}
impl std::io::Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > MAX_BYTES || self.budget.check().is_err()
        {
            return Err(std::io::Error::other("Package resource limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical(package: &Value, budget: &Budget) -> std::result::Result<Vec<u8>, ParseError> {
    let value = normalized(package, budget)?;
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        budget,
    };
    // serde_json without preserve_order uses a BTreeMap: UTF-8 byte-key order.
    // Its string encoder implements this named profile's escapes and scalars.
    serde_json::to_writer(&mut writer, &value).map_err(|_| ParseError::ResourceLimit)?;
    Ok(writer.bytes)
}
fn digest(bytes: &[u8], budget: &Budget) -> std::result::Result<String, ParseError> {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    for chunk in bytes.chunks(64 * 1024) {
        budget.check()?;
        hash.update(chunk);
    }
    Ok(format!("{ID_PREFIX}{}", hex::encode(hash.finalize())))
}
/// Content addressing for a structurally valid package. It establishes no provenance.
/// D11 can build this closed metadata representation before assigning package_id.
pub fn package_id(package: &Value) -> std::result::Result<String, ParseError> {
    let budget = Budget::new();
    // Bound programmatically created values through the same parser before work.
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        budget: &budget,
    };
    serde_json::to_writer(&mut writer, package).map_err(|_| ParseError::ResourceLimit)?;
    let value = parse(&writer.bytes, &budget)?;
    digest(&canonical(&value, &budget)?, &budget)
}

fn validate(raw: &[u8], budget: &Budget) -> Result<Value> {
    let mut report = Report::new();
    let package = match parse(raw, budget) {
        Ok(package) => package,
        Err(ParseError::Malformed) => return Err(Error::bad("The package body is malformed JSON")),
        Err(ParseError::NonObject) => return Err(Error::bad("The package body must be an object")),
        Err(error) => {
            report.issue(
                match error {
                    ParseError::DuplicateKey => "duplicate_json_key",
                    ParseError::ResourceLimit => "resource_limit",
                    _ => "invalid_shape",
                },
                "package",
                None,
            );
            report.check("structure", false);
            return Ok(report.value);
        }
    };
    if package.get("protocol_version").is_some_and(|v| v != 1) {
        report.value["status"] = json!("unsupported");
        report.issue("unsupported_version", "package", None);
        return Ok(report.value);
    }
    for (field, expected) in [
        ("serialization_profile", SERIALIZATION_PROFILE),
        ("redaction_profile", REDACTION_PROFILE),
        ("semantics_profile", SEMANTICS_PROFILE),
    ] {
        if package.get(field).is_some_and(|v| v != expected) {
            report.value["status"] = json!("unsupported");
            report.issue("unsupported_profile", "package", None);
            return Ok(report.value);
        }
    }
    let run = |report: &mut Report| -> std::result::Result<(), ParseError> {
        budget.check()?;
        for error in SCHEMA.iter_errors(&package) {
            budget.check()?;
            let (section, index) = location(error.instance_path.as_str());
            let code = if forbidden(&error) {
                "forbidden_metadata_field"
            } else {
                use jsonschema::error::ValidationErrorKind as K;
                match error.kind {
                    K::MaxItems { .. } | K::MaxLength { .. } | K::MaxProperties { .. } => {
                        "resource_limit"
                    }
                    K::UniqueItems => "duplicate_identity",
                    K::Pattern { .. } if error.schema_path.as_str().contains("64String") => {
                        "invalid_identifier"
                    }
                    _ => "invalid_shape",
                }
            };
            report.issue(code, section, index);
            if report.value["issues_truncated"] == true {
                break;
            }
        }
        report.check("structure", report.count() == 0);
        report.check("metadata_profile", report.count() == 0);
        if report.count() != 0 {
            return Ok(());
        }
        let all = identities(&package, report, budget)?;
        if report.count() != 0 {
            report.check("references", false);
            return Ok(());
        }
        references(&package, &all, report, budget)?;
        coverage(&package, report, budget)?;
        report.check("references", report.count() == 0);
        let computed = digest(&canonical(&package, budget)?, budget)?;
        let matches = package["package_id"] == computed;
        report.check("semantic_digest", matches);
        if matches {
            report.value["package_id"] = json!(computed);
        } else {
            report.issue("digest_mismatch", "package", None);
        }
        if report.count() == 0 {
            report.value["status"] = json!("valid");
        }
        Ok(())
    };
    if run(&mut report).is_err() {
        report.issue("resource_limit", "package", None);
        report.value["status"] = json!("invalid");
        report.value["package_id"] = Value::Null;
    }
    Ok(report.value)
}
/// Validate supplied bytes inertly. Success is internal consistency, not authenticity.
pub fn validate_bytes(raw: &[u8]) -> Result<Value> {
    validate(raw, &Budget::new())
}

pub const MAX_EXPORT_REQUEST_BYTES: usize = 256 * 1024;

/// Returns response bytes constructed under all requested shared store leases.
/// It never starts/stops capture, fetches content, or executes captured code.
pub fn export_bytes(
    raw: &[u8],
    events: &std::path::Path,
    artifacts: &std::path::Path,
) -> Result<Vec<u8>> {
    export_bytes_at(
        raw,
        events,
        artifacts,
        Instant::now() + Duration::from_secs(10),
    )
}
pub(crate) fn export_bytes_at(
    raw: &[u8],
    events: &std::path::Path,
    artifacts: &std::path::Path,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let budget = Budget { deadline };
    export_with_budget(raw, events, artifacts, &budget)
}
fn export_failure(error: ParseError, budget: &Budget) -> Error {
    use crate::error::Code;
    if budget.check().is_err() {
        Error::new(408, "The evidence export exceeded its deadline").with_code(Code::Timeout)
    } else if error == ParseError::ResourceLimit {
        Error::new(413, "The evidence export exceeds a resource limit")
            .with_code(Code::ResourceLimit)
    } else {
        Error::protocol("The evidence source has an unsupported or malformed record")
    }
}
fn export_request(raw: &[u8], budget: &Budget) -> Result<Value> {
    if raw.len() > MAX_EXPORT_REQUEST_BYTES {
        return Err(Error::bad("The export request exceeds its byte limit"));
    }
    let value = parse(raw, budget).map_err(|error| {
        if budget.check().is_err() {
            export_failure(error, budget)
        } else {
            Error::bad("The export request is invalid")
        }
    })?;
    if value["protocol_version"] != 1
        || value.get("profile").is_some_and(|v| v != REDACTION_PROFILE)
        || value
            .as_object()
            .unwrap()
            .keys()
            .any(|k| !["protocol_version", "profile", "selection"].contains(&k.as_str()))
        || !value["selection"].is_object()
        || value["selection"].as_object().unwrap().len() != 2
    {
        return Err(Error::bad("The export request is invalid"));
    }
    for (section, kind, maximum) in [
        ("events", "event", MAX_EVENTS),
        ("artifacts", "artifact", MAX_ARTIFACTS),
    ] {
        let values = value["selection"][section]
            .as_array()
            .ok_or_else(|| Error::bad("The export selection is invalid"))?;
        if values.len() > maximum {
            return Err(Error::bad("The export selection exceeds its count limit"));
        }
        let mut seen = BTreeSet::new();
        for item in values {
            budget.check().map_err(|e| export_failure(e, budget))?;
            let k = key(kind, item).ok_or_else(|| Error::bad("The export selection is invalid"))?;
            if *item != key_value(k) || !seen.insert(k) {
                return Err(Error::bad("The export selection is invalid or duplicated"));
            }
        }
    }
    Ok(value)
}
fn key_value(key: Key) -> Value {
    match key {
        Key::Event(session, process, sequence) => {
            json!({"session_id":session.to_string(),"process_id":process,"sequence_number":sequence.to_string()})
        }
        Key::Artifact(session, artifact) => {
            json!({"session_id":session.to_string(),"artifact_id":artifact.to_string()})
        }
    }
}
fn empty_package(selection: Value) -> Value {
    json!({"format":"reb-evidence-package","protocol_version":1,"serialization_profile":SERIALIZATION_PROFILE,
        "redaction_profile":REDACTION_PROFILE,"semantics_profile":SEMANTICS_PROFILE,"package_id":null,"selection":selection,
        "provenance":{"origin":"configured_local_stores","consistency":"empty_selection","producer_build":null,"browser_build":null,"capture_configuration":null,"capture_authorization":"not_attested","origin_scope":"unknown"},
        "coverage":{"selection":"empty","events":null,"artifacts":null,"excluded_sections":EXCLUDED_SECTIONS},
        "records":{"events":[],"artifacts":[]},"relationships":[],"gaps":[]})
}
fn build_coverage(package: &mut Value, budget: &Budget) -> std::result::Result<(), ParseError> {
    let empty = records(package, "events").is_empty() && records(package, "artifacts").is_empty();
    package["coverage"]["selection"] = json!(if empty { "empty" } else { "complete" });
    package["provenance"]["consistency"] = json!(if empty {
        "empty_selection"
    } else {
        "cooperative_stopped_store_v1"
    });
    for (section, kind) in [("events", "event"), ("artifacts", "artifact")] {
        let count = records(package, section).len();
        let (limitations, partial) = coverage_observations(package, section, kind, budget)?;
        package["coverage"][section] = json!({"selection_state":if count == 0 {"not_requested"} else {"complete"},"selected_count":count,
            "source_scan":if count == 0 {"not_read"} else {"complete"},"capture_state":if partial {"partial"} else {"unknown"},"limitations":limitations});
    }
    Ok(())
}
fn finish_export(mut package: Value, budget: &Budget) -> Result<Vec<u8>> {
    build_coverage(&mut package, budget).map_err(|e| export_failure(e, budget))?;
    let mut package = normalized(&package, budget).map_err(|e| export_failure(e, budget))?;
    package["package_id"] = json!(
        digest(
            &canonical(&package, budget).map_err(|e| export_failure(e, budget))?,
            budget
        )
        .map_err(|e| export_failure(e, budget))?
    );
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        budget,
    };
    serde_json::to_writer(&mut writer, &package)
        .map_err(|_| export_failure(ParseError::ResourceLimit, budget))?;
    let result = validate(&writer.bytes, budget)?;
    budget.check().map_err(|e| export_failure(e, budget))?;
    if result["status"] != "valid" {
        if array(&result, "issues")
            .iter()
            .any(|v| v["code"] == "resource_limit")
        {
            return Err(export_failure(ParseError::ResourceLimit, budget));
        }
        return Err(Error::protocol(
            "The retained evidence cannot form a consistent metadata package",
        ));
    }
    Ok(writer.bytes)
}
fn export_with_budget(
    raw: &[u8],
    events: &std::path::Path,
    artifacts: &std::path::Path,
    budget: &Budget,
) -> Result<Vec<u8>> {
    let request = export_request(raw, budget)?;
    let package = empty_package(request["selection"].clone());
    if array(&package["selection"], "events").is_empty()
        && array(&package["selection"], "artifacts").is_empty()
    {
        return finish_export(package, budget);
    }
    #[cfg(unix)]
    {
        stored_export(package, events, artifacts, budget)
    }
    #[cfg(not(unix))]
    {
        let _ = (events, artifacts);
        Err(
            Error::new(503, "Safe evidence export is unsupported on this platform")
                .with_code(crate::error::Code::DependencyUnavailable),
        )
    }
}

#[cfg(unix)]
fn source_event(value: &Value, budget: &Budget) -> Result<(Key, Value, Vec<u8>, bool)> {
    fn malformed() -> Error {
        Error::protocol("The evidence source has an unsupported or malformed record")
    }
    budget.check().map_err(|e| export_failure(e, budget))?;
    let k = key("event", value).ok_or_else(malformed)?;
    for field in [
        "protocol_version",
        "monotonic_time_ns",
        "navigation_id",
        "frame_id",
        "artifact_id",
        "request_id",
        "category",
        "type",
        "payload_encoding",
        "payload",
        "payload_size",
    ] {
        if value[field].is_null() {
            return Err(malformed());
        }
    }
    if value["payload_encoding"] != "hex" {
        return Err(malformed());
    }
    let payload_size = value["payload_size"]
        .as_u64()
        .filter(|n| *n <= 128)
        .ok_or_else(malformed)?;
    let raw_payload = value["payload"].as_str().ok_or_else(malformed)?;
    if raw_payload.len() != payload_size as usize * 2
        || !raw_payload.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(malformed());
    }
    let payload = hex::decode(raw_payload).map_err(|_| malformed())?;
    let mut projected = json!({"key":key_value(k),"operation":null,"observation":"marker_observed","outcome":"not_recorded","placement":"unknown"});
    for field in [
        "protocol_version",
        "monotonic_time_ns",
        "navigation_id",
        "frame_id",
        "thread_id",
        "tab_id",
        "artifact_id",
        "parent_event_id",
        "request_id",
        "browser_context_id_high",
        "browser_context_id_low",
        "initiator_request_id",
        "initiator_process_id",
        "category",
        "type",
        "status_code",
        "error_code",
        "resource_type",
        "flags",
        "encoded_data_length",
        "decoded_body_length",
        "payload_size",
        "payload_truncated",
    ] {
        if value.get(field).is_some_and(Value::is_null) {
            return Err(malformed());
        }
        projected[field] = value[field].clone();
    }
    if value["protocol_version"] == 2 {
        if value
            .get("tab_id")
            .is_some_and(|v| v.as_u64().is_none_or(|n| n > u32::MAX as u64))
        {
            return Err(malformed());
        }
        projected["tab_id"] = Value::Null;
    }
    let gap = value["type"] == "gap";
    if gap {
        projected["type"] = json!("api_call");
    }
    static SOURCE_EVENT: LazyLock<jsonschema::Validator> = LazyLock::new(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/evidence-package-v1.schema.json"
        ))
        .expect("package schema");
        jsonschema::validator_for(
            &json!({"$defs":schema["$defs"],"$ref":"#/$defs/EvidencePackageEventMetadata"}),
        )
        .expect("event metadata schema")
    });
    if !SOURCE_EVENT.is_valid(&projected) {
        return Err(malformed());
    }
    for field in [
        "monotonic_time_ns",
        "navigation_id",
        "frame_id",
        "artifact_id",
        "parent_event_id",
        "request_id",
        "browser_context_id_high",
        "browser_context_id_low",
    ] {
        if !projected[field].is_null() && unsigned(&projected[field], false).is_none() {
            return Err(malformed());
        }
    }
    for field in ["encoded_data_length", "decoded_body_length"] {
        if !projected[field].is_null() && signed(&projected[field]).is_none() {
            return Err(malformed());
        }
    }
    if projected["flags"].as_u64().is_some_and(|f| {
        projected["payload_truncated"]
            .as_bool()
            .is_some_and(|t| t != (f & 1 != 0))
    }) {
        return Err(malformed());
    }
    if !gap
        && projected["category"] == "web_audio"
        && projected["type"] == "api_call"
        && projected["payload_truncated"] == false
        && let Some(operation) = AUDIO_OPERATIONS
            .iter()
            .find(|name| name.as_bytes() == payload)
    {
        projected["operation"] = json!(operation);
    }
    Ok((k, projected, payload, gap))
}
#[cfg(unix)]
fn source_artifact(value: &mut Value) -> Result<(Key, Value)> {
    let k = key("artifact", value)
        .ok_or_else(|| Error::protocol("The artifact source contains a malformed record"))?;
    let legacy =
        value.get("execution_context_id").is_none() && value.get("capture_origin").is_none();
    crate::evidence::validate_artifact(value)
        .map_err(|_| Error::protocol("The artifact source contains a malformed record"))?;
    let mut projected =
        json!({"key":key_value(k),"verification":"sha256_verified_at_export","content":"omitted"});
    for field in [
        "protocol_version",
        "navigation_id",
        "frame_id",
        "parent_artifact_id",
        "creator_event_id",
        "execution_context_id",
        "capture_origin",
        "kind",
        "sha256",
        "sensitive",
    ] {
        projected[field] = value[field].clone();
    }
    projected["byte_size"] = json!(value["byte_size"].as_u64().unwrap().to_string());
    if legacy {
        projected["execution_context_id"] = Value::Null;
    }
    Ok((k, projected))
}
#[cfg(unix)]
struct ExportMemory {
    retained: usize,
}
#[cfg(unix)]
impl ExportMemory {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.retained = self
            .retained
            .checked_add(bytes)
            .ok_or_else(crate::evidence::frozen::limit)?;
        if self.retained > 32 * 1024 * 1024 {
            return Err(crate::evidence::frozen::limit());
        }
        Ok(())
    }
}
#[cfg(unix)]
fn stored_export(
    mut package: Value,
    events: &std::path::Path,
    artifacts: &std::path::Path,
    budget: &Budget,
) -> Result<Vec<u8>> {
    use crate::evidence::frozen::{self, Store};
    let events_selected: BTreeSet<_> = array(&package["selection"], "events")
        .iter()
        .map(|v| key("event", v).unwrap())
        .collect();
    let artifacts_selected: BTreeSet<_> = array(&package["selection"], "artifacts")
        .iter()
        .map(|v| key("artifact", v).unwrap())
        .collect();
    // Fixed lease order, before any source read, and held until final immutable
    // bytes and all descriptor/directory-entry checks have been completed.
    let events_store = if events_selected.is_empty() {
        None
    } else {
        Some(Store::event(events, false)?)
    };
    let artifacts_store = if artifacts_selected.is_empty() {
        None
    } else {
        Some(Store::artifacts(artifacts)?)
    };
    // Reserve fixed overhead for bounded selector/window trees and their roots
    // before charging each retained source identity, projection and reference.
    let mut memory = ExportMemory {
        retained: 1024 * 1024,
    };
    let mut seen: BTreeMap<Key, [u8; 32]> = BTreeMap::new();
    let mut windows: BTreeMap<(u64, u32), (u64, u64)> = BTreeMap::new();
    for k in &events_selected {
        if let Key::Event(s, p, n) = *k {
            windows
                .entry((s, p))
                .and_modify(|(lo, hi)| {
                    *lo = (*lo).min(n);
                    *hi = (*hi).max(n);
                })
                .or_insert((n, n));
        }
    }
    let mut markers: BTreeMap<(u64, u32, u64, u64, Option<u64>), u64> = BTreeMap::new();
    let mut event_file = None;
    if let Some((store, basename)) = &events_store {
        let mut file = store.root.file(basename, false)?;
        file.lines(64 * 1024 * 1024, 4096, 100_000, budget.deadline, |line| {
            let value = parse(line, budget).map_err(|e| export_failure(e, budget))?;
            let (k, projected, payload, gap) = source_event(&value, budget)?;
            if gap {
                if let Key::Event(s, p, n) = k
                    && windows
                        .get(&(s, p))
                        .is_some_and(|(lo, hi)| *lo <= n && n <= *hi)
                {
                    let count = if projected["payload_truncated"] == true
                        || projected["flags"].as_u64().is_some_and(|f| f & 1 != 0)
                    {
                        None
                    } else {
                        std::str::from_utf8(&payload)
                            .ok()
                            .and_then(|v| unsigned(&json!(v), false))
                    };
                    let marker = (
                        s,
                        p,
                        n,
                        unsigned(&projected["monotonic_time_ns"], false).unwrap(),
                        count,
                    );
                    if !markers.contains_key(&marker) {
                        if markers.len() >= MAX_GAPS {
                            return Err(frozen::limit());
                        }
                        memory.charge(512)?;
                    }
                    *markers.entry(marker).or_default() += 1;
                }
            } else {
                let digest: [u8; 32] =
                    Sha256::digest(serde_json::to_vec(&value).map_err(|_| frozen::limit())?).into();
                if let Some(previous) = seen.get(&k) {
                    return Err(Error::conflict(if *previous == digest {
                        "The evidence source contains a duplicate identity"
                    } else {
                        "The evidence source contains a conflicting identity"
                    }));
                }
                // Conservative allocation allowance includes map nodes, keys,
                // digests and selected Value trees, before retained growth.
                memory.charge(256)?;
                seen.insert(k, digest);
                if events_selected.contains(&k) {
                    memory.charge(16 * 1024)?;
                    package["records"]["events"]
                        .as_array_mut()
                        .unwrap()
                        .push(projected);
                }
            }
            Ok(())
        })?;
        event_file = Some(file);
    }
    let mut artifact_file = None;
    if let Some(store) = &artifacts_store {
        let mut file = store.root.file("manifest.jsonl", false)?;
        file.lines(16 * 1024 * 1024, 8192, 10_000, budget.deadline, |line| {
            let mut value = parse(line, budget).map_err(|e| export_failure(e, budget))?;
            let digest: [u8; 32] =
                Sha256::digest(serde_json::to_vec(&value).map_err(|_| frozen::limit())?).into();
            let (k, projected) = source_artifact(&mut value)?;
            if let Some(previous) = seen.get(&k) {
                return Err(Error::conflict(if *previous == digest {
                    "The evidence source contains a duplicate identity"
                } else {
                    "The evidence source contains a conflicting identity"
                }));
            }
            memory.charge(256)?;
            seen.insert(k, digest);
            if artifacts_selected.contains(&k) {
                memory.charge(8 * 1024)?;
                package["records"]["artifacts"]
                    .as_array_mut()
                    .unwrap()
                    .push(projected);
            }
            Ok(())
        })?;
        artifact_file = Some(file);
    }
    if events_selected
        .iter()
        .chain(artifacts_selected.iter())
        .any(|k| !seen.contains_key(k))
    {
        return Err(
            Error::new(404, "An exact selected evidence identity was not found")
                .with_code(crate::error::Code::TargetUnavailable),
        );
    }
    let mut verified = BTreeMap::new();
    let mut blobs_directory = None;
    if let Some(store) = &artifacts_store {
        let blobs = store.root.child("blobs")?;
        let mut verified_bytes = 0u64;
        for value in records(&package, "artifacts") {
            frozen::check(budget.deadline)?;
            let expected = unsigned(&value["byte_size"], false).unwrap();
            let hash = value["sha256"].as_str().unwrap();
            if expected > frozen::MAX_BLOB_BYTES {
                return Err(frozen::limit());
            }
            if let Some((size, _)) = verified.get(hash) {
                if *size != expected {
                    return Err(Error::protocol(
                        "The selected artifact byte count or hash is inconsistent",
                    ));
                }
                continue;
            }
            verified_bytes = frozen::verified_total(verified_bytes, expected)?;
            let mut blob = blobs.file(&format!("{hash}.bin"), false)?;
            blob.hash(expected, hash, budget.deadline)?;
            verified.insert(hash.to_owned(), (expected, blob));
        }
        blobs_directory = Some(blobs);
    }
    for ((s, p, n, time, count), occurrences) in markers {
        push_gap(
            &mut package,
            json!({"kind":"queue_drop_marker","session_id":s.to_string(),"process_id":p,"anchor_sequence":n.to_string(),"monotonic_time_ns":time.to_string(),"reported_dropped_count":count.map(|c| c.to_string()),"count_state":if count.is_some(){"reported"}else{"count_unknown"},"occurrences":occurrences}),
            &mut memory,
        )?;
    }
    let mut previous: Option<(u64, u32, u64)> = None;
    for k in seen.keys() {
        frozen::check(budget.deadline)?;
        if let Key::Event(s, p, n) = *k
            && windows
                .get(&(s, p))
                .is_some_and(|(lo, hi)| *lo <= n && n <= *hi)
        {
            if let Some((ps, pp, pn)) = previous
                && (ps, pp) == (s, p)
                && n > pn + 1
            {
                push_gap(
                    &mut package,
                    json!({"kind":"sequence_discontinuity","session_id":s.to_string(),"process_id":p,"first_missing_sequence":(pn+1).to_string(),"last_missing_sequence":(n-1).to_string()}),
                    &mut memory,
                )?;
            }
            previous = Some((s, p, n));
        }
    }
    let mut relationships = Vec::new();
    for (section, kind) in [("events", "event"), ("artifacts", "artifact")] {
        for value in records(&package, section) {
            frozen::check(budget.deadline)?;
            let from = key(kind, &value["key"]).unwrap();
            let claims = match from {
                Key::Event(s, p, _) => vec![
                    (
                        "parent_event",
                        "event",
                        unsigned(&value["parent_event_id"], true)
                            .map(|n| Some(Key::Event(s, p, n))),
                    ),
                    (
                        "event_artifact",
                        "artifact",
                        unsigned(&value["artifact_id"], true).map(|n| Some(Key::Artifact(s, n))),
                    ),
                ],
                Key::Artifact(s, _) => vec![
                    (
                        "parent_artifact",
                        "artifact",
                        unsigned(&value["parent_artifact_id"], true)
                            .map(|n| Some(Key::Artifact(s, n))),
                    ),
                    (
                        "artifact_creator",
                        "event",
                        unsigned(&value["creator_event_id"], true).map(|_| None),
                    ),
                ],
            };
            for (relation, to_kind, claim) in claims {
                let Some(to) = claim else { continue };
                let resolution = match to {
                    None => "insufficient_identity",
                    Some(k) if events_selected.contains(&k) || artifacts_selected.contains(&k) => {
                        "included"
                    }
                    Some(_)
                        if (to_kind == "event" && events_store.is_none())
                            || (to_kind == "artifact" && artifacts_store.is_none()) =>
                    {
                        "not_inspected"
                    }
                    Some(k) if seen.contains_key(&k) => "outside_selection",
                    Some(_) => "missing_in_retained_source",
                };
                if relationships.len() >= MAX_RELATIONSHIPS {
                    return Err(frozen::limit());
                }
                memory.charge(4096)?;
                relationships.push(json!({"from_kind":kind,"from_key":key_value(from),"relation":relation,"to_kind":to_kind,"to_key":to.map(key_value),"resolution":resolution}));
            }
        }
    }
    for relation in &relationships {
        if relation["resolution"] == "missing_in_retained_source" {
            push_gap(
                &mut package,
                json!({"kind":"missing_reference","from_kind":relation["from_kind"],"from_key":relation["from_key"],"relation":relation["relation"],"to_kind":relation["to_kind"],"to_key":relation["to_key"]}),
                &mut memory,
            )?;
        } else if relation["resolution"] == "insufficient_identity" {
            let from = key("artifact", &relation["from_key"]).unwrap();
            let creator = records(&package, "artifacts")
                .iter()
                .find(|v| key("artifact", &v["key"]) == Some(from))
                .unwrap()["creator_event_id"]
                .clone();
            push_gap(
                &mut package,
                json!({"kind":"creator_identity_incomplete","artifact_key":relation["from_key"],"creator_event_id":creator}),
                &mut memory,
            )?;
        }
    }
    package["relationships"] = json!(relationships);
    let bytes = finish_export(package, budget)?;
    if let Some(file) = &event_file {
        file.verify()?;
    }
    if let Some(file) = &artifact_file {
        file.verify()?;
    }
    for (_, file) in verified.values() {
        frozen::check(budget.deadline)?;
        file.verify()?;
    }
    if let Some(directory) = &blobs_directory {
        directory.verify()?;
    }
    if let Some((store, _)) = &events_store {
        store.verify()?;
    }
    if let Some(store) = &artifacts_store {
        store.verify()?;
    }
    frozen::check(budget.deadline)?;
    Ok(bytes)
}
#[cfg(unix)]
fn push_gap(package: &mut Value, gap: Value, memory: &mut ExportMemory) -> Result<()> {
    let gaps = package["gaps"].as_array_mut().unwrap();
    if gaps.len() >= MAX_GAPS {
        return Err(crate::evidence::frozen::limit());
    }
    memory.charge(4096)?;
    gaps.push(gap);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn golden() -> Value {
        serde_json::from_str(include_str!("../assets/evidence-packages/golden-v1.json")).unwrap()
    }
    fn check(value: &Value) -> Value {
        validate_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
    }
    fn seal(value: &mut Value) {
        value["package_id"] = json!(package_id(value).unwrap());
    }
    fn issue(result: &Value, code: &str) -> bool {
        array(result, "issues").iter().any(|i| i["code"] == code)
    }
    fn empty() -> Value {
        let mut v = golden();
        for section in ["events", "artifacts"] {
            v["records"][section] = json!([]);
            v["selection"][section] = json!([]);
            v["coverage"][section] = json!({"selection_state":"not_requested","selected_count":0,"source_scan":"not_read","capture_state":"unknown","limitations":BASE_LIMITATIONS});
        }
        v["relationships"] = json!([]);
        v["gaps"] = json!([]);
        v["coverage"]["selection"] = json!("empty");
        v["provenance"]["consistency"] = json!("empty_selection");
        seal(&mut v);
        v
    }
    fn unresolved_reference(
        value: &mut Value,
        section: &str,
        index: usize,
        relation: &str,
        target: &str,
        resolution: &str,
    ) {
        let (field, to_kind) = match relation {
            "parent_event" => ("parent_event_id", "event"),
            "event_artifact" => ("artifact_id", "artifact"),
            "parent_artifact" => ("parent_artifact_id", "artifact"),
            _ => unreachable!(),
        };
        let from_kind = if section == "events" {
            "event"
        } else {
            "artifact"
        };
        let record = &mut value["records"][section][index];
        record[field] = json!(target);
        let from = record["key"].clone();
        let to = if to_kind == "event" {
            json!({"session_id":from["session_id"],"process_id":from["process_id"],"sequence_number":target})
        } else {
            json!({"session_id":from["session_id"],"artifact_id":target})
        };
        value["relationships"].as_array_mut().unwrap().retain(|r| {
            !(r["from_kind"] == from_kind && r["from_key"] == from && r["relation"] == relation)
        });
        let mut edge = json!({"from_kind":from_kind,"from_key":from,"relation":relation,"to_kind":to_kind,"to_key":to,"resolution":resolution});
        value["relationships"]
            .as_array_mut()
            .unwrap()
            .push(edge.clone());
        let limitation = if resolution == "missing_in_retained_source" {
            edge.as_object_mut().unwrap().remove("resolution");
            edge["kind"] = json!("missing_reference");
            value["gaps"].as_array_mut().unwrap().push(edge);
            "reference_missing"
        } else {
            "reference_outside_selection"
        };
        let limitations = value["coverage"][section]["limitations"]
            .as_array_mut()
            .unwrap();
        if !limitations.contains(&json!(limitation)) {
            limitations.push(json!(limitation));
        }
    }
    fn stream_window(last: u64) -> Value {
        let mut value = golden();
        value["records"]["events"][1]["key"]["sequence_number"] = json!(last.to_string());
        value["selection"]["events"][1]["sequence_number"] = json!(last.to_string());
        for relation in value["relationships"].as_array_mut().unwrap() {
            if relation["from_kind"] == "event" && relation["from_key"]["sequence_number"] == "3" {
                relation["from_key"]["sequence_number"] = json!(last.to_string());
            }
        }
        value
    }
    fn sequence_hole(value: &mut Value, first: u64, last: u64) {
        value["gaps"].as_array_mut().unwrap().push(json!({"kind":"sequence_discontinuity","session_id":"7","process_id":42,"first_missing_sequence":first.to_string(),"last_missing_sequence":last.to_string()}));
        value["coverage"]["events"]["capture_state"] = json!("partial");
        let limitations = value["coverage"]["events"]["limitations"]
            .as_array_mut()
            .unwrap();
        if !limitations.contains(&json!("sequence_discontinuity")) {
            limitations.push(json!("sequence_discontinuity"));
        }
    }
    #[test]
    fn golden_identity_and_reordering_are_semantic_not_authenticity() {
        let mut value = golden();
        assert_eq!(
            value["package_id"],
            "reb-package-v1:sha256:0d7a7e61a4c71c44d77e74ec17ed071a980359427be4b6a475a154e443fc57b7"
        );
        let id = package_id(&value).unwrap();
        assert_eq!(value["package_id"], id);
        let result = check(&value);
        assert_eq!(result["status"], "valid", "{result}");
        assert_eq!(result["origin"], "untrusted_input");
        assert_eq!(result["authenticity"], "not_established");
        assert_eq!(result["artifact_bytes"], "not_present_not_reverified");
        for section in ["events", "artifacts"] {
            value["records"][section].as_array_mut().unwrap().reverse();
            value["selection"][section]
                .as_array_mut()
                .unwrap()
                .reverse();
            value["coverage"][section]["limitations"]
                .as_array_mut()
                .unwrap()
                .reverse();
        }
        value["relationships"].as_array_mut().unwrap().reverse();
        value["coverage"]["excluded_sections"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert_eq!(package_id(&value).unwrap(), id);
        assert_eq!(check(&value)["status"], "valid");
        value["records"]["events"][0]["monotonic_time_ns"] = json!("999");
        assert!(issue(&check(&value), "digest_mismatch"));
        seal(&mut value);
        assert_ne!(value["package_id"], id);
        assert_eq!(check(&value)["status"], "valid");
        assert_eq!(check(&value)["authenticity"], "not_established");
        assert_eq!(check(&empty())["status"], "valid");
    }
    #[test]
    fn canonical_scalar_encoding_and_declared_sets_are_exact() {
        let mut value = empty();
        // This private extra field is intentionally outside the accepted schema.
        // The canonical profile itself is tested independently of acceptance.
        value["extra"] = json!({"é":"é\u{1f680}\n\r\t\u{8}\u{c}\u{0}\"\\/", "a":1});
        let bytes = canonical(&value, &Budget::new()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.contains("\"extra\":{\"a\":1,\"é\":\"é🚀\\n\\r\\t\\b\\f\\u0000\\\"\\\\/\"}"),
            "{text}"
        );
        assert!(!text.contains("package_id"));
        seal(&mut value);
        assert!(issue(&check(&value), "forbidden_metadata_field"));
        let one: Value = parse_bytes(br#"{"a":"\u00e9","b":1}"#).unwrap();
        let two: Value = parse_bytes("{\"b\":1,\"a\":\"é\"}".as_bytes()).unwrap();
        assert_eq!(one, two);
    }
    #[test]
    fn strict_parser_rejects_duplicates_utf8_floats_and_exact_limits() {
        for raw in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":{"x":1,"\u0078":2}}"#,
        ] {
            assert_eq!(parse_bytes(raw).unwrap_err(), ParseError::DuplicateKey);
            assert!(issue(&validate_bytes(raw).unwrap(), "duplicate_json_key"));
        }
        for raw in [
            b"{\"a\":\"\xff\"}".as_slice(),
            br#"{"a":"\ud800"}"#,
            br#"{"a":1e9999}"#,
            br#"{"a":1} trailing"#,
        ] {
            assert!(validate_bytes(raw).is_err());
        }
        for raw in [br#"{"a":1.0}"#.as_slice(), br#"{"a":1e1}"#, br#"{"a":-0}"#] {
            assert!(issue(&validate_bytes(raw).unwrap(), "invalid_shape"));
        }
        assert!(validate_bytes(b"[]").is_err());
        assert!(parse_bytes(br#"{"max":18446744073709551615,"min":-9223372036854775808}"#).is_ok());
        assert_eq!(
            parse_bytes(br#"{"a":18446744073709551616}"#).unwrap_err(),
            ParseError::InvalidNumber
        );
        let string = format!("{{\"a\":\"{}\"}}", "a".repeat(MAX_STRING_BYTES));
        assert!(parse_bytes(string.as_bytes()).is_ok());
        assert_eq!(
            parse_bytes(
                string
                    .replace(
                        &"a".repeat(MAX_STRING_BYTES),
                        &"a".repeat(MAX_STRING_BYTES + 1)
                    )
                    .as_bytes()
            )
            .unwrap_err(),
            ParseError::ResourceLimit
        );
        let escaped = format!("{{\"a\":\"{}\"}}", "\\u0061".repeat(MAX_STRING_BYTES));
        assert!(parse_bytes(escaped.as_bytes()).is_ok());
        let string = format!("{{\"a\":\"{}\"}}", "é".repeat(MAX_STRING_BYTES / 2 + 1));
        assert_eq!(
            parse_bytes(string.as_bytes()).unwrap_err(),
            ParseError::ResourceLimit
        );
        let raw = format!(
            "{{\"a\":{}0{}}}",
            "[".repeat(MAX_DEPTH - 2),
            "]".repeat(MAX_DEPTH - 2)
        );
        assert!(parse_bytes(raw.as_bytes()).is_ok());
        let raw = format!(
            "{{\"a\":{}0{}}}",
            "[".repeat(MAX_DEPTH - 1),
            "]".repeat(MAX_DEPTH - 1)
        );
        assert_eq!(
            parse_bytes(raw.as_bytes()).unwrap_err(),
            ParseError::ResourceLimit
        );
        let mut raw = b"{}".to_vec();
        raw.resize(MAX_BYTES, b' ');
        assert!(parse_bytes(&raw).is_ok());
        raw.push(b' ');
        assert_eq!(parse_bytes(&raw).unwrap_err(), ParseError::ResourceLimit);
        // Root, member key and array consume three nodes; each scalar one.
        let raw = format!("{{\"a\":[{}]}}", vec!["0"; MAX_NODES - 3].join(","));
        assert!(parse_bytes(raw.as_bytes()).is_ok());
        let raw = raw.replacen("]", ",0]", 1);
        assert_eq!(
            parse_bytes(raw.as_bytes()).unwrap_err(),
            ParseError::ResourceLimit
        );
        let budget = Budget {
            deadline: Instant::now(),
        };
        assert_eq!(
            parse(b"{}", &budget).unwrap_err(),
            ParseError::ResourceLimit
        );
        assert!(issue(&validate(b"{}", &budget).unwrap(), "resource_limit"));
    }
    #[test]
    fn privacy_fields_and_canaries_never_escape_even_with_new_digest() {
        for field in [
            "payload",
            "payload_encoding",
            "payload_hash",
            "preview",
            "source",
            "url",
            "headers",
            "authorization",
            "cookie",
            "set-cookie",
            "request_body",
            "response_body",
            "hook_values",
            "content_path",
            "mime_type",
        ] {
            let mut value = golden();
            value["records"]["events"][0][field] =
                json!("CANARY-secret-https://user:pass@host/?token=value#fragment");
            seal(&mut value);
            let result = check(&value);
            assert_eq!(result["status"], "invalid", "{field}: {result}");
            assert!(issue(&result, "forbidden_metadata_field"), "{result}");
            let text = result.to_string();
            assert!(!text.contains("CANARY"));
            assert!(!text.contains("user:pass"));
            assert!(!text.contains("token=value"));
        }
        for field in ["operation", "outcome", "placement"] {
            let mut value = golden();
            value["records"]["events"][0][field] = json!("CANARY-secret");
            seal(&mut value);
            let result = check(&value);
            assert_eq!(result["status"], "invalid");
            assert!(!result.to_string().contains("CANARY"));
        }
        let mut value = golden();
        value["records"]["events"][0]["category"] = json!("network");
        seal(&mut value);
        assert_eq!(check(&value)["status"], "invalid");
        let mut value = golden();
        value["records"]["events"][0]["payload_truncated"] = json!(true);
        seal(&mut value);
        assert_eq!(check(&value)["status"], "invalid");
    }
    #[test]
    fn duplicate_scoped_identities_and_references_fail_closed() {
        let value = golden();
        assert_eq!(check(&value)["status"], "valid");
        for section in ["events", "artifacts"] {
            let mut value = golden();
            let duplicate = value["records"][section][0].clone();
            value["records"][section]
                .as_array_mut()
                .unwrap()
                .push(duplicate);
            seal(&mut value);
            assert!(issue(&check(&value), "duplicate_identity"));
            value["records"][section][0]["navigation_id"] = json!("2");
            seal(&mut value);
            assert!(issue(&check(&value), "conflicting_identity"));
            let mut value = golden();
            let duplicate = value["selection"][section][0].clone();
            value["selection"][section]
                .as_array_mut()
                .unwrap()
                .push(duplicate);
            seal(&mut value);
            assert!(issue(&check(&value), "duplicate_identity"));
        }
        let mut value = golden();
        value["selection"]["events"].as_array_mut().unwrap().pop();
        seal(&mut value);
        assert!(issue(&check(&value), "selection_mismatch"));
        let mut value = golden();
        value["records"]["events"][1]["parent_event_id"] = json!("99");
        let r = value["relationships"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["relation"] == "parent_event")
            .unwrap();
        r["to_key"]["sequence_number"] = json!("99");
        seal(&mut value);
        assert!(issue(&check(&value), "missing_reference"));
        let mut value = golden();
        value["relationships"].as_array_mut().unwrap().clear();
        seal(&mut value);
        assert!(issue(&check(&value), "missing_reference"));
        let mut value = golden();
        let creator = value["relationships"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["relation"] == "artifact_creator")
            .unwrap();
        creator["resolution"] = json!("included");
        creator["to_key"] = json!({"session_id":"7","process_id":42,"sequence_number":"1"});
        seal(&mut value);
        assert!(issue(&check(&value), "invalid_reference_state"));
    }
    #[test]
    fn parent_cycles_are_bounded_and_scoped() {
        let mut value = golden();
        value["records"]["events"][0]["parent_event_id"] = json!("3");
        let r = json!({"from_kind":"event","from_key":value["records"]["events"][0]["key"],"relation":"parent_event","to_kind":"event","to_key":value["records"]["events"][1]["key"],"resolution":"included"});
        value["relationships"].as_array_mut().unwrap().push(r);
        seal(&mut value);
        assert!(issue(&check(&value), "forbidden_cycle"));
        let mut value = golden();
        value["records"]["artifacts"][1]["parent_artifact_id"] = json!("9");
        let r = json!({"from_kind":"artifact","from_key":value["records"]["artifacts"][1]["key"],"relation":"parent_artifact","to_kind":"artifact","to_key":value["records"]["artifacts"][1]["key"],"resolution":"included"});
        value["relationships"].as_array_mut().unwrap().push(r);
        seal(&mut value);
        assert!(issue(&check(&value), "forbidden_cycle"));
    }
    #[test]
    fn coverage_is_scoped_and_does_not_infer_capture_from_selection() {
        let mut value = golden();
        let gap = json!({"kind":"sequence_discontinuity","session_id":"7","process_id":42,"first_missing_sequence":"2","last_missing_sequence":"2"});
        value["gaps"].as_array_mut().unwrap().push(gap);
        value["coverage"]["events"]["capture_state"] = json!("partial");
        value["coverage"]["events"]["limitations"]
            .as_array_mut()
            .unwrap()
            .push(json!("sequence_discontinuity"));
        seal(&mut value);
        assert_eq!(check(&value)["status"], "valid", "{}", check(&value));
        value["gaps"][1]["last_missing_sequence"] = json!("3");
        seal(&mut value);
        assert!(issue(&check(&value), "invalid_coverage"));
        let mut value = golden();
        value["coverage"]["events"]["capture_state"] = json!("partial");
        seal(&mut value);
        assert!(issue(&check(&value), "invalid_coverage"));
        let mut value = empty();
        value["coverage"]["events"]["source_scan"] = json!("complete");
        seal(&mut value);
        assert!(issue(&check(&value), "invalid_coverage"));
        let mut value = golden();
        value["gaps"] = json!([]);
        seal(&mut value);
        assert!(issue(&check(&value), "missing_reference"));
    }
    #[test]
    fn retained_target_existence_is_consistent_across_edges_and_scoped_keys() {
        for first in ["outside_selection", "missing_in_retained_source"] {
            for second in ["outside_selection", "missing_in_retained_source"] {
                for index in [1, 2, 3] {
                    let mut value = golden();
                    unresolved_reference(&mut value, "events", 0, "parent_event", "99", first);
                    unresolved_reference(&mut value, "events", index, "parent_event", "99", second);
                    seal(&mut value);
                    let result = check(&value);
                    let conflict = index == 1 && first != second;
                    assert_eq!(
                        result["status"],
                        if conflict { "invalid" } else { "valid" },
                        "{result}"
                    );
                    assert_eq!(issue(&result, "invalid_reference_state"), conflict);
                    value["relationships"].as_array_mut().unwrap().reverse();
                    assert_eq!(check(&value)["status"], result["status"]);
                }
                for index in [0, 1] {
                    let mut value = golden();
                    unresolved_reference(&mut value, "events", 0, "event_artifact", "99", first);
                    unresolved_reference(
                        &mut value,
                        "artifacts",
                        index,
                        "parent_artifact",
                        "99",
                        second,
                    );
                    seal(&mut value);
                    let result = check(&value);
                    let conflict = index == 0 && first != second;
                    assert_eq!(
                        result["status"],
                        if conflict { "invalid" } else { "valid" },
                        "{result}"
                    );
                    assert_eq!(issue(&result, "invalid_reference_state"), conflict);
                }
            }
        }
    }
    #[test]
    fn sequence_holes_reconcile_targets_and_adjacent_retained_neighbors() {
        for (ranges, valid) in [
            (vec![(2, 2), (3, 4)], false),
            (vec![(2, 3), (3, 4)], false),
            (vec![(2, 2), (4, 4)], true),
            (vec![(2, 4)], true),
        ] {
            let mut value = stream_window(5);
            for (first, last) in ranges {
                sequence_hole(&mut value, first, last);
            }
            seal(&mut value);
            let result = check(&value);
            assert_eq!(
                result["status"],
                if valid { "valid" } else { "invalid" },
                "{result}"
            );
            assert_eq!(issue(&result, "invalid_coverage"), !valid);
            value["gaps"].as_array_mut().unwrap().reverse();
            assert_eq!(check(&value)["status"], result["status"]);
        }
        for target in ["2", "3", "4"] {
            for resolution in ["outside_selection", "missing_in_retained_source"] {
                for index in [1, 2, 3] {
                    let mut value = stream_window(5);
                    unresolved_reference(
                        &mut value,
                        "events",
                        index,
                        "parent_event",
                        target,
                        resolution,
                    );
                    sequence_hole(&mut value, 3, 3);
                    seal(&mut value);
                    let result = check(&value);
                    let conflict =
                        index == 1 && ((target == "3") == (resolution == "outside_selection"));
                    assert_eq!(
                        result["status"],
                        if conflict { "invalid" } else { "valid" },
                        "{result}"
                    );
                    assert_eq!(issue(&result, "invalid_coverage"), conflict);
                }
            }
        }
        let mut value = stream_window(u64::MAX);
        sequence_hole(&mut value, 2, u64::MAX - 1);
        // Queue-loss anchors may overlap sequence holes without asserting that
        // the anchor itself is a retained ordinary event.
        value["gaps"].as_array_mut().unwrap().push(json!({"kind":"queue_drop_marker","session_id":"7","process_id":42,"anchor_sequence":"3","monotonic_time_ns":"31","reported_dropped_count":null,"count_state":"count_unknown","occurrences":1}));
        value["coverage"]["events"]["limitations"]
            .as_array_mut()
            .unwrap()
            .push(json!("capture_gap"));
        seal(&mut value);
        assert_eq!(check(&value)["status"], "valid", "{}", check(&value));
    }
    #[test]
    fn known_truncation_drives_coverage_without_rewriting_nullable_history() {
        for flags in std::iter::once(Value::Null).chain((0..=7).map(|flags| json!(flags))) {
            for truncated in [Value::Null, json!(false), json!(true)] {
                let mut value = golden();
                let event = &mut value["records"]["events"][0];
                event["operation"] = Value::Null;
                event["flags"] = flags.clone();
                event["payload_truncated"] = truncated.clone();
                let known = truncated == true || flags.as_u64().is_some_and(|flags| flags & 1 != 0);
                let conflict = flags
                    .as_u64()
                    .zip(truncated.as_bool())
                    .is_some_and(|(flags, truncated)| (flags & 1 != 0) != truncated);
                seal(&mut value);
                let result = check(&value);
                assert_eq!(
                    issue(&result, "invalid_coverage"),
                    known && !conflict,
                    "{result}"
                );
                assert_eq!(issue(&result, "invalid_shape"), conflict, "{result}");
                if known {
                    value["coverage"]["events"]["limitations"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("payload_was_truncated"));
                    seal(&mut value);
                }
                assert_eq!(
                    check(&value)["status"],
                    if conflict { "invalid" } else { "valid" },
                    "{}",
                    check(&value)
                );
                assert_eq!(value["records"]["events"][0]["flags"], flags);
                assert_eq!(
                    value["records"]["events"][0]["payload_truncated"],
                    truncated
                );
            }
        }
    }
    #[test]
    fn versions_counts_invalid_ids_and_issue_output_are_bounded() {
        for (field, changed, code) in [
            ("protocol_version", json!(2), "unsupported_version"),
            (
                "serialization_profile",
                json!("future"),
                "unsupported_profile",
            ),
            ("redaction_profile", json!("future"), "unsupported_profile"),
            ("semantics_profile", json!("future"), "unsupported_profile"),
        ] {
            let mut value = golden();
            value[field] = changed;
            let result = check(&value);
            assert_eq!(result["status"], "unsupported");
            assert!(issue(&result, code));
            assert!(result["package_id"].is_null());
        }
        for identifier in ["", "00", "-1", "18446744073709551616", "é"] {
            let mut value = golden();
            value["records"]["events"][0]["key"]["session_id"] = json!(identifier);
            assert_eq!(check(&value)["status"], "invalid");
            assert!(package_id(&value).is_err());
        }
        for (section, max) in [("events", MAX_EVENTS), ("artifacts", MAX_ARTIFACTS)] {
            let mut value = golden();
            let record = value["records"][section][0].clone();
            value["records"][section] = json!(vec![record; max + 1]);
            assert_eq!(check(&value)["status"], "invalid");
        }
        for (section, max) in [("relationships", MAX_RELATIONSHIPS), ("gaps", MAX_GAPS)] {
            let mut value = golden();
            value[section] = json!(vec![value[section][0].clone(); max + 1]);
            assert_eq!(check(&value)["status"], "invalid");
        }
        let mut value = golden();
        value["records"]["events"] = json!(vec![json!({}); MAX_EVENTS]);
        let result = check(&value);
        assert_eq!(array(&result, "issues").len(), 64);
        assert_eq!(result["issues_truncated"], true);
        assert!(serde_json::to_vec(&result).unwrap().len() < 64 * 1024);
        for issue in array(&result, "issues") {
            assert_eq!(issue.as_object().unwrap().len(), 3);
            assert!(issue["index"].is_null() || issue["index"].as_u64().unwrap() < 4096);
        }
    }
    #[test]
    fn unresolved_references_and_queue_observations_keep_distinct_states() {
        for resolution in ["outside_selection", "missing_in_retained_source"] {
            let mut value = golden();
            value["records"]["events"][1]["parent_event_id"] = json!("99");
            let relation = value["relationships"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["relation"] == "parent_event")
                .unwrap();
            relation["to_key"]["sequence_number"] = json!("99");
            relation["resolution"] = json!(resolution);
            let mut gap = relation.clone();
            gap.as_object_mut().unwrap().remove("resolution");
            gap["kind"] = json!("missing_reference");
            let limitation = if resolution == "outside_selection" {
                "reference_outside_selection"
            } else {
                value["gaps"].as_array_mut().unwrap().push(gap);
                "reference_missing"
            };
            value["coverage"]["events"]["limitations"]
                .as_array_mut()
                .unwrap()
                .push(json!(limitation));
            seal(&mut value);
            assert_eq!(check(&value)["status"], "valid", "{}", check(&value));
        }
        let mut value = golden();
        value["records"]["artifacts"] = json!([]);
        value["selection"]["artifacts"] = json!([]);
        value["coverage"]["artifacts"] = empty()["coverage"]["artifacts"].clone();
        value["relationships"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["from_kind"] != "artifact");
        let relation = value["relationships"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["relation"] == "event_artifact")
            .unwrap();
        relation["resolution"] = json!("not_inspected");
        value["gaps"] = json!([]);
        value["coverage"]["events"]["limitations"]
            .as_array_mut()
            .unwrap()
            .push(json!("reference_not_inspected"));
        seal(&mut value);
        assert_eq!(check(&value)["status"], "valid", "{}", check(&value));
        let mut value = golden();
        let gap = json!({"kind":"queue_drop_marker","session_id":"7","process_id":42,
            "anchor_sequence":"3","monotonic_time_ns":"31","reported_dropped_count":null,
            "count_state":"count_unknown","occurrences":2});
        value["gaps"].as_array_mut().unwrap().push(gap.clone());
        value["coverage"]["events"]["capture_state"] = json!("partial");
        value["coverage"]["events"]["limitations"]
            .as_array_mut()
            .unwrap()
            .push(json!("capture_gap"));
        seal(&mut value);
        assert_eq!(check(&value)["status"], "valid", "{}", check(&value));
        value["gaps"].as_array_mut().unwrap().push(gap);
        value["gaps"][2]["occurrences"] = json!(3);
        seal(&mut value);
        assert!(issue(&check(&value), "duplicate_identity"));
    }
    #[test]
    fn exact_record_and_collection_limits_are_reachable() {
        let mut value = empty();
        let fixture = golden();
        for (section, count) in [("events", MAX_EVENTS), ("artifacts", MAX_ARTIFACTS)] {
            let mut values = Vec::new();
            for n in 1..=count {
                let mut record = fixture["records"][section][0].clone();
                if section == "events" {
                    record["key"]["sequence_number"] = json!(n.to_string());
                    record["artifact_id"] = json!("0");
                } else {
                    record["key"]["artifact_id"] = json!(n.to_string());
                    record["creator_event_id"] = json!("0");
                }
                values.push(record);
            }
            value["selection"][section] =
                json!(values.iter().map(|r| r["key"].clone()).collect::<Vec<_>>());
            value["records"][section] = json!(values);
            value["coverage"][section]["selected_count"] = json!(count);
            value["coverage"][section]["selection_state"] = json!("complete");
            value["coverage"][section]["source_scan"] = json!("complete");
        }
        value["coverage"]["selection"] = json!("complete");
        value["provenance"]["consistency"] = json!("cooperative_stopped_store_v1");
        seal(&mut value);
        assert_eq!(check(&value)["status"], "valid", "{}", check(&value));
        for (section, maximum) in [("relationships", MAX_RELATIONSHIPS), ("gaps", MAX_GAPS)] {
            let mut value = golden();
            value[section] = json!(vec![value[section][0].clone(); maximum]);
            seal(&mut value);
            assert!(!issue(&check(&value), "resource_limit"));
            let next = value[section][0].clone();
            value[section].as_array_mut().unwrap().push(next);
            assert!(issue(&check(&value), "resource_limit"));
        }
    }
    #[test]
    fn legacy_nulls_native_ranges_and_registry_stay_source_owned() {
        let mut value = golden();
        let event = &mut value["records"]["events"][0];
        event["protocol_version"] = json!(2);
        event["tab_id"] = Value::Null;
        event["flags"] = Value::Null;
        event["payload_truncated"] = Value::Null;
        event["operation"] = Value::Null;
        event["encoded_data_length"] = json!(i64::MIN.to_string());
        event["decoded_body_length"] = json!(i64::MAX.to_string());
        event["monotonic_time_ns"] = json!(u64::MAX.to_string());
        seal(&mut value);
        assert_eq!(check(&value)["status"], "valid", "{}", check(&value));
        value["records"]["events"][0]["flags"] = json!(0);
        seal(&mut value);
        assert_eq!(check(&value)["status"], "valid");
        value["records"]["events"][0]["tab_id"] = json!(0);
        seal(&mut value);
        assert_eq!(check(&value)["status"], "invalid");
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/evidence-package-v1.schema.json"
        ))
        .unwrap();
        let allowed = schema["$defs"]["EvidencePackageOperation"]["anyOf"][0]["enum"]
            .as_array()
            .unwrap();
        let names: BTreeSet<_> = allowed.iter().filter_map(Value::as_str).collect();
        assert_eq!(names, AUDIO_OPERATIONS.into_iter().collect());
        let sources = concat!(
            include_str!(
                "../../../browser/integration/brave/patches/chromium/0002-record-web-audio-function-calls.patch"
            ),
            include_str!(
                "../../../browser/integration/brave/patches/0004-observe-native-web-audio-readbacks.patch"
            )
        );
        for operation in AUDIO_OPERATIONS {
            assert!(sources.contains(operation), "{operation}");
        }
    }
    #[cfg(unix)]
    #[test]
    fn export_request_memory_and_whole_deadline_bounds_are_exact() {
        let empty = json!({"protocol_version":1,"selection":{"events":[],"artifacts":[]}});
        let raw = serde_json::to_vec(&empty).unwrap();
        let path = std::path::Path::new("/nonexistent-source-that-empty-selection-must-not-read");
        let past = Budget {
            deadline: Instant::now(),
        };
        assert_eq!(
            export_with_budget(&raw, path, path, &past)
                .unwrap_err()
                .status,
            408
        );
        assert_eq!(
            finish_export(empty_package(empty["selection"].clone()), &past)
                .unwrap_err()
                .status,
            408
        );
        let mut exact = raw.clone();
        exact.resize(MAX_EXPORT_REQUEST_BYTES, b' ');
        assert!(export_request(&exact, &Budget::new()).is_ok());
        exact.push(b' ');
        assert_eq!(
            export_request(&exact, &Budget::new()).unwrap_err().status,
            400
        );
        for (section, kind, count) in [
            ("events", "event", MAX_EVENTS),
            ("artifacts", "artifact", MAX_ARTIFACTS),
        ] {
            let mut request = empty.clone();
            request["selection"][section] = json!(
                (1..=count)
                    .map(|n| key_value(if kind == "event" {
                        Key::Event(1, 1, n as u64)
                    } else {
                        Key::Artifact(1, n as u64)
                    }))
                    .collect::<Vec<_>>()
            );
            assert!(export_request(&serde_json::to_vec(&request).unwrap(), &Budget::new()).is_ok());
            request["selection"][section]
                .as_array_mut()
                .unwrap()
                .push(key_value(if kind == "event" {
                    Key::Event(1, 1, (count + 1) as u64)
                } else {
                    Key::Artifact(1, (count + 1) as u64)
                }));
            assert_eq!(
                export_request(&serde_json::to_vec(&request).unwrap(), &Budget::new())
                    .unwrap_err()
                    .status,
                400
            );
        }
        // Reserve fixed overhead for bounded selector/window trees and their roots
        // before charging each retained source identity, projection and reference.
        let mut memory = ExportMemory {
            retained: 1024 * 1024,
        };
        memory.charge(31 * 1024 * 1024).unwrap();
        assert_eq!(memory.charge(1).unwrap_err().status, 413);
        let mut total = 0;
        for _ in 0..8 {
            total = crate::evidence::frozen::verified_total(total, 16 * 1024 * 1024).unwrap();
        }
        assert_eq!(total, 128 * 1024 * 1024);
        assert_eq!(
            crate::evidence::frozen::verified_total(total, 1)
                .unwrap_err()
                .status,
            413
        );
        assert_eq!(
            crate::evidence::frozen::verified_total(0, 16 * 1024 * 1024 + 1)
                .unwrap_err()
                .status,
            413
        );
    }
    #[cfg(unix)]
    #[test]
    fn source_operation_projection_uses_exact_full_registry_and_historical_nulls() {
        let source = include_bytes!("../assets/evidence-packages/source-v1/events.jsonl");
        let first = source.split(|b| *b == b'\n').next().unwrap();
        let original: Value = serde_json::from_slice(first).unwrap();
        for operation in AUDIO_OPERATIONS {
            let mut value = original.clone();
            value["payload"] = json!(hex::encode(operation));
            value["payload_size"] = json!(operation.len());
            let (_, projected, _, _) = source_event(&value, &Budget::new()).unwrap();
            assert_eq!(projected["operation"], operation);
            assert_eq!(projected["placement"], "unknown");
            assert_eq!(projected["outcome"], "not_recorded");
            value["flags"] = json!(1);
            value["payload_truncated"] = json!(true);
            assert!(source_event(&value, &Budget::new()).unwrap().1["operation"].is_null());
        }
        for payload in [
            "AudioBuffer.getChannelData CANARY",
            "AudioBuffer.getChannel",
            "CANARY_UNKNOWN_OPERATION",
        ] {
            let mut value = original.clone();
            value["payload"] = json!(hex::encode(payload));
            value["payload_size"] = json!(payload.len());
            assert!(source_event(&value, &Budget::new()).unwrap().1["operation"].is_null());
        }
        let mut legacy = original;
        legacy.as_object_mut().unwrap().remove("payload_truncated");
        legacy["flags"] = json!(1);
        let (_, projection, _, _) = source_event(&legacy, &Budget::new()).unwrap();
        assert!(projection["payload_truncated"].is_null());
        assert!(projection["operation"].is_null());
        let mut package = empty_package(json!({"events":[projection["key"]],"artifacts":[]}));
        package["records"]["events"] = json!([projection]);
        let (limitations, _) =
            coverage_observations(&package, "events", "event", &Budget::new()).unwrap();
        assert!(limitations.contains("payload_was_truncated"));
    }
}
