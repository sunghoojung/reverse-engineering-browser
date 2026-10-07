use crate::{
    error::{Error, Result},
    evidence, validation,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

type Reference = (String, u32, String);
const RELATIONS: [&str; 4] = [
    "parent_event",
    "request_initiator",
    "request_lifecycle",
    "artifact_request",
];
const SOURCES: [&str; 8] = [
    "canvas",
    "webgl",
    "web_audio",
    "navigator",
    "permissions",
    "storage",
    "webrtc",
    "runtime",
];
fn reference(value: &Value) -> Result<Reference> {
    validation::canonical(&value["session_id"], 64, true, "session_id")?;
    let pid =
        validation::integer(&value["process_id"], "process_id", 0, u64::from(u32::MAX))? as u32;
    validation::canonical(&value["sequence_number"], 64, true, "sequence_number")?;
    Ok((
        value["session_id"].as_str().unwrap().into(),
        pid,
        value["sequence_number"].as_str().unwrap().into(),
    ))
}
fn step(value: &Value, relation: &str, confidence: &str) -> Result<Value> {
    let (session, pid, sequence) = reference(value)?;
    if !matches!(value["protocol_version"].as_u64(), Some(2 | 3))
        || !(SOURCES.contains(&value["category"].as_str().unwrap_or(""))
            || ["artifact", "network", "vm", "wasm"]
                .contains(&value["category"].as_str().unwrap_or("")))
    {
        return Err(Error::bad("Origin trace input contains a malformed event"));
    }
    validation::text(&value["type"], "Event operation", 256, false, false)?;
    for field in ["monotonic_time_ns", "frame_id", "artifact_id", "request_id"] {
        validation::canonical(&value[field], 64, false, field)?;
    }
    let payload = value["payload"].as_str().unwrap_or("");
    let decoded = hex::decode(payload)
        .map_err(|_| Error::bad("Origin trace input contains a malformed event payload"))?;
    if payload.len() > 256
        || value["payload_encoding"] != "hex"
        || value["payload_size"] != decoded.len()
    {
        return Err(Error::bad(
            "Origin trace input contains a malformed event payload",
        ));
    }
    Ok(
        json!({"event":{"session_id":session,"process_id":pid,"sequence_number":sequence},"monotonic_time_ns":value["monotonic_time_ns"],"category":value["category"],"operation":value["type"],"frame_id":value["frame_id"],"artifact_id":value["artifact_id"],"request_id":value["request_id"],"relation":relation,"confidence":confidence,"value":String::from_utf8_lossy(&decoded)}),
    )
}
fn gap(reason: &str, after: usize, detail: &str) -> Value {
    json!({"reason":reason,"after_step":after,"detail":detail})
}
pub fn build(
    events: &[Value],
    edges: &[Value],
    artifacts: &[Value],
    request_id: &str,
    root_process: Option<u32>,
    root_sequence: Option<&str>,
) -> Result<Value> {
    validation::canonical(&json!(request_id), 64, false, "request_id")?;
    if root_process.is_some() != root_sequence.is_some() {
        return Err(Error::bad(
            "Root process ID and sequence number must be supplied together",
        ));
    }
    if let Some(sequence) = root_sequence {
        validation::canonical(&json!(sequence), 64, false, "root_sequence_number")?;
    }
    let mut by_reference = BTreeMap::new();
    let mut capture_gaps = Vec::new();
    for event in events {
        let key = reference(event)?;
        // Queue-loss metadata deliberately shares the last retained event's
        // reference. It must never replace that event or satisfy an edge.
        if event["type"] == "gap" {
            let marker = step(event, "trace_target", "observed")?;
            validation::canonical(&marker["value"], 64, true, "Gap drop count")?;
            if event["payload_truncated"] != false {
                return Err(Error::bad("Origin trace input contains a malformed gap"));
            }
            capture_gaps.push(key);
        } else if by_reference.insert(key, event).is_some() {
            return Err(Error::bad(
                "Origin trace input contains a duplicate event reference",
            ));
        }
    }
    let mut by_source: BTreeMap<Reference, Vec<&Value>> = BTreeMap::new();
    for edge in edges {
        validation::fields(
            edge,
            &[
                "protocol_version",
                "session_id",
                "from_process_id",
                "from_sequence_number",
                "to_process_id",
                "to_sequence_number",
                "relation",
                "confidence",
                "request_id",
                "artifact_id",
            ],
            "Origin trace edge",
        )?;
        if edge["protocol_version"] != 1
            || !RELATIONS.contains(&edge["relation"].as_str().unwrap_or(""))
            || !["observed", "correlated"].contains(&edge["confidence"].as_str().unwrap_or(""))
        {
            return Err(Error::bad("Origin trace store contains a malformed edge"));
        }
        for field in ["session_id", "from_sequence_number", "to_sequence_number"] {
            validation::canonical(&edge[field], 64, true, field)?;
        }
        for field in ["request_id", "artifact_id"] {
            validation::canonical(&edge[field], 64, false, field)?;
        }
        let from = validation::integer(
            &edge["from_process_id"],
            "from_process_id",
            0,
            u64::from(u32::MAX),
        )? as u32;
        let to = validation::integer(
            &edge["to_process_id"],
            "to_process_id",
            0,
            u64::from(u32::MAX),
        )? as u32;
        if from == to && edge["from_sequence_number"] == edge["to_sequence_number"] {
            return Err(Error::bad("Origin trace store contains a self edge"));
        }
        by_source
            .entry((
                edge["session_id"].as_str().unwrap().into(),
                from,
                edge["from_sequence_number"].as_str().unwrap().into(),
            ))
            .or_default()
            .push(edge);
    }
    let candidates: Vec<_> = events
        .iter()
        .filter(|e| {
            e["type"] != "gap" && e["category"] == "network" && e["request_id"] == request_id
        })
        .collect();
    let preferred = if let (Some(pid), Some(sequence)) = (root_process, root_sequence) {
        candidates
            .into_iter()
            .filter(|e| e["process_id"] == pid && e["sequence_number"] == sequence)
            .collect::<Vec<_>>()
    } else {
        let mut selected = Vec::new();
        for operation in ["request_started", "request_initiated", ""] {
            selected = candidates
                .iter()
                .copied()
                .filter(|e| operation.is_empty() || e["type"] == operation)
                .collect();
            if !selected.is_empty() {
                break;
            }
        }
        selected
    };
    let mut steps = Vec::new();
    let mut gaps = Vec::new();
    let mut observed = 0;
    let mut correlated = 0;
    let status = if preferred.len() > 1 && root_process.is_none() {
        gaps.push(gap(
            "ambiguous_request",
            0,
            "More than one request start uses this identifier. Select a concrete request row.",
        ));
        "ambiguous"
    } else if preferred.len() != 1 {
        "empty"
    } else {
        let mut current = preferred[0];
        let mut visited = BTreeSet::from([reference(current)?]);
        steps.push(step(current, "trace_target", "observed")?);
        while steps.len() < 32 {
            let mut candidates = by_source
                .get(&reference(current)?)
                .cloned()
                .unwrap_or_default();
            candidates.sort_by(|a, b| {
                RELATIONS
                    .iter()
                    .position(|r| a["relation"].as_str() == Some(*r))
                    .cmp(
                        &RELATIONS
                            .iter()
                            .position(|r| b["relation"].as_str() == Some(*r)),
                    )
                    .then_with(|| {
                        b["to_sequence_number"]
                            .as_str()
                            .unwrap()
                            .parse::<u64>()
                            .unwrap()
                            .cmp(
                                &a["to_sequence_number"]
                                    .as_str()
                                    .unwrap()
                                    .parse::<u64>()
                                    .unwrap(),
                            )
                    })
            });
            let Some(edge) = candidates.first() else {
                if !SOURCES.contains(&current["category"].as_str().unwrap_or("")) {
                    gaps.push(gap(
                        "no_predecessor",
                        steps.len() - 1,
                        "No earlier observed relationship reaches this event.",
                    ));
                }
                break;
            };
            let target = (
                edge["session_id"].as_str().unwrap().into(),
                edge["to_process_id"].as_u64().unwrap() as u32,
                edge["to_sequence_number"].as_str().unwrap().into(),
            );
            let Some(event) = by_reference.get(&target) else {
                gaps.push(gap(
                    "missing_event",
                    steps.len() - 1,
                    "The highest-priority predecessor is outside the retained evidence window.",
                ));
                break;
            };
            if !visited.insert(target) {
                gaps.push(gap(
                    "cycle",
                    steps.len() - 1,
                    "The correlation index contains a cycle, so traversal stopped safely.",
                ));
                break;
            }
            steps.push(step(
                event,
                edge["relation"].as_str().unwrap(),
                edge["confidence"].as_str().unwrap(),
            )?);
            if edge["confidence"] == "observed" {
                observed += 1;
            } else {
                correlated += 1;
            }
            current = event;
        }
        if steps.len() == 32 {
            gaps.push(gap(
                "step_limit",
                31,
                "The bounded trace step limit was reached.",
            ));
        }
        let marker_count = capture_gaps
            .iter()
            .filter(|(session, process, _)| {
                steps.iter().any(|s| {
                    s["event"]["session_id"] == session.as_str()
                        && s["event"]["process_id"] == *process
                })
            })
            .count();
        if marker_count > 0 {
            gaps.push(gap(
                "capture_gap",
                0,
                &format!(
                    "The retained window contains {marker_count} native queue-drop markers in this trace's session/process streams. Counts may overlap; these markers do not identify a missing predecessor or prove value flow."
                ),
            ));
        }
        if gaps.is_empty() {
            "complete"
        } else {
            "partial"
        }
    };
    let linked = steps.len().saturating_sub(1);
    let denominator = linked + gaps.len();
    let percent = if denominator == 0 {
        0
    } else {
        ((linked * 100) as f64 / denominator as f64).round_ties_even() as usize
    };
    let selected: Vec<_> = artifacts
        .iter()
        .filter(|a| {
            a["artifact_id"] != "0" && steps.iter().any(|s| s["artifact_id"] == a["artifact_id"])
        })
        .map(|a| {
            let mut public = evidence::public_artifact(a);
            public.as_object_mut().unwrap().retain(|key, _| {
                [
                    "artifact_id",
                    "kind",
                    "url",
                    "sha256",
                    "byte_size",
                    "creator_event_id",
                    "parent_artifact_id",
                ]
                .contains(&key.as_str())
            });
            public
        })
        .collect();
    Ok(
        json!({"contract_version":1,"document_kind":"origin-trace","request_id":request_id,"status":status,"steps":steps,"gaps":gaps,"coverage":{"linked_steps":linked,"observed_links":observed,"correlated_links":correlated,"gap_count":gaps.len(),"percent":percent},"artifacts":selected}),
    )
}
