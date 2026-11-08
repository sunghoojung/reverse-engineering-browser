use crate::{
    error::{Error, Result},
    evidence, validation,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

type Reference = (String, u32, String);
/// Raw request body bytes keyed by the retained event that carries them.
pub type RequestBodies = BTreeMap<Reference, Vec<u8>>;
// Stored edge relations in priority order. The two invocation relations are
// exact identities drawn by the broker's index (protocol/native-js-invocation-v1.md).
const RELATIONS: [&str; 6] = [
    "parent_event",
    "request_initiator",
    "request_lifecycle",
    "artifact_request",
    "issued_during_invocation",
    "invocation_settlement",
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
/// What a JavaScript invocation record says, without its binary payload: an
/// invocation ID, a state, a kind and a length. Digests are never shown here.
fn invocation_value(value: &Value) -> Option<String> {
    const KINDS: [&str; 14] = [
        "integer",
        "number",
        "string",
        "symbol",
        "undefined",
        "null",
        "boolean",
        "BigInt",
        "object",
        "function",
        "array",
        "ArrayBuffer",
        "view",
        "promise",
    ];
    let kind = |k: u8| KINDS.get(usize::from(k).wrapping_sub(1)).copied();
    match value["type"].as_str()? {
        "js_invocation_start" => {
            let start = crate::js_invocation::start(value)?;
            Some(format!(
                "invocation {} started at site {} with {} argument(s){}",
                start.invocation_id,
                start.site_slot,
                start.argument_count,
                match (start.parent_invocation_id, start.parent_unknown) {
                    (0, true) => ", parent unknown".to_owned(),
                    (0, false) => String::new(),
                    (parent, _) => format!(", inside invocation {parent}"),
                }
            ))
        }
        "js_invocation_settle" => {
            let settle = crate::js_invocation::settle(value)?;
            Some(format!(
                "invocation {} {}: {}{}{}",
                settle.invocation_id,
                if settle.fulfilled {
                    "fulfilled"
                } else {
                    "rejected"
                },
                kind(settle.value_kind)?,
                if settle.value_length != 0 {
                    format!(", length {}", settle.value_length)
                } else {
                    String::new()
                },
                if settle.digest.is_some() {
                    ", digest retained"
                } else {
                    ""
                }
            ))
        }
        "js_invocation_request" => {
            let request = crate::js_invocation::request(value)?;
            Some(if request.inside {
                format!(
                    "request started inside invocation {}",
                    request.invocation_id
                )
            } else {
                "request started outside script while an invocation was open".to_owned()
            })
        }
        _ => None,
    }
}
fn overflow_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed overflow field"),
    )
}
/// Compact identity for a Wasm sample a budget refused. None is a malformed
/// record, which the caller rejects instead of showing the bytes as text.
fn overflow_summary(value: &Value) -> Option<String> {
    let kind = value["type"].as_str()?;
    let indirect = kind == "wasm_indirect_overflow";
    if !indirect && kind != "wasm_dispatch_overflow" {
        return None;
    }
    // An artifact id or a parent would present this identity as a full observation.
    if value["artifact_id"] != "0" || value["parent_event_id"] != "0" {
        return None;
    }
    let payload = value["payload"].as_str()?;
    let bytes = hex::decode(payload).ok()?;
    let size = if indirect { 40 } else { 32 };
    if bytes.len() != size
        || value["payload_size"] != size
        || u16::from_le_bytes(bytes[0..2].try_into().ok()?) != 1
        || u16::from_le_bytes(bytes[2..4].try_into().ok()?) != size as u16
        || bytes[5] != 0
    {
        return None;
    }
    if indirect {
        if u64::from_le_bytes(bytes[32..40].try_into().ok()?) != 0 {
            return None;
        }
    } else if overflow_u32(&bytes, 28) != 0 {
        return None;
    }
    let record_kind = bytes[4];
    let ring = u16::from_le_bytes(bytes[6..8].try_into().ok()?);
    let omitted_at = if indirect { 28 } else { 24 };
    let omitted = overflow_u32(&bytes, omitted_at);
    let label = if indirect {
        "call_indirect"
    } else {
        "br_table"
    };
    if record_kind == 2 {
        if ring != 0 || omitted == 0 || bytes[8..omitted_at].iter().any(|byte| *byte != 0) {
            return None;
        }
        return Some(format!(
            "Wasm {label} overflow omitted {omitted} identities past the ring. Not a full observation."
        ));
    }
    let limit = 16 * 1024 * 1024;
    let function = overflow_u32(&bytes, 8);
    let offset = overflow_u32(&bytes, 12);
    if record_kind != 1
        || omitted != 0
        || ring >= 32
        || function >= limit
        || offset < 8
        || offset >= limit
    {
        return None;
    }
    if !indirect {
        let selector = overflow_u32(&bytes, 16);
        let arms = overflow_u32(&bytes, 20);
        if arms >= limit {
            return None;
        }
        return Some(format!(
            "Wasm br_table overflow identity: function {function}, byte {offset}, selector {selector}, arms {arms}, ring {ring}. Not a full observation."
        ));
    }
    let table = overflow_u32(&bytes, 16);
    let slot = overflow_u32(&bytes, 20);
    let resolution = overflow_u32(&bytes, 24);
    let name =
        ["resolved", "null", "out-of-bounds", "foreign", "unresolved"].get(resolution as usize)?;
    if table >= limit {
        return None;
    }
    Some(format!(
        "Wasm call_indirect overflow identity: caller {function}, byte {offset}, table {table}, slot {slot}, resolution {name}, ring {ring}. Not a full observation."
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
    let text = match value["type"].as_str() {
        Some(kind) if kind.starts_with("js_invocation_") => invocation_value(value)
            .ok_or_else(|| Error::bad("Origin trace input contains a malformed event payload"))?,
        Some("wasm_dispatch_overflow" | "wasm_indirect_overflow") => overflow_summary(value)
            .ok_or_else(|| Error::bad("Origin trace input contains a malformed event payload"))?,
        _ => binary_record_summary(value, decoded.len())
            .unwrap_or_else(|| String::from_utf8_lossy(&decoded).into_owned()),
    };
    Ok(
        json!({"event":{"session_id":session,"process_id":pid,"sequence_number":sequence},"monotonic_time_ns":value["monotonic_time_ns"],"category":value["category"],"operation":value["type"],"frame_id":value["frame_id"],"artifact_id":value["artifact_id"],"request_id":value["request_id"],"relation":relation,"confidence":confidence,"value":text}),
    )
}
// Request target and body records are fixed binary layouts
// (protocol/native-network-v2.md), not text. A step names the record instead
// of decoding it, so no NUL or control byte reads as captured text; Traffic
// decodes their fields. The Swift builder writes the same summary.
fn binary_record_summary(value: &Value, size: usize) -> Option<String> {
    let operation = value["type"].as_str()?;
    let network = value["category"] == "network"
        && matches!(
            operation,
            "request_target"
                | "request_body"
                | "request_initiator_stack"
                | "script_identity"
                | "request_watch_match"
        );
    let observation = value["category"] == "runtime"
        && matches!(
            operation,
            "listener_dispatch"
                | "timer_observation"
                | "csp_violation"
                | "exception_observation"
                | "dom_mutation"
        );
    let where_shown = if network {
        "Traffic shows its fields"
    } else {
        "decoded on read"
    };
    (network || observation).then(|| {
        format!("Binary {operation} record, {size} bytes, not shown as text; {where_shown}")
    })
}
fn gap(reason: &str, after: usize, detail: &str) -> Value {
    json!({"reason":reason,"after_step":after,"detail":detail})
}
// `monotonic_time_ns` proximity is a declared correlation input in its own
// right, and a weaker one than the identity keys the edge index joins on. It is
// consulted only where the identity chain has already ended, and only for a
// cross-process record of the same retained request: the renderer-to-browser
// hop that initiator resolution failed to close. One millisecond bounds that
// hop with room to spare while staying far below navigation scale.
const ADJACENCY_WINDOW_NS: u64 = 1_000_000;
// Canonical decimal only, matching the step projection and the native builder,
// so a non-canonical sibling cannot count toward the uniqueness test in one
// implementation and be skipped in the other.
fn monotonic(value: &Value) -> Option<u64> {
    validation::canonical(&value["monotonic_time_ns"], 64, false, "monotonic_time_ns").ok()
}
// Exactly one surviving candidate, or none. Two adjacent records are a tie this
// function must not break; reporting the nearer one would present a choice
// between guesses as evidence. A candidate must also sit at or before the
// current event, so cross-process clock skew can drop a real pair but can never
// invent an order.
fn adjacent_candidate<'a>(
    retained: &BTreeMap<Reference, &'a Value>,
    visited: &BTreeSet<Reference>,
    current: &Value,
) -> Option<&'a Value> {
    let now = monotonic(current)?;
    // Scoped to the network lifecycle record this class was measured on. An
    // artifact, VM or Wasm head keeps the bare gap rather than a claim no lane
    // has characterised.
    if current["category"] != "network" || current["request_id"].as_str()? == "0" {
        return None;
    }
    let mut found = None;
    for (key, event) in retained {
        if visited.contains(key)
            || event["session_id"] != current["session_id"]
            || event["category"] != "network"
            || event["request_id"] != current["request_id"]
            || event["process_id"] == current["process_id"]
        {
            continue;
        }
        let Some(then) = monotonic(event) else {
            continue;
        };
        if then > now || now - then > ADJACENCY_WINDOW_NS {
            continue;
        }
        if found.replace(*event).is_some() {
            return None;
        }
    }
    found
}
/// A request body is searched only as retained raw bytes, at most this many.
const REQUEST_BODY_LIMIT: usize = 1 << 20;
/// Raw request bodies retained under sensitive capture for `request_id`, keyed
/// by the browser request record each belongs to. Native network v2
/// (protocol/native-network-v2.md) writes a `request_body` record as a child
/// of that request record; for a captured body its `artifact_id` names a
/// sensitive `request_body` artifact, capture origin `network_request`, whose
/// creator is that record. Only that exact pairing and verified bytes count;
/// anything else is no body, never a guess. Without request content capture
/// no body is retained and this is empty.
pub fn retained_request_bodies(
    events: &[Value],
    artifacts: &[Value],
    request_id: &str,
    root: &Path,
) -> RequestBodies {
    let mut bodies = RequestBodies::new();
    for event in events {
        if event["type"] != "request_body"
            || event["category"] != "network"
            || event["request_id"] != request_id
            || event["artifact_id"] == "0"
            || event["parent_event_id"] == "0"
        {
            continue;
        }
        let mut matching = artifacts.iter().filter(|artifact| {
            artifact["artifact_id"] == event["artifact_id"]
                && artifact["kind"] == "request_body"
                && artifact["capture_origin"] == "network_request"
                && artifact["creator_event_id"] == event["sequence_number"]
                && artifact["session_id"] == event["session_id"]
        });
        let (Some(artifact), None) = (matching.next(), matching.next()) else {
            continue;
        };
        let (Some(session), Some(process), Some(parent)) = (
            event["session_id"].as_str(),
            event["process_id"].as_u64(),
            event["parent_event_id"].as_str(),
        ) else {
            continue;
        };
        if let Ok(bytes) = evidence::content(root, artifact, REQUEST_BODY_LIMIT) {
            bodies.insert((session.into(), process as u32, parent.into()), bytes);
        }
    }
    bodies
}
/// The single settle record whose exact digested value occurs in `body`.
/// Candidates share the session and the renderer process of `request`, and
/// precede it in that process's sequence: causal order inside one stream, not
/// a time window. `Err` names why no link is drawn when more than one matches
/// or the search was not run.
fn value_flow<'a>(
    retained: &BTreeMap<Reference, &'a Value>,
    visited: &BTreeSet<Reference>,
    request: &Value,
    body: &[u8],
) -> std::result::Result<Option<&'a Value>, (&'static str, String)> {
    let Some(limit) = request["sequence_number"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
    else {
        return Ok(None);
    };
    let mut found: Vec<&Value> = Vec::new();
    for (key, event) in retained {
        if visited.contains(key)
            || event["type"] != "js_invocation_settle"
            || event["session_id"] != request["session_id"]
            || event["process_id"] != request["process_id"]
            || key.2.parse::<u64>().is_ok_and(|n| n >= limit)
        {
            continue;
        }
        let Some(digest) = crate::js_invocation::settle(event).and_then(|s| s.digest) else {
            continue;
        };
        match crate::js_invocation::body_contains(body, &digest) {
            Some(true) => found.push(event),
            Some(false) => {}
            None => {
                return Err((
                    "value_flow_unsearched",
                    "A retained returned value could not be searched in this request body within the bounded search, so no value-flow link is reported.".to_owned(),
                ));
            }
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(Some(found[0])),
        count => Err((
            "value_flow_ambiguous",
            format!(
                "{count} returned values with retained digests occur in this request body. None is chosen."
            ),
        )),
    }
}
#[allow(clippy::too_many_arguments)]
pub fn build(
    events: &[Value],
    edges: &[Value],
    artifacts: &[Value],
    request_id: &str,
    session_id: Option<&str>,
    root_process: Option<u32>,
    root_sequence: Option<&str>,
    artifact_root: Option<&Path>,
) -> Result<Value> {
    let bodies = artifact_root
        .map(|root| retained_request_bodies(events, artifacts, request_id, root))
        .unwrap_or_default();
    build_with_bodies(
        events,
        edges,
        artifacts,
        &bodies,
        request_id,
        session_id,
        root_process,
        root_sequence,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn build_with_bodies(
    events: &[Value],
    edges: &[Value],
    artifacts: &[Value],
    bodies: &RequestBodies,
    request_id: &str,
    session_id: Option<&str>,
    root_process: Option<u32>,
    root_sequence: Option<&str>,
) -> Result<Value> {
    validation::canonical(&json!(request_id), 64, false, "request_id")?;
    if let Some(session) = session_id {
        validation::canonical(&json!(session), 64, true, "session_id")?;
    }
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
            // A named capture-limit gap carries its reason, not a drop count,
            // in its own sequence slot. It is a sampling limit of its own
            // category that Traffic already leaves out, so a request trace
            // neither counts it as queue loss nor refuses the window over it.
            if crate::event_window::named_gap(event).is_some() {
                continue;
            }
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
            e["type"] != "gap"
                && e["category"] == "network"
                && e["request_id"] == request_id
                && session_id.is_none_or(|session| e["session_id"] == session)
                && root_process.is_none_or(|pid| e["process_id"] == pid)
                && root_sequence.is_none_or(|sequence| e["sequence_number"] == sequence)
        })
        .collect();
    // Operation preference only selects a lifecycle event within one session.
    // A reused request ID must not silently prefer another session's start.
    let ambiguous_session = candidates
        .iter()
        .map(|event| event["session_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>()
        .len()
        > 1;
    let preferred = if root_process.is_some() {
        candidates
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
    let mut time_adjacent_links = 0;
    let status = if ambiguous_session || preferred.len() > 1 {
        gaps.push(gap(
            "ambiguous_request",
            0,
            "More than one retained request matches these selectors. Supply session_id and a concrete root process/sequence pair.",
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
                // Where identity ends at the renderer's own request record, an
                // exact returned value found in a retained body of this request
                // is a correlated link. It is never a time window.
                if current["category"] == "network" && current["type"] == "request_initiated" {
                    let body = steps.iter().rev().find_map(|row| {
                        let event = &row["event"];
                        bodies.get(&(
                            event["session_id"].as_str()?.to_owned(),
                            event["process_id"].as_u64()? as u32,
                            event["sequence_number"].as_str()?.to_owned(),
                        ))
                    });
                    if let Some(body) = body {
                        match value_flow(&by_reference, &visited, current, body) {
                            Ok(Some(settle)) => {
                                visited.insert(reference(settle)?);
                                steps.push(step(settle, "invocation_value_flow", "correlated")?);
                                correlated += 1;
                                current = settle;
                                continue;
                            }
                            Ok(None) => {}
                            Err((reason, detail)) => {
                                gaps.push(gap(reason, steps.len() - 1, &detail));
                                break;
                            }
                        }
                    }
                }
                if !SOURCES.contains(&current["category"].as_str().unwrap_or("")) {
                    // Proximity never closes the gap. The identity chain really
                    // did end here, so the gap stays and the adjacency row is
                    // reported beside it rather than in place of it.
                    let adjacent = adjacent_candidate(&by_reference, &visited, current)
                        .and_then(|event| step(event, "temporal_adjacency", "time_adjacent").ok());
                    gaps.push(gap(
                        "no_predecessor",
                        steps.len() - 1,
                        if adjacent.is_some() {
                            "No earlier observed relationship reaches this event. The next row is time-adjacent only: it shares this request identity in another process within a bounded timestamp window, which is not a predecessor and not value flow."
                        } else {
                            "No earlier observed relationship reaches this event."
                        },
                    ));
                    // Adjacency is terminal. Walking on from a timestamp match
                    // would hang identity edges off a guess and count them as
                    // correlated links, so traversal always stops here.
                    if let Some(row) = adjacent {
                        steps.push(row);
                        time_adjacent_links += 1;
                    }
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
        // A time-adjacent row is only ever pushed where traversal broke, so it
        // can fill the step budget without the limit being the reason the walk
        // stopped. Only the identity steps decide whether the limit was hit.
        if steps.len() - time_adjacent_links == 32 {
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
    // Coverage stays an identity measure. A time-adjacent row is a step but not
    // a link, so it moves neither the denominator nor the reported percentage.
    let linked = steps.len().saturating_sub(1 + time_adjacent_links);
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
        json!({"contract_version":1,"document_kind":"origin-trace","request_id":request_id,"status":status,"steps":steps,"gaps":gaps,"coverage":{"linked_steps":linked,"observed_links":observed,"correlated_links":correlated,"time_adjacent_links":time_adjacent_links,"gap_count":gaps.len(),"percent":percent},"artifacts":selected}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_invocation::tests::{
        event as record, request_payload, settle_payload, start_payload,
    };

    fn network(kind: &str, seq: u64, process: u32, request: u64, initiator: (u32, u32)) -> Value {
        json!({"protocol_version":3,"session_id":"9","sequence_number":seq.to_string(),
            "monotonic_time_ns":seq.to_string(),"process_id":process,"thread_id":1,"tab_id":0,
            "navigation_id":"0","frame_id":"6","artifact_id":"0","parent_event_id":"0",
            "request_id":request.to_string(),"browser_context_id_high":"0","browser_context_id_low":"0",
            "encoded_data_length":"0","decoded_body_length":"0","status_code":0,"error_code":0,
            "resource_type":0,"flags":0,"initiator_request_id":initiator.1,
            "initiator_process_id":initiator.0,"category":"network","type":kind,"payload_size":4,
            "payload_encoding":"hex","payload_truncated":false,"payload":hex::encode("POST")})
    }
    fn edge(relation: &str, from: (u32, u64), to: (u32, u64)) -> Value {
        json!({"protocol_version":1,"session_id":"9","from_process_id":from.0,
            "from_sequence_number":from.1.to_string(),"to_process_id":to.0,
            "to_sequence_number":to.1.to_string(),"relation":relation,"confidence":"observed",
            "request_id":"0","artifact_id":"0"})
    }
    fn key(process: u32, seq: u64) -> Reference {
        ("9".to_owned(), process, seq.to_string())
    }
    fn renderer(seq: u64, kind: &str, payload: &[u8; 128], request: u64) -> Value {
        let mut event = record(kind, seq, request, payload);
        event["process_id"] = json!(42);
        event
    }
    /// Renderer 42 runs invocation 5 (start 1, settle 4) and starts request 9
    /// (seq 6); browser 84 records it as request 900 (seq 1).
    fn session(token: &[u8], other: &[u8]) -> (Vec<Value>, Vec<Value>) {
        let events = vec![
            renderer(1, "js_invocation_start", &start_payload(5, 0), 0),
            renderer(2, "js_invocation_start", &start_payload(6, 0), 0),
            renderer(
                3,
                "js_invocation_settle",
                &settle_payload(6, Some(other)),
                0,
            ),
            renderer(
                4,
                "js_invocation_settle",
                &settle_payload(5, Some(token)),
                0,
            ),
            network("request_initiated", 6, 42, 9, (0, 0)),
            network("request_started", 1, 84, 900, (42, 9)),
        ];
        let edges = vec![
            edge("request_initiator", (84, 1), (42, 6)),
            edge("invocation_settlement", (42, 3), (42, 2)),
            edge("invocation_settlement", (42, 4), (42, 1)),
        ];
        (events, edges)
    }
    fn trace(events: &[Value], edges: &[Value], bodies: &RequestBodies) -> Value {
        build_with_bodies(
            events,
            edges,
            &[],
            bodies,
            "900",
            Some("9"),
            Some(84),
            Some("1"),
        )
        .unwrap()
    }
    fn relations(document: &Value) -> Vec<&str> {
        document["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["relation"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn issued_during_invocation_is_an_observed_identity_step() {
        let (mut events, mut edges) = session(b"token-a", b"token-b");
        events.push(renderer(
            7,
            "js_invocation_request",
            &request_payload(2, 5),
            9,
        ));
        edges.push(edge("issued_during_invocation", (42, 6), (42, 1)));
        let document = trace(&events, &edges, &RequestBodies::new());
        assert_eq!(
            relations(&document),
            [
                "trace_target",
                "request_initiator",
                "issued_during_invocation"
            ]
        );
        assert_eq!(
            document["steps"][2]["value"],
            "invocation 5 started at site 0 with 2 argument(s)"
        );
        assert_eq!(document["coverage"]["observed_links"], 2);
        assert_eq!(document["coverage"]["correlated_links"], 0);
    }

    #[test]
    fn value_flow_links_only_the_exact_returned_bytes() {
        let (events, edges) = session(b"P1_token-a", b"P1_token-b");
        // No body: identity ends at the renderer request, with no link.
        let document = trace(&events, &edges, &RequestBodies::new());
        assert_eq!(relations(&document), ["trace_target", "request_initiator"]);
        assert_eq!(document["coverage"]["correlated_links"], 0);

        let mut bodies = RequestBodies::new();
        bodies.insert(key(84, 1), b"v=1&n=P1_token-a&c=x".to_vec());
        let document = trace(&events, &edges, &bodies);
        assert_eq!(
            relations(&document),
            [
                "trace_target",
                "request_initiator",
                "invocation_value_flow",
                "invocation_settlement"
            ]
        );
        assert_eq!(document["steps"][2]["confidence"], "correlated");
        assert_eq!(
            document["steps"][2]["value"],
            "invocation 5 fulfilled: string, length 10, digest retained"
        );
        assert_eq!(document["steps"][3]["event"]["sequence_number"], "1");
        assert_eq!(document["coverage"]["correlated_links"], 1);
        assert_eq!(document["coverage"]["observed_links"], 2);

        // The interleaved call's value is a different invocation.
        bodies.insert(key(84, 1), b"n=P1_token-b".to_vec());
        let document = trace(&events, &edges, &bodies);
        assert_eq!(document["steps"][3]["event"]["sequence_number"], "2");

        // Transformed, truncated or absent bytes never link.
        for body in [&b"n=P1%5Ftoken-a"[..], b"n=P1_token-", b"n=unrelated"] {
            bodies.insert(key(84, 1), body.to_vec());
            let document = trace(&events, &edges, &bodies);
            assert_eq!(relations(&document), ["trace_target", "request_initiator"]);
            assert_eq!(document["gaps"][0]["reason"], "no_predecessor");
        }
    }

    #[test]
    fn value_flow_refuses_ambiguity_later_values_and_other_processes() {
        let (mut events, edges) = session(b"same-token", b"same-token");
        let mut bodies = RequestBodies::new();
        bodies.insert(key(84, 1), b"n=same-token".to_vec());
        let document = trace(&events, &edges, &bodies);
        assert_eq!(relations(&document), ["trace_target", "request_initiator"]);
        assert_eq!(document["gaps"][0]["reason"], "value_flow_ambiguous");
        assert_eq!(document["coverage"]["correlated_links"], 0);

        // A value settled after the request was started cannot be in it.
        let (mut later, edges) = session(b"late-token", b"other");
        later[3]["sequence_number"] = json!("8");
        later[3]["monotonic_time_ns"] = json!("8");
        bodies.insert(key(84, 1), b"n=late-token".to_vec());
        assert_eq!(
            relations(&trace(&later, &edges, &bodies)),
            ["trace_target", "request_initiator"]
        );

        // Another renderer's equal value is not a candidate, so the one left
        // in the request's own process is no longer ambiguous.
        events[3]["process_id"] = json!(43);
        bodies.insert(key(84, 1), b"n=same-token".to_vec());
        let document = trace(&events, &edges, &bodies);
        assert_eq!(document["steps"][2]["event"]["process_id"], 42);
        assert_eq!(document["steps"][2]["event"]["sequence_number"], "3");
    }

    /// The cases tools/check-origin-trace-gaps.swift runs through the native
    /// app's builder: both builders must produce the same rows and gaps.
    #[test]
    fn shared_invocation_cases_match_the_swift_builder() {
        let fixture: Value =
            serde_json::from_str(include_str!("../assets/origin-trace-invocation-cases.json"))
                .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let pick = |kind: &str| -> Vec<Value> {
                case[kind]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| fixture[kind][n.as_str().unwrap()].clone())
                    .collect()
            };
            let mut bodies = RequestBodies::new();
            for name in case["bodies"].as_array().unwrap() {
                let body = &fixture["bodies"][name.as_str().unwrap()];
                let parts: Vec<&str> = body["event"].as_str().unwrap().split(':').collect();
                bodies.insert(
                    (parts[0].into(), parts[1].parse().unwrap(), parts[2].into()),
                    hex::decode(body["hex"].as_str().unwrap()).unwrap(),
                );
            }
            let query = &case["query"];
            let document = build_with_bodies(
                &pick("events"),
                &pick("edges"),
                &[],
                &bodies,
                query["request_id"].as_str().unwrap(),
                query["session_id"].as_str(),
                query["root_process_id"].as_u64().map(|n| n as u32),
                query["root_sequence_number"].as_str(),
            )
            .unwrap();
            let steps = document["steps"].as_array().unwrap();
            let column = |field: &str| -> Vec<Value> {
                steps
                    .iter()
                    .map(|s| match field {
                        "sequence_number" => s["event"]["sequence_number"].clone(),
                        _ => s[field].clone(),
                    })
                    .collect()
            };
            assert_eq!(
                json!(column("sequence_number")),
                case["step_sequences"],
                "{name}"
            );
            assert_eq!(json!(column("relation")), case["step_relations"], "{name}");
            assert_eq!(
                json!(column("confidence")),
                case["step_confidences"],
                "{name}"
            );
            let reasons: Vec<&Value> = document["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| &g["reason"])
                .collect();
            assert_eq!(json!(reasons), case["gap_reasons"], "{name}");
            assert_eq!(document["coverage"], case["coverage"], "{name}");
            if let Some(values) = case["step_values"].as_array() {
                for (expected, step) in values.iter().zip(steps) {
                    if !expected.is_null() {
                        assert_eq!(&step["value"], expected, "{name}");
                    }
                }
            }
        }
    }

    /// The request-body capture contract's pairing: a `request_body` child
    /// record of the request and its own sensitive artifact, verified bytes.
    #[test]
    fn retained_bodies_need_the_exact_record_and_verified_artifact() {
        use sha2::{Digest, Sha256};
        let root = tempfile::tempdir().unwrap();
        let body = b"n=P1_token-a".to_vec();
        let hash = hex::encode(Sha256::digest(&body));
        std::fs::create_dir_all(root.path().join("blobs")).unwrap();
        std::fs::write(root.path().join(format!("blobs/{hash}.bin")), &body).unwrap();
        let mut record = network("request_body", 2, 84, 900, (42, 9));
        record["artifact_id"] = json!("31");
        record["parent_event_id"] = json!("1");
        let artifact = json!({"artifact_id":"31","session_id":"9","kind":"request_body",
            "capture_origin":"network_request","creator_event_id":"2","byte_size":body.len(),
            "sha256":hash,"content_path":format!("blobs/{hash}.bin")});
        let bodies =
            retained_request_bodies(&[record.clone()], &[artifact.clone()], "900", root.path());
        assert_eq!(bodies.get(&key(84, 1)), Some(&body));
        assert!(
            retained_request_bodies(&[record.clone()], &[artifact.clone()], "901", root.path())
                .is_empty()
        );
        for (field, value) in [
            ("creator_event_id", json!("3")),
            ("kind", json!("response_body")),
            ("capture_origin", json!("unknown")),
            ("sha256", json!("00".repeat(32))),
        ] {
            let mut wrong = artifact.clone();
            wrong[field] = value;
            assert!(
                retained_request_bodies(&[record.clone()], &[wrong], "900", root.path()).is_empty(),
                "{field}"
            );
        }
        // Two artifacts claiming the same record are ambiguous: no body.
        assert!(
            retained_request_bodies(&[record], &[artifact.clone(), artifact], "900", root.path())
                .is_empty()
        );
    }

    #[test]
    fn digest_free_settles_never_link() {
        let (mut events, edges) = session(b"token-a", b"token-b");
        events[3] = renderer(4, "js_invocation_settle", &settle_payload(5, None), 0);
        let mut bodies = RequestBodies::new();
        bodies.insert(key(84, 1), b"n=token-a".to_vec());
        assert_eq!(
            relations(&trace(&events, &edges, &bodies)),
            ["trace_target", "request_initiator"]
        );
    }

    #[test]
    fn wasm_overflow_identity_is_text_and_malformed_bytes_are_rejected() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes[2] = 32;
        bytes[4] = 1;
        bytes[8..12].copy_from_slice(&9u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&47u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1000u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&2u32.to_le_bytes());
        let mut event = network("wasm_dispatch_overflow", 3, 7, 0, (0, 0));
        event["category"] = json!("vm");
        event["payload_size"] = json!(32);
        event["payload"] = json!(hex::encode(bytes));
        let built = step(&event, "request_lifecycle", "observed").unwrap();
        assert_eq!(
            built["value"],
            "Wasm br_table overflow identity: function 9, byte 47, selector 1000, arms 2, ring 0. Not a full observation."
        );
        bytes[6] = 31;
        event["payload"] = json!(hex::encode(bytes));
        assert!(
            step(&event, "request_lifecycle", "observed").unwrap()["value"]
                .as_str()
                .unwrap()
                .contains("ring 31")
        );
        bytes[6] = 32;
        event["payload"] = json!(hex::encode(bytes));
        assert!(step(&event, "request_lifecycle", "observed").is_err());
        bytes[6] = 0;
        event["payload"] = json!(hex::encode(bytes));
        event["artifact_id"] = json!("1");
        assert!(step(&event, "request_lifecycle", "observed").is_err());
        event["artifact_id"] = json!("0");
        event["parent_event_id"] = json!("4");
        assert!(step(&event, "request_lifecycle", "observed").is_err());
        event["parent_event_id"] = json!("0");
        bytes[4] = 9;
        event["payload"] = json!(hex::encode(bytes));
        assert!(step(&event, "request_lifecycle", "observed").is_err());
        let mut omitted = [0u8; 32];
        omitted[0] = 1;
        omitted[2] = 32;
        omitted[4] = 2;
        omitted[24..28].copy_from_slice(&3u32.to_le_bytes());
        event["payload"] = json!(hex::encode(omitted));
        assert_eq!(
            step(&event, "request_lifecycle", "observed").unwrap()["value"],
            "Wasm br_table overflow omitted 3 identities past the ring. Not a full observation."
        );
        omitted[8] = 1;
        event["payload"] = json!(hex::encode(omitted));
        assert!(step(&event, "request_lifecycle", "observed").is_err());
        let mut indirect = [0u8; 40];
        indirect[0] = 1;
        indirect[2] = 40;
        indirect[4] = 1;
        indirect[6] = 2;
        indirect[8..12].copy_from_slice(&4u32.to_le_bytes());
        indirect[12..16].copy_from_slice(&11u32.to_le_bytes());
        indirect[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        indirect[24..28].copy_from_slice(&2u32.to_le_bytes());
        event["type"] = json!("wasm_indirect_overflow");
        event["payload_size"] = json!(40);
        event["payload"] = json!(hex::encode(indirect));
        assert_eq!(
            step(&event, "request_lifecycle", "observed").unwrap()["value"],
            "Wasm call_indirect overflow identity: caller 4, byte 11, table 0, slot 4294967295, resolution out-of-bounds, ring 2. Not a full observation."
        );
        indirect[24] = 5;
        event["payload"] = json!(hex::encode(indirect));
        assert!(step(&event, "request_lifecycle", "observed").is_err());
    }
}
