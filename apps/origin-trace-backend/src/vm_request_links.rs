//! Exact native request -> captured response artifact evidence. Never URL/time joins.
use crate::evidence;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

type EventKey = (String, u64, String);
type RequestKey = (String, u64, String);
fn key(event: &Value) -> Option<EventKey> {
    if !evidence::canonical(&event["session_id"], 64, true)
        || !evidence::canonical(&event["sequence_number"], 64, true)
    {
        return None;
    }
    let process = event["process_id"]
        .as_u64()
        .filter(|p| *p > 0 && *p <= u32::MAX as u64)?;
    Some((
        event["session_id"].as_str()?.into(),
        process,
        event["sequence_number"].as_str()?.into(),
    ))
}
fn request_key(event: &Value) -> Option<RequestKey> {
    let (session, process, _) = key(event)?;
    evidence::canonical(&event["request_id"], 64, true).then(|| {
        (
            session,
            process,
            event["request_id"].as_str().unwrap().into(),
        )
    })
}
fn reference(event: &Value) -> Value {
    json!({"session_id":event["session_id"],"process_id":event["process_id"],"sequence_number":event["sequence_number"]})
}
fn scope(event: &Value) -> bool {
    matches!(event["protocol_version"].as_u64(), Some(2 | 3))
        && [
            "navigation_id",
            "frame_id",
            "artifact_id",
            "request_id",
            "parent_event_id",
        ]
        .iter()
        .all(|field| evidence::canonical(&event[field], 64, false))
}
pub(crate) struct Index<'a> {
    events: BTreeMap<EventKey, Option<&'a Value>>,
    captures: BTreeMap<(String, String), BTreeSet<EventKey>>,
    starts: BTreeMap<RequestKey, BTreeSet<EventKey>>,
}
impl<'a> Index<'a> {
    pub fn new(events: impl Iterator<Item = &'a Value>) -> Self {
        let mut index = Self {
            events: BTreeMap::new(),
            captures: BTreeMap::new(),
            starts: BTreeMap::new(),
        };
        for event in events {
            // Gap markers share the preceding event's identity but are not events.
            if event["type"] == "gap" {
                continue;
            }
            let Some(identity) = key(event) else {
                continue;
            };
            // Retain contradiction tombstones: dropping a conflicting record
            // must not make a surviving candidate look like a unique match.
            match index.events.entry(identity.clone()) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if entry.get().is_some_and(|previous| previous != event) {
                        entry.insert(None);
                    }
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Some(event));
                }
            }
            if event["type"] == "artifact_captured"
                && let Some(artifact) = event["artifact_id"].as_str()
            {
                let candidates = index
                    .captures
                    .entry((identity.0.clone(), artifact.into()))
                    .or_default();
                candidates.insert(identity.clone());
            }
            if event["category"] == "network"
                && event["type"] == "request_started"
                && let Some(request) = request_key(event)
            {
                let candidates = index.starts.entry(request).or_default();
                candidates.insert(identity);
            }
        }
        index
    }
    pub fn links(&self, artifact: &Value) -> Vec<Value> {
        self.link(artifact).into_iter().collect()
    }
    fn link(&self, artifact: &Value) -> Option<Value> {
        if artifact["capture_origin"] != "network_response"
            || artifact["execution_context_id"] != "0"
            || !evidence::canonical(&artifact["creator_event_id"], 64, true)
        {
            return None;
        }
        let candidates = self.captures.get(&(
            artifact["session_id"].as_str()?.into(),
            artifact["artifact_id"].as_str()?.into(),
        ))?;
        if candidates.len() != 1 {
            return None;
        }
        let capture_key = candidates.first()?;
        let capture = (*self.events.get(capture_key)?)?;
        if !scope(capture)
            || capture["category"] != "artifact"
            || capture["parent_event_id"] != artifact["creator_event_id"]
        {
            return None;
        }
        let creator_key = (
            capture_key.0.clone(),
            capture_key.1,
            artifact["creator_event_id"].as_str()?.into(),
        );
        let response = (*self.events.get(&creator_key)?)?;
        if !scope(response)
            || response["category"] != "network"
            || response["type"] != "response_started"
            || request_key(capture)? != request_key(response)?
        {
            return None;
        }
        // Zero context fields are not document proof. The explicit producer
        // parent sequence, scoped to its process/session, identifies this body.
        for field in ["session_id", "navigation_id", "frame_id"] {
            if artifact[field] != capture[field] || artifact[field] != response[field] {
                return None;
            }
        }
        if !["browser_context_id_high", "browser_context_id_low"]
            .iter()
            .all(|field| evidence::canonical(&response[field], 64, false))
            || (response["browser_context_id_high"] == "0"
                && response["browser_context_id_low"] == "0")
        {
            return None;
        }
        let starts = self.starts.get(&request_key(response)?)?;
        if starts.len() != 1 {
            return None;
        }
        let start_key = starts.first()?;
        let root = (*self.events.get(start_key)?)?;
        if !scope(root) {
            return None;
        }
        for field in [
            "navigation_id",
            "frame_id",
            "browser_context_id_high",
            "browser_context_id_low",
        ] {
            if root[field] != response[field] {
                return None;
            }
        }
        let sequence = |event: &Value| event["sequence_number"].as_str()?.parse::<u64>().ok();
        if !(sequence(root)? < sequence(response)? && sequence(response)? < sequence(capture)?) {
            return None;
        }
        Some(
            json!({"request_id":root["request_id"],"root_event":reference(root),
            "response_event":reference(response),"capture_event":reference(capture),
            "relation":"captured-response-body"}),
        )
    }
}
pub(crate) fn select(
    document: &mut Value,
    request: &str,
    session: &str,
    process: u64,
    sequence: &str,
) {
    let root = json!({"session_id":session,"process_id":process,"sequence_number":sequence});
    document["selection"] = json!({"kind":"request","request_id":request,"root_event":root,
        "edge_semantics":"exact-captured-response-body"});
    document["results"]
        .as_array_mut()
        .unwrap()
        .retain(|result| {
            result["exact_request_links"]
                .as_array()
                .is_some_and(|links| {
                    links
                        .iter()
                        .any(|link| link["request_id"] == request && link["root_event"] == root)
                })
        });
    // One linked constituent cannot establish an exact mixed-artifact relation.
    document["mixed_findings"] = json!([]);
    let results = document["results"].as_array().unwrap();
    document["summary"] = json!({"analyzed_artifacts":results.len(),
        "candidate_count":results.iter().filter(|result| result["tier"] == "candidate").count(),
        "likely_vm_count":results.iter().filter(|result| result["tier"] == "likely-vm").count(),
        "failed_count":0,"mixed_count":0});
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(kind: &str, seq: &str) -> Value {
        json!({"protocol_version":3,"session_id":"9007199254740993","process_id":12,"sequence_number":seq,
            "category":"network","type":kind,"navigation_id":"0","frame_id":"3","execution_context_id":"0",
            "request_id":"9007199254740995","artifact_id":"0","parent_event_id":"0",
            "browser_context_id_high":"7","browser_context_id_low":"8"})
    }
    fn fixture() -> (Value, Vec<Value>) {
        let root = event("request_started", "10");
        let response = event("response_started", "12");
        let mut capture = event("artifact_captured", "14");
        capture["category"] = json!("artifact");
        capture["artifact_id"] = json!("21");
        capture["parent_event_id"] = json!("12");
        (
            json!({"capture_origin":"network_response","session_id":"9007199254740993","artifact_id":"21",
            "creator_event_id":"12","navigation_id":"0","frame_id":"3","execution_context_id":"0"}),
            vec![root, response, capture],
        )
    }
    #[test]
    fn exact_chain_is_order_independent_and_duplicate_delivery_is_idempotent() {
        let (artifact, mut events) = fixture();
        events.push(events[1].clone());
        events.reverse();
        let links = Index::new(events.iter()).links(&artifact);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["root_event"]["sequence_number"], "10");
        events.push(event("request_redirected", "11"));
        assert_eq!(Index::new(events.iter()).links(&artifact), links);
    }
    #[test]
    fn missing_wrong_or_ambiguous_links_are_never_inferred() {
        let (artifact, events) = fixture();
        for field in [
            "session_id",
            "request_id",
            "process_id",
            "navigation_id",
            "frame_id",
            "parent_event_id",
        ] {
            let mut wrong = events.clone();
            wrong[2][field] = if field == "process_id" {
                json!(13)
            } else {
                json!("99")
            };
            assert!(
                Index::new(wrong.iter()).links(&artifact).is_empty(),
                "{field}"
            );
        }
        for missing in 0..3 {
            let mut wrong = events.clone();
            wrong.remove(missing);
            assert!(Index::new(wrong.iter()).links(&artifact).is_empty());
        }
        let mut ambiguous = events.clone();
        ambiguous.push(event("request_started", "9"));
        assert!(Index::new(ambiguous.iter()).links(&artifact).is_empty());
        let mut conflict = events.clone();
        let mut duplicate = events[1].clone();
        duplicate["frame_id"] = json!("4");
        conflict.push(duplicate);
        assert!(Index::new(conflict.iter()).links(&artifact).is_empty());
        for record in 0..3 {
            for field in ["artifact_id", "request_id", "parent_event_id"] {
                let mut malformed = events.clone();
                malformed[record][field] = json!("bogus");
                assert!(
                    Index::new(malformed.iter()).links(&artifact).is_empty(),
                    "record {record} {field}"
                );
            }
        }
        let mut missing_context = events.clone();
        for event in &mut missing_context {
            event["browser_context_id_high"] = json!("0");
            event["browser_context_id_low"] = json!("0");
        }
        assert!(
            Index::new(missing_context.iter())
                .links(&artifact)
                .is_empty()
        );
        let mut dynamic = artifact.clone();
        dynamic["capture_origin"] = json!("runtime_allocating_script");
        assert!(Index::new(events.iter()).links(&dynamic).is_empty());
    }
    #[test]
    fn projection_requires_complete_root_not_correlated_ids() {
        let (artifact, events) = fixture();
        let links = Index::new(events.iter()).links(&artifact);
        let document = json!({"results":[{"artifact_id":"21","exact_request_links":links},{"artifact_id":"22","related_request_ids":["9007199254740995"]}],"mixed_findings":[{}]});
        let mut exact = document.clone();
        select(&mut exact, "9007199254740995", "9007199254740993", 12, "10");
        assert_eq!(exact["results"].as_array().unwrap().len(), 1);
        assert_eq!(exact["mixed_findings"], json!([]));
        for (session, process, sequence) in [
            ("2", 12, "10"),
            ("9007199254740993", 13, "10"),
            ("9007199254740993", 12, "11"),
        ] {
            let mut wrong = document.clone();
            select(&mut wrong, "9007199254740995", session, process, sequence);
            assert_eq!(wrong["results"], json!([]));
        }
    }
}
