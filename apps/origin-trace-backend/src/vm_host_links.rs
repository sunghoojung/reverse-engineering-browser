//! Exact retained dispatch-parent links. Frame correlation never supplies a PC.
use crate::{durable, error::Result, vm};
use serde_json::{Value, json};
use std::path::Path;

const MAX_LINKS: usize = 4096;
const MAX_WORKSPACE_LINKS: usize = 256;

fn reference(event: &Value) -> Value {
    json!({"session_id":event["session_id"], "process_id":event["process_id"],
        "sequence_number":event["sequence_number"]})
}
fn host_event(event: &Value) -> bool {
    matches!(
        event["category"].as_str(),
        Some(
            "canvas"
                | "webgl"
                | "web_audio"
                | "navigator"
                | "permissions"
                | "storage"
                | "webrtc"
                | "network"
                | "runtime"
        )
    ) && matches!(
        event["type"].as_str(),
        Some(
            "api_call"
                | "property_read"
                | "request_started"
                | "request_initiated"
                | "request_redirected"
                | "response_started"
                | "response_completed"
                | "request_completed"
                | "request_failed"
        )
    )
}
fn position(host: &Value, artifact: &Value, samples: &[Value]) -> Option<Value> {
    if host["artifact_id"] != artifact["artifact_id"] {
        return None;
    }
    let sequence = host["sequence_number"].as_str()?.parse::<u64>().ok()?;
    samples.iter().find_map(|sample| {
        let event = &sample["event"];
        let before = event["sequence_number"].as_str()?.parse::<u64>().ok()?;
        (sample["invocation_id"].is_string()
            && sample["invocation_event"].is_object()
            && sample["instruction_pointer_units"] != "unknown"
            && event["session_id"] == host["session_id"]
            && event["process_id"] == host["process_id"]
            && event["sequence_number"] == host["parent_event_id"]
            && before < sequence)
            .then(|| {
                json!({
                    "sample_event": event, "invocation_event":sample["invocation_event"],
                    "invocation_id":sample["invocation_id"],
                    "instruction_pointer":sample["instruction_pointer"],
                    "instruction_pointer_units":sample["instruction_pointer_units"]
                })
            })
    })
}

pub(crate) fn store(
    root: &Path,
    workspace_document: &Value,
    artifacts: &[Value],
    events: &[Value],
) -> Result<Value> {
    let mut workspaces = Vec::new();
    let mut total = 0;
    for workspace in workspace_document["workspaces"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(artifact) = artifacts.iter().find(|artifact| {
            artifact["artifact_id"] == workspace["interpreter_artifact_id"]
                && artifact["sha256"] == workspace["source_artifact_sha256"]
        }) else {
            continue;
        };
        let samples = workspace["samples"]
            .as_array()
            .expect("validated workspace samples");
        let mut links = Vec::new();
        let mut omissions = Vec::new();
        if samples.is_empty() {
            omissions.push("dispatch-samples-unavailable");
        }
        if workspace["sample_count"].as_u64().unwrap_or(0) > samples.len() as u64 {
            omissions.push("dispatch-sample-retention-limit");
        }
        for event in events.iter().filter(|event| {
            host_event(event)
                && ["session_id", "navigation_id", "frame_id"]
                    .iter()
                    .all(|key| event[*key] == artifact[*key])
        }) {
            if links.len() == MAX_WORKSPACE_LINKS || total == MAX_LINKS {
                omissions.push("host-link-limit");
                break;
            }
            let guest = position(event, artifact, samples);
            let (state, reason) = if guest.is_some() {
                ("observed", "direct-dispatch-parent")
            } else if samples.is_empty() {
                ("unknown", "dispatch-samples-unavailable")
            } else {
                ("correlated", "guest-position-unproven")
            };
            links.push(json!({"host_event":reference(event), "category":event["category"], "type":event["type"],
                "state":state, "reason":reason, "guest_position":guest}));
            total += 1;
        }
        if links.is_empty() && !omissions.contains(&"host-link-limit") {
            omissions.push("host-events-unavailable");
        }
        workspaces.push(json!({"interpreter_artifact_id":artifact["artifact_id"],
            "source_artifact_sha256":artifact["sha256"], "links":links,"omissions":omissions}));
    }
    let mut document = json!({"contract_version":1,"document_kind":"vm-host-links",
        "workspace_document_digest":workspace_document["document_digest"], "workspaces":workspaces});
    document["document_digest"] = json!(vm::digest(&document)?);
    durable::write_private(
        &root.join("analysis/vm-host-links-v1.json"),
        &vm::canonical(&document)?,
    )?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> (Value, Value, Value) {
        let identity =
            |sequence| json!({"session_id":"1","process_id":7,"sequence_number":sequence});
        let artifact = json!({"artifact_id":"9","sha256":"a".repeat(64),"session_id":"1","navigation_id":"2","frame_id":"3"});
        let workspace = json!({"document_digest":"b".repeat(64),"workspaces":[{
            "interpreter_artifact_id":"9","source_artifact_sha256":"a".repeat(64),"sample_count":1,
            "samples":[{"event":identity("2"),"invocation_event":identity("1"),"invocation_id":"4",
                "instruction_pointer":2,"instruction_pointer_units":"instruction-index"}]}]});
        let host = json!({"session_id":"1","process_id":7,"sequence_number":"3","parent_event_id":"2",
            "artifact_id":"9","navigation_id":"2","frame_id":"3","category":"runtime","type":"api_call",
            "payload":"PRIVATE HOST PAYLOAD"});
        (workspace, artifact, host)
    }
    fn analyze(workspace: &Value, artifacts: &[Value], events: &[Value]) -> Value {
        let root = tempfile::tempdir().unwrap();
        let document = store(root.path(), workspace, artifacts, events).unwrap();
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/vm-host-links-v1.schema.json"
        ))
        .unwrap();
        jsonschema::validator_for(&schema)
            .unwrap()
            .validate(&document)
            .unwrap();
        let mut unsigned = document.clone();
        unsigned.as_object_mut().unwrap().remove("document_digest");
        assert_eq!(document["document_digest"], vm::digest(&unsigned).unwrap());
        assert!(!document.to_string().contains("PRIVATE HOST PAYLOAD"));
        document
    }
    #[test]
    fn exact_retained_dispatch_parent_proves_position_without_payload() {
        let (workspace, artifact, host) = inputs();
        let document = analyze(&workspace, &[artifact], &[host]);
        let link = &document["workspaces"][0]["links"][0];
        assert_eq!(link["state"], "observed");
        assert_eq!(link["host_event"]["sequence_number"], "3");
        assert_eq!(
            link["guest_position"]["sample_event"]["sequence_number"],
            "2"
        );
        assert_eq!(link["guest_position"]["instruction_pointer"], 2);
        assert_eq!(
            link["guest_position"]["instruction_pointer_units"],
            "instruction-index"
        );
    }
    #[test]
    fn frame_scope_never_substitutes_for_parent_process_or_invocation() {
        let (workspace, artifact, host) = inputs();
        for (key, value) in [
            ("parent_event_id", json!("1")),
            ("process_id", json!(8)),
            ("artifact_id", json!("10")),
            ("sequence_number", json!("2")),
        ] {
            let mut event = host.clone();
            event[key] = value;
            let document = analyze(&workspace, std::slice::from_ref(&artifact), &[event]);
            assert_eq!(document["workspaces"][0]["links"][0]["state"], "correlated");
            assert!(document["workspaces"][0]["links"][0]["guest_position"].is_null());
        }
        for (key, value) in [
            ("invocation_id", Value::Null),
            ("invocation_event", Value::Null),
            ("instruction_pointer_units", json!("unknown")),
        ] {
            let mut document = workspace.clone();
            document["workspaces"][0]["samples"][0][key] = value;
            let result = analyze(
                &document,
                std::slice::from_ref(&artifact),
                std::slice::from_ref(&host),
            );
            assert!(result["workspaces"][0]["links"][0]["guest_position"].is_null());
        }
        for key in ["session_id", "navigation_id", "frame_id"] {
            let mut event = host.clone();
            event[key] = json!("99");
            let result = analyze(&workspace, std::slice::from_ref(&artifact), &[event]);
            assert!(
                result["workspaces"][0]["links"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
    }
    #[test]
    fn absent_and_unretained_samples_remain_unknown_with_named_omissions() {
        let (mut workspace, artifact, host) = inputs();
        workspace["workspaces"][0]["samples"] = json!([]);
        let document = analyze(&workspace, &[artifact], &[host]);
        let row = &document["workspaces"][0];
        assert_eq!(row["links"][0]["state"], "unknown");
        assert!(row["links"][0]["guest_position"].is_null());
        assert_eq!(
            row["omissions"],
            json!([
                "dispatch-samples-unavailable",
                "dispatch-sample-retention-limit"
            ])
        );
    }
    #[test]
    fn host_link_retention_is_bounded_per_workspace_and_document() {
        let (mut workspace, artifact, host) = inputs();
        let events = (3..303)
            .map(|sequence| {
                let mut event = host.clone();
                event["sequence_number"] = json!(sequence.to_string());
                event
            })
            .collect::<Vec<_>>();
        let row = workspace["workspaces"][0].clone();
        let artifacts = (1..=17)
            .map(|index| {
                let mut item = artifact.clone();
                item["artifact_id"] = json!(index.to_string());
                item
            })
            .collect::<Vec<_>>();
        workspace["workspaces"] = json!(
            artifacts
                .iter()
                .map(|artifact| {
                    let mut item = row.clone();
                    item["interpreter_artifact_id"] = artifact["artifact_id"].clone();
                    item
                })
                .collect::<Vec<_>>()
        );
        let document = analyze(&workspace, &artifacts, &events);
        let rows = document["workspaces"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["links"].as_array().unwrap().len())
                .sum::<usize>(),
            MAX_LINKS
        );
        assert!(
            rows.iter()
                .all(|row| row["links"].as_array().unwrap().len() <= MAX_WORKSPACE_LINKS)
        );
        assert!(rows.iter().all(|row| {
            row["omissions"]
                .as_array()
                .unwrap()
                .contains(&json!("host-link-limit"))
        }));
    }
}
