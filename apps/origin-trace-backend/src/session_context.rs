//! Bounded discovery, not another evidence export. Never include source, bodies,
//! debugger endpoint tokens, arbitrary titles, or URL credentials/query/path.
use crate::{
    error::{Code, Error, Result},
    evidence,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub const ITEMS: usize = 16;
const MANIFEST_BYTES: u64 = 256 * 1024;

/// Same acceptance rule as `/api/health` `instance_id` and `X-REB-Expected-Instance`.
/// A non-matching value is omitted rather than trimmed into a different identity.
fn precondition_instance(value: &Value) -> Value {
    value
        .as_str()
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id.bytes().all(|byte| byte.is_ascii_digit() || byte == b':')
        })
        .map(|id| json!(id))
        .unwrap_or(Value::Null)
}
/// Answers whether this process is the ready live session: live capture mode
/// with its native event broker connected. Availability only: it does not
/// authorize effects or claim capture completeness.
pub fn live_admission(capture_mode: &str, broker_connected: bool) -> &'static str {
    match capture_mode {
        "live" if broker_connected => "ready",
        "live" => "native_capture_unavailable",
        "idle" => "idle",
        _ => "not_live_capture",
    }
}
fn url_label(value: &Value) -> Value {
    let Some(text) = value.as_str().filter(|text| text.len() <= 65536) else {
        return Value::Null;
    };
    let Ok(url) = url::Url::parse(text) else {
        return Value::Null;
    };
    match url.scheme() {
        "http" | "https" => {
            let origin = url.origin().ascii_serialization();
            if origin.len() <= 256 {
                json!(origin)
            } else {
                Value::Null
            }
        }
        "wasm" => {
            // Only the conventional browser-generated hex module label is kept.
            let label = url.path().trim_start_matches('/');
            if url.host_str() == Some("wasm")
                && !label.is_empty()
                && label.len() <= 64
                && label.bytes().all(|byte| byte.is_ascii_hexdigit())
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
            {
                json!(format!("wasm://wasm/{label}"))
            } else {
                Value::Null
            }
        }
        _ => Value::Null,
    }
}

/// The CDP debugger was removed. Version 1 keeps its debugger fields with
/// fixed retired values so existing clients still parse the context; no
/// target, script or debugger generation is ever reported.
pub fn retired_debugger(instance_id: &str) -> Value {
    json!({
        "instance_id": precondition_instance(&json!(instance_id)),
        "debugger_state": "unavailable",
        "generation": 0,
        "debugger_protocol_version": 1,
        "target_document_epoch": 0,
        "capture_epoch": 0,
        "target": null,
        "wasm_scripts": [],
        "wasm_scripts_omitted": 0,
        "debugger_etag": "\"debugger-0\"",
    })
}

/// Read only a bounded manifest tail; never read artifact blobs or launch a
/// browser. A tail is explicitly incomplete and is not a script/artifact join.
pub fn artifacts(root: &Path) -> Result<Value> {
    let mut file = match evidence::regular_file(&root.join("manifest.jsonl")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"items": [], "window_truncated": false, "items_omitted": 0}));
        }
        Err(_) => {
            return Err(Error::new(
                500,
                "Session context artifact manifest is unavailable",
            ));
        }
    };
    let length = file.metadata()?.len();
    let start = length.saturating_sub(MANIFEST_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(MANIFEST_BYTES).read_to_end(&mut bytes)?;
    let complete = if start > 0 {
        bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|end| &bytes[end + 1..])
            .unwrap_or(&[])
    } else {
        &bytes
    };
    let mut items = Vec::new();
    let mut omitted = 0usize;
    let mut identifiers = std::collections::BTreeSet::new();
    for line in complete.rsplit(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.len() > 8192 {
            return Err(
                Error::new(500, "Session context artifact record exceeds its limit")
                    .with_code(Code::ResourceLimit),
            );
        }
        let mut record: Value = serde_json::from_slice(line)
            .map_err(|_| Error::new(500, "Session context artifact manifest is malformed"))?;
        evidence::validate_artifact(&mut record)
            .map_err(|_| Error::new(500, "Session context artifact manifest is malformed"))?;
        if !identifiers.insert(record["artifact_id"].as_str().unwrap().to_owned()) {
            return Err(Error::new(
                500,
                "Session context manifest contains duplicate artifact IDs",
            ));
        }
        if record["kind"] != "wasm" {
            continue;
        }
        if items.len() == ITEMS {
            omitted += 1;
            continue;
        }
        items.push(json!({
            "artifact_id": record["artifact_id"], "session_id": record["session_id"],
            "url": url_label(&record["url"]), "byte_length": record["byte_size"].as_u64().filter(|n| *n <= crate::validation::MAX_SAFE_INTEGER),
            "sha256": record["sha256"], "script_id": null,
        }));
    }
    Ok(json!({"items": items, "window_truncated": start > 0, "items_omitted": omitted}))
}

pub async fn with_artifacts(
    mut context: Value,
    artifacts: impl std::future::Future<Output = Result<Value>>,
) -> Result<Value> {
    context["wasm_artifacts"] = artifacts.await?;
    context["consistency"] = json!("independent_debugger_snapshot_and_manifest_tail");
    Ok(context)
}

pub fn etag(value: &Value) -> String {
    format!(
        "\"session-context-{}\"",
        hex::encode(Sha256::digest(value.to_string().as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(id: usize) -> Value {
        json!({"protocol_version":1,"artifact_id":id.to_string(),"session_id":"9","navigation_id":"0","frame_id":"0","parent_artifact_id":"0","creator_event_id":"0","kind":"wasm","url":"https://user:secret_canary@owned.example/private_secret?token=secret_canary#secret_canary","mime_type":"application/wasm","byte_size":8,"sha256":"a".repeat(64),"sensitive":false,"content_path":format!("blobs/{}.bin", "a".repeat(64))})
    }
    #[test]
    fn retired_debugger_fields_are_fixed_and_admission_stays_explicit() {
        let summary = retired_debugger("12:34");
        assert_eq!(summary["instance_id"], "12:34");
        assert_eq!(summary["debugger_state"], "unavailable");
        assert!(summary["target"].is_null());
        assert_eq!(summary["wasm_scripts"], json!([]));
        assert!(retired_debugger("instance-1")["instance_id"].is_null());
        assert_eq!(live_admission("live", true), "ready");
        assert_eq!(live_admission("live", false), "native_capture_unavailable");
        assert_eq!(live_admission("idle", true), "idle");
        assert_eq!(live_admission("idle", false), "idle");
        assert_eq!(live_admission("demo", true), "not_live_capture");
        assert!(url_label(&json!("data:text/plain,secret_canary")).is_null());
        assert!(url_label(&json!("wasm://wasm/abcd?token=secret_canary")).is_null());
    }
    #[test]
    fn artifact_inventory_is_bounded_and_never_reads_blobs() {
        let root = tempfile::tempdir().unwrap();
        let rows: Vec<_> = (0..40).map(|id| record(id).to_string()).collect();
        std::fs::write(root.path().join("manifest.jsonl"), rows.join("\n")).unwrap();
        let value = artifacts(root.path()).unwrap();
        assert_eq!(value["items"].as_array().unwrap().len(), ITEMS);
        assert_eq!(value["items_omitted"], 24);
        assert_eq!(value["items"][0]["artifact_id"], "39");
        assert_eq!(value["items"][0]["url"], "https://owned.example");
        assert!(value["items"][0]["script_id"].is_null());
        assert!(!value.to_string().contains("secret_canary"));
        assert_eq!(value["window_truncated"], false);
        std::fs::write(
            root.path().join("manifest.jsonl"),
            format!(
                "{}\n{}\n",
                " ".repeat(MANIFEST_BYTES as usize + 10),
                record(1)
            ),
        )
        .unwrap();
        assert_eq!(artifacts(root.path()).unwrap()["window_truncated"], true);
        std::fs::write(
            root.path().join("manifest.jsonl"),
            format!("{}\n{}\n", record(1), record(1)),
        )
        .unwrap();
        assert!(
            artifacts(root.path())
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        std::fs::write(root.path().join("manifest.jsonl"), "secret_canary").unwrap();
        assert!(
            !artifacts(root.path())
                .unwrap_err()
                .to_string()
                .contains("secret_canary")
        );
    }
}
