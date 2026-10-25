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

fn identifier(value: &Value) -> Value {
    value
        .as_str()
        .filter(|text| text.len() <= 256 && !text.chars().any(char::is_control))
        .map(|text| json!(text))
        .unwrap_or(Value::Null)
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

pub fn debugger(state: &Value) -> Value {
    let scripts: Vec<_> = state["scripts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|script| {
            script["language"] == "WebAssembly"
                || script["url"]
                    .as_str()
                    .is_some_and(|url| url.starts_with("wasm:"))
        })
        .collect();
    let target = state["target"].is_object().then(|| {
        json!({
            "id": identifier(&state["target"]["id"]),
            "url": url_label(&state["target"]["url"]),
            "title": null,
            "title_omitted": true
        })
    });
    json!({
        "instance_id": identifier(&state["network"]["instance_id"]),
        "debugger_state": state["state"],
        "generation": state["generation"],
        "debugger_protocol_version": state["protocol_version"],
        "target_document_epoch": state["target_document_epoch"],
        "capture_epoch": state["network"]["capture_epoch"],
        "target": target,
        "wasm_scripts": scripts.iter().take(ITEMS).map(|script| json!({
            "script_id": identifier(&script["script_id"]),
            "target_id": identifier(&script["target_id"]),
            "url": url_label(&script["url"]),
            "byte_length": script["length"].as_u64().filter(|n| *n > 0 && *n <= crate::validation::MAX_SAFE_INTEGER),
            "artifact_id": null,
            "sha256": null
        })).collect::<Vec<_>>(),
        "wasm_scripts_omitted": scripts.len().saturating_sub(ITEMS),
        "debugger_etag": format!("\"debugger-{}\"", state["generation"]),
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
    mut debugger: Value,
    artifacts: impl std::future::Future<Output = Result<Value>>,
) -> Result<Value> {
    debugger["wasm_artifacts"] = artifacts.await?;
    debugger["consistency"] = json!("independent_debugger_snapshot_and_manifest_tail");
    Ok(debugger)
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
    fn compact_state_does_not_clone_sensitive_content_or_infer_joins() {
        let state = json!({"target":{"id":"target-1","url":"https://user:secret_canary@owned.example/private_secret?token=secret_canary#secret_canary","title":"secret_canary","web_socket_url":"ws://localhost/secret_canary"},"scripts":(0..40).map(|id| json!({"script_id":id.to_string(),"language":"WebAssembly","url":"wasm://wasm/abcd","length":8,"hash":"secret_canary","source":"secret_canary"})).collect::<Vec<_>>(),"network":{"instance_id":"instance-1"},"console":["secret_canary"]});
        let summary = debugger(&state);
        assert_eq!(summary["target"]["url"], "https://owned.example");
        assert_eq!(summary["target"]["title"], Value::Null);
        assert_eq!(summary["wasm_scripts"].as_array().unwrap().len(), ITEMS);
        assert_eq!(summary["wasm_scripts_omitted"], 24);
        assert!(summary["wasm_scripts"][0]["artifact_id"].is_null());
        assert!(!summary.to_string().contains("secret_canary"));
        assert!(!summary.to_string().contains("private_secret"));
        assert!(url_label(&json!("data:text/plain,secret_canary")).is_null());
        assert!(url_label(&json!("wasm://wasm/abcd?token=secret_canary")).is_null());
        assert!(identifier(&json!("a".repeat(257))).is_null());
    }
    #[tokio::test]
    async fn target_change_during_manifest_read_keeps_snapshot_identity_explicit() {
        let mut state =
            json!({"generation":7,"target":{"id":"before","url":"https://before.example"}});
        let snapshot = debugger(&state);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let pending = tokio::spawn(with_artifacts(snapshot, async move {
            Ok(receiver.await.unwrap())
        }));
        tokio::task::yield_now().await;
        state["generation"] = json!(8);
        state["target"]["id"] = json!("after");
        sender
            .send(json!({"items":[{"session_id":"later-session","artifact_id":"9"}]}))
            .unwrap();
        let context = pending.await.unwrap().unwrap();
        assert_eq!(context["target"]["id"], "before");
        assert_eq!(context["generation"], 7);
        assert_eq!(debugger(&state)["target"]["id"], "after");
        assert_eq!(
            context["wasm_artifacts"]["items"][0]["session_id"],
            "later-session"
        );
        assert_eq!(
            context["consistency"],
            "independent_debugger_snapshot_and_manifest_tail"
        );
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
