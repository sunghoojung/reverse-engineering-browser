//! Bounded discovery, not another evidence export. Never include source, bodies,
//! debugger endpoint tokens, arbitrary titles, or URL credentials/query/path.
use crate::error::{Error, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Instant};

pub const ITEMS: usize = 16;

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
pub(crate) fn url_label(value: &Value) -> Value {
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

/// What this session's launcher passed to Brave, as labels: whether request
/// content and Canvas images are retained, whether document-start Console
/// scripts are permitted, and what invocation capture armed. Counts and
/// switches only; site labels and source URLs stay in get_js_invocation_sites.
pub fn capture_options(options: &crate::config::Options, invocation: &Value) -> Value {
    let live = options.capture_mode() == crate::config::CaptureMode::Live;
    json!({
        "source": if live { "launcher" } else { "not_live" },
        "request_content": live && options.session_request_content,
        "content_limits": content_limits(options),
        "canvas_images": live && options.session_canvas_images,
        "request_stacks": live && options.session_request_stacks,
        "document_start": if live && options.session_document_start {
            "permitted"
        } else {
            "not_permitted"
        },
        "js_invocation": {
            "state": invocation["state"],
            "count": invocation["count"],
            "digests": invocation["digests"],
        },
    })
}

/// Version 1 of the content session's limits: its two budgets in MiB and
/// whether it keeps element media, named as the start options are. Null when
/// the session retains no request content, or is not live. A launcher from
/// before the limits were labeled names none of them, so a value it did not
/// name is null rather than a guessed default.
pub fn content_limits(options: &crate::config::Options) -> Value {
    if options.capture_mode() != crate::config::CaptureMode::Live
        || !options.session_request_content
    {
        return Value::Null;
    }
    json!({
        "version": 1,
        "request_content_budget_mib": options.session_request_content_budget_mib,
        "response_body_budget_mib": options.session_response_body_budget_mib,
        "response_media": options.session_response_media.as_deref().map(|media| media == "1"),
    })
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

/// The newest Wasm modules of the whole manifest, found through the artifact
/// lookup index, and how many more it holds; never reads artifact blobs or
/// launches a browser. While the index catches up the inventory says how far
/// it got. `list_artifacts` with `kind=wasm` pages the rest.
pub fn artifacts(root: &Path) -> Result<Value> {
    let wasm = crate::artifact_lookup::wasm(
        root,
        ITEMS,
        Instant::now() + crate::artifact_lookup::LOOKUP_DEADLINE,
    )
    .map_err(|error| {
        Error::new(
            500,
            format!(
                "Session context artifact manifest is unavailable: {}",
                error.message
            ),
        )
    })?;
    if let Some(damage) = wasm.damage {
        return Err(Error::new(
            500,
            format!("Session context artifact manifest is damaged: {damage}"),
        ));
    }
    let items = wasm
        .newest
        .iter()
        .map(|record| {
            json!({
                "artifact_id": record["artifact_id"], "session_id": record["session_id"],
                "url": url_label(&record["url"]), "byte_length": record["byte_size"].as_u64().filter(|n| *n <= crate::validation::MAX_SAFE_INTEGER),
                "sha256": record["sha256"], "script_id": null,
            })
        })
        .collect::<Vec<_>>();
    let scope = if wasm.stopped.is_some() {
        "stopped"
    } else if wasm.complete {
        "store"
    } else {
        "indexing"
    };
    Ok(json!({
        "items_omitted": wasm.total.saturating_sub(items.len() as u64),
        "items": items,
        "window_truncated": scope != "store",
        "scope": scope,
        "scan_end": wasm.indexed_to.to_string(),
        "store_end": wasm.file_end.to_string(),
    }))
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
    fn content_limits_label_only_a_live_content_session() {
        use clap::Parser;
        let parse = |arguments: &[&str]| {
            crate::config::Options::try_parse_from(
                ["origin-trace-backend"].iter().chain(arguments).copied(),
            )
        };
        let live = ["--socket", "/tmp/broker.sock"];
        let content = [&live[..], &["--session-request-content"]].concat();
        let limits = |arguments: &[&str]| {
            content_limits(&parse(&[&content[..], arguments].concat()).unwrap())
        };
        assert_eq!(
            limits(&[
                "--session-request-content-budget-mib",
                "256",
                "--session-response-body-budget-mib",
                "512",
                "--session-response-media",
                "0"
            ]),
            json!({"version":1,"request_content_budget_mib":256,"response_body_budget_mib":512,"response_media":false})
        );
        assert_eq!(
            limits(&[
                "--session-request-content-budget-mib",
                "4096",
                "--session-response-body-budget-mib",
                "16384",
                "--session-response-media",
                "1"
            ]),
            json!({"version":1,"request_content_budget_mib":4096,"response_body_budget_mib":16384,"response_media":true})
        );
        // A launcher that names no limit reports none, never a guessed default.
        assert_eq!(
            limits(&[]),
            json!({"version":1,"request_content_budget_mib":null,"response_body_budget_mib":null,"response_media":null})
        );
        // A metadata session and a backend that is not live carry no limits.
        assert!(content_limits(&parse(&live).unwrap()).is_null());
        assert!(content_limits(&parse(&[]).unwrap()).is_null());
        // The labels mean nothing without request content, and keep the
        // launcher's bounds.
        for arguments in [
            &[&live[..], &["--session-request-content-budget-mib", "64"]].concat(),
            &[&live[..], &["--session-response-media", "1"]].concat(),
            &[&content[..], &["--session-response-media"]].concat(),
            &[&content[..], &["--session-response-media", "yes"]].concat(),
            &[
                &content[..],
                &["--session-request-content-budget-mib", "4097"],
            ]
            .concat(),
            &[&content[..], &["--session-request-content-budget-mib", "0"]].concat(),
            &[
                &content[..],
                &["--session-response-body-budget-mib", "16385"],
            ]
            .concat(),
        ] {
            assert!(parse(arguments).is_err(), "{arguments:?}");
        }
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
    fn artifact_inventory_covers_the_whole_manifest_and_never_reads_blobs() {
        let root = tempfile::tempdir().unwrap();
        let rows: String = (0..40).map(|id| format!("{}\n", record(id))).collect();
        std::fs::write(root.path().join("manifest.jsonl"), rows).unwrap();
        let value = artifacts(root.path()).unwrap();
        assert_eq!(value["items"].as_array().unwrap().len(), ITEMS);
        assert_eq!(value["items_omitted"], 24);
        assert_eq!(value["items"][0]["artifact_id"], "39");
        assert_eq!(value["items"][0]["url"], "https://owned.example");
        assert!(value["items"][0]["script_id"].is_null());
        assert!(!value.to_string().contains("secret_canary"));
        assert_eq!(value["window_truncated"], false);
        assert_eq!(value["scope"], "store");
        // A Wasm module ahead of far more than the old 256 KiB tail is listed,
        // and every module behind it counted.
        let mut text = format!("{}\n", record(1));
        let mut id = 1;
        while text.len() < 4 << 20 {
            id += 1;
            let mut script = record(id);
            script["kind"] = json!("javascript");
            script["mime_type"] = json!("text/javascript");
            text.push_str(&format!("{script}\n"));
        }
        std::fs::write(root.path().join("manifest.jsonl"), &text).unwrap();
        let early = artifacts(root.path()).unwrap();
        assert_eq!(early["items"][0]["artifact_id"], "1", "{early}");
        assert_eq!(early["items_omitted"], 0);
        assert_eq!(early["window_truncated"], false);
        assert_eq!(early["store_end"], text.len().to_string());
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
        std::fs::write(root.path().join("manifest.jsonl"), "secret_canary\n").unwrap();
        assert!(
            !artifacts(root.path())
                .unwrap_err()
                .to_string()
                .contains("secret_canary")
        );
    }
}
