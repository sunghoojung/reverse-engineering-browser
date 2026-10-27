//! Exact, inert reads of one retained Traffic record. Identity is the same
//! five-field tuple used by apiCatalogResolveSource in the research UI.
use super::Debugger;
use crate::{
    error::{Code, Error, Reason, Result, SelectionReason},
    validation,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Write};

pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUERY_BYTES: usize = 40 * 1024;

pub struct NetworkRequestSelection {
    instance: String,
    epoch: u64,
    request: String,
    target: String,
    started: f64,
}
impl NetworkRequestSelection {
    pub fn parse(raw: &str) -> Result<Self> {
        if raw.len() > MAX_QUERY_BYTES {
            return Err(Error::bad(
                "Network request selection exceeds its byte limit",
            ));
        }
        let mut fields = BTreeMap::new();
        for pair in raw.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| Error::bad("Network request selection is invalid"))?;
            let key = decode(key)?;
            if ![
                "instance_id",
                "capture_epoch",
                "request_id",
                "target_id",
                "started_monotonic_ms",
            ]
            .contains(&key.as_str())
                || fields.insert(key, decode(value)?).is_some()
            {
                return Err(Error::bad(
                    "Network request selection has unknown or duplicate fields",
                ));
            }
        }
        if fields.len() != 5 {
            return Err(Error::bad(
                "Network request selection requires all five identity fields",
            ));
        }
        for (key, limit) in [
            ("instance_id", 128),
            ("request_id", 8192),
            ("target_id", 4096),
        ] {
            if fields[key].is_empty() || fields[key].len() > limit {
                return Err(Error::bad("Network request identity is empty or oversized"));
            }
        }
        let epoch =
            validation::canonical(&json!(fields["capture_epoch"]), 64, false, "Capture epoch")?;
        if epoch > validation::MAX_SAFE_INTEGER {
            return Err(Error::bad("Capture epoch exceeds its safe integer range"));
        }
        let text = &fields["started_monotonic_ms"];
        // JSON spelling rejects whitespace, NaN, Infinity, hex and leading '+'.
        // float_roundtrip keeps the exact retained binary64 identity, not a UI
        // timestamp rounded to milliseconds or microseconds.
        let started = if text.len() <= 64 && text.trim() == text {
            serde_json::from_str::<Value>(text)
                .ok()
                .and_then(|v| v.as_f64())
                .filter(|v| v.is_finite() && *v >= 0.0)
        } else {
            None
        }
        .ok_or_else(|| {
            Error::bad("Started monotonic time must be a finite nonnegative JSON number")
        })?;
        Ok(Self {
            instance: fields.remove("instance_id").unwrap(),
            epoch,
            request: fields.remove("request_id").unwrap(),
            target: fields.remove("target_id").unwrap(),
            started,
        })
    }
    fn source(&self) -> Value {
        json!({"instance_id":self.instance,"capture_epoch":self.epoch,
            "request_id":self.request,"target_id":self.target,"started_monotonic_ms":self.started})
    }
}
// Form decoding must not replace invalid UTF-8 or malformed escapes and thereby
// select a different retained identity. '+' has the usual query-space meaning.
fn decode(raw: &str) -> Result<String> {
    let invalid = || Error::bad("Network request selection has invalid query encoding");
    let mut bytes = Vec::with_capacity(raw.len());
    let mut input = raw.bytes();
    while let Some(byte) = input.next() {
        bytes.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = (input.next().ok_or_else(invalid)? as char)
                    .to_digit(16)
                    .ok_or_else(invalid)?;
                let low = (input.next().ok_or_else(invalid)? as char)
                    .to_digit(16)
                    .ok_or_else(invalid)?;
                (high * 16 + low) as u8
            }
            byte => byte,
        });
    }
    String::from_utf8(bytes).map_err(|_| invalid())
}
fn limit_error() -> Error {
    Error::new(
        413,
        "Selected Traffic record exceeds the response byte limit",
    )
    .with_code(Code::ResourceLimit)
}
struct SizeBudget(usize);
impl Write for SizeBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_RESPONSE_BYTES)
            .ok_or_else(|| std::io::Error::other("Response byte limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Debugger {
    pub fn network_request(&self, selection: &NetworkRequestSelection) -> Result<Vec<u8>> {
        let mut output = json!({"format":"reb-network-request-v1",
            "source":selection.source(),"debugger_generation":null,"request":null});
        {
            // One lock defines a coherent ownership/uniqueness/row snapshot.
            // No complete debugger snapshot, selected-target refresh or CDP call.
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let network = &state["network"];
            if network["instance_id"].as_str() != Some(selection.instance.as_str())
                || network["capture_epoch"].as_u64() != Some(selection.epoch)
            {
                return Err(
                    Error::conflict("Traffic capture identity has changed").with_reason(
                        Reason::selection(Code::StateConflict, SelectionReason::StaleCapture),
                    ),
                );
            }
            let mut rows = network["requests"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|row| row["id"].as_str() == Some(selection.request.as_str()));
            let selected = rows.next();
            // The public ID must be unique across the whole retained window,
            // even when exactly one duplicate matches target and start time.
            if rows.next().is_some() {
                return Err(
                    Error::conflict("Traffic request identity is ambiguous").with_reason(
                        Reason::selection(Code::StateConflict, SelectionReason::AmbiguousRequest),
                    ),
                );
            }
            let selected = selected
                .filter(|row| {
                    row["target_id"].as_str() == Some(selection.target.as_str())
                        && row["started_monotonic_ms"].as_f64() == Some(selection.started)
                })
                .ok_or_else(|| {
                    Error::new(404, "Exact Traffic request is not retained").with_reason(
                        Reason::selection(
                            Code::TargetUnavailable,
                            SelectionReason::RequestNotRetained,
                        ),
                    )
                })?;
            output["debugger_generation"] = state["generation"].clone();
            // Count actual JSON escaping without allocating or copying a row
            // that cannot fit. Replace the four bytes of the null placeholder.
            let mut budget = SizeBudget(0);
            serde_json::to_writer(&mut budget, &output).map_err(|_| limit_error())?;
            budget.0 -= 4;
            serde_json::to_writer(&mut budget, selected).map_err(|_| limit_error())?;
            output["request"] = selected.clone();
        }
        // The immutable copy was measured in full. No truncation, normalization,
        // redaction, body fetch or unrelated state is added to the result.
        serde_json::to_vec(&output)
            .map_err(|_| Error::new(500, "Selected Traffic serialization failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::sync::Arc;

    fn query(source: &Value) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(source.as_object().unwrap().iter().map(|(key, value)| {
                (
                    key.clone(),
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), str::to_owned),
                )
            }))
            .finish()
    }
    fn selection(debugger: &Debugger, index: usize) -> NetworkRequestSelection {
        let snapshot = debugger.snapshot();
        let network = &snapshot["network"];
        let row = &network["requests"][index];
        NetworkRequestSelection::parse(&query(&json!({
            "instance_id":network["instance_id"],"capture_epoch":network["capture_epoch"],
            "request_id":row["id"],"target_id":row["target_id"],
            "started_monotonic_ms":row["started_monotonic_ms"]
        })))
        .unwrap()
    }
    async fn fixture() -> Arc<Debugger> {
        let options = crate::config::Options::parse_from(["test"]);
        let debugger = Debugger::new(&options);
        debugger.update(|s| {
            s["target"] = json!({"id":"synthetic-target","title":"Synthetic title"});
            s["network"]["capture_enabled"] = json!(true);
            s["console"] = json!({"unrelated":"synthetic-unrelated-console"});
            s["error"] = json!("synthetic-unrelated-debugger-error");
        });
        for (id, time) in [("selected", 0.1000000001), ("other", 0.1000000002)] {
            debugger.historical_fixture("Network.requestWillBeSent", &json!({
                "requestId":id,"timestamp":time,"type":"Fetch","documentURL":"https://example.test/",
                "request":{"url":format!("https://user:synthetic-pass@example.test/{id}?token=synthetic-query#fragment"),
                    "method":"POST","postData":format!("synthetic-{id}-body"),
                    "headers":{"Content-Type":"text/plain","Authorization":"Bearer synthetic-secret"}}
            })).await;
        }
        debugger
    }
    fn output(debugger: &Debugger, selection: &NetworkRequestSelection) -> Value {
        let bytes = debugger.network_request(selection).unwrap();
        assert!(bytes.len() <= MAX_RESPONSE_BYTES);
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        validation::schema("NetworkRequestResponse", &value, 500).unwrap();
        value
    }
    fn failure(
        debugger: &Debugger,
        selection: &NetworkRequestSelection,
        status: u16,
        code: &str,
        reason: &str,
    ) {
        let error = debugger.network_request(selection).unwrap_err();
        assert_eq!(error.status, status);
        let error = serde_json::to_value(error).unwrap();
        assert_eq!(error["code"], code);
        assert_eq!(error["details"]["selection_reason"], reason);
        validation::schema("Error", &error, 500).unwrap();
        assert!(!error.to_string().contains("synthetic-"));
        assert_eq!(error.as_object().unwrap().len(), 3);
    }
    #[tokio::test]
    async fn exact_row_is_lossless_inert_and_not_a_full_snapshot() {
        let debugger = fixture().await;
        let selected = selection(&debugger, 0);
        let before = debugger.snapshot();
        let value = output(&debugger, &selected);
        assert_eq!(value["request"], before["network"]["requests"][0]);
        assert_eq!(value["source"], selected.source());
        assert_eq!(value["debugger_generation"], before["generation"]);
        assert_eq!(value.as_object().unwrap().len(), 4);
        let text = value.to_string();
        for absent in [
            "synthetic-other-body",
            "synthetic-unrelated-console",
            "synthetic-unrelated-debugger-error",
        ] {
            assert!(!text.contains(absent));
        }
        assert!(text.contains("Bearer synthetic-secret"));
        assert!(text.contains("synthetic-pass"));
        assert_eq!(value["request"]["response"]["body"]["state"], "loading");
        assert_eq!(before, debugger.snapshot());
        assert!(debugger.action(&json!({"action":"connect"})).await.is_err());
    }
    #[tokio::test]
    async fn body_completion_and_redirect_hops_preserve_original_selection() {
        let debugger = fixture().await;
        let selected = selection(&debugger, 0);
        let pending = output(&debugger, &selected);
        assert_eq!(pending["request"]["response"]["body"]["state"], "loading");
        debugger.update(|state| {
            // Import a later authored snapshot; there is no live transport to
            // advance this historical generation on our behalf.
            state["generation"] = json!(state["generation"].as_u64().unwrap() + 1);
            state["network"]["requests"][0]["response"]["body"] = json!({
                "state":"available", "mime":"application/json",
                "text":"{\"synthetic\":true}", "base64":"",
                "truncated":false, "reason":""
            });
        });
        let complete = output(&debugger, &selected);
        assert_eq!(complete["source"], pending["source"]);
        assert_eq!(
            complete["request"]["response"]["body"]["state"],
            "available"
        );
        assert!(
            complete["debugger_generation"].as_u64().unwrap()
                > pending["debugger_generation"].as_u64().unwrap()
        );

        // One protocol ID owns distinct public identities for redirect hops.
        debugger
            .historical_fixture(
                "Network.requestWillBeSent",
                &json!({
                    "requestId":"selected", "timestamp":0.2,
                    "type":"Fetch", "documentURL":"https://example.test/",
                    "redirectResponse":{
                        "status":302, "statusText":"Found", "headers":{},
                        "mimeType":"text/plain", "encodedDataLength":0
                    },
                    "request":{
                        "url":"https://example.test/redirected", "method":"GET",
                        "headers":{}
                    }
                }),
            )
            .await;
        let original_hop = output(&debugger, &selected);
        assert_eq!(original_hop["source"], pending["source"]);
        assert_eq!(original_hop["request"]["status"], 302);
        assert_eq!(
            original_hop["request"]["response"]["body"]["state"],
            "missing"
        );
        let next = selection(&debugger, 2);
        let next_hop = output(&debugger, &next);
        assert_ne!(next_hop["source"]["request_id"], selected.request);
        assert_eq!(next_hop["request"]["protocol_request_id"], "selected");
        assert_eq!(
            next_hop["request"]["url"],
            "https://example.test/redirected"
        );
        let mut protocol_selection = selection(&debugger, 2);
        protocol_selection.request = "selected".into();
        failure(
            &debugger,
            &protocol_selection,
            404,
            "target_unavailable",
            "request_not_retained",
        );
    }
    #[tokio::test]
    async fn stale_missing_rounded_and_duplicate_identities_never_fall_back() {
        let debugger = fixture().await;
        let mut selected = selection(&debugger, 0);
        selected.instance.push_str("-stale");
        failure(&debugger, &selected, 409, "state_conflict", "stale_capture");
        selected = selection(&debugger, 0);
        selected.epoch += 1;
        failure(&debugger, &selected, 409, "state_conflict", "stale_capture");
        selected = selection(&debugger, 0);
        selected.request.push_str("-missing");
        failure(
            &debugger,
            &selected,
            404,
            "target_unavailable",
            "request_not_retained",
        );
        selected = selection(&debugger, 0);
        selected.target.push_str("-other");
        failure(
            &debugger,
            &selected,
            404,
            "target_unavailable",
            "request_not_retained",
        );
        selected = selection(&debugger, 0);
        selected.started = selected.started.round();
        failure(
            &debugger,
            &selected,
            404,
            "target_unavailable",
            "request_not_retained",
        );
        selected = selection(&debugger, 0);
        debugger.update(|s| {
            s["network"]["requests"][1]["id"] = s["network"]["requests"][0]["id"].clone();
        });
        failure(
            &debugger,
            &selected,
            409,
            "state_conflict",
            "ambiguous_request",
        );
        // Ambiguity is public-ID-wide, including when no target/time is exact.
        selected.target.push_str("-other");
        failure(
            &debugger,
            &selected,
            409,
            "state_conflict",
            "ambiguous_request",
        );
        selected.epoch += 1;
        failure(&debugger, &selected, 409, "state_conflict", "stale_capture");
    }
    #[tokio::test]
    async fn eviction_epoch_change_and_disabled_capture_are_explicit() {
        let debugger = fixture().await;
        let selected = selection(&debugger, 0);
        debugger.update(|s| s["network"]["capture_enabled"] = json!(false));
        output(&debugger, &selected); // Read retained evidence without enabling capture.
        debugger.update(|s| {
            s["network"]["requests"].as_array_mut().unwrap().remove(0);
        });
        failure(
            &debugger,
            &selected,
            404,
            "target_unavailable",
            "request_not_retained",
        );
        debugger.update(|s| s["network"]["capture_epoch"] = json!(1));
        failure(&debugger, &selected, 409, "state_conflict", "stale_capture");
    }
    #[tokio::test]
    async fn unicode_identities_preserve_exact_bytes_and_submillisecond_start() {
        let debugger = fixture().await;
        debugger.update(|s| {
            s["network"]["instance_id"] = json!("合成%owner+identity");
            s["network"]["capture_epoch"] = json!(validation::MAX_SAFE_INTEGER);
            s["network"]["requests"][0]["id"] = json!("合成%request+id&x=1");
            s["network"]["requests"][0]["target_id"] = json!("合成/target?x=1");
        });
        let selected = selection(&debugger, 0);
        let value = output(&debugger, &selected);
        assert_eq!(
            value["request"]["started_monotonic_ms"].as_f64(),
            Some(selected.started)
        );
        assert_eq!(value["request"]["target_id"], selected.target);
        assert_eq!(
            value["source"]["capture_epoch"],
            validation::MAX_SAFE_INTEGER
        );
    }
    #[test]
    fn query_is_closed_strict_and_bounded() {
        let base = json!({"instance_id":"owner","capture_epoch":"0","request_id":"request","target_id":"target","started_monotonic_ms":"100.0000001"});
        assert!(NetworkRequestSelection::parse(&query(&base)).is_ok());
        for field in base.as_object().unwrap().keys() {
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(NetworkRequestSelection::parse(&query(&missing)).is_err());
            assert!(
                NetworkRequestSelection::parse(&format!("{}&{field}=x", query(&base))).is_err()
            );
            let mut empty = base.clone();
            empty[field] = json!("");
            assert!(NetworkRequestSelection::parse(&query(&empty)).is_err());
        }
        for suffix in [
            "&unknown=x",
            "&%72equest_id=other",
            "&",
            "&request_id",
            "&%ff=x",
        ] {
            assert!(NetworkRequestSelection::parse(&format!("{}{suffix}", query(&base))).is_err());
        }
        for invalid in [
            "-1",
            "01",
            "+1",
            "1.0",
            "1e0",
            "9007199254740992",
            "18446744073709551616",
            " 1",
        ] {
            let mut value = base.clone();
            value["capture_epoch"] = json!(invalid);
            assert!(
                NetworkRequestSelection::parse(&query(&value)).is_err(),
                "{invalid}"
            );
        }
        for invalid in [
            "NaN",
            "Infinity",
            "-Infinity",
            "-0.1",
            "1e999",
            "+1",
            "01",
            "0x10",
            " 1",
            "1 ",
            "true",
            "null",
            "\"1\"",
            "[]",
        ] {
            let mut value = base.clone();
            value["started_monotonic_ms"] = json!(invalid);
            assert!(
                NetworkRequestSelection::parse(&query(&value)).is_err(),
                "{invalid}"
            );
        }
        for valid in ["0", "-0", "1e-9", "100.0000001", "1.7976931348623157e308"] {
            let mut value = base.clone();
            value["started_monotonic_ms"] = json!(valid);
            assert!(
                NetworkRequestSelection::parse(&query(&value)).is_ok(),
                "{valid}"
            );
        }
        for invalid in ["%", "%0", "%GG", "%FF", "%C3%28"] {
            let raw = query(&base).replace("request_id=request", &format!("request_id={invalid}"));
            assert!(NetworkRequestSelection::parse(&raw).is_err());
        }
        for (field, limit) in [
            ("instance_id", 128),
            ("request_id", 8192),
            ("target_id", 4096),
        ] {
            let mut value = base.clone();
            value[field] = json!("é".repeat(limit / 2));
            assert!(NetworkRequestSelection::parse(&query(&value)).is_ok());
            value[field] = json!("é".repeat(limit / 2 + 1));
            assert!(NetworkRequestSelection::parse(&query(&value)).is_err());
        }
        assert!(NetworkRequestSelection::parse(&"x".repeat(MAX_QUERY_BYTES + 1)).is_err());
    }
    #[test]
    fn maximum_encoded_identity_fits_query_budget_without_loss() {
        let source = json!({"instance_id":"\0".repeat(128),
            "request_id":"\0".repeat(8192),"target_id":"\0".repeat(4096),
            "capture_epoch":validation::MAX_SAFE_INTEGER,"started_monotonic_ms":100.0000001});
        let raw = query(&source);
        assert!(raw.len() <= MAX_QUERY_BYTES);
        assert_eq!(
            NetworkRequestSelection::parse(&raw).unwrap().source(),
            source
        );
    }
    #[tokio::test]
    async fn maximum_escaping_preserves_all_producer_limits_and_truncation_flags() {
        let debugger = fixture().await;
        // Synthetic control bytes are worst-case six-byte JSON escapes.
        debugger.update(|s| {
            let row = &mut s["network"]["requests"][0];
            for key in ["url", "document_url", "target_title"] { row[key] = json!("\0".repeat(65536)); }
            row["url_truncated"] = json!(true);
            row["document_url_truncated"] = json!(true);
            row["method_truncated"] = json!(true);
            for side in ["request", "response"] {
                row[side]["headers"] = json!((0..8).map(|_| json!(["\0".repeat(128), "\0".repeat(8064)])).collect::<Vec<_>>());
                row[side]["headers_truncated"] = json!(true);
                row[side]["body"] = json!({"state":"available","mime":"\0".repeat(8192),"text":"\0".repeat(131072),"base64":"","truncated":true,"reason":"\0".repeat(512)});
            }
            row["initiator"] = json!({"sites":(0..16).map(|_| json!({"script_id":"\0".repeat(4096),"target_id":"\0".repeat(4096),"source":"\0".repeat(8192),"source_hash":"\0".repeat(256),"function":"\0".repeat(256),"line":0,"column":0,"source_truncated":true})).collect::<Vec<_>>(),"gaps":["call_site_limit"]});
        });
        let selected = selection(&debugger, 0);
        let before = debugger.snapshot();
        let value = output(&debugger, &selected);
        assert_eq!(value["request"], before["network"]["requests"][0]);
        assert_eq!(debugger.snapshot(), before);
        assert!(value.to_string().len() > 5 * 1024 * 1024);
        debugger.update(|s| s["network"]["requests"][0]["response"]["body"] = json!({"state":"available","mime":"image/png","text":"","base64":format!("{}=", "A".repeat(174763)),"truncated":true,"reason":""}));
        output(&debugger, &selected);
    }
    #[tokio::test]
    async fn response_byte_boundary_rejects_whole_row_without_content_in_errors() {
        let debugger = fixture().await;
        let selected = selection(&debugger, 0);
        debugger.update(|s| s["network"]["requests"][0]["synthetic_extension"] = json!(""));
        let size = debugger.network_request(&selected).unwrap().len();
        debugger.update(|s| {
            s["network"]["requests"][0]["synthetic_extension"] =
                json!("a".repeat(MAX_RESPONSE_BYTES - size))
        });
        assert_eq!(
            debugger.network_request(&selected).unwrap().len(),
            MAX_RESPONSE_BYTES
        );
        debugger.update(|s| {
            let mut text = s["network"]["requests"][0]["synthetic_extension"]
                .as_str()
                .unwrap()
                .to_owned();
            text.push('a');
            s["network"]["requests"][0]["synthetic_extension"] = json!(text);
        });
        let before = debugger.snapshot();
        let error = debugger.network_request(&selected).unwrap_err();
        assert_eq!(error.status, 413);
        let value = serde_json::to_value(error).unwrap();
        assert_eq!(value["code"], "resource_limit");
        assert_eq!(value["details"], json!({}));
        assert!(value.to_string().len() < 256);
        assert!(!value.to_string().contains("synthetic"));
        assert_eq!(before, debugger.snapshot());
    }
}
