//! HAR 1.2 entries of Traffic rows, for `export_requests_har`
//! (protocol/http-api.md, "Request HAR export"). Each hop of a row is one
//! entry: a redirect keeps its own entry, with its status and the next hop's
//! URL, and a request that failed, was interrupted or is still open keeps its
//! entry with status 0, labeled in `_reb`. Every value is what the capture
//! retained, joined only by exact lifecycle parents: targets from
//! `request_target` children, headers from the hop's header blocks
//! (`request_headers::build`, credential values only when asked), and bodies
//! from their verified artifacts. Nothing is inferred from a URL or adjacency.
//!
//! Native capture keeps a monotonic clock only. `startedDateTime` is that
//! clock written as an offset from the Unix epoch, so order and spacing are
//! exact and the calendar date is not; `log.comment` says so.
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::event_query::{self, EventFilter, RecordRange};
use crate::evidence;
use crate::gap_tally::GapTally;
use crate::request_headers::{self, Credentials, Drops};
use crate::request_index::{self, RequestIndex};

const FORMAT: &str = "reb-request-har-v1";
/// Rows read from the index under one lock, so a long export never holds it.
const BATCH: usize = 64;
/// Bytes buffered before a chunk is handed to the response.
const CHUNK: usize = 256 * 1024;

pub const CLOCK_COMMENT: &str = "Origin Trace native capture records a monotonic clock only. \
startedDateTime is that clock written as an offset from the Unix epoch: the order and spacing \
of entries are exact, the calendar date is not. Each entry's _reb object names its Traffic row, \
hop and outcome.";

/// One hop's lifecycle record and the target child it names.
struct Hop<'a> {
    record: &'a Value,
    method: Option<String>,
    host: Option<String>,
    target: Option<&'a Value>,
}

/// The records of `row` that `build` reads: every record of its root
/// request. `artifacts` are the manifest records those records name.
pub fn entries(
    row: &Value,
    records: &[Value],
    drops: &Drops,
    artifacts: &[Value],
    root: &Path,
    credentials: Credentials,
) -> Vec<Value> {
    let Some((session, process, request)) = root_of(row) else {
        return vec![unlinked(row)];
    };
    let ours = |event: &Value| {
        event["session_id"] == session.as_str()
            && event["request_id"] == request.as_str()
            && event["category"] == "network"
            && event["process_id"].as_u64() == Some(process)
    };
    let mut lifecycle: Vec<&Value> = records
        .iter()
        .filter(|event| {
            ours(event)
                && matches!(
                    event["type"].as_str(),
                    Some("request_started" | "request_redirected")
                )
        })
        .collect();
    lifecycle.sort_by_key(|event| sequence(event));
    // A redirect chain starts at its one request_started record.
    if lifecycle
        .first()
        .is_some_and(|event| event["type"] != "request_started")
    {
        lifecycle.clear();
    }
    let hops: Vec<Hop> = lifecycle
        .iter()
        .map(|record| {
            let payload = request_index::payload_text(
                &hex::decode(record["payload"].as_str().unwrap_or("")).unwrap_or_default(),
            );
            let kind = record["type"].as_str().unwrap_or("");
            let (method, host) = request_index::network_target(&payload, kind)
                .map_or((None, None), |(method, host)| (method, Some(host)));
            let target = records.iter().find(|child| {
                child["type"] == "request_target"
                    && child["session_id"] == record["session_id"]
                    && child["process_id"] == record["process_id"]
                    && child["parent_event_id"] == record["sequence_number"]
            });
            Hop {
                record,
                method,
                host,
                target,
            }
        })
        .collect();
    if hops.is_empty() {
        return vec![unlinked(row)];
    }
    let headers = request_headers::build(
        records,
        drops,
        artifacts,
        root,
        &session,
        &request,
        credentials,
    );
    let blocks = |hop: usize| {
        headers["hops"]
            .as_array()
            .and_then(|hops| hops.iter().find(|entry| entry["hop"] == hop))
    };
    let urls: Vec<(String, bool)> = hops
        .iter()
        .map(|hop| url_of(hop, artifacts, root))
        .collect();
    let last = hops.len() - 1;
    let end_ns = number(&row["last_time_ns"]);
    let method = row["method"].as_str().unwrap_or("GET").to_owned();
    hops.iter()
        .enumerate()
        .map(|(index, hop)| {
            let start = number(&hop.record["monotonic_time_ns"]);
            let next = hops.get(index + 1);
            let final_hop = index == last;
            let hop_blocks = blocks(index);
            let sent = hop_blocks.and_then(|entry| {
                let request = entry["request"].as_array()?;
                // What the network stack sent, else the browser's provisional block.
                request
                    .iter()
                    .rev()
                    .find(|block| block["source"] == "network" && block["headers"].is_array())
                    .or_else(|| {
                        request
                            .iter()
                            .rev()
                            .find(|block| block["headers"].is_array())
                    })
            });
            let received = hop_blocks.and_then(|entry| {
                let response = entry["response"].as_array()?;
                response
                    .iter()
                    .rev()
                    .find(|block| block["source"] == "network" && block["headers"].is_array())
                    .or_else(|| {
                        response
                            .iter()
                            .rev()
                            .find(|block| block["headers"].is_array())
                    })
            });
            let request_headers = har_headers(sent);
            let response_headers = har_headers(received);
            let status = if final_hop {
                row["status"].as_u64().unwrap_or(0)
            } else {
                // The redirect's status: the next hop's record carries it, else
                // the hop's response block.
                next.and_then(|next| next.record["status_code"].as_u64())
                    .filter(|status| *status > 0)
                    .or_else(|| received.and_then(|block| block["status_code"].as_u64()))
                    .unwrap_or(0)
            };
            let outcome = if !final_hop {
                "redirect"
            } else if row["failed"] == true {
                "failed"
            } else if row["status"] == "incomplete" {
                "incomplete"
            } else if row["status"] == "pending" {
                "pending"
            } else {
                "complete"
            };
            let finish = match next {
                Some(next) => number(&next.record["monotonic_time_ns"]),
                None => end_ns.max(start),
            };
            let response_at = if final_hop {
                row["response_time_ns"]
                    .as_str()
                    .and_then(|time| time.parse::<u64>().ok())
                    .filter(|time| *time >= start && *time <= finish)
            } else {
                None
            };
            let wait = milliseconds(response_at.unwrap_or(finish) - start);
            let receive = milliseconds(finish - response_at.unwrap_or(finish));
            let (url, url_complete) = urls[index].clone();
            let hop_method = hop.method.clone().unwrap_or_else(|| method.clone());
            let mut har_request = json!({
                "method": hop_method,
                "url": url,
                "httpVersion": if final_hop { row["protocol"].as_str().unwrap_or("") } else { "" },
                "cookies": cookies(&request_headers, "cookie"),
                "headers": request_headers,
                "queryString": query_string(&urls[index].0),
                "headersSize": -1,
                "bodySize": -1,
            });
            if index == 0
                && let Some(body) = request_body(records, &hops[0], artifacts, root)
            {
                har_request["bodySize"] = body.0;
                if let Some(data) = body.1 {
                    har_request["postData"] = data;
                }
            }
            let mut content = json!({
                "size": if final_hop { row["resource_size"].as_i64().unwrap_or(0) } else { 0 },
                "mimeType": if final_hop { row["mime_type"].as_str().unwrap_or("") } else { "" },
            });
            let mut body_case = Value::Null;
            if final_hop {
                body_case = row["response_body"]["case"].clone();
                if let Some((text, encoding)) = response_body(row, artifacts, root) {
                    content["text"] = json!(text);
                    if let Some(encoding) = encoding {
                        content["encoding"] = json!(encoding);
                    }
                }
            }
            let redirect_url = next
                .map(|_| urls[index + 1].0.clone())
                .unwrap_or_default();
            let mut entry = json!({
                "startedDateTime": iso_date(start),
                "time": wait + receive,
                "request": har_request,
                "response": {
                    "status": status,
                    "statusText": "",
                    "httpVersion": if final_hop { row["protocol"].as_str().unwrap_or("") } else { "" },
                    "cookies": cookies(&response_headers, "set-cookie"),
                    "headers": response_headers,
                    "content": content,
                    "redirectURL": redirect_url,
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "cache": {},
                "timings": {"send": 0, "wait": wait, "receive": receive},
                "_reb": {
                    "row_id": row["id"],
                    "session_id": session,
                    "process_id": process,
                    "request_id": request,
                    "hop": index,
                    "hops": hops.len(),
                    "outcome": outcome,
                    "error_code": if final_hop { row["error_code"].clone() } else { json!(0) },
                    "from_cache": final_hop && row["from_cache"] == true,
                    "from_service_worker": final_hop && row["from_service_worker"] == true,
                    "monotonic_time_ns": start.to_string(),
                    "url_complete": url_complete,
                    "request_headers": block_state(sent, hop_blocks, "request"),
                    "response_headers": block_state(received, hop_blocks, "response"),
                    "response_body": body_case,
                    "credential_values": credentials.name(),
                },
            });
            if let Some(address) = received.and_then(|block| block["remote_address"].as_str()) {
                entry["serverIPAddress"] = json!(address);
            }
            entry
        })
        .collect()
}

/// The row's root request: (session, browser process, request).
fn root_of(row: &Value) -> Option<(String, u64, String)> {
    let root = &row["root"];
    Some((
        root["session_id"].as_str()?.to_owned(),
        root["process_id"].as_u64()?,
        root["request_id"].as_str()?.to_owned(),
    ))
}

/// A row with no lifecycle start to join hops to, such as a memory-cache
/// reuse: one entry from the row alone, labeled as such.
fn unlinked(row: &Value) -> Value {
    let start = number(&row["first_time_ns"]);
    let path = row["path"].as_str().unwrap_or("").to_owned();
    json!({
        "startedDateTime": iso_date(start),
        "time": row["duration_ns"].as_str().and_then(|d| d.parse::<u64>().ok()).map_or(0.0, milliseconds),
        "request": {"method": row["method"], "url": path, "httpVersion": "", "cookies": [], "headers": [],
            "queryString": query_string(&path), "headersSize": -1, "bodySize": -1},
        "response": {"status": row["status"].as_u64().unwrap_or(0), "statusText": "", "httpVersion": "",
            "cookies": [], "headers": [],
            "content": {"size": row["resource_size"].as_i64().unwrap_or(0), "mimeType": row["mime_type"].as_str().unwrap_or("")},
            "redirectURL": "", "headersSize": -1, "bodySize": -1},
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
        "_reb": {"row_id": row["id"], "hop": 0, "hops": 0, "outcome": "unlinked",
            "monotonic_time_ns": start.to_string(), "url_complete": false,
            "memory_cache": row["memory_cache"], "target_kind": row["target_kind"]},
    })
}

/// The hop's URL and whether it is the whole captured target. A target past
/// 116 bytes is read from its verified artifact; without one the prefix
/// stands, marked incomplete.
fn url_of(hop: &Hop, artifacts: &[Value], root: &Path) -> (String, bool) {
    let host = hop.host.clone().unwrap_or_default();
    let Some(child) = hop.target else {
        // A metadata-only session names the host alone.
        return (host, false);
    };
    let Some(target) = request_index::decode_target(child) else {
        return (host, false);
    };
    let mut text = target.text.clone();
    let mut complete = target.length as usize <= 116;
    if !complete
        && let Some(artifact) = named(artifacts, child, "request_target")
        && let Ok(bytes) = evidence::content(root, artifact, target.length as usize)
        && bytes.len() == target.length as usize
    {
        text = request_index::payload_text(&bytes);
        complete = true;
    }
    let port = if target.port != 0 {
        format!(":{}", target.port)
    } else {
        String::new()
    };
    // A target without a scheme is written as the row composes it.
    let url = match &target.scheme {
        Some(scheme) => format!("{scheme}://{host}{port}{text}"),
        None => format!("{host}{port}{text}"),
    };
    (url, complete)
}

/// The one manifest record of `kind` that `record` names.
fn named<'a>(artifacts: &'a [Value], record: &Value, kind: &str) -> Option<&'a Value> {
    let id = record["artifact_id"].as_str().filter(|id| *id != "0")?;
    artifacts.iter().find(|artifact| {
        artifact["artifact_id"] == id
            && artifact["session_id"] == record["session_id"]
            && artifact["kind"] == kind
    })
}

/// `bodySize` and `postData` from the request's `request_body` record
/// (protocol/native-network-v2.md), with the bytes when they were retained
/// whole. A truncated or refused body keeps its size and says why.
fn request_body(
    records: &[Value],
    start: &Hop,
    artifacts: &[Value],
    root: &Path,
) -> Option<(Value, Option<Value>)> {
    let record = records.iter().find(|child| {
        child["type"] == "request_body"
            && child["session_id"] == start.record["session_id"]
            && child["process_id"] == start.record["process_id"]
            && child["parent_event_id"] == start.record["sequence_number"]
    })?;
    let bytes = hex::decode(record["payload"].as_str()?).ok()?;
    if bytes.len() != 128 || u16::from_le_bytes([bytes[0], bytes[1]]) != 1 {
        return None;
    }
    let state = bytes[5];
    let type_length = (bytes[7] as usize).min(64);
    let length = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let mime = String::from_utf8_lossy(&bytes[64..64 + type_length]).into_owned();
    // State 1: no body object at all.
    if state == 1 {
        return Some((json!(0), None));
    }
    let mut data = json!({"mimeType": mime, "text": ""});
    let state_name = [
        "",
        "no_body",
        "empty",
        "metadata_only",
        "captured",
        "captured_truncated",
        "not_captured_body_kind",
        "not_captured_artifact_unavailable",
        "not_captured_transfer_refused",
        "not_captured_url",
        "not_captured_session_budget",
        "not_captured_credential_form",
    ]
    .get(state as usize)
    .copied()
    .unwrap_or("unknown");
    data["_reb_state"] = json!(state_name);
    if state == 4
        && let Some(artifact) = named(artifacts, record, "request_body")
        && let Ok(body) = evidence::content(
            root,
            artifact,
            artifact["byte_size"].as_u64().unwrap_or(0) as usize,
        )
    {
        match String::from_utf8(body) {
            Ok(text) => data["text"] = json!(text),
            Err(error) => {
                data["comment"] = json!("Binary body: its bytes are in _reb_base64.");
                data["_reb_base64"] =
                    json!(base64::engine::general_purpose::STANDARD.encode(error.into_bytes()));
            }
        }
    } else if state != 2 {
        data["comment"] = json!(format!("Body not retained whole: {state_name}."));
    }
    Some((json!(length), Some(data)))
}

/// The final response's retained body as HAR `content.text`, base64 when it
/// is not UTF-8. Only a body retained whole is written; a partial body's
/// case stays in `_reb.response_body`.
fn response_body(
    row: &Value,
    artifacts: &[Value],
    root: &Path,
) -> Option<(String, Option<&'static str>)> {
    let body = &row["response_body"];
    let id = body["artifact_id"].as_str()?;
    if body["body_length"] != body["captured_length"] {
        return None;
    }
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact["artifact_id"] == id && artifact["kind"] == "response_body")?;
    let bytes = evidence::content(
        root,
        artifact,
        artifact["byte_size"].as_u64().unwrap_or(0) as usize,
    )
    .ok()?;
    Some(match String::from_utf8(bytes) {
        Ok(text) => (text, None),
        Err(error) => (
            base64::engine::general_purpose::STANDARD.encode(error.into_bytes()),
            Some("base64"),
        ),
    })
}

/// HAR headers from one header block. A withheld credential value is an
/// empty value named as withheld, never a guess.
fn har_headers(block: Option<&Value>) -> Value {
    let Some(headers) = block.and_then(|block| block["headers"].as_array()) else {
        return json!([]);
    };
    Value::Array(
        headers
            .iter()
            .map(|header| {
                let mut out = Map::new();
                out.insert("name".into(), header["name"].clone());
                match header["value"].as_str() {
                    Some(value) => {
                        out.insert("value".into(), json!(value));
                    }
                    None => {
                        out.insert("value".into(), json!(""));
                        out.insert("_reb_withheld".into(), json!(true));
                        out.insert("_reb_value_bytes".into(), header["value_bytes"].clone());
                    }
                }
                Value::Object(out)
            })
            .collect(),
    )
}

/// Request `Cookie` pairs, or the name and value of each `Set-Cookie`.
fn cookies(headers: &Value, name: &str) -> Value {
    let mut out = Vec::new();
    for header in headers.as_array().into_iter().flatten() {
        if !header["name"]
            .as_str()
            .is_some_and(|header| header.eq_ignore_ascii_case(name))
            || header["_reb_withheld"] == true
        {
            continue;
        }
        let value = header["value"].as_str().unwrap_or("");
        let pairs: Vec<&str> = if name == "cookie" {
            value.split(';').collect()
        } else {
            value.split(';').take(1).collect()
        };
        for pair in pairs {
            if let Some((key, value)) = pair.trim().split_once('=') {
                out.push(json!({"name": key.trim(), "value": value.trim()}));
            }
        }
    }
    Value::Array(out)
}

fn query_string(url: &str) -> Value {
    match url::Url::parse(url) {
        Ok(url) => Value::Array(
            url.query_pairs()
                .map(|(name, value)| json!({"name": name, "value": value}))
                .collect(),
        ),
        Err(_) => json!([]),
    }
}

/// Why a hop's chosen header block is what it is: the source written, or the
/// reason no block was (`network_block_missing`).
fn block_state(chosen: Option<&Value>, hop: Option<&Value>, side: &str) -> Value {
    match chosen {
        Some(block) => json!({"source": block["source"], "state": block["state"]}),
        None => json!({"source": null,
        "missing": hop.map_or(Value::Null, |hop| if side == "request" {
            hop["network_block_missing"].clone()
        } else {
            Value::Null
        })}),
    }
}

fn sequence(event: &Value) -> u64 {
    number(&event["sequence_number"])
}

fn number(value: &Value) -> u64 {
    value
        .as_str()
        .and_then(|text| text.parse().ok())
        .or_else(|| value.as_u64())
        .unwrap_or(0)
}

fn milliseconds(ns: u64) -> f64 {
    ns as f64 / 1_000_000.0
}

/// `ns` after the Unix epoch as ISO 8601 with milliseconds, UTC.
pub fn iso_date(ns: u64) -> String {
    let millis = ns / 1_000_000;
    let (seconds, millis) = (millis / 1000, millis % 1000);
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The manifest records that `records` and the row's response body name,
/// each found by its ID in the artifact lookup index rather than by a scan of
/// the whole manifest.
pub fn artifacts_of(root: &Path, row: &Value, records: &[Value]) -> Result<Vec<Value>> {
    let mut ids: Vec<&str> = records
        .iter()
        .chain([&row["response_body"]])
        .filter_map(|record| record["artifact_id"].as_str())
        .filter(|id| *id != "0")
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut found = Vec::with_capacity(ids.len());
    for id in ids {
        match evidence::find_artifact(root, id) {
            Ok(artifact) => found.push(artifact),
            Err(error) if error.status == 404 => {}
            Err(error) => return Err(error),
        }
    }
    Ok(found)
}

/// The response body of a streamed export: chunks the export task writes.
pub struct Chunks(pub mpsc::Receiver<std::io::Result<Vec<u8>>>);
impl futures_core::Stream for Chunks {
    type Item = std::io::Result<Vec<u8>>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

/// Buffers the archive into chunks. A send fails once the client has gone,
/// which ends the export.
pub struct Sink {
    sender: mpsc::Sender<std::io::Result<Vec<u8>>>,
    buffer: Vec<u8>,
}
impl Sink {
    pub fn new(sender: mpsc::Sender<std::io::Result<Vec<u8>>>) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(CHUNK),
        }
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> bool {
        self.buffer.extend_from_slice(bytes);
        self.buffer.len() < CHUNK || self.flush()
    }
    pub(crate) fn flush(&mut self) -> bool {
        if self.buffer.is_empty() {
            return true;
        }
        let chunk = std::mem::replace(&mut self.buffer, Vec::with_capacity(CHUNK));
        self.sender.blocking_send(Ok(chunk)).is_ok()
    }
}

/// What one export reads: the index, the stores and the credential mode.
pub struct Export<'a> {
    pub requests: &'a tokio::sync::Mutex<RequestIndex>,
    pub gaps: &'a GapTally,
    pub store: &'a Path,
    pub artifacts: &'a Path,
    pub credentials: Credentials,
}

/// Writes the whole archive of `rows`, in their order, with one row's records
/// in memory at a time. The archive is valid JSON however it ends: a failure
/// after the first byte closes it with `_reb.complete` false and the error,
/// since the status line has already been sent.
pub fn export(sink: &mut Sink, rows: &[i64], index: Value, export: &Export) {
    let header = json!({"name": "Origin Trace", "version": env!("CARGO_PKG_VERSION")});
    let opening = format!(
        "{{\"log\":{{\"version\":\"1.2\",\"creator\":{header},\"comment\":{},\"pages\":[],\"entries\":[",
        json!(CLOCK_COMMENT)
    );
    if !sink.write(opening.as_bytes()) {
        return;
    }
    let mut written = 0u64;
    let mut outcomes: HashMap<&'static str, u64> = HashMap::new();
    let result = (|| -> Result<bool> {
        let mut drops: HashMap<String, Drops> = HashMap::new();
        for batch in rows.chunks(BATCH) {
            let documents = export.requests.blocking_lock().export_documents(batch)?;
            for row in &documents {
                for entry in row_entries(row, &mut drops, export)? {
                    let outcome = match entry["_reb"]["outcome"].as_str() {
                        Some("redirect") => "redirect",
                        Some("failed") => "failed",
                        Some("incomplete") => "incomplete",
                        Some("pending") => "pending",
                        Some("unlinked") => "unlinked",
                        _ => "complete",
                    };
                    *outcomes.entry(outcome).or_default() += 1;
                    let separator: &[u8] = if written == 0 { b"" } else { b"," };
                    let bytes = serde_json::to_vec(&entry).expect("A HAR entry serializes");
                    written += 1;
                    if !sink.write(separator) || !sink.write(&bytes) {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    })();
    let (complete, error) = match result {
        Ok(false) => return,
        Ok(true) => (true, Value::Null),
        Err(error) => (false, json!(error.message)),
    };
    let closing = json!({
        "format": FORMAT, "complete": complete, "error": error, "rows": rows.len(),
        "entries": written, "outcomes": outcomes, "index": index,
        "credential_values": export.credentials.name(),
    });
    if sink.write(format!("],\"_reb\":{closing}}}}}").as_bytes()) {
        sink.flush();
    }
}

/// One row's entries from every record of its root request.
fn row_entries(
    row: &Value,
    drops: &mut HashMap<String, Drops>,
    export: &Export,
) -> Result<Vec<Value>> {
    let Some((session, _, request)) = root_of(row) else {
        return Ok(entries(
            row,
            &[],
            &Drops::default(),
            &[],
            export.artifacts,
            export.credentials,
        ));
    };
    let offset = |key: &str| {
        row[key]
            .as_str()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| Error::new(500, "A request row has no byte range"))
    };
    let range = RecordRange {
        first: offset("first_offset")?,
        end: offset("end_offset")?,
        indexed: true,
    };
    let ids = |text: &str| {
        text.parse::<u64>()
            .map_err(|_| Error::new(500, "A request row has a malformed root"))
    };
    let filter = EventFilter::exact(
        &[],
        vec![
            ("session_id", ids(&session)?),
            ("request_id", ids(&request)?),
        ],
    );
    let records = event_query::read_request_range(export.store, range, &filter)?.records;
    if !drops.contains_key(&session) {
        let tally = export.gaps.drops(export.store, &session)?;
        drops.insert(session.clone(), tally);
    }
    let artifacts = artifacts_of(export.artifacts, row, &records)?;
    Ok(entries(
        row,
        &records,
        &drops[&session],
        &artifacts,
        export.artifacts,
        export.credentials,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_time_is_an_epoch_offset() {
        assert_eq!(iso_date(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_date(1_500_123_456_789), "1970-01-01T00:25:00.123Z");
        // 2000-03-01, past a century leap rule.
        assert_eq!(
            iso_date(951_868_800_000_000_000),
            "2000-03-01T00:00:00.000Z"
        );
    }
}
