//! Cross-references for one selection: the evidence that points at it and the
//! evidence it points at. This is a projection over links the stores already
//! hold (parent events, request initiators and lifecycle, host links, artifact
//! creators, Wasm import/export uses and retained dispatch samples). A link
//! that was not recorded is a gap row, never an inferred caller.
//!
//! The event store is read forward once for each new selection, with a regular
//! expression over raw bytes so only candidate records are parsed. Rows outside
//! the requested window are counted and dropped, so a selection with a million
//! links costs the same memory as one with ten. The only state kept between
//! requests is one small cursor entry for the current selection, so scrolling
//! seeks close to a page instead of rereading the whole store.
use crate::{
    app::Query,
    error::{Error, Result},
    event_window, evidence,
    store_scan::{Reader, Stopped, Stores, complete_end, field_pattern, same_session},
    vm_opcode, wasm,
};
use regex::bytes::Regex;
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};
use wasmparser::{ExternalKind, Operator, Parser, Payload, TypeRef};

pub const DEFAULT_LIMIT: usize = 128;
pub const MAX_LIMIT: usize = 512;
/// One cursor per this many matching rows and direction. A hundred million
/// links stay under a megabyte of anchors.
const ANCHOR_EVERY: u64 = 2048;
/// A pathological store is reported as a visible cut rather than an endless
/// request. Reaching this is rare: the byte prefilter reads gigabytes in it.
const SCAN_DEADLINE: Duration = Duration::from_secs(30);
const FILTER_BYTES: usize = 256;
const NAME_CHARS: usize = 256;
const QUERY_KEYS: [&str; 14] = [
    "kind",
    "session_id",
    "process_id",
    "sequence_number",
    "request_id",
    "artifact_id",
    "sha256",
    "byte_offset",
    "byte_size",
    "instruction_pointer",
    "direction",
    "offset",
    "filter",
    "snapshot",
];
const HOST_CATEGORIES: [&str; 9] = [
    "canvas",
    "webgl",
    "web_audio",
    "navigator",
    "permissions",
    "storage",
    "webrtc",
    "network",
    "runtime",
];
const FINGERPRINT_CATEGORIES: [&str; 8] = [
    "canvas",
    "webgl",
    "web_audio",
    "navigator",
    "permissions",
    "storage",
    "webrtc",
    "runtime",
];
const HOST_TYPES: [&str; 9] = [
    "api_call",
    "property_read",
    "request_started",
    "request_initiated",
    "request_redirected",
    "response_started",
    "response_completed",
    "request_completed",
    "request_failed",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Direction {
    In,
    Out,
}
impl Direction {
    const ALL: [Self; 2] = [Self::In, Self::Out];
    fn key(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }
    fn index(self) -> usize {
        match self {
            Self::In => 0,
            Self::Out => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Selection {
    Request {
        session: u64,
        process: u64,
        sequence: u64,
        request: u64,
    },
    Api {
        session: u64,
        process: u64,
        sequence: u64,
    },
    Artifact {
        session: u64,
        artifact: u64,
        byte_offset: Option<u32>,
    },
    VmHandler {
        session: u64,
        artifact: u64,
        sha256: String,
        byte_offset: u32,
        byte_size: u32,
        instruction_pointer: Option<u64>,
    },
}

/// One parsed `/api/xrefs` request.
pub struct XrefQuery {
    selection: Selection,
    directions: Vec<Direction>,
    offset: u64,
    limit: usize,
    filter: String,
    snapshot: Option<u64>,
}

fn required(q: &Query, key: &str, bits: u32) -> Result<u64> {
    q.number(key, None, bits, true)
}

fn small(value: u64, key: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::bad(format!("{key} is out of range")))
}

impl XrefQuery {
    pub fn parse(q: &Query) -> Result<Self> {
        q.only(&QUERY_KEYS, &["limit"])?;
        let session = required(q, "session_id", 64)?;
        let selection = match q.one("kind")?.unwrap_or("") {
            "request" => Selection::Request {
                session,
                process: required(q, "process_id", 32)?,
                sequence: required(q, "sequence_number", 64)?,
                request: required(q, "request_id", 64)?,
            },
            "api" => Selection::Api {
                session,
                process: required(q, "process_id", 32)?,
                sequence: required(q, "sequence_number", 64)?,
            },
            "artifact" => Selection::Artifact {
                session,
                artifact: required(q, "artifact_id", 64)?,
                byte_offset: q
                    .one("byte_offset")?
                    .map(|_| small(q.number("byte_offset", None, 32, false)?, "byte_offset"))
                    .transpose()?,
            },
            "vm_handler" => {
                let sha256 = q
                    .one("sha256")?
                    .filter(|value| {
                        value.len() == 64
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                    .ok_or_else(|| Error::bad("sha256 must be 64 lowercase hex digits"))?
                    .to_owned();
                Selection::VmHandler {
                    session,
                    artifact: required(q, "artifact_id", 64)?,
                    sha256,
                    byte_offset: small(q.number("byte_offset", None, 32, false)?, "byte_offset")?,
                    byte_size: small(q.number("byte_size", None, 32, false)?, "byte_size")?,
                    instruction_pointer: q
                        .one("instruction_pointer")?
                        .map(|_| q.number("instruction_pointer", None, 64, false))
                        .transpose()?,
                }
            }
            "" => return Err(Error::bad("kind is required")),
            _ => {
                return Err(Error::bad(
                    "kind must be request, api, artifact or vm_handler",
                ));
            }
        };
        let directions = match q.one("direction")?.unwrap_or("both") {
            "both" => Direction::ALL.to_vec(),
            "in" => vec![Direction::In],
            "out" => vec![Direction::Out],
            _ => return Err(Error::bad("direction must be in, out or both")),
        };
        let filter = q.one("filter")?.unwrap_or("").trim();
        if filter.len() > FILTER_BYTES {
            return Err(Error::bad(format!(
                "filter must be at most {FILTER_BYTES} bytes"
            )));
        }
        Ok(Self {
            selection,
            directions,
            offset: q.number("offset", Some("0"), 64, false)?,
            limit: q.limit(DEFAULT_LIMIT, MAX_LIMIT)?,
            filter: filter.to_lowercase(),
            snapshot: q
                .one("snapshot")?
                .map(|_| q.number("snapshot", None, 64, false))
                .transpose()?,
        })
    }

    /// The retained workspace row that a VM handler selection must resolve
    /// against before the blocking scan. The workspace lives behind the
    /// analysis cache lock, which the scan does not hold.
    pub fn vm_target(&self) -> Option<(String, String, u32, u32)> {
        match &self.selection {
            Selection::VmHandler {
                artifact,
                sha256,
                byte_offset,
                byte_size,
                ..
            } => Some((
                artifact.to_string(),
                sha256.clone(),
                *byte_offset,
                *byte_size,
            )),
            _ => None,
        }
    }

    fn cache_key(&self) -> String {
        format!("{:?}\u{0}{}", self.selection, self.filter)
    }
}

/// The retained handler row and its samples, extracted under the analysis lock.
#[derive(Default, Clone)]
pub struct VmHandlerInput {
    not_ready: bool,
    found: bool,
    label: Option<String>,
    samples: Vec<Value>,
    sample_count: u64,
    omissions: Vec<String>,
}

impl VmHandlerInput {
    pub fn not_ready() -> Self {
        Self {
            not_ready: true,
            ..Self::default()
        }
    }
}

/// Copies only what a handler selection needs out of the opcode workspace, so
/// the caller never clones the whole document.
pub fn vm_handler_input(
    workspace: &Value,
    artifact: &str,
    sha256: &str,
    byte_offset: u32,
    byte_size: u32,
) -> VmHandlerInput {
    let Some(row) = workspace["workspaces"].as_array().and_then(|rows| {
        rows.iter().find(|row| {
            row["interpreter_artifact_id"] == artifact && row["source_artifact_sha256"] == sha256
        })
    }) else {
        return VmHandlerInput::default();
    };
    let handlers = row["handlers"].as_array().map_or(&[][..], Vec::as_slice);
    let matching = handlers
        .iter()
        .filter(|handler| {
            handler["source"]["byte_offset"] == byte_offset
                && handler["source"]["byte_size"] == byte_size
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return VmHandlerInput::default();
    }
    let samples_for = |key: &str| row[key].as_array().map_or(&[][..], Vec::as_slice);
    let opcodes = matching
        .iter()
        .map(|handler| handler["opcode"].clone())
        .filter(|opcode| !opcode.is_null())
        .collect::<Vec<_>>();
    let mut samples = samples_for("samples")
        .iter()
        .filter(|sample| opcodes.contains(&sample["opcode"]))
        .cloned()
        .collect::<Vec<_>>();
    for key in ["native_guest_samples", "native_wasm_observations"] {
        samples.extend(
            samples_for(key)
                .iter()
                .filter(|sample| {
                    matching
                        .iter()
                        .any(|handler| native_row_matches(sample, handler))
                })
                .cloned(),
        );
    }
    let mut omissions = Vec::new();
    if row["sample_count"].as_u64().unwrap_or(0) > samples_for("samples").len() as u64 {
        omissions.push("dispatch-sample-retention-limit".to_owned());
    }
    let label = matching[0]["label"].as_str().map(str::to_owned);
    VmHandlerInput {
        not_ready: false,
        found: true,
        label,
        sample_count: row["sample_count"].as_u64().unwrap_or(samples.len() as u64),
        samples,
        omissions,
    }
}

fn native_row_matches(row: &Value, handler: &Value) -> bool {
    if row["module_byte_offset"] != handler["source"]["byte_offset"] {
        return false;
    }
    if row["is_default"] == true {
        return handler["opcode"].is_null()
            && handler["label"]
                .as_str()
                .is_some_and(|label| label.starts_with("br_table") && label.ends_with("default"));
    }
    handler["opcode"] == row["selector"]
}

#[derive(Clone)]
struct ArtifactRef {
    name: String,
    sha256: String,
    byte_size: u64,
    kind: String,
}

fn artifact_ref(record: &Value) -> ArtifactRef {
    let url = record["url"].as_str().unwrap_or("");
    let path = url.split(['?', '#']).next().unwrap_or("");
    let tail = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let kind = record["kind"].as_str().unwrap_or("artifact").to_owned();
    let name = if tail.is_empty() || tail.contains(':') {
        format!("{kind} {}", record["artifact_id"].as_str().unwrap_or("?"))
    } else {
        truncated(tail)
    };
    ArtifactRef {
        name,
        sha256: record["sha256"].as_str().unwrap_or("").to_owned(),
        byte_size: record["byte_size"].as_u64().unwrap_or(0),
        kind,
    }
}

fn truncated(text: &str) -> String {
    if text.chars().count() <= NAME_CHARS {
        return text.to_owned();
    }
    text.chars().take(NAME_CHARS).collect()
}

fn text_id(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => "0".to_owned(),
    }
}

fn unsigned(value: &Value) -> u64 {
    event_window::unsigned(value).unwrap_or(0)
}

/// The captured operation text of a marker event, or the event type.
fn operation(event: &Value) -> String {
    if event["payload_encoding"] == "hex"
        && matches!(event["type"].as_str(), Some("api_call" | "property_read"))
        && let Some(text) = event["payload"]
            .as_str()
            .and_then(|hex_text| hex::decode(hex_text).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|text| !text.trim().is_empty())
    {
        return truncated(&text);
    }
    event["type"].as_str().unwrap_or("event").to_owned()
}

fn pretty(kind: &str) -> String {
    kind.replace('_', " ")
}

/// One row before it is known to be inside the requested window. Identifiers
/// are copied out only for rows that are actually returned.
struct Row<'a> {
    kind: &'static str,
    name: String,
    detail: String,
    source: String,
    operation: String,
    state: &'static str,
    target: Target<'a>,
    /// The Wasm function this row names, in the module's full index space.
    function: Option<u32>,
}

enum Target<'a> {
    Event(&'a Value),
    Artifact {
        session: &'a str,
        id: &'a str,
        info: &'a ArtifactRef,
        byte_offset: Option<u32>,
    },
    Sample(&'a Value, Option<&'a Value>),
}

impl Row<'_> {
    fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        [
            self.name.as_str(),
            self.detail.as_str(),
            self.kind,
            self.source.as_str(),
            self.operation.as_str(),
        ]
        .iter()
        .any(|field| field.to_lowercase().contains(needle))
    }

    fn json(&self, direction: Direction) -> Value {
        let (evidence, ids, time) = match &self.target {
            Target::Event(event) => event_identity(event),
            Target::Artifact {
                session,
                id,
                info,
                byte_offset,
            } => {
                let mut evidence = json!({"type":"artifact","session_id":session,"artifact_id":id,
                    "sha256":info.sha256,"byte_size":info.byte_size,"kind":info.kind});
                if let Some(offset) = byte_offset {
                    evidence["byte_offset"] = json!(offset);
                }
                (
                    evidence,
                    json!({"session_id":session,"artifact_id":id}),
                    Value::Null,
                )
            }
            Target::Sample(reference, time) => {
                let ids = json!({"session_id":reference["session_id"],
                    "process_id":reference["process_id"],
                    "sequence_number":reference["sequence_number"]});
                let mut evidence = ids.clone();
                evidence["type"] = json!("event");
                (evidence, ids, time.cloned().unwrap_or(Value::Null))
            }
        };
        let mut row = json!({
            "direction": direction.key(),
            "kind": self.kind,
            "name": self.name,
            "detail": self.detail,
            "source": self.source,
            "operation": self.operation,
            "state": self.state,
            "evidence": evidence,
            "ids": ids,
            "time_ns": time,
        });
        if let Some(function) = self.function {
            row["function_index"] = json!(function);
        }
        row
    }
}

fn event_identity(event: &Value) -> (Value, Value, Value) {
    let ids = json!({
        "session_id": event["session_id"],
        "process_id": event["process_id"],
        "sequence_number": event["sequence_number"],
        "navigation_id": event["navigation_id"],
        "frame_id": event["frame_id"],
        "artifact_id": event["artifact_id"],
        "request_id": event["request_id"],
        "parent_event_id": event["parent_event_id"],
    });
    let evidence = json!({
        "type": "event",
        "session_id": event["session_id"],
        "process_id": event["process_id"],
        "sequence_number": event["sequence_number"],
        "category": event["category"],
        "event_type": event["type"],
        "request_id": event["request_id"],
    });
    (evidence, ids, event["monotonic_time_ns"].clone())
}

fn event_row<'a>(kind: &'static str, name: String, detail: String, event: &'a Value) -> Row<'a> {
    Row {
        kind,
        name,
        detail,
        source: event["category"].as_str().unwrap_or("event").to_owned(),
        operation: event["type"].as_str().unwrap_or("event").to_owned(),
        state: "observed",
        target: Target::Event(event),
        function: None,
    }
}

fn gap(reason: &str, name: &str, detail: String) -> Value {
    json!({"reason":reason,"name":name,"detail":detail})
}

fn compile(alternatives: &[String]) -> Result<Regex> {
    Regex::new(&alternatives.join("|"))
        .map_err(|_| Error::new(500, "Cross-reference filter failed"))
}

fn parse_event(record: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(record)
        .ok()
        .filter(Value::is_object)
}

/// Finds an event by exact identity. `process` of `None` matches any stream,
/// which only the artifact creator lookup uses when no capture event exists.
fn find_events(
    reader: &Reader<'_>,
    store: &Path,
    end: u64,
    session: u64,
    process: Option<u64>,
    sequence: u64,
) -> Result<Vec<Value>> {
    let needle = compile(&[field_pattern("sequence_number", sequence)])?;
    let mut found = Vec::new();
    reader.lines(store, 0, end, Some(&needle), &mut |_, record| {
        let event = parse_event(record)?;
        if same_session(&event, session)
            && unsigned(&event["sequence_number"]) == sequence
            && process.is_none_or(|process| unsigned(&event["process_id"]) == process)
            && event["type"] != "gap"
        {
            found.push(event);
        }
        Some(found.len() < 2)
    })?;
    Ok(found)
}

struct WasmModule {
    names: HashMap<u32, String>,
    imported: u32,
    target: Option<u32>,
    target_is_import: bool,
}

/// Names and target of a retained module. A malformed module is a coverage
/// note for the caller, never a panic.
fn inspect_module(bytes: &[u8], byte_offset: Option<u32>) -> Option<WasmModule> {
    let mut names = HashMap::new();
    let mut imported = 0u32;
    let mut defined = 0u32;
    let mut target = None;
    let mut target_is_import = false;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.ok()? {
            Payload::ImportSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    let (offset, import) = entry.ok()?;
                    if matches!(import.ty, TypeRef::Func(_)) {
                        names.insert(imported, format!("{}.{}", import.module, import.name));
                        if byte_offset == Some(offset as u32) {
                            target = Some(imported);
                            target_is_import = true;
                        }
                        imported += 1;
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    let (offset, export) = entry.ok()?;
                    if export.kind == ExternalKind::Func {
                        names
                            .entry(export.index)
                            .or_insert_with(|| export.name.to_owned());
                        if byte_offset == Some(offset as u32) {
                            target = Some(export.index);
                            target_is_import = export.index < imported;
                        }
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index = imported.checked_add(defined)?;
                defined += 1;
                let range = body.range();
                if byte_offset.is_some_and(|offset| {
                    (offset as usize) >= range.start && (offset as usize) < range.end
                }) {
                    target = Some(index);
                }
            }
            _ => {}
        }
    }
    Some(WasmModule {
        names,
        imported,
        target,
        target_is_import,
    })
}

impl WasmModule {
    fn function_name(&self, index: u32) -> String {
        self.names
            .get(&index)
            .cloned()
            .unwrap_or_else(|| format!("func {index}"))
    }
}

/// The state a page needs beyond the window: everything built once per selection.
/// One value exists per selection, behind an `Arc`, so variant size is irrelevant.
#[allow(clippy::large_enum_variant)]
enum Plan {
    Unresolved {
        selection: Value,
    },
    Request {
        selection: Value,
        prefilter: Regex,
        root: Value,
        session: u64,
    },
    Api {
        selection: Value,
        prefilter: Regex,
        root: Value,
        session: u64,
        category: String,
        event_type: String,
        payload: Value,
        script_names: HashMap<String, String>,
    },
    Artifact {
        selection: Value,
        prefilter: Regex,
        session: u64,
        session_text: String,
        artifact: u64,
        artifact_text: String,
        info: ArtifactRef,
        creator: Option<Value>,
        capture: Option<Value>,
        creator_id: u64,
        parent: Option<(String, ArtifactRef)>,
        children: Vec<(String, ArtifactRef)>,
        wasm: Option<WasmModule>,
        wasm_note: Option<String>,
        /// The manifest row, to reread module bytes for the static rows of a
        /// page. The bytes are not kept between requests.
        record: Value,
    },
    VmHandler {
        selection: Value,
        prefilter: Regex,
        session: u64,
        samples: Vec<Value>,
        parents: HashSet<(u64, u64)>,
        sample_count: u64,
        omissions: Vec<String>,
    },
}

impl Plan {
    fn selection(&self) -> &Value {
        match self {
            Self::Unresolved { selection }
            | Self::Request { selection, .. }
            | Self::Api { selection, .. }
            | Self::Artifact { selection, .. }
            | Self::VmHandler { selection, .. } => selection,
        }
    }
}

fn unresolved(kind: &str, reason: &str, detail: &str) -> Plan {
    Plan::Unresolved {
        selection: json!({"kind":kind,"status":"unavailable","label":null,"reason":reason,"detail":detail}),
    }
}

fn resolved(kind: &str, label: Option<String>) -> Value {
    json!({"kind":kind,"status":"resolved","label":label})
}

fn artifact_index(root: &Path, session: u64) -> (HashMap<String, Value>, Option<String>) {
    match evidence::artifacts(root, 10000) {
        Ok(records) => (
            records
                .into_iter()
                .filter(|record| same_session(record, session))
                .map(|record| (text_id(&record["artifact_id"]), record))
                .collect(),
            None,
        ),
        Err(_) => (
            HashMap::new(),
            Some("The artifact manifest could not be read.".to_owned()),
        ),
    }
}

fn build_plan(
    query: &XrefQuery,
    stores: &Stores,
    reader: &Reader<'_>,
    end: u64,
    handler: Option<VmHandlerInput>,
) -> Result<Plan> {
    let store = &stores.events;
    Ok(match &query.selection {
        Selection::Request {
            session,
            process,
            sequence,
            request,
        } => {
            let found = find_events(reader, store, end, *session, Some(*process), *sequence)?;
            match found.as_slice() {
                [] => unresolved(
                    "request",
                    "not-retained",
                    "This exact request is no longer retained in the event store.",
                ),
                [root]
                    if root["category"] == "network"
                        && unsigned(&root["request_id"]) == *request =>
                {
                    // A captured response names only its parent lifecycle event,
                    // so every capture is a candidate.
                    let mut patterns = vec![
                        field_pattern("request_id", request),
                        field_pattern("parent_event_id", sequence),
                        r#""type":"artifact_captured""#.to_owned(),
                    ];
                    let initiator = unsigned(&root["initiator_request_id"]);
                    if unsigned(&root["initiator_process_id"]) != 0 && initiator != 0 {
                        patterns.push(field_pattern("request_id", initiator));
                    }
                    let parent = unsigned(&root["parent_event_id"]);
                    if parent != 0 {
                        patterns.push(field_pattern("sequence_number", parent));
                    }
                    Plan::Request {
                        selection: resolved("request", None),
                        prefilter: compile(&patterns)?,
                        root: root.clone(),
                        session: *session,
                    }
                }
                [_] => unresolved(
                    "request",
                    "identity-mismatch",
                    "The retained event at this identity is not this network request.",
                ),
                _ => unresolved(
                    "request",
                    "ambiguous",
                    "More than one retained event has this identity. Choose the evidence explicitly.",
                ),
            }
        }
        Selection::Api {
            session,
            process,
            sequence,
        } => {
            let found = find_events(reader, store, end, *session, Some(*process), *sequence)?;
            match found.as_slice() {
                [] => unresolved(
                    "api",
                    "not-retained",
                    "This exact event is no longer retained in the event store.",
                ),
                [root]
                    if FINGERPRINT_CATEGORIES
                        .contains(&root["category"].as_str().unwrap_or(""))
                        && matches!(root["type"].as_str(), Some("api_call" | "property_read")) =>
                {
                    let payload = root["payload"].clone();
                    let mut patterns = vec![
                        format!(
                            r#""payload":"{}""#,
                            regex::escape(payload.as_str().unwrap_or(""))
                        ),
                        field_pattern("parent_event_id", sequence),
                    ];
                    let parent = unsigned(&root["parent_event_id"]);
                    if parent != 0 {
                        patterns.push(field_pattern("sequence_number", parent));
                    }
                    Plan::Api {
                        selection: resolved("api", Some(operation(root))),
                        prefilter: compile(&patterns)?,
                        root: root.clone(),
                        session: *session,
                        category: root["category"].as_str().unwrap_or("").to_owned(),
                        event_type: root["type"].as_str().unwrap_or("").to_owned(),
                        payload,
                        script_names: artifact_index(&stores.artifacts, *session)
                            .0
                            .iter()
                            .map(|(id, record)| (id.clone(), artifact_ref(record).name))
                            .collect(),
                    }
                }
                [_] => unresolved(
                    "api",
                    "unsupported-event",
                    "The selected event is not a fingerprint API call or property read.",
                ),
                _ => unresolved(
                    "api",
                    "ambiguous",
                    "More than one retained event has this identity. Choose the evidence explicitly.",
                ),
            }
        }
        Selection::Artifact {
            session,
            artifact,
            byte_offset,
        } => artifact_plan(stores, reader, end, *session, *artifact, *byte_offset)?,
        Selection::VmHandler {
            session,
            instruction_pointer,
            ..
        } => vm_plan(handler.unwrap_or_default(), *session, *instruction_pointer)?,
    })
}

fn artifact_plan(
    stores: &Stores,
    reader: &Reader<'_>,
    end: u64,
    session: u64,
    artifact: u64,
    byte_offset: Option<u32>,
) -> Result<Plan> {
    let (index, _) = artifact_index(&stores.artifacts, session);
    let Some(record) = index.get(&artifact.to_string()) else {
        return Ok(unresolved(
            "artifact",
            "not-retained",
            "This exact artifact is not in the retained manifest for this session.",
        ));
    };
    let info = artifact_ref(record);
    let creator_id = unsigned(&record["creator_event_id"]);
    let parent_id = text_id(&record["parent_artifact_id"]);
    let parent = (parent_id != "0")
        .then(|| {
            index
                .get(&parent_id)
                .map(|parent| (parent_id.clone(), artifact_ref(parent)))
        })
        .flatten();
    let artifact_text = artifact.to_string();
    let mut children: Vec<_> = index
        .iter()
        .filter(|(_, candidate)| text_id(&candidate["parent_artifact_id"]) == artifact_text)
        .map(|(id, candidate)| (id.clone(), artifact_ref(candidate)))
        .collect();
    children.sort_by(|(a, _), (b, _)| {
        a.parse::<u64>()
            .unwrap_or(0)
            .cmp(&b.parse::<u64>().unwrap_or(0))
    });
    let mut capture = None;
    let capture_needle = compile(&[r#""type":"artifact_captured""#.to_owned()])?;
    reader.lines(
        &stores.events,
        0,
        end,
        Some(&capture_needle),
        &mut |_, record| {
            let event = parse_event(record)?;
            if same_session(&event, session) && unsigned(&event["artifact_id"]) == artifact {
                capture = Some(event);
                return Some(false);
            }
            Some(true)
        },
    )?;
    let creator = if creator_id == 0 {
        None
    } else if let Some(capture) = &capture {
        find_events(
            reader,
            &stores.events,
            end,
            session,
            Some(unsigned(&capture["process_id"])),
            creator_id,
        )?
        .into_iter()
        .next()
    } else {
        let found = find_events(reader, &stores.events, end, session, None, creator_id)?;
        if found.len() == 1 {
            found.into_iter().next()
        } else {
            None
        }
    };
    let (wasm, wasm_note) = if info.kind == "wasm" {
        match evidence::content(&stores.artifacts, record, wasm::MAX_BYTES) {
            Ok(bytes) => match inspect_module(&bytes, byte_offset) {
                Some(module) => (Some(module), None),
                None => (
                    None,
                    Some("The retained module bytes could not be parsed.".to_owned()),
                ),
            },
            Err(_) => (
                None,
                Some(
                    "The retained module bytes are unavailable or over the inspection limit."
                        .to_owned(),
                ),
            ),
        }
    } else {
        (None, None)
    };
    let label = wasm
        .as_ref()
        .and_then(|module| module.target.map(|target| module.function_name(target)))
        .or_else(|| Some(info.name.clone()));
    let mut patterns = vec![field_pattern("artifact_id", artifact)];
    if wasm.as_ref().is_some_and(|module| module.target.is_some()) {
        patterns.push(r#""parent_event_id":"?[1-9]"#.to_owned());
        patterns.push(r#""type":"gap""#.to_owned());
    }
    let mut selection = resolved("artifact", label);
    // The module digest and selected function are the researcher-name key.
    if wasm.is_some() {
        selection["wasm_sha256"] = json!(info.sha256);
        if let Some(target) = wasm.as_ref().and_then(|module| module.target) {
            selection["function_index"] = json!(target);
        }
    }
    Ok(Plan::Artifact {
        selection,
        prefilter: compile(&patterns)?,
        session,
        session_text: session.to_string(),
        artifact,
        artifact_text,
        info,
        creator,
        capture,
        creator_id,
        parent,
        children,
        wasm,
        wasm_note,
        record: record.clone(),
    })
}

fn vm_plan(input: VmHandlerInput, session: u64, pc: Option<u64>) -> Result<Plan> {
    if input.not_ready {
        return Ok(unresolved(
            "vm_handler",
            "analysis-not-ready",
            "No VM analysis is loaded yet. Open VM to analyze this capture.",
        ));
    }
    if !input.found {
        return Ok(unresolved(
            "vm_handler",
            "not-retained",
            "This handler is not in the current VM analysis.",
        ));
    }
    let samples: Vec<_> = input
        .samples
        .into_iter()
        .filter(|sample| {
            same_session(&sample["event"], session)
                && pc.is_none_or(|pc| sample["instruction_pointer"].as_u64() == Some(pc))
        })
        .collect();
    let parents = samples
        .iter()
        .map(|sample| {
            (
                unsigned(&sample["event"]["process_id"]),
                unsigned(&sample["event"]["sequence_number"]),
            )
        })
        .collect();
    Ok(Plan::VmHandler {
        selection: resolved("vm_handler", input.label),
        prefilter: compile(&[r#""parent_event_id":"?[1-9]"#.to_owned()])?,
        session,
        samples,
        parents,
        sample_count: input.sample_count,
        omissions: input.omissions,
    })
}

fn host_event(event: &Value) -> bool {
    HOST_CATEGORIES.contains(&event["category"].as_str().unwrap_or(""))
        && HOST_TYPES.contains(&event["type"].as_str().unwrap_or(""))
}

fn dispatch_sample(event: &Value) -> bool {
    matches!(
        event["type"].as_str(),
        Some("wasm_dispatch_observation" | "wasm_indirect_observation" | "wasm_guest_dispatch")
    )
}

struct Sink {
    offset: u64,
    limit: usize,
    total: u64,
    matching: u64,
    rows: Vec<Value>,
    wanted: bool,
    last_anchor: u64,
}

impl Sink {
    fn new(wanted: bool, offset: u64, limit: usize) -> Self {
        Self {
            offset,
            limit,
            total: 0,
            matching: 0,
            rows: Vec::new(),
            wanted,
            last_anchor: 0,
        }
    }
    fn push(&mut self, row: &Row<'_>, direction: Direction, needle: &str) {
        self.total += 1;
        if !row.matches(needle) {
            return;
        }
        if self.wanted && self.matching >= self.offset && self.rows.len() < self.limit {
            self.rows.push(row.json(direction));
        }
        self.matching += 1;
    }
    fn full(&self) -> bool {
        self.wanted && self.rows.len() >= self.limit
    }
}

#[derive(Clone, Copy, Default)]
struct Anchor {
    position: u64,
    total: u64,
    matching: u64,
}

/// Counters of the first full pass, kept with the cursors.
#[derive(Default)]
struct PassFacts {
    saw_samples: bool,
    saw_gap_reasons: BTreeSet<String>,
    initiator_found: bool,
    /// A memory-cache reuse's named source request was found.
    source_found: bool,
    /// Why a request of the named ID is not the reuse's load, as the request
    /// index's `memory_cache_source.reason` says.
    source_mismatch: Option<&'static str>,
    parent_found: bool,
    link_parents: HashSet<(u64, u64)>,
    scanned_end: u64,
    stopped_deadline: bool,
    malformed: u64,
}

/// Emits one event's rows. A resumed page sees an already complete
/// `link_parents`; the first pass builds it, because a parent record always
/// precedes its children in the append-only store.
fn classify_event(
    plan: &Plan,
    event: &mut Value,
    facts: &mut PassFacts,
    sinks: &mut [Sink; 2],
    needle: &str,
) {
    let emit = |sinks: &mut [Sink; 2], direction: Direction, row: Row<'_>| {
        sinks[direction.index()].push(&row, direction, needle);
    };
    match plan {
        Plan::Unresolved { .. } => {}
        Plan::Request { root, session, .. } => {
            if !same_session(event, *session) || event["type"] == "gap" {
                return;
            }
            let root_process = unsigned(&root["process_id"]);
            let root_sequence = unsigned(&root["sequence_number"]);
            let process = unsigned(&event["process_id"]);
            let sequence = unsigned(&event["sequence_number"]);
            if process == root_process && sequence == root_sequence {
                return;
            }
            let label = pretty(event["type"].as_str().unwrap_or("event"));
            let parent = unsigned(&root["parent_event_id"]);
            if process == root_process && sequence == parent {
                facts.parent_found = true;
                let (kind, name) = if dispatch_sample(event) {
                    ("host_link", format!("Dispatch sample {sequence}"))
                } else {
                    ("parent_event", label.clone())
                };
                let detail = format!(
                    "recorded parent · {} · {}",
                    event["category"].as_str().unwrap_or(""),
                    event["type"].as_str().unwrap_or("")
                );
                emit(sinks, Direction::In, event_row(kind, name, detail, event));
                return;
            }
            let initiator_process = unsigned(&root["initiator_process_id"]);
            let initiator_request = unsigned(&root["initiator_request_id"]);
            if initiator_process != 0
                && process == initiator_process
                && unsigned(&event["request_id"]) == initiator_request
                && event["type"] == "request_initiated"
            {
                // A version 2 memory_cache_reuse names, in those fields, the
                // request whose response Blink reused, not an initiator
                // (protocol/native-network-v3.md).
                if root["type"] == "memory_cache_reuse" {
                    // A renderer request ID names a request only within its
                    // process, which can be reused within the session: the
                    // source must have the reuse's host and have started first.
                    let source_host = hex::decode(event["payload"].as_str().unwrap_or(""))
                        .ok()
                        .and_then(|bytes| {
                            crate::request_index::network_target(
                                &crate::request_index::payload_text(&bytes),
                                "request_initiated",
                            )
                        })
                        .map(|(_, host)| host)
                        .unwrap_or_default();
                    let reuse_host = crate::request_index::reuse_host(root).unwrap_or_default();
                    let class = root["scheme_class"].as_u64().unwrap_or(0) as u8;
                    let mismatch = if crate::request_index::reuse_host_differs(
                        class,
                        &reuse_host,
                        &source_host,
                    ) {
                        Some("host_differs")
                    } else {
                        (unsigned(&event["monotonic_time_ns"])
                            > unsigned(&root["monotonic_time_ns"]))
                        .then_some("started_after")
                    };
                    if mismatch.is_some() {
                        facts.source_mismatch = facts.source_mismatch.or(mismatch);
                        return;
                    }
                    facts.source_found = true;
                    let detail = format!(
                        "renderer process {process} · request {initiator_request} · Blink reused its response"
                    );
                    emit(
                        sinks,
                        Direction::In,
                        event_row(
                            "reused_response",
                            "Reused response of".to_owned(),
                            detail,
                            event,
                        ),
                    );
                    return;
                }
                facts.initiator_found = true;
                let detail = format!("renderer process {process} · request {initiator_request}");
                emit(
                    sinks,
                    Direction::In,
                    event_row(
                        "request_initiator",
                        "Renderer request".to_owned(),
                        detail,
                        event,
                    ),
                );
                return;
            }
            if process == root_process
                && event["category"] == "network"
                && unsigned(&event["request_id"]) == unsigned(&root["request_id"])
            {
                facts.link_parents.insert((process, sequence));
                let status = event["status_code"].as_u64().unwrap_or(0);
                let detail = if status == 0 {
                    "no status recorded".to_owned()
                } else {
                    format!("status {status}")
                };
                emit(
                    sinks,
                    Direction::Out,
                    event_row("request_event", label, detail, event),
                );
                return;
            }
            let parent_of = unsigned(&event["parent_event_id"]);
            if process == root_process && parent_of == root_sequence {
                let detail = format!("child event · {}", event["category"].as_str().unwrap_or(""));
                emit(
                    sinks,
                    Direction::Out,
                    event_row("child_event", label, detail, event),
                );
                return;
            }
            if event["type"] == "artifact_captured"
                && facts.link_parents.contains(&(process, parent_of))
            {
                let detail = format!("artifact {}", text_id(&event["artifact_id"]));
                emit(
                    sinks,
                    Direction::Out,
                    event_row(
                        "response_artifact",
                        "Captured response".to_owned(),
                        detail,
                        event,
                    ),
                );
            }
        }
        Plan::Api {
            root,
            session,
            category,
            event_type,
            payload,
            script_names,
            ..
        } => {
            if !same_session(event, *session) || event["type"] == "gap" {
                return;
            }
            let process = unsigned(&event["process_id"]);
            let sequence = unsigned(&event["sequence_number"]);
            let root_process = unsigned(&root["process_id"]);
            let root_sequence = unsigned(&root["sequence_number"]);
            let is_root = process == root_process && sequence == root_sequence;
            if process == root_process && sequence == unsigned(&root["parent_event_id"]) {
                facts.parent_found = true;
                let (kind, name) = if dispatch_sample(event) {
                    ("host_link", format!("Dispatch sample {sequence}"))
                } else {
                    (
                        "parent_event",
                        pretty(event["type"].as_str().unwrap_or("event")),
                    )
                };
                let detail = format!(
                    "direct parent · {}",
                    event["category"].as_str().unwrap_or("")
                );
                emit(sinks, Direction::In, event_row(kind, name, detail, event));
            }
            if !is_root
                && process == root_process
                && unsigned(&event["parent_event_id"]) == root_sequence
            {
                let name = pretty(event["type"].as_str().unwrap_or("event"));
                let detail = format!("child event · {}", event["category"].as_str().unwrap_or(""));
                emit(
                    sinks,
                    Direction::Out,
                    event_row("child_event", name, detail, event),
                );
            }
            if event["category"] == category.as_str()
                && event["type"] == event_type.as_str()
                && event["payload"] == *payload
            {
                let frame = text_id(&event["frame_id"]);
                let artifact = text_id(&event["artifact_id"]);
                let caller = if artifact == "0" {
                    format!("frame {frame}")
                } else {
                    script_names
                        .get(&artifact)
                        .cloned()
                        .unwrap_or_else(|| format!("artifact {artifact}"))
                };
                let detail = if artifact == "0" {
                    format!("no script recorded · tab {}", text_id(&event["tab_id"]))
                } else {
                    format!(
                        "frame {frame} · tab {} · artifact {artifact}",
                        text_id(&event["tab_id"])
                    )
                };
                let name = if is_root {
                    format!("{caller} (selected call)")
                } else {
                    caller
                };
                let kind = if event_type == "api_call" {
                    "call"
                } else {
                    "read"
                };
                emit(sinks, Direction::In, event_row(kind, name, detail, event));
            }
        }
        Plan::Artifact {
            session,
            artifact,
            wasm,
            ..
        } => {
            if !same_session(event, *session) {
                return;
            }
            let target = wasm.as_ref().and_then(|module| module.target);
            if let Some(target) = target {
                classify_wasm(
                    event,
                    *artifact,
                    target,
                    wasm.as_ref().expect("target"),
                    facts,
                    sinks,
                    needle,
                );
                return;
            }
            if event["type"] == "gap" || unsigned(&event["artifact_id"]) != *artifact {
                return;
            }
            let name = operation(event);
            let detail = format!(
                "{} · {}",
                event["category"].as_str().unwrap_or(""),
                event["type"].as_str().unwrap_or("")
            );
            emit(
                sinks,
                Direction::Out,
                event_row("artifact_use", name, detail, event),
            );
        }
        Plan::VmHandler {
            session, parents, ..
        } => {
            if !same_session(event, *session) || !host_event(event) {
                return;
            }
            let key = (
                unsigned(&event["process_id"]),
                unsigned(&event["parent_event_id"]),
            );
            if !parents.contains(&key) {
                return;
            }
            let name = operation(event);
            let detail = format!(
                "dispatch parent {} · {}",
                key.1,
                event["category"].as_str().unwrap_or("")
            );
            emit(
                sinks,
                Direction::Out,
                event_row("host_link", name, detail, event),
            );
        }
    }
}

fn classify_wasm(
    event: &mut Value,
    artifact: u64,
    target: u32,
    module: &WasmModule,
    facts: &mut PassFacts,
    sinks: &mut [Sink; 2],
    needle: &str,
) {
    if event["type"] == "gap" {
        if let Some(named) = event_window::named_gap(event)
            && named.0 == "vm"
            && named.1.contains("wasm")
            && facts.saw_gap_reasons.len() < 16
        {
            facts.saw_gap_reasons.insert(named.1.clone());
        }
        return;
    }
    let process = unsigned(&event["process_id"]);
    let sequence = unsigned(&event["sequence_number"]);
    let is_observation = matches!(
        event["type"].as_str(),
        Some("wasm_dispatch_observation" | "wasm_indirect_observation")
    );
    if is_observation && unsigned(&event["artifact_id"]) == artifact {
        facts.saw_samples = true;
        vm_opcode::annotate_wasm_observations(std::slice::from_mut(event));
        let observation = &event["wasm_observation"];
        if observation["status"] != "decoded" {
            return;
        }
        let function = observation["function_index"].as_u64().unwrap_or(u64::MAX);
        let direct = (observation["direct_caller"]["kind"] == "same-instance")
            .then(|| observation["direct_caller"]["function_index"].as_u64())
            .flatten();
        // Only a resolved entry names a callee of this instance. A null,
        // out-of-bounds, foreign or unresolved entry records index 0, which
        // is not function 0, so it is labeled by its resolution instead.
        let resolution = observation["resolution"].as_str();
        let callee = (resolution == Some("resolved"))
            .then(|| observation["callee_function_index"].as_u64())
            .flatten();
        let unresolved = resolution.filter(|value| *value != "resolved");
        let offset = observation["module_byte_offset"].as_u64().unwrap_or(0);
        let function_name = |index: u64| module.function_name(index as u32);
        if function == u64::from(target) {
            facts.link_parents.insert((process, sequence));
            if let Some(caller) = direct {
                let mut row = event_row(
                    "direct_caller",
                    function_name(caller),
                    format!("called this function · sample {sequence} · byte {offset}"),
                    event,
                );
                row.function = u32::try_from(caller).ok();
                sinks[0].push(&row, Direction::In, needle);
            }
            if let Some(callee) = callee {
                let mut row = event_row(
                    "indirect_call",
                    function_name(callee),
                    format!(
                        "call_indirect · slot {} · byte {offset}",
                        observation["slot"]
                    ),
                    event,
                );
                row.function = u32::try_from(callee).ok();
                sinks[1].push(&row, Direction::Out, needle);
            } else if let Some(resolution) = unresolved {
                let row = event_row(
                    "indirect_call",
                    format!("{resolution} callee"),
                    format!(
                        "call_indirect · slot {} · byte {offset} · no callee of this instance",
                        observation["slot"]
                    ),
                    event,
                );
                sinks[1].push(&row, Direction::Out, needle);
            }
            return;
        }
        if direct == Some(u64::from(target)) {
            let mut row = event_row(
                "direct_caller",
                function_name(function),
                format!("called by this function · sample {sequence}"),
                event,
            );
            row.function = u32::try_from(function).ok();
            sinks[1].push(&row, Direction::Out, needle);
            return;
        }
        if callee == Some(u64::from(target)) {
            let mut row = event_row(
                "indirect_call",
                function_name(function),
                format!(
                    "call_indirect · slot {} · byte {offset}",
                    observation["slot"]
                ),
                event,
            );
            row.function = u32::try_from(function).ok();
            sinks[0].push(&row, Direction::In, needle);
        }
        return;
    }
    if host_event(event)
        && facts
            .link_parents
            .contains(&(process, unsigned(&event["parent_event_id"])))
    {
        let name = operation(event);
        let detail = format!(
            "dispatch parent {} · {}",
            text_id(&event["parent_event_id"]),
            event["category"].as_str().unwrap_or("")
        );
        let row = event_row("host_link", name, detail, event);
        sinks[1].push(&row, Direction::Out, needle);
    }
}

/// Rows known without reading events. Replayed by every page that starts
/// inside them; their count is small next to the event rows.
fn static_rows(plan: &Plan, stores: &Stores, sinks: &mut [Sink; 2], needle: &str) {
    let Plan::Artifact {
        session_text,
        artifact_text,
        info,
        creator,
        capture,
        creator_id,
        parent,
        children,
        wasm,
        record,
        ..
    } = plan
    else {
        if let Plan::VmHandler { samples, .. } = plan {
            for sample in samples {
                let reference = &sample["event"];
                let position = sample["instruction_pointer"]
                    .as_u64()
                    .map(|pc| {
                        format!(
                            "pc {pc} ({})",
                            sample["instruction_pointer_units"].as_str().unwrap_or("?")
                        )
                    })
                    .unwrap_or_else(|| format!("byte {}", sample["module_byte_offset"]));
                let row = Row {
                    kind: "dispatch_sample",
                    name: format!("Sample {}", text_id(&reference["sequence_number"])),
                    detail: position,
                    source: "vm".to_owned(),
                    operation: "dispatch_sample".to_owned(),
                    state: "observed",
                    target: Target::Sample(reference, sample.get("monotonic_time_ns")),
                    function: None,
                };
                sinks[0].push(&row, Direction::In, needle);
            }
        }
        return;
    };
    if let Some(event) = creator {
        let name = pretty(event["type"].as_str().unwrap_or("event"));
        let detail = format!(
            "created this artifact · {}",
            event["category"].as_str().unwrap_or("")
        );
        let row = event_row("artifact_creator", name, detail, event);
        sinks[0].push(&row, Direction::In, needle);
    }
    if let Some(event) = capture
        && unsigned(&event["sequence_number"]) != *creator_id
    {
        let row = event_row(
            "artifact_capture",
            "Artifact captured".to_owned(),
            format!(
                "capture event · {}",
                event["category"].as_str().unwrap_or("")
            ),
            event,
        );
        sinks[0].push(&row, Direction::In, needle);
    }
    if let Some((id, parent)) = parent {
        let row = artifact_row(
            "parent_artifact",
            parent.name.clone(),
            format!("parent artifact {id}"),
            session_text,
            id,
            parent,
            None,
        );
        sinks[0].push(&row, Direction::In, needle);
    }
    for (id, child) in children {
        let row = artifact_row(
            "child_artifact",
            child.name.clone(),
            format!("child artifact {id}"),
            session_text,
            id,
            child,
            None,
        );
        sinks[1].push(&row, Direction::Out, needle);
    }
    if let Some(module) = wasm
        && let Ok(bytes) = evidence::content(&stores.artifacts, record, wasm::MAX_BYTES)
    {
        emit_wasm_static(
            module,
            &bytes,
            session_text,
            artifact_text,
            info,
            sinks,
            needle,
        );
    }
}

fn artifact_row<'a>(
    kind: &'static str,
    name: String,
    detail: String,
    session: &'a str,
    id: &'a str,
    info: &'a ArtifactRef,
    byte_offset: Option<u32>,
) -> Row<'a> {
    Row {
        kind,
        name,
        detail,
        source: "artifact".to_owned(),
        operation: info.kind.clone(),
        // Import, export and call rows are decoded from retained module bytes.
        state: if kind.starts_with("wasm_") {
            "static"
        } else {
            "observed"
        },
        target: Target::Artifact {
            session,
            id,
            info,
            byte_offset,
        },
        function: None,
    }
}

/// Walks the retained module once more, for one page, and keeps nothing.
fn emit_wasm_static(
    module: &WasmModule,
    bytes: &[u8],
    session: &str,
    artifact: &str,
    info: &ArtifactRef,
    sinks: &mut [Sink; 2],
    needle: &str,
) {
    let mut defined = 0u32;
    let target = module.target;
    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else { return };
        match payload {
            Payload::ImportSection(reader) if target.is_none() => {
                let mut index = 0u32;
                for entry in reader.into_iter_with_offsets().flatten() {
                    let (offset, import) = entry;
                    if matches!(import.ty, TypeRef::Func(_)) {
                        let name = format!("{}.{}", import.module, import.name);
                        let mut row = artifact_row(
                            "wasm_import",
                            name,
                            format!("import · func {index}"),
                            session,
                            artifact,
                            info,
                            Some(offset as u32),
                        );
                        row.function = Some(index);
                        sinks[1].push(&row, Direction::Out, needle);
                        index += 1;
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for entry in reader.into_iter_with_offsets().flatten() {
                    let (offset, export) = entry;
                    if export.kind == ExternalKind::Func
                        && target.is_none_or(|target| export.index == target)
                    {
                        let mut row = artifact_row(
                            "wasm_export",
                            export.name.to_owned(),
                            format!("export · func {}", export.index),
                            session,
                            artifact,
                            info,
                            Some(offset as u32),
                        );
                        row.function = Some(export.index);
                        sinks[0].push(&row, Direction::In, needle);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let Some(caller) = module.imported.checked_add(defined) else {
                    return;
                };
                defined += 1;
                let Some(target) = target else { continue };
                if caller != target && module.target_is_import && target >= module.imported {
                    continue;
                }
                let Ok(reader) = body.get_operators_reader() else {
                    continue;
                };
                for item in reader.into_iter_with_offsets() {
                    let Ok((operator, offset)) = item else { break };
                    let callee = match operator {
                        Operator::Call { function_index }
                        | Operator::ReturnCall { function_index } => function_index,
                        _ => continue,
                    };
                    if callee == target {
                        let mut row = artifact_row(
                            "wasm_call",
                            module.function_name(caller),
                            format!("calls this function · byte {offset}"),
                            session,
                            artifact,
                            info,
                            Some(offset as u32),
                        );
                        row.function = Some(caller);
                        sinks[0].push(&row, Direction::In, needle);
                    }
                    if caller == target {
                        let mut row = artifact_row(
                            "wasm_call",
                            module.function_name(callee),
                            format!("call · byte {offset}"),
                            session,
                            artifact,
                            info,
                            Some(offset as u32),
                        );
                        row.function = Some(callee);
                        sinks[1].push(&row, Direction::Out, needle);
                    }
                }
            }
            _ => {}
        }
    }
}

fn gaps_for(plan: &Plan, facts: &PassFacts) -> [Vec<Value>; 2] {
    let mut gaps = [Vec::new(), Vec::new()];
    match plan {
        Plan::Unresolved { .. } => {}
        Plan::Request { root, .. } => {
            let parent = unsigned(&root["parent_event_id"]);
            if parent != 0 && !facts.parent_found {
                gaps[0].push(gap(
                    "parent-not-retained",
                    "Parent event not retained",
                    format!("Event {parent} is named as the parent but is not retained."),
                ));
            }
            if root["type"] == "memory_cache_reuse" {
                gaps[0].push(gap(
                    "no-initiator-stack",
                    "No initiator recorded",
                    "A memory-cache reuse makes no request, so it has no initiator.".to_owned(),
                ));
                if unsigned(&root["initiator_process_id"]) != 0 && !facts.source_found {
                    let named = unsigned(&root["initiator_request_id"]);
                    gaps[0].push(match facts.source_mismatch {
                        Some(reason) => gap(
                            "reused-source-not-this-load",
                            "Reused request not identified",
                            format!(
                                "Blink names request {named} of this renderer, but the retained request of that ID {}, so it is not this resource's load: the renderer's process ID may have been reused within the session.",
                                if reason == "host_differs" {
                                    "was requested from another host"
                                } else {
                                    "started after this reuse"
                                }
                            ),
                        ),
                        None => gap(
                            "reused-source-not-retained",
                            "Reused request not retained",
                            "The request whose response Blink reused is not retained.".to_owned(),
                        ),
                    });
                }
            } else if unsigned(&root["initiator_process_id"]) == 0 && parent == 0 {
                gaps[0].push(gap(
                    "no-initiator-stack",
                    "No initiator recorded",
                    "This request carries no renderer initiator or parent event. No caller is inferred.".to_owned(),
                ));
            } else if unsigned(&root["initiator_process_id"]) != 0 && !facts.initiator_found {
                gaps[0].push(gap(
                    "initiator-not-retained",
                    "Initiator not retained",
                    "The renderer initiator named by this request is not retained.".to_owned(),
                ));
            }
        }
        Plan::Api { root, .. } => {
            let parent = unsigned(&root["parent_event_id"]);
            if parent == 0 {
                gaps[0].push(gap(
                    "no-dispatch-sample",
                    "No dispatch sample for this call",
                    "The selected call has no recorded parent event. No caller is inferred."
                        .to_owned(),
                ));
            } else if !facts.parent_found {
                gaps[0].push(gap(
                    "parent-not-retained",
                    "Parent event not retained",
                    format!("Event {parent} is named as the parent but is not retained."),
                ));
            }
        }
        Plan::Artifact {
            creator,
            creator_id,
            wasm,
            wasm_note,
            ..
        } => {
            if let Some(note) = wasm_note {
                gaps[0].push(gap(
                    "static-inspection-unavailable",
                    "Module not inspected",
                    note.clone(),
                ));
            }
            if *creator_id == 0 {
                gaps[0].push(gap(
                    "no-creator-event",
                    "No creator event recorded",
                    "The manifest names no creator event for this artifact.".to_owned(),
                ));
            } else if creator.is_none() {
                gaps[0].push(gap(
                    "creator-not-retained",
                    "Creator event not retained",
                    format!("Event {creator_id} created this artifact but is not retained."),
                ));
            }
            if wasm.as_ref().is_some_and(|module| module.target.is_some()) {
                if !facts.saw_samples {
                    gaps[0].push(gap(
                        "no-dispatch-samples",
                        "No dispatch samples for this module",
                        "No native Wasm observation names this module, so dynamic callers are unknown.".to_owned(),
                    ));
                }
                for reason in &facts.saw_gap_reasons {
                    gaps[0].push(gap(
                        "sampler-unavailable",
                        "Sampler limit recorded",
                        reason.clone(),
                    ));
                }
                if wasm.as_ref().is_some_and(|module| module.target_is_import) {
                    gaps[1].push(gap(
                        "no-function-body",
                        "Imported function",
                        "An imported function has no body in this module, so it has no outgoing calls.".to_owned(),
                    ));
                }
            }
        }
        Plan::VmHandler {
            samples,
            sample_count,
            omissions,
            ..
        } => {
            if samples.is_empty() {
                gaps[0].push(gap(
                    "no-dispatch-samples",
                    "No dispatch samples for this handler",
                    "No retained sample names this handler, so no guest position or host link is shown.".to_owned(),
                ));
            } else if *sample_count > samples.len() as u64 || !omissions.is_empty() {
                gaps[0].push(gap(
                    "dispatch-sample-retention-limit",
                    "Dispatch samples outnumber retained samples",
                    format!(
                        "{sample_count} samples were accepted and {} are retained for this handler.",
                        samples.len()
                    ),
                ));
            }
        }
    }
    gaps
}

/// The current selection's cursors, shared by the pages of one list.
pub struct Entry {
    key: String,
    snapshot: u64,
    plan: Arc<Plan>,
    counts: [(u64, u64); 2],
    static_counts: [(u64, u64); 2],
    anchors: [Vec<Anchor>; 2],
    gaps: [Vec<Value>; 2],
    coverage: Value,
    link_parents: Arc<HashSet<(u64, u64)>>,
}

/// One entry: selections replace it, so a closed dock or a new session leaves
/// nothing behind beyond this.
#[derive(Default)]
pub struct Cursors(Mutex<Option<Arc<Entry>>>);

impl Cursors {
    fn current(&self, key: &str, snapshot: Option<u64>) -> Option<Arc<Entry>> {
        let entry = self.0.lock().ok()?.clone()?;
        (entry.key == key && snapshot.is_none_or(|snapshot| snapshot == entry.snapshot))
            .then_some(entry)
    }
    fn store(&self, entry: Arc<Entry>) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(entry);
        }
    }
}

fn anchor_positions(sinks: &[Sink; 2], position: u64, anchors: &mut [Vec<Anchor>; 2]) {
    for (index, sink) in sinks.iter().enumerate() {
        if sink.matching >= sink.last_anchor + ANCHOR_EVERY
            || (sink.matching > 0 && anchors[index].is_empty())
        {
            let anchor = Anchor {
                position,
                total: sink.total,
                matching: sink.matching,
            };
            anchors[index].push(anchor);
        }
    }
}

/// Serves a page. A new selection is scanned from the start of the store; a
/// page of the selection already held resumes from its nearest cursor.
pub fn run(
    query: &XrefQuery,
    stores: &Stores,
    cursors: &Cursors,
    handler: Option<VmHandlerInput>,
    cancel: &AtomicBool,
) -> Result<Value> {
    let reader = Reader {
        cancel,
        deadline: Instant::now() + SCAN_DEADLINE,
        cancelled: "The cross-reference request was cancelled",
    };
    let end = complete_end(&stores.events)?;
    let snapshot = query.snapshot.map_or(end, |value| value.min(end));
    let key = query.cache_key();
    let entry = cursors.current(&key, query.snapshot);
    let entry = match entry {
        Some(entry) => entry,
        None => {
            let plan = Arc::new(build_plan(query, stores, &reader, snapshot, handler)?);
            let entry = full_pass(query, stores, plan, snapshot, &reader)?;
            cursors.store(entry.clone());
            return Ok(document(query, &entry, snapshot));
        }
    };
    let window = window_pass(query, stores, &entry, snapshot, &reader)?;
    let mut value = document(query, &entry, snapshot);
    for (direction, rows) in window {
        value["pages"][direction.key()]["rows"] = Value::Array(rows);
    }
    Ok(value)
}

fn full_pass(
    query: &XrefQuery,
    stores: &Stores,
    plan: Arc<Plan>,
    snapshot: u64,
    reader: &Reader<'_>,
) -> Result<Arc<Entry>> {
    let needle = query.filter.as_str();
    let wants = |direction: Direction| query.directions.contains(&direction);
    let mut sinks = [
        Sink::new(wants(Direction::In), query.offset, query.limit),
        Sink::new(wants(Direction::Out), query.offset, query.limit),
    ];
    let mut facts = PassFacts::default();
    if let Plan::VmHandler { parents, .. } = plan.as_ref() {
        facts.link_parents = parents.clone();
    }
    static_rows(&plan, stores, &mut sinks, needle);
    let static_counts = [
        (sinks[0].total, sinks[0].matching),
        (sinks[1].total, sinks[1].matching),
    ];
    let mut anchors = [Vec::new(), Vec::new()];
    if !matches!(plan.as_ref(), Plan::Unresolved { .. }) {
        let prefilter = plan_filter(&plan);
        let scanned = reader.lines(
            &stores.events,
            0,
            snapshot,
            prefilter,
            &mut |position, record| {
                let mut event = parse_event(record)?;
                anchor_positions(&sinks, position, &mut anchors);
                for sink in &mut sinks {
                    if sink.matching >= sink.last_anchor + ANCHOR_EVERY {
                        sink.last_anchor = sink.matching;
                    }
                }
                classify_event(&plan, &mut event, &mut facts, &mut sinks, needle);
                Some(true)
            },
        )?;
        facts.scanned_end = scanned.position;
        facts.stopped_deadline = scanned.stopped == Stopped::Deadline;
        facts.malformed = scanned.malformed;
    }
    let gaps = gaps_for(&plan, &facts);
    let coverage = coverage_document(
        &facts,
        snapshot,
        matches!(plan.as_ref(), Plan::Unresolved { .. }),
    );
    let counts = [
        (sinks[0].total, sinks[0].matching),
        (sinks[1].total, sinks[1].matching),
    ];
    let link_parents = Arc::new(std::mem::take(&mut facts.link_parents));
    let [in_rows, out_rows] = sinks;
    let entry = Arc::new(Entry {
        key: query.cache_key(),
        snapshot,
        plan,
        counts,
        static_counts,
        anchors,
        gaps,
        coverage,
        link_parents,
    });
    FIRST_PAGE.with(|slot| {
        *slot.borrow_mut() = Some([in_rows.rows, out_rows.rows]);
    });
    Ok(entry)
}

// The first pass already built the first page; carrying it through a thread
// local keeps `Entry` free of rows, so nothing else can retain them.
thread_local! {
    static FIRST_PAGE: std::cell::RefCell<Option<[Vec<Value>; 2]>> = const { std::cell::RefCell::new(None) };
}

fn plan_filter(plan: &Plan) -> Option<&Regex> {
    match plan {
        Plan::Unresolved { .. } => None,
        Plan::Request { prefilter, .. }
        | Plan::Api { prefilter, .. }
        | Plan::Artifact { prefilter, .. }
        | Plan::VmHandler { prefilter, .. } => Some(prefilter),
    }
}

fn coverage_document(facts: &PassFacts, snapshot: u64, unresolved_plan: bool) -> Value {
    let complete = !facts.stopped_deadline;
    let mut coverage = json!({
        "status": if complete { "complete" } else { "partial" },
        "scanned_bytes": if unresolved_plan { 0 } else { facts.scanned_end }.to_string(),
        "snapshot_bytes": snapshot.to_string(),
        "malformed_records": facts.malformed,
    });
    if !complete {
        coverage["reason"] = json!("scan-deadline");
    }
    coverage
}

/// One page of a selection whose totals are already known. The nearest cursor
/// is the only reason this does not read the store from the start.
fn window_pass(
    query: &XrefQuery,
    stores: &Stores,
    entry: &Entry,
    snapshot: u64,
    reader: &Reader<'_>,
) -> Result<Vec<(Direction, Vec<Value>)>> {
    let needle = query.filter.as_str();
    let mut result = Vec::new();
    for direction in &query.directions {
        let index = direction.index();
        let (static_total, static_matching) = entry.static_counts[index];
        let mut sinks = [Sink::new(false, 0, 0), Sink::new(false, 0, 0)];
        sinks[index] = Sink::new(true, query.offset, query.limit);
        let plan = &entry.plan;
        if query.offset < static_matching {
            static_rows(plan, stores, &mut sinks, needle);
        } else {
            sinks[index].total = static_total;
            sinks[index].matching = static_matching;
        }
        let mut start = 0;
        if query.offset >= static_matching
            && let Some(anchor) = entry.anchors[index]
                .iter()
                .rev()
                .find(|anchor| anchor.matching <= query.offset)
        {
            start = anchor.position;
            sinks[index].total = anchor.total;
            sinks[index].matching = anchor.matching;
        }
        if !sinks[index].full() && !matches!(plan.as_ref(), Plan::Unresolved { .. }) {
            let mut facts = PassFacts {
                link_parents: (*entry.link_parents).clone(),
                ..PassFacts::default()
            };
            reader.lines(
                &stores.events,
                start,
                snapshot,
                plan_filter(plan),
                &mut |_, record| {
                    let mut event = parse_event(record)?;
                    classify_event(plan, &mut event, &mut facts, &mut sinks, needle);
                    Some(!sinks[index].full())
                },
            )?;
        }
        result.push((*direction, std::mem::take(&mut sinks[index].rows)));
    }
    Ok(result)
}

fn document(query: &XrefQuery, entry: &Entry, snapshot: u64) -> Value {
    let first = FIRST_PAGE.with(|slot| slot.borrow_mut().take());
    let mut pages = serde_json::Map::new();
    for direction in Direction::ALL {
        if !query.directions.contains(&direction) {
            continue;
        }
        let rows = first
            .as_ref()
            .map(|pages| pages[direction.index()].clone())
            .unwrap_or_default();
        pages.insert(
            direction.key().to_owned(),
            json!({
                "offset": query.offset,
                "limit": query.limit,
                "returned": rows.len(),
                "rows": rows,
            }),
        );
    }
    let [(in_total, in_matching), (out_total, out_matching)] = entry.counts;
    json!({
        "contract_version": 1,
        "document_kind": "reb-xrefs",
        "selection": entry.plan.selection(),
        "filter": query.filter,
        "snapshot": snapshot.to_string(),
        "counts": {
            "in": {"total": in_total, "matching": in_matching},
            "out": {"total": out_total, "matching": out_matching},
        },
        "pages": pages,
        "gaps": {
            "in": entry.gaps[0],
            "out": entry.gaps[1],
        },
        "coverage": entry.coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::io::Write;

    struct Fixture {
        _dir: tempfile::TempDir,
        stores: Stores,
    }

    fn event(sequence: u64, fields: Value) -> Value {
        let mut event = json!({"protocol_version":3,"session_id":"7","process_id":42,
            "sequence_number":sequence.to_string(),"monotonic_time_ns":sequence.to_string(),
            "navigation_id":"1","frame_id":"2","artifact_id":"0","parent_event_id":"0",
            "request_id":"0","initiator_request_id":0,"initiator_process_id":0,
            "category":"network","type":"request_started","status_code":0,
            "payload_encoding":"hex","payload":""});
        for (key, value) in fields.as_object().unwrap() {
            event[key] = value.clone();
        }
        event
    }

    fn fixture(events: &[Value], manifest: &[Value]) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("events.jsonl");
        let mut file = std::fs::File::create(&store).unwrap();
        for event in events {
            writeln!(file, "{event}").unwrap();
        }
        let artifacts = dir.path().join("artifacts");
        std::fs::create_dir_all(&artifacts).unwrap();
        let mut file = std::fs::File::create(artifacts.join("manifest.jsonl")).unwrap();
        for artifact in manifest {
            writeln!(file, "{artifact}").unwrap();
        }
        Fixture {
            stores: Stores {
                events: store,
                artifacts,
            },
            _dir: dir,
        }
    }

    fn query(raw: &str) -> XrefQuery {
        XrefQuery::parse(&Query::new(raw)).unwrap()
    }

    fn page(fixture: &Fixture, cursors: &Cursors, raw: &str) -> Value {
        run(
            &query(raw),
            &fixture.stores,
            cursors,
            None,
            &AtomicBool::new(false),
        )
        .unwrap()
    }

    #[test]
    fn a_request_lists_its_initiator_and_lifecycle_and_names_a_missing_initiator() {
        let events = [
            event(
                1,
                json!({"process_id":9,"request_id":"5","type":"request_initiated"}),
            ),
            event(
                2,
                json!({"request_id":"5","initiator_process_id":9,"initiator_request_id":5}),
            ),
            event(
                3,
                json!({"request_id":"5","type":"response_completed","status_code":200}),
            ),
            event(
                4,
                json!({"parent_event_id":"3","category":"artifact","type":"artifact_captured","artifact_id":"11"}),
            ),
            event(8, json!({"request_id":"6"})),
        ];
        let fixture = fixture(&events, &[]);
        let cursors = Cursors::default();
        let document = page(
            &fixture,
            &cursors,
            "kind=request&session_id=7&process_id=42&sequence_number=2&request_id=5",
        );
        assert_eq!(document["selection"]["status"], "resolved");
        assert_eq!(document["counts"]["in"]["total"], 1);
        assert_eq!(
            document["pages"]["in"]["rows"][0]["kind"],
            "request_initiator"
        );
        assert_eq!(
            document["pages"]["in"]["rows"][0]["evidence"]["process_id"],
            9
        );
        assert_eq!(
            document["pages"]["in"]["rows"][0]["ids"]["sequence_number"],
            "1"
        );
        let out = document["pages"]["out"]["rows"].as_array().unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["kind"], "request_event");
        assert_eq!(out[0]["detail"], "status 200");
        assert_eq!(out[1]["kind"], "response_artifact");
        assert_eq!(document["gaps"]["in"], json!([]));
        let orphan = page(
            &fixture,
            &Cursors::default(),
            "kind=request&session_id=7&process_id=42&sequence_number=8&request_id=6",
        );
        assert_eq!(orphan["counts"]["in"]["total"], 0);
        assert_eq!(orphan["gaps"]["in"][0]["reason"], "no-initiator-stack");
    }

    // A version 2 memory_cache_reuse names its source request in the initiator
    // fields; it is the reused response, never the reuse's initiator.
    #[test]
    fn a_reuse_names_its_reused_request_not_an_initiator() {
        let reuse = |sequence: u64, source: u64| {
            event(
                sequence,
                json!({"process_id":61,"request_id":"21","type":"memory_cache_reuse",
                    "initiator_process_id":61,"initiator_request_id":source}),
            )
        };
        let events = vec![
            event(
                1,
                json!({"process_id":61,"request_id":"20","type":"request_initiated"}),
            ),
            reuse(2, 20),
        ];
        let store = fixture(&events, &[]);
        let document = page(
            &store,
            &Cursors::default(),
            "kind=request&session_id=7&process_id=61&sequence_number=2&request_id=21",
        );
        let rows = document["pages"]["in"]["rows"].as_array().unwrap();
        assert!(
            rows.iter().all(|row| row["kind"] != "request_initiator"),
            "{rows:?}"
        );
        assert_eq!(rows[0]["kind"], "reused_response");
        assert_eq!(rows[0]["name"], "Reused response of");
        assert_eq!(rows[0]["ids"]["request_id"], "20");
        let reasons = |document: &Value| {
            document["gaps"]["in"]
                .as_array()
                .unwrap()
                .iter()
                .map(|gap| gap["reason"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(reasons(&document), ["no-initiator-stack"]);
        // A source that is not retained is named as that, never as a lost initiator.
        let missing = fixture(&[reuse(2, 30)], &[]);
        let document = page(
            &missing,
            &Cursors::default(),
            "kind=request&session_id=7&process_id=61&sequence_number=2&request_id=21",
        );
        assert_eq!(document["counts"]["in"]["total"], 0);
        assert_eq!(
            reasons(&document),
            ["no-initiator-stack", "reused-source-not-retained"]
        );
        // As in the request index, the source must have the reuse's host and
        // have started before it.
        let hosted = |sequence: u64, host: &[u8]| {
            let mut payload = vec![0u8; 128];
            payload[..8].copy_from_slice(&[2, 0, 128, 0, 2, 4, host.len() as u8, 0]);
            payload[8..8 + host.len()].copy_from_slice(host);
            let mut event = reuse(sequence, 20);
            event["flags"] = json!(0);
            event["scheme_class"] = json!(1);
            event["payload"] = json!(hex::encode(payload));
            event
        };
        let initiated = |sequence: u64, host: &str| {
            event(
                sequence,
                json!({"process_id":61,"request_id":"20","type":"request_initiated",
                    "payload":hex::encode(format!("GET {host}"))}),
            )
        };
        let query = |sequence: u64| {
            format!(
                "kind=request&session_id=7&process_id=61&sequence_number={sequence}&request_id=21"
            )
        };
        let same = fixture(&[initiated(1, "a.test"), hosted(2, b"a.test")], &[]);
        let document = page(&same, &Cursors::default(), &query(2));
        assert_eq!(
            document["pages"]["in"]["rows"][0]["kind"],
            "reused_response"
        );
        for (events, sequence, words) in [
            (
                vec![initiated(1, "b.test"), hosted(2, b"a.test")],
                2,
                "was requested from another host",
            ),
            (
                vec![hosted(1, b"a.test"), initiated(2, "a.test")],
                1,
                "started after this reuse",
            ),
        ] {
            let store = fixture(&events, &[]);
            let document = page(&store, &Cursors::default(), &query(sequence));
            assert_eq!(document["counts"]["in"]["total"], 0, "{words}");
            assert_eq!(
                reasons(&document),
                ["no-initiator-stack", "reused-source-not-this-load"],
                "{words}"
            );
            assert!(
                document["gaps"]["in"][1]["detail"]
                    .as_str()
                    .unwrap()
                    .contains(words),
                "{words}"
            );
        }
    }

    #[test]
    fn unknown_and_mismatched_selections_are_states_not_errors() {
        let fixture = fixture(&[event(2, json!({"request_id":"5"}))], &[]);
        let cursors = Cursors::default();
        let missing = page(
            &fixture,
            &cursors,
            "kind=request&session_id=7&process_id=42&sequence_number=99&request_id=5",
        );
        assert_eq!(missing["selection"]["status"], "unavailable");
        assert_eq!(missing["selection"]["reason"], "not-retained");
        let wrong = page(
            &fixture,
            &cursors,
            "kind=request&session_id=7&process_id=42&sequence_number=2&request_id=6",
        );
        assert_eq!(wrong["selection"]["reason"], "identity-mismatch");
        assert!(XrefQuery::parse(&Query::new("kind=request&session_id=abc")).is_err());
        assert!(XrefQuery::parse(&Query::new("kind=unknown&session_id=1")).is_err());
        assert!(
            XrefQuery::parse(&Query::new(
                "kind=api&session_id=1&process_id=1&sequence_number=1&bogus=1"
            ))
            .is_err()
        );
    }

    #[test]
    fn filtering_and_paging_over_a_large_selection_hold_only_one_window() {
        let payload = hex::encode("HTMLCanvasElement.toDataURL");
        // Sized for a debug test; the release proof runs at 100,000+ links.
        const LINKS: u64 = 12_000;
        let events: Vec<Value> = (1..=LINKS)
            .map(|sequence| {
                event(
                    sequence,
                    json!({"category":"canvas","type":"api_call","payload":payload,
                    "frame_id": (sequence % 7).to_string()}),
                )
            })
            .collect();
        let fixture = fixture(&events, &[]);
        let cursors = Cursors::default();
        let raw = "kind=api&session_id=7&process_id=42&sequence_number=5";
        let first = page(&fixture, &cursors, &format!("{raw}&limit=64"));
        assert_eq!(first["counts"]["in"]["total"], LINKS);
        assert_eq!(first["pages"]["in"]["rows"].as_array().unwrap().len(), 64);
        assert_eq!(first["gaps"]["in"][0]["reason"], "no-dispatch-sample");
        let snapshot = first["snapshot"].as_str().unwrap().to_owned();
        let later = page(
            &fixture,
            &cursors,
            &format!("{raw}&direction=in&limit=64&offset=10000&snapshot={snapshot}"),
        );
        let rows = later["pages"]["in"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 64);
        assert_eq!(rows[0]["ids"]["sequence_number"], "10001");
        assert_eq!(later["counts"]["in"]["total"], LINKS);
        let filtered = page(
            &fixture,
            &Cursors::default(),
            &format!("{raw}&filter=FRAME%205"),
        );
        assert_eq!(filtered["counts"]["in"]["total"], LINKS);
        assert_eq!(filtered["counts"]["in"]["matching"], 1714);
        assert!(
            filtered["pages"]["in"]["rows"][0]["name"]
                .as_str()
                .unwrap()
                .contains("frame 5")
        );
    }

    #[test]
    fn a_malformed_record_is_counted_and_cancellation_stops_the_scan() {
        let mut events = vec![event(
            1,
            json!({"category":"canvas","type":"api_call","payload":"41"}),
        )];
        events.extend((2..2200u64).map(|sequence| {
            event(
                sequence,
                json!({"category":"canvas","type":"api_call","payload":"41"}),
            )
        }));
        let fixture = fixture(&events, &[]);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&fixture.stores.events)
            .unwrap();
        writeln!(file, "{{\"payload\":\"41\" not json").unwrap();
        drop(file);
        let cursors = Cursors::default();
        let document = page(
            &fixture,
            &cursors,
            "kind=api&session_id=7&process_id=42&sequence_number=1",
        );
        assert_eq!(document["coverage"]["malformed_records"], 1);
        assert_eq!(document["counts"]["in"]["total"], 2199);
        let cancelled = AtomicBool::new(true);
        let result = run(
            &query("kind=api&session_id=7&process_id=42&sequence_number=1&filter=x"),
            &Stores {
                events: fixture.stores.events.clone(),
                artifacts: fixture.stores.artifacts.clone(),
            },
            &Cursors::default(),
            None,
            &cancelled,
        );
        assert_eq!(result.err().map(|error| error.status), Some(499));
    }

    fn dispatch_observation(sequence: u64, function: u32, caller: u32) -> Value {
        let mut payload = [0u8; 128];
        payload[0] = 3;
        payload[2] = 128;
        payload[4..8].copy_from_slice(&function.to_le_bytes());
        payload[8..12].copy_from_slice(&40u32.to_le_bytes());
        payload[12..16].copy_from_slice(&1u32.to_le_bytes());
        payload[16..20].copy_from_slice(&3u32.to_le_bytes());
        payload[32] = 1;
        payload[36..40].copy_from_slice(&caller.to_le_bytes());
        event(
            sequence,
            json!({"category":"vm","type":"wasm_dispatch_observation","artifact_id":"11","flags":0,
                "payload_size":128,"payload_truncated":false,"payload":hex::encode(payload)}),
        )
    }

    #[test]
    fn a_wasm_function_lists_static_calls_exports_and_sampled_callers() {
        let bytes = wat::parse_str(
            r#"(module
              (import "env" "host" (func $host))
              (func $inner (export "inner") call $host)
              (func $outer (export "outer") call $inner call $host))"#,
        )
        .unwrap();
        let hash = hex::encode(sha2::Sha256::digest(&bytes));
        let manifest = json!({"protocol_version":1,"artifact_id":"11","session_id":"7","navigation_id":"1","frame_id":"2",
            "parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"unknown",
            "kind":"wasm","url":"https://synthetic.test/m.wasm","mime_type":"application/wasm",
            "byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        let events = [
            dispatch_observation(1, 1, 2),
            event(
                2,
                json!({"parent_event_id":"1","category":"canvas","type":"api_call","payload":hex::encode("fillText")}),
            ),
            dispatch_observation(3, 2, 1),
        ];
        let fixture = fixture(&events, &[manifest]);
        std::fs::create_dir_all(fixture.stores.artifacts.join("blobs")).unwrap();
        std::fs::write(
            fixture.stores.artifacts.join(format!("blobs/{hash}.bin")),
            &bytes,
        )
        .unwrap();
        let mut bodies = Vec::new();
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::CodeSectionEntry(body) = payload.unwrap() {
                bodies.push(body.range().start);
            }
        }
        let cursors = Cursors::default();
        let document = page(
            &fixture,
            &cursors,
            &format!(
                "kind=artifact&session_id=7&artifact_id=11&byte_offset={}",
                bodies[0]
            ),
        );
        assert_eq!(document["selection"]["label"], "inner");
        let incoming = document["pages"]["in"]["rows"].as_array().unwrap();
        let kinds: Vec<_> = incoming
            .iter()
            .map(|row| row["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["wasm_export", "wasm_call", "direct_caller"]);
        assert_eq!(incoming[1]["name"], "outer");
        assert_eq!(incoming[2]["name"], "outer");
        let outgoing = document["pages"]["out"]["rows"].as_array().unwrap();
        let kinds: Vec<_> = outgoing
            .iter()
            .map(|row| row["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["wasm_call", "host_link", "direct_caller"]);
        assert_eq!(outgoing[0]["name"], "env.host");
        assert_eq!(outgoing[1]["name"], "fillText");
        assert_eq!(document["gaps"]["in"][0]["reason"], "no-creator-event");
        let module_level = page(
            &fixture,
            &Cursors::default(),
            "kind=artifact&session_id=7&artifact_id=11",
        );
        let rows = module_level["pages"]["out"]["rows"].as_array().unwrap();
        assert_eq!(rows[0]["kind"], "wasm_import");
        assert_eq!(rows[0]["name"], "env.host");
        assert_eq!(module_level["counts"]["in"]["matching"], 2);
    }

    fn indirect_observation(sequence: u64, function: u32, resolution: u32, callee: u32) -> Value {
        let mut payload = [0u8; 128];
        payload[..4].copy_from_slice(&[1, 0, 128, 0]);
        for (at, value) in [
            (4, function),
            (8, 40),
            (12, 0),
            (16, 3),
            (20, callee),
            (24, resolution),
        ] {
            payload[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        event(
            sequence,
            json!({"category":"vm","type":"wasm_indirect_observation","artifact_id":"11","flags":0,
                "payload_size":128,"payload_truncated":false,"payload":hex::encode(payload)}),
        )
    }

    // An indirect call names a callee only when its entry resolved in this
    // instance. A foreign or null entry records index 0, which is not function
    // 0 (the import here), so it is labeled by its resolution, never named.
    #[test]
    fn unresolved_indirect_calls_name_no_function() {
        let bytes = wat::parse_str(
            r#"(module
              (import "env" "host" (func $host))
              (func $inner (export "inner"))
              (func $outer (export "outer")))"#,
        )
        .unwrap();
        let hash = hex::encode(sha2::Sha256::digest(&bytes));
        let manifest = json!({"protocol_version":1,"artifact_id":"11","session_id":"7","navigation_id":"1","frame_id":"2",
            "parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"unknown",
            "kind":"wasm","url":"https://synthetic.test/m.wasm","mime_type":"application/wasm",
            "byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        // Resolutions: 0 resolved, 1 null, 3 foreign.
        let events = [
            indirect_observation(1, 1, 0, 2),
            indirect_observation(2, 1, 3, 0),
            indirect_observation(3, 1, 1, 0),
        ];
        let fixture = fixture(&events, &[manifest]);
        std::fs::create_dir_all(fixture.stores.artifacts.join("blobs")).unwrap();
        std::fs::write(
            fixture.stores.artifacts.join(format!("blobs/{hash}.bin")),
            &bytes,
        )
        .unwrap();
        let bodies: Vec<usize> = Parser::new(0)
            .parse_all(&bytes)
            .filter_map(|payload| match payload.unwrap() {
                Payload::CodeSectionEntry(body) => Some(body.range().start),
                _ => None,
            })
            .collect();
        let document = page(
            &fixture,
            &Cursors::default(),
            &format!(
                "kind=artifact&session_id=7&artifact_id=11&byte_offset={}",
                bodies[0]
            ),
        );
        let outgoing: Vec<&Value> = document["pages"]["out"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["kind"] == "indirect_call")
            .collect();
        assert_eq!(outgoing.len(), 3, "{outgoing:?}");
        assert_eq!(outgoing[0]["name"], "outer");
        assert_eq!(outgoing[0]["function_index"], 2);
        assert_eq!(outgoing[1]["name"], "foreign callee");
        assert_eq!(outgoing[2]["name"], "null callee");
        for row in &outgoing[1..] {
            assert!(row.get("function_index").is_none(), "{row}");
        }
        // Selecting the import (function 0) finds no indirect caller at all.
        let import = page(
            &fixture,
            &Cursors::default(),
            "kind=artifact&session_id=7&artifact_id=11",
        );
        assert!(
            !import["pages"]["in"]["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["kind"] == "indirect_call" && row["function_index"] == 0),
            "{import}"
        );
    }

    #[test]
    fn a_module_without_samples_names_the_gap() {
        let bytes = wat::parse_str(r#"(module (func (export "f")))"#).unwrap();
        let hash = hex::encode(sha2::Sha256::digest(&bytes));
        let manifest = json!({"protocol_version":1,"artifact_id":"11","session_id":"7","navigation_id":"1","frame_id":"2",
            "parent_artifact_id":"0","creator_event_id":"0","execution_context_id":"1","capture_origin":"unknown",
            "kind":"wasm","url":"https://synthetic.test/m.wasm","mime_type":"application/wasm",
            "byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        let fixture = fixture(
            &[event(1, json!({"category":"canvas","type":"api_call"}))],
            &[manifest],
        );
        std::fs::create_dir_all(fixture.stores.artifacts.join("blobs")).unwrap();
        std::fs::write(
            fixture.stores.artifacts.join(format!("blobs/{hash}.bin")),
            &bytes,
        )
        .unwrap();
        let mut body = 0;
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Payload::CodeSectionEntry(entry) = payload.unwrap() {
                body = entry.range().start;
            }
        }
        let document = page(
            &fixture,
            &Cursors::default(),
            &format!("kind=artifact&session_id=7&artifact_id=11&byte_offset={body}"),
        );
        let reasons: Vec<_> = document["gaps"]["in"]
            .as_array()
            .unwrap()
            .iter()
            .map(|gap| gap["reason"].as_str().unwrap())
            .collect();
        assert!(reasons.contains(&"no-dispatch-samples"));
    }

    #[test]
    fn a_vm_handler_links_only_children_of_its_retained_samples() {
        let events = [
            event(2, json!({"category":"vm","type":"wasm_guest_dispatch"})),
            event(
                3,
                json!({"parent_event_id":"2","category":"canvas","type":"api_call","payload":hex::encode("fillText")}),
            ),
            event(
                4,
                json!({"parent_event_id":"9","category":"canvas","type":"api_call","payload":hex::encode("fillRect")}),
            ),
        ];
        let fixture = fixture(&events, &[]);
        let workspace = json!({"workspaces":[{
            "interpreter_artifact_id":"33","source_artifact_sha256":"a".repeat(64),"sample_count":1,
            "handlers":[{"source":{"byte_offset":12,"byte_size":4},"opcode":1,"label":"push"}],
            "samples":[{"opcode":1,"event":{"session_id":"7","process_id":42,"sequence_number":"2"},"instruction_pointer":12,"instruction_pointer_units":"byte-offset"}]
        }]});
        let input = vm_handler_input(&workspace, "33", &"a".repeat(64), 12, 4);
        assert!(input.found);
        let raw = format!(
            "kind=vm_handler&session_id=7&artifact_id=33&sha256={}&byte_offset=12&byte_size=4",
            "a".repeat(64)
        );
        let document = run(
            &query(&raw),
            &fixture.stores,
            &Cursors::default(),
            Some(input),
            &AtomicBool::new(false),
        )
        .unwrap();
        let waiting = run(
            &query(&raw),
            &fixture.stores,
            &Cursors::default(),
            Some(VmHandlerInput::not_ready()),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(waiting["selection"]["reason"], "analysis-not-ready");
        assert_eq!(document["selection"]["label"], "push");
        assert_eq!(document["counts"]["in"]["total"], 1);
        assert_eq!(
            document["pages"]["in"]["rows"][0]["kind"],
            "dispatch_sample"
        );
        assert_eq!(document["counts"]["out"]["total"], 1);
        assert_eq!(document["pages"]["out"]["rows"][0]["kind"], "host_link");
        assert_eq!(document["pages"]["out"]["rows"][0]["name"], "fillText");
        assert_eq!(
            operation(&event(9, json!({"type":"api_call","payload":""}))),
            "api_call"
        );
    }
}
