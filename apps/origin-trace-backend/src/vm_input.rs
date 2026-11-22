//! The VM analysis inputs, read whole. The artifact manifest and the event
//! store are streamed line by line up to the length each had when its read
//! began, and only what the analysis reads is kept: VM records, artifact
//! captures, the response and request records an exact request link follows,
//! and host events that name an artifact and a parent. Request and
//! browser-signal records are folded into per-frame counts (`Runtime`), so
//! correlating an artifact with its frame is a lookup, and frame context is a
//! count and a `get_events` filter rather than a list copied into every
//! artifact. Omissions are counted per reason with the first line, so a
//! damaged store costs one entry rather than one per line.
use super::{capture_mode::Provenance, event_reference, runtime_rule};
use crate::{error::Result, evidence};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::File,
    hash::{DefaultHasher, Hash, Hasher},
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
    sync::LazyLock,
};

/// The longest manifest and event lines the analysis reads, as the profile
/// names them, so a line too long to be a record costs one bounded read.
static MANIFEST_LINE_BYTES: LazyLock<usize> =
    LazyLock::new(|| super::CONFIG["MAX_MANIFEST_LINE_BYTES"].as_u64().unwrap() as usize);
static EVENT_LINE_BYTES: LazyLock<usize> =
    LazyLock::new(|| super::CONFIG["MAX_EVENT_LINE_BYTES"].as_u64().unwrap() as usize);

/// Omissions counted by reason in the order each was first seen, with the
/// line it was first seen on when it has one.
#[derive(Default, Clone)]
pub(super) struct Omissions {
    reasons: Vec<(String, u64, Option<usize>)>,
}
impl Omissions {
    pub fn add(&mut self, reason: &str, line: Option<usize>) {
        self.add_count(reason, 1, line);
    }
    pub fn add_count(&mut self, reason: &str, count: u64, line: Option<usize>) {
        match self.reasons.iter_mut().find(|(known, ..)| known == reason) {
            Some((_, total, _)) => *total = total.saturating_add(count),
            None => self.reasons.push((reason.to_owned(), count, line)),
        }
    }
    pub fn extend(&mut self, other: Omissions) {
        for (reason, count, line) in other.reasons {
            self.add_count(&reason, count, line);
        }
    }
    pub fn is_empty(&self) -> bool {
        self.reasons.is_empty()
    }
    pub fn values(&self) -> Vec<Value> {
        self.reasons
            .iter()
            .map(|(reason, count, line)| {
                let mut value = json!({"reason": reason, "observed_records": count});
                if let Some(line) = line {
                    value["line"] = json!(line);
                }
                value
            })
            .collect()
    }
}

/// One line of a scanned file: its 1-based number, byte range, and bytes
/// without the newline, or None when it is longer than the scan's limit.
pub(super) struct Line<'a> {
    pub number: usize,
    pub start: u64,
    pub end: u64,
    pub bytes: Option<&'a [u8]>,
}

/// Streams `path` up to `length` (its length now when None), calling `each`
/// with every line. A line over `limit` bytes is passed without its bytes and
/// never held whole. A last line without its newline is passed only when it
/// parses as JSON, since otherwise it is a record still being written.
/// Returns the SHA-256 of the bytes read and their length, or None when the
/// file does not exist.
pub(super) fn scan(
    path: &Path,
    limit: usize,
    length: Option<u64>,
    mut each: impl FnMut(Line<'_>) -> Result<()>,
) -> Result<Option<(String, u64)>> {
    let file = match evidence::regular_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let length = match length {
        Some(length) => length,
        None => file.metadata()?.len(),
    };
    let mut reader = BufReader::with_capacity(1 << 20, file.take(length));
    let mut hash = Sha256::new();
    let mut line = Vec::new();
    let (mut offset, mut line_start, mut number, mut oversized) = (0u64, 0u64, 0usize, false);
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            break;
        }
        let (used, ended) = match buffer.iter().position(|byte| *byte == b'\n') {
            Some(at) => (at + 1, true),
            None => (buffer.len(), false),
        };
        hash.update(&buffer[..used]);
        let content = &buffer[..if ended { used - 1 } else { used }];
        if !oversized {
            if line.len() + content.len() > limit {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(content);
            }
        }
        reader.consume(used);
        offset += used as u64;
        if ended {
            number += 1;
            each(Line {
                number,
                start: line_start,
                end: offset,
                bytes: (!oversized).then_some(line.as_slice()),
            })?;
            line.clear();
            oversized = false;
            line_start = offset;
        }
    }
    // A last record without its newline is complete when it parses.
    if offset > line_start
        && (oversized || serde_json::from_slice::<serde::de::IgnoredAny>(&line).is_ok())
    {
        each(Line {
            number: number + 1,
            start: line_start,
            end: offset,
            bytes: (!oversized).then_some(line.as_slice()),
        })?;
    }
    Ok(Some((hex::encode(hash.finalize()), length)))
}

/// The bytes of the line at `start..end`, read again from `path`.
pub(super) fn read_line(file: &mut File, start: u64, end: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0; (end - start) as usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut bytes)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(bytes)
}

/// (session, navigation, frame) of an artifact or event.
pub(super) type Frame = (String, String, String);

pub(super) fn frame_of(value: &Value) -> Option<Frame> {
    Some((
        value["session_id"].as_str()?.to_owned(),
        value["navigation_id"].as_str()?.to_owned(),
        value["frame_id"].as_str()?.to_owned(),
    ))
}

/// The records of one signal rule: how many, and the first of them.
#[derive(Default)]
pub(super) struct Rule {
    pub count: u64,
    pub first: Option<Value>,
}
impl Rule {
    fn add(&mut self, event: &Value) {
        self.count = self.count.saturating_add(1);
        self.first.get_or_insert_with(|| {
            json!({"session_id":event["session_id"],"process_id":event["process_id"],
                "sequence_number":event["sequence_number"],"category":event["category"],"type":event["type"]})
        });
    }
}

/// What one frame holds of the records an artifact is correlated with.
#[derive(Default)]
pub(super) struct FrameContext {
    /// `request_started` and `request_initiated` records with a request ID.
    pub requests: u64,
    /// Host events, as `vm_host_links` reads them.
    pub hosts: u64,
    pub rules: BTreeMap<&'static str, Rule>,
}

/// Per-frame counts of request, host and signal records, and per artifact
/// the signal and host records that name it.
#[derive(Default)]
pub(crate) struct Runtime {
    frames: HashMap<Frame, FrameContext>,
    attributed: HashMap<(Frame, String), BTreeMap<&'static str, Rule>>,
    attributed_hosts: HashMap<(Frame, String), u64>,
}
impl Runtime {
    /// The context of `events`, each folded once as given.
    #[cfg(test)]
    pub(crate) fn of(events: &[Value]) -> Self {
        let mut runtime = Self::default();
        for event in events {
            runtime.fold(event);
        }
        runtime
    }
    /// Whether the runtime context reads `event`.
    fn reads(event: &Value) -> bool {
        runtime_rule(event).is_some() || request(event) || crate::vm_host_links::host_event(event)
    }
    pub(super) fn fold(&mut self, event: &Value) {
        let rule = runtime_rule(event);
        let request = request(event);
        let host = crate::vm_host_links::host_event(event);
        if rule.is_none() && !request && !host {
            return;
        }
        let Some(frame) = frame_of(event) else {
            return;
        };
        let context = self.frames.entry(frame.clone()).or_default();
        context.requests += u64::from(request);
        context.hosts += u64::from(host);
        let artifact = event["artifact_id"].as_str().filter(|id| *id != "0");
        if host && let Some(artifact) = artifact {
            *self
                .attributed_hosts
                .entry((frame.clone(), artifact.to_owned()))
                .or_default() += 1;
        }
        if let Some(rule) = rule {
            context.rules.entry(rule).or_default().add(event);
            if let Some(artifact) = artifact {
                self.attributed
                    .entry((frame, artifact.to_owned()))
                    .or_default()
                    .entry(rule)
                    .or_default()
                    .add(event);
            }
        }
    }
    pub(super) fn frame(&self, frame: &Frame) -> Option<&FrameContext> {
        self.frames.get(frame)
    }
    pub(super) fn attributed(
        &self,
        frame: &Frame,
        artifact: &str,
    ) -> Option<&BTreeMap<&'static str, Rule>> {
        self.attributed.get(&(frame.clone(), artifact.to_owned()))
    }
    /// Host events in the artifact's frame, and those of them naming it.
    pub(crate) fn hosts(&self, artifact: &Value) -> (u64, u64) {
        let Some((frame, id)) = frame_of(artifact).zip(artifact["artifact_id"].as_str()) else {
            return (0, 0);
        };
        let frame_hosts = self.frames.get(&frame).map_or(0, |context| context.hosts);
        let named = self.attributed_hosts.get(&(frame, id.to_owned()));
        (frame_hosts, named.copied().unwrap_or(0))
    }
}

fn request(event: &Value) -> bool {
    event["category"] == "network"
        && matches!(
            event["type"].as_str(),
            Some("request_started" | "request_initiated")
        )
        && event["request_id"].as_str().is_some_and(|id| id != "0")
}

/// The manifest's first pass: its failures, the snapshot artifacts every
/// workspace reads, the IDs no exact link may name, and the response
/// records a network response artifact can be linked through.
pub(super) struct Manifest {
    pub failures: Vec<Value>,
    pub snapshot_artifacts: Vec<Value>,
    pub invalid_ids: HashSet<String>,
    /// (session, creator event) of each network response artifact.
    pub creators: HashSet<(String, String)>,
    pub omissions: Omissions,
    pub modes: BTreeSet<&'static str>,
    pub digest: String,
    pub length: u64,
}

/// One validated manifest record and what it is to the analysis.
pub(super) enum Record {
    Invalid(Value, String),
    Snapshot(Value),
    Analyzed(Value),
}

fn manifest_record(mut artifact: Value) -> Record {
    let snapshot = crate::vm_opcode::is_snapshot_candidate(&artifact);
    let checked = if snapshot {
        crate::vm_opcode::validate_snapshot_artifact(&artifact)
    } else {
        evidence::validate_artifact(&mut artifact)
    };
    match checked {
        Err(error) => Record::Invalid(artifact, error.message),
        Ok(()) if snapshot || artifact["kind"] == "wasm_guest_adapter" => {
            Record::Snapshot(artifact)
        }
        Ok(()) => Record::Analyzed(artifact),
    }
}

pub(super) fn manifest(path: &Path, provenance: &Provenance) -> Result<Manifest> {
    let mut manifest = Manifest {
        failures: Vec::new(),
        snapshot_artifacts: Vec::new(),
        invalid_ids: HashSet::new(),
        creators: HashSet::new(),
        omissions: Omissions::default(),
        modes: BTreeSet::new(),
        digest: hex::encode(Sha256::digest([])),
        length: 0,
    };
    let mut seen = HashSet::new();
    let scanned = scan(path, *MANIFEST_LINE_BYTES, None, |line| {
        let Some(bytes) = line.bytes else {
            manifest
                .omissions
                .add("artifact-manifest-line-byte-limit", Some(line.number));
            return Ok(());
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
            manifest
                .omissions
                .add("malformed-artifact-manifest", Some(line.number));
            return Ok(());
        };
        manifest.modes.insert(provenance.mode(&value["session_id"]));
        let record = match manifest_record(value) {
            Record::Invalid(artifact, reason) => Some((artifact, reason)),
            Record::Snapshot(artifact) | Record::Analyzed(artifact)
                if !seen.insert(artifact["artifact_id"].as_str().unwrap_or("").to_owned()) =>
            {
                Some((artifact, "duplicate artifact ID".to_owned()))
            }
            Record::Snapshot(artifact) => {
                manifest.snapshot_artifacts.push(artifact);
                None
            }
            Record::Analyzed(artifact) => {
                if artifact["capture_origin"] == "network_response"
                    && artifact["execution_context_id"] == "0"
                    && let (Some(session), Some(creator)) = (
                        artifact["session_id"].as_str(),
                        artifact["creator_event_id"].as_str(),
                    )
                {
                    manifest
                        .creators
                        .insert((session.to_owned(), creator.to_owned()));
                }
                None
            }
        };
        if let Some((artifact, reason)) = record {
            manifest
                .failures
                .push(failure(&artifact, line.number, &reason));
            manifest
                .omissions
                .add("invalid-artifact-manifest", Some(line.number));
            if let Some(id) = manifest.failures.last().unwrap()["artifact_id"].as_str() {
                manifest.invalid_ids.insert(id.to_owned());
            }
        }
        Ok(())
    })?;
    if let Some((digest, length)) = scanned {
        (manifest.digest, manifest.length) = (digest, length);
    }
    let invalid = &manifest.invalid_ids;
    manifest.snapshot_artifacts.retain(|a| {
        a["capture_origin"] != "native_wasm_guest"
            || !invalid.contains(a["artifact_id"].as_str().unwrap_or(""))
    });
    Ok(manifest)
}

fn failure(artifact: &Value, line: usize, reason: &str) -> Value {
    let omission = json!({"reason":"invalid-artifact-manifest","line":line});
    let id = if evidence::canonical(&artifact["artifact_id"], 64, false) {
        artifact["artifact_id"].clone()
    } else {
        json!("0")
    };
    let hash = artifact["sha256"]
        .as_str()
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    json!({"artifact_id":id,"artifact_sha256":hash,"runtime":match artifact["kind"].as_str() {Some("javascript")=>"javascript",Some("wasm")=>"webassembly",_=>"unknown"},"status":"failed","error":{"code":"invalid-artifact-manifest","message":format!("Artifact manifest line {line}: {reason}")},"coverage":{"complete":false,"omissions":[omission]}})
}

/// The manifest's second pass: each valid JavaScript or Wasm record, the
/// first with its ID, in manifest order, up to the first pass's length.
pub(super) fn analyzed_artifacts(
    path: &Path,
    length: u64,
    mut each: impl FnMut(Value) -> Result<()>,
) -> Result<()> {
    let mut seen = HashSet::new();
    scan(path, *MANIFEST_LINE_BYTES, Some(length), |line| {
        let Some(value) = line
            .bytes
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        else {
            return Ok(());
        };
        let artifact = match manifest_record(value) {
            Record::Analyzed(artifact) => artifact,
            Record::Snapshot(artifact) => {
                seen.insert(artifact["artifact_id"].as_str().unwrap_or("").to_owned());
                return Ok(());
            }
            Record::Invalid(..) => return Ok(()),
        };
        if seen.insert(artifact["artifact_id"].as_str().unwrap_or("").to_owned()) {
            each(artifact)?;
        }
        Ok(())
    })?;
    Ok(())
}

/// The event store as the analysis reads it.
pub(super) struct Events {
    /// VM records, artifact captures and host events naming an artifact and
    /// a parent, in store order, each identity once.
    pub records: Vec<(usize, Value)>,
    /// Gap markers, which share the preceding record's identity.
    pub gaps: Vec<Value>,
    /// The records an exact request link follows: captures, the response
    /// records network response artifacts name, and their request starts.
    pub links: Vec<Value>,
    pub runtime: Runtime,
    pub omissions: Omissions,
    pub modes: BTreeSet<&'static str>,
    pub digest: String,
}

type Identity = (u64, u32, u64);

fn identity(reference: &(String, u32, String)) -> Option<Identity> {
    Some((
        reference.0.parse().ok()?,
        reference.1,
        reference.2.parse().ok()?,
    ))
}

fn line_hash(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// Whether the event is a contract-valid record the analysis can read.
fn contract(event: &Value) -> Option<(String, u32, String)> {
    let reference = if event["type"] == "vm_dispatch_report" {
        crate::vm_dispatch_input::report_reference(event)
    } else {
        event_reference(event)
    };
    (reference.is_some()
        && matches!(event["protocol_version"].as_u64(), Some(2 | 3))
        && ["navigation_id", "frame_id"]
            .iter()
            .all(|k| evidence::canonical(&event[k], 64, false))
        && ["category", "type"].iter().all(|k| event[k].is_string())
        && !["artifact_id", "request_id"].iter().any(|k| {
            event
                .get(k)
                .is_some_and(|v| !evidence::canonical(v, 64, false))
        }))
    .then_some(reference)
    .flatten()
}

/// Kept whole: VM records. Kept without their payload: captures, and host
/// events naming an artifact whose direct parent is an earlier VM record,
/// the only host events a dispatch sample can position. Every other host
/// event is counted by `Runtime`.
fn retained(event: &Value, vm: &HashSet<Identity>) -> Option<bool> {
    if event["category"] == "vm" {
        return Some(true);
    }
    let capture = event["category"] == "artifact" && event["type"] == "artifact_captured";
    let positioned = crate::vm_host_links::host_event(event)
        && event["artifact_id"].as_str().is_some_and(|id| id != "0")
        && parent(event).is_some_and(|parent| vm.contains(&parent));
    (capture || positioned).then_some(false)
}

fn parent(event: &Value) -> Option<Identity> {
    Some((
        event["session_id"].as_str()?.parse().ok()?,
        u32::try_from(event["process_id"].as_u64()?).ok()?,
        event["parent_event_id"].as_str()?.parse().ok()?,
    ))
}

fn without_payload(mut event: Value) -> Value {
    if let Some(object) = event.as_object_mut() {
        object.remove("payload");
    }
    event
}

pub(super) fn events(
    path: &Path,
    provenance: &Provenance,
    creators: &HashSet<(String, String)>,
) -> Result<Events> {
    let mut input = Events {
        records: Vec::new(),
        gaps: Vec::new(),
        links: Vec::new(),
        runtime: Runtime::default(),
        omissions: Omissions::default(),
        modes: BTreeSet::new(),
        digest: hex::encode(Sha256::digest([])),
    };
    // Each identity the analysis reads, by the hash of its first line, and
    // where its kept record sits. A different line with the same identity
    // tombstones both, as identical redelivery is idempotent.
    let mut identities = HashMap::<Identity, (u64, Option<usize>)>::new();
    let mut tombstones = HashSet::<Identity>::new();
    let mut records = Vec::<Option<(usize, Value)>>::new();
    let mut responses = Vec::<Option<Value>>::new();
    let mut response_at = HashMap::<Identity, usize>::new();
    // Request starts by (session, process, request): their identities and
    // byte ranges, read back only for the requests a response names.
    let mut starts = HashMap::<(u64, u32, u64), Vec<(Identity, u64, u64)>>::new();
    // VM record identities, the parents a retained host event names.
    let mut vm = HashSet::<Identity>::new();
    let scanned = scan(path, *EVENT_LINE_BYTES, None, |line| {
        let Some(bytes) = line.bytes else {
            input
                .omissions
                .add("event-line-byte-limit", Some(line.number));
            return Ok(());
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let Ok(event) = serde_json::from_slice::<Value>(bytes) else {
            input.omissions.add("malformed-event", Some(line.number));
            return Ok(());
        };
        input.modes.insert(provenance.mode(&event["session_id"]));
        let Some(reference) = contract(&event) else {
            input
                .omissions
                .add("invalid-event-contract", Some(line.number));
            return Ok(());
        };
        // Transport gap markers reuse the preceding retained event's
        // sequence. They are coverage evidence, not conflicting events.
        if event["type"] == "gap" {
            input.gaps.push(event);
            return Ok(());
        }
        let keep = retained(&event, &vm);
        let start = event["category"] == "network" && event["type"] == "request_started";
        let response = event["category"] == "network"
            && event["type"] == "response_started"
            && event["session_id"]
                .as_str()
                .zip(event["sequence_number"].as_str())
                .is_some_and(|(s, q)| creators.contains(&(s.to_owned(), q.to_owned())));
        if keep.is_none() && !start && !response && !Runtime::reads(&event) {
            return Ok(());
        }
        let Some(key) = identity(&reference) else {
            return Ok(());
        };
        let hash = line_hash(bytes);
        match identities.get(&key) {
            Some((known, _)) if *known == hash => return Ok(()),
            Some(_) => {
                tombstones.insert(key);
                input
                    .omissions
                    .add("conflicting-event-identity", Some(line.number));
                return Ok(());
            }
            None => {}
        }
        let mut at = None;
        if let Some(whole) = keep {
            at = Some(records.len());
            records.push(Some((
                line.number,
                if whole {
                    event.clone()
                } else {
                    without_payload(event.clone())
                },
            )));
        }
        identities.insert(key, (hash, at));
        if event["category"] == "vm" {
            vm.insert(key);
        }
        if start && let Some(request) = event["request_id"].as_str().and_then(|r| r.parse().ok()) {
            starts
                .entry((key.0, key.1, request))
                .or_default()
                .push((key, line.start, line.end));
        }
        if response {
            response_at.insert(key, responses.len());
            responses.push(Some(without_payload(event.clone())));
        }
        input.runtime.fold(&event);
        Ok(())
    })?;
    let Some((digest, length)) = scanned else {
        return Ok(input);
    };
    input.digest = digest;
    for key in &tombstones {
        if let Some((_, Some(at))) = identities.get(key) {
            records[*at] = None;
        }
        if let Some(at) = response_at.get(key) {
            responses[*at] = None;
        }
    }
    if !tombstones.is_empty() {
        // A record folded before its conflict arrived is taken back out by
        // folding the store again without any tombstoned identity.
        input.runtime = Runtime::default();
        let mut folded = HashSet::<Identity>::new();
        scan(path, *EVENT_LINE_BYTES, Some(length), |line| {
            let Some(event) = line
                .bytes
                .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            else {
                return Ok(());
            };
            if event["type"] == "gap" || !Runtime::reads(&event) {
                return Ok(());
            }
            if let Some(key) = contract(&event).as_ref().and_then(identity)
                && !tombstones.contains(&key)
                && folded.insert(key)
            {
                input.runtime.fold(&event);
            }
            Ok(())
        })?;
    }
    input.records = records.into_iter().flatten().collect();
    let responses = responses.into_iter().flatten().collect::<Vec<_>>();
    // Each response's request starts, read back by byte range.
    let mut file = evidence::regular_file(path)?;
    let mut wanted = BTreeSet::new();
    for response in &responses {
        if let (Some(reference), Some(request)) = (
            event_reference(response),
            response["request_id"]
                .as_str()
                .and_then(|r| r.parse::<u64>().ok()),
        ) && let Some(key) = identity(&reference)
        {
            wanted.insert((key.0, key.1, request));
        }
    }
    let mut links = input
        .records
        .iter()
        .filter(|(_, event)| event["type"] == "artifact_captured")
        .map(|(_, event)| event.clone())
        .collect::<Vec<_>>();
    links.extend(responses);
    for request in wanted {
        for (key, start, end) in starts.get(&request).into_iter().flatten() {
            if tombstones.contains(key) {
                continue;
            }
            if let Ok(event) = serde_json::from_slice::<Value>(&read_line(&mut file, *start, *end)?)
            {
                links.push(without_payload(event));
            }
        }
    }
    input.links = links;
    Ok(input)
}
