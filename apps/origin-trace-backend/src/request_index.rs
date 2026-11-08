//! Session-wide request index for Traffic; contract in protocol/request-index-v1.md.
use crate::{
    app::{Query, validate_event},
    durable,
    error::{Error, Result},
    event_window::unsigned,
    evidence,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::LazyLock,
    time::{Duration, Instant},
};

pub const SIDECAR_SUFFIX: &str = ".requests-v1";
const FORMAT: &str = "reb-request-index-v1";
/// Bounds one call; a larger store reports partial coverage and continues next call.
const SCAN_BYTES: u64 = 64 * 1024 * 1024;
const RECORD_BYTES: usize = 4096;
const ANCHOR_BYTES: u64 = 4096;
pub const MAX_REQUESTS: usize = 131_072;
const MAX_KEYS: usize = 4 * MAX_REQUESTS;
const MAX_MEMBERS: usize = 8;
const MAX_TARGETS: usize = 8;
const SIDECAR_BYTES: usize = 256 * 1024 * 1024;
pub const PERSIST_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 500;
const MAX_DOMAINS: usize = 512;
const TAB_DOMAINS: usize = 8;
const MAX_NAMED: usize = 64;
const MAX_LOCATE: usize = 4;
const MAX_TEXT: usize = 512;
const UNIDENTIFIED: &str = "Unidentified network event";

pub const QUERY_KEYS: [&str; 12] = [
    "limit", "offset", "through", "since", "sort", "order", "q", "tab_id", "domain", "type",
    "named", "locate",
];
const SORTS: [&str; 6] = ["capture", "name", "status", "type", "method", "time"];
const TYPES: [(&str, &str); 10] = [
    ("xhr", "Fetch/XHR"),
    ("doc", "Document"),
    ("css", "CSS"),
    ("js", "Script"),
    ("font", "Font"),
    ("img", "Image"),
    ("media", "Media"),
    ("socket", "WebSocket"),
    ("wasm", "Wasm"),
    ("other", "Other"),
];

static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:localhost|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::[0-9]{1,5})?$",
    )
    .expect("host pattern")
});

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Root {
    session: String,
    process: u32,
    sequence: String,
    request: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Member {
    session: String,
    process: u32,
    request: String,
    records: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Target {
    scheme: Option<String>,
    port: u16,
    length: u32,
    text: String,
}
/// First `request_target` child of a lifecycle record; `None` is malformed.
#[derive(Clone, Serialize, Deserialize)]
struct Child {
    parent: (String, u32, String),
    target: Option<Target>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Row {
    id: String,
    path: String,
    method: String,
    code: i64,
    rank: u8,
    status_rank: u8,
    target_rank: u8,
    target_event: Option<(String, u32, String)>,
    children: Vec<Child>,
    resource: String,
    tab: u64,
    operation: String,
    first_ns: u64,
    last_ns: u64,
    failed: bool,
    interrupted: bool,
    /// request_started, request_initiated, then any record with a request ID.
    roots: [Option<Root>; 3],
    members: Vec<Member>,
    members_limited: bool,
    first_offset: u64,
    end_offset: u64,
    records: u64,
}

#[derive(Serialize, Deserialize)]
struct State {
    format: String,
    epoch: String,
    identity: String,
    indexed_to: u64,
    head: String,
    tail: String,
    malformed: u64,
    unindexed: u64,
    rows: Vec<Row>,
    keys: HashMap<String, String>,
    #[serde(skip)]
    by_id: HashMap<String, u32>,
}
impl State {
    fn empty(identity: String) -> Self {
        let seed = format!(
            "{}:{identity}:{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        );
        Self {
            format: FORMAT.into(),
            epoch: hex::encode(&Sha256::digest(seed)[..8]),
            identity,
            indexed_to: 0,
            head: digest(&[]),
            tail: digest(&[]),
            malformed: 0,
            unindexed: 0,
            rows: Vec::new(),
            keys: HashMap::new(),
            by_id: HashMap::new(),
        }
    }
}

struct View {
    path: String,
    target_kind: &'static str,
    host: Option<String>,
    target: Option<String>,
    url_truncated: bool,
    target_length: Option<u32>,
    target_malformed: bool,
    status: Value,
    domain: String,
    haystack: String,
    name: String,
    method: String,
}

pub struct RequestIndex {
    store: PathBuf,
    sidecar: PathBuf,
    state: Option<State>,
    views: Vec<View>,
    generation: u64,
    reopened: bool,
    loaded: bool,
    changed: bool,
    persisted_at: Option<Instant>,
    persist_error: Option<String>,
    store_end: u64,
    order: Option<(String, u64, Vec<u32>)>,
}

pub enum Answer {
    Unchanged(String),
    Document(Value, String),
}

pub struct RequestQuery {
    limit: usize,
    offset: usize,
    through: Option<usize>,
    since: Option<usize>,
    sort: &'static str,
    descending: bool,
    needle: String,
    tab: Option<u64>,
    domain: Option<String>,
    kind: Option<&'static str>,
    named: Vec<(String, u32, String)>,
    locate: Vec<String>,
    raw: String,
}
impl RequestQuery {
    pub fn parse(q: &Query, raw: &str) -> Result<Self> {
        q.only(&QUERY_KEYS, &[])?;
        let count = |key: &str| -> Result<Option<usize>> {
            q.one(key)?
                .map(|_| q.number(key, None, 64, false).map(|n| n as usize))
                .transpose()
        };
        let text = |key: &str| -> Result<Option<String>> {
            match q.one(key)? {
                Some(value) if value.chars().count() > MAX_TEXT => Err(Error::bad(format!(
                    "{key} is longer than {MAX_TEXT} characters"
                ))),
                value => Ok(value.map(str::to_owned)),
            }
        };
        let sort =
            match q.one("sort")? {
                None => "capture",
                Some(value) => SORTS.iter().copied().find(|s| *s == value).ok_or_else(|| {
                    Error::bad(format!("sort must be one of {}", SORTS.join(", ")))
                })?,
            };
        let descending = match q.one("order")? {
            None | Some("asc") => false,
            Some("desc") => true,
            Some(_) => return Err(Error::bad("order must be asc or desc")),
        };
        let tab = match q.one("tab_id")? {
            None => None,
            Some("unattributed") => Some(0),
            Some(_) => Some(q.number("tab_id", None, 32, true)?),
        };
        let kind = match q.one("type")? {
            None => None,
            Some(value) => Some(
                TYPES
                    .iter()
                    .find(|(id, _)| *id == value)
                    .map(|t| t.0)
                    .ok_or_else(|| {
                        Error::bad("type must be a Traffic resource type such as xhr, doc or wasm")
                    })?,
            ),
        };
        let mut named = Vec::new();
        if let Some(list) = q.one("named")? {
            for item in list.split(',') {
                let parts = item.split(':').collect::<Vec<_>>();
                let valid = |text: &str, bits| {
                    crate::validation::canonical(&json!(text), bits, true, "named").is_ok()
                };
                if named.len() == MAX_NAMED
                    || parts.len() != 3
                    || !valid(parts[0], 64)
                    || !valid(parts[1], 32)
                    || !valid(parts[2], 64)
                {
                    return Err(Error::bad(format!(
                        "named lists 1 to {MAX_NAMED} session:process:sequence root events"
                    )));
                }
                named.push((parts[0].into(), parts[1].parse().unwrap(), parts[2].into()));
            }
        }
        Ok(Self {
            limit: q.limit(DEFAULT_PAGE, MAX_PAGE)?,
            offset: count("offset")?.unwrap_or(0),
            through: count("through")?,
            since: count("since")?,
            sort,
            descending,
            needle: text("q")?.unwrap_or_default().trim().to_lowercase(),
            tab,
            domain: text("domain")?,
            kind,
            named,
            locate: match text("locate")? {
                None => Vec::new(),
                Some(list) => {
                    let ids = list.split(',').map(str::to_owned).collect::<Vec<_>>();
                    if ids.len() > MAX_LOCATE || ids.iter().any(String::is_empty) {
                        return Err(Error::bad(format!(
                            "locate lists 1 to {MAX_LOCATE} request IDs"
                        )));
                    }
                    ids
                }
            },
            raw: raw.into(),
        })
    }
    fn order_key(&self, through: usize) -> String {
        format!(
            "{}:{}:{}:{:?}:{:?}:{:?}:{:?}:{through}",
            self.sort, self.descending, self.needle, self.tab, self.domain, self.kind, self.named
        )
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}
fn number(value: &Value) -> i64 {
    value.as_i64().unwrap_or(0)
}
fn identity_of(metadata: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!("{}:{}", metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        format!("{:?}", metadata.created().ok())
    }
}
fn read_range(file: &mut File, start: u64, end: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0; (end - start) as usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn anchors(file: &mut File, end: u64) -> Result<(String, String)> {
    let head = read_range(file, 0, end.min(ANCHOR_BYTES))?;
    let tail = read_range(file, end.saturating_sub(ANCHOR_BYTES), end)?;
    Ok((digest(&head), digest(&tail)))
}

// Matches TextDecoder (drops a leading BOM) and JavaScript's whitespace set.
fn payload_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned()
}
fn js_space(c: char) -> bool {
    (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}'
}
fn rank(kind: &str) -> Option<u8> {
    Some(match kind {
        "request_initiated" => 1,
        "request_started" => 2,
        "request_redirected" => 3,
        "response_started" => 4,
        "response_completed" | "request_completed" | "request_failed" => 5,
        _ => return None,
    })
}
fn resource(code: i64) -> &'static str {
    match code {
        0 | 1 | 19 | 20 => "doc",
        2 => "css",
        3 => "js",
        4 => "img",
        5 => "font",
        8 => "media",
        11 | 13 => "xhr",
        _ => "other",
    }
}
/// Port of `networkTargetFromPayload`.
fn network_target(payload: &str, kind: &str) -> Option<(Option<String>, String)> {
    let source = payload.trim_matches(js_space);
    if source.is_empty() {
        return None;
    }
    let token =
        |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || "!#$%&'*+.^_`|~-".contains(c);
    if matches!(
        kind,
        "request_initiated" | "request_started" | "request_redirected"
    ) && source.starts_with(|c: char| c.is_ascii_uppercase())
    {
        let method_end = source.find(|c| !token(c)).unwrap_or(source.len());
        let rest = &source[method_end..];
        let value = rest.trim_start_matches(js_space);
        if method_end <= 32
            && value.len() < rest.len()
            && !value.is_empty()
            && !value.contains(js_space)
        {
            return Some((Some(source[..method_end].into()), value.into()));
        }
    }
    HOST.is_match(source).then(|| (None, source.into()))
}
fn context_token(event: &Value) -> Option<String> {
    let (high, low) = (
        &event["browser_context_id_high"],
        &event["browser_context_id_low"],
    );
    if high.is_null() || low.is_null() || (high == "0" && low == "0") {
        return None;
    }
    Some(format!("{}:{}", text(high), text(low)))
}
fn legacy_key(event: &Value) -> Option<String> {
    let (session, request) = (text(&event["session_id"]), text(&event["request_id"]));
    if request == "0" {
        return None;
    }
    let initiator = number(&event["initiator_process_id"]);
    Some(if initiator > 0 {
        format!("S{session}:R{initiator}:B{request}")
    } else {
        format!(
            "S{session}:P{}:F{}:B{request}",
            number(&event["process_id"]),
            text(&event["frame_id"])
        )
    })
}
fn browser_key(event: &Value) -> Option<String> {
    let (session, request) = (text(&event["session_id"]), text(&event["request_id"]));
    if request == "0" {
        return None;
    }
    match context_token(event) {
        Some(context) => Some(format!(
            "S{session}:P{}:C{context}:B{request}",
            number(&event["process_id"])
        )),
        None => legacy_key(event),
    }
}
fn renderer_identity(event: &Value) -> String {
    format!(
        "S{}:R{}:{}",
        text(&event["session_id"]),
        number(&event["process_id"]),
        text(&event["request_id"])
    )
}
fn correlated_identity(event: &Value) -> String {
    format!(
        "S{}:R{}:{}",
        text(&event["session_id"]),
        number(&event["initiator_process_id"]),
        number(&event["initiator_request_id"])
    )
}
/// Port of `requestIdentity` over the browser keys learned so far.
fn request_identity(event: &Value, keys: &HashMap<String, String>) -> String {
    if event["type"] == "request_initiated" {
        return renderer_identity(event);
    }
    let request = text(&event["request_id"]);
    let correlated = if number(&event["initiator_process_id"]) > 0 {
        correlated_identity(event)
    } else if request != "0" {
        browser_key(event).expect("nonzero request")
    } else {
        format!(
            "S{}:P{}:E{}",
            text(&event["session_id"]),
            number(&event["process_id"]),
            text(&event["sequence_number"])
        )
    };
    browser_key(event)
        .and_then(|key| keys.get(&key).cloned())
        .unwrap_or(correlated)
}
fn learn_keys(event: &Value, keys: &mut HashMap<String, String>) {
    if text(&event["request_id"]) == "0" || keys.len() >= MAX_KEYS {
        return;
    }
    if event["type"] == "request_initiated" {
        if let Some(key) = legacy_key(event) {
            keys.insert(key, renderer_identity(event));
        }
        return;
    }
    if number(&event["initiator_process_id"]) == 0 {
        return;
    }
    let identity = correlated_identity(event);
    for key in [browser_key(event), legacy_key(event)]
        .into_iter()
        .flatten()
    {
        keys.entry(key).or_insert_with(|| identity.clone());
    }
}
fn canonical(value: &Value, nonzero: bool) -> Option<u64> {
    value
        .as_str()
        .and_then(|_| crate::validation::canonical(value, 64, nonzero, "").ok())
}
/// Port of `decodeRequestTargetRecord`.
fn decode_target(event: &Value) -> Option<Target> {
    let payload = event["payload"].as_str()?;
    let (sequence, parent) = (
        canonical(&event["sequence_number"], true)?,
        canonical(&event["parent_event_id"], true)?,
    );
    let process = event["process_id"].as_u64()?;
    if event["protocol_version"] != 3
        || event["flags"] != 0
        || event["payload_truncated"] != false
        || event["payload_size"] != 128
        || payload.len() != 256
        || canonical(&event["session_id"], true).is_none()
        || parent >= sequence
        || !(1..=u64::from(u32::MAX)).contains(&process)
        || event["navigation_id"] != "0"
        || event["status_code"] != 0
        || event["error_code"] != 0
        || event["encoded_data_length"] != "0"
        || event["decoded_body_length"] != "0"
        || event["resource_type"] != 0
        || event["artifact_id"] != "0"
    {
        return None;
    }
    let bytes = hex::decode(payload).ok()?;
    let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let length = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let prefix = 12 + (length as usize).min(116);
    if u16_at(0) != 1
        || u16_at(2) != 128
        || bytes[8] > 4
        || bytes[9] != 0
        || bytes[12..prefix].contains(&0)
        || bytes[prefix..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    Some(Target {
        scheme: [None, Some("http"), Some("https"), Some("ws"), Some("wss")][bytes[8] as usize]
            .map(str::to_owned),
        port: u16_at(10),
        length,
        text: payload_text(&bytes[12..prefix]),
    })
}
/// Port of `trafficRequestDomain`.
fn domain(path: &str) -> String {
    let target = path.trim_matches(js_space);
    if target.is_empty() || target == UNIDENTIFIED {
        return "unknown".into();
    }
    match url::Url::parse(target) {
        Ok(url) => match url.host_str() {
            Some(host) if !host.is_empty() => match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.into(),
            },
            _ => "unknown".into(),
        },
        Err(_) => {
            let first = target
                .strip_prefix("//")
                .unwrap_or(target)
                .split('/')
                .next()
                .unwrap_or("");
            if first.is_empty() {
                "unknown".into()
            } else {
                first.into()
            }
        }
    }
}
fn view(row: &Row) -> View {
    let mut path = row.path.clone();
    let mut target_kind = if row.target_event.is_some() {
        "host"
    } else {
        "unknown"
    };
    let (mut host, mut target, mut url_truncated, mut target_length) = (None, None, false, None);
    let child = row
        .target_event
        .as_ref()
        .and_then(|parent| row.children.iter().find(|child| child.parent == *parent));
    let target_malformed = child.is_some_and(|child| child.target.is_none());
    if let (Some(found), "host") = (child.and_then(|child| child.target.as_ref()), target_kind) {
        let base = path.clone();
        let port = if found.port != 0 {
            format!(":{}", found.port)
        } else {
            String::new()
        };
        host = Some(format!("{base}{port}"));
        path = match &found.scheme {
            Some(scheme) => format!("{scheme}://{base}{port}{}", found.text),
            None => format!("{base}{}", found.text),
        };
        target_kind = if found.scheme.is_some() {
            "url"
        } else {
            "path"
        };
        target = Some(found.text.clone());
        url_truncated = found.length > 116;
        target_length = Some(found.length);
    }
    let status = if row.failed {
        json!("failed")
    } else if row.interrupted {
        json!("incomplete")
    } else if row.code > 0 {
        json!(row.code)
    } else {
        json!("pending")
    };
    let trimmed = path.trim_matches(js_space);
    let more = if url_truncated { "…" } else { "" };
    let name = if target_kind == "host" {
        if trimmed.is_empty() {
            "Unknown host".into()
        } else {
            trimmed.into()
        }
    } else if let Some(target) = &target {
        format!("{target}{more}")
    } else {
        match url::Url::parse(trimmed) {
            Ok(url) if ["http", "https", "ws", "wss"].contains(&url.scheme()) => format!(
                "{}{}{more}",
                url.path(),
                url.query()
                    .filter(|q| !q.is_empty())
                    .map(|q| format!("?{q}"))
                    .unwrap_or_default()
            ),
            _ if trimmed.is_empty() => "Unidentified request".into(),
            _ => trimmed.into(),
        }
    };
    View {
        haystack: format!("{} {path} {}", row.method, text(&status)).to_lowercase(),
        domain: domain(&path),
        name,
        method: row.method.clone(),
        path,
        target_kind,
        host,
        target,
        url_truncated,
        target_length,
        target_malformed,
        status,
    }
}
fn duration(row: &Row) -> Option<u64> {
    (row.rank >= 5).then(|| row.last_ns.saturating_sub(row.first_ns))
}
fn milliseconds(nanoseconds: u64) -> String {
    format!(
        "{}.{:03} ms",
        nanoseconds / 1_000_000,
        nanoseconds % 1_000_000 / 1000
    )
}
fn type_label(kind: &str) -> &'static str {
    TYPES
        .iter()
        .find(|(id, _)| *id == kind)
        .map_or("Other", |t| t.1)
}
// Locale collation stand-in: case-folded first, then exact text.
fn compare_text(left: &str, right: &str) -> Ordering {
    left.to_lowercase()
        .cmp(&right.to_lowercase())
        .then_with(|| left.cmp(right))
}

impl RequestIndex {
    pub fn new(store: &Path) -> Self {
        let mut name = store.file_name().unwrap_or_default().to_os_string();
        name.push(SIDECAR_SUFFIX);
        Self {
            store: store.to_owned(),
            sidecar: store.with_file_name(name),
            state: None,
            views: Vec::new(),
            generation: 0,
            reopened: false,
            loaded: false,
            changed: false,
            persisted_at: None,
            persist_error: None,
            store_end: 0,
            order: None,
        }
    }

    /// Removes the derived copy before a capture clear empties the store.
    pub fn discard(&mut self) -> Result<()> {
        self.reset(None);
        self.loaded = true;
        match std::fs::remove_file(&self.sidecar) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    fn reset(&mut self, state: Option<State>) {
        self.views = state
            .as_ref()
            .map_or_else(Vec::new, |state| state.rows.iter().map(view).collect());
        self.state = state;
        self.generation += 1;
        self.order = None;
        self.changed = false;
    }

    fn load_sidecar(&mut self) -> Option<State> {
        let bytes = durable::read_private(&self.sidecar, SIDECAR_BYTES).ok()??;
        let mut state: State = serde_json::from_slice(&bytes).ok()?;
        if state.format != FORMAT || state.rows.len() > MAX_REQUESTS {
            return None;
        }
        for (ordinal, row) in state.rows.iter().enumerate() {
            if state.by_id.insert(row.id.clone(), ordinal as u32).is_some() {
                return None;
            }
        }
        Some(state)
    }

    fn persist(&mut self) {
        let Some(state) = &self.state else { return };
        let result = serde_json::to_vec(state)
            .map_err(|error| Error::new(500, error.to_string()))
            .and_then(|bytes| durable::write_private(&self.sidecar, &bytes));
        self.persist_error = result.err().map(|error| error.message);
        self.persisted_at = Some(Instant::now());
        self.changed = false;
    }

    /// The backend's own schedule; reads never write the sidecar.
    pub fn maintain(&mut self) -> Result<()> {
        self.refresh()?;
        if self.changed {
            self.persist();
        }
        Ok(())
    }

    /// A rewritten or replaced store rebuilds from byte 0.
    pub fn refresh(&mut self) -> Result<()> {
        let mut file = match evidence::regular_file(&self.store) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if self
                    .state
                    .as_ref()
                    .is_none_or(|state| state.indexed_to > 0 || !state.rows.is_empty())
                {
                    self.reset(Some(State::empty(String::new())));
                }
                self.store_end = 0;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        let identity = identity_of(&metadata);
        let end = metadata.len();
        if !self.loaded {
            self.loaded = true;
            let state = self.load_sidecar();
            self.reopened = state.is_some();
            self.reset(state);
        }
        let valid = match &self.state {
            Some(state) => {
                state.identity == identity
                    && state.indexed_to <= end
                    && anchors(&mut file, state.indexed_to)?
                        == (state.head.clone(), state.tail.clone())
            }
            None => false,
        };
        if !valid {
            self.reopened = false;
            self.reset(Some(State::empty(identity)));
        }
        self.store_end = end;
        let from = self.state.as_ref().expect("index state").indexed_to;
        let limit = end.min(from + SCAN_BYTES);
        if limit == from {
            return Ok(());
        }
        let bytes = read_range(&mut file, from, limit)?;
        let Some(last) = bytes.iter().rposition(|byte| *byte == b'\n') else {
            if bytes.len() > RECORD_BYTES {
                return Err(Error::new(
                    500,
                    "The evidence store contains an oversized event",
                ));
            }
            return Ok(());
        };
        let mut position = 0;
        while position <= last {
            let newline = position
                + bytes[position..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .expect("terminated");
            self.fold(
                &bytes[position..newline],
                from + position as u64,
                from + newline as u64 + 1,
            );
            position = newline + 1;
        }
        let indexed_to = from + last as u64 + 1;
        let (head, tail) = anchors(&mut file, indexed_to)?;
        let state = self.state.as_mut().expect("index state");
        (state.indexed_to, state.head, state.tail) = (indexed_to, head, tail);
        self.generation += 1;
        self.order = None;
        self.changed = true;
        Ok(())
    }

    fn fold(&mut self, line: &[u8], start: u64, end: u64) {
        let state = self.state.as_mut().expect("index state");
        if line.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        // Only a network record names its category in its bytes.
        if line.len() <= RECORD_BYTES && !line.windows(7).any(|window| window == b"network") {
            return;
        }
        let event = match serde_json::from_slice::<Value>(line) {
            Ok(event) if line.len() <= RECORD_BYTES && validate_event(&event).is_ok() => event,
            _ => {
                state.malformed += 1;
                return;
            }
        };
        let kind = event["type"].as_str().unwrap_or("");
        if event["category"] != "network" {
            return;
        }
        let Some(incoming) = rank(kind) else {
            if kind == "request_target" || kind == "request_body" {
                let id = request_identity(&event, &state.keys);
                if let Some(&ordinal) = state.by_id.get(&id) {
                    let row = &mut state.rows[ordinal as usize];
                    Self::member(row, &event, start, end);
                    let parent = (
                        text(&event["session_id"]),
                        number(&event["process_id"]) as u32,
                        text(&event["parent_event_id"]),
                    );
                    if kind == "request_target"
                        && row.children.len() < MAX_TARGETS
                        && !row.children.iter().any(|child| child.parent == parent)
                    {
                        row.children.push(Child {
                            parent,
                            target: decode_target(&event),
                        });
                    }
                    self.views[ordinal as usize] = view(row);
                }
            }
            return;
        };
        learn_keys(&event, &mut state.keys);
        let id = request_identity(&event, &state.keys);
        let ordinal = match state.by_id.get(&id) {
            Some(&ordinal) => ordinal,
            None if state.rows.len() >= MAX_REQUESTS => {
                state.unindexed += 1;
                return;
            }
            None => {
                let ordinal = state.rows.len() as u32;
                state.by_id.insert(id.clone(), ordinal);
                state.rows.push(Row {
                    id,
                    path: UNIDENTIFIED.into(),
                    method: "EVENT".into(),
                    code: 0,
                    rank: 0,
                    status_rank: 0,
                    target_rank: 0,
                    target_event: None,
                    children: Vec::new(),
                    resource: "other".into(),
                    tab: 0,
                    operation: kind.into(),
                    first_ns: u64::MAX,
                    last_ns: 0,
                    failed: false,
                    interrupted: false,
                    roots: [None, None, None],
                    members: Vec::new(),
                    members_limited: false,
                    first_offset: start,
                    end_offset: end,
                    records: 0,
                });
                self.views.push(view(state.rows.last().unwrap()));
                ordinal
            }
        };
        let row = &mut state.rows[ordinal as usize];
        let payload =
            payload_text(&hex::decode(event["payload"].as_str().unwrap_or("")).unwrap_or_default());
        let target = network_target(&payload, kind);
        let version = event["protocol_version"].as_u64().unwrap_or(0);
        let time = unsigned(&event["monotonic_time_ns"]).unwrap_or(0);
        row.first_ns = row.first_ns.min(time);
        row.last_ns = row.last_ns.max(time);
        let interruption = version >= 3
            && kind == "request_failed"
            && number(&event["error_code"]) == -3
            && ["proxy_destroyed", "redirect_handoff"].contains(&payload.as_str());
        row.failed |= !interruption
            && (kind == "request_failed" || (version >= 2 && number(&event["error_code"]) != 0));
        row.interrupted |= interruption;
        let code = if version >= 2 {
            number(&event["status_code"])
        } else {
            0
        };
        if code > 0 && incoming >= row.status_rank {
            row.code = code;
            row.status_rank = incoming;
        }
        if let Some((method, value)) = target.filter(|_| incoming >= row.target_rank) {
            row.target_rank = incoming;
            row.path = value;
            if let Some(method) = method {
                row.method = method;
            }
            row.target_event = Some((
                text(&event["session_id"]),
                number(&event["process_id"]) as u32,
                text(&event["sequence_number"]),
            ));
        }
        let lower = payload.to_ascii_lowercase();
        if lower
            .strip_prefix("application/wasm")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(';'))
        {
            row.resource = "wasm".into();
        } else if version >= 2 && kind == "request_started" {
            row.resource = resource(number(&event["resource_type"])).into();
        }
        if incoming >= row.rank {
            row.operation = kind.into();
        }
        row.rank = row.rank.max(incoming);
        if version == 3 && number(&event["tab_id"]) > 0 {
            row.tab = number(&event["tab_id"]) as u64;
        }
        let request = text(&event["request_id"]);
        if request != "0" {
            let root = Root {
                session: text(&event["session_id"]),
                process: number(&event["process_id"]) as u32,
                sequence: text(&event["sequence_number"]),
                request,
            };
            let slot = match kind {
                "request_started" => Some(0),
                "request_initiated" => Some(1),
                _ => None,
            };
            if let Some(slot) = slot {
                row.roots[slot].get_or_insert_with(|| root.clone());
            }
            row.roots[2].get_or_insert(root);
        }
        Self::member(row, &event, start, end);
        self.views[ordinal as usize] = view(row);
    }

    fn member(row: &mut Row, event: &Value, start: u64, end: u64) {
        row.first_offset = row.first_offset.min(start);
        row.end_offset = row.end_offset.max(end);
        row.records += 1;
        let (session, process, request) = (
            text(&event["session_id"]),
            number(&event["process_id"]) as u32,
            text(&event["request_id"]),
        );
        let found = row
            .members
            .iter()
            .position(|m| m.session == session && m.process == process && m.request == request);
        match found {
            Some(index) => row.members[index].records += 1,
            None if row.members.len() < MAX_MEMBERS => row.members.push(Member {
                session,
                process,
                request,
                records: 1,
            }),
            None => row.members_limited = true,
        }
    }

    fn matches(&self, query: &RequestQuery, ordinal: usize, search: bool) -> bool {
        let (row, view) = (
            &self.state.as_ref().unwrap().rows[ordinal],
            &self.views[ordinal],
        );
        query.tab.is_none_or(|tab| row.tab == tab)
            && query
                .domain
                .as_ref()
                .is_none_or(|domain| view.domain == *domain)
            && query.kind.is_none_or(|kind| row.resource == kind)
            && (!search
                || query.needle.is_empty()
                || view.haystack.contains(&query.needle)
                || Self::root(row).is_some_and(|root| {
                    query.named.iter().any(|(session, process, sequence)| {
                        root.session == *session
                            && root.process == *process
                            && root.sequence == *sequence
                    })
                }))
    }

    fn root(row: &Row) -> Option<&Root> {
        row.roots.iter().flatten().next()
    }

    fn ordered(&mut self, query: &RequestQuery, through: usize) -> &[u32] {
        let key = query.order_key(through);
        if self
            .order
            .as_ref()
            .is_none_or(|(cached, generation, _)| *cached != key || *generation != self.generation)
        {
            let mut order: Vec<u32> = (0..through)
                .filter(|&i| self.matches(query, i, true))
                .map(|i| i as u32)
                .collect();
            let rows = &self.state.as_ref().unwrap().rows;
            let views = &self.views;
            let direction = |ordering: Ordering| {
                if query.descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            };
            match query.sort {
                "capture" if query.descending => order.reverse(),
                "capture" => {}
                "time" | "status" => {
                    let value = |i: u32| {
                        let row = &rows[i as usize];
                        // Traffic compares the displayed microseconds.
                        if query.sort == "time" {
                            duration(row).map(|d| (d / 1000) as i64)
                        } else {
                            views[i as usize].status.as_i64()
                        }
                    };
                    order.sort_by(|&a, &b| match (value(a), value(b)) {
                        (Some(x), Some(y)) => direction(x.cmp(&y)).then(a.cmp(&b)),
                        (None, None) => a.cmp(&b),
                        (None, _) => Ordering::Greater,
                        (_, None) => Ordering::Less,
                    });
                }
                sort => {
                    let value = |i: u32| -> &str {
                        let (row, view) = (&rows[i as usize], &views[i as usize]);
                        match sort {
                            "name" => &view.name,
                            "type" => type_label(&row.resource),
                            _ => &view.method,
                        }
                    };
                    order.sort_by(|&a, &b| {
                        direction(compare_text(value(a), value(b))).then(a.cmp(&b))
                    });
                }
            }
            self.order = Some((key, self.generation, order));
        }
        &self.order.as_ref().unwrap().2
    }

    fn row_document(&self, ordinal: usize) -> Value {
        let (row, view) = (
            &self.state.as_ref().unwrap().rows[ordinal],
            &self.views[ordinal],
        );
        let member = |member: &Member| {
            json!({"session_id": member.session, "process_id": member.process,
            "request_id": member.request, "records": member.records})
        };
        json!({
            "id": row.id, "ordinal": ordinal, "method": row.method, "path": view.path,
            "target_kind": view.target_kind, "host": view.host, "target": view.target,
            "url_truncated": view.url_truncated, "target_length": view.target_length,
            "target_malformed": view.target_malformed, "status": view.status,
            "failed": row.failed, "interrupted": row.interrupted,
            "time": duration(row).map_or_else(|| "pending".to_owned(), milliseconds),
            "duration_ns": duration(row).map(|d| d.to_string()),
            "type": row.resource, "tab_id": row.tab.to_string(), "operation": row.operation,
            "first_time_ns": row.first_ns.to_string(), "last_time_ns": row.last_ns.to_string(),
            "domain": view.domain,
            "root": Self::root(row).map(|root| json!({"session_id": root.session, "process_id": root.process,
                "sequence_number": root.sequence, "request_id": root.request})),
            "members": row.members.iter().map(member).collect::<Vec<_>>(),
            "members_limited": row.members_limited,
            "first_offset": row.first_offset.to_string(), "end_offset": row.end_offset.to_string(),
            "records": row.records,
        })
    }

    fn facets(&self, query: &RequestQuery, through: usize) -> Value {
        let rows = &self.state.as_ref().unwrap().rows;
        let mut tabs: BTreeMap<u64, (u64, u64, Vec<String>, bool)> = BTreeMap::new();
        let mut domains: BTreeMap<&str, u64> = BTreeMap::new();
        for (row, view) in rows.iter().zip(&self.views).take(through) {
            let tab = tabs
                .entry(row.tab)
                .or_insert((0, row.first_ns, Vec::new(), false));
            tab.0 += 1;
            tab.1 = tab.1.min(row.first_ns);
            if !tab.2.contains(&view.domain) {
                if tab.2.len() < TAB_DOMAINS {
                    tab.2.push(view.domain.clone())
                } else {
                    tab.3 = true
                }
            }
            if query.tab.is_none_or(|tab| row.tab == tab) {
                *domains.entry(&view.domain).or_default() += 1;
            }
        }
        let mut tabs = tabs.into_iter().collect::<Vec<_>>();
        tabs.sort_by_key(|(tab, (_, first, _, _))| (*tab == 0, *first, *tab));
        let truncated = domains.len() > MAX_DOMAINS;
        let selected = query.domain.as_deref();
        let listed = domains
            .iter()
            .enumerate()
            .filter(|(index, (domain, _))| *index < MAX_DOMAINS || selected == Some(**domain))
            .map(|(_, (domain, count))| json!({"domain": domain, "count": count}))
            .collect::<Vec<_>>();
        json!({
            "tabs": tabs.iter().map(|(tab, (count, first, domains, more))| json!({"tab_id": tab.to_string(),
                "count": count, "first_time_ns": first.to_string(), "domains": domains, "domains_truncated": more}))
                .collect::<Vec<_>>(),
            "domains": listed,
            "domains_truncated": truncated,
        })
    }

    pub fn respond(&mut self, query: &RequestQuery, etag: Option<&str>) -> Result<Answer> {
        self.refresh()?;
        let store_end = self.store_end;
        let state = self.state.as_ref().expect("index state");
        let tag = format!(
            "\"{}\"",
            digest(
                format!(
                    "{}:{}:{}:{store_end}:{}",
                    state.epoch, self.generation, state.indexed_to, query.raw
                )
                .as_bytes()
            )
        );
        if etag == Some(tag.as_str()) {
            return Ok(Answer::Unchanged(tag));
        }
        let total = state.rows.len();
        let through = query.through.unwrap_or(total).min(total);
        let failed = (0..through).filter(|&i| state.rows[i].failed).count();
        let index = json!({
            "epoch": state.epoch, "indexed_end": state.indexed_to.to_string(), "store_end": store_end.to_string(),
            "complete": store_end.saturating_sub(state.indexed_to) <= RECORD_BYTES as u64,
            "malformed_records": state.malformed.to_string(), "unindexed_records": state.unindexed.to_string(),
            "request_limit": MAX_REQUESTS, "reopened": self.reopened,
            "persisted": self.persisted_at.is_some() && self.persist_error.is_none(), "persist_error": self.persist_error,
        });
        let facets = self.facets(query, through);
        let since = query.since;
        let order = self.ordered(query, through).to_vec();
        let page = order
            .iter()
            .skip(query.offset)
            .take(query.limit)
            .map(|&i| self.row_document(i as usize))
            .collect::<Vec<_>>();
        let rows = &self.state.as_ref().unwrap().rows;
        let mut document = json!({
            "format": FORMAT, "total": total, "matching": order.len(), "through": through,
            "offset": query.offset, "limit": query.limit, "returned": page.len(),
            "next_offset": (query.offset + page.len() < order.len()).then_some(query.offset + page.len()),
            "previous_offset": (query.offset > 0).then(|| query.offset.saturating_sub(query.limit)),
            "failed": failed, "facets": facets, "index": index,
            "query": {"sort": query.sort, "order": if query.descending { "desc" } else { "asc" }, "q": query.needle,
                "tab_id": query.tab.map(|tab| if tab == 0 { "unattributed".to_owned() } else { tab.to_string() }),
                "domain": query.domain, "type": query.kind, "named": query.named.len()},
            "requests": page,
        });
        if let Some(since) = since {
            document["added"] = json!(order.iter().filter(|&&i| i as usize >= since).count());
        }
        if !query.locate.is_empty() {
            let mut located = serde_json::Map::new();
            for id in &query.locate {
                located.insert(
                    id.clone(),
                    json!(order.iter().position(|&i| rows[i as usize].id == *id)),
                );
            }
            document["located"] = Value::Object(located);
        }
        Ok(Answer::Document(document, tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};

    struct Store {
        events: Vec<Value>,
        sequence: u64,
    }
    impl Store {
        fn push(
            &mut self,
            process: u64,
            request: u64,
            kind: &str,
            payload: &[u8],
            extra: Value,
        ) -> String {
            self.sequence += 1;
            let mut event = json!({"protocol_version":3,"session_id":"1","sequence_number":self.sequence.to_string(),
                "monotonic_time_ns":(1_000_000 * self.sequence).to_string(),"navigation_id":"0","frame_id":"9",
                "artifact_id":"0","parent_event_id":"0","request_id":request.to_string(),"process_id":process,
                "thread_id":1,"tab_id":0,"category":"network","type":kind,"flags":0,"status_code":0,"error_code":0,
                "encoded_data_length":"0","decoded_body_length":"0","resource_type":0,"initiator_process_id":0,
                "initiator_request_id":0,"payload_encoding":"hex","payload":hex::encode(payload),
                "payload_size":payload.len(),"payload_truncated":false});
            for (key, value) in extra.as_object().unwrap() {
                event[key] = value.clone();
            }
            self.events.push(event);
            self.sequence.to_string()
        }
        fn bytes(&self) -> Vec<u8> {
            self.events
                .iter()
                .flat_map(|event| {
                    let mut line = serde_json::to_vec(event).unwrap();
                    line.push(b'\n');
                    line
                })
                .collect()
        }
    }
    fn merge(mut base: Value, extra: Value) -> Value {
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        base
    }
    fn target(scheme: u8, port: u16, text: &[u8], length: u32) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        bytes[0..2].copy_from_slice(&1u16.to_le_bytes());
        bytes[2..4].copy_from_slice(&128u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&length.to_le_bytes());
        bytes[8] = scheme;
        bytes[10..12].copy_from_slice(&port.to_le_bytes());
        let prefix = text.len().min(116);
        bytes[12..12 + prefix].copy_from_slice(&text[..prefix]);
        bytes
    }
    /// The lifecycle shapes the Traffic model distinguishes, in one session.
    fn fixture() -> Store {
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        let context =
            json!({"tab_id": 3, "browser_context_id_high": "5", "browser_context_id_low": "6"});
        let joined = merge(
            context.clone(),
            json!({"initiator_process_id": 41, "initiator_request_id": 10}),
        );
        // A renderer initiation joined to its browser loader, with a target.
        store.push(
            41,
            10,
            "request_initiated",
            b"GET api.example.test",
            json!({}),
        );
        let start = store.push(
            7,
            900,
            "request_started",
            b"GET api.example.test",
            merge(joined.clone(), json!({"resource_type": 11})),
        );
        store.push(
            7,
            900,
            "request_target",
            &target(2, 8443, b"/v1/items?page=2", 16),
            merge(joined.clone(), json!({"parent_event_id": start})),
        );
        store.push(
            7,
            900,
            "response_started",
            b"application/json",
            merge(joined.clone(), json!({"status_code": 200})),
        );
        store.push(
            7,
            900,
            "request_completed",
            b"completed",
            merge(joined, json!({"status_code": 200})),
        );
        // A navigation whose redirect replaces the captured target.
        let start = store.push(
            7,
            901,
            "request_started",
            b"GET www.example.test",
            context.clone(),
        );
        store.push(
            7,
            901,
            "request_target",
            &target(1, 0, &[b'a'; 120], 300),
            merge(context.clone(), json!({"parent_event_id": start})),
        );
        store.push(
            7,
            901,
            "request_redirected",
            b"GET cdn.example.test",
            merge(context.clone(), json!({"status_code": 302})),
        );
        store.push(
            7,
            901,
            "response_started",
            b"application/wasm; charset=binary",
            merge(context, json!({"status_code": 200})),
        );
        // A failure, an observation that ended, and a malformed target child.
        store.push(
            7,
            902,
            "request_started",
            b"POST pay.example.test",
            json!({"resource_type": 13, "tab_id": 4}),
        );
        store.push(
            7,
            902,
            "request_failed",
            b"net::ERR_FAILED",
            json!({"error_code": -2, "tab_id": 4}),
        );
        store.push(
            7,
            903,
            "request_started",
            b"GET slow.example.test",
            json!({"resource_type": 3}),
        );
        store.push(
            7,
            903,
            "request_failed",
            b"proxy_destroyed",
            json!({"error_code": -3}),
        );
        let start = store.push(
            7,
            904,
            "request_started",
            b"GET localhost:8080",
            json!({"resource_type": 4}),
        );
        let mut broken = target(0, 0, b"/x", 2);
        broken[13] = 0;
        store.push(
            7,
            904,
            "request_target",
            &broken,
            json!({"parent_event_id": start}),
        );
        // No start, no request ID, a path target, a long target, an unknown payload.
        store.push(
            7,
            905,
            "response_started",
            b"text/css",
            json!({"status_code": 404}),
        );
        store.push(7, 0, "request_completed", b"completed", json!({}));
        let start = store.push(
            7,
            906,
            "request_started",
            b"PUT files.example.test",
            json!({"resource_type": 2}),
        );
        store.push(
            7,
            906,
            "request_target",
            &target(0, 0, b"/upload/1", 9),
            json!({"parent_event_id": start}),
        );
        store.push(
            7,
            906,
            "request_completed",
            b"completed",
            json!({"status_code": 201}),
        );
        let start = store.push(
            7,
            907,
            "request_started",
            b"GET long.example.test",
            json!({"resource_type": 3}),
        );
        store.push(
            7,
            907,
            "request_target",
            &target(2, 0, &[b'b'; 130], 400),
            json!({"parent_event_id": start}),
        );
        store.push(42, 11, "request_initiated", b"completed", json!({}));
        store
    }
    fn write(path: &Path, store: &Store) {
        fs::write(path, store.bytes()).unwrap();
    }
    fn page(index: &mut RequestIndex, raw: &str) -> Value {
        let query = RequestQuery::parse(&Query::new(raw), raw).unwrap();
        match index.respond(&query, None).unwrap() {
            Answer::Document(document, _) => document,
            Answer::Unchanged(_) => panic!("unexpected 304"),
        }
    }
    fn ids(document: &Value) -> Vec<String> {
        document["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn rows_follow_the_traffic_model() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        write(&path, &fixture());
        let mut index = RequestIndex::new(&path);
        let document = page(&mut index, "");
        let rows = document["requests"].as_array().unwrap();
        assert_eq!(document["total"], 10);
        let joined = &rows[0];
        assert_eq!(joined["id"], "S1:R41:10");
        assert_eq!(
            joined["path"],
            "https://api.example.test:8443/v1/items?page=2"
        );
        assert_eq!(joined["host"], "api.example.test:8443");
        assert_eq!(
            (&joined["status"], &joined["type"], &joined["tab_id"]),
            (&json!(200), &json!("xhr"), &json!("3"))
        );
        assert_eq!(joined["domain"], "api.example.test:8443");
        assert_eq!(joined["time"], "4.000 ms");
        assert_eq!(joined["root"]["sequence_number"], "2");
        assert_eq!(joined["members"].as_array().unwrap().len(), 2);
        assert_eq!(joined["records"], 5);
        let redirected = &rows[1];
        assert_eq!(
            (&redirected["path"], &redirected["target_kind"]),
            (&json!("cdn.example.test"), &json!("host"))
        );
        assert_eq!(
            (
                &redirected["type"],
                &redirected["status"],
                &redirected["time"]
            ),
            (&json!("wasm"), &json!(200), &json!("pending"))
        );
        assert_eq!(rows[2]["status"], "failed");
        assert_eq!(rows[3]["status"], "incomplete");
        assert_eq!(
            (&rows[4]["target_malformed"], &rows[4]["domain"]),
            (&json!(true), &json!("unknown"))
        );
        assert_eq!(
            (&rows[7]["path"], &rows[7]["target_kind"]),
            (&json!("files.example.test/upload/1"), &json!("path"))
        );
        assert_eq!(
            (&rows[8]["url_truncated"], &rows[8]["target_length"]),
            (&json!(true), &json!(400))
        );
        assert_eq!(rows[9]["method"], "EVENT");
        assert_eq!(document["failed"], 1);
        let tabs = document["facets"]["tabs"].as_array().unwrap();
        assert_eq!(
            (&tabs[0]["tab_id"], &tabs.last().unwrap()["tab_id"]),
            (&json!("3"), &json!("0"))
        );
        assert_eq!(document["index"]["complete"], true);
    }

    #[test]
    fn filters_search_sort_and_pages_cover_the_whole_index() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        for request in 1..=2500u64 {
            let host = format!("GET host{}.example.test", request % 7);
            store.push(7, request, "request_started", host.as_bytes(),
                json!({"resource_type": if request % 2 == 0 { 11 } else { 3 }, "tab_id": 1 + request % 3}));
            if request % 5 != 0 {
                store.push(
                    7,
                    request,
                    "request_completed",
                    b"completed",
                    json!({"status_code": 200 + request % 3}),
                );
            }
        }
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let all = page(&mut index, "limit=500&offset=2400");
        assert_eq!(
            (
                all["total"].as_u64(),
                all["matching"].as_u64(),
                all["returned"].as_u64()
            ),
            (Some(2500), Some(2500), Some(100))
        );
        assert_eq!(all["next_offset"], Value::Null);
        assert_eq!(
            page(&mut index, "order=desc&limit=1")["requests"][0]["ordinal"],
            2499
        );
        let scoped = page(&mut index, "type=xhr&tab_id=2&q=HOST3");
        let expected = (1..=2500u64)
            .filter(|r| r % 2 == 0 && 1 + r % 3 == 2 && r % 7 == 3)
            .count();
        assert_eq!(scoped["matching"].as_u64(), Some(expected as u64));
        let time = page(&mut index, "sort=time&order=desc&limit=500&offset=2000");
        assert!(
            time["requests"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["time"] == "pending"),
            "unfinished rows sort last"
        );
        assert_eq!(
            page(&mut index, "sort=status&order=desc&limit=1")["requests"][0]["status"],
            202
        );
        let id = all["requests"][0]["id"].as_str().unwrap().to_owned();
        let encoded = url::form_urlencoded::byte_serialize(id.as_bytes()).collect::<String>();
        assert_eq!(
            page(&mut index, &format!("locate={encoded}"))["located"][&id],
            2400
        );
        let filtered = page(&mut index, &format!("locate={encoded},missing&type=css"));
        assert_eq!(
            filtered["located"],
            json!({id.clone(): null, "missing": null})
        );
        assert_eq!(page(&mut index, "through=100&since=90")["added"], 10);
        assert_eq!(
            page(&mut index, "tab_id=1")["facets"]["domains"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        for bad in [
            "sort=size",
            "order=up",
            "type=fetch",
            "tab_id=0",
            "named=1:2",
            "limit=1&limit=2",
            "offset=-1",
            "q2=x",
        ] {
            assert!(RequestQuery::parse(&Query::new(bad), bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn incremental_refresh_persistence_reopen_and_store_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = fixture();
        write(&path, &store);
        let mut first = RequestIndex::new(&path);
        let epoch = page(&mut first, "")["index"]["epoch"].clone();
        let sidecar = root.path().join("events.jsonl.requests-v1");
        assert!(!sidecar.exists(), "a read never writes the sidecar");
        first.maintain().unwrap();
        assert!(sidecar.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // A partial record waits for its newline; a malformed one is counted.
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        store.push(
            7,
            950,
            "request_started",
            b"GET late.example.test",
            json!({}),
        );
        let line = serde_json::to_vec(store.events.last().unwrap()).unwrap();
        file.write_all(&line[..20]).unwrap();
        assert_eq!(page(&mut first, "")["total"], 10);
        file.write_all(&line[20..]).unwrap();
        file.write_all(b"\n{\"category\":\"network\",broken\n")
            .unwrap();
        let grown = page(&mut first, "");
        assert_eq!(
            (&grown["total"], &grown["index"]["malformed_records"]),
            (&json!(11), &json!("1"))
        );
        assert_eq!(grown["index"]["epoch"], epoch);
        first.persist();
        let mut reopened = RequestIndex::new(&path);
        let document = page(&mut reopened, "");
        assert_eq!(
            (&document["total"], &document["index"]["reopened"]),
            (&json!(11), &json!(true))
        );
        assert_eq!(document["index"]["epoch"], epoch);
        // A same-length rewrite rebuilds under a new epoch.
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] = b' ';
        fs::write(&path, &bytes).unwrap();
        let rebuilt = page(&mut reopened, "");
        assert_ne!(rebuilt["index"]["epoch"], epoch);
        assert_eq!(
            (&rebuilt["total"], &rebuilt["index"]["reopened"]),
            (&json!(11), &json!(false))
        );
        assert_eq!(rebuilt["index"]["malformed_records"], "2");
        reopened.discard().unwrap();
        assert!(!sidecar.exists(), "a clear removes the derived copy");
        fs::write(&path, b"").unwrap();
        assert_eq!(page(&mut reopened, "")["total"], 0);
    }

    #[test]
    fn unchanged_pages_are_not_modified_and_the_request_limit_is_counted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        write(&path, &fixture());
        let mut index = RequestIndex::new(&path);
        let query = RequestQuery::parse(&Query::new(""), "").unwrap();
        let Answer::Document(_, tag) = index.respond(&query, None).unwrap() else {
            panic!("document")
        };
        assert!(matches!(
            index.respond(&query, Some(&tag)).unwrap(),
            Answer::Unchanged(_)
        ));
        let other = RequestQuery::parse(&Query::new("limit=1"), "limit=1").unwrap();
        assert!(matches!(
            index.respond(&other, Some(&tag)).unwrap(),
            Answer::Document(..)
        ));
        let state = index.state.as_mut().unwrap();
        let first = state.rows[0].clone();
        state.rows.resize(MAX_REQUESTS, first);
        let mut late = Store {
            events: Vec::new(),
            sequence: 900,
        };
        late.push(
            7,
            999,
            "request_started",
            b"GET over.example.test",
            json!({}),
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&late.bytes())
            .unwrap();
        index.refresh().unwrap();
        assert_eq!(
            index.state.as_ref().unwrap().unindexed,
            1,
            "a request past the limit is counted"
        );
    }

    /// Golden for tools/check-request-index.mjs.
    #[test]
    #[ignore]
    fn request_index_ui_parity_golden() {
        let output =
            std::env::var_os("REB_REQUEST_INDEX_GOLDEN").expect("REB_REQUEST_INDEX_GOLDEN");
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let store = fixture();
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let mut document = page(&mut index, "limit=500");
        let orders = ["name", "method", "type", "status", "time"].map(|sort| {
            (
                sort.to_owned(),
                json!({"asc": ids(&page(&mut index, &format!("limit=500&sort={sort}"))),
                "desc": ids(&page(&mut index, &format!("limit=500&sort={sort}&order=desc")))}),
            )
        });
        let searches = ["example", "200", "post", "failed", "8443/v1", "event"].map(|needle| {
            (
                needle.to_owned(),
                json!(ids(&page(&mut index, &format!("limit=500&q={needle}")))),
            )
        });
        let golden = json!({"events": store.events, "rows": document["requests"].take(),
            "orders": orders.into_iter().collect::<serde_json::Map<_, _>>(),
            "searches": searches.into_iter().collect::<serde_json::Map<_, _>>()});
        fs::write(output, serde_json::to_vec_pretty(&golden).unwrap()).unwrap();
    }
}
