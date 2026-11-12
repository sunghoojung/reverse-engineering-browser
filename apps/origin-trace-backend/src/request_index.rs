//! Session-wide request index for Traffic; contract in protocol/request-index-v1.md.
use crate::{
    app::{Query, validate_event},
    durable,
    error::{Error, Result},
    event_query::RecordRange,
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
/// Sidecar row layout; a sidecar of another layout is rebuilt from byte 0.
const LAYOUT: u32 = 9;
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
const TIMELINE_BUCKETS: usize = 120;
/// Worker tab sets a row links to (protocol/native-network-v3.md `tab_set`).
const MAX_TAB_SETS: usize = 4096;
const MAX_SET_TABS: usize = 256;
/// `script_identity` payloads of one renderer, keyed by isolate key and script
/// ID: script IDs are unique only within one isolate.
pub type IdentityPayloads = HashMap<(u64, u32), String>;
/// `script_identity` records kept for the Initiator column's innermost frame.
const MAX_IDENTITIES: usize = 16_384;
const UNIDENTIFIED: &str = "Unidentified network event";
/// Records that belong to a row without changing its lifecycle; a selected
/// row reads them back by member (protocol/native-network-v2.md and v3).
const CHILD_TYPES: [&str; 11] = [
    "request_target",
    "request_body",
    "response_body",
    "request_headers",
    "response_headers",
    "cookie_list",
    "request_initiator_stack",
    "request_tab_link",
    "navigation_initiator_link",
    "request_extension_link",
    "request_watch_match",
];

pub const QUERY_KEYS: [&str; 18] = [
    "limit",
    "offset",
    "through",
    "since",
    "sort",
    "order",
    "q",
    "tab_id",
    "domain",
    "type",
    "named",
    "locate",
    "failed",
    "invert",
    "hide_internal",
    "third_party",
    "from_ns",
    "to_ns",
];
const SORTS: [&str; 10] = [
    "capture",
    "name",
    "status",
    "type",
    "method",
    "time",
    "size",
    "initiator",
    "start",
    "protocol",
];
const FILTER_KEYS: [&str; 5] = [
    "domain",
    "method",
    "status-code",
    "larger-than",
    "mime-type",
];
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
/// A start payload that names only its method, as a hostless URL's does.
static METHOD_ONLY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}) $").expect("method pattern")
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
    /// The last terminal record's `encoded_data_length` and `decoded_body_length`.
    transfer: Option<i64>,
    decoded: Option<i64>,
    cache: bool,
    worker_served: bool,
    /// A `memory_cache_reuse` row (protocol/native-network-v3.md) and its
    /// static-data flag.
    memory_cache: bool,
    static_data: bool,
    /// The target names only a scheme (`data:`); its child then gives the URL.
    scheme_only: bool,
    /// A renderer completion with from_service_worker: what the page received,
    /// as failed, status code and error (protocol/native-network-v3.md).
    worker_answer: Option<(bool, i64, i64)>,
    /// A record of the row carries a BrowserContext: the browser proxy saw it.
    browser: bool,
    /// A service_worker_end_lost gap names the row.
    end_lost: bool,
    mime: Option<String>,
    protocol: Option<String>,
    response_ns: Option<u64>,
    error: i64,
    /// Any lifecycle record other than the renderer's `request_initiated`.
    loader: bool,
    renderer: bool,
    worker_started: bool,
    main_frame: bool,
    /// The newest nonzero envelope scheme class (protocol/native-network-v3.md).
    scheme_class: u8,
    /// The renderer's request_initiator_stack state, or 0.
    stack_state: u8,
    /// A navigation_initiator_link names the renderer stack that started it.
    navigation_script: bool,
    stack_frame: Option<(String, u32, u64, [u8; 16])>,
    /// The thread a version 3 stack names: 1 document, 2-4 a worker; else 0.
    stack_thread: u8,
    /// The newest `request_tab_link`: its set key, kind and tab count.
    tab_set: Option<String>,
    tab_link: (u8, u32),
    /// The extension a `request_extension_link` names.
    extension: Option<String>,
    /// The renderer `request_initiated`'s loader kind and whether it had a
    /// frame, and the browser `request_started`'s newest nonzero loader kind:
    /// why a row without an owner has none (`request_tabs::unresolved_reason`).
    renderer_start: Option<(u8, bool)>,
    browser_start: Option<u8>,
}

#[derive(Serialize, Deserialize)]
struct State {
    format: String,
    layout: u32,
    epoch: String,
    identity: String,
    indexed_to: u64,
    head: String,
    tail: String,
    malformed: u64,
    unindexed: u64,
    rows: Vec<Row>,
    keys: HashMap<String, String>,
    /// `session:set_id` to the set's total and the tabs of its parts seen so far.
    tab_sets: HashMap<String, (u32, Vec<u64>)>,
    /// `session:process:script_id` to its newest `script_identity` payload.
    identities: HashMap<String, String>,
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
            layout: LAYOUT,
            epoch: hex::encode(&Sha256::digest(seed)[..8]),
            identity,
            indexed_to: 0,
            head: digest(&[]),
            tail: digest(&[]),
            malformed: 0,
            unindexed: 0,
            rows: Vec::new(),
            keys: HashMap::new(),
            tab_sets: HashMap::new(),
            identities: HashMap::new(),
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
    internal: bool,
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
    order: Option<(String, u64, Selection)>,
}

/// One query's rows plus what the footer and timing strip show for it.
#[derive(Clone)]
struct Selection {
    order: Vec<u32>,
    hidden_internal: usize,
    transferred: u64,
    resources: u64,
    /// First start, last record and per-bucket starts of every row the time range would admit.
    timeline: Option<(u64, u64, Vec<u32>)>,
}

pub enum Answer {
    Unchanged(String),
    Document(Value, String),
}

/// A `tab_id` filter: a tab (0 selects rows with no owner) or an extension.
#[derive(Clone, Debug, PartialEq)]
enum TabScope {
    Tab(u64),
    Extension(String),
}

pub struct RequestQuery {
    limit: usize,
    offset: usize,
    through: Option<usize>,
    since: Option<usize>,
    sort: &'static str,
    descending: bool,
    needle: String,
    tab: Option<TabScope>,
    domain: Option<String>,
    kind: Option<&'static str>,
    named: Vec<(String, u32, String)>,
    locate: Vec<String>,
    filter: Filter,
    failed: bool,
    invert: bool,
    hide_internal: bool,
    third_party: bool,
    from: u64,
    to: u64,
    raw: String,
}
/// The `q` grammar Traffic search uses; port of `trafficParseFilter`.
#[derive(Default)]
struct Filter {
    text: String,
    exclude: Vec<String>,
    tokens: Vec<Token>,
}
struct Token {
    key: &'static str,
    value: String,
    negated: bool,
    bytes: u64,
}
impl Filter {
    fn parse(needle: &str) -> Self {
        let mut filter = Self::default();
        let mut free = Vec::new();
        for word in needle.split(js_space).filter(|word| !word.is_empty()) {
            let negated = word.len() > 1 && word.starts_with('-');
            let body = if negated { &word[1..] } else { word };
            let token = body.split_once(':').and_then(|(key, value)| {
                let key = FILTER_KEYS.iter().copied().find(|known| *known == key)?;
                filter_bytes(key, value).map(|bytes| Token {
                    key,
                    value: value.into(),
                    negated,
                    bytes,
                })
            });
            match token {
                Some(token) => filter.tokens.push(token),
                None if negated => filter.exclude.push(body.into()),
                None => free.push(word),
            }
        }
        filter.text = free.join(" ");
        filter
    }
    fn active(&self) -> bool {
        !self.text.is_empty() || !self.exclude.is_empty() || !self.tokens.is_empty()
    }
}
/// Validates a token value; `larger-than` yields its byte count.
fn filter_bytes(key: &str, value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    match key {
        "status-code" => {
            (value.len() <= 3 && value.bytes().all(|b| b.is_ascii_digit())).then_some(0)
        }
        "larger-than" => {
            let (digits, unit) = match value.as_bytes()[value.len() - 1] {
                b'k' => (&value[..value.len() - 1], 1024),
                b'm' => (&value[..value.len() - 1], 1024 * 1024),
                _ => (value, 1),
            };
            (!digits.is_empty() && digits.len() <= 9 && digits.bytes().all(|b| b.is_ascii_digit()))
                .then(|| digits.parse::<u64>().unwrap() * unit)
        }
        "method" => value.chars().all(token_char).then_some(0),
        _ => Some(0),
    }
}
fn token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c)
}
/// `*` matches any run of characters; port of `trafficGlob`.
fn glob(pattern: &str, text: &str) -> bool {
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) {
        return false;
    }
    let mut at = first.len();
    for part in &parts[1..parts.len() - 1] {
        match text[at..].find(part) {
            Some(found) => at += found + part.len(),
            None => return false,
        }
    }
    text.len() >= at + last.len() && text.ends_with(last)
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
            Some("unattributed") => Some(TabScope::Tab(0)),
            Some(value) if value.starts_with("extension:") => {
                let id = &value["extension:".len()..];
                if id.len() != 32 || !id.bytes().all(|byte| (b'a'..=b'p').contains(&byte)) {
                    return Err(Error::bad(
                        "tab_id extension: must name a 32-letter extension id",
                    ));
                }
                Some(TabScope::Extension(id.to_owned()))
            }
            Some(_) => Some(TabScope::Tab(q.number("tab_id", None, 32, true)?)),
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
        let flag = |key: &str| -> Result<bool> {
            match q.one(key)? {
                None | Some("0") => Ok(false),
                Some("1") => Ok(true),
                Some(_) => Err(Error::bad(format!("{key} must be 0 or 1"))),
            }
        };
        let bound = |key: &str| -> Result<Option<u64>> {
            q.one(key)?
                .map(|_| q.number(key, None, 64, false))
                .transpose()
        };
        let (from, to) = (bound("from_ns")?, bound("to_ns")?);
        if from.zip(to).is_some_and(|(from, to)| from > to) {
            return Err(Error::bad("from_ns must not exceed to_ns"));
        }
        let needle = text("q")?.unwrap_or_default().trim().to_lowercase();
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
            filter: Filter::parse(&needle),
            needle,
            failed: flag("failed")?,
            invert: flag("invert")?,
            hide_internal: flag("hide_internal")?,
            third_party: flag("third_party")?,
            from: from.unwrap_or(0),
            to: to.unwrap_or(u64::MAX),
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
            "{}:{}:{}:{:?}:{:?}:{:?}:{:?}:{:?}:{through}",
            self.sort,
            self.descending,
            self.needle,
            self.tab,
            self.domain,
            self.kind,
            self.named,
            (
                self.failed,
                self.invert,
                self.hide_internal,
                self.third_party,
                self.from,
                self.to
            )
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
pub(crate) fn payload_text(bytes: &[u8]) -> String {
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
        "response_completed" | "request_completed" | "request_failed" | "memory_cache_reuse" => 5,
        _ => return None,
    })
}
/// What the page received: failed, interrupted, status code and error. A
/// renderer completion with from_service_worker decides over the browser's
/// records, which on such a row are a race network request; port of the
/// worker-answer pass in `requestsFromEvents`.
fn outcome(row: &Row) -> (bool, bool, i64, i64) {
    match row.worker_answer {
        Some((failed, code, error)) => {
            (failed, false, if code > 0 { code } else { row.code }, error)
        }
        None => (row.failed, row.interrupted, row.code, row.error),
    }
}
/// Blink `ResourceType` at the pin, from a `memory_cache_reuse` record; port
/// of `memoryCacheTypeFilter`.
fn memory_cache_resource(kind: u8) -> &'static str {
    match kind {
        1 => "img",
        2 => "css",
        3 => "js",
        4 => "font",
        10 | 11 => "media",
        _ => "other",
    }
}
/// Scheme class names of protocol/native-network-v3.md.
fn scheme_name(class: u8) -> Option<&'static str> {
    Some(match class {
        1 => "http",
        2 => "https",
        3 => "ws",
        4 => "wss",
        5 => "data",
        6 => "blob",
        7 => "file",
        8 => "chrome-extension",
        15 => "other",
        16 => "chrome",
        17 => "chrome-untrusted",
        18 => "brave",
        19 => "devtools",
        20 => "chrome-search",
        _ => return None,
    })
}
/// A `memory_cache_reuse` payload: Blink resource type, static data and host.
/// Port of `decodeMemoryCacheReuse`; the C++ core and Python share its rules.
fn memory_cache(event: &Value) -> Option<(u8, bool, String)> {
    // Every lifecycle record comes here; only a reuse pays for decoding.
    if event["type"] != "memory_cache_reuse" {
        return None;
    }
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    let (kind, flags, length) = (*bytes.get(4)?, *bytes.get(5)?, usize::from(*bytes.get(6)?));
    let host = bytes.get(8..8 + length)?;
    (event["protocol_version"] == 3
        && event["flags"] == 0
        && bytes.len() == 128
        && bytes[..4] == [1, 0, 128, 0]
        && (1..=15).contains(&kind)
        && flags & !3 == 0
        && length <= 120
        && bytes[7] == 0
        && (flags & 2 == 0 || length == 120)
        && host.iter().all(|b| (0x21..=0x7e).contains(b))
        && bytes[8 + length..].iter().all(|b| *b == 0))
    .then(|| {
        (
            kind,
            flags & 1 != 0,
            String::from_utf8_lossy(host).into_owned(),
        )
    })
}
type RowTarget = (Option<String>, String);
/// A reuse names its host, or its scheme for a URL with no web host; Blink
/// keeps only GET resources in the memory cache. Port of `memoryCacheTarget`;
/// the flag marks a scheme-only target.
fn memory_cache_target(event: &Value, host: &str) -> (Option<RowTarget>, bool) {
    let class = event["scheme_class"].as_u64().unwrap_or(0) as u8;
    let Some(scheme) = scheme_name(class) else {
        return (None, false);
    };
    let (value, scheme_only) = match (class <= 4, host.is_empty()) {
        (true, _) => (host.to_owned(), false),
        (false, false) => (format!("{scheme}://{host}"), false),
        (false, true) => (format!("{scheme}:"), true),
    };
    (Some((Some("GET".into()), value)), scheme_only)
}
/// Hostless URLs (`data:`, `blob:`) and browser schemes name their scheme;
/// port of `scopedNetworkTarget`.
fn scoped_target(
    target: Option<RowTarget>,
    payload: &str,
    event: &Value,
) -> (Option<RowTarget>, bool) {
    let class = event["scheme_class"].as_u64().unwrap_or(0) as u8;
    let scheme = match scheme_name(class) {
        Some(scheme)
            if class > 4
                && matches!(
                    event["type"].as_str(),
                    Some("request_initiated" | "request_started")
                ) =>
        {
            scheme
        }
        _ => return (target, false),
    };
    match target {
        Some((Some(method), value)) => (Some((Some(method), format!("{scheme}://{value}"))), false),
        Some(target) => (Some(target), false),
        None => match METHOD_ONLY.captures(payload) {
            Some(found) => (
                Some((Some(found[1].to_owned()), format!("{scheme}:"))),
                true,
            ),
            None => (None, false),
        },
    }
}
/// blink::mojom::ResourceType at the pin; port of `resourceTypeFilters`.
fn resource(code: i64) -> &'static str {
    match code {
        0 | 1 | 19 | 20 => "doc",
        2 => "css",
        3 | 9 | 10 | 15 => "js",
        4 | 12 => "img",
        5 => "font",
        8 => "media",
        13 => "xhr",
        _ => "other",
    }
}
/// A resource type that says only "other" is classed by MIME; port of `mimeTypeFilter`.
fn mime_class(mime: &str) -> &'static str {
    match mime {
        "text/css" => "css",
        "text/javascript"
        | "application/javascript"
        | "application/x-javascript"
        | "text/ecmascript"
        | "application/ecmascript" => "js",
        "text/html" | "application/xhtml+xml" => "doc",
        "application/vnd.ms-fontobject" => "font",
        _ if mime.starts_with("image/") => "img",
        _ if mime.starts_with("font/")
            || mime.starts_with("application/font-")
            || mime.starts_with("application/x-font-") =>
        {
            "font"
        }
        _ if mime.starts_with("audio/") || mime.starts_with("video/") => "media",
        _ => "other",
    }
}
/// `response_started` payload: `mime; protocol=alpn`, or `synthetic_shields; mime`.
fn response_metadata(payload: &str) -> (Option<String>, Option<String>) {
    let (text, synthetic) = match payload.strip_prefix("synthetic_shields; ") {
        Some(rest) => (rest, true),
        None => (payload, false),
    };
    let at = if synthetic {
        None
    } else {
        text.find("; protocol=")
    };
    let essence = at
        .map_or(text, |at| &text[..at])
        .split(';')
        .next()
        .unwrap_or("")
        .trim_matches(js_space);
    let mime = essence
        .split_once('/')
        .filter(|(kind, subtype)| {
            !kind.is_empty()
                && !subtype.is_empty()
                && kind.chars().all(token_char)
                && subtype.chars().all(token_char)
        })
        .map(|_| essence.to_ascii_lowercase());
    let protocol = at
        .map(|at| text[at + 11..].trim_matches(js_space))
        .filter(|p| (1..=32).contains(&p.len()) && p.bytes().all(|b| (0x21..=0x7e).contains(&b)))
        .map(str::to_owned);
    (mime, protocol)
}
fn length(value: &Value) -> Option<i64> {
    value
        .as_str()
        .and_then(|text| text.parse::<i64>().ok())
        .filter(|length| *length >= 0)
}
/// Last path segment plus query; port of `trafficShortName`.
fn short_name(target: &str) -> String {
    let (path, query) = target
        .find('?')
        .map_or((target, ""), |at| (&target[..at], &target[at..]));
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    let segment = if trimmed.is_empty() {
        ""
    } else {
        &path[trimmed.rfind('/').map_or(0, |at| at + 1)..]
    };
    format!("{segment}{query}")
}

fn fold_tab_set(event: &Value, sets: &mut HashMap<String, (u32, Vec<u64>)>) {
    let Ok(bytes) = hex::decode(event["payload"].as_str().unwrap_or("")) else {
        return;
    };
    if bytes.len() != 128 {
        return;
    }
    let set_id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let total = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let count = usize::from(u16::from_le_bytes([bytes[20], bytes[21]])).min(26);
    let key = format!("{}:{set_id}", text(&event["session_id"]));
    if !sets.contains_key(&key) && sets.len() >= MAX_TAB_SETS {
        return;
    }
    let (_, tabs) = sets.entry(key).or_insert((total, Vec::new()));
    for slot in bytes[24..24 + 4 * count].as_chunks::<4>().0 {
        let tab = u64::from(u32::from_le_bytes(*slot));
        if tab != 0 && tabs.len() < MAX_SET_TABS && !tabs.contains(&tab) {
            tabs.push(tab);
        }
    }
    tabs.sort_unstable();
}

fn fold_identity(event: &Value, identities: &mut HashMap<String, String>) {
    let payload = event["payload"].as_str().unwrap_or("");
    // Script IDs are unique per isolate; version 2 names a worker's at byte 80.
    let Some((isolate, script)) = hex::decode(payload)
        .ok()
        .filter(|bytes| bytes.len() == 128)
        .map(|bytes| {
            let isolate = if bytes[0] == 2 {
                u64::from_le_bytes(bytes[80..88].try_into().unwrap())
            } else {
                0
            };
            (
                isolate,
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            )
        })
    else {
        return;
    };
    let key = format!(
        "{}:{}:{isolate}:{script}",
        text(&event["session_id"]),
        number(&event["process_id"])
    );
    if identities.contains_key(&key) || identities.len() < MAX_IDENTITIES {
        identities.insert(key, payload.to_owned());
    }
}

fn extension_link(event: &Value) -> Option<String> {
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    let id = bytes.get(8..40)?;
    (bytes.len() == 40 && id.iter().all(|byte| (b'a'..=b'p').contains(byte)))
        .then(|| String::from_utf8_lossy(id).into_owned())
}

fn tab_link(event: &Value) -> Option<(String, (u8, u32))> {
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    if bytes.len() != 24 || !(1..=5).contains(&bytes[4]) {
        return None;
    }
    let set_id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    Some((
        format!("{}:{set_id}", text(&event["session_id"])),
        (bytes[4], count),
    ))
}

/// The row's own tab and its linked set's tabs; empty is a capture error.
fn row_tabs(row: &Row, sets: &HashMap<String, (u32, Vec<u64>)>) -> Vec<u64> {
    let mut tabs = row
        .tab_set
        .as_ref()
        .and_then(|key| sets.get(key))
        .map_or_else(Vec::new, |(_, tabs)| tabs.clone());
    if row.tab != 0 && !tabs.contains(&row.tab) {
        tabs.push(row.tab);
        tabs.sort_unstable();
    }
    tabs
}

/// Tab 0 selects the rows with no tab and no extension.
fn in_tab(row: &Row, sets: &HashMap<String, (u32, Vec<u64>)>, scope: &TabScope) -> bool {
    let linked = row.tab_set.as_ref().and_then(|key| sets.get(key));
    match scope {
        TabScope::Extension(id) => row.extension.as_ref() == Some(id),
        TabScope::Tab(0) => {
            row.tab == 0
                && row.extension.is_none()
                && linked.is_none_or(|(_, tabs)| tabs.is_empty())
        }
        TabScope::Tab(tab) => row.tab == *tab || linked.is_some_and(|(_, tabs)| tabs.contains(tab)),
    }
}

fn initiator(row: &Row) -> Option<&'static str> {
    if row.worker_started {
        Some("worker")
    } else if row.renderer && (2..=4).contains(&row.stack_thread) && row.stack_state != 3 {
        // A version 3 stack from a worker's isolate (protocol/native-network-v3.md).
        Some(match row.stack_state {
            2 => "worker_loader",
            6 => "worker_unwalked",
            _ => "worker_script",
        })
    } else if row.navigation_script || (row.renderer && matches!(row.stack_state, 1 | 4 | 5)) {
        // A walked request_initiator_stack (protocol/native-network-v3.md).
        Some("script")
    } else if row.renderer && row.stack_state == 2 {
        Some("parser")
    } else if row.renderer {
        Some("renderer")
    } else if row.loader {
        Some("browser")
    } else {
        None
    }
}
fn initiator_label(row: &Row) -> Option<&'static str> {
    initiator(row).map(|kind| match kind {
        "worker" => "Service worker",
        "worker_script" => "Worker script",
        "worker_loader" => "Worker loader",
        "worker_unwalked" => "Worker, not walked",
        "script" => "Script",
        "parser" => "Parser",
        "renderer" => "Renderer",
        _ => "Browser",
    })
}
fn host_of(domain: &str) -> &str {
    match domain.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => domain,
    }
}
/// Approximate site without a public suffix list; port of `trafficSite`.
fn site(domain: &str) -> Option<String> {
    let host = host_of(domain).to_lowercase();
    if host.is_empty() || host == "unknown" {
        return None;
    }
    if host.starts_with('[')
        || !host.contains('.')
        || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return Some(host);
    }
    let labels = host.split('.').collect::<Vec<_>>();
    let count = labels.len();
    let keep = if count >= 3 && labels[count - 1].len() == 2 && labels[count - 2].len() <= 3 {
        3
    } else {
        2
    };
    Some(labels[count.saturating_sub(keep)..].join("."))
}
/// Port of `networkTargetFromPayload`.
pub(crate) fn network_target(payload: &str, kind: &str) -> Option<(Option<String>, String)> {
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
    if event["type"] == "request_initiated" || event["type"] == "memory_cache_reuse" {
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
    if event["type"] == "request_initiated" || event["type"] == "memory_cache_reuse" {
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
    {
        return None;
    }
    let artifact = canonical(&event["artifact_id"], false)? != 0;
    let bytes = hex::decode(payload).ok()?;
    let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let length = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let prefix = 12 + (length as usize).min(116);
    // Version 2 byte 9 says where bytes past the prefix went; version 1 has none.
    let retention = bytes[9];
    let retention_valid = match u16_at(0) {
        1 => retention == 0 && !artifact,
        2 => retention <= 5 && (retention == 0) != (length > 116) && (retention == 1) == artifact,
        _ => false,
    };
    if !retention_valid
        || u16_at(2) != 128
        || bytes[8] > 4
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
        target_kind = if found.scheme.is_some() || row.scheme_only {
            "url"
        } else {
            "path"
        };
        target = Some(found.text.clone());
        url_truncated = found.length > 116;
        target_length = Some(found.length);
    }
    let (failed, interrupted, code, _) = outcome(row);
    let status = if failed {
        json!("failed")
    } else if interrupted || (row.end_lost && row.rank < 5) {
        json!("incomplete")
    } else if code > 0 {
        json!(code)
    } else if row.memory_cache {
        // A reuse is a finished load; an MHTML archive resource has no HTTP status.
        json!("finished")
    } else {
        json!("pending")
    };
    let trimmed = path.trim_matches(js_space);
    let more = if url_truncated { "…" } else { "" };
    // The root path names the request by its host.
    let named = |target: &str, host: &str| match short_name(target) {
        short if short.is_empty() => {
            format!("{}{more}", if host.is_empty() { target } else { host })
        }
        short => format!("{short}{more}"),
    };
    let name = if target_kind == "host" {
        if trimmed.is_empty() {
            "Unknown host".into()
        } else {
            trimmed.into()
        }
    } else if let Some(target) = &target {
        named(target, host.as_deref().unwrap_or(""))
    } else {
        match url::Url::parse(trimmed) {
            Ok(url) if ["http", "https", "ws", "wss"].contains(&url.scheme()) => named(
                &format!(
                    "{}{}",
                    url.path(),
                    url.query()
                        .filter(|q| !q.is_empty())
                        .map(|q| format!("?{q}"))
                        .unwrap_or_default()
                ),
                &match (url.host_str(), url.port()) {
                    (Some(host), Some(port)) => format!("{host}:{port}"),
                    (Some(host), None) => host.into(),
                    _ => String::new(),
                },
            ),
            _ if trimmed.is_empty() => "Unidentified request".into(),
            _ => trimmed.into(),
        }
    };
    // A recorded scheme class decides. Before scheme classes, WebUI loads
    // (chrome://resources, newtab) never reached the browser loader proxy.
    let internal = if row.scheme_class != 0 {
        (16..=20).contains(&row.scheme_class)
    } else {
        !row.loader
            && target_kind == "host"
            && !trimmed.is_empty()
            && trimmed
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !trimmed.eq_ignore_ascii_case("localhost")
    };
    View {
        internal,
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
        if state.format != FORMAT || state.layout != LAYOUT || state.rows.len() > MAX_REQUESTS {
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
        // Only a network record names its category in its bytes. A line that is
        // no complete object may have lost those bytes, so it cannot be skipped.
        if line.len() <= RECORD_BYTES && !line.windows(7).any(|window| window == b"network") {
            if line.trim_ascii().first() != Some(&b'{') || line.trim_ascii().last() != Some(&b'}') {
                state.malformed += 1;
            }
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
            // A service worker's end the renderer could not join to its start
            // names the row as a request_tab_link would.
            if kind == "gap"
                && number(&event["initiator_process_id"]) > 0
                && hex::decode(event["payload"].as_str().unwrap_or(""))
                    .ok()
                    .as_deref()
                    == Some(b"service_worker_end_lost".as_slice())
            {
                if let Some(&ordinal) = state.by_id.get(&correlated_identity(&event)) {
                    state.rows[ordinal as usize].end_lost = true;
                    self.views[ordinal as usize] = view(&state.rows[ordinal as usize]);
                }
                return;
            }
            if kind == "tab_set" {
                fold_tab_set(&event, &mut state.tab_sets);
                return;
            }
            if kind == "script_identity" {
                fold_identity(&event, &mut state.identities);
                return;
            }
            if CHILD_TYPES.contains(&kind) {
                let id = request_identity(&event, &state.keys);
                if let Some(&ordinal) = state.by_id.get(&id) {
                    let row = &mut state.rows[ordinal as usize];
                    Self::member(row, &event, start, end);
                    if kind == "request_initiator_stack" {
                        let bytes = hex::decode(event["payload"].as_str().unwrap_or(""))
                            .unwrap_or_default();
                        row.stack_state = bytes.get(4).copied().unwrap_or(0);
                        // Version 3 names the isolate its script IDs belong to.
                        let scoped = bytes.len() == 128 && bytes[0] == 3;
                        row.stack_thread = if scoped { bytes[80] } else { 0 };
                        row.stack_frame = (bytes.len() == 128
                            && matches!(row.stack_state, 1 | 4 | 5))
                        .then(|| {
                            (
                                text(&event["session_id"]),
                                number(&event["process_id"]) as u32,
                                if scoped {
                                    u64::from_le_bytes(bytes[88..96].try_into().unwrap())
                                } else {
                                    0
                                },
                                bytes[64..80].try_into().unwrap(),
                            )
                        });
                    }
                    row.navigation_script |= kind == "navigation_initiator_link";
                    if kind == "request_tab_link"
                        && let Some((set, link)) = tab_link(&event)
                    {
                        (row.tab_set, row.tab_link) = (Some(set), link);
                    }
                    if kind == "request_extension_link"
                        && let Some(id) = extension_link(&event)
                    {
                        row.extension = Some(id);
                    }
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
                    transfer: None,
                    decoded: None,
                    cache: false,
                    worker_served: false,
                    memory_cache: false,
                    static_data: false,
                    scheme_only: false,
                    worker_answer: None,
                    browser: false,
                    end_lost: false,
                    mime: None,
                    protocol: None,
                    response_ns: None,
                    error: 0,
                    loader: false,
                    renderer: false,
                    worker_started: false,
                    main_frame: false,
                    scheme_class: 0,
                    stack_state: 0,
                    navigation_script: false,
                    stack_frame: None,
                    stack_thread: 0,
                    tab_set: None,
                    tab_link: (0, 0),
                    extension: None,
                    renderer_start: None,
                    browser_start: None,
                });
                self.views.push(view(state.rows.last().unwrap()));
                ordinal
            }
        };
        let row = &mut state.rows[ordinal as usize];
        let payload =
            payload_text(&hex::decode(event["payload"].as_str().unwrap_or("")).unwrap_or_default());
        let reuse = memory_cache(&event);
        let (target, scheme_only) = match &reuse {
            Some((_, _, host)) => memory_cache_target(&event, host),
            None => scoped_target(network_target(&payload, kind), &payload, &event),
        };
        let version = event["protocol_version"].as_u64().unwrap_or(0);
        let time = unsigned(&event["monotonic_time_ns"]).unwrap_or(0);
        row.first_ns = row.first_ns.min(time);
        row.last_ns = row.last_ns.max(time);
        let interruption = version >= 3
            && kind == "request_failed"
            && number(&event["error_code"]) == -3
            && ["proxy_destroyed", "redirect_handoff"].contains(&payload.as_str());
        row.failed |=
            !interruption && (kind == "request_failed" || number(&event["error_code"]) != 0);
        row.interrupted |= interruption;
        let code = number(&event["status_code"]);
        if code > 0 && incoming >= row.status_rank {
            row.code = code;
            row.status_rank = incoming;
        }
        row.browser |= context_token(&event).is_some();
        if matches!(kind, "request_completed" | "request_failed")
            && number(&event["flags"]) & 4 != 0
            && number(&event["initiator_process_id"]) == 0
            && context_token(&event).is_none()
        {
            row.worker_answer =
                Some((kind == "request_failed", code, number(&event["error_code"])));
        }
        if let Some((method, value)) = target.filter(|_| incoming >= row.target_rank) {
            row.target_rank = incoming;
            row.path = value;
            row.scheme_only = scheme_only;
            if let Some(method) = method {
                row.method = method;
            }
            row.target_event = Some((
                text(&event["session_id"]),
                number(&event["process_id"]) as u32,
                text(&event["sequence_number"]),
            ));
        }
        let flags = number(&event["flags"]);
        if let Some(class) = event["scheme_class"]
            .as_u64()
            .filter(|class| (1..=255).contains(class))
        {
            row.scheme_class = class as u8;
        }
        // A memory-cache reuse is the renderer's own row; no loader made it.
        let renderer_row = kind == "request_initiated" || kind == "memory_cache_reuse";
        row.loader |= !renderer_row;
        row.renderer |= renderer_row || number(&event["initiator_process_id"]) > 0;
        let loader_kind = u8::try_from(number(&event["loader_kind"])).unwrap_or(0);
        // A memory-cache reuse names its owner as request_initiated does.
        if renderer_row && row.renderer_start.is_none() {
            let frame = text(&event["frame_id"]);
            row.renderer_start = Some((loader_kind, !frame.is_empty() && frame != "0"));
        }
        if kind == "request_started" {
            row.worker_started |= flags & 4 != 0;
            row.main_frame |= number(&event["resource_type"]) == 0;
            row.browser_start = Some(if loader_kind == 0 {
                row.browser_start.unwrap_or(0)
            } else {
                loader_kind
            });
        }
        let response = (kind == "response_started").then(|| response_metadata(&payload));
        // A renderer completion carries the response's cache and service-worker
        // flags, and a service worker's end without a response its own.
        if response.is_some() || matches!(kind, "request_completed" | "request_failed") {
            row.cache |= flags & 2 != 0;
            row.worker_served |= flags & 4 != 0;
        }
        if let Some((blink_type, static_data, _)) = &reuse {
            row.memory_cache = true;
            row.static_data = *static_data;
            row.resource = memory_cache_resource(*blink_type).into();
        }
        if let Some((mime, protocol)) = &response {
            row.mime = mime.clone();
            row.protocol = protocol.clone();
            row.response_ns.get_or_insert(time);
        }
        if incoming == 5 {
            row.transfer = length(&event["encoded_data_length"]);
            row.decoded = length(&event["decoded_body_length"]);
        }
        if number(&event["error_code"]) != 0 {
            row.error = number(&event["error_code"]);
        }
        let lower = payload.to_ascii_lowercase();
        if lower
            .strip_prefix("application/wasm")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(';'))
        {
            row.resource = "wasm".into();
        } else if kind == "request_started" {
            row.resource = resource(number(&event["resource_type"])).into();
        } else if let Some((Some(mime), _)) = &response
            && row.resource == "other"
        {
            row.resource = mime_class(mime).into();
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
        // A link is no request of its own; tab_link, tab_ids and extension_id carry it.
        if event["type"] == "request_tab_link" || event["type"] == "request_extension_link" {
            return;
        }
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

    /// Every filter except the time range and the browser-internal switch.
    fn matches(&self, query: &RequestQuery, ordinal: usize, third_party: &[bool]) -> bool {
        let (row, view) = (
            &self.state.as_ref().unwrap().rows[ordinal],
            &self.views[ordinal],
        );
        let sets = &self.state.as_ref().unwrap().tab_sets;
        let scoped = query.tab.as_ref().is_none_or(|tab| in_tab(row, sets, tab))
            && query
                .domain
                .as_ref()
                .is_none_or(|domain| view.domain == *domain)
            && query.kind.is_none_or(|kind| row.resource == kind)
            && (!query.failed || outcome(row).0)
            && (!query.third_party || third_party[ordinal]);
        if !scoped {
            return false;
        }
        let filter = &query.filter;
        let named = || {
            Self::root(row).is_some_and(|root| {
                query.named.iter().any(|(session, process, sequence)| {
                    root.session == *session
                        && root.process == *process
                        && root.sequence == *sequence
                })
            })
        };
        let token = |token: &Token| match token.key {
            "domain" => {
                let domain = view.domain.to_lowercase();
                glob(&token.value, &domain) || glob(&token.value, host_of(&domain))
            }
            "method" => view.method.to_lowercase() == token.value,
            "status-code" => view.status.as_i64() == token.value.parse().ok(),
            "larger-than" => row.transfer.is_some_and(|size| size as u64 > token.bytes),
            _ => row.mime.as_deref() == Some(token.value.as_str()),
        };
        let found = (filter.text.is_empty() || view.haystack.contains(&filter.text) || named())
            && filter
                .exclude
                .iter()
                .all(|text| !view.haystack.contains(text.as_str()))
            && filter.tokens.iter().all(|t| token(t) != t.negated);
        found != (query.invert && filter.active())
    }

    /// Rows whose site differs from their tab's latest top-level document at their start.
    fn third_party(&self, through: usize) -> Vec<bool> {
        let rows = &self.state.as_ref().unwrap().rows;
        let mut documents: HashMap<u64, Vec<(u64, usize)>> = HashMap::new();
        for (ordinal, row) in rows.iter().enumerate().take(through) {
            if row.main_frame && row.tab != 0 {
                documents
                    .entry(row.tab)
                    .or_default()
                    .push((row.first_ns, ordinal));
            }
        }
        for list in documents.values_mut() {
            list.sort_unstable();
        }
        (0..through)
            .map(|ordinal| {
                let row = &rows[ordinal];
                let Some(list) = documents.get(&row.tab) else {
                    return false;
                };
                let at = list.partition_point(|key| *key <= (row.first_ns, ordinal));
                let (Some(own), Some(&(_, document))) = (
                    site(&self.views[ordinal].domain),
                    at.checked_sub(1).map(|at| &list[at]),
                ) else {
                    return false;
                };
                site(&self.views[document].domain).is_some_and(|first| first != own)
            })
            .collect()
    }

    fn root(row: &Row) -> Option<&Root> {
        row.roots.iter().flatten().next()
    }

    fn select(&mut self, query: &RequestQuery, through: usize) -> &Selection {
        let key = query.order_key(through);
        if self
            .order
            .as_ref()
            .is_none_or(|(cached, generation, _)| *cached != key || *generation != self.generation)
        {
            let third_party = if query.third_party {
                self.third_party(through)
            } else {
                Vec::new()
            };
            let rows = &self.state.as_ref().unwrap().rows;
            let (mut order, mut scope, mut hidden_internal) = (Vec::new(), Vec::new(), 0);
            for (ordinal, row) in rows.iter().enumerate().take(through) {
                if !self.matches(query, ordinal, &third_party) {
                    continue;
                }
                let in_range = row.first_ns <= query.to && row.last_ns >= query.from;
                if query.hide_internal && self.views[ordinal].internal {
                    hidden_internal += usize::from(in_range);
                    continue;
                }
                scope.push(ordinal as u32);
                if in_range {
                    order.push(ordinal as u32);
                }
            }
            let timeline = scope.iter().map(|&i| &rows[i as usize]).fold(
                None,
                |bounds: Option<(u64, u64)>, row| {
                    Some(bounds.map_or((row.first_ns, row.last_ns), |(first, last)| {
                        (first.min(row.first_ns), last.max(row.last_ns))
                    }))
                },
            );
            let timeline = timeline.map(|(first, last)| {
                let mut buckets = vec![0u32; TIMELINE_BUCKETS];
                let span = u128::from(last - first) + 1;
                for &i in &scope {
                    let offset = u128::from(rows[i as usize].first_ns - first);
                    buckets[(offset * TIMELINE_BUCKETS as u128 / span) as usize] += 1;
                }
                (first, last, buckets)
            });
            let total = |pick: fn(&Row) -> Option<i64>| {
                order
                    .iter()
                    .map(|&i| pick(&rows[i as usize]).unwrap_or(0) as u64)
                    .sum::<u64>()
            };
            let (transferred, resources) = (total(|row| row.transfer), total(|row| row.decoded));
            let views = &self.views;
            let direction = |ordering: Ordering| {
                if query.descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            };
            let numeric = |order: &mut Vec<u32>, value: &dyn Fn(u32) -> Option<i64>| {
                order.sort_by(|&a, &b| match (value(a), value(b)) {
                    (Some(x), Some(y)) => direction(x.cmp(&y)).then(a.cmp(&b)),
                    (None, None) => a.cmp(&b),
                    (None, _) => Ordering::Greater,
                    (_, None) => Ordering::Less,
                });
            };
            match query.sort {
                "capture" if query.descending => order.reverse(),
                "capture" => {}
                // Traffic compares the displayed microseconds.
                "time" => numeric(&mut order, &|i| {
                    duration(&rows[i as usize]).map(|d| (d / 1000) as i64)
                }),
                "status" => numeric(&mut order, &|i| views[i as usize].status.as_i64()),
                "size" => numeric(&mut order, &|i| rows[i as usize].transfer),
                "start" => numeric(&mut order, &|i| {
                    i64::try_from(rows[i as usize].first_ns).ok()
                }),
                sort => {
                    let value = |i: u32| -> Option<&str> {
                        let (row, view) = (&rows[i as usize], &views[i as usize]);
                        match sort {
                            "name" => Some(&view.name),
                            "type" => Some(type_label(&row.resource)),
                            "initiator" => initiator_label(row),
                            "protocol" => row.protocol.as_deref(),
                            _ => Some(&view.method),
                        }
                    };
                    order.sort_by(|&a, &b| match (value(a), value(b)) {
                        (Some(x), Some(y)) => direction(compare_text(x, y)).then(a.cmp(&b)),
                        (None, None) => a.cmp(&b),
                        (None, _) => Ordering::Greater,
                        (_, None) => Ordering::Less,
                    });
                }
            }
            let selection = Selection {
                order,
                hidden_internal,
                transferred,
                resources,
                timeline,
            };
            self.order = Some((key, self.generation, selection));
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
        let mut document = json!({
            "id": row.id, "ordinal": ordinal, "method": row.method, "path": view.path,
            "target_kind": view.target_kind, "host": view.host, "target": view.target,
            "url_truncated": view.url_truncated, "target_length": view.target_length,
            "target_malformed": view.target_malformed, "status": view.status,
            "failed": outcome(row).0, "interrupted": outcome(row).1,
            "time": duration(row).map_or_else(|| "pending".to_owned(), milliseconds),
            "duration_ns": duration(row).map(|d| d.to_string()),
            "type": row.resource, "tab_id": row.tab.to_string(), "operation": row.operation,
            "tab_ids": row_tabs(row, &self.state.as_ref().unwrap().tab_sets).iter().map(u64::to_string).collect::<Vec<_>>(),
            "tab_link": (row.tab_link.0 != 0).then(|| {
                let set = row.tab_set.as_ref().and_then(|key| self.state.as_ref().unwrap().tab_sets.get(key));
                json!({"kind": row.tab_link.0, "count": row.tab_link.1,
                    "complete": set.is_some_and(|(total, tabs)| tabs.len() == *total as usize)})
            }),
            "first_time_ns": row.first_ns.to_string(), "last_time_ns": row.last_ns.to_string(),
            "domain": view.domain,
            "root": Self::root(row).map(|root| json!({"session_id": root.session, "process_id": root.process,
                "sequence_number": root.sequence, "request_id": root.request})),
            "members": row.members.iter().map(member).collect::<Vec<_>>(),
            "members_limited": row.members_limited,
            "first_offset": row.first_offset.to_string(), "end_offset": row.end_offset.to_string(),
            "records": row.records,
            "transfer_size": row.transfer, "resource_size": row.decoded,
            "from_cache": row.cache, "from_service_worker": row.worker_served,
            "mime_type": row.mime, "protocol": row.protocol,
            "response_time_ns": row.response_ns.map(|time| time.to_string()),
            "error_code": outcome(row).3, "loader_observed": row.loader, "initiator": initiator(row),
            "main_frame": row.main_frame, "browser_internal": view.internal,
        });
        document["extension_id"] = json!(row.extension);
        document["memory_cache"] = json!(row.memory_cache);
        document["static_data"] = json!(row.static_data);
        document["race_network"] = json!(row.worker_answer.is_some() && row.browser);
        document["end_lost"] = json!(row.end_lost);
        let owned = row.extension.is_some()
            || !row_tabs(row, &self.state.as_ref().unwrap().tab_sets).is_empty();
        document["tab_reason"] = json!((!owned).then(|| {
            crate::request_tabs::unresolved_reason(
                row.renderer_start
                    .map(|(kind, frame)| (u64::from(kind), frame)),
                row.browser_start.map(u64::from),
            )
        }));
        // Raw; the get_requests handler replaces it with the frame's resolution.
        document["initiator_frame"] = json!(row.stack_frame.as_ref().map(|(session, process, isolate, frame)| {
            let script = u32::from_le_bytes(frame[4..8].try_into().unwrap());
            json!({"session_id": session, "process_id": process, "isolate_key": isolate.to_string(),
                "thread": row.stack_thread,
                "frame": hex::encode(frame),
                "identity": self.state.as_ref().unwrap().identities.get(&format!("{session}:{process}:{isolate}:{script}"))})
        }));
        document
    }

    fn facets(&self, query: &RequestQuery, through: usize) -> Value {
        let state = self.state.as_ref().unwrap();
        let (rows, sets) = (&state.rows, &state.tab_sets);
        // Tab ids, `extension:<id>` and `0` for rows with no owner.
        let mut tabs: BTreeMap<String, (u64, u64, Vec<String>, bool)> = BTreeMap::new();
        let mut domains: BTreeMap<&str, u64> = BTreeMap::new();
        for (row, view) in rows.iter().zip(&self.views).take(through) {
            let mut own = row_tabs(row, sets)
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>();
            if let Some(id) = &row.extension {
                own.push(format!("extension:{id}"));
            }
            if own.is_empty() {
                own.push("0".to_owned());
            }
            for id in own {
                let tab = tabs
                    .entry(id)
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
            }
            if query.tab.as_ref().is_none_or(|tab| in_tab(row, sets, tab)) {
                *domains.entry(&view.domain).or_default() += 1;
            }
        }
        let mut tabs = tabs.into_iter().collect::<Vec<_>>();
        tabs.sort_by_key(|(tab, (_, first, _, _))| {
            (
                tab == "0",
                *first,
                tab.parse::<u64>().unwrap_or(u64::MAX),
                tab.clone(),
            )
        });
        let truncated = domains.len() > MAX_DOMAINS;
        let selected = query.domain.as_deref();
        let listed = domains
            .iter()
            .enumerate()
            .filter(|(index, (domain, _))| *index < MAX_DOMAINS || selected == Some(**domain))
            .map(|(_, (domain, count))| json!({"domain": domain, "count": count}))
            .collect::<Vec<_>>();
        json!({
            "tabs": tabs.iter().map(|(tab, (count, first, domains, more))| json!({"tab_id": tab,
                "count": count, "first_time_ns": first.to_string(), "domains": domains, "domains_truncated": more}))
                .collect::<Vec<_>>(),
            "domains": listed,
            "domains_truncated": truncated,
        })
    }

    /// Whether the index has folded every complete record in the store.
    fn caught_up(&self, indexed_to: u64) -> bool {
        self.store_end.saturating_sub(indexed_to) <= RECORD_BYTES as u64
    }

    /// Whether the index covers the store, as of the last refresh. A route uses
    /// this to tell a transient "not named yet" from a final one.
    pub fn is_caught_up(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(|state| self.caught_up(state.indexed_to))
    }

    /// The bytes of the rows that have this member, across rows when several do.
    /// Without a process, a request number is ambiguous: renderers and the
    /// browser count requests separately, so the same number can name unrelated
    /// rows far apart. Only the browser's own row is chosen when one has it.
    pub fn member_range(
        &mut self,
        session: Option<&str>,
        process: Option<u32>,
        request: &str,
    ) -> Result<Option<RecordRange>> {
        self.refresh()?;
        let state = self.state.as_ref().expect("index state");
        let names = |row: &Row| {
            row.members.iter().any(|member| {
                member.request == request
                    && session.is_none_or(|session| member.session == session)
                    && process.is_none_or(|process| member.process == process)
            })
        };
        // A row's browser identity is its request_started record's.
        let browser_row = |row: &&Row| {
            names(row)
                && process.is_none()
                && row.loader
                && row.roots[0]
                    .as_ref()
                    .is_none_or(|root| root.request == request)
        };
        let chosen: Vec<&Row> = if state.rows.iter().any(|row| browser_row(&row)) {
            state.rows.iter().filter(browser_row).collect()
        } else {
            state.rows.iter().filter(|row| names(row)).collect()
        };
        let range = chosen.iter().fold(None, |range: Option<(u64, u64)>, row| {
            let (first, end) = range.unwrap_or((row.first_offset, row.end_offset));
            Some((first.min(row.first_offset), end.max(row.end_offset)))
        });
        let indexed = self.caught_up(state.indexed_to);
        Ok(range.map(|(first, end)| RecordRange {
            first,
            end,
            indexed,
        }))
    }

    /// Identifies how far the index has reached while it is behind the store,
    /// so a validator on a detail answer changes as its coverage can change.
    pub fn progress_marker(&self) -> String {
        match &self.state {
            Some(state) if !self.caught_up(state.indexed_to) => state.indexed_to.to_string(),
            Some(_) => "caught-up".to_owned(),
            None => "unopened".to_owned(),
        }
    }

    /// `script_identity` payloads of one renderer by isolate key and script
    /// ID, and whether a script missing from them is missing from the store.
    pub fn identities(&mut self, session: &str, process: u32) -> Result<(IdentityPayloads, bool)> {
        self.refresh()?;
        let state = self.state.as_ref().expect("index state");
        let prefix = format!("{session}:{process}:");
        let identities = state
            .identities
            .iter()
            .filter_map(|(key, payload)| {
                let (isolate, script) = key.strip_prefix(&prefix)?.split_once(':')?;
                Some((
                    (isolate.parse().ok()?, script.parse().ok()?),
                    payload.clone(),
                ))
            })
            .collect();
        let exhaustive =
            self.caught_up(state.indexed_to) && state.identities.len() < MAX_IDENTITIES;
        Ok((identities, exhaustive))
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
        let failed = (0..through).filter(|&i| outcome(&state.rows[i]).0).count();
        let index = json!({
            "epoch": state.epoch, "indexed_end": state.indexed_to.to_string(), "store_end": store_end.to_string(),
            "complete": self.caught_up(state.indexed_to),
            "malformed_records": state.malformed.to_string(), "unindexed_records": state.unindexed.to_string(),
            "request_limit": MAX_REQUESTS, "reopened": self.reopened,
            "persisted": self.persisted_at.is_some() && self.persist_error.is_none(), "persist_error": self.persist_error,
        });
        let facets = self.facets(query, through);
        let since = query.since;
        let selection = self.select(query, through).clone();
        let order = &selection.order;
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
            "sizes": {"transferred": selection.transferred, "resources": selection.resources},
            "hidden_internal": selection.hidden_internal,
            "timeline": match &selection.timeline {
                Some((first, last, buckets)) => json!({"first_time_ns": first.to_string(),
                    "last_time_ns": last.to_string(), "buckets": buckets}),
                None => json!({"first_time_ns": null, "last_time_ns": null, "buckets": vec![0; TIMELINE_BUCKETS]}),
            },
            "query": {"sort": query.sort, "order": if query.descending { "desc" } else { "asc" }, "q": query.needle,
                "tab_id": query.tab.as_ref().map(|tab| match tab {
                    TabScope::Tab(0) => "unattributed".to_owned(),
                    TabScope::Tab(tab) => tab.to_string(),
                    TabScope::Extension(id) => format!("extension:{id}"),
                }),
                "domain": query.domain, "type": query.kind, "named": query.named.len(),
                "failed": query.failed, "invert": query.invert, "hide_internal": query.hide_internal,
                "third_party": query.third_party,
                "from_ns": (query.from > 0).then(|| query.from.to_string()),
                "to_ns": (query.to < u64::MAX).then(|| query.to.to_string())},
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
            merge(joined.clone(), json!({"resource_type": 13})),
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
            b"application/json; protocol=h2",
            merge(joined.clone(), json!({"status_code": 200})),
        );
        store.push(
            7,
            900,
            "request_completed",
            b"completed",
            merge(
                joined,
                json!({"status_code": 200, "encoded_data_length": "1234", "decoded_body_length": "4567"}),
            ),
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
        // Version 2: the whole target is retained as an artifact.
        let mut long = target(2, 0, &[b'b'; 130], 400);
        long[0] = 2;
        long[9] = 1;
        store.push(
            7,
            907,
            "request_target",
            &long,
            json!({"parent_event_id": start, "artifact_id": "77"}),
        );
        store.push(42, 11, "request_initiated", b"completed", json!({}));
        // A WebUI load only the renderer recorded.
        store.push(43, 12, "request_initiated", b"GET resources", json!({}));
        // Tab 3 subresources after its navigation: another site from the HTTP
        // cache, a service-worker start it served, a font by MIME and a prefetch
        // a Shields synthetic response answered.
        let tab = |extra: Value| merge(json!({"tab_id": 3}), extra);
        store.push(
            7,
            908,
            "request_started",
            b"GET tracker.other.test",
            tab(json!({"resource_type": 4})),
        );
        store.push(
            7,
            908,
            "response_started",
            b"image/gif; protocol=http/1.1",
            tab(json!({"status_code": 200, "flags": 2})),
        );
        store.push(
            7,
            908,
            "request_completed",
            b"completed",
            tab(json!({"encoded_data_length": "0", "decoded_body_length": "43"})),
        );
        store.push(
            7,
            909,
            "request_started",
            b"GET sw.example.test",
            tab(json!({"resource_type": 13, "flags": 4})),
        );
        store.push(
            7,
            909,
            "response_started",
            b"application/json; protocol=h3",
            tab(json!({"status_code": 200, "flags": 4})),
        );
        store.push(
            7,
            909,
            "request_completed",
            b"completed",
            tab(json!({"encoded_data_length": "-1", "decoded_body_length": "12"})),
        );
        store.push(
            7,
            910,
            "request_started",
            b"GET static.example.test",
            tab(json!({"resource_type": 6})),
        );
        store.push(
            7,
            910,
            "response_started",
            b"Font/WOFF2; protocol=h2",
            tab(json!({"status_code": 304})),
        );
        store.push(
            7,
            910,
            "request_completed",
            b"completed",
            tab(json!({"encoded_data_length": "2048", "decoded_body_length": "20480"})),
        );
        store.push(
            7,
            911,
            "request_started",
            b"GET ads.example.test",
            tab(json!({"resource_type": 11})),
        );
        store.push(
            7,
            911,
            "response_started",
            b"synthetic_shields; text/javascript",
            tab(json!({"status_code": 200})),
        );
        store.push(
            7,
            911,
            "request_failed",
            b"failed",
            tab(json!({"error_code": -20, "encoded_data_length": "0", "decoded_body_length": "0"})),
        );
        store
    }
    /// Renderer starts with initiator stacks: a document script, a dedicated
    /// worker's script and a service worker's loader
    /// (protocol/native-network-v3.md, version 3 scope at byte 80).
    fn push_stack_rows(store: &mut Store) {
        for (request, state, thread, key) in
            [(20u64, 1u8, 1u8, 0u64), (21, 1, 2, 0x77), (22, 2, 4, 0x78)]
        {
            let initiated = store.push(
                41,
                request,
                "request_initiated",
                b"GET w.example.test",
                json!({}),
            );
            let mut stack = vec![0u8; 128];
            stack[0] = 3;
            stack[2] = 128;
            stack[4] = state;
            if state == 1 {
                stack[12] = 1;
                stack[8] = 1;
                stack[32] = 9;
                stack[64] = 1;
                stack[68] = 7;
            }
            stack[80] = thread;
            stack[88..96].copy_from_slice(&key.to_le_bytes());
            store.push(
                41,
                request,
                "request_initiator_stack",
                &stack,
                json!({"parent_event_id": initiated}),
            );
        }
    }
    fn reuse(kind: u8, static_data: bool, host: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        bytes[..4].copy_from_slice(&[1, 0, 128, 0]);
        (bytes[4], bytes[5], bytes[6]) = (kind, u8::from(static_data), host.len() as u8);
        bytes[8..8 + host.len()].copy_from_slice(host);
        bytes
    }
    /// Rows only the renderer finishes (protocol/native-network-v3.md): a
    /// `data:` load, memory-cache reuses and a service worker's failure.
    fn renderer_answered(store: &mut Store) {
        let class = |class: u8| json!({"scheme_class": class, "loader_kind": 16, "tab_id": 3});
        let start = store.push(51, 30, "request_initiated", b"GET ", class(5));
        store.push(
            51,
            30,
            "request_target",
            &target(0, 0, b"text/plain,hi", 13),
            json!({"parent_event_id": start, "tab_id": 3}),
        );
        store.push(
            51,
            30,
            "request_completed",
            b"completed",
            merge(
                class(5),
                json!({"status_code": 200, "decoded_body_length": "2", "loader_kind": 0}),
            ),
        );
        let reused = store.push(
            51,
            31,
            "memory_cache_reuse",
            &reuse(1, false, b"cdn.example.test"),
            merge(
                class(2),
                json!({"status_code": 200, "decoded_body_length": "5120"}),
            ),
        );
        store.push(
            51,
            31,
            "request_target",
            &target(2, 0, b"/logo.png?v=2", 13),
            json!({"parent_event_id": reused, "tab_id": 3}),
        );
        store.push(
            51,
            32,
            "memory_cache_reuse",
            &reuse(2, true, b""),
            merge(
                class(5),
                json!({"status_code": 200, "decoded_body_length": "40"}),
            ),
        );
        let start = store.push(
            51,
            33,
            "request_initiated",
            b"GET sw.example.test",
            class(2),
        );
        store.push(
            51,
            33,
            "request_target",
            &target(2, 0, b"/api?id=7", 9),
            json!({"parent_event_id": start, "tab_id": 3}),
        );
        store.push(
            51,
            33,
            "request_failed",
            b"failed",
            merge(
                class(2),
                json!({"error_code": -2, "flags": 4, "loader_kind": 0}),
            ),
        );
        // A race network request: the browser's attempt completed, but the
        // service worker answered the page with a network error.
        store.push(
            51,
            35,
            "request_initiated",
            b"GET race.example.test",
            class(2),
        );
        let raced = json!({"tab_id": 3, "initiator_process_id": 51, "initiator_request_id": 35,
            "browser_context_id_high": "5", "browser_context_id_low": "6"});
        store.push(
            7,
            935,
            "request_started",
            b"GET race.example.test",
            merge(
                raced.clone(),
                json!({"resource_type": 13, "scheme_class": 2, "loader_kind": 3}),
            ),
        );
        store.push(
            7,
            935,
            "response_started",
            b"application/json",
            merge(raced.clone(), json!({"status_code": 200})),
        );
        store.push(
            7,
            935,
            "request_completed",
            b"completed",
            merge(
                raced,
                json!({"status_code": 200, "decoded_body_length": "9"}),
            ),
        );
        store.push(
            51,
            35,
            "request_failed",
            b"failed",
            merge(
                class(2),
                json!({"error_code": -2, "flags": 4, "loader_kind": 0}),
            ),
        );
        // A service worker's end whose start slot was reused: the gap names the row.
        store.push(
            51,
            36,
            "request_initiated",
            b"GET lost.example.test",
            class(2),
        );
        store.push(
            51,
            0,
            "gap",
            b"service_worker_end_lost",
            json!({"initiator_process_id": 51, "initiator_request_id": 36, "frame_id": "0"}),
        );
        // An MHTML archive resource Blink decoded itself: finished, no HTTP status.
        store.push(
            51,
            37,
            "memory_cache_reuse",
            &reuse(1, true, b"archive.example.test"),
            merge(class(2), json!({"decoded_body_length": "64"})),
        );
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
    fn renderer_answered_rows_name_their_scheme_and_memory_cache() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        renderer_answered(&mut store);
        write(&path, &store);
        let document = page(&mut RequestIndex::new(&path), "limit=50&sort=start");
        let rows = document["requests"].as_array().unwrap();
        let summary = |row: &Value| {
            json!([
                row["path"],
                row["target_kind"],
                row["status"],
                row["type"],
                row["memory_cache"],
                row["static_data"],
                row["from_service_worker"],
                row["loader_observed"],
                row["initiator"],
                row["race_network"],
                row["end_lost"]
            ])
        };
        let expected = [
            json!([
                "data:text/plain,hi",
                "url",
                200,
                "other",
                false,
                false,
                false,
                true,
                "renderer",
                false,
                false
            ]),
            json!([
                "https://cdn.example.test/logo.png?v=2",
                "url",
                200,
                "img",
                true,
                false,
                false,
                false,
                "renderer",
                false,
                false
            ]),
            json!([
                "data:", "host", 200, "css", true, true, false, false, "renderer", false, false
            ]),
            json!([
                "https://sw.example.test/api?id=7",
                "url",
                "failed",
                "other",
                false,
                false,
                true,
                true,
                "renderer",
                false,
                false
            ]),
            // The worker's network error, not the race attempt's 200.
            json!([
                "race.example.test",
                "host",
                "failed",
                "xhr",
                false,
                false,
                true,
                true,
                "renderer",
                true,
                false
            ]),
            json!([
                "lost.example.test",
                "host",
                "incomplete",
                "other",
                false,
                false,
                false,
                false,
                "renderer",
                false,
                true
            ]),
            json!([
                "archive.example.test",
                "host",
                "finished",
                "img",
                true,
                true,
                false,
                false,
                "renderer",
                false,
                false
            ]),
        ];
        assert_eq!(rows.iter().map(summary).collect::<Vec<_>>(), expected);
        assert_eq!(rows[4]["error_code"], -2);
        assert_eq!(rows[4]["interrupted"], false);
        // The Failed filter and count follow what the page received.
        let failed = page(&mut RequestIndex::new(&path), "limit=50&failed=1");
        assert_eq!(failed["matching"], 2);
        assert_eq!(rows[1]["resource_size"], 5120);
        assert_eq!(rows[1]["transfer_size"], 0);
        assert_eq!(rows[1]["host"], "cdn.example.test");
        assert_eq!(rows[0]["host"], "data:");
        assert!(rows.iter().all(|row| row["tab_ids"] == json!(["3"])));
        // A malformed reuse payload names no target and is no memory-cache row.
        let mut bad = Store {
            events: Vec::new(),
            sequence: 0,
        };
        let mut payload = reuse(1, false, b"cdn.example.test");
        payload[5] = 4;
        bad.push(
            51,
            34,
            "memory_cache_reuse",
            &payload,
            json!({"scheme_class": 2, "loader_kind": 16}),
        );
        write(&path, &bad);
        let document = page(&mut RequestIndex::new(&path), "limit=50");
        assert_eq!(document["requests"][0]["memory_cache"], false);
        assert_eq!(document["requests"][0]["path"], UNIDENTIFIED);
    }

    #[test]
    fn scheme_class_decides_browser_internal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        store.push(
            43,
            1,
            "request_initiated",
            b"GET newtab",
            json!({"scheme_class": 16}),
        );
        store.push(
            43,
            2,
            "request_initiated",
            b"GET intranet",
            json!({"scheme_class": 2}),
        );
        store.push(43, 3, "request_initiated", b"GET resources", json!({}));
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let document = page(&mut index, "sort=capture&order=asc");
        let internal: Vec<_> = document["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["browser_internal"].as_bool().unwrap())
            .collect();
        assert_eq!(internal, [true, false, true]);
        assert_eq!(page(&mut index, "hide_internal=1")["hidden_internal"], 2);
    }

    #[test]
    fn frameless_scripts_link_to_clients_and_extensions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        let context = json!({"browser_context_id_high": "3", "browser_context_id_low": "4"});
        let with = |extra: Value| {
            let mut fields = context.clone();
            for (key, value) in extra.as_object().unwrap() {
                fields[key] = value.clone();
            }
            fields
        };
        // An update check linked to its version's two client tabs.
        let update = store.push(2, 900, "request_started", b"GET sw.test", context.clone());
        let mut set = vec![0u8; 128];
        set[0..2].copy_from_slice(&1u16.to_le_bytes());
        set[2..4].copy_from_slice(&128u16.to_le_bytes());
        set[4] = 19;
        set[8..16].copy_from_slice(&78u64.to_le_bytes());
        set[16..20].copy_from_slice(&2u32.to_le_bytes());
        set[20..22].copy_from_slice(&2u16.to_le_bytes());
        set[24..28].copy_from_slice(&6u32.to_le_bytes());
        set[28..32].copy_from_slice(&7u32.to_le_bytes());
        store.push(2, 0, "tab_set", &set, json!({"tab_id": 6, "frame_id": "0"}));
        let mut link = vec![0u8; 24];
        link[0..2].copy_from_slice(&1u16.to_le_bytes());
        link[2..4].copy_from_slice(&24u16.to_le_bytes());
        link[4] = 3;
        link[8..16].copy_from_slice(&78u64.to_le_bytes());
        link[16..20].copy_from_slice(&2u32.to_le_bytes());
        store.push(
            2,
            900,
            "request_tab_link",
            &link,
            with(json!({"parent_event_id": update})),
        );
        // An extension's service-worker script recorded by opt-in.
        let id = "abcdefghijklmnopabcdefghijklmnop";
        let script = store.push(2, 901, "request_started", b"GET ext.test", context.clone());
        let mut extension = vec![1, 0, 40, 0, 6, 0, 0, 0];
        extension.extend_from_slice(id.as_bytes());
        store.push(
            2,
            901,
            "request_extension_link",
            &extension,
            with(json!({"parent_event_id": script})),
        );
        store.push(41, 2, "request_initiated", b"GET lost.test", json!({}));
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let document = page(&mut index, "sort=capture&order=asc");
        let tabs: Vec<_> = document["facets"]["tabs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tab| {
                (
                    tab["tab_id"].as_str().unwrap().to_owned(),
                    tab["count"].as_u64().unwrap(),
                )
            })
            .collect();
        let scope = format!("extension:{id}");
        assert_eq!(
            tabs,
            [
                ("6".into(), 1),
                ("7".into(), 1),
                (scope.clone(), 1),
                ("0".into(), 1)
            ]
        );
        let rows = document["requests"].as_array().unwrap();
        assert_eq!(rows[0]["tab_ids"], json!(["6", "7"]));
        assert_eq!(rows[0]["extension_id"], Value::Null);
        assert_eq!(rows[1]["extension_id"], id);
        assert_eq!(rows[1]["records"], 2);
        assert_eq!(page(&mut index, &format!("tab_id={scope}"))["matching"], 1);
        assert_eq!(page(&mut index, "tab_id=7")["matching"], 1);
        assert_eq!(page(&mut index, "tab_id=unattributed")["matching"], 1);
    }

    #[test]
    fn worker_rows_join_every_linked_tab() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        let worker = store.push(51, 5, "request_initiated", b"GET sw.test", json!({}));
        let mut set = vec![0u8; 128];
        set[0..2].copy_from_slice(&1u16.to_le_bytes());
        set[2..4].copy_from_slice(&128u16.to_le_bytes());
        set[4] = 19;
        set[8..16].copy_from_slice(&77u64.to_le_bytes());
        set[16..20].copy_from_slice(&2u32.to_le_bytes());
        set[20..22].copy_from_slice(&2u16.to_le_bytes());
        set[24..28].copy_from_slice(&3u32.to_le_bytes());
        set[28..32].copy_from_slice(&5u32.to_le_bytes());
        let set_sequence = store.push(2, 0, "tab_set", &set, json!({"tab_id": 3}));
        let mut link = vec![0u8; 24];
        link[0..2].copy_from_slice(&1u16.to_le_bytes());
        link[2..4].copy_from_slice(&24u16.to_le_bytes());
        link[4] = 3;
        link[8..16].copy_from_slice(&77u64.to_le_bytes());
        link[16..20].copy_from_slice(&2u32.to_le_bytes());
        store.push(
            2,
            0,
            "request_tab_link",
            &link,
            json!({"initiator_process_id": 51,
            "initiator_request_id": 5, "parent_event_id": set_sequence}),
        );
        store.push(
            41,
            1,
            "request_initiated",
            b"GET page.test",
            json!({"tab_id": 3}),
        );
        store.push(41, 2, "request_initiated", b"GET lost.test", json!({}));
        assert_ne!(worker, "0");
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let document = page(&mut index, "sort=capture&order=asc");
        let tabs: Vec<_> = document["facets"]["tabs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tab| {
                (
                    tab["tab_id"].as_str().unwrap().to_owned(),
                    tab["count"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(tabs, [("3".into(), 2), ("5".into(), 1), ("0".into(), 1)]);
        let row = &document["requests"][0];
        assert_eq!(row["tab_ids"], json!(["3", "5"]));
        assert_eq!(
            row["tab_link"],
            json!({"kind": 3, "count": 2, "complete": true})
        );
        // The link counts as a record but has no request ID to read it by.
        assert_eq!(
            (&row["records"], &row["members"]),
            (
                &json!(2),
                &json!([{"session_id": "1", "process_id": 51, "request_id": "5", "records": 1}])
            )
        );
        assert_eq!(page(&mut index, "tab_id=5")["matching"], 1);
        assert_eq!(page(&mut index, "tab_id=3")["matching"], 2);
        let lost = page(&mut index, "tab_id=unattributed");
        assert_eq!(
            (
                lost["matching"].as_u64(),
                lost["requests"][0]["tab_ids"].clone()
            ),
            (Some(1), json!([]))
        );
    }

    #[test]
    fn navigations_script_started_read_as_script() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        let context =
            json!({"tab_id": 3, "browser_context_id_high": "5", "browser_context_id_low": "6"});
        let start = store.push(
            7,
            950,
            "request_started",
            b"GET www.example.test",
            context.clone(),
        );
        let mut link = vec![1u8, 0, 128, 0, 41, 0, 0, 0, 9];
        link.resize(128, 0);
        store.push(
            7,
            950,
            "navigation_initiator_link",
            &link,
            merge(context.clone(), json!({"parent_event_id": start})),
        );
        store.push(
            7,
            951,
            "request_started",
            b"GET typed.example.test",
            context,
        );
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let document = page(&mut index, "sort=capture&order=asc");
        assert_eq!(document["requests"][0]["initiator"], "script");
        assert_eq!(document["requests"][0]["initiator_frame"], Value::Null);
        assert_eq!(document["requests"][1]["initiator"], "browser");
    }

    #[test]
    fn script_rows_carry_their_innermost_frame_and_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        let initiated = store.push(41, 1, "request_initiated", b"GET api.test", json!({}));
        let mut stack = vec![0u8; 128];
        stack[4] = 1;
        stack[64] = 1;
        stack[68..72].copy_from_slice(&7u32.to_le_bytes());
        stack[72..76].copy_from_slice(&30u32.to_le_bytes());
        store.push(
            41,
            1,
            "request_initiator_stack",
            &stack,
            json!({"parent_event_id": initiated}),
        );
        let mut identity = vec![0u8; 128];
        identity[8..12].copy_from_slice(&7u32.to_le_bytes());
        store.push(41, 0, "script_identity", &identity, json!({}));
        store.push(41, 2, "request_initiated", b"GET parser.test", json!({}));
        // A dedicated worker's version 3 stack names script 7 of its own isolate.
        let worker_initiated = store.push(41, 3, "request_initiated", b"GET w.test", json!({}));
        let mut worker_stack = stack.clone();
        worker_stack[0] = 3;
        worker_stack[80] = 2;
        worker_stack[88..96].copy_from_slice(&0x77u64.to_le_bytes());
        store.push(
            41,
            3,
            "request_initiator_stack",
            &worker_stack,
            json!({"parent_event_id": worker_initiated}),
        );
        let mut worker_identity = identity.clone();
        worker_identity[0] = 2;
        worker_identity[72] = 2;
        worker_identity[80..88].copy_from_slice(&0x77u64.to_le_bytes());
        store.push(41, 0, "script_identity", &worker_identity, json!({}));
        // A worker stack with no script on it is the worker's loader.
        let loader_initiated = store.push(41, 4, "request_initiated", b"GET l.test", json!({}));
        let mut loader = vec![0u8; 128];
        loader[0] = 3;
        loader[4] = 2;
        loader[80] = 3;
        loader[88..96].copy_from_slice(&0x78u64.to_le_bytes());
        store.push(
            41,
            4,
            "request_initiator_stack",
            &loader,
            json!({"parent_event_id": loader_initiated}),
        );
        // A worker past the renderer's stack table limit walked nothing.
        let limited_initiated = store.push(41, 5, "request_initiated", b"GET u.test", json!({}));
        let mut limited = loader.clone();
        limited[4] = 6;
        store.push(
            41,
            5,
            "request_initiator_stack",
            &limited,
            json!({"parent_event_id": limited_initiated}),
        );
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let document = page(&mut index, "sort=capture&order=asc");
        let (script, parser) = (&document["requests"][0], &document["requests"][1]);
        assert_eq!(script["initiator"], "script");
        assert_eq!(
            script["initiator_frame"],
            json!({"session_id": "1", "process_id": 41, "isolate_key": "0", "thread": 0,
                "frame": hex::encode(&stack[64..80]), "identity": hex::encode(&identity)})
        );
        assert_eq!(parser["initiator_frame"], Value::Null);
        let (worker, loader) = (&document["requests"][2], &document["requests"][3]);
        assert_eq!(worker["initiator"], "worker_script");
        assert_eq!(
            worker["initiator_frame"],
            json!({"session_id": "1", "process_id": 41, "isolate_key": "119", "thread": 2,
                "frame": hex::encode(&worker_stack[64..80]),
                "identity": hex::encode(&worker_identity)})
        );
        assert_eq!(loader["initiator"], "worker_loader");
        let limited = &document["requests"][4];
        assert_eq!(
            (&limited["initiator"], &limited["initiator_frame"]),
            (&json!("worker_unwalked"), &Value::Null)
        );
        // Identities of the same script ID stay apart per isolate.
        let (identities, _) = index.identities("1", 41).unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[&(0x77, 7)], hex::encode(&worker_identity));
    }

    #[test]
    fn rows_follow_the_traffic_model() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        write(&path, &fixture());
        let mut index = RequestIndex::new(&path);
        let document = page(&mut index, "");
        let rows = document["requests"].as_array().unwrap();
        assert_eq!(document["total"], 15);
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
        assert_eq!(document["failed"], 2);
        let tabs = document["facets"]["tabs"].as_array().unwrap();
        assert_eq!(
            (&tabs[0]["tab_id"], &tabs.last().unwrap()["tab_id"]),
            (&json!("3"), &json!("0"))
        );
        assert_eq!(document["index"]["complete"], true);
        let fields = |row: &Value, keys: &[&str]| {
            keys.iter().map(|key| row[*key].clone()).collect::<Vec<_>>()
        };
        let measured = [
            "transfer_size",
            "resource_size",
            "mime_type",
            "protocol",
            "initiator",
            "response_time_ns",
        ];
        assert_eq!(
            fields(joined, &measured),
            [
                json!(1234),
                json!(4567),
                json!("application/json"),
                json!("h2"),
                json!("renderer"),
                json!("4000000")
            ]
        );
        assert_eq!(
            fields(&rows[1], &["main_frame", "initiator"]),
            [json!(true), json!("browser")]
        );
        assert_eq!(rows[5]["type"], "css", "a missing start is classed by MIME");
        assert_eq!(
            fields(
                &rows[10],
                &["browser_internal", "loader_observed", "initiator", "status"]
            ),
            [
                json!(true),
                json!(false),
                json!("renderer"),
                json!("pending")
            ]
        );
        assert_eq!(
            fields(
                &rows[11],
                &[
                    "from_cache",
                    "type",
                    "transfer_size",
                    "resource_size",
                    "protocol"
                ]
            ),
            [
                json!(true),
                json!("img"),
                json!(0),
                json!(43),
                json!("http/1.1")
            ]
        );
        assert_eq!(
            fields(
                &rows[12],
                &[
                    "initiator",
                    "from_service_worker",
                    "transfer_size",
                    "resource_size"
                ]
            ),
            [json!("worker"), json!(true), Value::Null, json!(12)]
        );
        assert_eq!(
            fields(&rows[13], &["type", "mime_type", "status"]),
            [json!("font"), json!("font/woff2"), json!(304)]
        );
        assert_eq!(
            fields(
                &rows[14],
                &["type", "mime_type", "protocol", "error_code", "status"]
            ),
            [
                json!("js"),
                json!("text/javascript"),
                Value::Null,
                json!(-20),
                json!("failed")
            ]
        );
        assert_eq!(rows[7]["path"], "files.example.test/upload/1");
    }

    #[test]
    fn filter_tokens_flags_time_range_and_totals() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        write(&path, &fixture());
        let mut index = RequestIndex::new(&path);
        let ordinals = |document: &Value| {
            document["requests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["ordinal"].as_u64().unwrap())
                .collect::<Vec<_>>()
        };
        for (raw, expected) in [
            ("q=domain:*.other.test", vec![11]),
            ("q=domain:api.example.test", vec![0]),
            ("q=method:post", vec![2]),
            ("q=status-code:304", vec![13]),
            ("q=larger-than:2k", vec![]),
            ("q=larger-than:1k", vec![0, 13]),
            ("q=mime-type:application/json", vec![0, 12]),
            ("q=-example%20-localhost%20-event", vec![10, 11]),
            (
                "q=-status-code:200%20-domain:*.test",
                vec![4, 5, 6, 8, 9, 10],
            ),
            ("q=example&invert=1", vec![4, 5, 6, 9, 10, 11]),
            ("invert=1", (0..15).collect()),
            ("failed=1", vec![2, 14]),
            ("third_party=1", vec![11]),
            ("q=larger-than:big", vec![]),
            ("from_ns=30000000&to_ns=33000000", vec![12, 13]),
        ] {
            assert_eq!(ordinals(&page(&mut index, raw)), expected, "{raw}");
        }
        let hidden = page(&mut index, "hide_internal=1");
        assert_eq!(
            (hidden["matching"].as_u64(), &hidden["hidden_internal"]),
            (Some(14), &json!(1))
        );
        let totals = page(&mut index, "q=example");
        assert_eq!(
            totals["sizes"],
            json!({"transferred": 1234 + 2048, "resources": 4567 + 12 + 20480})
        );
        let timeline = &page(&mut index, "from_ns=30000000")["timeline"];
        assert_eq!(
            (&timeline["first_time_ns"], &timeline["last_time_ns"]),
            (&json!("1000000"), &json!("36000000"))
        );
        assert_eq!(
            timeline["buckets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap())
                .sum::<u64>(),
            15
        );
        for bad in [
            "failed=yes",
            "from_ns=9&to_ns=1",
            "invert=1&invert=0",
            "to_ns=-1",
        ] {
            assert!(RequestQuery::parse(&Query::new(bad), bad).is_err(), "{bad}");
        }
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
                json!({"resource_type": if request % 2 == 0 { 13 } else { 3 }, "tab_id": 1 + request % 3}));
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
            "sort=bytes",
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
    fn a_shared_request_number_chooses_the_browser_row() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        // A renderer's own number 5 for one request, then unrelated traffic.
        store.push(41, 5, "request_initiated", b"GET a.example.test", json!({}));
        store.push(
            41,
            77,
            "request_initiated",
            b"GET x.example.test",
            json!({}),
        );
        let renderer_end = store.bytes().len() as u64;
        // The browser's request 5, which is what its header records name.
        store.push(7, 5, "request_started", b"GET b.example.test", json!({}));
        store.push(
            7,
            5,
            "response_started",
            b"text/plain",
            json!({"status_code": 200}),
        );
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let range = index.member_range(Some("1"), None, "5").unwrap().unwrap();
        assert!(
            range.first >= renderer_end,
            "the browser row's range starts past the renderer's: {range:?}"
        );
        // A process still selects its own row.
        let renderer = index
            .member_range(Some("1"), Some(41), "5")
            .unwrap()
            .unwrap();
        assert!(renderer.end <= renderer_end, "{renderer:?}");
        // A number no browser row uses still finds its row.
        let only = index.member_range(Some("1"), None, "77").unwrap().unwrap();
        assert!(only.end <= renderer_end, "{only:?}");
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
        assert_eq!(page(&mut first, "")["total"], 15);
        file.write_all(&line[20..]).unwrap();
        file.write_all(b"\n{\"category\":\"network\",broken\n")
            .unwrap();
        let grown = page(&mut first, "");
        assert_eq!(
            (&grown["total"], &grown["index"]["malformed_records"]),
            (&json!(16), &json!("1"))
        );
        assert_eq!(grown["index"]["epoch"], epoch);
        first.persist();
        let mut reopened = RequestIndex::new(&path);
        let document = page(&mut reopened, "");
        assert_eq!(
            (&document["total"], &document["index"]["reopened"]),
            (&json!(16), &json!(true))
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
            (&json!(16), &json!(false))
        );
        assert_eq!(rebuilt["index"]["malformed_records"], "2");
        reopened.discard().unwrap();
        assert!(!sidecar.exists(), "a clear removes the derived copy");
        fs::write(&path, b"").unwrap();
        assert_eq!(page(&mut reopened, "")["total"], 0);
    }

    #[test]
    fn a_line_torn_before_its_category_is_counted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        store.push(42, 5, "request_initiated", b"", json!({}));
        let mut bytes = store.bytes();
        bytes.extend_from_slice(b"{\"protocol_version\":3,\"session\n");
        // A complete object of another category stays uncounted and unread.
        bytes.extend_from_slice(b"{\"category\":\"wasm\"}\n");
        fs::write(&path, bytes).unwrap();
        let mut index = RequestIndex::new(&path);
        assert_eq!(page(&mut index, "")["index"]["malformed_records"], "1");
    }

    #[test]
    fn a_watch_match_counts_toward_its_renderer_member() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        store.push(42, 5, "request_initiated", b"", json!({}));
        store.push(42, 5, "request_watch_match", &[0; 80], json!({}));
        fs::write(&path, store.bytes()).unwrap();
        let mut index = RequestIndex::new(&path);
        let row = &page(&mut index, "")["requests"][0];
        assert_eq!(row["records"], 2, "{row}");
        assert_eq!(row["members"][0]["records"], 2);
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
        let mut store = fixture();
        push_stack_rows(&mut store);
        renderer_answered(&mut store);
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        let mut document = page(&mut index, "limit=500");
        let orders = [
            "name",
            "method",
            "type",
            "status",
            "time",
            "size",
            "initiator",
            "start",
            "protocol",
        ]
        .map(|sort| {
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
        let filters = [
            "q=domain:*.example.test",
            "q=domain:localhost",
            "q=-example",
            "q=method:post%20larger-than:1",
            "q=-status-code:200",
            "q=larger-than:1k",
            "q=mime-type:application/json",
            "q=example&invert=1",
            "q=get%20-cdn&invert=1&hide_internal=1",
            "failed=1",
            "third_party=1",
            "hide_internal=1",
            "from_ns=5000000&to_ns=12000000",
            "q=example&from_ns=20000000&hide_internal=1",
        ]
        .map(|raw| {
            let answer = page(&mut index, &format!("limit=500&{raw}"));
            (
                raw.to_owned(),
                json!({"ids": ids(&answer), "sizes": answer["sizes"], "hidden_internal": answer["hidden_internal"],
                    "timeline": answer["timeline"]}),
            )
        });
        let golden = json!({"events": store.events, "rows": document["requests"].take(),
            "orders": orders.into_iter().collect::<serde_json::Map<_, _>>(),
            "searches": searches.into_iter().collect::<serde_json::Map<_, _>>(),
            "filters": filters.into_iter().collect::<serde_json::Map<_, _>>()});
        fs::write(output, serde_json::to_vec_pretty(&golden).unwrap()).unwrap();
    }
}
