//! Session-wide request index for Traffic; contract in protocol/request-index-v2.md.
//!
//! Rows live in a SQLite index beside the event store (`index_db`), one per
//! request of the whole session, so Traffic filters, sorts and pages a session
//! of any length with the database's bounded page cache in memory. Each row
//! keeps its folded state as JSON beside the columns its queries filter, sort
//! and count by; a query's ordered rows sit in a temporary table that the next
//! page reads instead of sorting again.
use crate::{
    app::{Query, validate_event},
    error::{Error, Result},
    event_query::RecordRange,
    event_window::unsigned,
    index_db::{self, Indexed, Position, SqlResult},
};
use regex::Regex;
use rusqlite::{
    Connection, OptionalExtension, Transaction, params, params_from_iter, types::Value as SqlValue,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, hash_map::Entry},
    path::{Path, PathBuf},
    sync::LazyLock,
    time::{Duration, Instant},
};

pub const SIDECAR_SUFFIX: &str = ".requests-v2";
/// Version 1 kept at most 131,072 rows in one JSON file; version 2 removes it.
const LEGACY_SUFFIX: &str = ".requests-v1";
const FORMAT: &str = "reb-request-index-v2";
/// The index's row layout; an index of another layout is rebuilt from byte 0.
const LAYOUT: &str = "reb-request-index-v2/3";
const RECORD_BYTES: usize = 4096;
/// How long a read folds new records before it answers from what is indexed.
/// The backend's indexer folds the rest in the background, so a long store
/// answers with partial coverage while it is first indexed.
const READ_FOLD: Duration = Duration::from_millis(200);
/// One background fold: a read waits for the index at most this long.
pub const FOLD_SLICE: Duration = Duration::from_millis(250);
/// Rows a fold holds before writing them back (`Batch`).
const HELD_ROWS: usize = 4096;
/// Row ids and request keys a fold remembers between write-backs.
const HELD_KEYS: usize = 65_536;
const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 500;
/// Domains a tab facet previews; the domain facet of that tab lists them all.
const TAB_DOMAINS: usize = 8;
const MAX_NAMED: usize = 64;
const MAX_LOCATE: usize = 4;
const MAX_TEXT: usize = 512;
const TIMELINE_BUCKETS: usize = 120;
/// `script_identity` payloads of one renderer, keyed by isolate key and script
/// ID: script IDs are unique only within one isolate.
pub type IdentityPayloads = HashMap<(u64, u32), String>;
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
pub(crate) struct Target {
    pub(crate) scheme: Option<String>,
    pub(crate) port: u16,
    pub(crate) length: u32,
    pub(crate) text: String,
}
/// A `response_body` child (protocol/native-network-v3.md), decoded as
/// `decodeResponseBodyRecord` does.
#[derive(Clone, Serialize, Deserialize)]
struct BodyRecord {
    state: u8,
    flags: u8,
    body_length: u64,
    captured: u64,
    partial_index: u16,
    artifact: String,
    sha256: Option<String>,
}
/// The newest `response_body` child of one lifecycle record: its parent, its
/// own sequence and time, and the record (`None` is malformed).
#[derive(Clone, Serialize, Deserialize)]
struct BodyChild {
    parent: (String, u32, u64),
    sequence: u64,
    time: u64,
    record: Option<BodyRecord>,
    /// The newest partial record of the same parent that names retained
    /// bytes: its sequence, time and record. A later refusal does not remove
    /// the snapshot the receiver holds.
    #[serde(default)]
    snapshot: Option<(u64, u64, BodyRecord)>,
}
/// The first `request_watch_match` of a row: the record, and its rule slot
/// and method flag as the debugger decoder reads them, or None for a record
/// the core refuses (protocol/native-debugger-observation-v1.md).
#[derive(Clone, Serialize, Deserialize)]
struct Watch {
    session: String,
    process: u32,
    sequence: String,
    frame: String,
    rule: Option<u64>,
    method_matched: Option<bool>,
}
/// First `request_target` child of a lifecycle record; `None` is malformed.
#[derive(Clone, Serialize, Deserialize)]
struct Child {
    parent: (String, u32, String),
    target: Option<Target>,
}

/// A request's folded state. It is stored without the fields that hold
/// their default (`encode`), which `#[serde(default)]` restores.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
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
    /// The row a version 2 reuse names as the request whose response Blink reused.
    memory_cache_source: Option<String>,
    /// The newest `response_started`: its session, process and sequence.
    response: Option<(String, u32, u64)>,
    /// `response_body` children, the newest of each parent.
    bodies: Vec<BodyChild>,
    /// The row has a `request_redirected` record.
    redirected: bool,
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
    /// The request watch rule that matched the row's request, if one did.
    watch: Option<Watch>,
    /// The renderer `request_initiated`'s loader kind and whether it had a
    /// frame, and the browser `request_started`'s newest nonzero loader kind:
    /// why a row without an owner has none (`request_tabs::unresolved_reason`).
    renderer_start: Option<(u8, bool)>,
    browser_start: Option<u8>,
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
    index: Indexed,
    /// Answers for a store that does not exist yet, or no longer does.
    empty: Option<Connection>,
    empty_epoch: String,
    /// Where the index stood at the last refresh; None before the first.
    position: Option<Position>,
    /// The store did not exist at the last refresh.
    missing: bool,
    /// Changes whenever the indexed rows may have changed.
    generation: u64,
    total: usize,
    malformed: u64,
    legacy_removed: bool,
    /// The query whose ordered rows the temporary `selection` table holds.
    selection: Option<(String, u64, Summary)>,
    facets: Option<(String, u64, (Value, i64))>,
}

/// What the footer and timing strip show for one query's rows.
#[derive(Clone)]
struct Summary {
    matching: usize,
    hidden_internal: u64,
    transferred: u64,
    resources: u64,
    /// First start, last record and per-bucket starts of every row the time range would admit.
    timeline: Option<(u64, u64, Vec<u64>)>,
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
    /// An export's exact rows by ID, in their order, in place of a selection.
    rows: Vec<String>,
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
/// The keys an export takes: a whole selection in list order, never a page.
pub const EXPORT_KEYS: [&str; 14] = [
    "through",
    "sort",
    "order",
    "q",
    "tab_id",
    "domain",
    "type",
    "named",
    "failed",
    "invert",
    "hide_internal",
    "third_party",
    "from_ns",
    "to_ns",
];
impl RequestQuery {
    pub fn parse(q: &Query, raw: &str) -> Result<Self> {
        q.only(&QUERY_KEYS, &[])?;
        Self::read(q, raw)
    }
    /// The selection of an export, which also takes `extra` keys of its own,
    /// or with `rows` the exact rows it names, in that order.
    pub fn parse_export(q: &Query, raw: &str, extra: &[&str]) -> Result<Self> {
        let mut keys = extra.to_vec();
        keys.push("rows");
        q.only(&EXPORT_KEYS, &keys)?;
        let mut query = Self::read(q, raw)?;
        if let Some(list) = q.one("rows")? {
            if EXPORT_KEYS
                .iter()
                .any(|key| q.one(key).is_ok_and(|value| value.is_some()))
            {
                return Err(Error::bad(
                    "rows names the exact rows to export; pass no selection parameter with it",
                ));
            }
            query.rows = list.split(',').map(str::to_owned).collect();
            if query
                .rows
                .iter()
                .any(|id| id.is_empty() || id.len() > MAX_TEXT)
            {
                return Err(Error::bad("rows lists request row IDs separated by commas"));
            }
        }
        Ok(query)
    }
    fn read(q: &Query, raw: &str) -> Result<Self> {
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
            failed: q.flag("failed")?,
            invert: q.flag("invert")?,
            hide_internal: q.flag("hide_internal")?,
            third_party: q.flag("third_party")?,
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
            rows: Vec::new(),
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
/// A decoded `memory_cache_reuse` payload.
struct Reuse {
    blink_type: u8,
    static_data: bool,
    host: String,
    /// Version 2: the row of the renderer request whose response was reused.
    source: Option<String>,
}
/// A `memory_cache_reuse` payload: Blink resource type, static data, host and
/// the source it names. Port of `decodeMemoryCacheReuse`; the C++ core and
/// Python share its rules.
fn memory_cache(event: &Value) -> Option<Reuse> {
    // Every lifecycle record comes here; only a reuse pays for decoding.
    if event["type"] != "memory_cache_reuse" {
        return None;
    }
    let bytes = hex::decode(event["payload"].as_str()?).ok()?;
    let (kind, flags, length) = (*bytes.get(4)?, *bytes.get(5)?, usize::from(*bytes.get(6)?));
    let host = bytes.get(8..8 + length)?;
    let version = *bytes.first()?;
    let named = flags & 4 != 0;
    let (process, initiator, request) = (
        number(&event["process_id"]),
        number(&event["initiator_process_id"]),
        number(&event["initiator_request_id"]),
    );
    (event["protocol_version"] == 3
        && event["flags"] == 0
        && bytes.len() == 128
        && (version == 1 || version == 2)
        && bytes[1..4] == [0, 128, 0]
        && (1..=15).contains(&kind)
        && flags & !(if version == 2 { 7 } else { 3 }) == 0
        && !(named && flags & 1 != 0)
        && if named {
            initiator == process && request > 0
        } else {
            initiator == 0 && request == 0
        }
        && length <= 120
        && bytes[7] == 0
        && (flags & 2 == 0 || length == 120)
        && host.iter().all(|b| (0x21..=0x7e).contains(b))
        && bytes[8 + length..].iter().all(|b| *b == 0))
    .then(|| Reuse {
        blink_type: kind,
        static_data: flags & 1 != 0,
        host: String::from_utf8_lossy(host).into_owned(),
        source: named.then(|| correlated_identity(event)),
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
pub(crate) fn site(domain: &str) -> Option<String> {
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
    // A reuse's initiator fields name its source row, not a loader of its own.
    let initiator = if event["type"] == "memory_cache_reuse" {
        0
    } else {
        number(&event["initiator_process_id"])
    };
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
fn canonical(value: &Value, nonzero: bool) -> Option<u64> {
    value
        .as_str()
        .and_then(|_| crate::validation::canonical(value, 64, nonzero, "").ok())
}
/// Port of `decodeRequestTargetRecord`.
/// Port of `decodeResponseBodyRecord`; the C++ core and the Python validator
/// share its rules (protocol/native-network-v3.md `response_body`).
fn decode_response_body(event: &Value) -> Option<BodyRecord> {
    // Versions 1 and 2 kept at most this much of a body.
    const CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
    let payload = event["payload"].as_str()?;
    let (sequence, parent) = (
        canonical(&event["sequence_number"], true)?,
        canonical(&event["parent_event_id"], true)?,
    );
    let process = event["process_id"].as_u64()?;
    let artifact = canonical(&event["artifact_id"], false)?;
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
    let bytes = hex::decode(payload).ok()?;
    let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let (state, flags, type_length, coding_count) = (bytes[4], bytes[5], bytes[6], bytes[7]);
    let (body, captured, partial) = (u64_at(8), u64_at(16), u16_at(28));
    let digest = &bytes[32..64];
    let content_type = &bytes[64..64 + usize::from(type_length.min(64))];
    let token = |part: &[u8]| {
        !part.is_empty()
            && part.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || b"!#$%&'*+.^_`|~-".contains(byte)
            })
    };
    let typed = flags & 0x40 != 0;
    let mut halves = content_type.splitn(2, |byte| *byte == b'/');
    let well_typed = !typed
        || matches!((halves.next(), halves.next()), (Some(kind), Some(sub)) if token(kind) && token(sub));
    // Version 2 adds bit 7, snapshots withheld by a byte bound. Version 3
    // keeps every body whole and every media type.
    let version = u16_at(0);
    let limited = version < 3;
    if !(1..=3).contains(&version)
        || u16_at(2) != 128
        || u16_at(30) != 0
        || !(1..=13).contains(&state)
        || flags & !(if version == 1 { 0x7f } else { 0xff }) != 0
        || type_length > 64
        || typed != (type_length != 0)
        || bytes[64 + usize::from(type_length.min(64))..]
            .iter()
            .any(|byte| *byte != 0)
        || !well_typed
        || coding_count > 4
        || (flags & 0x10 != 0 && coding_count != 4)
        || bytes[24..28].iter().enumerate().any(|(index, coding)| {
            if index < usize::from(coding_count) {
                !matches!(coding, 1..=7 | 15)
            } else {
                *coding != 0
            }
        })
    {
        return None;
    }
    let retained = captured != 0;
    let whole = if limited {
        body.min(CAPTURE_BYTES)
    } else {
        body
    };
    if captured > body
        || (artifact != 0) != retained
        || digest.iter().any(|byte| *byte != 0) != retained
        || (flags & 1 != 0 && !retained)
        || (partial != 0) != (state == 3)
        || (flags & 0x20 != 0 && !matches!(state, 1 | 2 | 6))
    {
        return None;
    }
    let valid = match state {
        1 => body != 0 && captured == body,
        2 => limited && body > CAPTURE_BYTES && captured == CAPTURE_BYTES,
        3 => body != 0 && captured == whole,
        4 | 5 => !retained || captured == whole,
        6..=8 => body == 0,
        9 => limited && body == 0,
        12 => limited && !retained,
        13 => !limited && !retained,
        _ => !retained,
    };
    valid.then(|| BodyRecord {
        state,
        flags,
        body_length: body,
        captured,
        partial_index: partial,
        artifact: artifact.to_string(),
        sha256: retained.then(|| hex::encode(digest)),
    })
}
const BODY_STATES: [&str; 13] = [
    "captured",
    "captured_truncated",
    "partial",
    "aborted",
    "cancelled",
    "empty",
    "not_modified",
    "redirected",
    "not_captured_type",
    "not_captured_artifact_unavailable",
    "not_captured_transfer_refused",
    "not_captured_session_budget",
    "not_captured_disk_reserve",
];
/// Why a row's response body is or is not retained: its final response's
/// newest `response_body` record, else why there is none. Port of
/// `responseBodyCase` (protocol/native-network-v3.md "Bodies the proxy never
/// sees"); `request-index-check` holds the two equal.
fn body_case(row: &Row) -> (&'static str, Option<&BodyChild>) {
    let (failed, interrupted, _, error) = outcome(row);
    let body = row
        .response
        .as_ref()
        .and_then(|response| row.bodies.iter().find(|body| body.parent == *response));
    if let Some(body) = body {
        let case = body.record.as_ref().map_or("malformed", |record| {
            BODY_STATES[usize::from(record.state) - 1]
        });
        return (case, Some(body));
    }
    let case = if row.response.is_some() {
        if matches!(row.resource.as_str(), "js" | "wasm") {
            "source_artifact"
        } else {
            "no_record"
        }
    } else if row.memory_cache {
        "memory_cache"
    } else if row.worker_served && !failed && !interrupted && row.rank >= 5 {
        "service_worker"
    // A failure, an ended observation or an open request after a redirect is
    // that, not a redirect whose body was discarded.
    } else if failed {
        if error == -3 {
            "cancelled_before_response"
        } else {
            "failed_before_response"
        }
    } else if interrupted {
        "interrupted"
    } else if row.end_lost {
        "end_lost"
    } else if row.rank < 5 {
        "pending"
    } else if row.redirected {
        "redirected"
    } else if !row.browser {
        "renderer_answered"
    } else {
        "no_response"
    };
    (case, None)
}
/// Why a reuse's named source row is not its load. A renderer request ID names
/// a row only within its process and session, so a process ID reused within
/// the session can name another renderer's request: the source must have the
/// reuse's web host (a 120-byte reuse host is a prefix) and have started first.
fn source_mismatch(reuse: &Row, source: &Row) -> Option<&'static str> {
    if reuse_host_differs(reuse.scheme_class, &reuse.path, &source.path) {
        return Some("host_differs");
    }
    (source.first_ns > reuse.first_ns).then_some("started_after")
}
/// Whether a web reuse's host and its named source's host are known and
/// differ; a 120-byte reuse host is a prefix. `get_xrefs` applies the same rule.
pub(crate) fn reuse_host_differs(scheme_class: u8, reuse: &str, source: &str) -> bool {
    let (host, other) = (reuse.to_ascii_lowercase(), source.to_ascii_lowercase());
    let known = |name: &str| !name.is_empty() && name != UNIDENTIFIED.to_ascii_lowercase();
    (1..=4).contains(&scheme_class)
        && known(&host)
        && known(&other)
        && host != other
        && !(host.len() == 120 && other.starts_with(&host))
}
/// The host a valid `memory_cache_reuse` record names, else None.
pub(crate) fn reuse_host(event: &Value) -> Option<String> {
    memory_cache(event).map(|reuse| reuse.host)
}
/// The `response_body` answer of a row: its case and, for a record, what it names.
fn body_document(row: &Row) -> Value {
    let (case, body) = body_case(row);
    let record = body.and_then(|body| body.record.as_ref().map(|record| (body, record)));
    json!({
        "case": case,
        "artifact_id": record.and_then(|(_, record)| (record.artifact != "0").then(|| record.artifact.clone())),
        "body_length": record.map(|(_, record)| record.body_length.to_string()),
        "captured_length": record.map(|(_, record)| record.captured.to_string()),
        "partial_index": record.map(|(_, record)| record.partial_index),
        "shared": record.is_some_and(|(_, record)| record.flags & 1 != 0),
        // Version 2 bit 7: a byte bound withheld a snapshot the spacing allowed.
        "snapshots_withheld": record.is_some_and(|(_, record)| record.flags & 0x80 != 0),
        "sha256": record.and_then(|(_, record)| record.sha256.clone()),
        "record_sequence": body.map(|body| body.sequence.to_string()),
        "record_time_ns": body.map(|body| body.time.to_string()),
        "response_started": row.response.as_ref().map(|(session, process, sequence)| json!({
            "session_id": session, "process_id": process, "sequence_number": sequence.to_string()})),
        // A refusal, or any newest record without bytes, does not hide a
        // snapshot of the same response the receiver still holds.
        "earlier_snapshot": body
            .filter(|body| body.record.as_ref().is_none_or(|record| record.artifact == "0"))
            .and_then(|body| body.snapshot.as_ref())
            .map(|(sequence, time, snapshot)| json!({
                "artifact_id": snapshot.artifact, "body_length": snapshot.body_length.to_string(),
                "captured_length": snapshot.captured.to_string(), "partial_index": snapshot.partial_index,
                "sha256": snapshot.sha256, "record_sequence": sequence.to_string(), "record_time_ns": time.to_string()})),
    })
}
pub(crate) fn decode_target(event: &Value) -> Option<Target> {
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

/// One row per request: the columns queries filter, sort and count by,
/// derived from its folded state at each write. The state itself is in
/// `states`, so a query that scans every row reads only these. Times and
/// offsets are below 2^63 (`clamp`); tab IDs keep their bits (`index_db::key`).
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS rows(
    ordinal INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    first_ns INTEGER NOT NULL,
    last_ns INTEGER NOT NULL,
    tab INTEGER NOT NULL,
    tab_set TEXT,
    extension TEXT,
    resource TEXT NOT NULL,
    failed INTEGER NOT NULL,
    internal INTEGER NOT NULL,
    main_frame INTEGER NOT NULL,
    domain TEXT NOT NULL,
    domain_lower TEXT NOT NULL,
    host_lower TEXT NOT NULL,
    site TEXT,
    haystack TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    transfer INTEGER,
    decoded INTEGER,
    mime TEXT,
    protocol TEXT,
    name TEXT NOT NULL,
    name_fold TEXT NOT NULL,
    type_label TEXT NOT NULL,
    initiator_label TEXT,
    duration_us INTEGER,
    root_session TEXT,
    root_process INTEGER,
    root_sequence TEXT,
    body_case TEXT NOT NULL,
    body_withheld INTEGER NOT NULL,
    body_earlier INTEGER NOT NULL,
    first_offset INTEGER NOT NULL,
    end_offset INTEGER NOT NULL,
    loader INTEGER NOT NULL,
    start_request TEXT);
-- Each row's folded state as JSON (`encode`).
CREATE TABLE IF NOT EXISTS states(ordinal INTEGER PRIMARY KEY, data BLOB NOT NULL);
-- Third-party rows compare their site with their tab's latest document.
CREATE INDEX IF NOT EXISTS rows_documents ON rows(tab, first_ns, ordinal)
    WHERE main_frame = 1 AND tab != 0;
-- The session summary counts every row's body case from this compact index,
-- without reading the rows or sorting them.
CREATE INDEX IF NOT EXISTS rows_body_cases ON rows(body_case, body_withheld, body_earlier);
-- The rows each (session, process, request) member belongs to.
CREATE TABLE IF NOT EXISTS members(
    request TEXT NOT NULL,
    session TEXT NOT NULL,
    process INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    PRIMARY KEY (request, session, process, ordinal)) WITHOUT ROWID;
-- Browser request keys to the row id a renderer record gave them.
CREATE TABLE IF NOT EXISTS keys(key TEXT PRIMARY KEY, id TEXT NOT NULL) WITHOUT ROWID;
-- Worker tab sets (protocol/native-network-v3.md `tab_set`): each set's total
-- and the tabs of its parts seen so far.
CREATE TABLE IF NOT EXISTS tab_sets(key TEXT PRIMARY KEY, total INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS set_tabs(
    set_key TEXT NOT NULL,
    tab INTEGER NOT NULL,
    PRIMARY KEY (set_key, tab)) WITHOUT ROWID;
-- The newest `script_identity` payload of each script, for the Initiator
-- column's innermost frame.
CREATE TABLE IF NOT EXISTS identities(
    session TEXT NOT NULL,
    process INTEGER NOT NULL,
    isolate INTEGER NOT NULL,
    script INTEGER NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (session, process, isolate, script)) WITHOUT ROWID;
-- Each session's `script_cookie` records by byte range: a cookie spans the
-- session, so provenance reads its script calls wherever they sit.
CREATE TABLE IF NOT EXISTS script_cookies(
    session TEXT NOT NULL,
    start INTEGER NOT NULL,
    end INTEGER NOT NULL,
    PRIMARY KEY (session, start)) WITHOUT ROWID;
-- Each session's `cookie_list` records of an indexed request by byte range,
-- for the same reason: provenance reads every list that set or sent a name.
CREATE TABLE IF NOT EXISTS cookie_lists(
    session TEXT NOT NULL,
    start INTEGER NOT NULL,
    end INTEGER NOT NULL,
    PRIMARY KEY (session, start)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS counts(id INTEGER PRIMARY KEY CHECK (id = 0), malformed INTEGER NOT NULL);
INSERT OR IGNORE INTO counts VALUES (0, 0);
";

/// A stored time for SQL comparison: monotonic times stay below 2^63.
fn clamp(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn root(row: &Row) -> Option<&Root> {
    row.roots.iter().flatten().next()
}

impl Row {
    fn new(id: String, kind: &str, start: u64, end: u64) -> Self {
        Self {
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
            first_offset: start,
            end_offset: end,
            records: 0,
            transfer: None,
            decoded: None,
            cache: false,
            worker_served: false,
            memory_cache: false,
            static_data: false,
            memory_cache_source: None,
            response: None,
            bodies: Vec::new(),
            redirected: false,
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
            watch: None,
            renderer_start: None,
            browser_start: None,
        }
    }
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
    match row
        .members
        .iter_mut()
        .find(|m| m.session == session && m.process == process && m.request == request)
    {
        Some(member) => member.records += 1,
        None => row.members.push(Member {
            session,
            process,
            request,
            records: 1,
        }),
    }
}

/// A record that belongs to a row without changing its lifecycle.
fn fold_child(row: &mut Row, event: &Value, kind: &str, start: u64, end: u64) {
    member(row, event, start, end);
    if kind == "request_initiator_stack" {
        let bytes = hex::decode(event["payload"].as_str().unwrap_or("")).unwrap_or_default();
        row.stack_state = bytes.get(4).copied().unwrap_or(0);
        // Version 3 names the isolate its script IDs belong to.
        let scoped = bytes.len() == 128 && bytes[0] == 3;
        row.stack_thread = if scoped { bytes[80] } else { 0 };
        row.stack_frame = (bytes.len() == 128 && matches!(row.stack_state, 1 | 4 | 5)).then(|| {
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
        && let Some((set, link)) = tab_link(event)
    {
        (row.tab_set, row.tab_link) = (Some(set), link);
    }
    if kind == "request_extension_link"
        && let Some(id) = extension_link(event)
    {
        row.extension = Some(id);
    }
    if kind == "request_watch_match" && row.watch.is_none() {
        let detail =
            crate::debugger_observation::decode(event).map(|decoded| decoded["detail"].clone());
        row.watch = Some(Watch {
            session: text(&event["session_id"]),
            process: number(&event["process_id"]) as u32,
            sequence: text(&event["sequence_number"]),
            frame: text(&event["frame_id"]),
            rule: detail.as_ref().and_then(|d| d["rule"].as_u64()),
            method_matched: detail.and_then(|d| d["method_matched"].as_bool()),
        });
    }
    let parent = (
        text(&event["session_id"]),
        number(&event["process_id"]) as u32,
        text(&event["parent_event_id"]),
    );
    if kind == "response_body"
        && let (Some(parent_sequence), Some(sequence)) = (
            canonical(&event["parent_event_id"], true),
            canonical(&event["sequence_number"], true),
        )
    {
        let time = unsigned(&event["monotonic_time_ns"]).unwrap_or(0);
        let record = decode_response_body(event);
        let snapshot = record
            .as_ref()
            .filter(|record| record.state == 3 && record.captured != 0)
            .map(|record| (sequence, time, record.clone()));
        let mut child = BodyChild {
            parent: (parent.0.clone(), parent.1, parent_sequence),
            sequence,
            time,
            record,
            snapshot,
        };
        // A later end supersedes partial snapshots of the same response; the
        // newest retained snapshot is kept beside it.
        match row
            .bodies
            .iter_mut()
            .find(|body| body.parent == child.parent)
        {
            Some(held) => {
                let newer_snapshot = match (&held.snapshot, &child.snapshot) {
                    (Some(old), Some(new)) => new.0 > old.0,
                    (None, Some(_)) => true,
                    _ => false,
                };
                // A repeated or older record replaces nothing, so it must not
                // take the held snapshot either.
                if held.sequence < sequence {
                    if !newer_snapshot {
                        child.snapshot = held.snapshot.take();
                    }
                    *held = child;
                } else if newer_snapshot {
                    held.snapshot = child.snapshot;
                }
            }
            None => row.bodies.push(child),
        }
    }
    if kind == "request_target" && !row.children.iter().any(|child| child.parent == parent) {
        row.children.push(Child {
            parent,
            target: decode_target(event),
        });
    }
}

/// A lifecycle record of `incoming` rank.
fn fold_lifecycle(row: &mut Row, event: &Value, kind: &str, incoming: u8, start: u64, end: u64) {
    let payload =
        payload_text(&hex::decode(event["payload"].as_str().unwrap_or("")).unwrap_or_default());
    let reuse = memory_cache(event);
    let (target, scheme_only) = match &reuse {
        Some(reuse) => memory_cache_target(event, &reuse.host),
        None => scoped_target(network_target(&payload, kind), &payload, event),
    };
    let version = event["protocol_version"].as_u64().unwrap_or(0);
    let time = unsigned(&event["monotonic_time_ns"]).unwrap_or(0);
    row.first_ns = row.first_ns.min(time);
    row.last_ns = row.last_ns.max(time);
    let interruption = version >= 3
        && kind == "request_failed"
        && number(&event["error_code"]) == -3
        && ["proxy_destroyed", "redirect_handoff"].contains(&payload.as_str());
    row.failed |= !interruption && (kind == "request_failed" || number(&event["error_code"]) != 0);
    row.interrupted |= interruption;
    let code = number(&event["status_code"]);
    if code > 0 && incoming >= row.status_rank {
        row.code = code;
        row.status_rank = incoming;
    }
    row.browser |= context_token(event).is_some();
    if matches!(kind, "request_completed" | "request_failed")
        && number(&event["flags"]) & 4 != 0
        && number(&event["initiator_process_id"]) == 0
        && context_token(event).is_none()
    {
        row.worker_answer = Some((kind == "request_failed", code, number(&event["error_code"])));
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
    row.redirected |= kind == "request_redirected";
    if kind == "response_started"
        && let Some(sequence) = canonical(&event["sequence_number"], true)
        && row
            .response
            .as_ref()
            .is_none_or(|(_, _, newest)| *newest < sequence)
    {
        row.response = Some((
            text(&event["session_id"]),
            number(&event["process_id"]) as u32,
            sequence,
        ));
    }
    // A renderer completion carries the response's cache and service-worker
    // flags, and a service worker's end without a response its own.
    if response.is_some() || matches!(kind, "request_completed" | "request_failed") {
        row.cache |= flags & 2 != 0;
        row.worker_served |= flags & 4 != 0;
    }
    if let Some(reuse) = &reuse {
        row.memory_cache = true;
        row.static_data = reuse.static_data;
        row.resource = memory_cache_resource(reuse.blink_type).into();
        if reuse.source.is_some() {
            row.memory_cache_source.clone_from(&reuse.source);
        }
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
    member(row, event, start, end);
}

fn fold_tab_set(transaction: &Transaction<'_>, event: &Value) -> Result<()> {
    let Ok(bytes) = hex::decode(event["payload"].as_str().unwrap_or("")) else {
        return Ok(());
    };
    if bytes.len() != 128 {
        return Ok(());
    }
    let set_id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let total = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let count = usize::from(u16::from_le_bytes([bytes[20], bytes[21]])).min(26);
    let key = format!("{}:{set_id}", text(&event["session_id"]));
    // The first part names the set's total.
    transaction
        .prepare_cached("INSERT OR IGNORE INTO tab_sets(key, total) VALUES (?1, ?2)")
        .sql()?
        .execute(params![key, total])
        .sql()?;
    let mut insert = transaction
        .prepare_cached("INSERT OR IGNORE INTO set_tabs(set_key, tab) VALUES (?1, ?2)")
        .sql()?;
    for slot in bytes[24..24 + 4 * count].as_chunks::<4>().0 {
        let tab = u32::from_le_bytes(*slot);
        if tab != 0 {
            insert.execute(params![key, tab]).sql()?;
        }
    }
    Ok(())
}

fn fold_identity(transaction: &Transaction<'_>, event: &Value) -> Result<()> {
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
        return Ok(());
    };
    transaction
        .prepare_cached(
            "INSERT OR REPLACE INTO identities(session, process, isolate, script, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .sql()?
        .execute(params![
            text(&event["session_id"]),
            number(&event["process_id"]),
            index_db::key(isolate),
            script,
            payload
        ])
        .sql()?;
    Ok(())
}

const INSERT_ROW: &str = "INSERT OR REPLACE INTO rows(ordinal, id, first_ns, last_ns, tab,
    tab_set, extension, resource, failed, internal, main_frame, domain, domain_lower, host_lower,
    site, haystack, method, status_code, transfer, decoded, mime, protocol, name, name_fold,
    type_label, initiator_label, duration_us, root_session, root_process, root_sequence,
    body_case, body_withheld, body_earlier, first_offset, end_offset, loader, start_request)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
    ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37)";
const INSERT_STATE: &str = "INSERT OR REPLACE INTO states(ordinal, data) VALUES (?1, ?2)";

/// Writes a row's state and the columns its queries filter, sort and count by.
fn write_row(transaction: &Transaction<'_>, ordinal: i64, row: &Row) -> Result<()> {
    let view = view(row);
    let (case, body) = body_case(row);
    let withheld = body
        .and_then(|body| body.record.as_ref())
        .is_some_and(|record| record.flags & 0x80 != 0);
    // A refused or malformed newest record whose row names an earlier
    // snapshot, as body_document's earlier_snapshot does.
    let earlier = body.is_some_and(|body| {
        body.snapshot.is_some()
            && body
                .record
                .as_ref()
                .is_none_or(|record| record.artifact == "0")
    });
    let root = root(row);
    let domain_lower = view.domain.to_lowercase();
    transaction
        .prepare_cached(INSERT_STATE)
        .sql()?
        .execute(params![ordinal, encode(row)?])
        .sql()?;
    transaction
        .prepare_cached(INSERT_ROW)
        .sql()?
        .execute(params![
            ordinal,
            row.id,
            clamp(row.first_ns),
            clamp(row.last_ns),
            index_db::key(row.tab),
            row.tab_set,
            row.extension,
            row.resource,
            outcome(row).0,
            view.internal,
            row.main_frame,
            view.domain,
            domain_lower,
            host_of(&domain_lower),
            site(&view.domain),
            view.haystack,
            view.method,
            view.status.as_i64(),
            row.transfer,
            row.decoded,
            row.mime,
            row.protocol,
            view.name,
            view.name.to_lowercase(),
            type_label(&row.resource),
            initiator_label(row),
            duration(row).map(|d| (d / 1000) as i64),
            root.map(|root| &root.session),
            root.map(|root| root.process),
            root.map(|root| &root.sequence),
            case,
            withheld,
            earlier,
            clamp(row.first_offset),
            clamp(row.end_offset),
            row.loader,
            row.roots[0].as_ref().map(|root| &root.request),
        ])
        .sql()?;
    Ok(())
}

/// A row's JSON without its null, false and empty-list fields: most rows hold
/// their default in most of them. Only an `Option` serializes as null, a
/// `bool` as false and a `Vec` as an empty list, so each restores exactly.
/// Zero and empty text stay: a `Some(0)` would come back as `None`.
fn encode(row: &Row) -> Result<Vec<u8>> {
    let failed = |error: serde_json::Error| Error::new(500, error.to_string());
    let mut value = serde_json::to_value(row).map_err(failed)?;
    if let Value::Object(fields) = &mut value {
        fields.retain(|_, field| match field {
            Value::Null | Value::Bool(false) => false,
            Value::Array(items) => !items.is_empty(),
            _ => true,
        });
    }
    serde_json::to_vec(&value).map_err(failed)
}

/// One fold's working set. Rows it changes stay in memory and are written
/// back before the fold commits, or sooner once `HELD_ROWS` are held: a
/// request's records sit close together in the store, so most records find
/// their row here and each row is written once per fold instead of once per
/// record. Request keys are written through; ids and keys read from the
/// index are remembered until the next write-back.
#[derive(Default)]
struct Batch {
    rows: HashMap<i64, Row>,
    ids: HashMap<String, Option<i64>>,
    keys: HashMap<String, Option<String>>,
    next: Option<i64>,
    malformed: u64,
}
impl Batch {
    fn ordinal(&mut self, transaction: &Transaction<'_>, id: &str) -> Result<Option<i64>> {
        if let Some(found) = self.ids.get(id) {
            return Ok(*found);
        }
        let found = transaction
            .prepare_cached("SELECT ordinal FROM rows WHERE id = ?1")
            .sql()?
            .query_row([id], |row| row.get(0))
            .optional()
            .sql()?;
        self.ids.insert(id.to_owned(), found);
        Ok(found)
    }

    fn row(&mut self, transaction: &Transaction<'_>, ordinal: i64) -> Result<&mut Row> {
        Ok(match self.rows.entry(ordinal) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(slot) => slot.insert(load(transaction, ordinal)?),
        })
    }

    fn create(
        &mut self,
        transaction: &Transaction<'_>,
        id: String,
        kind: &str,
        start: u64,
        end: u64,
    ) -> Result<i64> {
        let ordinal = match self.next {
            Some(next) => next,
            None => transaction
                .query_row(
                    "SELECT COALESCE(MAX(ordinal) + 1, 0) FROM rows",
                    [],
                    |row| row.get(0),
                )
                .sql()?,
        };
        self.next = Some(ordinal + 1);
        self.ids.insert(id.clone(), Some(ordinal));
        self.rows.insert(ordinal, Row::new(id, kind, start, end));
        Ok(ordinal)
    }

    fn key(&mut self, transaction: &Transaction<'_>, key: &str) -> Result<Option<String>> {
        if let Some(found) = self.keys.get(key) {
            return Ok(found.clone());
        }
        let found: Option<String> = transaction
            .prepare_cached("SELECT id FROM keys WHERE key = ?1")
            .sql()?
            .query_row([key], |row| row.get(0))
            .optional()
            .sql()?;
        self.keys.insert(key.to_owned(), found.clone());
        Ok(found)
    }

    /// Records the row a browser key names; the first key learned stays
    /// unless `replace`.
    fn learn(
        &mut self,
        transaction: &Transaction<'_>,
        key: String,
        id: String,
        replace: bool,
    ) -> Result<()> {
        if !replace && matches!(self.keys.get(&key), Some(Some(_))) {
            return Ok(());
        }
        let sql = if replace {
            "INSERT OR REPLACE INTO keys(key, id) VALUES (?1, ?2)"
        } else {
            "INSERT OR IGNORE INTO keys(key, id) VALUES (?1, ?2)"
        };
        let changed = transaction
            .prepare_cached(sql)
            .sql()?
            .execute(params![key, id])
            .sql()?;
        if changed == 1 {
            self.keys.insert(key, Some(id));
        } else {
            self.keys.remove(&key);
        }
        Ok(())
    }

    fn learn_keys(&mut self, transaction: &Transaction<'_>, event: &Value) -> Result<()> {
        if text(&event["request_id"]) == "0" {
            return Ok(());
        }
        if event["type"] == "request_initiated" || event["type"] == "memory_cache_reuse" {
            if let Some(key) = legacy_key(event) {
                self.learn(transaction, key, renderer_identity(event), true)?;
            }
            return Ok(());
        }
        if number(&event["initiator_process_id"]) == 0 {
            return Ok(());
        }
        let identity = correlated_identity(event);
        for key in [browser_key(event), legacy_key(event)]
            .into_iter()
            .flatten()
        {
            self.learn(transaction, key, identity.clone(), false)?;
        }
        Ok(())
    }

    /// Port of `requestIdentity` over the browser keys learned so far.
    fn identity(&mut self, transaction: &Transaction<'_>, event: &Value) -> Result<String> {
        if event["type"] == "request_initiated" || event["type"] == "memory_cache_reuse" {
            return Ok(renderer_identity(event));
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
        Ok(match browser_key(event) {
            Some(key) => self.key(transaction, &key)?.unwrap_or(correlated),
            None => correlated,
        })
    }

    fn fold(
        &mut self,
        transaction: &Transaction<'_>,
        line: &[u8],
        start: u64,
        end: u64,
    ) -> Result<()> {
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        // Only a network record names its category in its bytes. A line that is
        // no complete object may have lost those bytes, so it cannot be skipped.
        if line.len() <= RECORD_BYTES && !line.windows(7).any(|window| window == b"network") {
            if line.trim_ascii().first() != Some(&b'{') || line.trim_ascii().last() != Some(&b'}') {
                self.malformed += 1;
            }
            return Ok(());
        }
        let event = match serde_json::from_slice::<Value>(line) {
            Ok(event) if line.len() <= RECORD_BYTES && validate_event(&event).is_ok() => event,
            _ => {
                self.malformed += 1;
                return Ok(());
            }
        };
        let kind = event["type"].as_str().unwrap_or("");
        if event["category"] != "network" {
            return Ok(());
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
                if let Some(ordinal) = self.ordinal(transaction, &correlated_identity(&event))? {
                    self.row(transaction, ordinal)?.end_lost = true;
                }
                return Ok(());
            }
            match kind {
                "tab_set" => fold_tab_set(transaction, &event)?,
                "script_identity" => fold_identity(transaction, &event)?,
                "script_cookie" => {
                    transaction
                        .prepare_cached(
                            "INSERT OR IGNORE INTO script_cookies(session, start, end) VALUES (?1, ?2, ?3)",
                        )
                        .sql()?
                        .execute(params![text(&event["session_id"]), clamp(start), clamp(end)])
                        .sql()?;
                }
                _ if CHILD_TYPES.contains(&kind) => {
                    let id = self.identity(transaction, &event)?;
                    if let Some(ordinal) = self.ordinal(transaction, &id)? {
                        fold_child(self.row(transaction, ordinal)?, &event, kind, start, end);
                        if kind == "cookie_list" {
                            transaction
                                .prepare_cached(
                                    "INSERT OR IGNORE INTO cookie_lists(session, start, end) VALUES (?1, ?2, ?3)",
                                )
                                .sql()?
                                .execute(params![
                                    text(&event["session_id"]),
                                    clamp(start),
                                    clamp(end)
                                ])
                                .sql()?;
                        }
                    }
                }
                _ => {}
            }
            return Ok(());
        };
        self.learn_keys(transaction, &event)?;
        let id = self.identity(transaction, &event)?;
        let ordinal = match self.ordinal(transaction, &id)? {
            Some(ordinal) => ordinal,
            None => self.create(transaction, id, kind, start, end)?,
        };
        let row = self.row(transaction, ordinal)?;
        fold_lifecycle(row, &event, kind, incoming, start, end);
        Ok(())
    }

    /// Writes every held row back and forgets what was read from the index.
    fn flush(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        let mut members = transaction
            .prepare_cached(
                "INSERT OR IGNORE INTO members(request, session, process, ordinal) VALUES (?1, ?2, ?3, ?4)",
            )
            .sql()?;
        // In ordinal order, so new rows append to full pages.
        let mut rows = self.rows.drain().collect::<Vec<_>>();
        rows.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        for (ordinal, row) in rows {
            write_row(transaction, ordinal, &row)?;
            for member in &row.members {
                members
                    .execute(params![
                        member.request,
                        member.session,
                        member.process,
                        ordinal
                    ])
                    .sql()?;
            }
        }
        self.ids.clear();
        self.keys.clear();
        Ok(())
    }
}
impl index_db::Fold for Batch {
    fn line(
        &mut self,
        transaction: &Transaction<'_>,
        line: &[u8],
        start: u64,
        end: u64,
    ) -> Result<()> {
        self.fold(transaction, line, start, end)?;
        if self.rows.len() >= HELD_ROWS || self.ids.len() + self.keys.len() >= HELD_KEYS {
            self.flush(transaction)?;
        }
        Ok(())
    }

    fn finish(&mut self, transaction: &Transaction<'_>) -> Result<()> {
        self.flush(transaction)?;
        transaction
            .execute(
                "UPDATE counts SET malformed = malformed + ?1 WHERE id = 0",
                [clamp(std::mem::take(&mut self.malformed))],
            )
            .sql()?;
        Ok(())
    }
}

fn unreadable(error: serde_json::Error) -> Error {
    Error::new(
        500,
        format!("The request index holds an unreadable row: {error}"),
    )
}

fn load(connection: &Connection, ordinal: i64) -> Result<Row> {
    let data: Vec<u8> = connection
        .prepare_cached("SELECT data FROM states WHERE ordinal = ?1")
        .sql()?
        .query_row([ordinal], |row| row.get(0))
        .sql()?;
    serde_json::from_slice(&data).map_err(unreadable)
}

fn load_id(connection: &Connection, id: &str) -> Result<Option<Row>> {
    let data: Option<Vec<u8>> = connection
        .prepare_cached(
            "SELECT s.data FROM rows r JOIN states s ON s.ordinal = r.ordinal WHERE r.id = ?1",
        )
        .sql()?
        .query_row([id], |row| row.get(0))
        .optional()
        .sql()?;
    data.map(|data| serde_json::from_slice(&data).map_err(unreadable))
        .transpose()
}

/// The row's own tab and its linked set's tabs; empty is a capture error.
fn row_tabs(connection: &Connection, row: &Row) -> Result<Vec<u64>> {
    let mut tabs = match &row.tab_set {
        Some(key) => connection
            .prepare_cached("SELECT tab FROM set_tabs WHERE set_key = ?1 ORDER BY tab")
            .sql()?
            .query_map([key], |row| row.get::<_, i64>(0))
            .sql()?
            .map(|tab| tab.map(|tab| tab as u64))
            .collect::<rusqlite::Result<Vec<_>>>()
            .sql()?,
        None => Vec::new(),
    };
    if row.tab != 0 && !tabs.contains(&row.tab) {
        tabs.push(row.tab);
        tabs.sort_unstable();
    }
    Ok(tabs)
}

/// A query's condition over `rows r`, with its parameters in the order the
/// SQL names them.
struct Condition {
    sql: String,
    values: Vec<SqlValue>,
}
impl Condition {
    fn and(&mut self, sql: &str, values: impl IntoIterator<Item = SqlValue>) {
        self.sql.push_str(" AND ");
        self.sql.push_str(sql);
        self.values.extend(values);
    }

    /// Tab 0 selects the rows with no tab and no extension.
    fn tab(&mut self, scope: &TabScope) {
        match scope {
            TabScope::Extension(id) => self.and("r.extension = ?", [SqlValue::Text(id.clone())]),
            TabScope::Tab(0) => self.and(
                "r.tab = 0 AND r.extension IS NULL
                 AND NOT EXISTS (SELECT 1 FROM set_tabs s WHERE s.set_key = r.tab_set)",
                [],
            ),
            TabScope::Tab(tab) => self.and(
                "(r.tab = ? OR EXISTS (SELECT 1 FROM set_tabs s WHERE s.set_key = r.tab_set AND s.tab = ?))",
                [SqlValue::Integer(index_db::key(*tab)), SqlValue::Integer(index_db::key(*tab))],
            ),
        }
    }
}

/// Rows of the first `through` whose site differs from their tab's latest
/// top-level document at their start.
const THIRD_PARTY: &str = "COALESCE(r.site != (SELECT d.site FROM rows d
    WHERE d.main_frame = 1 AND d.tab != 0 AND d.tab = r.tab AND d.ordinal < ?
      AND (d.first_ns, d.ordinal) <= (r.first_ns, r.ordinal)
    ORDER BY d.first_ns DESC, d.ordinal DESC LIMIT 1), 0) = 1";

/// Every filter except the time range and the browser-internal switch.
fn matching(query: &RequestQuery, through: usize) -> Condition {
    let through = SqlValue::Integer(i64::try_from(through).unwrap_or(i64::MAX));
    let mut condition = Condition {
        sql: "r.ordinal < ?".into(),
        values: vec![through.clone()],
    };
    if let Some(tab) = &query.tab {
        condition.tab(tab);
    }
    if let Some(domain) = &query.domain {
        condition.and("r.domain = ?", [SqlValue::Text(domain.clone())]);
    }
    if let Some(kind) = query.kind {
        condition.and("r.resource = ?", [SqlValue::Text(kind.into())]);
    }
    if query.failed {
        condition.and("r.failed = 1", []);
    }
    if query.third_party {
        condition.and(THIRD_PARTY, [through]);
    }
    let filter = &query.filter;
    if !filter.active() {
        return condition;
    }
    let (mut found, mut values) = (Vec::new(), Vec::new());
    if !filter.text.is_empty() {
        let mut text = "instr(r.haystack, ?) > 0".to_owned();
        values.push(SqlValue::Text(filter.text.clone()));
        if !query.named.is_empty() {
            text.push_str(&format!(
                " OR (r.root_session, r.root_process, r.root_sequence) IN (VALUES {})",
                vec!["(?, ?, ?)"; query.named.len()].join(", ")
            ));
            for (session, process, sequence) in &query.named {
                values.extend([
                    SqlValue::Text(session.clone()),
                    SqlValue::Integer(i64::from(*process)),
                    SqlValue::Text(sequence.clone()),
                ]);
            }
        }
        found.push(format!("({text})"));
    }
    for exclude in &filter.exclude {
        found.push("instr(r.haystack, ?) = 0".into());
        values.push(SqlValue::Text(exclude.clone()));
    }
    for token in &filter.tokens {
        let value = SqlValue::Text(token.value.clone());
        let test = match token.key {
            "domain" => {
                values.extend([value.clone(), value]);
                "(reb_glob(?, r.domain_lower) OR reb_glob(?, r.host_lower))"
            }
            "method" => {
                values.push(value);
                "lower(r.method) = ?"
            }
            "status-code" => {
                values.push(SqlValue::Integer(token.value.parse().unwrap_or(-1)));
                "r.status_code = ?"
            }
            "larger-than" => {
                values.push(SqlValue::Integer(clamp(token.bytes)));
                "r.transfer > ?"
            }
            _ => {
                values.push(value);
                "r.mime = ?"
            }
        };
        found.push(format!(
            "COALESCE({test}, 0) = {}",
            if token.negated { 0 } else { 1 }
        ));
    }
    let expected = if query.invert { 0 } else { 1 };
    condition.and(
        &format!("COALESCE({}, 0) = {expected}", found.join(" AND ")),
        values,
    );
    condition
}

/// Nulls last in either direction, then capture order; text compares
/// case-folded first, then exactly, as a locale collation would.
fn order(sort: &str, descending: bool) -> String {
    let direction = if descending { "DESC" } else { "ASC" };
    let numeric = |column: &str| format!("{column} IS NULL, {column} {direction}, r.ordinal");
    let text = |column: &str, folded: &str| {
        format!("{column} IS NULL, {folded} {direction}, {column} {direction}, r.ordinal")
    };
    match sort {
        "capture" => format!("r.ordinal {direction}"),
        // Traffic compares the displayed microseconds.
        "time" => numeric("r.duration_us"),
        "status" => numeric("r.status_code"),
        "size" => numeric("r.transfer"),
        "start" => numeric("r.first_ns"),
        "name" => text("r.name", "r.name_fold"),
        // These labels are ASCII, which SQL's lower() folds as Rust does.
        "type" => text("r.type_label", "lower(r.type_label)"),
        "initiator" => text("r.initiator_label", "lower(r.initiator_label)"),
        "protocol" => text("r.protocol", "lower(r.protocol)"),
        _ => text("r.method", "lower(r.method)"),
    }
}

/// SQL functions the queries use, on every connection that answers them.
fn register(connection: &Connection) -> rusqlite::Result<()> {
    use rusqlite::functions::FunctionFlags;
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    connection.create_scalar_function("reb_glob", 2, flags, |context| {
        Ok(glob(
            context.get_raw(0).as_str()?,
            context.get_raw(1).as_str()?,
        ))
    })?;
    // The timeline bucket of a start between `first` and `last`.
    connection.create_scalar_function("reb_bucket", 3, flags, |context| {
        let (at, first, last) = (
            i128::from(context.get::<i64>(0)?),
            i128::from(context.get::<i64>(1)?),
            i128::from(context.get::<i64>(2)?),
        );
        let span = (last - first) as u128 + 1;
        Ok(((at - first) as u128 * TIMELINE_BUCKETS as u128 / span) as i64)
    })?;
    Ok(())
}

fn collect<T, F>(rows: rusqlite::Result<rusqlite::MappedRows<'_, F>>) -> Result<Vec<T>>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    rows.sql()?.collect::<rusqlite::Result<Vec<_>>>().sql()
}

impl RequestIndex {
    pub fn new(store: &Path) -> Self {
        Self {
            store: store.to_owned(),
            index: Indexed::new(store, SIDECAR_SUFFIX, LAYOUT, SCHEMA).with_setup(register),
            empty: None,
            empty_epoch: hex::encode(
                &Sha256::digest(format!(
                    "{}:{}:{:?}",
                    std::process::id(),
                    store.display(),
                    std::time::SystemTime::now()
                ))[..8],
            ),
            position: None,
            missing: false,
            generation: 0,
            total: 0,
            malformed: 0,
            legacy_removed: false,
            selection: None,
            facets: None,
        }
    }

    /// Removes the index from disk before a capture clear empties the store.
    pub fn discard(&mut self) -> Result<()> {
        self.index.discard()?;
        self.remove_legacy()?;
        self.position = None;
        self.selection = None;
        self.facets = None;
        self.generation += 1;
        Ok(())
    }

    /// Version 1 kept every row in one JSON file that nothing reads now.
    fn remove_legacy(&mut self) -> Result<()> {
        self.legacy_removed = true;
        match std::fs::remove_file(index_db::sidecar_path(&self.store, LEGACY_SUFFIX)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    /// The connection that answers queries: the index, or an empty one while
    /// the store does not exist.
    fn db(&self) -> &Connection {
        match self.index.connection() {
            Some(connection) if !self.missing => connection,
            _ => self.empty.as_ref().expect("a refreshed index"),
        }
    }

    /// Folds what the store gained until `deadline`; the background indexer
    /// folds the rest. A rewritten or replaced store rebuilds from byte 0.
    pub fn refresh(&mut self, deadline: Instant) -> Result<()> {
        if !self.legacy_removed {
            // A read-only evidence directory keeps its old file.
            let _ = self.remove_legacy();
        }
        let position = match self.index.open()? {
            Some((mut file, position)) => {
                self.missing = false;
                self.index.sidecar().fold(
                    &mut file,
                    &position,
                    u64::MAX,
                    deadline,
                    RECORD_BYTES,
                    "The evidence store contains an oversized event",
                    &mut Batch::default(),
                )?
            }
            None => {
                self.missing = true;
                if self.empty.is_none() {
                    let connection = Connection::open_in_memory().sql()?;
                    connection.execute_batch(SCHEMA).sql()?;
                    register(&connection).sql()?;
                    self.empty = Some(connection);
                }
                Position {
                    epoch: self.empty_epoch.clone(),
                    indexed_to: 0,
                    scanned_to: 0,
                    file_end: 0,
                    reopened: false,
                }
            }
        };
        let moved = self
            .position
            .as_ref()
            .is_none_or(|old| old.epoch != position.epoch || old.indexed_to != position.indexed_to);
        self.position = Some(position);
        if moved {
            self.generation += 1;
            let db = self.db();
            let total: i64 = db
                .query_row(
                    "SELECT COALESCE(MAX(ordinal) + 1, 0) FROM rows",
                    [],
                    |row| row.get(0),
                )
                .sql()?;
            let malformed: i64 = db
                .query_row("SELECT malformed FROM counts WHERE id = 0", [], |row| {
                    row.get(0)
                })
                .sql()?;
            (self.total, self.malformed) = (total as usize, malformed as u64);
        }
        Ok(())
    }

    fn read(&mut self) -> Result<()> {
        self.refresh(Instant::now() + READ_FOLD)
    }

    fn select(&mut self, query: &RequestQuery, through: usize) -> Result<Summary> {
        let key = query.order_key(through);
        if let Some((cached, generation, summary)) = &self.selection
            && *cached == key
            && *generation == self.generation
        {
            return Ok(summary.clone());
        }
        self.selection = None;
        let db = self.db();
        let condition = matching(query, through);
        let hidden = if query.hide_internal {
            "r.internal = 1"
        } else {
            "0"
        };
        // ?1 and ?2 come first in each statement, so the condition's own
        // parameters number from 3.
        let mut values = vec![
            SqlValue::Integer(clamp(query.to)),
            SqlValue::Integer(clamp(query.from)),
        ];
        values.extend(condition.values.iter().cloned());
        let in_range = "(r.first_ns <= ?1 AND r.last_ns >= ?2)";
        let (hidden_internal, first, last, transferred, resources) = db
            .query_row(
                &format!(
                    "SELECT COALESCE(SUM({hidden} AND {in_range}), 0),
                        MIN(CASE WHEN NOT ({hidden}) THEN r.first_ns END),
                        MAX(CASE WHEN NOT ({hidden}) THEN r.last_ns END),
                        COALESCE(SUM(CASE WHEN NOT ({hidden}) AND {in_range} THEN COALESCE(r.transfer, 0) END), 0),
                        COALESCE(SUM(CASE WHEN NOT ({hidden}) AND {in_range} THEN COALESCE(r.decoded, 0) END), 0)
                     FROM rows r WHERE {}",
                    condition.sql
                ),
                params_from_iter(&values),
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .sql()?;
        let timeline = match first.zip(last) {
            Some((first, last)) => {
                let mut buckets = vec![0u64; TIMELINE_BUCKETS];
                let mut bounds = vec![SqlValue::Integer(first), SqlValue::Integer(last)];
                bounds.extend(condition.values.iter().cloned());
                let mut statement = db
                    .prepare(&format!(
                        "SELECT reb_bucket(r.first_ns, ?1, ?2), COUNT(*) FROM rows r
                         WHERE {} AND NOT ({hidden}) GROUP BY 1",
                        condition.sql
                    ))
                    .sql()?;
                let counts = collect(statement.query_map(params_from_iter(&bounds), |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                }))?;
                for (bucket, count) in counts {
                    buckets[bucket as usize] = count as u64;
                }
                Some((first as u64, last as u64, buckets))
            }
            None => None,
        };
        db.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS selection(position INTEGER PRIMARY KEY, ordinal INTEGER NOT NULL);
             DELETE FROM temp.selection;",
        )
        .sql()?;
        // Positions number from 1 in this order: the table starts empty.
        let matching = db
            .execute(
                &format!(
                    "INSERT INTO temp.selection(ordinal) SELECT r.ordinal FROM rows r
                     WHERE {in_range} AND {} AND NOT ({hidden}) ORDER BY {}",
                    condition.sql,
                    order(query.sort, query.descending)
                ),
                params_from_iter(&values),
            )
            .sql()?;
        let summary = Summary {
            matching,
            hidden_internal: hidden_internal as u64,
            transferred: transferred as u64,
            resources: resources as u64,
            timeline,
        };
        self.selection = Some((key, self.generation, summary.clone()));
        Ok(summary)
    }

    fn row_document(&self, ordinal: i64) -> Result<Value> {
        let db = self.db();
        let row = load(db, ordinal)?;
        let view = view(&row);
        let tabs = row_tabs(db, &row)?;
        let member = |member: &Member| {
            json!({"session_id": member.session, "process_id": member.process,
            "request_id": member.request, "records": member.records})
        };
        let set: Option<(i64, i64)> = match &row.tab_set {
            Some(key) => db
                .prepare_cached(
                    "SELECT total, (SELECT COUNT(*) FROM set_tabs s WHERE s.set_key = t.key)
                     FROM tab_sets t WHERE t.key = ?1",
                )
                .sql()?
                .query_row([key], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()
                .sql()?,
            None => None,
        };
        let mut document = json!({
            "id": row.id, "ordinal": ordinal, "method": row.method, "path": view.path,
            "target_kind": view.target_kind, "host": view.host, "target": view.target,
            "url_truncated": view.url_truncated, "target_length": view.target_length,
            "target_malformed": view.target_malformed, "status": view.status,
            "failed": outcome(&row).0, "interrupted": outcome(&row).1,
            "time": duration(&row).map_or_else(|| "pending".to_owned(), milliseconds),
            "duration_ns": duration(&row).map(|d| d.to_string()),
            "type": row.resource, "tab_id": row.tab.to_string(), "operation": row.operation,
            "tab_ids": tabs.iter().map(u64::to_string).collect::<Vec<_>>(),
            "tab_link": (row.tab_link.0 != 0).then(|| {
                json!({"kind": row.tab_link.0, "count": row.tab_link.1,
                    "complete": set.is_some_and(|(total, tabs)| tabs == total)})
            }),
            "first_time_ns": row.first_ns.to_string(), "last_time_ns": row.last_ns.to_string(),
            "domain": view.domain,
            "root": root(&row).map(|root| json!({"session_id": root.session, "process_id": root.process,
                "sequence_number": root.sequence, "request_id": root.request})),
            "members": row.members.iter().map(member).collect::<Vec<_>>(),
            "first_offset": row.first_offset.to_string(), "end_offset": row.end_offset.to_string(),
            "records": row.records,
            "transfer_size": row.transfer, "resource_size": row.decoded,
            "from_cache": row.cache, "from_service_worker": row.worker_served,
            "mime_type": row.mime, "protocol": row.protocol,
            "response_time_ns": row.response_ns.map(|time| time.to_string()),
            "error_code": outcome(&row).3, "loader_observed": row.loader, "initiator": initiator(&row),
            "main_frame": row.main_frame, "browser_internal": view.internal,
        });
        document["extension_id"] = json!(row.extension);
        document["watch"] = json!(row.watch.as_ref().map(|watch| json!({
            "session_id": watch.session, "process_id": watch.process,
            "sequence_number": watch.sequence, "frame_id": watch.frame,
            "rule": watch.rule, "method_matched": watch.method_matched})));
        document["memory_cache"] = json!(row.memory_cache);
        document["static_data"] = json!(row.static_data);
        document["race_network"] = json!(row.worker_answer.is_some() && row.browser);
        document["end_lost"] = json!(row.end_lost);
        document["response_body"] = body_document(&row);
        // The reused response's own row, when this session recorded it.
        document["memory_cache_source"] = match &row.memory_cache_source {
            None => Value::Null,
            Some(id) => {
                let source = load_id(db, id)?;
                let reason = match &source {
                    None => Some("not_recorded"),
                    Some(source) => source_mismatch(&row, source),
                };
                let shown = source.as_ref().filter(|_| reason.is_none());
                json!({"id": id, "found": shown.is_some(), "reason": reason,
                    "response_body": shown.map(body_document),
                    "method": shown.map(|row| row.method.clone()), "path": shown.map(|row| row.path.clone()),
                    "type": shown.map(|row| row.resource.clone()), "mime_type": shown.and_then(|row| row.mime.clone())})
            }
        };
        let owned = row.extension.is_some() || !tabs.is_empty();
        document["tab_reason"] = json!((!owned).then(|| {
            crate::request_tabs::unresolved_reason(
                row.renderer_start
                    .map(|(kind, frame)| (u64::from(kind), frame)),
                row.browser_start.map(u64::from),
            )
        }));
        // Raw; the get_requests handler replaces it with the frame's resolution.
        document["initiator_frame"] = match &row.stack_frame {
            None => Value::Null,
            Some((session, process, isolate, frame)) => {
                let script = u32::from_le_bytes(frame[4..8].try_into().unwrap());
                let identity: Option<String> = db
                    .prepare_cached(
                        "SELECT payload FROM identities
                         WHERE session = ?1 AND process = ?2 AND isolate = ?3 AND script = ?4",
                    )
                    .sql()?
                    .query_row(
                        params![session, process, index_db::key(*isolate), script],
                        |row| row.get(0),
                    )
                    .optional()
                    .sql()?;
                json!({"session_id": session, "process_id": process, "isolate_key": isolate.to_string(),
                    "thread": row.stack_thread, "frame": hex::encode(frame), "identity": identity})
            }
        };
        Ok(document)
    }

    /// Owners and domains of the first `through` rows, and how many failed.
    fn facets(&mut self, query: &RequestQuery, through: usize) -> Result<(Value, i64)> {
        let key = format!("{through}:{:?}", query.tab);
        if let Some((cached, generation, facets)) = &self.facets
            && *cached == key
            && *generation == self.generation
        {
            return Ok(facets.clone());
        }
        let db = self.db();
        let limit = i64::try_from(through).unwrap_or(i64::MAX);
        // Tab ids, `extension:<id>` and `0` for rows with no owner, each with
        // its first TAB_DOMAINS domains in capture order and one more to tell
        // whether there are others.
        let mut statement = db
            .prepare_cached(
                "WITH owned(owner, ordinal, first_ns, domain) AS (
                    SELECT CAST(r.tab AS TEXT), r.ordinal, r.first_ns, r.domain FROM rows r
                     WHERE r.ordinal < ?1 AND r.tab != 0
                    UNION
                    SELECT CAST(s.tab AS TEXT), r.ordinal, r.first_ns, r.domain
                      FROM rows r JOIN set_tabs s ON s.set_key = r.tab_set WHERE r.ordinal < ?1
                    UNION ALL
                    SELECT 'extension:' || r.extension, r.ordinal, r.first_ns, r.domain FROM rows r
                     WHERE r.ordinal < ?1 AND r.extension IS NOT NULL
                    UNION ALL
                    SELECT '0', r.ordinal, r.first_ns, r.domain FROM rows r
                     WHERE r.ordinal < ?1 AND r.tab = 0 AND r.extension IS NULL
                       AND NOT EXISTS (SELECT 1 FROM set_tabs s WHERE s.set_key = r.tab_set))
                 SELECT owner, domain, place, count, first FROM (
                    SELECT owner, domain,
                        ROW_NUMBER() OVER (PARTITION BY owner ORDER BY MIN(ordinal)) AS place,
                        SUM(COUNT(*)) OVER (PARTITION BY owner) AS count,
                        MIN(MIN(first_ns)) OVER (PARTITION BY owner) AS first
                    FROM owned GROUP BY owner, domain)
                 WHERE place <= ?2 ORDER BY owner, place",
            )
            .sql()?;
        let listed = collect(
            statement.query_map(params![limit, TAB_DOMAINS as i64 + 1], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            }),
        )?;
        drop(statement);
        let mut tabs: Vec<(String, i64, i64, Vec<String>, bool)> = Vec::new();
        for (owner, domain, place, count, first) in listed {
            if tabs.last().is_none_or(|tab| tab.0 != owner) {
                tabs.push((owner, count, first, Vec::new(), false));
            }
            let tab = tabs.last_mut().unwrap();
            if place as usize <= TAB_DOMAINS {
                tab.3.push(domain);
            } else {
                tab.4 = true;
            }
        }
        tabs.sort_by_key(|(tab, _, first, _, _)| {
            (
                tab == "0",
                *first,
                tab.parse::<u64>().unwrap_or(u64::MAX),
                tab.clone(),
            )
        });
        let mut scope = Condition {
            sql: "r.ordinal < ?".into(),
            values: vec![SqlValue::Integer(limit)],
        };
        if let Some(tab) = &query.tab {
            scope.tab(tab);
        }
        let mut statement = db
            .prepare(&format!(
                "SELECT r.domain, COUNT(*) FROM rows r WHERE {} GROUP BY r.domain ORDER BY r.domain",
                scope.sql
            ))
            .sql()?;
        let domains = collect(statement.query_map(params_from_iter(&scope.values), |row| {
            Ok(json!({"domain": row.get::<_, String>(0)?, "count": row.get::<_, i64>(1)?}))
        }))?;
        drop(statement);
        let failed: i64 = db
            .prepare_cached("SELECT COUNT(*) FROM rows WHERE ordinal < ?1 AND failed = 1")
            .sql()?
            .query_row([limit], |row| row.get(0))
            .sql()?;
        let facets = (
            json!({
                "tabs": tabs.iter().map(|(tab, count, first, domains, more)| json!({"tab_id": tab,
                    "count": count, "first_time_ns": first.to_string(), "domains": domains,
                    "domains_truncated": more}))
                    .collect::<Vec<_>>(),
                "domains": domains,
            }),
            failed,
        );
        self.facets = Some((key, self.generation, facets.clone()));
        Ok(facets)
    }

    /// Whether the index has folded every complete record in the store, as of
    /// the last refresh. A route uses this to tell a transient "not named
    /// yet" from a final one.
    pub fn is_caught_up(&self) -> bool {
        self.position
            .as_ref()
            .is_some_and(|position| position.caught_up(RECORD_BYTES as u64))
    }

    /// The store epoch the index rows belong to and the byte offset folded
    /// up to, as of the last refresh: what a cached answer derived from the
    /// index depends on.
    pub fn position(&self) -> Option<(String, u64)> {
        self.position
            .as_ref()
            .map(|position| (position.epoch.clone(), position.indexed_to))
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
        self.read()?;
        let db = self.db();
        let named = "SELECT MIN(r.first_offset), MAX(r.end_offset) FROM rows r
            WHERE r.ordinal IN (SELECT m.ordinal FROM members m WHERE m.request = ?1
                AND (?2 IS NULL OR m.session = ?2) AND (?3 IS NULL OR m.process = ?3))";
        // A row's browser identity is its request_started record's.
        let browser = format!(
            "{named} AND ?3 IS NULL AND r.loader = 1
                AND (r.start_request IS NULL OR r.start_request = ?1)"
        );
        let range = |sql: &str| -> Result<Option<(i64, i64)>> {
            let (first, end): (Option<i64>, Option<i64>) = db
                .prepare_cached(sql)
                .sql()?
                .query_row(params![request, session, process], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .sql()?;
            Ok(first.zip(end))
        };
        let found = match range(&browser)? {
            Some(found) => Some(found),
            None => range(named)?,
        };
        let indexed = self.is_caught_up();
        Ok(found.map(|(first, end)| RecordRange {
            first: first as u64,
            end: end as u64,
            indexed,
        }))
    }

    /// Identifies how far the index has reached while it is behind the store,
    /// so a validator on a detail answer changes as its coverage can change.
    /// The record boundary the index has folded to and the store's length,
    /// as of the last refresh.
    pub fn extent(&self) -> (u64, u64) {
        self.position
            .as_ref()
            .map_or((0, 0), |position| (position.indexed_to, position.file_end))
    }

    pub fn progress_marker(&self) -> String {
        match &self.position {
            Some(_) if self.is_caught_up() => "caught-up".to_owned(),
            Some(position) => position.indexed_to.to_string(),
            None => "unopened".to_owned(),
        }
    }

    /// `script_identity` payloads of one renderer by isolate key and script
    /// ID, and whether a script missing from them is missing from the store.
    pub fn identities(&mut self, session: &str, process: u32) -> Result<(IdentityPayloads, bool)> {
        self.read()?;
        let mut statement = self
            .db()
            .prepare_cached(
                "SELECT isolate, script, payload FROM identities WHERE session = ?1 AND process = ?2",
            )
            .sql()?;
        let identities = collect(statement.query_map(params![session, process], |row| {
            Ok((
                (row.get::<_, i64>(0)? as u64, row.get::<_, u32>(1)?),
                row.get::<_, String>(2)?,
            ))
        }))?;
        Ok((identities.into_iter().collect(), self.is_caught_up()))
    }

    /// Byte ranges of a session's `script_cookie` records, oldest first, and
    /// whether they are every one the store holds.
    pub fn script_cookies(&mut self, session: &str) -> Result<(Vec<RecordRange>, bool)> {
        self.session_ranges(
            "SELECT start, end FROM script_cookies WHERE session = ?1 ORDER BY start",
            session,
        )
    }

    /// Byte ranges of the `cookie_list` records of a session's indexed
    /// requests, oldest first, and whether they are every one the store holds.
    pub fn cookie_lists(&mut self, session: &str) -> Result<(Vec<RecordRange>, bool)> {
        self.session_ranges(
            "SELECT start, end FROM cookie_lists WHERE session = ?1 ORDER BY start",
            session,
        )
    }

    fn session_ranges(&mut self, query: &str, session: &str) -> Result<(Vec<RecordRange>, bool)> {
        self.read()?;
        let mut statement = self.db().prepare_cached(query).sql()?;
        let ranges = collect(statement.query_map([session], |row| {
            Ok(RecordRange {
                first: row.get::<_, i64>(0)? as u64,
                end: row.get::<_, i64>(1)? as u64,
                indexed: true,
            })
        }))?;
        Ok((ranges, self.is_caught_up()))
    }

    /// Every row's body case, counted for `get_session_summary`, and whether
    /// the index has caught up with the store.
    pub fn response_bodies(&mut self) -> Result<Value> {
        self.read()?;
        let mut statement = self
            .db()
            .prepare_cached(
                "SELECT body_case, COUNT(*), SUM(body_withheld), SUM(body_earlier)
                 FROM rows GROUP BY body_case ORDER BY body_case",
            )
            .sql()?;
        let counted = collect(statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        }))?;
        let (mut cases, mut earlier, mut withheld) =
            (serde_json::Map::new(), serde_json::Map::new(), 0);
        for (case, count, held, snapshots) in counted {
            withheld += held;
            if snapshots > 0 {
                earlier.insert(case.clone(), json!(snapshots.to_string()));
            }
            cases.insert(case, json!(count.to_string()));
        }
        Ok(json!({
            "complete": self.is_caught_up(),
            "requests": self.total.to_string(),
            "snapshots_withheld": withheld.to_string(),
            "cases": cases,
            "earlier_snapshots": earlier,
        }))
    }

    /// Every row `query` selects, in its order with no page bound, as the
    /// ordinals an export reads in batches; and the index state they are from.
    pub fn export_rows(&mut self, query: &RequestQuery) -> Result<(Vec<i64>, Value)> {
        self.read()?;
        let position = self.position.clone().expect("a refreshed index");
        let through = query.through.unwrap_or(self.total).min(self.total);
        let ordinals = if query.rows.is_empty() {
            self.select(query, through)?;
            collect(
                self.db()
                    .prepare_cached("SELECT ordinal FROM temp.selection ORDER BY position")
                    .sql()?
                    .query_map([], |row| row.get::<_, i64>(0)),
            )?
        } else {
            let mut statement = self
                .db()
                .prepare_cached("SELECT ordinal FROM rows WHERE id = ?1")
                .sql()?;
            let mut ordinals = Vec::with_capacity(query.rows.len());
            for id in &query.rows {
                let ordinal: Option<i64> = statement
                    .query_row([id], |row| row.get(0))
                    .optional()
                    .sql()?;
                ordinals.push(
                    ordinal
                        .ok_or_else(|| Error::new(404, format!("No request row has ID {id}")))?,
                );
            }
            ordinals
        };
        let index = json!({
            "epoch": position.epoch, "indexed_end": position.indexed_to.to_string(),
            "store_end": position.file_end.to_string(), "complete": self.is_caught_up(),
            "through": through,
        });
        Ok((ordinals, index))
    }
    /// The `get_requests` documents of these rows, read as they are now.
    pub fn export_documents(&mut self, ordinals: &[i64]) -> Result<Vec<Value>> {
        ordinals
            .iter()
            .map(|ordinal| self.row_document(*ordinal))
            .collect()
    }
    pub fn respond(&mut self, query: &RequestQuery, etag: Option<&str>) -> Result<Answer> {
        self.read()?;
        let position = self.position.clone().expect("a refreshed index");
        let tag = format!(
            "\"{}\"",
            digest(
                format!(
                    "{}:{}:{}:{}:{}",
                    position.epoch,
                    self.generation,
                    position.indexed_to,
                    position.file_end,
                    query.raw
                )
                .as_bytes()
            )
        );
        if etag == Some(tag.as_str()) {
            return Ok(Answer::Unchanged(tag));
        }
        let total = self.total;
        let through = query.through.unwrap_or(total).min(total);
        let index = json!({
            "epoch": position.epoch, "indexed_end": position.indexed_to.to_string(),
            "store_end": position.file_end.to_string(), "complete": self.is_caught_up(),
            "malformed_records": self.malformed.to_string(), "reopened": position.reopened,
            "persisted": self.index.temporary_reason().is_none(),
            "persist_error": self.index.temporary_reason(),
        });
        let (facets, failed) = self.facets(query, through)?;
        let summary = self.select(query, through)?;
        let db = self.db();
        let clamped = |value: usize| i64::try_from(value).unwrap_or(i64::MAX);
        let ordinals = collect(
            db.prepare_cached(
                "SELECT ordinal FROM temp.selection WHERE position > ?1 ORDER BY position LIMIT ?2",
            )
            .sql()?
            .query_map(
                params![clamped(query.offset), clamped(query.limit)],
                |row| row.get::<_, i64>(0),
            ),
        )?;
        let page = ordinals
            .into_iter()
            .map(|ordinal| self.row_document(ordinal))
            .collect::<Result<Vec<_>>>()?;
        let matching = summary.matching;
        let mut document = json!({
            "format": FORMAT, "total": total, "matching": matching, "through": through,
            "offset": query.offset, "limit": query.limit, "returned": page.len(),
            "next_offset": (query.offset.saturating_add(page.len()) < matching).then_some(query.offset + page.len()),
            "previous_offset": (query.offset > 0).then(|| query.offset.saturating_sub(query.limit)),
            "failed": failed, "facets": facets, "index": index,
            "sizes": {"transferred": summary.transferred, "resources": summary.resources},
            "hidden_internal": summary.hidden_internal,
            "timeline": match &summary.timeline {
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
        if let Some(since) = query.since {
            let added: i64 = db
                .prepare_cached("SELECT COUNT(*) FROM temp.selection WHERE ordinal >= ?1")
                .sql()?
                .query_row([clamped(since)], |row| row.get(0))
                .sql()?;
            document["added"] = json!(added);
        }
        if !query.locate.is_empty() {
            let mut statement = db
                .prepare_cached(
                    "SELECT s.position - 1 FROM temp.selection s
                     WHERE s.ordinal = (SELECT ordinal FROM rows WHERE id = ?1)",
                )
                .sql()?;
            let mut located = serde_json::Map::new();
            for id in &query.locate {
                let at: Option<i64> = statement
                    .query_row([id], |row| row.get(0))
                    .optional()
                    .sql()?;
                located.insert(id.clone(), json!(at));
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
    /// A `response_body` payload: state, lengths, partial index and, with a
    /// retained body, a nonzero digest (protocol/native-network-v3.md).
    fn body(state: u8, length: u64, captured: u64, partial: u16) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        bytes[..4].copy_from_slice(&[1, 0, 128, 0]);
        bytes[4] = state;
        bytes[8..16].copy_from_slice(&length.to_le_bytes());
        bytes[16..24].copy_from_slice(&captured.to_le_bytes());
        bytes[28..30].copy_from_slice(&partial.to_le_bytes());
        if captured != 0 {
            bytes[32..64].fill(0xab);
        }
        bytes
    }
    /// Every reason a row's body is or is not retained, and a reuse that names
    /// the request whose response it reused.
    fn response_bodies(store: &mut Store) {
        let context =
            json!({"tab_id": 3, "browser_context_id_high": "5", "browser_context_id_low": "6"});
        let browser = |request: u64| {
            merge(
                context.clone(),
                json!({"initiator_process_id": 61, "initiator_request_id": request}),
            )
        };
        let child = |parent: &str, artifact: &str, request: u64| {
            merge(
                browser(request),
                json!({"parent_event_id": parent, "artifact_id": artifact}),
            )
        };
        // Retained: a partial snapshot, then the ended body supersedes it.
        store.push(
            61,
            20,
            "request_initiated",
            b"GET bodies.example.test",
            json!({}),
        );
        store.push(
            7,
            960,
            "request_started",
            b"GET bodies.example.test",
            merge(browser(20), json!({"resource_type": 13})),
        );
        let response = store.push(
            7,
            960,
            "response_started",
            b"application/json",
            merge(browser(20), json!({"status_code": 200})),
        );
        store.push(
            7,
            960,
            "response_body",
            &body(3, 40, 40, 1),
            child(&response, "77", 20),
        );
        store.push(
            7,
            960,
            "response_body",
            &body(1, 90, 90, 0),
            child(&response, "78", 20),
        );
        store.push(
            7,
            960,
            "request_completed",
            b"completed",
            merge(
                browser(20),
                json!({"status_code": 200, "decoded_body_length": "90"}),
            ),
        );
        // A memory-cache reuse naming that request (payload version 2, bit 2).
        let mut named = reuse(5, false, b"bodies.example.test");
        (named[0], named[5]) = (2, 4);
        store.push(61, 21, "memory_cache_reuse", &named,
            json!({"scheme_class": 2, "loader_kind": 16, "tab_id": 3, "status_code": 200,
                "decoded_body_length": "90", "initiator_process_id": 61, "initiator_request_id": 20}));
        // Not modified, and a malformed record (captured past its length).
        store.push(
            7,
            961,
            "request_started",
            b"GET bodies.example.test",
            merge(browser(23), json!({})),
        );
        let cached = store.push(
            7,
            961,
            "response_started",
            b"application/json",
            merge(browser(23), json!({"status_code": 304})),
        );
        store.push(
            7,
            961,
            "response_body",
            &body(7, 0, 0, 0),
            child(&cached, "0", 23),
        );
        store.push(
            7,
            962,
            "request_started",
            b"GET bodies.example.test",
            merge(browser(24), json!({})),
        );
        let broken = store.push(
            7,
            962,
            "response_started",
            b"application/json",
            merge(browser(24), json!({"status_code": 200})),
        );
        store.push(
            7,
            962,
            "response_body",
            &body(1, 4, 9, 0),
            child(&broken, "79", 24),
        );
        // A redirect with nothing after it, and a request cancelled before any response.
        store.push(
            7,
            963,
            "request_started",
            b"GET bodies.example.test",
            merge(browser(25), json!({})),
        );
        store.push(
            7,
            963,
            "request_redirected",
            b"GET bodies.example.test",
            merge(browser(25), json!({"status_code": 302})),
        );
        store.push(
            7,
            964,
            "request_started",
            b"GET bodies.example.test",
            merge(browser(26), json!({})),
        );
        store.push(
            7,
            964,
            "request_failed",
            b"failed",
            merge(browser(26), json!({"error_code": -3})),
        );
        // A service worker answered the page in the renderer.
        store.push(
            61,
            22,
            "request_initiated",
            b"GET sw.example.test",
            json!({"scheme_class": 2, "loader_kind": 16, "tab_id": 3}),
        );
        store.push(61, 22, "request_completed", b"completed",
            json!({"scheme_class": 2, "tab_id": 3, "status_code": 200, "decoded_body_length": "12", "flags": 4}));
        // The redirect above then ends without another response: redirected.
        store.push(
            7,
            963,
            "request_completed",
            b"completed",
            merge(browser(25), json!({})),
        );
        more_response_bodies(store);
    }
    /// The remaining body cases, refusals after snapshots, redirects that end
    /// otherwise, and memory-cache reuses whose source is missing, cut,
    /// partial, on another host or started later (renderers 62 and 63).
    fn more_response_bodies(store: &mut Store) {
        let context =
            json!({"tab_id": 3, "browser_context_id_high": "5", "browser_context_id_low": "6"});
        let browser = |request: u64| {
            merge(
                context.clone(),
                json!({"initiator_process_id": 62, "initiator_request_id": request}),
            )
        };
        let child = |parent: &str, artifact: &str, request: u64| {
            merge(
                browser(request),
                json!({"parent_event_id": parent, "artifact_id": artifact}),
            )
        };
        // A request ending with one record body: each pushes start, response, record.
        let mut answered = |request: u64, payload: Vec<u8>, artifact: &str, status: i64| {
            let id = 970 + request;
            store.push(
                7,
                id,
                "request_started",
                b"GET more.example.test",
                merge(browser(request), json!({})),
            );
            let response = store.push(
                7,
                id,
                "response_started",
                b"application/json",
                merge(browser(request), json!({"status_code": status})),
            );
            store.push(
                7,
                id,
                "response_body",
                &payload,
                child(&response, artifact, request),
            );
            response
        };
        const MIB: u64 = 1024 * 1024;
        answered(1, body(3, 30, 30, 1), "81", 200);
        answered(2, body(2, 20 * MIB, 16 * MIB, 0), "82", 200);
        answered(3, body(4, 10, 10, 0), "83", 200);
        answered(4, body(5, 0, 0, 0), "0", 200);
        answered(5, body(6, 0, 0, 0), "0", 200);
        // Version 2 bit 7: a byte bound withheld a snapshot the spacing allowed.
        let mut withheld = body(3, 30, 30, 1);
        (withheld[0], withheld[5]) = (2, 0x80);
        answered(12, withheld, "88", 200);
        // A refused end keeps the newest snapshot beside it; Traffic tries
        // the older one when the receiver refused the newest.
        let refused = answered(6, body(3, 30, 30, 1), "85", 200);
        store.push(
            7,
            976,
            "response_body",
            &body(3, 45, 45, 2),
            child(&refused, "89", 6),
        );
        store.push(
            7,
            976,
            "response_body",
            &body(12, 60, 0, 0),
            child(&refused, "0", 6),
        );
        // Ended with no response, and a redirect then a 304.
        store.push(
            7,
            977,
            "request_started",
            b"GET more.example.test",
            merge(browser(7), json!({})),
        );
        store.push(
            7,
            977,
            "request_completed",
            b"completed",
            merge(browser(7), json!({})),
        );
        store.push(
            7,
            978,
            "request_started",
            b"GET more.example.test",
            merge(browser(8), json!({})),
        );
        let hop = store.push(
            7,
            978,
            "request_redirected",
            b"GET more.example.test",
            merge(browser(8), json!({"status_code": 302})),
        );
        store.push(
            7,
            978,
            "response_body",
            &body(8, 0, 0, 0),
            child(&hop, "0", 8),
        );
        let cached = store.push(
            7,
            978,
            "response_started",
            b"application/json",
            merge(browser(8), json!({"status_code": 304})),
        );
        store.push(
            7,
            978,
            "response_body",
            &body(7, 0, 0, 0),
            child(&cached, "0", 8),
        );
        // A redirect then a failure, a cancel, or no end yet: never redirected.
        for (request, end) in [(9, Some(-105)), (10, Some(-3)), (11, None)] {
            let id = 970 + request;
            store.push(
                7,
                id,
                "request_started",
                b"GET more.example.test",
                merge(browser(request), json!({})),
            );
            store.push(
                7,
                id,
                "request_redirected",
                b"GET more.example.test",
                merge(browser(request), json!({"status_code": 302})),
            );
            if let Some(error) = end {
                store.push(
                    7,
                    id,
                    "request_failed",
                    b"failed",
                    merge(browser(request), json!({"error_code": error})),
                );
            }
        }
        // Reuse sources: cut at the limit, and a snapshot.
        let source = |store: &mut Store, renderer: u64, payload: Vec<u8>, artifact: &str| {
            store.push(
                63,
                renderer,
                "request_initiated",
                b"GET src.example.test",
                json!({}),
            );
            let id = 990 + renderer;
            let joined = merge(
                context.clone(),
                json!({"initiator_process_id": 63, "initiator_request_id": renderer}),
            );
            store.push(
                7,
                id,
                "request_started",
                b"GET src.example.test",
                joined.clone(),
            );
            let response = store.push(
                7,
                id,
                "response_started",
                b"application/json",
                merge(joined.clone(), json!({"status_code": 200})),
            );
            store.push(
                7,
                id,
                "response_body",
                &payload,
                merge(
                    joined,
                    json!({"parent_event_id": response, "artifact_id": artifact}),
                ),
            );
        };
        let reuse_of = |store: &mut Store, renderer: u64, host: &[u8], source: Option<u64>| {
            let mut payload = reuse(1, false, host);
            let mut fields =
                json!({"scheme_class": 2, "loader_kind": 16, "tab_id": 3, "status_code": 200});
            if let Some(source) = source {
                (payload[0], payload[5]) = (2, 4);
                fields["initiator_process_id"] = json!(63);
                fields["initiator_request_id"] = json!(source);
            }
            store.push(63, renderer, "memory_cache_reuse", &payload, fields);
        };
        source(store, 1, body(2, 20 * MIB, 16 * MIB, 0), "86");
        reuse_of(store, 2, b"src.example.test", Some(1));
        source(store, 3, body(3, 50, 50, 1), "87");
        reuse_of(store, 4, b"src.example.test", Some(3));
        reuse_of(store, 5, b"src.example.test", Some(99));
        reuse_of(store, 6, b"other.example.test", Some(1));
        reuse_of(store, 7, b"src.example.test", Some(8));
        store.push(
            63,
            8,
            "request_initiated",
            b"GET src.example.test",
            json!({}),
        );
        // A version 1 reuse names no source.
        reuse_of(store, 9, b"src.example.test", None);
    }
    fn write(path: &Path, store: &Store) {
        fs::write(path, store.bytes()).unwrap();
    }
    /// Indexes the store to its end. A read folds new records for at most
    /// `READ_FOLD` and answers from what is indexed, so a test that expects
    /// an answer over the whole store catches up first instead of racing that
    /// slice on a loaded machine.
    fn catch_up(index: &mut RequestIndex) {
        index
            .refresh(Instant::now() + Duration::from_secs(120))
            .unwrap();
        assert!(index.is_caught_up());
    }
    fn page(index: &mut RequestIndex, raw: &str) -> Value {
        catch_up(index);
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
        catch_up(&mut index);
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
        let legacy = root.path().join("events.jsonl.requests-v1");
        fs::write(&legacy, b"{}").unwrap();
        let mut first = RequestIndex::new(&path);
        let epoch = page(&mut first, "")["index"]["epoch"].clone();
        let sidecar = root.path().join("events.jsonl.requests-v2");
        assert!(
            sidecar.is_file(),
            "rows commit with the position they describe"
        );
        assert!(!legacy.exists(), "the version 1 file is removed");
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
        drop(first);
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
        // A whole match: a no_script stack summary, rule 2, method matched.
        let mut matched = vec![1, 0, 128, 0, 2, 0x08];
        matched.resize(80, 0);
        matched.extend([2, 1]);
        matched.resize(128, 0);
        store.push(42, 6, "request_initiated", b"", json!({}));
        let sequence = store.push(42, 6, "request_watch_match", &matched, json!({}));
        store.push(42, 6, "request_watch_match", &matched, json!({}));
        store.push(42, 7, "request_initiated", b"", json!({}));
        fs::write(&path, store.bytes()).unwrap();
        let mut index = RequestIndex::new(&path);
        let rows = page(&mut index, "sort=capture&order=asc")["requests"].clone();
        let row = &rows[0];
        assert_eq!(row["records"], 2, "{row}");
        assert_eq!(row["members"][0]["records"], 2);
        // A match the core refuses still marks its row, with no rule.
        assert_eq!(row["watch"]["rule"], Value::Null, "{row}");
        assert_eq!(row["watch"]["sequence_number"], "2");
        // The first match names the rule; the row counts every match.
        assert_eq!(
            rows[1]["watch"],
            json!({"session_id": "1", "process_id": 42, "sequence_number": sequence,
                "frame_id": "9", "rule": 2, "method_matched": true})
        );
        assert_eq!(rows[1]["records"], 3);
        assert_eq!(rows[2]["watch"], Value::Null);
    }

    #[test]
    fn unchanged_pages_are_not_modified_until_the_store_grows() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        write(&path, &fixture());
        let mut index = RequestIndex::new(&path);
        catch_up(&mut index);
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
        let mut late = Store {
            events: Vec::new(),
            sequence: 900,
        };
        late.push(
            7,
            999,
            "request_started",
            b"GET late.example.test",
            json!({}),
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&late.bytes())
            .unwrap();
        catch_up(&mut index);
        let Answer::Document(document, _) = index.respond(&query, Some(&tag)).unwrap() else {
            panic!("a grown store answers again")
        };
        assert_eq!(document["total"], 16);
    }

    #[test]
    fn every_row_names_why_its_body_is_or_is_not_retained() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events.jsonl");
        let mut store = Store {
            events: Vec::new(),
            sequence: 0,
        };
        response_bodies(&mut store);
        write(&path, &store);
        let mut index = RequestIndex::new(&path);
        catch_up(&mut index);
        let counts = index.response_bodies().unwrap();
        assert_eq!(counts["complete"], true);
        let cases = counts["cases"].as_object().unwrap();
        assert_eq!(
            cases
                .iter()
                .map(|(case, count)| format!("{case}={}", count.as_str().unwrap()))
                .collect::<Vec<_>>(),
            [
                "aborted=1",
                "cancelled=1",
                "cancelled_before_response=2",
                "captured=1",
                "captured_truncated=2",
                "empty=1",
                "failed_before_response=1",
                "malformed=1",
                "memory_cache=7",
                "no_response=1",
                "not_captured_session_budget=1",
                "not_modified=2",
                "partial=3",
                "pending=2",
                "redirected=1",
                "service_worker=1",
            ]
        );
        let document = page(&mut index, "limit=500");
        let rows = document["requests"].as_array().unwrap();
        let row = |id: &str| rows.iter().find(|row| row["id"] == id).unwrap();
        // A refused end names the snapshot of the same response that is retained.
        let refused = &row("S1:R62:6")["response_body"];
        assert_eq!(refused["case"], "not_captured_session_budget");
        assert!(refused["artifact_id"].is_null());
        assert_eq!(refused["earlier_snapshot"]["artifact_id"], "89");
        assert_eq!(refused["earlier_snapshot"]["captured_length"], "45");
        assert_eq!(refused["earlier_snapshot"]["partial_index"], 2);
        assert!(row("S1:R62:1")["response_body"]["earlier_snapshot"].is_null());
        assert_eq!(
            row("S1:R62:12")["response_body"]["snapshots_withheld"],
            true
        );
        assert_eq!(
            row("S1:R62:1")["response_body"]["snapshots_withheld"],
            false
        );
        assert_eq!(counts["snapshots_withheld"], "1");
        assert_eq!(
            counts["earlier_snapshots"],
            json!({"not_captured_session_budget": "1"})
        );
        // A redirect then a failure, a cancel or no end is never redirected.
        for (id, case) in [
            ("S1:R62:9", "failed_before_response"),
            ("S1:R62:10", "cancelled_before_response"),
            ("S1:R62:11", "pending"),
            ("S1:R62:8", "not_modified"),
            ("S1:R61:25", "redirected"),
        ] {
            assert_eq!(row(id)["response_body"]["case"], case, "{id}");
        }
        // Each reuse source is the reuse's load only on its host and before it.
        for (id, found, reason, case) in [
            ("S1:R63:2", true, None, Some("captured_truncated")),
            ("S1:R63:4", true, None, Some("partial")),
            ("S1:R63:5", false, Some("not_recorded"), None),
            ("S1:R63:6", false, Some("host_differs"), None),
            ("S1:R63:7", false, Some("started_after"), None),
        ] {
            let source = &row(id)["memory_cache_source"];
            assert_eq!(source["found"], found, "{id}");
            assert_eq!(source["reason"].as_str(), reason, "{id}");
            assert_eq!(source["response_body"]["case"].as_str(), case, "{id}");
        }
        assert!(row("S1:R63:9")["memory_cache_source"].is_null());
        let reuse = rows.iter().find(|row| row["memory_cache"] == true).unwrap();
        let source = &reuse["memory_cache_source"];
        assert_eq!(source["id"], "S1:R61:20");
        assert_eq!(source["found"], true);
        // The ended body supersedes its snapshot, and names its own artifact.
        assert_eq!(source["response_body"]["artifact_id"], "78");
        assert_eq!(source["response_body"]["body_length"], "90");
        assert_eq!(source["response_body"]["response_started"]["process_id"], 7);
        let retained = rows.iter().find(|row| row["id"] == "S1:R61:20").unwrap();
        assert_eq!(retained["response_body"]["case"], "captured");
        assert!(retained["memory_cache_source"].is_null());
    }

    #[test]
    fn a_repeated_or_late_body_record_keeps_the_retained_snapshot() {
        let context = json!({"tab_id": 3, "initiator_process_id": 64, "initiator_request_id": 1});
        // A duplicate line, then an older record read after the refusal.
        for late in [None, Some("3")] {
            let mut store = Store {
                events: Vec::new(),
                sequence: 0,
            };
            store.push(
                7,
                990,
                "request_started",
                b"GET late.example.test",
                context.clone(),
            );
            let response = store.push(
                7,
                990,
                "response_started",
                b"application/json",
                merge(context.clone(), json!({"status_code": 200})),
            );
            let child = |artifact: &str| {
                merge(
                    context.clone(),
                    json!({"parent_event_id": response, "artifact_id": artifact}),
                )
            };
            store.push(7, 990, "response_body", &body(3, 30, 30, 1), child("85"));
            store.push(7, 990, "response_body", &body(12, 60, 0, 0), child("0"));
            let mut repeated = store.events.last().unwrap().clone();
            if let Some(sequence) = late {
                repeated["sequence_number"] = json!(sequence);
            }
            store.events.push(repeated);
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("events.jsonl");
            write(&path, &store);
            let mut index = RequestIndex::new(&path);
            let document = page(&mut index, "limit=10");
            let body = &document["requests"][0]["response_body"];
            assert_eq!(body["case"], "not_captured_session_budget", "{late:?}");
            assert_eq!(body["earlier_snapshot"]["artifact_id"], "85", "{late:?}");
        }
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
        response_bodies(&mut store);
        // A request a watch rule matched: the match is a child of its row.
        let initiated = store.push(
            41,
            30,
            "request_initiated",
            b"POST w.example.test",
            json!({}),
        );
        let mut matched = vec![1, 0, 128, 0, 2, 0x08];
        matched.resize(80, 0);
        matched.extend([3, 1]);
        matched.resize(128, 0);
        store.push(
            41,
            30,
            "request_watch_match",
            &matched,
            json!({"parent_event_id": initiated}),
        );
        // The renderer records one match per request; a second one, as a
        // replayed or merged store could hold, never replaces the first.
        matched[80] = 5;
        store.push(
            41,
            30,
            "request_watch_match",
            &matched,
            json!({"parent_event_id": initiated}),
        );
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
        // The events as a row's store read delivers them to Traffic: a filtered
        // read, with each observation decoded beside its hex. The polling
        // window carries no decode; check-request-index.mjs reads those too.
        let mut events = store.events.clone();
        crate::event_query::annotate_events(&mut events);
        crate::debugger_observation::annotate(&mut events);
        let golden = json!({"events": events, "rows": document["requests"].take(),
            "orders": orders.into_iter().collect::<serde_json::Map<_, _>>(),
            "searches": searches.into_iter().collect::<serde_json::Map<_, _>>(),
            "filters": filters.into_iter().collect::<serde_json::Map<_, _>>()});
        fs::write(output, serde_json::to_vec_pretty(&golden).unwrap()).unwrap();
    }
}
