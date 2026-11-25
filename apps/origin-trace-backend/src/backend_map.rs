//! Backend map (docs/product/backend-map-v1.md, protocol/http-api.md
//! "Backend map"): an offline reading of every Traffic row of a session that
//! guesses the site's backend from what its front end already received. It
//! sends no request and looks nothing up; every finding names the rows,
//! hops and header, cookie, host, path or body signal it rests on.
//!
//! Rows are read through the HAR export's exact joins (`request_har`), one
//! row's records at a time. Credential header values never reach a rule:
//! cookie names are taken from `Cookie` and `Set-Cookie` and every value of a
//! credential-named header is dropped before matching. A rule may return a
//! short token it captured, such as an edge region, and nothing else of a
//! value, since whole values of headers such as `x-vercel-id` carry request
//! identifiers.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::request_headers::credential_name;
use crate::request_index;

pub const FORMAT: &str = "reb-backend-map-v1";
const RULES_FORMAT: &str = "reb-backend-signatures-v1";
const RANGES_FORMAT: &str = "reb-backend-ip-ranges-v1";
/// A captured token is returned only in this shape: short and plain, so a
/// rule that matched more than it meant to cannot echo a request ID or a
/// secret-length value.
static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,47}$").unwrap());

/// Where a signal looks. Header, cookie and query names are compared in
/// ASCII lowercase; patterns see values as captured.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum On {
    ResponseHeader,
    ResponseHeaderPrefix,
    RequestHeader,
    RequestHeaderPrefix,
    Cookie,
    Host,
    Path,
    QueryKey,
    Body,
    RequestBody,
    RemoteAddress,
    Protocol,
}

impl On {
    fn name(self) -> &'static str {
        match self {
            On::ResponseHeader => "response_header",
            On::ResponseHeaderPrefix => "response_header_prefix",
            On::RequestHeader => "request_header",
            On::RequestHeaderPrefix => "request_header_prefix",
            On::Cookie => "cookie",
            On::Host => "host",
            On::Path => "path",
            On::QueryKey => "query_key",
            On::Body => "body",
            On::RequestBody => "request_body",
            On::RemoteAddress => "remote_address",
            On::Protocol => "protocol",
        }
    }
    /// Signals that read captured content rather than metadata.
    fn content(self) -> bool {
        matches!(self, On::Body | On::RequestBody)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    format: String,
    reviewed: String,
    categories: Vec<CategoryDef>,
    technologies: Vec<TechnologyDef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CategoryDef {
    id: String,
    label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TechnologyDef {
    id: String,
    name: String,
    category: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    implies: Vec<String>,
    signals: Vec<SignalDef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignalDef {
    id: String,
    on: On,
    /// The header, cookie or query name, or a header-name prefix.
    #[serde(default)]
    name: Option<String>,
    /// A pattern over the value (headers), the name (cookies), the host,
    /// path, body or protocol.
    #[serde(default)]
    pattern: Option<String>,
    /// For body signals, a pattern the response MIME type must match.
    #[serde(default)]
    mime: Option<String>,
    /// For remote address signals, a provider of the ranges file.
    #[serde(default)]
    ranges: Option<String>,
    #[serde(default)]
    capture: Option<CaptureDef>,
    weight: u8,
    tier: Tier,
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureDef {
    /// What the token is, such as `edge_region` or `version`.
    name: String,
    group: usize,
}

/// `vendor`: a marker one product emits by design. `convention`: a name or
/// shape that products share or that anyone can set, so it supports a guess.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Tier {
    Vendor,
    Convention,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Tier::Vendor => "vendor",
            Tier::Convention => "convention",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RangeFile {
    format: String,
    retrieved: String,
    providers: Vec<ProviderDef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderDef {
    id: String,
    name: String,
    sources: Vec<String>,
    prefixes: Vec<String>,
}

struct Signal {
    id: String,
    technology: usize,
    on: On,
    name: Option<String>,
    pattern: Option<Regex>,
    mime: Option<Regex>,
    ranges: Option<usize>,
    capture: Option<(String, usize)>,
    weight: u8,
    tier: Tier,
    description: String,
}

struct Technology {
    id: String,
    name: String,
    category: String,
    references: Vec<String>,
    implies: Vec<usize>,
}

struct Prefix {
    network: IpAddr,
    bits: u8,
}

struct Provider {
    id: String,
    name: String,
    prefixes: Vec<Prefix>,
}

pub(crate) struct Rules {
    reviewed: String,
    digest: String,
    categories: Vec<(String, String)>,
    technologies: Vec<Technology>,
    signals: Vec<Signal>,
    providers: Vec<Provider>,
    ranges_retrieved: String,
    ranges_digest: String,
}

const SIGNATURES: &str = include_str!("../assets/backend-signatures.json");
const RANGES: &str = include_str!("../assets/backend-ip-ranges.json");

pub(crate) static RULES: LazyLock<Rules> =
    LazyLock::new(|| compile(SIGNATURES, RANGES).expect("Reviewed backend signatures"));

fn parse_prefix(text: &str) -> std::result::Result<Prefix, String> {
    let (address, bits) = text
        .split_once('/')
        .ok_or_else(|| format!("prefix {text} has no length"))?;
    let network: IpAddr = address
        .parse()
        .map_err(|_| format!("prefix {text} has no address"))?;
    let bits: u8 = bits
        .parse()
        .map_err(|_| format!("prefix {text} has no length"))?;
    let max = if network.is_ipv4() { 32 } else { 128 };
    if bits > max || masked(network, bits) != network {
        return Err(format!("prefix {text} is not a network"));
    }
    Ok(Prefix { network, bits })
}

fn masked(address: IpAddr, bits: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            IpAddr::V6((u128::from(v6) & mask).into())
        }
    }
}

/// The providers whose published ranges hold `address`.
fn providers_of(rules: &Rules, address: IpAddr) -> Vec<usize> {
    rules
        .providers
        .iter()
        .enumerate()
        .filter(|(_, provider)| {
            provider
                .prefixes
                .iter()
                .any(|prefix| contains(prefix, address))
        })
        .map(|(index, _)| index)
        .collect()
}

fn contains(prefix: &Prefix, address: IpAddr) -> bool {
    prefix.network.is_ipv4() == address.is_ipv4() && masked(address, prefix.bits) == prefix.network
}

/// Checks and compiles the two embedded files. Every reference must resolve
/// and every pattern compile, so a review mistake fails the build's tests
/// rather than a reader's request.
fn compile(signatures: &str, ranges: &str) -> std::result::Result<Rules, String> {
    let file: RuleFile = serde_json::from_str(signatures).map_err(|error| error.to_string())?;
    if file.format != RULES_FORMAT {
        return Err(format!("signature format {}", file.format));
    }
    let range_file: RangeFile = serde_json::from_str(ranges).map_err(|error| error.to_string())?;
    if range_file.format != RANGES_FORMAT {
        return Err(format!("range format {}", range_file.format));
    }
    let mut providers = Vec::new();
    for provider in &range_file.providers {
        if providers
            .iter()
            .any(|known: &Provider| known.id == provider.id)
            || provider.sources.is_empty()
        {
            return Err(format!("provider {}", provider.id));
        }
        providers.push(Provider {
            id: provider.id.clone(),
            name: provider.name.clone(),
            prefixes: provider
                .prefixes
                .iter()
                .map(|prefix| parse_prefix(prefix))
                .collect::<std::result::Result<_, _>>()?,
        });
    }
    let mut categories = Vec::new();
    for category in &file.categories {
        if categories.iter().any(|(id, _)| *id == category.id) {
            return Err(format!("category {} repeats", category.id));
        }
        categories.push((category.id.clone(), category.label.clone()));
    }
    let index: HashMap<&str, usize> = file
        .technologies
        .iter()
        .enumerate()
        .map(|(position, technology)| (technology.id.as_str(), position))
        .collect();
    if index.len() != file.technologies.len() {
        return Err("a technology id repeats".into());
    }
    let mut technologies = Vec::new();
    let mut signals: Vec<Signal> = Vec::new();
    for (position, technology) in file.technologies.iter().enumerate() {
        if !categories.iter().any(|(id, _)| *id == technology.category) {
            return Err(format!("{} has no category", technology.id));
        }
        let implies = technology
            .implies
            .iter()
            .map(|id| {
                index
                    .get(id.as_str())
                    .copied()
                    .filter(|implied| *implied != position)
                    .ok_or_else(|| format!("{} implies unknown {id}", technology.id))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if technology.signals.is_empty() && technology.implies.is_empty() {
            // A technology only ever implied still names no signal of its own.
        }
        technologies.push(Technology {
            id: technology.id.clone(),
            name: technology.name.clone(),
            category: technology.category.clone(),
            references: technology.references.clone(),
            implies,
        });
        for signal in &technology.signals {
            let id = format!("{}.{}", technology.id, signal.id);
            if signals.iter().any(|known| known.id == id) {
                return Err(format!("signal {id} repeats"));
            }
            if signal.weight == 0 || signal.weight > 100 || signal.description.is_empty() {
                return Err(format!("signal {id} weight or description"));
            }
            let named = matches!(
                signal.on,
                On::ResponseHeader
                    | On::ResponseHeaderPrefix
                    | On::RequestHeader
                    | On::RequestHeaderPrefix
                    | On::QueryKey
            );
            if named != signal.name.is_some() {
                return Err(format!("signal {id} name"));
            }
            if let Some(name) = &signal.name
                && (name.is_empty() || *name != name.to_ascii_lowercase())
            {
                return Err(format!("signal {id} name is not lowercase"));
            }
            let needs_pattern = matches!(
                signal.on,
                On::Cookie | On::Host | On::Path | On::Body | On::RequestBody | On::Protocol
            );
            if needs_pattern && signal.pattern.is_none() {
                return Err(format!("signal {id} needs a pattern"));
            }
            if signal.mime.is_some() && !signal.on.content() {
                return Err(format!("signal {id} mime"));
            }
            let ranges = match (signal.on, &signal.ranges) {
                (On::RemoteAddress, Some(provider)) => Some(
                    providers
                        .iter()
                        .position(|known| known.id == *provider)
                        .ok_or_else(|| format!("signal {id} ranges {provider}"))?,
                ),
                (On::RemoteAddress, None) => return Err(format!("signal {id} needs ranges")),
                (_, Some(_)) => return Err(format!("signal {id} ranges")),
                (_, None) => None,
            };
            if signal.on == On::RemoteAddress && signal.pattern.is_some() {
                return Err(format!("signal {id} pattern"));
            }
            let compiled = |pattern: &Option<String>| {
                pattern
                    .as_deref()
                    .map(Regex::new)
                    .transpose()
                    .map_err(|error| format!("signal {id}: {error}"))
            };
            let pattern = compiled(&signal.pattern)?;
            let mime = compiled(&signal.mime)?;
            let capture = match &signal.capture {
                Some(capture) => {
                    let groups = pattern.as_ref().map_or(0, |pattern| pattern.captures_len());
                    if capture.group == 0 || capture.group >= groups || capture.name.is_empty() {
                        return Err(format!("signal {id} capture group"));
                    }
                    if signal.on == On::Cookie {
                        // A cookie name is matched, never returned.
                        return Err(format!("signal {id} captures a cookie name"));
                    }
                    Some((capture.name.clone(), capture.group))
                }
                None => None,
            };
            signals.push(Signal {
                id,
                technology: position,
                on: signal.on,
                name: signal.name.clone(),
                pattern,
                mime,
                ranges,
                capture,
                weight: signal.weight,
                tier: signal.tier,
                description: signal.description.clone(),
            });
        }
    }
    // An implication cycle would never settle.
    for start in 0..technologies.len() {
        let mut seen = BTreeSet::new();
        let mut stack = vec![start];
        while let Some(at) = stack.pop() {
            for &next in &technologies[at].implies {
                if next == start {
                    return Err(format!("{} implies itself", technologies[start].id));
                }
                if seen.insert(next) {
                    stack.push(next);
                }
            }
        }
    }
    Ok(Rules {
        reviewed: file.reviewed,
        digest: hex::encode(Sha256::digest(signatures.as_bytes())),
        categories,
        technologies,
        signals,
        providers,
        ranges_retrieved: range_file.retrieved,
        ranges_digest: hex::encode(Sha256::digest(ranges.as_bytes())),
    })
}

/// Where one finding's evidence came from: a Traffic row and hop, and for a
/// header signal the header's own name as captured.
#[derive(Clone)]
struct Place {
    row: String,
    request: Value,
    hop: u64,
    /// The hop's start on the capture's monotonic clock.
    time: String,
    header: Option<String>,
    /// A script artifact (ID, SHA-256) instead of a Traffic row: scripts are
    /// kept as source artifacts, not as response bodies.
    artifact: Option<(String, String)>,
}

impl Place {
    fn json(&self) -> Value {
        if let Some((id, sha256)) = &self.artifact {
            return json!({"artifact_id": id, "sha256": sha256});
        }
        let mut out = json!({"row_id": self.row, "request_id": self.request, "hop": self.hop, "time_ns": self.time});
        if let Some(header) = &self.header {
            out["header"] = json!(header);
        }
        out
    }
}

#[derive(Default)]
struct Hits {
    count: u64,
    first: Option<Place>,
    last: Option<Place>,
}

impl Hits {
    fn add(&mut self, place: Place) {
        self.count += 1;
        if self.first.is_none() {
            self.first = Some(place);
        } else {
            self.last = Some(place);
        }
    }
    fn json(&self) -> Value {
        let mut out = json!({"count": self.count, "first": self.first.as_ref().map(Place::json)});
        if let Some(last) = &self.last {
            out["last"] = last.json();
        }
        out
    }
}

#[derive(Default)]
struct Route {
    count: u64,
    statuses: BTreeMap<String, u64>,
    mime_types: BTreeMap<String, u64>,
    styles: BTreeMap<&'static str, u64>,
    query_keys: BTreeSet<String>,
    /// Route templates the server named itself (`x-matched-path`,
    /// `x-sveltekit-routeid`).
    matched: BTreeSet<String>,
    first: Option<Place>,
}

#[derive(Default)]
struct Host {
    rows: BTreeSet<String>,
    entries: u64,
    document: bool,
    methods: BTreeMap<String, u64>,
    statuses: BTreeMap<String, u64>,
    types: BTreeMap<String, u64>,
    mime_types: BTreeMap<String, u64>,
    protocols: BTreeMap<String, u64>,
    addresses: BTreeMap<String, u64>,
    with_response_headers: u64,
    static_prefixes: BTreeMap<String, u64>,
    static_count: u64,
    routes: BTreeMap<(String, String), Route>,
    /// Header names this host's CORS headers expose to the page, accept from
    /// it, and the page asked to send.
    cors_exposed: BTreeSet<String>,
    cors_allowed: BTreeSet<String>,
    cors_requested: BTreeSet<String>,
}

/// A host the session's traffic names without necessarily contacting it:
/// in a policy or Link header, or as a URL in a script, page or JSON body.
struct Declared {
    sources: BTreeSet<String>,
    wildcard: bool,
    count: u64,
    first: Place,
}

#[derive(Default)]
struct Coverage {
    rows: u64,
    entries: u64,
    unlinked: u64,
    response_headers: u64,
    no_response_headers: u64,
    withheld_values: u64,
    bodies_read: u64,
    bodies_binary: u64,
    bodies_absent: u64,
    request_bodies_read: u64,
    paths_known: u64,
    captures_refused: u64,
    declarations: u64,
    internal: u64,
    scripts_read: u64,
    scripts_unreadable: u64,
}

/// One HAR entry seen through what rules may read.
struct Seen<'a> {
    host: String,
    path: String,
    query_keys: Vec<String>,
    method: String,
    status: u64,
    protocol: String,
    mime: String,
    address: Option<IpAddr>,
    providers: Vec<usize>,
    response: Vec<(String, String, &'a str)>,
    request: Vec<(String, String, &'a str)>,
    cookies: BTreeSet<String>,
    body: Option<&'a str>,
    request_body: Option<&'a str>,
    request_type: String,
}

/// Lowercase name, value, and the name as captured. Credential-named values
/// are dropped here, so no rule can match or capture them.
fn readable<'a>(headers: &'a Value, withheld: &mut u64) -> Vec<(String, String, &'a str)> {
    let mut out = Vec::new();
    for header in headers.as_array().into_iter().flatten() {
        let Some(name) = header["name"].as_str() else {
            continue;
        };
        let value = if header["_reb_withheld"] == true || credential_name(name) {
            *withheld += 1;
            String::new()
        } else {
            header["value"].as_str().unwrap_or("").to_owned()
        };
        out.push((name.to_ascii_lowercase(), value, name));
    }
    out
}

/// Cookie names from `Cookie` and `Set-Cookie`. Only the name before `=` is
/// kept; the value is never stored.
fn cookie_names(headers: &Value, out: &mut BTreeSet<String>) {
    for header in headers.as_array().into_iter().flatten() {
        let name = header["name"].as_str().unwrap_or("").to_ascii_lowercase();
        let value = header["value"].as_str().unwrap_or("");
        let pairs: Vec<&str> = match name.as_str() {
            "cookie" => value.split(';').collect(),
            "set-cookie" => value
                .lines()
                .filter_map(|line| line.split(';').next())
                .collect(),
            _ => continue,
        };
        for pair in pairs {
            if let Some((key, _)) = pair.split_once('=') {
                let key = key.trim();
                if !key.is_empty() && key.len() <= 128 {
                    out.insert(key.to_owned());
                }
            }
        }
    }
}

fn status_class(status: u64) -> String {
    match status {
        0 => "none".into(),
        100..=599 => format!("{}xx", status / 100),
        _ => "other".into(),
    }
}

static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .unwrap()
});
static ULID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$").unwrap());
static PREFIXED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([a-z]{2,10})_[A-Za-z0-9]{8,}$").unwrap());
static DATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?$").unwrap());

/// One path segment as a template part: identifiers collapse to their shape
/// (`{int}`, `{uuid}`, `{objectid}`, `{ulid}`, `{hex}`, `{cus_id}`,
/// `{date}`, `{token}`), names stay.
fn template_segment(segment: &str) -> String {
    let all = |test: fn(u8) -> bool| !segment.is_empty() && segment.bytes().all(test);
    if all(|b| b.is_ascii_digit()) {
        return "{int}".into();
    }
    if UUID.is_match(segment) {
        return "{uuid}".into();
    }
    if segment.len() == 24 && all(|b| b.is_ascii_hexdigit()) {
        return "{objectid}".into();
    }
    if ULID.is_match(segment) {
        return "{ulid}".into();
    }
    if segment.len() >= 16 && all(|b| b.is_ascii_hexdigit()) {
        return "{hex}".into();
    }
    if let Some(found) = PREFIXED.captures(segment) {
        return format!("{{{}_id}}", &found[1]);
    }
    if DATE.is_match(segment) {
        return "{date}".into();
    }
    if segment.contains('@') {
        return "{email}".into();
    }
    let digits = segment.bytes().filter(u8::is_ascii_digit).count();
    let letters = segment.bytes().filter(u8::is_ascii_alphabetic).count();
    if segment.len() > 64
        || (segment.len() >= 20 && digits >= 2 && letters >= 2 && !segment.contains('.'))
    {
        return "{token}".into();
    }
    segment.to_owned()
}

fn template(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".into();
    }
    path.split('/')
        .map(template_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// The first two path segments of a static resource, which name its bundle
/// directory (`/_next/static`, `/assets`) without each hashed file.
fn static_prefix(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    match parts.len() {
        0 | 1 => "/".into(),
        2 => format!("/{}", parts[0]),
        _ => format!("/{}/{}", parts[0], template_segment(parts[1])),
    }
}

fn header<'a>(headers: &'a [(String, String, &str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(lower, _, _)| lower == name)
        .map(|(_, value, _)| value.as_str())
}

/// How a request talks to its backend, from its transport alone.
fn api_style(seen: &Seen) -> &'static str {
    let request_type = header(&seen.request, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = seen.path.to_ascii_lowercase();
    if seen.status == 101
        || header(&seen.request, "upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
    {
        "websocket"
    } else if seen.mime.starts_with("text/event-stream") {
        "server_sent_events"
    } else if request_type.starts_with("application/grpc-web")
        || seen.mime.starts_with("application/grpc-web")
    {
        "grpc_web"
    } else if request_type.starts_with("application/connect+")
        || header(&seen.request, "connect-protocol-version").is_some()
    {
        "connect"
    } else if path.contains("graphql")
        || request_type.starts_with("application/graphql")
        || seen.mime.starts_with("application/graphql")
    {
        "graphql"
    } else if path.contains("/trpc/") {
        "trpc"
    } else if seen.mime.contains("text/x-component") || header(&seen.request, "rsc").is_some() {
        "react_server_components"
    } else if seen.mime.contains("json") {
        "json"
    } else if seen.mime.starts_with("text/html") {
        "document"
    } else if request_type.starts_with("application/x-www-form-urlencoded")
        || request_type.starts_with("multipart/form-data")
    {
        "form"
    } else {
        "other"
    }
}

fn is_static(request_type: &str, mime: &str) -> bool {
    matches!(request_type, "css" | "js" | "img" | "font" | "media")
        || mime.starts_with("image/")
        || mime.starts_with("font/")
        || mime == "text/css"
        || mime.contains("javascript")
        || mime == "application/wasm"
}

#[derive(Default)]
struct Finding {
    signals: BTreeMap<usize, BTreeMap<String, Hits>>,
    captures: BTreeMap<String, BTreeMap<String, u64>>,
}

/// Everything one walk of a session's rows has gathered.
#[derive(Default)]
pub(crate) struct Map {
    coverage: Coverage,
    hosts: BTreeMap<String, Host>,
    findings: BTreeMap<usize, Finding>,
    /// Providers whose ranges hold each address seen, so each distinct
    /// address is tested against the ranges once.
    providers: HashMap<IpAddr, Vec<usize>>,
    declared: BTreeMap<String, Declared>,
    /// Header names a CORS header declared, with where it first did.
    declared_request_headers: BTreeMap<String, (String, Place)>,
    declared_response_headers: BTreeMap<String, (String, Place)>,
}

impl Map {
    /// Folds one Traffic row and its HAR entries.
    pub(crate) fn add_row(&mut self, row: &Value, entries: &[Value]) {
        let rules = &*RULES;
        self.coverage.rows += 1;
        let row_id = row["id"].as_str().unwrap_or("").to_owned();
        let request_type = row["type"].as_str().unwrap_or("other").to_owned();
        let last = entries.len().saturating_sub(1);
        for (position, entry) in entries.iter().enumerate() {
            self.coverage.entries += 1;
            let reb = &entry["_reb"];
            if reb["outcome"] == "unlinked" {
                self.coverage.unlinked += 1;
            }
            let url_text = entry["request"]["url"].as_str().unwrap_or("");
            let parsed = url::Url::parse(url_text).ok();
            let host = parsed
                .as_ref()
                .and_then(|url| {
                    url.host_str().map(|host| match url.port() {
                        Some(port) => format!("{host}:{port}"),
                        None => host.to_owned(),
                    })
                })
                .or_else(|| row["host"].as_str().map(str::to_owned))
                .or_else(|| row["domain"].as_str().map(str::to_owned))
                .unwrap_or_default()
                .to_ascii_lowercase();
            // Browser-internal pages (new tab, theme, resources) are not the
            // site's traffic: a parsed URL must be the web's, and a host-only
            // row must name a network host.
            let web = match &parsed {
                Some(url) => matches!(url.scheme(), "http" | "https" | "ws" | "wss"),
                None => network_host(&host),
            };
            if row["browser_internal"] == true || !web {
                self.coverage.internal += 1;
                continue;
            }
            let path = parsed
                .as_ref()
                .map(|url| url.path().to_owned())
                .unwrap_or_default();
            if parsed.is_some() {
                self.coverage.paths_known += 1;
            }
            let query_keys: Vec<String> = parsed
                .as_ref()
                .map(|url| {
                    url.query_pairs()
                        .map(|(key, _)| key.to_ascii_lowercase())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()
                })
                .unwrap_or_default();
            let final_hop = position == last;
            let response = &entry["response"];
            let mime = if final_hop {
                row["mime_type"].as_str().unwrap_or("")
            } else {
                ""
            }
            .to_ascii_lowercase();
            let mut cookies = BTreeSet::new();
            cookie_names(&entry["request"]["headers"], &mut cookies);
            cookie_names(&response["headers"], &mut cookies);
            let response_headers =
                readable(&response["headers"], &mut self.coverage.withheld_values);
            let request_headers = readable(
                &entry["request"]["headers"],
                &mut self.coverage.withheld_values,
            );
            if response_headers.is_empty() {
                self.coverage.no_response_headers += 1;
            } else {
                self.coverage.response_headers += 1;
            }
            let content = &response["content"];
            let body = match (content["text"].as_str(), content["encoding"].as_str()) {
                (Some(text), None) => {
                    self.coverage.bodies_read += 1;
                    Some(text)
                }
                (Some(_), Some(_)) => {
                    self.coverage.bodies_binary += 1;
                    None
                }
                _ => {
                    if final_hop {
                        self.coverage.bodies_absent += 1;
                    }
                    None
                }
            };
            let request_body = entry["request"]["postData"]["text"].as_str();
            if request_body.is_some() {
                self.coverage.request_bodies_read += 1;
            }
            let address: Option<IpAddr> = entry["serverIPAddress"].as_str().and_then(|text| {
                text.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse()
                    .ok()
            });
            let providers = address
                .map(|address| {
                    self.providers
                        .entry(address)
                        .or_insert_with(|| providers_of(rules, address))
                        .clone()
                })
                .unwrap_or_default();
            let seen = Seen {
                host: host.clone(),
                path: path.clone(),
                query_keys,
                method: entry["request"]["method"]
                    .as_str()
                    .unwrap_or("GET")
                    .to_owned(),
                status: response["status"].as_u64().unwrap_or(0),
                protocol: response["httpVersion"]
                    .as_str()
                    .unwrap_or("")
                    .to_ascii_lowercase(),
                mime,
                address,
                providers,
                response: response_headers,
                request: request_headers,
                cookies,
                body,
                request_body,
                request_type: request_type.clone(),
            };
            let place = |header: Option<&str>| Place {
                row: row_id.clone(),
                request: reb["request_id"].clone(),
                hop: reb["hop"].as_u64().unwrap_or(0),
                time: reb["monotonic_time_ns"]
                    .as_str()
                    .or_else(|| row["first_time_ns"].as_str())
                    .unwrap_or("0")
                    .to_owned(),
                header: header.map(str::to_owned),
                artifact: None,
            };
            self.fold_host(row, &seen, &place(None), final_hop);
            self.declare(&seen, &place);
            for (index, signal) in rules.signals.iter().enumerate() {
                for (header_name, token) in matches(signal, &seen) {
                    let finding = self.findings.entry(signal.technology).or_default();
                    finding
                        .signals
                        .entry(index)
                        .or_default()
                        .entry(seen.host.clone())
                        .or_default()
                        .add(place(header_name.as_deref()));
                    if let (Some((name, _)), Some(token)) = (&signal.capture, token) {
                        if TOKEN.is_match(&token) {
                            *finding
                                .captures
                                .entry(name.clone())
                                .or_default()
                                .entry(token)
                                .or_default() += 1;
                        } else {
                            self.coverage.captures_refused += 1;
                        }
                    }
                }
            }
        }
    }

    fn fold_host(&mut self, row: &Value, seen: &Seen, place: &Place, final_hop: bool) {
        let host = self.hosts.entry(seen.host.clone()).or_default();
        host.rows.insert(place.row.clone());
        host.entries += 1;
        if row["main_frame"] == true && seen.request_type == "doc" {
            host.document = true;
        }
        *host.methods.entry(seen.method.clone()).or_default() += 1;
        let status = status_class(seen.status);
        *host.statuses.entry(status.clone()).or_default() += 1;
        if final_hop {
            *host.types.entry(seen.request_type.clone()).or_default() += 1;
        }
        if !seen.mime.is_empty() {
            *host.mime_types.entry(seen.mime.clone()).or_default() += 1;
        }
        if !seen.protocol.is_empty() {
            *host.protocols.entry(seen.protocol.clone()).or_default() += 1;
        }
        if let Some(address) = seen.address {
            *host.addresses.entry(address.to_string()).or_default() += 1;
        }
        if !seen.response.is_empty() {
            host.with_response_headers += 1;
        }
        if seen.path.is_empty() {
            return;
        }
        if final_hop && is_static(&seen.request_type, &seen.mime) {
            host.static_count += 1;
            *host
                .static_prefixes
                .entry(static_prefix(&seen.path))
                .or_default() += 1;
            return;
        }
        let route = host
            .routes
            .entry((seen.method.clone(), template(&seen.path)))
            .or_default();
        route.count += 1;
        *route.statuses.entry(status).or_default() += 1;
        if !seen.mime.is_empty() {
            *route.mime_types.entry(seen.mime.clone()).or_default() += 1;
        }
        *route.styles.entry(api_style(seen)).or_default() += 1;
        route.query_keys.extend(seen.query_keys.iter().cloned());
        for name in [
            "x-matched-path",
            "x-nextjs-matched-path",
            "x-sveltekit-routeid",
        ] {
            if let Some(value) = header(&seen.response, name)
                && ROUTE_TEMPLATE.is_match(value)
            {
                route.matched.insert(value.to_owned());
            }
        }
        if route.first.is_none() {
            route.first = Some(place.clone());
        }
    }

    /// The hosts the walk of rows saw, so scripts can be kept to them.
    pub(crate) fn hosts(&self) -> BTreeSet<String> {
        self.hosts.keys().cloned().collect()
    }

    /// A script artifact that could not be read whole and verified.
    pub(crate) fn script_unreadable(&mut self) {
        self.coverage.scripts_unreadable += 1;
    }

    /// Folds one distinct script artifact: body signals that read scripts and
    /// the URLs it names. Its host is the artifact URL's host; nothing about
    /// the host itself is counted again, since its rows were.
    pub(crate) fn add_script(&mut self, artifact: &Value, text: &str) {
        let rules = &*RULES;
        self.coverage.scripts_read += 1;
        let url = artifact["url"].as_str().unwrap_or("");
        let host = url::Url::parse(url)
            .ok()
            .and_then(|url| {
                url.host_str().map(|host| match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_owned(),
                })
            })
            .unwrap_or_default()
            .to_ascii_lowercase();
        let seen = Seen {
            host: host.clone(),
            path: String::new(),
            query_keys: Vec::new(),
            method: String::new(),
            status: 0,
            protocol: String::new(),
            mime: "application/javascript".into(),
            address: None,
            providers: Vec::new(),
            response: Vec::new(),
            request: Vec::new(),
            cookies: BTreeSet::new(),
            body: Some(text),
            request_body: None,
            request_type: "js".into(),
        };
        let identity = (
            artifact["artifact_id"].as_str().unwrap_or("").to_owned(),
            artifact["sha256"].as_str().unwrap_or("").to_owned(),
        );
        let place = |_: Option<&str>| Place {
            row: String::new(),
            request: Value::Null,
            hop: 0,
            time: String::new(),
            header: None,
            artifact: Some(identity.clone()),
        };
        for (index, signal) in rules.signals.iter().enumerate() {
            if signal.on != On::Body {
                continue;
            }
            for (_, token) in matches(signal, &seen) {
                let finding = self.findings.entry(signal.technology).or_default();
                finding
                    .signals
                    .entry(index)
                    .or_default()
                    .entry(host.clone())
                    .or_default()
                    .add(place(None));
                if let (Some((name, _)), Some(token)) = (&signal.capture, token) {
                    if TOKEN.is_match(&token) {
                        *finding
                            .captures
                            .entry(name.clone())
                            .or_default()
                            .entry(token)
                            .or_default() += 1;
                    } else {
                        self.coverage.captures_refused += 1;
                    }
                }
            }
        }
        self.declare(&seen, &place);
    }

    /// Records the hosts and header names one entry declares.
    fn declare(&mut self, seen: &Seen, place: &dyn Fn(Option<&str>) -> Place) {
        let mut found: Vec<(String, bool, String, Option<&str>)> = Vec::new();
        for (lower, value, original) in &seen.response {
            match lower.as_str() {
                "content-security-policy" | "content-security-policy-report-only" => {
                    let suffix = if lower.ends_with("-only") {
                        "-report-only"
                    } else {
                        ""
                    };
                    for (directive, host, wildcard) in csp_hosts(value) {
                        found.push((
                            host,
                            wildcard,
                            format!("csp{suffix}:{directive}"),
                            Some(*original),
                        ));
                    }
                }
                "report-to" | "reporting-endpoints" | "nel" => {
                    for host in url_hosts(value) {
                        found.push((host, false, lower.clone(), Some(*original)));
                    }
                }
                "link" => {
                    for (rel, host) in link_hosts(value) {
                        found.push((host, false, format!("link:{rel}"), Some(*original)));
                    }
                }
                "access-control-expose-headers" | "access-control-allow-headers" => {
                    let host = self.hosts.entry(seen.host.clone()).or_default();
                    let exposed = lower == "access-control-expose-headers";
                    for name in header_names(value) {
                        let declared = if exposed {
                            host.cors_exposed.insert(name.clone());
                            &mut self.declared_response_headers
                        } else {
                            host.cors_allowed.insert(name.clone());
                            &mut self.declared_request_headers
                        };
                        declared
                            .entry(name)
                            .or_insert_with(|| (seen.host.clone(), place(Some(original))));
                    }
                }
                _ => {}
            }
        }
        if let Some((_, value, original)) = seen
            .request
            .iter()
            .find(|(lower, _, _)| lower == "access-control-request-headers")
        {
            let host = self.hosts.entry(seen.host.clone()).or_default();
            for name in header_names(value) {
                host.cors_requested.insert(name.clone());
                self.declared_request_headers
                    .entry(name)
                    .or_insert_with(|| (seen.host.clone(), place(Some(original))));
            }
        }
        if let Some(body) = seen.body {
            let source = if seen.mime.contains("javascript") || seen.mime.contains("ecmascript") {
                Some("script")
            } else if seen.mime.starts_with("text/html")
                || seen.mime.starts_with("application/xhtml")
            {
                Some("page")
            } else if seen.mime.contains("json") {
                Some("json")
            } else {
                None
            };
            if let Some(source) = source {
                let mut hosts: BTreeSet<String> = URL_LITERAL
                    .captures_iter(body)
                    .filter_map(|found| found.get(1))
                    .map(|host| host.as_str().to_ascii_lowercase())
                    .collect();
                if source == "page" {
                    for policy in META_CSP
                        .captures_iter(body)
                        .filter_map(|found| found.get(1))
                    {
                        for (directive, host, wildcard) in csp_hosts(policy.as_str()) {
                            found.push((host, wildcard, format!("meta-csp:{directive}"), None));
                        }
                    }
                }
                hosts.remove(&seen.host);
                for host in hosts {
                    found.push((host, false, source.to_owned(), None));
                }
            }
        }
        for (host, wildcard, source, header) in found {
            self.coverage.declarations += 1;
            let entry = self.declared.entry(host).or_insert_with(|| Declared {
                sources: BTreeSet::new(),
                wildcard,
                count: 0,
                first: place(header),
            });
            entry.sources.insert(source);
            entry.wildcard |= wildcard;
            entry.count += 1;
        }
    }

    /// Host and header-name signals matched against what the traffic declared
    /// rather than sent: technology, signal, host and where it was declared.
    fn declared_matches(&self) -> Vec<(usize, usize, String, Place)> {
        let rules = &*RULES;
        let mut out = Vec::new();
        for (index, signal) in rules.signals.iter().enumerate() {
            match signal.on {
                On::Host => {
                    let Some(pattern) = &signal.pattern else {
                        continue;
                    };
                    for (host, declared) in &self.declared {
                        if pattern.is_match(host) {
                            out.push((
                                signal.technology,
                                index,
                                host.clone(),
                                declared.first.clone(),
                            ));
                        }
                    }
                }
                On::RequestHeader | On::ResponseHeader if signal.pattern.is_none() => {
                    let names = if signal.on == On::RequestHeader {
                        &self.declared_request_headers
                    } else {
                        &self.declared_response_headers
                    };
                    if let Some((host, place)) =
                        signal.name.as_ref().and_then(|name| names.get(name))
                    {
                        out.push((signal.technology, index, host.clone(), place.clone()));
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// The finished document.
    pub(crate) fn document(&self, index: Value) -> Value {
        let rules = &*RULES;
        // Sites of the top-level documents name the first party.
        let mut sites: BTreeSet<String> = self
            .hosts
            .iter()
            .filter(|(_, host)| host.document)
            .filter_map(|(name, _)| request_index::site(name))
            .collect();
        if sites.is_empty() {
            // Without a top-level document, the busiest host stands in, labeled.
            if let Some((name, _)) = self.hosts.iter().max_by_key(|(_, host)| host.entries) {
                sites.extend(request_index::site(name));
            }
        }
        let party = |host: &str| {
            if request_index::site(host).is_some_and(|site| sites.contains(&site)) {
                "first_party"
            } else {
                "third_party"
            }
        };

        // Direct confidence: each distinct signal counts once, capped at 100.
        let mut direct: BTreeMap<usize, u32> = BTreeMap::new();
        for (&technology, finding) in &self.findings {
            let total: u32 = finding
                .signals
                .keys()
                .map(|&signal| u32::from(rules.signals[signal].weight))
                .sum();
            direct.insert(technology, total.min(100));
        }
        // An implied technology takes the confidence of what implies it.
        let mut implied: BTreeMap<usize, (u32, BTreeSet<usize>)> = BTreeMap::new();
        let mut stack: Vec<(usize, u32, usize)> = direct
            .iter()
            .flat_map(|(&from, &confidence)| {
                rules.technologies[from]
                    .implies
                    .iter()
                    .map(move |&to| (to, confidence, from))
            })
            .collect();
        while let Some((to, confidence, from)) = stack.pop() {
            let entry = implied.entry(to).or_insert((0, BTreeSet::new()));
            let grew = confidence > entry.0;
            let named = entry.1.insert(from);
            entry.0 = entry.0.max(confidence);
            if grew || named {
                for &next in &rules.technologies[to].implies {
                    stack.push((next, confidence, to));
                }
            }
        }
        // Declared evidence: a host or header name the traffic named without
        // the page contacting or sending it. It is listed beside direct
        // evidence and, alone, supports at most DECLARED_CONFIDENCE.
        let mut declared: BTreeMap<usize, BTreeMap<usize, BTreeMap<String, Place>>> =
            BTreeMap::new();
        for (technology, signal, host, place) in self.declared_matches() {
            declared
                .entry(technology)
                .or_default()
                .entry(signal)
                .or_default()
                .entry(host)
                .or_insert(place);
        }
        let mut technologies = Vec::new();
        let ids: BTreeSet<usize> = direct
            .keys()
            .chain(implied.keys())
            .chain(declared.keys())
            .copied()
            .collect();
        for id in ids {
            let technology = &rules.technologies[id];
            let finding = self.findings.get(&id);
            let own = direct.get(&id).copied();
            let by = implied.get(&id);
            let declarations = declared.get(&id);
            let declared_confidence = declarations.map(|signals| {
                let total: u32 = signals
                    .keys()
                    .map(|&signal| u32::from(rules.signals[signal].weight))
                    .sum();
                total.min(DECLARED_CONFIDENCE)
            });
            let confidence = own
                .unwrap_or(0)
                .max(by.map_or(0, |by| by.0))
                .max(declared_confidence.unwrap_or(0));
            let mut hosts: BTreeSet<String> = BTreeSet::new();
            let mut tiers = BTreeSet::new();
            let indices: BTreeSet<usize> = finding
                .map(|finding| finding.signals.keys().copied().collect::<Vec<_>>())
                .unwrap_or_default()
                .into_iter()
                .chain(
                    declarations
                        .into_iter()
                        .flat_map(|signals| signals.keys().copied()),
                )
                .collect();
            let signals: Vec<Value> = indices
                .iter()
                .map(|&index| {
                    let signal = &rules.signals[index];
                    tiers.insert(signal.tier.name());
                    let mut list: Vec<Value> = Vec::new();
                    if let Some(places) = finding.and_then(|finding| finding.signals.get(&index)) {
                        hosts.extend(places.keys().cloned());
                        list.extend(places.iter().map(|(host, hits)| {
                            let mut out = hits.json();
                            out["host"] = json!(host);
                            out["party"] = json!(party(host));
                            out["declared"] = json!(false);
                            out
                        }));
                    }
                    if let Some(places) = declarations.and_then(|signals| signals.get(&index)) {
                        list.extend(places.iter().map(|(host, place)| {
                            json!({"host": host, "party": party(host), "declared": true, "count": 1, "first": place.json()})
                        }));
                    }
                    json!({
                        "signal_id": signal.id, "on": signal.on.name(),
                        "tier": signal.tier.name(), "weight": signal.weight,
                        "content": signal.on.content(),
                        "description": signal.description,
                        "hosts": list,
                    })
                })
                .collect();
            // A declared-only technology's party comes from its declared hosts.
            if own.is_none()
                && let Some(signals) = declarations
            {
                hosts.extend(signals.values().flat_map(|places| places.keys().cloned()));
            }
            let parties: BTreeSet<&str> = hosts.iter().map(|host| party(host)).collect();
            let details: serde_json::Map<String, Value> = finding
                .map(|finding| {
                    finding
                        .captures
                        .iter()
                        .map(|(name, values)| {
                            let mut values: Vec<(&String, &u64)> = values.iter().collect();
                            values.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                            (
                                name.clone(),
                                json!(
                                    values
                                        .iter()
                                        .map(
                                            |(value, count)| json!({"value": value, "count": count})
                                        )
                                        .collect::<Vec<_>>()
                                ),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            technologies.push(json!({
                "id": technology.id, "name": technology.name, "category": technology.category,
                "category_label": rules.categories.iter().find(|(category, _)| *category == technology.category).map(|(_, label)| label),
                "confidence": confidence,
                "basis": if own.is_some() { "direct" } else if by.is_some() { "implied" } else { "declared" },
                "strongest_tier": if tiers.contains("vendor") { Some("vendor") } else if tiers.is_empty() { None } else { Some("convention") },
                "implied_by": by.map(|by| by.1.iter().map(|&from| rules.technologies[from].id.clone()).collect::<Vec<_>>()).unwrap_or_default(),
                "party": match (parties.contains("first_party"), parties.contains("third_party")) {
                    (true, true) => "mixed",
                    (true, false) => "first_party",
                    (false, true) => "third_party",
                    (false, false) => "implied",
                },
                "hosts": hosts,
                "details": details,
                "signals": signals,
                "references": technology.references,
            }));
        }
        // Scope: whose stack a technology belongs to. Evidence on a first-party
        // host makes it the site's; a service seen only on its vendor's hosts
        // is a service the site uses; infrastructure seen only there is the
        // vendor's own. An implied technology takes the widest scope of what
        // implies it, settled over the implication chains.
        for technology in &mut technologies {
            let scope = match technology["party"].as_str() {
                Some("first_party" | "mixed") => "site",
                Some("third_party")
                    if !infrastructure(technology["category"].as_str().unwrap_or("")) =>
                {
                    "service"
                }
                Some("third_party") => "vendor",
                _ => "",
            };
            technology["scope"] = json!(scope);
        }
        loop {
            let scopes: HashMap<String, String> = technologies
                .iter()
                .map(|t| {
                    (
                        t["id"].as_str().unwrap_or("").to_owned(),
                        t["scope"].as_str().unwrap_or("").to_owned(),
                    )
                })
                .collect();
            let mut changed = false;
            for technology in &mut technologies {
                if technology["basis"] != "implied" {
                    continue;
                }
                let best = technology["implied_by"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|id| scopes.get(id.as_str().unwrap_or("")))
                    .map(String::as_str)
                    .min_by_key(|scope| scope_rank(scope))
                    .unwrap_or("");
                if !best.is_empty()
                    && scope_rank(best) < scope_rank(technology["scope"].as_str().unwrap_or(""))
                {
                    technology["scope"] = json!(best);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for technology in &mut technologies {
            if technology["scope"] == "" {
                technology["scope"] = json!("vendor");
            }
        }
        technologies.sort_by(|a, b| {
            let rank = |value: &Value| {
                rules
                    .categories
                    .iter()
                    .position(|(id, _)| value["category"] == id.as_str())
                    .unwrap_or(usize::MAX)
            };
            scope_rank(a["scope"].as_str().unwrap_or(""))
                .cmp(&scope_rank(b["scope"].as_str().unwrap_or("")))
                .then(rank(a).cmp(&rank(b)))
                .then(b["confidence"].as_u64().cmp(&a["confidence"].as_u64()))
                .then(a["id"].as_str().cmp(&b["id"].as_str()))
        });

        let by_host: BTreeMap<&str, Vec<&str>> =
            technologies
                .iter()
                .fold(BTreeMap::new(), |mut out, technology| {
                    for host in technology["hosts"].as_array().into_iter().flatten() {
                        if let (Some(host), Some(id)) = (host.as_str(), technology["id"].as_str()) {
                            out.entry(host).or_insert_with(Vec::new).push(id);
                        }
                    }
                    out
                });
        let mut hosts: Vec<Value> = self
            .hosts
            .iter()
            .map(|(name, host)| {
                let addresses: Vec<Value> = host
                    .addresses
                    .iter()
                    .map(|(address, count)| {
                        let providers: Vec<&str> = address
                            .parse::<IpAddr>()
                            .ok()
                            .and_then(|address| self.providers.get(&address))
                            .into_iter()
                            .flatten()
                            .map(|&provider| rules.providers[provider].id.as_str())
                            .collect();
                        json!({"address": address, "count": count, "ranges": providers})
                    })
                    .collect();
                let mut routes: Vec<Value> = host
                    .routes
                    .iter()
                    .map(|((method, template), route)| {
                        let style = route
                            .styles
                            .iter()
                            .max_by_key(|(_, count)| **count)
                            .map_or("other", |(style, _)| *style);
                        json!({
                            "method": method, "template": template, "count": route.count,
                            "api_style": style, "statuses": route.statuses,
                            "mime_types": route.mime_types, "query_keys": route.query_keys,
                            "matched_paths": route.matched,
                            "first": route.first.as_ref().map(Place::json),
                        })
                    })
                    .collect();
                routes.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()).then(a["template"].as_str().cmp(&b["template"].as_str())));
                let mut prefixes: Vec<(&String, &u64)> = host.static_prefixes.iter().collect();
                prefixes.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                let styles: BTreeMap<&str, u64> = routes.iter().fold(BTreeMap::new(), |mut out, route| {
                    *out.entry(route["api_style"].as_str().unwrap_or("other")).or_default() += route["count"].as_u64().unwrap_or(0);
                    out
                });
                json!({
                    "host": name, "site": request_index::site(name), "party": party(name),
                    "document": host.document,
                    "rows": host.rows.len(), "entries": host.entries,
                    "role": role(host, &styles, party(name)),
                    "methods": host.methods, "statuses": host.statuses, "types": host.types,
                    "mime_types": host.mime_types, "protocols": host.protocols,
                    "addresses": addresses,
                    "entries_with_response_headers": host.with_response_headers,
                    "technologies": by_host.get(name.as_str()).cloned().unwrap_or_default(),
                    "api_styles": styles,
                    "cors": {"exposed": host.cors_exposed, "allowed": host.cors_allowed, "requested": host.cors_requested},
                    "routes": routes,
                    "static": {"count": host.static_count, "prefixes": prefixes.iter().map(|(prefix, count)| json!({"prefix": prefix, "count": count})).collect::<Vec<_>>()},
                })
            })
            .collect();
        hosts.sort_by(|a, b| {
            let first = |value: &Value| value["party"] != "first_party";
            first(a)
                .cmp(&first(b))
                .then(b["entries"].as_u64().cmp(&a["entries"].as_u64()))
                .then(a["host"].as_str().cmp(&b["host"].as_str()))
        });
        // Hosts named in a header are all listed; a URL in a body only when a
        // signal matched it or it is on the first party's site, since bundles
        // name many hosts no backend uses.
        let matched: BTreeSet<&str> = technologies
            .iter()
            .flat_map(|technology| technology["signals"].as_array().into_iter().flatten())
            .flat_map(|signal| signal["hosts"].as_array().into_iter().flatten())
            .filter(|host| host["declared"] == true)
            .filter_map(|host| host["host"].as_str())
            .collect();
        let declared_hosts: Vec<Value> = self
            .declared
            .iter()
            .filter(|(host, declared)| {
                matched.contains(host.as_str())
                    || party(host) == "first_party"
                    || declared.sources.iter().any(|source| !matches!(source.as_str(), "script" | "page" | "json"))
            })
            .map(|(host, declared)| {
                json!({
                    "host": host, "party": party(host), "wildcard": declared.wildcard,
                    "contacted": self.hosts.contains_key(host),
                    "sources": declared.sources, "count": declared.count,
                    "technologies": technologies.iter()
                        .filter(|technology| technology["signals"].as_array().into_iter().flatten()
                            .flat_map(|signal| signal["hosts"].as_array().into_iter().flatten())
                            .any(|entry| entry["declared"] == true && entry["host"] == host.as_str()))
                        .filter_map(|technology| technology["id"].as_str())
                        .collect::<Vec<_>>(),
                    "first": declared.first.json(),
                })
            })
            .collect();
        let coverage = &self.coverage;
        let complete = index["complete"] == true;
        json!({
            "format": FORMAT,
            "mode": "offline-passive",
            "network_requests": 0,
            "rule_set": {
                "format": RULES_FORMAT, "reviewed": rules.reviewed, "sha256": rules.digest,
                "technologies": rules.technologies.len(), "signals": rules.signals.len(),
                "ranges": {"format": RANGES_FORMAT, "retrieved": rules.ranges_retrieved, "sha256": rules.ranges_digest,
                    "providers": rules.providers.iter().map(|provider| json!({"id": provider.id, "name": provider.name, "prefixes": provider.prefixes.len()})).collect::<Vec<_>>()},
            },
            "first_party": {
                "sites": sites,
                "from_documents": self.hosts.values().any(|host| host.document),
            },
            "technologies": technologies,
            "hosts": hosts,
            "declared_hosts": declared_hosts,
            "coverage": {
                "complete": complete,
                "index": index,
                "rows": coverage.rows, "entries": coverage.entries, "unlinked_entries": coverage.unlinked,
                "entries_with_response_headers": coverage.response_headers,
                "entries_without_response_headers": coverage.no_response_headers,
                "entries_with_urls": coverage.paths_known,
                "credential_values_dropped": coverage.withheld_values,
                "response_bodies_read": coverage.bodies_read,
                "response_bodies_binary": coverage.bodies_binary,
                "response_bodies_not_captured": coverage.bodies_absent,
                "request_bodies_read": coverage.request_bodies_read,
                "captures_refused": coverage.captures_refused,
                "declarations": coverage.declarations,
                "internal_entries": coverage.internal,
                "scripts_read": coverage.scripts_read,
                "scripts_unreadable": coverage.scripts_unreadable,
            },
            "limitations": [
                "Every finding is a guess from what the front end received: a header, cookie name, host, path or body shape can be set by any server, removed by a proxy, or come from a CDN in front of a different origin. Confidence adds the reviewed weights of distinct signals and is not a probability.",
                "Only captured traffic is read. A Metadata-only session has hosts and remote addresses but no paths, headers or bodies, and a response the HTTP cache or a service worker answered may carry no network headers.",
                "Credential header values and cookie values are never read; cookies are matched by name only. A captured token is returned only when it is a short plain token; whole header values are not returned.",
                "Remote address attribution uses the provider ranges retrieved on the date given; ranges change, and an address outside them is not evidence of another provider.",
                "First party means the approximate site (no public suffix list) of the session's top-level documents.",
            ],
        })
    }
}

/// The most confidence declared evidence alone supports: a policy or a URL in
/// a bundle says what the site may use, not what it used.
const DECLARED_CONFIDENCE: u32 = 40;

/// An absolute http(s) or ws(s) URL literal's host, in a body.
static URL_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:https?|wss?)://([A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.[A-Za-z]{2,63})\b"#).unwrap()
});
/// A page's `<meta http-equiv="Content-Security-Policy" content="...">`.
static META_CSP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\s+http-equiv=["']?content-security-policy["']?\s+content="([^"]*)""#)
        .unwrap()
});
/// A route template a server names: a path of plain segments and `[param]`.
static ROUTE_TEMPLATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9_.~@:+()\[\]/-]{0,199}$").unwrap());
static HEADER_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$").unwrap());
static HOST_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$")
        .unwrap()
});

/// The host of a URL or CSP source expression: scheme, port and path dropped,
/// a leading `*.` reported as a wildcard. None for keywords and schemes.
fn source_host(source: &str) -> Option<(String, bool)> {
    let source = source.trim().trim_matches('\'').to_ascii_lowercase();
    let rest = source
        .split_once("://")
        .map_or(source.as_str(), |(_, rest)| rest);
    let rest = rest.split(['/', '?', '#']).next()?;
    let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    let host = match rest.rsplit_once(':') {
        Some((host, port)) if port == "*" || port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => rest,
    };
    let (host, wildcard) = match host.strip_prefix("*.") {
        Some(host) => (host, true),
        None => (host, false),
    };
    HOST_NAME
        .is_match(host)
        .then(|| (host.to_owned(), wildcard))
}

/// (directive, host, wildcard) for every host source of a policy.
fn csp_hosts(policy: &str) -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    for directive in policy.split([';', ',']) {
        let mut tokens = directive.split_ascii_whitespace();
        let Some(name) = tokens.next() else { continue };
        let name = name.to_ascii_lowercase();
        if !HEADER_NAME.is_match(&name) {
            continue;
        }
        for token in tokens {
            if token.starts_with('\'') || token.ends_with(':') {
                continue;
            }
            if let Some((host, wildcard)) = source_host(token) {
                out.push((name.clone(), host, wildcard));
            }
        }
    }
    out
}

/// Hosts of the absolute URLs in a Report-To, Reporting-Endpoints or NEL value.
fn url_hosts(value: &str) -> Vec<String> {
    URL_LITERAL
        .captures_iter(value)
        .filter_map(|found| found.get(1))
        .map(|host| host.as_str().to_ascii_lowercase())
        .collect()
}

/// (rel, host) for each absolute URL a Link header names.
fn link_hosts(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for link in value.split(',') {
        let Some((target, params)) = link
            .trim()
            .strip_prefix('<')
            .and_then(|rest| rest.split_once('>'))
        else {
            continue;
        };
        let rel = params
            .split(';')
            .filter_map(|param| param.trim().strip_prefix("rel="))
            .map(|rel| rel.trim_matches('"').to_ascii_lowercase())
            .find(|rel| HEADER_NAME.is_match(rel))
            .unwrap_or_else(|| "link".into());
        if target.contains("://")
            && let Some((host, _)) = source_host(target)
        {
            out.push((rel, host));
        }
    }
    out
}

/// A host a network request can name: a dotted name, `localhost` or an IP
/// literal, with an optional port. Brave's own pages arrive as bare words.
fn network_host(host: &str) -> bool {
    let name = match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    name == "localhost"
        || name.parse::<IpAddr>().is_ok()
        || name.trim_matches(['[', ']']).parse::<IpAddr>().is_ok()
        || HOST_NAME.is_match(name)
}

/// Lowercase header names of a CORS list.
fn header_names(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| name != "*" && HEADER_NAME.is_match(name))
        .collect()
}

/// Categories that describe how something is served rather than a service a
/// site chooses to call.
fn infrastructure(category: &str) -> bool {
    matches!(
        category,
        "hosting" | "cdn" | "proxy" | "web_server" | "language" | "framework" | "frontend"
    )
}

fn scope_rank(scope: &str) -> u8 {
    match scope {
        "site" => 0,
        "service" => 1,
        "vendor" => 2,
        _ => 3,
    }
}

/// What a host does for the page, from its traffic.
fn role(host: &Host, styles: &BTreeMap<&str, u64>, party: &str) -> &'static str {
    let api: u64 = styles
        .iter()
        .filter(|(style, _)| !matches!(**style, "document" | "other"))
        .map(|(_, count)| count)
        .sum();
    if host.document {
        "document"
    } else if api > 0 && api * 2 >= host.entries {
        if party == "first_party" {
            "api"
        } else {
            "third_party_api"
        }
    } else if host.static_count > 0 && host.static_count * 2 >= host.entries {
        "static"
    } else if party == "first_party" {
        "first_party"
    } else {
        "third_party"
    }
}

/// Each match of `signal` in one entry: the header name it matched as
/// captured, if any, and its capture.
fn matches(signal: &Signal, seen: &Seen) -> Vec<(Option<String>, Option<String>)> {
    let capture = |text: &str| -> Option<Option<String>> {
        match &signal.pattern {
            None => Some(None),
            Some(pattern) => {
                let found = pattern.captures(text)?;
                Some(
                    signal
                        .capture
                        .as_ref()
                        .and_then(|(_, group)| found.get(*group))
                        .map(|m| m.as_str().to_owned()),
                )
            }
        }
    };
    let mut out = Vec::new();
    let mut headers = |list: &[(String, String, &str)], prefix: bool| {
        let name = signal.name.as_deref().unwrap_or("");
        for (lower, value, original) in list {
            let named = if prefix {
                lower.starts_with(name)
            } else {
                lower == name
            };
            if named && let Some(token) = capture(value) {
                out.push((Some((*original).to_owned()), token));
                if !prefix {
                    break;
                }
            }
        }
    };
    match signal.on {
        On::ResponseHeader => headers(&seen.response, false),
        On::ResponseHeaderPrefix => headers(&seen.response, true),
        On::RequestHeader => headers(&seen.request, false),
        On::RequestHeaderPrefix => headers(&seen.request, true),
        On::Cookie => {
            if seen.cookies.iter().any(|name| capture(name).is_some()) {
                out.push((None, None));
            }
        }
        On::Host => out.extend(capture(&seen.host).map(|token| (None, token))),
        On::Path => {
            if !seen.path.is_empty() {
                out.extend(capture(&seen.path).map(|token| (None, token)));
            }
        }
        On::QueryKey => {
            if seen
                .query_keys
                .iter()
                .any(|key| Some(key.as_str()) == signal.name.as_deref())
            {
                out.push((None, None));
            }
        }
        On::Body | On::RequestBody => {
            let text = if signal.on == On::Body {
                seen.body
            } else {
                seen.request_body
            };
            let mime_ok = signal
                .mime
                .as_ref()
                .is_none_or(|mime| mime.is_match(&seen.mime));
            if let Some(text) = text
                && mime_ok
            {
                out.extend(capture(text).map(|token| (None, token)));
            }
        }
        On::RemoteAddress => {
            if signal
                .ranges
                .is_some_and(|provider| seen.providers.contains(&provider))
            {
                out.push((None, None));
            }
        }
        On::Protocol => {
            if !seen.protocol.is_empty() {
                out.extend(capture(&seen.protocol).map(|token| (None, token)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_compile_and_resolve() {
        let rules = &*RULES;
        assert!(rules.technologies.len() > 100);
        assert!(rules.signals.iter().all(|signal| signal.weight > 0));
        for provider in ["cloudflare", "fastly", "cloudfront", "aws", "gcp", "google"] {
            assert!(
                rules.providers.iter().any(|known| known.id == provider),
                "{provider}"
            );
        }
    }

    #[test]
    fn review_mistakes_are_refused() {
        let ranges = RANGES;
        let file = |technologies: Value| {
            json!({"format": RULES_FORMAT, "reviewed": "2026-11-25",
                "categories": [{"id": "hosting", "label": "Hosting"}],
                "technologies": technologies})
            .to_string()
        };
        let signal = |extra: Value| {
            let mut out = json!({"id": "s", "on": "response_header", "name": "server",
                "weight": 50, "tier": "vendor", "description": "d"});
            for (key, value) in extra.as_object().unwrap() {
                out[key] = value.clone();
            }
            out
        };
        let one = |extra: Value| {
            file(
                json!([{"id": "a", "name": "A", "category": "hosting", "signals": [signal(extra)]}]),
            )
        };
        assert!(compile(&one(json!({})), ranges).is_ok());
        for bad in [
            json!({"name": "Server"}),
            json!({"weight": 0}),
            json!({"weight": 101}),
            json!({"pattern": "("}),
            json!({"pattern": "^a$", "capture": {"name": "x", "group": 1}}),
            json!({"on": "cookie", "name": null, "pattern": "^(a)$", "capture": {"name": "x", "group": 1}}),
            json!({"on": "remote_address", "name": null}),
            json!({"on": "remote_address", "name": null, "ranges": "nobody"}),
            json!({"mime": "html"}),
            json!({"surprise": true}),
        ] {
            assert!(compile(&one(bad.clone()), ranges).is_err(), "{bad}");
        }
        let cycle = file(json!([
            {"id": "a", "name": "A", "category": "hosting", "implies": ["b"], "signals": []},
            {"id": "b", "name": "B", "category": "hosting", "implies": ["a"], "signals": []},
        ]));
        assert!(compile(&cycle, ranges).is_err());
        let unknown = file(json!([{"id": "a", "name": "A", "category": "nope", "signals": []}]));
        assert!(compile(&unknown, ranges).is_err());
    }

    #[test]
    fn ranges_match_by_prefix() {
        let rules = &*RULES;
        let of = |text: &str| -> Vec<&str> {
            providers_of(rules, text.parse().unwrap())
                .into_iter()
                .map(|index| rules.providers[index].id.as_str())
                .collect()
        };
        assert_eq!(of("104.16.1.1"), ["cloudflare"]);
        assert_eq!(of("151.101.1.1"), ["fastly"]);
        assert_eq!(of("2606:4700::1"), ["cloudflare"]);
        assert!(of("192.0.2.1").is_empty());
        assert!(parse_prefix("10.0.0.1/8").is_err());
        assert!(parse_prefix("10.0.0.0/33").is_err());
    }

    #[test]
    fn identifiers_collapse_to_their_shape() {
        assert_eq!(template("/api/users/42/orders"), "/api/users/{int}/orders");
        assert_eq!(
            template("/v1/items/3f2b8c1e-7a4d-4c2b-9f1e-2a3b4c5d6e7f"),
            "/v1/items/{uuid}"
        );
        assert_eq!(
            template("/posts/507f1f77bcf86cd799439011"),
            "/posts/{objectid}"
        );
        assert_eq!(template("/x/01ARZ3NDEKTSV4RRFFQ69G5FAV"), "/x/{ulid}");
        assert_eq!(
            template("/customers/cus_NffrFeUfNV2Hib"),
            "/customers/{cus_id}"
        );
        assert_eq!(
            template("/blob/9f86d081884c7d659a2feaa0c55ad015"),
            "/blob/{hex}"
        );
        assert_eq!(template("/day/2026-11-25"), "/day/{date}");
        assert_eq!(template("/api/graphql"), "/api/graphql");
        assert_eq!(template("/"), "/");
        assert_eq!(
            static_prefix("/_next/static/chunks/main-abc.js"),
            "/_next/static"
        );
        assert_eq!(static_prefix("/favicon.ico"), "/");
    }

    fn entry(
        url: &str,
        request: Value,
        response: Value,
        address: Option<&str>,
        body: Option<&str>,
    ) -> Value {
        let mut out = json!({
            "request": {"method": "GET", "url": url, "headers": request},
            "response": {"status": 200, "httpVersion": "h2", "headers": response, "content": {}},
            "_reb": {"request_id": "17", "hop": 0, "outcome": "complete"},
        });
        if let Some(address) = address {
            out["serverIPAddress"] = json!(address);
        }
        if let Some(body) = body {
            out["response"]["content"]["text"] = json!(body);
        }
        out
    }

    #[test]
    fn a_vercel_next_supabase_session_maps_its_stack_without_values() {
        let mut map = Map::default();
        let document =
            json!({"id": "1", "type": "doc", "main_frame": true, "mime_type": "text/html"});
        map.add_row(
            &document,
            &[entry(
                "https://app.example.com/",
                json!([{"name": "Cookie", "value": "sid=COOKIE-SECRET; __client_uat=1"}]),
                json!([
                    {"name": "Server", "value": "Vercel"},
                    {"name": "X-Vercel-Id", "value": "iad1::fra1::abcde-1732560000000-0123456789ab"},
                    {"name": "X-Powered-By", "value": "Next.js"},
                    {"name": "Set-Cookie", "value": "__session=JWT-SECRET; Path=/"},
                    {"name": "X-Session-Token", "value": "HEADER-SECRET"},
                ]),
                Some("76.76.21.21"),
                Some("<html><script>self.__next_f.push([1])</script></html>"),
            )],
        );
        let api = json!({"id": "2", "type": "xhr", "mime_type": "application/json"});
        map.add_row(
            &api,
            &[entry(
                "https://abcdefghijklmnopqrst.supabase.co/rest/v1/todos?select=*&id=eq.4",
                json!([{"name": "X-Client-Info", "value": "supabase-js-web/2.45.4"},
                    {"name": "Authorization", "value": "Bearer AUTH-SECRET"}]),
                json!([{"name": "CF-Ray", "value": "8e1b2c3d4e5f6a7b-SJC"}, {"name": "Server", "value": "cloudflare"}]),
                Some("104.18.38.10"),
                None,
            )],
        );
        let user = json!({"id": "3", "type": "xhr", "mime_type": "application/json"});
        map.add_row(
            &user,
            &[entry(
                "https://app.example.com/api/users/42",
                json!([]),
                json!([]),
                None,
                None,
            )],
        );
        let out = map.document(json!({"complete": true}));
        let text = out.to_string();
        for secret in [
            "COOKIE-SECRET",
            "JWT-SECRET",
            "HEADER-SECRET",
            "AUTH-SECRET",
            "1732560000000",
        ] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
        let find = |id: &str| {
            out["technologies"]
                .as_array()
                .unwrap()
                .iter()
                .find(|technology| technology["id"] == id)
                .cloned()
                .unwrap_or_else(|| panic!("no {id} in {out:#}"))
        };
        let vercel = find("vercel");
        assert_eq!(vercel["confidence"], 100);
        assert_eq!(vercel["party"], "first_party");
        assert_eq!(vercel["details"]["edge_region"][0]["value"], "iad1");
        assert_eq!(vercel["signals"][0]["hosts"][0]["first"]["row_id"], "1");
        let next = find("nextjs");
        assert_eq!(next["basis"], "direct");
        let react = find("react");
        assert_eq!(react["basis"], "implied");
        assert_eq!(react["implied_by"], json!(["nextjs"]));
        let supabase = find("supabase");
        assert_eq!(supabase["party"], "third_party");
        assert_eq!(
            supabase["details"]["project"][0]["value"],
            "abcdefghijklmnopqrst"
        );
        assert_eq!(supabase["details"]["client_version"][0]["value"], "2.45.4");
        assert_eq!(find("postgresql")["basis"], "implied");
        assert_eq!(vercel["scope"], "site");
        assert_eq!(react["scope"], "site");
        assert_eq!(supabase["scope"], "service");
        assert_eq!(find("postgresql")["scope"], "service");
        let cloudflare = find("cloudflare");
        assert_eq!(cloudflare["details"]["pop"][0]["value"], "SJC");
        assert!(
            cloudflare["signals"]
                .as_array()
                .unwrap()
                .iter()
                .any(|signal| signal["on"] == "remote_address")
        );
        // Clerk is matched by its cookie name only.
        assert_eq!(find("clerk")["signals"][0]["on"], "cookie");
        assert_eq!(out["first_party"]["sites"], json!(["example.com"]));
        let hosts = out["hosts"].as_array().unwrap();
        assert_eq!(hosts[0]["host"], "app.example.com");
        assert_eq!(hosts[0]["role"], "document");
        let routes = hosts[0]["routes"].as_array().unwrap();
        assert!(
            routes.iter().any(
                |route| route["template"] == "/api/users/{int}" && route["api_style"] == "json"
            )
        );
        let supabase_host = hosts
            .iter()
            .find(|host| host["host"] == "abcdefghijklmnopqrst.supabase.co")
            .unwrap();
        assert_eq!(
            supabase_host["routes"][0]["query_keys"],
            json!(["id", "select"])
        );
        assert_eq!(
            supabase_host["addresses"][0]["ranges"],
            json!(["cloudflare"])
        );
        assert_eq!(out["coverage"]["credential_values_dropped"], 4);
    }

    #[test]
    fn policies_cors_and_bundles_declare_what_was_not_contacted() {
        let mut map = Map::default();
        let document =
            json!({"id": "1", "type": "doc", "main_frame": true, "mime_type": "text/html"});
        map.add_row(
            &document,
            &[entry(
                "https://www.shop.test/",
                json!([]),
                json!([
                    {"name": "Content-Security-Policy", "value": "default-src 'self'; connect-src 'self' https://*.supabase.co wss://ws-us3.pusher.com https://api.shop.test:8443; script-src 'nonce-abc' js.stripe.com https:"},
                    {"name": "Report-To", "value": "{\"group\":\"cf-nel\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://a.nel.cloudflare.com/report/v4?s=SIGNATURE\"}]}"},
                    {"name": "Link", "value": "<https://o1.ingest.sentry.io>; rel=preconnect, </style.css>; rel=preload"},
                    {"name": "Access-Control-Expose-Headers", "value": "Content-Range, X-Total-Count"},
                    {"name": "Access-Control-Allow-Headers", "value": "authorization, x-client-info, apikey, apollo-require-preflight"},
                    {"name": "X-Matched-Path", "value": "/products/[slug]"},
                    {"name": "ETag", "value": "\"5e1f1c2a-264\""},
                ]),
                None,
                Some("<html><script>fetch('https://api.shop.test/v2/cart');fetch('https://docs.example.org/x')</script></html>"),
            )],
        );
        let out = map.document(json!({"complete": true}));
        let text = out.to_string();
        assert!(!text.contains("SIGNATURE"), "{text}");
        let declared: Vec<&str> = out["declared_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|host| host["host"].as_str().unwrap())
            .collect();
        for host in [
            "supabase.co",
            "ws-us3.pusher.com",
            "api.shop.test",
            "js.stripe.com",
            "a.nel.cloudflare.com",
            "o1.ingest.sentry.io",
        ] {
            assert!(
                declared.contains(&host),
                "{host} not declared: {declared:?}"
            );
        }
        // A third-party URL in a page that no signal knows is not listed.
        assert!(!declared.contains(&"docs.example.org"), "{declared:?}");
        let supabase_host = out["declared_hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|host| host["host"] == "supabase.co")
            .unwrap();
        assert_eq!(supabase_host["wildcard"], true);
        assert_eq!(supabase_host["contacted"], false);
        assert_eq!(supabase_host["sources"], json!(["csp:connect-src"]));
        let find = |id: &str| {
            out["technologies"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["id"] == id)
                .cloned()
                .unwrap_or_else(|| panic!("no {id}: {text}"))
        };
        for id in ["supabase", "pusher", "stripe", "sentry"] {
            let technology = find(id);
            assert_eq!(technology["basis"], "declared", "{technology}");
            assert!(technology["confidence"].as_u64().unwrap() <= u64::from(DECLARED_CONFIDENCE));
            assert_eq!(technology["signals"][0]["hosts"][0]["declared"], true);
        }
        // CORS names alone point at the clients that send them.
        assert_eq!(find("apollo")["basis"], "declared");
        assert_eq!(
            find("apollo")["signals"][0]["hosts"][0]["first"]["header"],
            "Access-Control-Allow-Headers"
        );
        let host = &out["hosts"][0];
        assert_eq!(
            host["cors"]["exposed"],
            json!(["content-range", "x-total-count"])
        );
        assert_eq!(
            host["routes"][0]["matched_paths"],
            json!(["/products/[slug]"])
        );
        // Cloudflare is declared by its NEL endpoint; nginx by its ETag shape.
        assert_eq!(find("cloudflare")["basis"], "declared");
        assert_eq!(find("nginx")["basis"], "direct");
        assert_eq!(find("vercel")["basis"], "direct");
        assert_eq!(find("vercel")["confidence"], 60);
    }

    #[test]
    fn csp_sources_parse_to_hosts() {
        let hosts = csp_hosts(
            "default-src 'self' data: blob:; img-src * https://cdn.a.test:443/x *.b.test; report-uri https://r.c.test/csp",
        );
        assert_eq!(
            hosts,
            vec![
                ("img-src".to_owned(), "cdn.a.test".to_owned(), false),
                ("img-src".to_owned(), "b.test".to_owned(), true),
                ("report-uri".to_owned(), "r.c.test".to_owned(), false),
            ]
        );
        assert_eq!(header_names("X-A, *, bad name, x-b"), ["x-a", "x-b"]);
        assert_eq!(
            link_hosts("<https://fonts.gstatic.test>; rel=\"preconnect\"; crossorigin"),
            [("preconnect".to_owned(), "fonts.gstatic.test".to_owned())]
        );
    }

    #[test]
    fn script_artifacts_are_read_for_bundle_signals() {
        let mut map = Map::default();
        let row = json!({"id": "1", "type": "doc", "main_frame": true});
        map.add_row(
            &row,
            &[entry(
                "https://app.example.com/",
                json!([]),
                json!([]),
                None,
                None,
            )],
        );
        let artifact = json!({"artifact_id": "19", "sha256": "ab".repeat(32), "url": "https://app.example.com/_next/static/main.js"});
        map.add_script(
            &artifact,
            r#"window.next={version:"15.1.2",appDir:!0};const sb="https://abcdefghijklmnopqrst.supabase.co";const dsn="https://0123456789abcdef0123456789abcdef@o4505.ingest.us.sentry.io/4505";"#,
        );
        let out = map.document(json!({"complete": true}));
        let find = |id: &str| {
            out["technologies"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["id"] == id)
                .cloned()
                .unwrap()
        };
        let next = find("nextjs");
        assert_eq!(next["details"]["version"][0]["value"], "15.1.2");
        assert_eq!(
            next["signals"][0]["hosts"][0]["first"],
            json!({"artifact_id": "19", "sha256": "ab".repeat(32)})
        );
        assert_eq!(
            find("supabase")["details"]["project"][0]["value"],
            "abcdefghijklmnopqrst"
        );
        assert_eq!(find("sentry")["basis"], "direct");
        assert_eq!(out["coverage"]["scripts_read"], 1);
        assert!(
            !out.to_string().contains("0123456789abcdef0123456789abcdef"),
            "the DSN key is not returned"
        );
    }

    #[test]
    fn browser_pages_are_not_hosts() {
        let mut map = Map::default();
        let newtab = json!({"id": "1", "type": "doc", "main_frame": true, "host": "newtab"});
        map.add_row(
            &newtab,
            &[entry("newtab/", json!([]), json!([]), None, None)],
        );
        let internal =
            json!({"id": "2", "type": "other", "browser_internal": true, "host": "resources"});
        map.add_row(
            &internal,
            &[entry(
                "chrome://resources/x.js",
                json!([]),
                json!([]),
                None,
                None,
            )],
        );
        let site = json!({"id": "3", "type": "doc", "main_frame": true});
        map.add_row(
            &site,
            &[entry(
                "http://127.0.0.1:8080/",
                json!([]),
                json!([]),
                None,
                None,
            )],
        );
        let out = map.document(json!({"complete": true}));
        let hosts: Vec<&str> = out["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|host| host["host"].as_str().unwrap())
            .collect();
        assert_eq!(hosts, ["127.0.0.1:8080"]);
        assert_eq!(out["coverage"]["internal_entries"], 2);
        assert!(
            network_host("localhost:3000")
                && network_host("api.example.test")
                && network_host("[::1]:8443")
        );
        assert!(!network_host("newtab") && !network_host("theme"));
    }

    #[test]
    fn a_long_capture_is_refused_not_returned() {
        let mut map = Map::default();
        let row = json!({"id": "1", "type": "doc", "main_frame": true});
        let long = format!("{}-1", "a".repeat(60));
        map.add_row(
            &row,
            &[entry(
                "https://x.test/",
                json!([]),
                json!([{"name": "server", "value": format!("deno/{long}")}]),
                None,
                None,
            )],
        );
        let out = map.document(json!({"complete": true}));
        assert!(!out.to_string().contains(&long));
        assert_eq!(out["coverage"]["captures_refused"], 1);
    }
}
