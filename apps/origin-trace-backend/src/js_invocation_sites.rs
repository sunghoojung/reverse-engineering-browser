//! Native JavaScript invocation sites: the site key, the app's saved set, and
//! resolving a name or a position in a retained artifact to exactly one site.
//! The wire and file contract is protocol/native-js-invocation-v1.md; why the
//! app saves sites for its next capture is in docs/product/native-js-invocation-v1.md.
//!
//! A site is computed exactly as tools/native-js-invocation-site.py computes
//! it. Both read tools/fixtures/native-js-invocation/site-cases.json, so the
//! two computations cannot drift.
use crate::{
    durable,
    error::{Code, Error, Result},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

pub const SITE_LIMIT: usize = 8;
pub const FILE_LIMIT: usize = 4096;
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const LABELS_LIMIT: usize = 128 * 1024;
const LABEL_CHARS: usize = 128;
const URL_BYTES: usize = 8192;
const CONTEXT_CHARS: usize = 60;
const CANDIDATE_LIMIT: usize = 32;
const NEXT_CAPTURE: &str = "Tracking starts with the next capture Origin Trace starts, not the open page: a function compiled before its site is armed cannot gain tracking.";

/// One `native-js-invocation-sites-v1` entry with shape `function-entry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    pub anchor_offset: u32,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub byte_offset: u32,
    pub source_length: u32,
    pub source_sha256: String,
}

impl Site {
    /// Compact canonical JSON with sorted keys, as the browser requires.
    /// Every string is ASCII digits or lowercase hex, so none needs escaping.
    fn canonical(&self) -> String {
        format!(
            r#"{{"anchor_offset":{},"artifact_id":"{}","artifact_sha256":"{}","byte_offset":{},"shape":"function-entry","source_length":{},"source_sha256":"{}"}}"#,
            self.anchor_offset,
            self.artifact_id,
            self.artifact_sha256,
            self.byte_offset,
            self.source_length,
            self.source_sha256
        )
    }
    pub fn value(&self) -> Value {
        serde_json::from_str(&self.canonical()).expect("canonical site JSON")
    }
    fn same_function(&self, other: &Site) -> bool {
        self.source_sha256 == other.source_sha256 && self.anchor_offset == other.anchor_offset
    }
}

/// Why a byte offset names no site. `kind` matches the shared case fixture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteError {
    ArtifactId,
    Utf8,
    Outside,
    Boundary,
    NotParen,
    Count,
    Duplicate,
    FileSize,
}

impl SiteError {
    #[cfg(test)]
    pub fn kind(self) -> &'static str {
        match self {
            Self::ArtifactId => "artifact_id",
            Self::Utf8 => "utf8",
            Self::Outside => "outside",
            Self::Boundary => "boundary",
            Self::NotParen => "not_paren",
            Self::Count => "count",
            Self::Duplicate => "duplicate",
            Self::FileSize => "file_size",
        }
    }
}

/// The browser reads `artifact_id` as an ASCII unsigned 64-bit decimal.
pub fn canonical_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 20
        && id.bytes().all(|byte| byte.is_ascii_digit())
        && (id == "0" || !id.starts_with('0'))
        && id.parse::<u64>().is_ok()
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// SHA-256 of the text as UTF-16LE code units and the number of units.
fn utf16_digest(text: &str) -> (String, usize) {
    let mut hasher = Sha256::new();
    let mut buffer = Vec::with_capacity(64 * 1024);
    let mut units = 0;
    for unit in text.encode_utf16() {
        buffer.extend_from_slice(&unit.to_le_bytes());
        units += 1;
        if buffer.len() >= 64 * 1024 {
            hasher.update(&buffer);
            buffer.clear();
        }
    }
    hasher.update(&buffer);
    (hex::encode(hasher.finalize()), units)
}

const BOM: &[u8] = b"\xef\xbb\xbf";

/// The script text V8 compiles: strict UTF-8 with one leading BOM removed.
pub fn script_text(raw: &[u8]) -> Option<(&str, usize)> {
    let text = std::str::from_utf8(raw).ok()?;
    let bom = if raw.starts_with(BOM) { BOM.len() } else { 0 };
    Some((&text[bom..], bom))
}

/// The site whose anchor is the `(` at `byte_offset` of the artifact bytes.
pub fn site(
    raw: &[u8],
    artifact_id: &str,
    byte_offset: usize,
) -> std::result::Result<Site, SiteError> {
    if !canonical_id(artifact_id) {
        return Err(SiteError::ArtifactId);
    }
    let (text, bom) = script_text(raw).ok_or(SiteError::Utf8)?;
    if !(bom <= byte_offset && byte_offset < raw.len()) {
        return Err(SiteError::Outside);
    }
    let prefix = std::str::from_utf8(&raw[bom..byte_offset]).map_err(|_| SiteError::Boundary)?;
    if !text[prefix.len()..].starts_with('(') {
        return Err(SiteError::NotParen);
    }
    let anchor = prefix.encode_utf16().count();
    let (source_sha256, source_length) = utf16_digest(text);
    let fits = |value: usize| u32::try_from(value).map_err(|_| SiteError::Outside);
    Ok(Site {
        anchor_offset: fits(anchor)?,
        artifact_id: artifact_id.to_owned(),
        artifact_sha256: hex::encode(Sha256::digest(raw)),
        byte_offset: fits(byte_offset)?,
        source_length: fits(source_length)?,
        source_sha256,
    })
}

/// The exact `native-js-invocation-sites-v1` file for 1 to 8 distinct sites.
pub fn sites_file(sites: &[Site]) -> std::result::Result<String, SiteError> {
    if !(1..=SITE_LIMIT).contains(&sites.len()) {
        return Err(SiteError::Count);
    }
    for (index, site) in sites.iter().enumerate() {
        if sites[..index].iter().any(|prior| prior.same_function(site)) {
            return Err(SiteError::Duplicate);
        }
    }
    let entries = sites.iter().map(Site::canonical).collect::<Vec<_>>();
    let text = format!(r#"{{"sites":[{}],"version":1}}"#, entries.join(","));
    if text.len() > FILE_LIMIT {
        return Err(SiteError::FileSize);
    }
    Ok(text)
}

fn keys(object: &Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

/// Accepts exactly what the browser accepts: canonical text, 1 to 8 distinct
/// valid `function-entry` sites.
pub fn parse_sites_file(text: &str) -> Option<Vec<Site>> {
    if text.is_empty() || text.len() > FILE_LIMIT {
        return None;
    }
    let value: Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    if !keys(object, &["sites", "version"]) || object["version"] != 1 {
        return None;
    }
    let u32_field = |entry: &Map<String, Value>, key: &str| {
        entry[key].as_u64().and_then(|n| u32::try_from(n).ok())
    };
    let mut sites = Vec::new();
    for entry in object["sites"].as_array()? {
        let entry = entry.as_object()?;
        let fields = [
            "anchor_offset",
            "artifact_id",
            "artifact_sha256",
            "byte_offset",
            "shape",
            "source_length",
            "source_sha256",
        ];
        if !keys(entry, &fields) || entry["shape"] != "function-entry" {
            return None;
        }
        let site = Site {
            anchor_offset: u32_field(entry, "anchor_offset")?,
            artifact_id: entry["artifact_id"]
                .as_str()
                .filter(|id| canonical_id(id))?
                .to_owned(),
            artifact_sha256: entry["artifact_sha256"]
                .as_str()
                .filter(|v| hex64(v))?
                .to_owned(),
            byte_offset: u32_field(entry, "byte_offset")?,
            source_length: u32_field(entry, "source_length")?,
            source_sha256: entry["source_sha256"]
                .as_str()
                .filter(|v| hex64(v))?
                .to_owned(),
        };
        if site.source_length == 0 || site.anchor_offset >= site.source_length {
            return None;
        }
        sites.push(site);
    }
    (sites_file(&sites).ok()? == text).then_some(sites)
}

/// A saved site and what the researcher needs to recognize it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub site: Site,
    pub label: String,
    pub source_url: Option<String>,
    pub session_id: Option<String>,
}

impl Saved {
    fn label_entry(&self) -> Value {
        json!({
            "anchor_offset": self.site.anchor_offset,
            "label": self.label,
            "session_id": self.session_id,
            "source_sha256": self.site.source_sha256,
            "source_url": self.source_url,
        })
    }
    pub fn value(&self) -> Value {
        json!({
            "site": self.site.value(),
            "label": self.label,
            "source_url": self.source_url,
            "session_id": self.session_id,
        })
    }
}

/// A researcher label: 1 to 128 characters, no control characters.
pub fn label(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > LABEL_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(Error::bad(
            "A site label must be 1 to 128 characters without control characters",
        ));
    }
    Ok(value.to_owned())
}

fn derived_label(value: &str) -> String {
    let value = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();
    let value = value.trim();
    if value.chars().count() <= LABEL_CHARS {
        return value.to_owned();
    }
    let mut short = value.chars().take(LABEL_CHARS - 1).collect::<String>();
    short.push('…');
    short
}

/// The app's saved site set: `native-js-invocation-sites-v1` exactly, which
/// the next app-started capture arms, plus a label sidecar the browser never
/// reads. The site file is the authority; a sidecar entry without a site is
/// ignored and a site without one is shown unlabeled.
pub struct Store {
    pub path: PathBuf,
    labels: PathBuf,
    lock: Mutex<()>,
}

pub fn labels_path(path: &Path) -> PathBuf {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "js-invocation-sites-v1".into());
    path.with_file_name(format!("{stem}.labels.json"))
}

impl Store {
    pub fn new(path: PathBuf) -> Self {
        Self {
            labels: labels_path(&path),
            path,
            lock: Mutex::new(()),
        }
    }

    fn read(&self) -> Result<Vec<Saved>> {
        let Some(bytes) = durable::read_private(&self.path, FILE_LIMIT)? else {
            return Ok(Vec::new());
        };
        let sites = std::str::from_utf8(&bytes)
            .ok()
            .and_then(parse_sites_file)
            .ok_or_else(|| {
                Error::new(
                    500,
                    "The saved invocation site file is not a valid native-js-invocation-sites-v1 file. Clear the saved sites to start again.",
                )
            })?;
        let labels = durable::read_private(&self.labels, LABELS_LIMIT)
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|value| value["version"] == 1)
            .and_then(|value| value["sites"].as_array().cloned())
            .unwrap_or_default();
        Ok(sites
            .into_iter()
            .map(|site| {
                let entry = labels.iter().find(|entry| {
                    entry["source_sha256"] == site.source_sha256.as_str()
                        && entry["anchor_offset"] == site.anchor_offset
                });
                let text = |key: &str, limit: usize| {
                    entry
                        .and_then(|entry| entry[key].as_str())
                        .filter(|value| !value.is_empty() && value.len() <= limit)
                        .map(str::to_owned)
                };
                Saved {
                    label: text("label", LABEL_CHARS * 4)
                        .and_then(|value| label(&value).ok())
                        .unwrap_or_else(|| "Unlabeled function".into()),
                    source_url: text("source_url", URL_BYTES),
                    session_id: text("session_id", 20).filter(|id| canonical_id(id)),
                    site,
                }
            })
            .collect())
    }

    /// Labels first, then the site file, each replaced atomically with
    /// user-only permissions, so the site file never names a site whose label
    /// was lost. An empty set has no site file: the format needs 1 to 8 sites.
    fn write(&self, saved: &[Saved]) -> Result<()> {
        if saved.is_empty() {
            for path in [&self.path, &self.labels] {
                match std::fs::remove_file(path) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(error.into());
                    }
                    _ => {}
                }
            }
            return Ok(());
        }
        let file = sites_file(&saved.iter().map(|s| s.site.clone()).collect::<Vec<_>>())
            .map_err(|_| Error::new(500, "The saved site set could not be written"))?;
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty())
            && !parent.exists()
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        let labels = json!({
            "sites": saved.iter().map(Saved::label_entry).collect::<Vec<_>>(),
            "version": 1,
        });
        durable::write_private(&self.labels, &serde_json::to_vec(&labels)?)?;
        durable::write_private(&self.path, file.as_bytes())
    }

    pub fn load(&self) -> Result<Vec<Saved>> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.read()
    }

    pub fn add(&self, saved: Saved) -> Result<Vec<Saved>> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut current = self.read()?;
        if current
            .iter()
            .any(|prior| prior.site.same_function(&saved.site))
        {
            return Err(Error::conflict(
                "This function is already saved: the same source digest and anchor offset name it.",
            ));
        }
        if current.len() >= SITE_LIMIT {
            return Err(Error::conflict(
                "The saved set already tracks 8 functions, the most one capture can arm. Remove one first.",
            )
            .with_code(Code::ResourceLimit));
        }
        current.push(saved);
        self.write(&current)?;
        Ok(current)
    }

    pub fn remove(&self, source_sha256: &str, anchor_offset: u32) -> Result<Vec<Saved>> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut current = self.read()?;
        let before = current.len();
        current.retain(|saved| {
            !(saved.site.source_sha256 == source_sha256
                && saved.site.anchor_offset == anchor_offset)
        });
        if current.len() == before {
            return Err(Error::new(
                404,
                "No saved site has that source digest and anchor offset",
            ));
        }
        self.write(&current)?;
        Ok(current)
    }

    pub fn clear(&self) -> Result<usize> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        // An unreadable set can still be cleared; that is how it is repaired.
        let count = self.read().map(|current| current.len()).unwrap_or(0);
        self.write(&[])?;
        Ok(count)
    }
}

/// What this session's launcher armed, read once when the backend starts.
pub struct Session {
    pub state: &'static str,
    pub sites: Vec<Saved>,
    pub digests: bool,
}

impl Session {
    pub fn read(path: Option<&Path>, state: Option<&str>, digests: bool, store: &Store) -> Self {
        let Some(path) = path else {
            return Self {
                state: "not_armed",
                sites: Vec::new(),
                digests: false,
            };
        };
        let sites = durable::read_private(path, FILE_LIMIT)
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| parse_sites_file(&text));
        let Some(sites) = sites else {
            return Self {
                state: "unreadable",
                sites: Vec::new(),
                digests: false,
            };
        };
        let saved = store.load().unwrap_or_default();
        let browser_unsupported = state == Some("browser_unsupported");
        Self {
            state: if browser_unsupported {
                "browser_unsupported"
            } else {
                "armed"
            },
            sites: sites
                .into_iter()
                .map(|site| {
                    saved
                        .iter()
                        .find(|prior| prior.site.same_function(&site))
                        .cloned()
                        .unwrap_or(Saved {
                            site,
                            label: "Unlabeled function".into(),
                            source_url: None,
                            session_id: None,
                        })
                })
                .collect(),
            digests: digests && !browser_unsupported,
        }
    }

    pub fn value(&self) -> Value {
        json!({
            "state": self.state,
            "count": self.sites.len(),
            "digests": self.digests,
            "sites": self.sites.iter().map(|saved| json!({
                "source_sha256": saved.site.source_sha256,
                "anchor_offset": saved.site.anchor_offset,
                "label": saved.label,
                "source_url": saved.source_url,
            })).collect::<Vec<_>>(),
        })
    }
}

/// Whether this session retained the saved script version. Artifacts are
/// compared by their own SHA-256 first; a same-URL artifact with other bytes
/// is compared by its script-text digest, which `text_digest` computes.
pub fn retained(
    saved: &Saved,
    artifacts: &[Value],
    mut text_digest: impl FnMut(&Value) -> Option<String>,
) -> Value {
    let javascript = artifacts.iter().filter(|a| a["kind"] == "javascript");
    let mut matching = None;
    let mut other = None;
    for artifact in javascript.rev() {
        let same_bytes = artifact["sha256"] == saved.site.artifact_sha256.as_str();
        let same_url = saved
            .source_url
            .as_deref()
            .is_some_and(|url| artifact["url"] == url);
        if !same_bytes && !same_url {
            continue;
        }
        let id = artifact["artifact_id"].clone();
        if same_bytes || text_digest(artifact).as_deref() == Some(&saved.site.source_sha256) {
            matching.get_or_insert(id);
        } else {
            other.get_or_insert(id);
        }
        if matching.is_some() && other.is_some() {
            break;
        }
    }
    let state = match (&matching, &other) {
        (Some(_), _) => "matches",
        (None, Some(_)) => "other_version",
        (None, None) => "not_retained",
    };
    json!({"state": state, "matching_artifact_id": matching, "other_version_artifact_id": other})
}

/// The script-text digest of a retained artifact, for `retained`.
pub fn text_digest(raw: &[u8]) -> Option<String> {
    script_text(raw).map(|(text, _)| utf16_digest(text).0)
}

pub fn set_document(saved: &[Saved], retained: Vec<Value>, session: &Session) -> Value {
    json!({
        "format": "reb-js-invocation-site-set-v1",
        "limit": SITE_LIMIT,
        "count": saved.len(),
        "sites": saved.iter().zip(retained).map(|(saved, retained)| {
            let mut value = saved.value();
            value["retained"] = retained;
            value
        }).collect::<Vec<_>>(),
        "next_capture": NEXT_CAPTURE,
        "session": session.value(),
    })
}

/// A request to name one function in one retained artifact.
#[derive(Clone, Debug)]
pub enum Target {
    Name(String),
    /// A UTF-8 byte offset in the artifact bytes, BOM included.
    Offset(usize),
}

impl Target {
    /// Reads `name` or `byte_offset`, exactly one of them.
    pub fn from_fields(name: Option<&Value>, offset: Option<&Value>) -> Result<Self> {
        match (name, offset) {
            (Some(name), None) => {
                let name = name.as_str().unwrap_or_default();
                let valid = !name.is_empty()
                    && name.len() <= 256
                    && name.split('.').count() <= 8
                    && name.split('.').all(identifier);
                if !valid {
                    return Err(Error::bad(
                        "name must be 1 to 8 dot-separated JavaScript identifiers, such as window.hsw",
                    ));
                }
                Ok(Self::Name(name.to_owned()))
            }
            (None, Some(offset)) => offset
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n < MAX_SOURCE_BYTES)
                .map(Self::Offset)
                .ok_or_else(|| {
                    Error::bad("byte_offset must be a UTF-8 byte offset in the artifact")
                }),
            _ => Err(Error::bad(
                "Name the function by exactly one of name and byte_offset",
            )),
        }
    }
    fn query(&self) -> Value {
        match self {
            Self::Name(name) => json!({"name": name}),
            Self::Offset(offset) => json!({"byte_offset": offset}),
        }
    }
}

fn identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '$' || first == '_' || first.is_alphabetic())
        && chars.all(|c| c == '$' || c == '_' || c.is_alphanumeric())
}

/// The worker request for `target`, with offsets in the BOM-free text.
pub fn worker_request(raw: &[u8], target: &Target) -> Result<Value> {
    let (text, bom) =
        script_text(raw).ok_or_else(|| Error::bad("Artifact is not valid UTF-8 JavaScript"))?;
    let mut request = json!({"operation": "invocation_site", "source": text});
    match target {
        Target::Name(name) => request["name"] = json!(name),
        Target::Offset(offset) => {
            if *offset < bom || *offset >= raw.len() || !text.is_char_boundary(offset - bom) {
                return Err(Error::bad(
                    "byte_offset must name a character of the script text in this artifact",
                ));
            }
            request["byte_offset"] = json!(offset - bom);
        }
    }
    Ok(request)
}

fn invalid_worker() -> Error {
    Error::new(
        502,
        "The JavaScript analysis worker returned an invalid invocation site response",
    )
}

/// Checks the worker's reply against the text it was given, so no offset it
/// reports is trusted before it names a character of this artifact.
pub fn validate_worker(raw: &[u8], target: &Target, response: &Value) -> Result<()> {
    let (text, _) = script_text(raw).ok_or_else(invalid_worker)?;
    if response["schema"] != "reb-invocation-site-worker-v1"
        || response["source_bytes"].as_u64() != Some(text.len() as u64)
        || !response["ok"].is_boolean()
    {
        return Err(invalid_worker());
    }
    if response["ok"] == false {
        return response["error"]
            .as_str()
            .filter(|message| message.len() <= 200)
            .map(drop)
            .ok_or_else(invalid_worker);
    }
    let offset = |value: &Value| {
        value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n <= text.len() && text.is_char_boundary(*n))
    };
    let candidate = |value: &Value| -> bool {
        let start = offset(&value["start"]);
        let end = offset(&value["end"]);
        let anchor_ok = match &value["anchor_byte"] {
            Value::Null => true,
            anchor => offset(anchor).is_some_and(|n| text.as_bytes().get(n) == Some(&b'(')),
        };
        matches!((start, end), (Some(s), Some(e)) if s < e)
            && anchor_ok
            && value["kind"].as_str().is_some_and(|k| {
                [
                    "function",
                    "arrow",
                    "method",
                    "getter",
                    "setter",
                    "generator",
                    "constructor",
                ]
                .contains(&k)
            })
            && (value["binding"].is_null()
                || value["binding"].as_str().is_some_and(|b| b.len() <= 512))
            && (value["unsupported"].is_null()
                || value["unsupported"]
                    .as_str()
                    .is_some_and(|u| refusal(u).is_some()))
    };
    let list = |key: &str, count: &str| {
        response[key].as_array().is_some_and(|items| {
            items.len() <= CANDIDATE_LIMIT
                && items.iter().all(candidate)
                && response[count]
                    .as_u64()
                    .is_some_and(|n| items.len() == (n as usize).min(CANDIDATE_LIMIT))
        })
    };
    let valid = match target {
        Target::Name(_) => list("matches", "match_count") && list("related", "related_count"),
        Target::Offset(_) => match (&response["selected"], response["reason"].as_str()) {
            (Value::Null, Some("no_function" | "class_initializer")) => true,
            (selected, None) => candidate(selected),
            _ => false,
        },
    };
    valid.then_some(()).ok_or_else(invalid_worker)
}

fn refusal(code: &str) -> Option<&'static str> {
    Some(match code {
        "arrow_bare_parameter" => {
            "An arrow function with a bare parameter starts at that parameter, not at a `(`, so it cannot be tracked from here. Author its site by hand (protocol/native-js-invocation-v1.md)."
        }
        "async_arrow" => {
            "An async arrow function starts at `async`, not at a `(`, so it cannot be tracked from here. Author its site by hand (protocol/native-js-invocation-v1.md)."
        }
        "generator" => {
            "Generators and async generators are never armed; the capture would only report an unsupported function."
        }
        "class_constructor" => {
            "Class constructors are never armed; the capture would only report an unsupported function."
        }
        "no_parameter_list" => "This function has no `(` parameter list to anchor its site at.",
        _ => return None,
    })
}

/// One-based line and column of each sorted byte offset in the artifact text
/// as Sources shows it: strict UTF-8 with the BOM kept, lines split at LF,
/// columns in UTF-16 code units. One pass over the text.
fn positions(text: &str, offsets: &[usize]) -> Vec<(usize, usize)> {
    let mut result = Vec::with_capacity(offsets.len());
    let (mut at, mut line, mut column) = (0usize, 1usize, 1usize);
    for &offset in offsets {
        for c in text[at..offset].chars() {
            if c == '\n' {
                line += 1;
                column = 1;
            } else {
                column += c.len_utf16();
            }
        }
        at = offset;
        result.push((line, column));
    }
    result
}

/// A short single line around `at`, as inert display text.
fn context(text: &str, at: usize) -> String {
    let clean = |c: char| if c.is_control() { ' ' } else { c };
    let before = text[..at]
        .chars()
        .rev()
        .take_while(|c| *c != '\n')
        .take(CONTEXT_CHARS + 1)
        .collect::<Vec<_>>();
    let after = text[at..]
        .chars()
        .take_while(|c| *c != '\n')
        .take(CONTEXT_CHARS + 1)
        .collect::<Vec<_>>();
    let mut line = String::new();
    if before.len() > CONTEXT_CHARS {
        line.push('…');
    }
    line.extend(before.iter().take(CONTEXT_CHARS).rev().map(|c| clean(*c)));
    line.extend(after.iter().take(CONTEXT_CHARS).map(|c| clean(*c)));
    if after.len() > CONTEXT_CHARS {
        line.push('…');
    }
    line
}

fn candidates(raw: &[u8], items: &[&Value]) -> Vec<Value> {
    let text = std::str::from_utf8(raw).expect("validated UTF-8");
    let bom = if raw.starts_with(BOM) { BOM.len() } else { 0 };
    let at = |item: &Value| {
        bom + item["anchor_byte"]
            .as_u64()
            .or_else(|| item["start"].as_u64())
            .unwrap() as usize
    };
    let mut order = (0..items.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| at(items[*index]));
    let sorted = order
        .iter()
        .map(|index| at(items[*index]))
        .collect::<Vec<_>>();
    let located = positions(text, &sorted);
    let mut result = vec![Value::Null; items.len()];
    for (rank, index) in order.into_iter().enumerate() {
        let item = items[index];
        let unsupported = item["unsupported"].as_str();
        result[index] = json!({
            "byte_offset": item["anchor_byte"].as_u64().map(|n| n as usize + bom),
            "start_byte": item["start"].as_u64().unwrap() as usize + bom,
            "line": located[rank].0,
            "column": located[rank].1,
            "kind": item["kind"],
            "binding": item["binding"],
            "context": context(text, sorted[rank]),
            "supported": unsupported.is_none(),
            "refusal": unsupported.and_then(refusal),
        });
    }
    result
}

/// The resolution document for a validated worker reply: exactly one site,
/// or a refusal with its reason and the bounded candidate list. Never a guess.
pub fn resolution(
    raw: &[u8],
    artifact: &Value,
    target: &Target,
    response: &Value,
    requested_label: Option<&str>,
    saved: &[Saved],
) -> Result<Value> {
    let mut document = json!({
        "format": "reb-js-invocation-site-resolution-v1",
        "status": "refused",
        "reason": Value::Null,
        "message": "",
        "query": target.query(),
        "artifact": crate::evidence::public_artifact(artifact),
        "function": Value::Null,
        "candidates": [],
        "candidate_relation": Value::Null,
        "candidate_count": 0,
        "candidates_truncated": false,
        "site": Value::Null,
        "label": Value::Null,
        "saved": false,
        "next_capture": NEXT_CAPTURE,
    });
    let refuse = |document: &mut Value, reason: &str, message: String| {
        document["reason"] = json!(reason);
        document["message"] = json!(message);
    };
    if response["ok"] == false {
        refuse(
            &mut document,
            "source_unavailable",
            format!(
                "This JavaScript could not be analyzed: {}. Nothing was guessed.",
                response["error"].as_str().unwrap_or("unknown failure")
            ),
        );
        return Ok(document);
    }
    let chosen = match target {
        Target::Name(name) => {
            let matches = response["matches"].as_array().unwrap();
            let count = response["match_count"].as_u64().unwrap();
            if count == 1 {
                Some((matches[0].clone(), name.clone()))
            } else {
                let (items, total, relation, message) = if count == 0 {
                    let related = response["related"].as_array().unwrap();
                    let total = response["related_count"].as_u64().unwrap();
                    (
                        related,
                        total,
                        "same_final_name",
                        format!(
                            "No function definition in this artifact binds {name}; text in strings and comments never matches.{}",
                            if total > 0 {
                                " Definitions bound to a name with the same final segment are listed; choose one by its position."
                            } else {
                                ""
                            }
                        ),
                    )
                } else {
                    (
                        matches,
                        count,
                        "matches",
                        format!(
                            "{count} function definitions bind {name}. Choose one by its position; nothing was guessed."
                        ),
                    )
                };
                let listed = items.iter().collect::<Vec<_>>();
                document["candidates"] = json!(candidates(raw, &listed));
                document["candidate_relation"] = json!(relation);
                document["candidate_count"] = json!(total);
                document["candidates_truncated"] = json!(total as usize > listed.len());
                refuse(
                    &mut document,
                    if count == 0 { "no_match" } else { "ambiguous" },
                    message,
                );
                None
            }
        }
        Target::Offset(_) => match response["reason"].as_str() {
            Some("class_initializer") => {
                refuse(
                    &mut document,
                    "class_initializer",
                    "This position is in a class field initializer or static block, which V8 compiles as a synthesized function that is never armed.".into(),
                );
                None
            }
            Some(_) => {
                refuse(
                    &mut document,
                    "no_function",
                    "No function encloses this position; top-level script code is never armed."
                        .into(),
                );
                None
            }
            None => {
                let selected = response["selected"].clone();
                let label = selected["binding"].as_str().map(str::to_owned);
                Some((selected, label.unwrap_or_default()))
            }
        },
    };
    let Some((chosen, name)) = chosen else {
        return Ok(document);
    };
    let function = candidates(raw, &[&chosen]).remove(0);
    document["function"] = function.clone();
    if let Some(reason) = function["refusal"].as_str() {
        refuse(&mut document, "unsupported_function", reason.to_owned());
        return Ok(document);
    }
    let anchor = function["byte_offset"].as_u64().unwrap() as usize;
    let artifact_id = artifact["artifact_id"].as_str().unwrap_or_default();
    let site = site(raw, artifact_id, anchor).map_err(|_| invalid_worker())?;
    let label = match requested_label {
        Some(value) => label(value)?,
        None if !name.is_empty() => derived_label(&name),
        None => format!(
            "Function at line {}, column {}",
            function["line"], function["column"]
        ),
    };
    document["status"] = json!("resolved");
    document["message"] = json!(format!(
        "Resolved to the function at line {}, column {}. {NEXT_CAPTURE}",
        function["line"], function["column"]
    ));
    document["saved"] = json!(saved.iter().any(|prior| prior.site.same_function(&site)));
    document["site"] = site.value();
    document["label"] = json!(label);
    Ok(document)
}

/// The saved entry for a resolved document.
pub fn saved_from(document: &Value, artifact: &Value) -> Option<Saved> {
    let site = parse_sites_file(&format!(
        r#"{{"sites":[{}],"version":1}}"#,
        serde_json::to_string(&document["site"]).ok()?
    ))?
    .remove(0);
    Some(Saved {
        site,
        label: document["label"].as_str()?.to_owned(),
        source_url: artifact["url"]
            .as_str()
            .filter(|url| !url.is_empty() && url.len() <= URL_BYTES)
            .map(str::to_owned),
        session_id: artifact["session_id"].as_str().map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../tools/fixtures/native-js-invocation/site-cases.json"
        ))
        .unwrap()
    }

    fn case_bytes(case: &Value) -> Vec<u8> {
        match case["source_hex"].as_str() {
            Some(hex) => hex::decode(hex).unwrap(),
            None => case["source"].as_str().unwrap().as_bytes().to_vec(),
        }
    }

    #[test]
    fn site_computation_matches_the_shared_python_cases() {
        let fixture = fixture();
        assert_eq!(fixture["format"], "reb-native-js-invocation-site-cases-v1");
        let mut computed = std::collections::BTreeMap::new();
        for case in fixture["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let result = site(
                &case_bytes(case),
                case["artifact_id"].as_str().unwrap(),
                case["byte_offset"].as_u64().unwrap() as usize,
            );
            match (&result, case["error"].as_str()) {
                (Ok(site), None) => {
                    assert_eq!(site.value(), case["site"], "{name}");
                    computed.insert(name.to_owned(), site.clone());
                }
                (Err(error), Some(kind)) => assert_eq!(error.kind(), kind, "{name}"),
                _ => panic!("{name}: {result:?}"),
            }
        }
        for entry in fixture["files"].as_array().unwrap() {
            let name = entry["name"].as_str().unwrap();
            let sites = entry["cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|case| computed[case.as_str().unwrap()].clone())
                .collect::<Vec<_>>();
            match (sites_file(&sites), entry["error"].as_str()) {
                (Ok(text), None) => {
                    assert_eq!(text, entry["file"].as_str().unwrap(), "{name}");
                    assert_eq!(parse_sites_file(&text), Some(sites), "{name}");
                }
                (Err(error), Some(kind)) => assert_eq!(error.kind(), kind, "{name}"),
                (result, _) => panic!("{name}: {result:?}"),
            }
        }
    }

    #[test]
    fn a_site_file_is_accepted_only_in_its_exact_canonical_form() {
        let fixture = fixture();
        let file = fixture["files"][0]["file"].as_str().unwrap();
        assert!(parse_sites_file(file).is_some());
        let pretty =
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(file).unwrap()).unwrap();
        for bad in [
            pretty.as_str(),
            &file.replace("\"version\":1", "\"version\":2"),
            &file.replace("function-entry", "dispatch"),
            &file.replacen("\"anchor_offset\":", "\"extra\":1,\"anchor_offset\":", 1),
            "",
            "{}",
        ] {
            assert!(parse_sites_file(bad).is_none(), "{bad}");
        }
    }

    fn saved(index: u32) -> Saved {
        Saved {
            site: Site {
                anchor_offset: index,
                artifact_id: "12".into(),
                artifact_sha256: "a".repeat(64),
                byte_offset: index,
                source_length: 100,
                source_sha256: "b".repeat(64),
            },
            label: format!("f{index}"),
            source_url: Some("https://example.test/glue.js".into()),
            session_id: Some("7".into()),
        }
    }

    #[test]
    fn the_saved_set_is_bounded_unique_private_and_exact() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("app/js-invocation-sites-v1.json");
        let store = Store::new(path.clone());
        assert!(store.load().unwrap().is_empty());
        for index in 0..8 {
            store.add(saved(index)).unwrap();
        }
        let ninth = store.add(saved(8)).unwrap_err();
        assert_eq!(ninth.status, 409);
        assert!(ninth.message.contains("8 functions"));
        let duplicate = store.add(saved(3)).unwrap_err();
        assert_eq!(
            (
                duplicate.status,
                duplicate.message.contains("already saved")
            ),
            (409, true)
        );
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&labels_path(&path)), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let text = std::fs::read_to_string(&path).unwrap();
        let sites = parse_sites_file(&text).expect("the browser's exact format");
        assert_eq!(sites.len(), 8);
        let loaded = store.load().unwrap();
        assert_eq!(loaded[3], saved(3));
        assert_eq!(store.remove(&"b".repeat(64), 3).unwrap().len(), 7);
        assert_eq!(store.remove(&"b".repeat(64), 3).unwrap_err().status, 404);
        // A lost sidecar never loses a site, only its label.
        std::fs::remove_file(labels_path(&path)).unwrap();
        assert_eq!(store.load().unwrap()[0].label, "Unlabeled function");
        assert_eq!(store.clear().unwrap(), 7);
        assert!(!path.exists() && !labels_path(&path).exists());
        assert!(store.load().unwrap().is_empty());
        // An invalid site file is reported, and clearing repairs it.
        std::fs::write(&path, "{\"sites\":[]}").unwrap();
        assert_eq!(store.load().unwrap_err().status, 500);
        assert_eq!(store.clear().unwrap(), 0);
        assert!(store.load().unwrap().is_empty());
    }

    fn worker(source: &str, target: &Target) -> Value {
        let raw = source.as_bytes();
        let request = worker_request(raw, target).unwrap();
        // The fixture stands in for the worker with what it would return.
        let anchor = source
            .find("(aGh")
            .map(|n| n - if raw.starts_with(BOM) { 3 } else { 0 });
        match target {
            Target::Name(_) => {
                json!({"schema":"reb-invocation-site-worker-v1","ok":true,"error":null,
                "source_bytes":request["source"].as_str().unwrap().len(),
                "matches":[{"kind":"function","anchor_byte":anchor,"start":anchor.unwrap()-8,"end":anchor.unwrap()+20,"binding":"window.hsw","unsupported":null}],
                "match_count":1,"related":[],"related_count":0,"selected":null,"reason":null})
            }
            Target::Offset(_) => {
                json!({"schema":"reb-invocation-site-worker-v1","ok":true,"error":null,
                "source_bytes":request["source"].as_str().unwrap().len(),
                "matches":[],"match_count":0,"related":[],"related_count":0,"reason":null,
                "selected":{"kind":"arrow","anchor_byte":null,"start":1,"end":5,"binding":"a","unsupported":"arrow_bare_parameter"}})
            }
        }
    }

    #[test]
    fn a_resolution_names_one_site_or_refuses_with_a_reason() {
        let source = "\u{feff}var a='é';\nwindow.hsw=function(aGh,jR,qN){return aGh};";
        let raw = source.as_bytes();
        let artifact = json!({"artifact_id":"12","session_id":"7","kind":"javascript","url":"https://example.test/glue.js","sha256":hex::encode(Sha256::digest(raw))});
        let target = Target::Name("window.hsw".into());
        let response = worker(source, &target);
        validate_worker(raw, &target, &response).unwrap();
        let document = resolution(raw, &artifact, &target, &response, None, &[]).unwrap();
        assert_eq!(document["status"], "resolved", "{document}");
        assert_eq!(document["label"], "window.hsw");
        let anchor = source.find("(aGh").unwrap();
        assert_eq!(document["site"], site(raw, "12", anchor).unwrap().value());
        assert_eq!(document["function"]["byte_offset"], anchor);
        assert_eq!(
            (
                document["function"]["line"].as_u64(),
                document["function"]["column"].as_u64()
            ),
            (Some(2), Some(20))
        );
        assert!(
            document["function"]["context"]
                .as_str()
                .unwrap()
                .contains("window.hsw=function(aGh")
        );
        let saved = saved_from(&document, &artifact).unwrap();
        assert_eq!(
            saved.source_url.as_deref(),
            Some("https://example.test/glue.js")
        );
        let again = resolution(
            raw,
            &artifact,
            &target,
            &response,
            Some("hsw entry"),
            std::slice::from_ref(&saved),
        )
        .unwrap();
        assert_eq!(
            (again["saved"].as_bool(), again["label"].as_str()),
            (Some(true), Some("hsw entry"))
        );

        let arrow = "a=x=>x;";
        let target = Target::Offset(2);
        let response = worker(arrow, &target);
        validate_worker(arrow.as_bytes(), &target, &response).unwrap();
        let refused =
            resolution(arrow.as_bytes(), &artifact, &target, &response, None, &[]).unwrap();
        assert_eq!(refused["status"], "refused");
        assert_eq!(refused["reason"], "unsupported_function");
        assert!(
            refused["message"]
                .as_str()
                .unwrap()
                .contains("bare parameter")
        );
        assert!(refused["site"].is_null());

        // A reply whose anchor is not a `(` of this text is never trusted.
        let mut forged = worker(source, &Target::Name("hsw".into()));
        forged["matches"][0]["anchor_byte"] = json!(2);
        assert_eq!(
            validate_worker(raw, &Target::Name("hsw".into()), &forged)
                .unwrap_err()
                .status,
            502
        );
        assert!(worker_request(raw, &Target::Offset(1)).is_err());
        assert!(worker_request(raw, &Target::Offset(raw.len())).is_err());
        assert!(Target::from_fields(Some(&json!("1a")), None).is_err());
        assert!(Target::from_fields(Some(&json!("a")), Some(&json!(1))).is_err());
    }

    #[test]
    fn candidate_positions_and_context_are_bounded_display_text() {
        let text = "x\n\u{1F600}ab(c)\t<b>";
        assert_eq!(positions(text, &[0, 2, 8]), vec![(1, 1), (2, 1), (2, 5)]);
        assert_eq!(context(text, 8), "😀ab(c) <b>");
        let long = format!("{}({})", "a".repeat(200), "b".repeat(200));
        let line = context(&long, 200);
        assert!(line.starts_with('…') && line.ends_with('…'));
        assert_eq!(line.chars().count(), 2 * CONTEXT_CHARS + 2);
    }

    #[test]
    fn retained_versions_are_compared_by_bytes_then_by_script_text() {
        let entry = saved(1);
        let artifact = |id: &str, sha: &str, url: &str| json!({"artifact_id":id,"kind":"javascript","sha256":sha,"url":url});
        let url = "https://example.test/glue.js";
        let same = retained(&entry, &[artifact("4", &"a".repeat(64), "other")], |_| None);
        assert_eq!(
            (
                same["state"].as_str(),
                same["matching_artifact_id"].as_str()
            ),
            (Some("matches"), Some("4"))
        );
        let changed = retained(&entry, &[artifact("5", &"c".repeat(64), url)], |_| {
            Some("d".repeat(64))
        });
        assert_eq!(
            (
                changed["state"].as_str(),
                changed["other_version_artifact_id"].as_str()
            ),
            (Some("other_version"), Some("5"))
        );
        let bom_only = retained(&entry, &[artifact("6", &"c".repeat(64), url)], |_| {
            Some("b".repeat(64))
        });
        assert_eq!(bom_only["state"], "matches");
        assert_eq!(retained(&entry, &[], |_| None)["state"], "not_retained");
    }
}
