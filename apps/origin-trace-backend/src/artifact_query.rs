//! Filtered, cursor-paged reads of the artifact manifest, with the same
//! scanner and cursor rules as filtered event reads. Records are validated
//! exactly as `/api/artifacts` validates them and keep only public fields.
use crate::{
    app::Query,
    error::{Error, Result},
    event_query::{self, Cursor, Page},
    evidence,
};
use serde_json::{Map, Value, json};
use std::{collections::HashSet, path::Path};

pub const MANIFEST_RECORD_BYTES: usize = 8192;
const ID_FIELDS: [&str; 5] = [
    "artifact_id",
    "session_id",
    "navigation_id",
    "frame_id",
    "execution_context_id",
];
pub const ARTIFACT_QUERY_KEYS: [&str; 10] = [
    "kind",
    "artifact_id",
    "session_id",
    "navigation_id",
    "frame_id",
    "execution_context_id",
    "sha256",
    "host",
    "after",
    "before",
];

#[derive(Default)]
pub struct ArtifactFilter {
    kinds: Vec<String>,
    ids: Vec<(&'static str, u64)>,
    sha256: Option<String>,
    host: Option<String>,
}
impl ArtifactFilter {
    pub fn parse(q: &Query) -> Result<Self> {
        let mut filter = Self::default();
        if let Some(text) = q.one("kind")? {
            filter.kinds = event_query::names(text, "kind")?;
        }
        for field in ID_FIELDS {
            if q.one(field)?.is_some() {
                filter.ids.push((field, q.number(field, None, 64, false)?));
            }
        }
        if let Some(text) = q.one("sha256")? {
            if text.len() != 64
                || !text
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(Error::bad(
                    "sha256 must be 64 lowercase hexadecimal characters",
                ));
            }
            filter.sha256 = Some(text.to_owned());
        }
        if let Some(text) = q.one("host")? {
            let host = text.to_ascii_lowercase();
            if host.is_empty()
                || host.len() > 253
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]_".contains(&byte))
            {
                return Err(Error::bad(
                    "host must be a URL host name such as example.com",
                ));
            }
            filter.host = Some(host);
        }
        Ok(filter)
    }
    pub(crate) fn matches(&self, artifact: &Value) -> bool {
        let host = || {
            artifact["url"]
                .as_str()
                .and_then(|url| url::Url::parse(url).ok())
                .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        };
        (self.kinds.is_empty()
            || artifact["kind"]
                .as_str()
                .is_some_and(|kind| self.kinds.iter().any(|k| k == kind)))
            && self.ids.iter().all(|(field, value)| {
                artifact[*field]
                    .as_str()
                    .and_then(|text| text.parse::<u64>().ok())
                    == Some(*value)
            })
            && self
                .sha256
                .as_ref()
                .is_none_or(|digest| artifact["sha256"] == digest.as_str())
            && self
                .host
                .as_ref()
                .is_none_or(|expected| host().as_deref() == Some(expected.as_str()))
    }
    pub fn echo(&self) -> Value {
        let mut object = Map::new();
        if !self.kinds.is_empty() {
            object.insert("kind".into(), json!(self.kinds));
        }
        for (field, value) in &self.ids {
            object.insert((*field).into(), json!(value.to_string()));
        }
        if let Some(digest) = &self.sha256 {
            object.insert("sha256".into(), json!(digest));
        }
        if let Some(host) = &self.host {
            object.insert("host".into(), json!(host));
        }
        Value::Object(object)
    }
}

/// Parses, validates and publicly projects one manifest record. A duplicate
/// artifact ID inside the scanned scope fails the read, as the unfiltered
/// route does, rather than choosing one record.
pub fn visitor<'a>(
    seen: &'a mut HashSet<String>,
    mut select: impl FnMut(&Value) -> bool + 'a,
) -> impl FnMut(&[u8]) -> Result<Option<Value>> + 'a {
    move |line| {
        let mut artifact: Value = serde_json::from_slice(line)
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| Error::new(500, "The evidence store contains a malformed artifact"))?;
        evidence::validate_artifact(&mut artifact)?;
        if !seen.insert(artifact["artifact_id"].as_str().unwrap_or("").to_owned()) {
            return Err(Error::new(
                500,
                "The artifact manifest contains a duplicate artifact ID",
            ));
        }
        let artifact = evidence::public_artifact(&artifact);
        Ok(select(&artifact).then_some(artifact))
    }
}

pub fn read(root: &Path, filter: &ArtifactFilter, cursor: Cursor, limit: usize) -> Result<Page> {
    let mut seen = HashSet::new();
    event_query::read_page(
        &root.join("manifest.jsonl"),
        cursor,
        limit,
        event_query::SCAN_BYTES,
        MANIFEST_RECORD_BYTES,
        visitor(&mut seen, |artifact| filter.matches(artifact)),
    )
}

pub fn query_document(page: &Page, filter: &ArtifactFilter, cursor: Cursor, limit: usize) -> Value {
    let direction = if matches!(cursor, Cursor::After(_)) {
        "forward"
    } else {
        "backward"
    };
    let mut query = page.paging(direction, limit);
    query["filters"] = filter.echo();
    query["scope"] = json!(page.scope());
    query["scan_start"] = json!(page.scan_start.to_string());
    query["scan_end"] = json!(page.scan_end.to_string());
    query
}
