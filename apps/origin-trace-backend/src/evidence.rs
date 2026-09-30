use crate::{
    error::{Error, Result},
    validation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

pub const PUBLIC_ARTIFACT_FIELDS: [&str; 15] = [
    "protocol_version",
    "artifact_id",
    "session_id",
    "navigation_id",
    "frame_id",
    "parent_artifact_id",
    "creator_event_id",
    "execution_context_id",
    "capture_origin",
    "kind",
    "url",
    "mime_type",
    "byte_size",
    "sha256",
    "sensitive",
];
pub fn recent(path: &Path, limit: usize, maximum: usize, label: &str) -> Result<Vec<Value>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut file = match regular_file(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(Error::new(500, "Evidence store must be a regular file"));
    }
    let mut position = file.seek(SeekFrom::End(0))?;
    let mut suffix = Vec::new();
    let mut lines = Vec::new();
    while position > 0 && lines.len() < limit {
        let size = position.min(64 * 1024) as usize;
        position -= size as u64;
        file.seek(SeekFrom::Start(position))?;
        let mut chunk = vec![0; size];
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&suffix);
        let mut parts = chunk.rsplit(|b| *b == b'\n').collect::<Vec<_>>();
        let first = parts.pop().unwrap_or(&[]);
        for line in parts {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if line.len() > maximum {
                return Err(Error::new(
                    500,
                    format!("The evidence store contains an oversized {label}"),
                ));
            }
            let value: Value = serde_json::from_slice(line).map_err(|_| {
                Error::new(
                    500,
                    format!("The evidence store contains a malformed {label}"),
                )
            })?;
            if !value.is_object() {
                return Err(Error::new(
                    500,
                    format!("The evidence store contains a malformed {label}"),
                ));
            }
            lines.push(value);
            if lines.len() == limit {
                break;
            }
        }
        suffix = first.to_vec();
        if suffix.len() > maximum {
            return Err(Error::new(
                500,
                format!("The evidence store contains an oversized {label}"),
            ));
        }
    }
    if position == 0 && lines.len() < limit && !suffix.iter().all(u8::is_ascii_whitespace) {
        let value: Value = serde_json::from_slice(&suffix).map_err(|_| {
            Error::new(
                500,
                format!("The evidence store contains a malformed {label}"),
            )
        })?;
        if !value.is_object() {
            return Err(Error::new(
                500,
                format!("The evidence store contains a malformed {label}"),
            ));
        }
        lines.push(value);
    }
    lines.reverse();
    Ok(lines)
}
pub fn canonical(value: &Value, bits: u32, nonzero: bool) -> bool {
    validation::canonical(value, bits, nonzero, "Identifier").is_ok()
}
pub fn artifacts(root: &Path, limit: usize) -> Result<Vec<Value>> {
    let mut records = recent(&root.join("manifest.jsonl"), limit, 8192, "artifact")?;
    let mut seen = BTreeSet::new();
    for artifact in &mut records {
        validate_artifact(artifact)?;
        if !seen.insert(artifact["artifact_id"].as_str().unwrap().to_owned()) {
            return Err(Error::new(
                500,
                "The artifact manifest contains a duplicate artifact ID",
            ));
        }
    }
    Ok(records)
}
pub fn public_artifact(artifact: &Value) -> Value {
    json!(
        artifact
            .as_object()
            .map(|object| object
                .iter()
                .filter(|(key, _)| PUBLIC_ARTIFACT_FIELDS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<serde_json::Map<_, _>>())
            .unwrap_or_default()
    )
}
pub fn content(root: &Path, artifact: &Value, maximum: usize) -> Result<Vec<u8>> {
    let root = root.canonicalize()?;
    let path = root
        .join(
            artifact["content_path"]
                .as_str()
                .ok_or_else(|| Error::new(500, "Malformed artifact content path"))?,
        )
        .canonicalize()?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(Error::new(
            500,
            "Artifact content path escapes the artifact store",
        ));
    }
    let file = regular_file(&path)?;
    if file.metadata()?.len() != artifact["byte_size"].as_u64().unwrap_or(u64::MAX) {
        return Err(Error::new(500, "Artifact content byte size is invalid"));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(Error::bad("Artifact content exceeds its byte limit"));
    }
    if hex::encode(Sha256::digest(&bytes)) != artifact["sha256"].as_str().unwrap_or("") {
        return Err(Error::new(500, "Artifact content hash is invalid"));
    }
    Ok(bytes)
}
pub fn verified_range(
    root: &Path,
    artifact: &Value,
    offset: usize,
    limit: usize,
) -> Result<Vec<u8>> {
    let root = root.canonicalize()?;
    let path = root
        .join(
            artifact["content_path"]
                .as_str()
                .ok_or_else(|| Error::new(500, "Malformed artifact content path"))?,
        )
        .canonicalize()?;
    if !path.starts_with(&root) {
        return Err(Error::new(
            500,
            "Artifact content path escapes the artifact store",
        ));
    }
    let mut file = regular_file(&path)?;
    let expected = artifact["byte_size"]
        .as_u64()
        .ok_or_else(|| Error::new(500, "Artifact content byte size is invalid"))?;
    if file.metadata()?.len() != expected {
        return Err(Error::new(500, "Artifact content byte size is invalid"));
    }
    let started = std::time::Instant::now();
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut position = 0usize;
    let mut selected = Vec::with_capacity(limit.min(2 * 1024 * 1024));
    loop {
        if started.elapsed() > std::time::Duration::from_secs(30) {
            return Err(Error::new(
                408,
                "Artifact verification exceeded its deadline",
            ));
        }
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
        let start = offset.saturating_sub(position).min(size);
        let end = offset
            .saturating_add(limit)
            .saturating_sub(position)
            .min(size);
        if end > start {
            selected.extend_from_slice(&buffer[start..end]);
        }
        position = position
            .checked_add(size)
            .ok_or_else(|| Error::new(500, "Artifact byte size overflow"))?;
        if position as u64 > expected {
            return Err(Error::new(500, "Artifact changed during verification"));
        }
    }
    if position as u64 != expected
        || file.metadata()?.len() != expected
        || hex::encode(hash.finalize()) != artifact["sha256"].as_str().unwrap_or("")
    {
        return Err(Error::new(500, "Artifact content integrity is invalid"));
    }
    Ok(selected)
}

pub fn resource_etag(path: &Path, signature: &str) -> String {
    let metadata = path.metadata().ok();
    let size = metadata.as_ref().map_or(0, |m| m.len());
    let modified = metadata
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    format!(
        "\"{}\"",
        hex::encode(Sha256::digest(format!(
            "{}:{size}:{modified}:{signature}",
            path.display()
        )))
    )
}

pub(crate) fn regular_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("Evidence must be a regular file"));
    }
    Ok(file)
}

pub fn validate_artifact(artifact: &mut Value) -> Result<()> {
    let valid = artifact["protocol_version"] == 1
        && [
            "artifact_id",
            "session_id",
            "navigation_id",
            "frame_id",
            "parent_artifact_id",
            "creator_event_id",
        ]
        .iter()
        .all(|k| canonical(&artifact[k], 64, false))
        && [
            "javascript",
            "wasm",
            "source_map",
            "response_body",
            "canvas_data_url",
        ]
        .contains(&artifact["kind"].as_str().unwrap_or(""))
        && artifact["url"].as_str().is_some_and(|s| !s.is_empty())
        && artifact["mime_type"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        && artifact["byte_size"].as_u64().is_some()
        && artifact["sensitive"].as_bool().is_some();
    let hash = artifact["sha256"].as_str().unwrap_or("");
    if !valid
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || artifact["content_path"] != format!("blobs/{hash}.bin")
        || artifact["sensitive"]
            != matches!(
                artifact["kind"].as_str(),
                Some("response_body" | "canvas_data_url")
            )
    {
        return Err(Error::new(
            500,
            "The artifact manifest contains a malformed record",
        ));
    }
    if artifact.get("execution_context_id").is_some() || artifact.get("capture_origin").is_some() {
        let origin = artifact["capture_origin"].as_str().unwrap_or("");
        if !canonical(&artifact["execution_context_id"], 64, false)
            || ![
                "unknown",
                "network_response",
                "dynamic_javascript",
                "webassembly_compile",
                "webassembly_module",
                "webassembly_instantiate",
                "canvas_to_data_url",
            ]
            .contains(&origin)
            || (origin == "dynamic_javascript"
                && (artifact["kind"] != "javascript" || artifact["execution_context_id"] == "0"))
            || (origin.starts_with("webassembly_")
                && (artifact["kind"] != "wasm" || artifact["execution_context_id"] == "0"))
            || (origin == "canvas_to_data_url"
                && (artifact["kind"] != "canvas_data_url"
                    || artifact["execution_context_id"] != "0"))
        {
            return Err(Error::new(
                500,
                "The artifact manifest contains a malformed record",
            ));
        }
    } else {
        artifact["execution_context_id"] = json!("0");
        artifact["capture_origin"] = json!("unknown");
    }
    Ok(())
}

pub fn find_artifact(root: &Path, id: &str) -> Result<Value> {
    use std::io::BufRead;
    let path = root.join("manifest.jsonl");
    let file = match regular_file(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::new(404, "Artifact not found"));
        }
        Err(e) => return Err(e.into()),
    };
    let mut reader = std::io::BufReader::new(file);
    let mut selected = None;
    let mut seen = BTreeSet::new();
    let started = std::time::Instant::now();
    loop {
        if started.elapsed() > std::time::Duration::from_secs(5) {
            return Err(Error::new(
                408,
                "Artifact manifest read exceeded its deadline",
            ));
        }
        let mut bytes = Vec::new();
        let size = reader.by_ref().take(8193).read_until(b'\n', &mut bytes)?;
        if size == 0 {
            break;
        }
        if size > 8192 {
            return Err(Error::new(
                500,
                "The artifact manifest contains an oversized record",
            ));
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let mut value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::new(500, "The artifact manifest contains malformed JSON"))?;
        validate_artifact(&mut value)?;
        let identifier = value["artifact_id"].as_str().unwrap().to_owned();
        if !seen.insert(identifier) {
            return Err(Error::new(
                500,
                "The artifact manifest contains a duplicate artifact ID",
            ));
        }
        if value["artifact_id"] == id {
            selected = Some(value);
        }
    }
    selected.ok_or_else(|| Error::new(404, "Artifact not found"))
}
