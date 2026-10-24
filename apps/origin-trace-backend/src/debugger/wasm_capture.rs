//! CDP `Debugger.getScriptSource` returns an empty `scriptSource` for
//! WebAssembly and puts the module in base64 `bytecode`. An empty string must
//! not hide that field. `Debugger.getWasmBytecode` is the fallback when
//! bytecode is absent.
//!
//! The artifact receiver keeps the browser's authenticated socket open, so this
//! path appends one receiver-format manifest line directly. Artifact IDs start
//! at 2^32 and stay above the browser allocator, which starts at 1.

use super::Debugger;
use crate::{
    error::{Code, Error, Result},
    evidence, validation,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;

const ID_FLOOR: u64 = 1 << 32;
const MAX_WASM_BYTES: usize = 16 * 1024 * 1024;
const MAX_MODULES: usize = 64;
const MAX_URL_BYTES: usize = 8192;
const SOURCE_LIMIT: usize = 2_097_152;
const MANIFEST_LINE_LIMIT: usize = 8192;
const CACHE_ENTRIES: usize = 8;
const CACHE_BYTES: usize = 32 * 1024 * 1024;

pub(super) struct WasmCapture {
    gate: AsyncMutex<()>,
    cache: Mutex<BTreeMap<String, Arc<Vec<u8>>>>,
    store: Mutex<()>,
    next_id: AtomicU64,
}

impl WasmCapture {
    pub(super) fn new() -> Self {
        Self {
            gate: AsyncMutex::new(()),
            cache: Mutex::new(BTreeMap::new()),
            store: Mutex::new(()),
            next_id: AtomicU64::new(ID_FLOOR),
        }
    }
}

struct ManifestFields<'a> {
    artifact_id: u64,
    session_id: u64,
    navigation_id: u64,
    frame_id: u64,
    parent_artifact_id: u64,
    creator_event_id: u64,
    execution_context_id: u64,
    capture_origin: &'a str,
    kind: &'a str,
    url: &'a str,
    mime_type: &'a str,
    byte_size: u64,
    sha256: &'a str,
    sensitive: bool,
}

pub(super) fn is_wasm_script(script: &Value) -> bool {
    script["language"] == "WebAssembly"
        || script["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("wasm:"))
}

/// Non-empty `scriptSource` wins. Non-empty `bytecode` wins when script source
/// is empty or absent. A present empty script source is preserved for JavaScript.
pub(super) fn script_text(result: &Value) -> Result<&str> {
    let source = result.get("scriptSource").and_then(Value::as_str);
    if let Some(source) = source.filter(|text| !text.is_empty()) {
        return Ok(source);
    }
    if let Some(bytecode) = result
        .get("bytecode")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        return Ok(bytecode);
    }
    source.ok_or_else(|| Error::protocol("Debugger returned malformed script source"))
}

fn decode_bytecode(value: &Value) -> Option<Vec<u8>> {
    let text = value.as_str().filter(|text| !text.is_empty())?;
    let bytes = STANDARD
        .decode(text)
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .ok()?;
    if bytes.is_empty() { None } else { Some(bytes) }
}

fn json_escape(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                let code = other as u32;
                output.push_str(&format!("\\u{code:04x}"));
            }
            other => output.push(other),
        }
    }
    output
}

fn manifest_line(fields: &ManifestFields<'_>) -> Result<String> {
    let sensitive = if fields.sensitive { "true" } else { "false" };
    let line = format!(
        "{{\"protocol_version\":1,\"artifact_id\":\"{artifact_id}\",\"session_id\":\"{session_id}\",\"navigation_id\":\"{navigation_id}\",\"frame_id\":\"{frame_id}\",\"parent_artifact_id\":\"{parent_artifact_id}\",\"creator_event_id\":\"{creator_event_id}\",\"execution_context_id\":\"{execution_context_id}\",\"capture_origin\":\"{capture_origin}\",\"kind\":\"{kind}\",\"url\":\"{url}\",\"mime_type\":\"{mime_type}\",\"byte_size\":{byte_size},\"sha256\":\"{sha256}\",\"sensitive\":{sensitive},\"content_path\":\"blobs/{sha256}.bin\"}}",
        artifact_id = fields.artifact_id,
        session_id = fields.session_id,
        navigation_id = fields.navigation_id,
        frame_id = fields.frame_id,
        parent_artifact_id = fields.parent_artifact_id,
        creator_event_id = fields.creator_event_id,
        execution_context_id = fields.execution_context_id,
        capture_origin = fields.capture_origin,
        kind = fields.kind,
        url = json_escape(fields.url),
        mime_type = json_escape(fields.mime_type),
        byte_size = fields.byte_size,
        sha256 = fields.sha256,
        sensitive = sensitive,
    );
    if line.len() > MANIFEST_LINE_LIMIT {
        return Err(Error::conflict(
            "WebAssembly artifact URL exceeds the manifest line limit",
        ));
    }
    let mut parsed: Value =
        serde_json::from_str(&line).map_err(|_| Error::conflict("Artifact record is malformed"))?;
    evidence::validate_artifact(&mut parsed)
        .map_err(|_| Error::conflict("Artifact record is malformed"))?;
    Ok(line)
}

fn resolve_session_id(options: &crate::config::Options, records: &[Value]) -> Result<u64> {
    if let Some(id) = options.capture_session_id {
        if id == 0 {
            return Err(Error::conflict(
                "WebAssembly artifact capture has no session ID",
            ));
        }
        return Ok(id);
    }
    if let Some(name) = options
        .artifacts
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        && let Ok(id) = validation::canonical(&json!(name), 64, true, "Session ID")
    {
        return Ok(id);
    }
    for record in records {
        if let Ok(id) = validation::canonical(&record["session_id"], 64, true, "Session ID") {
            return Ok(id);
        }
    }
    Err(Error::conflict(
        "WebAssembly artifact capture has no session ID",
    ))
}

fn preflight(script: &Value) -> Result<()> {
    let url = script["url"].as_str().unwrap_or("");
    if url.is_empty() {
        return Err(Error::conflict("WebAssembly script URL is empty"));
    }
    if url.len() > MAX_URL_BYTES {
        return Err(Error::conflict(
            "WebAssembly script URL exceeds the artifact limit",
        ));
    }
    if script["execution_context_id"].as_u64().unwrap_or(0) == 0 {
        return Err(Error::conflict(
            "WebAssembly script has no execution context",
        ));
    }
    if script["length"]
        .as_u64()
        .is_some_and(|length| length > MAX_WASM_BYTES as u64)
    {
        return Err(Error::conflict(
            "WebAssembly module exceeds the 16 MiB artifact limit",
        ));
    }
    Ok(())
}

fn bounded_module(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.len() > MAX_WASM_BYTES {
        Err(Error::conflict(
            "WebAssembly module exceeds the 16 MiB artifact limit",
        ))
    } else {
        Ok(bytes)
    }
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn read_manifest(root: &Path) -> Result<Vec<Value>> {
    let file = match File::open(root.join("manifest.jsonl")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut reader = BufReader::new(file);
    let mut records = Vec::new();
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if line.len() > MANIFEST_LINE_LIMIT {
            return Err(Error::conflict(
                "Artifact manifest contains an oversized record",
            ));
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| Error::conflict("Artifact manifest contains a malformed record"))?;
        let mut value: Value = serde_json::from_str(text)
            .map_err(|_| Error::conflict("Artifact manifest contains a malformed record"))?;
        evidence::validate_artifact(&mut value)
            .map_err(|_| Error::conflict("Artifact manifest contains a malformed record"))?;
        records.push(value);
    }
    Ok(records)
}

fn publish_blob(root: &Path, hash: &str, bytes: &[u8]) -> Result<()> {
    let blobs = root.join("blobs");
    ensure_private_dir(&blobs)?;
    let final_path = blobs.join(format!("{hash}.bin"));
    if final_path.is_file() {
        return Ok(());
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = blobs.join(format!(".{hash}.{}.{nanos}.tmp", std::process::id()));
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match fs::hard_link(&temporary, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists || final_path.is_file() => {
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
    }
    let _ = fs::remove_file(&temporary);
    Ok(())
}

fn append_manifest_line(root: &Path, line: &str) -> Result<()> {
    ensure_private_dir(root)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(root.join("manifest.jsonl"))?;
    let mut payload = Vec::with_capacity(line.len() + 1);
    payload.extend_from_slice(line.as_bytes());
    payload.push(b'\n');
    write_one(&mut file, &payload)?;
    file.sync_all()?;
    Ok(())
}

fn write_one(file: &mut File, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        loop {
            let written =
                unsafe { libc::write(file.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
            if written < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            let Ok(written) = usize::try_from(written) else {
                return Err(Error::conflict("Artifact manifest line was short-written"));
            };
            if written != bytes.len() {
                return Err(Error::conflict("Artifact manifest line was short-written"));
            }
            return Ok(());
        }
    }
    #[cfg(not(unix))]
    {
        file.write_all(bytes)?;
        Ok(())
    }
}

#[cfg(test)]
fn commit_record(root: &Path, fields: &ManifestFields<'_>, bytes: &[u8]) -> Result<()> {
    let line = manifest_line(fields)?;
    publish_blob(root, fields.sha256, bytes)?;
    append_manifest_line(root, &line)
}

fn wasm_source_body(id: &str, bytes: &[u8]) -> Value {
    let encoded = STANDARD.encode(bytes);
    let (source, truncated) = if encoded.len() <= SOURCE_LIMIT {
        (encoded, false)
    } else {
        let end = (SOURCE_LIMIT / 4) * 4;
        (encoded[..end].to_owned(), true)
    };
    json!({
        "protocol_version": 1,
        "script_id": id,
        "source": source,
        "truncated": truncated,
        "encoding": "base64",
        "byte_size": bytes.len(),
    })
}

impl Debugger {
    pub(super) fn on_script_parsed(self: &Arc<Self>, params: &Value) {
        if let Some(script) = super::parse::script(params) {
            let wasm = is_wasm_script(&script).then(|| script.clone());
            self.update(|state| {
                self.hooks
                    .candidate_source_changed(state["target"]["id"].as_str().unwrap_or(""));
                let scripts = state["scripts"].as_array_mut().unwrap();
                scripts.retain(|entry| entry["script_id"] != script["script_id"]);
                if scripts.len() >= 5000 {
                    self.hooks
                        .candidate_catalog_incomplete
                        .store(true, Ordering::Release);
                    scripts.remove(0);
                }
                scripts.push(script);
            });
            if let Some(script) = wasm {
                self.schedule_wasm_capture(script);
            }
        } else {
            self.hooks
                .candidate_catalog_incomplete
                .store(true, Ordering::Release);
            self.hooks.candidate_epoch.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(super) fn schedule_wasm_capture(self: &Arc<Self>, script: Value) {
        if !is_wasm_script(&script) {
            return;
        }
        self.note_capture("attempted", None);
        let debugger = Arc::clone(self);
        tokio::spawn(async move {
            let _ = debugger.ensure_wasm(&script).await;
        });
    }

    pub(super) async fn wasm_source(&self, id: &str, script: &Value) -> Result<Value> {
        let bytes = self.ensure_wasm(script).await?;
        if bytes.is_empty() {
            return Err(Error::protocol(
                "Debugger returned empty WebAssembly bytecode",
            ));
        }
        Ok(wasm_source_body(id, &bytes))
    }

    async fn ensure_wasm(&self, script: &Value) -> Result<Arc<Vec<u8>>> {
        let _gate = self.wasm.gate.lock().await;
        let id = script["script_id"].as_str().unwrap_or("");
        if id.is_empty() {
            return Err(Error::conflict("WebAssembly script is unavailable"));
        }
        let cached = {
            let cache = self
                .wasm
                .cache
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            cache.get(id).cloned()
        };
        let bytes = if let Some(bytes) = cached {
            bytes
        } else {
            let fetched = match self.fetch_wasm(script).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.note_capture("failed", Some(error.message.clone()));
                    return Err(error);
                }
            };
            let bytes = Arc::new(fetched);
            self.remember(id, Arc::clone(&bytes));
            bytes
        };
        let retained = {
            let _store = self
                .wasm
                .store
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            self.retain(script, &bytes)
        };
        match retained {
            Ok(true) => self.note_capture("retained", None),
            Ok(false) => {}
            Err(error) => self.note_capture("failed", Some(error.message)),
        }
        Ok(bytes)
    }

    fn remember(&self, id: &str, bytes: Arc<Vec<u8>>) {
        let mut cache = self
            .wasm
            .cache
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        cache.insert(id.to_owned(), bytes);
        while cache.len() > CACHE_ENTRIES
            || cache.values().map(|entry| entry.len()).sum::<usize>() > CACHE_BYTES
        {
            let Some(oldest) = cache.keys().next().cloned() else {
                break;
            };
            cache.remove(&oldest);
        }
    }

    async fn fetch_wasm(&self, script: &Value) -> Result<Vec<u8>> {
        preflight(script)?;
        let target = script
            .get("target_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| self.snapshot()["target"]["id"].as_str().map(str::to_owned))
            .ok_or_else(|| {
                Error::conflict("Debugger target is unavailable").with_code(Code::TargetUnavailable)
            })?;
        let cdp_id = script
            .get("cdp_script_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .or_else(|| script["script_id"].as_str())
            .unwrap_or("");
        if cdp_id.is_empty() {
            return Err(Error::conflict("WebAssembly script is unavailable"));
        }
        let session = self.hook_session(&target).await?;
        let params = json!({"scriptId": cdp_id});
        let deadline = Duration::from_secs(15);
        let first = session
            .command("Debugger.getScriptSource", params.clone(), deadline)
            .await;
        if let Ok(result) = &first
            && let Some(bytes) = decode_bytecode(&result["bytecode"])
        {
            return bounded_module(bytes);
        }
        match session
            .command("Debugger.getWasmBytecode", params, deadline)
            .await
        {
            Ok(result) => decode_bytecode(&result["bytecode"])
                .map(bounded_module)
                .unwrap_or_else(|| {
                    Err(Error::protocol(
                        "Debugger returned empty WebAssembly bytecode",
                    ))
                }),
            Err(error) => {
                let detail = match &first {
                    Err(first_error) => format!(
                        "Debugger.getScriptSource failed: {first_error}; Debugger.getWasmBytecode failed: {error}"
                    ),
                    Ok(_) => format!("Debugger.getWasmBytecode failed: {error}"),
                };
                Err(Error::protocol(detail))
            }
        }
    }

    fn retain(&self, script: &Value, bytes: &[u8]) -> Result<bool> {
        preflight(script)?;
        if bytes.is_empty() || bytes.len() > MAX_WASM_BYTES {
            return Err(Error::conflict(
                "WebAssembly module exceeds the 16 MiB artifact limit",
            ));
        }
        let url = script["url"].as_str().unwrap_or("");
        let context = script["execution_context_id"].as_u64().unwrap_or(0);
        let root = &self.options.artifacts;
        ensure_private_dir(root)?;
        let records = read_manifest(root)?;
        let session_id = resolve_session_id(&self.options, &records)?;
        let hash = hex::encode(Sha256::digest(bytes));
        if records.iter().any(|record| {
            record["kind"] == "wasm" && record["url"] == url && record["sha256"] == hash
        }) {
            publish_blob(root, &hash, bytes)?;
            return Ok(false);
        }
        if records
            .iter()
            .filter(|record| record["capture_origin"] == "webassembly_compile")
            .count()
            >= MAX_MODULES
        {
            return Err(Error::conflict("WebAssembly artifact limit reached"));
        }
        let max_id = records
            .iter()
            .filter_map(|record| {
                validation::canonical(&record["artifact_id"], 64, false, "Identifier").ok()
            })
            .max()
            .unwrap_or(0);
        if max_id == u64::MAX {
            return Err(Error::conflict(
                "WebAssembly artifact ID space is exhausted",
            ));
        }
        let mut next = self.wasm.next_id.load(Ordering::Relaxed).max(ID_FLOOR);
        if max_id + 1 > next {
            next = max_id + 1;
        }
        self.wasm
            .next_id
            .store(next.saturating_add(1), Ordering::Relaxed);
        let line = manifest_line(&ManifestFields {
            artifact_id: next,
            session_id,
            navigation_id: 0,
            frame_id: 0,
            parent_artifact_id: 0,
            creator_event_id: 0,
            execution_context_id: context,
            capture_origin: "webassembly_compile",
            kind: "wasm",
            url,
            mime_type: "application/wasm",
            byte_size: bytes.len() as u64,
            sha256: &hash,
            sensitive: false,
        })?;
        publish_blob(root, &hash, bytes)?;
        append_manifest_line(root, &line)?;
        Ok(true)
    }

    fn note_capture(&self, field: &str, error: Option<String>) {
        self.update(|state| {
            let count = state["wasm_capture"][field]
                .as_u64()
                .unwrap_or(0)
                .saturating_add(1);
            state["wasm_capture"][field] = json!(count);
            if let Some(error) = error {
                state["wasm_capture"]["last_error"] = json!(validation::truncate(&error, 512));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Options;
    use base64::Engine;
    use clap::Parser;
    use std::path::PathBuf;

    fn br_table_bytes() -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/fixtures/vm-dynamic-debug/wasm-dispatch.json");
        let fixtures: Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        hex::decode(fixtures["br_table"].as_str().unwrap()).unwrap()
    }

    fn seed_strings(root: &Path, session_id: u64) {
        let bytes = b"window.__rebStrings = {title: 'New Tab'};\n";
        let hash = hex::encode(Sha256::digest(bytes));
        commit_record(
            root,
            &ManifestFields {
                artifact_id: 7,
                session_id,
                navigation_id: 0,
                frame_id: 0,
                parent_artifact_id: 0,
                creator_event_id: 0,
                execution_context_id: 0,
                capture_origin: "network_response",
                kind: "javascript",
                url: "chrome://newtab/strings.js",
                mime_type: "text/javascript",
                byte_size: bytes.len() as u64,
                sha256: &hash,
                sensitive: false,
            },
            bytes,
        )
        .unwrap();
    }

    #[test]
    fn empty_script_source_prefers_bytecode() {
        let with_bytecode = json!({"scriptSource": "", "bytecode": "AGFzbQ=="});
        assert_eq!(script_text(&with_bytecode).unwrap(), "AGFzbQ==");
        let absent = json!({"bytecode": "AGFzbQ=="});
        assert_eq!(script_text(&absent).unwrap(), "AGFzbQ==");
        let javascript = json!({"scriptSource": "function f(){}", "bytecode": "AGFzbQ=="});
        assert_eq!(script_text(&javascript).unwrap(), "function f(){}");
        assert_eq!(script_text(&json!({"scriptSource": ""})).unwrap(), "");
        assert!(script_text(&json!({})).is_err());
        let bytes = decode_bytecode(&json!("AGFzbQ==")).unwrap();
        assert_eq!(bytes, b"\0asm");
    }

    #[test]
    fn session_id_and_quoted_url_round_trip() {
        let records = vec![json!({"session_id": "15"})];
        let mut options = Options::parse_from(["test"]);
        options.capture_session_id = Some(42);
        options.artifacts = PathBuf::from("/tmp/sessions/artifacts");
        assert_eq!(resolve_session_id(&options, &records).unwrap(), 42);
        options.capture_session_id = Some(0);
        assert!(resolve_session_id(&options, &records).is_err());
        options.capture_session_id = None;
        options.artifacts = PathBuf::from("/tmp/live/42/artifacts");
        assert_eq!(resolve_session_id(&options, &[]).unwrap(), 42);
        options.artifacts = PathBuf::from("/tmp/live/042/artifacts");
        assert_eq!(resolve_session_id(&options, &records).unwrap(), 15);
        options.artifacts = PathBuf::from("/tmp/live/sessions/artifacts");
        assert_eq!(resolve_session_id(&options, &records).unwrap(), 15);
        assert!(resolve_session_id(&options, &[]).is_err());

        let bytes = b"\0asm";
        let hash = hex::encode(Sha256::digest(bytes));
        let line = manifest_line(&ManifestFields {
            artifact_id: ID_FLOOR,
            session_id: 42,
            navigation_id: 0,
            frame_id: 0,
            parent_artifact_id: 0,
            creator_event_id: 0,
            execution_context_id: 3,
            capture_origin: "webassembly_compile",
            kind: "wasm",
            url: "wasm://wasm/ab\"cd",
            mime_type: "application/wasm",
            byte_size: bytes.len() as u64,
            sha256: &hash,
            sensitive: false,
        })
        .unwrap();
        assert!(line.contains("ab\\\"cd"));
        let mut parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["url"], "wasm://wasm/ab\"cd");
        evidence::validate_artifact(&mut parsed).unwrap();
    }

    #[cfg(unix)]
    async fn harness(fallback: bool) -> (tempfile::TempDir, Arc<Debugger>, Vec<u8>) {
        use std::os::unix::fs::PermissionsExt;
        let bytes = br_table_bytes();
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        fs::create_dir_all(&artifacts).unwrap();
        seed_strings(&artifacts, 42);
        std::fs::write(dir.path().join("bytecode"), STANDARD.encode(&bytes)).unwrap();
        std::fs::write(dir.path().join("javascript"), "function f(){return 1;}\n").unwrap();
        if fallback {
            std::fs::write(dir.path().join("fallback"), "1").unwrap();
        }
        let interpreter = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("python3"))
            .find(|path| crate::worker::executable(path))
            .expect("python3")
            .canonicalize()
            .unwrap();
        let python = r#"import sys,json,struct,pathlib
root=pathlib.Path(__file__).parent
inp=sys.stdin.buffer; out=sys.stdout.buffer
def emit(v):
 b=b'' if v is None else json.dumps(v).encode();out.write(b'REB\x01'+struct.pack('>I',len(b))+b);out.flush()
emit(None)
while True:
 h=inp.read(8)
 if not h:break
 q=json.loads(inp.read(struct.unpack('>I',h[4:])[0]));m=q['method'];sid=q.get('params',{}).get('scriptId')
 with (root/'commands').open('a') as log:log.write(json.dumps(q)+'\n')
 r={}
 if m=='Debugger.getScriptSource':
  if sid=='25' and not (root/'fallback').exists() and (root/'bytecode').exists():
   r={'scriptSource':'','bytecode':(root/'bytecode').read_text()}
  elif sid=='js':
   r={'scriptSource':(root/'javascript').read_text()}
  elif sid=='empty-js':
   r={'scriptSource':'','bytecode':'Ynl0ZWNvZGU='}
  else:
   r={'scriptSource':''}
 if m=='Debugger.getWasmBytecode' and (root/'fallback').exists():
  r={'bytecode':(root/'bytecode').read_text()}
 emit({'id':q['id'],'result':r})
"#;
        let source = dir.path().join("transport.py");
        let transport = dir.path().join("transport");
        std::fs::write(&source, python).unwrap();
        let quote = |path: &Path| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
        std::fs::write(
            &transport,
            format!(
                "#!/bin/sh\nexec {} {} \"$@\"\n",
                quote(&interpreter),
                quote(&source)
            ),
        )
        .unwrap();
        std::fs::set_permissions(&transport, fs::Permissions::from_mode(0o700)).unwrap();
        let mut options = Options::parse_from(["test"]);
        options.artifacts = artifacts;
        options.capture_session_id = Some(42);
        let debugger = Debugger::new(&options);
        let (connection, _events) =
            super::super::connection::Connection::open(&transport, "ws://127.0.0.1:1")
                .await
                .unwrap();
        *debugger.connection.lock().await = Some(connection);
        debugger.update(|state| {
            state["state"] = json!("running");
            state["target"] = json!({"id": "page"});
        });
        (dir, debugger, bytes)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wasm_script_parsed_retains_artifact_and_exports_bytecode() {
        let (dir, debugger, bytes) = harness(false).await;
        let javascript = std::fs::read_to_string(dir.path().join("javascript")).unwrap();
        debugger
            .event(json!({"method":"Debugger.scriptParsed","params":{
                "scriptId":"25","url":"wasm://wasm/003d9df6","scriptLanguage":"WebAssembly",
                "executionContextId":3,"length":bytes.len()
            }}))
            .await;
        debugger
            .event(json!({"method":"Debugger.scriptParsed","params":{
                "scriptId":"js","url":"https://example.test/app.js","scriptLanguage":"JavaScript",
                "executionContextId":3,"length":javascript.len()
            }}))
            .await;
        debugger
            .event(json!({"method":"Debugger.scriptParsed","params":{
                "scriptId":"empty-js","url":"https://example.test/empty.js","scriptLanguage":"JavaScript",
                "executionContextId":3,"length":12
            }}))
            .await;
        let wasm = debugger.source("25").await.unwrap();
        assert_eq!(wasm["protocol_version"], 1);
        assert_eq!(wasm["script_id"], "25");
        assert_eq!(wasm["encoding"], "base64");
        assert_eq!(wasm["truncated"], false);
        assert_eq!(wasm["byte_size"], bytes.len());
        assert_eq!(
            STANDARD.decode(wasm["source"].as_str().unwrap()).unwrap(),
            bytes
        );
        let js = debugger.source("js").await.unwrap();
        assert_eq!(js["source"], javascript);
        assert!(js["encoding"].is_null());
        let empty = debugger.source("empty-js").await.unwrap();
        assert_eq!(empty["source"], "Ynl0ZWNvZGU=");
        assert!(empty["encoding"].is_null());
        debugger
            .event(json!({"method":"Debugger.scriptParsed","params":{
                "scriptId":"25","url":"wasm://wasm/003d9df6","scriptLanguage":"WebAssembly",
                "executionContextId":3,"length":bytes.len()
            }}))
            .await;
        let _ = debugger.source("25").await.unwrap();
        let artifacts = dir.path().join("artifacts");
        let records = evidence::artifacts(&artifacts, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["kind"], "javascript");
        assert_eq!(records[0]["artifact_id"], "7");
        assert_eq!(records[0]["url"], "chrome://newtab/strings.js");
        assert_eq!(records[0]["capture_origin"], "network_response");
        assert_eq!(
            evidence::content(&artifacts, &records[0], 1024).unwrap(),
            b"window.__rebStrings = {title: 'New Tab'};\n"
        );
        let wasm_record = &records[1];
        assert_eq!(wasm_record["kind"], "wasm");
        assert_eq!(wasm_record["capture_origin"], "webassembly_compile");
        assert_eq!(wasm_record["url"], "wasm://wasm/003d9df6");
        assert_eq!(wasm_record["mime_type"], "application/wasm");
        assert_eq!(wasm_record["execution_context_id"], "3");
        assert_eq!(wasm_record["sensitive"], false);
        assert_eq!(wasm_record["byte_size"], bytes.len());
        let artifact_id = wasm_record["artifact_id"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert!(artifact_id >= ID_FLOOR);
        assert_eq!(
            evidence::content(&artifacts, wasm_record, MAX_WASM_BYTES).unwrap(),
            bytes
        );
        let snapshot = debugger.snapshot();
        assert_eq!(snapshot["wasm_capture"]["attempted"], 2);
        assert_eq!(snapshot["wasm_capture"]["retained"], 1);
        assert_eq!(snapshot["wasm_capture"]["failed"], 0);
        assert!(snapshot["error"].is_null());
        let events = dir.path().join("events.jsonl");
        let documents = crate::vm::store_documents(&artifacts, &events).unwrap();
        let results = documents.analysis["results"].as_array().unwrap();
        assert!(
            results.iter().any(|result| {
                result["runtime"] == "javascript" && result["artifact_id"] == "7"
            })
        );
        let wasm_result = results
            .iter()
            .find(|result| result["runtime"] == "webassembly")
            .unwrap();
        assert_eq!(wasm_result["tier"], "likely-vm");
        assert_eq!(wasm_result["artifact_id"], wasm_record["artifact_id"]);
        assert!(
            documents.analysis["summary"]["likely_vm_count"]
                .as_u64()
                .unwrap()
                >= 1
        );
        let workspace = documents.opcode_workspace.expect("opcode workspace");
        assert_eq!(workspace["summary"]["workspace_count"], 1);
        assert_eq!(workspace["workspaces"][0]["runtime"], "webassembly");
        assert_eq!(
            workspace["workspaces"][0]["interpreter_artifact_id"],
            wasm_record["artifact_id"]
        );
        assert_ne!(workspace["workspaces"][0]["interpreter_artifact_id"], "7");
        documents.host_links.expect("host links");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wasm_bytecode_falls_back_to_get_wasm_bytecode() {
        let (dir, debugger, bytes) = harness(true).await;
        debugger
            .event(json!({"method":"Debugger.scriptParsed","params":{
                "scriptId":"25","url":"wasm://wasm/003d9df6","scriptLanguage":"WebAssembly",
                "executionContextId":3,"length":bytes.len()
            }}))
            .await;
        let wasm = debugger.source("25").await.unwrap();
        assert_eq!(
            STANDARD.decode(wasm["source"].as_str().unwrap()).unwrap(),
            bytes
        );
        assert_eq!(wasm["encoding"], "base64");
        let commands = std::fs::read_to_string(dir.path().join("commands")).unwrap();
        assert!(commands.contains("getScriptSource"));
        assert!(commands.contains("getWasmBytecode"));
        let records = evidence::artifacts(&dir.path().join("artifacts"), 10).unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|record| record["kind"] == "wasm")
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["kind"] == "javascript")
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_bytecode_is_an_error_and_context_zero_writes_nothing() {
        let (dir, debugger, _bytes) = harness(false).await;
        std::fs::remove_file(dir.path().join("bytecode")).unwrap();
        debugger
            .event(json!({"method":"Debugger.scriptParsed","params":{
                "scriptId":"25","url":"wasm://wasm/003d9df6","scriptLanguage":"WebAssembly",
                "executionContextId":3,"length":8
            }}))
            .await;
        let error = debugger.source("25").await.unwrap_err();
        assert!(
            error.message.contains("empty WebAssembly bytecode")
                || error.message.contains("getWasmBytecode")
        );
        let records = evidence::artifacts(&dir.path().join("artifacts"), 10).unwrap();
        assert!(records.iter().all(|record| record["kind"] != "wasm"));

        let dir = tempfile::tempdir().unwrap();
        let mut options = Options::parse_from(["test"]);
        options.artifacts = dir.path().join("artifacts");
        options.capture_session_id = Some(42);
        let debugger = Debugger::new(&options);
        debugger
            .event(json!({"method":"Debugger.scriptParsed","params":{
                "scriptId":"25","url":"wasm://wasm/003d9df6","scriptLanguage":"WebAssembly",
                "length":8
            }}))
            .await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if debugger.snapshot()["wasm_capture"]["failed"]
                    .as_u64()
                    .unwrap_or(0)
                    >= 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("context-free wasm capture should fail visibly");
        let snapshot = debugger.snapshot();
        assert!(
            snapshot["wasm_capture"]["last_error"]
                .as_str()
                .unwrap_or("")
                .contains("execution context")
        );
        assert!(!dir.path().join("artifacts/manifest.jsonl").exists());
        assert!(snapshot["error"].is_null());
    }
}
