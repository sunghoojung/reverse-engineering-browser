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

/// Strict, cooperative stopped-store reads used only by metadata package export.
/// Configured roots may resolve symlinks once; every descendant is opened
/// relative to a pinned directory, without following a symlink.
#[cfg(unix)]
pub(crate) mod frozen {
    use crate::error::{Code, Error, Result};
    use sha2::{Digest, Sha256};
    use std::{
        ffi::{CString, OsStr},
        fs::{File, Metadata},
        io::{BufRead, BufReader, Read},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Path, PathBuf},
        time::Instant,
    };

    pub const GUARD_MARKER: &[u8] = b"REB_EVIDENCE_GUARD_V1\n";
    pub const MAX_BLOB_BYTES: u64 = 16 * 1024 * 1024;
    pub const MAX_VERIFIED_BYTES: u64 = 128 * 1024 * 1024;
    pub fn verified_total(total: u64, next: u64) -> Result<u64> {
        if next > MAX_BLOB_BYTES {
            return Err(limit());
        }
        total
            .checked_add(next)
            .filter(|n| *n <= MAX_VERIFIED_BYTES)
            .ok_or_else(limit)
    }
    pub fn unavailable() -> Error {
        Error::new(
            503,
            "The requested store lacks a supported safe evidence guard or source",
        )
        .with_code(Code::DependencyUnavailable)
    }
    pub fn changed() -> Error {
        Error::conflict("The evidence source changed during export")
    }
    pub fn limit() -> Error {
        Error::new(413, "The evidence export exceeds a resource limit")
            .with_code(Code::ResourceLimit)
    }
    pub fn check(deadline: Instant) -> Result<()> {
        if Instant::now() >= deadline {
            Err(Error::new(408, "The evidence export exceeded its deadline")
                .with_code(Code::Timeout))
        } else {
            Ok(())
        }
    }
    fn name(value: &OsStr) -> Result<CString> {
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
            return Err(unavailable());
        }
        CString::new(bytes).map_err(|_| unavailable())
    }
    fn open_at(parent: &File, name: &CString, flags: i32) -> Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(unavailable());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn safe(metadata: &Metadata, directory: bool) -> bool {
        metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.nlink() == 1
            }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Stamp {
        dev: u64,
        ino: u64,
        size: u64,
        mtime: i64,
        mtime_ns: i64,
        ctime: i64,
        ctime_ns: i64,
    }
    impl Stamp {
        fn of(metadata: &Metadata) -> Self {
            Self {
                dev: metadata.dev(),
                ino: metadata.ino(),
                size: metadata.len(),
                mtime: metadata.mtime(),
                mtime_ns: metadata.mtime_nsec(),
                ctime: metadata.ctime(),
                ctime_ns: metadata.ctime_nsec(),
            }
        }
    }
    fn entry_matches(directory: &File, name: &CString, stamp: Stamp) -> Result<()> {
        // Opening O_NONBLOCK before checking type cannot hang on a FIFO.
        let entry = open_at(directory, name, libc::O_RDONLY).map_err(|_| changed())?;
        if Stamp::of(&entry.metadata().map_err(|_| changed())?) != stamp {
            return Err(changed());
        }
        Ok(())
    }
    pub struct Directory {
        file: File,
        stamp: Stamp,
        parent: File,
        name: CString,
        configured: Option<PathBuf>,
    }
    impl Directory {
        fn root(path: &Path) -> Result<Self> {
            let resolved = path.canonicalize().map_err(|_| unavailable())?;
            let parent_path = resolved.parent().ok_or_else(unavailable)?;
            let entry = name(resolved.file_name().ok_or_else(unavailable)?)?;
            use std::os::unix::fs::OpenOptionsExt;
            let parent = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(parent_path)
                .map_err(|_| unavailable())?;
            Self::open(parent, entry, Some(path.to_owned()))
        }
        fn open(parent: File, name: CString, configured: Option<PathBuf>) -> Result<Self> {
            let file = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let metadata = file.metadata().map_err(|_| unavailable())?;
            if !safe(&metadata, true) {
                return Err(unavailable());
            }
            Ok(Self {
                file,
                stamp: Stamp::of(&metadata),
                parent,
                name,
                configured,
            })
        }
        pub fn child(&self, basename: &str) -> Result<Self> {
            Self::open(
                self.file.try_clone().map_err(|_| unavailable())?,
                name(OsStr::new(basename))?,
                None,
            )
        }
        pub fn file(&self, basename: &str, writable: bool) -> Result<PinnedFile> {
            let name = name(OsStr::new(basename))?;
            let file = open_at(
                &self.file,
                &name,
                if writable {
                    libc::O_RDWR
                } else {
                    libc::O_RDONLY
                },
            )?;
            let metadata = file.metadata().map_err(|_| unavailable())?;
            if !safe(&metadata, false) {
                return Err(unavailable());
            }
            Ok(PinnedFile {
                file,
                stamp: Stamp::of(&metadata),
                parent: self.file.try_clone().map_err(|_| unavailable())?,
                name,
            })
        }
        pub fn verify(&self) -> Result<()> {
            let metadata = self.file.metadata().map_err(|_| changed())?;
            if !safe(&metadata, true) || Stamp::of(&metadata) != self.stamp {
                return Err(changed());
            }
            entry_matches(&self.parent, &self.name, self.stamp)?;
            // Detect replacement of the configured root or a configured symlink
            // as well as its anchored entry. No evidence is read through it.
            if let Some(path) = &self.configured
                && Stamp::of(&std::fs::metadata(path).map_err(|_| changed())?) != self.stamp
            {
                return Err(changed());
            }
            Ok(())
        }
    }
    pub struct PinnedFile {
        file: File,
        stamp: Stamp,
        parent: File,
        name: CString,
    }
    impl PinnedFile {
        pub fn truncate(&self) -> Result<()> {
            self.verify()?;
            self.file.set_len(0).map_err(|_| unavailable())?;
            self.file.sync_all().map_err(|_| unavailable())?;
            Ok(())
        }
        pub fn verify(&self) -> Result<()> {
            let metadata = self.file.metadata().map_err(|_| changed())?;
            if !safe(&metadata, false) || Stamp::of(&metadata) != self.stamp {
                return Err(changed());
            }
            entry_matches(&self.parent, &self.name, self.stamp)
        }
        pub fn lines(
            &mut self,
            maximum: u64,
            max_line: usize,
            max_records: usize,
            deadline: Instant,
            mut accept: impl FnMut(&[u8]) -> Result<()>,
        ) -> Result<()> {
            check(deadline)?;
            if self.stamp.size > maximum {
                return Err(limit());
            }
            let mut reader = BufReader::with_capacity(64 * 1024, &mut self.file);
            let mut line = Vec::with_capacity(max_line.min(8192));
            let (mut total, mut records) = (0u64, 0usize);
            loop {
                check(deadline)?;
                line.clear();
                let count = reader
                    .by_ref()
                    .take(max_line as u64 + 1)
                    .read_until(b'\n', &mut line)
                    .map_err(|_| unavailable())?;
                if count == 0 {
                    break;
                }
                total = total.checked_add(count as u64).ok_or_else(limit)?;
                if count > max_line || total > maximum {
                    return Err(limit());
                }
                if total > self.stamp.size {
                    return Err(changed());
                }
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                records = records.checked_add(1).ok_or_else(limit)?;
                if records > max_records {
                    return Err(limit());
                }
                check(deadline)?;
                accept(&line)?;
            }
            if total != self.stamp.size {
                return Err(changed());
            }
            check(deadline)?;
            self.verify()
        }
        pub fn hash(
            &mut self,
            expected: u64,
            expected_hash: &str,
            deadline: Instant,
        ) -> Result<()> {
            check(deadline)?;
            if expected > MAX_BLOB_BYTES {
                return Err(limit());
            }
            if self.stamp.size != expected {
                return Err(Error::protocol(
                    "The selected artifact byte count or hash is inconsistent",
                ));
            }
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                check(deadline)?;
                let count = self.file.read(&mut buffer).map_err(|_| unavailable())?;
                if count == 0 {
                    break;
                }
                total = total.checked_add(count as u64).ok_or_else(limit)?;
                if total > expected {
                    return Err(changed());
                }
                hash.update(&buffer[..count]);
            }
            self.verify()?;
            check(deadline)?;
            if total != expected || hex::encode(hash.finalize()) != expected_hash {
                return Err(Error::protocol(
                    "The selected artifact byte count or hash is inconsistent",
                ));
            }
            Ok(())
        }
    }
    /// The held flock coordinates updated REB writers only. Kernel filesystem
    /// reads can still block; deadlines are cooperative, not a hard kill.
    pub struct Store {
        pub root: Directory,
        guard: PinnedFile,
    }
    impl Drop for Store {
        fn drop(&mut self) {
            // A concurrent fork can briefly inherit CLOEXEC descriptors before
            // exec. Explicitly release this owner's open-file-description lease
            // rather than making another request depend on that helper's exec.
            unsafe {
                libc::flock(self.guard.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
    impl Store {
        pub fn event(path: &Path, exclusive: bool) -> Result<(Self, String)> {
            let basename = path
                .file_name()
                .ok_or_else(unavailable)?
                .to_str()
                .ok_or_else(unavailable)?
                .to_owned();
            let root = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            Ok((
                Self::acquire(root, &format!("{basename}.reb-lock-v1"), exclusive)?,
                basename,
            ))
        }
        pub fn artifacts(path: &Path) -> Result<Self> {
            Self::acquire(path, "evidence.reb-lock-v1", false)
        }
        fn acquire(path: &Path, guard_name: &str, exclusive: bool) -> Result<Self> {
            let root = Directory::root(path)?;
            let mut guard = root.file(guard_name, false)?;
            if guard.file.metadata().map_err(|_| unavailable())?.mode() & 0o777 != 0o600
                || guard.stamp.size != GUARD_MARKER.len() as u64
            {
                return Err(unavailable());
            }
            let mode = if exclusive {
                libc::LOCK_EX
            } else {
                libc::LOCK_SH
            };
            if unsafe { libc::flock(guard.file.as_raw_fd(), mode | libc::LOCK_NB) } != 0 {
                let errno = std::io::Error::last_os_error().raw_os_error();
                return Err(
                    if errno == Some(libc::EWOULDBLOCK) || errno == Some(libc::EAGAIN) {
                        Error::conflict(
                            "Stop the relevant evidence writer before exporting or clearing evidence",
                        )
                    } else {
                        unavailable()
                    },
                );
            }
            let mut marker = [0u8; GUARD_MARKER.len()];
            guard
                .file
                .read_exact(&mut marker)
                .map_err(|_| unavailable())?;
            if marker != GUARD_MARKER {
                return Err(unavailable());
            }
            let store = Self { root, guard };
            store.verify()?;
            Ok(store)
        }
        pub fn verify(&self) -> Result<()> {
            self.guard.verify()?;
            self.root.verify()
        }
    }
}

/// Event clear participates in the same lifetime lease as both export and the
/// broker. Sidecars remain under that ownership until all truncations finish.
pub fn clear_stores(paths: &[std::path::PathBuf]) -> Result<()> {
    #[cfg(unix)]
    {
        let first = paths.first().ok_or_else(frozen::unavailable)?;
        let mut stores = Vec::new();
        for path in paths {
            if path == first || path.exists() {
                stores.push(frozen::Store::event(path, true)?);
            }
        }
        // Match every broker output guard, acquiring all before any truncation.
        let mut files = Vec::new();
        for (store, basename) in &stores {
            files.push(store.root.file(basename, true)?);
        }
        for (store, _) in &stores {
            store.verify()?;
        }
        for file in &files {
            file.verify()?;
        }
        for file in files {
            file.truncate()?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
        Err(
            Error::new(503, "Safe evidence clear is unsupported on this platform")
                .with_code(crate::error::Code::DependencyUnavailable),
        )
    }
}

#[cfg(all(test, unix))]
mod frozen_tests {
    use super::frozen::*;
    use std::{
        fs,
        io::Write,
        os::{
            fd::AsRawFd,
            unix::fs::{PermissionsExt, symlink},
        },
        sync::{Arc, Barrier},
        time::{Duration, Instant},
    };

    fn store() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("events.jsonl"), b"one\ntwo\n").unwrap();
        let guard = root.path().join("events.jsonl.reb-lock-v1");
        fs::write(&guard, GUARD_MARKER).unwrap();
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o600)).unwrap();
        root
    }
    #[test]
    fn frozen_read_leases_are_shared_and_clear_is_exclusive() {
        let root = store();
        let path = root.path().join("events.jsonl");
        let (first, _) = Store::event(&path, false).unwrap();
        let (second, _) = Store::event(&path, false).unwrap();
        assert_eq!(Store::event(&path, true).err().unwrap().status, 409);
        assert_eq!(
            super::clear_stores(&[path.clone()]).unwrap_err().status,
            409
        );
        assert_eq!(fs::read(&path).unwrap(), b"one\ntwo\n");
        drop(first);
        drop(second);
        let (exclusive, _) = Store::event(&path, true).unwrap();
        assert_eq!(Store::event(&path, false).err().unwrap().status, 409);
        drop(exclusive);
        super::clear_stores(&[path.clone()]).unwrap();
        assert!(fs::read(path).unwrap().is_empty());
    }
    #[test]
    fn frozen_guards_and_descendants_fail_closed() {
        let root = store();
        let path = root.path().join("events.jsonl");
        let guard = root.path().join("events.jsonl.reb-lock-v1");
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(Store::event(&path, false).err().unwrap().status, 503);
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&guard, root.path().join("guard-link")).unwrap();
        assert_eq!(Store::event(&path, false).err().unwrap().status, 503);
        fs::remove_file(root.path().join("guard-link")).unwrap();
        fs::remove_file(&guard).unwrap();
        symlink(&path, &guard).unwrap();
        assert_eq!(Store::event(&path, false).err().unwrap().status, 503);
        fs::remove_file(&guard).unwrap();
        assert_eq!(Store::event(&path, false).err().unwrap().status, 503);
        fs::write(&guard, GUARD_MARKER).unwrap();
        fs::set_permissions(&guard, fs::Permissions::from_mode(0o600)).unwrap();
        let (store, basename) = Store::event(&path, false).unwrap();
        fs::remove_file(&path).unwrap();
        symlink("/dev/null", &path).unwrap();
        assert_eq!(store.root.file(&basename, false).err().unwrap().status, 503);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(store.root.file(&basename, false).err().unwrap().status, 503);
        fs::remove_dir(&path).unwrap();
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert_eq!(store.root.file(&basename, false).err().unwrap().status, 503);
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"regular").unwrap();
        fs::hard_link(&path, root.path().join("hard")).unwrap();
        assert_eq!(store.root.file(&basename, false).err().unwrap().status, 503);
    }
    #[test]
    fn frozen_barriers_detect_noncooperating_changes_and_preserve_supported_writer_exclusion() {
        for mutation in [
            "append",
            "replace",
            "truncate",
            "same_size",
            "replace_guard",
            "replace_root",
        ] {
            let root = store();
            let path = root.path().join("events.jsonl");
            let (store, basename) = Store::event(&path, false).unwrap();
            let mut file = store.root.file(&basename, false).unwrap();
            let ready = Arc::new(Barrier::new(2));
            let finish = Arc::new(Barrier::new(2));
            let ready_child = ready.clone();
            let finish_child = finish.clone();
            let path_child = path.clone();
            let root_path = root.path().to_owned();
            let child = std::thread::spawn(move || {
                ready_child.wait();
                let guard = fs::File::open(root_path.join("events.jsonl.reb-lock-v1")).unwrap();
                assert_ne!(
                    unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                    0
                );
                match mutation {
                    "append" => {
                        fs::OpenOptions::new()
                            .append(true)
                            .open(&path_child)
                            .unwrap()
                            .write_all(b"three\n")
                            .unwrap();
                    }
                    "replace" => {
                        fs::write(root_path.join("new"), b"one\ntwo\n").unwrap();
                        fs::rename(root_path.join("new"), &path_child).unwrap();
                    }
                    "truncate" => {
                        fs::File::create(&path_child).unwrap();
                    }
                    "same_size" => {
                        let old = fs::metadata(&path_child).unwrap().modified().unwrap();
                        fs::write(&path_child, b"red\nblu\n").unwrap();
                        fs::File::open(&path_child)
                            .unwrap()
                            .set_times(fs::FileTimes::new().set_modified(old))
                            .unwrap();
                    }
                    "replace_guard" => {
                        fs::write(root_path.join("new"), GUARD_MARKER).unwrap();
                        fs::rename(
                            root_path.join("new"),
                            root_path.join("events.jsonl.reb-lock-v1"),
                        )
                        .unwrap();
                    }
                    "replace_root" => {
                        let old = root_path.with_extension("old");
                        fs::rename(&root_path, &old).unwrap();
                        fs::create_dir(&root_path).unwrap();
                        fs::write(root_path.join("old-root-location"), old.to_str().unwrap())
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
                finish_child.wait();
            });
            let mut first = true;
            let read = file.lines(
                1024,
                128,
                20,
                Instant::now() + Duration::from_secs(5),
                |_| {
                    if first {
                        first = false;
                        ready.wait();
                        finish.wait();
                    }
                    Ok(())
                },
            );
            child.join().unwrap();
            let result = read.and_then(|_| store.verify());
            assert_eq!(result.unwrap_err().status, 409, "{mutation}");
            if mutation == "replace_root" {
                let old = fs::read_to_string(root.path().join("old-root-location")).unwrap();
                fs::remove_dir_all(old).unwrap();
            }
        }
    }
    #[test]
    fn frozen_rows_hashes_and_deadlines_are_bounded() {
        use sha2::{Digest, Sha256};
        let root = store();
        let path = root.path().join("events.jsonl");
        let (store, basename) = Store::event(&path, false).unwrap();
        for (max, line, records, status) in [
            (7, 10, 10, 413),
            (8, 3, 10, 413),
            (8, 4, 1, 413),
            (8, 4, 2, 200),
        ] {
            let mut file = store.root.file(&basename, false).unwrap();
            let result = file.lines(
                max,
                line,
                records,
                Instant::now() + Duration::from_secs(5),
                |_| Ok(()),
            );
            assert_eq!(result.map(|_| 200).unwrap_or_else(|e| e.status), status);
        }
        let mut file = store.root.file(&basename, false).unwrap();
        assert_eq!(
            file.lines(8, 4, 2, Instant::now(), |_| Ok(()))
                .unwrap_err()
                .status,
            408
        );
        let hash = hex::encode(Sha256::digest(b"one\ntwo\n"));
        let mut file = store.root.file(&basename, false).unwrap();
        file.hash(8, &hash, Instant::now() + Duration::from_secs(5))
            .unwrap();
        let mut file = store.root.file(&basename, false).unwrap();
        assert_eq!(
            file.hash(7, &hash, Instant::now() + Duration::from_secs(5))
                .unwrap_err()
                .status,
            422
        );
        let mut file = store.root.file(&basename, false).unwrap();
        assert_eq!(
            file.hash(8, &"0".repeat(64), Instant::now() + Duration::from_secs(5))
                .unwrap_err()
                .status,
            422
        );
        let mut file = store.root.file(&basename, false).unwrap();
        assert_eq!(
            file.hash(
                MAX_BLOB_BYTES + 1,
                &hash,
                Instant::now() + Duration::from_secs(5)
            )
            .unwrap_err()
            .status,
            413
        );
    }
}
