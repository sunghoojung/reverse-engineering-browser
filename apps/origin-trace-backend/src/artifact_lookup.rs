//! Byte-verified metadata lookup acceleration; content integrity is never cached.
use crate::{
    error::{Error, Result},
    evidence,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::{File, Metadata},
    io::Read,
    path::Path,
    time::Instant,
};

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(PartialEq, Eq)]
struct Stamp {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
}
impl Stamp {
    fn of(metadata: &Metadata) -> Self {
        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            identity: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
            #[cfg(not(unix))]
            created: metadata.created().ok(),
        }
    }
    fn same_file(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.identity.0 == other.identity.0 && self.identity.1 == other.identity.1
        }
        #[cfg(not(unix))]
        {
            let _ = other;
            false
        }
    }
    fn verify(&self, path: &Path, file: &File) -> Result<()> {
        let current = path.symlink_metadata()?;
        if !current.is_file() || *self != Self::of(&current) || *self != Self::of(&file.metadata()?)
        {
            return Err(Error::new(500, "Artifact manifest changed during lookup"));
        }
        Ok(())
    }
}
struct Snapshot {
    stamp: Stamp,
    bytes: Vec<u8>,
    // Canonical unsigned IDs have one spelling. Offsets refer only to these bytes.
    offsets: HashMap<u64, (usize, usize)>,
}
pub struct ArtifactLookupCache {
    snapshot: Option<Snapshot>,
    // A false positive only forgoes indexing: complete streaming validation still
    // runs. Keep one hint, and recover caching after a shrink or replacement.
    noncacheable: Option<Stamp>,
    maximum_bytes: usize,
    maximum_records: usize,
    #[cfg(test)]
    parsed_records: usize,
    #[cfg(test)]
    read_bytes: usize,
}
impl Default for ArtifactLookupCache {
    fn default() -> Self {
        Self {
            snapshot: None,
            noncacheable: None,
            maximum_bytes: MAX_BYTES,
            maximum_records: MAX_RECORDS,
            #[cfg(test)]
            parsed_records: 0,
            #[cfg(test)]
            read_bytes: 0,
        }
    }
}
impl ArtifactLookupCache {
    #[cfg(test)]
    fn find(&mut self, root: &Path, id: &str) -> Result<Value> {
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        match self.find_until(root, id, deadline)? {
            Some(value) => Ok(value),
            None => evidence::find_artifact_until(root, id, deadline),
        }
    }
    /// None requests complete streaming validation after releasing the cache lock.
    pub fn find_until(
        &mut self,
        root: &Path,
        id: &str,
        deadline: Instant,
    ) -> Result<Option<Value>> {
        // Failures discard reuse authority; a partial index must never hide a bad row.
        let previous = self.snapshot.take();
        #[cfg(test)]
        {
            self.parsed_records = 0;
            self.read_bytes = 0;
        }
        let path = root.join("manifest.jsonl");
        let mut file = match evidence::regular_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(not_found()),
            Err(error) => return Err(error.into()),
        };
        let stamp = Stamp::of(&file.metadata()?);
        check_deadline(deadline)?;
        self.noncacheable = self
            .noncacheable
            .take()
            .filter(|hint| hint.same_file(&stamp) && stamp.length >= hint.length);
        if stamp.length > self.maximum_bytes as u64 || self.noncacheable.is_some() {
            drop(previous);
            return Ok(None);
        }
        let mut bytes = vec![0; stamp.length as usize];
        file.read_exact(&mut bytes)?;
        #[cfg(test)]
        {
            self.read_bytes = bytes.len();
        }
        stamp.verify(&path, &file)?;
        check_deadline(deadline)?;
        let mut offsets = HashMap::new();
        let mut position = 0;
        if let Some(old) = previous.filter(|old| {
            old.stamp.same_file(&stamp)
                && (old.bytes.is_empty() || old.bytes.last() == Some(&b'\n'))
                && bytes.starts_with(&old.bytes)
        }) {
            position = old.bytes.len();
            offsets = old.offsets;
        }
        // Decide fallback before parsing: a large noncacheable manifest must not
        // validate its first 100k records twice or monopolize the cache mutex.
        let remaining = self.maximum_records.saturating_sub(offsets.len());
        if bytes[position..]
            .split_inclusive(|byte| *byte == b'\n')
            .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
            .take(remaining + 1)
            .count()
            > remaining
        {
            self.noncacheable = Some(stamp);
            return Ok(None);
        }
        for line in bytes[position..].split_inclusive(|byte| *byte == b'\n') {
            check_deadline(deadline)?;
            let start = position;
            position += line.len();
            if line.len() > 8192 {
                return Err(Error::new(
                    500,
                    "The artifact manifest contains an oversized record",
                ));
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let value = parse(line)?;
            let key = value["artifact_id"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap();
            if offsets.insert(key, (start, position)).is_some() {
                return Err(Error::new(
                    500,
                    "The artifact manifest contains a duplicate artifact ID",
                ));
            }
            #[cfg(test)]
            {
                self.parsed_records += 1;
            }
        }
        check_deadline(deadline)?;
        stamp.verify(&path, &file)?;
        // Parse just the selected row into the existing public representation.
        let selected = id
            .parse::<u64>()
            .ok()
            .filter(|key| key.to_string() == id)
            .and_then(|key| offsets.get(&key))
            .map(|&(start, end)| parse(&bytes[start..end]))
            .transpose()?;
        self.snapshot = Some(Snapshot {
            stamp,
            bytes,
            offsets,
        });
        selected.map(Some).ok_or_else(not_found)
    }
}
fn parse(bytes: &[u8]) -> Result<Value> {
    let mut value = serde_json::from_slice(bytes)
        .map_err(|_| Error::new(500, "The artifact manifest contains malformed JSON"))?;
    evidence::validate_artifact(&mut value)?;
    Ok(value)
}
fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::new(
            408,
            "Artifact manifest read exceeded its deadline",
        ));
    }
    Ok(())
}
fn not_found() -> Error {
    Error::new(404, "Artifact not found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{fs, io::Write};

    fn record(id: u64) -> Vec<u8> {
        let hash = "a".repeat(64);
        let value = json!({"protocol_version":1,"artifact_id":id.to_string(),"session_id":"1",
            "navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0",
            "kind":"javascript","url":"https://synthetic.invalid/source.js","mime_type":"text/javascript",
            "byte_size":1,"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        format!("{value}\n").into_bytes()
    }
    fn compare(cache: &mut ArtifactLookupCache, root: &Path, id: &str) {
        match (cache.find(root, id), evidence::find_artifact(root, id)) {
            (Ok(cached), Ok(fresh)) => assert_eq!(cached, fresh),
            (Err(cached), Err(fresh)) => {
                assert_eq!(cached.status, fresh.status);
                assert_eq!(cached.message, fresh.message);
            }
            _ => panic!("cached and fresh manifest results differ"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn exact_byte_reuse_append_and_lifecycle_match_complete_scan() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        let mut bytes = [record(1), record(u64::MAX)].concat();
        fs::write(&path, &bytes).unwrap();
        let mut cache = ArtifactLookupCache::default();
        compare(&mut cache, root.path(), &u64::MAX.to_string());
        assert_eq!(cache.parsed_records, 2);
        compare(&mut cache, root.path(), "1");
        assert_eq!(cache.parsed_records, 0);
        compare(&mut cache, root.path(), "2"); // Missing selections may share validated bytes.
        assert_eq!(cache.parsed_records, 0);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&record(2))
            .unwrap();
        compare(&mut cache, root.path(), "2");
        assert_eq!(cache.parsed_records, 1);
        bytes.extend(record(2));
        // Same-size rewrite with restored mtime must not retain the old ID index.
        let modified = path.metadata().unwrap().modified().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"artifact_id\":\"1\"",
            "\"artifact_id\":\"3\"",
            1,
        );
        assert_eq!(text.len(), bytes.len());
        fs::write(&path, text).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        compare(&mut cache, root.path(), "3");
        assert_eq!(cache.parsed_records, 3);
        compare(&mut cache, root.path(), "1");
        let replacement = root.path().join("replacement");
        fs::write(&replacement, &bytes).unwrap();
        fs::rename(&replacement, &path).unwrap();
        compare(&mut cache, root.path(), "1");
        assert_eq!(cache.parsed_records, 3);
        fs::write(&path, record(1)).unwrap();
        compare(&mut cache, root.path(), "2");
        assert_eq!(cache.parsed_records, 1);
        fs::remove_file(&path).unwrap();
        compare(&mut cache, root.path(), "1");
        assert!(cache.snapshot.is_none());
        fs::write(&path, &bytes).unwrap();
        compare(&mut cache, root.path(), "1");
        assert_eq!(cache.parsed_records, 3);
    }

    #[test]
    fn incomplete_duplicate_malformed_and_oversized_tails_never_publish_partial_index() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        let mut cache = ArtifactLookupCache::default();
        for tail in [
            record(1),
            b"{\"protocol_version\":".to_vec(),
            b"{}\n".to_vec(),
            vec![b' '; 8193],
        ] {
            fs::write(&path, record(1)).unwrap();
            compare(&mut cache, root.path(), "1");
            fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&tail)
                .unwrap();
            compare(&mut cache, root.path(), "1");
            assert!(cache.snapshot.is_none());
        }
        let mut complete = record(1);
        complete.pop();
        fs::write(&path, &complete).unwrap();
        compare(&mut cache, root.path(), "1");
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[b"\n".to_vec(), record(2)].concat())
            .unwrap();
        compare(&mut cache, root.path(), "2");
        assert_eq!(
            cache.parsed_records, 2,
            "unterminated tail is reparsed rather than reused"
        );
    }

    #[test]
    fn cache_caps_fall_back_without_narrowing_validation_or_resetting_deadline() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        let mut cache = ArtifactLookupCache {
            maximum_records: 1,
            ..Default::default()
        };
        fs::write(&path, [record(1), record(2)].concat()).unwrap();
        compare(&mut cache, root.path(), "2");
        assert!(cache.snapshot.is_none());
        assert_eq!(
            cache.parsed_records, 0,
            "fallback does not parse the prefix twice"
        );
        fs::write(&path, [record(1), record(2), record(1)].concat()).unwrap();
        compare(&mut cache, root.path(), "2");
        assert!(cache.snapshot.is_none());
        cache.maximum_bytes = 1;
        compare(&mut cache, root.path(), "2");
        assert_eq!(cache.parsed_records, 0);
        fs::write(&path, record(1)).unwrap();
        assert_eq!(
            cache
                .find_until(root.path(), "1", Instant::now())
                .unwrap_err()
                .status,
            408
        );
        cache.maximum_bytes = MAX_BYTES;
        fs::write(&path, [record(1), record(2)].concat()).unwrap();
        assert_eq!(
            cache
                .find_until(root.path(), "1", Instant::now())
                .unwrap_err()
                .status,
            408
        );
        assert!(cache.snapshot.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn noncacheable_hint_skips_only_indexing_and_recovers_after_shrink_or_rotation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        let rows = [record(1), record(2)].concat();
        fs::write(&path, &rows).unwrap();
        let mut cache = ArtifactLookupCache {
            maximum_records: 1,
            ..Default::default()
        };
        compare(&mut cache, root.path(), "2");
        assert_eq!(cache.read_bytes, rows.len());
        assert!(cache.noncacheable.is_some());
        compare(&mut cache, root.path(), "2");
        assert_eq!(
            cache.read_bytes, 0,
            "noncacheable stores are not read twice"
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&record(3))
            .unwrap();
        compare(&mut cache, root.path(), "3");
        assert_eq!(cache.read_bytes, 0, "growth keeps the streaming-only hint");
        // Same-size rewrites cannot turn the hint into trusted evidence.
        fs::write(&path, [record(1), record(2), record(1)].concat()).unwrap();
        compare(&mut cache, root.path(), "2");
        assert_eq!(cache.read_bytes, 0);
        fs::write(&path, record(1)).unwrap();
        compare(&mut cache, root.path(), "1");
        assert!(cache.noncacheable.is_none());
        assert!(cache.snapshot.is_some());
        fs::write(&path, &rows).unwrap();
        compare(&mut cache, root.path(), "2");
        assert!(cache.noncacheable.is_some());
        let replacement = root.path().join("replacement");
        let mut padded = record(1);
        padded.extend(vec![b'\n'; rows.len()]);
        fs::write(&replacement, padded).unwrap();
        fs::rename(replacement, &path).unwrap();
        compare(&mut cache, root.path(), "1");
        assert!(cache.noncacheable.is_none());
        assert!(
            cache.snapshot.is_some(),
            "replacement recovers indexing even at a larger size"
        );
    }

    #[test]
    fn verification_rejects_mutation_and_replacement_after_read() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        fs::write(&path, record(1)).unwrap();
        let file = File::open(&path).unwrap();
        let stamp = Stamp::of(&file.metadata().unwrap());
        fs::write(&path, record(2)).unwrap();
        assert!(stamp.verify(&path, &file).is_err());
        let stamp = Stamp::of(&file.metadata().unwrap());
        let replacement = root.path().join("replacement");
        fs::write(&replacement, record(2)).unwrap();
        fs::rename(replacement, &path).unwrap();
        assert!(stamp.verify(&path, &file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn replaced_manifest_symlink_is_not_a_cache_hit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        fs::write(&path, record(1)).unwrap();
        let mut cache = ArtifactLookupCache::default();
        compare(&mut cache, root.path(), "1");
        let other = root.path().join("other");
        fs::rename(&path, &other).unwrap();
        std::os::unix::fs::symlink(other, &path).unwrap();
        assert!(cache.find(root.path(), "1").is_err());
        assert!(cache.snapshot.is_none());
    }
}
