//! The artifact manifest indexed by artifact ID on disk (`index_db`), so a
//! record of any age is found in a manifest of any length. Every appended
//! row is validated once as it is indexed; a malformed, oversized or
//! duplicate row fails every lookup until the manifest is rewritten, as a
//! complete scan of it would. Content integrity is never cached: a caller
//! verifies the bytes a record names when it reads them. The index also
//! counts the manifest for the session summary: records by kind, and the
//! unique bytes each content budget's artifacts hold. JavaScript artifacts are
//! also kept by content digest and URL, so a saved invocation site finds the
//! retained versions of its script in a manifest of any length.
use crate::{
    error::{Error, Result},
    evidence,
    index_db::{self, Indexed, Position, SqlResult},
};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

pub const SUFFIX: &str = ".lookup-v1";
/// The second layout adds the summary's counts and manifest order, the
/// third JavaScript artifacts by digest and URL.
const FORMAT: &str = "reb-artifact-lookup-v1/3";
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, start INTEGER NOT NULL, end INTEGER NOT NULL, parent INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS artifacts_parent ON artifacts(parent) WHERE parent != 0;
    CREATE INDEX IF NOT EXISTS artifacts_order ON artifacts(start);
    CREATE TABLE IF NOT EXISTS damage(id INTEGER PRIMARY KEY CHECK (id = 0), message TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS kinds(kind TEXT PRIMARY KEY, count INTEGER NOT NULL) WITHOUT ROWID;
    -- A content budget's artifacts by digest, as its start option names it.
    -- The browser charges unique bytes, so identical content counts once; a
    -- digest is kept as its first 64 bits.
    CREATE TABLE IF NOT EXISTS budget_digests(budget TEXT NOT NULL, digest INTEGER NOT NULL,
        PRIMARY KEY(budget, digest)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS budget_bytes(budget TEXT PRIMARY KEY, bytes INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS scripts(id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, url TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS scripts_sha256 ON scripts(sha256);
    CREATE INDEX IF NOT EXISTS scripts_url ON scripts(url);";
/// A manifest line, its newline included, as the receiver writes it.
pub const RECORD_BYTES: usize = 8192;
/// Bytes folded per call, so a lookup never holds the index for long.
const FOLD_BYTES: u64 = 64 * 1024 * 1024;
/// How long one lookup may spend bringing the index up to the manifest.
pub const LOOKUP_DEADLINE: Duration = Duration::from_secs(5);
/// Open indexes kept between lookups. A cache of connections, not of rows:
/// a root dropped from it is reopened from disk when it is next used.
const OPEN_ROOTS: usize = 8;

pub struct ArtifactIndex {
    index: Indexed,
}

type Shared = Arc<Mutex<ArtifactIndex>>;
/// Open indexes by manifest path, least recently used first.
static OPEN: LazyLock<Mutex<Vec<(PathBuf, Shared)>>> = LazyLock::new(Mutex::default);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The index of the manifest under `root`, shared by every caller in the
/// process so it is folded once.
fn index(root: &Path) -> Shared {
    let manifest = root.join("manifest.jsonl");
    let mut open = lock(&OPEN);
    if let Some(at) = open.iter().position(|(path, _)| *path == manifest) {
        let entry = open.remove(at);
        let index = entry.1.clone();
        open.push(entry);
        return index;
    }
    let index = Arc::new(Mutex::new(ArtifactIndex {
        index: Indexed::new(&manifest, SUFFIX, FORMAT, SCHEMA),
    }));
    open.push((manifest, index.clone()));
    if open.len() > OPEN_ROOTS {
        open.remove(0);
    }
    index
}

/// The validated manifest record of `id`, from the whole manifest.
pub fn find(root: &Path, id: &str, deadline: Instant) -> Result<Value> {
    let index = index(root);
    let mut index = lock(&index);
    index.find(id, deadline)
}

/// Brings the index of `root` up to its manifest within `deadline`, for the
/// backend's background indexer. Returns whether it is caught up.
pub fn catch_up(root: &Path, deadline: Instant) -> Result<bool> {
    let index = index(root);
    let mut index = lock(&index);
    let Some((mut file, position)) = index.open()? else {
        return Ok(true);
    };
    let position = index.fold(&mut file, position, deadline)?;
    Ok(position.caught_up(RECORD_BYTES as u64))
}

/// The validated records whose parent is `parent`, in manifest order.
pub fn children(root: &Path, parent: u64, deadline: Instant) -> Result<Vec<Value>> {
    let index = index(root);
    let mut index = lock(&index);
    index.children(parent, deadline)
}

/// The validated JavaScript records whose content has `sha256` or whose URL
/// is `url`, from the whole manifest in manifest order.
pub fn scripts(
    root: &Path,
    sha256: &str,
    url: Option<&str>,
    deadline: Instant,
) -> Result<Vec<Value>> {
    let index = index(root);
    let mut index = lock(&index);
    index.scripts(sha256, url, deadline)
}

fn not_found() -> Error {
    Error::new(404, "Artifact not found")
}

fn parse(bytes: &[u8]) -> Result<Value> {
    let mut value = serde_json::from_slice(bytes)
        .map_err(|_| Error::new(500, "The artifact manifest contains malformed JSON"))?;
    evidence::validate_artifact(&mut value)?;
    Ok(value)
}

fn read(file: &mut File, start: u64, end: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0; (end - start) as usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

impl ArtifactIndex {
    fn open(&mut self) -> Result<Option<(File, Position)>> {
        self.index.open()
    }

    fn fold(
        &mut self,
        file: &mut File,
        mut position: Position,
        deadline: Instant,
    ) -> Result<Position> {
        let sidecar = self.index.sidecar();
        while !position.caught_up(0) {
            let before = position.indexed_to;
            let oversized = "The artifact manifest contains an oversized record";
            position = sidecar.fold(file, &position, FOLD_BYTES, deadline, RECORD_BYTES, oversized, &mut |tx: &rusqlite::Transaction<'_>, line: &[u8], start: u64, end: u64| {
                if line.len() + 1 > RECORD_BYTES {
                    return damage(tx, oversized);
                }
                if line.iter().all(u8::is_ascii_whitespace) {
                    return Ok(());
                }
                let value = match parse(line) {
                    Ok(value) => value,
                    Err(error) => return damage(tx, &error.message),
                };
                let parent = value["parent_artifact_id"].as_str().unwrap().parse::<u64>().unwrap();
                let inserted = tx
                    .execute(
                        "INSERT OR IGNORE INTO artifacts(id, start, end, parent) VALUES (?1, ?2, ?3, ?4)",
                        params![index_db::key(artifact_key(&value)), start as i64, end as i64, index_db::key(parent)],
                    )
                    .sql()?;
                if inserted == 0 {
                    return damage(tx, "The artifact manifest contains a duplicate artifact ID");
                }
                count(tx, &value)
            })?;
            if position.indexed_to == before || Instant::now() >= deadline {
                break;
            }
        }
        Ok(position)
    }

    /// The index caught up with every complete line and the manifest's last
    /// record if it still lacks its newline. An answer stands for the whole
    /// manifest, so a bad row anywhere in it fails every lookup.
    fn ready(&mut self, deadline: Instant) -> Result<Option<Ready>> {
        let Some((mut file, position)) = self.open()? else {
            return Ok(None);
        };
        let position = self.fold(&mut file, position, deadline)?;
        let behind = || Error::new(408, "Artifact manifest read exceeded its deadline");
        if position.file_end - position.indexed_to > RECORD_BYTES as u64 {
            return Err(behind());
        }
        let bytes = read(&mut file, position.indexed_to, position.file_end)?;
        if bytes.contains(&b'\n') {
            return Err(behind());
        }
        let connection = self.index.sidecar().connection();
        if let Some(message) = connection
            .query_row("SELECT message FROM damage WHERE id = 0", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .sql()?
        {
            return Err(Error::new(500, message));
        }
        let unterminated = if bytes.iter().all(u8::is_ascii_whitespace) {
            None
        } else {
            let value = parse(&bytes)?;
            let key = artifact_key(&value);
            let duplicate: Option<i64> = connection
                .query_row(
                    "SELECT id FROM artifacts WHERE id = ?1",
                    [index_db::key(key)],
                    |row| row.get(0),
                )
                .optional()
                .sql()?;
            if duplicate.is_some() {
                return Err(Error::new(
                    500,
                    "The artifact manifest contains a duplicate artifact ID",
                ));
            }
            Some(value)
        };
        Ok(Some(Ready { file, unterminated }))
    }

    fn row(&self, file: &mut File, start: i64, end: i64) -> Result<Value> {
        parse(&index_db::record(file, start, end)?)
    }

    fn find(&mut self, id: &str, deadline: Instant) -> Result<Value> {
        let Some(mut ready) = self.ready(deadline)? else {
            return Err(not_found());
        };
        let Some(key) = id.parse::<u64>().ok().filter(|key| key.to_string() == id) else {
            return Err(not_found());
        };
        if let Some(value) = ready
            .unterminated
            .take()
            .filter(|value| artifact_key(value) == key)
        {
            return Ok(value);
        }
        let range: Option<(i64, i64)> = self
            .index
            .sidecar()
            .connection()
            .query_row(
                "SELECT start, end FROM artifacts WHERE id = ?1",
                [index_db::key(key)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .sql()?;
        let (start, end) = range.ok_or_else(not_found)?;
        let value = self.row(&mut ready.file, start, end)?;
        // The anchors cover only the prefix ends; the row itself must still say so.
        if value["artifact_id"] != id {
            return Err(Error::new(500, "Artifact manifest changed during lookup"));
        }
        Ok(value)
    }

    fn children(&mut self, parent: u64, deadline: Instant) -> Result<Vec<Value>> {
        let Some(mut ready) = self.ready(deadline)? else {
            return Ok(Vec::new());
        };
        let ranges: Vec<(i64, i64)> = self
            .index
            .sidecar()
            .connection()
            // `parent != 0` lets SQLite use the partial index, which a bound
            // parameter alone never implies.
            .prepare_cached(
                "SELECT start, end FROM artifacts WHERE parent = ?1 AND parent != 0 ORDER BY start",
            )
            .sql()?
            .query_map([index_db::key(parent)], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .sql()?
            .collect::<rusqlite::Result<_>>()
            .sql()?;
        let mut children = ranges
            .into_iter()
            .map(|(start, end)| self.row(&mut ready.file, start, end))
            .collect::<Result<Vec<_>>>()?;
        children.extend(ready.unterminated.filter(|value| {
            value["parent_artifact_id"].as_str() == Some(parent.to_string().as_str())
        }));
        Ok(children)
    }
}

impl ArtifactIndex {
    fn scripts(
        &mut self,
        sha256: &str,
        url: Option<&str>,
        deadline: Instant,
    ) -> Result<Vec<Value>> {
        let Some(mut ready) = self.ready(deadline)? else {
            return Ok(Vec::new());
        };
        // Each arm of the OR reads its own index.
        let ranges: Vec<(i64, i64)> = self
            .index
            .sidecar()
            .connection()
            .prepare_cached(
                "SELECT a.start, a.end FROM scripts s JOIN artifacts a ON a.id = s.id
                 WHERE s.sha256 = ?1 OR s.url = ?2 ORDER BY a.start",
            )
            .sql()?
            .query_map(params![sha256, url], |row| Ok((row.get(0)?, row.get(1)?)))
            .sql()?
            .collect::<rusqlite::Result<_>>()
            .sql()?;
        let mut scripts = ranges
            .into_iter()
            .map(|(start, end)| self.row(&mut ready.file, start, end))
            .collect::<Result<Vec<_>>>()?;
        scripts.extend(ready.unterminated.filter(|value| {
            value["kind"] == "javascript"
                && (value["sha256"] == sha256 || url.is_some_and(|url| value["url"] == url))
        }));
        Ok(scripts)
    }
}

struct Ready {
    file: File,
    /// The manifest's last record when it still lacks its newline.
    unterminated: Option<Value>,
}

/// A validated record's canonical decimal artifact ID.
fn artifact_key(value: &Value) -> u64 {
    value["artifact_id"].as_str().unwrap().parse().unwrap()
}

/// Counts one indexed record for the summary, and keeps a script by its
/// digest and URL.
fn count(transaction: &rusqlite::Transaction<'_>, value: &Value) -> Result<()> {
    let kind = value["kind"].as_str().unwrap_or("");
    if kind == "javascript" {
        transaction
            .prepare_cached("INSERT INTO scripts(id, sha256, url) VALUES (?1, ?2, ?3)")
            .sql()?
            .execute(params![
                index_db::key(artifact_key(value)),
                value["sha256"].as_str().unwrap_or(""),
                value["url"].as_str().unwrap_or("")
            ])
            .sql()?;
    }
    transaction
        .prepare_cached(
            "INSERT INTO kinds(kind, count) VALUES (?1, 1)
             ON CONFLICT(kind) DO UPDATE SET count = count + 1",
        )
        .sql()?
        .execute([kind])
        .sql()?;
    let (Some(budget), Some(digest), Some(size)) = (
        crate::session_summary::budget_of_kind(kind),
        value["sha256"]
            .as_str()
            .and_then(|text| text.get(..16))
            .and_then(|prefix| u64::from_str_radix(prefix, 16).ok()),
        value["byte_size"].as_u64(),
    ) else {
        return Ok(());
    };
    let fresh = transaction
        .prepare_cached("INSERT OR IGNORE INTO budget_digests(budget, digest) VALUES (?1, ?2)")
        .sql()?
        .execute(params![budget, index_db::key(digest)])
        .sql()?;
    if fresh == 1 {
        transaction
            .prepare_cached(
                "INSERT INTO budget_bytes(budget, bytes) VALUES (?1, ?2)
                 ON CONFLICT(budget) DO UPDATE SET bytes = bytes + excluded.bytes",
            )
            .sql()?
            .execute(params![budget, i64::try_from(size).unwrap_or(i64::MAX)])
            .sql()?;
    }
    Ok(())
}

/// What the session summary reports of the manifest, as far as it is indexed.
#[derive(Default)]
pub struct Summary {
    /// Every complete record is indexed.
    pub complete: bool,
    pub indexed_to: u64,
    pub file_end: u64,
    pub total: u64,
    pub by_kind: Vec<(String, u64)>,
    /// Unique bytes by the start option of the budget they are charged to.
    pub retained: Vec<(String, u64)>,
    /// The newest records, newest first, with public fields only.
    pub newest: Vec<Value>,
    /// The first malformed or duplicate record, which no count includes.
    pub damage: Option<String>,
    /// Why the index cannot read past `indexed_to`, when it cannot.
    pub stopped: Option<String>,
}

/// The manifest's counts and its `items` newest records, from the index
/// brought up to the manifest until `deadline`. A bad row is left out of the
/// counts and named, where a lookup fails on it; a record the index cannot
/// read stops the counts there.
pub fn summary(root: &Path, items: usize, deadline: Instant) -> Result<Summary> {
    let index = index(root);
    let mut index = lock(&index);
    let Some((mut file, position)) = index.open()? else {
        return Ok(Summary {
            complete: true,
            ..Summary::default()
        });
    };
    let (position, stopped) = match index.fold(&mut file, position.clone(), deadline) {
        Ok(position) => (position, None),
        Err(error) => match index.open()? {
            Some((_, position)) => (position, Some(error.message)),
            None => (position, Some(error.message)),
        },
    };
    let connection = index.index.sidecar().connection();
    let damage = connection
        .query_row("SELECT message FROM damage WHERE id = 0", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .sql()?;
    let pairs = |sql: &str| -> Result<Vec<(String, u64)>> {
        connection
            .prepare_cached(sql)
            .sql()?
            .query_map([], |row| Ok((row.get(0)?, row.get::<_, i64>(1)? as u64)))
            .sql()?
            .map(|row| row.sql())
            .collect()
    };
    let by_kind = pairs("SELECT kind, count FROM kinds ORDER BY kind")?;
    let ranges: Vec<(i64, i64)> = connection
        .prepare_cached("SELECT start, end FROM artifacts ORDER BY start DESC LIMIT ?1")
        .sql()?
        .query_map([i64::try_from(items).unwrap_or(i64::MAX)], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .sql()?
        .collect::<rusqlite::Result<_>>()
        .sql()?;
    let newest = ranges
        .into_iter()
        .map(|(start, end)| {
            parse(&index_db::record(&mut file, start, end)?)
                .map(|value| evidence::public_artifact(&value))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Summary {
        complete: stopped.is_none() && position.caught_up(RECORD_BYTES as u64),
        damage,
        stopped,
        indexed_to: position.indexed_to,
        file_end: position.file_end,
        total: by_kind
            .iter()
            .fold(0u64, |sum, (_, count)| sum.saturating_add(*count)),
        by_kind,
        retained: pairs("SELECT budget, bytes FROM budget_bytes")?,
        newest,
    })
}

/// Records why the manifest cannot answer; the first reason stands.
fn damage(transaction: &rusqlite::Transaction<'_>, message: &str) -> Result<()> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO damage(id, message) VALUES (0, ?1)",
            [message],
        )
        .sql()?;
    Ok(())
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
    fn lookup(root: &Path, id: &str) -> Result<Value> {
        find(root, id, Instant::now() + LOOKUP_DEADLINE)
    }
    fn compare(root: &Path, id: &str) {
        match (lookup(root, id), evidence::scan_find_artifact(root, id)) {
            (Ok(indexed), Ok(scanned)) => assert_eq!(indexed, scanned),
            (Err(indexed), Err(scanned)) => {
                assert_eq!(indexed.status, scanned.status);
                assert_eq!(indexed.message, scanned.message);
            }
            (indexed, scanned) => {
                panic!("indexed {indexed:?} and scanned {scanned:?} results differ")
            }
        }
    }
    fn append(path: &Path, bytes: &[u8]) {
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    #[test]
    fn the_oldest_record_of_a_long_manifest_is_found() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        let mut file = fs::File::create(&path).unwrap();
        // Past the old 10,000-row window and, with the background catch-up a
        // backend runs, without a row cap; tools/long-session-fixture covers
        // 300,000 rows through the product path.
        for id in 1..=20_001u64 {
            file.write_all(&record(id)).unwrap();
        }
        drop(file);
        while !catch_up(root.path(), Instant::now() + LOOKUP_DEADLINE).unwrap() {}
        assert_eq!(lookup(root.path(), "1").unwrap()["artifact_id"], "1");
        assert_eq!(
            lookup(root.path(), "20001").unwrap()["artifact_id"],
            "20001"
        );
        assert_eq!(lookup(root.path(), "20002").unwrap_err().status, 404);
        assert!(index_db::sidecar_path(&path, SUFFIX).exists());
    }

    #[cfg(unix)]
    #[test]
    fn appends_rewrites_replacement_and_removal_match_a_complete_scan() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        let mut bytes = [record(1), record(u64::MAX)].concat();
        fs::write(&path, &bytes).unwrap();
        compare(root.path(), &u64::MAX.to_string());
        compare(root.path(), "1");
        compare(root.path(), "2");
        compare(root.path(), "01");
        append(&path, &record(2));
        compare(root.path(), "2");
        bytes.extend(record(2));
        // A same-size rewrite with restored mtime must not keep the old IDs.
        let modified = path.metadata().unwrap().modified().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap().replacen(
            "\"artifact_id\":\"1\"",
            "\"artifact_id\":\"3\"",
            1,
        );
        fs::write(&path, text).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        compare(root.path(), "3");
        compare(root.path(), "1");
        let replacement = root.path().join("replacement");
        fs::write(&replacement, &bytes).unwrap();
        fs::rename(&replacement, &path).unwrap();
        compare(root.path(), "1");
        fs::write(&path, record(1)).unwrap();
        compare(root.path(), "2");
        fs::remove_file(&path).unwrap();
        compare(root.path(), "1");
        fs::write(&path, &bytes).unwrap();
        compare(root.path(), "1");
    }

    #[test]
    fn incomplete_duplicate_malformed_and_oversized_rows_fail_like_a_complete_scan() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        for tail in [
            record(1),
            b"{\"protocol_version\":".to_vec(),
            b"{}\n".to_vec(),
            vec![b' '; 8193],
        ] {
            fs::write(&path, record(1)).unwrap();
            compare(root.path(), "1");
            append(&path, &tail);
            compare(root.path(), "1");
            compare(root.path(), "2");
        }
        // A last record without its newline is still a record.
        let mut complete = record(1);
        complete.pop();
        fs::write(&path, &complete).unwrap();
        compare(root.path(), "1");
        append(&path, &[b"\n".to_vec(), record(2)].concat());
        compare(root.path(), "2");
        // A damaged row stays damage after later appends.
        append(&path, b"{}\n");
        append(&path, &record(3));
        compare(root.path(), "3");
    }

    #[test]
    fn a_lookup_past_its_deadline_keeps_its_progress() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.jsonl");
        fs::write(&path, [record(1), record(2)].concat()).unwrap();
        assert_eq!(
            find(root.path(), "1", Instant::now()).unwrap_err().status,
            408
        );
        assert_eq!(lookup(root.path(), "2").unwrap()["artifact_id"], "2");
    }
}
