//! The artifact manifest indexed by artifact ID on disk (`index_db`), so a
//! record of any age is found in a manifest of any length. Every appended
//! row is validated once as it is indexed; a malformed, oversized or
//! duplicate row fails every lookup until the manifest is rewritten, as a
//! complete scan of it would. Content integrity is never cached: a caller
//! verifies the bytes a record names when it reads them. The index also
//! counts the manifest's records by kind for the session summary. JavaScript
//! artifacts are kept by content digest and URL, so a saved invocation site
//! finds the retained versions of its script in a manifest of any length,
//! and Wasm modules by ID, so the session context lists the newest of them.
use crate::{
    error::{Error, Result},
    evidence,
    index_db::{self, Indexed, Position, SqlResult},
};
use hex::FromHex;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

pub const SUFFIX: &str = ".lookup-v1";
/// The second layout adds the summary's counts and manifest order, the
/// third JavaScript artifacts by digest and URL, the fourth Wasm modules.
/// The fifth folds records of any URL length, which the fourth recorded as
/// damage past 8 KiB, and the sixth adds the flow graph's content by SHA-256.
const FORMAT: &str = "reb-artifact-lookup-v1/6";
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY, start INTEGER NOT NULL, end INTEGER NOT NULL, parent INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS artifacts_parent ON artifacts(parent) WHERE parent != 0;
    CREATE INDEX IF NOT EXISTS artifacts_order ON artifacts(start);
    CREATE TABLE IF NOT EXISTS damage(id INTEGER PRIMARY KEY CHECK (id = 0), message TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS kinds(kind TEXT PRIMARY KEY, count INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS scripts(id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL, url TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS scripts_sha256 ON scripts(sha256);
    CREATE INDEX IF NOT EXISTS scripts_url ON scripts(url);
    CREATE TABLE IF NOT EXISTS wasm(id INTEGER PRIMARY KEY);
    -- The newest record of each SHA-256 per session and content (1 stack
    -- artifacts, 2 scripts and modules), as the flow graph reads them.
    CREATE TABLE IF NOT EXISTS digests(session INTEGER NOT NULL, content INTEGER NOT NULL,
        sha256 BLOB NOT NULL, start INTEGER NOT NULL, end INTEGER NOT NULL,
        PRIMARY KEY(session, content, sha256)) WITHOUT ROWID;";
/// A manifest line, its newline included, as the receiver writes it: one
/// with a URL as long as Chromium carries, 2 MiB, fits.
pub const RECORD_BYTES: usize = crate::artifact_query::MANIFEST_RECORD_BYTES;
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

/// The validated manifest records of `ids` the manifest has, keyed by ID,
/// after one catch-up for all of them.
pub fn find_many(root: &Path, ids: &[&str], deadline: Instant) -> Result<HashMap<String, Value>> {
    let index = index(root);
    let mut index = lock(&index);
    index.find_many(ids, deadline)
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
                digest(tx, &value, start, end)?;
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
        self.find_many(&[id], deadline)?
            .remove(id)
            .ok_or_else(not_found)
    }

    fn find_many(&mut self, ids: &[&str], deadline: Instant) -> Result<HashMap<String, Value>> {
        let mut found = HashMap::new();
        let Some(mut ready) = self.ready(deadline)? else {
            return Ok(found);
        };
        for &id in ids {
            let Some(key) = id.parse::<u64>().ok().filter(|key| key.to_string() == id) else {
                continue;
            };
            if let Some(value) = ready
                .unterminated
                .as_ref()
                .filter(|value| artifact_key(value) == key)
            {
                found.insert(id.to_owned(), value.clone());
                continue;
            }
            let range: Option<(i64, i64)> = self
                .index
                .sidecar()
                .connection()
                .prepare_cached("SELECT start, end FROM artifacts WHERE id = ?1")
                .sql()?
                .query_row([index_db::key(key)], |row| Ok((row.get(0)?, row.get(1)?)))
                .optional()
                .sql()?;
            let Some((start, end)) = range else {
                continue;
            };
            let value = self.row(&mut ready.file, start, end)?;
            // The anchors cover only the prefix ends; the row itself must still say so.
            if value["artifact_id"] != id {
                return Err(Error::new(500, "Artifact manifest changed during lookup"));
            }
            found.insert(id.to_owned(), value);
        }
        Ok(found)
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

/// What a flow graph reads by SHA-256: a stack artifact, or the retained
/// source of a script or module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    Stack = 1,
    Source = 2,
}

/// Keeps a stack, script or module record as the newest of its SHA-256 in
/// its session; later manifest records are newer and win.
fn digest(
    transaction: &rusqlite::Transaction<'_>,
    value: &Value,
    start: u64,
    end: u64,
) -> Result<()> {
    let content = match value["kind"].as_str() {
        Some("stack") => Content::Stack,
        Some("javascript" | "wasm") => Content::Source,
        _ => return Ok(()),
    };
    // A validated record has a canonical session and a lowercase hex digest.
    let session: u64 = value["session_id"].as_str().unwrap().parse().unwrap();
    let sha256 = <[u8; 32]>::from_hex(value["sha256"].as_str().unwrap()).unwrap();
    transaction
        .prepare_cached(
            "INSERT INTO digests(session, content, sha256, start, end) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(session, content, sha256) DO UPDATE SET start = excluded.start, end = excluded.end",
        )
        .sql()?
        .execute(params![
            index_db::key(session),
            content as i64,
            &sha256[..],
            start as i64,
            end as i64
        ])
        .sql()?;
    Ok(())
}

/// Manifest records found by SHA-256, and how far the index had reached.
pub struct Digests {
    /// Changes whenever the index is rebuilt from byte 0.
    pub epoch: String,
    /// The manifest bytes the index covers; a digest not found can appear
    /// only once this grows.
    pub indexed_to: u64,
    /// Every complete manifest record was indexed.
    pub caught_up: bool,
    /// The validated newest record of each digest found, in the order asked.
    pub found: Vec<([u8; 32], Value)>,
}

/// The newest validated record of each digest of `session` and `content`,
/// from the index brought up to the manifest until `deadline`. A bad row
/// anywhere in the manifest fails the lookup, as it fails every lookup.
pub fn by_digest(
    root: &Path,
    session: u64,
    content: Content,
    digests: &[[u8; 32]],
    deadline: Instant,
) -> Result<Digests> {
    let index = index(root);
    let mut index = lock(&index);
    let Some((mut file, position)) = index.open()? else {
        return Ok(Digests {
            epoch: String::new(),
            indexed_to: 0,
            caught_up: true,
            found: Vec::new(),
        });
    };
    let position = index.fold(&mut file, position, deadline)?;
    let connection = index.index.sidecar().connection();
    if let Some(message) = connection
        .query_row("SELECT message FROM damage WHERE id = 0", [], |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .sql()?
    {
        return Err(Error::new(500, message));
    }
    let mut statement = connection
        .prepare_cached(
            "SELECT start, end FROM digests WHERE session = ?1 AND content = ?2 AND sha256 = ?3",
        )
        .sql()?;
    let mut found = Vec::new();
    for sha256 in digests {
        let range: Option<(i64, i64)> = statement
            .query_row(
                params![index_db::key(session), content as i64, &sha256[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .sql()?;
        if let Some((start, end)) = range {
            let value = parse(&index_db::record(&mut file, start, end)?)?;
            // The anchors cover only the prefix ends; the row itself must still say so.
            if value["sha256"].as_str() != Some(hex::encode(sha256).as_str()) {
                return Err(Error::new(500, "Artifact manifest changed during lookup"));
            }
            found.push((*sha256, value));
        }
    }
    Ok(Digests {
        epoch: position.epoch.clone(),
        indexed_to: position.indexed_to,
        caught_up: position.caught_up(RECORD_BYTES as u64),
        found,
    })
}

/// Counts one indexed record for the summary, keeps a script by its digest
/// and URL, and a Wasm module by its ID.
fn count(transaction: &rusqlite::Transaction<'_>, value: &Value) -> Result<()> {
    let kind = value["kind"].as_str().unwrap_or("");
    if kind == "wasm" {
        transaction
            .prepare_cached("INSERT INTO wasm(id) VALUES (?1)")
            .sql()?
            .execute([index_db::key(artifact_key(value))])
            .sql()?;
    }
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
    /// The newest records, newest first, with public fields only.
    pub newest: Vec<Value>,
    /// The first malformed or duplicate record, which no count includes.
    pub damage: Option<String>,
    /// Why the index cannot read past `indexed_to`, when it cannot.
    pub stopped: Option<String>,
}

/// The manifest's counts and its `items` newest records, from the index
/// brought up to the manifest until `deadline`.
pub fn summary(root: &Path, items: usize, deadline: Instant) -> Result<Summary> {
    counted(root, deadline, |connection, file, summary| {
        let pairs = |sql: &str| -> Result<Vec<(String, u64)>> {
            connection
                .prepare_cached(sql)
                .sql()?
                .query_map([], |row| Ok((row.get(0)?, row.get::<_, i64>(1)? as u64)))
                .sql()?
                .map(|row| row.sql())
                .collect()
        };
        summary.by_kind = pairs("SELECT kind, count FROM kinds ORDER BY kind")?;
        summary.total = summary
            .by_kind
            .iter()
            .fold(0u64, |sum, (_, count)| sum.saturating_add(*count));
        summary.newest = newest(
            connection,
            file,
            "SELECT start, end FROM artifacts ORDER BY start DESC LIMIT ?1",
            items,
        )?;
        Ok(())
    })
}

/// The manifest's Wasm modules as far as it is indexed: their count as
/// `total` and `by_kind`, and the `items` newest as `newest`, in the
/// summary's form.
pub fn wasm(root: &Path, items: usize, deadline: Instant) -> Result<Summary> {
    counted(root, deadline, |connection, file, summary| {
        summary.total = connection
            .query_row("SELECT count FROM kinds WHERE kind = 'wasm'", [], |row| {
                row.get::<_, i64>(0)
            })
            .optional()
            .sql()?
            .map_or(0, |count| count as u64);
        summary.by_kind = vec![("wasm".to_owned(), summary.total)];
        summary.newest = newest(
            connection,
            file,
            "SELECT a.start, a.end FROM wasm w JOIN artifacts a ON a.id = w.id
             ORDER BY a.start DESC LIMIT ?1",
            items,
        )?;
        Ok(())
    })
}

/// Brings the index up to the manifest until `deadline`, then lets `fill`
/// read its counts. A bad row is left out of the counts and named, where a
/// lookup fails on it; a record the index cannot read stops the counts there.
fn counted(
    root: &Path,
    deadline: Instant,
    fill: impl FnOnce(&rusqlite::Connection, &mut File, &mut Summary) -> Result<()>,
) -> Result<Summary> {
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
    let mut summary = Summary {
        complete: stopped.is_none() && position.caught_up(RECORD_BYTES as u64),
        damage: connection
            .query_row("SELECT message FROM damage WHERE id = 0", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .sql()?,
        stopped,
        indexed_to: position.indexed_to,
        file_end: position.file_end,
        ..Summary::default()
    };
    fill(connection, &mut file, &mut summary)?;
    Ok(summary)
}

/// The records `sql` ranges, newest first, with public fields only.
fn newest(
    connection: &rusqlite::Connection,
    file: &mut File,
    sql: &str,
    items: usize,
) -> Result<Vec<Value>> {
    let ranges: Vec<(i64, i64)> = connection
        .prepare_cached(sql)
        .sql()?
        .query_map([i64::try_from(items).unwrap_or(i64::MAX)], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .sql()?
        .collect::<rusqlite::Result<_>>()
        .sql()?;
    ranges
        .into_iter()
        .map(|(start, end)| {
            parse(&index_db::record(file, start, end)?)
                .map(|value| evidence::public_artifact(&value))
        })
        .collect()
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

    // An artifact URL can be as long as any URL Chromium carries, 2 MiB.
    #[test]
    fn a_record_with_a_two_mib_url_is_found_and_listed() {
        let root = tempfile::tempdir().unwrap();
        let url = format!(
            "https://synthetic.invalid/{}",
            "a".repeat(2 * 1024 * 1024 - 26)
        );
        let mut long: Value = serde_json::from_slice(&record(2)).unwrap();
        long["url"] = json!(url);
        let manifest = [record(1), format!("{long}\n").into_bytes()].concat();
        fs::write(root.path().join("manifest.jsonl"), manifest).unwrap();
        compare(root.path(), "2");
        assert_eq!(
            evidence::find_artifact(root.path(), "2").unwrap()["url"],
            url
        );
        let filter = crate::artifact_query::ArtifactFilter::default();
        let page =
            crate::artifact_query::read(root.path(), &filter, crate::event_query::Cursor::Tail, 10)
                .unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.records[1]["url"], url);
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
            vec![b' '; crate::artifact_query::MANIFEST_RECORD_BYTES + 1],
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
