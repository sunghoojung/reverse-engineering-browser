//! Disk-backed indexes beside the append-only evidence files.
//!
//! An index is a private SQLite database next to the file it describes
//! (`<file><suffix>`), so a session of any length is indexed once, reopens
//! after a restart without a rescan, and is answered from the database's
//! bounded page cache instead of every row held in memory. It is derived
//! data, never an authority: each use checks the file's device and inode and
//! the digests of its first and last indexed bytes, and a file that was
//! rewritten, truncated or replaced is indexed again from byte 0 under a new
//! epoch. The anchors a fold commits are those of the bytes it read, and only
//! while the file still holds them, so a store rewritten in place during a
//! fold is never described by the rows of the file it replaced. Rows and the
//! indexed position commit in one transaction, so a crash leaves the position
//! the rows describe. A directory that cannot hold the database, such as a
//! read-only bundle, gets one in a private temporary directory that lives as
//! long as the index.
use crate::error::{Error, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Instant,
};

/// Bytes hashed at each end of the indexed prefix to recognize the same file.
const ANCHOR_BYTES: u64 = 4096;
/// Bytes read from the file at a time while folding; the page cache, not
/// this buffer, holds the index.
const CHUNK: usize = 8 * 1024 * 1024;
/// Database page cache per index, in KiB (SQLite's negative `cache_size`).
const CACHE_KIB: i64 = 16 * 1024;

/// Where the index stands against its file, as of the last check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    /// Changes whenever the index is rebuilt from byte 0.
    pub epoch: String,
    /// The record boundary the index covers up to.
    pub indexed_to: u64,
    /// How far the last fold read the file. Between `indexed_to` and here
    /// there is no newline: a record still being written.
    pub scanned_to: u64,
    /// The file's length at the last check.
    pub file_end: u64,
    /// The index was found on disk rather than built in this process.
    pub reopened: bool,
}
impl Position {
    /// Every complete record of the file is indexed: the last fold read to
    /// the end, and what remains is at most one record still being written.
    /// A fold its deadline stopped leaves complete records unread however few
    /// bytes they span, so the remainder's length alone does not say so.
    pub fn caught_up(&self, record_bytes: u64) -> bool {
        self.indexed_to >= self.file_end
            || (self.scanned_to >= self.file_end && self.file_end - self.indexed_to <= record_bytes)
    }
}

pub struct Sidecar {
    connection: Connection,
    /// The private directory holding the database when its file's own
    /// directory cannot, as for read-only evidence. It lives as long as the index.
    _temporary: Option<tempfile::TempDir>,
    /// Why the database is not beside its file, when it is not.
    temporary_reason: Option<String>,
    format: &'static str,
    schema: &'static str,
    reopened: bool,
}

/// The path of the index `suffix` names for `source`.
pub fn sidecar_path(source: &Path, suffix: &str) -> PathBuf {
    let mut name = source.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    source.with_file_name(name)
}

/// Removes an index and its write-ahead files, as a capture clear does
/// before it empties the store the index describes.
pub fn remove(source: &Path, suffix: &str) -> Result<()> {
    let path = sidecar_path(source, suffix);
    for extra in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.clone().into_os_string();
        name.push(extra);
        match std::fs::remove_file(PathBuf::from(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error.into());
            }
            _ => {}
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn identity_of(metadata: &std::fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!("{}:{}", metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        format!("{:?}", metadata.created().ok())
    }
}

pub fn read_range(file: &mut File, start: u64, end: u64) -> Result<Vec<u8>> {
    let mut bytes = vec![0; (end - start) as usize];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// The first and last `ANCHOR_BYTES` before `end`, or None when the file now
/// ends before `end`, as one truncated since it was measured does.
fn ends(file: &mut File, end: u64) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut read = |start: u64, end: u64| -> Result<Option<Vec<u8>>> {
        let mut bytes = vec![0; (end - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        match file.read_exact(&mut bytes) {
            Ok(()) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error.into()),
        }
    };
    let head = read(0, end.min(ANCHOR_BYTES))?;
    let tail = read(end.saturating_sub(ANCHOR_BYTES), end)?;
    Ok(head.zip(tail))
}

/// The anchors of a prefix: digests of its `ends`.
fn anchors((head, tail): &(Vec<u8>, Vec<u8>)) -> (String, String) {
    (digest(head), digest(tail))
}

/// The bytes one fold read that the anchors of its end cover: those before
/// `ANCHOR_BYTES` and the last `ANCHOR_BYTES`.
#[derive(Default)]
struct Folded {
    head: Vec<u8>,
    tail: Vec<u8>,
}
impl Folded {
    /// Keeps what `bytes`, read at offset `start`, adds to either end.
    fn add(&mut self, start: u64, bytes: &[u8]) {
        if start < ANCHOR_BYTES {
            let take = ((ANCHOR_BYTES - start) as usize).min(bytes.len());
            self.head.extend_from_slice(&bytes[..take]);
        }
        let keep = ANCHOR_BYTES as usize;
        if bytes.len() >= keep {
            self.tail.clear();
            self.tail.extend_from_slice(&bytes[bytes.len() - keep..]);
        } else {
            self.tail.extend_from_slice(bytes);
            let excess = self.tail.len().saturating_sub(keep);
            self.tail.drain(..excess);
        }
    }

    /// The anchors of `at` for an index that held `from` bytes under `stored`
    /// and then read these up to `at`. They describe what the index holds,
    /// never a later read of the file, and only while the file still holds
    /// it: None when the prefix or the bytes read changed since, as a store
    /// rewritten in place during the fold does.
    fn anchors(
        &self,
        file: &mut File,
        stored: &(String, String),
        from: u64,
        at: u64,
    ) -> Result<Option<(String, String)>> {
        let Some((head, tail)) = ends(file, from)? else {
            return Ok(None);
        };
        if from > 0 && (digest(&head), digest(&tail)) != *stored {
            return Ok(None);
        }
        // Fewer bytes read than an anchor spans: the tail reaches before `from`.
        let before = at.min(ANCHOR_BYTES) as usize - self.tail.len();
        let held = (
            [head.as_slice(), &self.head].concat(),
            [&tail[tail.len() - before..], &self.tail].concat(),
        );
        Ok((ends(file, at)? == Some(held.clone())).then(|| anchors(&held)))
    }
}

fn sql(error: rusqlite::Error) -> Error {
    Error::new(500, format!("Evidence index failed: {error}"))
}
pub(crate) trait SqlResult<T> {
    fn sql(self) -> Result<T>;
}
impl<T> SqlResult<T> for rusqlite::Result<T> {
    fn sql(self) -> Result<T> {
        self.map_err(sql)
    }
}

const META: &str = "CREATE TABLE IF NOT EXISTS meta(
    id INTEGER PRIMARY KEY CHECK (id = 0),
    format TEXT NOT NULL,
    epoch TEXT NOT NULL,
    identity TEXT NOT NULL,
    indexed_to INTEGER NOT NULL,
    head TEXT NOT NULL,
    tail TEXT NOT NULL)";

fn new_epoch(seed: &str) -> String {
    let seed = format!(
        "{}:{seed}:{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    );
    hex::encode(&Sha256::digest(seed)[..8])
}

/// Creates the database file private (0600) before SQLite opens it; SQLite
/// gives its write-ahead files the database's permissions. A link or other
/// non-file at the path is refused, never followed.
fn create_private(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() => return Ok(()),
        Ok(_) => return Err(Error::new(500, "Evidence index path is not a regular file")),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        Err(_) => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => create_private(path),
        Err(error) => Err(error.into()),
    }
}

fn connect(path: &Path, format: &str, schema: &str) -> Result<(Connection, bool)> {
    create_private(path)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .sql()?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .sql()?;
    // Derived data: a crash may lose the last transaction, never corrupt one.
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .sql()?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::new(
            500,
            "Evidence index cannot use a write-ahead log",
        ));
    }
    connection
        .execute_batch(&format!(
            "PRAGMA synchronous=NORMAL; PRAGMA cache_size=-{CACHE_KIB}; PRAGMA temp_store=FILE; {META};"
        ))
        .sql()?;
    let stored: Option<String> = connection
        .query_row("SELECT format FROM meta WHERE id = 0", [], |row| row.get(0))
        .optional()
        .sql()?;
    let reopened = match stored {
        Some(stored) if stored == format => true,
        Some(_) => {
            // Another format or layout: rebuild rather than migrate.
            drop_tables(&connection)?;
            false
        }
        None => false,
    };
    connection.execute_batch(schema).sql()?;
    if !reopened {
        connection
            .execute(
                "INSERT OR REPLACE INTO meta(id, format, epoch, identity, indexed_to, head, tail)
                 VALUES (0, ?1, ?2, '', 0, '', '')",
                params![format, new_epoch(&path.display().to_string())],
            )
            .sql()?;
    }
    Ok((connection, reopened))
}

fn drop_tables(connection: &Connection) -> Result<()> {
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .sql()?
        .query_map([], |row| row.get(0))
        .sql()?
        .collect::<rusqlite::Result<_>>()
        .sql()?;
    for table in tables {
        connection
            .execute_batch(&format!("DROP TABLE IF EXISTS \"{table}\""))
            .sql()?;
    }
    connection.execute_batch(META).sql()?;
    Ok(())
}

impl Sidecar {
    /// Opens or creates the index `suffix` names for `source`. `format` names
    /// the row layout; an index of another format is rebuilt. `schema` is
    /// idempotent SQL creating the index's own tables.
    pub fn open(
        source: &Path,
        suffix: &str,
        format: &'static str,
        schema: &'static str,
    ) -> Result<Self> {
        let path = sidecar_path(source, suffix);
        match connect(&path, format, schema) {
            Ok((connection, reopened)) => Ok(Self {
                connection,
                _temporary: None,
                temporary_reason: None,
                format,
                schema,
                reopened,
            }),
            Err(error) => {
                let temporary = tempfile::Builder::new()
                    .prefix("reb-evidence-index-")
                    .tempdir()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        temporary.path(),
                        std::fs::Permissions::from_mode(0o700),
                    )?;
                }
                let fallback = temporary.path().join("index.sqlite");
                let (connection, _) = connect(&fallback, format, schema)?;
                eprintln!(
                    "Indexing {} in a temporary directory: {}",
                    source.display(),
                    error.message
                );
                Ok(Self {
                    connection,
                    _temporary: Some(temporary),
                    temporary_reason: Some(error.message),
                    format,
                    schema,
                    reopened: false,
                })
            }
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Why the database lives in a temporary directory, when it does.
    pub fn temporary_reason(&self) -> Option<&str> {
        self.temporary_reason.as_deref()
    }

    fn meta(&self) -> Result<(String, String, u64, String, String)> {
        self.connection
            .query_row(
                "SELECT epoch, identity, indexed_to, head, tail FROM meta WHERE id = 0",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get::<_, i64>(2)? as u64,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .sql()
    }

    /// Empties every table under a new epoch, for a file that is no longer
    /// the one indexed.
    pub fn reset(&mut self, identity: &str) -> Result<()> {
        drop_tables(&self.connection)?;
        self.connection.execute_batch(self.schema).sql()?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO meta(id, format, epoch, identity, indexed_to, head, tail)
                 VALUES (0, ?1, ?2, ?3, 0, '', '')",
                params![self.format, new_epoch(identity), identity],
            )
            .sql()?;
        // Returns the dropped pages, which held captured text, to the file system.
        self.connection
            .execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
            .sql()?;
        self.reopened = false;
        Ok(())
    }

    /// Checks the index against `file`, rebuilding it when the file is not
    /// the one it describes, and returns where it stands.
    pub fn check(&mut self, file: &mut File) -> Result<Position> {
        let metadata = file.metadata()?;
        let identity = identity_of(&metadata);
        let end = metadata.len();
        let (_, stored, indexed_to, head, tail) = self.meta()?;
        let same = stored == identity
            && indexed_to <= end
            && ends(file, indexed_to)?.as_ref().map(anchors) == Some((head, tail));
        if !same {
            self.reset(&identity)?;
        }
        let (epoch, _, indexed_to, _, _) = self.meta()?;
        Ok(Position {
            epoch,
            indexed_to,
            scanned_to: indexed_to,
            file_end: end,
            reopened: self.reopened,
        })
    }

    /// The position of an index whose file does not exist: empty.
    pub fn missing(&mut self) -> Result<Position> {
        let (_, identity, indexed_to, _, _) = self.meta()?;
        if indexed_to > 0 || !identity.is_empty() {
            self.reset("")?;
        }
        let (epoch, ..) = self.meta()?;
        Ok(Position {
            epoch,
            indexed_to: 0,
            scanned_to: 0,
            file_end: 0,
            reopened: self.reopened,
        })
    }

    /// Folds complete lines after the indexed position into one transaction:
    /// at most `budget` bytes, and no new chunk after `deadline`. `each` sees
    /// every terminated line with its byte range; the bytes after the last
    /// newline wait for a later fold. A partial line longer than
    /// `max_line` fails with `oversized`, since no newline can make it a
    /// record. Past `deadline` no further chunk is read. A file that changed
    /// under the fold commits nothing and is checked again, which rebuilds an
    /// index whose prefix it no longer holds.
    #[allow(clippy::too_many_arguments)]
    pub fn fold(
        &mut self,
        file: &mut File,
        position: &Position,
        budget: u64,
        deadline: Instant,
        max_line: usize,
        oversized: &str,
        each: &mut dyn Fold,
    ) -> Result<Position> {
        let from = position.indexed_to;
        let limit = position.file_end.min(from.saturating_add(budget));
        if limit <= from {
            return Ok(position.clone());
        }
        let transaction = self.connection.transaction().sql()?;
        each.begin();
        let mut at = from;
        let mut pending = Vec::new();
        let mut read_to = from;
        let mut folded = Folded::default();
        let mut truncated = false;
        file.seek(SeekFrom::Start(from))?;
        while read_to < limit && Instant::now() < deadline {
            let size = ((limit - read_to) as usize).min(CHUNK);
            let mut chunk = std::mem::take(&mut pending);
            let carried = chunk.len();
            chunk.resize(carried + size, 0);
            match file.read_exact(&mut chunk[carried..]) {
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    truncated = true;
                    break;
                }
                read => read?,
            }
            read_to += size as u64;
            let Some(last) = chunk.iter().rposition(|byte| *byte == b'\n') else {
                if chunk.len() > max_line {
                    return Err(Error::new(500, oversized));
                }
                pending = chunk;
                continue;
            };
            folded.add(at, &chunk[..=last]);
            let mut start = 0;
            for line in chunk[..=last].split_inclusive(|byte| *byte == b'\n') {
                let line_start = at + start as u64;
                start += line.len();
                each.line(
                    &transaction,
                    &line[..line.len() - 1],
                    line_start,
                    at + start as u64,
                )?;
            }
            at += start as u64;
            pending = chunk[last + 1..].to_vec();
            if pending.len() > max_line {
                return Err(Error::new(500, oversized));
            }
        }
        each.finish(&transaction)?;
        if at > from || truncated {
            let stored = transaction
                .query_row("SELECT head, tail FROM meta WHERE id = 0", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .sql()?;
            let held = if truncated {
                None
            } else {
                folded.anchors(file, &stored, from, at)?
            };
            let Some((head, tail)) = held else {
                drop(transaction);
                return self.check(file);
            };
            transaction
                .execute(
                    "UPDATE meta SET indexed_to = ?1, head = ?2, tail = ?3 WHERE id = 0",
                    params![at as i64, head, tail],
                )
                .sql()?;
        }
        transaction.commit().sql()?;
        Ok(Position {
            indexed_to: at,
            scanned_to: read_to,
            ..position.clone()
        })
    }
}

/// What a fold does with each terminated line, and before its transaction
/// commits: an index that changes rows in memory writes them back there, so
/// they commit with the position they describe.
pub trait Fold {
    /// Called before each fold's first line, so state a failed fold left
    /// behind is not written with the next one.
    fn begin(&mut self) {}
    fn line(
        &mut self,
        transaction: &Transaction<'_>,
        line: &[u8],
        start: u64,
        end: u64,
    ) -> Result<()>;
    fn finish(&mut self, _transaction: &Transaction<'_>) -> Result<()> {
        Ok(())
    }
}
impl<F: FnMut(&Transaction<'_>, &[u8], u64, u64) -> Result<()>> Fold for F {
    fn line(
        &mut self,
        transaction: &Transaction<'_>,
        line: &[u8],
        start: u64,
        end: u64,
    ) -> Result<()> {
        self(transaction, line, start, end)
    }
}

/// SQL functions or collations an index's queries use, registered on each
/// connection it opens.
pub type Setup = fn(&Connection) -> rusqlite::Result<()>;

/// One file and its index, opened when first used. A missing file has an
/// empty index; a capture clear removes the index from disk.
pub struct Indexed {
    source: PathBuf,
    suffix: &'static str,
    format: &'static str,
    schema: &'static str,
    setup: Option<Setup>,
    sidecar: Option<Sidecar>,
}
impl Indexed {
    pub fn new(
        source: &Path,
        suffix: &'static str,
        format: &'static str,
        schema: &'static str,
    ) -> Self {
        Self {
            source: source.to_owned(),
            suffix,
            format,
            schema,
            setup: None,
            sidecar: None,
        }
    }

    pub fn with_setup(mut self, setup: Setup) -> Self {
        self.setup = Some(setup);
        self
    }

    /// The file and the index checked against it; None when there is no file.
    pub fn open(&mut self) -> Result<Option<(File, Position)>> {
        let mut file = match crate::evidence::regular_file(&self.source) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(sidecar) = &mut self.sidecar {
                    sidecar.missing()?;
                }
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        if self.sidecar.is_none() {
            let sidecar = Sidecar::open(&self.source, self.suffix, self.format, self.schema)?;
            if let Some(setup) = self.setup {
                setup(sidecar.connection()).sql()?;
            }
            self.sidecar = Some(sidecar);
        }
        let position = self.sidecar.as_mut().unwrap().check(&mut file)?;
        Ok(Some((file, position)))
    }

    /// The open index; `open` must have returned a file.
    pub fn sidecar(&mut self) -> &mut Sidecar {
        self.sidecar.as_mut().expect("an opened index")
    }

    /// Why the open index lives in a temporary directory, when it does.
    pub fn temporary_reason(&self) -> Option<&str> {
        self.sidecar.as_ref().and_then(Sidecar::temporary_reason)
    }

    /// The open index's database, if it has been opened.
    pub fn connection(&self) -> Option<&Connection> {
        self.sidecar.as_ref().map(Sidecar::connection)
    }

    /// Closes the index and removes it from disk.
    pub fn discard(&mut self) -> Result<()> {
        self.sidecar = None;
        remove(&self.source, self.suffix)
    }
}

/// The bytes of one record at its indexed range, without its newline.
pub fn record(file: &mut File, start: i64, end: i64) -> Result<Vec<u8>> {
    let mut bytes = read_range(file, start as u64, end as u64)?;
    if bytes.pop() != Some(b'\n') {
        return Err(Error::new(500, "An indexed record no longer ends a line"));
    }
    Ok(bytes)
}

/// u64 identifiers keep their bits in SQLite's signed integers. Equality and
/// joins are exact; ordering is only meaningful below 2^63.
pub fn key(value: u64) -> i64 {
    value as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SCHEMA: &str =
        "CREATE TABLE IF NOT EXISTS lines(start INTEGER PRIMARY KEY, end INTEGER NOT NULL)";

    fn fold_all(sidecar: &mut Sidecar, path: &Path) -> Position {
        fold_until(
            sidecar,
            path,
            Instant::now() + std::time::Duration::from_secs(5),
        )
    }
    fn fold_until(sidecar: &mut Sidecar, path: &Path, deadline: Instant) -> Position {
        let mut file = File::open(path).unwrap();
        let position = sidecar.check(&mut file).unwrap();
        sidecar
            .fold(
                &mut file,
                &position,
                u64::MAX,
                deadline,
                64,
                "oversized",
                &mut |tx: &Transaction<'_>, _: &[u8], start: u64, end: u64| {
                    tx.execute(
                        "INSERT INTO lines VALUES (?1, ?2)",
                        params![start as i64, end as i64],
                    )
                    .sql()?;
                    Ok(())
                },
            )
            .unwrap()
    }
    fn count(sidecar: &Sidecar) -> i64 {
        sidecar
            .connection()
            .query_row("SELECT count(*) FROM lines", [], |row| row.get(0))
            .unwrap()
    }

    /// A fold its deadline stopped has not read what remains, however few
    /// bytes it spans, so the position is behind until a fold reads it; a
    /// remainder a fold did read without a newline is a record being written.
    #[test]
    fn only_a_fold_that_read_to_the_end_is_caught_up() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.jsonl");
        std::fs::write(&path, b"a\nbb\n").unwrap();
        let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
        let stopped = fold_until(&mut sidecar, &path, Instant::now());
        assert_eq!(
            (stopped.indexed_to, stopped.scanned_to, count(&sidecar)),
            (0, 0, 0)
        );
        assert!(
            !stopped.caught_up(64),
            "two unread records are not a record being written"
        );
        let read = fold_all(&mut sidecar, &path);
        assert_eq!((read.indexed_to, count(&sidecar)), (5, 2));
        assert!(read.caught_up(0));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"partial")
            .unwrap();
        assert!(!fold_until(&mut sidecar, &path, Instant::now()).caught_up(64));
        let partial = fold_all(&mut sidecar, &path);
        assert_eq!((partial.indexed_to, partial.scanned_to), (5, 12));
        assert!(partial.caught_up(64) && !partial.caught_up(0));
    }

    #[test]
    fn folds_appends_reopens_and_rebuilds_a_replaced_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.jsonl");
        std::fs::write(&path, b"a\nbb\npartial").unwrap();
        let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
        assert!(sidecar.temporary_reason().is_none());
        let first = fold_all(&mut sidecar, &path);
        assert_eq!((first.indexed_to, count(&sidecar)), (5, 2));
        assert!(!first.caught_up(0) && first.caught_up(64));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        assert_eq!(fold_all(&mut sidecar, &path).indexed_to, 13);
        assert_eq!(count(&sidecar), 3);
        drop(sidecar);
        let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
        let reopened = fold_all(&mut sidecar, &path);
        assert!(reopened.reopened);
        assert_eq!(
            (reopened.epoch.clone(), count(&sidecar)),
            (first.epoch.clone(), 3)
        );
        // A same-length rewrite changes the anchors.
        std::fs::write(&path, b"x\nyy\npartial\n").unwrap();
        let rebuilt = fold_all(&mut sidecar, &path);
        assert_ne!(rebuilt.epoch, first.epoch);
        assert_eq!(count(&sidecar), 3);
        // Another layout rebuilds rather than reading old rows.
        drop(sidecar);
        let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v2", SCHEMA).unwrap();
        assert!(
            !sidecar
                .check(&mut File::open(&path).unwrap())
                .unwrap()
                .reopened
        );
        assert_eq!(count(&sidecar), 0);
        drop(sidecar);
        remove(&path, ".test-v1").unwrap();
        assert!(!sidecar_path(&path, ".test-v1").exists());
    }

    /// A store rewritten in place while a fold reads it, as a copy over it
    /// does, is indexed again rather than left described by the rows of the
    /// file it replaced: from byte 0 or after an indexed prefix, and whether
    /// the new file is longer or shorter than what the fold read.
    #[test]
    fn a_store_rewritten_during_a_fold_is_indexed_again() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.jsonl");
        for indexed in [&b""[..], b"a\n"] {
            for replacement in [&b"x\nyy\nzzz\nwwww\n"[..], b"x\n"] {
                remove(&path, ".test-v1").unwrap();
                std::fs::write(&path, indexed).unwrap();
                let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
                assert_eq!(
                    fold_all(&mut sidecar, &path).indexed_to,
                    indexed.len() as u64
                );
                std::fs::write(&path, [indexed, b"bb\ncc\n"].concat()).unwrap();
                let mut file = File::open(&path).unwrap();
                let position = sidecar.check(&mut file).unwrap();
                let mut rewritten = false;
                let after = sidecar
                    .fold(
                        &mut file,
                        &position,
                        u64::MAX,
                        Instant::now() + std::time::Duration::from_secs(5),
                        64,
                        "oversized",
                        &mut |tx: &Transaction<'_>, _: &[u8], start: u64, end: u64| {
                            if !std::mem::replace(&mut rewritten, true) {
                                std::fs::write(&path, replacement).unwrap();
                            }
                            tx.execute(
                                "INSERT INTO lines VALUES (?1, ?2)",
                                params![start as i64, end as i64],
                            )
                            .sql()?;
                            Ok(())
                        },
                    )
                    .unwrap();
                assert!(rewritten);
                assert_ne!(after.epoch, position.epoch, "{indexed:?} {replacement:?}");
                assert_eq!((after.indexed_to, count(&sidecar)), (0, 0));
                let rebuilt = fold_all(&mut sidecar, &path);
                assert_eq!(rebuilt.indexed_to, replacement.len() as u64);
                assert_eq!(
                    count(&sidecar) as usize,
                    replacement.iter().filter(|byte| **byte == b'\n').count()
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn databases_are_private_and_a_read_only_directory_uses_a_temporary_one() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.jsonl");
        std::fs::write(&path, b"a\n").unwrap();
        let sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
        let mode = sidecar_path(&path, ".test-v1")
            .metadata()
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(sidecar);
        remove(&path, ".test-v1").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
        assert!(sidecar.temporary_reason().is_some());
        assert!(!sidecar_path(&path, ".test-v1").exists());
        assert_eq!(fold_all(&mut sidecar, &path).indexed_to, 2);
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // A link at the database path is never followed.
        let target = root.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, sidecar_path(&path, ".link-v1")).unwrap();
        let linked = Sidecar::open(&path, ".link-v1", "test-v1", SCHEMA).unwrap();
        assert!(linked.temporary_reason().is_some());
        assert_eq!(std::fs::read(&target).unwrap(), b"");
    }

    #[test]
    fn an_unterminated_line_past_the_record_limit_is_an_error() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.jsonl");
        std::fs::write(&path, [b"a\n".to_vec(), vec![b'x'; 100]].concat()).unwrap();
        let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
        let mut file = File::open(&path).unwrap();
        let position = sidecar.check(&mut file).unwrap();
        let error = sidecar
            .fold(
                &mut file,
                &position,
                u64::MAX,
                Instant::now() + std::time::Duration::from_secs(5),
                64,
                "oversized",
                &mut |_: &Transaction<'_>, _: &[u8], _: u64, _: u64| Ok(()),
            )
            .unwrap_err();
        assert_eq!(error.status, 500);
        // The failed fold committed nothing.
        assert_eq!(sidecar.check(&mut file).unwrap().indexed_to, 0);
    }
}
