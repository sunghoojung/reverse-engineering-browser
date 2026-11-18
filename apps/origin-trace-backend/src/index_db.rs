//! Disk-backed indexes beside the append-only evidence files.
//!
//! An index is a private SQLite database next to the file it describes
//! (`<file><suffix>`), so a session of any length is indexed once, reopens
//! after a restart without a rescan, and is answered from the database's
//! bounded page cache instead of every row held in memory. It is derived
//! data, never an authority: each use checks the file's device and inode and
//! the digests of its first and last indexed bytes, and a file that was
//! rewritten, truncated or replaced is indexed again from byte 0 under a new
//! epoch. Rows and the indexed position commit in one transaction, so a crash
//! leaves the position the rows describe. A directory that cannot hold the
//! database, such as a read-only bundle, gets one in a private temporary
//! directory that lives as long as the index.
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
    /// The file's length at the last check.
    pub file_end: u64,
    /// The index was found on disk rather than built in this process.
    pub reopened: bool,
}
impl Position {
    /// Every complete record of the file is indexed: what remains is at most
    /// one record still being written.
    pub fn caught_up(&self, record_bytes: u64) -> bool {
        self.file_end.saturating_sub(self.indexed_to) <= record_bytes
    }
}

pub struct Sidecar {
    connection: Connection,
    /// The private directory holding the database when its file's own
    /// directory cannot, as for read-only evidence. It lives as long as the index.
    _temporary: Option<tempfile::TempDir>,
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

/// Digests of the first and last `ANCHOR_BYTES` before `end`.
fn anchors(file: &mut File, end: u64) -> Result<(String, String)> {
    let head = read_range(file, 0, end.min(ANCHOR_BYTES))?;
    let tail = read_range(file, end.saturating_sub(ANCHOR_BYTES), end)?;
    Ok((digest(&head), digest(&tail)))
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
        let same =
            stored == identity && indexed_to <= end && anchors(file, indexed_to)? == (head, tail);
        if !same {
            self.reset(&identity)?;
        }
        let (epoch, _, indexed_to, _, _) = self.meta()?;
        Ok(Position {
            epoch,
            indexed_to,
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
            file_end: 0,
            reopened: self.reopened,
        })
    }

    /// Folds complete lines after the indexed position into one transaction:
    /// at most `budget` bytes, and no new chunk after `deadline`. `each` sees
    /// every terminated line with its byte range; the bytes after the last
    /// newline wait for a later fold. A partial line longer than
    /// `max_line` fails with `oversized`, since no newline can make it a
    /// record. Past `deadline` no further chunk is read.
    #[allow(clippy::too_many_arguments)]
    pub fn fold(
        &mut self,
        file: &mut File,
        position: &Position,
        budget: u64,
        deadline: Instant,
        max_line: usize,
        oversized: &str,
        mut each: impl FnMut(&Transaction<'_>, &[u8], u64, u64) -> Result<()>,
    ) -> Result<Position> {
        let from = position.indexed_to;
        let limit = position.file_end.min(from.saturating_add(budget));
        if limit <= from {
            return Ok(position.clone());
        }
        let transaction = self.connection.transaction().sql()?;
        let mut at = from;
        let mut pending = Vec::new();
        let mut read_to = from;
        file.seek(SeekFrom::Start(from))?;
        while read_to < limit && Instant::now() < deadline {
            let size = ((limit - read_to) as usize).min(CHUNK);
            let mut chunk = std::mem::take(&mut pending);
            let carried = chunk.len();
            chunk.resize(carried + size, 0);
            file.read_exact(&mut chunk[carried..])?;
            read_to += size as u64;
            let Some(last) = chunk.iter().rposition(|byte| *byte == b'\n') else {
                if chunk.len() > max_line {
                    return Err(Error::new(500, oversized));
                }
                pending = chunk;
                continue;
            };
            let mut start = 0;
            for line in chunk[..=last].split_inclusive(|byte| *byte == b'\n') {
                let line_start = at + start as u64;
                start += line.len();
                each(
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
        if at > from {
            let (head, tail) = anchors(file, at)?;
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
            ..position.clone()
        })
    }
}

/// One file and its index, opened when first used. A missing file has an
/// empty index; a capture clear removes the index from disk.
pub struct Indexed {
    source: PathBuf,
    suffix: &'static str,
    format: &'static str,
    schema: &'static str,
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
            sidecar: None,
        }
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
            self.sidecar = Some(Sidecar::open(
                &self.source,
                self.suffix,
                self.format,
                self.schema,
            )?);
        }
        let position = self.sidecar.as_mut().unwrap().check(&mut file)?;
        Ok(Some((file, position)))
    }

    /// The open index; `open` must have returned a file.
    pub fn sidecar(&mut self) -> &mut Sidecar {
        self.sidecar.as_mut().expect("an opened index")
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
        let mut file = File::open(path).unwrap();
        let position = sidecar.check(&mut file).unwrap();
        sidecar
            .fold(
                &mut file,
                &position,
                u64::MAX,
                Instant::now() + std::time::Duration::from_secs(5),
                64,
                "oversized",
                |tx, _, start, end| {
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

    #[test]
    fn folds_appends_reopens_and_rebuilds_a_replaced_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("store.jsonl");
        std::fs::write(&path, b"a\nbb\npartial").unwrap();
        let mut sidecar = Sidecar::open(&path, ".test-v1", "test-v1", SCHEMA).unwrap();
        assert!(sidecar._temporary.is_none());
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
        assert!(sidecar._temporary.is_some());
        assert!(!sidecar_path(&path, ".test-v1").exists());
        assert_eq!(fold_all(&mut sidecar, &path).indexed_to, 2);
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // A link at the database path is never followed.
        let target = root.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, sidecar_path(&path, ".link-v1")).unwrap();
        let linked = Sidecar::open(&path, ".link-v1", "test-v1", SCHEMA).unwrap();
        assert!(linked._temporary.is_some());
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
                |_, _, _, _| Ok(()),
            )
            .unwrap_err();
        assert_eq!(error.status, 500);
        // The failed fold committed nothing.
        assert_eq!(sidecar.check(&mut file).unwrap().indexed_to, 0);
    }
}
