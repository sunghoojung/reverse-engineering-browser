//! Forward reads of the event store's complete records, for the scans that
//! select lines with a byte prefilter before parsing any of them
//! (cross-references and the flow graph).
use crate::{
    error::{Error, Result},
    event_window, evidence,
};
use regex::bytes::Regex;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const MAX_RECORD_BYTES: usize = 64 * 1024;
const READ_BUFFER_BYTES: usize = 256 * 1024;

/// Evidence stores read by a scan.
pub struct Stores {
    pub events: PathBuf,
    pub artifacts: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stopped {
    End,
    Visitor,
    Deadline,
}

pub(crate) struct Scanned {
    pub(crate) position: u64,
    pub(crate) stopped: Stopped,
    pub(crate) malformed: u64,
}

/// Reads complete newline-terminated records from `[start, end)`.
pub(crate) struct Reader<'a> {
    pub(crate) cancel: &'a AtomicBool,
    pub(crate) deadline: Instant,
    /// The message of the 499 a cancelled read returns.
    pub(crate) cancelled: &'static str,
}

impl Reader<'_> {
    /// Calls `visit` with each record's start and bytes, without its newline,
    /// for records the prefilter selects. `visit` returns `None` for a
    /// malformed record, which is counted, and `Some(false)` to stop.
    pub(crate) fn lines(
        &self,
        path: &Path,
        start: u64,
        end: u64,
        prefilter: Option<&Regex>,
        visit: &mut dyn FnMut(u64, &[u8]) -> Option<bool>,
    ) -> Result<Scanned> {
        let mut scanned = Scanned {
            position: start,
            stopped: Stopped::End,
            malformed: 0,
        };
        let mut file = match evidence::regular_file(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(scanned),
            Err(error) => return Err(error.into()),
        };
        file.seek(SeekFrom::Start(start))?;
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, file.take(end - start));
        let mut line = Vec::with_capacity(8 * 1024);
        let mut read = 0u32;
        loop {
            read = read.wrapping_add(1);
            if read & 0x3ff == 0 {
                if self.cancel.load(Ordering::Relaxed) {
                    return Err(Error::new(499, self.cancelled));
                }
                if Instant::now() >= self.deadline {
                    scanned.stopped = Stopped::Deadline;
                    return Ok(scanned);
                }
            }
            let line_start = scanned.position;
            line.clear();
            let taken = reader
                .by_ref()
                .take(MAX_RECORD_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)?;
            if taken == 0 {
                return Ok(scanned);
            }
            if line.last() != Some(&b'\n') {
                if taken <= MAX_RECORD_BYTES {
                    // Unterminated tail: a record still being written.
                    return Ok(scanned);
                }
                // Oversized record: skip to its newline and count it.
                scanned.malformed += 1;
                scanned.position += taken as u64;
                loop {
                    let buffer = reader.fill_buf()?;
                    if buffer.is_empty() {
                        return Ok(scanned);
                    }
                    if let Some(index) = buffer.iter().position(|byte| *byte == b'\n') {
                        reader.consume(index + 1);
                        scanned.position += index as u64 + 1;
                        break;
                    }
                    let length = buffer.len();
                    reader.consume(length);
                    scanned.position += length as u64;
                }
                continue;
            }
            scanned.position += taken as u64;
            let record = &line[..line.len() - 1];
            if record.iter().all(u8::is_ascii_whitespace)
                || prefilter.is_some_and(|filter| !filter.is_match(record))
            {
                continue;
            }
            match visit(line_start, record) {
                Some(true) => {}
                Some(false) => {
                    scanned.stopped = Stopped::Visitor;
                    return Ok(scanned);
                }
                None => scanned.malformed += 1,
            }
        }
    }
}

/// The end of the last complete record: the read boundary of a snapshot.
pub(crate) fn complete_end(path: &Path) -> Result<u64> {
    let mut file = match evidence::regular_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let length = file.metadata()?.len();
    let window = length.min(MAX_RECORD_BYTES as u64 + 1);
    file.seek(SeekFrom::Start(length - window))?;
    let mut tail = vec![0; window as usize];
    file.read_exact(&mut tail)?;
    Ok(tail
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(length.saturating_sub(window), |index| {
            length - window + index as u64 + 1
        }))
}

/// A byte pattern for one field of a compact record, quoted or not.
pub(crate) fn field_pattern(field: &str, value: impl std::fmt::Display) -> String {
    format!(r#""{field}":"?{value}"?[,}}]"#)
}

pub(crate) fn same_session(event: &Value, session: u64) -> bool {
    event_window::unsigned(&event["session_id"]).unwrap_or(0) == session
}
