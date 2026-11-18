//! Paged text reads and search of retained artifacts, for clients allowed to
//! read captured content: `reb-api call`, the UI, and an MCP connection
//! admitted with `--allow-content` (`--permission full`).
//!
//! A page is bounded so its whole JSON document stays under the MCP inline
//! limit (128 KiB): the text costs at most `TEXT_BUDGET` bytes once JSON
//! escapes are counted, and `next_offset` continues the read. A search reads
//! every selected artifact whole, whatever its size, and pages its matches
//! the same way. Every page and every searched file is verified against its
//! manifest digest, as `get_artifact_content` is. Nothing here interprets the
//! bytes.
use crate::{
    artifact_query::ArtifactFilter,
    error::{Code, Error, Result, check_cancelled},
    evidence,
    request_headers::Credentials,
    result_cache::{Cache, kept},
};
use base64::Engine;
use regex::bytes::{Regex, RegexBuilder};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

/// Header blocks and cookie lists hold `Cookie`, `Set-Cookie`, `Authorization`
/// and cookie values, which `get_request_headers` and `get_request_cookies`
/// withhold by name unless the caller asks for them. Text pages and search
/// return them only on that same request, so below Full access, where
/// `reb-api mcp` never asks, those values stay withheld.
pub const WITHHELD_KINDS: [&str; 3] = ["request_headers", "response_headers", "cookie_list"];

fn withheld(artifact: &Value, credentials: Credentials) -> bool {
    credentials == Credentials::Withheld
        && artifact["kind"]
            .as_str()
            .is_some_and(|kind| WITHHELD_KINDS.contains(&kind))
}

/// The largest page in source bytes, before the escaped-size budget applies.
pub const UTF8_PAGE_BYTES: usize = 65_536;
/// Hex doubles each byte, so this keeps hex text at 64 KiB.
pub const HEX_PAGE_BYTES: usize = 32_768;
/// Base64 adds a third, so this keeps base64 text at 64 KiB.
pub const BASE64_PAGE_BYTES: usize = 49_152;
/// JSON bytes the `text` field may cost, escapes included. The rest of the
/// document is under 1 KiB, so a page always fits the 128 KiB inline limit.
pub const TEXT_BUDGET: usize = 98_304;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Hex,
    Base64,
}

impl Encoding {
    pub fn parse(raw: Option<&str>) -> Result<Self> {
        match raw.unwrap_or("utf-8") {
            "utf-8" => Ok(Self::Utf8),
            "hex" => Ok(Self::Hex),
            "base64" => Ok(Self::Base64),
            _ => Err(Error::bad("encoding must be utf-8, hex or base64")),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Hex => "hex",
            Self::Base64 => "base64",
        }
    }
    pub fn page_bytes(self) -> usize {
        match self {
            Self::Utf8 => UTF8_PAGE_BYTES,
            Self::Hex => HEX_PAGE_BYTES,
            Self::Base64 => BASE64_PAGE_BYTES,
        }
    }
}

/// What a JSON string costs for this character, as serde_json writes it.
fn escaped_len(ch: char) -> usize {
    match ch {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        ch if (ch as u32) < 0x20 => 6,
        ch => ch.len_utf8(),
    }
}

/// Decodes UTF-8 from the start of `bytes` until `max_bytes` source bytes or
/// the escaped `budget` are used. A character that starts before `max_bytes`
/// is finished from the bytes after it. Invalid sequences become U+FFFD and are
/// counted. An incomplete character at the end of `bytes` is left for the next
/// page unless `at_end` says nothing follows. Returns the text, the source
/// bytes it covers, and the replacement count.
fn decode_utf8(
    bytes: &[u8],
    max_bytes: usize,
    at_end: bool,
    budget: usize,
) -> (String, usize, usize) {
    let mut text = String::new();
    let mut used = 0usize;
    let mut cost = 0usize;
    let mut replacements = 0usize;
    'outer: while used < bytes.len() && used < max_bytes {
        let rest = &bytes[used..];
        let (valid, invalid) = match std::str::from_utf8(rest) {
            Ok(valid) => (valid, None),
            Err(error) => (
                std::str::from_utf8(&rest[..error.valid_up_to()]).unwrap_or(""),
                Some(error.error_len()),
            ),
        };
        for ch in valid.chars() {
            let next = escaped_len(ch);
            if used >= max_bytes || cost + next > budget {
                break 'outer;
            }
            cost += next;
            text.push(ch);
            used += ch.len_utf8();
        }
        match invalid {
            None => break,
            Some(Some(length)) => {
                if used >= max_bytes || cost + 3 > budget {
                    break;
                }
                cost += 3;
                text.push('\u{FFFD}');
                replacements += 1;
                used += length;
            }
            Some(None) => {
                if at_end && used < max_bytes && cost + 3 <= budget {
                    text.push('\u{FFFD}');
                    replacements += 1;
                    used = bytes.len();
                }
                break;
            }
        }
    }
    (text, used, replacements)
}

fn artifact_identity(artifact: &Value) -> Value {
    json!({
        "artifact_id": artifact["artifact_id"],
        "session_id": artifact["session_id"],
        "kind": artifact["kind"],
        "mime_type": artifact["mime_type"],
        "byte_size": artifact["byte_size"],
        "sha256": artifact["sha256"],
    })
}

/// One page of `artifact` from `offset`, at most `length` source bytes.
pub fn page(
    root: &Path,
    artifact: &Value,
    offset: usize,
    length: usize,
    encoding: Encoding,
    credentials: Credentials,
) -> Result<Value> {
    let total = artifact["byte_size"]
        .as_u64()
        .ok_or_else(|| Error::new(500, "Artifact content byte size is invalid"))?
        as usize;
    if withheld(artifact, credentials) {
        return Err(Error::bad(
            "Header blocks and cookie lists are returned as text only with credential_values=1, which reb-api mcp passes only with --allow-content. Read them with get_request_headers or get_request_cookies, which withhold credential and cookie values otherwise.",
        ));
    }
    if offset > total {
        return Err(Error::bad("offset exceeds the artifact byte size"));
    }
    let length = length.clamp(1, encoding.page_bytes());
    // Three more bytes let a UTF-8 page finish the character it started.
    let lookahead = if encoding == Encoding::Utf8 { 3 } else { 0 };
    let window = evidence::verified_range(root, artifact, offset, length + lookahead)?;
    let (start, text, used, replacements) = match encoding {
        Encoding::Utf8 => {
            // A page that begins inside a character starts at the next one.
            let mut start = 0usize;
            while offset > 0 && start < 3 && window.get(start).is_some_and(|b| b & 0xC0 == 0x80) {
                start += 1;
            }
            let at_end = offset + window.len() >= total;
            let (text, used, replacements) =
                decode_utf8(&window[start..], length, at_end, TEXT_BUDGET);
            (start, text, used, replacements)
        }
        Encoding::Hex => (0, hex::encode(&window), window.len(), 0),
        Encoding::Base64 => (
            0,
            base64::engine::general_purpose::STANDARD.encode(&window),
            window.len(),
            0,
        ),
    };
    let actual = offset + start;
    let next = actual + used;
    Ok(json!({
        "format": "reb-artifact-text-v1",
        "artifact": artifact_identity(artifact),
        "encoding": encoding.name(),
        "offset": actual,
        "length": used,
        "next_offset": if next < total { json!(next) } else { Value::Null },
        "complete": actual == 0 && next >= total,
        "replacements": replacements,
        "page_limit_bytes": encoding.page_bytes(),
        "text": text,
    }))
}

/// Matches one page may return. A page is a paging unit, not a cap on what
/// is searched: every match is counted and `next_offset` reaches each one.
pub const SEARCH_MAX_LIMIT: usize = 200;
/// Bytes of the same line kept on each side of a match.
const SNIPPET_BYTES: usize = 48;
/// Bytes of a long regular-expression match shown in `match`. `byte_length`
/// and `utf16_length` always give the whole match.
const MATCH_TEXT_BYTES: usize = 256;
/// Artifacts named in each coverage list; the counts beside them are exact.
const LISTED: usize = 32;
/// Counted results kept, so the next page of a search counts nothing again.
const CACHED_SEARCHES: usize = 8;
/// Artifact bytes the counting workers hold at once. A larger file is read
/// alone, so every file is searched; this only stops several large files
/// from being held at the same time.
const IN_FLIGHT_BYTES: u64 = 256 * 1024 * 1024;
/// Matches between polls of the request, so an abandoned search stops.
const POLL_MATCHES: u64 = 65_536;
const WHAT: &str = "Artifact search";

pub struct SearchRequest {
    /// `q` as given: literal text, or a regular expression when `regex` is set.
    pub text: String,
    pub regex: bool,
    pub match_case: bool,
    pub filter: ArtifactFilter,
    pub offset: u64,
    pub limit: usize,
    pub credentials: Credentials,
}

impl SearchRequest {
    /// One line of text. Captured text is adversarial, so a regular
    /// expression runs on the `regex` crate, whose matching time is linear in
    /// the text whatever the pattern: nothing can backtrack.
    pub fn query(raw: &str) -> Result<String> {
        if raw.is_empty() || raw.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
            return Err(Error::bad("q must be text on one line"));
        }
        Ok(raw.to_owned())
    }

    /// Literal text matches itself only. Without `match_case`, letters fold
    /// by Unicode simple case folding, as Find in Sources folds them.
    fn pattern(&self) -> Result<Regex> {
        let source = if self.regex {
            self.text.clone()
        } else {
            regex::escape(&self.text)
        };
        RegexBuilder::new(&source)
            .case_insensitive(!self.match_case)
            .multi_line(true)
            .build()
            .map_err(|error| Error::bad(format!("q is not a valid regular expression: {error}")))
    }
}

/// Every nonempty match of `pattern` in `bytes`, left to right. An empty match
/// (a pattern such as `a*` between two letters) is not a match here, so no
/// pattern can report one match per byte. Polls the request between matches.
fn matches<'a>(
    pattern: &'a Regex,
    bytes: &'a [u8],
    cancelled: &'a AtomicBool,
) -> impl Iterator<Item = Result<regex::bytes::Match<'a>>> + 'a {
    let mut seen = 0u64;
    pattern
        .find_iter(bytes)
        .filter(|found| !found.is_empty())
        .map(move |found| {
            seen += 1;
            if seen.is_multiple_of(POLL_MATCHES) {
                check_cancelled(cancelled, WHAT)?;
            }
            Ok(found)
        })
}

/// What `bytes` decode to as the UI decodes them (each maximal invalid
/// sequence is one U+FFFD): characters and UTF-16 code units.
fn measure(bytes: &[u8]) -> (u64, u64) {
    let (mut chars, mut units) = (0u64, 0u64);
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            chars += 1;
            units += ch.len_utf16() as u64;
        }
        if !chunk.invalid().is_empty() {
            chars += 1;
            units += 1;
        }
    }
    (chars, units)
}

/// The line and columns of successive match starts in one file. Each call
/// continues from the previous position, so a page of matches on one long
/// minified line walks that line once.
#[derive(Default)]
struct Position {
    byte: usize,
    /// Lines before `byte`, 0-based.
    line: u64,
    line_start: usize,
    /// Characters and UTF-16 units from `line_start` to `byte`.
    chars: u64,
    units: u64,
}

impl Position {
    fn advance(&mut self, bytes: &[u8], to: usize) {
        let step = &bytes[self.byte..to];
        let breaks = step.iter().filter(|byte| **byte == b'\n').count() as u64;
        if breaks > 0 {
            self.line += breaks;
            self.line_start =
                self.byte + step.iter().rposition(|byte| *byte == b'\n').unwrap_or(0) + 1;
            (self.chars, self.units) = measure(&bytes[self.line_start..to]);
        } else {
            let (chars, units) = measure(step);
            self.chars += chars;
            self.units += units;
        }
        self.byte = to;
    }
}

/// Lossy text of `bytes`. A character cut at either end is dropped rather
/// than shown as U+FFFD.
fn lossy(bytes: &[u8]) -> String {
    let mut start = 0;
    while start < bytes.len().min(3) && bytes[start] & 0xC0 == 0x80 {
        start += 1;
    }
    let mut end = bytes.len();
    for back in 1..=3.min(end - start) {
        let byte = bytes[end - back];
        if byte & 0xC0 == 0x80 {
            continue;
        }
        let width = match byte {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        };
        if width > back {
            end -= back;
        }
        break;
    }
    String::from_utf8_lossy(&bytes[start..end]).into_owned()
}

/// Matches in each selected artifact, from one count of every file.
struct Tally {
    /// Matches before each selected artifact.
    starts: Vec<u64>,
    total: u64,
    files_with_matches: usize,
    /// Indexes of artifacts that could not be read or verified.
    unreadable: Vec<usize>,
    /// Indexes of artifacts whose bytes are not valid UTF-8.
    not_utf8: Vec<usize>,
    bytes: u64,
}

/// Holds artifact bytes in flight to `IN_FLIGHT_BYTES`, waiting while it is
/// spent; one file always proceeds, whatever its size.
struct Budget {
    held: Mutex<u64>,
    freed: Condvar,
}

struct Held<'a>(&'a Budget, u64);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Ok(mut held) = self.0.held.lock() {
            *held -= self.1;
        }
        self.0.freed.notify_all();
    }
}

impl Budget {
    fn take(&self, size: u64, cancelled: &AtomicBool) -> Result<Held<'_>> {
        let poisoned = || Error::new(500, "Artifact search worker failed");
        let mut held = self.held.lock().map_err(|_| poisoned())?;
        while *held > 0 && *held + size > IN_FLIGHT_BYTES {
            held = self
                .freed
                .wait_timeout(held, Duration::from_millis(50))
                .map_err(|_| poisoned())?
                .0;
            check_cancelled(cancelled, WHAT)?;
        }
        *held += size;
        Ok(Held(self, size))
    }
}

/// One file's verified bytes, or None when it cannot be read or verified.
fn verified(root: &Path, artifact: &Value, cancelled: &AtomicBool) -> Result<Option<Vec<u8>>> {
    match evidence::verified_range_cancellable(root, artifact, 0, usize::MAX, cancelled) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.status == 499 => Err(error),
        Err(_) => Ok(None),
    }
}

/// Counts every match in every selected artifact on every core. Each worker
/// takes the next file; the first error, a cancelled request among them,
/// stops every worker.
fn tally(
    root: &Path,
    selected: &[Value],
    pattern: &Regex,
    cancelled: &AtomicBool,
) -> Result<Tally> {
    // (matches, readable, valid UTF-8, bytes) per selected artifact.
    let counts = Mutex::new(vec![(0u64, false, true, 0u64); selected.len()]);
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let budget = Budget {
        held: Mutex::new(0),
        freed: Condvar::new(),
    };
    let count_files = || -> Result<()> {
        loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            if index >= selected.len() || failed.load(Ordering::Relaxed) {
                return Ok(());
            }
            let work = || -> Result<(u64, bool, bool, u64)> {
                let size = selected[index]["byte_size"].as_u64().unwrap_or(0);
                let _held = budget.take(size, cancelled)?;
                let Some(bytes) = verified(root, &selected[index], cancelled)? else {
                    return Ok((0, false, true, 0));
                };
                let mut found = 0u64;
                for item in matches(pattern, &bytes, cancelled) {
                    item?;
                    found += 1;
                }
                Ok((
                    found,
                    true,
                    std::str::from_utf8(&bytes).is_ok(),
                    bytes.len() as u64,
                ))
            };
            match work() {
                Ok(count) => {
                    if let Ok(mut counts) = counts.lock() {
                        counts[index] = count;
                    }
                }
                Err(error) => {
                    failed.store(true, Ordering::Relaxed);
                    return Err(error);
                }
            }
        }
    };
    let workers = thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, selected.len().max(1));
    thread::scope(|scope| {
        let others: Vec<_> = (1..workers).map(|_| scope.spawn(count_files)).collect();
        let mut results = vec![count_files()];
        results.extend(others.into_iter().map(|worker| {
            worker
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }));
        results.into_iter().collect::<Result<Vec<()>>>()
    })?;
    let counts = counts
        .into_inner()
        .map_err(|_| Error::new(500, "Artifact search worker failed"))?;
    let mut tally = Tally {
        starts: Vec::with_capacity(counts.len()),
        total: 0,
        files_with_matches: 0,
        unreadable: Vec::new(),
        not_utf8: Vec::new(),
        bytes: 0,
    };
    for (index, (found, readable, utf8, bytes)) in counts.into_iter().enumerate() {
        tally.starts.push(tally.total);
        tally.total += found;
        tally.files_with_matches += usize::from(found > 0);
        tally.bytes += bytes;
        if !readable {
            tally.unreadable.push(index);
        } else if !utf8 {
            tally.not_utf8.push(index);
        }
    }
    Ok(tally)
}

/// One match as a result row: its byte range, its line and its columns in
/// characters and in UTF-16 units, and context from the same line.
fn match_row(artifact: &Value, bytes: &[u8], at: &Position, start: usize, end: usize) -> Value {
    let before_start = start.saturating_sub(SNIPPET_BYTES).max(at.line_start);
    let window = &bytes[end..bytes.len().min(end + SNIPPET_BYTES)];
    let after_end = window
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(end + window.len(), |line_end| end + line_end);
    let shown = end.min(start + MATCH_TEXT_BYTES);
    json!({
        "artifact_id": artifact["artifact_id"],
        "session_id": artifact["session_id"],
        "kind": artifact["kind"],
        "byte_offset": start,
        "byte_length": end - start,
        "line": at.line + 1,
        "column": at.chars + 1,
        "utf16_column": at.units + 1,
        "utf16_length": measure(&bytes[start..end]).1,
        "before": lossy(&bytes[before_start..start]).trim_start(),
        "match": if shown < end { lossy(&bytes[start..shown]) } else { String::from_utf8_lossy(&bytes[start..end]).into_owned() },
        "match_complete": shown == end,
        "after": lossy(&bytes[end..after_end]).trim_end(),
        "clipped_before": before_start > at.line_start,
        "clipped_after": after_end == end + SNIPPET_BYTES && after_end < bytes.len(),
    })
}

/// Every match in the selected artifacts, oldest artifact first, counted
/// exactly and returned a page at a time. Each artifact is searched whole,
/// whatever its size, and verified against its manifest digest. The count is
/// kept for the query and artifact set, so a later page reads only the files
/// whose matches it lists.
pub fn search(root: &Path, request: &SearchRequest, cancelled: &AtomicBool) -> Result<Value> {
    type Key = (String, bool, bool, Vec<(String, String)>);
    static SEARCHES: Cache<Key, Tally> = Mutex::new(Vec::new());
    let pattern = request.pattern()?;
    // Header blocks and cookie lists are searched only when credential
    // values were asked for, so no other match can show one.
    let selected = evidence::select_artifacts(root, |artifact| {
        !withheld(artifact, request.credentials)
            && request.filter.matches(&evidence::public_artifact(artifact))
    })?;
    let set = selected
        .iter()
        .map(|artifact| {
            (
                artifact["artifact_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                artifact["sha256"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let key = (request.text.clone(), request.regex, request.match_case, set);
    let tally = kept(&SEARCHES, key, CACHED_SEARCHES, || {
        tally(root, &selected, &pattern, cancelled)
    })?;
    let mut rows = Vec::new();
    let mut files = Vec::new();
    let first = tally
        .starts
        .partition_point(|start| *start <= request.offset)
        .saturating_sub(1);
    for (index, (artifact, start)) in selected.iter().zip(&tally.starts).enumerate().skip(first) {
        let start = *start;
        let end = tally.starts.get(index + 1).copied().unwrap_or(tally.total);
        if rows.len() >= request.limit || start >= tally.total {
            break;
        }
        // A file without a match on this page is never read again.
        if end == start || end <= request.offset {
            continue;
        }
        let bytes = verified(root, artifact, cancelled)?.ok_or_else(|| {
            Error::new(500, "Artifact changed during the search; search again")
                .with_code(Code::ArtifactIntegrity)
        })?;
        files.push(json!({
            "artifact_id": artifact["artifact_id"],
            "matches": end - start,
            "first_match": start,
            "valid_utf8": tally.not_utf8.binary_search(&index).is_err(),
        }));
        let mut rank = start;
        let mut at = Position::default();
        for found in matches(&pattern, &bytes, cancelled) {
            let found = found?;
            rank += 1;
            if rank <= request.offset {
                continue;
            }
            at.advance(&bytes, found.start());
            rows.push(match_row(artifact, &bytes, &at, found.start(), found.end()));
            if rows.len() >= request.limit {
                break;
            }
        }
    }
    let next = request.offset + rows.len() as u64;
    let listed = |indexes: &[usize], reason: Option<&str>| {
        indexes
            .iter()
            .take(LISTED)
            .map(|index| match reason {
                Some(reason) => {
                    json!({"artifact_id": selected[*index]["artifact_id"], "reason": reason})
                }
                None => selected[*index]["artifact_id"].clone(),
            })
            .collect::<Vec<_>>()
    };
    Ok(json!({
        "format": "reb-artifact-search-v2",
        "query": {
            "q_bytes": request.text.len(),
            "regex": request.regex,
            "match_case": request.match_case,
            "filters": request.filter.echo(),
            "offset": request.offset,
            "limit": request.limit,
        },
        "total_matches": tally.total,
        "files_with_matches": tally.files_with_matches,
        "matches": rows,
        "files": files,
        "next_offset": if next < tally.total { json!(next) } else { Value::Null },
        "coverage": {
            "artifacts_selected": selected.len(),
            "artifacts_searched": selected.len() - tally.unreadable.len(),
            "bytes_searched": tally.bytes,
            "not_searched": listed(&tally.unreadable, Some("unreadable_or_integrity")),
            "not_searched_count": tally.unreadable.len(),
            "not_valid_utf8": listed(&tally.not_utf8, None),
            "not_valid_utf8_count": tally.not_utf8.len(),
            "complete": tally.unreadable.is_empty(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_pages_keep_characters_whole_and_count_escapes() {
        let (text, used, replaced) = decode_utf8("aé".as_bytes(), 100, true, 100);
        assert_eq!((text.as_str(), used, replaced), ("aé", 3, 0));
        // A character that starts inside the page is finished from the lookahead.
        assert_eq!(decode_utf8("aé".as_bytes(), 2, false, 100).1, 3);
        // An incomplete character waits for the next page unless nothing follows.
        let bytes = "aé".as_bytes();
        assert_eq!(decode_utf8(&bytes[..2], 100, false, 100).1, 1);
        assert_eq!(decode_utf8(&bytes[..2], 100, true, 100).2, 1);
        // Control characters cost six JSON bytes each.
        let (_, used, _) = decode_utf8(&[1u8; 40], 100, true, 60);
        assert_eq!(used, 10);
        let (text, _, replaced) = decode_utf8(&[b'a', 0xff, b'b'], 100, true, 100);
        assert_eq!((text.as_str(), replaced), ("a\u{FFFD}b", 1));
    }

    fn request(text: &str, regex: bool, match_case: bool) -> SearchRequest {
        SearchRequest {
            text: text.to_owned(),
            regex,
            match_case,
            filter: ArtifactFilter::default(),
            offset: 0,
            limit: SEARCH_MAX_LIMIT,
            credentials: Credentials::Withheld,
        }
    }

    fn starts(request: &SearchRequest, bytes: &[u8]) -> Vec<usize> {
        let pattern = request.pattern().unwrap();
        matches(&pattern, bytes, &AtomicBool::new(false))
            .map(|found| found.unwrap().start())
            .collect()
    }

    #[test]
    fn literals_fold_unicode_case_and_regular_expressions_skip_empty_matches() {
        let text = "Token token TOKEN a.b axb".as_bytes();
        assert_eq!(starts(&request("token", false, false), text), [0, 6, 12]);
        assert_eq!(starts(&request("token", false, true), text), [6]);
        assert_eq!(
            starts(&request("a.b", false, false), text),
            [18],
            "pattern syntax in a literal is text"
        );
        assert_eq!(starts(&request("a.b", true, false), text), [18, 22]);
        // Unicode simple case folding, as a JavaScript `giu` Find folds: the
        // Kelvin sign is a K, and Σ folds to σ and ς.
        assert_eq!(
            starts(&request("kelvin", false, false), "\u{212A}elvin".as_bytes()),
            [0]
        );
        assert_eq!(
            starts(&request("σ", false, false), "ΣΑΣ ς".as_bytes()),
            [0, 4, 7]
        );
        // `a*` matches the empty string everywhere; only its nonempty matches count.
        assert_eq!(starts(&request("a*", true, false), b"xaaxa"), [1, 4]);
        // `^` and `$` are line anchors.
        assert_eq!(starts(&request("^b", true, false), b"ab\nbc\nb"), [3, 6]);
        // Invalid UTF-8 never stops a search.
        assert_eq!(
            starts(&request("ok", false, false), b"\xff\xfeok\x80ok"),
            [2, 5]
        );
        for refused in ["", "a\nb", "a\rb", "a\u{2028}b"] {
            assert!(SearchRequest::query(refused).is_err(), "{refused:?}");
        }
        assert!(
            SearchRequest::query(&"x".repeat(100_000)).is_ok(),
            "a literal of any length"
        );
        assert!(request("(", true, false).pattern().is_err());
        assert!(request("(", false, false).pattern().is_ok());
    }

    #[test]
    fn positions_continue_along_one_line_and_count_utf16_like_the_editor() {
        let mut bytes = "a😀b\nxé\u{FEFF}c".as_bytes().to_vec();
        bytes.extend_from_slice(b"\xff\xffd\ne");
        let mut at = Position::default();
        at.advance(&bytes, 5); // "b" after the astral character
        assert_eq!((at.line, at.chars, at.units), (0, 2, 3));
        let c = bytes.iter().position(|byte| *byte == b'c').unwrap();
        at.advance(&bytes, c);
        assert_eq!(
            (at.line, at.chars, at.units),
            (1, 3, 3),
            "a kept BOM is one unit"
        );
        let d = bytes.iter().position(|byte| *byte == b'd').unwrap();
        at.advance(&bytes, d);
        assert_eq!(
            (at.line, at.chars, at.units),
            (1, 6, 6),
            "each invalid byte is one U+FFFD"
        );
        at.advance(&bytes, bytes.len() - 1);
        assert_eq!((at.line, at.line_start, at.chars), (2, bytes.len() - 1, 0));
        assert_eq!(measure("😀".as_bytes()), (1, 2));
    }

    #[test]
    fn rows_clip_context_on_one_long_line_and_show_the_start_of_a_long_match() {
        let line = format!("{}needle{}", "x".repeat(400), "y".repeat(400));
        let artifact = json!({"artifact_id":"1","session_id":"1","kind":"javascript"});
        let start = 400;
        let mut at = Position::default();
        at.advance(line.as_bytes(), start);
        let row = match_row(&artifact, line.as_bytes(), &at, start, start + 6);
        assert_eq!(row["before"], "x".repeat(SNIPPET_BYTES));
        assert_eq!(row["after"], "y".repeat(SNIPPET_BYTES));
        assert_eq!(
            (
                row["clipped_before"].as_bool(),
                row["clipped_after"].as_bool()
            ),
            (Some(true), Some(true))
        );
        assert_eq!(
            (
                row["line"].as_u64(),
                row["column"].as_u64(),
                row["utf16_column"].as_u64()
            ),
            (Some(1), Some(401), Some(401))
        );
        let row = match_row(&artifact, line.as_bytes(), &at, start, line.len());
        assert_eq!(row["match"].as_str().unwrap().len(), MATCH_TEXT_BYTES);
        assert_eq!(
            (
                row["match_complete"].as_bool(),
                row["byte_length"].as_u64(),
                row["utf16_length"].as_u64()
            ),
            (Some(false), Some(406), Some(406))
        );
        let short = "  const a = fetch(b);\nnext";
        let mut at = Position::default();
        at.advance(short.as_bytes(), 12);
        let row = match_row(&artifact, short.as_bytes(), &at, 12, 17);
        assert_eq!(
            (row["before"].as_str(), row["after"].as_str()),
            (Some("const a = "), Some("(b);"))
        );
        assert_eq!(
            (
                row["clipped_before"].as_bool(),
                row["clipped_after"].as_bool()
            ),
            (Some(false), Some(false))
        );
    }

    #[test]
    fn the_in_flight_budget_lets_one_file_of_any_size_through() {
        let budget = Budget {
            held: Mutex::new(0),
            freed: Condvar::new(),
        };
        let cancelled = AtomicBool::new(false);
        let huge = budget.take(IN_FLIGHT_BYTES * 4, &cancelled).unwrap();
        drop(huge);
        let first = budget.take(IN_FLIGHT_BYTES - 1, &cancelled).unwrap();
        thread::scope(|scope| {
            let waiting = scope.spawn(|| budget.take(2, &cancelled).map(|held| held.1));
            thread::sleep(Duration::from_millis(100));
            assert!(
                !waiting.is_finished(),
                "a second file waits while the budget is spent"
            );
            drop(first);
            assert_eq!(waiting.join().unwrap().unwrap(), 2);
        });
        let _held = budget.take(IN_FLIGHT_BYTES, &cancelled).unwrap();
        cancelled.store(true, Ordering::Relaxed);
        assert_eq!(budget.take(1, &cancelled).err().unwrap().status, 499);
    }
}
