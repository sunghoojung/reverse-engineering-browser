//! Paged text reads and literal search of retained artifacts, for clients
//! allowed to read captured content: `reb-api call`, the UI, and an MCP
//! connection admitted with `--allow-content` (`--permission full`).
//!
//! A page is bounded so its whole JSON document stays under the MCP inline
//! limit (128 KiB): the text costs at most `TEXT_BUDGET` bytes once JSON
//! escapes are counted, and `next_offset` continues the read. Every page and
//! every searched file is verified against its manifest digest, as
//! `get_artifact_content` is. Nothing here interprets the bytes.
use crate::{
    artifact_query::ArtifactFilter,
    error::{Error, Result},
    evidence,
};
use base64::Engine;
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

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
) -> Result<Value> {
    let total = artifact["byte_size"]
        .as_u64()
        .ok_or_else(|| Error::new(500, "Artifact content byte size is invalid"))?
        as usize;
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

/// Bounds of one search: files above `FILE_BYTES` are skipped and named, the
/// call reads at most `TOTAL_BYTES`, and stops at its deadline.
pub const SEARCH_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const SEARCH_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const SEARCH_QUERY_BYTES: usize = 256;
pub const SEARCH_FILE_MATCHES: usize = 100;
pub const SEARCH_MAX_LIMIT: usize = 200;
const SEARCH_DEADLINE: Duration = Duration::from_secs(10);
const SNIPPET_BYTES: usize = 48;
const SKIPPED_LISTED: usize = 32;

pub struct SearchRequest {
    pub query: Vec<u8>,
    pub match_case: bool,
    pub filter: ArtifactFilter,
    pub offset: usize,
    pub limit: usize,
}

impl SearchRequest {
    /// The literal: 1 to 256 UTF-8 bytes on one line. Captured text is
    /// adversarial, so there is no pattern language to backtrack on.
    pub fn query(raw: &str) -> Result<Vec<u8>> {
        if raw.is_empty() || raw.len() > SEARCH_QUERY_BYTES || raw.contains(['\n', '\r']) {
            return Err(Error::bad(
                "q must be 1 to 256 bytes of literal text on one line",
            ));
        }
        Ok(raw.as_bytes().to_vec())
    }
}

fn find_all(haystack: &[u8], needle: &[u8], fold: bool, cap: usize) -> (Vec<usize>, bool) {
    let mut found = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return (found, false);
    }
    let first = needle[0];
    let mut at = 0usize;
    let last = haystack.len() - needle.len();
    while at <= last {
        let byte = haystack[at];
        let lead = if fold {
            byte.eq_ignore_ascii_case(&first)
        } else {
            byte == first
        };
        if lead {
            let candidate = &haystack[at..at + needle.len()];
            let equal = if fold {
                candidate.eq_ignore_ascii_case(needle)
            } else {
                candidate == needle
            };
            if equal {
                if found.len() == cap {
                    return (found, true);
                }
                found.push(at);
                at += needle.len();
                continue;
            }
        }
        at += 1;
    }
    (found, false)
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

/// Literal matches across selected artifacts, oldest artifact first.
pub fn search(root: &Path, request: &SearchRequest) -> Result<Value> {
    let started = Instant::now();
    let fold = !request.match_case;
    let selected = evidence::select_artifacts(root, |artifact| {
        request.filter.matches(&evidence::public_artifact(artifact))
    })?;
    let wanted = request.offset.saturating_add(request.limit);
    let mut matches = Vec::new();
    let mut seen = 0usize;
    let mut more = false;
    let mut bytes_searched = 0usize;
    let mut searched = 0usize;
    let mut skipped = Vec::new();
    let mut skipped_count = 0usize;
    let mut skip = |id: &Value, reason: &str, skipped: &mut Vec<Value>| {
        skipped_count += 1;
        if skipped.len() < SKIPPED_LISTED {
            skipped.push(json!({"artifact_id": id, "reason": reason}));
        }
    };
    let mut stopped = None;
    for artifact in &selected {
        if seen > wanted {
            more = true;
            break;
        }
        if started.elapsed() >= SEARCH_DEADLINE {
            stopped = Some("deadline");
            break;
        }
        let size = artifact["byte_size"].as_u64().unwrap_or(u64::MAX) as usize;
        if size > SEARCH_FILE_BYTES {
            skip(&artifact["artifact_id"], "larger_than_16_mib", &mut skipped);
            continue;
        }
        if bytes_searched + size > SEARCH_TOTAL_BYTES {
            stopped = Some("total_bytes");
            break;
        }
        let content = match evidence::content(root, artifact, SEARCH_FILE_BYTES) {
            Ok(content) => content,
            Err(_) => {
                skip(
                    &artifact["artifact_id"],
                    "unreadable_or_integrity",
                    &mut skipped,
                );
                continue;
            }
        };
        bytes_searched += content.len();
        searched += 1;
        let (positions, capped) = find_all(&content, &request.query, fold, SEARCH_FILE_MATCHES);
        if capped {
            skip(&artifact["artifact_id"], "file_match_limit", &mut skipped);
        }
        let mut line = 1usize;
        let mut line_start = 0usize;
        let mut cursor = 0usize;
        for position in positions {
            for (index, byte) in content[cursor..position].iter().enumerate() {
                if *byte == b'\n' {
                    line += 1;
                    line_start = cursor + index + 1;
                }
            }
            cursor = position;
            seen += 1;
            if seen <= request.offset {
                continue;
            }
            if seen > wanted {
                more = true;
                break;
            }
            let end = position + request.query.len();
            let column = content[line_start..position]
                .iter()
                .filter(|byte| **byte & 0xC0 != 0x80)
                .count()
                + 1;
            let before_start = position.saturating_sub(SNIPPET_BYTES).max(line_start);
            let line_end = content[end..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(content.len(), |at| end + at);
            let after_end = (end + SNIPPET_BYTES).min(line_end);
            matches.push(json!({
                "artifact_id": artifact["artifact_id"],
                "session_id": artifact["session_id"],
                "kind": artifact["kind"],
                "byte_offset": position,
                "line": line,
                "column": column,
                "before": lossy(&content[before_start..position]).trim_start().to_owned(),
                "match": String::from_utf8_lossy(&content[position..end]),
                "after": lossy(&content[end..after_end]).trim_end().to_owned(),
            }));
        }
    }
    let complete = stopped.is_none() && !more && skipped_count == 0;
    let returned = matches.len();
    Ok(json!({
        "format": "reb-artifact-search-v1",
        "query": {
            "q_bytes": request.query.len(),
            "match_case": request.match_case,
            "filters": request.filter.echo(),
            "offset": request.offset,
            "limit": request.limit,
        },
        "matches": matches,
        "next_offset": if more { json!(request.offset + returned) } else { Value::Null },
        "coverage": {
            "artifacts_selected": selected.len(),
            "artifacts_searched": searched,
            "bytes_searched": bytes_searched,
            "stopped": stopped,
            "not_fully_searched": skipped,
            "not_fully_searched_count": skipped_count,
            "complete": complete,
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

    #[test]
    fn literal_search_folds_ascii_only_when_asked() {
        let (found, capped) = find_all(b"Token token TOKEN", b"token", true, 10);
        assert_eq!((found, capped), (vec![0, 6, 12], false));
        assert_eq!(
            find_all(b"Token token TOKEN", b"token", false, 10).0,
            vec![6]
        );
        assert!(find_all(b"aaaa", b"a", false, 2).1);
        assert_eq!(lossy("éa".as_bytes()), "éa");
        assert_eq!(lossy(&"éa".as_bytes()[1..]), "a");
        assert_eq!(lossy(&"aé".as_bytes()[..2]), "a");
    }
}
