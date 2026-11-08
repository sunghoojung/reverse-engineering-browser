//! Prettier-style formatting of one verified JavaScript artifact or JavaScript
//! or JSON body. A derived display layer: the contained worker changes only
//! whitespace, and both the worker and this service prove it before a result
//! is returned or cached.
use crate::{
    error::{Code, Error, Result},
    evidence, source_format_doc, source_format_js,
};
use serde_json::{Value, json};
use std::{collections::VecDeque, path::Path, sync::Arc, time::Duration};
use tokio::sync::Mutex;

pub(crate) const WORKER_FLAG: &str = "--format-javascript-worker";
pub(crate) const WORKER_TEST_VALUE: &str = "format";
const MAGIC: &[u8; 8] = b"REBFMT01";
const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_WINDOW_LINES: u64 = 10_000;
const CACHE_ENTRIES: usize = 4;
const CACHE_BYTES: usize = 96 * 1024 * 1024;
const ENGINE: &str = "oxc-0.155-token-layout";
const ANCHOR_LINES: u64 = 1000;
/// JSON is laid out as one parenthesized expression; the newline ends a trailing line comment.
const JSON_OPEN: &str = "(";
const JSON_CLOSE: &str = "\n)";

/// Indentation and line breaks bound the growth of whitespace-only output.
fn output_limit(source_bytes: usize) -> usize {
    source_bytes.saturating_mul(4) + (1 << 20)
}
/// Measured peaks are 80 to 100 bytes per source byte, mostly the Oxc arena.
fn heap_limit(source_bytes: usize) -> u64 {
    (64 << 20) + source_bytes as u64 * 128
}
fn deadline(source_bytes: usize) -> Duration {
    Duration::from_secs(30 + 15 * source_bytes.div_ceil(1 << 20) as u64)
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Status {
    Formatted = 0,
    Parse = 1,
    Output = 2,
    Fidelity = 3,
    Memory = 4,
    Nesting = 5,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    JavaScript,
    Json,
}

impl Language {
    fn name(self) -> &'static str {
        match self {
            Language::JavaScript => "javascript",
            Language::Json => "json",
        }
    }
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "javascript" => Some(Language::JavaScript),
            "json" => Some(Language::Json),
            _ => None,
        }
    }
    fn of_mime(mime: &str) -> Option<Self> {
        let mime = mime
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if mime == "application/json" || mime == "text/json" || mime.ends_with("+json") {
            Some(Language::Json)
        } else if matches!(
            mime.as_str(),
            "text/javascript"
                | "application/javascript"
                | "application/x-javascript"
                | "text/ecmascript"
                | "application/ecmascript"
        ) {
            Some(Language::JavaScript)
        } else {
            None
        }
    }
}

struct Laid {
    text: Arc<str>,
    line_count: u64,
    /// Per block: its first line's byte offset in `text` and its first non-whitespace UTF-16 source offset.
    anchors: Vec<(usize, u64)>,
}

enum Outcome {
    Formatted(Laid),
    Unavailable(Status),
}

impl Status {
    fn reason(self) -> &'static str {
        match self {
            Status::Formatted => "formatted",
            Status::Parse => "parse-failed",
            Status::Output => "output-limit",
            Status::Fidelity => "fidelity-check-failed",
            Status::Memory => "memory-limit",
            Status::Nesting => "nesting-limit",
        }
    }
    fn detail(self) -> &'static str {
        match self {
            Status::Formatted => "",
            Status::Parse => {
                "The source does not parse as a JavaScript script or module, so no layout was derived."
            }
            Status::Output => "The formatted text would exceed four times the source size.",
            Status::Fidelity => {
                "The layout did not reproduce the original tokens and was discarded."
            }
            Status::Memory => "The contained formatter reached its memory ceiling.",
            Status::Nesting => "The source nests deeper than the parser admission limit.",
        }
    }
}

pub(crate) struct Window {
    pub start_line: u64,
    pub line_count: u64,
}

#[derive(Default)]
pub(crate) struct SourceFormat {
    cache: std::sync::Mutex<VecDeque<(String, Arc<Outcome>)>>,
    /// One contained formatter at a time; later requests reuse its result.
    run: Mutex<()>,
}

/// The verified UTF-8 source, identity and language of a JavaScript artifact or JavaScript or JSON body.
pub(crate) fn load(
    root: &Path,
    session: &str,
    id: &str,
    language: Option<Language>,
) -> Result<(String, Value, Language)> {
    let artifact = evidence::find_artifact(root, id)?;
    if artifact["session_id"] != session {
        return Err(Error::new(
            404,
            "Artifact not found in the requested session",
        ));
    }
    let language = match artifact["kind"].as_str() {
        Some("javascript") if language.is_none_or(|value| value == Language::JavaScript) => {
            Language::JavaScript
        }
        Some("request_body" | "response_body") => language
            .or_else(|| Language::of_mime(artifact["mime_type"].as_str().unwrap_or("")))
            .ok_or_else(|| Error::bad("Body is not JavaScript or JSON"))?,
        _ => {
            return Err(Error::bad(
                "Artifact is not JavaScript or a request or response body",
            ));
        }
    };
    let bytes = evidence::content(root, &artifact, MAX_SOURCE_BYTES)?;
    let source =
        String::from_utf8(bytes).map_err(|_| Error::bad("Artifact is not valid UTF-8 text"))?;
    Ok((source, evidence::public_artifact(&artifact), language))
}

impl SourceFormat {
    pub(crate) async fn format(
        &self,
        source: String,
        identity: Value,
        language: Language,
        window: Option<Window>,
    ) -> Result<Value> {
        let key = format!(
            "{}:{}",
            identity["sha256"].as_str().unwrap_or_default(),
            language.name()
        );
        let (outcome, cached) = match self.cached(&key) {
            Some(outcome) => (outcome, true),
            None => {
                let _run = self.run.lock().await;
                match self.cached(&key) {
                    Some(outcome) => (outcome, true),
                    None => {
                        let outcome = Arc::new(contained(source, language).await?);
                        self.store(key, outcome.clone());
                        (outcome, false)
                    }
                }
            }
        };
        document(&outcome, identity, language, window, cached)
    }

    fn cached(&self, key: &str) -> Option<Arc<Outcome>> {
        let mut cache = self.cache.lock().unwrap();
        let at = cache.iter().position(|(entry, _)| entry == key)?;
        let entry = cache.remove(at)?;
        let outcome = entry.1.clone();
        cache.push_front(entry);
        Some(outcome)
    }

    fn store(&self, key: String, outcome: Arc<Outcome>) {
        let size = |outcome: &Outcome| match outcome {
            Outcome::Formatted(laid) => laid.text.len(),
            Outcome::Unavailable(_) => 0,
        };
        let mut cache = self.cache.lock().unwrap();
        cache.push_front((key, outcome));
        while cache.len() > CACHE_ENTRIES
            || (cache.len() > 1
                && cache.iter().map(|(_, value)| size(value)).sum::<usize>() > CACHE_BYTES)
        {
            cache.pop_back();
        }
    }
}

fn document(
    outcome: &Outcome,
    identity: Value,
    language: Language,
    window: Option<Window>,
    cached: bool,
) -> Result<Value> {
    let mut result = json!({
        "schema": "source-format-v1",
        "source": identity,
        "language": language.name(),
        "engine": ENGINE,
        "layout": {"print_width": source_format_doc::PRINT_WIDTH, "indent": 2},
        "mapping": "whitespace-only",
        "cached": cached,
        "limits": {
            "max_source_bytes": MAX_SOURCE_BYTES,
            "max_output_ratio": 4,
            "max_window_lines": MAX_WINDOW_LINES
        }
    });
    match outcome {
        Outcome::Unavailable(status) => {
            result["status"] = json!("unavailable");
            result["reason"] = json!(status.reason());
            result["detail"] = json!(status.detail());
            result["text"] = Value::Null;
            result["line_count"] = Value::Null;
            result["window"] = Value::Null;
            result["anchors"] = Value::Null;
        }
        Outcome::Formatted(laid) => {
            result["status"] = json!("formatted");
            result["reason"] = Value::Null;
            result["detail"] = Value::Null;
            result["line_count"] = json!(laid.line_count);
            result["anchors"] = json!({
                "lines": ANCHOR_LINES,
                "source_utf16": laid.anchors.iter().map(|&(_, utf16)| utf16).collect::<Vec<_>>()
            });
            match window {
                None => {
                    result["text"] = json!(&*laid.text);
                    result["window"] = Value::Null;
                }
                Some(window) => {
                    if window.start_line > laid.line_count {
                        return Err(Error::bad("start_line is beyond the formatted text"));
                    }
                    let skip = window.start_line - 1;
                    let from = laid.anchors[(skip / ANCHOR_LINES) as usize].0;
                    let lines: Vec<&str> = laid.text[from..]
                        .split('\n')
                        .skip((skip % ANCHOR_LINES) as usize)
                        .take(window.line_count as usize)
                        .collect();
                    result["window"] = json!({
                        "start_line": window.start_line,
                        "line_count": lines.len()
                    });
                    result["text"] = json!(lines.join("\n"));
                }
            }
        }
    }
    Ok(result)
}

/// Whitespace-only, so the n-th non-whitespace characters of layout and source are the same.
fn laid(source: &str, text: String) -> Laid {
    let mut anchors = Vec::new();
    let mut original = source.chars();
    let (mut utf16, mut line, mut pending) = (0u64, 0u64, vec![0usize]);
    for (at, character) in text.char_indices() {
        if character == '\n' {
            line += 1;
            if line % ANCHOR_LINES == 0 {
                pending.push(at + 1);
            }
        }
        if js_space(character) {
            continue;
        }
        for next in original.by_ref() {
            if !js_space(next) {
                anchors.extend(pending.drain(..).map(|start| (start, utf16)));
                utf16 += next.len_utf16() as u64;
                break;
            }
            utf16 += next.len_utf16() as u64;
        }
    }
    utf16 += original.map(|next| next.len_utf16() as u64).sum::<u64>();
    anchors.extend(pending.drain(..).map(|start| (start, utf16)));
    Laid {
        text: Arc::from(text),
        line_count: line + 1,
        anchors,
    }
}

async fn contained(source: String, language: Language) -> Result<Outcome> {
    let program = match language {
        Language::JavaScript => source.clone(),
        Language::Json => format!("{JSON_OPEN}{source}{JSON_CLOSE}"),
    };
    let heap = heap_limit(program.len());
    let mut input = Vec::with_capacity(24 + program.len());
    input.extend_from_slice(MAGIC);
    input.extend_from_slice(&heap.to_le_bytes());
    input.extend_from_slice(&(program.len() as u64).to_le_bytes());
    input.extend_from_slice(program.as_bytes());
    drop(program);
    let mut command =
        crate::vm::dispatch_shape::javascript::worker_command_for(WORKER_FLAG, WORKER_TEST_VALUE)
            .map_err(|_| {
            Error::new(503, "The JavaScript formatter worker could not start")
                .with_code(Code::DependencyUnavailable)
        })?;
    let output = crate::worker::run(
        &mut command,
        &input,
        output_limit(source.len()) + 64,
        deadline(source.len()),
    )
    .await?;
    drop(input);
    let bytes = reply(&output.bytes);
    if bytes.starts_with(crate::js_worker_alloc::REFUSED) && output.exit_code == Some(75) {
        return Ok(Outcome::Unavailable(Status::Memory));
    }
    if !output.success || bytes.len() < 17 || &bytes[..8] != MAGIC {
        return Err(invalid());
    }
    let payload = bytes[17..].to_vec();
    match bytes[16] {
        0 => {
            // Repeated on the exact bytes returned: only whitespace may differ.
            tokio::task::spawn_blocking(move || {
                let text = String::from_utf8(payload).map_err(|_| invalid())?;
                let text = match language {
                    Language::JavaScript => text,
                    Language::Json => match json_value(&text) {
                        Some(value) => value.to_owned(),
                        None => return Ok(Outcome::Unavailable(Status::Fidelity)),
                    },
                };
                if text.len() > output_limit(source.len()) || !whitespace_only(&source, &text) {
                    return Err(invalid());
                }
                Ok(Outcome::Formatted(laid(&source, text)))
            })
            .await
            .map_err(|error| Error::new(500, error.to_string()))?
        }
        1 => Ok(Outcome::Unavailable(Status::Parse)),
        2 => Ok(Outcome::Unavailable(Status::Output)),
        3 => Ok(Outcome::Unavailable(Status::Fidelity)),
        5 => Ok(Outcome::Unavailable(Status::Nesting)),
        _ => Err(invalid()),
    }
}

fn json_value(text: &str) -> Option<&str> {
    text.strip_prefix(JSON_OPEN)?
        .trim_end_matches(js_space)
        .strip_suffix(')')
}

/// libtest prints a banner before the re-executed worker writes its reply.
fn reply(bytes: &[u8]) -> &[u8] {
    const BANNER: &[u8] = b"\nrunning 1 test\n";
    bytes.strip_prefix(BANNER).unwrap_or(bytes)
}

fn invalid() -> Error {
    Error::new(
        502,
        "The JavaScript formatter worker returned an invalid response",
    )
}

/// ECMAScript WhiteSpace and LineTerminator, the separators the layout may change.
fn js_space(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

pub(crate) fn whitespace_only(original: &str, formatted: &str) -> bool {
    original
        .chars()
        .filter(|character| !js_space(*character))
        .eq(formatted.chars().filter(|character| !js_space(*character)))
}

/// Entry for the contained worker process. Reads one request from stdin.
pub(crate) fn worker_main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    let mut input = std::io::stdin().lock();
    let mut header = [0u8; 24];
    input.read_exact(&mut header)?;
    let heap = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let length = u64::from_le_bytes(header[16..24].try_into().unwrap());
    if &header[..8] != MAGIC
        || length > (MAX_SOURCE_BYTES + JSON_OPEN.len() + JSON_CLOSE.len()) as u64
        || heap > heap_limit(length as usize)
    {
        return Err(std::io::Error::other("Invalid JavaScript formatter limits"));
    }
    crate::js_worker_alloc::start(heap);
    let mut source = String::new();
    input.take(length).read_to_string(&mut source)?;
    if source.len() as u64 != length {
        return Err(std::io::Error::other(
            "Incomplete JavaScript formatter source",
        ));
    }
    // The classifier's nesting admission also sizes the parser and layout stack.
    let result = crate::vm::dispatch_shape::javascript::syntax_stack(&source).map(|stack| {
        stacker::grow(stack, || {
            source_format_js::format(&source, output_limit(source.len()))
        })
    });
    let (status, text) = match result {
        None => (Status::Nesting, String::new()),
        Some(Ok(text)) => (Status::Formatted, text),
        Some(Err(source_format_js::Refusal::Parse)) => (Status::Parse, String::new()),
        Some(Err(source_format_js::Refusal::Output)) => (Status::Output, String::new()),
        Some(Err(source_format_js::Refusal::Fidelity)) => (Status::Fidelity, String::new()),
    };
    let peak = crate::js_worker_alloc::peak();
    let mut output = std::io::stdout().lock();
    output.write_all(MAGIC)?;
    output.write_all(&peak.to_le_bytes())?;
    output.write_all(&[status as u8])?;
    output.write_all(text.as_bytes())?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_name_the_source_offset_of_every_thousandth_line() {
        let source = "a;\u{e9}\u{1f600};".repeat(1500);
        let text = "a;\n\u{e9}\u{1f600};\n".repeat(1500);
        let laid = laid(&source, text.clone());
        assert_eq!(laid.line_count, 3001);
        assert_eq!(laid.anchors.len(), 4);
        for (block, &(start, utf16)) in laid.anchors.iter().enumerate() {
            let line = block * 1000;
            assert_eq!(text[start..].split('\n').next(), text.split('\n').nth(line));
            let expected: usize = source.chars().take(line / 2 * 5).map(char::len_utf16).sum();
            assert_eq!(
                utf16 as usize,
                if line % 2 == 0 {
                    expected
                } else {
                    expected + 2
                }
            );
        }
        assert_eq!(laid.anchors[3].1 as usize, source.encode_utf16().count());
        assert_eq!(json_value("({ a: 1 }\n)\n"), Some("{ a: 1 }\n"));
        assert_eq!(json_value("[1]"), None);
    }

    #[test]
    fn whitespace_only_ignores_javascript_separators_and_nothing_else() {
        assert!(whitespace_only("a=\u{feff}1;\u{2028}b", "a = 1;\n  b"));
        assert!(!whitespace_only("a=1", "a = 2"));
        assert!(!whitespace_only("a\u{85}b", "ab"));
        assert!(!whitespace_only("ab", "a b c"));
    }

    #[tokio::test]
    async fn contained_worker_formats_caches_and_refuses_broken_syntax() {
        let service = SourceFormat::default();
        let identity = |sha: &str| json!({"artifact_id": "1", "sha256": sha});
        let first = service
            .format(
                "var a=function(e,t){return e+t};".into(),
                identity("a"),
                Language::JavaScript,
                None,
            )
            .await
            .unwrap();
        assert_eq!(first["status"], "formatted");
        assert_eq!(
            first["text"],
            "var a = function (e, t) {\n  return e + t\n};\n"
        );
        assert_eq!(first["cached"], false);
        let again = service
            .format(
                String::new(),
                identity("a"),
                Language::JavaScript,
                Some(Window {
                    start_line: 2,
                    line_count: 1,
                }),
            )
            .await
            .unwrap();
        assert_eq!(again["cached"], true);
        assert_eq!(again["text"], "  return e + t");
        assert_eq!(again["window"], json!({"start_line": 2, "line_count": 1}));
        assert_eq!(
            again["anchors"],
            json!({"lines": 1000, "source_utf16": [0]})
        );
        let json_body = r#"{"a":[1,2],"é":{"b":null}}"#;
        let laid_json = service
            .format(json_body.into(), identity("j"), Language::Json, None)
            .await
            .unwrap();
        assert_eq!(laid_json["language"], "json");
        assert_eq!(laid_json["text"], r#"{ "a": [1, 2], "é": { "b": null } }"#);
        assert!(whitespace_only(
            json_body,
            laid_json["text"].as_str().unwrap()
        ));
        let broken = service
            .format(
                "function(){".into(),
                identity("b"),
                Language::JavaScript,
                None,
            )
            .await
            .unwrap();
        assert_eq!(broken["status"], "unavailable");
        assert_eq!(broken["reason"], "parse-failed");
        assert!(broken["text"].is_null());
        // Deep nesting formats on a grown stack or is refused, never a crash.
        for depth in [2_000, 9_000] {
            let source = format!("x={}1{};", "[".repeat(depth), "]".repeat(depth));
            let deep = service
                .format(
                    source,
                    identity(&depth.to_string()),
                    Language::JavaScript,
                    None,
                )
                .await
                .unwrap();
            let expected = if depth < 8192 {
                "formatted"
            } else {
                "unavailable"
            };
            assert_eq!(deep["status"], expected, "{depth}");
        }
    }
}
