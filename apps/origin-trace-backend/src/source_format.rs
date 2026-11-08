//! Prettier-style formatting of one verified JavaScript artifact. A derived
//! display layer: the contained worker changes only whitespace, and both the
//! worker and this service prove it before a result is returned or cached.
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

enum Outcome {
    Formatted(Arc<str>),
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

/// The verified UTF-8 source and public identity of one JavaScript artifact.
pub(crate) fn load(root: &Path, session: &str, id: &str) -> Result<(String, Value)> {
    let artifact = evidence::find_artifact(root, id)?;
    if artifact["session_id"] != session {
        return Err(Error::new(
            404,
            "Artifact not found in the requested session",
        ));
    }
    if artifact["kind"] != "javascript" {
        return Err(Error::bad("Artifact is not JavaScript"));
    }
    let bytes = evidence::content(root, &artifact, MAX_SOURCE_BYTES)?;
    let source = String::from_utf8(bytes)
        .map_err(|_| Error::bad("Artifact is not valid UTF-8 JavaScript"))?;
    Ok((source, evidence::public_artifact(&artifact)))
}

impl SourceFormat {
    pub(crate) async fn format(
        &self,
        source: String,
        identity: Value,
        window: Option<Window>,
    ) -> Result<Value> {
        let key = identity["sha256"].as_str().unwrap_or_default().to_owned();
        let (outcome, cached) = match self.cached(&key) {
            Some(outcome) => (outcome, true),
            None => {
                let _run = self.run.lock().await;
                match self.cached(&key) {
                    Some(outcome) => (outcome, true),
                    None => {
                        let outcome = Arc::new(contained(source).await?);
                        self.store(key, outcome.clone());
                        (outcome, false)
                    }
                }
            }
        };
        document(&outcome, identity, window, cached)
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
            Outcome::Formatted(text) => text.len(),
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
    window: Option<Window>,
    cached: bool,
) -> Result<Value> {
    let mut result = json!({
        "schema": "source-format-v1",
        "source": identity,
        "language": "javascript",
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
        }
        Outcome::Formatted(text) => {
            let line_count = text.split('\n').count() as u64;
            result["status"] = json!("formatted");
            result["reason"] = Value::Null;
            result["detail"] = Value::Null;
            result["line_count"] = json!(line_count);
            match window {
                None => {
                    result["text"] = json!(&**text);
                    result["window"] = Value::Null;
                }
                Some(window) => {
                    if window.start_line > line_count {
                        return Err(Error::bad("start_line is beyond the formatted text"));
                    }
                    let lines: Vec<&str> = text
                        .split('\n')
                        .skip(window.start_line as usize - 1)
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

async fn contained(source: String) -> Result<Outcome> {
    let heap = heap_limit(source.len());
    let mut input = Vec::with_capacity(24 + source.len());
    input.extend_from_slice(MAGIC);
    input.extend_from_slice(&heap.to_le_bytes());
    input.extend_from_slice(&(source.len() as u64).to_le_bytes());
    input.extend_from_slice(source.as_bytes());
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
                if text.len() > output_limit(source.len()) || !whitespace_only(&source, &text) {
                    return Err(invalid());
                }
                Ok(Outcome::Formatted(Arc::from(text)))
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
        || length > MAX_SOURCE_BYTES as u64
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
        let broken = service
            .format("function(){".into(), identity("b"), None)
            .await
            .unwrap();
        assert_eq!(broken["status"], "unavailable");
        assert_eq!(broken["reason"], "parse-failed");
        assert!(broken["text"].is_null());
        // Deep nesting formats on a grown stack or is refused, never a crash.
        for depth in [2_000, 9_000] {
            let source = format!("x={}1{};", "[".repeat(depth), "]".repeat(depth));
            let deep = service
                .format(source, identity(&depth.to_string()), None)
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
