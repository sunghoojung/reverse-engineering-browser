use std::io::{self, BufRead, Write};

use oxc_allocator::Allocator;
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
mod fold;
mod preflight;
mod proxy;
use serde::{Deserialize, Serialize};

const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_SOURCE_BYTES * 6 + 64 * 1024;
const MAX_TRANSFORMATIONS: usize = 4096;

#[derive(Debug, Deserialize)]
struct Request {
    source: String,
    #[serde(default)]
    assume_intrinsics: bool,
    #[serde(default)]
    function_at_byte: Option<u32>,
}

#[derive(Debug, Serialize)]
struct Response {
    schema: &'static str,
    ok: bool,
    parsed: bool,
    source_bytes: usize,
    syntax_errors: Vec<SyntaxError>,
    evidence: Evidence,
    derived_source: String,
    transformations: Vec<Transformation>,
    transformations_truncated: bool,
    assumptions: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_location: Option<preflight::FunctionLocation>,
}

#[derive(Debug, Serialize)]
struct SyntaxError {
    message: String,
    start: u32,
    end: u32,
}

#[derive(Debug, Default, Serialize)]
struct Evidence {
    statement_count: usize,
    comment_count: usize,
    source_type: &'static str,
}

#[derive(Debug, Serialize)]
struct Transformation {
    kind: &'static str,
    original_start: u32,
    original_end: u32,
    replacement: String,
}

fn error_response(message: impl Into<String>) -> Response {
    Response {
        schema: "reb-deobfuscator-worker-v1",
        ok: false,
        parsed: false,
        source_bytes: 0,
        syntax_errors: vec![SyntaxError {
            message: message.into(),
            start: 0,
            end: 0,
        }],
        evidence: Evidence::default(),
        derived_source: String::new(),
        transformations: Vec::new(),
        transformations_truncated: false,
        assumptions: vec![],
        function_location: None,
    }
}

fn analyze(request: Request) -> Response {
    let source_bytes = request.source.len();
    if source_bytes > MAX_SOURCE_BYTES {
        return error_response("source exceeds the deobfuscation byte limit");
    }

    if let Some(offset) = request.function_at_byte {
        return match preflight::function_at(&request.source, offset as usize) {
            Ok(function_location) => Response {
                schema: "reb-deobfuscator-worker-v1",
                ok: true,
                parsed: true,
                source_bytes,
                syntax_errors: vec![],
                evidence: Evidence::default(),
                derived_source: String::new(),
                transformations: vec![],
                transformations_truncated: false,
                assumptions: vec![],
                function_location,
            },
            Err(message) => {
                let mut response = error_response(message);
                response.source_bytes = source_bytes;
                response
            }
        };
    }
    if let Err(message) = preflight::check(&request.source) {
        let mut response = error_response(message);
        response.source_bytes = source_bytes;
        response.derived_source = request.source;
        return response;
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &request.source, SourceType::unambiguous()).parse();
    let syntax_errors = parsed
        .diagnostics
        .iter()
        .take(64)
        .map(|error| SyntaxError {
            message: error.to_string(),
            start: error.labels.first().map_or(0, |label| label.offset()),
            end: error
                .labels
                .first()
                .map_or(0, |label| label.offset().saturating_add(label.len())),
        })
        .collect::<Vec<_>>();
    let statement_count = parsed.program.body.len();
    let parsed_ok = syntax_errors.is_empty();
    let mut derived_source = request.source.clone();
    let mut transformations = Vec::new();
    let mut transformations_truncated = false;
    if parsed_ok {
        let mut folder =
            fold::Folder::new(&request.source, &parsed.program, request.assume_intrinsics);
        folder.visit_program(&parsed.program);
        transformations_truncated = folder.truncated;
        folder.rewrites.sort_by_key(|fold| fold.original_start);
        // Copy untouched slices once, instead of repeatedly shifting the tail.
        derived_source.clear();
        let mut offset = 0;
        for fold in folder.rewrites {
            let start = fold.original_start as usize;
            let end = fold.original_end as usize;
            derived_source.push_str(&request.source[offset..start]);
            derived_source.push_str(&fold.replacement);
            offset = end;
            transformations.push(Transformation {
                kind: fold.kind,
                original_start: fold.original_start,
                original_end: fold.original_end,
                replacement: fold.replacement,
            });
        }
        derived_source.push_str(&request.source[offset..]);
    }

    Response {
        schema: "reb-deobfuscator-worker-v1",
        ok: parsed_ok,
        parsed: true,
        source_bytes,
        syntax_errors,
        evidence: Evidence {
            statement_count,
            comment_count: parsed.program.comments.len(),
            source_type: "unambiguous",
        },
        derived_source,
        transformations,
        transformations_truncated,
        assumptions: if request.assume_intrinsics {
            vec!["standard-intrinsics"]
        } else {
            vec![]
        },
        function_location: None,
    }
}

// Read at most limit bytes, then drain the remainder of an oversized record.
// Keeping framing after rejection allows the next request to succeed.
fn read_request(reader: &mut impl BufRead, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let mut oversized = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return if oversized {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request exceeds the byte limit",
                ))
            } else if bytes.is_empty() {
                Ok(None)
            } else {
                Ok(Some(bytes))
            };
        }
        let end = chunk.iter().position(|byte| *byte == b'\n');
        let count = end.unwrap_or(chunk.len());
        if !oversized {
            if count > limit.saturating_sub(bytes.len()) {
                oversized = true;
                bytes.clear();
            } else {
                bytes.extend_from_slice(&chunk[..count]);
            }
        }
        reader.consume(count + usize::from(end.is_some()));
        if end.is_some() {
            return if oversized {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request exceeds the byte limit",
                ))
            } else {
                Ok(Some(bytes))
            };
        }
    }
}

fn serve(reader: &mut impl BufRead, writer: &mut impl Write) -> io::Result<()> {
    loop {
        let response = match read_request(reader, MAX_REQUEST_BYTES) {
            Ok(None) => return Ok(()),
            Ok(Some(line)) => match serde_json::from_slice::<Request>(&line) {
                Ok(request) => analyze(request),
                Err(error) => error_response(format!("invalid request: {error}")),
            },
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                error_response(error.to_string())
            }
            Err(error) => return Err(error),
        };
        serde_json::to_writer(&mut *writer, &response)?;
        writeln!(writer)?;
        writer.flush()?;
    }
}

fn main() -> io::Result<()> {
    serve(
        &mut io::stdin().lock(),
        &mut io::BufWriter::new(io::stdout().lock()),
    )
}

#[cfg(test)]
mod tests {
    use super::{MAX_SOURCE_BYTES, Request, analyze};

    #[test]
    fn folds_finite_numeric_literals_and_preserves_unsafe_math() {
        let response = analyze(Request {
            assume_intrinsics: false,
            source: "const value = 1 + 2 * 3; const unsafe = 1 / 0;".to_string(),
            function_at_byte: None,
        });

        assert!(response.ok);
        assert_eq!(
            response.derived_source,
            "const value = (7); const unsafe = 1 / 0;"
        );
        assert_eq!(response.transformations.len(), 1);
        assert_eq!(response.transformations[0].kind, "constant-fold");
    }

    #[test]
    fn reports_parse_errors_without_rewriting_source() {
        let response = analyze(Request {
            assume_intrinsics: false,
            source: "const broken = ;".to_string(),
            function_at_byte: None,
        });

        assert!(!response.ok);
        assert!(!response.parsed);
        assert!(!response.syntax_errors.is_empty());
        assert_eq!(response.derived_source, "const broken = ;");
        assert!(response.transformations.is_empty());
    }

    #[test]
    fn rejects_oversized_sources_before_parsing() {
        let response = analyze(Request {
            assume_intrinsics: false,
            source: "x".repeat(MAX_SOURCE_BYTES + 1),
            function_at_byte: None,
        });

        assert!(!response.ok);
        assert!(!response.parsed);
        assert!(response.syntax_errors[0].message.contains("byte limit"));
    }
}

#[cfg(test)]
mod framing_tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn drains_oversize_and_preserves_next_record() {
        let mut reader = BufReader::with_capacity(3, Cursor::new(b"123456789\nok\n"));
        assert_eq!(
            read_request(&mut reader, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(read_request(&mut reader, 4).unwrap(), Some(b"ok".to_vec()));
        assert!(read_request(&mut reader, 4).unwrap().is_none());
    }

    #[test]
    fn bounds_unterminated_records_and_accepts_exact_limit() {
        assert!(read_request(&mut Cursor::new(b"12345"), 4).is_err());
        assert_eq!(
            read_request(&mut Cursor::new(b"1234"), 4).unwrap(),
            Some(b"1234".to_vec())
        );
    }

    #[test]
    fn invalid_utf8_does_not_destroy_framing() {
        let mut output = Vec::new();
        serve(
            &mut Cursor::new(b"\xff\n{\"source\":\"1+2\"}\n"),
            &mut output,
        )
        .unwrap();
        let responses: Vec<serde_json::Value> = output
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert_eq!(responses[0]["ok"], false);
        assert_eq!(responses[1]["derived_source"], "(3)");
    }
}
