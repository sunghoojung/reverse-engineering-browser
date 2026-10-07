use std::io::{self, BufRead, Write};

use oxc_allocator::Allocator;
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
mod fold;
mod preflight;
mod proxy;
mod request_field;
mod source_facts;
use serde::{Deserialize, Serialize};

const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_SOURCE_BYTES * 6 + 64 * 1024;
const MAX_TRANSFORMATIONS: usize = 4096;
const MAX_DERIVED_BYTES: usize = MAX_SOURCE_BYTES + 512 * 1024;

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
    error_kind: Option<&'static str>,
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
        error_kind: None,
        function_location: None,
    }
}

// Validate the whole candidate before publishing any rewrite receipts. The
// heap-backed preflight bounds recursive Oxc parsing of generated text too.
fn validate_derived(source: &str, source_type: SourceType) -> Result<(), &'static str> {
    if source.len() > MAX_DERIVED_BYTES {
        return Err("derived output exceeds its byte limit; original source is preserved");
    }
    preflight::check(source).map_err(
        |_| "derived output failed bounded syntax preflight; original source is preserved",
    )?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.diagnostics.is_empty() {
        return Err("derived output failed syntax validation; original source is preserved");
    }
    Ok(())
}

fn validate_response(mut response: Response, original: &str, source_type: SourceType) -> Response {
    let Err(message) = validate_derived(&response.derived_source, source_type) else {
        return response;
    };
    response.ok = false;
    response.error_kind = Some("derived-validation");
    // This diagnostic describes generated text, not a range in original evidence.
    response.syntax_errors = vec![SyntaxError {
        message: message.to_string(),
        start: 0,
        end: 0,
    }];
    response.derived_source = original.to_string();
    response.transformations.clear();
    response
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
                error_kind: None,
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
        transformations_truncated = folder.is_truncated();
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

    let response = Response {
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
        error_kind: None,
        function_location: None,
    };
    if parsed_ok && !response.transformations.is_empty() {
        return validate_response(response, &request.source, parsed.program.source_type);
    }
    response
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
            Ok(Some(line)) => {
                let operation = serde_json::from_slice::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("operation")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned)
                    });
                if operation.as_deref() == Some("source_facts") {
                    match serde_json::from_slice::<source_facts::Request>(&line) {
                        Ok(request) => source_facts::analyze(request),
                        Err(_) => source_facts::invalid("invalid source facts request", 0),
                    }
                } else if operation.as_deref() == Some("request_field") {
                    match serde_json::from_slice::<request_field::Request>(&line) {
                        Ok(request) => serde_json::to_value(request_field::extract(request))?,
                        Err(_) => {
                            serde_json::to_value(request_field::extract(request_field::Request {
                                operation: String::new(),
                                body: String::new(),
                                pointer: String::new(),
                            }))?
                        }
                    }
                } else {
                    let analyzed = match serde_json::from_slice::<Request>(&line) {
                        Ok(request) => analyze(request),
                        Err(error) => error_response(format!("invalid request: {error}")),
                    };
                    serde_json::to_value(analyzed)?
                }
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                serde_json::to_value(error_response(error.to_string()))?
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
    use super::*;

    #[test]
    fn preserves_shorthand_while_folding_value_positions() {
        for source in [
            "const x=1; const result={x};",
            "const x=1; const result={nested:{x}, explicit:x, [x]:x};",
            "const 雪=1; const result={/* key */ 雪};",
            "const x=1; const result=()=>({x});",
            "const x=1; export {x};",
            "const x=1; let y; ({x:y}={x}); const result=y;",
        ] {
            let response = analyze(Request {
                source: source.to_string(),
                assume_intrinsics: false,
                function_at_byte: None,
            });
            assert!(response.ok, "{source}: {:?}", response.syntax_errors);
            assert!(validate_derived(&response.derived_source, SourceType::unambiguous()).is_ok());
            assert!(!response.derived_source.contains("{(1)}"));
            if source.contains("explicit:x") {
                assert!(response.derived_source.contains("explicit:(1)"));
                assert!(response.derived_source.contains("[(1)]:(1)"));
                assert!(response.derived_source.contains("nested:{x}"));
            } else {
                assert_eq!(response.derived_source, source);
            }
        }
    }

    #[test]
    fn malformed_candidate_discards_receipts_and_preserves_original() {
        let original = "const result=1+2;";
        let mut response = analyze(Request {
            source: original.to_string(),
            assume_intrinsics: false,
            function_at_byte: None,
        });
        assert_eq!(response.transformations.len(), 1);
        response.derived_source = "const result={(3)};".to_string();
        response.transformations[0].replacement = "{(3)}".to_string();
        let rejected = validate_response(response, original, SourceType::unambiguous());
        assert!(!rejected.ok);
        assert!(rejected.parsed); // The original parsed successfully.
        assert_eq!(rejected.error_kind, Some("derived-validation"));
        assert_eq!(rejected.derived_source, original);
        assert!(rejected.transformations.is_empty());
        assert!(
            rejected.syntax_errors[0]
                .message
                .contains("original source is preserved")
        );
        assert!(
            validate_derived(
                &"x".repeat(MAX_DERIVED_BYTES + 1),
                SourceType::unambiguous()
            )
            .is_err()
        );
        assert!(
            validate_derived(
                &format!("{}0;", "!".repeat(10_000)),
                SourceType::unambiguous()
            )
            .is_err()
        );
    }

    #[test]
    fn visible_intrinsic_mutations_and_exposure_suppress_proxy_modeling() {
        for prefix in [
            "delete \"\".__proto__.charAt;",
            "\"\".__proto__.charAt++;",
            "delete \"\"[\"__proto__\"][\"charAt\"];",
            "\"\"[\"__proto__\"][\"charAt\"]++;",
            "Reflect.defineProperty(\"\".__proto__,\"charAt\",{value:function(){return \"changed\"}});",
            "const prototype=\"\".__proto__;",
            "Reflect[\"defineProperty\"](\"\"[\"__proto__\"],\"charAt\",{value:function(){return \"changed\"}});",
        ] {
            let source = format!("{prefix}const f=s=>s.charAt(0);const result=f(\"ab\");");
            let response = analyze(Request {
                source,
                assume_intrinsics: true,
                function_at_byte: None,
            });
            assert!(response.ok);
            assert!(response.derived_source.contains("f(\"ab\")"));
            assert!(response.transformations.iter().all(|rewrite| rewrite.kind != "proxy-call" && rewrite.kind != "custom-decoder"));
        }
    }

    #[test]
    fn small_owned_array_decoder_still_recovers_a_primitive_result() {
        let response = analyze(Request {
            source: "const f=function(){var a=[0];for(var i=0;i<3;i++){a=[a,a]}return a.length};const result=f();".to_string(),
            assume_intrinsics: true,
            function_at_byte: None,
        });
        assert!(response.ok);
        assert!(!response.transformations_truncated);
        assert!(response.derived_source.ends_with("const result=(2);"));
    }

    #[test]
    fn direct_intrinsics_are_opt_in_with_exact_original_byte_receipts() {
        for (expression, replacement) in [
            ("String.fromCharCode(65,66)", "(\"AB\")"),
            ("\"abc\".charCodeAt(1)", "(98)"),
            ("\"abc\".charAt(1)", "(\"b\")"),
            ("\"a😀b\".indexOf(\"b\")", "(3)"),
            ("String.fromCharCode(0xd83d,0xde00)", "(\"😀\")"),
            ("\"😀\".charCodeAt(0)", "(55357)"),
        ] {
            let source = format!("\u{feff}const 雪=\"😀\";\r\nconst result={expression};");
            let disabled = analyze(Request {
                source: source.clone(),
                assume_intrinsics: false,
                function_at_byte: None,
            });
            assert!(disabled.ok);
            assert_eq!(disabled.derived_source, source);
            let enabled = analyze(Request {
                source: source.clone(),
                assume_intrinsics: true,
                function_at_byte: None,
            });
            assert!(enabled.ok);
            assert!(!enabled.transformations_truncated);
            assert_eq!(enabled.transformations.len(), 1);
            let rewrite = &enabled.transformations[0];
            let start = source.find(expression).unwrap();
            assert_eq!(rewrite.kind, "intrinsic-call");
            assert_eq!(rewrite.original_start as usize, start);
            assert_eq!(rewrite.original_end as usize, start + expression.len());
            assert_eq!(rewrite.replacement, replacement);
            assert_eq!(
                enabled.derived_source,
                source.replace(expression, replacement)
            );
        }
    }

    #[test]
    fn direct_dispatch_keeps_existing_proxy_and_enclosing_fold_paths() {
        for (source, required) in [
            (
                "const p=(a,b)=>a^b;const result=[String.fromCharCode(65),p(7,3)];",
                vec!["intrinsic-call", "proxy-call"],
            ),
            (
                "const result=\"2|0|1\".split(\"|\")[0];",
                vec!["literal-index"],
            ),
            (
                "const result=String.fromCharCode(65)+String.fromCharCode(66);",
                vec!["constant-fold"],
            ),
        ] {
            let response = analyze(Request {
                source: source.to_string(),
                assume_intrinsics: true,
                function_at_byte: None,
            });
            assert!(response.ok);
            for kind in required {
                assert!(
                    response
                        .transformations
                        .iter()
                        .any(|rewrite| rewrite.kind == kind)
                );
            }
        }
    }

    #[test]
    fn direct_intrinsic_refusals_keep_calls_unresolved() {
        for source in [
            "const result=String.fromCharCode(0xd800);",
            "const result=String.fromCharCode(1/0);",
            "const result=\"😀\".charAt(0);",
            "const result=\"abc\".charCodeAt(10);",
            "const result=\"abc\".charAt(0.5);",
            "const result=\"abc\".charAt(1,2);",
            "const result=\"abc\"?.charAt(1);",
            "const result=\"abc\".charAt?.(1);",
            "const result=\"abc\"[\"charAt\"](1);",
            "const result=String.fromCharCode(...[65]);",
            "const result=\"a|b\".split(/\\|/)[0];",
            "const code=String.fromCharCode;const result=code(65);",
            "const String={fromCharCode:function(){return \"shadow\"}};const result=String.fromCharCode(65);",
            "const inspect=eval;const result=\"abc\".charAt(0);",
            "let count=0;const object={valueOf(){count++;return 65;}};const result=String.fromCharCode(object);",
            "let count=0;const object={get text(){count++;return \"ab\";}};const result=object.text.charAt(0);",
        ] {
            let response = analyze(Request {
                source: source.to_string(),
                assume_intrinsics: true,
                function_at_byte: None,
            });
            assert!(response.ok, "{source}");
            assert!(
                response
                    .transformations
                    .iter()
                    .all(|rewrite| rewrite.kind != "intrinsic-call"),
                "{source}"
            );
        }
    }

    #[test]
    fn direct_intrinsic_resource_boundaries_preserve_the_original_call() {
        let split = format!(
            "const result={:?}.split(\"|\")[0];",
            format!("{}a", "a|".repeat(256))
        );
        let response = analyze(Request {
            source: split.clone(),
            assume_intrinsics: true,
            function_at_byte: None,
        });
        assert!(response.ok);
        assert!(response.transformations_truncated);
        assert_eq!(response.derived_source, split);
        for source in [
            format!(
                "const result=String.fromCharCode({});",
                vec!["65"; 257].join(",")
            ),
            format!("const result={:?}.charAt(0);", "a".repeat(16 * 1024 + 1)),
        ] {
            let response = analyze(Request {
                source: source.clone(),
                assume_intrinsics: true,
                function_at_byte: None,
            });
            assert!(response.ok);
            assert_eq!(response.derived_source, source);
        }
    }

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

    #[test]
    fn rejected_function_lookup_preserves_next_record() {
        let mut input = Vec::new();
        for request in [
            serde_json::json!({"source": "const broken = ;", "function_at_byte": u32::MAX}),
            serde_json::json!({"source": format!("{}0;", "!".repeat(10_000)), "function_at_byte": u32::MAX}),
            serde_json::json!({"source": "const f = () => '雪';", "function_at_byte": 16}),
            serde_json::json!({"source": "1+2"}),
        ] {
            serde_json::to_writer(&mut input, &request).unwrap();
            input.push(b'\n');
        }
        let mut output = Vec::new();
        serve(&mut Cursor::new(input), &mut output).unwrap();
        let responses: Vec<serde_json::Value> = output
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert_eq!(responses.len(), 4);
        for (response, error) in responses[..2].iter().zip(["malformed", "depth"]) {
            assert_eq!(response["ok"], false);
            assert_eq!(response["parsed"], false);
            assert!(
                response["syntax_errors"][0]["message"]
                    .as_str()
                    .unwrap()
                    .contains(error)
            );
        }
        assert_eq!(responses[2]["ok"], true);
        assert_eq!(responses[2]["function_location"]["kind"], "arrow_function");
        assert_eq!(responses[2]["function_location"]["body_start"], 16);
        assert_eq!(responses[2]["derived_source"], "");
        assert_eq!(responses[3]["derived_source"], "(3)");
    }
}
