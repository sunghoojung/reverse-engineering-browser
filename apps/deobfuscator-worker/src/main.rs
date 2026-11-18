use std::io::{self, BufRead, Write};

use oxc_allocator::Allocator;
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
mod fold;
mod invocation_site;
mod proxy;
mod request_field;
mod source_facts;
mod syntax_tree;
use serde::{Deserialize, Serialize};

/// Native stack for one request's recursive Oxc passes: a fixed base plus a
/// reserve per nesting level that `reb_js_lexer::nesting` measures without
/// recursing. The stack is mapped, not committed, so only the depth a pass
/// reaches costs memory. No source is refused for its size or depth; the
/// per-level reserve covers the parser, the folder and the facts visitors in
/// an unoptimized build, where frames are largest.
const PARSER_STACK: usize = 32 << 20;
const STACK_PER_LEVEL: usize = 16 << 10;

fn stack_for(source: &str) -> usize {
    reb_js_lexer::nesting(source)
        .saturating_mul(STACK_PER_LEVEL)
        .saturating_add(PARSER_STACK)
}

/// One JSON-line request. Deobfuscation and its function lookup predate the
/// `operation` tag and keep their untagged form, told apart by the lookup's
/// `function_at_byte`; every other operation is named. An unknown operation or
/// field is refused, never read as a deobfuscation request.
enum Operation {
    Deobfuscate(Request),
    FunctionLookup(FunctionLookup),
    SourceFacts(source_facts::Request),
    InvocationSite(invocation_site::Request),
    RequestField(request_field::Request),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    source: String,
    #[serde(default)]
    assume_intrinsics: bool,
}

/// No rewrite runs here, so the intrinsic assumption is not a field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionLookup {
    source: String,
    function_at_byte: u32,
    #[serde(default)]
    candidate_end_byte: Option<u32>,
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
    function_location: Option<syntax_tree::FunctionLocation>,
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

/// Every refusal names its kind: `invalid-request`, `syntax` (the parser that
/// answers the operation rejected the source) or `derived-validation`.
fn error_response(kind: &'static str, message: impl Into<String>) -> Response {
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
        error_kind: Some(kind),
        function_location: None,
    }
}

fn syntax_refusal(message: &'static str, source_bytes: usize) -> Response {
    let mut response = error_response("syntax", message);
    response.source_bytes = source_bytes;
    response
}

// Validate the whole candidate before publishing any rewrite receipts. Rewrites
// replace expressions with literals, so the candidate nests no deeper than the
// source whose stack this already runs on.
fn validate_derived(source: &str, source_type: SourceType) -> Result<(), &'static str> {
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

fn locate(request: FunctionLookup) -> Response {
    let source_bytes = request.source.len();
    let offset = request.function_at_byte as usize;
    match match request.candidate_end_byte {
        Some(end) => syntax_tree::candidate_function_at(&request.source, offset, end as usize),
        None => syntax_tree::function_at(&request.source, offset),
    } {
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
        Err(message) => syntax_refusal(message, source_bytes),
    }
}

fn analyze(request: Request) -> Response {
    let source_bytes = request.source.len();
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
        // Oxc rejected the source: `parsed` stays true because a parse ran,
        // but the source is not valid JavaScript.
        error_kind: (!parsed_ok).then_some("syntax"),
        function_location: None,
    };
    if parsed_ok && !response.transformations.is_empty() {
        return validate_response(response, &request.source, parsed.program.source_type);
    }
    response
}

/// A record that does not decode as the operation it names. Each operation
/// answers in its own response schema; untagged records use this worker's.
enum Rejected {
    Request(String),
    SourceFacts,
    InvocationSite,
    RequestField,
}

fn operation(line: &[u8]) -> Result<Operation, Rejected> {
    let value = serde_json::from_slice::<serde_json::Value>(line)
        .map_err(|error| Rejected::Request(format!("invalid request: {error}")))?;
    let lookup =
        value.get("function_at_byte").is_some() || value.get("candidate_end_byte").is_some();
    match value.get("operation").map(serde_json::Value::as_str) {
        None if lookup => serde_json::from_value(value)
            .map(Operation::FunctionLookup)
            .map_err(|error| Rejected::Request(format!("invalid function lookup: {error}"))),
        None => serde_json::from_value(value)
            .map(Operation::Deobfuscate)
            .map_err(|error| Rejected::Request(format!("invalid request: {error}"))),
        Some(Some("source_facts")) => serde_json::from_value(value)
            .map(Operation::SourceFacts)
            .map_err(|_| Rejected::SourceFacts),
        Some(Some("invocation_site")) => serde_json::from_value(value)
            .map(Operation::InvocationSite)
            .map_err(|_| Rejected::InvocationSite),
        Some(Some("request_field")) => serde_json::from_value(value)
            .map(Operation::RequestField)
            .map_err(|_| Rejected::RequestField),
        Some(_) => Err(Rejected::Request(
            "invalid request: unknown operation".into(),
        )),
    }
}

/// Reads one newline-terminated record, or the unterminated last one. A
/// record is as long as the source it carries.
fn read_request(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    if reader.read_until(b'\n', &mut bytes)? == 0 {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(Some(bytes))
}

/// Writes one response line straight from its value: a whole-bundle report
/// is never copied into an intermediate JSON tree first.
fn reply(writer: &mut impl Write, response: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, response)?;
    writeln!(writer)?;
    writer.flush()
}

fn serve(reader: &mut impl BufRead, writer: &mut impl Write) -> io::Result<()> {
    loop {
        let Some(line) = read_request(reader)? else {
            return Ok(());
        };
        match operation(&line) {
            Ok(Operation::Deobfuscate(request)) => {
                let stack = stack_for(&request.source);
                reply(writer, &stacker::grow(stack, || analyze(request)))?
            }
            Ok(Operation::FunctionLookup(request)) => reply(writer, &locate(request))?,
            Ok(Operation::SourceFacts(request)) => {
                let stack = stack_for(&request.source);
                reply(
                    writer,
                    &stacker::grow(stack, || source_facts::analyze(request)),
                )?
            }
            Ok(Operation::InvocationSite(request)) => {
                reply(writer, &invocation_site::analyze(request))?
            }
            Ok(Operation::RequestField(request)) => {
                reply(writer, &request_field::extract(request))?
            }
            Err(Rejected::Request(message)) => {
                reply(writer, &error_response("invalid-request", message))?
            }
            Err(Rejected::SourceFacts) => reply(
                writer,
                &source_facts::invalid("invalid source facts request", 0),
            )?,
            Err(Rejected::InvocationSite) => reply(
                writer,
                &invocation_site::invalid("invalid invocation site request", 0),
            )?,
            Err(Rejected::RequestField) => reply(
                writer,
                &request_field::extract(request_field::Request {
                    operation: String::new(),
                    body: String::new(),
                    pointer: String::new(),
                }),
            )?,
        }
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
        // Deep candidates are validated on the stack their nesting needs.
        let deep = format!("{}0;", "!".repeat(10_000));
        assert!(
            stacker::grow(stack_for(&deep), || validate_derived(
                &deep,
                SourceType::unambiguous()
            ))
            .is_ok()
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
            });
            assert!(disabled.ok);
            assert_eq!(disabled.derived_source, source);
            let enabled = analyze(Request {
                source: source.clone(),
                assume_intrinsics: true,
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
    fn direct_intrinsics_fold_at_any_part_or_argument_count() {
        let split = format!(
            "const result={:?}.split(\"|\")[4096];",
            format!("{}b", "a|".repeat(4096))
        );
        let response = analyze(Request {
            source: split,
            assume_intrinsics: true,
        });
        assert!(response.ok);
        assert!(!response.transformations_truncated);
        assert_eq!(response.derived_source, "const result=(\"b\");");
        let response = analyze(Request {
            source: format!(
                "const result=String.fromCharCode({});",
                vec!["65"; 4096].join(",")
            ),
            assume_intrinsics: true,
        });
        assert!(response.ok);
        assert_eq!(
            response.derived_source,
            format!("const result=(\"{}\");", "A".repeat(4096))
        );
    }

    /// Escaped string keys stay names. Visiting one as a value once produced
    /// `{("A"):1}`, which failed validation and discarded every rewrite of a
    /// real 6 MB bundle.
    #[test]
    fn escaped_string_keys_are_names_not_values() {
        let source = r#"const o={"\x41":1+1};class C{"\x42"(){return 2+2}}const {"\x43":c}=o;"#;
        let response = analyze(Request {
            source: source.to_string(),
            assume_intrinsics: false,
        });
        assert!(response.ok, "{:?}", response.syntax_errors);
        assert_eq!(
            response.derived_source,
            r#"const o={"\x41":(2)};class C{"\x42"(){return (4)}}const {"\x43":c}=o;"#
        );
    }

    /// A decoder loop runs until it completes or its expression's step
    /// allowance is spent, and a table is read past its first 256 entries.
    #[test]
    fn long_decoder_loops_and_large_tables_fold() {
        let response = analyze(Request {
            source: "const decode=function(n){var out=0;for(var i=0;i<n;i++){out+=1;}return out;};const result=decode(5000);".to_string(),
            assume_intrinsics: false,
        });
        assert!(response.ok);
        assert!(!response.transformations_truncated);
        assert!(
            response.derived_source.ends_with("const result=(5000);"),
            "{}",
            response.derived_source
        );
        for count in [3, 300] {
            let entries: Vec<String> = (0..count).map(|index| format!("\"e{index}\"")).collect();
            let last = count - 1;
            let response = analyze(Request {
                source: format!(
                    "function f(){{const t=[{}];return t[{last}];}}",
                    entries.join(",")
                ),
                assume_intrinsics: false,
            });
            assert!(response.ok);
            assert!(
                response
                    .derived_source
                    .ends_with(&format!("return (\"e{last}\");}}")),
                "{count}: {}",
                response.derived_source
            );
        }
    }

    /// A folded value is inlined as a literal, so one is never larger than
    /// MAX_VALUE_BYTES. The expression that would make one stays as written.
    #[test]
    fn a_value_past_the_inline_size_preserves_the_original_call() {
        let source = format!("const result={:?}.charAt(0);", "a".repeat(16 * 1024 + 1));
        let response = analyze(Request {
            source: source.clone(),
            assume_intrinsics: true,
        });
        assert!(response.ok);
        assert_eq!(response.derived_source, source);
    }

    #[test]
    fn folds_finite_numeric_literals_and_preserves_unsafe_math() {
        let response = analyze(Request {
            assume_intrinsics: false,
            source: "const value = 1 + 2 * 3; const unsafe = 1 / 0;".to_string(),
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
        });

        assert!(!response.ok);
        // A parse ran and found the error.
        assert!(response.parsed);
        assert!(!response.syntax_errors.is_empty());
        assert_eq!(response.derived_source, "const broken = ;");
        assert!(response.transformations.is_empty());
    }

    /// No byte cap: a source past the old 4 MiB bound is folded throughout,
    /// including its last statement.
    #[test]
    fn folds_sources_past_the_old_byte_cap_to_their_end() {
        let mut source = "var a=1+2;".repeat(512 * 1024);
        source.push_str("var z=40+2;");
        assert!(source.len() > 4 * 1024 * 1024);
        let response = stacker::grow(stack_for(&source), || {
            analyze(Request {
                assume_intrinsics: false,
                source: source.clone(),
            })
        });
        assert!(response.ok);
        assert!(!response.transformations_truncated);
        assert_eq!(response.transformations.len(), 512 * 1024 + 1);
        assert!(response.derived_source.ends_with("var z=(42);"));
    }
}

#[cfg(test)]
mod framing_tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufReader, Cursor};

    fn respond(request: serde_json::Value) -> serde_json::Value {
        let mut input = serde_json::to_vec(&request).unwrap();
        input.push(b'\n');
        let mut output = Vec::new();
        serve(&mut Cursor::new(input), &mut output).unwrap();
        serde_json::from_slice(output.trim_ascii_end()).unwrap()
    }

    #[test]
    fn unknown_operations_and_fields_are_refused_not_deobfuscated() {
        for request in [
            json!({"operation":"source_fact","source":"1+2"}),
            json!({"operation":7,"source":"1+2"}),
            json!({"source":"1+2","assume_intrinsic":true}),
            json!({"source":"function f(){}","function_at_byte":0,"assume_intrinsics":true}),
        ] {
            let response = respond(request.clone());
            assert_eq!(response["ok"], false, "{request}");
            assert_eq!(response["error_kind"], "invalid-request", "{request}");
            assert_eq!(response["derived_source"], "", "{request}");
        }
        assert_eq!(respond(json!({"source":"1+2"}))["derived_source"], "(3)");
    }

    /// Tree-sitter admits a top-level `return`; Oxc parses it and rejects it.
    /// That is a syntax refusal with `parsed: true`, not an unlabelled failure.
    #[test]
    fn every_refusal_names_its_kind() {
        for (request, kind, parsed) in [
            (json!({"source":"const broken = ;"}), "syntax", true),
            (json!({"source":"return 1;"}), "syntax", true),
            (
                json!({"source":"const broken = ;","function_at_byte":0}),
                "syntax",
                false,
            ),
        ] {
            let response = respond(request);
            assert_eq!(response["ok"], false, "{kind}");
            assert_eq!(response["error_kind"], kind);
            assert_eq!(response["parsed"], parsed, "{kind}");
        }
        assert!(respond(json!({"source":"1+2"})).get("error_kind").is_none());
        // Nesting is measured and given its stack, never refused.
        let deep = respond(json!({"source":format!("{}0;", "!".repeat(10_000))}));
        assert_eq!(deep["ok"], true);
    }

    #[test]
    fn records_of_any_length_keep_their_framing() {
        let long = "x".repeat(1 << 20);
        let input = format!("{long}\nok\nlast");
        let mut reader = BufReader::with_capacity(3, Cursor::new(input.into_bytes()));
        assert_eq!(read_request(&mut reader).unwrap(), Some(long.into_bytes()));
        assert_eq!(read_request(&mut reader).unwrap(), Some(b"ok".to_vec()));
        assert_eq!(read_request(&mut reader).unwrap(), Some(b"last".to_vec()));
        assert!(read_request(&mut reader).unwrap().is_none());
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
    fn candidate_query_wire_flag_is_explicit_and_ordinary_queries_stay_compatible() {
        let source = "function f(){return 'value';}";
        let start = source.find("value").unwrap();
        let base = serde_json::json!({"source":source,"function_at_byte":start});
        let ordinary = locate(serde_json::from_value(base.clone()).unwrap());
        assert!(!ordinary.function_location.unwrap().candidate_eligible);
        let mut strict = base;
        strict["candidate_end_byte"] = serde_json::json!(start + 5);
        let strict = locate(serde_json::from_value(strict).unwrap());
        assert!(strict.function_location.unwrap().candidate_eligible);
        let malformed = respond(serde_json::json!({"source":source,"candidate_end_byte":start+5}));
        assert_eq!(malformed["ok"], false);
        assert_eq!(malformed["error_kind"], "invalid-request");
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
        assert_eq!(responses[0]["ok"], false);
        assert_eq!(responses[0]["parsed"], false);
        assert!(
            responses[0]["syntax_errors"][0]["message"]
                .as_str()
                .unwrap()
                .contains("malformed")
        );
        // A deep source is parsed; an offset past its end names no function.
        assert_eq!(responses[1]["ok"], true);
        assert!(responses[1]["function_location"].is_null());
        assert_eq!(responses[2]["ok"], true);
        assert_eq!(responses[2]["function_location"]["kind"], "arrow_function");
        assert_eq!(responses[2]["function_location"]["body_start"], 16);
        assert_eq!(responses[2]["derived_source"], "");
        assert_eq!(responses[3]["derived_source"], "(3)");
    }
}
