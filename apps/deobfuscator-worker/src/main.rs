use std::io::{self, BufRead, Write};

use oxc_allocator::Allocator;
use oxc_ast::ast::{BinaryExpression, Expression};
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
use oxc_syntax::operator::BinaryOperator;
use serde::{Deserialize, Serialize};

const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_SOURCE_BYTES + 64 * 1024;

#[derive(Debug, Deserialize)]
struct Request {
    source: String,
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

#[derive(Debug)]
struct NumericFold {
    start: u32,
    end: u32,
    replacement: String,
}

#[derive(Default)]
struct NumericFolder {
    folds: Vec<NumericFold>,
}

impl<'a> Visit<'a> for NumericFolder {
    fn visit_binary_expression(&mut self, expression: &BinaryExpression<'a>) {
        self.visit_expression(&expression.left);
        self.visit_expression(&expression.right);

        let (Expression::NumericLiteral(left), Expression::NumericLiteral(right)) =
            (&expression.left, &expression.right)
        else {
            return;
        };
        let value = match expression.operator {
            BinaryOperator::Addition => left.value + right.value,
            BinaryOperator::Subtraction => left.value - right.value,
            BinaryOperator::Multiplication => left.value * right.value,
            BinaryOperator::Division if right.value != 0.0 => left.value / right.value,
            BinaryOperator::Remainder if right.value != 0.0 => left.value % right.value,
            BinaryOperator::Exponential => left.value.powf(right.value),
            _ => return,
        };
        if !value.is_finite() {
            return;
        }
        self.folds.push(NumericFold {
            start: expression.span.start,
            end: expression.span.end,
            replacement: value.to_string(),
        });
    }
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
    }
}

fn analyze(request: Request) -> Response {
    let source_bytes = request.source.len();
    if source_bytes > MAX_SOURCE_BYTES {
        return error_response("source exceeds the deobfuscation byte limit");
    }

    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &request.source, SourceType::unambiguous()).parse();
    let syntax_errors = parsed
        .diagnostics
        .iter()
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
    if parsed_ok {
        let mut folder = NumericFolder::default();
        folder.visit_program(&parsed.program);
        folder
            .folds
            .sort_by_key(|fold| std::cmp::Reverse(fold.start));
        for fold in folder.folds {
            let start = fold.start as usize;
            let end = fold.end as usize;
            if end <= derived_source.len() && start < end {
                derived_source.replace_range(start..end, &fold.replacement);
                transformations.push(Transformation {
                    kind: "constant-fold",
                    original_start: fold.start,
                    original_end: fold.end,
                    replacement: fold.replacement,
                });
            }
        }
        transformations.reverse();
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
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) if line.len() <= MAX_REQUEST_BYTES => line,
            Ok(_) => {
                serde_json::to_writer(
                    &mut stdout,
                    &error_response("request exceeds the byte limit"),
                )
                .expect("write response");
                writeln!(stdout).expect("write newline");
                continue;
            }
            Err(error) => {
                serde_json::to_writer(&mut stdout, &error_response(error.to_string()))
                    .expect("write response");
                writeln!(stdout).expect("write newline");
                continue;
            }
        };

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => analyze(request),
            Err(error) => error_response(format!("invalid request: {error}")),
        };
        serde_json::to_writer(&mut stdout, &response).expect("write response");
        writeln!(stdout).expect("write newline");
        stdout.flush().expect("flush response");
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_SOURCE_BYTES, Request, analyze};

    #[test]
    fn folds_finite_numeric_literals_and_preserves_unsafe_math() {
        let response = analyze(Request {
            source: "const value = 1 + 2 * 3; const unsafe = 1 / 0;".to_string(),
        });

        assert!(response.ok);
        assert_eq!(
            response.derived_source,
            "const value = 1 + 6; const unsafe = 1 / 0;"
        );
        assert_eq!(response.transformations.len(), 1);
        assert_eq!(response.transformations[0].kind, "constant-fold");
    }

    #[test]
    fn reports_parse_errors_without_rewriting_source() {
        let response = analyze(Request {
            source: "const broken = ;".to_string(),
        });

        assert!(!response.ok);
        assert!(response.parsed);
        assert!(!response.syntax_errors.is_empty());
        assert_eq!(response.derived_source, "const broken = ;");
        assert!(response.transformations.is_empty());
    }

    #[test]
    fn rejects_oversized_sources_before_parsing() {
        let response = analyze(Request {
            source: "x".repeat(MAX_SOURCE_BYTES + 1),
        });

        assert!(!response.ok);
        assert!(!response.parsed);
        assert!(response.syntax_errors[0].message.contains("byte limit"));
    }
}
