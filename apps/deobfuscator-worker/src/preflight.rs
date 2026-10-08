//! Heap-backed parse plus iterative traversal bounds recursive Oxc work.
//! This is a conservative admission check, not a second transformation engine.
use std::time::{Duration, Instant};

const MAX_TREE_DEPTH: usize = 128;
const MAX_TREE_NODES: usize = 500_000;

pub fn check(source: &str) -> Result<(), &'static str> {
    parse_checked(source).map(drop)
}

fn parse_checked(source: &str) -> Result<tree_sitter::Tree, &'static str> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|_| "JavaScript preflight grammar is unavailable")?;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut cancelled = |_: &tree_sitter::ParseState| Instant::now() >= deadline;
    let tree = parser
        .parse_with_options(
            &mut |offset, _| &source.as_bytes()[offset..],
            None,
            Some(tree_sitter::ParseOptions::new().progress_callback(&mut cancelled)),
        )
        .ok_or("JavaScript preflight exceeded its time budget")?;
    // Error recovery can flatten unsupported syntax. Never infer a depth bound
    // from such a tree and then send the unchecked syntax to the recursive parser.
    if tree.root_node().has_error() {
        return Err("JavaScript preflight found malformed or unsupported syntax");
    }
    let mut cursor = tree.walk();
    let mut depth = 0;
    let mut nodes = 0;
    loop {
        nodes += 1;
        if depth > MAX_TREE_DEPTH {
            return Err("JavaScript nesting exceeds the supported depth of 128");
        }
        if nodes > MAX_TREE_NODES || Instant::now() >= deadline {
            return Err("JavaScript preflight exceeded its complexity budget");
        }
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                drop(cursor);
                return Ok(tree);
            }
            depth -= 1;
        }
    }
}

/// Resolve the innermost function containing a source byte offset. The body
/// start is the CDP search origin, even when the cursor is mid-function.
pub fn function_at(source: &str, offset: usize) -> Result<Option<FunctionLocation>, &'static str> {
    let tree = parse_checked(source)?;
    if offset >= source.len() || !source.is_char_boundary(offset) {
        return Ok(None);
    }
    let mut node = tree
        .root_node()
        .descendant_for_byte_range(offset, offset + 1);
    while let Some(candidate) = node {
        let kind = candidate.kind();
        if matches!(
            kind,
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "generator_function_declaration"
                | "generator_function"
        ) && let Some(body) = candidate.child_by_field_name("body")
        {
            return Ok(Some(FunctionLocation {
                kind: kind.to_string(),
                candidate_eligible: false,
                start: candidate.start_byte() as u32,
                end: candidate.end_byte() as u32,
                body_start: body.start_byte() as u32,
            }));
        }
        node = candidate.parent();
    }
    Ok(None)
}

/// Narrow candidate admission: a literal string inside a synchronous function body.
/// Comments, parameter defaults, templates, async/generator functions and class
/// accessors are intentionally not candidate experiments in this version.
pub fn candidate_function_at(
    source: &str,
    start: usize,
    end: usize,
) -> Result<Option<FunctionLocation>, &'static str> {
    let tree = parse_checked(source)?;
    if start >= end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return Ok(None);
    }
    let mut node = tree.root_node().descendant_for_byte_range(start, end);
    let mut literal = false;
    while let Some(candidate) = node {
        let kind = candidate.kind();
        if matches!(kind, "comment" | "template_string") {
            return Ok(None);
        }
        literal |= kind == "string";
        if matches!(
            kind,
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "generator_function_declaration"
                | "generator_function"
        ) {
            let Some(body) = candidate.child_by_field_name("body") else {
                return Ok(None);
            };
            let mut cursor = candidate.walk();
            let unsupported = candidate
                .children(&mut cursor)
                .any(|child| matches!(child.kind(), "async" | "*" | "get" | "set"));
            if !literal
                || unsupported
                || kind.starts_with("generator_")
                || start < body.start_byte()
                || end > body.end_byte()
            {
                return Ok(None);
            }
            return Ok(Some(FunctionLocation {
                kind: kind.into(),
                candidate_eligible: true,
                start: candidate.start_byte() as u32,
                end: candidate.end_byte() as u32,
                body_start: body.start_byte() as u32,
            }));
        }
        node = candidate.parent();
    }
    Ok(None)
}

#[derive(Debug, serde::Serialize)]
pub struct FunctionLocation {
    pub candidate_eligible: bool,
    pub kind: String,
    pub start: u32,
    pub end: u32,
    pub body_start: u32,
}

#[cfg(test)]
mod tests {
    use super::{check, function_at};

    #[test]
    fn rejects_deep_structures_without_recursion() {
        // Program and expression-statement nodes precede the unary chain.
        assert!(check(&format!("{}0;", "!".repeat(126))).is_ok());
        for source in [
            format!("{}0;", "!".repeat(127)),
            format!("{}0;", "!".repeat(10_000)),
            format!("{}0{};", "[".repeat(10_000), "]".repeat(10_000)),
            format!("{}0;", "a=".repeat(10_000)),
        ] {
            let error = check(&source).unwrap_err();
            assert!(error.contains("depth"));
            assert_eq!(function_at(&source, usize::MAX).unwrap_err(), error);
        }
    }

    #[test]
    fn literal_punctuation_is_not_nesting() {
        assert!(check(&format!("const text='{}';", "[(!".repeat(10_000))).is_ok());
        assert!(check(&format!("/* {} */ const x=1;", "[(".repeat(10_000))).is_ok());
        assert!(check("const broken=;").is_err());
    }

    #[test]
    fn finds_inner_anonymous_function_from_body_cursor() {
        let source = "const outer = () => { const cb = x => x + 1; return cb(2); };";
        let location = function_at(source, source.find("x + 1").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(location.kind, "arrow_function");
        assert_eq!(
            &source[location.body_start as usize..location.end as usize],
            "x + 1"
        );
        assert_eq!(
            &source[location.start as usize..location.end as usize],
            "x => x + 1"
        );
        assert!(
            function_at(source, source.find("const outer").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_source_takes_precedence_over_invalid_offsets() {
        for source in ["function broken(", "const 雪 = ;"] {
            let error = check(source).unwrap_err();
            assert_eq!(
                error,
                "JavaScript preflight found malformed or unsupported syntax"
            );
            for offset in [0, source.len(), usize::MAX] {
                assert_eq!(function_at(source, offset).unwrap_err(), error);
            }
            if let Some(offset) = source.find('雪') {
                assert_eq!(function_at(source, offset + 1).unwrap_err(), error);
            }
        }
    }

    #[test]
    fn preserves_utf8_boundaries_and_half_open_nested_ranges() {
        let source = "/*雪*/ function outer() { return () => '🦀'; };";
        let offset = source.find('🦀').unwrap();
        let inner = function_at(source, offset).unwrap().unwrap();
        assert_eq!(inner.kind, "arrow_function");
        assert_eq!(
            &source[inner.start as usize..inner.end as usize],
            "() => '🦀'"
        );
        assert_eq!(
            &source[inner.body_start as usize..inner.end as usize],
            "'🦀'"
        );
        for invalid in [offset + 1, offset + 2, offset + 3, source.len(), usize::MAX] {
            assert!(function_at(source, invalid).unwrap().is_none());
        }
        assert!(function_at("", 0).unwrap().is_none());
        assert!(
            function_at(source, source.find('雪').unwrap())
                .unwrap()
                .is_none()
        );

        let outer = function_at(source, inner.end as usize).unwrap().unwrap();
        assert_eq!(outer.kind, "function_declaration");
        assert_eq!(
            &source[outer.start as usize..outer.end as usize],
            "function outer() { return () => '🦀'; }"
        );
        assert_eq!(
            &source[outer.body_start as usize..outer.end as usize],
            "{ return () => '🦀'; }"
        );
        assert!(function_at(source, outer.end as usize).unwrap().is_none());
    }

    #[test]
    fn resolves_all_supported_function_kinds_at_range_boundaries() {
        for (source, function, body, kind) in [
            (
                "function f() {}",
                "function f() {}",
                "{}",
                "function_declaration",
            ),
            (
                "const f = function() {};",
                "function() {}",
                "{}",
                "function_expression",
            ),
            (
                "const f = x => x + 1;",
                "x => x + 1",
                "x + 1",
                "arrow_function",
            ),
            (
                "class C { method() {} }",
                "method() {}",
                "{}",
                "method_definition",
            ),
            (
                "function* f() {}",
                "function* f() {}",
                "{}",
                "generator_function_declaration",
            ),
            (
                "const f = function*() {};",
                "function*() {}",
                "{}",
                "generator_function",
            ),
        ] {
            let start = source.find(function).unwrap();
            let end = start + function.len();
            let body_start = start + function.find(body).unwrap();
            for offset in [start, body_start, end - 1] {
                let location = function_at(source, offset).unwrap().unwrap();
                assert_eq!(location.kind, kind);
                assert_eq!(location.start as usize, start);
                assert_eq!(location.end as usize, end);
                assert_eq!(location.body_start as usize, body_start);
            }
            assert!(function_at(source, end).unwrap().is_none());
        }
    }
}

#[cfg(test)]
mod candidate_tests {
    use super::candidate_function_at;
    fn location(source: &str) -> Option<super::FunctionLocation> {
        let start = source.find("fixture-observed").unwrap();
        candidate_function_at(source, start, start + "fixture-observed".len()).unwrap()
    }
    #[test]
    fn candidate_requires_literal_inside_declared_synchronous_body() {
        for source in [
            "function f(){ return 'fixture-observed'; }",
            "const f=()=> 'fixture-observed';",
            "const f=function(){ return 'fixture-observed'; };",
            "const o={f(){ return 'fixture-observed'; }}",
        ] {
            assert!(location(source).unwrap().candidate_eligible, "{source}");
        }
        for source in [
            "function f(){ /* fixture-observed */ return 1; }",
            "const s='fixture-observed';",
            "async function f(){return 'fixture-observed';}",
            "function* f(){return 'fixture-observed';}",
            "const f=async()=> 'fixture-observed';",
            "const o={get f(){return 'fixture-observed';}}",
            "function f(x='fixture-observed'){return x;}",
            "function f(){return `fixture-observed`;}",
        ] {
            assert!(location(source).is_none(), "{source}");
        }
        // A synchronous declaration can still return a Promise. Runtime return
        // eligibility remains separate and must never imply an override works.
        assert!(location("function f(){ return Promise.resolve('fixture-observed'); }").is_some());
    }
    #[test]
    fn candidate_range_is_exact_utf8_and_never_crosses_literal_boundaries() {
        let s = "function f(){ return '雪'; }";
        let start = s.find('雪').unwrap();
        assert!(
            candidate_function_at(s, start, start + 3)
                .unwrap()
                .is_some()
        );
        assert!(
            candidate_function_at(s, start + 1, start + 3)
                .unwrap()
                .is_none()
        );
        assert!(
            candidate_function_at(s, start, start + 2)
                .unwrap()
                .is_none()
        );
        assert!(candidate_function_at(s, start, start).unwrap().is_none());
        assert!(
            candidate_function_at(s, start, s.len() + 1)
                .unwrap()
                .is_none()
        );
        assert!(candidate_function_at(s, start, s.len()).unwrap().is_none());
    }
}
