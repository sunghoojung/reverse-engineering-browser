//! Heap-backed parse plus iterative traversal bounds recursive Oxc work.
//! This is a conservative admission check, not a second transformation engine.
use std::time::{Duration, Instant};

const MAX_TREE_DEPTH: usize = 128;
const MAX_TREE_NODES: usize = 500_000;

pub fn check(source: &str) -> Result<(), &'static str> {
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
                return Ok(());
            }
            depth -= 1;
        }
    }
}

/// Resolve the innermost function containing a source byte offset. The body
/// start is the CDP search origin, even when the cursor is mid-function.
pub fn function_at(source: &str, offset: usize) -> Result<Option<FunctionLocation>, &'static str> {
    check(source)?;
    if offset >= source.len() || !source.is_char_boundary(offset) {
        return Ok(None);
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|_| "JavaScript preflight grammar is unavailable")?;
    let tree = parser
        .parse(source, None)
        .ok_or("JavaScript function parse failed")?;
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
        ) {
            if let Some(body) = candidate.child_by_field_name("body") {
                return Ok(Some(FunctionLocation {
                    kind: kind.to_string(),
                    start: candidate.start_byte() as u32,
                    end: candidate.end_byte() as u32,
                    body_start: body.start_byte() as u32,
                }));
            }
        }
        node = candidate.parent();
    }
    Ok(None)
}

#[derive(Debug, serde::Serialize)]
pub struct FunctionLocation {
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
        for source in [
            format!("{}0;", "!".repeat(10_000)),
            format!("{}0{};", "[".repeat(10_000), "]".repeat(10_000)),
            format!("{}0;", "a=".repeat(10_000)),
        ] {
            assert!(check(&source).unwrap_err().contains("depth"));
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
}
