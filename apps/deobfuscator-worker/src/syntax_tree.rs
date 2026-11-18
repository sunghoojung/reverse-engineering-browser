//! The Tree-sitter syntax tree behind the byte-position queries: the
//! function lookup, candidate admission and invocation sites. Tree-sitter
//! builds its tree on the heap and every walk here uses a cursor or parent
//! links, so neither the parse nor a query recurses on the native stack, and
//! no source is refused for its size, depth or node count. Oxc's recursive
//! passes are sized separately, from `reb_js_lexer::nesting`, in `main`.

/// The one refusal this module makes, and it is about syntax.
pub(crate) const MALFORMED: &str = "JavaScript syntax tree found malformed or unsupported syntax";

/// Parses the whole source. Error recovery can flatten unsupported syntax, so
/// a tree with an error node is refused rather than queried.
pub(crate) fn parse(source: &str) -> Result<tree_sitter::Tree, &'static str> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|_| "JavaScript syntax tree grammar is unavailable")?;
    let tree = parser
        .parse_with_options(&mut |offset, _| &source.as_bytes()[offset..], None, None)
        .ok_or("JavaScript syntax tree parse did not complete")?;
    if tree.root_node().has_error() {
        return Err(MALFORMED);
    }
    Ok(tree)
}

/// Resolve the innermost function containing a source byte offset. The body
/// start is the CDP search origin, even when the cursor is mid-function.
pub fn function_at(source: &str, offset: usize) -> Result<Option<FunctionLocation>, &'static str> {
    let tree = parse(source)?;
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
    let tree = parse(source)?;
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
    use super::{MALFORMED, function_at, parse};

    /// Real minifier output: one-character locals reused in every scope, bit
    /// operations, ternaries and object/array literals, with no whitespace.
    fn dense_minified(byte_target: usize) -> String {
        let mut out = String::from("(function(g){'use strict';");
        let mut index = 0usize;
        while out.len() < byte_target {
            out.push_str(&format!(
                "function f{index}(a,b){{var c=(a|0)+(b>>>2),d=a?b:c;\
                 return c>3?(a+b)*c-d:({{k:a,v:[b,c,a&b]}}).v[(c%3)|0];}}"
            ));
            index += 1;
        }
        out.push_str("g.f=f0;})(this);");
        out
    }

    /// A dense bundle past the old 4 MiB cap and the 2,097,152-node bound
    /// that used to refuse it before any query ran. The lookup is answered
    /// near its end, so the whole tree was built.
    #[test]
    fn a_dense_bundle_past_every_old_bound_is_queried() {
        let source = dense_minified(6 * 1024 * 1024);
        let offset = source.rfind("return c>3").unwrap();
        let location = function_at(&source, offset).unwrap().unwrap();
        assert_eq!(location.kind, "function_declaration");
        assert!(location.start as usize <= offset && offset < location.end as usize);
    }

    /// Nesting thousands of levels deep is a tree, not a stack: the old 128
    /// level bound refused it before a query could run.
    #[test]
    fn deep_nesting_is_queried_without_a_depth_bound() {
        let depth = 50_000;
        let source = format!(
            "var x={}function f(){{return 1}}{};",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        let offset = source.find("return").unwrap();
        let location = function_at(&source, offset).unwrap().unwrap();
        assert_eq!(location.kind, "function_expression");
    }

    #[test]
    fn malformed_syntax_is_the_only_refusal() {
        assert_eq!(parse("function(){").unwrap_err(), MALFORMED);
        assert!(parse("").is_ok());
    }
}
