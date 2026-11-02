//! Heap-backed parse plus iterative traversal bounds recursive Oxc work.
//! This is a conservative admission check, not a second transformation engine.
//!
//! Admission is a function of the supplied bytes. Every bound below is either a
//! byte count, a tree depth, a node count or a count of the bytes tree-sitter
//! asked its allocator for, so the same source is admitted or refused
//! identically on a slow machine and on an unoptimized build. The one wall
//! clock left in this module cannot decide the outcome for any source the other
//! bounds admit; see `PARSE_BUDGET`.
//!
//! The depth and node bounds read a finished tree, so they cannot bound what
//! building that tree costs. `MAX_PARSE_HEAP_BYTES` is the bound that runs
//! *inside* the parse, and it is the only one that keeps a refused source from
//! being paid for in full first.
use std::time::{Duration, Instant};

pub(crate) const MAX_TREE_DEPTH: usize = 128;
/// Bounds the traversal and every recursive stage behind it, expressed against
/// the source byte cap it guards rather than as a free-standing number: at most
/// one tree-sitter node per two declared source bytes.
///
/// The grammar cannot exceed two nodes per byte, which `;;;;` reaches, so this
/// admits *any* shape up to 1,048,576 bytes without a density assumption. Above
/// that it is a density bound, and the density that matters is real minifier
/// output: one-character locals reused in every scope measure 1.09 nodes per
/// byte, so minified code is admitted to roughly 1.9 MB, including the
/// ~1.5 MB obfuscated-glue class this harness exists to read.
///
/// The bound stays below `MAX_SOURCE_BYTES`, so the declared byte cap is still
/// unreachable for dense code. That gap is documented rather than closed: the
/// parse of a 4 MiB minified source costs at least 2.4 s on an unoptimized
/// build, which no budget can admit and still leave a recoverable diagnostic
/// inside the five-second process deadline.
pub(crate) const MAX_TREE_NODES: usize = crate::MAX_SOURCE_BYTES / 2;
/// The parse is the only step with no deterministic proxy for its own work, so
/// it keeps a wall clock. It is a pathological-grammar backstop and must never
/// decide admission: a source of exactly `MAX_TREE_NODES` nodes parses in
/// 0.35 s optimized and 1.80 s unoptimized, and 0.57 s optimized at the worst
/// per-node parse rate measured, so this budget clears the slowest of those by
/// more than twice. A single pathological parse still answers inside the
/// five-second deadline `DeobfuscationService` applies to the process, which
/// keeps the recoverable diagnostic and the next JSON-line request rather than
/// losing the worker.
///
/// The traversal deliberately does not consult this clock. A clock inside the
/// walk made admission depend on machine speed and build profile: the same
/// 1.5 MB glue bundle that an optimized worker admitted in 0.29 s was refused
/// by an unoptimized one against a one-second budget.
const PARSE_BUDGET: Duration = Duration::from_secs(4);
/// Peak tree-sitter heap a single parse may request, refused from inside the
/// parse rather than after it. Expressed against the node bound it completes:
/// at most 192 bytes of parser heap per node that bound admits.
///
/// The depth and node bounds are read from a tree that already exists, so a
/// source they refuse has been built and paid for first. Measured through the
/// real release worker, a 4 MiB source of nested sequence expressions reached
/// 2,011.7 MiB of transient tree and was then refused for its depth, and 4 MiB
/// of empty statements reached 1,177.9 MiB and was then refused for its node
/// count. Those become 441.2 MiB and 426.1 MiB. That is the exposure this
/// ceiling closes; it is the whole reason the bound is here and not a second
/// opinion about complexity.
///
/// 192 bytes per node is a measured margin, not a budget guess. The densest
/// shape the grammar admits, 1,048,576 bytes of empty statements, is also
/// exactly the node bound, and it requests 136 bytes of parser heap per node;
/// real minifier output at 1.09 nodes per byte requests 118. So the ceiling
/// clears the densest admissible tree by 1.41x and the obfuscated-glue class
/// this harness exists to read by 2.06x.
///
/// What it does narrow is stated rather than hidden. Shapes that hold several
/// GLR stack versions at once cost far more heap per node: a parenthesized
/// sequence expression measures 325 bytes per node, so one larger than about
/// 1.2 MB is now refused here instead of admitted by node count. Every shape
/// measured above this ceiling at the 1,048,576-byte floor reaches a tree depth
/// of at least 262,145 and was already refused by `MAX_TREE_DEPTH`; what
/// changes for those is which bound answers, not whether they are refused.
pub(crate) const MAX_PARSE_HEAP_BYTES: usize = MAX_TREE_NODES * 192;

/// Tree-sitter's own heap, counted so a parse can be stopped from inside it.
///
/// `ts_set_allocator` is the only hook the C parser offers into its allocation
/// and the progress callback is the only hook into its progress. Together they
/// turn "how much has this parse asked for" into a value the callback can
/// refuse on, which is what makes a memory bound enforceable before a tree
/// exists instead of after one is complete.
///
/// The count is deterministic. Allocation sizes and their order are a function
/// of the grammar and the supplied bytes, with no clock and no allocator state
/// in them, and the totals below are identical between an optimized and an
/// unoptimized build. That is the same property the node bound has and the
/// reason this is a byte count rather than an elapsed time or a measured RSS.
mod heap {
    use std::cell::Cell;
    use std::ffi::c_void;
    use std::sync::Once;

    // libc, not the Rust allocator: tree-sitter frees through whichever `free`
    // is installed, so a pointer `malloc` returned before these shims existed
    // must stay valid for the `free` they install. Every shim is the libc
    // function plus a counter, so installing them is safe at any point and
    // `begin` can do it lazily.
    unsafe extern "C" {
        fn malloc(size: usize) -> *mut c_void;
        fn calloc(count: usize, size: usize) -> *mut c_void;
        fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);
    }

    thread_local! {
        /// Bytes requested on this thread since `begin`. Thread-local because
        /// the test binary parses on several threads at once, and a shared
        /// counter would make the bound depend on the thread schedule instead
        /// of on the bytes.
        static REQUESTED: Cell<usize> = const { Cell::new(0) };
    }

    /// Counts the request and never the release: `free` is not subtracted and a
    /// `realloc` is counted at its new size rather than its growth, which
    /// double-counts the geometric growth of the parser's own arrays. The total
    /// is therefore an upper bound on live tree-sitter heap, so a ceiling on it
    /// can refuse a parse early but never late.
    fn add(bytes: usize) {
        REQUESTED.set(REQUESTED.get().saturating_add(bytes));
    }

    unsafe extern "C" fn counted_malloc(size: usize) -> *mut c_void {
        add(size);
        unsafe { malloc(size) }
    }

    unsafe extern "C" fn counted_calloc(count: usize, size: usize) -> *mut c_void {
        add(count.saturating_mul(size));
        unsafe { calloc(count, size) }
    }

    unsafe extern "C" fn counted_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
        add(size);
        unsafe { realloc(ptr, size) }
    }

    unsafe extern "C" fn counted_free(ptr: *mut c_void) {
        unsafe { free(ptr) }
    }

    /// Install the shims once per process, then start a fresh count. Called
    /// before the parser is built so the parser's own fixed cost is outside the
    /// ceiling, which measures one parse.
    pub(super) fn begin() {
        static INSTALLED: Once = Once::new();
        INSTALLED.call_once(|| unsafe {
            tree_sitter::set_allocator(
                Some(counted_malloc),
                Some(counted_calloc),
                Some(counted_realloc),
                Some(counted_free),
            );
        });
        REQUESTED.set(0);
    }

    pub(super) fn requested() -> usize {
        REQUESTED.get()
    }
}

pub fn check(source: &str) -> Result<(), &'static str> {
    parse_checked(source).map(drop)
}

fn parse_checked(source: &str) -> Result<tree_sitter::Tree, &'static str> {
    heap::begin();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .map_err(|_| "JavaScript preflight grammar is unavailable")?;
    let deadline = Instant::now() + PARSE_BUDGET;
    let mut over_heap = false;
    let mut cancelled = |_: &tree_sitter::ParseState| {
        // The heap ceiling is asked first so a parse that is both large and
        // slow reports the bound that is a function of the bytes rather than
        // the one that is a function of the machine.
        if heap::requested() > MAX_PARSE_HEAP_BYTES {
            over_heap = true;
            return true;
        }
        Instant::now() >= deadline
    };
    let parsed = parser.parse_with_options(
        &mut |offset, _| &source.as_bytes()[offset..],
        None,
        Some(tree_sitter::ParseOptions::new().progress_callback(&mut cancelled)),
    );
    let tree = match parsed {
        Some(tree) => tree,
        // Cancellation discards the partial stack, so the refusal costs the
        // heap measured at the ceiling and not a complete tree.
        None if over_heap => {
            return Err("JavaScript preflight exceeded its parse memory budget");
        }
        None => return Err("JavaScript preflight exceeded its time budget"),
    };
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
        // Bounded by node count alone. The walk visits at most MAX_TREE_NODES + 1
        // nodes, which is already a deterministic bound on its cost, so adding
        // the clock here would only make an admissible source refusable.
        if nodes > MAX_TREE_NODES {
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
    use super::{MAX_PARSE_HEAP_BYTES, MAX_TREE_NODES, check, function_at, heap};

    /// Real minifier output: one-character locals reused in every scope, bit
    /// operations, ternaries and object/array literals, with no whitespace.
    /// This is the densest realistic JavaScript shape, and density is what
    /// decides whether an obfuscated glue bundle is admitted at all.
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

    /// Counts what the admission walk counts, so a density claim about this
    /// guard is checked here instead of asserted in prose.
    fn node_count(source: &str) -> usize {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(!tree.root_node().has_error(), "fixture must parse cleanly");
        let mut cursor = tree.walk();
        let mut nodes = 0;
        loop {
            nodes += 1;
            if cursor.goto_first_child() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    return nodes;
                }
            }
        }
    }

    /// The byte size of the obfuscated glue bundle class this bound used to
    /// refuse before any analysis budget was consulted.
    const GLUE_BYTES: usize = 1_556_723;

    #[test]
    fn the_node_bound_admits_the_dense_minified_glue_class() {
        assert_eq!(MAX_TREE_NODES, crate::MAX_SOURCE_BYTES / 2);
        // Measured on a cheap sample so the expensive case below is one parse.
        let sample = dense_minified(128 * 1024);
        let density = node_count(&sample) as f64 / sample.len() as f64;
        assert!((1.0..1.2).contains(&density), "{density} nodes per byte");
        let implied = density * GLUE_BYTES as f64;
        // Fails before the bound moved, and not marginally: a glue bundle of
        // this size carries more than three times the previous 500_000-node
        // admission limit, so it was refused before `source_facts`, `fold` or a
        // candidate query could report anything about it.
        assert!(implied > 500_000.0, "{implied} nodes");
        assert!(implied < MAX_TREE_NODES as f64, "{implied} nodes");
        assert!(check(&dense_minified(GLUE_BYTES)).is_ok());
        // The parse heap ceiling must not take this class back. Asserted on the
        // parse above rather than on a second one, so the ceiling costs this
        // suite no extra multi-megabyte parse.
        let requested = heap::requested();
        assert!(requested * 2 < MAX_PARSE_HEAP_BYTES, "{requested} bytes");
    }

    #[test]
    fn a_source_over_the_node_bound_is_refused_by_the_bound_not_by_a_clock() {
        // Empty statements are the densest shape the grammar admits, at two
        // nodes per byte, so this crosses the bound with the least text and the
        // cheapest parse. Pin the ratio on a sample rather than re-walking it.
        assert_eq!(node_count(&";".repeat(8)), 17);
        let over = ";".repeat(MAX_TREE_NODES / 2);
        assert_eq!(
            check(&over).unwrap_err(),
            "JavaScript preflight exceeded its complexity budget"
        );
        // One node fewer is admitted. The walk is bounded by node count alone,
        // so the verdict is a function of the bytes and not of how long the
        // traversal took to reach them.
        assert!(check(&";".repeat(MAX_TREE_NODES / 2 - 1)).is_ok());
        // That source is also the densest tree the grammar can build at the
        // node bound, so it is the parse heap ceiling's calibration case: the
        // ceiling has to clear it, and here by 1.41x.
        let requested = heap::requested();
        assert!(requested < MAX_PARSE_HEAP_BYTES, "{requested} bytes");
        assert!(requested * 3 > MAX_PARSE_HEAP_BYTES, "{requested} bytes");
    }

    /// Nested sequence expressions: the shape that costs the most parser heap
    /// per source byte of any measured, which makes it both the cheapest way to
    /// cross the ceiling and the shape that reached 2,011.7 MiB of transient
    /// tree at the byte cap before being refused for its depth.
    fn nested_sequences(byte_target: usize) -> String {
        let depth = byte_target.saturating_sub(2) / 4;
        let mut out = String::with_capacity(byte_target + 8);
        for _ in 0..depth {
            out.push_str("(a,");
        }
        out.push('a');
        for _ in 0..depth {
            out.push(')');
        }
        out.push(';');
        out
    }

    /// A large source of long string literals: 4 MiB, a clean parse, few nodes
    /// and little parser heap. The ceiling must not refuse this, which is what
    /// separates it from a smaller byte cap for this operation.
    fn sparse_string_table(byte_target: usize) -> String {
        let mut out = String::from("var t=[");
        while out.len() < byte_target {
            out.push_str("'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',");
        }
        out.push_str("'z'];");
        out
    }

    /// One test rather than several so these parses run in sequence. The four
    /// seconds `PARSE_BUDGET` allows is measured against one parse at a time,
    /// and this suite already runs several multi-megabyte parses concurrently;
    /// the parser being built optimized in every profile is what keeps that
    /// clock away from the verdict, not headroom in the budget.
    #[test]
    fn the_parse_memory_ceiling_refuses_from_inside_the_parse() {
        assert_eq!(MAX_PARSE_HEAP_BYTES, MAX_TREE_NODES * 192);
        // Under the crossover the parse still fits, so the depth bound answers
        // from the finished tree exactly as it did before the ceiling existed.
        assert_eq!(
            check(&nested_sequences(256 * 1024)).unwrap_err(),
            "JavaScript nesting exceeds the supported depth of 128"
        );
        let fitted = heap::requested();
        assert!(fitted < MAX_PARSE_HEAP_BYTES, "{fitted} bytes");

        // Over it the ceiling answers instead, from inside the parse. This is
        // the honest narrowing: both are refusals, and which bound reports one
        // now depends on whether building the tree fits.
        let over = nested_sequences(768 * 1024);
        assert_eq!(
            check(&over).unwrap_err(),
            "JavaScript preflight exceeded its parse memory budget"
        );
        // The structural proxy for the peak. The ceiling is read at a progress
        // tick, so the count overshoots it by whatever the hundred operations
        // since the last tick asked for. That is usually a few kilobytes, 3,296
        // bytes for this source, but a geometric growth of one parser array can
        // land in the same window and was measured at 4.0 MiB. The slack below
        // is an eighth of the ceiling: loose enough for that growth, and
        // nowhere near the 1,088.5 MiB a complete tree for the byte cap asks
        // for.
        let requested = heap::requested();
        assert!(requested > MAX_PARSE_HEAP_BYTES, "{requested} bytes");
        assert!(
            requested < MAX_PARSE_HEAP_BYTES + MAX_PARSE_HEAP_BYTES / 8,
            "{requested} bytes"
        );
        assert_eq!(
            check(&over).unwrap_err(),
            "JavaScript preflight exceeded its parse memory budget"
        );
        // Same bytes, same count. The ceiling decides on the source, not on
        // allocator or machine state, which a measured RSS could not have kept.
        assert_eq!(heap::requested(), requested);

        // The declared byte cap is still admissible when the parse fits: 4 MiB
        // of long string literals costs little parser heap, so the ceiling is
        // not a smaller byte cap for this operation wearing another name.
        assert!(check(&sparse_string_table(crate::MAX_SOURCE_BYTES - 64)).is_ok());
        let requested = heap::requested();
        assert!(requested * 4 < MAX_PARSE_HEAP_BYTES, "{requested} bytes");
    }

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
