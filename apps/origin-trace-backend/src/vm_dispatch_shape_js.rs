//! JavaScript dispatch-site classification over comment- and literal-masked
//! function regions. Deliberately syntactic: bindings and mutations are
//! matched by name inside one region, which is evidence of shape, not a
//! data-flow proof. Anything outside the recognized forms stays `unknown`.
use super::{Kind, MIN_COMPARE_ARMS, Repeats, Site, Source};
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
};

const MAX_SITES_PER_REGION: usize = 256;
const MAX_TRACE_DEPTH: u8 = 4;

static LOOP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:while|for)\s*\(|\bdo\s*\{").expect("loop header"));
static SWITCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bswitch\s*\(").expect("switch"));
static CASE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bcase\b").expect("case"));
static INDEXED_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*\[((?:[^\[\]]+|\[[^\[\]]*\])+)\]\s*\(")
        .expect("indexed call")
});
static IF_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bif\s*\(").expect("if"));
static COMPARE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*===?\s*(0x[0-9a-fA-F]+|\d+)\b|\b(0x[0-9a-fA-F]+|\d+)\s*===?\s*([A-Za-z_$][\w$]*)\b",
    )
    .expect("equality test")
});
static SELF_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^.\w$])([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\(").expect("self call")
});
static INTEGER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:0x[0-9a-fA-F]+|\d+)$").expect("integer"));
static IDENTIFIER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_$][\w$]*$").expect("identifier"));
static MEMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)+$").expect("member")
});
static INDEXED_READ: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_$][\w$]*)\s*\[\s*(.+?)\s*\]$").expect("indexed read"));
static ACCESSOR_READ: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^([A-Za-z_$][\w$]*)\s*\.\s*(charCodeAt|charAt|codePointAt|getUint8|getInt8|getUint16|getInt16|getUint32|at)\s*\(\s*([^,()]+?)\s*(?:,[^()]*)?\)$",
    )
    .expect("accessor read")
});
static CURSOR_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:\+\+|--)?\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*(?:\+\+|--)?(?:\s*[+-]\s*(?:0x[0-9a-fA-F]+|\d+))?$",
    )
    .expect("cursor index")
});
static WRAPPER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(.+?)\s*(?:&|\||\^|>>>|>>|<<|-|\+)\s*(?:0x[0-9a-fA-F]+|\d+)$")
        .expect("value wrapper")
});
static TYPED_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^new\s+(?:Uint8|Int8|Uint8Clamped|Uint16|Int16|Uint32|Int32)Array\b")
        .expect("typed array")
});

/// One-based line and character column of a byte offset.
pub(crate) struct Lines {
    starts: Vec<usize>,
}

impl Lines {
    pub fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            source
                .bytes()
                .enumerate()
                .filter(|(_, byte)| *byte == b'\n')
                .map(|(index, _)| index + 1),
        );
        Self { starts }
    }
    fn locate(&self, source: &str, offset: usize) -> (usize, usize) {
        let line = self.starts.partition_point(|start| *start <= offset);
        let start = self.starts[line - 1];
        let column = source
            .get(start..offset)
            .map_or(offset - start, |text| text.chars().count());
        (line, column + 1)
    }
}

/// Parameter names from a function signature match.
pub(crate) fn parameters(signature: &str) -> Vec<String> {
    let text = signature.trim_end_matches('{').trim_end();
    let list = if let Some(open) = text.find('(') {
        let Some(close) = text.rfind(')') else {
            return Vec::new();
        };
        &text[open + 1..close.max(open + 1)]
    } else {
        text.trim_end_matches("=>").trim()
    };
    list.split(',')
        .filter_map(|part| {
            let name = part
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches("...");
            IDENTIFIER.is_match(name).then(|| name.to_owned())
        })
        .collect()
}

fn matching(bytes: &[u8], opening: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(opening) {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

/// Syntactic facts of one dispatch site before classification.
struct Found {
    kind: Kind,
    instruction: &'static str,
    at: usize,
    size: usize,
    expression: String,
    arm_count: Option<u64>,
    string_cases: bool,
}

struct Region<'a> {
    source: &'a str,
    text: &'a str,
    start: usize,
    params: &'a [String],
    loops: Vec<(usize, usize)>,
}

#[derive(Clone)]
struct Trace {
    source: Source,
    /// Identifier or member path whose mutation advances the selector.
    cursor: Option<String>,
    /// Region offset of the binding that produced the selector, if any.
    anchor: Option<usize>,
    buffer: Option<String>,
    accessor: Option<String>,
}

impl Trace {
    fn new(source: Source) -> Self {
        Self {
            source,
            cursor: None,
            anchor: None,
            buffer: None,
            accessor: None,
        }
    }
}

fn path_pattern(path: &str) -> String {
    path.split('.')
        .map(|part| regex::escape(part.trim()))
        .collect::<Vec<_>>()
        .join(r"\s*\.\s*")
}

impl Region<'_> {
    fn loops(text: &str) -> Vec<(usize, usize)> {
        let bytes = text.as_bytes();
        let mut loops = Vec::new();
        for header in LOOP.find_iter(text) {
            let end = if header.as_str().starts_with("do") {
                matching(bytes, header.end() - 1, b'{', b'}')
            } else {
                matching(bytes, header.end() - 1, b'(', b')').and_then(|close| {
                    let next = text[close + 1..].find(|c: char| !c.is_whitespace())? + close + 1;
                    if bytes[next] == b'{' {
                        matching(bytes, next, b'{', b'}')
                    } else {
                        text[next..].find(';').map(|end| next + end)
                    }
                })
            };
            if let Some(end) = end {
                loops.push((header.start(), end + 1));
            }
        }
        loops
    }

    /// Bindings and plain assignments of a name: (region offset, right side).
    fn definitions(&self, name: &str) -> Vec<(usize, String)> {
        let pattern = Regex::new(&format!(
            r"(?:^|[^.\w$])(?:(?:const|let|var)\s+)?{}\s*=([^=][^;\n]{{0,200}})",
            regex::escape(name)
        ))
        .expect("binding");
        pattern
            .captures_iter(self.text)
            .filter_map(|captures| {
                let whole = captures.get(0)?;
                let value = captures.get(1)?;
                Some((
                    whole.start(),
                    value.as_str().trim().trim_end_matches(',').to_owned(),
                ))
            })
            .collect()
    }

    fn mutated_within(&self, path: &str, (start, end): (usize, usize)) -> bool {
        let name = path_pattern(path);
        let pattern = Regex::new(&format!(
            r"(?:^|[^.\w$]){name}\s*(?:\+\+|--|[-+*/%&|^]=|<<=|>>>?=|=[^=])|(?:\+\+|--)\s*{name}\b"
        ))
        .expect("mutation");
        pattern.find_iter(&self.text[start..end]).next().is_some()
    }

    /// An arithmetic advance of a saved position (`f.pc++`, `f.pc += n`,
    /// `f.pc = f.pc + n`), not a state write such as `m.state = 3`.
    fn advanced_within(&self, path: &str, (start, end): (usize, usize)) -> bool {
        let name = path_pattern(path);
        let pattern = Regex::new(&format!(
            r"(?:^|[^.\w$]){name}\s*(?:\+\+|--|[-+]=)|(?:\+\+|--)\s*{name}\b|(?:^|[^.\w$]){name}\s*=\s*{name}\s*[-+]"
        ))
        .expect("advance");
        pattern.is_match(&self.text[start..end])
    }

    fn strip<'b>(&self, mut expression: &'b str) -> &'b str {
        for _ in 0..8 {
            let trimmed = expression.trim();
            let inner = if trimmed.starts_with('(')
                && matching(trimmed.as_bytes(), 0, b'(', b')') == Some(trimmed.len() - 1)
            {
                &trimmed[1..trimmed.len() - 1]
            } else if let Some(rest) = trimmed.strip_prefix('+').or(trimmed.strip_prefix('~')) {
                rest
            } else if let Some(captures) = WRAPPER.captures(trimmed) {
                captures.get(1).expect("wrapped value").as_str()
            } else {
                return trimmed;
            };
            expression = inner;
        }
        expression.trim()
    }

    fn classify(&self, expression: &str, depth: u8) -> Trace {
        let expression = self.strip(expression);
        if depth > MAX_TRACE_DEPTH {
            return Trace::new(Source::Unknown);
        }
        if INTEGER.is_match(expression) {
            return Trace::new(Source::Constant);
        }
        let read = INDEXED_READ
            .captures(expression)
            .map(|captures| (captures[1].to_owned(), captures[2].to_owned(), None))
            .or_else(|| {
                ACCESSOR_READ.captures(expression).map(|captures| {
                    (
                        captures[1].to_owned(),
                        captures[3].to_owned(),
                        Some(captures[2].to_owned()),
                    )
                })
            });
        if let Some((buffer, index, accessor)) = read {
            let index = self.strip(&index);
            let Some(cursor) = CURSOR_INDEX.captures(index) else {
                return Trace::new(Source::Unknown);
            };
            let cursor = cursor[1].split_whitespace().collect::<String>();
            let mut trace = Trace::new(Source::CursorIndex);
            trace.buffer = Some(buffer);
            trace.accessor = accessor;
            if cursor.contains('.') {
                // The position lives on a frame or state object.
                trace.source = Source::FrameSlot;
            } else if let [(at, value)] = self.definitions(&cursor).as_slice()
                && MEMBER.is_match(self.strip(value))
            {
                // A local copy of a saved frame position.
                trace.source = Source::FrameSlot;
                trace.anchor = Some(*at);
                trace.cursor = Some(self.strip(value).split_whitespace().collect());
                return trace;
            }
            trace.cursor = Some(cursor);
            return trace;
        }
        if MEMBER.is_match(expression) {
            let mut trace = Trace::new(Source::FrameSlot);
            trace.cursor = Some(expression.split_whitespace().collect());
            return trace;
        }
        if IDENTIFIER.is_match(expression) {
            return self.identifier(expression, depth);
        }
        Trace::new(Source::Unknown)
    }

    fn identifier(&self, name: &str, depth: u8) -> Trace {
        let parameter = self.params.iter().any(|param| param == name);
        let definitions = self.definitions(name);
        if definitions.is_empty() {
            return Trace::new(if parameter {
                Source::CallArgument
            } else {
                Source::Unknown
            });
        }
        let mut traces = Vec::new();
        for (at, value) in &definitions {
            // A write derived from itself advances, it does not produce.
            let own = Regex::new(&format!(r"(?:^|[^.\w$]){}\b", regex::escape(name)))
                .expect("self reference");
            if own.is_match(value) {
                continue;
            }
            if value.is_empty() {
                // A masked literal or an unrecognized form.
                traces.push(Trace::new(Source::Unknown));
                continue;
            }
            let mut trace = self.classify(value, depth + 1);
            if trace.anchor.is_none() {
                trace.anchor = Some(*at);
            }
            if trace.source == Source::Constant {
                trace.cursor = Some(name.to_owned());
                trace.anchor = Some(*at);
            }
            traces.push(trace);
        }
        if let Some(trace) = traces.iter().find(|trace| {
            matches!(
                trace.source,
                Source::CursorIndex | Source::CursorPointer | Source::FrameSlot
            )
        }) {
            return trace.clone();
        }
        if !traces.is_empty() && traces.iter().all(|trace| trace.source == Source::Constant) {
            let mut trace = Trace::new(Source::Constant);
            trace.cursor = Some(name.to_owned());
            trace.anchor = definitions.iter().map(|(at, _)| *at).max();
            return trace;
        }
        Trace::new(Source::Unknown)
    }

    fn repeats(&self, trace: &Trace, at: usize) -> (Repeats, Option<(usize, usize)>) {
        let mut loops = self
            .loops
            .iter()
            .filter(|(start, end)| *start <= at && at < *end)
            .copied()
            .collect::<Vec<_>>();
        loops.sort_by_key(|(start, end)| end - start);
        let Some(innermost) = loops.first().copied() else {
            return (Repeats::Once, None);
        };
        for range in loops {
            let inside = |offset: usize| range.0 <= offset && offset < range.1;
            if trace.anchor.is_some_and(|anchor| !inside(anchor)) {
                continue;
            }
            let advances = match trace.source {
                Source::CursorIndex
                | Source::CursorPointer
                | Source::Constant
                | Source::HandlerAddress => trace
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| self.mutated_within(cursor, range)),
                // A saved position must advance, not merely be rewritten.
                Source::FrameSlot => trace
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| self.advanced_within(cursor, range)),
                _ => false,
            };
            if advances {
                return (Repeats::Loop, Some(range));
            }
        }
        (Repeats::Unknown, Some(innermost))
    }

    fn buffer_kind(&self, trace: &Trace, string_cases: bool) -> Option<&'static str> {
        if !matches!(
            trace.source,
            Source::CursorIndex | Source::CursorPointer | Source::FrameSlot
        ) {
            return None;
        }
        if let Some(accessor) = &trace.accessor {
            return Some(match accessor.as_str() {
                "charCodeAt" | "charAt" | "codePointAt" => "string",
                "at" => "unknown",
                _ => "typed-array",
            });
        }
        if string_cases {
            return Some("string");
        }
        let Some(buffer) = &trace.buffer else {
            return Some("unknown");
        };
        for (at, value) in self.definitions(buffer) {
            if TYPED_ARRAY.is_match(&value) {
                return Some("typed-array");
            }
            if value.starts_with('[') {
                return Some("array");
            }
            // String literals are masked; the original byte shows the quote.
            let original = self.source.as_bytes();
            let value_start = self.text[at..].find('=').map(|eq| self.start + at + eq + 1);
            if let Some(first) = value_start.and_then(|start| {
                original[start..]
                    .iter()
                    .position(|byte| !byte.is_ascii_whitespace())
                    .map(|index| original[start + index])
            }) && matches!(first, b'"' | b'\'' | b'`')
            {
                return Some("string");
            }
            if value.starts_with("String(") {
                return Some("string");
            }
        }
        Some("unknown")
    }

    fn site(&self, lines: &Lines, trace: Trace, found: Found) -> Site {
        let Found {
            kind,
            instruction,
            at,
            size,
            expression,
            arm_count,
            string_cases,
        } = found;
        let (repeats, loop_range) = self.repeats(&trace, at);
        let absolute = self.start + at;
        let (line, column) = lines.locate(self.source, absolute);
        let buffer_kind = self.buffer_kind(&trace, string_cases);
        Site {
            kind,
            source: trace.source,
            repeats,
            instruction,
            function_index: None,
            function_body_offset: Some(self.start),
            byte_offset: absolute,
            byte_size: size,
            line: Some(line),
            column: Some(column),
            selector_expression: expression,
            selector_offset: trace.anchor.map(|anchor| self.start + anchor),
            arm_count,
            loop_range: loop_range.map(|(start, end)| (self.start + start, self.start + end)),
            buffer_kind,
            table: None,
        }
    }
}

/// Classify the dispatch sites of one masked function region. `text` has
/// comments, literals and nested function bodies blanked with the original
/// byte length, so region offsets map to `source` offsets.
pub(crate) fn classify_region(
    source: &str,
    lines: &Lines,
    text: &str,
    start: usize,
    params: &[String],
    sites: &mut Vec<Site>,
) {
    let region = Region {
        source,
        text,
        start,
        params,
        loops: Region::loops(text),
    };
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for switch in SWITCH.find_iter(text) {
        let open = switch.end() - 1;
        let Some(close) = matching(bytes, open, b'(', b')') else {
            continue;
        };
        let selector = &text[open + 1..close];
        let Some(body_open) = text[close..].find('{').map(|index| close + index) else {
            continue;
        };
        let body_close = matching(bytes, body_open, b'{', b'}').unwrap_or(text.len());
        let mut depth = 0usize;
        let mut cursor = body_open + 1;
        let mut arms = 0u64;
        let mut string_cases = false;
        for label in CASE.find_iter(&text[body_open + 1..body_close]) {
            let position = body_open + 1 + label.start();
            for byte in &bytes[cursor..position] {
                match byte {
                    b'{' => depth += 1,
                    b'}' => depth = depth.saturating_sub(1),
                    _ => (),
                }
            }
            cursor = position;
            if depth != 0 {
                continue;
            }
            arms += 1;
            let after = start + body_open + 1 + label.end();
            if source.as_bytes()[after..]
                .iter()
                .find(|byte| !byte.is_ascii_whitespace())
                .is_some_and(|byte| matches!(byte, b'"' | b'\'' | b'`'))
            {
                string_cases = true;
            }
        }
        let trace = region.classify(selector, 0);
        found.push(region.site(
            lines,
            trace,
            Found {
                kind: Kind::SwitchOnValue,
                instruction: "switch",
                at: switch.start(),
                size: switch.as_str().len(),
                expression: format!("switch ({})", selector.trim()),
                arm_count: Some(arms),
                string_cases,
            },
        ));
    }
    for call in INDEXED_CALL.captures_iter(text) {
        let whole = call.get(0).expect("indexed call");
        let selector = &call[2];
        let trace = region.classify(selector, 0);
        found.push(region.site(
            lines,
            trace,
            Found {
                kind: Kind::HandlerTable,
                instruction: "indexed call",
                at: whole.start(),
                size: whole.as_str().len(),
                expression: format!("{}[{}](...)", &call[1], selector.trim()),
                arm_count: None,
                string_cases: false,
            },
        ));
    }
    // Equality ladders: tests inside an if header or before a ternary `?`.
    let headers = IF_HEADER
        .find_iter(text)
        .filter_map(|header| {
            let close = matching(bytes, header.end() - 1, b'(', b')')?;
            Some((header.start(), close))
        })
        .collect::<Vec<_>>();
    let mut ladders = BTreeMap::<String, Vec<(usize, usize, String)>>::new();
    for captures in COMPARE.captures_iter(text) {
        let whole = captures.get(0).expect("comparison");
        let (name, constant, name_match) = match (captures.get(1), captures.get(2)) {
            (Some(name), Some(constant)) => (name.as_str(), constant.as_str(), name),
            _ => {
                let name = captures.get(4).expect("reversed comparison name");
                (name.as_str(), &captures[3], name)
            }
        };
        let at = name_match.start().min(whole.end());
        let in_header = headers
            .iter()
            .any(|(open, close)| *open < at && at < *close);
        let ternary = text[whole.end()..]
            .trim_start()
            .trim_start_matches(')')
            .trim_start()
            .starts_with('?');
        if !in_header && !ternary {
            continue;
        }
        ladders.entry(name.to_owned()).or_default().push((
            at,
            whole.end() - at,
            constant.to_ascii_lowercase(),
        ));
    }
    for (name, tests) in ladders {
        let constants = tests
            .iter()
            .map(|(_, _, constant)| constant.as_str())
            .collect::<BTreeSet<_>>();
        if constants.len() < MIN_COMPARE_ARMS {
            continue;
        }
        let (at, size, _) = tests[0];
        let trace = region.classify(&name, 0);
        found.push(region.site(
            lines,
            trace,
            Found {
                kind: Kind::CompareChain,
                instruction: "if ladder",
                at,
                size,
                expression: format!("{name} === constant ({} comparisons)", tests.len()),
                arm_count: Some(tests.len() as u64),
                string_cases: false,
            },
        ));
    }
    // Threaded: a loop where the current handler returns the next handler.
    for captures in SELF_CALL.captures_iter(text) {
        if captures[1] != captures[2] {
            continue;
        }
        let name = captures.get(1).expect("handler name");
        if !region
            .loops
            .iter()
            .any(|(start, end)| *start <= name.start() && name.start() < *end)
        {
            continue;
        }
        let mut trace = Trace::new(Source::HandlerAddress);
        trace.cursor = Some(name.as_str().to_owned());
        trace.anchor = Some(name.start());
        found.push(region.site(
            lines,
            trace,
            Found {
                kind: Kind::Threaded,
                instruction: "self call",
                at: name.start(),
                size: name.as_str().len(),
                expression: format!("{0} = {0}(...)", name.as_str()),
                arm_count: None,
                string_cases: false,
            },
        ));
    }
    found.sort_by_key(|site| site.byte_offset);
    found.truncate(MAX_SITES_PER_REGION);
    sites.extend(found);
}
