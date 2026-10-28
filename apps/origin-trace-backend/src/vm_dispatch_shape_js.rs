//! JavaScript dispatch-site classification over comment- and literal-masked
//! function regions. Deliberately syntactic: bindings and writes are indexed
//! by name inside one region, which is evidence of shape, not a data-flow
//! proof. Anything outside the recognized forms stays `unknown`.
//!
//! Each region is indexed once: bracket pairs, loop and `if` header
//! intervals, and every binding, write and arithmetic advance by name. Site
//! classification then only looks names up, under a per-query step budget and
//! the shared per-artifact budget, so work stays linear in the region size.
use super::{Budget, Kind, MAX_QUERY_STEPS, MIN_COMPARE_ARMS, Repeats, Site, Source, priority};
use regex::Regex;
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::LazyLock,
};

const MAX_TRACE_DEPTH: u8 = 4;
const MAX_VALUE_BYTES: usize = 200;
const MAX_ALTERNATIVES: usize = 16;
/// Classified sites per function region; further sites are counted as
/// omitted. A generated region with thousands of indexed calls stays bounded.
pub(crate) const MAX_REGION_SITES: u64 = 4096;
/// Characters of a line counted exactly per column checkpoint.
const COLUMN_CHECKPOINT: usize = 4096;

static LOOP_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:while|for)\s*\(|\bdo\b").expect("loop header"));
static SWITCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bswitch\s*\(").expect("switch"));
/// `table[selector](...)`, also through `.call(...)` or `.apply(...)`.
pub(crate) static INDEXED_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b([A-Za-z_$][\w$]*)\s*\[((?:[^\[\]]+|\[[^\[\]]*\])+)\]\s*(?:\.\s*(?:call|apply)\s*)?\(",
    )
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
static WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*(\+\+|--|<<=|>>>=|>>=|\*\*=|[-+*/%&|^]=|=)",
    )
    .expect("write")
});
static PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\+\+|--)\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)").expect("prefix")
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

/// One-based line and character column of a byte offset. Continuation-byte
/// checkpoints keep a column lookup bounded even on one minified line.
pub(crate) struct Lines {
    starts: Vec<usize>,
    continuation: Vec<usize>,
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
        let mut continuation = vec![0];
        let mut count = 0;
        for chunk in source.as_bytes().chunks(COLUMN_CHECKPOINT) {
            count += chunk.iter().filter(|byte| (**byte & 0xc0) == 0x80).count();
            continuation.push(count);
        }
        Self {
            starts,
            continuation,
        }
    }

    fn continuation_before(&self, source: &str, offset: usize) -> usize {
        let checkpoint = offset / COLUMN_CHECKPOINT;
        self.continuation[checkpoint]
            + source.as_bytes()[checkpoint * COLUMN_CHECKPOINT..offset]
                .iter()
                .filter(|byte| (**byte & 0xc0) == 0x80)
                .count()
    }

    fn locate(&self, source: &str, offset: usize) -> (usize, usize) {
        let line = self.starts.partition_point(|start| *start <= offset);
        let start = self.starts[line - 1];
        let characters = (offset - start)
            - (self.continuation_before(source, offset) - self.continuation_before(source, start));
        (line, characters + 1)
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

fn normalized(name: &str) -> String {
    name.split_whitespace().collect()
}

fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

/// A standalone mention of `name` (an identifier or member path) in `text`.
fn mentions(text: &str, name: &str) -> bool {
    let text = normalized(text);
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(found) = text[from..].find(name) {
        let start = from + found;
        let end = start + name.len();
        let before = start.checked_sub(1).map(|index| bytes[index]);
        let after = bytes.get(end).copied();
        if !before.is_some_and(|byte| identifier_byte(byte) || byte == b'.')
            && !after.is_some_and(identifier_byte)
        {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Nested intervals with parent links: the enclosing intervals of an offset
/// are found by walking up from the last one starting at or before it.
#[derive(Default)]
struct Intervals {
    ranges: Vec<(usize, usize)>,
    parents: Vec<Option<usize>>,
}

impl Intervals {
    fn new(mut ranges: Vec<(usize, usize)>) -> Self {
        ranges.sort_by_key(|(start, end)| (*start, std::cmp::Reverse(*end)));
        ranges.dedup();
        let mut parents = Vec::with_capacity(ranges.len());
        let mut stack: Vec<usize> = Vec::new();
        for (index, (start, end)) in ranges.iter().enumerate() {
            while let Some(top) = stack.last() {
                if ranges[*top].1 <= *start || ranges[*top].1 < *end {
                    stack.pop();
                } else {
                    break;
                }
            }
            parents.push(stack.last().copied());
            stack.push(index);
        }
        Self { ranges, parents }
    }

    /// Enclosing intervals, innermost first. `inclusive_start` decides
    /// whether an interval starting at `at` contains it.
    fn enclosing(&self, at: usize, inclusive_start: bool) -> Vec<(usize, usize)> {
        let upper = self.ranges.partition_point(|(start, _)| {
            if inclusive_start {
                *start <= at
            } else {
                *start < at
            }
        });
        let mut found = Vec::new();
        let mut candidate = upper.checked_sub(1);
        // Siblings before `at` are skipped by climbing to their parents.
        while let Some(index) = candidate {
            let (_, end) = self.ranges[index];
            if at < end {
                found.push(self.ranges[index]);
            }
            candidate = self.parents[index];
        }
        found
    }
}

/// Bindings, writes and arithmetic advances of every name in one region.
#[derive(Default)]
struct Index {
    /// Plain `=` writes: (name offset, value offset, value text).
    definitions: HashMap<String, Vec<(usize, usize, String)>>,
    writes: HashMap<String, Vec<usize>>,
    /// `++`, `--`, `+=`, `-=` and `name = name ± ...`.
    advances: HashMap<String, Vec<usize>>,
}

fn any_within(offsets: Option<&Vec<usize>>, (start, end): (usize, usize)) -> bool {
    offsets.is_some_and(|offsets| {
        let first = offsets.partition_point(|offset| *offset < start);
        offsets.get(first).is_some_and(|offset| *offset < end)
    })
}

/// Syntactic facts of one dispatch site before classification.
struct Found {
    kind: Kind,
    instruction: &'static str,
    at: usize,
    size: usize,
    selector: String,
    expression: String,
    arm_count: Option<u64>,
    string_cases: bool,
}

struct Region<'a> {
    source: &'a str,
    text: &'a str,
    start: usize,
    params: &'a [String],
    pairs: HashMap<usize, usize>,
    loops: Intervals,
    index: Index,
    steps: Cell<u64>,
    step_limit: Cell<u64>,
}

#[derive(Clone)]
struct Trace {
    source: Source,
    /// Identifier or member path whose writes re-derive the selector.
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

impl<'a> Region<'a> {
    fn new(source: &'a str, text: &'a str, start: usize, params: &'a [String]) -> Self {
        let mut region = Self {
            source,
            text,
            start,
            params,
            pairs: Self::pairs(text),
            loops: Intervals::default(),
            index: Index::default(),
            steps: Cell::new(0),
            step_limit: Cell::new(MAX_QUERY_STEPS),
        };
        region.loops = region.loop_intervals();
        region.index = region.build_index();
        region
    }

    /// Every bracket pair in one pass. Unbalanced brackets have no pair.
    fn pairs(text: &str) -> HashMap<usize, usize> {
        let mut pairs = HashMap::new();
        let mut stack: Vec<(u8, usize)> = Vec::new();
        for (index, byte) in text.bytes().enumerate() {
            match byte {
                b'(' | b'[' | b'{' => stack.push((byte, index)),
                b')' | b']' | b'}' => {
                    let open = match byte {
                        b')' => b'(',
                        b']' => b'[',
                        _ => b'{',
                    };
                    if let Some(position) = stack.iter().rposition(|(kind, _)| *kind == open) {
                        let (_, start) = stack[position];
                        stack.truncate(position);
                        pairs.insert(start, index);
                    }
                }
                _ => (),
            }
        }
        pairs
    }

    fn close(&self, open: usize) -> Option<usize> {
        self.pairs.get(&open).copied()
    }

    fn skip_space(&self, mut at: usize) -> usize {
        let bytes = self.text.as_bytes();
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        at
    }

    fn keyword_at(&self, at: usize, keyword: &str) -> bool {
        self.text[at..].starts_with(keyword)
            && !self
                .text
                .as_bytes()
                .get(at + keyword.len())
                .is_some_and(|byte| identifier_byte(*byte))
    }

    /// Inclusive end offset of the statement starting at `at`, covering
    /// blocks, braceless bodies and statement-form `do ... while (...)`.
    fn statement_end(&self, at: usize, depth: u8) -> Option<usize> {
        let at = self.skip_space(at);
        let bytes = self.text.as_bytes();
        if at >= bytes.len() || depth > 16 {
            return None;
        }
        if bytes[at] == b'{' {
            return self.close(at);
        }
        for keyword in ["switch", "if", "for", "while", "with"] {
            if !self.keyword_at(at, keyword) {
                continue;
            }
            let open = self.skip_space(at + keyword.len());
            if bytes.get(open) != Some(&b'(') {
                break;
            }
            let close = self.close(open)?;
            if keyword == "switch" {
                let body = self.skip_space(close + 1);
                return if bytes.get(body) == Some(&b'{') {
                    self.close(body)
                } else {
                    Some(close)
                };
            }
            return self.statement_end(close + 1, depth + 1);
        }
        if self.keyword_at(at, "do") {
            let body = self.statement_end(at + 2, depth + 1)?;
            let next = self.skip_space(body + 1);
            if self.keyword_at(next, "while") {
                let open = self.skip_space(next + 5);
                if bytes.get(open) == Some(&b'(') {
                    return self.close(open);
                }
            }
            return Some(body);
        }
        let mut index = at;
        while index < bytes.len() {
            match bytes[index] {
                b'(' | b'[' | b'{' => index = self.close(index)?,
                b';' => return Some(index),
                b')' | b']' | b'}' => return Some(index.saturating_sub(1)),
                _ => (),
            }
            index += 1;
        }
        Some(bytes.len() - 1)
    }

    fn loop_intervals(&self) -> Intervals {
        let bytes = self.text.as_bytes();
        let mut ranges = Vec::new();
        for header in LOOP_HEADER.find_iter(self.text) {
            if header.start() > 0 && bytes[header.start() - 1] == b'.' {
                continue;
            }
            let end = if header.as_str() == "do" {
                self.statement_end(header.start(), 0)
            } else {
                self.close(header.end() - 1)
                    .and_then(|close| self.statement_end(close + 1, 0))
            };
            if let Some(end) = end {
                ranges.push((header.start(), end + 1));
            }
        }
        Intervals::new(ranges)
    }

    /// The value of an assignment: up to a top-level `;`, `,`, closing
    /// bracket or line end, so comma declarations split per binding.
    fn value_end(&self, from: usize) -> usize {
        let bytes = self.text.as_bytes();
        let limit = (from + MAX_VALUE_BYTES).min(bytes.len());
        let mut index = from;
        while index < limit {
            match bytes[index] {
                b'(' | b'[' | b'{' => match self.close(index) {
                    Some(close) if close < limit => index = close,
                    _ => return limit,
                },
                b';' | b',' | b')' | b']' | b'}' => return index,
                b'\n' if !self.text[from..index].trim().is_empty() => return index,
                _ => (),
            }
            index += 1;
        }
        limit
    }

    fn build_index(&self) -> Index {
        let bytes = self.text.as_bytes();
        let mut index = Index::default();
        for captures in WRITE.captures_iter(self.text) {
            let whole = captures.get(0).expect("write");
            let name_match = captures.get(1).expect("written name");
            if name_match
                .start()
                .checked_sub(1)
                .is_some_and(|before| bytes[before] == b'.' || identifier_byte(bytes[before]))
            {
                continue;
            }
            let name = normalized(name_match.as_str());
            if ["var", "let", "const", "return", "typeof", "case"].contains(&name.as_str()) {
                continue;
            }
            let operator = &captures[2];
            let at = name_match.start();
            if operator == "=" {
                if matches!(bytes.get(whole.end()), Some(b'=' | b'>')) {
                    continue;
                }
                let value_start = self.skip_space(whole.end());
                let value_end = self.value_end(value_start).max(value_start);
                let value = self.text[value_start..value_end].trim().to_owned();
                if value.starts_with(&name)
                    && value[name.len()..].trim_start().starts_with(['+', '-'])
                {
                    index.advances.entry(name.clone()).or_default().push(at);
                }
                index
                    .definitions
                    .entry(name.clone())
                    .or_default()
                    .push((at, value_start, value));
            } else if ["++", "--", "+=", "-="].contains(&operator) {
                index.advances.entry(name.clone()).or_default().push(at);
            }
            index.writes.entry(name).or_default().push(at);
        }
        for captures in PREFIX.captures_iter(self.text) {
            let operator = captures.get(1).expect("prefix operator");
            if operator.start().checked_sub(1).is_some_and(|before| {
                identifier_byte(bytes[before]) || matches!(bytes[before], b')' | b']')
            }) {
                continue;
            }
            let name = normalized(&captures[2]);
            let at = operator.start();
            index.advances.entry(name.clone()).or_default().push(at);
            index.writes.entry(name).or_default().push(at);
        }
        for offsets in index.writes.values_mut().chain(index.advances.values_mut()) {
            offsets.sort_unstable();
        }
        index
    }

    fn definitions(&self, name: &str) -> &[(usize, usize, String)] {
        self.index.definitions.get(name).map_or(&[], Vec::as_slice)
    }

    fn written_within(&self, name: &str, range: (usize, usize)) -> bool {
        any_within(self.index.writes.get(name), range)
    }

    /// An arithmetic advance (`pc++`, `pc += n`, `pc = pc + n`), not a
    /// rewrite such as `m.state = 3` or `id = queue.pop()`.
    fn advanced_within(&self, name: &str, range: (usize, usize)) -> bool {
        any_within(self.index.advances.get(name), range)
    }

    fn advanced(&self, name: &str) -> bool {
        self.index
            .advances
            .get(name)
            .is_some_and(|offsets| !offsets.is_empty())
    }

    fn step(&self) -> bool {
        let used = self.steps.get();
        if used >= self.step_limit.get() {
            return false;
        }
        self.steps.set(used + 1);
        true
    }

    fn strip<'b>(&self, mut expression: &'b str) -> &'b str {
        for _ in 0..8 {
            let trimmed = expression.trim();
            let inner =
                if trimmed.starts_with('(') && trimmed.ends_with(')') && balanced_outer(trimmed) {
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

    /// Every source that can reach an expression, one per producing binding.
    fn classify(&self, expression: &str, depth: u8) -> Vec<Trace> {
        if depth > MAX_TRACE_DEPTH || !self.step() {
            return vec![Trace::new(Source::Unknown)];
        }
        let expression = self.strip(expression);
        if INTEGER.is_match(expression) {
            return vec![Trace::new(Source::Constant)];
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
                return vec![Trace::new(Source::Unknown)];
            };
            let cursor = normalized(&cursor[1]);
            let mut trace = Trace::new(Source::CursorIndex);
            trace.buffer = Some(buffer);
            trace.accessor = accessor;
            if cursor.contains('.') {
                // The position lives on a frame or state object.
                trace.source = Source::FrameSlot;
                trace.cursor = Some(cursor);
                return vec![trace];
            }
            if let [(at, _, value)] = self.definitions(&cursor)
                && MEMBER.is_match(self.strip(value))
            {
                // A local copy of a saved frame position.
                trace.source = Source::FrameSlot;
                trace.anchor = Some(*at);
                trace.cursor = Some(normalized(self.strip(value)));
                return vec![trace];
            }
            if self.advanced(&cursor) {
                trace.cursor = Some(cursor);
                return vec![trace];
            }
            // An index nothing advances is a lookup by value, not a cursor:
            // the selector comes from wherever the index comes from.
            return self.identifier(&cursor, depth);
        }
        if MEMBER.is_match(expression) {
            let mut trace = Trace::new(Source::FrameSlot);
            trace.cursor = Some(normalized(expression));
            return vec![trace];
        }
        if IDENTIFIER.is_match(expression) {
            return self.identifier(expression, depth);
        }
        vec![Trace::new(Source::Unknown)]
    }

    fn identifier(&self, name: &str, depth: u8) -> Vec<Trace> {
        let parameter = self.params.iter().any(|param| param == name);
        let definitions = self.definitions(name);
        let mut traces = Vec::new();
        // The incoming argument reaches every use the function does not
        // overwrite first; without flow order it is always an alternative.
        if parameter {
            traces.push(Trace::new(Source::CallArgument));
        } else if definitions.is_empty() {
            return vec![Trace::new(Source::Unknown)];
        }
        for (at, _, value) in definitions {
            if !self.step() {
                break;
            }
            // An advance (`k + 1`), a normalization (`k | 0`) or another
            // self-derived write adds no new value source.
            if mentions(value, name) {
                continue;
            }
            let sources = if value.is_empty() {
                vec![Trace::new(Source::Unknown)]
            } else {
                self.classify(value, depth + 1)
            };
            for mut trace in sources {
                if trace.anchor.is_none() {
                    trace.anchor = Some(*at);
                }
                if trace.source == Source::Constant {
                    trace.cursor = Some(name.to_owned());
                    trace.anchor = Some(*at);
                }
                if traces.len() < MAX_ALTERNATIVES
                    && !traces.iter().any(|known: &Trace| {
                        known.source == trace.source && known.anchor == trace.anchor
                    })
                {
                    traces.push(trace);
                }
            }
        }
        // Constant writes inside a loop make the argument only the seed of a
        // state machine. Outside loops they are guards or defaults.
        if parameter
            && traces.iter().any(|trace| {
                trace.source == Source::Constant
                    && trace
                        .anchor
                        .is_some_and(|at| !self.loops.enclosing(at, true).is_empty())
            })
        {
            traces.retain(|trace| trace.source != Source::CallArgument);
        }
        if traces.is_empty() {
            traces.push(Trace::new(Source::Unknown));
        }
        traces
    }

    fn repeats(&self, trace: &Trace, at: usize) -> (Repeats, Option<(usize, usize)>) {
        let loops = self.loops.enclosing(at, true);
        let Some(innermost) = loops.first().copied() else {
            return (Repeats::Once, None);
        };
        for range in loops {
            let inside = |offset: usize| range.0 <= offset && offset < range.1;
            if trace.anchor.is_some_and(|anchor| !inside(anchor)) {
                continue;
            }
            let advances = trace
                .cursor
                .as_ref()
                .is_some_and(|cursor| match trace.source {
                    // A position must advance, not merely be rewritten.
                    Source::CursorIndex | Source::CursorPointer | Source::FrameSlot => {
                        self.advanced_within(cursor, range)
                    }
                    Source::Constant | Source::HandlerAddress => self.written_within(cursor, range),
                    _ => false,
                });
            if advances {
                return (Repeats::Loop, Some(range));
            }
        }
        (Repeats::Unknown, Some(innermost))
    }

    /// The reaching source that best explains a site, as for Wasm: one
    /// re-derived in a loop with a cursor-like selector, then any loop, then
    /// by source.
    fn choose(&self, traces: Vec<Trace>, at: usize) -> (Trace, Repeats, Option<(usize, usize)>) {
        let evaluated = traces
            .into_iter()
            .map(|trace| {
                let (repeats, range) = self.repeats(&trace, at);
                (trace, repeats, range)
            })
            .collect::<Vec<_>>();
        let position = evaluated
            .iter()
            .position(|(trace, repeats, _)| *repeats == Repeats::Loop && trace.source.cursor_like())
            .or_else(|| {
                evaluated
                    .iter()
                    .position(|(_, repeats, _)| *repeats == Repeats::Loop)
            })
            .unwrap_or_else(|| {
                let best = evaluated
                    .iter()
                    .map(|(trace, _, _)| priority(trace.source))
                    .max()
                    .unwrap_or(0);
                evaluated
                    .iter()
                    .position(|(trace, _, _)| priority(trace.source) == best)
                    .unwrap_or(0)
            });
        evaluated.into_iter().nth(position).unwrap_or((
            Trace::new(Source::Unknown),
            Repeats::Unknown,
            None,
        ))
    }

    fn buffer_kind(&self, trace: &Trace, string_cases: bool) -> Option<&'static str> {
        if !trace.source.cursor_like() {
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
        for (_, value_start, value) in self.definitions(buffer) {
            if TYPED_ARRAY.is_match(value) {
                return Some("typed-array");
            }
            if value.starts_with('[') {
                return Some("array");
            }
            // String literals are masked; the original byte shows the quote.
            if matches!(
                self.source.as_bytes().get(self.start + value_start),
                Some(b'"' | b'\'' | b'`')
            ) || value.starts_with("String(")
            {
                return Some("string");
            }
        }
        Some("unknown")
    }

    /// Classify one site under a fresh per-query step budget.
    fn site(&self, lines: &Lines, found: Found, budget: u64) -> (Site, u64) {
        self.steps.set(0);
        self.step_limit.set(budget.min(MAX_QUERY_STEPS));
        let traces = match found.kind {
            Kind::Threaded => {
                let mut trace = Trace::new(Source::HandlerAddress);
                trace.cursor = Some(found.selector.clone());
                trace.anchor = Some(found.at);
                vec![trace]
            }
            _ => self.classify(&found.selector, 0),
        };
        let (trace, repeats, loop_range) = self.choose(traces, found.at);
        let absolute = self.start + found.at;
        let (line, column) = lines.locate(self.source, absolute);
        let buffer_kind = self.buffer_kind(&trace, found.string_cases);
        let site = Site {
            kind: found.kind,
            source: trace.source,
            repeats,
            instruction: found.instruction,
            function_index: None,
            function_body_offset: Some(self.start),
            byte_offset: absolute,
            byte_size: found.size,
            line: Some(line),
            column: Some(column),
            selector_expression: found.expression,
            selector_offset: trace.anchor.map(|anchor| self.start + anchor),
            arm_count: found.arm_count,
            loop_range: loop_range.map(|(start, end)| (self.start + start, self.start + end)),
            buffer_kind,
            table: None,
        };
        (site, self.steps.get())
    }

    fn switches(&self) -> Vec<Found> {
        let bytes = self.text.as_bytes();
        let mut found = Vec::new();
        for switch in SWITCH.find_iter(self.text) {
            let open = switch.end() - 1;
            let Some(close) = self.close(open) else {
                continue;
            };
            let selector = &self.text[open + 1..close];
            let body_open = self.skip_space(close + 1);
            if bytes.get(body_open) != Some(&b'{') {
                continue;
            }
            let body_close = self.close(body_open).unwrap_or(bytes.len());
            let mut arms = 0u64;
            let mut string_cases = false;
            let mut index = body_open + 1;
            // Only labels of this switch: nested blocks are skipped whole.
            while index < body_close {
                match bytes[index] {
                    b'(' | b'[' | b'{' => {
                        index = self.close(index).unwrap_or(body_close);
                    }
                    b'c' if self.keyword_at(index, "case")
                        && !index
                            .checked_sub(1)
                            .is_some_and(|before| identifier_byte(bytes[before])) =>
                    {
                        arms += 1;
                        let after = self.start + index + 4;
                        if self.source.as_bytes()[after..]
                            .iter()
                            .find(|byte| !byte.is_ascii_whitespace())
                            .is_some_and(|byte| matches!(byte, b'"' | b'\'' | b'`'))
                        {
                            string_cases = true;
                        }
                        index += 3;
                    }
                    _ => (),
                }
                index += 1;
            }
            found.push(Found {
                kind: Kind::SwitchOnValue,
                instruction: "switch",
                at: switch.start(),
                size: switch.as_str().len(),
                selector: selector.to_owned(),
                expression: format!("switch ({})", selector.trim()),
                arm_count: Some(arms),
                string_cases,
            });
        }
        found
    }

    fn indexed_calls(&self) -> Vec<Found> {
        INDEXED_CALL
            .captures_iter(self.text)
            .map(|call| {
                let whole = call.get(0).expect("indexed call");
                Found {
                    kind: Kind::HandlerTable,
                    instruction: "indexed call",
                    at: whole.start(),
                    size: whole.as_str().len(),
                    selector: call[2].to_owned(),
                    expression: format!("{}[{}](...)", &call[1], call[2].trim()),
                    arm_count: None,
                    string_cases: false,
                }
            })
            .collect()
    }

    /// Equality ladders: tests inside an `if` header or before a ternary `?`.
    fn ladders(&self) -> Vec<Found> {
        let headers = Intervals::new(
            IF_HEADER
                .find_iter(self.text)
                .filter_map(|header| {
                    let close = self.close(header.end() - 1)?;
                    Some((header.start(), close))
                })
                .collect(),
        );
        let mut ladders = BTreeMap::<String, Vec<(usize, usize, String)>>::new();
        for captures in COMPARE.captures_iter(self.text) {
            let whole = captures.get(0).expect("comparison");
            let (name, constant, name_match) = match (captures.get(1), captures.get(2)) {
                (Some(name), Some(constant)) => (name.as_str(), constant.as_str(), name),
                _ => {
                    let name = captures.get(4).expect("reversed comparison name");
                    (name.as_str(), &captures[3], name)
                }
            };
            let at = name_match.start().min(whole.end());
            let in_header = !headers.enclosing(at, false).is_empty();
            let ternary = self.text[whole.end()..]
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
        ladders
            .into_iter()
            .filter(|(_, tests)| {
                tests
                    .iter()
                    .map(|(_, _, constant)| constant.as_str())
                    .collect::<BTreeSet<_>>()
                    .len()
                    >= MIN_COMPARE_ARMS
            })
            .map(|(name, tests)| {
                let (at, size, _) = tests[0];
                Found {
                    kind: Kind::CompareChain,
                    instruction: "if ladder",
                    at,
                    size,
                    selector: name.clone(),
                    expression: format!("{name} === constant ({} comparisons)", tests.len()),
                    arm_count: Some(tests.len() as u64),
                    string_cases: false,
                }
            })
            .collect()
    }

    /// Threaded: a loop where the current handler returns the next handler.
    fn threaded(&self) -> Vec<Found> {
        SELF_CALL
            .captures_iter(self.text)
            .filter(|captures| captures[1] == captures[2])
            .filter_map(|captures| {
                let name = captures.get(1).expect("handler name");
                if self.loops.enclosing(name.start(), true).is_empty() {
                    return None;
                }
                Some(Found {
                    kind: Kind::Threaded,
                    instruction: "self call",
                    at: name.start(),
                    size: name.as_str().len(),
                    selector: name.as_str().to_owned(),
                    expression: format!("{0} = {0}(...)", name.as_str()),
                    arm_count: None,
                    string_cases: false,
                })
            })
            .collect()
    }
}

/// Whether the outer parentheses of `text` enclose all of it.
fn balanced_outer(text: &str) -> bool {
    let mut depth = 0usize;
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return index == text.len() - 1;
                }
            }
            _ => (),
        }
    }
    false
}

/// Classify the dispatch sites of one masked function region. `text` has
/// comments, literals and nested function bodies blanked with the original
/// byte length, so region offsets map to `source` offsets. Every site found
/// is either classified or counted in `budget` as unclassified.
pub(crate) fn classify_region(
    source: &str,
    lines: &Lines,
    text: &str,
    start: usize,
    params: &[String],
    sites: &mut Vec<Site>,
    budget: &mut Budget,
) {
    let region = Region::new(source, text, start, params);
    let mut candidates = region.switches();
    candidates.extend(region.indexed_calls());
    candidates.extend(region.ladders());
    candidates.extend(region.threaded());
    candidates.sort_by_key(|candidate| candidate.at);
    let mut classified = 0u64;
    for candidate in candidates {
        if classified >= MAX_REGION_SITES {
            budget.count_unclassified();
            continue;
        }
        if budget.refuse() {
            continue;
        }
        let (site, used) = region.site(lines, candidate, budget.remaining());
        budget.spend(used);
        classified += 1;
        sites.push(site);
    }
}
