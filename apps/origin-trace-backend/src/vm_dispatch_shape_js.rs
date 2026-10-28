//! JavaScript dispatch-site classification over comment- and literal-masked
//! function regions. Deliberately syntactic: bindings and writes are indexed
//! by name inside one region, which is evidence of shape, not a data-flow
//! proof. Anything outside the recognized forms stays `unknown`.
//!
//! Each region is indexed once: bracket pairs, loop and `if` header
//! intervals, and every binding, write and arithmetic advance by name. Site
//! classification then only looks names up, under a per-query step budget and
//! the shared per-artifact budget, so work stays linear in the region size.
use super::{Kind, MAX_QUERY_STEPS, MIN_COMPARE_ARMS, Meter, Repeats, Site, Source, priority};
use regex::Regex;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::LazyLock,
};

const MAX_TRACE_DEPTH: u8 = 8;
/// Bindings of one buffer examined for `buffer_kind`; beyond, it is unknown.
const MAX_BUFFER_DEFINITIONS: usize = 64;
const MAX_VALUE_BYTES: usize = 200;
const MAX_ALTERNATIVES: usize = 16;
/// Classified sites per function region; further sites are counted as
/// omitted. A generated region with thousands of indexed calls stays bounded.
pub(crate) const MAX_REGION_SITES: u64 = 4096;
/// Characters of a line counted exactly per column checkpoint.
const COLUMN_CHECKPOINT: usize = 4096;
/// Bytes one braceless statement body is scanned for its end. A body that
/// runs on without `;`, a line break or a closing bracket ends here, so a run
/// of such loops costs linear work.
const MAX_STATEMENT_SCAN: usize = 4096;

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

    /// Line, column, and the bytes counted to find them.
    fn locate(&self, source: &str, offset: usize) -> (usize, usize, u64) {
        let line = self.starts.partition_point(|start| *start <= offset);
        let start = self.starts[line - 1];
        let characters = (offset - start)
            - (self.continuation_before(source, offset) - self.continuation_before(source, start));
        let scanned = (offset % COLUMN_CHECKPOINT + start % COLUMN_CHECKPOINT) as u64 + 1;
        (line, characters + 1, scanned)
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
/// Entries are spans into the region text, never copies, so chained writes
/// keep a fixed number of bytes per write.
#[derive(Default)]
struct Index {
    /// Plain `=` writes: (name offset, value start, value end).
    definitions: HashMap<String, Vec<Definition>>,
    writes: HashMap<String, Vec<u32>>,
    /// `++`, `--`, `+=`, `-=` and `name = name ± ...`.
    advances: HashMap<String, Vec<u32>>,
}

type Definition = (u32, u32, u32);

/// Bytes one index entry keeps, for retained-memory accounting.
const DEFINITION_BYTES: u64 = 12;
const OFFSET_BYTES: u64 = 4;
const PAIR_BYTES: u64 = 24;

fn any_within(offsets: Option<&Vec<u32>>, (start, end): (usize, usize)) -> bool {
    offsets.is_some_and(|offsets| {
        let first = offsets.partition_point(|offset| (*offset as usize) < start);
        offsets
            .get(first)
            .is_some_and(|offset| (*offset as usize) < end)
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
    meter: &'a Meter,
    /// Bytes this region's index retains, released when it is dropped.
    retained: Cell<u64>,
    source: &'a str,
    text: &'a str,
    start: usize,
    params: &'a [String],
    pairs: HashMap<usize, usize>,
    loops: Intervals,
    index: Index,
    steps: Cell<u64>,
    step_limit: Cell<u64>,
    deepest: Cell<u8>,
    /// A bound cut the current query short: its result is an honest unknown.
    limited: Cell<bool>,
    /// The depth bound cut the current computation; it is never memoized.
    depth_cut: Cell<bool>,
    identifier_memo: RefCell<HashMap<String, Memo>>,
    buffer_memo: RefCell<HashMap<String, &'static str>>,
}

/// An identifier trace plus its fresh cost in steps and depth below itself.
/// A hit replays both, so results never depend on query order. When the step
/// budget cut the computation, `cost` is a lower bound: a hit that cannot
/// afford it is limited, as recomputing would be, and any other recomputes.
#[derive(Clone)]
struct Memo {
    traces: Vec<Trace>,
    cost: u64,
    height: u8,
    exhausted: bool,
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
    /// The selector is a table read keyed by a cursor-loaded value.
    through_lookup: bool,
}

impl Trace {
    fn new(source: Source) -> Self {
        Self {
            source,
            cursor: None,
            anchor: None,
            buffer: None,
            accessor: None,
            through_lookup: false,
        }
    }
}

impl Drop for Region<'_> {
    fn drop(&mut self) {
        self.meter.release(self.retained.get());
    }
}

impl<'a> Region<'a> {
    fn new(
        source: &'a str,
        text: &'a str,
        start: usize,
        params: &'a [String],
        meter: &'a Meter,
    ) -> Self {
        let mut region = Self {
            meter,
            retained: Cell::new(0),
            source,
            text,
            start,
            params,
            pairs: HashMap::new(),
            loops: Intervals::default(),
            index: Index::default(),
            steps: Cell::new(0),
            step_limit: Cell::new(MAX_QUERY_STEPS),
            deepest: Cell::new(0),
            limited: Cell::new(false),
            depth_cut: Cell::new(false),
            identifier_memo: RefCell::new(HashMap::new()),
            buffer_memo: RefCell::new(HashMap::new()),
        };
        meter.charge(text.len() as u64);
        region.pairs = Self::pairs(text);
        region.keep(region.pairs.len() as u64 * PAIR_BYTES);
        region.loops = region.loop_intervals();
        region.keep(region.loops.ranges.len() as u64 * PAIR_BYTES);
        region.index = region.build_index();
        region
    }

    /// Retain index memory against the meter's byte bound.
    fn keep(&self, bytes: u64) -> bool {
        self.retained.set(self.retained.get() + bytes);
        self.meter.retain(bytes)
    }

    /// Every bracket pair in one linear pass, one stack per bracket kind.
    /// Unmatched brackets, such as ones inside regex literals the masker
    /// keeps, pair with nothing and cost nothing extra.
    fn pairs(text: &str) -> HashMap<usize, usize> {
        let mut pairs = HashMap::new();
        let mut stacks: [Vec<usize>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (index, byte) in text.bytes().enumerate() {
            let (kind, opening) = match byte {
                b'(' => (0, true),
                b'[' => (1, true),
                b'{' => (2, true),
                b')' => (0, false),
                b']' => (1, false),
                b'}' => (2, false),
                _ => continue,
            };
            if opening {
                stacks[kind].push(index);
            } else if let Some(start) = stacks[kind].pop() {
                pairs.insert(start, index);
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
        // An expression statement ends at `;`, a line break (automatic
        // semicolon insertion), an enclosing closer, or the scan bound.
        let limit = (at + MAX_STATEMENT_SCAN).min(bytes.len());
        let mut index = at;
        while index < limit {
            match bytes[index] {
                b'(' | b'[' | b'{' => index = self.close(index)?,
                b';' | b'\n' => break,
                b')' | b']' | b'}' => {
                    self.meter.charge((index - at) as u64 + 1);
                    return Some(index.saturating_sub(1));
                }
                _ => (),
            }
            index += 1;
        }
        self.meter.charge((index.min(limit) - at) as u64 + 1);
        Some(index.min(bytes.len() - 1))
    }

    fn loop_intervals(&self) -> Intervals {
        let bytes = self.text.as_bytes();
        let mut ranges = Vec::new();
        self.meter.charge(self.text.len() as u64);
        for header in LOOP_HEADER.find_iter(self.text) {
            if self.meter.exhausted() {
                break;
            }
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
                    _ => break,
                },
                b';' | b',' | b')' | b']' | b'}' => break,
                b'\n' if !self.text[from..index].trim().is_empty() => break,
                _ => (),
            }
            index += 1;
        }
        let end = index.min(limit);
        self.meter.charge((end - from) as u64 + 1);
        end
    }

    fn build_index(&self) -> Index {
        let bytes = self.text.as_bytes();
        let mut index = Index::default();
        self.meter.charge(2 * self.text.len() as u64);
        for captures in WRITE.captures_iter(self.text) {
            if self.meter.exhausted() {
                break;
            }
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
            let at = name_match.start() as u32;
            let mut kept = OFFSET_BYTES;
            if operator == "=" {
                if matches!(bytes.get(whole.end()), Some(b'=' | b'>')) {
                    continue;
                }
                let value_start = self.skip_space(whole.end());
                let value_end = self.value_end(value_start).max(value_start);
                let value = self.text[value_start..value_end].trim();
                if value.starts_with(&name)
                    && value[name.len()..].trim_start().starts_with(['+', '-'])
                {
                    index.advances.entry(name.clone()).or_default().push(at);
                    kept += OFFSET_BYTES;
                }
                index.definitions.entry(name.clone()).or_default().push((
                    at,
                    value_start as u32,
                    value_end as u32,
                ));
                kept += DEFINITION_BYTES;
            } else if ["++", "--", "+=", "-="].contains(&operator) {
                index.advances.entry(name.clone()).or_default().push(at);
                kept += OFFSET_BYTES;
            }
            index.writes.entry(name).or_default().push(at);
            if !self.keep(kept) {
                break;
            }
        }
        for captures in PREFIX.captures_iter(self.text) {
            let operator = captures.get(1).expect("prefix operator");
            if operator.start().checked_sub(1).is_some_and(|before| {
                identifier_byte(bytes[before]) || matches!(bytes[before], b')' | b']')
            }) {
                continue;
            }
            let name = normalized(&captures[2]);
            let at = operator.start() as u32;
            index.advances.entry(name.clone()).or_default().push(at);
            index.writes.entry(name).or_default().push(at);
            if !self.keep(2 * OFFSET_BYTES) {
                break;
            }
        }
        for offsets in index.writes.values_mut().chain(index.advances.values_mut()) {
            self.meter.charge(offsets.len() as u64);
            offsets.sort_unstable();
        }
        index
    }

    fn definitions(&self, name: &str) -> &[Definition] {
        self.index.definitions.get(name).map_or(&[], Vec::as_slice)
    }

    /// The text of one binding's value.
    fn value(&self, definition: &Definition) -> &'a str {
        self.text[definition.1 as usize..definition.2 as usize].trim()
    }

    /// Enclosing loops, innermost first, charged by how many it walks.
    fn enclosing_loops(&self, at: usize) -> Vec<(usize, usize)> {
        let loops = self.loops.enclosing(at, true);
        self.meter.charge(loops.len() as u64 + 1);
        loops
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

    /// One logical step of the query budget, and one unit of real work.
    fn step(&self) -> bool {
        let used = self.steps.get();
        if used >= self.step_limit.get() || !self.meter.charge(1) {
            self.limited.set(true);
            return false;
        }
        self.steps.set(used + 1);
        true
    }

    fn reach(&self, depth: u8) {
        if depth > self.deepest.get() {
            self.deepest.set(depth);
        }
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
        self.reach(depth);
        if depth > MAX_TRACE_DEPTH {
            self.limited.set(true);
            self.depth_cut.set(true);
            return vec![Trace::new(Source::Unknown)];
        }
        if !self.step() {
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
            if let [definition] = self.definitions(&cursor)
                && MEMBER.is_match(self.strip(self.value(definition)))
            {
                // A local copy of a saved frame position.
                trace.source = Source::FrameSlot;
                trace.anchor = Some(definition.0 as usize);
                trace.cursor = Some(normalized(self.strip(self.value(definition))));
                return vec![trace];
            }
            if self.advanced(&cursor) {
                trace.cursor = Some(cursor);
                return vec![trace];
            }
            // An index nothing advances is a lookup by value, not a cursor:
            // the selector comes from wherever the index comes from. An index
            // loaded at a cursor makes a second-level lookup.
            let mut traces = self.identifier(&cursor, depth);
            for trace in &mut traces {
                trace.through_lookup |= trace.source.cursor_like();
            }
            return traces;
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
        let memo = self.identifier_memo.borrow().get(name).cloned();
        if let Some(memo) = memo {
            // Replay what computing it fresh would cost here.
            self.reach(depth.saturating_add(memo.height));
            if depth.saturating_add(memo.height) > MAX_TRACE_DEPTH {
                self.limited.set(true);
                self.depth_cut.set(true);
                return vec![Trace::new(Source::Unknown)];
            }
            let used = self.steps.get();
            if used.saturating_add(memo.cost) >= self.step_limit.get()
                && (memo.exhausted || used.saturating_add(memo.cost) > self.step_limit.get())
            {
                self.steps.set(self.step_limit.get());
                self.limited.set(true);
                return vec![Trace::new(Source::Unknown)];
            }
            if !memo.exhausted {
                // The meter sees only the lookup this hit performs.
                self.meter.charge(1 + memo.traces.len() as u64);
                self.steps.set(used + memo.cost);
                return memo.traces;
            }
        }
        let outer_deepest = self.deepest.replace(depth);
        let outer_limited = self.limited.replace(false);
        let outer_depth_cut = self.depth_cut.replace(false);
        let before = self.steps.get();
        let traces = self.identifier_uncached(name, depth);
        let limited = self.limited.get();
        let depth_cut = self.depth_cut.get();
        if !depth_cut {
            self.identifier_memo.borrow_mut().insert(
                name.to_owned(),
                Memo {
                    traces: traces.clone(),
                    cost: self.steps.get() - before,
                    height: self.deepest.get() - depth,
                    exhausted: limited,
                },
            );
        }
        self.deepest.set(outer_deepest.max(self.deepest.get()));
        self.limited.set(outer_limited || limited);
        self.depth_cut.set(outer_depth_cut || depth_cut);
        traces
    }

    fn identifier_uncached(&self, name: &str, depth: u8) -> Vec<Trace> {
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
        for definition in definitions {
            if !self.step() {
                break;
            }
            let at = &(definition.0 as usize);
            let value = self.value(definition);
            self.meter.charge(value.len() as u64);
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
                // Constant writes differ only by where they land: one per
                // enclosing loop explains every repeat decision.
                let loop_of = |anchor: Option<usize>| {
                    anchor.and_then(|at| self.enclosing_loops(at).first().copied())
                };
                let duplicate = traces.iter().any(|known: &Trace| {
                    known.source == trace.source
                        && known.through_lookup == trace.through_lookup
                        && if trace.source == Source::Constant {
                            loop_of(known.anchor) == loop_of(trace.anchor)
                        } else {
                            known.anchor == trace.anchor
                        }
                });
                if duplicate {
                    continue;
                }
                if traces.len() >= MAX_ALTERNATIVES {
                    self.limited.set(true);
                    break;
                }
                traces.push(trace);
            }
        }
        // Constant writes inside a loop make the argument only the seed of a
        // state machine. Outside loops they are guards or defaults.
        if parameter
            && traces.iter().any(|trace| {
                trace.source == Source::Constant
                    && trace
                        .anchor
                        .is_some_and(|at| !self.enclosing_loops(at).is_empty())
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
        let loops = self.enclosing_loops(at);
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
        if trace.buffer.as_deref() == Some("arguments") {
            return Some("arguments");
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
        // Once per buffer name, over a bounded prefix of its bindings.
        if let Some(kind) = self.buffer_memo.borrow().get(buffer) {
            self.meter.charge(1);
            return Some(kind);
        }
        let kind = self.binding_kind(buffer);
        self.buffer_memo.borrow_mut().insert(buffer.clone(), kind);
        Some(kind)
    }

    fn binding_kind(&self, buffer: &str) -> &'static str {
        let definitions = self.definitions(buffer);
        if definitions.len() > MAX_BUFFER_DEFINITIONS {
            self.meter.charge(1);
            return "unknown";
        }
        for definition in definitions {
            let (value_start, value) = (definition.1 as usize, self.value(definition));
            self.meter.charge(1 + value.len() as u64);
            if TYPED_ARRAY.is_match(value) {
                return "typed-array";
            }
            if value.starts_with('[') {
                return "array";
            }
            // String literals are masked; the original byte shows the quote.
            if matches!(
                self.source.as_bytes().get(self.start + value_start),
                Some(b'"' | b'\'' | b'`')
            ) || value.starts_with("String(")
            {
                return "string";
            }
        }
        "unknown"
    }

    /// Classify one site under a fresh per-query step budget. A query a
    /// bound cut short is an honest unknown, reported through the flag;
    /// None when the artifact meter ran out, so the site is unclassified.
    fn site(&self, lines: &Lines, found: Found) -> Option<(Site, bool)> {
        self.steps.set(0);
        self.step_limit.set(MAX_QUERY_STEPS);
        self.deepest.set(0);
        self.limited.set(false);
        self.depth_cut.set(false);
        let traces = match found.kind {
            Kind::Threaded => {
                let mut trace = Trace::new(Source::HandlerAddress);
                trace.cursor = Some(found.selector.clone());
                trace.anchor = Some(found.at);
                vec![trace]
            }
            _ => self.classify(&found.selector, 0),
        };
        let limited = self.limited.get();
        let (trace, repeats, loop_range) = if limited {
            let trace = Trace::new(Source::Unknown);
            let (repeats, range) = self.repeats(&trace, found.at);
            (trace, repeats, range)
        } else {
            self.choose(traces, found.at)
        };
        let absolute = self.start + found.at;
        let (line, column, scanned) = lines.locate(self.source, absolute);
        self.meter.charge(scanned);
        let buffer_kind = self.buffer_kind(&trace, found.string_cases);
        if self.meter.exhausted() {
            return None;
        }
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
            through_lookup: trace.through_lookup,
            arm_count: found.arm_count,
            loop_range: loop_range.map(|(start, end)| (self.start + start, self.start + end)),
            buffer_kind,
            table: None,
        };
        Some((site, limited))
    }

    /// Cheap dispatch strength for ordering: inside a loop, and a selector
    /// that reads a buffer at an index, directly or through one binding.
    fn strength(&self, found: &Found) -> u8 {
        let looped = !self.enclosing_loops(found.at).is_empty();
        let selector = self.strip(&found.selector);
        let reads = |text: &str| INDEXED_READ.is_match(text) || ACCESSOR_READ.is_match(text);
        self.meter.charge(selector.len() as u64 + 1);
        let fetched = reads(selector)
            || (IDENTIFIER.is_match(selector)
                && self.definitions(selector).iter().take(4).any(|definition| {
                    let value = self.value(definition);
                    self.meter.charge(value.len() as u64 + 1);
                    reads(self.strip(value))
                }));
        u8::from(looped) * 2 + u8::from(fetched)
    }

    fn switches(&self) -> Vec<Found> {
        let bytes = self.text.as_bytes();
        let mut found = Vec::new();
        self.meter.charge(self.text.len() as u64);
        for switch in SWITCH.find_iter(self.text) {
            if self.meter.exhausted() {
                break;
            }
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
            self.meter.charge((body_close - body_open) as u64);
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
        self.meter.charge(self.text.len() as u64);
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
        self.meter.charge(2 * self.text.len() as u64);
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
            let enclosing = headers.enclosing(at, false);
            self.meter.charge(enclosing.len() as u64 + 1);
            let in_header = !enclosing.is_empty();
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
        self.meter.charge(self.text.len() as u64);
        SELF_CALL
            .captures_iter(self.text)
            .filter(|captures| captures[1] == captures[2])
            .filter_map(|captures| {
                let name = captures.get(1).expect("handler name");
                if self.enclosing_loops(name.start()).is_empty() {
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
/// byte length, so region offsets map to `source` offsets. Candidates are
/// ranked by dispatch strength before the per-region site bound applies, so a
/// region full of trivial switches still classifies its interpreter first.
/// Every site found is classified or counted on the meter as unclassified.
pub(crate) fn classify_region(
    source: &str,
    lines: &Lines,
    text: &str,
    start: usize,
    params: &[String],
    sites: &mut Vec<Site>,
    meter: &Meter,
) {
    let region = Region::new(source, text, start, params, meter);
    let mut candidates = region.switches();
    candidates.extend(region.indexed_calls());
    candidates.extend(region.ladders());
    candidates.extend(region.threaded());
    let mut ranked = candidates
        .into_iter()
        .map(|candidate| (region.strength(&candidate), candidate))
        .collect::<Vec<_>>();
    ranked.sort_by_key(|(strength, candidate)| (std::cmp::Reverse(*strength), candidate.at));
    for (position, (_, candidate)) in ranked.into_iter().enumerate() {
        if position as u64 >= MAX_REGION_SITES || meter.exhausted() {
            meter.count_unclassified(1);
            continue;
        }
        match region.site(lines, candidate) {
            Some((site, limited)) => {
                meter.count_limited(limited);
                meter.retain(site.retained_bytes());
                sites.push(site);
            }
            None => meter.count_unclassified(1),
        }
    }
}
