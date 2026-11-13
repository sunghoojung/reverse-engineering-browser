//! A readable lifted listing of one Wasm function, derived on request.
//!
//! The operand stack is simulated with the declared effects in `wasm_stack`
//! and instructions fold into nested expressions, as `wasm2wat --fold-exprs`
//! and `wasm-decompile` do: `l3 = i32.load(l1, offset 8) + 1`. Every decoded
//! instruction is owned by exactly one output line, and every line carries the
//! original module byte ranges it covers, so a line can always be checked
//! against the disassembly and the hex. What the lift does not model (code
//! after an unconditional transfer, an operator whose stack effect is unknown,
//! exception handler delivery, GC casts that branch, stack switching) stays
//! the raw instruction text on a counted fallback line, never a guess.
//!
//! Folding never reorders observable effects: before a line is emitted, every
//! pending stack value it could conflict with (two effects, or a local one of
//! them writes and the other reads) is first assigned to a temporary `tN` on
//! its own line, deepest first. A value a branch discards is assigned too, so
//! no instruction disappears. Names come only from the module: its name
//! section, exports and imports (`display_name`). Nothing here runs the module.
use crate::{
    error::{Error, Result},
    wasm, wasm_graph,
    wasm_stack::{self, Label, ModuleTypes},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    path::Path,
    time::{Duration, Instant},
};
use wasmparser::{
    BlockType, ExternalKind, FrameKind, FuncValidatorAllocations, FunctionBody, KnownCustom,
    MemArg, Name, Operator, Parser, Payload, TypeRef, ValidPayload, Validator, WasmFeatures,
};

/// A lift keeps per-instruction offsets and per-line text; this many
/// instructions keep one request in tens of megabytes.
pub const MAX_INSTRUCTIONS: usize = 250_000;
pub const MAX_LINES: usize = 300_000;
const MAX_TEXT_BYTES: usize = 24 * 1024 * 1024;
const MAX_LINE_TEXT: usize = 2048;
/// Deeper or longer expressions are assigned to a temporary first, so a line
/// stays readable and nesting cannot grow with the body.
const MAX_EXPR_DEPTH: u16 = 12;
const MAX_EXPR_TEXT: usize = 200;
const MAX_INDENT: u32 = 24;
const MAX_NAME_BYTES: usize = 96;
const MAX_STORED_NAME_BYTES: usize = 1024;
const MAX_IMMEDIATE_TEXT: usize = 96;
const MAX_CASE_TEXT: usize = 240;
const MAX_FRAMES_LISTED: usize = 256;
/// Byte ranges listed per line before the rest merge into one span, so a
/// single line cannot push a page past the inline limit.
const MAX_LINE_RANGES: usize = 64;
pub const DEFAULT_LINE_LIMIT: usize = 400;
pub const MAX_LINE_LIMIT: usize = 2000;
/// The MCP server inlines a result of at most 131,072 bytes in both its
/// compact and its pretty-printed JSON; a window is cut until the whole
/// document fits 120 KiB in both, leaving room for the tool envelope.
const WINDOW_BYTES: usize = 120 * 1024;
const DEADLINE: Duration = Duration::from_secs(3);
/// The lift's size budgets; `BUDGET` in production, smaller in tests.
#[derive(Clone, Copy)]
struct Budget {
    instructions: usize,
    lines: usize,
    text_bytes: usize,
    /// Treat the deadline as passed once this much ordering work is done.
    /// Tests use it to check where the deadline is looked at without
    /// depending on the machine's speed; production leaves it unset.
    work: Option<u64>,
}
const BUDGET: Budget = Budget {
    instructions: MAX_INSTRUCTIONS,
    lines: MAX_LINES,
    text_bytes: MAX_TEXT_BYTES,
    work: None,
};
/// Stack entries visited between deadline checks.
const WORK_CHECK: u64 = 1 << 16;

const LINE_KINDS: [&str; 7] = [
    "header",
    "statement",
    "open",
    "middle",
    "close",
    "case",
    "fallback",
];
#[derive(Clone, Copy, PartialEq)]
enum LineKind {
    Header = 0,
    Statement = 1,
    Open = 2,
    Middle = 3,
    Close = 4,
    Case = 5,
    Fallback = 6,
}

const FALLBACK_REASONS: [&str; 6] = [
    "unreachable_code",
    "unknown_effect",
    "exception_handler",
    "gc_branch",
    "stack_switching",
    "label_out_of_range",
];
const UNREACHABLE_CODE: usize = 0;
const UNKNOWN_EFFECT: usize = 1;
const EXCEPTION_HANDLER: usize = 2;
const GC_BRANCH: usize = 3;
const STACK_SWITCHING: usize = 4;
const LABEL_OUT_OF_RANGE: usize = 5;

fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

/// Module-supplied names, each bounded and kept per function index.
#[derive(Default)]
struct Names {
    section: HashMap<u32, String>,
    exports: HashMap<u32, String>,
    imports: HashMap<u32, String>,
}

/// The one place a function's display name is chosen, in this order: the
/// name section, an export, an import's `module.field`, then `f<index>`.
/// Every line of the readable view and its callee table reads names through
/// here, so another name source (analyst names) is added in this function.
fn display_name(names: &Names, index: u32) -> (String, &'static str) {
    if let Some(name) = names.section.get(&index) {
        return (identifier(name), "name_section");
    }
    if let Some(name) = names.exports.get(&index) {
        return (identifier(name), "export");
    }
    if let Some(name) = names.imports.get(&index) {
        return (identifier(name), "import");
    }
    (format!("f{index}"), "index")
}

/// A module name used as written when it reads as an identifier, otherwise
/// quoted with control characters escaped, so it stays one inert line. A
/// name shaped like the lift's own `p0`, `l3`, `t9`, `g1` or `L2` is quoted
/// so it can never read as a local, temporary, global or label.
fn identifier(name: &str) -> String {
    let plain = !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_$.:<>".contains(c));
    let reserved = name.len() > 1
        && b"pltgLf".contains(&name.as_bytes()[0])
        && name.as_bytes()[1..].iter().all(u8::is_ascii_digit);
    if plain && !reserved {
        return name.to_owned();
    }
    let escaped: String = name.chars().flat_map(char::escape_debug).collect();
    format!("\"{}\"", head_and_tail(&escaped, MAX_NAME_BYTES))
}

/// Text cut to at most `limit` bytes around a `...`, keeping its start and
/// its end: overloads and numbered clones of one demangled name differ at
/// the end, so a head-only cut would print them all the same.
fn head_and_tail(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let keep = limit - 3;
    let mut head = keep * 3 / 5;
    while !text.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = text.len() - (keep - head);
    while !text.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}...{}", &text[..head], &text[tail..])
}

/// A module name kept for display. Its start and end survive, so names
/// that differ only in a long middle are the only ones that can collide.
fn bounded(name: &str) -> String {
    head_and_tail(name, MAX_STORED_NAME_BYTES)
}

/// Reads of and writes to locals, as a 64-bit bloom of local indexes. A
/// false positive only assigns a temporary earlier than needed.
#[derive(Clone, Copy, Default)]
struct Effects {
    /// Calls, memory, globals, tables, traps: anything whose order matters.
    impure: bool,
    reads: u64,
    writes: u64,
}
impl Effects {
    fn conflicts(self, other: Effects) -> bool {
        (self.impure && other.impure)
            || self.writes & (other.reads | other.writes) != 0
            || self.reads & other.writes != 0
    }
    fn union(self, other: Effects) -> Effects {
        Effects {
            impure: self.impure || other.impure,
            reads: self.reads | other.reads,
            writes: self.writes | other.writes,
        }
    }
}
fn local_bit(index: u32) -> u64 {
    1 << (index % 64)
}

/// One pending stack value: its folded text and the instructions it owns.
#[derive(Clone, Default)]
struct Expr {
    text: String,
    infix: bool,
    depth: u16,
    instrs: Vec<u32>,
    calls: Vec<u32>,
    effects: Effects,
    /// A constant or a temporary: never needs a temporary of its own.
    stable: bool,
}
impl Expr {
    fn constant(text: String, instr: u32) -> Self {
        Expr {
            text,
            instrs: vec![instr],
            stable: true,
            ..Default::default()
        }
    }
    fn temp(name: String) -> Self {
        Expr {
            text: name,
            stable: true,
            ..Default::default()
        }
    }
    /// A pop past the frame's known values: only after an unknown effect.
    fn unknown() -> Self {
        Expr::temp("?".into())
    }
    fn operand(&self) -> String {
        if self.infix {
            format!("({})", self.text)
        } else {
            self.text.clone()
        }
    }
}

struct Line {
    depth: u32,
    kind: LineKind,
    text: String,
    owned: Vec<u32>,
    /// Instructions the line names without owning (a switch's cases).
    refs: Vec<u32>,
    /// Bytes that are not instructions: the body header and local groups.
    span: Option<(u32, u32)>,
    /// A label shown at this text position when some branch targets it.
    label: Option<(u32, usize)>,
    /// A collapsed run of plain `block` openers: first label and count.
    run: Option<(u32, u32)>,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Function,
    Block,
    Loop,
    If,
    Else,
    Try,
    Catch,
    TryTable,
}
const KIND_NAMES: [&str; 8] = [
    "function",
    "block",
    "loop",
    "if",
    "else",
    "try",
    "catch",
    "try_table",
];
fn frame_kind(kind: Kind) -> FrameKind {
    match kind {
        Kind::Function | Kind::Block => FrameKind::Block,
        Kind::Loop => FrameKind::Loop,
        Kind::If => FrameKind::If,
        Kind::Else => FrameKind::Else,
        Kind::Try => FrameKind::LegacyTry,
        Kind::Catch => FrameKind::LegacyCatch,
        Kind::TryTable => FrameKind::TryTable,
    }
}

struct Frame {
    kind: Kind,
    /// The kind it opened as; `Else` and `Catch` keep `If` and `Try` here.
    opened: Kind,
    height: usize,
    /// Parameters as temporaries, restored for an `else` or `catch` arm.
    params: Vec<Expr>,
    label: u32,
    /// Temporaries a branch to this frame assigns: a loop's parameters, any
    /// other frame's results. Allocated on first use.
    slots: Vec<String>,
    branch_values: u32,
    /// Temporaries a loop's results reach its end in. A branch to a loop
    /// goes back to its start, so its results are not its branch values.
    /// Every other frame's results are its branch values, `slots`.
    result_slots: Vec<String>,
    results: u32,
    unreachable: bool,
    /// Structured instructions opened inside unreachable code.
    dead: u32,
    open_line: usize,
    open_offset: u32,
}

/// One closed frame, for the nesting summary.
struct Closed {
    open_line: usize,
    close_line: Option<usize>,
    depth: u32,
    kind: Kind,
    label: u32,
    byte_offset: u32,
}

struct Lifter<'m> {
    module: &'m ModuleTypes,
    names: &'m Names,
    params: u32,
    starts: Vec<u32>,
    ends: Vec<u32>,
    lines: Vec<Line>,
    stack: Vec<Expr>,
    frames: Vec<Frame>,
    labels: Vec<Label>,
    targeted: Vec<bool>,
    next_temp: u32,
    fallbacks: [u32; 6],
    spills: u32,
    unknown_operands: u32,
    clipped_lines: u32,
    text_bytes: usize,
    closed: Vec<Closed>,
    calls: Vec<(u32, u32)>,
    counts: BTreeMap<&'static str, u32>,
    max_depth: u32,
    omissions: Vec<String>,
    /// The line and instruction of the last collapsed `block` opener.
    run: Option<(usize, u32)>,
    ended: bool,
    /// Pending-stack entries visited while ordering effects. A deep operand
    /// stack makes each statement cost its height, so the deadline is
    /// checked by this work as well as by instruction count.
    work: u64,
    budget: Budget,
    /// A line or text budget ran out inside one instruction (a br_table's
    /// cases); the lift stops after it.
    halted: bool,
}

/// What the lift of one function produced, before windowing.
struct Lift {
    /// Pending-stack entries visited while ordering effects; the deadline
    /// tests read it.
    #[cfg_attr(not(test), allow(dead_code))]
    work: u64,
    lines: Vec<Line>,
    starts: Vec<u32>,
    ends: Vec<u32>,
    targeted: Vec<bool>,
    instruction_count: usize,
    fallbacks: [u32; 6],
    spills: u32,
    unknown_operands: u32,
    clipped_lines: u32,
    closed: Vec<Closed>,
    calls: Vec<(u32, u32)>,
    counts: BTreeMap<&'static str, u32>,
    max_depth: u32,
    truncated_instructions: bool,
    truncated_lines: bool,
    truncated_deadline: bool,
    omissions: Vec<String>,
}

/// A field of an operator whose memory argument is split from the rest by
/// autoref specialization, so no operator's debug text is parsed.
struct Field<'a, T>(&'a T);
trait MemArgField {
    fn memarg(&self) -> Option<MemArg>;
}
impl MemArgField for Field<'_, MemArg> {
    fn memarg(&self) -> Option<MemArg> {
        Some(*self.0)
    }
}
trait OtherField {
    fn memarg(&self) -> Option<MemArg>;
}
impl<T> OtherField for &Field<'_, T> {
    fn memarg(&self) -> Option<MemArg> {
        None
    }
}

macro_rules! immediates {
    ($(@$proposal:ident $op:ident $({ $($arg:ident: $argty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
        /// The operator's memory argument, with every other immediate
        /// appended to `out` by field name.
        fn immediates(op: &Operator<'_>, out: &mut Vec<(&'static str, String)>) -> Option<MemArg> {
            #[allow(unused_mut)]
            let mut memarg = None;
            #[allow(unreachable_patterns)]
            match op {
                $(Operator::$op $({ $($arg),* })? => {
                    $($(
                        match (&Field($arg)).memarg() {
                            Some(found) => memarg = Some(found),
                            None => out.push((stringify!($arg), format!("{:?}", $arg))),
                        }
                    )*)?
                })*
                _ => {}
            }
            memarg
        }
    };
}
wasmparser::for_each_operator!(immediates);

fn infix(suffix: &str, float: bool) -> Option<&'static str> {
    Some(match (suffix, float) {
        ("add", _) => "+",
        ("sub", _) => "-",
        ("mul", _) => "*",
        ("div", true) | ("div_s", false) => "/",
        ("div_u", false) => "/u",
        ("rem_s", false) => "%",
        ("rem_u", false) => "%u",
        ("and", false) => "&",
        ("or", false) => "|",
        ("xor", false) => "^",
        ("shl", false) => "<<",
        ("shr_s", false) => ">>",
        ("shr_u", false) => ">>>",
        ("eq", _) => "==",
        ("ne", _) => "!=",
        ("lt", true) | ("lt_s", false) => "<",
        ("lt_u", false) => "<u",
        ("gt", true) | ("gt_s", false) => ">",
        ("gt_u", false) => ">u",
        ("le", true) | ("le_s", false) => "<=",
        ("le_u", false) => "<=u",
        ("ge", true) | ("ge_s", false) => ">=",
        ("ge_u", false) => ">=u",
        _ => return None,
    })
}

/// Whether an operator without a memory argument can be reordered past
/// another effect: numeric and vector arithmetic that never traps.
fn pure(mnemonic: &str) -> bool {
    let (prefix, suffix) = mnemonic.split_once('.').unwrap_or((mnemonic, ""));
    match prefix {
        "i32" | "i64" => {
            !matches!(suffix, "div_s" | "div_u" | "rem_s" | "rem_u")
                && !suffix.starts_with("trunc_f")
                && !suffix.starts_with("atomic")
        }
        "f32" | "f64" | "v128" | "i8x16" | "i16x8" | "i32x4" | "i64x2" | "f32x4" | "f64x2" => true,
        "ref" => matches!(suffix, "null" | "func" | "is_null" | "eq" | "i31"),
        _ => false,
    }
}

fn clip(text: &mut String, limit: usize) -> bool {
    if text.len() <= limit {
        return false;
    }
    let mut cut = limit;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str(" [text limited]");
    true
}

fn float32(bits: u32) -> String {
    let value = f32::from_bits(bits);
    if value.is_finite() {
        format!("{value:?}f")
    } else {
        format!("f32.from_bits(0x{bits:08x})")
    }
}
fn float64(bits: u64) -> String {
    let value = f64::from_bits(bits);
    if value.is_finite() {
        format!("{value:?}")
    } else {
        format!("f64.from_bits(0x{bits:016x})")
    }
}

fn joined(values: &[Expr]) -> String {
    values
        .iter()
        .map(|value| value.text.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl<'m> Lifter<'m> {
    fn new(module: &'m ModuleTypes, names: &'m Names, type_index: u32, params: u32) -> Self {
        let function_label = Label {
            kind: FrameKind::Block,
            block_type: BlockType::FuncType(type_index),
        };
        let results = module
            .func_type(type_index)
            .map_or(0, |ty| ty.results().len() as u32);
        Lifter {
            module,
            names,
            params,
            starts: Vec::new(),
            ends: Vec::new(),
            lines: Vec::new(),
            stack: Vec::new(),
            frames: vec![Frame {
                kind: Kind::Function,
                opened: Kind::Function,
                height: 0,
                params: Vec::new(),
                label: 0,
                slots: Vec::new(),
                branch_values: results,
                result_slots: Vec::new(),
                results,
                unreachable: false,
                dead: 0,
                open_line: 0,
                open_offset: 0,
            }],
            labels: vec![function_label],
            targeted: vec![false],
            next_temp: 0,
            fallbacks: [0; 6],
            spills: 0,
            unknown_operands: 0,
            clipped_lines: 0,
            text_bytes: 0,
            closed: Vec::new(),
            calls: Vec::new(),
            counts: BTreeMap::new(),
            max_depth: 0,
            omissions: Vec::new(),
            run: None,
            ended: false,
            work: 0,
            budget: BUDGET,
            halted: false,
        }
    }

    fn local(&self, index: u32) -> String {
        if index < self.params {
            format!("p{index}")
        } else {
            format!("l{index}")
        }
    }
    fn temp(&mut self) -> String {
        let name = format!("t{}", self.next_temp);
        self.next_temp += 1;
        name
    }
    fn top(&mut self) -> &mut Frame {
        self.frames.last_mut().expect("an open frame")
    }
    fn base(&self) -> usize {
        self.frames.last().map_or(0, |frame| frame.height)
    }
    fn depth(&self) -> u32 {
        self.frames.len() as u32 + self.frames.last().map_or(0, |frame| frame.dead)
    }

    fn push_line(
        &mut self,
        kind: LineKind,
        mut text: String,
        owned: Vec<u32>,
        calls: &[u32],
    ) -> usize {
        if clip(&mut text, MAX_LINE_TEXT) {
            self.clipped_lines += 1;
        }
        self.text_bytes += text.len() + 1;
        let index = self.lines.len();
        for &function in calls {
            self.calls.push((index as u32, function));
        }
        self.lines.push(Line {
            depth: self.depth(),
            kind,
            text,
            owned,
            refs: Vec::new(),
            span: None,
            label: None,
            run: None,
        });
        self.run = None;
        index
    }

    /// Assigns every pending value that must be evaluated before `effects`
    /// to a temporary, deepest first. A value must go first when it conflicts
    /// with `effects` or with a value above it that must go first.
    fn spill_before(&mut self, effects: Effects) {
        self.spill_forced(effects, |_, _| false);
    }
    /// `spill_before`, also assigning every value `forced` selects. Marking
    /// runs from the top down and adds each marked value's effects, so a
    /// value below a forced one that conflicts with it (a read of a local the
    /// forced value writes) is assigned first too. Assigning a forced value
    /// alone would move it ahead of such a value and change what it reads.
    fn spill_forced(&mut self, effects: Effects, forced: impl Fn(usize, &Expr) -> bool) {
        let base = self.base();
        self.work += (self.stack.len() - base) as u64;
        let mut must = vec![false; self.stack.len() - base];
        let mut pending = effects;
        for position in (base..self.stack.len()).rev() {
            let entry = &self.stack[position];
            if !entry.stable && (forced(position, entry) || entry.effects.conflicts(pending)) {
                must[position - base] = true;
                pending = pending.union(entry.effects);
            }
        }
        for position in base..self.stack.len() {
            if must[position - base] {
                let entry = std::mem::take(&mut self.stack[position]);
                self.stack[position] = self.spill_line(entry);
            }
        }
    }
    /// Assigns every non-constant pending value of this frame to a temporary.
    fn spill_all(&mut self) {
        self.work += (self.stack.len() - self.base()) as u64;
        for position in self.base()..self.stack.len() {
            if !self.stack[position].stable {
                let entry = std::mem::take(&mut self.stack[position]);
                self.stack[position] = self.spill_line(entry);
            }
        }
    }
    /// One value as `tN = value`; the caller has ordered it.
    fn spill_line(&mut self, entry: Expr) -> Expr {
        let name = self.temp();
        self.spills += 1;
        let text = format!("{name} = {}", entry.text);
        self.push_line(LineKind::Statement, text, entry.instrs, &entry.calls);
        Expr::temp(name)
    }
    /// A value consumed out of order of the stack (an operand that is too
    /// deep, a branch value read twice) becomes a temporary after whatever it
    /// must follow.
    fn spill_value(&mut self, entry: Expr) -> Expr {
        if entry.stable {
            return entry;
        }
        self.spill_before(entry.effects);
        self.spill_line(entry)
    }
    /// Values a transfer discards are still evaluated: each pending value of
    /// the frame with instructions becomes its own line.
    fn flush(&mut self) {
        let base = self.base();
        self.work += (self.stack.len() - base) as u64;
        let pending = self.stack.split_off(base);
        for entry in pending {
            if !entry.instrs.is_empty() || !entry.stable {
                self.spill_line(entry);
            }
        }
    }

    fn pop(&mut self) -> Expr {
        if self.stack.len() > self.base() {
            self.stack.pop().expect("a pending value")
        } else {
            self.unknown_operands += 1;
            Expr::unknown()
        }
    }
    fn pop_n(&mut self, count: u32) -> Vec<Expr> {
        let mut values: Vec<Expr> = (0..count).map(|_| self.pop()).collect();
        values.reverse();
        values
    }

    /// Emits a statement after every pending value it must follow.
    fn statement(
        &mut self,
        kind: LineKind,
        text: String,
        values: Vec<Expr>,
        own: u32,
        extra: Effects,
    ) -> usize {
        let mut effects = extra;
        let mut owned = Vec::new();
        let mut calls = Vec::new();
        for value in values {
            effects = effects.union(value.effects);
            owned.extend(value.instrs);
            calls.extend(value.calls);
        }
        owned.push(own);
        self.spill_before(effects);
        self.push_line(kind, text, owned, &calls)
    }

    /// Folds `children` into one value, assigning operands to temporaries
    /// first when the result would be too deep or too long to read.
    fn combine(
        &mut self,
        mut children: Vec<Expr>,
        own: u32,
        effects: Effects,
        infix: bool,
        render: impl Fn(&[Expr]) -> String,
    ) -> Expr {
        let deep = children
            .iter()
            .any(|child| child.depth + 1 > MAX_EXPR_DEPTH);
        let long = children
            .iter()
            .map(|child| child.text.len() + 2)
            .sum::<usize>()
            > MAX_EXPR_TEXT;
        if deep || long {
            for child in children.iter_mut() {
                if !child.stable {
                    let taken = std::mem::take(child);
                    *child = self.spill_value(taken);
                }
            }
        }
        let text = render(&children);
        let mut value = Expr {
            text,
            infix,
            depth: children.iter().map(|child| child.depth).max().unwrap_or(0) + 1,
            effects,
            ..Default::default()
        };
        for child in children {
            value.effects = value.effects.union(child.effects);
            value.instrs.extend(child.instrs);
            value.calls.extend(child.calls);
        }
        value.instrs.push(own);
        value
    }

    fn label_name(&mut self, frame: usize) -> String {
        let label = self.frames[frame].label;
        self.targeted[label as usize] = true;
        format!("L{label}")
    }
    fn slots(&mut self, frame: usize) -> Vec<String> {
        let wanted = self.frames[frame].branch_values as usize;
        while self.frames[frame].slots.len() < wanted {
            let name = self.temp();
            self.frames[frame].slots.push(name);
        }
        self.frames[frame].slots.clone()
    }
    /// The temporaries a frame's results reach its end in: a loop's own
    /// result slots, any other frame's branch slots.
    fn result_slots(&mut self, frame: usize) -> Vec<String> {
        if self.frames[frame].kind != Kind::Loop {
            return self.slots(frame);
        }
        let wanted = self.frames[frame].results as usize;
        while self.frames[frame].result_slots.len() < wanted {
            let name = self.temp();
            self.frames[frame].result_slots.push(name);
        }
        self.frames[frame].result_slots.clone()
    }
    /// The text of a branch to `frame` carrying `values`, taken when `cond`
    /// holds if there is one. A branch to the function's frame is a return.
    fn branch_text(
        &mut self,
        keyword: &str,
        frame: usize,
        values: &[Expr],
        cond: Option<&str>,
    ) -> String {
        if self.frames[frame].kind == Kind::Function {
            let back = if values.is_empty() {
                "return".to_owned()
            } else {
                format!("return {}", joined(values))
            };
            return match cond {
                Some(cond) => format!("if ({cond}) {back}"),
                None => back,
            };
        }
        let label = self.label_name(frame);
        let slots = self.slots(frame);
        let mut text = format!("{keyword} {label}");
        if let Some(cond) = cond {
            let _ = write!(text, " ({cond})");
        }
        if !values.is_empty() {
            text.push_str(" with ");
            let pairs: Vec<String> = slots
                .iter()
                .zip(values)
                .map(|(slot, value)| format!("{slot} = {}", value.text))
                .collect();
            text.push_str(&pairs.join(", "));
        }
        text
    }
    fn target(&self, depth: u32) -> Option<usize> {
        self.frames.len().checked_sub(depth as usize + 1)
    }
    /// Values reaching a frame's end by falling through are assigned to its
    /// result slots, as a branch out of it would.
    fn assign_slots(&mut self, frame: usize, values: Vec<Expr>) {
        let slots = self.result_slots(frame);
        let extra = values.len().saturating_sub(slots.len());
        let mut values = values.into_iter();
        // More values than slots means an unknown effect upset the stack
        // shape; the extras are still evaluated, never dropped.
        for value in values.by_ref().take(extra) {
            if !value.instrs.is_empty() || !value.stable {
                self.spill_value(value);
            }
        }
        for (slot, value) in slots.into_iter().zip(values) {
            if value.text == slot && value.instrs.is_empty() {
                continue;
            }
            let text = format!("{slot} = {}", value.text);
            let effects = value.effects;
            let calls = value.calls.clone();
            self.spill_before(effects);
            self.push_line(LineKind::Statement, text, value.instrs, &calls);
        }
    }

    fn fallback(&mut self, reason: usize, op: &Operator<'_>, index: u32) {
        self.fallbacks[reason] += 1;
        let text = wasm::instruction(op);
        self.push_line(LineKind::Fallback, text, vec![index], &[]);
    }
    /// An operator the lift does not fold, with its declared stack effect
    /// bound to temporaries on the line: `t9 = <instruction> (t7, t8)`.
    fn fallback_with_effect(
        &mut self,
        reason: usize,
        op: &Operator<'_>,
        index: u32,
        pops: u32,
        pushes: u32,
    ) {
        self.spill_all();
        let inputs = self.pop_n(pops);
        let outputs: Vec<String> = (0..pushes).map(|_| self.temp()).collect();
        let mut text = String::new();
        if !outputs.is_empty() {
            let _ = write!(text, "{} = ", outputs.join(", "));
        }
        text.push_str(&wasm::instruction(op));
        if !inputs.is_empty() {
            let _ = write!(text, " ({})", joined(&inputs));
        }
        self.fallbacks[reason] += 1;
        let mut owned = Vec::new();
        for input in inputs {
            owned.extend(input.instrs);
        }
        owned.push(index);
        self.push_line(LineKind::Fallback, text, owned, &[]);
        for name in outputs {
            self.stack.push(Expr::temp(name));
        }
    }

    fn count(&mut self, what: &'static str) {
        *self.counts.entry(what).or_insert(0) += 1;
    }

    fn open(
        &mut self,
        kind: Kind,
        block_type: BlockType,
        index: u32,
        cond: Option<Expr>,
        extra: String,
    ) -> Result<()> {
        let Some((params, results)) = wasm_stack::block_arity(self.module, block_type) else {
            return Err(Error::protocol(
                "WASM block type names a type this module does not declare",
            ));
        };
        if self.stack.len() < self.base() + params as usize {
            self.unknown_operands += params;
            for _ in 0..params {
                self.stack.push(Expr::unknown());
            }
        }
        // Code inside a frame runs after everything pending outside it, so
        // nothing non-constant crosses the boundary unassigned. The condition
        // of an if was evaluated last, so its line follows these.
        self.spill_all();
        let mut values = self.stack.split_off(self.stack.len() - params as usize);
        // An else or catch arm starts from the same parameters, so they are
        // temporaries even when constant.
        if matches!(kind, Kind::If | Kind::Try) {
            for value in values.iter_mut() {
                if !value.instrs.is_empty() {
                    let taken = std::mem::take(value);
                    *value = self.spill_line(taken);
                }
            }
        }
        let label = self.targeted.len() as u32;
        self.targeted.push(false);
        let mut owned = Vec::new();
        let mut text = match kind {
            Kind::If => {
                let cond = cond.expect("an if condition");
                owned.extend(cond.instrs);
                format!("if ({})", cond.text)
            }
            Kind::Loop => "loop".to_owned(),
            Kind::Try => "try".to_owned(),
            Kind::TryTable => "try_table".to_owned(),
            _ => "block".to_owned(),
        };
        let at = text.len();
        let branch_values = if kind == Kind::Loop { params } else { results };
        let mut slots = Vec::new();
        let mut inner = values.clone();
        if kind == Kind::Loop && params > 0 {
            // A loop's parameters are what a branch back assigns.
            let mut pairs = Vec::new();
            inner.clear();
            for value in &values {
                let slot = self.temp();
                pairs.push(format!("{slot} = {}", value.text));
                inner.push(Expr::temp(slot.clone()));
                slots.push(slot);
            }
            let _ = write!(text, " with {}", pairs.join(", "));
            for value in &values {
                owned.extend(value.instrs.iter().copied());
            }
            values.clear();
        }
        text.push_str(&extra);
        text.push_str(" {");
        owned.push(index);
        let line = self.push_line(LineKind::Open, text, owned, &[]);
        self.lines[line].label = Some((label, at));
        let height = self.stack.len();
        self.frames.push(Frame {
            kind,
            opened: kind,
            height,
            params: values
                .iter()
                .map(|value| Expr::temp(value.text.clone()))
                .collect(),
            label,
            slots,
            branch_values,
            result_slots: Vec::new(),
            results,
            unreachable: false,
            dead: 0,
            open_line: line,
            open_offset: self.starts[index as usize],
        });
        self.labels.push(Label {
            kind: frame_kind(kind),
            block_type,
        });
        self.max_depth = self.max_depth.max(self.frames.len() as u32 - 1);
        self.stack.extend(inner);
        Ok(())
    }

    /// The `else`, `catch` and `catch_all` of the innermost frame.
    fn middle(&mut self, kind: Kind, index: u32, text: String, pushes: u32) {
        let frame = self.frames.len() - 1;
        if !self.frames[frame].unreachable {
            let results = self.frames[frame].results;
            let values = self.pop_n(results);
            self.assign_slots(frame, values);
            self.flush();
        }
        let base = self.base();
        self.stack.truncate(base);
        let params = self.frames[frame].params.clone();
        self.stack.extend(params);
        let outputs: Vec<String> = (0..pushes).map(|_| self.temp()).collect();
        let mut text = text;
        if !outputs.is_empty() {
            let _ = write!(text, " -> {}", outputs.join(", "));
        }
        text.push_str(" {");
        let top = self.top();
        top.kind = kind;
        top.unreachable = false;
        top.dead = 0;
        // The arm's opener reads at the frame's own depth.
        let line = self.push_line(LineKind::Middle, text, vec![index], &[]);
        self.lines[line].depth -= 1;
        if let Some(label) = self.labels.last_mut() {
            label.kind = frame_kind(kind);
        }
        for name in outputs {
            self.stack.push(Expr::temp(name));
        }
    }

    /// The `end` or `delegate` of the innermost frame.
    fn close(&mut self, index: u32, suffix: String) {
        let frame = self.frames.len() - 1;
        let kind = self.frames[frame].kind;
        let opened = self.frames[frame].opened;
        let results = self.frames[frame].results;
        let mut carried = None;
        if !self.frames[frame].unreachable {
            let values = self.pop_n(results);
            if kind == Kind::Function {
                self.flush();
                if !values.is_empty() {
                    let text = format!("return {}", joined(&values));
                    let mut effects = Effects::default();
                    let mut owned = Vec::new();
                    let mut calls = Vec::new();
                    for value in values {
                        effects = effects.union(value.effects);
                        owned.extend(value.instrs);
                        calls.extend(value.calls);
                    }
                    self.spill_before(effects);
                    self.push_line(LineKind::Statement, text, owned, &calls);
                }
            } else if kind == Kind::Block && !self.targeted[self.frames[frame].label as usize] {
                // The only way out is falling through, so the result stays a
                // pending value instead of a temporary. A try_table's result
                // is assigned inside it instead: carried past its end, the
                // value would read as computed outside the protected region.
                self.flush();
                carried = Some(values);
            } else {
                self.assign_slots(frame, values);
                self.flush();
            }
        }
        let mut text = "}".to_owned();
        if kind == Kind::If && results > 0 {
            // No else arm: the false path passes the parameters through.
            let slots = self.slots(frame);
            let params = &self.frames[frame].params;
            let pairs: Vec<String> = slots
                .iter()
                .zip(params)
                .map(|(slot, value)| format!("{slot} = {}", value.text))
                .collect();
            let _ = write!(text, " else {{ {} }}", pairs.join(", "));
        }
        text.push_str(&suffix);
        let slots = if carried.is_none() && kind != Kind::Function {
            self.result_slots(frame)
        } else {
            Vec::new()
        };
        let closing = self.frames.pop().expect("an open frame");
        self.labels.pop();
        self.stack.truncate(closing.height);
        let line = self.push_line(LineKind::Close, text, vec![index], &[]);
        self.closed.push(Closed {
            open_line: closing.open_line,
            close_line: Some(line),
            depth: self.frames.len() as u32,
            kind: opened,
            label: closing.label,
            byte_offset: closing.open_offset,
        });
        if kind == Kind::Function {
            self.ended = true;
            return;
        }
        match carried {
            Some(values) => self.stack.extend(values),
            None => {
                for slot in slots.into_iter().take(results as usize) {
                    self.stack.push(Expr::temp(slot));
                }
            }
        }
    }

    fn unreachable_after(&mut self) {
        let base = self.base();
        self.stack.truncate(base);
        self.top().unreachable = true;
    }

    fn step(&mut self, op: &Operator<'_>, index: u32) -> Result<()> {
        if self.ended {
            return Err(Error::protocol(
                "WASM function has instructions after its end",
            ));
        }
        let run = self.run.take();
        if self.frames.last().is_some_and(|frame| frame.unreachable) {
            let dead = self.frames.last().map_or(0, |frame| frame.dead);
            match op {
                Operator::Block { .. }
                | Operator::Loop { .. }
                | Operator::If { .. }
                | Operator::Try { .. }
                | Operator::TryTable { .. } => {
                    self.fallback(UNREACHABLE_CODE, op, index);
                    self.top().dead += 1;
                    return Ok(());
                }
                Operator::End | Operator::Delegate { .. } if dead > 0 => {
                    self.top().dead -= 1;
                    self.fallback(UNREACHABLE_CODE, op, index);
                    return Ok(());
                }
                Operator::Else | Operator::Catch { .. } | Operator::CatchAll if dead > 0 => {
                    self.top().dead -= 1;
                    self.fallback(UNREACHABLE_CODE, op, index);
                    self.top().dead += 1;
                    return Ok(());
                }
                Operator::Else
                | Operator::Catch { .. }
                | Operator::CatchAll
                | Operator::End
                | Operator::Delegate { .. } => {}
                _ => {
                    self.fallback(UNREACHABLE_CODE, op, index);
                    return Ok(());
                }
            }
        }
        match op {
            Operator::Block { blockty } => {
                // A run of plain openers (a dispatcher's) reads as one line.
                if let Some((line, last)) = run
                    && *blockty == BlockType::Empty
                    && last + 1 == index
                    && self.stack.len() == self.base()
                {
                    let label = self.targeted.len() as u32;
                    self.targeted.push(false);
                    let entry = &mut self.lines[line];
                    entry.owned.push(index);
                    let (first, count) = entry.run.unwrap_or((label - 1, 1));
                    entry.run = Some((first, count + 1));
                    let height = self.stack.len();
                    self.frames.push(Frame {
                        kind: Kind::Block,
                        opened: Kind::Block,
                        height,
                        params: Vec::new(),
                        label,
                        slots: Vec::new(),
                        branch_values: 0,
                        result_slots: Vec::new(),
                        results: 0,
                        unreachable: false,
                        dead: 0,
                        open_line: line,
                        open_offset: self.starts[index as usize],
                    });
                    self.labels.push(Label {
                        kind: FrameKind::Block,
                        block_type: BlockType::Empty,
                    });
                    self.max_depth = self.max_depth.max(self.frames.len() as u32 - 1);
                    self.count("block");
                    self.run = Some((line, index));
                    return Ok(());
                }
                self.count("block");
                self.open(Kind::Block, *blockty, index, None, String::new())?;
                if *blockty == BlockType::Empty {
                    self.run = Some((self.lines.len() - 1, index));
                }
            }
            Operator::Loop { blockty } => {
                self.count("loop");
                self.open(Kind::Loop, *blockty, index, None, String::new())?;
            }
            Operator::If { blockty } => {
                self.count("if");
                let cond = self.pop();
                self.open(Kind::If, *blockty, index, Some(cond), String::new())?;
            }
            Operator::Try { blockty } => {
                self.count("try");
                self.open(Kind::Try, *blockty, index, None, String::new())?;
            }
            Operator::TryTable { try_table } => {
                self.count("try_table");
                // Catch clauses name labels outside this frame and deliver
                // values the lift does not assign, so the opener is counted.
                let mut clauses = Vec::new();
                for catch in &try_table.catches {
                    let (what, label) = match catch {
                        wasmparser::Catch::One { tag, label } => {
                            (format!("catch tag {tag}"), *label)
                        }
                        wasmparser::Catch::OneRef { tag, label } => {
                            (format!("catch_ref tag {tag}"), *label)
                        }
                        wasmparser::Catch::All { label } => ("catch_all".to_owned(), *label),
                        wasmparser::Catch::AllRef { label } => ("catch_all_ref".to_owned(), *label),
                    };
                    let target = match self.target(label) {
                        Some(frame) if self.frames[frame].kind == Kind::Function => {
                            "return".to_owned()
                        }
                        Some(frame) => self.label_name(frame),
                        None => format!("label {label} (out of range)"),
                    };
                    clauses.push(format!("{what} -> {target}"));
                }
                let extra = if clauses.is_empty() {
                    String::new()
                } else {
                    format!(" {}", clauses.join(", "))
                };
                self.open(Kind::TryTable, try_table.ty, index, None, extra)?;
                if !try_table.catches.is_empty() {
                    self.fallbacks[EXCEPTION_HANDLER] += 1;
                    let line = self.frames.last().map_or(0, |frame| frame.open_line);
                    self.lines[line].kind = LineKind::Fallback;
                }
            }
            Operator::Else => {
                if self
                    .frames
                    .last()
                    .is_none_or(|frame| frame.kind != Kind::If)
                {
                    return Err(Error::protocol("WASM else does not match an if"));
                }
                self.count("else");
                self.middle(Kind::Else, index, "} else".to_owned(), 0);
            }
            Operator::Catch { tag_index: tag } => {
                if self
                    .frames
                    .last()
                    .is_none_or(|frame| !matches!(frame.kind, Kind::Try | Kind::Catch))
                {
                    return Err(Error::protocol("WASM catch does not match a try"));
                }
                let pushes = wasm_stack::arity(op, self.module, &self.labels)
                    .map_or(0, |(_, pushes)| pushes);
                self.middle(Kind::Catch, index, format!("}} catch tag {tag}"), pushes);
            }
            Operator::CatchAll => {
                if self
                    .frames
                    .last()
                    .is_none_or(|frame| !matches!(frame.kind, Kind::Try | Kind::Catch))
                {
                    return Err(Error::protocol("WASM catch does not match a try"));
                }
                self.middle(Kind::Catch, index, "} catch_all".to_owned(), 0);
            }
            Operator::End => self.close(index, String::new()),
            Operator::Delegate { relative_depth } => {
                if self
                    .frames
                    .last()
                    .is_none_or(|frame| frame.kind != Kind::Try)
                {
                    return Err(Error::protocol("WASM delegate does not match a try"));
                }
                // The depth counts from the frame around the try.
                let target = self.frames.len().checked_sub(*relative_depth as usize + 2);
                let suffix = match target {
                    Some(frame) if self.frames[frame].kind == Kind::Function => {
                        " delegate caller".to_owned()
                    }
                    Some(frame) => format!(" delegate {}", self.label_name(frame)),
                    None => format!(" delegate label {relative_depth} (out of range)"),
                };
                self.close(index, suffix);
            }
            Operator::Br { relative_depth } => {
                let Some(frame) = self.target(*relative_depth) else {
                    self.fallback(LABEL_OUT_OF_RANGE, op, index);
                    self.unreachable_after();
                    return Ok(());
                };
                let values = self.pop_n(self.frames[frame].branch_values);
                self.flush();
                let text = self.branch_text("br", frame, &values, None);
                self.statement(LineKind::Statement, text, values, index, Effects::default());
                self.unreachable_after();
            }
            Operator::BrIf { relative_depth } => {
                let Some(frame) = self.target(*relative_depth) else {
                    self.fallback(LABEL_OUT_OF_RANGE, op, index);
                    return Ok(());
                };
                let cond = self.pop();
                let count = self.frames[frame].branch_values as usize;
                // Everything pending ran before the branch whether or not it
                // is taken, so a value with an effect (a call, a load, a
                // global, a local write) is assigned first, deepest first.
                // The carried values stay on the stack when the branch is not
                // taken, so they are read twice and become temporaries too.
                // A pure pending value can wait: on the taken path it is
                // discarded unobserved.
                // The condition was evaluated last, so what conflicts with it
                // is assigned too.
                let carried_from = self.stack.len().saturating_sub(count).max(self.base());
                self.spill_forced(cond.effects, |position, entry| {
                    position >= carried_from || entry.effects.impure || entry.effects.writes != 0
                });
                let mut values = self.pop_n(count as u32);
                let text = self.branch_text("br_if", frame, &values, Some(&cond.text));
                let constants: Vec<Expr> = values
                    .iter_mut()
                    .map(|value| Expr {
                        instrs: std::mem::take(&mut value.instrs),
                        ..Default::default()
                    })
                    .collect();
                let mut inputs = vec![cond];
                inputs.extend(constants);
                self.statement(LineKind::Statement, text, inputs, index, Effects::default());
                self.stack.extend(values);
            }
            Operator::BrTable { targets } => self.br_table(targets, index)?,
            Operator::Return => {
                let results = self.frames[0].results;
                let values = self.pop_n(results);
                self.flush();
                let text = if values.is_empty() {
                    "return".to_owned()
                } else {
                    format!("return {}", joined(&values))
                };
                self.statement(LineKind::Statement, text, values, index, Effects::default());
                self.unreachable_after();
            }
            Operator::Unreachable => {
                self.flush();
                self.statement(
                    LineKind::Statement,
                    "unreachable".into(),
                    Vec::new(),
                    index,
                    Effects::default(),
                );
                self.unreachable_after();
            }
            Operator::Nop => {
                self.push_line(LineKind::Statement, "nop".into(), vec![index], &[]);
            }
            Operator::Drop => {
                let value = self.pop();
                let text = format!("drop({})", value.text);
                self.statement(
                    LineKind::Statement,
                    text,
                    vec![value],
                    index,
                    Effects::default(),
                );
            }
            Operator::LocalGet { local_index } => {
                self.stack.push(Expr {
                    text: self.local(*local_index),
                    instrs: vec![index],
                    effects: Effects {
                        reads: local_bit(*local_index),
                        ..Default::default()
                    },
                    ..Default::default()
                });
            }
            Operator::LocalSet { local_index } => {
                let value = self.pop();
                let text = format!("{} = {}", self.local(*local_index), value.text);
                let writes = Effects {
                    writes: local_bit(*local_index),
                    ..Default::default()
                };
                self.statement(LineKind::Statement, text, vec![value], index, writes);
            }
            Operator::LocalTee { local_index } => {
                let value = self.pop();
                let name = self.local(*local_index);
                let writes = Effects {
                    writes: local_bit(*local_index),
                    ..Default::default()
                };
                let folded = self.combine(vec![value], index, writes, true, |values| {
                    format!("{name} = {}", values[0].text)
                });
                self.stack.push(folded);
            }
            Operator::GlobalGet { global_index } => {
                self.stack.push(Expr {
                    text: format!("g{global_index}"),
                    instrs: vec![index],
                    effects: Effects {
                        impure: true,
                        ..Default::default()
                    },
                    ..Default::default()
                });
            }
            Operator::GlobalSet { global_index } => {
                let value = self.pop();
                let text = format!("g{global_index} = {}", value.text);
                let effects = Effects {
                    impure: true,
                    ..Default::default()
                };
                self.statement(LineKind::Statement, text, vec![value], index, effects);
            }
            Operator::I32Const { value } => {
                self.stack.push(Expr::constant(value.to_string(), index));
            }
            Operator::I64Const { value } => {
                self.stack.push(Expr::constant(format!("{value}L"), index));
            }
            Operator::F32Const { value } => {
                self.stack
                    .push(Expr::constant(float32(value.bits()), index));
            }
            Operator::F64Const { value } => {
                self.stack
                    .push(Expr::constant(float64(value.bits()), index));
            }
            Operator::V128Const { value } => {
                let hex: String = value
                    .bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                self.stack
                    .push(Expr::constant(format!("v128(0x{hex})"), index));
            }
            Operator::RefNull { hty } => {
                let text = wasmparser::RefType::new(true, *hty).map_or_else(
                    || format!("ref.null({hty:?})"),
                    |ty| format!("ref.null({ty})"),
                );
                self.stack.push(Expr::constant(text, index));
            }
            Operator::Select | Operator::TypedSelect { .. } => {
                let cond = self.pop();
                let second = self.pop();
                let first = self.pop();
                let folded = self.combine(
                    vec![first, second, cond],
                    index,
                    Effects::default(),
                    false,
                    |values| {
                        format!(
                            "select({}, {}, {})",
                            values[0].text, values[1].text, values[2].text
                        )
                    },
                );
                self.stack.push(folded);
            }
            Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
                let Some((pops, pushes)) = wasm_stack::arity(
                    &Operator::Call {
                        function_index: *function_index,
                    },
                    self.module,
                    &self.labels,
                ) else {
                    self.fallback_unknown(op, index);
                    return Ok(());
                };
                let args = self.pop_n(pops);
                let (name, _) = display_name(self.names, *function_index);
                let impure = Effects {
                    impure: true,
                    ..Default::default()
                };
                let mut call = self.combine(args, index, impure, false, |values| {
                    format!("{name}({})", joined(values))
                });
                call.calls.push(*function_index);
                let tail = matches!(op, Operator::ReturnCall { .. });
                self.push_call(call, pushes, tail);
            }
            Operator::CallIndirect {
                type_index,
                table_index,
            }
            | Operator::ReturnCallIndirect {
                type_index,
                table_index,
            } => {
                let Some((params, pushes)) = self
                    .module
                    .func_type(*type_index)
                    .map(|ty| (ty.params().len() as u32, ty.results().len() as u32))
                else {
                    self.fallback_unknown(op, index);
                    return Ok(());
                };
                let callee = self.pop();
                let mut args = self.pop_n(params);
                args.push(callee);
                let impure = Effects {
                    impure: true,
                    ..Default::default()
                };
                let (type_index, table_index) = (*type_index, *table_index);
                let call = self.combine(args, index, impure, false, |values| {
                    let (callee, args) = values.split_last().expect("a callee");
                    if args.is_empty() {
                        format!(
                            "call_indirect(index {}, type {type_index}, table {table_index})",
                            callee.text
                        )
                    } else {
                        format!(
                            "call_indirect({}; index {}, type {type_index}, table {table_index})",
                            joined(args),
                            callee.text
                        )
                    }
                });
                let tail = matches!(op, Operator::ReturnCallIndirect { .. });
                self.push_call(call, pushes, tail);
            }
            Operator::CallRef { type_index } | Operator::ReturnCallRef { type_index } => {
                let Some((params, pushes)) = self
                    .module
                    .func_type(*type_index)
                    .map(|ty| (ty.params().len() as u32, ty.results().len() as u32))
                else {
                    self.fallback_unknown(op, index);
                    return Ok(());
                };
                let callee = self.pop();
                let mut args = self.pop_n(params);
                args.push(callee);
                let impure = Effects {
                    impure: true,
                    ..Default::default()
                };
                let type_index = *type_index;
                let call = self.combine(args, index, impure, false, |values| {
                    let (callee, args) = values.split_last().expect("a callee");
                    if args.is_empty() {
                        format!("call_ref(ref {}, type {type_index})", callee.text)
                    } else {
                        format!(
                            "call_ref({}; ref {}, type {type_index})",
                            joined(args),
                            callee.text
                        )
                    }
                });
                let tail = matches!(op, Operator::ReturnCallRef { .. });
                self.push_call(call, pushes, tail);
            }
            Operator::Throw { tag_index } => {
                let pops =
                    wasm_stack::arity(op, self.module, &self.labels).map_or(0, |(pops, _)| pops);
                let args = self.pop_n(pops);
                self.flush();
                let text = format!("throw tag {tag_index}({})", joined(&args));
                let impure = Effects {
                    impure: true,
                    ..Default::default()
                };
                self.statement(LineKind::Statement, text, args, index, impure);
                self.unreachable_after();
            }
            Operator::ThrowRef => {
                let value = self.pop();
                self.flush();
                let text = format!("throw_ref({})", value.text);
                self.statement(
                    LineKind::Statement,
                    text,
                    vec![value],
                    index,
                    Effects::default(),
                );
                self.unreachable_after();
            }
            Operator::Rethrow { relative_depth } => {
                self.flush();
                let text = match self.target(*relative_depth) {
                    Some(frame) => format!("rethrow {}", self.label_name(frame)),
                    None => format!("rethrow label {relative_depth} (out of range)"),
                };
                self.statement(
                    LineKind::Statement,
                    text,
                    Vec::new(),
                    index,
                    Effects::default(),
                );
                self.unreachable_after();
            }
            Operator::BrOnNull { relative_depth }
            | Operator::BrOnNonNull { relative_depth }
            | Operator::BrOnCast { relative_depth, .. }
            | Operator::BrOnCastFail { relative_depth, .. } => {
                if let Some(frame) = self.target(*relative_depth) {
                    self.label_name(frame);
                }
                match wasm_stack::arity(op, self.module, &self.labels) {
                    Some((pops, pushes)) => {
                        self.fallback_with_effect(GC_BRANCH, op, index, pops, pushes)
                    }
                    None => {
                        self.fallback_unknown(op, index);
                    }
                }
            }
            Operator::Resume { .. }
            | Operator::ResumeThrow { .. }
            | Operator::Switch { .. }
            | Operator::Suspend { .. } => match wasm_stack::arity(op, self.module, &self.labels) {
                Some((pops, pushes)) => {
                    self.fallback_with_effect(STACK_SWITCHING, op, index, pops, pushes)
                }
                None => {
                    self.fallback_unknown(op, index);
                }
            },
            _ => self.generic(op, index),
        }
        Ok(())
    }

    /// A call's result: a pending value, a statement, temporaries for several
    /// results, or the return of a tail call.
    fn push_call(&mut self, call: Expr, pushes: u32, tail: bool) {
        if tail {
            self.flush();
            let text = format!("return {}", call.text);
            let calls = call.calls.clone();
            self.spill_before(call.effects);
            self.push_line(LineKind::Statement, text, call.instrs, &calls);
            self.unreachable_after();
            return;
        }
        match pushes {
            0 => {
                let calls = call.calls.clone();
                self.spill_before(call.effects);
                self.push_line(LineKind::Statement, call.text, call.instrs, &calls);
            }
            1 => self.stack.push(call),
            _ => self.push_results(call, pushes),
        }
    }
    /// Several results are named on one line: `t4, t5 = f(x)`.
    fn push_results(&mut self, value: Expr, pushes: u32) {
        let outputs: Vec<String> = (0..pushes).map(|_| self.temp()).collect();
        let text = format!("{} = {}", outputs.join(", "), value.text);
        let calls = value.calls.clone();
        self.spill_before(value.effects);
        self.push_line(LineKind::Statement, text, value.instrs, &calls);
        for name in outputs {
            self.stack.push(Expr::temp(name));
        }
    }
    /// An operator with no declared effect leaves its frame's stack shape
    /// unknown: what was pending is assigned first, and later pops read `?`.
    fn fallback_unknown(&mut self, op: &Operator<'_>, index: u32) {
        let offset = self.starts[index as usize];
        self.flush();
        self.fallback(UNKNOWN_EFFECT, op, index);
        let message = format!(
            "The stack effect at byte {offset} is unknown; later operands of its frame may read ?."
        );
        if self.omissions.len() < 8 && !self.omissions.contains(&message) {
            self.omissions.push(message);
        }
    }

    fn br_table(&mut self, targets: &wasmparser::BrTable<'_>, index: u32) -> Result<()> {
        let default = targets.default();
        let Some(default_frame) = self.target(default) else {
            self.fallbacks[LABEL_OUT_OF_RANGE] += 1;
            let text = wasm::instruction(&Operator::BrTable {
                targets: targets.clone(),
            });
            self.flush();
            self.push_line(LineKind::Fallback, text, vec![index], &[]);
            self.unreachable_after();
            return Ok(());
        };
        self.count("br_table");
        let selector = self.pop();
        let count = self.frames[default_frame].branch_values;
        let mut values = self.pop_n(count);
        for value in values.iter_mut() {
            let taken = std::mem::take(value);
            *value = self.spill_value(taken);
        }
        self.flush();
        // Cases are grouped by target in order of first appearance.
        let mut order: Vec<u32> = Vec::new();
        let mut cases: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
        for (case, depth) in targets.targets().enumerate() {
            let depth = depth.map_err(bad)?;
            let runs = cases.entry(depth).or_insert_with(|| {
                order.push(depth);
                Vec::new()
            });
            let case = case as u32;
            match runs.last_mut() {
                Some((_, stop)) if *stop + 1 == case => *stop = case,
                _ => runs.push((case, case)),
            }
        }
        let mut owned = selector.instrs.clone();
        for value in values.iter_mut() {
            owned.append(&mut value.instrs);
        }
        owned.push(index);
        let text = format!("switch ({}) {{", selector.text);
        self.spill_before(selector.effects);
        self.push_line(LineKind::Open, text, owned, &selector.calls);
        for depth in order {
            // One br_table can name tens of thousands of targets, so the line
            // and text budgets are checked per case line, not per instruction.
            if self.over_budget() {
                self.halted = true;
                return Ok(());
            }
            let runs = &cases[&depth];
            let mut label = String::new();
            for (shown, (start, stop)) in runs.iter().enumerate() {
                let piece = if start == stop {
                    start.to_string()
                } else {
                    format!("{start}-{stop}")
                };
                if label.len() + piece.len() + 2 > MAX_CASE_TEXT {
                    let more: u32 = runs[shown..].iter().map(|(a, b)| b - a + 1).sum();
                    let _ = write!(label, ", ... (+{more} cases)");
                    break;
                }
                if !label.is_empty() {
                    label.push_str(", ");
                }
                label.push_str(&piece);
            }
            let (text, kind) = match self.target(depth) {
                Some(frame) => (
                    format!(
                        "case {label}: {}",
                        self.branch_text("br", frame, &values, None)
                    ),
                    LineKind::Case,
                ),
                None => {
                    // Counted as a fallback, so it is a fallback line.
                    self.fallbacks[LABEL_OUT_OF_RANGE] += 1;
                    (
                        format!("case {label}: label {depth} (out of range)"),
                        LineKind::Fallback,
                    )
                }
            };
            self.case_line(text, index, kind);
        }
        if self.over_budget() {
            self.halted = true;
            return Ok(());
        }
        let text = format!(
            "default: {}",
            self.branch_text("br", default_frame, &values, None)
        );
        self.case_line(text, index, LineKind::Case);
        let close = self.push_line(LineKind::Close, "}".into(), Vec::new(), &[]);
        self.lines[close].refs.push(index);
        self.unreachable_after();
        Ok(())
    }
    fn over_budget(&self) -> bool {
        self.lines.len() >= self.budget.lines || self.text_bytes >= self.budget.text_bytes
    }
    fn case_line(&mut self, text: String, index: u32, kind: LineKind) {
        let line = self.push_line(kind, text, Vec::new(), &[]);
        self.lines[line].depth += 1;
        self.lines[line].refs.push(index);
    }

    /// Every other operator folds by its declared effect: infix arithmetic,
    /// typed loads and stores with their offset and alignment, and calls of
    /// the mnemonic for the rest.
    fn generic(&mut self, op: &Operator<'_>, index: u32) {
        let Some((pops, pushes)) = wasm_stack::arity(op, self.module, &self.labels) else {
            self.fallback_unknown(op, index);
            return;
        };
        let mnemonic = wasm::mnemonic(op);
        let mut fields = Vec::new();
        let memarg = immediates(op, &mut fields);
        let mut suffix = String::new();
        if let Some(memarg) = memarg {
            if memarg.offset != 0 {
                let _ = write!(suffix, ", offset {}", memarg.offset);
            }
            if memarg.align != memarg.max_align {
                let _ = write!(suffix, ", align {}", 1u64 << memarg.align.min(63));
            }
            if memarg.memory != 0 {
                let _ = write!(suffix, ", memory {}", memarg.memory);
            }
        }
        for (name, mut value) in fields {
            if matches!(
                name,
                "mem" | "dst_mem" | "src_mem" | "table" | "dst_table" | "src_table"
            ) && value == "0"
            {
                continue;
            }
            clip(&mut value, MAX_IMMEDIATE_TEXT);
            let _ = write!(suffix, ", {name}: {value}");
        }
        let effects = Effects {
            impure: memarg.is_some() || !pure(&mnemonic),
            ..Default::default()
        };
        let args = self.pop_n(pops);
        let (prefix, operation) = mnemonic.split_once('.').unwrap_or((&mnemonic, ""));
        let numeric = matches!(prefix, "i32" | "i64" | "f32" | "f64");
        let float = prefix.starts_with('f');
        if numeric
            && memarg.is_none()
            && pops == 2
            && pushes == 1
            && let Some(symbol) = infix(operation, float)
        {
            let folded = self.combine(args, index, effects, true, |values| {
                format!("{} {symbol} {}", values[0].operand(), values[1].operand())
            });
            self.stack.push(folded);
            return;
        }
        if numeric && operation == "eqz" && pops == 1 {
            let zero = if prefix == "i64" { "0L" } else { "0" };
            let folded = self.combine(args, index, effects, true, |values| {
                format!("{} == {zero}", values[0].operand())
            });
            self.stack.push(folded);
            return;
        }
        if memarg.is_some() && pops == 2 && pushes == 0 {
            // A store reads as an assignment to the typed location.
            let stored = self.combine(args, index, effects, false, |values| {
                format!(
                    "{}({}{suffix}) = {}",
                    mnemonic, values[0].text, values[1].text
                )
            });
            let calls = stored.calls.clone();
            self.spill_before(stored.effects);
            self.push_line(LineKind::Statement, stored.text, stored.instrs, &calls);
            return;
        }
        let folded = self.combine(args, index, effects, false, |values| {
            let mut text = format!("{mnemonic}({}", joined(values));
            let rest = if values.is_empty() {
                suffix.trim_start_matches(", ")
            } else {
                suffix.as_str()
            };
            text.push_str(rest);
            text.push(')');
            text
        });
        match pushes {
            0 => {
                let calls = folded.calls.clone();
                self.spill_before(folded.effects);
                self.push_line(LineKind::Statement, folded.text, folded.instrs, &calls);
            }
            1 => self.stack.push(folded),
            _ => self.push_results(folded, pushes),
        }
    }

    fn finish(mut self, stopped: Option<&'static str>, instruction_count: usize) -> Lift {
        // Frames still open when a limit stopped the lift.
        let open: Vec<Closed> = self
            .frames
            .iter()
            .enumerate()
            .skip(1)
            .map(|(depth, frame)| Closed {
                open_line: frame.open_line,
                close_line: None,
                depth: depth as u32,
                kind: frame.opened,
                label: frame.label,
                byte_offset: frame.open_offset,
            })
            .collect();
        self.closed.extend(open);
        self.closed
            .sort_by_key(|frame| (frame.open_line, frame.depth));
        Lift {
            lines: self.lines,
            starts: self.starts,
            ends: self.ends,
            targeted: self.targeted,
            instruction_count,
            fallbacks: self.fallbacks,
            spills: self.spills,
            unknown_operands: self.unknown_operands,
            clipped_lines: self.clipped_lines,
            closed: self.closed,
            calls: self.calls,
            counts: self.counts,
            max_depth: self.max_depth,
            truncated_instructions: stopped == Some("instructions"),
            truncated_lines: stopped == Some("lines"),
            truncated_deadline: stopped == Some("deadline"),
            work: self.work,
            omissions: self.omissions,
        }
    }
}

/// What one module pass collects for one function.
struct Scan<'a> {
    module: ModuleTypes,
    names: Names,
    body: Option<FunctionBody<'a>>,
    type_index: Option<u32>,
}

fn scan(bytes: &[u8], function: u32) -> Result<Scan<'_>> {
    let mut result = Scan {
        module: ModuleTypes::default(),
        names: Names::default(),
        body: None,
        type_index: None,
    };
    let mut defined = 0u32;
    // The lift reads declared stack effects and assumes the body type
    // checks; a body that does not would read as plausible junk (a branch
    // with no value, a read of a temporary never assigned). So the module's
    // sections and the one function are validated first, and an invalid one
    // gets a named error instead of a listing. Other bodies are not decoded.
    let mut validator = Validator::new_with_features(WasmFeatures::all());
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(bad)?;
        match validator
            .payload(&payload)
            .map_err(|error| Error::protocol(format!("WASM module does not validate: {error}")))?
        {
            ValidPayload::Func(body_validator, body) if body_validator.index == function => {
                body_validator
                    .into_validator(FuncValidatorAllocations::default())
                    .validate(&body)
                    .map_err(|error| {
                        Error::protocol(format!(
                            "WASM function {function} does not validate: {error}"
                        ))
                    })?;
            }
            _ => {}
        }
        match payload {
            Payload::TypeSection(reader) => {
                for group in reader {
                    result.module.add_rec_group(group.map_err(bad)?);
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(bad)?;
                    match import.ty {
                        TypeRef::Func(ty) => {
                            let index = result.module.imported_functions();
                            result.module.add_imported_function(ty);
                            result.names.imports.insert(
                                index,
                                format!("{}.{}", bounded(import.module), bounded(import.name)),
                            );
                        }
                        TypeRef::Tag(tag) => result.module.add_tag(tag.func_type_idx),
                        _ => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    result.module.add_function(ty.map_err(bad)?);
                }
            }
            Payload::TagSection(reader) => {
                for tag in reader {
                    result.module.add_tag(tag.map_err(bad)?.func_type_idx);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(bad)?;
                    if export.kind == ExternalKind::Func {
                        result
                            .names
                            .exports
                            .entry(export.index)
                            .or_insert_with(|| bounded(export.name));
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index = result.module.imported_functions() + defined;
                defined += 1;
                if index == function {
                    result.type_index =
                        Some(result.module.function_type_index(index).ok_or_else(|| {
                            Error::protocol("WASM function declaration is unavailable")
                        })?);
                    result.body = Some(body);
                }
            }
            Payload::CustomSection(reader) => {
                if let KnownCustom::Name(section) = reader.as_known() {
                    for subsection in section {
                        // A name section is advisory; a malformed one never
                        // fails a lift built from the code section.
                        if let Ok(Name::Function(map)) = subsection {
                            for naming in map.into_iter().flatten() {
                                result
                                    .names
                                    .section
                                    .insert(naming.index, bounded(naming.name));
                            }
                        }
                    }
                }
            }
            Payload::End(_) => break,
            _ => {}
        }
    }
    Ok(result)
}

fn lift(
    scan: &Scan<'_>,
    body: &FunctionBody<'_>,
    type_index: u32,
    function: u32,
    deadline: Instant,
    budget: Budget,
) -> Result<(Lift, u32)> {
    let signature = scan.module.func_type(type_index);
    let params = signature.map_or(0, |ty| ty.params().len() as u32);
    let mut lifter = Lifter::new(&scan.module, &scan.names, type_index, params);
    lifter.budget = budget;
    let range = body.range();
    // The header and local declarations are bytes, not instructions.
    let (name, _) = display_name(&scan.names, function);
    let mut header = format!("func {name}(");
    if let Some(ty) = signature {
        let list: Vec<String> = ty
            .params()
            .iter()
            .enumerate()
            .map(|(i, t)| format!("p{i}: {t}"))
            .collect();
        header.push_str(&list.join(", "));
        header.push(')');
        match ty.results() {
            [] => {}
            [one] => {
                let _ = write!(header, " -> {one}");
            }
            many => {
                let list: Vec<String> = many.iter().map(ToString::to_string).collect();
                let _ = write!(header, " -> ({})", list.join(", "));
            }
        }
    } else {
        header.push_str("?)");
    }
    header.push_str(" {");
    let mut locals = body.get_locals_reader().map_err(bad)?;
    let line = lifter.push_line(LineKind::Header, header, Vec::new(), &[]);
    lifter.lines[line].depth = 0;
    lifter.lines[line].span = Some((range.start as u32, locals.original_position() as u32));
    let mut next_local = u64::from(params);
    let mut local_total = 0u64;
    for _ in 0..locals.get_count() {
        let start = locals.original_position() as u32;
        let (count, ty) = locals.read().map_err(bad)?;
        let end = locals.original_position() as u32;
        local_total += u64::from(count);
        if count == 0 {
            continue;
        }
        let first = next_local;
        next_local += u64::from(count);
        let text = match count {
            1 => format!("var l{first}: {ty}"),
            2..=4 => {
                let names: Vec<String> = (first..next_local).map(|i| format!("l{i}")).collect();
                format!("var {}: {ty}", names.join(", "))
            }
            _ => format!("var l{first}..l{}: {ty} ({count} locals)", next_local - 1),
        };
        let line = lifter.push_line(LineKind::Header, text, Vec::new(), &[]);
        lifter.lines[line].span = Some((start, end));
    }
    let mut reader = body.get_operators_reader().map_err(bad)?;
    let mut stopped = None;
    let mut message = None;
    let mut next_check = WORK_CHECK;
    while !reader.eof() {
        if lifter.starts.len() >= budget.instructions {
            stopped = Some("instructions");
            message = Some(format!(
                "Instruction limit of {} reached at byte {}; later instructions are not lifted.",
                budget.instructions,
                reader.original_position()
            ));
            break;
        }
        if lifter.over_budget() {
            stopped = Some("lines");
            message = Some(format!(
                "Line budget reached at byte {}; later instructions are not lifted.",
                reader.original_position()
            ));
            break;
        }
        let checkpoint = lifter.starts.len() & 1023 == 0 || lifter.work >= next_check;
        if checkpoint {
            next_check = lifter.work + WORK_CHECK;
        }
        if checkpoint
            && (Instant::now() > deadline || budget.work.is_some_and(|work| lifter.work > work))
        {
            stopped = Some("deadline");
            message = Some(format!(
                "Lift deadline reached at byte {}; later instructions are not lifted.",
                reader.original_position()
            ));
            break;
        }
        let (op, offset) = reader.read_with_offset().map_err(bad)?;
        let index = lifter.starts.len() as u32;
        lifter.starts.push(offset as u32);
        lifter.ends.push(reader.original_position() as u32);
        lifter.step(&op, index)?;
        if lifter.halted {
            stopped = Some("lines");
            message = Some(format!(
                "Line budget reached inside the instruction at byte {offset}; it and later instructions are not completely lifted."
            ));
            break;
        }
    }
    if stopped.is_none() {
        reader.finish().map_err(bad)?;
        if !lifter.ended {
            return Err(Error::protocol(
                "WASM function control structure is unterminated",
            ));
        }
    }
    let count = lifter.starts.len();
    let mut result = lifter.finish(stopped, count);
    if let Some(message) = message {
        result.omissions.insert(0, message);
    }
    Ok((result, u32::try_from(local_total).unwrap_or(u32::MAX)))
}

/// Byte ranges a line covers: its own instructions and those it names,
/// merged where they touch, and its header span.
fn ranges(lift: &Lift, line: &Line) -> (Vec<[u32; 2]>, bool) {
    let mut indexes: Vec<u32> = line.owned.iter().chain(&line.refs).copied().collect();
    indexes.sort_unstable();
    indexes.dedup();
    let mut out: Vec<[u32; 2]> = Vec::new();
    if let Some((start, end)) = line.span {
        out.push([start, end]);
    }
    for index in indexes {
        let (start, end) = (lift.starts[index as usize], lift.ends[index as usize]);
        match out.last_mut() {
            Some(last) if last[1] == start => last[1] = end,
            _ => out.push([start, end]),
        }
    }
    if out.len() > MAX_LINE_RANGES {
        // One line can own tens of thousands of scattered instructions (a
        // return of many values). The rest become one covering span, which
        // also covers bytes other lines own; `truncation.merged_ranges`
        // counts the lines cut this way.
        let end = out[out.len() - 1][1];
        out.truncate(MAX_LINE_RANGES);
        out[MAX_LINE_RANGES - 1][1] = end;
        return (out, true);
    }
    (out, false)
}

fn rendered(lift: &Lift, line: &Line) -> String {
    let mut text = String::new();
    for _ in 0..line.depth.min(MAX_INDENT) {
        text.push_str("  ");
    }
    if line.depth > MAX_INDENT {
        let _ = write!(text, "[depth {}] ", line.depth);
    }
    let mut body = line.text.clone();
    if let Some((first, count)) = line.run {
        body = format!("block x{count} L{first}..L{} {{", first + count - 1);
    } else if let Some((label, at)) = line.label
        && lift.targeted.get(label as usize).copied().unwrap_or(false)
        && at <= body.len()
    {
        body.insert_str(at, &format!(" L{label}"));
    }
    text.push_str(&body);
    text
}

/// The readable lift of one defined function, one window of lines at a time.
pub fn pseudocode(
    root: &Path,
    id: &str,
    function: u32,
    line_offset: usize,
    line_limit: usize,
) -> Result<String> {
    if line_limit == 0 || line_limit > MAX_LINE_LIMIT {
        return Err(Error::bad(format!(
            "line_limit must be between 1 and {MAX_LINE_LIMIT}"
        )));
    }
    let artifact = wasm_graph::artifact(root, id)?;
    let deadline = Instant::now() + DEADLINE;
    let scan = scan(&artifact.bytes, function)?;
    let imported = scan.module.imported_functions();
    let (Some(body), Some(type_index)) = (scan.body.clone(), scan.type_index) else {
        if function < imported {
            return Err(Error::new(
                404,
                format!("WASM function {function} is imported and has no body in this module"),
            ));
        }
        return Err(Error::new(
            404,
            format!("WASM function {function} is not defined by this module"),
        ));
    };
    let range = body.range();
    if range.len() > wasm_graph::MAX_BODY_BYTES {
        return Err(Error::bad(format!(
            "WASM function {function} is {} bytes, past the {}-byte body limit web engines enforce",
            range.len(),
            wasm_graph::MAX_BODY_BYTES
        )));
    }
    let (lift, locals) = lift(&scan, &body, type_index, function, deadline, BUDGET)?;
    if line_offset > lift.lines.len() {
        return Err(Error::bad("line_offset exceeds the line count"));
    }
    // Ownership is checked, not assumed: a lift is complete only when every
    // decoded instruction is owned by exactly one line.
    let mut owners = vec![0u8; lift.instruction_count];
    for line in &lift.lines {
        for &instruction in &line.owned {
            if let Some(count) = owners.get_mut(instruction as usize) {
                *count = count.saturating_add(1);
            }
        }
    }
    let unowned = owners.iter().filter(|count| **count == 0).count();
    let repeated = owners.iter().filter(|count| **count > 1).count();
    let stopped = lift.truncated_instructions || lift.truncated_lines || lift.truncated_deadline;
    let complete = !stopped && unowned == 0 && repeated == 0;
    let lifted: usize = owners.iter().filter(|count| **count > 0).count();
    let fallback_count: u32 = lift.fallbacks.iter().sum();
    let mut fallbacks = serde_json::Map::new();
    for (name, count) in FALLBACK_REASONS.iter().zip(lift.fallbacks) {
        fallbacks.insert((*name).to_owned(), json!(count));
    }
    let (name, name_source) = display_name(&scan.names, function);
    let signature = scan.module.func_type(type_index);
    let mut nesting = serde_json::Map::new();
    nesting.insert("max_depth".into(), json!(lift.max_depth));
    for kind in [
        "block",
        "loop",
        "if",
        "else",
        "try",
        "try_table",
        "br_table",
    ] {
        nesting.insert(
            kind.into(),
            json!(lift.counts.get(kind).copied().unwrap_or(0)),
        );
    }
    let mut omissions = lift.omissions.clone();
    if !stopped && (unowned > 0 || repeated > 0) {
        omissions.insert(
            0,
            format!(
                "{unowned} instructions are owned by no line and {repeated} by more than one; this lift is not a complete reading."
            ),
        );
    }
    if fallback_count > 0 {
        omissions.push(format!(
            "{fallback_count} instructions are raw fallback lines; fallbacks names why."
        ));
    }
    let limits = json!({
        "max_input_bytes": wasm_graph::MAX_BYTES,
        "max_body_bytes": wasm_graph::MAX_BODY_BYTES,
        "max_instructions": MAX_INSTRUCTIONS,
        "max_lines": MAX_LINES,
        "max_text_bytes": MAX_TEXT_BYTES,
        "max_line_text_bytes": MAX_LINE_TEXT,
        "max_expression_depth": MAX_EXPR_DEPTH,
        "max_line_limit": MAX_LINE_LIMIT,
        "window_bytes": WINDOW_BYTES,
        "max_frames_listed": MAX_FRAMES_LISTED,
        "max_line_ranges": MAX_LINE_RANGES,
        "deadline_ms": DEADLINE.as_millis() as u64,
    });
    let available = line_limit.min(lift.lines.len() - line_offset);
    let mut count = available;
    loop {
        let mut document = json!({
            "schema": "wasm-pseudocode-v1",
            "artifact_id": artifact.artifact_id,
            "sha256": artifact.sha256,
            "byte_size": artifact.bytes.len(),
            "function_index": function,
            "name": name,
            "name_source": name_source,
            "byte_offset": range.start,
            "byte_end": range.end,
            "type_index": type_index,
            "params": signature.map_or(0, |ty| ty.params().len()),
            "results": signature.map_or(0, |ty| ty.results().len()),
            "locals": locals,
            "evidence": "static_lift",
            "status": if complete { "complete" } else { "partial" },
            "instruction_count": lift.instruction_count,
            "lifted_instructions": lifted,
            "unowned_instructions": unowned,
            "repeated_instructions": repeated,
            "line_count": lift.lines.len(),
            "fallback_count": fallback_count,
            "fallbacks": fallbacks,
            "spill_count": lift.spills,
            "unknown_operands": lift.unknown_operands,
            "nesting": nesting,
            "frame_fields": ["open_line", "close_line", "depth", "kind", "label", "byte_offset"],
            "line_kinds": LINE_KINDS,
            "line_fields": ["depth", "kind", "instructions", "ranges"],
            "callee_fields": ["function_index", "name", "name_source"],
            "omissions": omissions,
            "limits": limits,
            "notice": "Static lift of declared stack effects; the module was not executed. A complete lift owns every instruction on exactly one line, and folding keeps the order of calls, memory, globals, tables, traps and local writes. Fallback lines keep the raw instruction text. Names come from the module's name section, exports and imports.",
        });
        let mut merged = 0usize;
        let frames_truncated = window_document(
            &mut merged,
            &mut document,
            &lift,
            &scan.names,
            line_offset,
            count,
        );
        let stop = line_offset + count;
        document["window"] = json!({
            "line_offset": line_offset,
            "line_limit": line_limit,
            "lines": count,
            "next_line_offset": if stop < lift.lines.len() { json!(stop) } else { Value::Null },
        });
        document["truncation"] = json!({
            "instructions": lift.truncated_instructions,
            "lines": lift.truncated_lines,
            "deadline": lift.truncated_deadline,
            "clipped_lines": lift.clipped_lines,
            "window_bytes": count < available,
            "frames": frames_truncated,
            "merged_ranges": merged,
        });
        // The MCP server inlines a result only when both its compact and its
        // pretty form fit, so the window is measured in both.
        let compact = document.to_string();
        let pretty = serde_json::to_string_pretty(&document).map_or(usize::MAX, |text| text.len());
        if count <= 1 || (compact.len() <= WINDOW_BYTES && pretty <= WINDOW_BYTES) {
            return Ok(compact);
        }
        let largest = compact.len().max(pretty);
        count = (count * WINDOW_BYTES / largest).clamp(1, count - 1);
    }
}

/// Fills the window's lines, text, callees and frames into `document`, and
/// says whether frames around the window were left out.
fn window_document(
    merged: &mut usize,
    document: &mut Value,
    lift: &Lift,
    names: &Names,
    line_offset: usize,
    count: usize,
) -> bool {
    let mut text = String::new();
    let mut lines = Vec::with_capacity(count);
    for line in lift.lines.iter().skip(line_offset).take(count) {
        text.push_str(&rendered(lift, line));
        text.push('\n');
        let (covered, cut) = ranges(lift, line);
        if cut {
            *merged += 1;
        }
        lines.push(json!([
            line.depth,
            line.kind as u8,
            line.owned.len(),
            covered
        ]));
    }
    let stop = line_offset + count;
    let window = line_offset..stop;
    let mut callees: Vec<u32> = lift
        .calls
        .iter()
        .filter(|(line, _)| window.contains(&(*line as usize)))
        .map(|(_, function)| *function)
        .collect();
    callees.sort_unstable();
    callees.dedup();
    let callees: Vec<Value> = callees
        .into_iter()
        .map(|index| {
            let (name, source) = display_name(names, index);
            json!([index, name, source])
        })
        .collect();
    let relevant: Vec<&Closed> = lift
        .closed
        .iter()
        .filter(|frame| {
            frame.open_line < stop && frame.close_line.is_none_or(|close| close >= line_offset)
        })
        .collect();
    let frames: Vec<Value> = relevant
        .iter()
        .take(MAX_FRAMES_LISTED)
        .map(|frame| {
            json!([
                frame.open_line,
                frame.close_line,
                frame.depth,
                KIND_NAMES[frame.kind as usize],
                frame.label,
                frame.byte_offset
            ])
        })
        .collect();
    document["lines"] = Value::Array(lines);
    document["text"] = Value::String(text);
    document["callees"] = Value::Array(callees);
    document["frames"] = Value::Array(frames);
    relevant.len() > MAX_FRAMES_LISTED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(bytes: &[u8]) -> tempfile::TempDir {
        use sha2::{Digest, Sha256};
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("blobs")).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        std::fs::write(directory.path().join(format!("blobs/{hash}.bin")), bytes).unwrap();
        let record = json!({"protocol_version":1,"artifact_id":"7","session_id":"1","navigation_id":"1","frame_id":"1",
            "parent_artifact_id":"0","creator_event_id":"0","kind":"wasm","url":"https://example.test/module.wasm",
            "mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        std::fs::write(
            directory.path().join("manifest.jsonl"),
            format!("{record}\n"),
        )
        .unwrap();
        directory
    }
    fn lift_of(wat: &str, function: u32) -> Value {
        let bytes = wat::parse_str(wat).expect("fixture");
        let directory = store(&bytes);
        let text = pseudocode(directory.path(), "7", function, 0, MAX_LINE_LIMIT).unwrap();
        let document: Value = serde_json::from_str(&text).unwrap();
        check_accounting(&document, &bytes);
        document
    }
    /// Every instruction is owned by one line and every range lies inside
    /// the function body.
    fn check_accounting(document: &Value, bytes: &[u8]) {
        let owned: u64 = document["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line[2].as_u64().unwrap())
            .sum();
        if document["status"] == "complete" && document["window"]["next_line_offset"].is_null() {
            assert_eq!(
                owned,
                document["instruction_count"].as_u64().unwrap(),
                "{document}"
            );
        }
        let start = document["byte_offset"].as_u64().unwrap();
        let end = document["byte_end"].as_u64().unwrap();
        assert!(end as usize <= bytes.len());
        for line in document["lines"].as_array().unwrap() {
            for range in line[3].as_array().unwrap() {
                let (a, b) = (range[0].as_u64().unwrap(), range[1].as_u64().unwrap());
                assert!(
                    start <= a && a < b && b <= end,
                    "{range} outside {start}..{end}"
                );
            }
        }
        let text_lines = document["text"].as_str().unwrap().lines().count();
        assert_eq!(text_lines, document["lines"].as_array().unwrap().len());
    }
    fn text(document: &Value) -> Vec<String> {
        document["text"]
            .as_str()
            .unwrap()
            .lines()
            .map(|line| line.trim().to_owned())
            .collect()
    }

    /// Lifts `function` and checks the reading is whole: status complete,
    /// every instruction owned, and every code byte owned by exactly one line.
    /// Returns the trimmed lines.
    fn exact(wat: &str, function: u32) -> Vec<String> {
        let bytes = wat::parse_str(wat).expect("fixture");
        let document = lift_of(wat, function);
        assert_eq!(document["status"], "complete", "{}", document["text"]);
        assert_eq!(document["unowned_instructions"], 0);
        assert_eq!(document["repeated_instructions"], 0);
        assert_bytes_owned_once(&bytes, function);
        text(&document)
    }
    fn internal(
        bytes: &[u8],
        function: u32,
        deadline: Instant,
        budget: Budget,
    ) -> (Lift, usize, usize) {
        let scanned = scan(bytes, function).unwrap();
        let body = scanned.body.clone().unwrap();
        let (lift, _) = lift(
            &scanned,
            &body,
            scanned.type_index.unwrap(),
            function,
            deadline,
            budget,
        )
        .unwrap();
        let mut locals = body.get_locals_reader().unwrap();
        for _ in 0..locals.get_count() {
            locals.read().unwrap();
        }
        (lift, locals.original_position(), body.range().end)
    }
    fn assert_bytes_owned_once(bytes: &[u8], function: u32) {
        let (lift, start, end) = internal(bytes, function, Instant::now() + DEADLINE, BUDGET);
        let mut owners = vec![0u32; end - start];
        for line in &lift.lines {
            for &instruction in &line.owned {
                for byte in lift.starts[instruction as usize]..lift.ends[instruction as usize] {
                    owners[byte as usize - start] += 1;
                }
            }
        }
        let wrong: Vec<usize> = owners
            .iter()
            .enumerate()
            .filter(|(_, count)| **count != 1)
            .map(|(byte, _)| byte + start)
            .collect();
        assert!(wrong.is_empty(), "bytes not owned exactly once: {wrong:?}");
    }

    #[test]
    fn a_loop_result_reaches_its_end_in_its_own_temporary() {
        assert_eq!(
            exact(
                "(module (func (result i32) loop (result i32) i32.const 7 end))",
                0
            ),
            [
                "func f0() -> i32 {",
                "loop {",
                "t0 = 7",
                "}",
                "return t0",
                "}"
            ]
        );
        // Inside an if arm, the loop's result flows on to the if's result.
        assert_eq!(
            exact(
                "(module (func (param i32) (result i32)
                    local.get 0
                    if (result i32) loop (result i32) i32.const 1 end else i32.const 2 end))",
                0
            ),
            [
                "func f0(p0: i32) -> i32 {",
                "if (p0) {",
                "loop {",
                "t0 = 1",
                "}",
                "t1 = t0",
                "} else {",
                "t1 = 2",
                "}",
                "return t1",
                "}"
            ]
        );
        // A br_if out of a loop and the loop's own fallthrough both arrive.
        assert_eq!(
            exact(
                "(module (func (param i32) (result i32)
                    block (result i32)
                      loop (result i32) i32.const 5 local.get 0 br_if 1 drop i32.const 6 end
                    end))",
                0
            ),
            [
                "func f0(p0: i32) -> i32 {",
                "block L1 {",
                "loop {",
                "br_if L1 (p0) with t0 = 5",
                "drop(5)",
                "t1 = 6",
                "}",
                "t0 = t1",
                "}",
                "return t0",
                "}"
            ]
        );
        // A loop's i64 result never lands in its i32 parameter's temporary.
        assert_eq!(
            exact(
                "(module (func (param i32) (result i64)
                    local.get 0 loop (param i32) (result i64) drop i64.const 9 end))",
                0
            ),
            [
                "func f0(p0: i32) -> i64 {",
                "t0 = p0",
                "loop with t1 = t0 {",
                "drop(t1)",
                "t2 = 9L",
                "}",
                "return t2",
                "}"
            ]
        );
    }

    #[test]
    fn effects_pending_at_a_br_if_run_before_it() {
        // f runs whether or not the branch is taken, so it reads first.
        assert_eq!(
            exact(
                "(module (func $f (result i32) i32.const 1) (func $h (param i32))
                  (func (param i32) block call $f local.get 0 br_if 0 call $h end))",
                2
            ),
            [
                "func f2(p0: i32) {",
                "block L1 {",
                "t0 = f()",
                "br_if L1 (p0)",
                "h(t0)",
                "}",
                "}"
            ]
        );
        // A global read and a trapping load stay before the branch, and the
        // lines' first bytes keep the order of the code.
        let wat = "(module (global (mut i32) (i32.const 0)) (memory 1)
            (func (param i32)
              block global.get 0 local.get 0 i32.load local.get 0 br_if 0 i32.add drop end))";
        assert_eq!(
            exact(wat, 0),
            [
                "func f0(p0: i32) {",
                "block L1 {",
                "t0 = g0",
                "t1 = i32.load(p0)",
                "br_if L1 (p0)",
                "drop(t0 + t1)",
                "}",
                "}"
            ]
        );
        let document = lift_of(wat, 0);
        let firsts: Vec<u64> = document["lines"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|line| line[2].as_u64().unwrap() > 0)
            .map(|line| line[3][0][0].as_u64().unwrap())
            .collect();
        assert!(
            firsts.windows(2).all(|pair| pair[0] <= pair[1]),
            "{firsts:?}"
        );
        // A pure pending value may wait: if the branch is taken it is unseen.
        assert_eq!(
            exact(
                "(module (func (param i32) (result i32)
                    block (result i32) local.get 0 i32.const 1 i32.add local.get 0 br_if 0 end))",
                0
            ),
            [
                "func f0(p0: i32) -> i32 {",
                "block L1 {",
                "t0 = p0 + 1",
                "br_if L1 (p0) with t1 = t0",
                "t1 = t0",
                "}",
                "return t1",
                "}"
            ]
        );
    }

    #[test]
    fn a_br_if_never_moves_a_local_read_past_a_write_of_it() {
        // The call's argument writes p0 and must run before the branch; the
        // pending read of the original p0 below it is assigned first.
        assert_eq!(
            exact(
                "(module (func $f (param i32) (result i32) local.get 0)
                  (func (param i32) (result i32) (local i32)
                    block local.get 0 i32.const 3 local.tee 0 call $f i32.const 0 br_if 0
                      i32.add local.set 1 end
                    local.get 1))",
                1
            ),
            [
                "func f1(p0: i32) -> i32 {",
                "var l1: i32",
                "block L1 {",
                "t0 = p0",
                "t1 = f(p0 = 3)",
                "br_if L1 (0)",
                "l1 = t0 + t1",
                "}",
                "return l1",
                "}"
            ]
        );
        // The same for a carried value: the sum reads the parameter, not 9.
        assert_eq!(
            exact(
                "(module (func (param i32) (result i32)
                    block (result i32)
                      local.get 0 i32.const 1 i32.add i32.const 9 local.tee 0 local.get 0 br_if 0
                      i32.add
                    end))",
                0
            ),
            [
                "func f0(p0: i32) -> i32 {",
                "block L1 {",
                "t0 = p0 + 1",
                "t1 = p0 = 9",
                "br_if L1 (p0) with t2 = t1",
                "t2 = t0 + t1",
                "}",
                "return t2",
                "}"
            ]
        );
    }

    #[test]
    fn a_try_table_result_is_assigned_inside_the_protected_region() {
        assert_eq!(
            exact(
                "(module (func $f (result i32) i32.const 1)
                  (func (result i32)
                    block $h
                      try_table (result i32) (catch_all $h) call $f end
                      return
                    end
                    i32.const 0))",
                1
            ),
            [
                "func f1() -> i32 {",
                "block L1 {",
                "try_table catch_all -> L1 {",
                "t0 = f()",
                "}",
                "return t0",
                "}",
                "return 0",
                "}"
            ]
        );
    }

    #[test]
    fn a_load_reads_before_a_later_store() {
        assert_eq!(
            exact(
                "(module (memory 1) (func (param i32) (result i32)
                    local.get 0 i32.load local.get 0 i32.const 5 i32.store))",
                0
            ),
            [
                "func f0(p0: i32) -> i32 {",
                "t0 = i32.load(p0)",
                "i32.store(p0) = 5",
                "return t0",
                "}"
            ]
        );
    }

    #[test]
    fn a_br_table_stops_at_the_line_budget_inside_its_cases() {
        let mut wat = String::from("(module (func (param i32)");
        for _ in 0..60 {
            wat.push_str(" block");
        }
        wat.push_str(" local.get 0 br_table");
        for depth in 0..60 {
            let _ = write!(wat, " {depth}");
        }
        wat.push_str(" 0");
        for _ in 0..60 {
            wat.push_str(" end");
        }
        wat.push_str("))");
        let bytes = wat::parse_str(&wat).unwrap();
        let budget = Budget {
            lines: 20,
            ..BUDGET
        };
        let (lift, _, _) = internal(&bytes, 0, Instant::now() + DEADLINE, budget);
        assert!(lift.lines.len() <= 20, "{} lines", lift.lines.len());
        assert!(lift.truncated_lines);
        assert!(
            lift.omissions[0].contains("inside the instruction"),
            "{:?}",
            lift.omissions
        );
    }

    #[test]
    fn the_deadline_holds_on_a_deep_operand_stack() {
        // Each statement orders itself against every pending value, so on a
        // 100,000-deep stack one statement visits 100,000 of them. Looked at
        // only every 1,024 instructions, a passed deadline would let 512
        // statements, 51 million visits, run past it; it is also looked at
        // every WORK_CHECK visits. The deadline here is work, not time, so
        // the bound holds on a loaded machine.
        let mut wat = String::from("(module (func (param i32) (local i32)");
        for _ in 0..100_000 {
            wat.push_str(" i32.const 1");
        }
        for _ in 0..4_000 {
            wat.push_str(" local.get 0 local.set 1");
        }
        for _ in 0..100_000 {
            wat.push_str(" drop");
        }
        wat.push_str("))");
        let bytes = wat::parse_str(&wat).unwrap();
        let budget = Budget {
            work: Some(1_000_000),
            ..BUDGET
        };
        let (lift, _, _) = internal(
            &bytes,
            0,
            Instant::now() + Duration::from_secs(3600),
            budget,
        );
        assert!(
            lift.truncated_deadline,
            "the lift finished before its deadline"
        );
        assert!(
            lift.work <= 1_000_000 + 65_536 + 2 * 100_001,
            "{} visits past a 1,000,000-visit deadline",
            lift.work - 1_000_000
        );
    }

    #[test]
    fn long_names_keep_their_start_and_end() {
        let stem = "std::__2::basic_string<char, std::__2::char_traits<char>, std::__2::allocator<char>>::__grow_by_and_replace_and_append";
        let wat = format!(
            r#"(module (func (export "{stem}_1")) (func (export "{stem}_2"))
                (func call 0 call 1))"#
        );
        let lines = exact(&wat, 2);
        let calls: Vec<&String> = lines.iter().filter(|line| line.ends_with("()")).collect();
        assert_eq!(calls.len(), 2, "{lines:?}");
        assert_ne!(calls[0], calls[1]);
        assert!(
            calls[0].starts_with("\"std::__2::basic_string") && calls[0].contains("..."),
            "{calls:?}"
        );
        assert!(
            calls[0].ends_with("append_1\"()") && calls[1].ends_with("append_2\"()"),
            "{calls:?}"
        );
        assert!(calls[0].len() <= MAX_NAME_BYTES + 4, "{}", calls[0].len());
    }

    #[test]
    fn an_invalid_body_gets_a_named_error_instead_of_a_listing() {
        // A label past the open frames, a branch missing its value, and a
        // read of an undeclared local would each lift as plausible junk.
        for (wat, expected) in [
            (
                "(module (func (param i32) block local.get 0 br_table 0 7 0 end))",
                "unknown label",
            ),
            (
                "(module (func (result i32) block (result i32) br 0 end))",
                "type mismatch",
            ),
            ("(module (func local.get 3 drop))", "unknown local"),
        ] {
            let bytes = wat::parse_str(wat).unwrap();
            let directory = store(&bytes);
            let error = pseudocode(directory.path(), "7", 0, 0, 10).unwrap_err();
            assert_eq!(error.status, 422, "{wat}");
            assert!(
                error
                    .message
                    .starts_with("WASM function 0 does not validate"),
                "{}",
                error.message
            );
            assert!(error.message.contains(expected), "{}", error.message);
        }
        // A module whose sections do not validate is refused as a module.
        let bytes =
            wat::parse_str("(module (func) (export \"a\" (func 0)) (export \"a\" (func 0)))")
                .unwrap();
        let directory = store(&bytes);
        let error = pseudocode(directory.path(), "7", 0, 0, 10).unwrap_err();
        assert_eq!(error.status, 422);
        assert!(
            error.message.starts_with("WASM module does not validate"),
            "{}",
            error.message
        );
    }

    /// The MCP server inlines a result only when its compact and its pretty
    /// JSON are both at most 131,072 bytes.
    fn assert_pages_fit(bytes: &[u8], function: u32, line_limit: usize) -> usize {
        let directory = store(bytes);
        let mut offset = 0;
        let mut pages = 0;
        let mut seen = 0;
        loop {
            let text = pseudocode(directory.path(), "7", function, offset, line_limit).unwrap();
            let document: Value = serde_json::from_str(&text).unwrap();
            let pretty = serde_json::to_string_pretty(&document).unwrap();
            assert!(
                text.len() <= 131_072 && pretty.len() <= 131_072,
                "page at {offset}: {} compact, {} pretty",
                text.len(),
                pretty.len()
            );
            let lines = document["window"]["lines"].as_u64().unwrap() as usize;
            assert!(lines >= 1);
            seen += lines;
            pages += 1;
            match document["window"]["next_line_offset"].as_u64() {
                Some(next) => {
                    assert_eq!(next as usize, offset + lines, "windows are contiguous");
                    offset = next as usize;
                }
                None => {
                    assert_eq!(seen, document["line_count"].as_u64().unwrap() as usize);
                    return pages;
                }
            }
        }
    }

    #[test]
    fn one_line_with_scattered_bytes_still_fits_a_page() {
        // A return of 1,000 values, each a sum with nops between its terms:
        // the return line owns thousands of instructions that never touch.
        let mut wat = String::from("(module (func (result");
        for _ in 0..1_000 {
            wat.push_str(" i32");
        }
        wat.push(')');
        for _ in 0..1_000 {
            wat.push_str(" i32.const 1");
            for term in 0..12 {
                let _ = write!(wat, " nop i32.const {term} nop i32.add");
            }
        }
        wat.push_str(" return))");
        let bytes = wat::parse_str(&wat).unwrap();
        let directory = store(&bytes);
        let first: Value =
            serde_json::from_str(&pseudocode(directory.path(), "7", 0, 0, 1).unwrap()).unwrap();
        // The return line is the last but one; read the window that ends there.
        let last = first["line_count"].as_u64().unwrap() as usize - 2;
        let text = pseudocode(directory.path(), "7", 0, last, 2).unwrap();
        let document: Value = serde_json::from_str(&text).unwrap();
        let pretty = serde_json::to_string_pretty(&document).unwrap();
        assert!(
            text.len() <= 131_072 && pretty.len() <= 131_072,
            "{} compact, {} pretty",
            text.len(),
            pretty.len()
        );
        assert!(
            document["text"]
                .as_str()
                .unwrap()
                .trim_start()
                .starts_with("return "),
            "{}",
            document["text"]
        );
        assert_eq!(document["truncation"]["merged_ranges"], 1);
        let ranges = document["lines"][0][3].as_array().unwrap();
        assert_eq!(ranges.len(), MAX_LINE_RANGES);
        // The covering span ends where the line's last instruction does.
        let end = ranges[MAX_LINE_RANGES - 1][1].as_u64().unwrap();
        assert!(end <= document["byte_end"].as_u64().unwrap());
    }

    #[test]
    fn every_page_fits_the_inline_limit_compact_and_pretty() {
        // Demangled C++ names, quote-heavy export names, and many calls.
        let mut wat = String::from("(module");
        for index in 0..300 {
            let _ = write!(
                wat,
                r#" (func (export "std::__2::basic_string<char, \"traits\"<char>>::__grow_by_and_replace_{index}") (param i32) (result i32) local.get 0)"#
            );
        }
        wat.push_str(" (func (param i32) (result i32)");
        for index in 0..1_200 {
            let _ = write!(wat, " local.get 0 call {} local.set 0", index % 300);
        }
        wat.push_str(" local.get 0))");
        let bytes = wat::parse_str(&wat).unwrap();
        assert!(assert_pages_fit(&bytes, 300, 400) > 1);
        assert!(assert_pages_fit(&bytes, 300, MAX_LINE_LIMIT) > 1);
        // Plain straight-line code at the largest window: structure alone
        // pretty-prints to several times its compact size.
        let mut wat = String::from("(module (func (param i32)");
        for index in 0..4_000 {
            let _ = write!(wat, " local.get 0 i32.const {index} i32.add local.set 0");
        }
        wat.push_str("))");
        let bytes = wat::parse_str(&wat).unwrap();
        assert!(assert_pages_fit(&bytes, 0, MAX_LINE_LIMIT) > 2);
    }

    /// The folding guarantee, checked on a lift: read in line order, with an
    /// expression's operands before the expression, the instructions with an
    /// effect (calls, memory, globals, tables, traps, throws) and the
    /// branches (if, br, br_if, br_table, return) keep their byte order, and
    /// no access to a local moves across a write to that local.
    fn assert_effect_order(bytes: &[u8], function: u32) {
        let (lift, _, _) = internal(bytes, function, Instant::now() + DEADLINE, BUDGET);
        let scanned = scan(bytes, function).unwrap();
        let body = scanned.body.clone().unwrap();
        let mut reader = body.get_operators_reader().unwrap();
        // Per instruction: an effect, or a local access (index, is a write).
        let mut effect = Vec::new();
        let mut local = Vec::new();
        while !reader.eof() {
            let op = reader.read().unwrap();
            let mut fields = Vec::new();
            let memarg = immediates(&op, &mut fields).is_some();
            let mnemonic = wasm::mnemonic(&op);
            let (is_effect, access) = match op {
                Operator::LocalGet { local_index } => (false, Some((local_index, false))),
                Operator::LocalSet { local_index } | Operator::LocalTee { local_index } => {
                    (false, Some((local_index, true)))
                }
                Operator::GlobalGet { .. } | Operator::GlobalSet { .. } => (true, None),
                Operator::Call { .. }
                | Operator::CallIndirect { .. }
                | Operator::CallRef { .. }
                | Operator::ReturnCall { .. }
                | Operator::ReturnCallIndirect { .. }
                | Operator::Throw { .. }
                | Operator::Unreachable
                // A branch decides whether what follows runs, so nothing
                // with an effect may cross it either way.
                | Operator::If { .. }
                | Operator::Br { .. }
                | Operator::BrIf { .. }
                | Operator::BrTable { .. }
                | Operator::Return => (true, None),
                _ => (
                    memarg
                        || (wasm_stack::arity(&op, &scanned.module, &[])
                            .is_some_and(|(_, pushes)| pushes <= 1)
                            && !pure(&mnemonic)
                            && !matches!(
                                op,
                                Operator::I32Const { .. }
                                    | Operator::I64Const { .. }
                                    | Operator::F32Const { .. }
                                    | Operator::F64Const { .. }
                                    | Operator::Drop
                                    | Operator::Select
                                    | Operator::Nop
                                    | Operator::End
                                    | Operator::Else
                                    | Operator::Block { .. }
                                    | Operator::Loop { .. }
                                    | Operator::If { .. }
                                    | Operator::Br { .. }
                                    | Operator::BrIf { .. }
                                    | Operator::BrTable { .. }
                                    | Operator::Return
                            )),
                    None,
                ),
            };
            effect.push(is_effect);
            local.push(access);
        }
        let order: Vec<u32> = lift
            .lines
            .iter()
            .flat_map(|line| line.owned.iter().copied())
            .collect();
        let effects: Vec<u32> = order
            .iter()
            .copied()
            .filter(|i| effect[*i as usize])
            .collect();
        assert!(
            effects.windows(2).all(|pair| pair[0] < pair[1]),
            "effects out of byte order: {effects:?}"
        );
        let mut by_local: HashMap<u32, Vec<(u32, bool)>> = HashMap::new();
        for &instruction in &order {
            if let Some((index, write)) = local[instruction as usize] {
                by_local
                    .entry(index)
                    .or_default()
                    .push((instruction, write));
            }
        }
        for (index, accesses) in by_local {
            for (a, &(first, first_write)) in accesses.iter().enumerate() {
                for &(second, second_write) in &accesses[a + 1..] {
                    assert!(
                        !(first_write || second_write) || first < second,
                        "local {index}: instruction {second} reads as before {first}"
                    );
                }
            }
        }
    }

    /// Small valid i32 stack programs mixing calls, loads, stores, globals,
    /// locals, trapping division and conditional branches.
    fn generated(seed: u64) -> String {
        let mut state = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut next = move |bound: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % bound
        };
        let mut body = String::new();
        let mut height = 0u32;
        let mut open = 0u32;
        for _ in 0..80 {
            let choice = next(13);
            let op = match choice {
                0 => {
                    height += 1;
                    format!("i32.const {}", next(9))
                }
                1 => {
                    height += 1;
                    format!("local.get {}", next(3))
                }
                2 if height >= 1 => {
                    height -= 1;
                    format!("local.set {}", next(3))
                }
                3 if height >= 1 => format!("local.tee {}", next(3)),
                4 => {
                    height += 1;
                    "global.get 0".into()
                }
                5 if height >= 1 => {
                    height -= 1;
                    "global.set 0".into()
                }
                6 if height >= 1 => "call $f".into(),
                7 => {
                    height += 1;
                    "call $g".into()
                }
                8 if height >= 1 => "i32.load offset=4".into(),
                9 if height >= 2 => {
                    height -= 2;
                    "i32.store".into()
                }
                10 if height >= 2 => {
                    height -= 1;
                    if next(2) == 0 {
                        "i32.add".into()
                    } else {
                        "i32.div_s".into()
                    }
                }
                11 if open < 3 && height == 0 => {
                    open += 1;
                    "block".into()
                }
                12 if open > 0 && height >= 1 => {
                    height -= 1;
                    "br_if 0".into()
                }
                _ if open > 0 && height == 0 => {
                    open -= 1;
                    "end".into()
                }
                _ => {
                    height += 1;
                    "i32.const 3".into()
                }
            };
            body.push(' ');
            body.push_str(&op);
        }
        // Close blocks only at an empty stack, as a block without a result needs.
        for _ in 0..height {
            body.push_str(" drop");
        }
        for _ in 0..open {
            body.push_str(" end");
        }
        format!(
            "(module (memory 1) (global (mut i32) (i32.const 0))
               (func $f (param i32) (result i32) local.get 0) (func $g (result i32) i32.const 1)
               (func (param i32) (local i32 i32) {body}))"
        )
    }

    /// A typed generator of valid modules: i32 programs with nested block,
    /// loop, if/else and try_table frames, br, br_if and br_table at any
    /// depth, return_call, select, tee, memory.grow, a multi-value call and
    /// throw. It tracks the operand stack height per frame and the arity of
    /// each label, so every module it writes validates.
    fn typed(seed: u64) -> String {
        #[derive(Clone, Copy, PartialEq)]
        enum Frame {
            Block,
            Loop,
            If,
            TryTable,
        }
        struct Open {
            kind: Frame,
            base: u32,
            results: u32,
            dead: bool,
        }
        let arity = |open: &Open| {
            if open.kind == Frame::Loop {
                0
            } else {
                open.results
            }
        };
        let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
        let mut next = move |bound: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % bound
        };
        let mut body = String::new();
        let mut emit = |text: &str, body: &mut String| {
            body.push(' ');
            body.push_str(text);
        };
        // Frame 0 is the function, with one i32 result.
        let mut frames = vec![Open {
            kind: Frame::Block,
            base: 0,
            results: 1,
            dead: false,
        }];
        let mut height = 0u32;
        let close = |frames: &mut Vec<Open>,
                     height: &mut u32,
                     body: &mut String,
                     emit: &mut dyn FnMut(&str, &mut String)| {
            let open = frames.pop().unwrap();
            let need = open.base + open.results;
            if !open.dead {
                while *height > need {
                    emit("drop", body);
                    *height -= 1;
                }
                while *height < need {
                    emit("i32.const 1", body);
                    *height += 1;
                }
            }
            if open.kind == Frame::If && open.results == 1 {
                emit("else i32.const 2", body);
            }
            emit("end", body);
            *height = need;
        };
        for _ in 0..20 + next(60) {
            let depth = frames.len();
            let available = height - frames[depth - 1].base;
            match next(30) {
                0 | 1 => {
                    emit(&format!("i32.const {}", next(9)), &mut body);
                    height += 1;
                }
                2..=4 => {
                    emit(&format!("local.get {}", next(3)), &mut body);
                    height += 1;
                }
                5 if available >= 1 => {
                    emit(&format!("local.set {}", next(3)), &mut body);
                    height -= 1;
                }
                6 | 7 if available >= 1 => emit(&format!("local.tee {}", next(3)), &mut body),
                8 => {
                    emit("global.get 0", &mut body);
                    height += 1;
                }
                9 if available >= 1 => {
                    emit("global.set 0", &mut body);
                    height -= 1;
                }
                10 if available >= 1 => emit("call $f", &mut body),
                11 => {
                    emit("call $g", &mut body);
                    height += 1;
                }
                12 if available >= 1 => {
                    emit("call $h", &mut body);
                    height -= 1;
                }
                13 => {
                    emit("call $two", &mut body);
                    height += 2;
                }
                14 if available >= 1 => emit("i32.load offset=4", &mut body),
                15 if available >= 2 => {
                    emit("i32.store", &mut body);
                    height -= 2;
                }
                16 if available >= 2 => {
                    emit(
                        if next(2) == 0 { "i32.add" } else { "i32.div_s" },
                        &mut body,
                    );
                    height -= 1;
                }
                17 if available >= 3 => {
                    emit("select", &mut body);
                    height -= 2;
                }
                18 if available >= 1 => emit("memory.grow", &mut body),
                19 if available >= 1 => {
                    emit("drop", &mut body);
                    height -= 1;
                }
                20 | 21 if depth < 6 => {
                    let results = next(2) as u32;
                    let kind = match next(4) {
                        1 => Frame::Loop,
                        2 if available >= 1 => Frame::If,
                        3 => Frame::TryTable,
                        _ => Frame::Block,
                    };
                    let ty = if results == 1 { " (result i32)" } else { "" };
                    let opener = match kind {
                        Frame::Block => "block",
                        Frame::Loop => "loop",
                        Frame::If => {
                            height -= 1;
                            "if"
                        }
                        Frame::TryTable => "try_table",
                    };
                    emit(&format!("{opener}{ty}"), &mut body);
                    frames.push(Open {
                        kind,
                        base: height,
                        results,
                        dead: false,
                    });
                }
                22 | 23 if available >= 1 => {
                    let label = next(depth as u64) as usize;
                    if available > arity(&frames[depth - 1 - label]) {
                        emit(&format!("br_if {label}"), &mut body);
                        height -= 1;
                    }
                }
                24 if available >= 1 => {
                    let first = next(depth as u64) as usize;
                    let carried = arity(&frames[depth - 1 - first]);
                    if available > carried {
                        let mut labels: Vec<String> = (0..depth)
                            .filter(|label| {
                                arity(&frames[depth - 1 - label]) == carried && next(2) == 0
                            })
                            .map(|label| label.to_string())
                            .collect();
                        labels.push(first.to_string());
                        emit(&format!("br_table {}", labels.join(" ")), &mut body);
                        frames.last_mut().unwrap().dead = true;
                    }
                }
                25 => {
                    let label = next(depth as u64) as usize;
                    if available >= arity(&frames[depth - 1 - label]) {
                        emit(&format!("br {label}"), &mut body);
                        frames.last_mut().unwrap().dead = true;
                    }
                }
                26 if available >= 1 => {
                    emit("return_call $f", &mut body);
                    frames.last_mut().unwrap().dead = true;
                }
                27 if available >= 1 => {
                    emit("throw $e", &mut body);
                    frames.last_mut().unwrap().dead = true;
                }
                28 | 29 if depth > 1 => close(&mut frames, &mut height, &mut body, &mut emit),
                _ => {}
            }
            if frames.last().unwrap().dead {
                if frames.len() == 1 {
                    return typed_module(&body);
                }
                // Code after an unconditional transfer: the frame ends here.
                close(&mut frames, &mut height, &mut body, &mut emit);
            }
        }
        while frames.len() > 1 {
            close(&mut frames, &mut height, &mut body, &mut emit);
        }
        while height > 1 {
            emit("drop", &mut body);
            height -= 1;
        }
        if height == 0 {
            emit("i32.const 0", &mut body);
        }
        typed_module(&body)
    }
    fn typed_module(body: &str) -> String {
        format!(
            r#"(module (memory 1) (global (mut i32) (i32.const 0)) (tag $e (param i32))
              (func $f (param i32) (result i32) local.get 0) (func $g (result i32) i32.const 1)
              (func $h (param i32)) (func $two (result i32 i32) i32.const 1 i32.const 2)
              (func (param i32) (result i32) (local i32 i32) {body}))"#
        )
    }

    #[test]
    fn typed_generated_modules_validate_and_keep_effect_order() {
        for seed in 0..2_000 {
            let wat = typed(seed);
            let bytes = wat::parse_str(&wat).unwrap();
            Validator::new_with_features(WasmFeatures::all())
                .validate_all(&bytes)
                .unwrap_or_else(|error| panic!("seed {seed} does not validate: {error}\n{wat}"));
            let directory = store(&bytes);
            let document: Value = serde_json::from_str(
                &pseudocode(directory.path(), "7", 4, 0, MAX_LINE_LIMIT).unwrap(),
            )
            .unwrap();
            assert_eq!(document["status"], "complete", "seed {seed}\n{wat}");
            assert_eq!(document["unknown_operands"], 0, "seed {seed}\n{wat}");
            let order = std::panic::catch_unwind(|| assert_effect_order(&bytes, 4));
            assert!(
                order.is_ok(),
                "seed {seed}\n{wat}\n{}",
                document["text"].as_str().unwrap()
            );
            assert_bytes_owned_once(&bytes, 4);
        }
    }

    /// Every place that assigns only part of the pending stack, with a
    /// pending value below that conflicts with what it assigns. Each one
    /// orders through spill_before or spill_forced (which add the effects of
    /// what they mark) or assigns the whole frame (flush, spill_all); these
    /// fixtures hold them to the guarantees.
    #[test]
    fn every_partial_assignment_keeps_the_guarantees() {
        let prelude = r#"(module (memory 1) (table 2 funcref) (global (mut i32) (i32.const 0)) (tag $e (param i32))
            (type $t (func (param i32) (result i32)))
            (func $f (param i32) (result i32) local.get 0) (func $g (result i32) i32.const 1)
            (func $h (param i32)) (func $two (result i32 i32) i32.const 1 i32.const 2)"#;
        let sites = [
            // br_if: a forced value writes a local read below it.
            "(func (param i32) (result i32) (local i32)
               block local.get 0 i32.const 3 local.tee 0 call $f i32.const 0 br_if 0 i32.add local.set 1 end local.get 1)",
            "(func (param i32) (result i32)
               block (result i32) local.get 0 i32.const 1 i32.add i32.const 9 local.tee 0 local.get 0 br_if 0 i32.add end)",
            "(func (param i32) (result i32) (local i32)
               block local.get 0 i32.const 0 local.tee 0 br_if 0 local.set 1 end local.get 1)",
            // br and br_table: carried values and the frame below them.
            "(func (param i32) (result i32)
               block (result i32) local.get 0 i32.const 4 local.tee 0 br 0 end local.get 0 i32.add)",
            "(func (param i32) (result i32)
               block (result i32) block (result i32) call $g local.get 0 i32.const 2 local.tee 0 br_table 0 1 1 end end)",
            "(func (param i32) (result i32)
               block $o try_table (catch_all $o)
                 call $g drop local.get 0 i32.const 1 local.tee 0 call $f br_table 0 1 end end local.get 0)",
            // return and tail calls.
            "(func (param i32) (result i32) local.get 0 i32.const 6 local.tee 0 i32.add return)",
            "(func (param i32) (result i32) local.get 0 global.get 0 drop i32.const 1 local.tee 0 i32.add return_call $f)",
            "(func (param i32) (result i32) call $g local.get 0 i32.const 7 local.tee 0 return_call_indirect (type $t))",
            // call_indirect and select operands.
            "(func (param i32) (result i32) local.get 0 i32.const 1 local.tee 0 local.get 0 call_indirect (type $t) i32.add)",
            "(func (param i32) (result i32) call $g global.get 0 local.get 0 i32.load select)",
            "(func (param i32) (result i32) local.get 0 i32.const 2 local.tee 0 local.get 0 select)",
            // if entry: the condition writes a local read below it.
            "(func (param i32) (result i32) local.get 0 i32.const 5 local.tee 0 if (result i32) i32.const 1 else i32.const 2 end i32.add)",
            // try_table entry and end.
            "(func (param i32) (result i32) block $c (result i32) try_table (catch $e $c) local.get 0 call $f throw $e end i32.const 0 end)",
            "(func (param i32) (result i32) local.get 0 try_table (result i32) i32.const 8 local.tee 0 end i32.add)",
            // end: a carried block result and a loop result above a read.
            "(func (param i32) (result i32) local.get 0 block (result i32) i32.const 3 local.tee 0 end i32.add)",
            "(func (param i32) (result i32) local.get 0 loop (result i32) i32.const 3 local.tee 0 end i32.add)",
            "(func (param i32) (result i32) local.get 0 local.get 0 if (result i32) i32.const 1 local.tee 0 else i32.const 2 end i32.add)",
            // memory.grow between loads, and a multi-value call.
            "(func (param i32) (result i32) local.get 0 i32.load i32.const 1 memory.grow local.get 0 i32.load i32.add i32.add)",
            "(func (param i32) (result i32) (local i32 i32) call $two local.set 1 local.set 2 local.get 1 local.get 2 i32.sub)",
        ];
        for body in sites {
            let wat = format!("{prelude} {body})");
            let bytes = wat::parse_str(&wat).unwrap_or_else(|error| panic!("{error}: {body}"));
            Validator::new_with_features(WasmFeatures::all())
                .validate_all(&bytes)
                .unwrap_or_else(|error| panic!("{error}: {body}"));
            let document = lift_of(&wat, 4);
            assert_eq!(document["status"], "complete", "{body}");
            let order = std::panic::catch_unwind(|| assert_effect_order(&bytes, 4));
            assert!(
                order.is_ok(),
                "{body}\n{}",
                document["text"].as_str().unwrap()
            );
            assert_bytes_owned_once(&bytes, 4);
        }
    }

    #[test]
    fn folding_keeps_effect_order_and_owns_every_byte_once() {
        let mut fixtures = vec![
            "(module (func $f (result i32) i32.const 1) (func $h (param i32))
              (func (param i32) block call $f local.get 0 br_if 0 call $h end))"
                .to_owned(),
            "(module (memory 1) (func (param i32) (result i32)
                local.get 0 i32.load local.get 0 i32.const 5 i32.store))"
                .to_owned(),
            "(module (import \"env\" \"f\" (func (result i32))) (global $g (mut i32) (i32.const 0))
                (func (param i32) (result i32)
                  call 0 i32.const 5 global.set $g local.get 0 i32.const 9 local.set 0 i32.add global.get $g i32.add))"
                .to_owned(),
        ];
        // Seeds 445, 1408, 1678, 4160 and 4959 found a br_if that moved a
        // local read past a write, so every seed below 5,000 runs.
        fixtures.extend((0..5_000).map(generated));
        for wat in &fixtures {
            let bytes = wat::parse_str(wat).unwrap_or_else(|error| panic!("{error}: {wat}"));
            let function = scan(&bytes, u32::MAX).unwrap().module.imported_functions() + {
                let mut count = 0u32;
                for payload in Parser::new(0).parse_all(&bytes) {
                    if let Ok(Payload::CodeSectionEntry(_)) = payload {
                        count += 1;
                    }
                }
                count - 1
            };
            assert_effect_order(&bytes, function);
            assert_bytes_owned_once(&bytes, function);
        }
    }

    #[test]
    fn folds_loads_arithmetic_calls_and_names_from_the_module() {
        let document = lift_of(
            r#"(module (import "env" "log" (func (param i32)))
                (memory 1)
                (func $helper (param i32) (result i32) local.get 0)
                (func (export "run") (param i32) (result i32) (local i32 i32)
                  local.get 0 i32.load offset=8 i32.const 1 i32.add local.set 2
                  local.get 2 call $helper call 0
                  local.get 0 local.get 2 i32.store8 offset=3 align=1
                  local.get 2))"#,
            2,
        );
        assert_eq!(document["schema"], "wasm-pseudocode-v1");
        assert_eq!(document["status"], "complete");
        assert_eq!(document["name"], "run");
        assert_eq!(document["name_source"], "export");
        assert_eq!(document["params"], 1);
        assert_eq!(document["locals"], 2);
        assert_eq!(document["fallback_count"], 0);
        let lines = text(&document);
        assert_eq!(lines[0], "func run(p0: i32) -> i32 {");
        assert_eq!(lines[1], "var l1, l2: i32");
        assert!(
            lines.contains(&"l2 = i32.load(p0, offset 8) + 1".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"env.log(helper(l2))".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"i32.store8(p0, offset 3) = l2".to_owned()),
            "{lines:?}"
        );
        assert_eq!(lines.last().unwrap(), "}");
        assert!(lines.contains(&"return l2".to_owned()), "{lines:?}");
        let callees = document["callees"].as_array().unwrap();
        assert!(callees.contains(&json!([0, "env.log", "import"])));
        assert!(callees.contains(&json!([1, "helper", "name_section"])));
        // The folded load line covers the four instructions it came from as
        // one contiguous range.
        let position = lines
            .iter()
            .position(|line| line.starts_with("l2 = i32.load"))
            .unwrap();
        let line = &document["lines"][position];
        assert_eq!(line[2], 5);
        assert_eq!(line[3].as_array().unwrap().len(), 1);
    }

    #[test]
    fn structured_control_reads_as_blocks_with_labels_only_where_targeted() {
        let document = lift_of(
            r#"(module (func (param i32) (result i32) (local i32)
                block $out
                  loop $again
                    local.get 1 i32.const 1 i32.add local.set 1
                    local.get 1 local.get 0 i32.lt_s br_if $again
                    local.get 1 i32.const 100 i32.gt_u br_if $out
                  end
                end
                local.get 0
                if (result i32) i32.const 1 else i32.const 2 end))"#,
            0,
        );
        let lines = text(&document);
        assert!(lines.contains(&"block L1 {".to_owned()), "{lines:?}");
        assert!(lines.contains(&"loop L2 {".to_owned()), "{lines:?}");
        assert!(
            lines.contains(&"br_if L2 (l1 < p0)".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"br_if L1 (l1 >u 100)".to_owned()),
            "{lines:?}"
        );
        assert!(lines.contains(&"if (p0) {".to_owned()), "{lines:?}");
        assert!(lines.contains(&"} else {".to_owned()), "{lines:?}");
        let slot = lines
            .iter()
            .find(|line| line.ends_with(" = 1"))
            .unwrap()
            .clone();
        let name = slot.trim_end_matches(" = 1");
        assert!(lines.contains(&format!("{name} = 2")), "{lines:?}");
        assert!(lines.contains(&format!("return {name}")), "{lines:?}");
        assert_eq!(document["nesting"]["max_depth"], 2);
        assert_eq!(document["nesting"]["loop"], 1);
        let frames = document["frames"].as_array().unwrap();
        assert!(
            frames
                .iter()
                .any(|frame| frame[3] == "loop" && frame[2] == 2)
        );
        // Lines are indented by depth.
        let raw = document["text"].as_str().unwrap();
        assert!(raw.contains("\n    loop L2 {\n"), "{raw}");
    }

    #[test]
    fn br_table_reads_as_a_switch_and_call_indirect_names_type_and_table() {
        let document = lift_of(
            r#"(module (type $t (func (param i32) (result i32))) (table 4 funcref)
                (func (param i32) (result i32)
                  block block block
                    local.get 0 br_table 0 1 1 2 0
                  end i32.const 10 return
                  end i32.const 20 return
                  end
                  i32.const 7 local.get 0 call_indirect (type $t)))"#,
            0,
        );
        let lines = text(&document);
        assert!(lines.contains(&"block x3 L1..L3 {".to_owned()), "{lines:?}");
        assert!(lines.contains(&"switch (p0) {".to_owned()), "{lines:?}");
        assert!(lines.contains(&"case 0: br L3".to_owned()), "{lines:?}");
        assert!(lines.contains(&"case 1-2: br L2".to_owned()), "{lines:?}");
        assert!(lines.contains(&"case 3: br L1".to_owned()), "{lines:?}");
        assert!(lines.contains(&"default: br L3".to_owned()), "{lines:?}");
        assert!(lines.contains(&"return 10".to_owned()), "{lines:?}");
        assert!(
            lines.contains(&"return call_indirect(7; index p0, type 0, table 0)".to_owned()),
            "{lines:?}"
        );
        assert_eq!(document["nesting"]["br_table"], 1);
    }

    #[test]
    fn effects_keep_their_order_through_temporaries() {
        let document = lift_of(
            r#"(module (import "env" "f" (func (result i32))) (global $g (mut i32) (i32.const 0))
                (func (param i32) (result i32)
                  call 0
                  i32.const 5 global.set $g
                  local.get 0
                  i32.const 9 local.set 0
                  i32.add
                  global.get $g
                  i32.add))"#,
            1,
        );
        let lines = text(&document);
        // The call ran before the global was written, and the old p0 was read
        // before p0 was set: both become temporaries first.
        let call = lines
            .iter()
            .position(|line| line.ends_with("= env.f()"))
            .unwrap();
        let global = lines.iter().position(|line| line == "g0 = 5").unwrap();
        let read = lines
            .iter()
            .position(|line| line.ends_with("= p0"))
            .unwrap();
        let write = lines.iter().position(|line| line == "p0 = 9").unwrap();
        assert!(call < global && read < write, "{lines:?}");
        assert!(document["spill_count"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn unreachable_code_and_unmodelled_operators_stay_raw_and_counted() {
        let document = lift_of(
            r#"(module (func (param i32) (result i32)
                block (result i32)
                  local.get 0 br 0
                  i32.const 1 i32.const 2 i32.add drop
                end))"#,
            0,
        );
        let lines = text(&document);
        assert_eq!(document["fallbacks"]["unreachable_code"], 4);
        assert_eq!(document["fallback_count"], 4);
        assert!(
            lines.iter().any(|line| line.starts_with("i32.const")),
            "{lines:?}"
        );
        assert!(
            document["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o.as_str().unwrap().contains("raw fallback"))
        );
        let kinds: Vec<u64> = document["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line[1].as_u64().unwrap())
            .collect();
        assert_eq!(kinds.iter().filter(|kind| **kind == 6).count(), 4);
    }

    #[test]
    fn every_proposal_decodes_to_lines_that_account_for_each_instruction() {
        // Multi-value, SIMD lanes, atomics, bulk memory, reference types,
        // tail calls, exceptions and GC: folded or raw, never dropped.
        let document = lift_of(
            r#"(module
                (type $pair (func (result i32 i64)))
                (type $s (struct (field i32)))
                (memory 1 1 shared) (table 2 funcref) (tag $e (param i32))
                (func $two (type $pair) i32.const 1 i64.const 2)
                (func (param i32 v128) (result i32)
                  (local (ref null $s))
                  call $two drop
                  local.get 1 i32x4.extract_lane 2 drop
                  local.get 1 local.get 1 i8x16.shuffle 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 drop
                  local.get 0 i32.const 1 i32.atomic.rmw.add offset=4 drop
                  local.get 0 i32.const 0 i32.const 4 memory.fill
                  ref.null func drop
                  i32.const 3 struct.new $s local.set 2
                  block $h (result i32)
                    try_table (catch $e $h)
                      local.get 0 throw $e
                    end
                    i32.const 0
                  end
                  drop
                  block $n
                    local.get 2 br_on_null $n drop
                  end
                  local.get 0
                  return_call 2)
                (func (param i32) (result i32) local.get 0))"#,
            1,
        );
        assert_eq!(document["status"], "complete");
        assert_eq!(document["unknown_operands"], 0, "{}", document["text"]);
        let lines = text(&document);
        assert!(
            lines
                .iter()
                .any(|line| line.contains(", ") && line.ends_with("= two()")),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"drop(i32x4.extract_lane(p1, lane: 2))".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("drop(i32.atomic.rmw.add(p0, 1, offset 4))")),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"memory.fill(p0, 0, 4)".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("try_table catch tag 0 -> L")),
            "{lines:?}"
        );
        assert!(lines.contains(&"throw tag 0(p0)".to_owned()), "{lines:?}");
        assert!(lines.contains(&"return f2(p0)".to_owned()), "{lines:?}");
        assert_eq!(document["fallbacks"]["exception_handler"], 1);
        assert_eq!(document["fallbacks"]["gc_branch"], 1);
        assert!(
            lines.contains(&"drop(ref.null(funcref))".to_owned()),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("br_on_null")),
            "{lines:?}"
        );
    }

    #[test]
    fn windows_page_lines_and_limits_are_named() {
        let mut body = String::new();
        for _ in 0..50 {
            body.push_str("local.get 0 i32.const 1 i32.add local.set 0\n");
        }
        let wat = format!("(module (func (param i32) {body}))");
        let bytes = wat::parse_str(&wat).unwrap();
        let directory = store(&bytes);
        let first: Value =
            serde_json::from_str(&pseudocode(directory.path(), "7", 0, 0, 10).unwrap()).unwrap();
        assert_eq!(first["window"]["lines"], 10);
        assert_eq!(first["window"]["next_line_offset"], 10);
        assert_eq!(first["line_count"], 52);
        let last: Value =
            serde_json::from_str(&pseudocode(directory.path(), "7", 0, 50, 10).unwrap()).unwrap();
        assert_eq!(last["window"]["lines"], 2);
        assert!(last["window"]["next_line_offset"].is_null());
        assert_eq!(
            pseudocode(directory.path(), "7", 0, 53, 10)
                .unwrap_err()
                .status,
            400
        );
        assert_eq!(
            pseudocode(directory.path(), "7", 0, 0, 0)
                .unwrap_err()
                .status,
            400
        );
        assert_eq!(
            pseudocode(directory.path(), "7", 0, 0, MAX_LINE_LIMIT + 1)
                .unwrap_err()
                .status,
            400
        );
        assert_eq!(
            pseudocode(directory.path(), "7", 1, 0, 10)
                .unwrap_err()
                .status,
            404
        );
    }

    #[test]
    fn deep_expressions_are_split_and_long_names_quoted() {
        let mut body = String::from("local.get 0");
        for _ in 0..40 {
            body.push_str(" i32.const 3 i32.mul");
        }
        let wat = format!(
            r#"(module (func (export "p1") (param i32) (result i32) {body})
                (func (export "a b\n") (result i32) i32.const 0 call 0))"#
        );
        let document = lift_of(&wat, 0);
        assert_eq!(document["name"], "\"p1\"");
        assert!(document["spill_count"].as_u64().unwrap() >= 3);
        for line in text(&document) {
            assert!(
                line.matches('(').count() <= MAX_EXPR_DEPTH as usize + 2,
                "{line}"
            );
        }
        let caller = lift_of(&wat, 1);
        assert_eq!(caller["name"], "\"a b\\n\"");
        assert!(
            text(&caller).contains(&"return \"p1\"(0)".to_owned()),
            "{:?}",
            text(&caller)
        );
    }

    #[test]
    fn malformed_imported_and_oversized_inputs_get_named_errors() {
        let bytes = wat::parse_str(r#"(module (import "env" "f" (func)) (func nop))"#).unwrap();
        let directory = store(&bytes);
        let imported = pseudocode(directory.path(), "7", 0, 0, 10).unwrap_err();
        assert_eq!(imported.status, 404);
        assert!(imported.message.contains("imported"));
        let mut bad = bytes.clone();
        let last = bad.len() - 1;
        bad[last] = 0x01;
        let directory = store(&bad);
        assert_eq!(
            pseudocode(directory.path(), "7", 1, 0, 10)
                .unwrap_err()
                .status,
            422
        );
        let directory = store(b"\0asm\x01\0\0\0\x0a");
        assert_eq!(
            pseudocode(directory.path(), "7", 0, 0, 10)
                .unwrap_err()
                .status,
            422
        );
    }
}
