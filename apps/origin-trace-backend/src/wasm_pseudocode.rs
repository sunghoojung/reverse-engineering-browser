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
    BlockType, ExternalKind, FrameKind, FunctionBody, KnownCustom, MemArg, Name, Operator, Parser,
    Payload, TypeRef,
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
const MAX_NAME_BYTES: usize = 64;
const MAX_IMMEDIATE_TEXT: usize = 96;
const MAX_CASE_TEXT: usize = 240;
const MAX_FRAMES_LISTED: usize = 256;
pub const DEFAULT_LINE_LIMIT: usize = 400;
pub const MAX_LINE_LIMIT: usize = 2000;
/// One page stays well inside the 128 KiB MCP inline limit.
const WINDOW_BYTES: usize = 96 * 1024;
const DEADLINE: Duration = Duration::from_secs(3);

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
    let mut text = String::from("\"");
    for character in name.chars().flat_map(char::escape_debug) {
        if text.len() + character.len_utf8() > MAX_NAME_BYTES {
            text.push_str("...");
            break;
        }
        text.push(character);
    }
    text.push('"');
    text
}

fn bounded(name: &str) -> String {
    let mut text = String::new();
    for character in name.chars() {
        if text.len() + character.len_utf8() > 2 * MAX_NAME_BYTES {
            break;
        }
        text.push(character);
    }
    text
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
}

/// What the lift of one function produced, before windowing.
struct Lift {
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
        let base = self.base();
        let mut must = vec![false; self.stack.len() - base];
        let mut pending = effects;
        for position in (base..self.stack.len()).rev() {
            let entry = &self.stack[position];
            if !entry.stable && entry.effects.conflicts(pending) {
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
    /// slots, as a branch to it would.
    fn assign_slots(&mut self, frame: usize, values: Vec<Expr>) {
        let slots = self.slots(frame);
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
            } else if matches!(kind, Kind::Block | Kind::TryTable)
                && !self.targeted[self.frames[frame].label as usize]
            {
                // The only way out is falling through, so the result stays a
                // pending value instead of a temporary.
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
            self.slots(frame)
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
                let count = self.frames[frame].branch_values;
                // The values stay on the stack when the branch is not taken,
                // so they are read twice and become temporaries.
                let mut values = self.pop_n(count);
                for value in values.iter_mut() {
                    let taken = std::mem::take(value);
                    *value = self.spill_value(taken);
                }
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
            let text = match self.target(depth) {
                Some(frame) => format!(
                    "case {label}: {}",
                    self.branch_text("br", frame, &values, None)
                ),
                None => {
                    self.fallbacks[LABEL_OUT_OF_RANGE] += 1;
                    format!("case {label}: label {depth} (out of range)")
                }
            };
            self.case_line(text, index);
        }
        let text = format!(
            "default: {}",
            self.branch_text("br", default_frame, &values, None)
        );
        self.case_line(text, index);
        let close = self.push_line(LineKind::Close, "}".into(), Vec::new(), &[]);
        self.lines[close].refs.push(index);
        self.unreachable_after();
        Ok(())
    }
    fn case_line(&mut self, text: String, index: u32) {
        let line = self.push_line(LineKind::Case, text, Vec::new(), &[]);
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
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(bad)? {
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
) -> Result<(Lift, u32)> {
    let signature = scan.module.func_type(type_index);
    let params = signature.map_or(0, |ty| ty.params().len() as u32);
    let mut lifter = Lifter::new(&scan.module, &scan.names, type_index, params);
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
    while !reader.eof() {
        if lifter.starts.len() >= MAX_INSTRUCTIONS {
            stopped = Some("instructions");
            message = Some(format!(
                "Instruction limit of {MAX_INSTRUCTIONS} reached at byte {}; later instructions are not lifted.",
                reader.original_position()
            ));
            break;
        }
        if lifter.lines.len() >= MAX_LINES || lifter.text_bytes >= MAX_TEXT_BYTES {
            stopped = Some("lines");
            message = Some(format!(
                "Line budget reached at byte {}; later instructions are not lifted.",
                reader.original_position()
            ));
            break;
        }
        if lifter.starts.len() & 1023 == 0 && Instant::now() > deadline {
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
fn ranges(lift: &Lift, line: &Line) -> Vec<[u32; 2]> {
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
    out
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
    let (lift, locals) = lift(&scan, &body, type_index, function, deadline)?;
    if line_offset > lift.lines.len() {
        return Err(Error::bad("line_offset exceeds the line count"));
    }
    let mut text = String::new();
    let mut lines = Vec::new();
    let mut bytes = 0usize;
    let mut stop = line_offset;
    for line in lift.lines.iter().skip(line_offset).take(line_limit) {
        let shown = rendered(&lift, line);
        let covered = ranges(&lift, line);
        let size = shown.len() + 24 + covered.len() * 24;
        if !lines.is_empty() && bytes + size > WINDOW_BYTES {
            break;
        }
        bytes += size;
        text.push_str(&shown);
        text.push('\n');
        lines.push(json!([
            line.depth,
            line.kind as u8,
            line.owned.len(),
            covered
        ]));
        stop += 1;
    }
    let window_bytes_reached = stop < (line_offset + line_limit).min(lift.lines.len());
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
            let (name, source) = display_name(&scan.names, index);
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
    let frames_truncated = relevant.len() > MAX_FRAMES_LISTED;
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
    let lifted: usize = lift.lines.iter().map(|line| line.owned.len()).sum();
    let fallback_count: u32 = lift.fallbacks.iter().sum();
    let mut fallbacks = serde_json::Map::new();
    for (name, count) in FALLBACK_REASONS.iter().zip(lift.fallbacks) {
        fallbacks.insert((*name).to_owned(), json!(count));
    }
    let complete =
        !(lift.truncated_instructions || lift.truncated_lines || lift.truncated_deadline);
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
    if fallback_count > 0 {
        omissions.push(format!(
            "{fallback_count} instructions are raw fallback lines; fallbacks names why."
        ));
    }
    let window_value = json!({
        "line_offset": line_offset,
        "line_limit": line_limit,
        "lines": stop - line_offset,
        "next_line_offset": if stop < lift.lines.len() { json!(stop) } else { Value::Null },
    });
    let truncation = json!({
        "instructions": lift.truncated_instructions,
        "lines": lift.truncated_lines,
        "deadline": lift.truncated_deadline,
        "clipped_lines": lift.clipped_lines,
        "window_bytes": window_bytes_reached,
        "frames": frames_truncated,
    });
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
        "deadline_ms": DEADLINE.as_millis() as u64,
    });
    let document = json!({
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
        "line_count": lift.lines.len(),
        "fallback_count": fallback_count,
        "fallbacks": fallbacks,
        "spill_count": lift.spills,
        "unknown_operands": lift.unknown_operands,
        "nesting": nesting,
        "frame_fields": ["open_line", "close_line", "depth", "kind", "label", "byte_offset"],
        "frames": frames,
        "line_kinds": LINE_KINDS,
        "line_fields": ["depth", "kind", "instructions", "ranges"],
        "lines": lines,
        "text": text,
        "callee_fields": ["function_index", "name", "name_source"],
        "callees": callees,
        "window": window_value,
        "truncation": truncation,
        "omissions": omissions,
        "limits": limits,
        "notice": "Static lift of declared stack effects; the module was not executed. Every instruction is owned by one line, and fallback lines keep the raw instruction text. Names come from the module's name section, exports and imports.",
    });
    Ok(document.to_string())
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
