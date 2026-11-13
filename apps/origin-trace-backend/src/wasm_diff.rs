//! Function matching between two captured Wasm modules.
//!
//! Each function gets two fingerprints computed from its declared body: a
//! normalized body hash that survives renumbering, and a coarser structural
//! fingerprint. Matching then runs in a fixed order (byte-identical,
//! normalized-identical, import and export names, call-graph propagation,
//! structural similarity) and never forces a one-to-one pick between tied
//! candidates. Every result is a correspondence hypothesis with its method and
//! score, keyed by each side's module SHA-256 and function index. Nothing here
//! executes either module, and no instruction text or constant value leaves
//! this module: the report is structure only.
//!
//! One budget bounds all of the work: a deadline checked inside every body
//! and every loop that can grow with the module, and a cap on similarity
//! scores. A step the budget stops leaves its functions unclassified rather
//! than guessed.
use crate::{
    error::{Error, Result},
    evidence, validation, wasm,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use wasmparser::{
    BlockType, CompositeInnerType, DataKind, Encoding, ExternalKind, FunctionBody, KnownCustom,
    MemArg, Name, Operator, Parser, Payload, TypeRef, ValType,
};

/// Bumped whenever a normalization rule, a structural input or the decoder
/// spelling a fingerprint depends on changes, so a stored fingerprint is never
/// compared with one computed under different rules.
pub const FINGERPRINT_VERSION: u32 = 1;
/// The same per-module input limit as the block graph.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Imports plus defined functions fingerprinted per module. Large Unity and
/// Emscripten builds stay under it; a larger module is compared on a prefix.
const MAX_FUNCTIONS: usize = 262_144;
/// Web engines reject a body above this size, so a longer one cannot have run.
const MAX_BODY_BYTES: usize = 7_654_321;
/// Web engines reject a function with more locals than this.
const MAX_LOCALS: usize = 50_000;
/// Similarity scores computed by propagation and the structural pass together.
const MAX_COMPARISONS: u64 = 4_000_000;
/// Nearest-size candidates scored for one function in the structural pass.
/// Fewer are scored when the comparisons left, shared by every open function,
/// cannot pay for this many, so the pass can still finish.
const MAX_CANDIDATES: usize = 64;
/// Below this many candidates each, a mutual best says too little, and the
/// pass is not run.
const MIN_CANDIDATES: usize = 4;
/// Open callees or callers of a matched pair compared with each other. A hub
/// called from more places proposes nothing, so one function called from
/// everywhere cannot make propagation quadratic.
const MAX_NEIGHBOURHOOD: usize = 64;
/// Rounds of exact matching between propagation steps: a later round only
/// resolves ties whose other members propagation matched meanwhile.
const MAX_EXACT_ROUNDS: usize = 4;
/// Instructions decoded between two deadline checks inside one body.
const CHECK_EVERY: u32 = 4096;
/// Fingerprinting and matching share one deadline. It sits under the native
/// helper's five-second process limit so a report, partial or not, arrives.
const DEADLINE: Duration = Duration::from_secs(4);
const SIMILARITY_THRESHOLD: f64 = 0.75;
/// A propagated match must still look like the function it claims to be.
const PROPAGATION_FLOOR: f64 = 0.5;
/// Two candidates whose scores differ by less than this are a tie.
const TIE_MARGIN: f64 = 0.01;
/// Constants and memory offsets below this are kept even inside the static
/// data span: small integers are far more often counts and flags than
/// addresses, and common toolchains place static data at or above 1,024.
const MIN_ADDRESS: u64 = 1024;
const MAX_NAME_BYTES: usize = 128;
const MAX_TYPE_TEXT: usize = 256;
pub const PAGE_MAX_ROWS: usize = 1000;
pub const PAGE_DEFAULT_ROWS: usize = 200;
/// A page's whole document, pretty-printed as the MCP server measures it,
/// stays below this, which leaves room under the 131,072-byte inline limit.
const PAGE_BYTES: usize = 122_880;
/// The MCP server's inline limit, which a page must stay under.
const _: () = assert!(PAGE_BYTES < 131_072);
/// Reports kept so paging a comparison does not repeat it.
const CACHED_REPORTS: usize = 2;
const NONE: u32 = u32::MAX;

/// Row statuses in page order: what changed first, then what stayed.
const STATUSES: [&str; 7] = [
    "changed",
    "added",
    "removed",
    "ambiguous",
    "unclassified",
    "renumbered",
    "identical",
];
const CHANGED: u8 = 0;
const ADDED: u8 = 1;
const REMOVED: u8 = 2;
const AMBIGUOUS: u8 = 3;
const UNCLASSIFIED: u8 = 4;
const RENUMBERED: u8 = 5;
const IDENTICAL: u8 = 6;

const METHODS: [&str; 7] = [
    "identical",
    "normalized",
    "import_name",
    "export_name",
    "name",
    "call_graph",
    "structural",
];
const BY_BYTES: u8 = 0;
const BY_NORMALIZED: u8 = 1;
const BY_IMPORT: u8 = 2;
const BY_EXPORT: u8 = 3;
const BY_NAME: u8 = 4;
const BY_CALL_GRAPH: u8 = 5;
const BY_STRUCTURE: u8 = 6;

/// Opcode classes for the histogram, in the order the contract lists them.
const CATEGORIES: usize = 17;

/// Steps the budget can stop, named in omissions and in test hooks.
const FINGERPRINTING: &str = "fingerprinting";
const EXACT: &str = "exact matching";
const PROPAGATION: &str = "call-graph propagation";
const STRUCTURAL: &str = "structural matching";
const PARSING: &str = "section parsing";

fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

/// FNV-1a: a fixed, documented hash for the small structural inputs, so a
/// fingerprint does not depend on a hasher's per-process seed.
fn fnv(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn first8(digest: &[u8]) -> u64 {
    u64::from_be_bytes(digest[..8].try_into().expect("digest prefix"))
}

/// A name stays one inert line of bounded text, whatever the module supplied.
fn bounded(name: &str) -> String {
    let mut text = String::new();
    for character in name.chars().flat_map(char::escape_debug) {
        if text.len() + character.len_utf8() > MAX_NAME_BYTES {
            text.push_str("...");
            break;
        }
        text.push(character);
    }
    text
}

/// The work limits. Production uses [`Limits::DEFAULT`]; tests shrink them,
/// or name a step whose next check stops, so every truncation path is covered
/// without depending on how fast the machine is.
#[derive(Clone, Copy)]
struct Limits {
    deadline: Duration,
    max_comparisons: u64,
    max_functions: usize,
    /// Stops `step` at its check after this many of its own checks passed.
    stop_in: Option<(&'static str, u64)>,
    /// Stops at the check after this many, wherever it falls.
    stop_after_checks: Option<u64>,
}

impl Limits {
    const DEFAULT: Self = Self {
        deadline: DEADLINE,
        max_comparisons: MAX_COMPARISONS,
        max_functions: MAX_FUNCTIONS,
        stop_in: None,
        stop_after_checks: None,
    };
}

/// The shared budget. Once a check fails it stays failed, and `stopped` says
/// which step stopped and why.
struct Budget {
    started: Instant,
    limits: Limits,
    comparisons: u64,
    checks: u64,
    /// Checks made by the step `limits.stop_in` names.
    step_checks: u64,
    stopped: Option<(&'static str, &'static str)>,
}

impl Budget {
    fn new(limits: Limits, started: Instant) -> Self {
        Self {
            started,
            limits,
            comparisons: 0,
            checks: 0,
            step_checks: 0,
            stopped: None,
        }
    }
    /// Whether `step` must stop now.
    fn late(&mut self, step: &'static str) -> bool {
        self.checks += 1;
        let named = self.limits.stop_in.filter(|(name, _)| *name == step);
        if named.is_some() {
            self.step_checks += 1;
        }
        if self.stopped.is_none() {
            if named.is_some_and(|(_, after)| self.step_checks > after)
                || self
                    .limits
                    .stop_after_checks
                    .is_some_and(|n| self.checks > n)
            {
                self.stopped = Some((step, "test stop"));
            } else if self.started.elapsed() > self.limits.deadline {
                self.stopped = Some((step, "deadline"));
            }
        }
        self.stopped.is_some()
    }
    /// Takes one similarity score from the cap; false once the cap is spent.
    fn score(&mut self, step: &'static str) -> bool {
        if self.stopped.is_some() {
            return false;
        }
        if self.comparisons >= self.limits.max_comparisons {
            self.stopped = Some((step, "comparison limit"));
            return false;
        }
        self.comparisons += 1;
        true
    }
}

macro_rules! memarg_field {
    (memarg, $value:ident) => {
        return Some(*$value)
    };
    ($other:ident, $value:ident) => {};
}
macro_rules! memarg_of {
    ($(@$proposal:ident $op:ident $({ $($field:ident: $ty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
        /// The memory immediate of any load, store or atomic access.
        #[allow(unused_variables, unreachable_code)]
        fn memarg_of(op: &Operator<'_>) -> Option<MemArg> {
            match op {
                $(Operator::$op $( { $($field),* } )? => { $($( memarg_field!($field, $field); )*)? None })*
                _ => None,
            }
        }
    };
}
wasmparser::for_each_operator!(memarg_of);

/// Spellings that make a mnemonic a comparison: as its end (`i32_eq`) or
/// followed by a signedness suffix (`i32_lt_s`).
const COMPARE_ENDS: [&str; 7] = ["eqz", "_eq", "_ne", "_lt", "_gt", "_le", "_ge"];
const COMPARE_INFIXES: [&str; 7] = ["eqz_", "_eq_", "_ne_", "_lt_", "_gt_", "_le_", "_ge_"];
const CONVERSIONS: [&str; 7] = [
    "convert",
    "trunc",
    "extend",
    "wrap",
    "demote",
    "promote",
    "reinterpret",
];
const SIMD_PREFIXES: [&str; 7] = ["v128", "i8x16", "i16x8", "i32x4", "i64x2", "f32x4", "f64x2"];

/// The histogram class of one operator (see `CATEGORIES`). It allocates
/// nothing: it runs once per instruction.
fn category(op: &Operator<'_>, name: &str) -> usize {
    match op {
        Operator::Block { .. }
        | Operator::Loop { .. }
        | Operator::If { .. }
        | Operator::Else
        | Operator::End
        | Operator::Try { .. }
        | Operator::TryTable { .. }
        | Operator::Catch { .. }
        | Operator::CatchAll
        | Operator::Delegate { .. } => 0,
        Operator::Br { .. }
        | Operator::BrIf { .. }
        | Operator::BrTable { .. }
        | Operator::Return
        | Operator::Throw { .. }
        | Operator::ThrowRef
        | Operator::Rethrow { .. } => 1,
        Operator::Call { .. }
        | Operator::ReturnCall { .. }
        | Operator::CallRef { .. }
        | Operator::ReturnCallRef { .. } => 2,
        Operator::CallIndirect { .. } | Operator::ReturnCallIndirect { .. } => 3,
        Operator::LocalGet { .. } | Operator::LocalSet { .. } | Operator::LocalTee { .. } => 4,
        Operator::GlobalGet { .. } | Operator::GlobalSet { .. } => 5,
        Operator::I32Const { .. }
        | Operator::I64Const { .. }
        | Operator::F32Const { .. }
        | Operator::F64Const { .. } => 8,
        Operator::Drop
        | Operator::Select
        | Operator::TypedSelect { .. }
        | Operator::Nop
        | Operator::Unreachable => 16,
        _ => {
            let name = name.trim_start_matches("visit_");
            if name.contains("atomic") {
                14
            } else if SIMD_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
                13
            } else if name.contains("load") {
                6
            } else if name.contains("store") {
                7
            } else if name.starts_with("br_on") {
                1
            } else if CONVERSIONS.iter().any(|part| name.contains(part)) {
                12
            } else if COMPARE_ENDS.iter().any(|end| name.ends_with(end))
                || COMPARE_INFIXES.iter().any(|infix| name.contains(infix))
            {
                11
            } else if name.starts_with("i32") || name.starts_with("i64") {
                9
            } else if name.starts_with("f32") || name.starts_with("f64") {
                10
            } else {
                15
            }
        }
    }
}

/// Structure that survives renaming and renumbering, used for the coarse
/// fingerprint and for similarity scores.
#[derive(Clone, Default)]
struct Shape {
    histogram: [u32; CATEGORIES],
    instructions: u32,
    blocks: u32,
    loops: u32,
    branches: u32,
    calls: u32,
    callees: u32,
    skeleton: u64,
}

fn ratio(a: u32, b: u32) -> f64 {
    if a == b {
        1.0
    } else {
        f64::from(a.min(b)) / f64::from(a.max(b))
    }
}

/// A score in [0, 1]: weighted histogram overlap, size, control shape, calls,
/// and whether the control skeletons are identical. The weights are part of
/// fingerprint version 1.
fn similarity(x: &Shape, y: &Shape) -> f64 {
    let (mut low, mut high) = (0u64, 0u64);
    for (a, b) in x.histogram.iter().zip(&y.histogram) {
        low += u64::from(*a.min(b));
        high += u64::from(*a.max(b));
    }
    let histogram = if high == 0 {
        1.0
    } else {
        low as f64 / high as f64
    };
    let control =
        (ratio(x.blocks, y.blocks) + ratio(x.loops, y.loops) + ratio(x.branches, y.branches)) / 3.0;
    let calls = (ratio(x.calls, y.calls) + ratio(x.callees, y.callees)) / 2.0;
    let skeleton = if x.skeleton == y.skeleton { 1.0 } else { 0.0 };
    0.45 * histogram
        + 0.15 * ratio(x.instructions, y.instructions)
        + 0.2 * control
        + 0.1 * calls
        + 0.1 * skeleton
}

/// An import's identity: its names, and its position among the imports that
/// share them, so a module that imports `env.f` twice still pairs each one.
#[derive(Clone)]
struct Import {
    module: String,
    name: String,
    /// Position among imports with the same names and signature.
    same_signature: u32,
    /// Position among imports with the same names.
    same_name: u32,
}

struct Func {
    index: u32,
    import: Option<Import>,
    start: usize,
    end: usize,
    ty: u32,
    signature: u64,
    export: Option<String>,
    section_name: Option<String>,
    body: [u8; 16],
    normalized: u64,
    /// Where each static data address points, as data segment and offset in
    /// it, so a relocation can be told from a changed constant.
    addresses: u64,
    structure: u64,
    shape: Shape,
    /// Direct call targets in call-site order.
    calls: Vec<u32>,
    /// The same targets, sorted and distinct.
    callees: Vec<u32>,
}

struct Module {
    imported: u32,
    defined: u32,
    funcs: Vec<Func>,
    callers: Vec<Vec<u32>>,
    type_text: Vec<String>,
    /// Functions past a limit or the deadline that were never fingerprinted.
    truncated: bool,
}

impl Module {
    fn declared(&self) -> usize {
        self.imported as usize + self.defined as usize
    }
}

struct Context<'a> {
    bytes: &'a [u8],
    func_types: &'a [u32],
    signatures: &'a [u64],
    params: &'a [Vec<ValType>],
    globals: &'a [u64],
    span: Option<(u64, u64)>,
    /// Active data segments of memory 0 with a constant offset, by start.
    segments: &'a [(u64, u64)],
}
impl Context<'_> {
    fn signature_of_type(&self, ty: u32) -> u64 {
        self.signatures.get(ty as usize).copied().unwrap_or(0)
    }
    fn signature_of_function(&self, index: u32) -> u64 {
        self.func_types
            .get(index as usize)
            .map_or(0, |ty| self.signature_of_type(*ty))
    }
    fn address(&self, value: u64) -> bool {
        value >= MIN_ADDRESS
            && self
                .span
                .is_some_and(|(low, high)| value >= low && value < high)
    }
    /// The segment ordinal and offset of an address, or the offset from the
    /// span start, marked, when it falls between segments.
    fn located(&self, value: u64) -> (u64, u64) {
        let after = self.segments.partition_point(|(start, _)| *start <= value);
        if after > 0 {
            let (start, end) = self.segments[after - 1];
            if value < end {
                return ((after - 1) as u64, value - start);
            }
        }
        let low = self.span.map_or(0, |(low, _)| low);
        (u64::MAX, value - low)
    }
    fn block(&self, ty: BlockType) -> u64 {
        match ty {
            BlockType::Empty => 0,
            BlockType::Type(value) => fnv(value.to_string().as_bytes()),
            BlockType::FuncType(index) => self.signature_of_type(index),
        }
    }
}

/// Scratch buffers reused across functions so a body costs no allocation per
/// instruction. The id tables are sized to the module's locals and globals
/// and reset only where a body touched them.
#[derive(Default)]
struct Scratch {
    local_ids: Vec<u32>,
    local_touched: Vec<u32>,
    local_types: Vec<u64>,
    global_ids: Vec<u32>,
    global_touched: Vec<u32>,
    skeleton: Vec<u8>,
}

fn token(hasher: &mut Sha256, kind: u8, payload: &[u64]) {
    hasher.update([1, kind]);
    for value in payload {
        hasher.update(value.to_le_bytes());
    }
}

struct Print {
    body: [u8; 16],
    normalized: u64,
    addresses: u64,
    structure: u64,
    shape: Shape,
    calls: Vec<u32>,
}

/// Both fingerprints and the call list of one body, or `None` when the budget
/// stopped inside it. The normalized hash takes each instruction's original
/// bytes, except that it rewrites the immediates that only renumber or
/// relocate (see the contract for the exact list).
fn fingerprint(
    body: &FunctionBody<'_>,
    ty: u32,
    context: &Context<'_>,
    scratch: &mut Scratch,
    budget: &mut Budget,
) -> Result<Option<Print>> {
    let range = body.range();
    if range.len() > MAX_BODY_BYTES {
        return Err(Error::protocol(
            "A WASM function body exceeds the 7,654,321 bytes web engines accept",
        ));
    }
    let raw = Sha256::digest(&context.bytes[range.clone()]);
    let mut body_hash = [0u8; 16];
    body_hash.copy_from_slice(&raw[..16]);
    let signature = context.signature_of_type(ty);
    let params = context
        .params
        .get(ty as usize)
        .map_or(&[][..], Vec::as_slice);
    scratch.local_types.clear();
    for param in params {
        scratch.local_types.push(fnv(param.to_string().as_bytes()));
    }
    let mut declared = BTreeMap::<u64, u64>::new();
    let mut locals = body.get_locals_reader().map_err(bad)?;
    for _ in 0..locals.get_count() {
        let (count, value) = locals.read().map_err(bad)?;
        let tag = fnv(value.to_string().as_bytes());
        *declared.entry(tag).or_default() += u64::from(count);
        if scratch.local_types.len() + count as usize > MAX_LOCALS {
            return Err(Error::protocol(
                "A WASM function declares more than the 50,000 locals web engines accept",
            ));
        }
        scratch
            .local_types
            .extend(std::iter::repeat_n(tag, count as usize));
    }
    let parameters = params.len() as u32;
    let total = scratch.local_types.len();
    if scratch.local_ids.len() < total {
        scratch.local_ids.resize(total, NONE);
    }
    if scratch.global_ids.len() < context.globals.len() {
        scratch.global_ids.resize(context.globals.len(), NONE);
    }
    scratch.skeleton.clear();
    let mut next_local = parameters;
    let mut next_global = 0u32;
    let mut normalized = Sha256::new();
    normalized.update(signature.to_le_bytes());
    for (tag, count) in &declared {
        normalized.update(tag.to_le_bytes());
        normalized.update(count.to_le_bytes());
    }
    let mut addresses = Sha256::new();
    let mut shape = Shape::default();
    let mut calls = Vec::new();
    let mut reader = body.get_operators_reader().map_err(bad)?;
    let mut stopped = false;
    while !reader.eof() {
        if shape.instructions.is_multiple_of(CHECK_EVERY) && budget.late(FINGERPRINTING) {
            stopped = true;
            break;
        }
        let (op, offset) = reader.read_with_offset().map_err(bad)?;
        let end = reader.original_position();
        shape.instructions += 1;
        let name = wasm::operator_name(&op);
        shape.histogram[category(&op, name)] += 1;
        let mut address = |value: u64| {
            let (segment, within) = context.located(value);
            addresses.update(segment.to_le_bytes());
            addresses.update(within.to_le_bytes());
        };
        match &op {
            Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
                let kind = if matches!(op, Operator::Call { .. }) {
                    1
                } else {
                    2
                };
                token(
                    &mut normalized,
                    kind,
                    &[context.signature_of_function(*function_index)],
                );
                calls.push(*function_index);
            }
            Operator::RefFunc { function_index } => token(
                &mut normalized,
                3,
                &[context.signature_of_function(*function_index)],
            ),
            Operator::CallIndirect {
                type_index,
                table_index,
            } => token(
                &mut normalized,
                4,
                &[
                    context.signature_of_type(*type_index),
                    u64::from(*table_index),
                ],
            ),
            Operator::ReturnCallIndirect {
                type_index,
                table_index,
            } => token(
                &mut normalized,
                5,
                &[
                    context.signature_of_type(*type_index),
                    u64::from(*table_index),
                ],
            ),
            Operator::CallRef { type_index } => token(
                &mut normalized,
                6,
                &[context.signature_of_type(*type_index)],
            ),
            Operator::ReturnCallRef { type_index } => token(
                &mut normalized,
                7,
                &[context.signature_of_type(*type_index)],
            ),
            Operator::LocalGet { local_index }
            | Operator::LocalSet { local_index }
            | Operator::LocalTee { local_index } => {
                let kind = match op {
                    Operator::LocalGet { .. } => 8,
                    Operator::LocalSet { .. } => 9,
                    _ => 10,
                };
                let index = *local_index;
                let id = if index < parameters {
                    u64::from(index)
                } else if (index as usize) < total {
                    let slot = &mut scratch.local_ids[index as usize];
                    if *slot == NONE {
                        *slot = next_local;
                        next_local += 1;
                        scratch.local_touched.push(index);
                    }
                    u64::from(*slot)
                } else {
                    // Past the declared locals: invalid, kept verbatim and marked.
                    u64::from(index) | 1 << 40
                };
                let tag = scratch
                    .local_types
                    .get(index as usize)
                    .copied()
                    .unwrap_or(0);
                token(&mut normalized, kind, &[id, tag]);
            }
            Operator::GlobalGet { global_index } | Operator::GlobalSet { global_index } => {
                let kind = if matches!(op, Operator::GlobalGet { .. }) {
                    11
                } else {
                    12
                };
                let index = *global_index;
                let id = match scratch.global_ids.get_mut(index as usize) {
                    Some(slot) => {
                        if *slot == NONE {
                            *slot = next_global;
                            next_global += 1;
                            scratch.global_touched.push(index);
                        }
                        u64::from(*slot)
                    }
                    None => u64::from(index) | 1 << 40,
                };
                let tag = context.globals.get(index as usize).copied().unwrap_or(0);
                token(&mut normalized, kind, &[id, tag]);
            }
            Operator::Block { blockty } => token(&mut normalized, 13, &[context.block(*blockty)]),
            Operator::Loop { blockty } => token(&mut normalized, 14, &[context.block(*blockty)]),
            Operator::If { blockty } => token(&mut normalized, 15, &[context.block(*blockty)]),
            Operator::Try { blockty } => token(&mut normalized, 16, &[context.block(*blockty)]),
            Operator::TryTable { try_table } => {
                token(&mut normalized, 17, &[context.block(try_table.ty)]);
                normalized.update(format!("{:?}", try_table.catches).as_bytes());
            }
            Operator::I32Const { value } => {
                let value = u64::from(*value as u32);
                if context.address(value) {
                    token(&mut normalized, 18, &[]);
                    address(value);
                } else {
                    normalized.update([0]);
                    normalized.update(&context.bytes[offset..end]);
                }
            }
            Operator::I64Const { value } => {
                if context.address(*value as u64) {
                    token(&mut normalized, 19, &[]);
                    address(*value as u64);
                } else {
                    normalized.update([0]);
                    normalized.update(&context.bytes[offset..end]);
                }
            }
            _ => match memarg_of(&op).filter(|memarg| context.address(memarg.offset)) {
                Some(memarg) => {
                    token(
                        &mut normalized,
                        20,
                        &[
                            fnv(name.as_bytes()),
                            u64::from(memarg.align),
                            u64::from(memarg.memory),
                        ],
                    );
                    address(memarg.offset);
                }
                None => {
                    normalized.update([0]);
                    normalized.update(&context.bytes[offset..end]);
                }
            },
        }
        let control = match op {
            Operator::Block { .. } => Some(b'B'),
            Operator::Loop { .. } => Some(b'L'),
            Operator::If { .. } => Some(b'I'),
            Operator::Else => Some(b'E'),
            Operator::End => Some(b'e'),
            Operator::Br { .. } => Some(b'b'),
            Operator::BrIf { .. } => Some(b'c'),
            Operator::BrTable { .. } => Some(b't'),
            Operator::Return => Some(b'r'),
            Operator::Unreachable => Some(b'u'),
            Operator::Try { .. } | Operator::TryTable { .. } => Some(b'T'),
            Operator::Catch { .. } | Operator::CatchAll => Some(b'C'),
            Operator::Throw { .. } | Operator::ThrowRef | Operator::Rethrow { .. } => Some(b'h'),
            _ => None,
        };
        if let Some(mark) = control {
            scratch.skeleton.push(mark);
            match mark {
                b'B' | b'I' | b'T' => shape.blocks += 1,
                b'L' => shape.loops += 1,
                b'b' | b'c' | b't' | b'r' => shape.branches += 1,
                _ => {}
            }
        }
    }
    for index in scratch.local_touched.drain(..) {
        scratch.local_ids[index as usize] = NONE;
    }
    for index in scratch.global_touched.drain(..) {
        scratch.global_ids[index as usize] = NONE;
    }
    if stopped {
        return Ok(None);
    }
    reader.finish().map_err(bad)?;
    shape.skeleton = fnv(&scratch.skeleton);
    shape.calls = calls.len() as u32;
    let mut distinct = calls.clone();
    distinct.sort_unstable();
    distinct.dedup();
    shape.callees = distinct.len() as u32;
    let structure = structure_fingerprint(signature, &shape);
    Ok(Some(Print {
        body: body_hash,
        normalized: first8(&normalized.finalize()),
        addresses: first8(&addresses.finalize()),
        structure,
        shape,
        calls,
    }))
}

fn bucket(count: u32) -> u8 {
    (32 - count.leading_zeros()) as u8
}

fn structure_fingerprint(signature: u64, shape: &Shape) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(signature.to_le_bytes());
    hasher.update(shape.skeleton.to_le_bytes());
    for count in shape.histogram {
        hasher.update([bucket(count)]);
    }
    hasher.update(shape.calls.to_le_bytes());
    hasher.update(shape.callees.to_le_bytes());
    first8(&hasher.finalize())
}

fn type_text(params: &[ValType], results: &[ValType]) -> String {
    let list = |values: &[ValType]| {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("({}) -> ({})", list(params), list(results))
}

fn clip(mut text: String, limit: usize) -> String {
    if text.len() > limit {
        let mut end = limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(" [type limited]");
    }
    text
}

fn global_tag(content: ValType, mutable: bool) -> u64 {
    fnv(format!("{content} {mutable}").as_bytes())
}

/// Decodes one module's function tables and fingerprints every body the
/// budget allows.
fn analyze(
    bytes: &[u8],
    label: &str,
    budget: &mut Budget,
    omissions: &mut Vec<String>,
) -> Result<Module> {
    if bytes.is_empty() {
        return Err(Error::protocol(format!("WASM module {label} is empty")));
    }
    let mut type_text_list = Vec::new();
    let mut signatures = Vec::new();
    let mut params = Vec::new();
    let mut func_types = Vec::new();
    let mut imports = Vec::new();
    let mut globals = Vec::new();
    let mut exports = HashMap::<u32, String>::new();
    let mut names = HashMap::<u32, String>::new();
    let mut bodies = Vec::new();
    let mut segments = Vec::new();
    let mut declared = 0u32;
    // Imported functions past the function limit are counted, not kept.
    let mut imported = 0u32;
    let limit = budget.limits.max_functions;
    // Every section entry counts toward the next budget check, so a module
    // of millions of imports, exports, names or segments cannot outrun the
    // deadline while it is parsed.
    let mut entries = 0u64;
    let mut parsing_stopped = false;
    macro_rules! poll {
        ($label:lifetime) => {
            entries += 1;
            if entries.is_multiple_of(4096) && budget.late(PARSING) {
                parsing_stopped = true;
                break $label;
            }
        };
    }
    'module: for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(bad)? {
            Payload::Version {
                num: 1,
                encoding: Encoding::Module,
                ..
            } => {}
            Payload::Version { .. } => {
                return Err(Error::protocol(
                    "Only WASM core module version 1 is supported",
                ));
            }
            Payload::TypeSection(reader) => {
                for group in reader {
                    poll!('module);
                    let group = group.map_err(bad)?;
                    for ty in group.types() {
                        match &ty.composite_type.inner {
                            CompositeInnerType::Func(function) => {
                                let text = type_text(function.params(), function.results());
                                signatures.push(fnv(text.as_bytes()));
                                type_text_list.push(clip(text, MAX_TYPE_TEXT));
                                params.push(function.params().to_vec());
                            }
                            _ => {
                                signatures.push(fnv(b"non-function type"));
                                type_text_list.push("non-function type".into());
                                params.push(Vec::new());
                            }
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    poll!('module);
                    let (offset, import) = entry.map_err(bad)?;
                    match import.ty {
                        TypeRef::Func(ty) => {
                            func_types.push(ty);
                            imported += 1;
                            if imports.len() < limit {
                                imports.push((
                                    offset,
                                    bounded(import.module),
                                    bounded(import.name),
                                ));
                            }
                        }
                        TypeRef::Global(global) => {
                            globals.push(global_tag(global.content_type, global.mutable))
                        }
                        _ => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                declared = reader.count();
                for ty in reader {
                    poll!('module);
                    func_types.push(ty.map_err(bad)?);
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    poll!('module);
                    let global = global.map_err(bad)?;
                    globals.push(global_tag(global.ty.content_type, global.ty.mutable));
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    poll!('module);
                    let export = export.map_err(bad)?;
                    if export.kind == ExternalKind::Func {
                        exports
                            .entry(export.index)
                            .or_insert_with(|| bounded(export.name));
                    }
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                if count != declared {
                    return Err(Error::protocol("WASM function and code counts disagree"));
                }
            }
            Payload::CodeSectionEntry(body) => {
                poll!('module);
                bodies.push(body);
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    poll!('module);
                    let data = data.map_err(bad)?;
                    if let DataKind::Active {
                        memory_index: 0,
                        offset_expr,
                    } = data.kind
                    {
                        let start = match offset_expr.get_operators_reader().read() {
                            Ok(Operator::I32Const { value }) => Some(u64::from(value as u32)),
                            Ok(Operator::I64Const { value }) => Some(value as u64),
                            _ => None,
                        };
                        if let Some(start) = start {
                            segments.push((start, start.saturating_add(data.data.len() as u64)));
                        }
                    }
                }
            }
            Payload::CustomSection(reader) => {
                if let KnownCustom::Name(section) = reader.as_known() {
                    for subsection in section {
                        // A name section is advisory; a malformed one never
                        // fails a comparison built from the code section.
                        if let Ok(Name::Function(map)) = subsection {
                            for naming in map.into_iter().flatten() {
                                poll!('module);
                                names
                                    .entry(naming.index)
                                    .or_insert_with(|| bounded(naming.name));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !parsing_stopped && bodies.len() as u32 != declared {
        return Err(Error::protocol("WASM function bodies are missing"));
    }
    segments.sort_unstable();
    let span = segments.iter().fold(None, |span, (start, end)| {
        Some(span.map_or((*start, *end), |(low, high): (u64, u64)| {
            (low.min(*start), high.max(*end))
        }))
    });
    let context = Context {
        bytes,
        func_types: &func_types,
        signatures: &signatures,
        params: &params,
        globals: &globals,
        span,
        segments: &segments,
    };
    let total = imported as usize + declared as usize;
    let mut truncated = parsing_stopped || total > limit;
    let mut funcs = Vec::with_capacity(total.min(limit));
    let mut same_signature = HashMap::<(String, String, u64), u32>::new();
    let mut same_name = HashMap::<(String, String), u32>::new();
    for (index, (offset, module, field)) in imports.into_iter().enumerate() {
        if funcs.len() >= limit {
            break;
        }
        let ty = func_types[index];
        let signature = context.signature_of_type(ty);
        let by_signature = same_signature
            .entry((module.clone(), field.clone(), signature))
            .or_default();
        let by_name = same_name
            .entry((module.clone(), field.clone()))
            .or_default();
        let import = Import {
            module,
            name: field,
            same_signature: *by_signature,
            same_name: *by_name,
        };
        *by_signature += 1;
        *by_name += 1;
        funcs.push(Func {
            index: index as u32,
            import: Some(import),
            start: offset,
            end: offset,
            ty,
            signature,
            export: exports.remove(&(index as u32)),
            section_name: names.remove(&(index as u32)),
            body: [0; 16],
            normalized: 0,
            addresses: 0,
            structure: 0,
            shape: Shape::default(),
            calls: Vec::new(),
            callees: Vec::new(),
        });
    }
    let mut scratch = Scratch::default();
    for (position, body) in bodies.iter().enumerate() {
        if funcs.len() >= limit {
            break;
        }
        if budget.late(FINGERPRINTING) {
            truncated = true;
            break;
        }
        let index = imported + position as u32;
        let ty = func_types[index as usize];
        let Some(print) = fingerprint(body, ty, &context, &mut scratch, budget)? else {
            truncated = true;
            break;
        };
        let range = body.range();
        let mut callees = print.calls.clone();
        callees.sort_unstable();
        callees.dedup();
        funcs.push(Func {
            index,
            import: None,
            start: range.start,
            end: range.end,
            ty,
            signature: context.signature_of_type(ty),
            export: exports.remove(&index),
            section_name: names.remove(&index),
            body: print.body,
            normalized: print.normalized,
            addresses: print.addresses,
            structure: print.structure,
            shape: print.shape,
            calls: print.calls,
            callees,
        });
    }
    if parsing_stopped {
        omissions.push(format!(
            "Module {label}: parsing stopped before the end of the module, so its function count is unknown; {} functions were fingerprinted.",
            funcs.len()
        ));
    } else if truncated {
        omissions.push(format!(
            "Module {label}: {} of its {total} functions were fingerprinted; the others were not compared.",
            funcs.len()
        ));
    }
    let mut callers = vec![Vec::new(); funcs.len()];
    for func in &funcs {
        for target in &func.callees {
            if let Some(list) = callers.get_mut(*target as usize) {
                list.push(func.index);
            }
        }
    }
    Ok(Module {
        imported,
        defined: declared,
        funcs,
        callers,
        type_text: type_text_list,
        truncated,
    })
}

/// One ambiguous group: functions on both sides that tie, with the method
/// that tied them. Every member is its own row, so paging reaches them all.
struct Group {
    method: u8,
    score: f64,
    a: Vec<u32>,
    b: Vec<u32>,
}

#[derive(Clone)]
struct Row {
    status: u8,
    method: Option<u8>,
    score: f64,
    a: Option<u32>,
    b: Option<u32>,
    group: Option<u32>,
}

/// The best score among `scored` and the candidates within the tie margin
/// of it, sorted, for function `x`.
fn tied_best(x: u32, scored: &[(u32, f64)]) -> Option<(u32, f64, Vec<u32>)> {
    let top = scored.iter().map(|s| s.1).reduce(f64::max)?;
    let mut tied = scored
        .iter()
        .filter(|s| top - s.1 < TIE_MARGIN)
        .map(|s| s.0)
        .collect::<Vec<_>>();
    tied.sort_unstable();
    Some((x, top, tied))
}

fn single(status: u8, a: Option<u32>, b: Option<u32>) -> Row {
    Row {
        status,
        method: None,
        score: 0.0,
        a,
        b,
        group: None,
    }
}

/// Union-find over A functions (0..na) then B functions (na..na+nb), with
/// each set's size, so whether a function joined anything is explicit rather
/// than read from which member became the root.
struct Sets {
    parent: Vec<u32>,
    size: Vec<u32>,
}
impl Sets {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n as u32).collect(),
            size: vec![1; n],
        }
    }
    fn find(&mut self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            let parent = self.parent[x as usize];
            self.parent[x as usize] = self.parent[parent as usize];
            x = parent;
        }
        x
    }
    fn union(&mut self, x: u32, y: u32) {
        let (x, y) = (self.find(x), self.find(y));
        if x != y {
            let (root, child) = (x.min(y), x.max(y));
            self.parent[child as usize] = root;
            self.size[root as usize] += self.size[child as usize];
        }
    }
    /// Whether `x` was joined with anything.
    fn joined(&mut self, x: u32) -> bool {
        let root = self.find(x);
        self.size[root as usize] > 1
    }
}

struct Matcher<'m> {
    a: &'m Module,
    b: &'m Module,
    a_to_b: Vec<u32>,
    b_to_a: Vec<u32>,
    method: Vec<(u8, f64)>,
    grouped_a: Vec<bool>,
    grouped_b: Vec<bool>,
    groups: Vec<Group>,
    budget: Budget,
    /// A matched pair whose positional proposals were already made.
    positional_done: Vec<bool>,
    /// Similarity scores already paid for during propagation.
    scores: HashMap<(u32, u32), f64>,
    structural_incomplete: bool,
}

impl<'m> Matcher<'m> {
    fn new(a: &'m Module, b: &'m Module, budget: Budget) -> Self {
        Self {
            a,
            b,
            a_to_b: vec![NONE; a.funcs.len()],
            b_to_a: vec![NONE; b.funcs.len()],
            method: vec![(0, 0.0); a.funcs.len()],
            grouped_a: vec![false; a.funcs.len()],
            grouped_b: vec![false; b.funcs.len()],
            groups: Vec::new(),
            budget,
            positional_done: vec![false; a.funcs.len()],
            scores: HashMap::new(),
            structural_incomplete: false,
        }
    }
    fn open_a(&self, index: u32) -> bool {
        self.a_to_b
            .get(index as usize)
            .is_some_and(|b| *b == NONE && !self.grouped_a[index as usize])
    }
    fn open_b(&self, index: u32) -> bool {
        self.b_to_a
            .get(index as usize)
            .is_some_and(|a| *a == NONE && !self.grouped_b[index as usize])
    }
    fn pair(&mut self, a: u32, b: u32, method: u8, score: f64) {
        self.a_to_b[a as usize] = b;
        self.b_to_a[b as usize] = a;
        self.method[a as usize] = (method, score);
    }
    fn same_signature(&self, a: u32, b: u32) -> bool {
        self.a.funcs[a as usize].signature == self.b.funcs[b as usize].signature
    }
    /// A similarity score taken from the budget; `None` once it is spent.
    fn score(&mut self, step: &'static str, a: u32, b: u32) -> Option<f64> {
        self.budget.score(step).then(|| {
            similarity(
                &self.a.funcs[a as usize].shape,
                &self.b.funcs[b as usize].shape,
            )
        })
    }
    /// Groups the open functions of both sides by `key`. A key held by exactly
    /// one function on each side is a match; any other shared key is a tie
    /// left for later passes or reported as ambiguous.
    fn groups_by<K: std::hash::Hash + Eq + Ord + Clone>(
        &self,
        key: impl Fn(&Func) -> Option<K>,
    ) -> BTreeMap<K, (Vec<u32>, Vec<u32>)> {
        let mut groups = HashMap::<K, (Vec<u32>, Vec<u32>)>::new();
        for func in &self.a.funcs {
            if self.open_a(func.index)
                && let Some(k) = key(func)
            {
                groups.entry(k).or_default().0.push(func.index);
            }
        }
        for func in &self.b.funcs {
            if self.open_b(func.index)
                && let Some(k) = key(func)
                && let Some(group) = groups.get_mut(&k)
            {
                group.1.push(func.index);
            }
        }
        groups
            .into_iter()
            .filter(|(_, (a, b))| !a.is_empty() && !b.is_empty())
            .collect()
    }
    fn exact<K: std::hash::Hash + Eq + Ord + Clone>(
        &mut self,
        method: u8,
        key: impl Fn(&Func) -> Option<K>,
        made: &mut Vec<u32>,
    ) {
        if self.budget.late(EXACT) {
            return;
        }
        for (_, (a, b)) in self.groups_by(key) {
            if a.len() == 1 && b.len() == 1 {
                let score = match method {
                    BY_BYTES | BY_NORMALIZED => 1.0,
                    _ => similarity(
                        &self.a.funcs[a[0] as usize].shape,
                        &self.b.funcs[b[0] as usize].shape,
                    ),
                };
                self.pair(a[0], b[0], method, score);
                made.push(a[0]);
            }
        }
    }
    /// Every exact key in contract order; returns the A functions it matched.
    fn exact_passes(&mut self) -> Vec<u32> {
        let defined = |f: &Func| f.import.is_none();
        let mut made = Vec::new();
        self.exact(
            BY_IMPORT,
            |f| {
                f.import.as_ref().map(|i| {
                    (
                        i.module.clone(),
                        i.name.clone(),
                        f.signature,
                        i.same_signature,
                    )
                })
            },
            &mut made,
        );
        self.exact(
            BY_IMPORT,
            |f| {
                f.import
                    .as_ref()
                    .map(|i| (i.module.clone(), i.name.clone(), i.same_name))
            },
            &mut made,
        );
        self.exact(BY_BYTES, |f| defined(f).then_some(f.body), &mut made);
        self.exact(
            BY_NORMALIZED,
            |f| defined(f).then_some(f.normalized),
            &mut made,
        );
        self.exact(
            BY_EXPORT,
            |f| defined(f).then(|| f.export.clone()).flatten(),
            &mut made,
        );
        self.exact(
            BY_NAME,
            |f| defined(f).then(|| f.section_name.clone()).flatten(),
            &mut made,
        );
        made
    }
    fn open_neighbours(&self, list: &[u32], side_a: bool) -> Vec<u32> {
        list.iter()
            .copied()
            .filter(|index| {
                if side_a {
                    self.open_a(*index)
                } else {
                    self.open_b(*index)
                }
            })
            .collect()
    }
    /// A similarity score, computed once per pair and then reused, so a
    /// pair seen from many parents or call sites spends the cap once.
    fn cached_score(&mut self, a: u32, b: u32) -> Option<f64> {
        if let Some(score) = self.scores.get(&(a, b)) {
            return Some(*score);
        }
        let score = self.score(PROPAGATION, a, b)?;
        self.scores.insert((a, b), score);
        Some(score)
    }
    /// Scores of every same-signature pair between `xs` and `ys`, row by row;
    /// other pairs are negative infinity. `None` when the budget ran out.
    fn matrix(&mut self, xs: &[u32], ys: &[u32]) -> Option<Vec<f64>> {
        let mut scores = vec![f64::NEG_INFINITY; xs.len() * ys.len()];
        for (i, x) in xs.iter().enumerate() {
            for (j, y) in ys.iter().enumerate() {
                if self.same_signature(*x, *y) {
                    scores[i * ys.len() + j] = self.cached_score(*x, *y)?;
                }
            }
        }
        Some(scores)
    }
    /// What one matched pair proposes. `None` when the budget ran out.
    ///
    /// A pair whose bodies normalize equally proposes its k-th callees, which
    /// sit at corresponding places in both bodies, but only when no other open
    /// callee looks more like either one. Any matched pair proposes the open
    /// callees, and separately the open callers, that are each other's best
    /// candidate by at least the tie margin. A proposal never overrides a
    /// better-shaped candidate, so a reordered call sequence cannot carry a
    /// wrong pair.
    fn proposals(&mut self, a: u32, b: u32) -> Option<Vec<(u32, u32, f64)>> {
        let (module_a, module_b) = (self.a, self.b);
        let (fa, fb) = (&module_a.funcs[a as usize], &module_b.funcs[b as usize]);
        let mut proposed = Vec::new();
        let sets = [
            (
                self.open_neighbours(&fa.callees, true),
                self.open_neighbours(&fb.callees, false),
            ),
            (
                self.open_neighbours(&module_a.callers[a as usize], true),
                self.open_neighbours(&module_b.callers[b as usize], false),
            ),
        ];
        for (kind, (xs, ys)) in sets.iter().enumerate() {
            if xs.is_empty()
                || ys.is_empty()
                || xs.len() > MAX_NEIGHBOURHOOD
                || ys.len() > MAX_NEIGHBOURHOOD
            {
                continue;
            }
            let scores = self.matrix(xs, ys)?;
            let at = |i: usize, j: usize| scores[i * ys.len() + j];
            let row_max = |i: usize| {
                (0..ys.len())
                    .map(|j| at(i, j))
                    .fold(f64::NEG_INFINITY, f64::max)
            };
            let column_max = |j: usize| {
                (0..xs.len())
                    .map(|i| at(i, j))
                    .fold(f64::NEG_INFINITY, f64::max)
            };
            if kind == 0
                && !self.positional_done[a as usize]
                && fa.import.is_none()
                && fa.normalized == fb.normalized
                && fa.calls.len() == fb.calls.len()
            {
                self.positional_done[a as usize] = true;
                // Each distinct pair of call targets once, however many call
                // sites repeat it.
                let sites = fa
                    .calls
                    .iter()
                    .zip(&fb.calls)
                    .map(|(x, y)| (*x, *y))
                    .collect::<std::collections::BTreeSet<_>>();
                for (x, y) in sites {
                    let (Ok(i), Ok(j)) = (xs.binary_search(&x), ys.binary_search(&y)) else {
                        continue;
                    };
                    let score = at(i, j);
                    if score >= PROPAGATION_FLOOR && score >= row_max(i) && score >= column_max(j) {
                        proposed.push((x, y, score));
                    }
                }
            }
            let best = |values: &mut dyn Iterator<Item = (usize, f64)>| {
                let mut first = (usize::MAX, f64::NEG_INFINITY);
                let mut second = f64::NEG_INFINITY;
                for (index, value) in values {
                    if value > first.1 {
                        second = first.1;
                        first = (index, value);
                    } else if value > second {
                        second = value;
                    }
                }
                (first.1 - second >= TIE_MARGIN).then_some(first)
            };
            for i in 0..xs.len() {
                let Some((j, value)) = best(&mut (0..ys.len()).map(|j| (j, at(i, j)))) else {
                    continue;
                };
                if value >= PROPAGATION_FLOOR
                    && best(&mut (0..xs.len()).map(|k| (k, at(k, j)))).is_some_and(|(k, _)| k == i)
                {
                    proposed.push((xs[i], ys[j], value));
                }
            }
        }
        Some(proposed)
    }
    /// Carries matches along the call graph from the `seeds` (matched A
    /// functions), one round at a time. A round collects what every pair in
    /// it proposes and only then accepts: a function proposed for one partner
    /// by every proposer is paired, and one proposed for two different
    /// partners is a tie with them. The order pairs are visited in therefore
    /// never decides a contested function. A round the budget stops accepts
    /// nothing. The next round looks at the new pairs and the matched pairs
    /// beside them, whose open neighbourhoods just shrank.
    fn propagate(&mut self, seeds: &[u32]) -> Vec<u32> {
        let (module_a, module_b) = (self.a, self.b);
        let mut made = Vec::new();
        let mut frontier = seeds.to_vec();
        frontier.sort_unstable();
        frontier.dedup();
        while !frontier.is_empty() {
            let mut proposed = BTreeMap::<(u32, u32), f64>::new();
            for a in &frontier {
                if self.budget.late(PROPAGATION) {
                    return made;
                }
                let b = self.a_to_b[*a as usize];
                if b == NONE {
                    continue;
                }
                let Some(pairs) = self.proposals(*a, b) else {
                    return made;
                };
                for (x, y, score) in pairs {
                    let entry = proposed.entry((x, y)).or_insert(score);
                    *entry = entry.max(score);
                }
            }
            let mut partners_a = BTreeMap::<u32, Vec<u32>>::new();
            let mut partners_b = BTreeMap::<u32, Vec<u32>>::new();
            for (x, y) in proposed.keys() {
                partners_a.entry(*x).or_default().push(*y);
                partners_b.entry(*y).or_default().push(*x);
            }
            let mut accepted = Vec::new();
            let mut contested = Vec::new();
            for ((x, y), score) in &proposed {
                if partners_a[x].len() == 1 && partners_b[y].len() == 1 {
                    accepted.push((*x, *y, *score));
                } else {
                    contested.push((*x, *y, *score));
                }
            }
            if !contested.is_empty() {
                // A small union-find over just the contested functions: A
                // functions as themselves, B functions offset past every A.
                let offset = module_a.funcs.len() as u64;
                let mut parent = BTreeMap::<u64, u64>::new();
                fn root(parent: &mut BTreeMap<u64, u64>, mut x: u64) -> u64 {
                    while let Some(&up) = parent.get(&x) {
                        if up == x {
                            break;
                        }
                        x = up;
                    }
                    x
                }
                for (x, y, _) in &contested {
                    let (x, y) = (u64::from(*x), offset + u64::from(*y));
                    parent.entry(x).or_insert(x);
                    parent.entry(y).or_insert(y);
                    let (rx, ry) = (root(&mut parent, x), root(&mut parent, y));
                    if rx != ry {
                        parent.insert(rx.max(ry), rx.min(ry));
                    }
                }
                type Tie = (
                    std::collections::BTreeSet<u32>,
                    std::collections::BTreeSet<u32>,
                    f64,
                );
                let mut ties = BTreeMap::<u64, Tie>::new();
                for (x, y, score) in &contested {
                    let entry = ties.entry(root(&mut parent, u64::from(*x))).or_default();
                    entry.0.insert(*x);
                    entry.1.insert(*y);
                    entry.2 = entry.2.max(*score);
                }
                for (_, (a, b, score)) in ties {
                    self.group(
                        BY_CALL_GRAPH,
                        score,
                        a.into_iter().collect(),
                        b.into_iter().collect(),
                    );
                }
            }
            let mut next = Vec::new();
            for (x, y, score) in accepted {
                self.pair(x, y, BY_CALL_GRAPH, score);
                made.push(x);
                let fx = &module_a.funcs[x as usize];
                let fy = &module_b.funcs[y as usize];
                next.push(x);
                next.extend(
                    fx.callees
                        .iter()
                        .chain(&module_a.callers[x as usize])
                        .copied()
                        .filter(|n| self.a_to_b[*n as usize] != NONE),
                );
                next.extend(
                    fy.callees
                        .iter()
                        .chain(&module_b.callers[y as usize])
                        .map(|n| self.b_to_a[*n as usize])
                        .filter(|n| *n != NONE),
                );
            }
            next.sort_unstable();
            next.dedup();
            frontier = next;
        }
        made
    }
    /// Exact passes and propagation until neither adds a match, at most
    /// `MAX_EXACT_ROUNDS` times.
    fn settle(&mut self, mut seeds: Vec<u32>) {
        for _ in 0..MAX_EXACT_ROUNDS {
            seeds.extend(self.exact_passes());
            if seeds.is_empty() || self.budget.stopped.is_some() {
                break;
            }
            let carried = self.propagate(&seeds);
            seeds = carried;
            if seeds.is_empty() {
                // Propagation added nothing, so no exact tie can have opened.
                break;
            }
        }
    }
    /// Functions still sharing an exact key with another open function. They
    /// stay out of the structural pass, which could only tie them again.
    fn exact_ties(&self) -> Vec<(u8, Vec<u32>, Vec<u32>)> {
        let defined = |f: &Func| f.import.is_none();
        let mut ties = Vec::new();
        for (_, (a, b)) in self.groups_by(|f| defined(f).then_some(f.body)) {
            ties.push((BY_BYTES, a, b));
        }
        let mut seen_a = vec![false; self.a.funcs.len()];
        for (_, a, _) in &ties {
            for index in a {
                seen_a[*index as usize] = true;
            }
        }
        for (_, (a, b)) in self.groups_by(|f| defined(f).then_some(f.normalized)) {
            if a.iter().all(|index| !seen_a[*index as usize]) {
                ties.push((BY_NORMALIZED, a, b));
            }
        }
        ties
    }
    fn group(&mut self, method: u8, score: f64, mut a: Vec<u32>, mut b: Vec<u32>) {
        a.sort_unstable();
        b.sort_unstable();
        for index in &a {
            self.grouped_a[*index as usize] = true;
        }
        for index in &b {
            self.grouped_b[*index as usize] = true;
        }
        self.groups.push(Group {
            method,
            score,
            a,
            b,
        });
    }
    /// Scores open functions of the same signature against the nearest-size
    /// candidates on the other side. Only a mutual best with a margin over
    /// every runner-up becomes a match, and ties become ambiguous groups.
    ///
    /// The decision needs every candidate's score, so a pass the budget stops
    /// accepts nothing: its functions stay open and end up unclassified.
    fn structural(&mut self) -> Vec<u32> {
        let (module_a, module_b) = (self.a, self.b);
        let ties = self.exact_ties();
        let mut excluded_a = vec![false; module_a.funcs.len()];
        let mut excluded_b = vec![false; module_b.funcs.len()];
        for (_, a, b) in &ties {
            for index in a {
                excluded_a[*index as usize] = true;
            }
            for index in b {
                excluded_b[*index as usize] = true;
            }
        }
        // Ordered maps throughout: what this pass returns seeds propagation,
        // so its order must not depend on a hasher.
        let mut buckets = BTreeMap::<u64, Vec<u32>>::new();
        for func in &module_b.funcs {
            if func.import.is_none() && self.open_b(func.index) && !excluded_b[func.index as usize]
            {
                buckets.entry(func.signature).or_default().push(func.index);
            }
        }
        for list in buckets.values_mut() {
            list.sort_by_key(|index| (module_b.funcs[*index as usize].shape.instructions, *index));
        }
        let mut buckets_a = BTreeMap::<u64, Vec<u32>>::new();
        for func in &module_a.funcs {
            if func.import.is_none() && self.open_a(func.index) && !excluded_a[func.index as usize]
            {
                buckets_a
                    .entry(func.signature)
                    .or_default()
                    .push(func.index);
            }
        }
        for list in buckets_a.values_mut() {
            list.sort_by_key(|index| (module_a.funcs[*index as usize].shape.instructions, *index));
        }
        // Functions with someone of their signature on the other side. Both
        // directions may be scored, so the comparisons left are shared by all.
        let paired = |buckets: &BTreeMap<u64, Vec<u32>>, other: &BTreeMap<u64, Vec<u32>>| {
            buckets
                .iter()
                .filter(|(signature, _)| other.contains_key(*signature))
                .map(|(_, list)| list.len())
                .sum::<usize>()
        };
        let open = (paired(&buckets_a, &buckets) + paired(&buckets, &buckets_a)).max(1);
        let left = self
            .budget
            .limits
            .max_comparisons
            .saturating_sub(self.budget.comparisons);
        let per = usize::try_from(left / open as u64)
            .unwrap_or(usize::MAX)
            .min(MAX_CANDIDATES);
        if per < MIN_CANDIDATES {
            self.structural_incomplete = true;
            self.budget
                .stopped
                .get_or_insert((STRUCTURAL, "comparison limit"));
            return Vec::new();
        }
        // Each open A function's best score and the B candidates within the
        // tie margin of it.
        let mut best = Vec::<(u32, f64, Vec<u32>)>::new();
        for list in buckets_a.values() {
            for a in list {
                let func = &module_a.funcs[*a as usize];
                let Some(candidates) = buckets.get(&func.signature) else {
                    continue;
                };
                let Some(scored) = self.window(*a, true, candidates, per) else {
                    return Vec::new();
                };
                if let Some(entry) = tied_best(*a, &scored) {
                    best.push(entry);
                }
            }
        }
        // Every open B function also scores its own nearest A candidates. A
        // function outside an A function's window, even one an unrelated A
        // function happened to score, would otherwise look added. A B function
        // that ties an A function's own best, without already being among
        // that function's best candidates, contests it.
        let best_of = best
            .iter()
            .map(|(a, score, tied)| (*a, (*score, tied.as_slice())))
            .collect::<HashMap<_, _>>();
        let mut contests = Vec::new();
        for list in buckets.values() {
            for b in list {
                let func = &module_b.funcs[*b as usize];
                let Some(candidates) = buckets_a.get(&func.signature) else {
                    continue;
                };
                let Some(scored) = self.window(*b, false, candidates, per) else {
                    return Vec::new();
                };
                let Some((_, top, tied)) = tied_best(*b, &scored) else {
                    continue;
                };
                if top < SIMILARITY_THRESHOLD {
                    continue;
                }
                for a in tied {
                    let contested = best_of.get(&a).is_none_or(|(own, own_tied)| {
                        own - top < TIE_MARGIN && !own_tied.contains(b)
                    });
                    if contested {
                        contests.push((a, *b));
                    }
                }
            }
        }
        // Claims on each B function from the A functions that rank it best.
        let mut claims = BTreeMap::<u32, Vec<(u32, f64)>>::new();
        for (a, score, tied) in &best {
            if *score >= SIMILARITY_THRESHOLD {
                for b in tied {
                    claims.entry(*b).or_default().push((*a, *score));
                }
            }
        }
        let na = module_a.funcs.len() as u32;
        let mut sets = Sets::new(na as usize + module_b.funcs.len());
        // Every tie is joined before any pair is accepted, so whether a pair
        // stands does not depend on the order functions were scored in.
        for (a, score, tied) in &best {
            if *score >= SIMILARITY_THRESHOLD && tied.len() > 1 {
                for b in tied {
                    sets.union(*a, na + b);
                }
            }
        }
        // A contested function's best is no longer unique, so its own best
        // candidates join the tie with the contesting one.
        let tied_of = best
            .iter()
            .map(|(a, _, tied)| (*a, tied.as_slice()))
            .collect::<HashMap<_, _>>();
        for (a, b) in &contests {
            sets.union(*a, na + b);
            for own in tied_of.get(a).copied().unwrap_or_default() {
                sets.union(*a, na + own);
            }
        }
        for (b, list) in &claims {
            let top = list.iter().map(|c| c.1).fold(f64::NEG_INFINITY, f64::max);
            let rivals = list
                .iter()
                .filter(|c| top - c.1 < TIE_MARGIN)
                .collect::<Vec<_>>();
            if rivals.len() > 1 {
                for (a, _) in rivals {
                    sets.union(*a, na + b);
                }
            }
        }
        let mut made = Vec::new();
        let mut members = BTreeMap::<u32, (Vec<u32>, Vec<u32>, f64)>::new();
        for (a, score, tied) in &best {
            if *score < SIMILARITY_THRESHOLD {
                continue;
            }
            let b = tied[0];
            // A function another claimant beats by the margin simply loses
            // this candidate; one that ties was joined into a group above.
            let alone = tied.len() == 1
                && !sets.joined(*a)
                && !sets.joined(na + b)
                && claims[&b]
                    .iter()
                    .all(|(claimant, value)| *claimant == *a || *score - *value >= TIE_MARGIN);
            if alone {
                self.pair(*a, b, BY_STRUCTURE, *score);
                made.push(*a);
            }
        }
        for (a, score, _) in &best {
            if *score < SIMILARITY_THRESHOLD || !self.open_a(*a) {
                continue;
            }
            // A function that lost its candidate outright is alone in its set
            // and, with no B member, forms no group: it stays open.
            let root = sets.find(*a);
            let entry = members.entry(root).or_default();
            entry.0.push(*a);
            entry.2 = entry.2.max(*score);
        }
        let mut listed = vec![false; module_b.funcs.len()];
        for b in claims.keys().chain(contests.iter().map(|(_, b)| b)) {
            if !self.open_b(*b) || std::mem::replace(&mut listed[*b as usize], true) {
                continue;
            }
            let root = sets.find(na + b);
            if let Some(entry) = members.get_mut(&root) {
                entry.1.push(*b);
            }
        }
        for (_, (a, b, score)) in members {
            if !a.is_empty() && !b.is_empty() {
                self.group(BY_STRUCTURE, score, a, b);
            }
        }
        made.sort_unstable();
        made
    }
    /// Scores `x` against up to `per` members of `candidates` (one signature,
    /// sorted by size) nearest to it in instruction count. `None` when the
    /// budget stopped, which leaves the whole pass incomplete.
    fn window(
        &mut self,
        x: u32,
        x_on_a: bool,
        candidates: &[u32],
        per: usize,
    ) -> Option<Vec<(u32, f64)>> {
        if self.budget.late(STRUCTURAL) {
            self.structural_incomplete = true;
            return None;
        }
        let (own, other) = if x_on_a {
            (self.a, self.b)
        } else {
            (self.b, self.a)
        };
        let size_of = |index: u32| other.funcs[index as usize].shape.instructions;
        let size = own.funcs[x as usize].shape.instructions;
        let mid = candidates.partition_point(|index| size_of(*index) < size);
        let (mut low, mut high) = (mid, mid);
        let mut scored = Vec::with_capacity(per);
        while scored.len() < per && (low > 0 || high < candidates.len()) {
            let below = (low > 0).then(|| size - size_of(candidates[low - 1]).min(size));
            let above =
                (high < candidates.len()).then(|| size_of(candidates[high]).saturating_sub(size));
            let candidate = match (below, above) {
                (Some(d), Some(u)) if d <= u => {
                    low -= 1;
                    candidates[low]
                }
                (Some(_), None) => {
                    low -= 1;
                    candidates[low]
                }
                (_, Some(_)) => {
                    high += 1;
                    candidates[high - 1]
                }
                (None, None) => break,
            };
            let (a, b) = if x_on_a {
                (x, candidate)
            } else {
                (candidate, x)
            };
            let Some(score) = self.score(STRUCTURAL, a, b) else {
                self.structural_incomplete = true;
                return None;
            };
            scored.push((candidate, score));
        }
        Some(scored)
    }
    /// Whether each call site of a matched pair calls the matched function on
    /// the other side.
    fn calls_correspond(&self, fa: &Func, fb: &Func) -> bool {
        fa.calls.len() == fb.calls.len()
            && fa
                .calls
                .iter()
                .zip(&fb.calls)
                .all(|(x, y)| self.a_to_b.get(*x as usize) == Some(y))
    }
    fn run(mut self) -> (Vec<Row>, Vec<Group>, Budget, bool) {
        self.settle(Vec::new());
        if self.budget.stopped.is_none() {
            let made = self.structural();
            if self.budget.stopped.is_none() && !made.is_empty() {
                self.settle(made);
            }
        }
        // A stopped run never resolved its ties, so it reports them as
        // unclassified rather than as settled ambiguity.
        let ties = if self.budget.stopped.is_none() {
            self.exact_ties()
        } else {
            Vec::new()
        };
        for (method, a, b) in ties {
            let a = a
                .into_iter()
                .filter(|i| self.open_a(*i))
                .collect::<Vec<_>>();
            let b = b
                .into_iter()
                .filter(|i| self.open_b(*i))
                .collect::<Vec<_>>();
            if !a.is_empty() && !b.is_empty() {
                self.group(method, 1.0, a, b);
            }
        }
        let unknown = self.budget.stopped.is_some() || self.a.truncated || self.b.truncated;
        let mut rows = Vec::new();
        for (id, group) in self.groups.iter().enumerate() {
            let member = |a: Option<u32>, b: Option<u32>| Row {
                status: AMBIGUOUS,
                method: Some(group.method),
                score: group.score,
                a,
                b,
                group: Some(id as u32),
            };
            rows.extend(group.a.iter().map(|a| member(Some(*a), None)));
            rows.extend(group.b.iter().map(|b| member(None, Some(*b))));
        }
        for (a, b) in self.a_to_b.iter().enumerate() {
            let fa = &self.a.funcs[a];
            if *b == NONE {
                if !self.grouped_a[a] {
                    rows.push(single(
                        if unknown { UNCLASSIFIED } else { REMOVED },
                        Some(fa.index),
                        None,
                    ));
                }
                continue;
            }
            let fb = &self.b.funcs[*b as usize];
            let (method, score) = self.method[a];
            let status = match (&fa.import, &fb.import) {
                (Some(x), Some(y))
                    if fa.signature == fb.signature && x.module == y.module && x.name == y.name =>
                {
                    IDENTICAL
                }
                (Some(_), Some(_)) => CHANGED,
                _ if fa.body == fb.body => IDENTICAL,
                _ if fa.normalized == fb.normalized
                    && fa.addresses == fb.addresses
                    && self.calls_correspond(fa, fb) =>
                {
                    RENUMBERED
                }
                _ => CHANGED,
            };
            rows.push(Row {
                status,
                method: Some(method),
                score,
                a: Some(fa.index),
                b: Some(fb.index),
                group: None,
            });
        }
        for (b, a) in self.b_to_a.iter().enumerate() {
            if *a == NONE && !self.grouped_b[b] {
                rows.push(single(
                    if unknown { UNCLASSIFIED } else { ADDED },
                    None,
                    Some(b as u32),
                ));
            }
        }
        rows.sort_by_key(|row| {
            (
                row.status,
                row.group.unwrap_or(0),
                row.a.unwrap_or(NONE),
                row.b.unwrap_or(NONE),
            )
        });
        let incomplete = self.structural_incomplete;
        (rows, self.groups, self.budget, incomplete)
    }
}

/// What a page needs of one function after matching; call lists are dropped.
struct Side {
    index: u32,
    start: usize,
    end: usize,
    import: Option<(String, String)>,
    name: Option<String>,
    ty: u32,
    instructions: u32,
    normalized: u64,
    structure: u64,
}

struct Report {
    a: Value,
    b: Value,
    a_sides: Vec<Side>,
    b_sides: Vec<Side>,
    a_types: Vec<String>,
    b_types: Vec<String>,
    rows: Vec<Row>,
    /// Member counts of each ambiguous group, by group id.
    groups: Vec<(usize, usize)>,
    summary: Value,
    omissions: Vec<String>,
    complete: bool,
}

fn sides(module: Module) -> (Vec<Side>, Vec<String>) {
    let sides = module
        .funcs
        .into_iter()
        .map(|f| Side {
            index: f.index,
            start: f.start,
            end: f.end,
            name: f.section_name.or(f.export),
            import: f.import.map(|i| (i.module, i.name)),
            ty: f.ty,
            instructions: f.shape.instructions,
            normalized: f.normalized,
            structure: f.structure,
        })
        .collect();
    (sides, module.type_text)
}

#[cfg(test)]
fn compare(a_bytes: &[u8], b_bytes: &[u8], a: Value, b: Value) -> Result<Report> {
    compare_with(a_bytes, b_bytes, a, b, Limits::DEFAULT, Instant::now())
}

/// `started` is when the request began, so reading and verifying both
/// modules counts against the deadline too.
fn compare_with(
    a_bytes: &[u8],
    b_bytes: &[u8],
    a: Value,
    b: Value,
    limits: Limits,
    started: Instant,
) -> Result<Report> {
    let mut budget = Budget::new(limits, started);
    let mut omissions = Vec::new();
    let module_a = analyze(a_bytes, "A", &mut budget, &mut omissions)?;
    let module_b = analyze(b_bytes, "B", &mut budget, &mut omissions)?;
    if module_a.declared() == 0 || module_b.declared() == 0 {
        omissions.push(
            "A module declares no functions, so every function of the other is added or removed."
                .into(),
        );
    }
    let (rows, groups, budget, structural_incomplete) =
        Matcher::new(&module_a, &module_b, budget).run();
    let mut counts = [0u64; 7];
    let mut methods = [0u64; 7];
    for row in &rows {
        counts[row.status as usize] += 1;
        if row.a.is_some()
            && row.b.is_some()
            && let Some(method) = row.method
        {
            methods[method as usize] += 1;
        }
    }
    if let Some((step, reason)) = budget.stopped {
        omissions.push(format!(
            "The {step} step stopped at the {reason}; {} unmatched functions are unclassified, not added or removed.",
            counts[UNCLASSIFIED as usize]
        ));
    }
    if structural_incomplete {
        omissions.push(
            "The structural pass did not score every candidate, so none of its pairs or ties were kept."
                .into(),
        );
    }
    let side_meta = |mut meta: Value, module: &Module| {
        meta["imported_functions"] = json!(module.imported);
        meta["defined_functions"] = json!(module.defined);
        meta["analyzed_functions"] = json!(module.funcs.len());
        meta
    };
    let a = side_meta(a, &module_a);
    let b = side_meta(b, &module_b);
    let matched = methods.iter().sum::<u64>();
    let summary = json!({
        "matched": matched,
        "statuses": STATUSES.iter().zip(counts).map(|(name, count)| (name.to_string(), json!(count))).collect::<serde_json::Map<_, _>>(),
        "methods": METHODS.iter().zip(methods).map(|(name, count)| (name.to_string(), json!(count))).collect::<serde_json::Map<_, _>>(),
        "ambiguous_groups": groups.len(),
        "comparisons": budget.comparisons,
        "elapsed_ms": budget.started.elapsed().as_millis() as u64,
    });
    // Complete means nothing was left uncompared. A note such as "this
    // module declares no functions" describes a complete answer.
    let complete = budget.stopped.is_none()
        && !structural_incomplete
        && !module_a.truncated
        && !module_b.truncated;
    let (a_sides, a_types) = sides(module_a);
    let (b_sides, b_types) = sides(module_b);
    Ok(Report {
        a,
        b,
        a_sides,
        b_sides,
        a_types,
        b_types,
        rows,
        groups: groups.iter().map(|g| (g.a.len(), g.b.len())).collect(),
        summary,
        omissions,
        complete,
    })
}

/// Which rows a page returns.
pub struct Page {
    pub offset: usize,
    pub limit: usize,
    pub statuses: Option<Vec<String>>,
}

impl Page {
    /// A validated page request: `limit` is 1 to `PAGE_MAX_ROWS`, and an
    /// unknown or repeated status is refused.
    pub fn new(offset: usize, limit: usize, statuses: Option<&str>) -> Result<Self> {
        if limit == 0 || limit > PAGE_MAX_ROWS {
            return Err(Error::bad("row_limit is 1 to 1000"));
        }
        Ok(Self {
            offset,
            limit,
            statuses: statuses.map(requested_statuses).transpose()?,
        })
    }
}

/// Parses a `status` request into known status names, refusing an unknown or
/// repeated one instead of widening to every row.
pub fn requested_statuses(raw: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in raw.split(',') {
        if !STATUSES.contains(&name) {
            return Err(Error::bad(format!(
                "A WASM module diff status names only: {}",
                STATUSES.join(", ")
            )));
        }
        if names.iter().any(|known| known == name) {
            return Err(Error::bad("Name each WASM module diff status once"));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn hex16(value: u64) -> String {
    format!("{value:016x}")
}

fn side_json(side: &Side, types: &[String]) -> Value {
    let defined = side.import.is_none();
    json!({
        "function": side.index,
        "byte_offset": side.start,
        "byte_end": side.end,
        "name": side.name,
        "import": side.import.as_ref().map(|(module, name)| json!({"module": module, "name": name})),
        "type": types.get(side.ty as usize).cloned().unwrap_or_else(|| format!("type {}", side.ty)),
        "instructions": defined.then_some(side.instructions),
        "normalized": defined.then(|| hex16(side.normalized)),
        "structure": defined.then(|| hex16(side.structure)),
    })
}

fn row_json(report: &Report, row: &Row) -> Value {
    let a = |index: u32| side_json(&report.a_sides[index as usize], &report.a_types);
    let b = |index: u32| side_json(&report.b_sides[index as usize], &report.b_types);
    let mut value = json!({
        "status": STATUSES[row.status as usize],
        "method": row.method.map(|m| METHODS[m as usize]),
        "score": row.method.map(|_| (row.score * 1000.0).round() / 1000.0),
        "a": row.a.map(a),
        "b": row.b.map(b),
    });
    if let Some(id) = row.group {
        let (in_a, in_b) = report.groups[id as usize];
        value["group"] = json!({"id": id, "a": in_a, "b": in_b});
    }
    value
}

/// Bytes `value` adds to a pretty-printed document as an element of the
/// top-level `rows` array: its own pretty text, indented four more spaces on
/// every line, and a separator.
fn pretty_row_bytes(value: &Value) -> usize {
    let text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.len() + 4 * (text.matches('\n').count() + 1) + 2
}

fn render(report: &Report, page: &Page) -> Result<Value> {
    let selected = |row: &&Row| {
        page.statuses.as_ref().is_none_or(|names| {
            names
                .iter()
                .any(|name| name == STATUSES[row.status as usize])
        })
    };
    let total = report.rows.iter().filter(selected).count();
    if page.offset > total {
        return Err(Error::bad("row_offset exceeds the row count"));
    }
    let document = |rows: Vec<Value>| {
        let next = page.offset + rows.len();
        json!({
            "schema": "wasm-module-diff-v1",
            "fingerprint_version": FINGERPRINT_VERSION,
            "artifact_id": report.a["artifact_id"],
            "compare_artifact_id": report.b["artifact_id"],
            "status": if report.complete { "complete" } else { "partial" },
            "a": report.a,
            "b": report.b,
            "summary": report.summary,
            "requested_statuses": page.statuses,
            "row_window": {
                "offset": page.offset,
                "rows": rows.len(),
                "total_rows": total,
                "next_offset": if next < total { json!(next) } else { Value::Null },
            },
            "rows": rows,
            "omissions": report.omissions,
            "limits": {
                "max_module_bytes": MAX_BYTES,
                "max_functions": MAX_FUNCTIONS,
                "max_body_bytes": MAX_BODY_BYTES,
                "max_comparisons": MAX_COMPARISONS,
                "max_candidates_per_function": MAX_CANDIDATES,
                "max_neighbourhood": MAX_NEIGHBOURHOOD,
                "deadline_ms": DEADLINE.as_millis() as u64,
                "max_page_rows": PAGE_MAX_ROWS,
                "page_bytes": PAGE_BYTES,
                "similarity_threshold": SIMILARITY_THRESHOLD,
                "tie_margin": TIE_MARGIN,
                "min_address": MIN_ADDRESS,
            },
            "notice": "Static comparison of declared function bodies. A match is a correspondence hypothesis with its method and score, not proof of equal behavior. Neither module was executed.",
        })
    };
    let pretty =
        |value: &Value| serde_json::to_string_pretty(value).map_or(usize::MAX, |t| t.len());
    let mut budget = PAGE_BYTES.saturating_sub(pretty(&document(Vec::new())));
    let mut kept = Vec::new();
    for row in report
        .rows
        .iter()
        .filter(selected)
        .skip(page.offset)
        .take(page.limit)
    {
        let value = row_json(report, row);
        let size = pretty_row_bytes(&value);
        if !kept.is_empty() && size > budget {
            break;
        }
        budget = budget.saturating_sub(size);
        kept.push(value);
    }
    // The estimate is exact for rows; this only guards the window numbers,
    // which grow by a digit or two with the row count.
    let mut built = document(kept.clone());
    while kept.len() > 1 && pretty(&built) > PAGE_BYTES {
        kept.pop();
        built = document(kept.clone());
    }
    Ok(built)
}

static REPORTS: Mutex<Vec<(String, Arc<Report>)>> = Mutex::new(Vec::new());

fn record(artifacts: &[Value], id: &str) -> Result<Value> {
    validation::canonical(&json!(id), 64, true, "Artifact ID")?;
    let record = artifacts
        .iter()
        .find(|a| a["artifact_id"] == id)
        .cloned()
        .ok_or_else(|| Error::new(404, "Artifact not found"))?;
    if record["kind"] != "wasm" {
        return Err(Error::bad("Artifact is not WebAssembly"));
    }
    Ok(record)
}

/// Compares two captured modules and returns one page of the match table.
///
/// `started` is when the request arrived, before it waited for a reader, so
/// the deadline bounds the whole request. A complete report is cached in this
/// process by both artifact IDs and SHA-256 digests, so paging the same pair
/// does not repeat the comparison; a partial one is not, so a retry gets a
/// fresh attempt. The native helper is a new process per page, so it has no
/// such cache.
pub fn diff(root: &Path, a_id: &str, b_id: &str, page: &Page, started: Instant) -> Result<Value> {
    diff_with(root, a_id, b_id, page, Limits::DEFAULT, started)
}

fn diff_with(
    root: &Path,
    a_id: &str,
    b_id: &str,
    page: &Page,
    limits: Limits,
    started: Instant,
) -> Result<Value> {
    if a_id == b_id {
        return Err(Error::bad("Compare two different artifacts"));
    }
    let artifacts = evidence::artifacts(root, 10000)?;
    let a = record(&artifacts, a_id)?;
    let b = record(&artifacts, b_id)?;
    // The store is part of the key: two stores can hold the same IDs.
    let key = format!(
        "{}:{a_id}:{}:{b_id}:{}",
        root.display(),
        a["sha256"],
        b["sha256"]
    );
    let cached = REPORTS.lock().ok().and_then(|reports| {
        reports
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, r)| r.clone())
    });
    let report = match cached {
        Some(report) => report,
        None => {
            let a_bytes = evidence::content(root, &a, MAX_BYTES)?;
            let b_bytes = evidence::content(root, &b, MAX_BYTES)?;
            let meta = |record: &Value, bytes: &[u8]| {
                json!({"artifact_id": record["artifact_id"], "sha256": record["sha256"],
                    "session_id": record["session_id"], "byte_size": bytes.len()})
            };
            let report = Arc::new(compare_with(
                &a_bytes,
                &b_bytes,
                meta(&a, &a_bytes),
                meta(&b, &b_bytes),
                limits,
                started,
            )?);
            if report.complete
                && let Ok(mut reports) = REPORTS.lock()
            {
                reports.retain(|(k, _)| *k != key);
                reports.push((key, report.clone()));
                while reports.len() > CACHED_REPORTS {
                    reports.remove(0);
                }
            }
            report
        }
    };
    render(&report, page)
}

#[cfg(test)]
mod tests;
