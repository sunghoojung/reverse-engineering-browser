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
/// Similarity scores computed in the structural pass, across all functions.
const MAX_COMPARISONS: u64 = 4_000_000;
/// Nearest-size candidates scored for one function in the structural pass.
const MAX_CANDIDATES: usize = 64;
const MAX_PROPAGATION_ROUNDS: usize = 16;
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
const MAX_AMBIGUOUS_CANDIDATES: usize = 16;
const MAX_NAME_BYTES: usize = 128;
const MAX_TYPE_TEXT: usize = 256;
pub const PAGE_MAX_ROWS: usize = 1000;
pub const PAGE_DEFAULT_ROWS: usize = 200;
/// One page always fits a 128 KiB MCP result, as for inspection row windows.
const PAGE_BYTES: usize = 98_304;
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

/// The histogram class of one operator (see `CATEGORIES`).
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
            } else if name.starts_with("v128")
                || name.starts_with("i8x16")
                || name.starts_with("i16x8")
                || name.starts_with("i32x4")
                || name.starts_with("i64x2")
                || name.starts_with("f32x4")
                || name.starts_with("f64x2")
            {
                13
            } else if name.contains("load") {
                6
            } else if name.contains("store") {
                7
            } else if name.starts_with("br_on") {
                1
            } else if name.contains("convert")
                || name.contains("trunc")
                || name.contains("extend")
                || name.contains("wrap")
                || name.contains("demote")
                || name.contains("promote")
                || name.contains("reinterpret")
            {
                12
            } else if ["eqz", "_eq", "_ne", "_lt", "_gt", "_le", "_ge"]
                .iter()
                .any(|suffix| name.ends_with(suffix) || name.contains(&format!("{suffix}_")))
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

struct Func {
    index: u32,
    import: Option<(String, String)>,
    start: usize,
    end: usize,
    ty: u32,
    signature: u64,
    export: Option<String>,
    section_name: Option<String>,
    body: [u8; 16],
    normalized: u64,
    structure: u64,
    shape: Shape,
    calls: Vec<u32>,
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

struct Context<'a> {
    bytes: &'a [u8],
    func_types: &'a [u32],
    signatures: &'a [u64],
    params: &'a [Vec<ValType>],
    globals: &'a [u64],
    span: Option<(u64, u64)>,
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
    fn block(&self, ty: BlockType) -> u64 {
        match ty {
            BlockType::Empty => 0,
            BlockType::Type(value) => fnv(value.to_string().as_bytes()),
            BlockType::FuncType(index) => self.signature_of_type(index),
        }
    }
}

/// Scratch buffers reused across functions so a body costs no allocation per
/// instruction.
#[derive(Default)]
struct Scratch {
    local_ids: Vec<u32>,
    touched: Vec<u32>,
    local_types: Vec<u64>,
    globals: Vec<(u32, u32)>,
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
    structure: u64,
    shape: Shape,
    calls: Vec<u32>,
}

/// Both fingerprints and the call list of one body. The normalized hash takes
/// each instruction's original bytes, except that it rewrites the immediates
/// that only renumber or relocate (see the contract for the exact list).
fn fingerprint(
    body: &FunctionBody<'_>,
    ty: u32,
    context: &Context<'_>,
    scratch: &mut Scratch,
) -> Result<Print> {
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
    scratch.touched.clear();
    scratch.globals.clear();
    let mut next_local = parameters;
    let mut normalized = Sha256::new();
    normalized.update(signature.to_le_bytes());
    for (tag, count) in &declared {
        normalized.update(tag.to_le_bytes());
        normalized.update(count.to_le_bytes());
    }
    let mut shape = Shape::default();
    let mut skeleton = Vec::new();
    let mut calls = Vec::new();
    let mut reader = body.get_operators_reader().map_err(bad)?;
    while !reader.eof() {
        let (op, offset) = reader.read_with_offset().map_err(bad)?;
        let end = reader.original_position();
        shape.instructions += 1;
        let name = wasm::operator_name(&op);
        shape.histogram[category(&op, name)] += 1;
        let mut local = |index: u32| -> u64 {
            if index < parameters {
                u64::from(index)
            } else if (index as usize) < total {
                let slot = &mut scratch.local_ids[index as usize];
                if *slot == NONE {
                    *slot = next_local;
                    next_local += 1;
                    scratch.touched.push(index);
                }
                u64::from(*slot)
            } else {
                // Past the declared locals: invalid, kept verbatim and marked.
                u64::from(index) | 1 << 40
            }
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
                let id = local(*local_index);
                let tag = scratch
                    .local_types
                    .get(*local_index as usize)
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
                let id = match scratch.globals.iter().find(|(g, _)| g == global_index) {
                    Some((_, id)) => *id,
                    None => {
                        let id = scratch.globals.len() as u32;
                        scratch.globals.push((*global_index, id));
                        id
                    }
                };
                let tag = context
                    .globals
                    .get(*global_index as usize)
                    .copied()
                    .unwrap_or(0);
                token(&mut normalized, kind, &[u64::from(id), tag]);
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
                } else {
                    normalized.update([0]);
                    normalized.update(&context.bytes[offset..end]);
                }
            }
            Operator::I64Const { value } => {
                if context.address(*value as u64) {
                    token(&mut normalized, 19, &[]);
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
            skeleton.push(mark);
            match mark {
                b'B' | b'I' | b'T' => shape.blocks += 1,
                b'L' => shape.loops += 1,
                b'b' | b'c' | b't' | b'r' => shape.branches += 1,
                _ => {}
            }
        }
    }
    reader.finish().map_err(bad)?;
    for index in scratch.touched.drain(..) {
        scratch.local_ids[index as usize] = NONE;
    }
    shape.skeleton = fnv(&skeleton);
    shape.calls = calls.len() as u32;
    let mut distinct = calls.clone();
    distinct.sort_unstable();
    distinct.dedup();
    shape.callees = distinct.len() as u32;
    let structure = structure_fingerprint(signature, &shape);
    Ok(Print {
        body: body_hash,
        normalized: first8(&normalized.finalize()),
        structure,
        shape,
        calls,
    })
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

/// Decodes one module's function tables and fingerprints every body.
fn analyze(
    bytes: &[u8],
    label: &str,
    started: Instant,
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
    let mut span: Option<(u64, u64)> = None;
    let mut declared = 0u32;
    for payload in Parser::new(0).parse_all(bytes) {
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
                    let (offset, import) = entry.map_err(bad)?;
                    match import.ty {
                        TypeRef::Func(ty) => {
                            func_types.push(ty);
                            imports.push((offset, bounded(import.module), bounded(import.name)));
                        }
                        TypeRef::Global(global) => {
                            globals
                                .push(fnv(format!("{} {}", global.content_type, global.mutable)
                                    .as_bytes()))
                        }
                        _ => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                declared = reader.count();
                for ty in reader {
                    func_types.push(ty.map_err(bad)?);
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let global = global.map_err(bad)?;
                    globals.push(fnv(format!(
                        "{} {}",
                        global.ty.content_type, global.ty.mutable
                    )
                    .as_bytes()));
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
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
            Payload::CodeSectionEntry(body) => bodies.push(body),
            Payload::DataSection(reader) => {
                for data in reader {
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
                            let end = start.saturating_add(data.data.len() as u64);
                            span = Some(span.map_or((start, end), |(low, high)| {
                                (low.min(start), high.max(end))
                            }));
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
    if bodies.len() as u32 != declared {
        return Err(Error::protocol("WASM function bodies are missing"));
    }
    let imported = imports.len() as u32;
    let context = Context {
        bytes,
        func_types: &func_types,
        signatures: &signatures,
        params: &params,
        globals: &globals,
        span,
    };
    let total = imports.len() + bodies.len();
    let mut truncated = false;
    if total > MAX_FUNCTIONS {
        truncated = true;
        omissions.push(format!(
            "Module {label} has {total} functions; only the first {MAX_FUNCTIONS} were compared."
        ));
    }
    let mut funcs = Vec::with_capacity(total.min(MAX_FUNCTIONS));
    for (index, (offset, module, field)) in imports.into_iter().enumerate() {
        if funcs.len() >= MAX_FUNCTIONS {
            break;
        }
        let ty = func_types[index];
        funcs.push(Func {
            index: index as u32,
            import: Some((module, field)),
            start: offset,
            end: offset,
            ty,
            signature: context.signature_of_type(ty),
            export: exports.remove(&(index as u32)),
            section_name: names.remove(&(index as u32)),
            body: [0; 16],
            normalized: 0,
            structure: 0,
            shape: Shape::default(),
            calls: Vec::new(),
        });
    }
    let mut scratch = Scratch::default();
    for (position, body) in bodies.iter().enumerate() {
        if funcs.len() >= MAX_FUNCTIONS {
            break;
        }
        if position.is_multiple_of(64) && started.elapsed() > DEADLINE {
            truncated = true;
            omissions.push(format!(
                "Fingerprinting stopped at the deadline; module {label} functions from index {} on were not compared.",
                imported as usize + position
            ));
            break;
        }
        let index = imported + position as u32;
        let ty = func_types[index as usize];
        let print = fingerprint(body, ty, &context, &mut scratch)?;
        let range = body.range();
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
            structure: print.structure,
            shape: print.shape,
            calls: print.calls,
        });
    }
    let mut callers = vec![Vec::new(); funcs.len()];
    for func in &funcs {
        for target in &func.calls {
            if let Some(list) = callers.get_mut(*target as usize)
                && list.last() != Some(&func.index)
            {
                list.push(func.index);
            }
        }
    }
    for list in &mut callers {
        list.sort_unstable();
        list.dedup();
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

#[derive(Clone)]
struct Row {
    status: u8,
    method: Option<u8>,
    score: f64,
    a: Option<u32>,
    b: Option<u32>,
    candidates_a: Vec<u32>,
    candidates_b: Vec<u32>,
    candidates_truncated: bool,
}

struct Matcher<'m> {
    a: &'m Module,
    b: &'m Module,
    a_to_b: Vec<u32>,
    b_to_a: Vec<u32>,
    method: Vec<(u8, f64)>,
    grouped_a: Vec<bool>,
    grouped_b: Vec<bool>,
    groups: Vec<Row>,
    started: Instant,
    comparisons: u64,
    stopped: Option<String>,
}

impl<'m> Matcher<'m> {
    fn new(a: &'m Module, b: &'m Module, started: Instant) -> Self {
        Self {
            a,
            b,
            a_to_b: vec![NONE; a.funcs.len()],
            b_to_a: vec![NONE; b.funcs.len()],
            method: vec![(0, 0.0); a.funcs.len()],
            grouped_a: vec![false; a.funcs.len()],
            grouped_b: vec![false; b.funcs.len()],
            groups: Vec::new(),
            started,
            comparisons: 0,
            stopped: None,
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
    fn late(&mut self, phase: &str) -> bool {
        if self.stopped.is_none() && self.started.elapsed() > DEADLINE {
            self.stopped = Some(format!(
                "Matching stopped at the deadline during {phase}; unmatched functions are unclassified."
            ));
        }
        self.stopped.is_some()
    }
    fn score(&self, a: u32, b: u32) -> f64 {
        similarity(
            &self.a.funcs[a as usize].shape,
            &self.b.funcs[b as usize].shape,
        )
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
    ) -> usize {
        let mut made = 0;
        for (_, (a, b)) in self.groups_by(key) {
            if a.len() == 1 && b.len() == 1 {
                let score = match method {
                    BY_BYTES | BY_NORMALIZED => 1.0,
                    _ => self.score(a[0], b[0]),
                };
                self.pair(a[0], b[0], method, score);
                made += 1;
            }
        }
        made
    }
    fn exact_passes(&mut self) -> usize {
        let defined = |f: &Func| f.import.is_none();
        let mut made = self.exact(BY_IMPORT, |f| f.import.clone());
        made += self.exact(BY_BYTES, |f| defined(f).then_some(f.body));
        made += self.exact(BY_NORMALIZED, |f| defined(f).then_some(f.normalized));
        made += self.exact(BY_EXPORT, |f| {
            defined(f).then(|| f.export.clone()).flatten()
        });
        made += self.exact(BY_NAME, |f| {
            defined(f).then(|| f.section_name.clone()).flatten()
        });
        made
    }
    /// Carries matches along the call graph. A matched pair with the same
    /// number of call sites proposes its k-th callee pairs; a matched pair
    /// with exactly one open callee, or one open caller, on each side
    /// proposes that pair. A function proposed for two partners is left open.
    fn propagate(&mut self) -> usize {
        let mut made = 0;
        for _ in 0..MAX_PROPAGATION_ROUNDS {
            if self.late("call-graph propagation") {
                break;
            }
            let mut by_a = HashMap::<u32, u32>::new();
            let mut by_b = HashMap::<u32, u32>::new();
            let mut conflicted_a = std::collections::HashSet::new();
            let mut conflicted_b = std::collections::HashSet::new();
            let mut propose = |x: u32, y: u32, this: &Self| {
                if !this.open_a(x)
                    || !this.open_b(y)
                    || this.a.funcs[x as usize].signature != this.b.funcs[y as usize].signature
                {
                    return;
                }
                if *by_a.entry(x).or_insert(y) != y {
                    conflicted_a.insert(x);
                }
                if *by_b.entry(y).or_insert(x) != x {
                    conflicted_b.insert(y);
                }
            };
            for (a, b) in self.a_to_b.iter().enumerate() {
                if *b == NONE {
                    continue;
                }
                let (fa, fb) = (&self.a.funcs[a], &self.b.funcs[*b as usize]);
                if fa.calls.len() == fb.calls.len() {
                    for (x, y) in fa.calls.iter().zip(&fb.calls) {
                        propose(*x, *y, self);
                    }
                }
                let lone = |list: &[u32], open: &dyn Fn(u32) -> bool| {
                    let mut found = None;
                    for index in list {
                        if open(*index) {
                            if found.is_some_and(|f| f != *index) {
                                return None;
                            }
                            found = Some(*index);
                        }
                    }
                    found
                };
                let open_a = |i: u32| self.open_a(i);
                let open_b = |i: u32| self.open_b(i);
                if let (Some(x), Some(y)) = (lone(&fa.calls, &open_a), lone(&fb.calls, &open_b)) {
                    propose(x, y, self);
                }
                if let (Some(x), Some(y)) = (
                    lone(&self.a.callers[a], &open_a),
                    lone(&self.b.callers[*b as usize], &open_b),
                ) {
                    propose(x, y, self);
                }
            }
            let mut accepted = Vec::new();
            for (x, y) in &by_a {
                if conflicted_a.contains(x) || conflicted_b.contains(y) || by_b.get(y) != Some(x) {
                    continue;
                }
                let score = self.score(*x, *y);
                if score >= PROPAGATION_FLOOR {
                    accepted.push((*x, *y, score));
                }
            }
            if accepted.is_empty() {
                break;
            }
            for (x, y, score) in accepted {
                self.pair(x, y, BY_CALL_GRAPH, score);
                made += 1;
            }
        }
        made
    }
    fn fixpoint(&mut self) {
        loop {
            let made = self.exact_passes() + self.propagate();
            if made == 0 || self.late("exact matching") {
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
        let truncated = a.len() > MAX_AMBIGUOUS_CANDIDATES || b.len() > MAX_AMBIGUOUS_CANDIDATES;
        a.truncate(MAX_AMBIGUOUS_CANDIDATES);
        b.truncate(MAX_AMBIGUOUS_CANDIDATES);
        self.groups.push(Row {
            status: AMBIGUOUS,
            method: Some(method),
            score,
            a: None,
            b: None,
            candidates_a: a,
            candidates_b: b,
            candidates_truncated: truncated,
        });
    }
    /// Scores open functions of the same signature against the nearest-size
    /// candidates on the other side. Only a mutual best with a margin over
    /// every runner-up becomes a match; a tie becomes an ambiguous group.
    fn structural(&mut self) {
        let (module_a, module_b) = (self.a, self.b);
        let ties = self.exact_ties();
        let mut excluded_a = vec![false; self.a.funcs.len()];
        let mut excluded_b = vec![false; self.b.funcs.len()];
        for (_, a, b) in &ties {
            for index in a {
                excluded_a[*index as usize] = true;
            }
            for index in b {
                excluded_b[*index as usize] = true;
            }
        }
        let mut buckets = HashMap::<u64, Vec<u32>>::new();
        for func in &module_b.funcs {
            if func.import.is_none() && self.open_b(func.index) && !excluded_b[func.index as usize]
            {
                buckets.entry(func.signature).or_default().push(func.index);
            }
        }
        for list in buckets.values_mut() {
            list.sort_by_key(|index| (module_b.funcs[*index as usize].shape.instructions, *index));
        }
        // For each open A function: its best B, the B candidates tied with
        // it, and the runner-up score.
        let mut best_a: Vec<(u32, f64, f64, Vec<u32>)> = Vec::new();
        // For each B function: the best A claimant and the runner-up score.
        let mut claims = HashMap::<u32, (u32, f64, f64, Vec<u32>)>::new();
        'functions: for func in &module_a.funcs {
            if func.import.is_some() || !self.open_a(func.index) || excluded_a[func.index as usize]
            {
                continue;
            }
            if self.late("structural matching") {
                break;
            }
            let Some(list) = buckets.get(&func.signature) else {
                continue;
            };
            let size = func.shape.instructions;
            let size_of = |index: u32| module_b.funcs[index as usize].shape.instructions;
            let mid = list.partition_point(|index| size_of(*index) < size);
            let (mut low, mut high) = (mid, mid);
            let mut chosen = Vec::with_capacity(MAX_CANDIDATES);
            while chosen.len() < MAX_CANDIDATES && (low > 0 || high < list.len()) {
                let below = (low > 0).then(|| size - size_of(list[low - 1]).min(size));
                let above = (high < list.len()).then(|| size_of(list[high]).saturating_sub(size));
                match (below, above) {
                    (Some(d), Some(u)) if d <= u => {
                        low -= 1;
                        chosen.push(list[low]);
                    }
                    (Some(_), None) => {
                        low -= 1;
                        chosen.push(list[low]);
                    }
                    (_, Some(_)) => {
                        chosen.push(list[high]);
                        high += 1;
                    }
                    (None, None) => break,
                }
            }
            let mut scored = Vec::with_capacity(chosen.len());
            for candidate in chosen {
                if self.comparisons >= MAX_COMPARISONS {
                    self.stopped = Some(format!(
                        "The structural pass reached its {MAX_COMPARISONS} comparison limit; unmatched functions are unclassified."
                    ));
                    break 'functions;
                }
                self.comparisons += 1;
                scored.push((candidate, self.score(func.index, candidate)));
            }
            scored.sort_by(|x, y| y.1.total_cmp(&x.1).then(x.0.cmp(&y.0)));
            let Some(&(_, score)) = scored.first() else {
                continue;
            };
            let runner = scored.get(1).map_or(0.0, |s| s.1);
            let tied = scored
                .iter()
                .filter(|s| score - s.1 < TIE_MARGIN)
                .map(|s| s.0)
                .collect::<Vec<_>>();
            for (candidate, value) in &scored {
                let entry =
                    claims
                        .entry(*candidate)
                        .or_insert((func.index, *value, 0.0, Vec::new()));
                if entry.0 == func.index {
                    continue;
                }
                if *value > entry.1 {
                    entry.2 = entry.1;
                    entry.0 = func.index;
                    entry.1 = *value;
                } else if *value > entry.2 {
                    entry.2 = *value;
                }
            }
            best_a.push((func.index, score, runner, tied));
        }
        // Claimants tied for one B function, collected for its group.
        let mut b_ties = HashMap::<u32, Vec<u32>>::new();
        for (a, score, _, tied) in &best_a {
            for b in tied {
                if let Some(claim) = claims.get(b)
                    && claim.1 - score < TIE_MARGIN
                {
                    b_ties.entry(*b).or_default().push(*a);
                }
            }
        }
        let mut accepted = Vec::new();
        let mut ambiguous = Vec::new();
        for (a, score, runner, tied) in best_a {
            if score < SIMILARITY_THRESHOLD {
                continue;
            }
            let b = tied[0];
            let claim = &claims[&b];
            let alone_a = score - runner >= TIE_MARGIN;
            let alone_b = claim.0 == a && claim.1 - claim.2 >= TIE_MARGIN;
            if alone_a && alone_b {
                accepted.push((a, b, score));
            } else if claim.0 == a || tied.len() > 1 {
                let mut others = b_ties.get(&b).cloned().unwrap_or_default();
                if !others.contains(&a) {
                    others.push(a);
                }
                ambiguous.push((score, others, tied));
            }
        }
        for (a, b, score) in accepted {
            self.pair(a, b, BY_STRUCTURE, score);
        }
        for (score, a, b) in ambiguous {
            let a = a
                .into_iter()
                .filter(|i| self.open_a(*i))
                .collect::<Vec<_>>();
            let b = b
                .into_iter()
                .filter(|i| self.open_b(*i))
                .collect::<Vec<_>>();
            if !a.is_empty() && !b.is_empty() {
                self.group(BY_STRUCTURE, score, a, b);
            }
        }
    }
    fn run(mut self) -> (Vec<Row>, Option<String>, u64) {
        self.fixpoint();
        if self.stopped.is_none() {
            self.structural();
        }
        if self.stopped.is_none() {
            self.fixpoint();
        }
        for (method, a, b) in self.exact_ties() {
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
        let unknown = self.stopped.is_some() || self.a.truncated || self.b.truncated;
        let mut rows = std::mem::take(&mut self.groups);
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
                (Some(_), Some(_)) if fa.signature == fb.signature => IDENTICAL,
                (Some(_), Some(_)) => CHANGED,
                _ if fa.body == fb.body => IDENTICAL,
                _ if fa.normalized == fb.normalized => RENUMBERED,
                _ => CHANGED,
            };
            rows.push(Row {
                status,
                method: Some(method),
                score,
                a: Some(fa.index),
                b: Some(fb.index),
                candidates_a: Vec::new(),
                candidates_b: Vec::new(),
                candidates_truncated: false,
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
                row.a.or(row.candidates_a.first().copied()).unwrap_or(NONE),
                row.b.or(row.candidates_b.first().copied()).unwrap_or(NONE),
            )
        });
        (rows, self.stopped, self.comparisons)
    }
}

fn single(status: u8, a: Option<u32>, b: Option<u32>) -> Row {
    Row {
        status,
        method: None,
        score: 0.0,
        a,
        b,
        candidates_a: Vec::new(),
        candidates_b: Vec::new(),
        candidates_truncated: false,
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
            import: f.import,
            ty: f.ty,
            instructions: f.shape.instructions,
            normalized: f.normalized,
            structure: f.structure,
        })
        .collect();
    (sides, module.type_text)
}

fn compare(a_bytes: &[u8], b_bytes: &[u8], a: Value, b: Value) -> Result<Report> {
    let started = Instant::now();
    let mut omissions = Vec::new();
    let module_a = analyze(a_bytes, "A", started, &mut omissions)?;
    let module_b = analyze(b_bytes, "B", started, &mut omissions)?;
    if module_a.funcs.is_empty() || module_b.funcs.is_empty() {
        omissions.push(
            "A module declares no functions, so every function of the other is added or removed."
                .into(),
        );
    }
    let (rows, stopped, comparisons) = Matcher::new(&module_a, &module_b, started).run();
    omissions.extend(stopped);
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
        "comparisons": comparisons,
        "elapsed_ms": started.elapsed().as_millis() as u64,
    });
    let complete = omissions.is_empty();
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
    if row.status == AMBIGUOUS {
        value["candidates"] = json!({
            "a": row.candidates_a.iter().map(|i| a(*i)).collect::<Vec<_>>(),
            "b": row.candidates_b.iter().map(|i| b(*i)).collect::<Vec<_>>(),
            "truncated": row.candidates_truncated,
        });
    }
    value
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
    let mut kept = Vec::new();
    let mut bytes = 0usize;
    for row in report
        .rows
        .iter()
        .filter(selected)
        .skip(page.offset)
        .take(page.limit)
    {
        let value = row_json(report, row);
        let size = serde_json::to_vec(&value).map_or(usize::MAX, |encoded| encoded.len() + 1);
        if !kept.is_empty() && bytes + size > PAGE_BYTES {
            break;
        }
        bytes += size;
        kept.push(value);
    }
    let next = page.offset + kept.len();
    Ok(json!({
        "schema": "wasm-module-diff-v1",
        "fingerprint_version": FINGERPRINT_VERSION,
        "artifact_id": report.a["artifact_id"],
        "compare_artifact_id": report.b["artifact_id"],
        "status": if report.complete { "complete" } else { "partial" },
        "a": report.a,
        "b": report.b,
        "summary": report.summary,
        "requested_statuses": page.statuses,
        "rows": kept,
        "row_window": {
            "offset": page.offset,
            "rows": next - page.offset,
            "total_rows": total,
            "next_offset": if next < total { json!(next) } else { Value::Null },
        },
        "omissions": report.omissions,
        "limits": {
            "max_module_bytes": MAX_BYTES,
            "max_functions": MAX_FUNCTIONS,
            "max_body_bytes": MAX_BODY_BYTES,
            "max_comparisons": MAX_COMPARISONS,
            "max_candidates_per_function": MAX_CANDIDATES,
            "max_ambiguous_candidates": MAX_AMBIGUOUS_CANDIDATES,
            "deadline_ms": DEADLINE.as_millis() as u64,
            "max_page_rows": PAGE_MAX_ROWS,
            "page_bytes": PAGE_BYTES,
            "similarity_threshold": SIMILARITY_THRESHOLD,
            "tie_margin": TIE_MARGIN,
            "min_address": MIN_ADDRESS,
        },
        "notice": "Static comparison of declared function bodies. A match is a correspondence hypothesis with its method and score, not proof of equal behavior. Neither module was executed.",
    }))
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
/// A report is cached by both artifact IDs and SHA-256 digests, so paging the
/// same pair does not repeat the comparison.
pub fn diff(root: &Path, a_id: &str, b_id: &str, page: &Page) -> Result<Value> {
    if a_id == b_id {
        return Err(Error::bad("Compare two different artifacts"));
    }
    let artifacts = evidence::artifacts(root, 10000)?;
    let a = record(&artifacts, a_id)?;
    let b = record(&artifacts, b_id)?;
    let key = format!("{a_id}:{}:{b_id}:{}", a["sha256"], b["sha256"]);
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
            let report = Arc::new(compare(
                &a_bytes,
                &b_bytes,
                meta(&a, &a_bytes),
                meta(&b, &b_bytes),
            )?);
            if let Ok(mut reports) = REPORTS.lock() {
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
mod tests {
    use super::*;

    fn report(a: &str, b: &str) -> Report {
        let a = wat::parse_str(a).unwrap();
        let b = wat::parse_str(b).unwrap();
        compare(
            &a,
            &b,
            json!({"artifact_id":"1"}),
            json!({"artifact_id":"2"}),
        )
        .unwrap()
    }
    type Found = (String, Option<String>, Option<u32>, Option<u32>);

    fn rows(report: &Report) -> Vec<Found> {
        report
            .rows
            .iter()
            .map(|row| {
                (
                    STATUSES[row.status as usize].to_owned(),
                    row.method.map(|m| METHODS[m as usize].to_owned()),
                    row.a,
                    row.b,
                )
            })
            .collect()
    }
    fn row(status: &str, method: Option<&str>, a: Option<u32>, b: Option<u32>) -> Found {
        (status.into(), method.map(Into::into), a, b)
    }

    #[test]
    fn renumbered_calls_locals_and_data_addresses_normalize_to_the_same_hash() {
        // B inserts an import and a helper, so every call index shifts, and
        // moves its static data, so the address constant changes.
        let a = r#"(module (memory 1) (data (i32.const 2048) "hello")
            (func $leaf (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
            (func $root (export "root") (param i32) (result i32) (local i32 i64)
              local.get 0 call $leaf local.set 1 i32.const 2048 i32.load local.get 1 i32.add))"#;
        let b = r#"(module (import "env" "log" (func $log (param i32))) (memory 1)
            (data (i32.const 4096) "hello")
            (func $extra (param f64) (result f64) local.get 0)
            (func $leaf (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
            (func $root (export "root") (param i32) (result i32) (local i64 i32)
              local.get 0 call $leaf local.set 2 i32.const 4096 i32.load local.get 2 i32.add))"#;
        let report = report(a, b);
        let found = rows(&report);
        assert!(
            found.contains(&row("identical", Some("identical"), Some(0), Some(2))),
            "{found:?}"
        );
        assert!(
            found.contains(&row("renumbered", Some("normalized"), Some(1), Some(3))),
            "{found:?}"
        );
        assert!(
            found.contains(&row("added", None, None, Some(0))),
            "{found:?}"
        );
        assert!(
            found.contains(&row("added", None, None, Some(1))),
            "{found:?}"
        );
        assert!(report.complete);
    }

    #[test]
    fn changed_bodies_match_by_export_call_graph_and_structure() {
        // Unnamed functions: wat would otherwise emit a name section.
        let a = r#"(module
            (func (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
            (func (param i32) (result i32) local.get 0 call 0 i32.const 1 i32.add)
            (func (export "run") (param i32) (result i32) local.get 0 call 1 i32.const 7 i32.xor))"#;
        let b = r#"(module
            (func (param i32) (result i32) local.get 0 i32.const 5 i32.mul)
            (func (param i32) (result i32) local.get 0 call 0 i32.const 2 i32.add)
            (func (export "run") (param i32) (result i32) local.get 0 call 1 i32.const 9 i32.xor))"#;
        let found = rows(&report(a, b));
        assert!(
            found.contains(&row("changed", Some("export_name"), Some(2), Some(2))),
            "{found:?}"
        );
        assert!(
            found.contains(&row("changed", Some("call_graph"), Some(1), Some(1))),
            "{found:?}"
        );
        assert!(
            found.contains(&row("changed", Some("call_graph"), Some(0), Some(0))),
            "{found:?}"
        );
    }

    #[test]
    fn name_section_names_match_changed_functions() {
        let a = r#"(module (func $parse (result i32) i32.const 1) (func $emit (param i32)))"#;
        let b = r#"(module (func $emit (param i32)) (func $parse (result i32) i32.const 2))"#;
        let found = rows(&report(a, b));
        assert!(
            found.contains(&row("changed", Some("name"), Some(0), Some(1))),
            "{found:?}"
        );
        assert!(
            found.contains(&row("identical", Some("identical"), Some(1), Some(0))),
            "{found:?}"
        );
    }

    #[test]
    fn identical_twins_stay_ambiguous_instead_of_a_forced_pick() {
        let twin = "(func (result i32) i32.const 42)";
        let a = format!("(module {twin} {twin})");
        let b = format!("(module {twin} {twin} {twin})");
        let report = report(&a, &b);
        assert_eq!(report.rows.len(), 1, "{:?}", rows(&report));
        let group = &report.rows[0];
        assert_eq!(group.status, AMBIGUOUS);
        assert_eq!(group.method, Some(BY_BYTES));
        assert_eq!(group.candidates_a, vec![0, 1]);
        assert_eq!(group.candidates_b, vec![0, 1, 2]);
    }

    #[test]
    fn imports_match_by_name_and_report_a_signature_change() {
        let a = r#"(module (import "env" "f" (func (param i32))) (import "env" "g" (func)))"#;
        let b = r#"(module (import "env" "g" (func)) (import "env" "f" (func (param i64))))"#;
        let found = rows(&report(a, b));
        assert!(
            found.contains(&row("changed", Some("import_name"), Some(0), Some(1))),
            "{found:?}"
        );
        assert!(
            found.contains(&row("identical", Some("import_name"), Some(1), Some(0))),
            "{found:?}"
        );
    }

    fn fixtures() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/fixtures/wasm-module-diff")
    }

    /// The checked-in builds are exactly what the pinned assembler makes from
    /// their sources, and they keep the rows their README lists. Run
    /// `make wasm-diff-fixtures` after editing a `.wat`.
    #[test]
    fn checked_in_builds_match_their_sources_and_expected_rows() {
        let mut bytes = Vec::new();
        for name in ["build-a", "build-b"] {
            let built = wat::parse_file(fixtures().join(format!("{name}.wat"))).unwrap();
            wasmparser::Validator::new().validate_all(&built).unwrap();
            let checked_in = std::fs::read(fixtures().join(format!("{name}.wasm")))
                .unwrap_or_else(|_| panic!("{name}.wasm is missing; run make wasm-diff-fixtures"));
            assert!(
                built == checked_in,
                "{name}.wasm drifted; run make wasm-diff-fixtures"
            );
            bytes.push(checked_in);
        }
        let report = compare(&bytes[0], &bytes[1], json!({}), json!({})).unwrap();
        assert!(report.complete, "{:?}", report.omissions);
        let found = rows(&report);
        for expected in [
            row("identical", Some("import_name"), Some(0), Some(0)),
            row("added", None, None, Some(1)),
            row("identical", Some("identical"), Some(1), Some(2)),
            row("renumbered", Some("normalized"), Some(2), Some(3)),
            row("changed", Some("call_graph"), Some(3), Some(4)),
            row("renumbered", Some("normalized"), Some(4), Some(5)),
            row("removed", None, Some(5), None),
            row("changed", Some("structural"), Some(8), Some(8)),
            row("added", None, None, Some(9)),
        ] {
            assert!(found.contains(&expected), "{expected:?} not in {found:?}");
        }
        let ambiguous = report
            .rows
            .iter()
            .filter(|r| r.status == AMBIGUOUS)
            .collect::<Vec<_>>();
        assert_eq!(ambiguous.len(), 1);
        assert_eq!(
            (
                ambiguous[0].candidates_a.as_slice(),
                ambiguous[0].candidates_b.as_slice()
            ),
            (&[6, 7][..], &[6, 7][..])
        );
        assert_eq!(report.rows.len(), 10, "{found:?}");
    }

    #[test]
    #[ignore = "writes fixtures; run through make wasm-diff-fixtures"]
    fn write_wasm_diff_fixtures() {
        for name in ["build-a", "build-b"] {
            let built = wat::parse_file(fixtures().join(format!("{name}.wat"))).unwrap();
            std::fs::write(fixtures().join(format!("{name}.wasm")), built).unwrap();
        }
    }

    #[test]
    fn malformed_and_empty_modules_are_named_errors() {
        let error = compare(&[], b"\0asm\x01\0\0\0", json!({}), json!({}))
            .err()
            .unwrap();
        assert_eq!(error.status, 422);
        assert!(error.message.contains("module A is empty"));
        let error = compare(
            b"\0asm\x01\0\0\0\x0a\x05",
            b"\0asm\x01\0\0\0",
            json!({}),
            json!({}),
        )
        .err()
        .unwrap();
        assert_eq!(error.status, 422);
    }

    #[test]
    fn pages_filter_by_status_and_stop_at_the_window() {
        let report = report(
            r#"(module (func (export "x") (result i32) i32.const 1) (func (result i32) i32.const 2))"#,
            r#"(module (func (export "x") (result i32) i32.const 5) (func (param i32)))"#,
        );
        let page = render(
            &report,
            &Page {
                offset: 0,
                limit: 1,
                statuses: Some(vec!["changed".into()]),
            },
        )
        .unwrap();
        assert_eq!(page["rows"].as_array().unwrap().len(), 1);
        assert_eq!(page["rows"][0]["status"], "changed");
        assert_eq!(page["row_window"]["total_rows"], 1);
        assert!(page["row_window"]["next_offset"].is_null());
        let error = render(
            &report,
            &Page {
                offset: 9,
                limit: 1,
                statuses: None,
            },
        )
        .err()
        .unwrap();
        assert_eq!(error.status, 400);
        assert!(requested_statuses("changed,bogus").is_err());
        assert!(requested_statuses("changed,changed").is_err());
    }
}
