//! Offline execution of one function of a captured WebAssembly module.
//!
//! This is the only place captured code runs, and it runs only on an explicit
//! confirmed request: never automatically, never from an analysis. The module
//! bytes are verified against their manifest SHA-256 and executed by `wasmi`,
//! a pure interpreter with fuel metering and no JIT, inside this process.
//! Every import is a stub this file defines, so the module reaches no
//! filesystem, network, clock, randomness or other host state: an import
//! returns only values the request supplied, and otherwise traps. Every call
//! a stub receives is recorded in the result.
//!
//! The interpreter's public API reaches functions only by export name and runs
//! a start function inside instantiation, where no deadline can stop it. So the
//! module is rewritten before compilation: the start section is dropped, and
//! the target function, the start function and memory 0 receive private export
//! names. The rewrite adds and removes whole entries only; the original bytes,
//! their SHA-256 and every byte offset this result reports stay those of the
//! captured artifact. A run is a derived experiment record stored beside the
//! other experiment outputs, never captured evidence.
use crate::{
    error::{Code, Error, Result},
    evidence, validation,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use wasmi::{
    CompilationMode, Config, Engine, Extern, ExternType, F32, F64, Func, FuncType, Global,
    Instance, Memory, Module, Mutability, Nullable, Ref, RefType, ResourceLimiter, ResumableCall,
    Store, Table, TrapCode, V128, Val, ValType, errors::ErrorKind,
};
use wasmi_core::LimiterError;
use wasmparser::{ExternalKind, Parser, Payload, TypeRef};

pub const SCHEMA: &str = "wasm-run-v1";
const STORE_SCHEMA: &str = "reb-wasm-runs-v1";
/// The artifact receiver's default per-artifact limit. A larger module is
/// refused before compilation, which no deadline can interrupt. Compiling
/// takes about 25 to 30 times the module size in memory at its peak (a
/// 6.9 MB body of nested ifs peaked near 320 MB resident), so a module at
/// this cap can need about 480 MB for the length of the run.
pub const MAX_MODULE_BYTES: usize = 16 * 1024 * 1024;
/// Wasm itself allows 1,000 parameters and results per function type.
const MAX_VALUES: usize = 1000;
const MAX_STUBS: usize = 256;
const MAX_SEQUENCE: usize = 256;
const MAX_WRITES: usize = 16;
const MAX_READS: usize = 16;
/// Memory written before the call and read after it, each in total.
pub const MAX_WRITE_BYTES: usize = 256 * 1024;
/// Reads are returned as hex, so 32 KiB of reads is 64 KiB of text: with the
/// rest of a record that still fits the 128 KiB MCP inline limit.
pub const MAX_READ_BYTES: usize = 32 * 1024;
/// A record is trimmed in a fixed order until its pretty-printed JSON fits
/// this, so a whole run result always inlines through `reb-api mcp`.
const RECORD_INLINE_BUDGET: usize = 120 * 1024;
/// Captured import and export names, and messages that quote them, are cut to
/// this many bytes in a record; a module can declare a name of any length.
const MAX_RECORD_NAME: usize = 128;
const MAX_RECORD_MESSAGE: usize = 1024;
const MAX_RECORDED_CALLS: usize = 256;
const MAX_RECORDED_ARGS: usize = 16;
const MAX_RECORDED_RESULTS: usize = 16;
/// A stored record past this is returned but not stored.
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
/// The longest value literal; a float's shortest round-trip form is at most
/// 24 characters and a v128 34.
const MAX_LITERAL: usize = 64;
/// wasmi builds a constant expression as nested closures, one level per
/// operator, and evaluates and drops it recursively. Real modules use one to
/// three operators (a constant, a global, extended-const arithmetic); a long
/// one would overflow the native stack and abort the backend.
const MAX_CONST_OPERATORS: usize = 64;
/// Memories and tables a run instantiates, imported and defined together.
const MAX_MEMORIES: u32 = 16;
/// Element segment items across the module. Instantiation materializes every
/// item, active or passive, and cannot be interrupted, so this bounds it: about
/// 5.6 million items took 4.5 s past a 50 ms deadline. Large real tables hold
/// tens of thousands.
const MAX_ELEMENT_ITEMS: u64 = 262_144;
const MAX_TABLES: u32 = 16;
/// Fuel is granted in slices so the wall-clock deadline is checked between
/// them, and every import call checks it too; a slice is well under a
/// millisecond of interpretation.
const FUEL_SLICE: u64 = 100_000;
const MAX_RUNS: usize = 64;
const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;
const PAGE: u64 = 65_536;
const INTERPRETER: &str = "wasmi";
const INTERPRETER_VERSION: &str = "2.0.0";

/// Default and maximum for each limit. The maxima bound what the module may
/// use while it runs: linear memory and tables up to 64 MiB and 1,000,000
/// elements in total, and 10 s. Compilation memory is bounded separately, by
/// MAX_MODULE_BYTES.
const FUEL: (u64, u64) = (100_000_000, 10_000_000_000);
const MEMORY_PAGES: (u64, u64) = (256, 1024);
const TABLE_ELEMENTS: (u64, u64) = (10_000, 1_000_000);
const CALL_DEPTH: (u64, u64) = (1000, 10_000);
const DEADLINE_MS: (u64, u64) = (2000, 10_000);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Typed {
    #[serde(rename = "type")]
    pub ty: String,
    pub value: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stub {
    pub module: String,
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<Typed>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<Vec<Vec<Typed>>>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryWrite {
    pub offset: u64,
    pub hex: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRead {
    pub offset: u64,
    pub length: u64,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_pages: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_elements: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedMemory {
    pub read: usize,
    pub hex: String,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<Typed>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory: Vec<ExpectedMemory>,
}
/// Field order is fixed, so the serialized request (without the confirmation)
/// is a stable input to `inputs_digest`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub artifact_id: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_index: Option<u32>,
    #[serde(default)]
    pub args: Vec<Typed>,
    #[serde(default)]
    pub imports: Vec<Stub>,
    #[serde(default)]
    pub memory_writes: Vec<MemoryWrite>,
    #[serde(default)]
    pub memory_reads: Vec<MemoryRead>,
    #[serde(default)]
    pub run_start: bool,
    #[serde(default)]
    pub limits: LimitRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Expect>,
    #[serde(default, skip_serializing)]
    pub confirm_offline_execution: Option<bool>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Limits {
    pub fuel: u64,
    pub memory_pages: u64,
    pub table_elements: u64,
    pub call_depth: u64,
    pub deadline_ms: u64,
    pub max_write_bytes: usize,
    pub max_read_bytes: usize,
    pub max_recorded_import_calls: usize,
}

fn limit(value: Option<u64>, (default, maximum): (u64, u64), name: &str) -> Result<u64> {
    match value {
        None => Ok(default),
        Some(0) => Err(Error::bad(format!(
            "WASM run limit {name} must be positive"
        ))),
        Some(value) if value > maximum => Err(Error::bad(format!(
            "WASM run limit {name} exceeds its maximum of {maximum}"
        ))),
        Some(value) => Ok(value),
    }
}

fn decode_hex(text: &str, label: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::bad(format!(
            "{label} must be an even number of hexadecimal digits"
        )));
    }
    hex::decode(text).map_err(|_| Error::bad(format!("{label} is not hexadecimal")))
}

impl Request {
    /// Parses and bounds a request. The confirmation is checked first, so a
    /// request without it is refused before any artifact is read.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Limits)> {
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::bad(format!("Invalid WASM run request: {error}")))?;
        if request.confirm_offline_execution != Some(true) {
            return Err(Error::bad(
                "WASM run refused: confirm_offline_execution must be true. Captured code runs only on an explicit confirmed request. Nothing ran.",
            ));
        }
        validation::canonical(&json!(request.artifact_id), 64, true, "Artifact ID")?;
        if request.sha256.len() != 64
            || !request
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::bad("sha256 must be 64 lowercase hexadecimal digits"));
        }
        if request.export.is_some() == request.function_index.is_some() {
            return Err(Error::bad(
                "A WASM run names exactly one of export or function_index",
            ));
        }
        if request.args.len() > MAX_VALUES {
            return Err(Error::bad("A WASM run takes at most 1000 arguments"));
        }
        for arg in &request.args {
            value(arg)?;
        }
        if request.imports.len() > MAX_STUBS {
            return Err(Error::bad("A WASM run takes at most 256 import stubs"));
        }
        for stub in &request.imports {
            let lists = match (&stub.results, &stub.sequence) {
                (Some(results), None) => vec![results],
                (None, Some(sequence)) if !sequence.is_empty() => {
                    if sequence.len() > MAX_SEQUENCE {
                        return Err(Error::bad(
                            "An import stub sequence has at most 256 entries",
                        ));
                    }
                    sequence.iter().collect()
                }
                _ => {
                    return Err(Error::bad(
                        "An import stub names exactly one of results or a nonempty sequence; an import without a stub traps",
                    ));
                }
            };
            for list in lists {
                if list.len() > MAX_VALUES {
                    return Err(Error::bad("An import stub returns at most 1000 values"));
                }
                for item in list {
                    value(item)?;
                }
            }
        }
        if request.memory_writes.len() > MAX_WRITES || request.memory_reads.len() > MAX_READS {
            return Err(Error::bad(
                "A WASM run takes at most 16 memory writes and 16 memory reads",
            ));
        }
        let mut written = 0usize;
        for write in &request.memory_writes {
            written += decode_hex(&write.hex, "A memory write")?.len();
        }
        if written > MAX_WRITE_BYTES {
            return Err(Error::bad(
                "WASM run memory writes exceed their 256 KiB limit",
            ));
        }
        let read = request
            .memory_reads
            .iter()
            .try_fold(0u64, |total, r| total.checked_add(r.length));
        if read.is_none_or(|total| total > MAX_READ_BYTES as u64) {
            return Err(Error::bad(
                "WASM run memory reads exceed their 32 KiB limit",
            ));
        }
        if request.memory_reads.iter().any(|r| r.length == 0) {
            return Err(Error::bad("A memory read length must be positive"));
        }
        if let Some(expect) = &request.expect {
            for item in expect.results.iter().flatten() {
                value(item)?;
            }
            // One expectation per read bounds the request and its record. It
            // is not a disclosure control: only a caller that may read the
            // run's values (Full access) can run captured code at all.
            let mut named = std::collections::BTreeSet::new();
            for memory in &expect.memory {
                if memory.read >= request.memory_reads.len() {
                    return Err(Error::bad(
                        "An expected memory entry names a read the request does not make",
                    ));
                }
                if !named.insert(memory.read) {
                    return Err(Error::bad(
                        "A WASM run takes at most one expected memory entry per read",
                    ));
                }
                decode_hex(&memory.hex, "Expected memory")?;
            }
        }
        let limits = Limits {
            fuel: limit(request.limits.fuel, FUEL, "fuel")?,
            memory_pages: limit(request.limits.memory_pages, MEMORY_PAGES, "memory_pages")?,
            table_elements: limit(
                request.limits.table_elements,
                TABLE_ELEMENTS,
                "table_elements",
            )?,
            call_depth: limit(request.limits.call_depth, CALL_DEPTH, "call_depth")?,
            deadline_ms: limit(request.limits.deadline_ms, DEADLINE_MS, "deadline_ms")?,
            max_write_bytes: MAX_WRITE_BYTES,
            max_read_bytes: MAX_READ_BYTES,
            max_recorded_import_calls: MAX_RECORDED_CALLS,
        };
        Ok((request, limits))
    }
    fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("WASM run request serializes"),
        ))
    }
}

/// A request value as an interpreter value. Integers accept the signed and
/// unsigned decimal ranges of their width. Floats accept decimal text, `inf`,
/// `-inf`, or `nan:0x...` with an exact bit pattern. A `v128` is one
/// hexadecimal integer with lane 0 in the low bits. References accept only
/// `null`: a request cannot name a host object.
fn value(typed: &Typed) -> Result<Val> {
    let text = typed.value.as_str();
    let bad = || {
        Error::bad(format!(
            "Value is not a valid {} literal",
            typed.ty.chars().take(16).collect::<String>()
        ))
    };
    if text.len() > MAX_LITERAL {
        return Err(Error::bad("A value literal is at most 64 characters"));
    }
    let float_bits = |text: &str| text.strip_prefix("nan:0x").map(|bits| bits.to_owned());
    // Exactly the contract's spellings: Rust's parsers also take a leading
    // `+` and extra leading zeros, which would make two literals of one value.
    let hex_digits = |digits: &str, exact: Option<usize>| {
        !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_hexdigit())
            && exact.is_none_or(|length| digits.len() == length)
    };
    let integer = |text: &str| {
        let digits = text.strip_prefix('-').unwrap_or(text);
        !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'))
    };
    if matches!(typed.ty.as_str(), "i32" | "i64") && !integer(text) {
        return Err(bad());
    }
    Ok(match typed.ty.as_str() {
        "i32" => {
            let wide: i64 = text.parse().map_err(|_| bad())?;
            if !(i64::from(i32::MIN)..=i64::from(u32::MAX)).contains(&wide) {
                return Err(bad());
            }
            Val::I32(wide as u32 as i32)
        }
        "i64" => {
            let wide: i128 = text.parse().map_err(|_| bad())?;
            if !(i128::from(i64::MIN)..=i128::from(u64::MAX)).contains(&wide) {
                return Err(bad());
            }
            Val::I64(wide as u64 as i64)
        }
        "f32" => match float_bits(text) {
            Some(bits) => {
                if !hex_digits(&bits, Some(8)) {
                    return Err(bad());
                }
                let bits = u32::from_str_radix(&bits, 16).map_err(|_| bad())?;
                if !f32::from_bits(bits).is_nan() {
                    return Err(bad());
                }
                Val::F32(F32::from_bits(bits))
            }
            None => Val::F32(F32::from(float::<f32>(text).ok_or_else(bad)?)),
        },
        "f64" => match float_bits(text) {
            Some(bits) => {
                if !hex_digits(&bits, Some(16)) {
                    return Err(bad());
                }
                let bits = u64::from_str_radix(&bits, 16).map_err(|_| bad())?;
                if !f64::from_bits(bits).is_nan() {
                    return Err(bad());
                }
                Val::F64(F64::from_bits(bits))
            }
            None => Val::F64(F64::from(float::<f64>(text).ok_or_else(bad)?)),
        },
        "v128" => {
            let digits = text.strip_prefix("0x").unwrap_or(text);
            if !hex_digits(digits, None) || digits.len() > 32 {
                return Err(bad());
            }
            Val::V128(V128::from(
                u128::from_str_radix(digits, 16).map_err(|_| bad())?,
            ))
        }
        "funcref" if text == "null" => Val::FuncRef(Nullable::Null),
        "externref" if text == "null" => Val::ExternRef(Nullable::Null),
        _ => return Err(bad()),
    })
}

/// The contract's float spellings only: `inf`, `-inf`, or an optionally
/// negative decimal with an optional fraction and exponent. A finite literal
/// that rounds to infinity is refused rather than silently changed.
fn float<T: std::str::FromStr + Into<f64> + Copy>(text: &str) -> Option<T> {
    if text == "inf" || text == "-inf" {
        return text.parse().ok();
    }
    let body = text.strip_prefix('-').unwrap_or(text);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => (&body[..at], Some(&body[at + 1..])),
        None => (body, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty()
        || !digits(whole)
        || !digits(fraction)
        || exponent.is_some_and(|e| {
            let e = e.strip_prefix(['+', '-']).unwrap_or(e);
            e.is_empty() || !digits(e)
        })
    {
        return None;
    }
    let parsed: T = text.parse().ok()?;
    parsed.into().is_finite().then_some(parsed)
}

fn type_name(ty: &ValType) -> &'static str {
    match ty {
        ValType::I32 => "i32",
        ValType::I64 => "i64",
        ValType::F32 => "f32",
        ValType::F64 => "f64",
        ValType::V128 => "v128",
        ValType::FuncRef => "funcref",
        ValType::ExternRef => "externref",
    }
}

/// Debug is the shortest form that round-trips, with an exponent for large
/// and small magnitudes, so `1e300` stays five characters.
fn float_text<T: std::fmt::Debug>(value: T, nan: bool, bits: String) -> String {
    if nan {
        format!("nan:0x{bits}")
    } else {
        format!("{value:?}")
    }
}

/// The inverse of `value`: the same literal forms, so a result can be pasted
/// back as an argument or an expectation.
fn encode(val: &Val) -> Typed {
    let (ty, value) = match val {
        Val::I32(v) => ("i32", v.to_string()),
        Val::I64(v) => ("i64", v.to_string()),
        Val::F32(v) => {
            let f = f32::from(*v);
            (
                "f32",
                float_text(f, f.is_nan(), format!("{:08x}", v.to_bits())),
            )
        }
        Val::F64(v) => {
            let f = f64::from(*v);
            (
                "f64",
                float_text(f, f.is_nan(), format!("{:016x}", v.to_bits())),
            )
        }
        Val::V128(v) => ("v128", format!("0x{:032x}", v.as_u128())),
        Val::FuncRef(r) => ("funcref", reference(r.is_null())),
        Val::ExternRef(r) => ("externref", reference(r.is_null())),
    };
    Typed {
        ty: ty.into(),
        value,
    }
}

fn reference(null: bool) -> String {
    if null {
        "null".into()
    } else {
        "non-null".into()
    }
}

/// Exact equality, by bit pattern for floats.
fn same(left: &Typed, right: &Typed) -> bool {
    match (value(left), value(right)) {
        (Ok(a), Ok(b)) => encode(&a) == encode(&b),
        _ => left == right,
    }
}

fn val_type(val: &Val) -> ValType {
    match val {
        Val::I32(_) => ValType::I32,
        Val::I64(_) => ValType::I64,
        Val::F32(_) => ValType::F32,
        Val::F64(_) => ValType::F64,
        Val::V128(_) => ValType::V128,
        Val::FuncRef(_) => ValType::FuncRef,
        Val::ExternRef(_) => ValType::ExternRef,
    }
}

fn zero(ty: &ValType) -> Val {
    match ty {
        ValType::I32 => Val::I32(0),
        ValType::I64 => Val::I64(0),
        ValType::F32 => Val::F32(F32::from_bits(0)),
        ValType::F64 => Val::F64(F64::from_bits(0)),
        ValType::V128 => Val::V128(V128::from(0u128)),
        ValType::FuncRef => Val::FuncRef(Nullable::Null),
        ValType::ExternRef => Val::ExternRef(Nullable::Null),
    }
}

fn signature(types: &[ValType]) -> Vec<&'static str> {
    types.iter().map(type_name).collect()
}

fn values_match(values: &[Val], types: &[ValType], label: &str) -> Result<()> {
    if values.len() != types.len() || values.iter().zip(types).any(|(v, t)| val_type(v) != *t) {
        return Err(Error::bad(format!(
            "{label} must be ({}) but the request gives ({})",
            signature(types).join(", "),
            values
                .iter()
                .map(|v| type_name(&val_type(v)))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM run module is malformed: {error}"))
}

/// The facts of the original module a run needs, read with the same
/// `wasmparser` the inspection routes use. Section spans include the section
/// ID and size prefix, so the rewrite can copy sections verbatim.
#[derive(Default)]
struct Scan {
    imported_functions: u32,
    defined_functions: u32,
    memories: u32,
    tables: u32,
    element_items: u64,
    exports: Vec<(String, ExternalKind, u32)>,
    start: Option<u32>,
    bodies: Vec<Range<usize>>,
    sections: Vec<(u8, Range<usize>, Range<usize>)>,
}

/// Refuses a constant expression longer than MAX_CONST_OPERATORS before the
/// interpreter sees it.
fn constant(expr: &wasmparser::ConstExpr<'_>, label: &str) -> Result<()> {
    let mut reader = expr.get_operators_reader();
    let mut operators = 0usize;
    while !reader.eof() {
        reader.read().map_err(bad)?;
        operators += 1;
        if operators > MAX_CONST_OPERATORS {
            return Err(Error::protocol(format!(
                "WASM run module has a {label} constant expression over {MAX_CONST_OPERATORS} operators, which the interpreter would evaluate recursively; nothing ran"
            )));
        }
    }
    Ok(())
}

fn scan(bytes: &[u8]) -> Result<Scan> {
    if bytes.is_empty() {
        return Err(Error::protocol("WASM run module is empty"));
    }
    let mut facts = Scan::default();
    let mut previous_end = 8usize;
    let mut ended = false;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(bad)?;
        if let Some((id, range)) = payload.as_section() {
            facts
                .sections
                .push((id, previous_end..range.end, range.clone()));
            previous_end = range.end;
        }
        match payload {
            Payload::Version { encoding, .. } => {
                if encoding != wasmparser::Encoding::Module {
                    return Err(Error::protocol(
                        "WASM run module is a component, not a core module",
                    ));
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    match import.map_err(bad)?.ty {
                        TypeRef::Func(_) => facts.imported_functions += 1,
                        TypeRef::Memory(_) => facts.memories += 1,
                        TypeRef::Table(_) => facts.tables += 1,
                        _ => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => facts.defined_functions = reader.count(),
            Payload::MemorySection(reader) => facts.memories += reader.count(),
            Payload::TableSection(reader) => {
                facts.tables += reader.count();
                for table in reader {
                    if let wasmparser::TableInit::Expr(expr) = table.map_err(bad)?.init {
                        constant(&expr, "table initializer")?;
                    }
                }
            }
            Payload::GlobalSection(reader) => {
                for global in reader {
                    constant(&global.map_err(bad)?.init_expr, "global initializer")?;
                }
            }
            Payload::ElementSection(reader) => {
                for element in reader {
                    let element = element.map_err(bad)?;
                    if let wasmparser::ElementKind::Active { offset_expr, .. } = &element.kind {
                        constant(offset_expr, "element offset")?;
                    }
                    facts.element_items += u64::from(match &element.items {
                        wasmparser::ElementItems::Functions(items) => items.count(),
                        wasmparser::ElementItems::Expressions(_, items) => items.count(),
                    });
                    if facts.element_items > MAX_ELEMENT_ITEMS {
                        return Err(Error::protocol(format!(
                            "WASM run module has over {MAX_ELEMENT_ITEMS} element segment items, which instantiation would materialize without a deadline; nothing ran"
                        )));
                    }
                    if let wasmparser::ElementItems::Expressions(_, items) = element.items {
                        for item in items {
                            constant(&item.map_err(bad)?, "element item")?;
                        }
                    }
                }
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    if let wasmparser::DataKind::Active { offset_expr, .. } =
                        &data.map_err(bad)?.kind
                    {
                        constant(offset_expr, "data offset")?;
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(bad)?;
                    facts
                        .exports
                        .push((export.name.to_owned(), export.kind, export.index));
                }
            }
            Payload::StartSection { func, .. } => facts.start = Some(func),
            Payload::CodeSectionEntry(body) => facts.bodies.push(body.range()),
            Payload::End(_) => ended = true,
            _ => {}
        }
    }
    if !ended {
        return Err(Error::protocol("WASM run module ended early"));
    }
    if facts.bodies.len() != facts.defined_functions as usize {
        return Err(Error::protocol(
            "WASM run module function and code counts disagree",
        ));
    }
    Ok(facts)
}

fn leb(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Reads an unsigned LEB128 and its encoded length, which may be padded.
fn read_leb(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// Canonical section order; custom sections (ID 0) may appear anywhere.
fn rank(id: u8) -> u8 {
    match id {
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 5,
        13 => 6,
        6 => 7,
        7 => 8,
        8 => 9,
        9 => 10,
        12 => 11,
        10 => 12,
        11 => 13,
        _ => 0,
    }
}

struct Aliases {
    target: String,
    start: Option<String>,
    memory: Option<String>,
}

fn alias(base: &str, taken: &[(String, ExternalKind, u32)], chosen: &[String]) -> String {
    let mut name = base.to_owned();
    while taken.iter().any(|(n, _, _)| *n == name) || chosen.contains(&name) {
        name.push('~');
    }
    name
}

/// The execution copy: the start section dropped, and private export names
/// for the target, the start function (only when the request runs it) and
/// memory 0. Every other byte is copied from the original.
fn rewrite(bytes: &[u8], facts: &Scan, target: u32, run_start: bool) -> Result<(Vec<u8>, Aliases)> {
    let mut chosen = Vec::new();
    let target_name = alias("\u{1}reb.run.target", &facts.exports, &chosen);
    chosen.push(target_name.clone());
    let mut entries: Vec<(String, u8, u32)> = vec![(target_name.clone(), 0, target)];
    let start = match (run_start, facts.start) {
        (true, Some(index)) => {
            let name = alias("\u{1}reb.run.start", &facts.exports, &chosen);
            chosen.push(name.clone());
            entries.push((name.clone(), 0, index));
            Some(name)
        }
        _ => None,
    };
    let memory = (facts.memories > 0).then(|| {
        let name = alias("\u{1}reb.run.memory", &facts.exports, &chosen);
        entries.push((name.clone(), 2, 0));
        name
    });
    let mut added = Vec::new();
    for (name, kind, index) in &entries {
        leb(name.len() as u64, &mut added);
        added.extend_from_slice(name.as_bytes());
        added.push(*kind);
        leb(u64::from(*index), &mut added);
    }
    let section = |payload: &[u8], out: &mut Vec<u8>| {
        out.push(7);
        leb(payload.len() as u64, out);
        out.extend_from_slice(payload);
    };
    let mut out = bytes[..8].to_vec();
    let mut placed = false;
    for (id, span, payload) in &facts.sections {
        if *id == 8 {
            continue;
        }
        if *id == 7 {
            let raw = &bytes[payload.clone()];
            let (count, width) = read_leb(raw)
                .ok_or_else(|| Error::protocol("WASM run module export count is malformed"))?;
            let mut rewritten = Vec::new();
            leb(count + entries.len() as u64, &mut rewritten);
            rewritten.extend_from_slice(&raw[width..]);
            rewritten.extend_from_slice(&added);
            section(&rewritten, &mut out);
            placed = true;
            continue;
        }
        if !placed && rank(*id) > rank(7) {
            let mut fresh = Vec::new();
            leb(entries.len() as u64, &mut fresh);
            fresh.extend_from_slice(&added);
            section(&fresh, &mut out);
            placed = true;
        }
        out.extend_from_slice(&bytes[span.clone()]);
    }
    if !placed {
        let mut fresh = Vec::new();
        leb(entries.len() as u64, &mut fresh);
        fresh.extend_from_slice(&added);
        section(&fresh, &mut out);
    }
    Ok((
        out,
        Aliases {
            target: target_name,
            start,
            memory,
        },
    ))
}

/// The limits are totals across every memory and every table of the run.
/// Denials are counted, never hidden: a refused `memory.grow` returns -1 to
/// the module as the specification requires, and the result reports it.
#[derive(Default)]
struct Limiter {
    memory_bytes: usize,
    table_elements: usize,
    memory_total: usize,
    table_total: usize,
    /// The growth last admitted, undone if the growth then fails.
    memory_pending: usize,
    table_pending: usize,
    memory_denied: u64,
    table_denied: u64,
}
/// Admits `current` growing to `desired` when the running total stays within
/// `limit`, and updates the total.
fn admit(
    total: &mut usize,
    pending: &mut usize,
    denied: &mut u64,
    limit: usize,
    (current, desired, maximum): (usize, usize, Option<usize>),
) -> bool {
    let growth = desired.saturating_sub(current);
    let after = total.saturating_add(growth);
    if after > limit {
        *denied += 1;
        return false;
    }
    if maximum.is_some_and(|maximum| desired > maximum) {
        return false;
    }
    *total = after;
    *pending = growth;
    true
}
impl ResourceLimiter for Limiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> std::result::Result<bool, LimiterError> {
        Ok(admit(
            &mut self.memory_total,
            &mut self.memory_pending,
            &mut self.memory_denied,
            self.memory_bytes,
            (current, desired, maximum),
        ))
    }
    fn memory_grow_failed(
        &mut self,
        _error: &wasmi_core::MemoryError,
    ) -> std::result::Result<(), LimiterError> {
        self.memory_total -= std::mem::take(&mut self.memory_pending);
        Ok(())
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> std::result::Result<bool, LimiterError> {
        Ok(admit(
            &mut self.table_total,
            &mut self.table_pending,
            &mut self.table_denied,
            self.table_elements,
            (current, desired, maximum),
        ))
    }
    fn table_grow_failed(
        &mut self,
        _error: &wasmi_core::TableError,
    ) -> std::result::Result<(), LimiterError> {
        self.table_total -= std::mem::take(&mut self.table_pending);
        Ok(())
    }
    fn instances(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        MAX_TABLES as usize
    }
    fn memories(&self) -> usize {
        MAX_MEMORIES as usize
    }
}

enum Plan {
    Trap,
    Results(Vec<Val>),
    Sequence(Vec<Vec<Val>>),
}
struct ImportFunction {
    function_index: u32,
    module: String,
    field: String,
    plan: Plan,
    calls: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportTrapReason {
    NoStub,
    SequenceExhausted,
}
struct HostState {
    limiter: Limiter,
    functions: Vec<ImportFunction>,
    calls: Vec<Value>,
    total_calls: u64,
    trapped: Option<(usize, ImportTrapReason)>,
    /// Import calls are cheap in fuel but not in time, so each one checks the
    /// deadline and ends the run once it has passed.
    deadline: Instant,
    deadline_hit: bool,
}

fn stub_call(
    state: &mut HostState,
    import: usize,
    params: &[Val],
    results: &mut [Val],
) -> std::result::Result<(), wasmi::Error> {
    if Instant::now() >= state.deadline {
        state.deadline_hit = true;
        return Err(wasmi::Error::new("Origin Trace run deadline reached"));
    }
    let sequence = state.total_calls;
    state.total_calls += 1;
    let function = &mut state.functions[import];
    let call = function.calls;
    function.calls += 1;
    let reply = match &function.plan {
        Plan::Trap => Err(ImportTrapReason::NoStub),
        Plan::Results(values) => Ok(values.clone()),
        Plan::Sequence(list) => list
            .get(call as usize)
            .cloned()
            .ok_or(ImportTrapReason::SequenceExhausted),
    };
    if state.calls.len() < MAX_RECORDED_CALLS {
        let args = params
            .iter()
            .take(MAX_RECORDED_ARGS)
            .map(encode)
            .collect::<Vec<_>>();
        state.calls.push(json!({
            "sequence": sequence,
            "function_index": function.function_index,
            "module": function.module,
            "field": function.field,
            "args": args,
            "args_truncated": params.len() > MAX_RECORDED_ARGS,
            "outcome": if reply.is_ok() { "returned" } else { "trapped" },
            "results": reply.as_ref().ok().map(|values| values.iter().take(MAX_RECORDED_RESULTS).map(encode).collect::<Vec<_>>()),
            "results_truncated": reply.as_ref().is_ok_and(|values| values.len() > MAX_RECORDED_RESULTS),
        }));
    }
    match reply {
        Ok(values) => {
            for (slot, value) in results.iter_mut().zip(values) {
                *slot = value;
            }
            Ok(())
        }
        Err(reason) => {
            state.trapped = Some((import, reason));
            Err(wasmi::Error::new("Origin Trace import stub trapped"))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Returned,
    Trap,
    ImportTrap,
    FuelExhausted,
    DeadlineExceeded,
    CallDepthExceeded,
    MemoryLimit,
    TableLimit,
    InstantiationFailed,
    MemoryWriteOutOfBounds,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Instantiate,
    Start,
    Prepare,
    Call,
}
struct Outcome {
    status: Status,
    phase: Phase,
    trap_kind: Option<&'static str>,
    message: String,
}
impl Outcome {
    fn new(status: Status, phase: Phase, message: impl Into<String>) -> Self {
        Self {
            status,
            phase,
            trap_kind: None,
            message: message.into(),
        }
    }
}

fn trap_kind(code: TrapCode) -> &'static str {
    match code {
        TrapCode::UnreachableCodeReached => "unreachable",
        TrapCode::MemoryOutOfBounds => "memory_out_of_bounds",
        TrapCode::TableOutOfBounds => "table_out_of_bounds",
        TrapCode::IndirectCallToNull => "indirect_call_to_null",
        TrapCode::IntegerDivisionByZero => "integer_division_by_zero",
        TrapCode::IntegerOverflow => "integer_overflow",
        TrapCode::BadConversionToInteger => "bad_conversion_to_integer",
        TrapCode::StackOverflow => "stack_overflow",
        TrapCode::BadSignature => "indirect_call_type_mismatch",
        TrapCode::OutOfFuel => "out_of_fuel",
        TrapCode::GrowthOperationLimited => "growth_limited",
        TrapCode::OutOfSystemMemory => "out_of_system_memory",
    }
}

struct Budget {
    fuel: u64,
    granted: u64,
    deadline: Instant,
}

/// Runs one function under the fuel and deadline budget. Fuel is granted a
/// slice at a time; between slices the deadline is checked, so a loop that
/// never returns ends as `deadline_exceeded` or `fuel_exhausted`.
fn drive(
    store: &mut Store<HostState>,
    func: &Func,
    args: &[Val],
    outputs: &mut [Val],
    budget: &mut Budget,
    phase: Phase,
) -> Option<Outcome> {
    let grant = |store: &mut Store<HostState>, budget: &mut Budget, required: u64| -> bool {
        let remaining = store.get_fuel().unwrap_or(0);
        let left = budget.fuel - budget.granted;
        let add = FUEL_SLICE.max(required.saturating_sub(remaining)).min(left);
        if remaining + add < required.max(1) || add == 0 && remaining == 0 {
            return false;
        }
        budget.granted += add;
        store.set_fuel(remaining + add).is_ok()
    };
    let deadline = || {
        Outcome::new(
            Status::DeadlineExceeded,
            phase,
            "The wall-clock deadline was reached; execution stopped between fuel slices or at an import call",
        )
    };
    if Instant::now() >= budget.deadline {
        return Some(deadline());
    }
    if !grant(store, budget, 1) {
        return Some(Outcome::new(
            Status::FuelExhausted,
            phase,
            "The fuel limit was reached before the call started",
        ));
    }
    let mut step = func.call_resumable(&mut *store, args, outputs);
    loop {
        match step {
            Ok(ResumableCall::Finished) => return None,
            Ok(ResumableCall::OutOfFuel(call)) => {
                if Instant::now() >= budget.deadline {
                    return Some(deadline());
                }
                if !grant(store, budget, call.required_fuel()) {
                    return Some(Outcome::new(
                        Status::FuelExhausted,
                        phase,
                        "The fuel limit was reached; execution stopped",
                    ));
                }
                step = call.resume(&mut *store, outputs);
            }
            Ok(ResumableCall::HostTrap(_)) if store.data().deadline_hit => return Some(deadline()),
            Ok(ResumableCall::HostTrap(_)) => {
                let message = match store.data().trapped {
                    Some((index, reason)) => {
                        let function = &store.data().functions[index];
                        format!(
                            "Import {}.{} (function {}) was called and {}",
                            function.module,
                            function.field,
                            function.function_index,
                            if reason == ImportTrapReason::NoStub {
                                "has no stub, so it trapped"
                            } else {
                                "exhausted its stub sequence, so it trapped"
                            }
                        )
                    }
                    None => "An import stub trapped".into(),
                };
                return Some(Outcome::new(Status::ImportTrap, phase, message));
            }
            Err(error) => return Some(classify(&error, phase, store.data())),
        }
    }
}

fn classify(error: &wasmi::Error, phase: Phase, state: &HostState) -> Outcome {
    let message = error.to_string();
    match error.as_trap_code() {
        Some(TrapCode::StackOverflow) => Outcome {
            status: Status::CallDepthExceeded,
            phase,
            trap_kind: Some("stack_overflow"),
            message,
        },
        Some(TrapCode::OutOfFuel) => Outcome::new(Status::FuelExhausted, phase, message),
        Some(TrapCode::GrowthOperationLimited) if state.limiter.table_denied > 0 => {
            Outcome::new(Status::TableLimit, phase, message)
        }
        Some(TrapCode::GrowthOperationLimited) => Outcome::new(Status::MemoryLimit, phase, message),
        Some(code) => Outcome {
            status: Status::Trap,
            phase,
            trap_kind: Some(trap_kind(code)),
            message,
        },
        None => Outcome {
            status: Status::Trap,
            phase,
            trap_kind: Some("host"),
            message,
        },
    }
}

struct Selected {
    index: u32,
    export: Option<String>,
    body: Range<usize>,
}

fn select(request: &Request, facts: &Scan) -> Result<Selected> {
    let index = match (&request.export, request.function_index) {
        (Some(name), _) => facts
            .exports
            .iter()
            .find(|(n, kind, _)| n == name && *kind == ExternalKind::Func)
            .map(|(_, _, index)| *index)
            .ok_or_else(|| Error::new(404, "The module exports no function with that name"))?,
        (None, Some(index)) => index,
        (None, None) => unreachable!("parse requires one selector"),
    };
    if index < facts.imported_functions {
        return Err(Error::bad(
            "That function index is an import, which runs only as a stub; choose a defined function",
        ));
    }
    let body = facts
        .bodies
        .get((index - facts.imported_functions) as usize)
        .cloned()
        .ok_or_else(|| Error::new(404, "The module defines no function with that index"))?;
    let export = request.export.clone().or_else(|| {
        facts
            .exports
            .iter()
            .find(|(_, kind, i)| *kind == ExternalKind::Func && *i == index)
            .map(|(name, _, _)| name.clone())
    });
    Ok(Selected {
        index,
        export: export.map(|name| bounded(&name, MAX_RECORD_NAME)),
        body,
    })
}

/// Compiles, instantiates and runs. Request errors return `Err` before any
/// module code runs; every outcome after that is part of the record.
fn execute(request: &Request, limits: Limits, bytes: &[u8], started: Instant) -> Result<Value> {
    let facts = scan(bytes)?;
    let selected = select(request, &facts)?;
    let (executable, aliases) = rewrite(bytes, &facts, selected.index, request.run_start)?;
    let mut config = Config::default();
    // Eager compilation happens in Module::new, bounded by the module size
    // cap. Lazy compilation would charge a body's translation against one fuel
    // slice on its first call, so a large body could never run.
    config
        .consume_fuel(true)
        .compilation_mode(CompilationMode::Eager)
        .set_max_recursion_depth(limits.call_depth as usize);
    let engine = Engine::new(&config);
    let module = Module::new(&engine, &executable[..]).map_err(|error| {
        Error::protocol(format!(
            "WASM run module was rejected by the interpreter: {error}"
        ))
    })?;
    // Stubs must name a function import with exactly the declared results.
    let mut functions = Vec::new();
    let mut others = Vec::new();
    let mut matched = vec![false; request.imports.len()];
    let mut function_index = 0u32;
    for import in module.imports() {
        if let ExternType::Func(ty) = import.ty() {
            let stubs = request
                .imports
                .iter()
                .enumerate()
                .filter(|(_, s)| s.module == import.module() && s.field == import.name())
                .collect::<Vec<_>>();
            if stubs.len() > 1 {
                return Err(Error::bad(format!(
                    "Import {}.{} has more than one stub",
                    import.module(),
                    import.name()
                )));
            }
            let plan = match stubs.first() {
                None => Plan::Trap,
                Some((position, stub)) => {
                    matched[*position] = true;
                    let convert = |list: &Vec<Typed>| -> Result<Vec<Val>> {
                        let values = list.iter().map(value).collect::<Result<Vec<_>>>()?;
                        values_match(
                            &values,
                            ty.results(),
                            &format!("The stub results of {}.{}", import.module(), import.name()),
                        )?;
                        Ok(values)
                    };
                    match (&stub.results, &stub.sequence) {
                        (Some(results), _) => Plan::Results(convert(results)?),
                        (_, Some(sequence)) => Plan::Sequence(
                            sequence.iter().map(convert).collect::<Result<Vec<_>>>()?,
                        ),
                        _ => Plan::Trap,
                    }
                }
            };
            functions.push(ImportFunction {
                function_index,
                module: bounded(import.module(), MAX_RECORD_NAME),
                field: bounded(import.name(), MAX_RECORD_NAME),
                plan,
                calls: 0,
            });
            function_index += 1;
        }
    }
    if let Some(position) = matched.iter().position(|m| !m) {
        return Err(Error::bad(format!(
            "Import stub {} names no function import of this module",
            position
        )));
    }
    let deadline = started + Duration::from_millis(limits.deadline_ms);
    let mut store = Store::new(
        &engine,
        HostState {
            limiter: Limiter {
                memory_bytes: (limits.memory_pages * PAGE) as usize,
                table_elements: limits.table_elements as usize,
                ..Limiter::default()
            },
            functions,
            calls: Vec::new(),
            total_calls: 0,
            trapped: None,
            deadline,
            deadline_hit: false,
        },
    );
    store.limiter(|state| &mut state.limiter);
    let mut budget = Budget {
        fuel: limits.fuel,
        granted: 0,
        deadline,
    };
    let mut externs = Vec::new();
    // The counts are checked before anything is created, so the outcome names
    // the limit rather than an interpreter message.
    let mut failure = if facts.memories > MAX_MEMORIES {
        Some(Outcome::new(
            Status::MemoryLimit,
            Phase::Instantiate,
            format!(
                "The module has {} memories; a run instantiates at most {MAX_MEMORIES}",
                facts.memories
            ),
        ))
    } else if facts.tables > MAX_TABLES {
        Some(Outcome::new(
            Status::TableLimit,
            Phase::Instantiate,
            format!(
                "The module has {} tables; a run instantiates at most {MAX_TABLES}",
                facts.tables
            ),
        ))
    } else {
        None
    };
    let mut function_slot = 0usize;
    let imports = if failure.is_none() {
        module.imports().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for import in imports {
        let label = format!("{}.{}", import.module(), import.name());
        match import.ty().clone() {
            ExternType::Func(ty) => {
                let slot = function_slot;
                function_slot += 1;
                externs.push(Extern::Func(Func::new(
                    &mut store,
                    ty,
                    move |mut caller, params, results| {
                        stub_call(caller.data_mut(), slot, params, results)
                    },
                )));
            }
            ExternType::Memory(ty) => match Memory::new(&mut store, ty) {
                Ok(memory) => {
                    others.push(json!({"kind":"memory","module":bounded(import.module(), MAX_RECORD_NAME),"field":bounded(import.name(), MAX_RECORD_NAME),"provided":"fresh_zeroed","minimum_pages":ty.minimum()}));
                    externs.push(Extern::Memory(memory));
                }
                Err(error) => {
                    failure = Some(memory_failure(&error, &store, &label));
                    break;
                }
            },
            ExternType::Table(ty) => {
                let init = match ty.element() {
                    RefType::Func => Ref::Func(Nullable::Null),
                    RefType::Extern => Ref::Extern(Nullable::Null),
                };
                match Table::new(&mut store, ty, init) {
                    Ok(table) => {
                        others.push(json!({"kind":"table","module":bounded(import.module(), MAX_RECORD_NAME),"field":bounded(import.name(), MAX_RECORD_NAME),"provided":"fresh_null","minimum_elements":ty.minimum()}));
                        externs.push(Extern::Table(table));
                    }
                    Err(error) => {
                        failure = Some(memory_failure(&error, &store, &label));
                        break;
                    }
                }
            }
            ExternType::Global(ty) => {
                others.push(json!({"kind":"global","module":bounded(import.module(), MAX_RECORD_NAME),"field":bounded(import.name(), MAX_RECORD_NAME),"provided":"zero","type":type_name(&ty.content()),"mutable":ty.mutability() == Mutability::Var}));
                externs.push(Extern::Global(Global::new(
                    &mut store,
                    zero(&ty.content()),
                    ty.mutability(),
                )));
            }
        }
    }
    let instance = match failure {
        Some(outcome) => Err(outcome),
        None => Instance::new(&mut store, &module, &externs)
            .map_err(|error| instantiation_failure(&error, &store)),
    };
    // Compilation and instantiation cannot be interrupted; they are bounded by
    // the module, element and constant-expression caps. A deadline that passed
    // during them is reported as such, before any function is called.
    let instance = match instance {
        Ok(_) if Instant::now() >= deadline => Err(Outcome::new(
            Status::DeadlineExceeded,
            Phase::Instantiate,
            "The deadline passed while the module was compiled and instantiated; no function was called",
        )),
        other => other,
    };
    let mut outcome = None;
    let mut results = None;
    let mut function_type = None;
    let mut memory = None;
    let mut start_ran = false;
    match instance {
        Err(failed) => outcome = Some(failed),
        Ok(instance) => {
            let target = instance
                .get_func(&store, &aliases.target)
                .ok_or_else(|| Error::new(500, "WASM run target alias is missing"))?;
            let ty: FuncType = target.ty(&store);
            // Arguments are checked before the start function, so a refused
            // request never runs module code.
            let args = request.args.iter().map(value).collect::<Result<Vec<_>>>()?;
            values_match(&args, ty.params(), "The arguments")?;
            function_type =
                Some(json!({"params":signature(ty.params()),"results":signature(ty.results())}));
            memory = aliases
                .memory
                .as_ref()
                .and_then(|name| instance.get_memory(&store, name));
            if let Some(name) = &aliases.start {
                let start = instance
                    .get_func(&store, name)
                    .ok_or_else(|| Error::new(500, "WASM run start alias is missing"))?;
                start_ran = true;
                outcome = drive(&mut store, &start, &[], &mut [], &mut budget, Phase::Start);
            }
            if outcome.is_none() {
                for (index, write) in request.memory_writes.iter().enumerate() {
                    let data = decode_hex(&write.hex, "A memory write")?;
                    let fits = memory.as_ref().is_some_and(|m| {
                        usize::try_from(write.offset)
                            .is_ok_and(|offset| m.write(&mut store, offset, &data).is_ok())
                    });
                    if !fits {
                        outcome = Some(Outcome::new(
                            Status::MemoryWriteOutOfBounds,
                            Phase::Prepare,
                            format!(
                                "Memory write {index} does not fit memory 0; the function was not called"
                            ),
                        ));
                        break;
                    }
                }
            }
            if outcome.is_none() {
                let mut outputs = ty.results().iter().map(zero).collect::<Vec<_>>();
                outcome = drive(
                    &mut store,
                    &target,
                    &args,
                    &mut outputs,
                    &mut budget,
                    Phase::Call,
                );
                if outcome.is_none() {
                    results = Some(outputs.iter().map(encode).collect::<Vec<_>>());
                }
            }
        }
    }
    let outcome = outcome
        .unwrap_or_else(|| Outcome::new(Status::Returned, Phase::Call, "The function returned"));
    let reads = request
        .memory_reads
        .iter()
        .map(|read| {
            let Some(memory) = memory.as_ref() else {
                return json!({"offset":read.offset,"length":read.length,"status":"no_memory","sha256":null,"hex":null});
            };
            let size = memory.data_size(&store) as u64;
            if read.offset.checked_add(read.length).is_none_or(|end| end > size) {
                return json!({"offset":read.offset,"length":read.length,"status":"out_of_bounds","sha256":null,"hex":null});
            }
            let mut buffer = vec![0u8; read.length as usize];
            if memory.read(&store, read.offset as usize, &mut buffer).is_err() {
                return json!({"offset":read.offset,"length":read.length,"status":"out_of_bounds","sha256":null,"hex":null});
            }
            json!({"offset":read.offset,"length":read.length,"status":"read","sha256":hex::encode(Sha256::digest(&buffer)),"hex":hex::encode(&buffer)})
        })
        .collect::<Vec<_>>();
    let expectation = request.expect.as_ref().map(|expect| {
        let results_match = expect.results.as_ref().map(|expected| {
            results.as_ref().is_some_and(|actual: &Vec<Typed>| {
                actual.len() == expected.len()
                    && actual.iter().zip(expected).all(|(a, e)| same(a, e))
            })
        });
        let memory = expect
            .memory
            .iter()
            .map(|entry| {
                let read = &reads[entry.read];
                json!({"read":entry.read,"match":read["hex"].as_str() == Some(entry.hex.to_ascii_lowercase().as_str())})
            })
            .collect::<Vec<_>>();
        let all = results_match.unwrap_or(true)
            && memory.iter().all(|m| m["match"] == true)
            && outcome.status == Status::Returned;
        json!({"results_match":results_match,"memory":memory,"all_match":all})
    });
    let state = store.data();
    let consumed = budget.granted - store.get_fuel().unwrap_or(0);
    let imports = state
        .functions
        .iter()
        .map(|f| {
            json!({"function_index":f.function_index,"module":f.module,"field":f.field,
                "stub":match f.plan { Plan::Trap => "trap", Plan::Results(_) => "results", Plan::Sequence(_) => "sequence" },
                "calls":f.calls})
        })
        .collect::<Vec<_>>();
    let import_trap = state.trapped.map(|(index, reason)| {
        let f = &state.functions[index];
        json!({"function_index":f.function_index,"module":f.module,"field":f.field,
            "reason":if reason == ImportTrapReason::NoStub { "no_stub" } else { "sequence_exhausted" }})
    });
    Ok(json!({
        "outcome": {
            "status": outcome.status,
            "phase": outcome.phase,
            "trap_kind": outcome.trap_kind,
            "import": if outcome.status == Status::ImportTrap { import_trap } else { None },
            "byte_offset": null,
            "byte_offset_note": "wasmi 2.0.0 does not report the instruction offset of a trap",
            "message": outcome.message,
        },
        "function": {
            "index": selected.index,
            "export": selected.export,
            "byte_offset": selected.body.start,
            "byte_end": selected.body.end,
            "type": function_type,
        },
        "start_function": {
            "index": facts.start,
            "ran": start_ran,
        },
        "results": results,
        "fuel_consumed": consumed,
        "imports": imports,
        "other_imports": others,
        "import_calls": state.calls,
        "import_calls_total": state.total_calls,
        "import_calls_truncated": state.total_calls > state.calls.len() as u64,
        "memory_grow_denied": state.limiter.memory_denied,
        "table_grow_denied": state.limiter.table_denied,
        "memory_pages_after": memory.as_ref().map(|m| m.size(&store)),
        "memory_reads": reads,
        "expectation": expectation,
        "executed_module_sha256": hex::encode(Sha256::digest(&executable)),
    }))
}

fn memory_failure(error: &wasmi::Error, store: &Store<HostState>, label: &str) -> Outcome {
    let state = store.data();
    let status = if state.limiter.memory_denied > 0 {
        Status::MemoryLimit
    } else if state.limiter.table_denied > 0 {
        Status::TableLimit
    } else {
        Status::InstantiationFailed
    };
    Outcome::new(
        status,
        Phase::Instantiate,
        format!("Import {label} could not be provided: {error}"),
    )
}

fn instantiation_failure(error: &wasmi::Error, store: &Store<HostState>) -> Outcome {
    let state = store.data();
    let mut outcome = if state.limiter.memory_denied > 0 {
        Outcome::new(Status::MemoryLimit, Phase::Instantiate, error.to_string())
    } else if state.limiter.table_denied > 0 {
        Outcome::new(Status::TableLimit, Phase::Instantiate, error.to_string())
    } else {
        Outcome::new(
            Status::InstantiationFailed,
            Phase::Instantiate,
            error.to_string(),
        )
    };
    if let ErrorKind::TrapCode(code) = error.kind() {
        outcome.trap_kind = Some(trap_kind(*code));
    }
    outcome
}

/// Reads the artifact, verifies it, runs it, and builds the derived record.
fn run_blocking(root: &Path, request: &Request, limits: Limits) -> Result<Value> {
    let started = Instant::now();
    let artifact = evidence::artifacts(root, 10000)?
        .into_iter()
        .find(|a| a["artifact_id"] == request.artifact_id.as_str())
        .ok_or_else(|| Error::new(404, "Artifact not found"))?;
    if artifact["kind"] != "wasm" {
        return Err(Error::bad("Artifact is not WebAssembly"));
    }
    if artifact["sha256"] != request.sha256.as_str() {
        return Err(Error::conflict(
            "The artifact's SHA-256 differs from the request; nothing ran",
        )
        .with_code(Code::StateConflict));
    }
    if artifact["byte_size"]
        .as_u64()
        .is_some_and(|size| size > MAX_MODULE_BYTES as u64)
    {
        return Err(Error::bad("WASM run input exceeds 16 MiB"));
    }
    let bytes = evidence::content(root, &artifact, MAX_MODULE_BYTES)?;
    let mut record = execute(request, limits, &bytes, started)?;
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let inputs_digest = request.digest();
    record["schema"] = json!(SCHEMA);
    // A random nonce: an identifier derived from the inputs would let anyone
    // who sees it test guesses at those inputs.
    record["run_id"] = json!(format!("wr-{}-{}", created.as_millis(), nonce()));
    record["record_class"] = json!("derived_experiment");
    record["created_at_ms"] = json!(created.as_millis() as u64);
    record["elapsed_ms"] = json!(started.elapsed().as_millis() as u64);
    record["provenance"] = json!({
        "artifact_id": request.artifact_id,
        "module_sha256": request.sha256,
        "module_byte_size": bytes.len(),
        "inputs_digest": inputs_digest,
        "interpreter": {
            "name": INTERPRETER,
            "version": INTERPRETER_VERSION,
            "jit": false,
            "fuel_metering": true,
            "nan_canonicalization": true,
            "proposals": "wasmi defaults plus simd",
        },
        "limits": limits,
        "host_access": "none: every import is a stub; no filesystem, network, clock, randomness or host object is reachable",
        "rewrite": "start section dropped; private exports added for the target, the start function when run, and memory 0",
    });
    record["request"] = serde_json::to_value(request)?;
    record["notice"] = json!(
        "Captured code ran offline in a local interpreter with every import stubbed. This result describes these inputs only and is a derived experiment record, not captured evidence."
    );
    fit(&mut record);
    Ok(record)
}

/// At most `limit` bytes of `text` on a character boundary, marked when cut.
fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} [cut]", &text[..end])
}

fn pretty_len(value: &Value) -> usize {
    serde_json::to_string_pretty(value).map_or(usize::MAX, |text| text.len())
}

/// Trims a record until its pretty-printed JSON fits RECORD_INLINE_BUDGET, in a
/// fixed order, and lists each step in `size_trimmed`. Outcomes, counts,
/// memory reads, digests and the expectation are never trimmed: the reads cap
/// leaves room for them.
fn fit(record: &mut Value) {
    if let Some(message) = record["outcome"]["message"].as_str() {
        record["outcome"]["message"] = json!(bounded(message, MAX_RECORD_MESSAGE));
    }
    let mut trimmed = Vec::new();
    let over = |record: &Value| pretty_len(record) > RECORD_INLINE_BUDGET;
    if over(record) {
        let kept = record["import_calls"].as_array().map_or(0, Vec::len);
        record["import_calls"] = json!([]);
        record["import_calls_truncated"] = json!(true);
        trimmed.push(format!("import_calls: 0 of {kept} recorded calls kept"));
    }
    if over(record) {
        let bytes = serde_json::to_vec(&record["request"]).map_or(0, |bytes| bytes.len());
        record["request"] = json!({"omitted": "size", "bytes": bytes});
        trimmed.push("request: replaced by its size; provenance.inputs_digest names it".into());
    }
    for key in ["imports", "other_imports"] {
        if over(record)
            && let Some(list) = record[key].as_array_mut()
            && list.len() > 32
        {
            let total = list.len();
            list.truncate(32);
            trimmed.push(format!("{key}: first 32 of {total}"));
        }
    }
    if over(record)
        && let Some(list) = record["results"].as_array_mut()
        && list.len() > 64
    {
        let total = list.len();
        list.truncate(64);
        trimmed.push(format!("results: first 64 of {total}"));
    }
    if over(record) && record["function"]["type"].is_object() {
        let count = |key: &str| {
            record["function"]["type"][key]
                .as_array()
                .map_or(0, Vec::len)
        };
        let (params, results) = (count("params"), count("results"));
        record["function"]["type"] = json!({"params_count": params, "results_count": results});
        trimmed.push("function.type: replaced by its counts".into());
    }
    record["size_trimmed"] = json!(trimmed);
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    evicted_runs: u64,
    runs: Vec<Value>,
}

fn store_path(root: &Path) -> PathBuf {
    root.join("analysis/wasm-runs-v1.json")
}

fn decode(bytes: Option<Vec<u8>>) -> Result<Document> {
    let Some(bytes) = bytes else {
        return Ok(Document {
            schema: STORE_SCHEMA.into(),
            evicted_runs: 0,
            runs: Vec::new(),
        });
    };
    let document: Document = serde_json::from_slice(&bytes).map_err(|_| unreadable())?;
    if document.schema != STORE_SCHEMA
        || document.runs.len() > MAX_RUNS
        || document.runs.iter().any(|run| run["schema"] != SCHEMA)
    {
        return Err(unreadable());
    }
    Ok(document)
}

/// A store that cannot be read is an integrity failure of this backend's own
/// derived records, never a fault in the caller's request.
fn unreadable() -> Error {
    Error::new(
        500,
        "The WASM run store analysis/wasm-runs-v1.json is unreadable. The next run moves it aside as wasm-runs-v1.json.unreadable-<time> and starts a new store; to keep the listing working until then, move it aside yourself",
    )
    .with_code(Code::ArtifactIntegrity)
}

/// Keeps the newest runs. A run is derived, not evidence, so the oldest is
/// evicted at capacity, and `evicted_runs` counts every eviction.
/// 96 random bits from the operating system, as hex. If that source is
/// unreadable, a randomly keyed hash of the time and a counter stands in: it is
/// still unrelated to the run's inputs.
fn nonce() -> String {
    use std::io::Read as _;
    let mut bytes = [0u8; 12];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .is_ok()
    {
        return hex::encode(bytes);
    }
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    hasher.write_u64(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    format!("{:016x}", hasher.finish())
}

/// Renames `from` to `to` only if `to` does not exist, atomically where the
/// system offers it.
fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let source = std::ffi::CString::new(from.as_os_str().as_bytes())?;
        let target = std::ffi::CString::new(to.as_os_str().as_bytes())?;
        #[cfg(target_os = "macos")]
        let status = unsafe {
            libc::renameatx_np(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(target_os = "linux")]
        let status = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        // A hard link fails when the target exists, so nothing is replaced.
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}

/// Moves an unreadable store aside under a name that does not exist yet, and
/// returns that name. An existing file is never replaced: a name in use gets a
/// counter suffix.
fn move_aside(path: &Path, millis: u128) -> Result<String> {
    for attempt in 0..1000u32 {
        let name = if attempt == 0 {
            format!("wasm-runs-v1.json.unreadable-{millis}")
        } else {
            format!("wasm-runs-v1.json.unreadable-{millis}-{attempt}")
        };
        match rename_no_replace(path, &path.with_file_name(&name)) {
            Ok(()) => return Ok(name),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(Error::new(
        500,
        "Could not find a free name to move the unreadable run store aside",
    )
    .with_code(Code::ArtifactIntegrity))
}

/// Returns a notice when an unreadable store was moved aside. Its bytes are
/// kept under a new name, never overwritten, and the run that moved it says so.
fn persist(root: &Path, record: &Value) -> Result<Option<String>> {
    let path = store_path(root);
    let lease = crate::workspace_lease::Lease::acquire(&path)?;
    let (mut document, notice) = match lease.read(MAX_STORE_BYTES).and_then(decode) {
        Ok(document) => (document, None),
        Err(_) => {
            let millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let name = move_aside(&path, millis)?;
            (
                decode(None)?,
                Some(format!(
                    "The unreadable run store was moved to analysis/{name} and a new store was started; the runs it held are not listed"
                )),
            )
        }
    };
    document.runs.push(record.clone());
    loop {
        let bytes = serde_json::to_vec(&document)?;
        if document.runs.len() <= MAX_RUNS && bytes.len() <= MAX_STORE_BYTES {
            return lease.write(&bytes).map(|()| notice);
        }
        if document.runs.len() == 1 {
            return Err(Error::bad("A WASM run record exceeds the store limit"));
        }
        document.runs.remove(0);
        document.evicted_runs += 1;
    }
}

/// The contract check runs before a record is stored. Its error never carries
/// the validator's message, which quotes the offending value: a value derived
/// from captured code would reach a client that may not read content.
fn checked(record: &Value) -> Result<()> {
    validation::schema("WasmRun", record, 500).map_err(|_| {
        Error::new(
            500,
            "The run record did not match its contract and was not stored; its values are not reported",
        )
    })
}

pub struct Runs {
    root: PathBuf,
    permit: Arc<Semaphore>,
}
impl Runs {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            permit: Arc::new(Semaphore::new(1)),
        }
    }
    /// One run at a time per backend. Once admitted, HTTP cancellation does
    /// not cancel the run or its persistence; the deadline ends it.
    pub async fn run(&self, bytes: &[u8]) -> Result<Value> {
        let (request, limits) = Request::parse(bytes)?;
        let permit = self.permit.clone().try_acquire_owned().map_err(|_| {
            Error::conflict("A WASM run is already in progress; nothing ran")
                .with_code(Code::ResourceLimit)
        })?;
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut record = run_blocking(&root, &request, limits)?;
            checked(&record)?;
            record["store_notice"] = Value::Null;
            let stored = if serde_json::to_vec(&record)?.len() > MAX_RECORD_BYTES {
                Err(Error::bad(
                    "The run record exceeds 4 MiB and was not stored",
                ))
            } else {
                persist(&root, &record)
            };
            match stored {
                Ok(notice) => {
                    record["stored"] = json!(true);
                    record["store_error"] = Value::Null;
                    record["store_notice"] = json!(notice);
                }
                Err(error) => {
                    record["stored"] = json!(false);
                    record["store_error"] = json!(error.message);
                }
            }
            Ok(record)
        })
        .await
        .map_err(|_| Error::new(500, "WASM run task failed"))?
    }
}

/// Stored runs, newest first, optionally for one artifact. Reads only.
pub fn list(root: &Path, artifact_id: Option<&str>, limit: usize) -> Result<Value> {
    let document = decode(
        crate::durable::read_private(&store_path(root), MAX_STORE_BYTES)
            .map_err(|_| unreadable())?,
    )?;
    let matching = document
        .runs
        .iter()
        .rev()
        .filter(|run| artifact_id.is_none_or(|id| run["provenance"]["artifact_id"] == id))
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": "wasm-runs-v1",
        "artifact_id": artifact_id,
        "total": matching.len(),
        "evicted_runs": document.evicted_runs,
        "max_runs": MAX_RUNS,
        "runs": matching.into_iter().take(limit).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(source: &str) -> Vec<u8> {
        wat::parse_str(source).unwrap()
    }
    fn request(extra: Value) -> (Request, Limits) {
        let mut body = json!({"artifact_id":"1","sha256":"0".repeat(64),"export":"run",
            "confirm_offline_execution":true});
        for (key, value) in extra.as_object().unwrap() {
            body[key] = value.clone();
        }
        if body.get("function_index").is_some() {
            body.as_object_mut().unwrap().remove("export");
        }
        Request::parse(&serde_json::to_vec(&body).unwrap()).unwrap()
    }
    fn run(source: &str, extra: Value) -> Value {
        let (request, limits) = request(extra);
        execute(&request, limits, &module(source), Instant::now()).unwrap()
    }
    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/fixtures/wasm-runs")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn values_round_trip_and_refuse_out_of_range_literals() {
        for (ty, text) in [
            ("i32", "-1"),
            ("i64", "9223372036854775807"),
            ("f32", "1.5"),
            ("f64", "-0"),
            ("f32", "nan:0x7fc00001"),
            ("f64", "inf"),
            ("v128", "0x000000000000000000000000000000ff"),
            ("funcref", "null"),
        ] {
            let typed = Typed {
                ty: ty.into(),
                value: text.into(),
            };
            assert!(
                same(&encode(&value(&typed).unwrap()), &typed),
                "{ty} {text}"
            );
        }
        assert_eq!(
            encode(
                &value(&Typed {
                    ty: "i32".into(),
                    value: "4294967295".into()
                })
                .unwrap()
            )
            .value,
            "-1"
        );
        for (ty, text) in [
            ("i32", "4294967296"),
            ("i32", "1.0"),
            ("f32", "nan"),
            ("f32", "nan:0x00000001"),
            ("externref", "0"),
            ("i128", "1"),
        ] {
            assert!(
                value(&Typed {
                    ty: ty.into(),
                    value: text.into()
                })
                .is_err(),
                "{ty} {text}"
            );
        }
    }

    #[test]
    fn a_request_without_confirmation_is_refused_before_anything_is_read() {
        for body in [
            json!({"artifact_id":"1","sha256":"0".repeat(64),"export":"run"}),
            json!({"artifact_id":"1","sha256":"0".repeat(64),"export":"run","confirm_offline_execution":false}),
        ] {
            let error = Request::parse(&serde_json::to_vec(&body).unwrap()).unwrap_err();
            assert_eq!(error.status, 400);
            assert!(error.message.contains("confirm_offline_execution"));
        }
        let unknown = json!({"artifact_id":"1","sha256":"0".repeat(64),"export":"run",
            "confirm_offline_execution":true,"network":true});
        assert!(Request::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }

    #[test]
    fn a_function_returns_and_meets_its_expectation() {
        let result = run(
            &fixture("arith.wat"),
            json!({"args":[{"type":"i32","value":"7"},{"type":"i32","value":"5"}],
                "expect":{"results":[{"type":"i32","value":"12"}]}}),
        );
        assert_eq!(result["outcome"]["status"], "returned");
        assert_eq!(result["results"], json!([{"type":"i32","value":"12"}]));
        assert_eq!(result["expectation"]["all_match"], true);
        assert!(result["fuel_consumed"].as_u64().unwrap() > 0);
        let index = run(
            &fixture("arith.wat"),
            json!({"function_index":1,
            "args":[{"type":"i32","value":"1"}]}),
        );
        assert_eq!(index["outcome"]["status"], "returned");
        assert_eq!(index["function"]["export"], "double");
        assert_eq!(index["results"][0]["value"], "2");
    }

    #[test]
    fn a_trap_names_its_kind_and_phase() {
        let result = run(
            &fixture("arith.wat"),
            json!({"export":"divide",
            "args":[{"type":"i32","value":"1"},{"type":"i32","value":"0"}]}),
        );
        assert_eq!(result["outcome"]["status"], "trap");
        assert_eq!(result["outcome"]["phase"], "call");
        assert_eq!(result["outcome"]["trap_kind"], "integer_division_by_zero");
        assert_eq!(result["results"], Value::Null);
        let unreachable = run(&fixture("arith.wat"), json!({"export":"crash"}));
        assert_eq!(unreachable["outcome"]["trap_kind"], "unreachable");
        let deep = run(
            &fixture("arith.wat"),
            json!({"export":"recurse","limits":{"call_depth":64}}),
        );
        assert_eq!(deep["outcome"]["status"], "call_depth_exceeded");
    }

    #[test]
    fn a_loop_ends_at_the_fuel_limit_or_the_deadline() {
        let fuel = run(
            &fixture("loops.wat"),
            json!({"export":"spin","limits":{"fuel":1_500_000,"deadline_ms":10_000}}),
        );
        assert_eq!(fuel["outcome"]["status"], "fuel_exhausted");
        assert!(fuel["fuel_consumed"].as_u64().unwrap() <= 1_500_000);
        let deadline = run(
            &fixture("loops.wat"),
            json!({"export":"spin","limits":{"fuel":10_000_000_000u64,"deadline_ms":50}}),
        );
        assert_eq!(deadline["outcome"]["status"], "deadline_exceeded");
    }

    #[test]
    fn a_start_function_that_never_returns_runs_only_on_request() {
        let skipped = run(&fixture("loops.wat"), json!({"export":"answer"}));
        assert_eq!(skipped["outcome"]["status"], "returned");
        assert_eq!(skipped["start_function"]["ran"], false);
        assert_eq!(skipped["results"][0]["value"], "42");
        let started = run(
            &fixture("loops.wat"),
            json!({"export":"answer","run_start":true,"limits":{"fuel":1_500_000,"deadline_ms":10_000}}),
        );
        assert_eq!(started["outcome"]["status"], "fuel_exhausted");
        assert_eq!(started["outcome"]["phase"], "start");
        assert_eq!(started["start_function"]["ran"], true);
        assert_eq!(started["results"], Value::Null);
    }

    #[test]
    fn imports_return_supplied_values_or_trap_and_every_call_is_recorded() {
        let supplied = run(
            &fixture("imports.wat"),
            json!({"export":"mix","args":[{"type":"i32","value":"3"}],
                "imports":[{"module":"env","field":"now","sequence":[[{"type":"f64","value":"1000"}],[{"type":"f64","value":"1001"}]]},
                    {"module":"env","field":"random","results":[{"type":"i32","value":"4"}]}]}),
        );
        assert_eq!(supplied["outcome"]["status"], "returned", "{supplied}");
        assert_eq!(supplied["results"][0]["value"], "1008");
        assert_eq!(supplied["import_calls_total"], 3);
        let calls = supplied["import_calls"].as_array().unwrap();
        assert_eq!(calls[0]["field"], "now");
        assert_eq!(calls[1]["field"], "random");
        assert_eq!(calls[1]["args"][0]["value"], "3");
        assert_eq!(calls[2]["results"][0]["value"], "1001.0");
        let other = supplied["other_imports"].as_array().unwrap();
        assert_eq!(other[0]["kind"], "memory");
        assert_eq!(other[0]["provided"], "fresh_zeroed");
        let missing = run(
            &fixture("imports.wat"),
            json!({"export":"mix","args":[{"type":"i32","value":"3"}],
                "imports":[{"module":"env","field":"now","results":[{"type":"f64","value":"1000"}]}]}),
        );
        assert_eq!(missing["outcome"]["status"], "import_trap");
        assert_eq!(missing["outcome"]["import"]["field"], "random");
        assert_eq!(missing["outcome"]["import"]["reason"], "no_stub");
        assert_eq!(missing["import_calls"][1]["outcome"], "trapped");
        assert_eq!(missing["imports"][1]["stub"], "trap");
        let exhausted = run(
            &fixture("imports.wat"),
            json!({"export":"mix","args":[{"type":"i32","value":"3"}],
                "imports":[{"module":"env","field":"now","sequence":[[{"type":"f64","value":"1"}]]},
                    {"module":"env","field":"random","results":[{"type":"i32","value":"4"}]}]}),
        );
        assert_eq!(
            exhausted["outcome"]["import"]["reason"],
            "sequence_exhausted"
        );
        let (request, limits) = request(json!({"export":"mix","args":[{"type":"i32","value":"3"}],
            "imports":[{"module":"env","field":"now","results":[{"type":"i32","value":"1"}]}]}));
        assert_eq!(
            execute(
                &request,
                limits,
                &module(&fixture("imports.wat")),
                Instant::now()
            )
            .unwrap_err()
            .status,
            400
        );
    }

    #[test]
    fn memory_writes_and_bounded_reads_surround_the_call() {
        let result = run(
            &fixture("memory.wat"),
            json!({"export":"sum","args":[{"type":"i32","value":"16"},{"type":"i32","value":"4"}],
                "memory_writes":[{"offset":16,"hex":"01020304"}],
                "memory_reads":[{"offset":0,"length":4},{"offset":65534,"length":4},{"offset":16,"length":4}],
                "expect":{"memory":[{"read":0,"hex":"0a000000"}]}}),
        );
        assert_eq!(result["outcome"]["status"], "returned", "{result}");
        assert_eq!(result["results"][0]["value"], "10");
        assert_eq!(result["memory_reads"][0]["hex"], "0a000000");
        assert_eq!(result["memory_reads"][1]["status"], "out_of_bounds");
        assert_eq!(result["memory_reads"][2]["hex"], "01020304");
        assert_eq!(result["expectation"]["all_match"], true);
        let body = json!({"artifact_id":"1","sha256":"0".repeat(64),"export":"sum",
            "confirm_offline_execution":true,"memory_reads":[{"offset":0,"length":MAX_READ_BYTES + 1}]});
        let error = Request::parse(&serde_json::to_vec(&body).unwrap()).unwrap_err();
        assert!(error.message.contains("32 KiB"));
        let outside = run(
            &fixture("memory.wat"),
            json!({"export":"sum",
            "args":[{"type":"i32","value":"0"},{"type":"i32","value":"0"}],
            "memory_writes":[{"offset":65535,"hex":"0102"}]}),
        );
        assert_eq!(outside["outcome"]["status"], "memory_write_out_of_bounds");
    }

    #[test]
    fn memory_growth_past_the_limit_is_denied_and_counted() {
        let result = run(
            &fixture("memory.wat"),
            json!({"export":"grow",
            "args":[{"type":"i32","value":"10"}],"limits":{"memory_pages":4}}),
        );
        assert_eq!(result["outcome"]["status"], "returned");
        assert_eq!(result["results"][0]["value"], "-1");
        assert_eq!(result["memory_grow_denied"], 1);
        let large = run(
            "(module (memory 8) (func (export \"run\")))",
            json!({"limits":{"memory_pages":4}}),
        );
        assert_eq!(large["outcome"]["status"], "memory_limit");
        assert_eq!(large["outcome"]["phase"], "instantiate");
    }

    #[test]
    fn malformed_empty_and_imported_targets_are_named_errors() {
        let (request, limits) = request(json!({}));
        for bytes in [&b""[..], &b"\0asm\x01\0\0\0\x01\x05"[..], &b"not wasm"[..]] {
            let error = execute(&request, limits, bytes, Instant::now()).unwrap_err();
            assert_eq!(error.status, 422, "{bytes:?}");
        }
        let invalid = module("(module (func (export \"run\") (result i32) i64.const 1))");
        let error = execute(&request, limits, &invalid, Instant::now()).unwrap_err();
        assert!(error.message.contains("rejected by the interpreter"));
        let (imported, limits) = self::request(json!({"function_index":0}));
        let error = execute(
            &imported,
            limits,
            &module(&fixture("imports.wat")),
            Instant::now(),
        )
        .unwrap_err();
        assert_eq!(error.status, 400);
        let (missing, limits) = self::request(json!({"export":"absent"}));
        let error = execute(
            &missing,
            limits,
            &module(&fixture("arith.wat")),
            Instant::now(),
        )
        .unwrap_err();
        assert_eq!(error.status, 404);
    }

    #[test]
    fn the_rewrite_keeps_the_original_and_adds_only_private_exports() {
        let bytes = module(&fixture("loops.wat"));
        let facts = scan(&bytes).unwrap();
        assert!(facts.start.is_some());
        let (rewritten, aliases) = rewrite(&bytes, &facts, 1, false).unwrap();
        let again = scan(&rewritten).unwrap();
        assert_eq!(again.start, None);
        assert!(aliases.start.is_none());
        // The target only: this module has no memory and the start was not asked for.
        assert_eq!(again.exports.len(), facts.exports.len() + 1);
        let (_, aliases) = rewrite(&bytes, &facts, 1, true).unwrap();
        assert!(aliases.start.is_some());
        let none = module("(module (func) (func (result i32) i32.const 1))");
        let facts = scan(&none).unwrap();
        let (rewritten, _) = rewrite(&none, &facts, 1, false).unwrap();
        assert_eq!(scan(&rewritten).unwrap().exports.len(), 1);
    }

    fn repeated(prefix: &str, unit: &str, count: usize, suffix: &str) -> String {
        let mut text = String::with_capacity(prefix.len() + unit.len() * count + suffix.len());
        text.push_str(prefix);
        for _ in 0..count {
            text.push_str(unit);
        }
        text.push_str(suffix);
        text
    }

    #[test]
    fn a_long_constant_expression_is_refused_before_the_interpreter_sees_it() {
        // 100,000 nested additions overflowed the native stack in wasmi's
        // constant-expression closures and aborted the whole backend.
        let (request, limits) = request(json!({}));
        let deep = module(&repeated(
            "(module (global i32 i32.const 0 ",
            "i32.const 1 i32.add ",
            100_000,
            ") (func (export \"run\") (result i32) i32.const 7))",
        ));
        let error = execute(&request, limits, &deep, Instant::now()).unwrap_err();
        assert_eq!(error.status, 422);
        assert!(
            error
                .message
                .contains("global initializer constant expression"),
            "{}",
            error.message
        );
        for (label, source) in [
            (
                "data offset",
                repeated(
                    "(module (memory 1) (data (offset i32.const 0 ",
                    "i32.const 0 i32.add ",
                    40,
                    ") \"x\") (func (export \"run\")))",
                ),
            ),
            (
                "element offset",
                repeated(
                    "(module (table 2 funcref) (elem (offset i32.const 0 ",
                    "i32.const 0 i32.add ",
                    40,
                    ") func $f) (func $f) (func (export \"run\")))",
                ),
            ),
        ] {
            let error = execute(&request, limits, &module(&source), Instant::now()).unwrap_err();
            assert!(error.message.contains(label), "{label}: {}", error.message);
        }
        // Extended-const arithmetic of ordinary length still runs.
        let short = run(
            "(module (global i32 i32.const 40 i32.const 2 i32.add) (func (export \"run\") (result i32) global.get 0))",
            json!({}),
        );
        assert_eq!(short["results"][0]["value"], "42");
    }

    #[test]
    fn memory_and_table_limits_are_totals() {
        // Each memory or table fits the limit alone; together they do not.
        let memories = run(&fixture("limits.wat"), json!({}));
        assert_eq!(memories["outcome"]["status"], "memory_limit", "{memories}");
        assert_eq!(memories["outcome"]["phase"], "instantiate");
        let fits = run(
            &fixture("limits.wat"),
            json!({"limits":{"memory_pages":320}}),
        );
        assert_eq!(fits["outcome"]["status"], "returned", "{fits}");
        let tables = run(&fixture("tables.wat"), json!({}));
        assert_eq!(tables["outcome"]["status"], "table_limit", "{tables}");
        let many = run(
            &repeated("(module ", "(memory 1) ", 17, "(func (export \"run\")))"),
            json!({}),
        );
        assert_eq!(many["outcome"]["status"], "memory_limit");
        assert!(
            many["outcome"]["message"]
                .as_str()
                .unwrap()
                .contains("at most 16")
        );
        // Growth counts against the same total: 2 + 3 pages fit 5, 2 more do not.
        let grow = run(
            "(module (memory $a 2) (memory $b 1) (func (export \"run\") (result i32)
                (drop (memory.grow $b (i32.const 2))) (memory.grow $a (i32.const 1))))",
            json!({"limits":{"memory_pages":5}}),
        );
        assert_eq!(grow["results"][0]["value"], "-1", "{grow}");
        assert_eq!(grow["memory_grow_denied"], 1);
    }

    #[test]
    fn a_large_function_body_runs_within_an_ordinary_fuel_limit() {
        // Lazy compilation charged about 7 fuel per body byte against one fuel
        // slice on the first call, so a body over about 140 KB never ran.
        let source = repeated(
            "(module (func (export \"run\") (result i32) i32.const 0 ",
            "i32.const 1 i32.add ",
            70_000,
            "))",
        );
        let bytes = module(&source);
        assert!(bytes.len() > 200_000, "{}", bytes.len());
        let (request, limits) = request(json!({}));
        let result = execute(&request, limits, &bytes, Instant::now()).unwrap();
        assert_eq!(
            result["outcome"]["status"], "returned",
            "{}",
            result["outcome"]
        );
        assert_eq!(result["results"][0]["value"], "70000");
    }

    #[test]
    fn long_float_results_are_short_literals_and_no_error_quotes_a_value() {
        let big = run(&fixture("floats.wat"), json!({}));
        assert_eq!(big["results"][0]["value"], "1e300");
        let small = run(&fixture("floats.wat"), json!({"export":"small"}));
        assert_eq!(small["results"][0]["value"], "1.2345678901234566e-50");
        for record in [&big, &small] {
            let mut full = record.clone();
            full["schema"] = json!(SCHEMA);
            assert!(validation::schema("WasmTypedValue", &full["results"][0], 500).is_ok());
        }
        // A forged record whose value breaks the contract is refused without
        // the validator's message, which quotes the value.
        let forged =
            json!({"results":[{"type":"f64","value":format!("SECRET{}", "9".repeat(80))}]});
        let error = checked(&forged).unwrap_err();
        assert!(
            !error.message.contains("SECRET") && !error.message.contains("999"),
            "{}",
            error.message
        );
        // Every request refusal names the problem, never the value itself.
        let long = format!("0.{}1", "0".repeat(80));
        for body in [
            json!({"args":[{"type":"f64","value":long}]}),
            json!({"args":[{"type":"f32","value":"1e40"}]}),
            json!({"args":[{"type":"f64","value":"infinity"}]}),
        ] {
            let mut full = json!({"artifact_id":"1","sha256":"0".repeat(64),"export":"echo","confirm_offline_execution":true});
            full["args"] = body["args"].clone();
            let error = Request::parse(&serde_json::to_vec(&full).unwrap()).unwrap_err();
            let quoted = body["args"][0]["value"].as_str().unwrap();
            assert!(!error.message.contains(quoted), "{}", error.message);
        }
    }

    #[test]
    fn float_literals_take_only_the_contract_spellings() {
        for (ty, text) in [
            ("f64", "-nan"),
            ("f64", "+nan"),
            ("f64", "NaN"),
            ("f64", "infinity"),
            ("f64", "+inf"),
            ("f64", "+1"),
            ("f64", ".5"),
            ("f64", "1e"),
            ("f32", "1e40"),
            ("f32", "-1e40"),
            ("f64", "1e400"),
        ] {
            assert!(
                value(&Typed {
                    ty: ty.into(),
                    value: text.into()
                })
                .is_err(),
                "{ty} {text}"
            );
        }
        for (ty, text, back) in [
            ("f64", "1e300", "1e300"),
            ("f64", "1.5e-3", "0.0015"),
            ("f32", "-0", "-0.0"),
            ("f64", "inf", "inf"),
            ("f32", "-inf", "-inf"),
            ("f64", "2", "2.0"),
            ("f64", "1E+2", "100.0"),
        ] {
            let parsed = value(&Typed {
                ty: ty.into(),
                value: text.into(),
            })
            .unwrap();
            assert_eq!(encode(&parsed).value, back, "{ty} {text}");
        }
        assert!(
            value(&Typed {
                ty: "i64".into(),
                value: "1".repeat(65)
            })
            .is_err()
        );
    }

    #[test]
    fn import_calls_check_the_deadline() {
        // A loop of import calls is cheap in fuel but slow in time; checking the
        // deadline only between fuel slices let a 1 s deadline run for 3 s.
        let started = Instant::now();
        let result = run(
            &fixture("hostloop.wat"),
            json!({
            "imports":[{"module":"env","field":"tick","results":[{"type":"i32","value":"1"}]}],
            "limits":{"fuel":10_000_000_000u64,"deadline_ms":300}}),
        );
        let elapsed = started.elapsed();
        assert_eq!(
            result["outcome"]["status"], "deadline_exceeded",
            "{}",
            result["outcome"]
        );
        assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
    }

    #[test]
    fn an_import_call_after_the_deadline_ends_the_run() {
        // Deterministic half of the check above: once the deadline has passed,
        // the next import call refuses, whatever fuel is left.
        let mut state = HostState {
            limiter: Limiter::default(),
            functions: vec![ImportFunction {
                function_index: 0,
                module: "env".into(),
                field: "tick".into(),
                plan: Plan::Results(vec![Val::I32(1)]),
                calls: 0,
            }],
            calls: Vec::new(),
            total_calls: 0,
            trapped: None,
            deadline: Instant::now() - Duration::from_millis(1),
            deadline_hit: false,
        };
        let mut results = [Val::I32(0)];
        assert!(stub_call(&mut state, 0, &[], &mut results).is_err());
        assert!(state.deadline_hit);
        assert_eq!(
            state.total_calls, 0,
            "a refused call is not recorded as made"
        );
        state.deadline = Instant::now() + Duration::from_secs(60);
        state.deadline_hit = false;
        assert!(stub_call(&mut state, 0, &[], &mut results).is_ok());
        assert!(matches!(results[0], Val::I32(1)));
    }

    #[test]
    fn element_items_are_capped_and_a_late_instantiation_is_reported() {
        let (request, limits) = request(json!({}));
        let many = module(&repeated(
            "(module (func $f) (elem func ",
            "$f ",
            MAX_ELEMENT_ITEMS as usize + 1,
            ") (func (export \"run\")))",
        ));
        let error = execute(&request, limits, &many, Instant::now()).unwrap_err();
        assert_eq!(error.status, 422);
        assert!(
            error.message.contains("element segment items"),
            "{}",
            error.message
        );
        // Within the cap, a deadline that passes while the module is compiled
        // and instantiated ends the run there, not as a call that returned.
        let full = module(&repeated(
            "(module (func $f) (elem func ",
            "$f ",
            MAX_ELEMENT_ITEMS as usize,
            ") (func (export \"run\") (result i32) i32.const 1))",
        ));
        let (late, limits) = self::request(json!({"limits":{"deadline_ms":1}}));
        let result = execute(
            &late,
            limits,
            &full,
            Instant::now() - Duration::from_millis(5),
        )
        .unwrap();
        assert_eq!(
            result["outcome"]["status"], "deadline_exceeded",
            "{}",
            result["outcome"]
        );
        assert_eq!(result["outcome"]["phase"], "instantiate");
        assert_eq!(result["results"], Value::Null);
    }

    #[test]
    fn integer_nan_and_v128_literals_take_only_the_contract_spellings() {
        for (ty, text) in [
            ("i32", "+1"),
            ("i32", "01"),
            ("i64", "-007"),
            ("i32", "-"),
            ("i32", " 1"),
            ("f32", "nan:0x0007fc00000"),
            ("f32", "nan:0x7fc0000"),
            ("f64", "nan:0x+7ff8000000000001"),
            ("v128", "+1"),
            ("v128", "0x+1"),
            ("v128", ""),
        ] {
            assert!(
                value(&Typed {
                    ty: ty.into(),
                    value: text.into()
                })
                .is_err(),
                "{ty} {text}"
            );
        }
        for (ty, text) in [
            ("i32", "0"),
            ("i32", "-0"),
            ("i64", "-12"),
            ("f32", "nan:0x7fc00001"),
            ("f64", "nan:0x7ff8000000000001"),
            ("v128", "0x1"),
        ] {
            assert!(
                value(&Typed {
                    ty: ty.into(),
                    value: text.into()
                })
                .is_ok(),
                "{ty} {text}"
            );
        }
    }

    #[test]
    fn moving_an_unreadable_store_aside_never_replaces_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("wasm-runs-v1.json");
        let taken = directory.path().join("wasm-runs-v1.json.unreadable-7");
        std::fs::write(&taken, b"an earlier unreadable store").unwrap();
        std::fs::write(&store, b"{not json").unwrap();
        let name = move_aside(&store, 7).unwrap();
        assert_eq!(name, "wasm-runs-v1.json.unreadable-7-1");
        assert_eq!(
            std::fs::read(&taken).unwrap(),
            b"an earlier unreadable store"
        );
        assert_eq!(
            std::fs::read(directory.path().join(&name)).unwrap(),
            b"{not json"
        );
        assert!(!store.exists());
    }

    #[test]
    fn a_run_id_is_random_not_derived_from_the_inputs() {
        // run_id carried 48 bits of inputs_digest, which a reader could test
        // guesses at the inputs against.
        let (request, limits) = request(json!({}));
        let first = run_blocking_record(&request, limits);
        let second = run_blocking_record(&request, limits);
        assert_eq!(
            first["provenance"]["inputs_digest"],
            second["provenance"]["inputs_digest"]
        );
        let digest = first["provenance"]["inputs_digest"].as_str().unwrap();
        for record in [&first, &second] {
            let id = record["run_id"].as_str().unwrap();
            assert!(!id.contains(&digest[..12]), "{id}");
            assert_eq!(id.rsplit('-').next().unwrap().len(), 24, "{id}");
        }
        assert_ne!(first["run_id"], second["run_id"]);
    }

    /// The record run_blocking builds for one artifact in a fresh store.
    fn run_blocking_record(request: &Request, limits: Limits) -> Value {
        let directory = tempfile::tempdir().unwrap();
        let bytes = module(&fixture("arith.wat"));
        let hash = hex::encode(Sha256::digest(&bytes));
        std::fs::create_dir_all(directory.path().join("blobs")).unwrap();
        std::fs::write(directory.path().join(format!("blobs/{hash}.bin")), &bytes).unwrap();
        let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"wasm","url":"https://example.test/a.wasm","mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        std::fs::write(
            directory.path().join("manifest.jsonl"),
            format!("{artifact}\n"),
        )
        .unwrap();
        let mut request = request.clone();
        request.sha256 = hash;
        request.args = vec![
            Typed {
                ty: "i32".into(),
                value: "1".into(),
            },
            Typed {
                ty: "i32".into(),
                value: "2".into(),
            },
        ];
        run_blocking(directory.path(), &request, limits).unwrap()
    }

    /// run_blocking on `bytes` in a fresh store, with `body` as the request
    /// (artifact_id, sha256 and the confirmation are filled in).
    fn run_stored(bytes: &[u8], mut body: Value) -> Value {
        let directory = tempfile::tempdir().unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        std::fs::create_dir_all(directory.path().join("blobs")).unwrap();
        std::fs::write(directory.path().join(format!("blobs/{hash}.bin")), bytes).unwrap();
        let artifact = json!({"protocol_version":1,"artifact_id":"1","session_id":"1","navigation_id":"1","frame_id":"1","parent_artifact_id":"0","creator_event_id":"0","kind":"wasm","url":"https://example.test/a.wasm","mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        std::fs::write(
            directory.path().join("manifest.jsonl"),
            format!("{artifact}\n"),
        )
        .unwrap();
        body["artifact_id"] = json!("1");
        body["sha256"] = json!(hash);
        body["confirm_offline_execution"] = json!(true);
        let (request, limits) = Request::parse(&serde_json::to_vec(&body).unwrap()).unwrap();
        run_blocking(directory.path(), &request, limits).unwrap()
    }

    /// A module that fills every part of a record: 200 imports with long
    /// names, 300 import calls of 16 values each way, 100 results and memory
    /// for the largest writes and reads.
    pub(super) fn maximal_module() -> Vec<u8> {
        let sixteen = " i64".repeat(16);
        let long = "m".repeat(200);
        let mut source = format!(
            "(module (import \"env\" \"big\" (func $big (param{sixteen}) (result{sixteen})))"
        );
        for index in 0..200 {
            source.push_str(&format!(
                "(import \"{long}\" \"f{index}\" (func (param{sixteen})))"
            ));
        }
        source.push_str("(memory 8) (func (export \"run\") (param");
        source.push_str(&sixteen);
        source.push_str(") (result");
        source.push_str(&" i64".repeat(100));
        source
            .push_str(") (local $n i32) (local.set $n (i32.const 300)) (block $done (loop $again");
        source.push_str("(br_if $done (i32.eqz (local.get $n)))");
        for index in 0..16 {
            source.push_str(&format!("(local.get {index})"));
        }
        source.push_str("(call $big)");
        source.push_str(&"(drop)".repeat(16));
        source.push_str("(local.set $n (i32.sub (local.get $n) (i32.const 1))) (br $again)))");
        source.push_str(&"(i64.const -9223372036854775808)".repeat(100));
        source.push_str("))");
        module(&source)
    }

    /// The largest request a run admits against maximal_module.
    pub(super) fn maximal_body() -> Value {
        let value = json!({"type": "i64", "value": "-9223372036854775808"});
        let sixteen = vec![value.clone(); 16];
        json!({"export": "run", "args": sixteen,
            "imports": [{"module": "env", "field": "big", "results": sixteen}],
            "memory_writes": (0..16).map(|index| json!({"offset": index * 16384, "hex": "ab".repeat(16384)})).collect::<Vec<_>>(),
            "memory_reads": (0..16).map(|index| json!({"offset": index * 2048, "length": 2048})).collect::<Vec<_>>(),
            "expect": {"memory": (0..16).map(|index| json!({"read": index, "hex": "ab".repeat(2048)})).collect::<Vec<_>>()},
            "limits": {"deadline_ms": 10000}})
    }

    #[test]
    fn a_maximal_record_fits_the_mcp_inline_limit() {
        // 64 KiB of reads and the rest of a large record came to more than the
        // 128 KiB reb-api mcp inlines, so a Full client got a structural
        // summary without the bytes.
        let record = run_stored(&maximal_module(), maximal_body());
        assert_eq!(
            record["outcome"]["status"], "returned",
            "{}",
            record["outcome"]
        );
        let pretty = serde_json::to_string_pretty(&record).unwrap().len();
        assert!(pretty <= RECORD_INLINE_BUDGET, "{pretty}");
        assert!(!record["size_trimmed"].as_array().unwrap().is_empty());
        assert_eq!(record["import_calls_total"], 300);
        assert_eq!(record["expectation"]["all_match"], true);
        for read in record["memory_reads"].as_array().unwrap() {
            assert_eq!(
                read["hex"].as_str().unwrap().len(),
                4096,
                "reads are never trimmed"
            );
        }
        let names = record["imports"].as_array().unwrap();
        assert!(
            names
                .iter()
                .all(|entry| entry["module"].as_str().unwrap().len() <= MAX_RECORD_NAME + 6)
        );
        // A small record is left whole.
        let small = run_blocking_record(&request(json!({})).0, request(json!({})).1);
        assert_eq!(small["size_trimmed"], json!([]));
    }

    #[test]
    fn one_expectation_per_read() {
        let body = |memory: Value| {
            json!({"artifact_id":"1","sha256":"0".repeat(64),"export":"run","confirm_offline_execution":true,
                "memory_reads":[{"offset":0,"length":1},{"offset":1,"length":1}],"expect":{"memory":memory}})
        };
        let one_each = body(json!([{"read":0,"hex":"53"},{"read":1,"hex":"45"}]));
        assert!(Request::parse(&serde_json::to_vec(&one_each).unwrap()).is_ok());
        let guesses = body(json!([{"read":0,"hex":"52"},{"read":0,"hex":"53"}]));
        let error = Request::parse(&serde_json::to_vec(&guesses).unwrap()).unwrap_err();
        assert!(
            error.message.contains("one expected memory entry per read"),
            "{}",
            error.message
        );
    }

    #[test]
    fn recorded_import_results_are_capped() {
        let values = (0..40)
            .map(|_| json!({"type":"i64","value":"9"}))
            .collect::<Vec<_>>();
        let result = run(
            &fixture("wide.wat"),
            json!({"imports":[{"module":"env","field":"many","results":values}]}),
        );
        assert_eq!(
            result["outcome"]["status"], "returned",
            "{}",
            result["outcome"]
        );
        let call = &result["import_calls"][0];
        assert_eq!(
            call["results"].as_array().unwrap().len(),
            MAX_RECORDED_RESULTS
        );
        assert_eq!(call["results_truncated"], true);
    }
}
