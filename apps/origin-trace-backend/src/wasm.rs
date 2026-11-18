//! Inert binary inspection of a module of any size, read page by page.
//!
//! One pass indexes where each unit's rows begin (a section header, a
//! section's entries, one function body); a page decodes only the units it
//! shows, from their original bytes. Decoding is not semantic validation or
//! execution.
use crate::{
    error::{Error, Result, check_cancelled},
    result_cache::{Cache, kept},
    wasm_graph,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Write as _,
    path::Path,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
};
use wasmparser::{
    BinaryReader, CompositeInnerType, Data, Element, Encoding, Export, FromReader, FunctionBody,
    Global, Import, MemoryType, Operator, Parser, Payload, RecGroup, SectionLimited, Table,
    TagType, TypeRef,
};

/// Every section name once, comma separated, is the longest honest request.
const MAX_SECTION_REQUEST: usize = 128;
/// A row window stops at `row_limit` rows or `WINDOW_BYTES` of serialized
/// rows, whichever comes first, so one page always fits a 128 KiB MCP result;
/// `next_offset` continues.
pub const WINDOW_MAX_ROWS: usize = 2048;
pub const WINDOW_BYTES: usize = 98_304;
/// Matches per search page; `next_offset` continues.
pub const MATCH_PAGE: usize = 1000;
/// Indexes and search tallies kept by module SHA-256 and section request, so
/// later pages and Find steps decode only the units they show.
const CACHED_INSPECTIONS: usize = 4;
const CACHED_SEARCHES: usize = 8;
/// Rows between polls of the request, so an abandoned read stops.
const POLL_ROWS: u64 = 4096;
const WHAT: &str = "WASM inspection";
const NOTICE: &str = "Static binary decoding only. Type validity, runtime calls, traps, memory growth, and value flow are not established.";

/// Section names double as the request vocabulary, so a row label and the
/// filter that selects it cannot drift apart. The index is the section ID.
const SECTION_NAMES: [&str; 14] = [
    "custom",
    "type",
    "import",
    "function",
    "table",
    "memory",
    "global",
    "export",
    "start",
    "element",
    "code",
    "data",
    "data_count",
    "tag",
];

fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

pub(crate) fn section_name(id: u8) -> &'static str {
    SECTION_NAMES.get(id as usize).copied().unwrap_or("unknown")
}

/// Names in section ID order, which is not always the binary's order:
/// `data_count` (12) precedes `code` (10) and `tag` (13) sits between `memory`
/// and `global`. Repeated custom sections and IDs this version cannot name
/// collapse to one name.
fn section_list(ids: &BTreeSet<u8>) -> Vec<&'static str> {
    let mut names = ids.iter().map(|id| section_name(*id)).collect::<Vec<_>>();
    names.dedup();
    names
}

/// Parses a `sections` request value into section IDs.
///
/// An empty or unknown name is refused instead of widening to the whole
/// module: a caller that misspells a section must not receive a
/// complete-looking document it never asked for. The rejected name is not
/// echoed back, so the message carries the vocabulary instead of the input.
pub fn requested_sections(raw: &str) -> Result<BTreeSet<u8>> {
    if raw.len() > MAX_SECTION_REQUEST {
        return Err(Error::bad("WASM section request exceeds 128 bytes"));
    }
    let mut ids = BTreeSet::new();
    for name in raw.split(',') {
        let id = SECTION_NAMES
            .iter()
            .position(|known| *known == name)
            .ok_or_else(|| {
                Error::bad(format!(
                    "A WASM section request names only: {}",
                    SECTION_NAMES.join(", ")
                ))
            })?;
        ids.insert(id as u8);
    }
    Ok(ids)
}

macro_rules! operator_names {
    ($(@$proposal:ident $op:ident $({ $($field:ident: $ty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
        pub(crate) fn operator_name(op: &Operator<'_>) -> &'static str {
            match op { $(Operator::$op $( { $($field: _),* } )? => stringify!($visit),)* _ => "visit_unknown" }
        }
        const OPERATOR_NAMES: &[&str] = &[$(stringify!($visit)),*];
    };
}
wasmparser::for_each_operator!(operator_names);

/// The dotted mnemonic for an operator. The linear listing and the block graph
/// share one spelling so a row can be matched between the two views.
pub(crate) fn mnemonic(op: &Operator<'_>) -> String {
    spelled(op).to_owned()
}

/// Each operator's mnemonic, spelled once: a listing of millions of rows
/// looks it up instead of rebuilding it per instruction.
fn spelled(op: &Operator<'_>) -> &'static str {
    static SPELLED: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    let name = operator_name(op);
    SPELLED
        .get_or_init(|| {
            OPERATOR_NAMES
                .iter()
                .map(|name| (*name, spell(name)))
                .collect()
        })
        .get(name)
        .map_or("unknown", String::as_str)
}

fn spell(name: &str) -> String {
    let name = name.trim_start_matches("visit_");
    let mut mnemonic = if let Some((prefix, suffix)) = name.split_once('_') {
        if [
            "i32", "i64", "f32", "f64", "v128", "i8x16", "i16x8", "i32x4", "i64x2", "f32x4",
            "f64x2", "local", "global", "memory", "table", "ref", "struct", "array",
        ]
        .contains(&prefix)
        {
            format!("{prefix}.{suffix}")
        } else {
            name.into()
        }
    } else {
        name.into()
    };
    mnemonic = mnemonic.replace(".atomic_", ".atomic.");
    if mnemonic.contains(".atomic.rmw")
        && let Some(index) = mnemonic.find('_')
    {
        mnemonic.replace_range(index..index + 1, ".");
    }
    mnemonic
}

/// An instruction's mnemonic and named immediates. A branch table lists every
/// target, however many it has.
pub(crate) fn instruction(op: &Operator<'_>) -> String {
    let mnemonic = spelled(op);
    if let Operator::BrTable { targets } = op {
        let labels = targets
            .targets()
            .map(|t| {
                t.map(|v| v.to_string())
                    .unwrap_or_else(|_| "invalid".into())
            })
            .collect::<Vec<_>>();
        return format!(
            "{mnemonic} [{}] default={}",
            labels.join(", "),
            targets.default()
        );
    }
    // The immediates are the parser's Debug fields after its variant name,
    // written once into the row's own string.
    let mut text = String::with_capacity(mnemonic.len() + 32);
    text.push_str(mnemonic);
    let start = text.len();
    let _ = write!(text, "{op:?}");
    match text[start..].find(" { ") {
        Some(index) => text.replace_range(start..start + index, ""),
        None => text.truncate(start),
    }
    text
}

fn type_text(inner: &CompositeInnerType) -> String {
    match inner {
        CompositeInnerType::Func(function) => {
            let list = |values: &[wasmparser::ValType]| {
                values
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            format!(
                "({}) -> ({})",
                list(function.params()),
                list(function.results())
            )
        }
        CompositeInnerType::Struct(value) => format!(
            "struct - {} fields (inspect original bytes for field layout)",
            value.fields.len()
        ),
        CompositeInnerType::Array(_) => "array (inspect original bytes for element layout)".into(),
        CompositeInnerType::Cont(_) => {
            "continuation (inspect original bytes for type details)".into()
        }
    }
}

/// The entry sections whose rows are one entry each.
#[derive(Clone, Copy)]
enum Entries {
    Table,
    Memory,
    Global,
    Tag,
    Export,
    Data,
    Element,
}

/// A run of rows one decode reproduces on its own, from its byte range.
enum Unit {
    /// A row known when indexing: a section header, the start function or a
    /// custom section.
    Single {
        kind: &'static str,
        start: usize,
        end: usize,
        function: Option<u32>,
        text: String,
    },
    Types {
        start: usize,
        end: usize,
        first_type: u64,
    },
    Imports {
        start: usize,
        end: usize,
        first_function: u32,
    },
    Declarations {
        start: usize,
        end: usize,
        first_function: u32,
    },
    Entries {
        kind: Entries,
        start: usize,
        end: usize,
    },
    Body {
        index: u32,
        ty: u32,
        start: usize,
        end: usize,
    },
}

/// One row's place in the original bytes, ahead of its text.
struct Coord {
    kind: &'static str,
    start: usize,
    end: usize,
    function: Option<u32>,
    /// The direct callee of `call` and `return_call`, or the function
    /// `ref.func` names: structure, like `function`, so a read that omits row
    /// text still names it (and a researcher name joins to it).
    target: Option<u32>,
}

/// Receives each row of a unit in order. It formats the row's text only if it
/// calls `text`, and returns false to stop the unit.
type Emit<'e> = dyn FnMut(&Coord, &mut dyn FnMut() -> String) -> Result<bool> + 'e;

fn each<'a, T: FromReader<'a>>(
    bytes: &'a [u8],
    start: usize,
    end: usize,
    mut row: impl FnMut(usize, T) -> Result<bool>,
) -> Result<()> {
    let reader =
        SectionLimited::<T>::new(BinaryReader::new(&bytes[start..end], start)).map_err(bad)?;
    for entry in reader.into_iter_with_offsets() {
        let (offset, entry) = entry.map_err(bad)?;
        if !row(offset, entry)? {
            break;
        }
    }
    Ok(())
}

fn point(kind: &'static str, at: usize, function: Option<u32>) -> Coord {
    Coord {
        kind,
        start: at,
        end: at,
        function,
        target: None,
    }
}

/// Reproduces a unit's rows in order from the original bytes. Metadata
/// entries without a complete item range use a point coordinate.
fn decode(bytes: &[u8], unit: &Unit, emit: &mut Emit) -> Result<()> {
    match unit {
        Unit::Single {
            kind,
            start,
            end,
            function,
            text,
        } => {
            let coord = Coord {
                kind,
                start: *start,
                end: *end,
                function: *function,
                target: None,
            };
            emit(&coord, &mut || text.clone())?;
        }
        Unit::Types {
            start,
            end,
            first_type,
        } => {
            let mut index = *first_type;
            each::<RecGroup>(bytes, *start, *end, |offset, group| {
                // Recursive type groups share the group's start.
                for ty in group.types() {
                    let at = index;
                    index += 1;
                    let inner = &ty.composite_type.inner;
                    if !emit(&point("type", offset, None), &mut || {
                        format!("type {at}: {}", type_text(inner))
                    })? {
                        return Ok(false);
                    }
                }
                Ok(true)
            })?;
        }
        Unit::Imports {
            start,
            end,
            first_function,
        } => {
            let mut next = *first_function;
            each::<Import>(bytes, *start, *end, |offset, entry| {
                let function = if matches!(entry.ty, TypeRef::Func(_)) {
                    let index = next;
                    next = next
                        .checked_add(1)
                        .ok_or_else(|| Error::protocol("WASM function index overflow"))?;
                    Some(index)
                } else {
                    None
                };
                emit(&point("import", offset, function), &mut || {
                    format!("{:?} :: {:?} - {:?}", entry.module, entry.name, entry.ty)
                })
            })?;
        }
        Unit::Declarations {
            start,
            end,
            first_function,
        } => {
            let mut index = *first_function;
            each::<u32>(bytes, *start, *end, |offset, ty| {
                let at = index;
                index = index
                    .checked_add(1)
                    .ok_or_else(|| Error::protocol("WASM function index overflow"))?;
                // The declared type of every function is static data in this
                // section, so an export's type is reachable without decoding
                // any function body.
                emit(&point("declaration", offset, Some(at)), &mut || {
                    format!("func {at} declares type {ty}")
                })
            })?;
        }
        Unit::Entries { kind, start, end } => {
            let (start, end) = (*start, *end);
            match kind {
                Entries::Table => each::<Table>(bytes, start, end, |offset, entry| {
                    emit(&point("table", offset, None), &mut || format!("{entry:?}"))
                })?,
                Entries::Memory => each::<MemoryType>(bytes, start, end, |offset, entry| {
                    emit(&point("memory", offset, None), &mut || format!("{entry:?}"))
                })?,
                Entries::Global => each::<Global>(bytes, start, end, |offset, entry| {
                    emit(&point("global", offset, None), &mut || format!("{entry:?}"))
                })?,
                Entries::Tag => each::<TagType>(bytes, start, end, |offset, entry| {
                    emit(&point("tag", offset, None), &mut || format!("{entry:?}"))
                })?,
                Entries::Export => each::<Export>(bytes, start, end, |offset, entry| {
                    emit(&point("export", offset, None), &mut || {
                        format!("{:?} - {:?} {}", entry.name, entry.kind, entry.index)
                    })
                })?,
                // A segment's bytes are shown by Hex at its exact range, so
                // the row names its kind and size with a short preview.
                Entries::Data => each::<Data>(bytes, start, end, |offset, entry| {
                    let coord = Coord {
                        end: entry.range.end,
                        ..point("data", offset, None)
                    };
                    emit(&coord, &mut || {
                        let preview = hex::encode(&entry.data[..entry.data.len().min(32)]);
                        format!(
                            "{:?} - {} bytes - hex {preview}{}",
                            entry.kind,
                            entry.data.len(),
                            if entry.data.len() > 32 {
                                " [preview; Hex shows every byte]"
                            } else {
                                ""
                            }
                        )
                    })
                })?,
                Entries::Element => each::<Element>(bytes, start, end, |offset, entry| {
                    let coord = Coord {
                        end: entry.range.end,
                        ..point("element", offset, None)
                    };
                    emit(&coord, &mut || {
                        "element segment (references retained in original bytes)".into()
                    })
                })?,
            }
        }
        Unit::Body {
            index,
            ty,
            start,
            end,
        } => {
            let index = *index;
            let body = FunctionBody::new(BinaryReader::new(&bytes[*start..*end], *start));
            let header = Coord {
                kind: "function",
                start: *start,
                end: *end,
                function: Some(index),
                target: None,
            };
            if !emit(&header, &mut || format!("func {index} (type {ty})"))? {
                return Ok(());
            }
            let mut locals = body.get_locals_reader().map_err(bad)?;
            for _ in 0..locals.get_count() {
                let offset = locals.original_position();
                let (count, ty) = locals.read().map_err(bad)?;
                let coord = Coord {
                    end: locals.original_position(),
                    ..point("local", offset, Some(index))
                };
                if !emit(&coord, &mut || format!("local group: {count} x {ty:?}"))? {
                    return Ok(());
                }
            }
            let mut reader = body.get_operators_reader().map_err(bad)?;
            while !reader.eof() {
                let (op, offset) = reader.read_with_offset().map_err(bad)?;
                let target = match op {
                    Operator::Call { function_index }
                    | Operator::ReturnCall { function_index }
                    | Operator::RefFunc { function_index } => Some(function_index),
                    _ => None,
                };
                let coord = Coord {
                    kind: "instruction",
                    start: offset,
                    end: reader.original_position(),
                    function: Some(index),
                    target,
                };
                if !emit(&coord, &mut || instruction(&op))? {
                    return Ok(());
                }
            }
            reader.finish().map_err(bad)?;
        }
    }
    Ok(())
}

fn row(coord: &Coord, text: String) -> Value {
    let mut row = json!({"kind":coord.kind,"byte_offset":coord.start,"byte_end":coord.end,
        "function_index":coord.function,"text":text});
    if let Some(target) = coord.target {
        row["target_function_index"] = json!(target);
    }
    row
}

struct Segment {
    first_row: u64,
    /// The first row's byte offset. Rows never move backward in the binary,
    /// so a byte offset is found by bisecting these.
    first_byte: usize,
    unit: Unit,
}

/// One module's row index under one section request.
pub struct Inspection {
    summary: Value,
    segments: Vec<Segment>,
    total_rows: u64,
}

struct Builder<'b> {
    bytes: &'b [u8],
    cancelled: &'b AtomicBool,
    segments: Vec<Segment>,
    total_rows: u64,
    instructions: u64,
}
impl Builder<'_> {
    /// Walks a unit once, so its row count comes from the same decode a page
    /// uses and every byte it covers is decoded before any page is served.
    fn add(&mut self, unit: Unit) -> Result<u64> {
        let (mut rows, mut first, mut instructions) = (0u64, None, 0u64);
        let cancelled = self.cancelled;
        decode(self.bytes, &unit, &mut |coord, _| {
            if rows.is_multiple_of(POLL_ROWS) {
                check_cancelled(cancelled, WHAT)?;
            }
            first.get_or_insert(coord.start);
            rows += 1;
            instructions += u64::from(coord.kind == "instruction");
            Ok(true)
        })?;
        if let Some(first_byte) = first {
            self.segments.push(Segment {
                first_row: self.total_rows,
                first_byte,
                unit,
            });
            self.total_rows += rows;
            self.instructions += instructions;
        }
        Ok(rows)
    }
}

/// Indexes `bytes`, with rows only for the requested sections.
///
/// `sections` of `None` requests the whole module. A request narrows which
/// sections produce rows; it never narrows the traversal itself, so section
/// framing, import and function counts, and the function/code agreement check
/// hold exactly as they do for an unfiltered request.
fn index(
    bytes: &[u8],
    sections: Option<&BTreeSet<u8>>,
    cancelled: &AtomicBool,
) -> Result<Inspection> {
    // An absent request selects every section, including an ID this version
    // cannot name. A present request selects exactly the IDs it names.
    let selected = |id: u8| sections.is_none_or(|ids| ids.contains(&id));
    let mut built = Builder {
        bytes,
        cancelled,
        segments: Vec::new(),
        total_rows: 0,
        instructions: 0,
    };
    let mut omissions: Vec<String> = Vec::new();
    let mut analyzed = BTreeSet::new();
    let mut excluded = BTreeSet::new();
    let mut truncated = BTreeSet::new();
    // The section whose rows are being decoded, or `None` while a section the
    // request excluded is walked, so an excluded section is never reported
    // as left opaque.
    let mut current = None;
    let mut section_count = 0u64;
    let mut imported_functions = 0u32;
    let mut functions = 0u32;
    let mut declared_functions = 0u32;
    let mut types = 0u64;
    let mut ended = false;
    let mut function_types = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        check_cancelled(cancelled, WHAT)?;
        let payload = payload.map_err(bad)?;
        if let Some((id, range)) = payload.as_section() {
            section_count += 1;
            if selected(id) {
                analyzed.insert(id);
                current = Some(id);
            } else {
                excluded.insert(id);
                current = None;
            }
            // Every section keeps its row, including one the request excludes,
            // so a filtered document still names the bytes it did not decode.
            built.add(Unit::Single {
                kind: "section",
                start: range.start,
                end: range.end,
                function: None,
                text: format!("{} section ({} bytes)", section_name(id), range.len()),
            })?;
        }
        let entries = |wanted: bool, kind: Entries, range: std::ops::Range<usize>| {
            wanted.then_some(Unit::Entries {
                kind,
                start: range.start,
                end: range.end,
            })
        };
        let unit = match payload {
            Payload::Version {
                num: 1,
                encoding: Encoding::Module,
                ..
            } => None,
            Payload::Version { .. } => {
                return Err(Error::protocol(
                    "Only WASM core module version 1 is supported",
                ));
            }
            Payload::TypeSection(reader) => {
                let range = reader.range();
                if selected(1) {
                    types += built.add(Unit::Types {
                        start: range.start,
                        end: range.end,
                        first_type: types,
                    })?;
                }
                None
            }
            Payload::ImportSection(reader) => {
                // A defined function's index continues the imported range, so
                // imports are always counted even when their rows are not
                // requested. Only the rows follow the request.
                let range = reader.range();
                let first_function = imported_functions;
                for (seen, entry) in reader.into_iter().enumerate() {
                    if (seen as u64).is_multiple_of(POLL_ROWS) {
                        check_cancelled(cancelled, WHAT)?;
                    }
                    if matches!(entry.map_err(bad)?.ty, TypeRef::Func(_)) {
                        imported_functions = imported_functions
                            .checked_add(1)
                            .ok_or_else(|| Error::protocol("WASM function index overflow"))?;
                    }
                }
                selected(2).then_some(Unit::Imports {
                    start: range.start,
                    end: range.end,
                    first_function,
                })
            }
            Payload::FunctionSection(reader) => {
                let range = reader.range();
                declared_functions = reader.count();
                for (seen, ty) in reader.into_iter().enumerate() {
                    if (seen as u64).is_multiple_of(POLL_ROWS) {
                        check_cancelled(cancelled, WHAT)?;
                    }
                    function_types.push(ty.map_err(bad)?);
                }
                selected(3).then_some(Unit::Declarations {
                    start: range.start,
                    end: range.end,
                    first_function: imported_functions,
                })
            }
            Payload::TableSection(reader) => entries(selected(4), Entries::Table, reader.range()),
            Payload::MemorySection(reader) => entries(selected(5), Entries::Memory, reader.range()),
            Payload::GlobalSection(reader) => entries(selected(6), Entries::Global, reader.range()),
            Payload::TagSection(reader) => entries(selected(13), Entries::Tag, reader.range()),
            Payload::ExportSection(reader) => entries(selected(7), Entries::Export, reader.range()),
            Payload::ElementSection(reader) => {
                entries(selected(9), Entries::Element, reader.range())
            }
            Payload::DataSection(reader) => entries(selected(11), Entries::Data, reader.range()),
            Payload::StartSection { func, range } => selected(8).then(|| Unit::Single {
                kind: "start",
                start: range.start,
                end: range.end,
                function: Some(func),
                text: format!("start function {func}"),
            }),
            Payload::CodeSectionStart { count, .. } => {
                if count != declared_functions {
                    return Err(Error::protocol("WASM function and code counts disagree"));
                }
                None
            }
            Payload::CodeSectionEntry(body) => {
                let index = imported_functions
                    .checked_add(functions)
                    .ok_or_else(|| Error::protocol("WASM function index overflow"))?;
                let ty = *function_types
                    .get(functions as usize)
                    .ok_or_else(|| Error::protocol("WASM function declaration is unavailable"))?;
                functions += 1;
                // A body this request did not ask for is counted from the
                // section's own framing and never read: its locals,
                // instructions and control structure stay unverified, which
                // the coverage lists report.
                let range = body.range();
                selected(10).then_some(Unit::Body {
                    index,
                    ty,
                    start: range.start,
                    end: range.end,
                })
            }
            Payload::CustomSection(reader) => selected(0).then(|| {
                let range = reader.range();
                Unit::Single {
                    kind: "custom",
                    start: range.start,
                    end: range.end,
                    function: None,
                    text: format!(
                        "{:?} - {} bytes (opaque custom data)",
                        reader.name(),
                        reader.data().len()
                    ),
                }
            }),
            Payload::DataCountSection { .. } => None,
            Payload::End(_) => {
                ended = true;
                None
            }
            _ => {
                // Every payload reaching this arm carries a section ID, so the
                // section row above named it and its contents stay opaque.
                let reason = "An unsupported section was left opaque.";
                if !omissions.iter().any(|v| v == reason) {
                    omissions.push(reason.into());
                }
                if let Some(id) = current {
                    truncated.insert(id);
                }
                None
            }
        };
        if let Some(unit) = unit {
            built.add(unit)?;
        }
    }
    if ended && declared_functions != functions {
        return Err(Error::protocol("WASM function bodies are missing"));
    }
    for id in &truncated {
        analyzed.remove(id);
    }
    if let Some(ids) = sections {
        // A filtered document never claims the whole module, even when the
        // request happened to exclude nothing present in these bytes.
        omissions.push(format!(
            "Only the requested sections were decoded: {}.",
            section_list(ids).join(", ")
        ));
    }
    let summary = json!({"schema":"wasm-inspection-v2","artifact_id":null,"sha256":null,"byte_size":bytes.len(),
        "status":if ended && omissions.is_empty() {"decoded"} else {"partial"},
        "sections":section_count,"defined_functions":functions,"imported_functions":imported_functions,
        "instructions":built.instructions,"omissions":omissions,
        "coverage":{"requested_sections":sections.map(section_list),"analyzed_sections":section_list(&analyzed),
        "excluded_sections":section_list(&excluded),"truncated_sections":section_list(&truncated),
        "section_map_complete":ended},
        "notice":NOTICE});
    Ok(Inspection {
        summary,
        segments: built.segments,
        total_rows: built.total_rows,
    })
}

/// Where a row window starts.
#[derive(Clone, Copy)]
pub enum Start {
    Row(u64),
    /// The first row at this byte offset, or else the last row before it.
    Byte(usize),
}

impl Inspection {
    fn segment_of_row(&self, row: u64) -> usize {
        self.segments
            .partition_point(|segment| segment.first_row <= row)
            .saturating_sub(1)
    }

    /// The first row whose byte offset is `byte`, or else the last row that
    /// starts before it.
    fn locate(&self, bytes: &[u8], byte: usize, cancelled: &AtomicBool) -> Result<u64> {
        if byte >= bytes.len() {
            return Err(Error::bad("byte_offset is past the module's last byte"));
        }
        let after = self.segments.partition_point(|s| s.first_byte < byte);
        if let Some(exact) = self.segments.get(after).filter(|s| s.first_byte == byte) {
            return Ok(exact.first_row);
        }
        let Some(segment) = after.checked_sub(1).map(|at| &self.segments[at]) else {
            return Err(Error::bad("byte_offset precedes the first inspection row"));
        };
        let (mut at, mut found) = (segment.first_row, segment.first_row);
        decode(bytes, &segment.unit, &mut |coord, _| {
            if (at - segment.first_row).is_multiple_of(POLL_ROWS) {
                check_cancelled(cancelled, WHAT)?;
            }
            if coord.start > byte {
                return Ok(false);
            }
            found = at;
            at += 1;
            Ok(coord.start != byte)
        })?;
        Ok(found)
    }

    /// Rows from `offset`, up to `limit` rows or `WINDOW_BYTES`.
    fn rows(
        &self,
        bytes: &[u8],
        offset: u64,
        limit: usize,
        cancelled: &AtomicBool,
    ) -> Result<Vec<Value>> {
        let mut rows = Vec::new();
        let mut used = 0usize;
        let mut full = false;
        for segment in &self.segments[self.segment_of_row(offset).min(self.segments.len())..] {
            let mut at = segment.first_row;
            decode(bytes, &segment.unit, &mut |coord, text| {
                if (at - segment.first_row).is_multiple_of(POLL_ROWS) {
                    check_cancelled(cancelled, WHAT)?;
                }
                at += 1;
                if at <= offset {
                    return Ok(true);
                }
                let value = row(coord, text());
                let size = serde_json::to_vec(&value).map_or(usize::MAX, |v| v.len() + 1);
                if !rows.is_empty() && used.saturating_add(size) > WINDOW_BYTES {
                    full = true;
                    return Ok(false);
                }
                used = used.saturating_add(size);
                rows.push(value);
                full = rows.len() >= limit;
                Ok(!full)
            })?;
            if full {
                break;
            }
        }
        Ok(rows)
    }
}

type Key = (String, Option<BTreeSet<u8>>);

fn inspection(
    artifact: &wasm_graph::Artifact,
    sections: Option<&BTreeSet<u8>>,
    cancelled: &AtomicBool,
) -> Result<Arc<Inspection>> {
    static INSPECTIONS: Cache<Key, Inspection> = Mutex::new(Vec::new());
    let key = (
        artifact.sha256.as_str().unwrap_or_default().to_owned(),
        sections.cloned(),
    );
    kept(&INSPECTIONS, key, CACHED_INSPECTIONS, || {
        index(&artifact.bytes, sections, cancelled)
    })
}

/// One window of a module's inspection. The bytes are read and verified on
/// every request; only the row index is kept between requests.
pub fn load(
    root: &Path,
    id: &str,
    sections: Option<&BTreeSet<u8>>,
    start: Start,
    limit: usize,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let artifact = wasm_graph::artifact(root, id)?;
    let inspection = inspection(&artifact, sections, cancelled)?;
    let offset = match start {
        Start::Row(row) if row > inspection.total_rows => {
            return Err(Error::bad("row_offset exceeds the row count"));
        }
        Start::Row(row) => row,
        Start::Byte(byte) => inspection.locate(&artifact.bytes, byte, cancelled)?,
    };
    let rows = inspection.rows(&artifact.bytes, offset, limit, cancelled)?;
    let next = offset + rows.len() as u64;
    let mut document = inspection.summary.clone();
    document["artifact_id"] = artifact.artifact_id;
    document["sha256"] = artifact.sha256;
    document["row_window"] = json!({
        "offset": offset,
        "rows": rows.len(),
        "total_rows": inspection.total_rows,
        "next_offset": if next < inspection.total_rows { json!(next) } else { Value::Null },
    });
    document["rows"] = Value::Array(rows);
    Ok(document)
}

/// Unicode simple lowercase of one character. Folding never changes a text's
/// character count, so a match maps back to the original one to one.
fn fold(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_lowercase();
    }
    let mut lower = c.to_lowercase();
    match (lower.next(), lower.next()) {
        (Some(single), None) => single,
        _ => c,
    }
}

/// The folded form of a Find query: a nonempty single-line literal.
pub fn needle(query: &str) -> Result<String> {
    if query.is_empty() {
        return Err(Error::bad("q is required"));
    }
    if query.contains(['\r', '\n', '\u{2028}', '\u{2029}']) {
        return Err(Error::bad(
            "Find uses a single-line literal; line separators are not supported",
        ));
    }
    Ok(query.chars().map(fold).collect())
}

/// Calls `found` with the UTF-16 column and length of each nonoverlapping
/// case-insensitive occurrence of `needle` in `text`, left to right, as a
/// JavaScript `giu` search finds them. Returns false once `found` does.
/// `scratch` holds the folded text, so a caller searching many rows reuses
/// one buffer.
fn occurrences(
    text: &str,
    needle: &str,
    scratch: &mut String,
    found: &mut dyn FnMut(usize, usize) -> Result<bool>,
) -> Result<bool> {
    if text.is_ascii() {
        // An ASCII character folds to an ASCII one, so a needle that is not
        // ASCII once folded cannot occur here.
        if !needle.is_ascii() {
            return Ok(true);
        }
        scratch.clear();
        scratch.push_str(text);
        scratch.make_ascii_lowercase();
        for (at, _) in scratch.match_indices(needle) {
            if !found(at, needle.len())? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    let mut folded = String::with_capacity(text.len());
    // The UTF-16 column of the original character behind each folded byte,
    // and one past the end.
    let mut columns = Vec::with_capacity(text.len() + 1);
    let mut column = 0;
    for c in text.chars() {
        let f = fold(c);
        folded.push(f);
        columns.extend(std::iter::repeat_n(column, f.len_utf8()));
        column += c.len_utf16();
    }
    columns.push(column);
    for (at, matched) in folded.match_indices(needle) {
        let start = columns[at];
        if !found(start, columns[at + matched.len()] - start)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Matches per segment, so a page of matches decodes only its segments.
struct Tally {
    /// Matches before each segment.
    starts: Vec<u64>,
    total: u64,
}

/// Segments one counting worker takes at a time.
const TALLY_RUN: usize = 64;

/// Counts every segment's matches on every core. Each worker takes the next
/// run of segments until none is left, so a module of a few huge bodies and
/// one of many small ones both spread across workers. The first error, a
/// cancelled request among them, stops every worker.
fn tally(
    inspection: &Inspection,
    bytes: &[u8],
    needle: &str,
    cancelled: &AtomicBool,
) -> Result<Tally> {
    let segments = &inspection.segments;
    let runs = segments.len().div_ceil(TALLY_RUN);
    let workers = thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, runs.max(1));
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let count_runs = || -> Result<Vec<(usize, Vec<u64>)>> {
        let mut counted = Vec::new();
        let mut scratch = String::new();
        let mut seen = 0u64;
        loop {
            let run = next.fetch_add(1, Ordering::Relaxed);
            if run >= runs || failed.load(Ordering::Relaxed) {
                return Ok(counted);
            }
            let mut counts = Vec::with_capacity(TALLY_RUN);
            for segment in &segments[run * TALLY_RUN..segments.len().min((run + 1) * TALLY_RUN)] {
                let mut count = 0u64;
                let decoded = decode(bytes, &segment.unit, &mut |_, text| {
                    if seen.is_multiple_of(POLL_ROWS) {
                        check_cancelled(cancelled, WHAT)?;
                    }
                    seen += 1;
                    occurrences(&text(), needle, &mut scratch, &mut |_, _| {
                        count += 1;
                        Ok(true)
                    })
                });
                if let Err(error) = decoded {
                    failed.store(true, Ordering::Relaxed);
                    return Err(error);
                }
                counts.push(count);
            }
            counted.push((run, counts));
        }
    };
    let mut counted = thread::scope(|scope| {
        let others: Vec<_> = (1..workers).map(|_| scope.spawn(count_runs)).collect();
        let mut counted = vec![count_runs()];
        counted.extend(others.into_iter().map(|worker| {
            worker
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }));
        counted
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    counted.sort_unstable_by_key(|(run, _)| *run);
    let mut starts = Vec::with_capacity(segments.len());
    let mut total = 0u64;
    for count in counted.into_iter().flat_map(|(_, counts)| counts) {
        starts.push(total);
        total += count;
    }
    Ok(Tally { starts, total })
}

/// Every case-insensitive occurrence of `query` in the rows' text, paged. The
/// whole inspection is searched once per query, and the count of matches in
/// each unit is kept, so a later page decodes only the units it lists.
pub fn search(
    root: &Path,
    id: &str,
    sections: Option<&BTreeSet<u8>>,
    query: &str,
    offset: u64,
    limit: usize,
    cancelled: &AtomicBool,
) -> Result<Value> {
    static SEARCHES: Cache<(Key, String), Tally> = Mutex::new(Vec::new());
    let needle = needle(query)?;
    let artifact = wasm_graph::artifact(root, id)?;
    let inspection = inspection(&artifact, sections, cancelled)?;
    let key = (
        (
            artifact.sha256.as_str().unwrap_or_default().to_owned(),
            sections.cloned(),
        ),
        needle.clone(),
    );
    let tally = kept(&SEARCHES, key, CACHED_SEARCHES, || {
        tally(&inspection, &artifact.bytes, &needle, cancelled)
    })?;
    if offset > tally.total {
        return Err(Error::bad("match_offset exceeds the match count"));
    }
    let mut matches = Vec::new();
    let mut scratch = String::new();
    let first = tally
        .starts
        .partition_point(|start| *start <= offset)
        .saturating_sub(1);
    for (at, (segment, start)) in inspection
        .segments
        .iter()
        .zip(&tally.starts)
        .enumerate()
        .skip(first)
    {
        if matches.len() >= limit || *start >= tally.total {
            break;
        }
        // A unit without a match is never decoded.
        if tally.starts.get(at + 1).is_some_and(|next| next == start) {
            continue;
        }
        let (mut at, mut rank) = (segment.first_row, *start);
        decode(&artifact.bytes, &segment.unit, &mut |coord, text| {
            if (at - segment.first_row).is_multiple_of(POLL_ROWS) {
                check_cancelled(cancelled, WHAT)?;
            }
            let row = at;
            at += 1;
            occurrences(&text(), &needle, &mut scratch, &mut |column, length| {
                rank += 1;
                if rank > offset {
                    matches.push(json!({"row":row,"byte_offset":coord.start,"column":column,"length":length}));
                }
                Ok(matches.len() < limit)
            })
        })?;
    }
    let next = offset + matches.len() as u64;
    Ok(
        json!({"schema":"wasm-inspection-search-v1","artifact_id":artifact.artifact_id,"sha256":artifact.sha256,
        "query":query,"requested_sections":sections.map(section_list),"total_matches":tally.total,
        "total_rows":inspection.total_rows,"matches":matches,
        "match_window":{"offset":offset,"matches":matches.len(),
        "next_offset":if next < tally.total {json!(next)} else {Value::Null}}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(out: &mut Vec<u8>, id: u8, body: &[u8]) {
        out.push(id);
        leb(out, body.len() as u64);
        out.extend(body);
    }
    fn leb(out: &mut Vec<u8>, mut value: u64) {
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

    /// A module with `functions` bodies of `body_ops` `i32.const 7; drop` pairs,
    /// one export and one data segment.
    fn module(functions: u32, body_ops: u32) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
        let mut declarations = Vec::new();
        leb(&mut declarations, functions.into());
        declarations.extend(std::iter::repeat_n(0, functions as usize));
        section(&mut bytes, 3, &declarations);
        section(&mut bytes, 5, &[1, 0, 1]);
        section(&mut bytes, 7, &[1, 3, b'r', b'u', b'n', 0, 0]);
        let mut code = Vec::new();
        leb(&mut code, functions.into());
        for _ in 0..functions {
            let mut body = vec![0];
            for _ in 0..body_ops {
                body.extend([0x41, 7, 0x1a]);
            }
            body.push(0x0b);
            leb(&mut code, body.len() as u64);
            code.extend(body);
        }
        section(&mut bytes, 10, &code);
        section(&mut bytes, 11, &[1, 0, 0x41, 0, 0x0b, 3, 1, 2, 3]);
        bytes
    }

    fn all(inspection: &Inspection, bytes: &[u8]) -> Vec<Value> {
        let mut rows = Vec::new();
        while (rows.len() as u64) < inspection.total_rows {
            let page = inspection
                .rows(bytes, rows.len() as u64, 7, &AtomicBool::new(false))
                .unwrap();
            assert!(!page.is_empty());
            rows.extend(page);
        }
        rows
    }

    #[test]
    fn every_row_of_a_large_module_is_indexed_and_paged_in_order() {
        let bytes = module(20_000, 5);
        let inspection = index(&bytes, None, &AtomicBool::new(false)).unwrap();
        assert_eq!(inspection.summary["status"], "decoded");
        assert_eq!(inspection.summary["defined_functions"], 20_000);
        assert_eq!(inspection.summary["instructions"], 20_000 * 11);
        // Sections, the type, declarations, memory, export, bodies with their
        // instructions, and the data segment.
        let rows = 6 + 1 + 20_000 + 1 + 1 + 20_000 * 12 + 1;
        assert_eq!(inspection.total_rows, rows);
        let small = module(3, 2);
        let small_index = index(&small, None, &AtomicBool::new(false)).unwrap();
        let listed = all(&small_index, &small);
        assert_eq!(listed.len() as u64, small_index.total_rows);
        let offsets = listed
            .iter()
            .map(|row| row["byte_offset"].as_u64().unwrap())
            .collect::<Vec<_>>();
        assert!(offsets.windows(2).all(|pair| pair[0] <= pair[1]));
        let kinds = listed
            .iter()
            .map(|r| r["kind"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(&kinds[..4], ["section", "type", "section", "declaration"]);
        assert!(listed.iter().any(|row| {
            row["kind"] == "data"
                && row["text"]
                    .as_str()
                    .unwrap()
                    .ends_with("3 bytes - hex 010203")
        }));
        // A window that starts inside a body continues across later units.
        let page = small_index
            .rows(&small, 9, 4, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(page, listed[9..13]);
    }

    #[test]
    fn a_byte_offset_finds_its_row_and_a_row_between_rows_finds_the_one_before() {
        let bytes = module(3, 2);
        let inspection = index(&bytes, None, &AtomicBool::new(false)).unwrap();
        let rows = all(&inspection, &bytes);
        let running = AtomicBool::new(false);
        for (at, row) in rows.iter().enumerate() {
            let offset = row["byte_offset"].as_u64().unwrap() as usize;
            let found = inspection.locate(&bytes, offset, &running).unwrap() as usize;
            assert_eq!(rows[found]["byte_offset"], row["byte_offset"]);
            assert!(found <= at, "the first row at a byte wins");
        }
        let instruction = rows
            .iter()
            .position(|r| r["kind"] == "instruction")
            .unwrap();
        let inside = rows[instruction]["byte_offset"].as_u64().unwrap() as usize + 1;
        assert_eq!(
            inspection.locate(&bytes, inside, &running).unwrap() as usize,
            instruction
        );
        assert_eq!(
            inspection.locate(&bytes, 0, &running).unwrap_err().status,
            400
        );
        assert_eq!(
            inspection
                .locate(&bytes, bytes.len(), &running)
                .unwrap_err()
                .status,
            400
        );
    }

    #[test]
    fn a_section_request_narrows_rows_but_not_the_traversal() {
        let bytes = module(4, 1);
        let ids = requested_sections("export,function").unwrap();
        let inspection = index(&bytes, Some(&ids), &AtomicBool::new(false)).unwrap();
        let rows = all(&inspection, &bytes);
        assert_eq!(inspection.summary["status"], "partial");
        assert_eq!(inspection.summary["instructions"], 0);
        assert_eq!(inspection.summary["defined_functions"], 4);
        assert_eq!(
            rows.iter().filter(|r| r["kind"] == "declaration").count(),
            4
        );
        assert_eq!(rows.iter().filter(|r| r["kind"] == "export").count(), 1);
        assert!(
            rows.iter().all(
                |r| ["section", "declaration", "export"].contains(&r["kind"].as_str().unwrap())
            )
        );
        assert_eq!(
            inspection.summary["coverage"]["excluded_sections"],
            json!(["type", "memory", "code", "data"])
        );
    }

    #[test]
    fn a_branch_table_lists_every_target() {
        let mut body = vec![0, 0x02, 0x40, 0x41, 0, 0x0e];
        leb(&mut body, 140);
        body.extend(std::iter::repeat_n(0, 141));
        body.extend([0x0b, 0x0b]);
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 0]);
        section(&mut bytes, 3, &[1, 0]);
        let mut code = vec![1];
        leb(&mut code, body.len() as u64);
        code.extend(body);
        section(&mut bytes, 10, &code);
        let inspection = index(&bytes, None, &AtomicBool::new(false)).unwrap();
        let rows = all(&inspection, &bytes);
        let table = rows
            .iter()
            .find(|r| r["text"].as_str().unwrap().starts_with("br_table"))
            .unwrap();
        let text = table["text"].as_str().unwrap();
        assert_eq!(text.matches(", ").count(), 139, "{text}");
        assert!(!text.contains("limited"));
    }

    #[test]
    fn find_counts_every_match_and_pages_them_by_unit() {
        let bytes = module(50, 3);
        let inspection = index(&bytes, None, &AtomicBool::new(false)).unwrap();
        let running = AtomicBool::new(false);
        let found = tally(&inspection, &bytes, &needle("I32.CONST").unwrap(), &running).unwrap();
        assert_eq!(found.total, 150);
        let none = tally(
            &inspection,
            &bytes,
            &needle("no such text").unwrap(),
            &running,
        )
        .unwrap();
        assert_eq!(none.total, 0);
        // Runs of segments are counted on different workers; each segment's
        // start is what counting them one after another gives.
        let many = module(1000, 3);
        let inspection = index(&many, None, &running).unwrap();
        assert!(inspection.segments.len() > 8 * TALLY_RUN);
        let counted = tally(&inspection, &many, "i32.const", &running).unwrap();
        assert_eq!(counted.total, 3000);
        assert_eq!(counted.starts.len(), inspection.segments.len());
        let (mut total, mut scratch) = (0, String::new());
        for (segment, start) in inspection.segments.iter().zip(&counted.starts) {
            assert_eq!(*start, total);
            decode(&many, &segment.unit, &mut |_, text| {
                occurrences(&text(), "i32.const", &mut scratch, &mut |_, _| {
                    total += 1;
                    Ok(true)
                })
            })
            .unwrap();
        }
        assert_eq!(total, 3000);
        let mut columns = Vec::new();
        occurrences(
            "aXa xa ÄXa",
            "xa",
            &mut String::new(),
            &mut |column, length| {
                columns.push((column, length));
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(columns, [(1, 2), (4, 2), (8, 2)]);
        columns.clear();
        occurrences(
            "\u{1F600}Ä",
            "ä",
            &mut String::new(),
            &mut |column, length| {
                columns.push((column, length));
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(columns, [(2, 1)], "columns count UTF-16 units");
        assert!(needle("").is_err() && needle("a\nb").is_err());
    }

    #[test]
    fn every_pass_stops_when_the_request_is_cancelled() {
        let bytes = module(200, 50);
        let cancelled = AtomicBool::new(true);
        assert_eq!(index(&bytes, None, &cancelled).err().unwrap().status, 499);
        let inspection = index(&bytes, None, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            inspection
                .rows(&bytes, 0, 10, &cancelled)
                .unwrap_err()
                .status,
            499
        );
        assert_eq!(
            tally(&inspection, &bytes, "i32", &cancelled)
                .err()
                .unwrap()
                .status,
            499
        );
    }

    #[test]
    fn malformed_modules_fail_instead_of_paging() {
        let running = AtomicBool::new(false);
        for malformed in [
            vec![],
            vec![0, 97, 115, 109],
            b"\0asm\x01\0\0\0\x0a\x02\x01\x7f".to_vec(),
        ] {
            assert_eq!(index(&malformed, None, &running).err().unwrap().status, 422);
        }
        let mut trailing = module(1, 1);
        trailing.push(0xff);
        assert_eq!(index(&trailing, None, &running).err().unwrap().status, 422);
        let empty = index(b"\0asm\x01\0\0\0", None, &running).unwrap();
        assert_eq!(
            (empty.summary["status"].as_str(), empty.total_rows),
            (Some("decoded"), 0)
        );
    }
}
