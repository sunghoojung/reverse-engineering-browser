//! Inert, bounded binary inspection. Decoding is not semantic validation or execution.
use crate::{
    error::{Error, Result},
    evidence, validation,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};
use wasmparser::{CompositeInnerType, Encoding, Operator, Parser, Payload, TypeRef};

pub const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROWS: usize = 8192;
const MAX_SECTIONS: usize = 128;
const MAX_TEXT: usize = 512;
/// Every section name once, comma separated, is the longest honest request.
const MAX_SECTION_REQUEST: usize = 128;

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

pub fn load(root: &Path, id: &str, sections: Option<&BTreeSet<u8>>) -> Result<Value> {
    validation::canonical(&json!(id), 64, true, "Artifact ID")?;
    let artifact = evidence::artifacts(root, 10000)?
        .into_iter()
        .find(|a| a["artifact_id"] == id)
        .ok_or_else(|| Error::new(404, "Artifact not found"))?;
    if artifact["kind"] != "wasm" {
        return Err(Error::bad("Artifact is not WebAssembly"));
    }
    let bytes = evidence::content(root, &artifact, MAX_BYTES)?;
    let mut document = inspect(&bytes, sections)?;
    document["artifact_id"] = artifact["artifact_id"].clone();
    document["sha256"] = artifact["sha256"].clone();
    Ok(document)
}

/// Row windows let a client page through a whole module's rows when the
/// document is larger than its inline limit. The window stops at `limit` rows
/// or `WINDOW_BYTES` of serialized rows, whichever comes first, so one page
/// always fits a 128 KiB MCP result; `next_offset` continues.
pub const WINDOW_MAX_ROWS: usize = 2048;
pub const WINDOW_BYTES: usize = 98_304;

pub fn window(document: &mut Value, offset: usize, limit: usize) -> Result<()> {
    let rows = document["rows"].as_array().cloned().unwrap_or_default();
    let total = rows.len();
    if offset > total {
        return Err(Error::bad("row_offset exceeds the row count"));
    }
    let mut kept = Vec::new();
    let mut bytes = 0usize;
    for row in rows.into_iter().skip(offset).take(limit) {
        let size = serde_json::to_vec(&row).map_or(usize::MAX, |encoded| encoded.len() + 1);
        if !kept.is_empty() && bytes + size > WINDOW_BYTES {
            break;
        }
        bytes += size;
        kept.push(row);
    }
    let next = offset + kept.len();
    document["rows"] = Value::Array(kept);
    document["row_window"] = json!({
        "offset": offset,
        "rows": next - offset,
        "total_rows": total,
        "next_offset": if next < total { json!(next) } else { Value::Null },
    });
    Ok(())
}

struct Rows {
    values: Vec<Value>,
    started: Instant,
    omissions: Vec<String>,
    /// The section whose rows are being decoded, or `None` while a section the
    /// request excluded is walked. A limit reached here leaves that section
    /// partly covered, so an excluded section is never blamed for a limit.
    current: Option<u8>,
    truncated: BTreeSet<u8>,
}
impl Rows {
    /// Names an omission once and records the current section as incompletely
    /// covered. Every traversal limit funnels through here so a stopped
    /// section cannot be reported as analyzed.
    fn stop(&mut self, reason: &str) {
        if !self.omissions.iter().any(|v| v == reason) {
            self.omissions.push(reason.into());
        }
        if let Some(id) = self.current {
            self.truncated.insert(id);
        }
    }
    fn room(&mut self) -> bool {
        let reason = if self.values.len() >= MAX_ROWS {
            Some("Inspection row limit reached; the remaining bytes were not decoded.")
        } else if self.started.elapsed() > Duration::from_secs(2) {
            Some("Inspection deadline reached; the remaining bytes were not decoded.")
        } else {
            None
        };
        match reason {
            Some(reason) => {
                self.stop(reason);
                false
            }
            None => true,
        }
    }
    fn push(&mut self, kind: &str, start: usize, end: usize, function: Option<u32>, text: String) {
        let clipped = text.len() > MAX_TEXT;
        let mut text = text.chars().take(MAX_TEXT).collect::<String>();
        // A character cap alone does not bound UTF-8 bytes.
        while text.len() > MAX_TEXT {
            text.pop();
        }
        if clipped {
            text.push_str(" [text limited]");
        }
        self.values
            .push(json!({"kind":kind,"byte_offset":start,"byte_end":end,
            "function_index":function,"text":text,"text_truncated":clipped}));
    }
}

macro_rules! operator_names {
    ($(@$proposal:ident $op:ident $({ $($field:ident: $ty:ty),* })? => $visit:ident ($($ann:tt)*))*) => {
        fn operator_name(op: &Operator<'_>) -> &'static str {
            match op { $(Operator::$op $( { $($field: _),* } )? => stringify!($visit),)* _ => "visit_unknown" }
        }
    };
}
wasmparser::for_each_operator!(operator_names);

/// The dotted mnemonic for an operator. The linear listing and the block graph
/// share one spelling so a row can be matched between the two views.
pub(crate) fn mnemonic(op: &Operator<'_>) -> String {
    let name = operator_name(op).trim_start_matches("visit_");
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

fn instruction(op: &Operator<'_>) -> String {
    let mnemonic = mnemonic(op);
    if let Operator::BrTable { targets } = op {
        // Large branch tables keep exact instruction ranges and a bounded preview.
        let labels = targets
            .targets()
            .take(32)
            .map(|t| {
                t.map(|v| v.to_string())
                    .unwrap_or_else(|_| "invalid".into())
            })
            .collect::<Vec<_>>();
        return format!(
            "{mnemonic} [{}] default={}{}",
            labels.join(", "),
            targets.default(),
            if targets.len() > 32 {
                " [targets limited]"
            } else {
                ""
            }
        );
    }
    let debug = format!("{op:?}");
    match debug.find(" { ") {
        Some(index) => format!("{mnemonic}{}", &debug[index..]),
        None => mnemonic,
    }
}

/// Decodes `bytes`, emitting rows only for the requested sections.
///
/// `sections` of `None` requests the whole module. A request narrows which
/// sections produce rows; it never narrows the traversal itself, so section
/// framing, import and function counts, and the function/code agreement check
/// hold exactly as they do for an unfiltered request.
pub fn inspect(bytes: &[u8], sections: Option<&BTreeSet<u8>>) -> Result<Value> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::bad("WASM inspection input exceeds 2 MiB"));
    }
    // An absent request selects every section, including an ID this version
    // cannot name. A present request selects exactly the IDs it names.
    let selected = |id: u8| sections.is_none_or(|ids| ids.contains(&id));
    // Declaration rows cost one row per defined function ahead of the export
    // and code sections, so only a request that names `function` pays for
    // them. An unfiltered document keeps its budget for exports and bodies, as
    // before, and each decoded body's header row still names its type.
    let declare = sections.is_some_and(|ids| ids.contains(&3));
    let mut rows = Rows {
        values: Vec::new(),
        started: Instant::now(),
        omissions: Vec::new(),
        current: None,
        truncated: BTreeSet::new(),
    };
    let mut analyzed = BTreeSet::new();
    let mut excluded = BTreeSet::new();
    let mut section_count = 0;
    let mut imported_functions = 0u32;
    let mut functions = 0u32;
    let mut declared_functions = 0u32;
    let mut instructions = 0usize;
    let mut ended = false;
    let mut function_types = Vec::new();
    let mut type_index = 0;
    'module: for payload in Parser::new(0).parse_all(bytes) {
        if !rows.room() {
            break;
        }
        let payload = payload.map_err(bad)?;
        if let Some((id, range)) = payload.as_section() {
            if section_count >= MAX_SECTIONS {
                rows.omissions
                    .push("Section limit reached; the remaining bytes were not decoded.".into());
                break;
            }
            section_count += 1;
            if selected(id) {
                analyzed.insert(id);
                rows.current = Some(id);
            } else {
                excluded.insert(id);
                rows.current = None;
            }
            // Every section keeps its row, including one the request excludes,
            // so a filtered document still names the bytes it did not decode.
            rows.push(
                "section",
                range.start,
                range.end,
                None,
                format!("{} section ({} bytes)", section_name(id), range.len()),
            );
        }
        macro_rules! entries {
            ($reader:expr, $kind:expr, $id:expr) => {
                if selected($id) {
                    for entry in $reader.into_iter_with_offsets() {
                        if !rows.room() {
                            break 'module;
                        }
                        let (offset, entry) = entry.map_err(bad)?;
                        rows.push($kind, offset, offset, None, format!("{entry:?}"));
                    }
                }
            };
        }
        match payload {
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
                if selected(1) {
                    for group in reader.into_iter_with_offsets() {
                        let (offset, group) = group.map_err(bad)?;
                        for ty in group.types() {
                            if !rows.room() {
                                break 'module;
                            }
                            let detail = match &ty.composite_type.inner {
                                CompositeInnerType::Func(function) => {
                                    let list = |values: &[wasmparser::ValType]| {
                                        let mut text = values
                                            .iter()
                                            .take(32)
                                            .map(ToString::to_string)
                                            .collect::<Vec<_>>()
                                            .join(", ");
                                        if values.len() > 32 {
                                            text.push_str(", [types limited]");
                                        }
                                        text
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
                                CompositeInnerType::Array(_) => {
                                    "array (inspect original bytes for element layout)".into()
                                }
                                CompositeInnerType::Cont(_) => {
                                    "continuation (inspect original bytes for type details)".into()
                                }
                            };
                            rows.push(
                                "type",
                                offset,
                                offset,
                                None,
                                format!("type {type_index}: {detail}"),
                            );
                            type_index += 1;
                        }
                    }
                }
            }
            Payload::ImportSection(reader) => {
                // A defined function's index continues the imported range, so
                // imports are always counted even when their rows are not
                // requested. Only the rows follow the request. Counting
                // formats nothing and is linear in a 2 MiB input: 480,000
                // imports cost under half a second in a debug build, inside
                // the deadline this walk does not stop to check.
                for entry in reader.into_iter_with_offsets() {
                    let (offset, entry) = entry.map_err(bad)?;
                    let index = if matches!(entry.ty, TypeRef::Func(_)) {
                        let i = imported_functions;
                        imported_functions += 1;
                        Some(i)
                    } else {
                        None
                    };
                    if selected(2) {
                        if !rows.room() {
                            break 'module;
                        }
                        rows.push(
                            "import",
                            offset,
                            offset,
                            index,
                            format!("{:?} :: {:?} - {:?}", entry.module, entry.name, entry.ty),
                        );
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                declared_functions = reader.count();
                for entry in reader.into_iter_with_offsets() {
                    if function_types.len() >= MAX_ROWS {
                        rows.stop("Function declaration limit reached.");
                        break 'module;
                    }
                    let (offset, ty) = entry.map_err(bad)?;
                    let index = imported_functions
                        .checked_add(function_types.len() as u32)
                        .ok_or_else(|| Error::protocol("WASM function index overflow"))?;
                    function_types.push(ty);
                    // The declared type of every function is static data in
                    // this section. Keeping it as a row makes an export's type
                    // reachable without decoding any function body, which the
                    // row budget cannot afford for a large module.
                    if declare && rows.room() {
                        rows.push(
                            "declaration",
                            offset,
                            offset,
                            Some(index),
                            format!("func {index} declares type {ty}"),
                        );
                    }
                }
            }
            Payload::TableSection(reader) => {
                entries!(reader, "table", 4);
            }
            Payload::MemorySection(reader) => {
                entries!(reader, "memory", 5);
            }
            Payload::GlobalSection(reader) => {
                entries!(reader, "global", 6);
            }
            Payload::TagSection(reader) => {
                entries!(reader, "tag", 13);
            }
            Payload::ExportSection(reader) => {
                if selected(7) {
                    for entry in reader.into_iter_with_offsets() {
                        if !rows.room() {
                            break 'module;
                        }
                        let (offset, entry) = entry.map_err(bad)?;
                        rows.push(
                            "export",
                            offset,
                            offset,
                            None,
                            format!("{:?} - {:?} {}", entry.name, entry.kind, entry.index),
                        );
                    }
                }
            }
            Payload::StartSection { func, range } => {
                if selected(8) {
                    if !rows.room() {
                        break;
                    }
                    rows.push(
                        "start",
                        range.start,
                        range.end,
                        Some(func),
                        format!("start function {func}"),
                    );
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                if count != declared_functions {
                    return Err(Error::protocol("WASM function and code counts disagree"));
                }
            }
            Payload::CodeSectionEntry(body) => {
                let decode = selected(10);
                if decode && !rows.room() {
                    break;
                }
                let index = imported_functions
                    .checked_add(functions)
                    .ok_or_else(|| Error::protocol("WASM function index overflow"))?;
                let ty = function_types
                    .get(functions as usize)
                    .ok_or_else(|| Error::protocol("WASM function declaration is unavailable"))?;
                functions += 1;
                // A body this request did not ask for is counted from the
                // section's own framing and never read: its locals,
                // instructions and control structure stay unverified, which
                // the coverage lists report. The count stays bounded because a
                // module declaring more than MAX_ROWS functions stops at the
                // declaration limit before any body is reached.
                if !decode {
                    continue;
                }
                let range = body.range();
                rows.push(
                    "function",
                    range.start,
                    range.end,
                    Some(index),
                    format!("func {index} (type {ty})"),
                );
                let mut locals = body.get_locals_reader().map_err(bad)?;
                for _ in 0..locals.get_count() {
                    if !rows.room() {
                        break 'module;
                    }
                    let offset = locals.original_position();
                    let (count, ty) = locals.read().map_err(bad)?;
                    rows.push(
                        "local",
                        offset,
                        locals.original_position(),
                        Some(index),
                        format!("local group: {count} x {ty:?}"),
                    );
                }
                let mut reader = body.get_operators_reader().map_err(bad)?;
                while !reader.eof() {
                    if !rows.room() {
                        break 'module;
                    }
                    let (op, offset) = reader.read_with_offset().map_err(bad)?;
                    instructions += 1;
                    rows.push(
                        "instruction",
                        offset,
                        reader.original_position(),
                        Some(index),
                        instruction(&op),
                    );
                    // A direct callee or function reference is structure, like
                    // `function_index`, so a read that omits row text still
                    // names it (and a researcher name joins to it).
                    if let Operator::Call { function_index }
                    | Operator::ReturnCall { function_index }
                    | Operator::RefFunc { function_index } = op
                        && let Some(row) = rows.values.last_mut()
                    {
                        row["target_function_index"] = json!(function_index);
                    }
                }
                reader.finish().map_err(bad)?;
            }
            Payload::DataSection(reader) => {
                if selected(11) {
                    for entry in reader.into_iter_with_offsets() {
                        if !rows.room() {
                            break 'module;
                        }
                        let (offset, entry) = entry.map_err(bad)?;
                        let preview = hex::encode(&entry.data[..entry.data.len().min(32)]);
                        rows.push(
                            "data",
                            offset,
                            entry.range.end,
                            None,
                            format!(
                                "{:?} - {} bytes - hex {preview}{}",
                                entry.kind,
                                entry.data.len(),
                                if entry.data.len() > 32 {
                                    " [preview limited]"
                                } else {
                                    ""
                                }
                            ),
                        );
                    }
                }
            }
            Payload::ElementSection(reader) => {
                if selected(9) {
                    for entry in reader.into_iter_with_offsets() {
                        if !rows.room() {
                            break 'module;
                        }
                        let (offset, entry) = entry.map_err(bad)?;
                        rows.push(
                            "element",
                            offset,
                            entry.range.end,
                            None,
                            "element segment (references retained in original bytes)".into(),
                        );
                    }
                }
            }
            Payload::CustomSection(reader) => {
                if selected(0) {
                    if !rows.room() {
                        break;
                    }
                    let range = reader.range();
                    rows.push(
                        "custom",
                        range.start,
                        range.end,
                        None,
                        format!(
                            "{:?} - {} bytes (opaque custom data)",
                            reader.name(),
                            reader.data().len()
                        ),
                    );
                }
            }
            Payload::DataCountSection { .. } => {}
            Payload::End(_) => {
                ended = true;
            }
            _ => {
                // Every payload reaching this arm carries a section ID, so the
                // section row above named it and `stop` records that its
                // contents were left opaque.
                rows.stop("An unsupported section was left opaque.");
            }
        }
    }
    if ended && declared_functions != functions {
        return Err(Error::protocol("WASM function bodies are missing"));
    }
    for id in &rows.truncated {
        analyzed.remove(id);
    }
    if let Some(ids) = sections {
        // A filtered document never claims the whole module, even when the
        // request happened to exclude nothing present in these bytes.
        rows.omissions.push(format!(
            "Only the requested sections were decoded: {}.",
            section_list(ids).join(", ")
        ));
    }
    Ok(
        json!({"schema":"wasm-inspection-v1","artifact_id":null,"sha256":null,"byte_size":bytes.len(),
        "status":if ended && rows.omissions.is_empty() {"decoded"} else {"partial"},
        "sections":section_count,"defined_functions":functions,"imported_functions":imported_functions,"instructions":instructions,
        "rows":rows.values,"omissions":rows.omissions,
        "coverage":{"requested_sections":sections.map(section_list),"analyzed_sections":section_list(&analyzed),
        "excluded_sections":section_list(&excluded),"truncated_sections":section_list(&rows.truncated),
        "section_map_complete":ended},
        "limits":{"max_bytes":MAX_BYTES,"max_rows":MAX_ROWS,"max_sections":MAX_SECTIONS,"max_text_bytes":MAX_TEXT,"deadline_ms":2000},
        "notice":"Static binary decoding only. Type validity, runtime calls, traps, memory growth, and value flow are not established."}),
    )
}
