//! Inert, bounded binary inspection. Decoding is not semantic validation or execution.
use crate::{
    error::{Error, Result},
    evidence, validation,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use wasmparser::{CompositeInnerType, Encoding, Operator, Parser, Payload, TypeRef};

pub const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_ROWS: usize = 8192;
const MAX_SECTIONS: usize = 128;
const MAX_TEXT: usize = 512;

fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

pub fn load(root: &Path, id: &str) -> Result<Value> {
    validation::canonical(&json!(id), 64, true, "Artifact ID")?;
    let artifact = evidence::artifacts(root, 10000)?
        .into_iter()
        .find(|a| a["artifact_id"] == id)
        .ok_or_else(|| Error::new(404, "Artifact not found"))?;
    if artifact["kind"] != "wasm" {
        return Err(Error::bad("Artifact is not WebAssembly"));
    }
    let bytes = evidence::content(root, &artifact, MAX_BYTES)?;
    let mut document = inspect(&bytes)?;
    document["artifact_id"] = artifact["artifact_id"].clone();
    document["sha256"] = artifact["sha256"].clone();
    Ok(document)
}

struct Rows {
    values: Vec<Value>,
    started: Instant,
    omissions: Vec<String>,
}
impl Rows {
    fn room(&mut self) -> bool {
        let reason = if self.values.len() >= MAX_ROWS {
            Some("Inspection row limit reached; the remaining bytes were not decoded.")
        } else if self.started.elapsed() > Duration::from_secs(2) {
            Some("Inspection deadline reached; the remaining bytes were not decoded.")
        } else {
            None
        };
        if let Some(reason) = reason {
            if !self.omissions.iter().any(|v| v == reason) {
                self.omissions.push(reason.into());
            }
            false
        } else {
            true
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

fn instruction(op: &Operator<'_>) -> String {
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

fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data count",
        13 => "tag",
        _ => "unknown",
    }
}

pub fn inspect(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::bad("WASM inspection input exceeds 2 MiB"));
    }
    let mut rows = Rows {
        values: Vec::new(),
        started: Instant::now(),
        omissions: Vec::new(),
    };
    let mut sections = 0;
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
            if sections >= MAX_SECTIONS {
                rows.omissions
                    .push("Section limit reached; the remaining bytes were not decoded.".into());
                break;
            }
            sections += 1;
            rows.push(
                "section",
                range.start,
                range.end,
                None,
                format!("{} section ({} bytes)", section_name(id), range.len()),
            );
        }
        macro_rules! entries {
            ($reader:expr, $kind:expr) => {
                for entry in $reader.into_iter_with_offsets() {
                    if !rows.room() {
                        break 'module;
                    }
                    let (offset, entry) = entry.map_err(bad)?;
                    rows.push($kind, offset, offset, None, format!("{entry:?}"));
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
            Payload::ImportSection(reader) => {
                for entry in reader.into_iter_with_offsets() {
                    if !rows.room() {
                        break 'module;
                    }
                    let (offset, entry) = entry.map_err(bad)?;
                    let index = if matches!(entry.ty, TypeRef::Func(_)) {
                        let i = imported_functions;
                        imported_functions += 1;
                        Some(i)
                    } else {
                        None
                    };
                    rows.push(
                        "import",
                        offset,
                        offset,
                        index,
                        format!("{:?} :: {:?} - {:?}", entry.module, entry.name, entry.ty),
                    );
                }
            }
            Payload::FunctionSection(reader) => {
                declared_functions = reader.count();
                for entry in reader {
                    if !rows.room() || function_types.len() >= MAX_ROWS {
                        rows.omissions
                            .push("Function declaration limit reached.".into());
                        break 'module;
                    }
                    function_types.push(entry.map_err(bad)?);
                }
            }
            Payload::TableSection(reader) => {
                entries!(reader, "table");
            }
            Payload::MemorySection(reader) => {
                entries!(reader, "memory");
            }
            Payload::GlobalSection(reader) => {
                entries!(reader, "global");
            }
            Payload::TagSection(reader) => {
                entries!(reader, "tag");
            }
            Payload::ExportSection(reader) => {
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
            Payload::StartSection { func, range } => {
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
            Payload::CodeSectionStart { count, .. } => {
                if count != declared_functions {
                    return Err(Error::protocol("WASM function and code counts disagree"));
                }
            }
            Payload::CodeSectionEntry(body) => {
                if !rows.room() {
                    break;
                }
                let index = imported_functions
                    .checked_add(functions)
                    .ok_or_else(|| Error::protocol("WASM function index overflow"))?;
                let ty = function_types
                    .get(functions as usize)
                    .ok_or_else(|| Error::protocol("WASM function declaration is unavailable"))?;
                functions += 1;
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
                }
                reader.finish().map_err(bad)?;
            }
            Payload::DataSection(reader) => {
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
            Payload::ElementSection(reader) => {
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
            Payload::CustomSection(reader) => {
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
            Payload::DataCountSection { .. } => {}
            Payload::End(_) => {
                ended = true;
            }
            _ => {
                if !rows
                    .omissions
                    .iter()
                    .any(|v| v == "An unsupported section was left opaque.")
                {
                    rows.omissions
                        .push("An unsupported section was left opaque.".into());
                }
            }
        }
    }
    if ended && declared_functions != functions {
        return Err(Error::protocol("WASM function bodies are missing"));
    }
    Ok(
        json!({"schema":"wasm-inspection-v1","artifact_id":null,"sha256":null,"byte_size":bytes.len(),
        "status":if ended && rows.omissions.is_empty() {"decoded"} else {"partial"},
        "sections":sections,"defined_functions":functions,"imported_functions":imported_functions,"instructions":instructions,
        "rows":rows.values,"omissions":rows.omissions,
        "limits":{"max_bytes":MAX_BYTES,"max_rows":MAX_ROWS,"max_sections":MAX_SECTIONS,"max_text_bytes":MAX_TEXT,"deadline_ms":2000},
        "notice":"Static binary decoding only. Type validity, runtime calls, traps, memory growth, and value flow are not established."}),
    )
}
