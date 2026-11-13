//! One function's basic blocks, derived on demand from the inspection decoder.
//!
//! Wasm control flow is structured, so every branch names a label whose target
//! is a byte position in the same body and this module never guesses. What it
//! cannot resolve from the body (tail calls, throws, a label past the frames it
//! decoded) stays an explicit unresolved edge with a label. Nothing here runs
//! the module, and a graph is one function at a time: nothing retains a
//! whole-module structure.
use crate::{
    error::{Error, Result},
    evidence, validation, wasm, wasm_names,
};
use serde_json::Value;
use std::{
    fmt::Write as _,
    path::Path,
    time::{Duration, Instant},
};
use wasmparser::{ExternalKind, KnownCustom, Name, Operator, Parser, Payload};

/// The artifact receiver's default store limit is 16 MiB and its configured
/// limit can be raised; 64 MiB covers both without an unbounded read.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Web engines reject a body above this size, so a longer one cannot have run.
const MAX_BODY_BYTES: usize = 7_654_321;
/// Instruction rows are the bulk of a large function's response.
const MAX_ROW_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STRUCTURE_BYTES: usize = 32 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 8 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 96;
const DEADLINE: Duration = Duration::from_secs(4);
/// Edge kinds in the order `edge_kinds` lists them.
const EDGE_KINDS: [&str; 8] = [
    "fallthrough",
    "branch",
    "taken",
    "not_taken",
    "table",
    "table_default",
    "exception",
    "unresolved",
];
const FALLTHROUGH: u8 = 0;
const BRANCH: u8 = 1;
const TAKEN: u8 = 2;
const NOT_TAKEN: u8 = 3;
const TABLE: u8 = 4;
const TABLE_DEFAULT: u8 = 5;
const EXCEPTION: u8 = 6;
const UNRESOLVED: u8 = 7;
const ENTRY: u32 = 1;
const REACHABLE: u32 = 2;
const EXIT: u32 = 4;
const TRAP: u32 = 8;
/// Some of this block's rows fell outside the row text budget.
const ROWS_CUT: u32 = 32;

fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

pub(crate) struct Artifact {
    pub(crate) bytes: Vec<u8>,
    pub(crate) artifact_id: Value,
    pub(crate) sha256: Value,
}

pub(crate) fn artifact(root: &Path, id: &str) -> Result<Artifact> {
    validation::canonical(&serde_json::json!(id), 64, true, "Artifact ID")?;
    let record = evidence::artifacts(root, 10000)?
        .into_iter()
        .find(|a| a["artifact_id"] == id)
        .ok_or_else(|| Error::new(404, "Artifact not found"))?;
    if record["kind"] != "wasm" {
        return Err(Error::bad("Artifact is not WebAssembly"));
    }
    let bytes = evidence::content(root, &record, MAX_BYTES)?;
    Ok(Artifact {
        bytes,
        artifact_id: record["artifact_id"].clone(),
        sha256: record["sha256"].clone(),
    })
}

/// A body's byte range and its declared type, retained per function only for
/// the index document, never decoded into instructions.
struct Row {
    start: usize,
    end: usize,
    ty: u32,
}

/// Lists a module's functions without decoding any instruction.
pub fn function_index(root: &Path, id: &str) -> Result<String> {
    function_index_named(root, id, None)
}

/// The function list with the researcher names of this module's functions as
/// an `analyst_names` member beside the name-section `names`.
pub(crate) fn function_index_named(
    root: &Path,
    id: &str,
    analyst: Option<&wasm_names::Names>,
) -> Result<String> {
    let artifact = artifact(root, id)?;
    let mut imported = 0u32;
    let mut types = Vec::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut names: Vec<(u32, String)> = Vec::new();
    let mut exports: Vec<(u32, String)> = Vec::new();
    let mut omissions: Vec<String> = Vec::new();
    let mut listed_bytes = 0usize;
    let mut stopped = false;
    let mut ended = false;
    for payload in Parser::new(0).parse_all(&artifact.bytes) {
        let payload = payload.map_err(bad)?;
        match payload {
            Payload::Version { num: 1, .. } | Payload::Version { .. } => {}
            Payload::ImportSection(reader) => {
                for import in reader.into_iter() {
                    if matches!(import.map_err(bad)?.ty, wasmparser::TypeRef::Func(_)) {
                        imported += 1;
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    types.push(ty.map_err(bad)?);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(bad)?;
                    if export.kind == ExternalKind::Func {
                        exports.push((export.index, bounded_name(export.name)));
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let range = body.range();
                let ty = types
                    .get(rows.len())
                    .copied()
                    .ok_or_else(|| Error::protocol("WASM function declaration is unavailable"))?;
                listed_bytes += 28;
                if listed_bytes > MAX_INDEX_BYTES {
                    stopped = true;
                    omissions.push(
                        "Function index byte budget reached; later functions are not listed."
                            .into(),
                    );
                    break;
                }
                rows.push(Row {
                    start: range.start,
                    end: range.end,
                    ty,
                });
            }
            Payload::CustomSection(reader) => {
                if let KnownCustom::Name(section) = reader.as_known() {
                    for subsection in section {
                        // A name section is advisory; a malformed one never
                        // fails an index built from the code section.
                        if let Ok(Name::Function(map)) = subsection {
                            for naming in map.into_iter().flatten() {
                                names.push((naming.index, bounded_name(naming.name)));
                            }
                        }
                    }
                }
            }
            Payload::End(_) => ended = true,
            _ => {}
        }
    }
    if !ended && !stopped {
        omissions.push("Module traversal stopped before its end.".into());
    }
    if rows.is_empty() {
        omissions.push("This module declares no function bodies.".into());
    }
    let mut out = String::with_capacity(rows.len() * 24 + 1024);
    out.push_str("{\"schema\":\"wasm-function-index-v1\",\"artifact_id\":");
    out.push_str(&serde_json::to_string(&artifact.artifact_id).expect("JSON value"));
    out.push_str(",\"sha256\":");
    out.push_str(&serde_json::to_string(&artifact.sha256).expect("JSON value"));
    let _ = write!(
        out,
        ",\"byte_size\":{},\"status\":\"{}\",\"imported_functions\":{imported},\"defined_functions\":{},\"listed_functions\":{},\"function_fields\":[\"index\",\"byte_offset\",\"byte_end\",\"type_index\"],\"functions\":[",
        artifact.bytes.len(),
        if omissions.is_empty() {
            "decoded"
        } else {
            "partial"
        },
        types.len(),
        rows.len()
    );
    let mut first = true;
    for (position, row) in rows.iter().enumerate() {
        if !std::mem::take(&mut first) {
            out.push(',');
        }
        let _ = write!(
            out,
            "[{},{},{},{}]",
            imported as u64 + position as u64,
            row.start,
            row.end,
            row.ty
        );
    }
    out.push_str("],\"names\":[");
    // The name section wins over an export, which wins over nothing, so one
    // line per function and a name can never move a row.
    let mut merged: Vec<(u32, &str)> = exports.iter().map(|(i, n)| (*i, n.as_str())).collect();
    merged.extend(names.iter().map(|(i, n)| (*i, n.as_str())));
    merged.sort_by_key(|(index, _)| *index);
    let mut last = None;
    let mut wrote = 0usize;
    for (position, (index, text)) in merged.iter().enumerate() {
        // Later entries are the name section's for the same index.
        if last == Some(*index) {
            continue;
        }
        let next_same = merged.get(position + 1).is_some_and(|(i, _)| i == index);
        let chosen = if next_same {
            merged[position + 1].1
        } else {
            *text
        };
        if wrote > 0 {
            out.push(',');
        }
        wrote += 1;
        let _ = write!(
            out,
            "[{index},{}]",
            serde_json::to_string(chosen).expect("JSON string")
        );
        last = Some(*index);
    }
    let _ = write!(
        out,
        "],\"omissions\":{},\"limits\":{{\"max_input_bytes\":{MAX_BYTES},\"max_index_bytes\":{MAX_INDEX_BYTES},\"max_name_bytes\":{MAX_NAME_BYTES}}},\"notice\":\"Static function list. Graphs are computed one function at a time.\"}}",
        serde_json::to_string(&omissions).expect("JSON strings"),
    );
    Ok(match (analyst, artifact.sha256.as_str()) {
        (Some(names), Some(sha)) => wasm_names::append_members(
            out,
            &[(
                "analyst_names",
                names.module_member(sha, u64::from(imported) + types.len() as u64),
            )],
        ),
        _ => out,
    })
}

/// A name stays one inert line of bounded text, whatever the module supplied.
pub(crate) fn bounded_name(name: &str) -> String {
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

#[derive(Clone, Copy, PartialEq)]
enum FrameKind {
    Function,
    Block,
    Loop,
    If,
    Try,
}

struct Frame {
    kind: FrameKind,
    start: u32,
    end: u32,
    else_at: u32,
}

const NONE: u32 = u32::MAX;

/// Structural control operations, retained per instruction index. Frames and
/// flows use indices so an in-progress graph costs a few words per operator.
#[derive(Clone, Copy)]
enum Flow {
    Br(u32),
    BrIf(u32),
    BrOn(u32),
    BrTable {
        arms: u32,
        count: u32,
        default: u32,
    },
    If(u32),
    Else(u32),
    Catch(u32),
    Return,
    Trap,
    /// A transfer this function's bytes cannot resolve (tail call, throw).
    Out(&'static str),
    /// A label deeper than the frames decoded so far.
    BadDepth,
}

struct Decoded {
    offsets: Vec<u32>,
    flows: Vec<(u32, Flow)>,
    frames: Vec<Frame>,
    arms: Vec<u32>,
    exceptions: Vec<(u32, u32)>,
    byte_end: u32,
    stopped: bool,
    omissions: Vec<String>,
}

fn decode(body: &wasmparser::FunctionBody<'_>, deadline: Instant) -> Result<Decoded> {
    let mut decoded = Decoded {
        offsets: Vec::new(),
        flows: Vec::new(),
        frames: vec![Frame {
            kind: FrameKind::Function,
            start: 0,
            end: NONE,
            else_at: NONE,
        }],
        arms: Vec::new(),
        exceptions: Vec::new(),
        byte_end: body.range().end as u32,
        stopped: false,
        omissions: Vec::new(),
    };
    let mut stack: Vec<u32> = vec![0];
    let mut reader = body.get_operators_reader().map_err(bad)?;
    let mut ended_function = false;
    while !reader.eof() {
        if decoded.offsets.len() & 4095 == 0 && Instant::now() > deadline {
            decoded.stopped = true;
            decoded.omissions.push(format!(
                "Decoding deadline reached at byte {}; remaining instructions are not in this graph.",
                reader.original_position()
            ));
            break;
        }
        let (op, offset) = reader.read_with_offset().map_err(bad)?;
        let index = decoded.offsets.len() as u32;
        decoded.offsets.push(offset as u32);
        if ended_function {
            return Err(Error::protocol(
                "WASM function has instructions after its end",
            ));
        }
        // A depth counts from the innermost open frame, so the target frame is
        // known the moment the branch is read.
        let frame_at = |stack: &[u32], depth: u32| -> Option<u32> {
            let position = stack.len().checked_sub(depth as usize + 1)?;
            stack.get(position).copied()
        };
        let mut flow = None;
        match op {
            Operator::Block { .. } => {
                decoded.frames.push(Frame {
                    kind: FrameKind::Block,
                    start: index,
                    end: NONE,
                    else_at: NONE,
                });
                stack.push(decoded.frames.len() as u32 - 1);
            }
            Operator::Loop { .. } => {
                decoded.frames.push(Frame {
                    kind: FrameKind::Loop,
                    start: index,
                    end: NONE,
                    else_at: NONE,
                });
                stack.push(decoded.frames.len() as u32 - 1);
            }
            Operator::If { .. } => {
                decoded.frames.push(Frame {
                    kind: FrameKind::If,
                    start: index,
                    end: NONE,
                    else_at: NONE,
                });
                let id = decoded.frames.len() as u32 - 1;
                stack.push(id);
                flow = Some(Flow::If(id));
            }
            Operator::Else => {
                let id = *stack
                    .last()
                    .ok_or_else(|| Error::protocol("WASM else without a block"))?;
                let frame = &mut decoded.frames[id as usize];
                if frame.kind != FrameKind::If || frame.else_at != NONE {
                    return Err(Error::protocol("WASM else does not match an if"));
                }
                frame.else_at = index;
                flow = Some(Flow::Else(id));
            }
            Operator::End => {
                let id = stack
                    .pop()
                    .ok_or_else(|| Error::protocol("WASM end without a block"))?;
                decoded.frames[id as usize].end = index;
                if stack.is_empty() {
                    ended_function = true;
                }
            }
            Operator::Br { relative_depth } => {
                flow = Some(frame_at(&stack, relative_depth).map_or(Flow::BadDepth, Flow::Br));
            }
            Operator::BrIf { relative_depth } => {
                flow = Some(frame_at(&stack, relative_depth).map_or(Flow::BadDepth, Flow::BrIf));
            }
            Operator::BrOnNull { relative_depth }
            | Operator::BrOnNonNull { relative_depth }
            | Operator::BrOnCast { relative_depth, .. }
            | Operator::BrOnCastFail { relative_depth, .. } => {
                flow = Some(frame_at(&stack, relative_depth).map_or(Flow::BadDepth, Flow::BrOn));
            }
            Operator::BrTable { targets } => {
                let start = decoded.arms.len() as u32;
                let mut count = 0u32;
                let mut bad_depth = false;
                for target in targets.targets() {
                    let depth = target.map_err(bad)?;
                    match frame_at(&stack, depth) {
                        Some(frame) => decoded.arms.push(frame),
                        None => {
                            decoded.arms.push(NONE);
                            bad_depth = true;
                        }
                    }
                    count += 1;
                }
                let default = frame_at(&stack, targets.default());
                if bad_depth || default.is_none() {
                    decoded.omissions.push(format!(
                        "A br_table at byte {offset} names a label past the open frames; those arms stay unresolved."
                    ));
                }
                flow = Some(Flow::BrTable {
                    arms: start,
                    count,
                    default: default.unwrap_or(NONE),
                });
            }
            Operator::Return => flow = Some(Flow::Return),
            Operator::Unreachable => flow = Some(Flow::Trap),
            Operator::ReturnCall { .. } => flow = Some(Flow::Out("tail call")),
            Operator::ReturnCallIndirect { .. } | Operator::ReturnCallRef { .. } => {
                flow = Some(Flow::Out("indirect tail call"));
            }
            Operator::Throw { .. } | Operator::ThrowRef | Operator::Rethrow { .. } => {
                flow = Some(Flow::Out("throw"));
            }
            Operator::Try { .. } => {
                decoded.frames.push(Frame {
                    kind: FrameKind::Try,
                    start: index,
                    end: NONE,
                    else_at: NONE,
                });
                stack.push(decoded.frames.len() as u32 - 1);
            }
            Operator::Catch { .. } | Operator::CatchAll => {
                let id = *stack
                    .last()
                    .ok_or_else(|| Error::protocol("WASM catch without a try"))?;
                let frame = &decoded.frames[id as usize];
                if frame.kind != FrameKind::Try {
                    return Err(Error::protocol("WASM catch does not match a try"));
                }
                decoded.exceptions.push((frame.start, index));
                flow = Some(Flow::Catch(id));
            }
            Operator::Delegate { .. } => {
                let id = stack
                    .pop()
                    .ok_or_else(|| Error::protocol("WASM delegate without a try"))?;
                decoded.frames[id as usize].end = index;
            }
            Operator::TryTable { try_table } => {
                decoded.frames.push(Frame {
                    kind: FrameKind::Block,
                    start: index,
                    end: NONE,
                    else_at: NONE,
                });
                stack.push(decoded.frames.len() as u32 - 1);
                for catch in &try_table.catches {
                    let label = match catch {
                        wasmparser::Catch::One { label, .. }
                        | wasmparser::Catch::OneRef { label, .. }
                        | wasmparser::Catch::All { label }
                        | wasmparser::Catch::AllRef { label } => *label,
                    };
                    // A catch clause names a label outside this try_table,
                    // relative to the frame around it.
                    match frame_at(&stack[..stack.len() - 1], label) {
                        Some(frame) => decoded.exceptions.push((index, encode_frame(frame))),
                        None => decoded.omissions.push(format!(
                            "A try_table catch at byte {offset} names a label past the open frames; that handler stays unresolved."
                        )),
                    }
                }
            }
            _ => {}
        }
        if let Some(flow) = flow {
            decoded.flows.push((index, flow));
        }
    }
    if !decoded.stopped {
        reader.finish().map_err(bad)?;
        if !ended_function || !stack.is_empty() {
            return Err(Error::protocol(
                "WASM function control structure is unterminated",
            ));
        }
    }
    Ok(decoded)
}

/// Exception handlers of a try_table name a frame, not an instruction; the
/// target is resolved once every frame has closed. The top bit marks them.
const FRAME_REF: u32 = 1 << 31;
fn encode_frame(frame: u32) -> u32 {
    frame | FRAME_REF
}

fn frame_target(frames: &[Frame], frame: u32) -> Option<u32> {
    let frame = &frames[frame as usize];
    let target = if frame.kind == FrameKind::Loop {
        frame.start
    } else {
        frame.end
    };
    (target != NONE).then_some(target)
}

struct Bits(Vec<u64>);
impl Bits {
    fn new(size: usize) -> Self {
        Self(vec![0; size / 64 + 1])
    }
    fn set(&mut self, index: usize) {
        self.0[index / 64] |= 1 << (index % 64);
    }
    fn get(&self, index: usize) -> bool {
        self.0[index / 64] & (1 << (index % 64)) != 0
    }
}

struct Graph {
    /// Instruction index of each block leader; a block runs to the next.
    leaders: Vec<u32>,
    edges: Vec<(u32, Option<u32>, u8, Option<String>)>,
    flags: Vec<u32>,
    omissions: Vec<String>,
}

/// Turns an ordered list of case numbers into a bounded `0-3,9` label.
fn case_label(cases: &[u32]) -> String {
    let mut text = String::new();
    let mut position = 0;
    while position < cases.len() {
        let start = cases[position];
        let mut stop = start;
        while position + 1 < cases.len() && cases[position + 1] == stop + 1 {
            position += 1;
            stop = cases[position];
        }
        position += 1;
        let piece = if stop == start {
            start.to_string()
        } else {
            format!("{start}-{stop}")
        };
        if text.len() + piece.len() + 1 > MAX_LABEL_BYTES {
            text.push_str(",...");
            break;
        }
        if !text.is_empty() {
            text.push(',');
        }
        text.push_str(&piece);
    }
    text
}

fn build(decoded: &Decoded) -> Graph {
    let count = decoded.offsets.len();
    let mut leader_bits = Bits::new(count + 2);
    if count > 0 {
        leader_bits.set(0);
    }
    let target = |frame: u32| frame_target(&decoded.frames, frame);
    let mark_next = |bits: &mut Bits, index: u32| {
        if (index as usize) + 1 < count {
            bits.set(index as usize + 1);
        }
    };
    let mark_target = |bits: &mut Bits, frame: u32| {
        if let Some(position) = target(frame) {
            bits.set(position as usize);
        }
    };
    for &(index, flow) in &decoded.flows {
        match flow {
            Flow::Br(frame) | Flow::BrIf(frame) | Flow::BrOn(frame) => {
                mark_target(&mut leader_bits, frame);
                mark_next(&mut leader_bits, index);
            }
            Flow::BrTable {
                arms,
                count: arm_count,
                default,
            } => {
                for &frame in &decoded.arms[arms as usize..(arms + arm_count) as usize] {
                    if frame != NONE {
                        mark_target(&mut leader_bits, frame);
                    }
                }
                if default != NONE {
                    mark_target(&mut leader_bits, default);
                }
                mark_next(&mut leader_bits, index);
            }
            Flow::If(frame) => {
                mark_next(&mut leader_bits, index);
                match decoded.frames[frame as usize].else_at {
                    NONE => mark_target(&mut leader_bits, frame),
                    at => mark_next(&mut leader_bits, at),
                }
            }
            Flow::Else(frame) => {
                mark_next(&mut leader_bits, index);
                mark_target(&mut leader_bits, frame);
            }
            Flow::Catch(frame) => {
                mark_next(&mut leader_bits, index);
                mark_target(&mut leader_bits, frame);
            }
            Flow::Return | Flow::Trap | Flow::Out(_) | Flow::BadDepth => {
                mark_next(&mut leader_bits, index);
            }
        }
    }
    for &(_, to) in &decoded.exceptions {
        // A try's handler is the instruction after its catch; a try_table's
        // handler is a frame's target, known now that frames have closed.
        let position = if to & FRAME_REF != 0 {
            target(to & !FRAME_REF)
        } else {
            ((to as usize) + 1 < count).then_some(to + 1)
        };
        if let Some(position) = position {
            leader_bits.set(position as usize);
        }
    }
    let mut leaders: Vec<u32> = Vec::new();
    for index in 0..count {
        if leader_bits.get(index) {
            leaders.push(index as u32);
        }
    }
    let block_of = |instruction: u32| -> u32 {
        leaders.partition_point(|leader| *leader <= instruction) as u32 - 1
    };
    let mut edges: Vec<(u32, Option<u32>, u8, Option<String>)> = Vec::new();
    let mut flags = vec![0u32; leaders.len()];
    if let Some(entry) = flags.first_mut() {
        *entry |= ENTRY;
    }
    let mut omissions = Vec::new();
    let mut unresolved_frame = false;
    let resolve = |edges: &mut Vec<(u32, Option<u32>, u8, Option<String>)>,
                   block: u32,
                   frame: u32,
                   kind: u8,
                   label: Option<String>,
                   unresolved_frame: &mut bool| {
        match target(frame) {
            Some(position) => edges.push((block, Some(block_of(position)), kind, label)),
            None => {
                *unresolved_frame = true;
                let text = label.map_or_else(
                    || "target past the decoded range".to_owned(),
                    |text| format!("{text}: target past the decoded range"),
                );
                edges.push((block, None, UNRESOLVED, Some(text)));
            }
        }
    };
    let mut cursor = 0usize;
    for block in 0..leaders.len() as u32 {
        let last = leaders
            .get(block as usize + 1)
            .map_or(count as u32 - 1, |next| next - 1);
        while cursor < decoded.flows.len() && decoded.flows[cursor].0 < last {
            cursor += 1;
        }
        let flow = decoded
            .flows
            .get(cursor)
            .filter(|(index, _)| *index == last)
            .map(|(_, flow)| *flow);
        let has_next = (block as usize + 1) < leaders.len();
        let fallthrough = |edges: &mut Vec<(u32, Option<u32>, u8, Option<String>)>,
                           kind: u8,
                           label: Option<&str>| {
            if has_next {
                edges.push((block, Some(block + 1), kind, label.map(str::to_owned)));
            }
        };
        match flow {
            None => {
                if has_next {
                    fallthrough(&mut edges, FALLTHROUGH, None);
                } else if !decoded.stopped {
                    flags[block as usize] |= EXIT;
                }
            }
            Some(Flow::Br(frame)) => {
                resolve(
                    &mut edges,
                    block,
                    frame,
                    BRANCH,
                    Some("br".into()),
                    &mut unresolved_frame,
                );
            }
            Some(Flow::BrIf(frame)) | Some(Flow::BrOn(frame)) => {
                resolve(
                    &mut edges,
                    block,
                    frame,
                    TAKEN,
                    Some("true".into()),
                    &mut unresolved_frame,
                );
                fallthrough(&mut edges, NOT_TAKEN, Some("false"));
            }
            Some(Flow::BrTable {
                arms,
                count: arm_count,
                default,
            }) => {
                let mut pairs: Vec<(u32, u32)> = decoded.arms
                    [arms as usize..(arms + arm_count) as usize]
                    .iter()
                    .enumerate()
                    .map(|(case, frame)| (*frame, case as u32))
                    .collect();
                pairs.sort_unstable();
                let mut position = 0;
                while position < pairs.len() {
                    let frame = pairs[position].0;
                    let mut cases = Vec::new();
                    while position < pairs.len() && pairs[position].0 == frame {
                        cases.push(pairs[position].1);
                        position += 1;
                    }
                    let label = case_label(&cases);
                    if frame == NONE {
                        edges.push((
                            block,
                            None,
                            UNRESOLVED,
                            Some(format!("case {label}: label out of range")),
                        ));
                    } else {
                        resolve(
                            &mut edges,
                            block,
                            frame,
                            TABLE,
                            Some(label),
                            &mut unresolved_frame,
                        );
                    }
                }
                if default == NONE {
                    edges.push((
                        block,
                        None,
                        UNRESOLVED,
                        Some("default: label out of range".into()),
                    ));
                } else {
                    resolve(
                        &mut edges,
                        block,
                        default,
                        TABLE_DEFAULT,
                        Some("default".into()),
                        &mut unresolved_frame,
                    );
                }
            }
            Some(Flow::If(frame)) => {
                fallthrough(&mut edges, TAKEN, Some("true"));
                let at = decoded.frames[frame as usize].else_at;
                if at == NONE {
                    resolve(
                        &mut edges,
                        block,
                        frame,
                        NOT_TAKEN,
                        Some("false".into()),
                        &mut unresolved_frame,
                    );
                } else if (at as usize) + 1 < count {
                    edges.push((
                        block,
                        Some(block_of(at + 1)),
                        NOT_TAKEN,
                        Some("false".into()),
                    ));
                }
            }
            Some(Flow::Else(frame)) | Some(Flow::Catch(frame)) => {
                resolve(
                    &mut edges,
                    block,
                    frame,
                    BRANCH,
                    Some("end".into()),
                    &mut unresolved_frame,
                );
            }
            Some(Flow::Return) => flags[block as usize] |= EXIT,
            Some(Flow::Trap) => flags[block as usize] |= TRAP,
            Some(Flow::Out(what)) => edges.push((block, None, UNRESOLVED, Some(what.to_owned()))),
            Some(Flow::BadDepth) => {
                edges.push((
                    block,
                    None,
                    UNRESOLVED,
                    Some("label out of range".to_owned()),
                ));
            }
        }
    }
    for &(from, to) in &decoded.exceptions {
        let from_block = block_of(from);
        if to & FRAME_REF != 0 {
            resolve(
                &mut edges,
                from_block,
                to & !FRAME_REF,
                EXCEPTION,
                Some("catch".into()),
                &mut unresolved_frame,
            );
        } else if (to as usize) + 1 < count {
            edges.push((
                from_block,
                Some(block_of(to + 1)),
                EXCEPTION,
                Some("catch".into()),
            ));
        }
    }
    if unresolved_frame {
        omissions
            .push("A branch targets a frame that never closed before decoding stopped.".to_owned());
    }
    // Reachability walks declared edges from the entry block. False means this
    // graph has no declared path here, not that the code never runs.
    let mut heads = vec![u32::MAX; leaders.len()];
    let mut next = vec![u32::MAX; edges.len()];
    for (position, edge) in edges.iter().enumerate() {
        next[position] = heads[edge.0 as usize];
        heads[edge.0 as usize] = position as u32;
    }
    if !flags.is_empty() {
        let mut stack = vec![0u32];
        flags[0] |= REACHABLE;
        while let Some(block) = stack.pop() {
            let mut edge = heads[block as usize];
            while edge != u32::MAX {
                if let Some(to) = edges[edge as usize].1
                    && flags[to as usize] & REACHABLE == 0
                {
                    flags[to as usize] |= REACHABLE;
                    stack.push(to);
                }
                edge = next[edge as usize];
            }
        }
    }
    Graph {
        leaders,
        edges,
        flags,
        omissions,
    }
}

/// Operands for a basic-block row: the same decoded fields as the linear
/// listing with the field names removed, so a row fits on a card.
fn operands(op: &Operator<'_>) -> String {
    match op {
        Operator::LocalGet { local_index }
        | Operator::LocalSet { local_index }
        | Operator::LocalTee { local_index } => local_index.to_string(),
        Operator::GlobalGet { global_index } | Operator::GlobalSet { global_index } => {
            global_index.to_string()
        }
        Operator::Call { function_index }
        | Operator::ReturnCall { function_index }
        | Operator::RefFunc { function_index } => function_index.to_string(),
        Operator::CallIndirect {
            type_index,
            table_index,
        }
        | Operator::ReturnCallIndirect {
            type_index,
            table_index,
        } => {
            format!("type {type_index}, table {table_index}")
        }
        Operator::I32Const { value } => value.to_string(),
        Operator::I64Const { value } => value.to_string(),
        Operator::F32Const { value } => f32::from_bits(value.bits()).to_string(),
        Operator::F64Const { value } => f64::from_bits(value.bits()).to_string(),
        Operator::Br { relative_depth } | Operator::BrIf { relative_depth } => {
            relative_depth.to_string()
        }
        Operator::BrTable { targets } => {
            format!("[{} targets] default {}", targets.len(), targets.default())
        }
        Operator::Block { blockty } | Operator::Loop { blockty } | Operator::If { blockty } => {
            match blockty {
                wasmparser::BlockType::Empty => String::new(),
                wasmparser::BlockType::Type(ty) => ty.to_string(),
                wasmparser::BlockType::FuncType(index) => format!("type {index}"),
            }
        }
        Operator::End
        | Operator::Else
        | Operator::Return
        | Operator::Unreachable
        | Operator::Nop => String::new(),
        other => {
            let debug = format!("{other:?}");
            let body = debug
                .find(" { ")
                .map_or("", |index| &debug[index + 3..])
                .trim_end_matches(" }");
            if let Some(pos) = body.find("MemArg {") {
                let inner = &body[pos..];
                let field = |name: &str| -> Option<&str> {
                    inner.find(name).map(|index| {
                        let rest = &inner[index + name.len()..];
                        rest.split(|c: char| !c.is_ascii_digit())
                            .next()
                            .unwrap_or("")
                    })
                };
                format!(
                    "offset={} align={}",
                    field("offset: ").unwrap_or("0"),
                    field("align: ").unwrap_or("0")
                )
            } else {
                body.chars().take(MAX_LABEL_BYTES).collect()
            }
        }
    }
}

fn block_run_text(operand: &str, count: u32) -> String {
    let mut text = String::from("block");
    if count > 1 {
        let _ = write!(text, " x{count}");
    }
    if !operand.is_empty() {
        text.push(' ');
        text.push_str(operand);
    }
    text
}

fn json_string(out: &mut String, value: &str) {
    out.push_str(&serde_json::to_string(value).expect("JSON string"));
}

/// Basic blocks for one defined function, or a provider error a caller shows.
pub fn function_graph(root: &Path, id: &str, function: u32) -> Result<String> {
    function_graph_named(root, id, function, None)
}

/// The block graph with the function's researcher name as `analyst_name` and
/// every name of its module as `analyst_names`, so a `call N` row resolves.
pub(crate) fn function_graph_named(
    root: &Path,
    id: &str,
    function: u32,
    analyst: Option<&wasm_names::Names>,
) -> Result<String> {
    let artifact = artifact(root, id)?;
    let started = Instant::now();
    let deadline = started + DEADLINE;
    let mut imported = 0u32;
    let mut types = Vec::new();
    let mut position = 0u32;
    for payload in Parser::new(0).parse_all(&artifact.bytes) {
        let payload = payload.map_err(bad)?;
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    if matches!(import.map_err(bad)?.ty, wasmparser::TypeRef::Func(_)) {
                        imported += 1;
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    types.push(ty.map_err(bad)?);
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index = imported + position;
                position += 1;
                if index != function {
                    continue;
                }
                let range = body.range();
                if range.len() > MAX_BODY_BYTES {
                    return Err(Error::bad(format!(
                        "WASM function {function} is {} bytes, past the {MAX_BODY_BYTES}-byte body limit web engines enforce",
                        range.len()
                    )));
                }
                let ty = types.get(position as usize - 1).copied();
                let out = graph_document(&artifact, function, ty, &body, deadline)?;
                let (Some(names), Some(sha)) = (analyst, artifact.sha256.as_str()) else {
                    return Ok(out);
                };
                let mut members = Vec::new();
                if let Some(name) = names.function(sha, function) {
                    members.push(("analyst_name", serde_json::json!(name)));
                }
                members.push((
                    "analyst_names",
                    names.module_member(sha, u64::from(imported) + types.len() as u64),
                ));
                return Ok(wasm_names::append_members(out, &members));
            }
            Payload::End(_) => break,
            _ => {}
        }
    }
    if function < imported {
        return Err(Error::new(
            404,
            format!("WASM function {function} is imported and has no body in this module"),
        ));
    }
    Err(Error::new(
        404,
        format!("WASM function {function} is not defined by this module"),
    ))
}

fn graph_document(
    artifact: &Artifact,
    function: u32,
    ty: Option<u32>,
    body: &wasmparser::FunctionBody<'_>,
    deadline: Instant,
) -> Result<String> {
    let decoded = decode(body, deadline)?;
    let mut graph = build(&decoded);
    let mut omissions = decoded.omissions.clone();
    omissions.append(&mut graph.omissions);
    let count = decoded.offsets.len();
    // Structure is ordered by leader, so a prefix keeps the entry and every
    // edge between retained blocks. An edge leaving the prefix stays labeled.
    let mut structure_bytes = 0usize;
    let mut kept = graph.leaders.len();
    let mut edges_by_block = vec![0usize; graph.leaders.len()];
    for edge in &graph.edges {
        edges_by_block[edge.0 as usize] += 1;
    }
    for (block, edge_count) in edges_by_block.iter().enumerate() {
        structure_bytes += 64 + edge_count * 56;
        if structure_bytes > MAX_STRUCTURE_BYTES {
            kept = block;
            omissions.push(format!(
                "Structure byte budget reached; {} blocks after byte {} are not in this graph.",
                graph.leaders.len() - block,
                decoded.offsets[graph.leaders[block] as usize]
            ));
            break;
        }
    }
    let mut block_rows: Vec<(u32, u32, u32)> = Vec::with_capacity(kept);
    let mut rows = String::new();
    let mut reader = body.get_operators_reader().map_err(bad)?;
    let mut row_index = 0u32;
    let mut text_stopped = false;
    for block in 0..kept {
        let leader = graph.leaders[block];
        let end = graph
            .leaders
            .get(block + 1)
            .map_or(count as u32, |next| *next);
        let first_row = row_index;
        let mut included = 0u32;
        let mut emit = |rows: &mut String, offset: usize, text: String| {
            if rows.len() + text.len() + 16 > MAX_ROW_TEXT_BYTES {
                if !text_stopped {
                    text_stopped = true;
                    omissions.push(format!(
                        "Instruction row byte budget reached at byte {offset:x}; later rows are not displayed. Block structure is unaffected."
                    ));
                }
                return;
            }
            let _ = writeln!(rows, "{offset:x} {text}");
            row_index += 1;
            included += 1;
        };
        // A run of identical `block` openers is structure, not behavior: a
        // dispatcher opens hundreds before its br_table. One row carries the
        // run's first offset and count, and the card's badge stays exact.
        let mut run: Option<(usize, String, u32)> = None;
        for instruction in leader..end {
            let (op, offset) = reader.read_with_offset().map_err(bad)?;
            if let Operator::Block { .. } = op {
                let text = operands(&op);
                match &mut run {
                    Some((_, current, count)) if *current == text => *count += 1,
                    _ => {
                        if let Some((at, text, count)) = run.take() {
                            emit(&mut rows, at, block_run_text(&text, count));
                        }
                        run = Some((offset, text, 1));
                    }
                }
                continue;
            }
            if let Some((at, text, count)) = run.take() {
                emit(&mut rows, at, block_run_text(&text, count));
            }
            let mut text = wasm::mnemonic(&op);
            let args = operands(&op);
            if !args.is_empty() {
                text.push(' ');
                text.push_str(&args);
            }
            if let Some(target) = branch_target(&decoded, instruction, &graph) {
                let _ = write!(text, " -> {target:x}");
            }
            emit(&mut rows, offset, text);
        }
        if let Some((at, text, count)) = run.take() {
            emit(&mut rows, at, block_run_text(&text, count));
        }
        if text_stopped {
            graph.flags[block] |= ROWS_CUT;
        }
        block_rows.push((first_row, included, end - leader));
    }
    // A decode stopped early leaves a suffix of operators unread; the graph is
    // already labeled partial, so the reader state past `kept` is irrelevant.
    let mut out =
        String::with_capacity(structure_bytes.min(MAX_STRUCTURE_BYTES) + rows.len() + 2048);
    out.push_str("{\"schema\":\"wasm-block-graph-v1\",\"artifact_id\":");
    out.push_str(&serde_json::to_string(&artifact.artifact_id).expect("JSON value"));
    out.push_str(",\"sha256\":");
    out.push_str(&serde_json::to_string(&artifact.sha256).expect("JSON value"));
    let range = body.range();
    let _ = write!(
        out,
        ",\"function_index\":{function},\"byte_offset\":{},\"byte_end\":{},\"type_index\":{},\"evidence\":\"declared_static\",\"complete\":false,\"status\":\"{}\",\"block_count\":{kept},\"edge_count\":{},\"instruction_count\":{count},\"edge_kinds\":{},\"block_fields\":[\"byte_offset\",\"byte_end\",\"first_row\",\"row_count\",\"instruction_count\",\"flags\"],\"flag_bits\":{{\"entry\":1,\"reachable\":2,\"exit\":4,\"trap\":8,\"rows_cut\":32}},\"edge_fields\":[\"from\",\"to\",\"kind\",\"label\"],\"blocks\":[",
        range.start,
        range.end,
        ty.map_or_else(|| "null".to_owned(), |t| t.to_string()),
        if omissions.is_empty() {
            "decoded"
        } else {
            "partial"
        },
        graph.edges.len(),
        serde_json::to_string(&EDGE_KINDS).expect("JSON strings"),
    );
    for (block, &(first, included, instructions)) in block_rows.iter().enumerate() {
        if block > 0 {
            out.push(',');
        }
        let leader = graph.leaders[block];
        let start = decoded.offsets[leader as usize];
        let end = graph
            .leaders
            .get(block + 1)
            .map_or(decoded.byte_end, |next| decoded.offsets[*next as usize]);
        let _ = write!(
            out,
            "[{start},{end},{first},{included},{instructions},{}]",
            graph.flags[block]
        );
    }
    out.push_str("],\"edges\":[");
    let mut wrote = 0usize;
    for (from, to, kind, label) in &graph.edges {
        if (*from as usize) >= kept {
            continue;
        }
        if wrote > 0 {
            out.push(',');
        }
        wrote += 1;
        let (to, kind, label) = match to {
            Some(target) if (*target as usize) >= kept => (
                None,
                UNRESOLVED,
                Some(label.as_deref().map_or_else(
                    || "target outside the block budget".to_owned(),
                    |text| format!("{text}: target outside the block budget"),
                )),
            ),
            other => (*other, *kind, label.clone()),
        };
        let _ = write!(
            out,
            "[{from},{},{kind},",
            to.map_or_else(|| "null".to_owned(), |t| t.to_string())
        );
        match label {
            Some(text) => json_string(&mut out, &text),
            None => out.push_str("null"),
        }
        out.push(']');
    }
    out.push_str("],\"rows\":");
    json_string(&mut out, &rows);
    let _ = write!(
        out,
        ",\"row_count\":{row_index},\"omissions\":{},\"limits\":{{\"max_input_bytes\":{MAX_BYTES},\"max_body_bytes\":{MAX_BODY_BYTES},\"max_row_text_bytes\":{MAX_ROW_TEXT_BYTES},\"max_structure_bytes\":{MAX_STRUCTURE_BYTES},\"deadline_ms\":{}}},\"notice\":\"Declared static control flow. Reachable here is not observed execution, and a complete drawing is not a proof.\"}}",
        serde_json::to_string(&omissions).expect("JSON strings"),
        DEADLINE.as_millis(),
    );
    Ok(out)
}

/// The byte offset a direct branch resolves to, shown on its row.
fn branch_target(decoded: &Decoded, instruction: u32, graph: &Graph) -> Option<u32> {
    let flow = decoded
        .flows
        .binary_search_by_key(&instruction, |(index, _)| *index)
        .ok()
        .map(|position| decoded.flows[position].1)?;
    let frame = match flow {
        Flow::Br(frame) | Flow::BrIf(frame) | Flow::BrOn(frame) => frame,
        _ => return None,
    };
    let target = frame_target(&decoded.frames, frame)?;
    graph
        .leaders
        .binary_search(&target)
        .ok()
        .map(|_| decoded.offsets[target as usize])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph_for(wat: &str, function: u32) -> Value {
        let bytes = wat::parse_str(wat).expect("fixture");
        let (document, _) = graph_of(&bytes, function).unwrap();
        document
    }
    fn graph_of(bytes: &[u8], function: u32) -> Result<(Value, usize)> {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("blobs")).unwrap();
        let hash = sha2_hex(bytes);
        std::fs::write(directory.path().join(format!("blobs/{hash}.bin")), bytes).unwrap();
        let record = json!({"protocol_version":1,"artifact_id":"7","session_id":"1","navigation_id":"1","frame_id":"1",
            "parent_artifact_id":"0","creator_event_id":"0","kind":"wasm","url":"https://example.test/module.wasm",
            "mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        std::fs::write(
            directory.path().join("manifest.jsonl"),
            format!("{record}\n"),
        )
        .unwrap();
        let text = function_graph(directory.path(), "7", function)?;
        Ok((serde_json::from_str(&text).unwrap(), text.len()))
    }
    fn sha2_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }
    fn kinds(document: &Value) -> Vec<(i64, Option<i64>, String, Option<String>)> {
        let names = document["edge_kinds"].as_array().unwrap().clone();
        document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| {
                (
                    edge[0].as_i64().unwrap(),
                    edge[1].as_i64(),
                    names[edge[2].as_u64().unwrap() as usize]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                    edge[3].as_str().map(str::to_owned),
                )
            })
            .collect()
    }

    #[test]
    fn if_else_forms_a_diamond_with_labeled_arms() {
        let document = graph_for(
            "(module (func (param i32) (result i32)
                local.get 0
                if (result i32) i32.const 1 else i32.const 2 end))",
            0,
        );
        assert_eq!(document["schema"], "wasm-block-graph-v1");
        assert_eq!(document["complete"], false);
        assert_eq!(document["evidence"], "declared_static");
        assert_eq!(document["block_count"], 4);
        assert_eq!(
            kinds(&document),
            vec![
                (0, Some(1), "taken".to_owned(), Some("true".to_owned())),
                (0, Some(2), "not_taken".to_owned(), Some("false".to_owned())),
                (1, Some(3), "branch".to_owned(), Some("end".to_owned())),
                (2, Some(3), "fallthrough".to_owned(), None),
            ]
        );
        assert_eq!(
            document["blocks"][3][5].as_u64().unwrap() & EXIT as u64,
            EXIT as u64
        );
    }

    #[test]
    fn loop_back_edges_target_the_loop_header() {
        let document = graph_for(
            "(module (func (local i32)
                block loop local.get 0 br_if 1 br 0 end end))",
            0,
        );
        let edges = kinds(&document);
        // The back edge names the loop header's block, not an invented one.
        assert!(
            edges
                .iter()
                .any(|edge| edge.2 == "branch" && edge.1 == Some(1)),
            "{edges:?}"
        );
        assert!(edges.iter().any(|edge| edge.2 == "taken"), "{edges:?}");
    }

    #[test]
    fn a_dispatcher_keeps_every_arm_and_merges_same_target_cases() {
        let arms = (0..300).map(|i| format!("(block ${i}")).collect::<String>();
        let table = (0..300).map(|i| format!("${i} ")).collect::<String>();
        let closes = (0..300)
            .map(|i| format!(") i32.const {i} return"))
            .collect::<Vec<_>>()
            .join(" ");
        let wat = format!(
            "(module (func (param i32) (result i32) {arms} local.get 0 br_table {table}$0 {closes} i32.const -1))"
        );
        let document = graph_for(&wat, 0);
        let edges = kinds(&document);
        let table_edges: Vec<_> = edges.iter().filter(|edge| edge.2 == "table").collect();
        assert_eq!(table_edges.len(), 300, "{}", edges.len());
        // Distinct arms keep distinct targets; nothing folds into one line.
        let targets: BTreeSet<_> = table_edges.iter().map(|edge| edge.1).collect();
        assert_eq!(targets.len(), 300);
        assert!(
            edges
                .iter()
                .any(|edge| edge.2 == "table_default" && edge.3.as_deref() == Some("default"))
        );
        assert_eq!(document["instruction_count"].as_u64().unwrap() > 900, true);
    }

    use std::collections::BTreeSet;

    #[test]
    fn unresolved_transfers_stay_labeled() {
        let document = graph_for(
            "(module (type $t (func)) (table funcref (elem $f))
              (func $f return_call_indirect (type $t) (i32.const 0))
              (func (throw $e)) (tag $e))",
            0,
        );
        let edges = kinds(&document);
        assert_eq!(
            edges,
            vec![(
                0,
                None,
                "unresolved".to_owned(),
                Some("indirect tail call".to_owned())
            )]
        );
        let second = graph_for("(module (func) (func (throw $e)) (tag $e))", 1);
        let edges = kinds(&second);
        assert_eq!(
            edges,
            vec![(0, None, "unresolved".to_owned(), Some("throw".to_owned()))]
        );
    }

    #[test]
    fn a_depth_past_the_frames_stays_unresolved() {
        // `wat` refuses this, so the fixture edits a well-formed body in place:
        // br 0 (0c 00) becomes br 9 (0c 09). The parser never validates depths.
        let mut bytes = wat::parse_str("(module (func br 0))").unwrap();
        let position = bytes
            .windows(2)
            .position(|window| window == [0x0c, 0x00])
            .unwrap();
        bytes[position + 1] = 9;
        let (document, _) = graph_of(&bytes, 0).unwrap();
        assert_eq!(
            kinds(&document),
            vec![(
                0,
                None,
                "unresolved".to_owned(),
                Some("label out of range".to_owned())
            )]
        );
    }

    #[test]
    fn missing_and_imported_functions_are_visible_errors() {
        let bytes = wat::parse_str(r#"(module (import "env" "f" (func)) (func))"#).unwrap();
        let missing = graph_of(&bytes, 9).unwrap_err();
        assert_eq!(missing.status, 404);
        assert!(
            missing.message.contains("not defined"),
            "{}",
            missing.message
        );
        let imported = graph_of(&bytes, 0).unwrap_err();
        assert_eq!(imported.status, 404);
        assert!(
            imported.message.contains("imported"),
            "{}",
            imported.message
        );
        let (document, _) = graph_of(&bytes, 1).unwrap();
        assert_eq!(document["function_index"], 1);
    }

    #[test]
    fn malformed_control_structure_is_refused() {
        // A body that ends without its `end` byte.
        let good = wat::parse_str("(module (func nop))").unwrap();
        let position = good
            .windows(2)
            .position(|window| window == [0x01, 0x0b])
            .unwrap();
        let mut bad = good.clone();
        bad[position + 1] = 0x01; // the closing end becomes another nop
        let error = graph_of(&bad, 0).unwrap_err();
        assert_eq!(error.status, 422, "{}", error.message);
    }

    #[test]
    fn function_index_lists_ranges_names_and_exports() {
        let bytes = wat::parse_str(
            r#"(module (import "env" "g" (func)) (func $first) (func (export "second") nop))"#,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("blobs")).unwrap();
        let hash = sha2_hex(&bytes);
        std::fs::write(directory.path().join(format!("blobs/{hash}.bin")), &bytes).unwrap();
        let record = json!({"protocol_version":1,"artifact_id":"7","session_id":"1","navigation_id":"1","frame_id":"1",
            "parent_artifact_id":"0","creator_event_id":"0","kind":"wasm","url":"https://example.test/module.wasm",
            "mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        std::fs::write(
            directory.path().join("manifest.jsonl"),
            format!("{record}\n"),
        )
        .unwrap();
        let document: Value =
            serde_json::from_str(&function_index(directory.path(), "7").unwrap()).unwrap();
        assert_eq!(document["schema"], "wasm-function-index-v1");
        assert_eq!(document["defined_functions"], 2);
        assert_eq!(document["imported_functions"], 1);
        assert_eq!(document["functions"][0][0], 1);
        assert_eq!(document["functions"][1][0], 2);
        let names = document["names"].as_array().unwrap();
        assert!(
            names.iter().any(|row| row[0] == 1 && row[1] == "first"),
            "{names:?}"
        );
        assert!(
            names.iter().any(|row| row[0] == 2 && row[1] == "second"),
            "{names:?}"
        );
    }

    #[test]
    fn case_labels_compress_and_stay_bounded() {
        assert_eq!(case_label(&[0, 1, 2, 5, 9, 10]), "0-2,5,9-10");
        let many: Vec<u32> = (0..2000).step_by(2).collect();
        let label = case_label(&many);
        assert!(label.len() <= MAX_LABEL_BYTES + 4, "{label}");
        assert!(label.ends_with(",..."), "{label}");
    }
}
