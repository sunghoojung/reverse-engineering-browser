//! One function's basic blocks, derived on demand from the inspection decoder.
//!
//! Wasm control flow is structured, so every branch names a label whose target
//! is a byte position in the same body and this module never guesses. What it
//! cannot resolve from the body (tail calls, a throw that may leave the
//! function, a label past the frames it decoded) stays an explicit unresolved
//! edge with a label. Nothing here runs
//! the module, and a graph is one function at a time: nothing retains a
//! whole-module structure.
use crate::{
    error::{Error, Result, check_cancelled},
    evidence, validation, wasm, wasm_names,
};
use serde_json::Value;
use std::{fmt::Write as _, path::Path, sync::atomic::AtomicBool};
use wasmparser::{ExternalKind, KnownCustom, Name, Operator, Parser, Payload};

/// Web engines reject a body above this size, so a longer one cannot have run.
pub(crate) const MAX_BODY_BYTES: usize = 7_654_321;
const MAX_NAME_BYTES: usize = 128;
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
    let record = evidence::find_artifact(root, id)?;
    if record["kind"] != "wasm" {
        return Err(Error::bad("Artifact is not WebAssembly"));
    }
    // A module of any size is read whole: one analysis holds it once.
    let bytes = evidence::read(root, &record)?;
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
    function_index_named(root, id, None, &AtomicBool::new(false))
}

/// The function list with the researcher names of this module's functions as
/// an `analyst_names` member beside the name-section `names`.
pub(crate) fn function_index_named(
    root: &Path,
    id: &str,
    analyst: Option<&wasm_names::Names>,
    cancelled: &AtomicBool,
) -> Result<String> {
    let artifact = artifact(root, id)?;
    let mut imported = 0u32;
    let mut types = Vec::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut names: Vec<(u32, String)> = Vec::new();
    let mut exports: Vec<(u32, String)> = Vec::new();
    let mut omissions: Vec<String> = Vec::new();
    let mut ended = false;
    for payload in Parser::new(0).parse_all(&artifact.bytes) {
        check_cancelled(cancelled, "WASM function index")?;
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
    if !ended {
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
        "],\"omissions\":{},\"limits\":{{\"max_name_bytes\":{MAX_NAME_BYTES}}},\"notice\":\"Static function list. Graphs are computed one function at a time.\"}}",
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
    /// A transfer this function's bytes cannot resolve (tail call).
    Out(&'static str),
    /// `throw`, `throw_ref` or `rethrow`: its edges are the handlers in
    /// `Decoded::throws`, and only an exception that may leave the function
    /// is unresolved.
    Throw,
    /// A label deeper than the frames decoded so far.
    BadDepth,
}

/// One exception handler scope: a legacy `try` body or a `try_table`.
struct Scope {
    /// The `try` or `try_table` instruction, so scopes are ordered by it.
    start: u32,
    /// The scope an exception goes to when no clause here catches it: the one
    /// covering this scope's opening, or NONE for the caller.
    outer: u32,
    /// A legacy `try ... delegate` hands its exceptions to this scope (NONE
    /// for the caller) instead of to clauses.
    delegate: Option<u32>,
    clauses: Vec<Clause>,
}

struct Clause {
    /// None catches every tag.
    tag: Option<u32>,
    /// A legacy catch's instruction (its handler starts after it), or a
    /// try_table clause's label frame with FRAME_REF set, or NONE for a label
    /// past the open frames.
    handler: u32,
    name: &'static str,
}

/// An instruction that may raise an exception into a local handler.
struct Throw {
    at: u32,
    /// The innermost scope covering the instruction, or NONE.
    scope: u32,
    /// The tag thrown, when the instruction names it.
    tag: Option<u32>,
    /// A call's callee may throw; a call outside every scope adds no edge,
    /// since any call can leave the function that way.
    call: bool,
    what: &'static str,
}

struct Decoded {
    offsets: Vec<u32>,
    flows: Vec<(u32, Flow)>,
    frames: Vec<Frame>,
    arms: Vec<u32>,
    scopes: Vec<Scope>,
    throws: Vec<Throw>,
    /// Imported tags take the lowest indices, and two of them can be one tag.
    /// The body alone does not say how many there are, so `decode` starts at
    /// u32::MAX (any two tags may be one) and a caller that read the import
    /// section narrows it.
    imported_tags: u32,
    byte_end: u32,
    omissions: Vec<String>,
}

fn decode(body: &wasmparser::FunctionBody<'_>, cancelled: &AtomicBool) -> Result<Decoded> {
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
        scopes: Vec::new(),
        throws: Vec::new(),
        imported_tags: u32::MAX,
        byte_end: body.range().end as u32,
        omissions: Vec::new(),
    };
    let mut stack: Vec<u32> = vec![0];
    // The scopes whose handlers cover the current instruction, innermost
    // last, each with its frame's position in `stack`. A legacy try leaves it
    // at its first catch: an exception in a catch body goes further out.
    let mut covering: Vec<(u32, usize)> = Vec::new();
    let mut reader = body.get_operators_reader().map_err(bad)?;
    let mut ended_function = false;
    while !reader.eof() {
        if decoded.offsets.len() & 4095 == 0 {
            check_cancelled(cancelled, "WASM block graph")?;
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
                if covering.last().is_some_and(|(_, at)| *at == stack.len()) {
                    covering.pop();
                }
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
            Operator::Throw { tag_index } => {
                decoded.throws.push(Throw {
                    at: index,
                    scope: covering.last().map_or(NONE, |(scope, _)| *scope),
                    tag: Some(tag_index),
                    call: false,
                    what: "throw",
                });
                flow = Some(Flow::Throw);
            }
            Operator::ThrowRef => {
                decoded.throws.push(Throw {
                    at: index,
                    scope: covering.last().map_or(NONE, |(scope, _)| *scope),
                    tag: None,
                    call: false,
                    what: "throw_ref",
                });
                flow = Some(Flow::Throw);
            }
            Operator::Rethrow { relative_depth } => {
                // The exception is the one its catch caught, so a `catch t`
                // rethrows tag t. It starts outside that try, which no longer
                // covers its own catch bodies.
                let tag = frame_at(&stack, relative_depth)
                    .filter(|frame| decoded.frames[*frame as usize].kind == FrameKind::Try)
                    .and_then(|frame| {
                        scope_of(&decoded.scopes, decoded.frames[frame as usize].start)
                    })
                    .and_then(|scope| decoded.scopes[scope as usize].clauses.last())
                    .and_then(|clause| clause.tag);
                decoded.throws.push(Throw {
                    at: index,
                    scope: covering.last().map_or(NONE, |(scope, _)| *scope),
                    tag,
                    call: false,
                    what: "rethrow",
                });
                flow = Some(Flow::Throw);
            }
            Operator::Call { .. } | Operator::CallIndirect { .. } | Operator::CallRef { .. } => {
                if let Some((scope, _)) = covering.last() {
                    decoded.throws.push(Throw {
                        at: index,
                        scope: *scope,
                        tag: None,
                        call: true,
                        what: "call",
                    });
                }
            }
            Operator::Try { .. } => {
                decoded.frames.push(Frame {
                    kind: FrameKind::Try,
                    start: index,
                    end: NONE,
                    else_at: NONE,
                });
                stack.push(decoded.frames.len() as u32 - 1);
                let outer = covering.last().map_or(NONE, |(scope, _)| *scope);
                covering.push((decoded.scopes.len() as u32, stack.len() - 1));
                decoded.scopes.push(Scope {
                    start: index,
                    outer,
                    delegate: None,
                    clauses: Vec::new(),
                });
            }
            Operator::Catch { .. } | Operator::CatchAll => {
                let id = *stack
                    .last()
                    .ok_or_else(|| Error::protocol("WASM catch without a try"))?;
                let frame = &decoded.frames[id as usize];
                if frame.kind != FrameKind::Try {
                    return Err(Error::protocol("WASM catch does not match a try"));
                }
                let scope = scope_of(&decoded.scopes, frame.start).expect("a try opens a scope");
                if covering
                    .last()
                    .is_some_and(|(_, at)| *at == stack.len() - 1)
                {
                    covering.pop();
                }
                let tag = match op {
                    Operator::Catch { tag_index } => Some(tag_index),
                    _ => None,
                };
                decoded.scopes[scope as usize].clauses.push(Clause {
                    tag,
                    handler: index,
                    name: if tag.is_some() { "catch" } else { "catch_all" },
                });
                flow = Some(Flow::Catch(id));
            }
            Operator::Delegate { relative_depth } => {
                let id = stack
                    .pop()
                    .ok_or_else(|| Error::protocol("WASM delegate without a try"))?;
                decoded.frames[id as usize].end = index;
                if covering.last().is_some_and(|(_, at)| *at == stack.len()) {
                    covering.pop();
                }
                // The label counts from the frame around the try. An
                // exception goes on as if thrown just inside that frame: to
                // its own handlers when it is a try still in its body, else
                // to the scope covering it. The function's label is the caller.
                let target = stack.len().checked_sub(relative_depth as usize + 1);
                if target.is_none() {
                    decoded.omissions.push(format!(
                        "A delegate at byte {offset} names a label past the open frames; its exceptions are shown leaving the function."
                    ));
                }
                let to = target
                    .filter(|position| *position > 0)
                    .and_then(|position| covering.iter().rev().find(|(_, at)| *at <= position))
                    .map_or(NONE, |(scope, _)| *scope);
                if let Some(scope) = scope_of(&decoded.scopes, decoded.frames[id as usize].start) {
                    decoded.scopes[scope as usize].delegate = Some(to);
                }
            }
            Operator::TryTable { try_table } => {
                decoded.frames.push(Frame {
                    kind: FrameKind::Block,
                    start: index,
                    end: NONE,
                    else_at: NONE,
                });
                stack.push(decoded.frames.len() as u32 - 1);
                let mut clauses = Vec::with_capacity(try_table.catches.len());
                for catch in &try_table.catches {
                    let (tag, label, name) = match *catch {
                        wasmparser::Catch::One { tag, label } => (Some(tag), label, "catch"),
                        wasmparser::Catch::OneRef { tag, label } => (Some(tag), label, "catch_ref"),
                        wasmparser::Catch::All { label } => (None, label, "catch_all"),
                        wasmparser::Catch::AllRef { label } => (None, label, "catch_all_ref"),
                    };
                    // A catch clause names a label outside this try_table,
                    // relative to the frame around it.
                    let handler = match frame_at(&stack[..stack.len() - 1], label) {
                        Some(frame) => encode_frame(frame),
                        None => {
                            decoded.omissions.push(format!(
                                "A try_table catch at byte {offset} names a label past the open frames; that handler stays unresolved."
                            ));
                            NONE
                        }
                    };
                    clauses.push(Clause { tag, handler, name });
                }
                let outer = covering.last().map_or(NONE, |(scope, _)| *scope);
                covering.push((decoded.scopes.len() as u32, stack.len() - 1));
                decoded.scopes.push(Scope {
                    start: index,
                    outer,
                    delegate: None,
                    clauses,
                });
            }
            _ => {}
        }
        if let Some(flow) = flow {
            decoded.flows.push((index, flow));
        }
    }
    reader.finish().map_err(bad)?;
    if !ended_function || !stack.is_empty() {
        return Err(Error::protocol(
            "WASM function control structure is unterminated",
        ));
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

/// The instruction a clause's handler starts at. A try's handler is the
/// instruction after its catch; a try_table's is a frame's target, known once
/// frames have closed.
fn clause_target(decoded: &Decoded, clause: &Clause) -> Option<u32> {
    if clause.handler == NONE {
        None
    } else if clause.handler & FRAME_REF != 0 {
        frame_target(&decoded.frames, clause.handler & !FRAME_REF)
    } else {
        ((clause.handler as usize) + 1 < decoded.offsets.len()).then_some(clause.handler + 1)
    }
}

/// The scope a `try` or `try_table` at instruction `start` opened.
fn scope_of(scopes: &[Scope], start: u32) -> Option<u32> {
    scopes
        .binary_search_by_key(&start, |scope| scope.start)
        .ok()
        .map(|position| position as u32)
}

/// Where one throw site's exception can go: `clause(scope, clause)` for every
/// clause that may catch it, innermost first. True when one of them certainly
/// catches it; false when it may also leave the function.
fn raise(decoded: &Decoded, site: &Throw, mut clause: impl FnMut(&Clause)) -> bool {
    let mut scope = site.scope;
    while scope != NONE {
        let current = &decoded.scopes[scope as usize];
        if let Some(to) = current.delegate {
            scope = to;
            continue;
        }
        for candidate in &current.clauses {
            match (candidate.tag, site.tag) {
                (None, _) => {
                    clause(candidate);
                    return true;
                }
                (Some(caught), Some(thrown)) if caught == thrown => {
                    clause(candidate);
                    return true;
                }
                // Only imported tags can alias: each defined tag is its own.
                (Some(caught), Some(thrown))
                    if caught >= decoded.imported_tags || thrown >= decoded.imported_tags => {}
                _ => clause(candidate),
            }
        }
        scope = current.outer;
    }
    false
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

/// Turns an ordered list of case numbers into a `0-3,9` label. Every case is
/// named: the arms are in the body, so the label is no longer than it.
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
        if !text.is_empty() {
            text.push(',');
        }
        let _ = if stop == start {
            write!(text, "{start}")
        } else {
            write!(text, "{start}-{stop}")
        };
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
            Flow::Return | Flow::Trap | Flow::Out(_) | Flow::Throw | Flow::BadDepth => {
                mark_next(&mut leader_bits, index);
            }
        }
    }
    let handler = |clause: &Clause| clause_target(decoded, clause);
    for scope in &decoded.scopes {
        for clause in &scope.clauses {
            if let Some(position) = handler(clause) {
                leader_bits.set(position as usize);
            }
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
                } else {
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
            Some(Flow::Throw) => {}
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
    // Exception edges run from the block of each instruction that may throw
    // to every handler that may catch it. A block keeps one edge per handler,
    // named by the clause; one only a call reaches says so.
    let mut raised: Vec<(u32, Option<u32>, u8, String, bool)> = Vec::new();
    for site in &decoded.throws {
        let block = block_of(site.at);
        let before = raised.len();
        let caught = raise(decoded, site, |clause| {
            let name = match clause.tag {
                Some(tag) => format!("{} {tag}", clause.name),
                None => clause.name.to_owned(),
            };
            match handler(clause) {
                Some(position) => {
                    raised.push((block, Some(block_of(position)), EXCEPTION, name, site.call));
                }
                None if clause.handler == NONE => raised.push((
                    block,
                    None,
                    UNRESOLVED,
                    format!("{name}: label out of range"),
                    site.call,
                )),
                None => {
                    unresolved_frame = true;
                    raised.push((
                        block,
                        None,
                        UNRESOLVED,
                        format!("{name}: target past the decoded range"),
                        site.call,
                    ));
                }
            }
        });
        if !caught && !site.call {
            let label = if raised.len() == before {
                site.what.to_owned()
            } else {
                format!("{}: may escape", site.what)
            };
            raised.push((block, None, UNRESOLVED, label, false));
        }
    }
    raised.sort_unstable_by(|a, b| (a.0, a.1, a.2, &a.3, a.4).cmp(&(b.0, b.1, b.2, &b.3, b.4)));
    raised.dedup_by(|later, kept| {
        (later.0, later.1, later.2, &later.3) == (kept.0, kept.1, kept.2, &kept.3)
    });
    for (block, to, kind, label, call) in raised {
        let label = if call {
            format!("call: {label}")
        } else {
            label
        };
        edges.push((block, to, kind, Some(label)));
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
pub(crate) fn operands(op: &Operator<'_>) -> String {
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
        Operator::F32Const { value } => {
            let value = f32::from_bits(value.bits());
            float_text(value.to_string(), || format!("{value:e}"))
        }
        Operator::F64Const { value } => {
            let value = f64::from_bits(value.bits());
            float_text(value.to_string(), || format!("{value:e}"))
        }
        Operator::Br { relative_depth } | Operator::BrIf { relative_depth } => {
            relative_depth.to_string()
        }
        Operator::BrTable { targets } => {
            format!("[{} targets] default {}", targets.len(), targets.default())
        }
        Operator::Block { blockty }
        | Operator::Loop { blockty }
        | Operator::If { blockty }
        | Operator::Try { blockty } => block_type(blockty),
        // Clauses read as in the text format: `(catch tag label)`.
        Operator::TryTable { try_table } => {
            let mut text = block_type(&try_table.ty);
            for catch in &try_table.catches {
                if !text.is_empty() {
                    text.push(' ');
                }
                let _ = match catch {
                    wasmparser::Catch::One { tag, label } => write!(text, "(catch {tag} {label})"),
                    wasmparser::Catch::OneRef { tag, label } => {
                        write!(text, "(catch_ref {tag} {label})")
                    }
                    wasmparser::Catch::All { label } => write!(text, "(catch_all {label})"),
                    wasmparser::Catch::AllRef { label } => write!(text, "(catch_all_ref {label})"),
                };
            }
            text
        }
        Operator::Catch { tag_index } | Operator::Throw { tag_index } => tag_index.to_string(),
        Operator::Rethrow { relative_depth } | Operator::Delegate { relative_depth } => {
            relative_depth.to_string()
        }
        Operator::End
        | Operator::Else
        | Operator::Return
        | Operator::Unreachable
        | Operator::CatchAll
        | Operator::ThrowRef
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
                body.to_owned()
            }
        }
    }
}

fn block_type(blockty: &wasmparser::BlockType) -> String {
    match blockty {
        wasmparser::BlockType::Empty => String::new(),
        wasmparser::BlockType::Type(ty) => ty.to_string(),
        wasmparser::BlockType::FuncType(index) => format!("type {index}"),
    }
}

/// A float's plain decimal form, or its shortest round-trip exponent form
/// when the decimal one is long: `1e-308` prints as hundreds of zeros that
/// would hide the value on a card.
fn float_text(decimal: String, exponent: impl FnOnce() -> String) -> String {
    if decimal.len() > MAX_FLOAT_DECIMAL {
        exponent()
    } else {
        decimal
    }
}

/// Longest plain decimal a float operand keeps; `f64::MAX` takes 309 digits.
const MAX_FLOAT_DECIMAL: usize = 24;

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

/// Where a graph document goes: a string, or the chunks of a streamed answer.
pub(crate) trait Out {
    /// False once the reader has gone, which stops the writer.
    fn put(&mut self, text: &str) -> bool;
}
impl Out for String {
    fn put(&mut self, text: &str) -> bool {
        self.push_str(text);
        true
    }
}
impl Out for crate::request_har::Sink {
    fn put(&mut self, text: &str) -> bool {
        self.write(text.as_bytes())
    }
}

/// Document text bound for `out`, handed over a piece at a time, so a graph
/// of any size is never held whole.
struct Writer<'a, O: Out> {
    out: &'a mut O,
    text: String,
    open: bool,
}
const PIECE_BYTES: usize = 64 * 1024;
impl<O: Out> Writer<'_, O> {
    /// Hands over a full piece; false once the reader has gone.
    fn spill(&mut self) -> bool {
        if self.text.len() >= PIECE_BYTES {
            self.flush();
        }
        self.open
    }
    fn flush(&mut self) -> bool {
        if self.open && !self.text.is_empty() {
            self.open = self.out.put(&self.text);
        }
        self.text.clear();
        self.open
    }
}

/// Appends `text` as the inside of a JSON string.
fn escape_into(out: &mut String, text: &str) {
    if !text
        .bytes()
        .any(|byte| byte < 0x20 || byte == b'"' || byte == b'\\')
    {
        out.push_str(text);
        return;
    }
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", control as u32);
            }
            other => out.push(other),
        }
    }
}

/// Basic blocks for one defined function, or a provider error a caller shows.
pub fn function_graph(root: &Path, id: &str, function: u32) -> Result<String> {
    function_graph_to(
        root,
        id,
        function,
        None,
        &AtomicBool::new(false),
        String::new,
    )
}

/// The block graph with the function's researcher name as `analyst_name` and
/// every name of its module as `analyst_names`, so a `call N` row resolves.
/// It is written to the `Out` that `open` returns, which runs only once the
/// graph is known to succeed: an error before it is an ordinary error answer,
/// and nothing after it can fail.
pub(crate) fn function_graph_to<O: Out>(
    root: &Path,
    id: &str,
    function: u32,
    analyst: Option<&wasm_names::Names>,
    cancelled: &AtomicBool,
    open: impl FnOnce() -> O,
) -> Result<O> {
    let artifact = artifact(root, id)?;
    let mut imported = 0u32;
    let mut imported_tags = 0u32;
    let mut types = Vec::new();
    let mut position = 0u32;
    for payload in Parser::new(0).parse_all(&artifact.bytes) {
        let payload = payload.map_err(bad)?;
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    match import.map_err(bad)?.ty {
                        wasmparser::TypeRef::Func(_) => imported += 1,
                        wasmparser::TypeRef::Tag(_) => imported_tags += 1,
                        _ => {}
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
                let mut members = Vec::new();
                if let (Some(names), Some(sha)) = (analyst, artifact.sha256.as_str()) {
                    if let Some(name) = names.function(sha, function) {
                        members.push(("analyst_name", serde_json::json!(name)));
                    }
                    members.push((
                        "analyst_names",
                        names.module_member(sha, u64::from(imported) + types.len() as u64),
                    ));
                }
                let graph = Function {
                    artifact: &artifact,
                    function,
                    ty: types.get(position as usize - 1).copied(),
                    imported_tags,
                    body: &body,
                    members: &members,
                };
                return graph.write(cancelled, open);
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

/// One function body and what its document says around the graph.
struct Function<'a> {
    artifact: &'a Artifact,
    function: u32,
    ty: Option<u32>,
    imported_tags: u32,
    body: &'a wasmparser::FunctionBody<'a>,
    members: &'a [(&'static str, Value)],
}

impl Function<'_> {
    /// Structure first, then rows: a block lists its first row and row count
    /// before any row text, so the rows are counted in one pass and written
    /// in a second. Both read the body that decoded, so neither can fail.
    fn write<O: Out>(&self, cancelled: &AtomicBool, open: impl FnOnce() -> O) -> Result<O> {
        let mut decoded = decode(self.body, cancelled)?;
        decoded.imported_tags = self.imported_tags;
        let graph = build(&decoded);
        let mut omissions = std::mem::take(&mut decoded.omissions);
        omissions.extend(graph.omissions.iter().cloned());
        let blocks = graph.leaders.len();
        let mut row_counts = vec![0u32; blocks];
        let mut counted = 0u32;
        let finished = each_row(self.body, &decoded, &graph, false, |block, _, _| {
            row_counts[block] += 1;
            counted += 1;
            counted & 4095 != 0 || !cancelled.load(std::sync::atomic::Ordering::Relaxed)
        })?;
        if !finished {
            check_cancelled(cancelled, "WASM block graph")?;
        }
        let mut out = open();
        let mut w = Writer {
            out: &mut out,
            text: String::with_capacity(PIECE_BYTES + 4096),
            open: true,
        };
        let count = decoded.offsets.len();
        let range = self.body.range();
        w.text
            .push_str("{\"schema\":\"wasm-block-graph-v1\",\"artifact_id\":");
        w.text
            .push_str(&serde_json::to_string(&self.artifact.artifact_id).expect("JSON value"));
        w.text.push_str(",\"sha256\":");
        w.text
            .push_str(&serde_json::to_string(&self.artifact.sha256).expect("JSON value"));
        let _ = write!(
            w.text,
            ",\"function_index\":{},\"byte_offset\":{},\"byte_end\":{},\"type_index\":{},\"evidence\":\"declared_static\",\"complete\":false,\"status\":\"{}\",\"block_count\":{blocks},\"edge_count\":{},\"instruction_count\":{count},\"edge_kinds\":{},\"block_fields\":[\"byte_offset\",\"byte_end\",\"first_row\",\"row_count\",\"instruction_count\",\"flags\"],\"flag_bits\":{{\"entry\":1,\"reachable\":2,\"exit\":4,\"trap\":8}},\"edge_fields\":[\"from\",\"to\",\"kind\",\"label\"],\"blocks\":[",
            self.function,
            range.start,
            range.end,
            self.ty.map_or_else(|| "null".to_owned(), |t| t.to_string()),
            if omissions.is_empty() {
                "decoded"
            } else {
                "partial"
            },
            graph.edges.len(),
            serde_json::to_string(&EDGE_KINDS).expect("JSON strings"),
        );
        let mut first_row = 0u32;
        for (block, (&leader, &rows)) in graph.leaders.iter().zip(&row_counts).enumerate() {
            if block > 0 {
                w.text.push(',');
            }
            let next = graph.leaders.get(block + 1).copied();
            let start = decoded.offsets[leader as usize];
            let end = next.map_or(decoded.byte_end, |next| decoded.offsets[next as usize]);
            let instructions = next.unwrap_or(count as u32) - leader;
            let _ = write!(
                w.text,
                "[{start},{end},{first_row},{rows},{instructions},{}]",
                graph.flags[block]
            );
            first_row += rows;
            if !w.spill() {
                return Ok(out);
            }
        }
        w.text.push_str("],\"edges\":[");
        for (position, (from, to, kind, label)) in graph.edges.iter().enumerate() {
            if position > 0 {
                w.text.push(',');
            }
            let _ = write!(
                w.text,
                "[{from},{},{kind},",
                to.map_or_else(|| "null".to_owned(), |t| t.to_string())
            );
            match label {
                Some(text) => {
                    w.text.push('"');
                    escape_into(&mut w.text, text);
                    w.text.push('"');
                }
                None => w.text.push_str("null"),
            }
            w.text.push(']');
            if !w.spill() {
                return Ok(out);
            }
        }
        w.text.push_str("],\"rows\":\"");
        let written = each_row(self.body, &decoded, &graph, true, |_, offset, text| {
            let _ = write!(w.text, "{offset:x} ");
            escape_into(&mut w.text, text);
            w.text.push_str("\\n");
            w.spill()
        })?;
        if !written {
            return Ok(out);
        }
        let _ = write!(
            w.text,
            "\",\"row_count\":{first_row},\"omissions\":{},\"limits\":{{\"max_body_bytes\":{MAX_BODY_BYTES}}},\"notice\":\"Declared static control flow. Reachable here is not observed execution, and a complete drawing is not a proof.\"",
            serde_json::to_string(&omissions).expect("JSON strings"),
        );
        for (key, value) in self.members {
            w.text.push(',');
            w.text
                .push_str(&serde_json::to_string(key).expect("JSON key"));
            w.text.push(':');
            w.text
                .push_str(&serde_json::to_string(value).expect("JSON value"));
        }
        w.text.push('}');
        w.flush();
        Ok(out)
    }
}

/// Each row of each block in order, as `row(block, offset, text)`, until
/// `row` returns false. A run of identical `block` openers is structure, not
/// behavior: a dispatcher opens hundreds before its br_table, so one row
/// carries the run's first offset and count, and the card's badge stays
/// exact. Without `text` only openers are formatted, enough to count rows.
fn each_row(
    body: &wasmparser::FunctionBody<'_>,
    decoded: &Decoded,
    graph: &Graph,
    text: bool,
    mut row: impl FnMut(usize, usize, &str) -> bool,
) -> Result<bool> {
    let mut reader = body.get_operators_reader().map_err(bad)?;
    let count = decoded.offsets.len() as u32;
    let mut line = String::new();
    for block in 0..graph.leaders.len() {
        let leader = graph.leaders[block];
        let end = graph.leaders.get(block + 1).map_or(count, |next| *next);
        let mut run: Option<(usize, String, u32)> = None;
        for instruction in leader..end {
            let (op, offset) = reader.read_with_offset().map_err(bad)?;
            if let Operator::Block { .. } = op {
                let operand = operands(&op);
                match &mut run {
                    Some((_, current, count)) if *current == operand => *count += 1,
                    _ => {
                        if let Some((at, operand, count)) = run.replace((offset, operand, 1))
                            && !row(block, at, &block_run_text(&operand, count))
                        {
                            return Ok(false);
                        }
                    }
                }
                continue;
            }
            if let Some((at, operand, count)) = run.take()
                && !row(block, at, &block_run_text(&operand, count))
            {
                return Ok(false);
            }
            line.clear();
            if text {
                line.push_str(&wasm::mnemonic(&op));
                let args = operands(&op);
                if !args.is_empty() {
                    line.push(' ');
                    line.push_str(&args);
                }
                if let Some(target) = branch_target(decoded, instruction, graph) {
                    let _ = write!(line, " -> {target:x}");
                }
                if let Operator::TryTable { .. } = op {
                    handler_targets(&mut line, decoded, instruction);
                }
            }
            if !row(block, offset, &line) {
                return Ok(false);
            }
        }
        if let Some((at, operand, count)) = run.take()
            && !row(block, at, &block_run_text(&operand, count))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A try_table row names where each clause lands, in clause order, as a
/// branch row names its target: `-> 3a, 51`, or `?` for a label past the
/// open frames.
fn handler_targets(line: &mut String, decoded: &Decoded, instruction: u32) {
    let Some(scope) = scope_of(&decoded.scopes, instruction) else {
        return;
    };
    for (position, clause) in decoded.scopes[scope as usize].clauses.iter().enumerate() {
        line.push_str(if position == 0 { " -> " } else { ", " });
        match clause_target(decoded, clause) {
            Some(target) => {
                let _ = write!(line, "{:x}", decoded.offsets[target as usize]);
            }
            None => line.push('?'),
        }
    }
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

/// One body's basic blocks as successor lists, for analyses that need the
/// control flow graph itself rather than a document (value flow's control
/// dependence). The blocks are exactly the graph route's.
pub(crate) struct ControlFlow {
    /// Instruction index of each block leader; a block runs to the next.
    pub(crate) leaders: Vec<u32>,
    successor_start: Vec<u32>,
    successors: Vec<u32>,
    /// Blocks that leave the function: a return, the final `end`, a trap, a
    /// tail call, a throw or a branch whose target is unresolved.
    pub(crate) exits: Vec<bool>,
}

impl ControlFlow {
    pub(crate) fn successors(&self, block: u32) -> &[u32] {
        let start = self.successor_start[block as usize] as usize;
        let end = self.successor_start[block as usize + 1] as usize;
        &self.successors[start..end]
    }
    /// The block holding instruction `index`.
    pub(crate) fn block_of(&self, index: u32) -> u32 {
        self.leaders.partition_point(|leader| *leader <= index) as u32 - 1
    }
}

pub(crate) fn control_flow(
    body: &wasmparser::FunctionBody<'_>,
    cancelled: &AtomicBool,
) -> Result<ControlFlow> {
    let decoded = decode(body, cancelled)?;
    let graph = build(&decoded);
    let blocks = graph.leaders.len();
    let mut exits = vec![false; blocks];
    // A br_table's cases to one label are one edge already; a block can
    // still name the same successor twice (a br_if to the next block).
    let mut pairs: Vec<(u32, u32)> = Vec::with_capacity(graph.edges.len());
    for (from, to, _, _) in &graph.edges {
        match to {
            Some(to) => pairs.push((*from, *to)),
            None => exits[*from as usize] = true,
        }
    }
    pairs.sort_unstable();
    pairs.dedup();
    for (block, flags) in graph.flags.iter().enumerate() {
        if flags & (EXIT | TRAP) != 0 {
            exits[block] = true;
        }
    }
    let mut successor_start = vec![0u32; blocks + 1];
    for (from, _) in &pairs {
        successor_start[*from as usize + 1] += 1;
    }
    for block in 0..blocks {
        successor_start[block + 1] += successor_start[block];
    }
    let successors: Vec<u32> = pairs.into_iter().map(|(_, to)| to).collect();
    Ok(ControlFlow {
        leaders: graph.leaders,
        successor_start,
        successors,
        exits,
    })
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
        assert!(document["instruction_count"].as_u64().unwrap() > 900);
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
    fn case_labels_compress_and_name_every_case() {
        assert_eq!(case_label(&[0, 1, 2, 5, 9, 10]), "0-2,5,9-10");
        let many: Vec<u32> = (0..2000).step_by(2).collect();
        let label = case_label(&many);
        assert_eq!(label.split(',').count(), 1000, "{label}");
        assert!(label.ends_with(",1996,1998"), "{label}");
    }

    #[test]
    fn long_float_constants_read_as_their_shortest_exponent_form() {
        let graph = graph_for(
            "(module (func (result f64) (f64.add (f64.const -2.2250738585072014e-308) (f64.const 1.5))) (func (result f32) (f32.const 3.4028235e38)))",
            0,
        );
        let rows = graph["rows"].as_str().unwrap();
        assert!(
            rows.contains("f64.const -2.2250738585072014e-308\n"),
            "{rows}"
        );
        assert!(rows.contains("f64.const 1.5\n"), "{rows}");
        let rows = graph_for(
            "(module (func (result f64) (f64.const 0)) (func (result f32) (f32.const 3.4028235e38)))",
            1,
        )["rows"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(rows.contains("f32.const 3.4028235e38\n"), "{rows}");
    }

    /// Edges out of the block whose rows hold `needle`.
    fn edges_from(document: &Value, needle: &str) -> Vec<(Option<i64>, String, Option<String>)> {
        let rows: Vec<&str> = document["rows"].as_str().unwrap().lines().collect();
        let block = document["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .position(|block| {
                let first = block[2].as_u64().unwrap() as usize;
                let count = block[3].as_u64().unwrap() as usize;
                rows[first..first + count]
                    .iter()
                    .any(|row| row.contains(needle))
            })
            .unwrap_or_else(|| panic!("no block holds {needle}: {rows:?}"));
        kinds(document)
            .into_iter()
            .filter(|edge| edge.0 == block as i64)
            .map(|edge| (edge.1, edge.2, edge.3))
            .collect()
    }
    /// The first block whose rows hold `needle`.
    fn block_at(document: &Value, needle: &str) -> i64 {
        let rows: Vec<&str> = document["rows"].as_str().unwrap().lines().collect();
        document["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .position(|block| {
                let first = block[2].as_u64().unwrap() as usize;
                let count = block[3].as_u64().unwrap() as usize;
                rows[first..first + count]
                    .iter()
                    .any(|row| row.contains(needle))
            })
            .unwrap_or_else(|| panic!("no block holds {needle}: {rows:?}")) as i64
    }

    #[test]
    fn a_throw_reaches_its_try_table_handler_and_a_call_inside_may() {
        let document = graph_for(
            r#"(module (import "env" "g" (func $g)) (tag $e (param i32)) (tag $f)
              (func (result i32)
                (block $h (result i32)
                  (try_table (catch $e $h)
                    call $g
                    i32.const 7
                    throw $e)
                  unreachable)
                i32.const 1
                i32.add)
              (func
                (block $h
                  (try_table (catch $e $h) (throw $f))
                  unreachable)))"#,
            1,
        );
        let rows = document["rows"].as_str().unwrap();
        assert!(rows.contains(" try_table (catch 0 0) -> "), "{rows}");
        assert!(rows.contains(" throw 0\n"), "{rows}");
        assert!(
            !rows.contains("TryTable") && !rows.contains("tag_index"),
            "{rows}"
        );
        let handler = block_at(&document, "i32.const 1");
        // The throw is certainly caught, so nothing leaves the function, and
        // the call's possible exception is the same edge.
        assert_eq!(
            edges_from(&document, "throw 0"),
            vec![(
                Some(handler),
                "exception".to_owned(),
                Some("catch 0".to_owned())
            )]
        );
        let flags = document["blocks"][handler as usize][5].as_u64().unwrap();
        assert_eq!(flags & REACHABLE as u64, REACHABLE as u64);
        // A defined tag never matches another one: the throw leaves.
        let other = graph_for(
            r#"(module (tag $e (param i32)) (tag $f)
              (func (block $h (result i32) (try_table (catch $e $h) (throw $f)) unreachable) drop))"#,
            0,
        );
        assert_eq!(
            edges_from(&other, "throw 1"),
            vec![(None, "unresolved".to_owned(), Some("throw".to_owned()))]
        );
    }

    #[test]
    fn legacy_try_resolves_throws_rethrows_and_calls() {
        let document = graph_for(
            r#"(module (import "env" "g" (func $g)) (tag $e (param i32))
              (func (param i32)
                try
                  local.get 0
                  if
                    i32.const 1
                    throw $e
                  end
                  call $g
                catch $e
                  drop
                  rethrow 0
                end))"#,
            1,
        );
        let rows = document["rows"].as_str().unwrap();
        assert!(
            rows.contains(" catch 0\n") && rows.contains(" rethrow 0\n"),
            "{rows}"
        );
        let handler = block_at(&document, "drop");
        assert_eq!(
            edges_from(&document, "throw 0"),
            vec![(
                Some(handler),
                "exception".to_owned(),
                Some("catch 0".to_owned())
            )]
        );
        // A call may throw any tag: it may reach the handler, and leaving the
        // function is what any call can do, so it adds no stub.
        let call = edges_from(&document, "call 0");
        assert!(
            call.contains(&(
                Some(handler),
                "exception".to_owned(),
                Some("call: catch 0".to_owned())
            )),
            "{call:?}"
        );
        assert!(call.iter().all(|edge| edge.1 != "unresolved"), "{call:?}");
        // A rethrow in a catch body starts outside its own try.
        assert_eq!(
            edges_from(&document, "rethrow 0"),
            vec![(None, "unresolved".to_owned(), Some("rethrow".to_owned()))]
        );
    }

    #[test]
    fn an_exception_moves_outward_until_a_catch_all_and_may_escape_without_one() {
        let document = graph_for(
            r#"(module (tag $e) (tag $f)
              (func (param exnref)
                try
                  try
                    local.get 0
                    throw_ref
                  catch $e
                  end
                catch_all
                end)
              (func (param exnref)
                try
                  local.get 0
                  throw_ref
                catch $f
                end))"#,
            0,
        );
        // The inner catch may take it; the outer catch_all certainly does.
        let edges = edges_from(&document, "throw_ref");
        assert_eq!(edges.len(), 2, "{edges:?}");
        assert_ne!(edges[0].0, edges[1].0, "{edges:?}");
        assert!(
            edges
                .iter()
                .any(|edge| edge.2.as_deref() == Some("catch 0")),
            "{edges:?}"
        );
        assert!(
            edges
                .iter()
                .any(|edge| edge.2.as_deref() == Some("catch_all")),
            "{edges:?}"
        );
        assert!(edges.iter().all(|edge| edge.1 == "exception"), "{edges:?}");
        // With no catch_all an exception of an unknown tag may also leave.
        let single = graph_for(
            r#"(module (tag $f) (func (param exnref) try local.get 0 throw_ref catch $f end))"#,
            0,
        );
        let edges = edges_from(&single, "throw_ref");
        assert!(
            edges
                .iter()
                .any(|edge| edge.1 == "exception" && edge.2.as_deref() == Some("catch 0")),
            "{edges:?}"
        );
        assert!(
            edges.contains(&(
                None,
                "unresolved".to_owned(),
                Some("throw_ref: may escape".to_owned())
            )),
            "{edges:?}"
        );
    }

    #[test]
    fn a_delegate_hands_exceptions_to_the_scope_it_names() {
        let document = graph_for(
            r#"(module (import "env" "g" (func $g)) (tag $e)
              (func
                try
                  try
                    call $g
                  delegate 0
                catch_all
                  nop
                end)
              (func
                try
                  throw $e
                delegate 0))"#,
            1,
        );
        let rows = document["rows"].as_str().unwrap();
        assert!(rows.contains(" delegate 0\n"), "{rows}");
        let handler = block_at(&document, "nop");
        // The try body's normal end goes past the catch_all to the end.
        assert_eq!(
            edges_from(&document, "call 0"),
            vec![
                (
                    Some(handler + 1),
                    "branch".to_owned(),
                    Some("end".to_owned())
                ),
                (
                    Some(handler),
                    "exception".to_owned(),
                    Some("call: catch_all".to_owned())
                )
            ]
        );
        // Delegating to the function's label hands the exception to the caller.
        let out = graph_for(r#"(module (tag $e) (func try throw $e delegate 0))"#, 0);
        assert_eq!(
            edges_from(&out, "throw 0"),
            vec![(None, "unresolved".to_owned(), Some("throw".to_owned()))]
        );
    }

    #[test]
    fn imported_tags_may_be_one_tag() {
        let document = graph_for(
            r#"(module (import "env" "a" (tag $a)) (import "env" "b" (tag $b))
              (func (block $h (try_table (catch $a $h) (throw $b)))))"#,
            0,
        );
        let edges = edges_from(&document, "throw 1");
        assert!(
            edges
                .iter()
                .any(|edge| edge.1 == "exception" && edge.2.as_deref() == Some("catch 0")),
            "{edges:?}"
        );
        assert!(
            edges.contains(&(
                None,
                "unresolved".to_owned(),
                Some("throw: may escape".to_owned())
            )),
            "{edges:?}"
        );
    }

    fn fixtures() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/fixtures/wasm-block-graph")
    }

    /// Each block's exception and unresolved edges, by an instruction one of
    /// its rows ends with (`throw 1`, never the end of `rethrow 1`).
    fn raised_from(document: &Value, instruction: &str) -> Vec<Vec<(Option<i64>, String, String)>> {
        let rows: Vec<&str> = document["rows"].as_str().unwrap().lines().collect();
        let needle = format!(" {instruction}");
        let edges = kinds(document);
        document["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, block)| {
                let first = block[2].as_u64().unwrap() as usize;
                let count = block[3].as_u64().unwrap() as usize;
                rows[first..first + count]
                    .iter()
                    .any(|row| row.ends_with(&needle))
            })
            .map(|(index, _)| {
                edges
                    .iter()
                    .filter(|edge| {
                        edge.0 == index as i64 && (edge.2 == "exception" || edge.2 == "unresolved")
                    })
                    .map(|edge| (edge.1, edge.2.clone(), edge.3.clone().unwrap_or_default()))
                    .collect()
            })
            .collect()
    }

    /// The checked-in module is exactly what the pinned assembler makes from
    /// its source, and its graph draws the edges README.md lists. Run
    /// `make wasm-block-graph-fixtures` after editing the `.wat`.
    #[test]
    fn the_exception_fixture_matches_its_source_and_draws_its_edges() {
        let built = wat::parse_file(fixtures().join("exceptions.wat")).unwrap();
        let bytes = std::fs::read(fixtures().join("exceptions.wasm")).unwrap();
        assert!(
            built == bytes,
            "exceptions.wasm drifted from its source; run make wasm-block-graph-fixtures"
        );
        let (document, _) = graph_of(&bytes, 1).unwrap();
        assert_eq!(document["status"], "decoded");
        let labels = |edges: &Vec<(Option<i64>, String, String)>| {
            let mut labels: Vec<String> = edges
                .iter()
                .map(|edge| format!("{}{}", if edge.0.is_some() { "" } else { "! " }, edge.2))
                .collect();
            labels.sort();
            labels
        };
        let calls = raised_from(&document, "call 0");
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(
            labels(&calls[0]),
            ["call: catch 2", "call: catch_all"],
            "a call reaches every clause"
        );
        assert_eq!(
            labels(&calls[1]),
            ["call: catch_all"],
            "a delegated call reaches the try around it"
        );
        assert_eq!(
            labels(&raised_from(&document, "throw 2")[0]),
            ["catch 2"],
            "a defined tag reaches only its clause"
        );
        assert_eq!(
            labels(&raised_from(&document, "throw 0")[0]),
            ["catch 1", "catch_all"],
            "an imported tag may be another"
        );
        assert_eq!(
            labels(&raised_from(&document, "rethrow 1")[0]),
            ["! rethrow"],
            "a catch body is not covered"
        );
        assert_eq!(
            labels(&raised_from(&document, "throw 1")[0]),
            ["! throw: may escape", "catch 0"]
        );
        let halts = raised_from(&document, "throw 3");
        assert_eq!(
            labels(&halts[0]),
            ["! throw"],
            "no handler: it leaves the function"
        );
        assert_eq!(labels(&halts[1]), ["catch_all_ref"]);
        assert_eq!(
            labels(&raised_from(&document, "throw_ref")[0]),
            ["! throw_ref"]
        );
        // Every handler edge lands on a block, never past the decoded range.
        assert!(
            kinds(&document)
                .iter()
                .all(|edge| edge.2 != "exception" || edge.1.is_some())
        );
    }

    #[test]
    #[ignore = "writes the checked-in fixture; run make wasm-block-graph-fixtures"]
    fn write_block_graph_fixtures() {
        let built = wat::parse_file(fixtures().join("exceptions.wat")).unwrap();
        std::fs::write(fixtures().join("exceptions.wasm"), built).unwrap();
    }

    #[test]
    fn a_large_body_keeps_every_row_and_streams_the_same_document() {
        // 300,000 rows of text, past the 16 MiB row budget this replaces once
        // operands are long: every row and every block stays in the graph.
        let body =
            "(drop (i64.const -9223372036854775808)) (br_if 0 (i32.const 0)) ".repeat(60_000);
        let bytes = wat::parse_str(format!("(module (func {body}))")).unwrap();
        let (document, length) = graph_of(&bytes, 0).unwrap();
        assert_eq!(document["status"], "decoded");
        assert_eq!(document["omissions"], json!([]));
        assert_eq!(
            document["limits"],
            json!({"max_body_bytes": MAX_BODY_BYTES})
        );
        assert!(document["flag_bits"].get("rows_cut").is_none());
        let rows = document["rows"].as_str().unwrap();
        assert_eq!(
            rows.lines().count() as u64,
            document["row_count"].as_u64().unwrap()
        );
        assert_eq!(
            document["row_count"].as_u64().unwrap(),
            document["instruction_count"].as_u64().unwrap()
        );
        assert_eq!(document["block_count"].as_u64().unwrap(), 60_001);
        assert!(length > PIECE_BYTES * 4, "{length}");
        // The same writer into many small pieces yields the same bytes.
        struct Pieces(Vec<String>);
        impl Out for Pieces {
            fn put(&mut self, text: &str) -> bool {
                self.0.push(text.to_owned());
                true
            }
        }
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
        let pieces = function_graph_to(
            directory.path(),
            "7",
            0,
            None,
            &AtomicBool::new(false),
            || Pieces(Vec::new()),
        )
        .unwrap();
        assert!(pieces.0.len() > 4);
        let joined: String = pieces.0.concat();
        assert_eq!(serde_json::from_str::<Value>(&joined).unwrap(), document);
        // A reader that goes away stops the writer at its next piece.
        struct Gone(usize);
        impl Out for Gone {
            fn put(&mut self, _: &str) -> bool {
                self.0 += 1;
                false
            }
        }
        let gone = function_graph_to(
            directory.path(),
            "7",
            0,
            None,
            &AtomicBool::new(false),
            || Gone(0),
        )
        .unwrap();
        assert_eq!(gone.0, 1);
        // Cancelled before the answer starts, the graph is an error answer.
        let error = function_graph_to(
            directory.path(),
            "7",
            0,
            None,
            &AtomicBool::new(true),
            String::new,
        )
        .unwrap_err();
        assert_eq!(error.status, 499, "{}", error.message);
    }
}
