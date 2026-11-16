//! Operand-stack and local def-use simulation for one WebAssembly function.
//!
//! Interface. [`Module::read`] collects what a body needs from its module:
//! types, function declarations, tags, function imports, exports, element
//! references and every code body. [`simulate`] walks one body once, in
//! instruction order, with an abstract operand stack and abstract locals, and
//! returns a [`Simulation`]:
//!
//! - one [`Node`] for every instruction that produces or consumes a value, at
//!   that instruction's original byte offset;
//! - synthetic nodes for parameters, the zero value of declared locals,
//!   exception values a handler receives, a value popped from an empty
//!   unreachable stack, and phi-like joins where control paths merge;
//! - [`Edge`]s from each produced value to each operand that consumes it, with
//!   the operand position and an [`EdgeKind`]; a join's incoming edges also
//!   name the branch that carried the value ([`Via`]) and its offset.
//!
//! Joins are built from structured control flow only. A block, `if` or `try`
//! join is placed at its `end` (or handler), and a loop join at its `loop`
//! instruction for every local the loop writes and every loop parameter. A
//! join is created only where incoming values differ, so a value that reaches
//! a merge unchanged keeps its producer.
//!
//! Memory is conservative: a load is a value source. The only exception is a
//! full-width load whose address is the same constant expression as the
//! immediately preceding store in the same basic block, with no store, call or
//! memory operation between them; that store's value is linked to the load as
//! a `forwarded_store` edge.
//!
//! This is a structural simulation of the bytes, not validation and not
//! execution. A malformed stack shape becomes an `unknown` value and a named
//! omission, never a panic. Operators whose stack effect this module does not
//! model (stack switching) stop the simulation with a named omission, and the
//! prefix before them stays valid. Work is bounded by an instruction cap, a
//! work counter and the caller's deadline.
//!
//! Each operator's stack effect and the open control frames come from
//! [`crate::wasm_stack`], the layer the readable lifted view also folds with;
//! this module keeps only its payload: values, nodes, edges and the paths that
//! merge at each frame.
use crate::error::{Error, Result};
use crate::wasm_stack::{self, Callee, Clause, Control, Effect, Kind, ModuleTypes, Test};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use wasmparser::{
    BlockType, ElementItems, ExternalKind, FunctionBody, Operator, Parser, Payload, TypeRef,
};

pub const NONE: u32 = u32::MAX;
/// Engines reject a function with more locals than this, so a body declaring
/// more cannot have run.
pub const MAX_LOCALS: u64 = 50_000;
/// Instructions simulated per body. A body at the engine size limit holds a
/// few million instructions; past this the prefix is returned as partial.
pub const MAX_INSTRUCTIONS: usize = 2_000_000;
/// Instructions plus loop-write, snapshot and join entries. Loop joins grow
/// with nesting depth times the locals written, so this is what bounds time
/// and memory on deeply nested bodies; it is checked inside every such loop.
pub const MAX_WORK: u64 = 4_000_000;

/// The simulation's budgets. Tests lower them to reach each stop.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_instructions: usize,
    pub max_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_instructions: MAX_INSTRUCTIONS,
            max_work: MAX_WORK,
        }
    }
}
const MAX_IMPORT_NAME_BYTES: usize = 128;

pub(crate) fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

/// What a node is. The names are the contract's `kind` vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeKind {
    Param,
    LocalInit,
    Phi,
    ExceptionValue,
    Unknown,
    Const,
    LocalGet,
    LocalSet,
    LocalTee,
    GlobalGet,
    GlobalSet,
    Load,
    Store,
    Atomic,
    Memory,
    Table,
    Call,
    ImportCall,
    CallIndirect,
    CallRef,
    Select,
    Operation,
    Branch,
    Return,
    Throw,
    Drop,
}

impl NodeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Param => "param",
            Self::LocalInit => "local_init",
            Self::Phi => "phi",
            Self::ExceptionValue => "exception_value",
            Self::Unknown => "unknown",
            Self::Const => "const",
            Self::LocalGet => "local_get",
            Self::LocalSet => "local_set",
            Self::LocalTee => "local_tee",
            Self::GlobalGet => "global_get",
            Self::GlobalSet => "global_set",
            Self::Load => "load",
            Self::Store => "store",
            Self::Atomic => "atomic",
            Self::Memory => "memory",
            Self::Table => "table",
            Self::Call => "call",
            Self::ImportCall => "import_call",
            Self::CallIndirect => "call_indirect",
            Self::CallRef => "call_ref",
            Self::Select => "select",
            Self::Operation => "operation",
            Self::Branch => "branch",
            Self::Return => "return",
            Self::Throw => "throw",
            Self::Drop => "drop",
        }
    }
}

/// How a value reaches its consumer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeKind {
    Operand,
    /// A local's current definition read by `local.get`.
    Local,
    LocalSet,
    GlobalSet,
    Address,
    StoredValue,
    ForwardedStore,
    Argument,
    CalleeIndex,
    CalleeRef,
    /// The condition of `if`, `br_if`, `select` or the index of `br_table`.
    Selector,
    Return,
    Drop,
    /// An incoming edge of a join.
    Merge,
}

impl EdgeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Operand => "operand",
            Self::Local => "local",
            Self::LocalSet => "local_set",
            Self::GlobalSet => "global_set",
            Self::Address => "address",
            Self::StoredValue => "stored_value",
            Self::ForwardedStore => "forwarded_store",
            Self::Argument => "argument",
            Self::CalleeIndex => "callee_index",
            Self::CalleeRef => "callee_ref",
            Self::Selector => "selector",
            Self::Return => "return",
            Self::Drop => "drop",
            Self::Merge => "merge",
        }
    }
}

/// The control transfer that carried a value into a join.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Via {
    None,
    /// The value a loop header or handler had on entry.
    Entry,
    Fallthrough,
    Br,
    BrIf,
    BrTable,
    BrOn,
    /// The end of an `if` arm, merged at `end`.
    ThenEnd,
    /// The implicit false path of an `if` without `else`.
    IfFalse,
    /// A definition inside a `try` body that a handler may observe.
    Catch,
    /// The store a `forwarded_store` edge came from.
    Store,
}

impl Via {
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::None => return None,
            Self::Entry => "entry",
            Self::Fallthrough => "fallthrough",
            Self::Br => "br",
            Self::BrIf => "br_if",
            Self::BrTable => "br_table",
            Self::BrOn => "br_on",
            Self::ThenEnd => "then_end",
            Self::IfFalse => "if_false",
            Self::Catch => "catch",
            Self::Store => "store",
        })
    }
}

/// The construct a join belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Join {
    None,
    Block,
    Loop,
    If,
    Try,
}

impl Join {
    pub fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::None => return None,
            Self::Block => "block",
            Self::Loop => "loop",
            Self::If => "if",
            Self::Try => "try",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Value {
    pub node: u32,
    pub result: u32,
}

impl Value {
    fn of(node: u32) -> Self {
        Self { node, result: 0 }
    }
    /// The not-yet-materialized initial value of local `local`.
    fn initial(local: u32) -> Self {
        Self {
            node: NONE,
            result: local,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub kind: NodeKind,
    /// Original module byte offset of the instruction, or of the declaration
    /// for parameters and declared locals.
    pub offset: u32,
    /// Instruction position in the body, `NONE` for synthetic nodes.
    pub instruction: u32,
    /// The local, global, function, type or tag index the node names.
    pub index: u32,
    pub results: u32,
    /// Constant bits, the table of `call_indirect`, or a join's result slot.
    pub aux: u64,
    pub join: Join,
}

#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub from: u32,
    pub result: u32,
    pub to: u32,
    pub operand: u32,
    pub kind: EdgeKind,
    pub via: Via,
    pub via_offset: u32,
}

pub struct Simulation {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Byte offset of each simulated instruction, in order.
    pub instructions: Vec<u32>,
    /// The node an instruction created, `NONE` when it created none.
    pub instruction_nodes: Vec<u32>,
    /// Whether declared control flow reaches each instruction. Unreachable
    /// instructions create no node, so dead code never feeds a slice.
    pub instruction_live: Vec<bool>,
    input_start: Vec<u32>,
    inputs: Vec<Value>,
    pub type_index: u32,
    pub params: u32,
    pub locals: u32,
    pub results: u32,
    /// Byte offset where simulation stopped early, with the omissions naming why.
    pub stopped_at: Option<u32>,
    /// Work units spent, including the loop-write prescan.
    pub work: u64,
    /// Values and locals stored on incoming paths for later merges: the
    /// memory a branch fan-out holds beyond nodes and edges.
    pub stored: u64,
    pub omissions: Vec<String>,
    /// Header joins of loops still open where the simulation stopped: their
    /// back edges after the stop were never read, so they are incomplete.
    pub open_joins: HashSet<u32>,
}

impl Simulation {
    pub fn instruction_at(&self, offset: u32) -> Option<u32> {
        self.instructions
            .binary_search(&offset)
            .ok()
            .map(|index| index as u32)
    }
    /// The values an instruction consumed, in operand (text) order.
    pub fn inputs(&self, instruction: u32) -> &[Value] {
        let start = self.input_start[instruction as usize] as usize;
        let end = self
            .input_start
            .get(instruction as usize + 1)
            .map_or(self.inputs.len(), |end| *end as usize);
        &self.inputs[start..end]
    }
}

/// The module context one body is simulated against.
pub struct Module<'a> {
    /// Types, function declarations and tags, which stack effects read.
    pub types: ModuleTypes,
    pub imported_functions: u32,
    /// Module and field names of imported functions, bounded inert text.
    pub imports: Vec<(String, String)>,
    pub bodies: Vec<FunctionBody<'a>>,
    pub exported: HashSet<u32>,
    pub element_functions: HashSet<u32>,
    pub start: Option<u32>,
}

fn bounded(name: &str) -> String {
    let mut text = String::new();
    for character in name.chars().flat_map(char::escape_debug) {
        if text.len() + character.len_utf8() > MAX_IMPORT_NAME_BYTES {
            text.push_str("...");
            break;
        }
        text.push(character);
    }
    text
}

impl<'a> Module<'a> {
    pub fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut module = Module {
            types: ModuleTypes::default(),
            imported_functions: 0,
            imports: Vec::new(),
            bodies: Vec::new(),
            exported: HashSet::new(),
            element_functions: HashSet::new(),
            start: None,
        };
        let mut ended = false;
        for payload in Parser::new(0).parse_all(bytes) {
            match payload.map_err(bad)? {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        module.types.add_rec_group(group.map_err(bad)?);
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        let import = import.map_err(bad)?;
                        match import.ty {
                            TypeRef::Func(ty) => {
                                module.types.add_imported_function(ty);
                                module.imported_functions += 1;
                                module
                                    .imports
                                    .push((bounded(import.module), bounded(import.name)));
                            }
                            TypeRef::Tag(tag) => module.types.add_tag(tag.func_type_idx),
                            _ => {}
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        module.types.add_function(ty.map_err(bad)?);
                    }
                }
                Payload::TagSection(reader) => {
                    for tag in reader {
                        module.types.add_tag(tag.map_err(bad)?.func_type_idx);
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(bad)?;
                        if export.kind == ExternalKind::Func {
                            module.exported.insert(export.index);
                        }
                    }
                }
                Payload::StartSection { func, .. } => module.start = Some(func),
                Payload::ElementSection(reader) => {
                    for element in reader {
                        match element.map_err(bad)?.items {
                            ElementItems::Functions(functions) => {
                                for function in functions {
                                    module.element_functions.insert(function.map_err(bad)?);
                                }
                            }
                            ElementItems::Expressions(_, expressions) => {
                                for expression in expressions {
                                    for op in expression.map_err(bad)?.get_operators_reader() {
                                        if let Operator::RefFunc { function_index } =
                                            op.map_err(bad)?
                                        {
                                            module.element_functions.insert(function_index);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Payload::CodeSectionEntry(body) => module.bodies.push(body),
                Payload::End(_) => ended = true,
                _ => {}
            }
        }
        if !ended {
            return Err(Error::protocol("WASM module ended before its last section"));
        }
        if module.bodies.len() as u64 + module.imported_functions as u64
            != module.types.function_count()
        {
            return Err(Error::protocol(
                "WASM function and code section counts differ",
            ));
        }
        Ok(module)
    }
}

struct Incoming {
    via: Via,
    via_offset: u32,
    values: Vec<Value>,
    /// Locals written since the frame was entered, sorted by local index.
    /// A local not listed still had its entry value.
    locals: Vec<(u32, Value)>,
}

struct TryCatch {
    /// Absolute index of the frame the clause branches to.
    target: usize,
    tag: u32,
    values: u32,
}

/// What the simulation keeps per open frame, beside the shared frame facts.
#[derive(Default)]
struct Flow {
    offset: u32,
    instruction: u32,
    param_values: Vec<Value>,
    /// Entry value of every local written since this frame was entered.
    saved: HashMap<u32, Value>,
    incoming: Vec<Incoming>,
    then_end: Option<Incoming>,
    loop_param_phis: Vec<u32>,
    loop_local_phis: Vec<(u32, u32)>,
    reachable_at_entry: bool,
    /// Reachable local definitions inside an open `try` or `try_table` body.
    try_writes: Vec<(u32, Value, u32)>,
    catch_phis: Option<Vec<(u32, u32)>>,
    catches: Vec<TryCatch>,
}

/// The construct a frame's joins belong to.
fn join_of(kind: Kind) -> Join {
    match kind {
        Kind::Loop => Join::Loop,
        Kind::If | Kind::Else => Join::If,
        Kind::Try | Kind::Catch | Kind::TryTable => Join::Try,
        Kind::Function | Kind::Block => Join::Block,
    }
}

/// A full-width store to a constant address, kept until the next store, call,
/// memory operation or block boundary.
#[derive(Clone, Copy)]
struct StoreFact {
    class: u8,
    memory: u32,
    address: u64,
    memarg: u64,
    value: Value,
    at: u32,
}

enum Stop {
    Unsupported(String),
}

struct Sim<'m, 'a> {
    module: &'m Module<'a>,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    instructions: Vec<u32>,
    instruction_nodes: Vec<u32>,
    instruction_live: Vec<bool>,
    input_start: Vec<u32>,
    inputs: Vec<Value>,
    stack: Vec<Value>,
    locals: Vec<Value>,
    init_nodes: Vec<u32>,
    local_offsets: Vec<(u32, u32)>,
    params: u32,
    body_offset: u32,
    control: Control<Flow>,
    open_tries: Vec<usize>,
    reachable: bool,
    unknown: u32,
    loop_writes: HashMap<u32, Vec<u32>>,
    /// The latest full-width store to a constant address in this block.
    store: Option<StoreFact>,
    work: u64,
    limits: Limits,
    stored: u64,
    deadline: Instant,
    /// Set once a budget runs out inside an instruction; the main loop stops
    /// at that instruction.
    exhausted: Option<&'static str>,
    omissions: Vec<String>,
    underflow_noted: bool,
}

/// Width class of a full-width load or store, its memory and its offset.
fn full_width(op: &Operator<'_>) -> Option<(bool, u8, u32, u64)> {
    let (store, class, memarg) = match op {
        Operator::I32Load { memarg } => (false, 0, memarg),
        Operator::I64Load { memarg } => (false, 1, memarg),
        Operator::F32Load { memarg } => (false, 2, memarg),
        Operator::F64Load { memarg } => (false, 3, memarg),
        Operator::V128Load { memarg } => (false, 4, memarg),
        Operator::I32Store { memarg } => (true, 0, memarg),
        Operator::I64Store { memarg } => (true, 1, memarg),
        Operator::F32Store { memarg } => (true, 2, memarg),
        Operator::F64Store { memarg } => (true, 3, memarg),
        Operator::V128Store { memarg } => (true, 4, memarg),
        _ => return None,
    };
    Some((store, class, memarg.memory, memarg.offset))
}

fn classify(op: &Operator<'_>) -> NodeKind {
    match op {
        Operator::I32Const { .. }
        | Operator::I64Const { .. }
        | Operator::F32Const { .. }
        | Operator::F64Const { .. }
        | Operator::V128Const { .. }
        | Operator::RefNull { .. }
        | Operator::RefFunc { .. } => return NodeKind::Const,
        _ => {}
    }
    let mnemonic = crate::wasm::mnemonic(op);
    if mnemonic.contains(".atomic") {
        if mnemonic.contains(".load") && !mnemonic.contains("rmw") {
            NodeKind::Load
        } else if mnemonic.contains(".store") && !mnemonic.contains("rmw") {
            NodeKind::Store
        } else {
            NodeKind::Atomic
        }
    } else if mnemonic.contains(".load") {
        NodeKind::Load
    } else if mnemonic.contains(".store") {
        NodeKind::Store
    } else if mnemonic.starts_with("memory.") || mnemonic == "data_drop" {
        NodeKind::Memory
    } else if mnemonic.starts_with("table.") || mnemonic == "elem_drop" {
        NodeKind::Table
    } else {
        NodeKind::Operation
    }
}

fn const_bits(op: &Operator<'_>) -> u64 {
    match op {
        Operator::I32Const { value } => *value as i64 as u64,
        Operator::I64Const { value } => *value as u64,
        Operator::F32Const { value } => value.bits() as u64,
        Operator::F64Const { value } => value.bits(),
        _ => 0,
    }
}

/// Simulates one body. `function` is its index in the module's function index
/// space, `deadline` is shared with the caller.
pub fn simulate(
    module: &Module<'_>,
    function: u32,
    body: &FunctionBody<'_>,
    deadline: Instant,
) -> Result<Simulation> {
    simulate_with(module, function, body, deadline, Limits::default())
}

/// [`simulate`] with explicit budgets.
pub fn simulate_with(
    module: &Module<'_>,
    function: u32,
    body: &FunctionBody<'_>,
    deadline: Instant,
    limits: Limits,
) -> Result<Simulation> {
    let type_index = module
        .types
        .function_type_index(function)
        .ok_or_else(|| Error::new(404, "WASM function is not declared"))?;
    let (params, results) = module.types.type_arity(type_index).ok_or_else(|| {
        Error::protocol(format!(
            "WASM function {function} declares type {type_index}, which is not a function type"
        ))
    })?;
    let mut locals_reader = body.get_locals_reader().map_err(bad)?;
    let mut total = params as u64;
    let mut local_offsets = Vec::new();
    for _ in 0..locals_reader.get_count() {
        let offset = locals_reader.original_position() as u32;
        let (count, _) = locals_reader.read().map_err(bad)?;
        local_offsets.push((total as u32, offset));
        total += count as u64;
        if total > MAX_LOCALS {
            return Err(Error::bad(format!(
                "WASM function {function} declares more than the {MAX_LOCALS} locals engines accept"
            )));
        }
    }
    let local_count = total as u32;
    let body_offset = body.range().start as u32;
    let mut sim = Sim {
        module,
        nodes: Vec::new(),
        edges: Vec::new(),
        instructions: Vec::new(),
        instruction_nodes: Vec::new(),
        instruction_live: Vec::new(),
        input_start: Vec::new(),
        inputs: Vec::new(),
        stack: Vec::new(),
        locals: (0..local_count).map(Value::initial).collect(),
        init_nodes: vec![NONE; local_count as usize],
        local_offsets,
        params,
        body_offset,
        control: Control::new(
            results,
            Flow {
                offset: body_offset,
                instruction: NONE,
                reachable_at_entry: true,
                ..Flow::default()
            },
        ),
        open_tries: Vec::new(),
        reachable: true,
        unknown: NONE,
        loop_writes: HashMap::new(),
        store: None,
        work: 0,
        limits,
        stored: 0,
        deadline,
        exhausted: None,
        omissions: Vec::new(),
        underflow_noted: false,
    };
    let mut stopped_at = sim.prescan(body, deadline)?;
    if stopped_at.is_none() {
        let mut reader = body.get_operators_reader().map_err(bad)?;
        let mut ended = false;
        while !reader.eof() {
            let position = reader.original_position() as u32;
            if sim.instructions.len() >= sim.limits.max_instructions
                || sim.work > sim.limits.max_work
            {
                let what = if sim.instructions.len() >= sim.limits.max_instructions {
                    format!(
                        "Simulation instruction cap of {}",
                        sim.limits.max_instructions
                    )
                } else {
                    "Simulation work budget".to_owned()
                };
                sim.omissions.push(format!(
                    "{what} reached at byte {position}; value flow after it is not computed."
                ));
                stopped_at = Some(position);
                break;
            }
            if sim.instructions.len() & 1023 == 0 && Instant::now() > deadline {
                sim.omissions.push(format!(
                    "Simulation deadline reached at byte {position}; value flow after it is not computed."
                ));
                stopped_at = Some(position);
                break;
            }
            let (op, offset) = reader.read_with_offset().map_err(bad)?;
            if ended {
                return Err(Error::protocol(
                    "WASM function has instructions after its end",
                ));
            }
            let index = sim.instructions.len() as u32;
            sim.instructions.push(offset as u32);
            sim.instruction_nodes.push(NONE);
            sim.instruction_live.push(sim.reachable);
            sim.input_start.push(sim.inputs.len() as u32);
            sim.work += 1;
            let step = sim.step(&op, offset as u32, index);
            if sim.reachable {
                sim.instruction_live[index as usize] = true;
            }
            if let Some(reason) = sim.exhausted.take() {
                sim.omissions.push(format!(
                    "{reason} at byte {offset}; value flow from this instruction on is not computed."
                ));
                stopped_at = Some(offset as u32);
                break;
            }
            match step {
                Ok(done) => ended = done,
                Err(Stop::Unsupported(what)) => {
                    sim.omissions.push(format!(
                        "{what} at byte {offset} is not modeled; value flow after it is not computed."
                    ));
                    stopped_at = Some(offset as u32);
                    break;
                }
            }
        }
        if stopped_at.is_none() {
            reader.finish().map_err(bad)?;
            if !ended {
                return Err(Error::protocol(
                    "WASM function control structure is unterminated",
                ));
            }
        }
    }
    let mut open_joins = HashSet::new();
    if let Some(stop) = stopped_at {
        for frame in sim.control.iter().filter(|frame| frame.kind == Kind::Loop) {
            let phis = frame
                .state
                .loop_param_phis
                .iter()
                .chain(frame.state.loop_local_phis.iter().map(|(_, phi)| phi));
            open_joins.extend(phis.copied());
            sim.omissions.push(format!(
                "The loop at byte {} was still open where simulation stopped at byte {stop}; values read in it may also arrive by back edges after the stop, and its header joins are incomplete.",
                frame.state.offset
            ));
        }
    }
    Ok(Simulation {
        nodes: sim.nodes,
        edges: sim.edges,
        instructions: sim.instructions,
        instruction_nodes: sim.instruction_nodes,
        instruction_live: sim.instruction_live,
        input_start: sim.input_start,
        inputs: sim.inputs,
        type_index,
        params,
        locals: local_count,
        results,
        stopped_at,
        work: sim.work,
        stored: sim.stored,
        omissions: sim.omissions,
        open_joins,
    })
}

impl Sim<'_, '_> {
    /// Records which locals each loop writes, so its header joins exist before
    /// the back edges that feed them are read. A write lands in the innermost
    /// open loop only; a loop's set joins its enclosing loop's set at `end`, so
    /// the pass costs one unit per write plus one per local a loop passes on.
    fn prescan(&mut self, body: &FunctionBody<'_>, deadline: Instant) -> Result<Option<u32>> {
        let mut reader = body.get_operators_reader().map_err(bad)?;
        // Every open frame; a loop carries its instruction index and its set.
        let mut open: Vec<Option<(u32, HashSet<u32>)>> = Vec::new();
        let mut loops: Vec<usize> = Vec::new();
        let mut index = 0u32;
        while !reader.eof() {
            // The pass reads the whole body even past the instruction cap: it
            // costs one step per instruction, and a loop the main loop leaves
            // open at the cap then still has its header joins, marked
            // incomplete, instead of none.
            let position = reader.original_position() as u32;
            if index & 255 == 0 && Instant::now() > deadline {
                self.omissions.push(format!(
                    "Simulation deadline reached at byte {position}; value flow is not computed."
                ));
                return Ok(Some(position));
            }
            let op = reader.read().map_err(bad)?;
            match wasm_stack::effect(&op) {
                Effect::Open {
                    kind: Kind::Loop, ..
                } => {
                    loops.push(open.len());
                    open.push(Some((index, HashSet::new())));
                }
                Effect::Open { .. } => open.push(None),
                Effect::End | Effect::Delegate { .. } => {
                    if let Some(Some((start, set))) = open.pop() {
                        loops.pop();
                        if !self.spend(set.len() as u64) {
                            break;
                        }
                        if let Some(Some((_, outer))) = loops.last().map(|at| &mut open[*at]) {
                            outer.extend(set.iter().copied());
                        }
                        let mut locals: Vec<u32> = set.into_iter().collect();
                        locals.sort_unstable();
                        self.loop_writes.insert(start, locals);
                    }
                }
                _ => {
                    if let Operator::LocalSet { local_index } | Operator::LocalTee { local_index } =
                        &op
                        && let Some(Some((_, set))) = loops.last().map(|at| &mut open[*at])
                    {
                        set.insert(*local_index);
                        if !self.spend(1) {
                            break;
                        }
                    }
                }
            }
            index += 1;
        }
        while let Some(frame) = open.pop() {
            if let Some((start, set)) = frame {
                loops.pop();
                if let Some(Some((_, outer))) = loops.last().map(|at| &mut open[*at]) {
                    outer.extend(set.iter().copied());
                }
                let mut locals: Vec<u32> = set.into_iter().collect();
                locals.sort_unstable();
                self.loop_writes.insert(start, locals);
            }
        }
        if let Some(reason) = self.exhausted.take() {
            let position = reader.original_position() as u32;
            self.omissions.push(format!(
                "{reason} while recording loop writes at byte {position}; value flow is not computed."
            ));
            return Ok(Some(position));
        }
        Ok(None)
    }

    /// Charges `units` of work. False, with the reason kept for the main loop,
    /// once the work budget or the deadline is exhausted.
    fn spend(&mut self, units: u64) -> bool {
        if self.exhausted.is_some() {
            return false;
        }
        let before = self.work;
        self.work += units;
        if self.work > self.limits.max_work {
            self.exhausted = Some("Simulation work budget reached");
            return false;
        }
        if before >> 12 != self.work >> 12 && Instant::now() > self.deadline {
            self.exhausted = Some("Simulation deadline reached");
            return false;
        }
        true
    }

    fn node(
        &mut self,
        kind: NodeKind,
        offset: u32,
        instruction: u32,
        index: u32,
        results: u32,
    ) -> u32 {
        self.nodes.push(Node {
            kind,
            offset,
            instruction,
            index,
            results,
            aux: 0,
            join: Join::None,
        });
        self.nodes.len() as u32 - 1
    }

    fn unknown_value(&mut self) -> Value {
        if self.unknown == NONE {
            self.unknown = self.node(NodeKind::Unknown, self.body_offset, NONE, NONE, 1);
        }
        Value::of(self.unknown)
    }

    fn materialize(&mut self, value: Value) -> Value {
        if value.node != NONE {
            return value;
        }
        let local = value.result;
        if self.init_nodes[local as usize] == NONE {
            let (kind, offset) = if local < self.params {
                (NodeKind::Param, self.body_offset)
            } else {
                let group = self
                    .local_offsets
                    .partition_point(|(first, _)| *first <= local)
                    .saturating_sub(1);
                (
                    NodeKind::LocalInit,
                    self.local_offsets
                        .get(group)
                        .map_or(self.body_offset, |(_, offset)| *offset),
                )
            };
            self.init_nodes[local as usize] = self.node(kind, offset, NONE, local, 1);
        }
        Value::of(self.init_nodes[local as usize])
    }

    fn same(&self, a: Value, b: Value) -> bool {
        let norm = |value: Value| {
            if value.node == NONE && self.init_nodes[value.result as usize] != NONE {
                Value::of(self.init_nodes[value.result as usize])
            } else {
                value
            }
        };
        norm(a) == norm(b)
    }

    fn edge(
        &mut self,
        from: Value,
        to: u32,
        operand: u32,
        kind: EdgeKind,
        via: Via,
        via_offset: u32,
    ) {
        let from = self.materialize(from);
        self.edges.push(Edge {
            from: from.node,
            result: from.result,
            to,
            operand,
            kind,
            via,
            via_offset,
        });
    }

    fn pop(&mut self, offset: u32) -> Value {
        let height = self.control.base();
        if self.stack.len() > height {
            return self.stack.pop().expect("stack above height");
        }
        if self.reachable && !self.underflow_noted {
            self.underflow_noted = true;
            self.omissions.push(format!(
                "The operand stack is empty at byte {offset}; the module may not validate, and the missing operand is an unknown value."
            ));
        }
        self.unknown_value()
    }

    /// Pops `count` operands and returns them in operand order.
    fn pop_n(&mut self, count: u32, offset: u32) -> Vec<Value> {
        let mut values: Vec<Value> = (0..count).map(|_| self.pop(offset)).collect();
        values.reverse();
        values
    }

    /// The top `count` values without popping, padded with unknown values.
    fn top(&mut self, count: u32) -> Vec<Value> {
        let height = self.control.base();
        self.top_at(height, count)
    }

    /// A reachable instruction found fewer operands than it carries: noted
    /// once per body, since such a body does not validate.
    fn note_short(&mut self, wanted: usize, available: usize) {
        if self.reachable && !self.underflow_noted {
            self.underflow_noted = true;
            let offset = self
                .instructions
                .last()
                .copied()
                .unwrap_or(self.body_offset);
            self.omissions.push(format!(
                "The instruction at byte {offset} carries {wanted} values but the operand stack holds {available}; the module may not validate, and the missing values are unknown."
            ));
        }
    }

    fn record(&mut self, index: u32, values: &[Value]) {
        self.spend(values.len() as u64);
        for value in values {
            let value = self.materialize(*value);
            self.inputs.push(value);
        }
        let _ = index;
    }

    /// One consumer node for `values`, operand kinds from `kind_of`.
    fn consume(
        &mut self,
        kind: NodeKind,
        index: u32,
        target: u32,
        results: u32,
        values: &[Value],
        kind_of: impl Fn(usize) -> EdgeKind,
    ) -> u32 {
        self.record(index, values);
        let offset = self.instructions[index as usize];
        let node = self.node(kind, offset, index, target, results);
        for (operand, value) in values.iter().enumerate() {
            self.edge(
                *value,
                node,
                operand as u32,
                kind_of(operand),
                Via::None,
                NONE,
            );
        }
        self.instruction_nodes[index as usize] = node;
        for result in 0..results {
            self.stack.push(Value { node, result });
        }
        node
    }

    /// The values a branch to `depth` carries, read without popping.
    fn carried(&mut self, depth: u32) -> Vec<Value> {
        match self.control.target(depth) {
            Some(target) => {
                let arity = self.control[target].branch_arity();
                self.top(arity)
            }
            None => Vec::new(),
        }
    }

    /// A branch node for `if`, `br_if` or `br_table`. Its operands, in text
    /// order, are the carried values and then the selector; only the selector
    /// is consumed here, since the carried values flow to the branch target.
    fn selector(&mut self, index: u32, carried: &[Value], selector: Value) {
        self.record(index, carried);
        self.record(index, &[selector]);
        let offset = self.instructions[index as usize];
        let node = self.node(NodeKind::Branch, offset, index, NONE, 0);
        self.edge(
            selector,
            node,
            carried.len() as u32,
            EdgeKind::Selector,
            Via::None,
            NONE,
        );
        self.instruction_nodes[index as usize] = node;
    }

    fn write_local(&mut self, local: u32, value: Value, offset: u32) {
        let old = self.locals[local as usize];
        let mut walked = 0u64;
        for frame in self.control.iter_mut().rev() {
            if frame.state.saved.contains_key(&local) {
                break;
            }
            walked += 1;
            frame.state.saved.insert(local, old);
        }
        self.spend(walked);
        if self.reachable {
            for position in 0..self.open_tries.len() {
                if !self.spend(1) {
                    break;
                }
                let frame = self.open_tries[position];
                self.control[frame]
                    .state
                    .try_writes
                    .push((local, value, offset));
            }
        }
        self.locals[local as usize] = value;
    }

    fn snapshot(&mut self, frame: usize) -> Vec<(u32, Value)> {
        let mut locals: Vec<(u32, Value)> = self.control[frame]
            .state
            .saved
            .keys()
            .map(|local| (*local, self.locals[*local as usize]))
            .collect();
        locals.sort_unstable_by_key(|(local, _)| *local);
        self.spend(locals.len() as u64);
        locals
    }

    fn returns(&mut self, offset: u32, index: u32, values: &[Value]) -> u32 {
        self.spend(values.len() as u64);
        let node = self.node(NodeKind::Return, offset, index, NONE, 0);
        for (operand, value) in values.iter().enumerate() {
            self.edge(
                *value,
                node,
                operand as u32,
                EdgeKind::Return,
                Via::None,
                NONE,
            );
        }
        node
    }

    /// Carries `values` and the current locals to the frame at `target`.
    /// Each target costs its values again (a return's edges, a loop's
    /// parameter edges or a stored incoming path), so a `br_table` with many
    /// targets is charged per target and stops once the budget is spent.
    fn branch_to(&mut self, target: usize, values: Vec<Value>, via: Via, offset: u32, index: u32) {
        if !self.spend(values.len() as u64) {
            return;
        }
        match self.control[target].kind {
            Kind::Function => {
                let node = self.returns(offset, index, &values);
                if self.instruction_nodes[index as usize] == NONE {
                    self.instruction_nodes[index as usize] = node;
                }
            }
            Kind::Loop => {
                let params = self.control[target].state.loop_param_phis.clone();
                for (slot, phi) in params.iter().enumerate() {
                    if let Some(value) = values.get(slot)
                        && !self.same(*value, Value::of(*phi))
                    {
                        self.edge(*value, *phi, slot as u32, EdgeKind::Merge, via, offset);
                    }
                }
                let locals = self.control[target].state.loop_local_phis.clone();
                for (local, phi) in locals {
                    if !self.spend(1) {
                        break;
                    }
                    let value = self.locals[local as usize];
                    if !self.same(value, Value::of(phi)) {
                        self.edge(value, phi, 0, EdgeKind::Merge, via, offset);
                    }
                }
            }
            _ => {
                let locals = self.snapshot(target);
                let values = values.into_iter().map(|v| self.materialize(v)).collect();
                let path = self.stored_path(Incoming {
                    via,
                    via_offset: offset,
                    values,
                    locals,
                });
                self.control[target].state.incoming.push(path);
            }
        }
    }

    fn branch(&mut self, depth: u32, via: Via, offset: u32, index: u32) {
        if !self.reachable {
            return;
        }
        let Some(target) = self.control.target(depth) else {
            self.omissions.push(format!(
                "A branch at byte {offset} names a label past the open frames; its values are not followed."
            ));
            return;
        };
        let arity = self.control[target].branch_arity();
        let values = self.top(arity);
        self.branch_to(target, values, via, offset, index);
    }

    fn unreachable(&mut self) {
        let height = self.control.base();
        self.stack.truncate(height);
        self.reachable = false;
    }

    fn push_frame(
        &mut self,
        kind: Kind,
        offset: u32,
        index: u32,
        ty: BlockType,
    ) -> std::result::Result<(), Stop> {
        let (params, results) = self.module.types.block_arity(ty).ok_or_else(|| {
            Stop::Unsupported("A block type that is not a function type".to_owned())
        })?;
        let param_values = self.top(params);
        let height = self
            .stack
            .len()
            .saturating_sub(params as usize)
            .max(self.control.base());
        // A block's parameters stay on the stack as the values they are.
        self.stack.truncate(height);
        self.stack.extend(param_values.iter().copied());
        self.control.push(
            kind,
            (params, results),
            height,
            Flow {
                offset,
                instruction: index,
                param_values,
                reachable_at_entry: self.reachable,
                ..Flow::default()
            },
        );
        Ok(())
    }

    fn enter_loop(&mut self, offset: u32, index: u32) {
        // A loop no path reaches has no header joins: nothing can enter it.
        if !self.reachable {
            return;
        }
        let frame = self.control.len() - 1;
        let params = self.control[frame].state.param_values.clone();
        let height = self.control[frame].height();
        let mut phis = Vec::with_capacity(params.len());
        for (slot, value) in params.iter().enumerate() {
            let phi = self.node(NodeKind::Phi, offset, index, NONE, 1);
            self.nodes[phi as usize].aux = slot as u64;
            self.nodes[phi as usize].join = Join::Loop;
            self.edge(
                *value,
                phi,
                slot as u32,
                EdgeKind::Merge,
                Via::Entry,
                offset,
            );
            phis.push(phi);
        }
        self.stack.truncate(height);
        self.stack.extend(phis.iter().map(|phi| Value::of(*phi)));
        self.control[frame].state.loop_param_phis = phis;
        let written = self.loop_writes.get(&index).cloned().unwrap_or_default();
        let mut local_phis = Vec::with_capacity(written.len());
        for local in written {
            if local as usize >= self.locals.len() {
                continue;
            }
            if !self.spend(1) {
                break;
            }
            let phi = self.node(NodeKind::Phi, offset, index, local, 1);
            self.nodes[phi as usize].join = Join::Loop;
            let value = self.locals[local as usize];
            self.edge(value, phi, 0, EdgeKind::Merge, Via::Entry, offset);
            self.write_local(local, Value::of(phi), offset);
            local_phis.push((local, phi));
        }
        self.control[frame].state.loop_local_phis = local_phis;
    }

    fn restore_locals(&mut self, frame: usize) {
        let saved: Vec<(u32, Value)> = self.control[frame]
            .state
            .saved
            .iter()
            .map(|(local, value)| (*local, *value))
            .collect();
        self.spend(saved.len() as u64);
        for (local, value) in saved {
            self.locals[local as usize] = value;
        }
    }

    /// Joins for every local a `try` body defined, with the entry value and
    /// each definition as incoming edges. Created once per `try`.
    fn catch_phis(&mut self, frame: usize) -> Vec<(u32, u32)> {
        if let Some(phis) = &self.control[frame].state.catch_phis {
            return phis.clone();
        }
        let writes = std::mem::take(&mut self.control[frame].state.try_writes);
        let offset = self.control[frame].state.offset;
        let instruction = self.control[frame].state.instruction;
        let mut by_local: Vec<(u32, Value, u32)> = writes;
        by_local.sort_by_key(|(local, _, _)| *local);
        let mut phis = Vec::new();
        let mut position = 0;
        while position < by_local.len() {
            let local = by_local[position].0;
            let entry = self.control[frame]
                .state
                .saved
                .get(&local)
                .copied()
                .unwrap_or(self.locals[local as usize]);
            let phi = self.node(NodeKind::Phi, offset, instruction, local, 1);
            self.nodes[phi as usize].join = Join::Try;
            self.edge(entry, phi, 0, EdgeKind::Merge, Via::Entry, offset);
            while position < by_local.len() && by_local[position].0 == local {
                let (_, value, at) = by_local[position];
                if !self.spend(1) {
                    // Ends both loops: the rest of the joins are cut with the
                    // simulation, which stops after this instruction.
                    position = by_local.len();
                    break;
                }
                self.edge(value, phi, 0, EdgeKind::Merge, Via::Catch, at);
                position += 1;
            }
            phis.push((local, phi));
        }
        self.control[frame].state.catch_phis = Some(phis.clone());
        phis
    }

    fn close_try_body(&mut self, frame: usize) {
        self.open_tries.retain(|open| *open != frame);
    }

    /// `live` is whether a throw can reach the handler: for a `try_table`
    /// clause that is the body's reachability at entry, not at its `end`
    /// (a compiled body usually ends in `br`, `return` or a throw).
    fn exception_values(
        &mut self,
        offset: u32,
        index: u32,
        tag: u32,
        count: u32,
        live: bool,
    ) -> Vec<Value> {
        if count == 0 {
            return Vec::new();
        }
        if !live {
            let unknown = self.unknown_value();
            return vec![unknown; count as usize];
        }
        let node = self.node(NodeKind::ExceptionValue, offset, index, tag, count);
        if self.instruction_nodes[index as usize] == NONE {
            self.instruction_nodes[index as usize] = node;
        }
        (0..count).map(|result| Value { node, result }).collect()
    }

    /// Closes the innermost frame at its `end` (or `delegate`), merging every
    /// path that reaches the instruction after it. The block's results, merged
    /// or passed through, are recorded as the `end`'s operands so the `end`
    /// itself can be traced.
    fn close(&mut self, offset: u32, index: u32) {
        let height = self.control.base();
        self.merge(offset, index);
        let results = self.stack.len().saturating_sub(height);
        if self.reachable && results > 0 {
            let values: Vec<Value> = self.stack[self.stack.len() - results..].to_vec();
            self.record(index, &values);
        }
    }

    fn merge(&mut self, offset: u32, index: u32) {
        let position = self.control.len() - 1;
        if matches!(self.control[position].kind, Kind::Try | Kind::TryTable) {
            self.close_try_body(position);
        }
        if self.control[position].kind == Kind::TryTable {
            self.route_try_table(position, offset, index);
        }
        if self.control[position].kind == Kind::Loop {
            let frame = self.control.pop().expect("loop frame");
            let results = frame.results;
            if self.reachable {
                let values = self.top_at(frame.height(), results);
                self.stack.truncate(frame.height());
                self.stack.extend(values);
            } else {
                self.stack.truncate(frame.height());
                for _ in 0..results {
                    let unknown = self.unknown_value();
                    self.stack.push(unknown);
                }
            }
            return;
        }
        let results = self.control[position].results;
        let mut incomings = std::mem::take(&mut self.control[position].state.incoming);
        if let Some(then) = self.control[position].state.then_end.take() {
            incomings.insert(0, then);
        }
        if self.reachable {
            let height = self.control[position].height();
            self.note_leftover(height, results, offset);
            let values = self.top_at(height, results);
            let values = values.into_iter().map(|v| self.materialize(v)).collect();
            let locals = self.snapshot(position);
            incomings.push(Incoming {
                via: Via::Fallthrough,
                via_offset: offset,
                values,
                locals,
            });
        }
        if self.control[position].kind == Kind::If
            && self.control[position].state.reachable_at_entry
        {
            let entry = self.control[position].state.offset;
            let values = self.control[position].state.param_values.clone();
            let values = values.into_iter().map(|v| self.materialize(v)).collect();
            let mut locals: Vec<(u32, Value)> = self.control[position]
                .state
                .saved
                .iter()
                .map(|(local, value)| (*local, *value))
                .collect();
            locals.sort_unstable_by_key(|(local, _)| *local);
            incomings.push(Incoming {
                via: Via::IfFalse,
                via_offset: entry,
                values,
                locals,
            });
        }
        let frame = self.control.pop().expect("frame");
        self.stack.truncate(frame.height());
        if incomings.is_empty() {
            self.reachable = false;
            for (local, value) in &frame.state.saved {
                self.locals[*local as usize] = *value;
            }
            for _ in 0..results {
                let unknown = self.unknown_value();
                self.stack.push(unknown);
            }
            return;
        }
        self.reachable = true;
        // Every path must carry the block's result count. A body that does not
        // validate can carry fewer or more; the merge pads with unknown values
        // or drops the extra ones, and says so.
        let unknown = self.unknown_value();
        for incoming in incomings.iter_mut() {
            let carried = incoming.values.len();
            if carried == results as usize {
                continue;
            }
            let from = incoming.via_offset;
            self.omissions.push(format!(
                "At byte {offset} a path from byte {from} carries {carried} values where the block declares {results}; the module may not validate, and missing values are unknown."
            ));
            incoming.values.resize(results as usize, unknown);
        }
        self.spend(results as u64 * incomings.len() as u64);
        for slot in 0..results as usize {
            if self.exhausted.is_some() {
                break;
            }
            let first = incomings[0].values[slot];
            if incomings
                .iter()
                .all(|incoming| self.same(incoming.values[slot], first))
            {
                self.stack.push(first);
                continue;
            }
            let phi = self.node(NodeKind::Phi, offset, index, NONE, 1);
            self.nodes[phi as usize].aux = slot as u64;
            self.nodes[phi as usize].join = join_of(frame.opened);
            for incoming in &incomings {
                self.edge(
                    incoming.values[slot],
                    phi,
                    slot as u32,
                    EdgeKind::Merge,
                    incoming.via,
                    incoming.via_offset,
                );
            }
            self.stack.push(Value::of(phi));
        }
        let mut written: Vec<(u32, Value)> = frame
            .state
            .saved
            .iter()
            .map(|(local, value)| (*local, *value))
            .collect();
        written.sort_unstable_by_key(|(local, _)| *local);
        for (local, entry) in written {
            if !self.spend(incomings.len() as u64) {
                break;
            }
            let value_in = |incoming: &Incoming| {
                incoming
                    .locals
                    .binary_search_by_key(&local, |(l, _)| *l)
                    .map_or(entry, |found| incoming.locals[found].1)
            };
            let first = value_in(&incomings[0]);
            if incomings
                .iter()
                .all(|incoming| self.same(value_in(incoming), first))
            {
                self.locals[local as usize] = first;
                continue;
            }
            let phi = self.node(NodeKind::Phi, offset, index, local, 1);
            self.nodes[phi as usize].join = join_of(frame.opened);
            for incoming in &incomings {
                let value = value_in(incoming);
                self.edge(
                    value,
                    phi,
                    0,
                    EdgeKind::Merge,
                    incoming.via,
                    incoming.via_offset,
                );
            }
            self.write_local(local, Value::of(phi), offset);
        }
    }

    fn top_at(&mut self, height: usize, count: u32) -> Vec<Value> {
        // Copies of carried values are kept per branch, so they count against
        // the budget like any other retained entry: a block with many results
        // and many branches to it is bounded in time and memory.
        self.spend(count as u64);
        let available = self.stack.len().saturating_sub(height);
        let count = count as usize;
        if available < count {
            self.note_short(count, available);
        }
        let mut values = Vec::with_capacity(count);
        for _ in available..count {
            values.push(self.unknown_value());
        }
        let take = count.min(available);
        values.extend_from_slice(&self.stack[self.stack.len() - take..]);
        values
    }

    /// Values left above a block's results at its end flow nowhere; a body
    /// that leaves them does not validate.
    fn note_leftover(&mut self, height: usize, results: u32, offset: u32) {
        let extra = self.stack.len().saturating_sub(height + results as usize);
        if extra > 0 {
            self.omissions.push(format!(
                "{extra} values are left on the operand stack at the end at byte {offset}; the module may not validate, and they flow nowhere."
            ));
        }
    }

    /// A `try_table` catch clause branches to its label from anywhere in the
    /// body, so it carries exception values and the body's definitions.
    fn route_try_table(&mut self, position: usize, offset: u32, index: u32) {
        if !self.control[position].state.reachable_at_entry
            || self.control[position].state.catches.is_empty()
        {
            return;
        }
        let phis = self.catch_phis(position);
        let entry_offset = self.control[position].state.offset;
        let instruction = self.control[position].state.instruction;
        let catches: Vec<(usize, u32, u32)> = self.control[position]
            .state
            .catches
            .iter()
            .map(|catch| (catch.target, catch.tag, catch.values))
            .collect();
        let saved = self.control[position].state.saved.clone();
        let _ = (offset, index);
        for (target, tag, count) in catches {
            // A try_table may name thousands of clauses with tags of up to a
            // thousand values each: every clause is charged before it is built.
            if !self.spend(u64::from(count) + 1) {
                break;
            }
            let values = self.exception_values(entry_offset, instruction, tag, count, true);
            let local_value = |local: u32, current: Value| -> Value {
                if let Ok(found) = phis.binary_search_by_key(&local, |(l, _)| *l) {
                    Value::of(phis[found].1)
                } else {
                    saved.get(&local).copied().unwrap_or(current)
                }
            };
            match self.control[target].kind {
                Kind::Function => {
                    self.returns(entry_offset, instruction, &values);
                }
                Kind::Loop => {
                    let params = self.control[target].state.loop_param_phis.clone();
                    for (slot, phi) in params.iter().enumerate() {
                        if let Some(value) = values.get(slot) {
                            self.edge(
                                *value,
                                *phi,
                                slot as u32,
                                EdgeKind::Merge,
                                Via::Catch,
                                entry_offset,
                            );
                        }
                    }
                    let locals = self.control[target].state.loop_local_phis.clone();
                    for (local, phi) in locals {
                        if !self.spend(1) {
                            break;
                        }
                        let value = local_value(local, self.locals[local as usize]);
                        if !self.same(value, Value::of(phi)) {
                            self.edge(value, phi, 0, EdgeKind::Merge, Via::Catch, entry_offset);
                        }
                    }
                }
                _ => {
                    let mut locals: Vec<(u32, Value)> = self.control[target]
                        .state
                        .saved
                        .keys()
                        .map(|local| (*local, local_value(*local, self.locals[*local as usize])))
                        .collect();
                    locals.sort_unstable_by_key(|(local, _)| *local);
                    self.spend(locals.len() as u64);
                    let path = self.stored_path(Incoming {
                        via: Via::Catch,
                        via_offset: entry_offset,
                        values,
                        locals,
                    });
                    self.control[target].state.incoming.push(path);
                }
            }
        }
    }

    /// Counts what an incoming path keeps until its merge.
    fn stored_path(&mut self, path: Incoming) -> Incoming {
        self.stored += (path.values.len() + path.locals.len()) as u64;
        path
    }

    fn clear_store(&mut self) {
        self.store = None;
    }

    /// Simulates one instruction. Returns true at the function's final `end`.
    fn step(
        &mut self,
        op: &Operator<'_>,
        offset: u32,
        index: u32,
    ) -> std::result::Result<bool, Stop> {
        let effect = wasm_stack::effect(op);
        // Code no declared path reaches creates no node: its values cannot
        // feed a slice and its calls cannot be reported as sinks. Structure
        // is still tracked so the frames stay aligned with the bytes.
        if !self.reachable && !effect.is_structure() {
            return Ok(false);
        }
        match effect {
            Effect::Unreachable => self.clear_store(),
            Effect::Open {
                kind,
                block_type,
                catches,
            } => {
                self.clear_store();
                if kind == Kind::If && self.reachable {
                    let condition = self.pop(offset);
                    self.selector(index, &[], condition);
                }
                let catches = self.clauses(catches, offset)?;
                self.push_frame(kind, offset, index, block_type)?;
                let frame = self.control.len() - 1;
                match kind {
                    Kind::Loop => self.enter_loop(offset, index),
                    Kind::Try | Kind::TryTable => {
                        self.control[frame].state.catches = catches;
                        if self.reachable {
                            self.open_tries.push(frame);
                        }
                    }
                    _ => {}
                }
            }
            Effect::Else => {
                self.clear_store();
                if !self.control.accepts(&effect) {
                    return Err(Stop::Unsupported("An else without its if".to_owned()));
                }
                let position = self.control.len() - 1;
                if self.reachable {
                    let height = self.control[position].height();
                    let results = self.control[position].results;
                    let values = self.top_at(height, results);
                    let values = values.into_iter().map(|v| self.materialize(v)).collect();
                    let locals = self.snapshot(position);
                    self.control[position].state.then_end = Some(Incoming {
                        via: Via::ThenEnd,
                        via_offset: offset,
                        values,
                        locals,
                    });
                }
                let height = self.control[position].height();
                self.stack.truncate(height);
                let params = self.control[position].state.param_values.clone();
                self.stack.extend(params);
                self.restore_locals(position);
                self.reachable = self.control[position].state.reachable_at_entry;
                self.control.enter_arm(Kind::Else);
            }
            Effect::End => {
                self.clear_store();
                if self.control.len() == 1 {
                    let results = self.control[0].results;
                    let mut node = NONE;
                    if self.reachable {
                        self.note_leftover(0, results, offset);
                        let values = self.top_at(0, results);
                        self.record(index, &values);
                        node = self.returns(offset, index, &values);
                    }
                    self.instruction_nodes[index as usize] = node;
                    self.control.pop();
                    return Ok(true);
                }
                if self.control.is_empty() {
                    return Err(Stop::Unsupported("An end without a block".to_owned()));
                }
                self.close(offset, index);
            }
            Effect::Branch {
                depth,
                conditional: false,
            } => {
                self.clear_store();
                if let Some(target) = self.control.target(depth) {
                    let arity = self.control[target].branch_arity();
                    let values = self.top(arity);
                    self.record(index, &values);
                }
                self.branch(depth, Via::Br, offset, index);
            }
            Effect::Branch {
                depth,
                conditional: true,
            } => {
                self.clear_store();
                let condition = self.pop(offset);
                let carried = self.carried(depth);
                self.selector(index, &carried, condition);
                self.branch(depth, Via::BrIf, offset, index);
            }
            Effect::BrTable(targets) => {
                self.clear_store();
                let selector = self.pop(offset);
                let carried = self.carried(targets.default());
                self.selector(index, &carried, selector);
                let mut depths: Vec<u32> = Vec::new();
                for target in targets.targets() {
                    let depth = target
                        .map_err(|e| Stop::Unsupported(format!("A br_table target ({e})")))?;
                    depths.push(depth);
                }
                depths.push(targets.default());
                depths.sort_unstable();
                depths.dedup();
                self.spend(depths.len() as u64);
                for depth in depths {
                    if self.exhausted.is_some() {
                        break;
                    }
                    self.branch(depth, Via::BrTable, offset, index);
                }
            }
            Effect::Return => {
                self.clear_store();
                if self.reachable {
                    let results = self.control[0].results;
                    let values = self.top(results);
                    self.record(index, &values);
                    let node = self.returns(offset, index, &values);
                    self.instruction_nodes[index as usize] = node;
                }
            }
            Effect::Call { callee, tail } => {
                self.clear_store();
                self.call(callee, tail, offset, index)?;
            }
            Effect::Catch { tag } => {
                self.clear_store();
                if !self.control.accepts(&effect) {
                    return Err(Stop::Unsupported("A catch without its try".to_owned()));
                }
                let position = self.control.len() - 1;
                if self.reachable {
                    let height = self.control[position].height();
                    let results = self.control[position].results;
                    let values = self.top_at(height, results);
                    let values = values.into_iter().map(|v| self.materialize(v)).collect();
                    let locals = self.snapshot(position);
                    let path = self.stored_path(Incoming {
                        via: Via::Fallthrough,
                        via_offset: offset,
                        values,
                        locals,
                    });
                    self.control[position].state.incoming.push(path);
                }
                self.close_try_body(position);
                let height = self.control[position].height();
                self.stack.truncate(height);
                self.restore_locals(position);
                self.reachable = self.control[position].state.reachable_at_entry;
                if self.reachable {
                    for (local, phi) in self.catch_phis(position) {
                        self.write_local(local, Value::of(phi), offset);
                    }
                }
                let (tag, count) = match tag {
                    Some(tag) => (
                        tag,
                        self.module.types.tag_params(tag).ok_or_else(|| {
                            Stop::Unsupported(format!("A catch of undeclared tag {tag}"))
                        })?,
                    ),
                    None => (NONE, 0),
                };
                let live = self.reachable;
                let values = self.exception_values(offset, index, tag, count, live);
                self.stack.extend(values);
                self.control.enter_arm(Kind::Catch);
            }
            Effect::Delegate { .. } => {
                self.clear_store();
                if !self.control.accepts(&effect) {
                    return Err(Stop::Unsupported("A delegate without its try".to_owned()));
                }
                self.close(offset, index);
            }
            Effect::Throw { tag: Some(tag) } => {
                self.clear_store();
                let count =
                    self.module.types.tag_params(tag).ok_or_else(|| {
                        Stop::Unsupported(format!("A throw of undeclared tag {tag}"))
                    })?;
                let args = self.pop_n(count, offset);
                self.consume(NodeKind::Throw, index, tag, 0, &args, |_| {
                    EdgeKind::Argument
                });
            }
            Effect::Throw { tag: None } => {
                self.clear_store();
                let value = self.pop(offset);
                self.consume(NodeKind::Throw, index, NONE, 0, &[value], |_| {
                    EdgeKind::Argument
                });
            }
            Effect::Rethrow { .. } => self.clear_store(),
            Effect::BrOn { depth, test } => {
                self.clear_store();
                let reference = self.pop(offset);
                let node = self.consume(NodeKind::Operation, index, NONE, 0, &[reference], |_| {
                    EdgeKind::Operand
                });
                self.nodes[node as usize].results = 1;
                let derived = Value::of(node);
                let Some(target) = self.control.target(depth) else {
                    self.omissions.push(format!(
                        "A branch at byte {offset} names a label past the open frames; its values are not followed."
                    ));
                    return Ok(false);
                };
                let arity = self.control[target].branch_arity();
                let null = test == Test::Null;
                if self.reachable {
                    let mut values = self.top(if null { arity } else { arity.saturating_sub(1) });
                    if !null {
                        values.push(derived);
                    }
                    self.branch_to(target, values, Via::BrOn, offset, index);
                }
                if test != Test::NonNull {
                    self.stack.push(derived);
                }
            }
            Effect::Switching => return Err(Self::switching(op)),
            Effect::Plain => self.plain(op, offset, index)?,
        }
        if effect.ends_path() {
            self.unreachable();
        }
        Ok(false)
    }

    fn switching(op: &Operator<'_>) -> Stop {
        Stop::Unsupported(format!(
            "The stack-switching operator {}",
            crate::wasm::mnemonic(op)
        ))
    }

    /// A `try_table`'s catch clauses, resolved against the frames around it.
    /// A clause past the open frames is noted and not followed.
    fn clauses(
        &mut self,
        catches: &[wasmparser::Catch],
        offset: u32,
    ) -> std::result::Result<Vec<TryCatch>, Stop> {
        let mut clauses = Vec::new();
        for catch in catches {
            let clause = Clause::of(catch, &self.module.types, &self.control);
            let Some(target) = clause.target else {
                self.omissions.push(format!(
                    "A try_table catch at byte {offset} names a label past the open frames; it is not followed."
                ));
                continue;
            };
            // `NONE` is this simulation's catch-all tag, so a clause naming
            // tag index u32::MAX reads as one, as it always has.
            let tag = clause.tag.unwrap_or(NONE);
            let values = if tag == NONE {
                u32::from(clause.with_ref)
            } else {
                clause
                    .values
                    .ok_or_else(|| Stop::Unsupported(format!("A catch of undeclared tag {tag}")))?
            };
            clauses.push(TryCatch {
                target,
                tag,
                values,
            });
        }
        Ok(clauses)
    }

    /// A call's arguments (and its callee operand) flow into one call node;
    /// a tail call pushes nothing, since its results go to the caller.
    fn call(
        &mut self,
        callee: Callee,
        tail: bool,
        offset: u32,
        index: u32,
    ) -> std::result::Result<(), Stop> {
        let Some((params, results)) = self.module.types.call_arity(callee) else {
            return Err(Stop::Unsupported(match callee {
                Callee::Function(function) => format!("A call to undeclared function {function}"),
                Callee::Indirect { type_index, .. } => {
                    format!("call_indirect of non-function type {type_index}")
                }
                Callee::Ref { type_index } => format!("call_ref of non-function type {type_index}"),
            }));
        };
        let pushed = if tail { 0 } else { results };
        let node = match callee {
            Callee::Function(function) => {
                let args = self.pop_n(params, offset);
                let kind = if function < self.module.imported_functions {
                    NodeKind::ImportCall
                } else {
                    NodeKind::Call
                };
                self.consume(kind, index, function, pushed, &args, |_| EdgeKind::Argument)
            }
            Callee::Indirect { type_index, table } => {
                // The table index is the last operand, after the arguments.
                let args = self.pop_n(params + 1, offset);
                let count = params as usize;
                let node = self.consume(
                    NodeKind::CallIndirect,
                    index,
                    type_index,
                    pushed,
                    &args,
                    |operand| {
                        if operand == count {
                            EdgeKind::CalleeIndex
                        } else {
                            EdgeKind::Argument
                        }
                    },
                );
                self.nodes[node as usize].aux = table as u64;
                node
            }
            Callee::Ref { type_index } => {
                let args = self.pop_n(params + 1, offset);
                let count = params as usize;
                self.consume(
                    NodeKind::CallRef,
                    index,
                    type_index,
                    pushed,
                    &args,
                    |operand| {
                        if operand == count {
                            EdgeKind::CalleeRef
                        } else {
                            EdgeKind::Argument
                        }
                    },
                )
            }
        };
        self.nodes[node as usize].results = results;
        Ok(())
    }

    /// An operator with no control effect.
    fn plain(
        &mut self,
        op: &Operator<'_>,
        offset: u32,
        index: u32,
    ) -> std::result::Result<(), Stop> {
        match op {
            Operator::Nop => {}
            Operator::LocalGet { local_index } => {
                let local = *local_index;
                if local as usize >= self.locals.len() {
                    return Err(Stop::Unsupported(format!(
                        "local.get of undeclared local {local}"
                    )));
                }
                let value = self.materialize(self.locals[local as usize]);
                self.consume(NodeKind::LocalGet, index, local, 1, &[value], |_| {
                    EdgeKind::Local
                });
            }
            Operator::LocalSet { local_index } | Operator::LocalTee { local_index } => {
                let local = *local_index;
                if local as usize >= self.locals.len() {
                    return Err(Stop::Unsupported(format!(
                        "A write to undeclared local {local}"
                    )));
                }
                let tee = matches!(op, Operator::LocalTee { .. });
                let value = self.pop(offset);
                let kind = if tee {
                    NodeKind::LocalTee
                } else {
                    NodeKind::LocalSet
                };
                let node = self.consume(kind, index, local, u32::from(tee), &[value], |_| {
                    EdgeKind::LocalSet
                });
                self.nodes[node as usize].results = 1;
                self.write_local(local, Value::of(node), offset);
            }
            Operator::GlobalGet { global_index } => {
                self.consume(NodeKind::GlobalGet, index, *global_index, 1, &[], |_| {
                    EdgeKind::Operand
                });
            }
            Operator::GlobalSet { global_index } => {
                let value = self.pop(offset);
                self.consume(
                    NodeKind::GlobalSet,
                    index,
                    *global_index,
                    0,
                    &[value],
                    |_| EdgeKind::GlobalSet,
                );
            }
            Operator::Select | Operator::TypedSelect { .. } => {
                let args = self.pop_n(3, offset);
                self.consume(NodeKind::Select, index, NONE, 1, &args, |operand| {
                    if operand == 2 {
                        EdgeKind::Selector
                    } else {
                        EdgeKind::Operand
                    }
                });
            }
            Operator::Drop => {
                let value = self.pop(offset);
                self.consume(NodeKind::Drop, index, NONE, 0, &[value], |_| EdgeKind::Drop);
            }
            // The fence's mnemonic is `atomic_fence`, with no `.atomic`, so it
            // is matched here: it orders memory with other agents, and a store
            // before it no longer stands for a load after it.
            Operator::AtomicFence => self.clear_store(),
            // Continuations are values, but this simulation does not follow
            // what they later resume, so stack switching stops it here.
            Operator::ContBind { .. } | Operator::ContNew { .. } => {
                return Err(Self::switching(op));
            }
            other => {
                let (params, results) = wasm_stack::plain_arity(other, &self.module.types)
                    .ok_or_else(|| {
                        Stop::Unsupported(format!("The operator {}", crate::wasm::mnemonic(other)))
                    })?;
                let kind = classify(other);
                let args = self.pop_n(params, offset);
                let address_first =
                    matches!(kind, NodeKind::Load | NodeKind::Store | NodeKind::Atomic);
                let node = self.consume(kind, index, NONE, results, &args, |operand| {
                    if address_first && operand == 0 {
                        EdgeKind::Address
                    } else if matches!(kind, NodeKind::Store | NodeKind::Atomic) {
                        EdgeKind::StoredValue
                    } else {
                        EdgeKind::Operand
                    }
                });
                match kind {
                    NodeKind::Const => self.nodes[node as usize].aux = const_bits(other),
                    NodeKind::Load => {
                        if let (Some((false, class, memory, memarg)), Some(address), Some(fact)) =
                            (full_width(other), args.first(), self.store)
                        {
                            let address = &self.nodes[address.node as usize];
                            if address.kind == NodeKind::Const
                                && address.aux == fact.address
                                && fact.class == class
                                && fact.memory == memory
                                && fact.memarg == memarg
                            {
                                self.edge(
                                    fact.value,
                                    node,
                                    1,
                                    EdgeKind::ForwardedStore,
                                    Via::Store,
                                    fact.at,
                                );
                            }
                        }
                    }
                    NodeKind::Store => {
                        self.clear_store();
                        if let (Some((true, class, memory, memarg)), [address, value]) =
                            (full_width(other), args.as_slice())
                            && self.nodes[address.node as usize].kind == NodeKind::Const
                        {
                            self.store = Some(StoreFact {
                                class,
                                memory,
                                address: self.nodes[address.node as usize].aux,
                                memarg,
                                value: *value,
                                at: offset,
                            });
                        }
                    }
                    NodeKind::Atomic => self.clear_store(),
                    NodeKind::Memory if !matches!(other, Operator::MemorySize { .. }) => {
                        self.clear_store();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}
