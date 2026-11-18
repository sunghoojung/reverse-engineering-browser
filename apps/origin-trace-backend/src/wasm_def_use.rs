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
//!   unreachable stack, phi-like joins where control paths merge, and memory
//!   cells that stand for one address read and written in the function;
//! - [`Edge`]s from each produced value to each operand that consumes it, with
//!   the operand position and an [`EdgeKind`]; a join's incoming edges also
//!   name the branch that carried the value ([`Via`]) and its offset.
//!
//! Joins are built from structured control flow only. A block, `if` or `try`
//! join is placed at its `end` (or handler), and a loop join at its `loop`
//! instruction for every loop parameter and every local the loop writes that
//! is read again: at or after the loop, or anywhere in a loop around it. A
//! local nothing reads again gets no join and records no entry value, so a
//! loop nest that writes thousands of dead locals stays linear. A join is
//! created only where incoming values differ, so a value that reaches a merge
//! unchanged keeps its producer.
//!
//! Memory has two layers. Exact: a full-width load reads the value of an
//! earlier full-width store of the same type to the same address in the same
//! basic block when nothing between them may have overwritten it; the
//! address is a constant, or a base value plus a static offset, and stores to
//! other offsets of the same base or other constant addresses do not
//! interfere. That store's value is linked to the load as a `forwarded_store`
//! edge, and a `global.set` reaches a later `global.get` of the same global
//! in the same block, with no call between, as `forwarded_global`. May:
//! every load and store of one width at one address key (a constant, or a
//! base value plus offset) meets at a `memory_cell` node, joined by
//! `memory_may` edges. Other bases may alias, so these edges are possible,
//! not proven, flow.
//!
//! Control: each join has `control` edges from the decisions (`if`, `br_if`,
//! `br_table`) its incoming paths are control dependent on, and each decision
//! from the decisions it depends on, from the post-dominator tree of the
//! body's basic blocks.
//!
//! This is a structural simulation of the bytes, not validation and not
//! execution. A malformed stack shape becomes an `unknown` value and a named
//! omission, never a panic. Operators whose stack effect this module does not
//! model (stack switching) stop the simulation with a named omission, and the
//! prefix before them stays valid. There is no instruction or work budget:
//! the walk runs to the end of the body unless the caller's request is
//! cancelled. One guard protects the machine: the prescan predicts the memory
//! the simulation will hold from the body's instruction, join and branch
//! counts, and a body that would need more than the machine can spare is
//! refused before anything is allocated.
//!
//! Each operator's stack effect and the open control frames come from
//! [`crate::wasm_stack`], the layer the readable lifted view also folds with;
//! this module keeps only its payload: values, nodes, edges and the paths that
//! merge at each frame.
use crate::error::{Code, Error, Result};
use crate::wasm_stack::{self, Callee, Clause, Control, Effect, Kind, ModuleTypes, Test};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use wasmparser::{
    BlockType, ElementItems, ExternalKind, FunctionBody, Operator, Parser, Payload, TypeRef,
};

pub const NONE: u32 = u32::MAX;
/// Engines reject a function with more locals than this, so a body declaring
/// more cannot have run.
pub const MAX_LOCALS: u64 = 50_000;

/// What one simulation may hold and build. Tests lower `memory` to reach the
/// refusal; summaries of other functions leave out control and memory cells.
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Bytes the simulation may be predicted to need before it is refused.
    pub memory: u64,
    /// Build `control` edges from the body's post-dominator tree.
    pub control: bool,
    /// Build `memory_cell` nodes and their `memory_may` edges.
    pub cells: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            memory: memory_budget(),
            control: true,
            cells: true,
        }
    }
}

/// Half of what this machine can hold without swapping: the rest stays for
/// the slice, the document and the other requests the backend serves.
pub fn memory_budget() -> u64 {
    crate::js_worker_alloc::machine_ceiling() / 2
}

/// Instructions simulated so far, shared with a progress reader.
#[derive(Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
}
const MAX_IMPORT_NAME_BYTES: usize = 128;

pub(crate) fn bad(error: wasmparser::BinaryReaderError) -> Error {
    Error::protocol(format!("WASM decoding failed: {error}"))
}

/// What a node is. The names are the contract's `kind` vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
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
    /// One address key's loads and stores of one width (`memory_may`).
    MemoryCell,
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
            Self::MemoryCell => "memory_cell",
        }
    }
}

/// How a value reaches its consumer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
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
    /// A `global.set` value read by a later `global.get` in the same block.
    ForwardedGlobal,
    /// A store into a memory cell, or a cell into a load: possible flow.
    MemoryMay,
    /// A decision into a join or a decision that depends on it.
    Control,
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
            Self::ForwardedGlobal => "forwarded_global",
            Self::MemoryMay => "memory_may",
            Self::Control => "control",
        }
    }
}

/// The control transfer that carried a value into a join.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
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
    /// The store a `forwarded_store` or `memory_may` edge came from.
    Store,
    /// The `global.set` a `forwarded_global` edge came from.
    GlobalSet,
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
            Self::GlobalSet => "global_set",
        })
    }
}

/// The construct a join belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
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

/// 20 bytes: a body at the engine size limit has millions of nodes, and a
/// cached simulation keeps them all.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    pub kind: NodeKind,
    pub join: Join,
    /// Values produced; a type declares at most 1,000 results.
    pub results: u16,
    /// Original module byte offset of the instruction, or of the declaration
    /// for parameters and declared locals.
    pub offset: u32,
    /// Instruction position in the body, `NONE` for synthetic nodes.
    pub instruction: u32,
    /// The local, global, function, type, tag or memory cell index the node
    /// names; a constant's low 32 bits.
    pub index: u32,
    /// A join's result slot, the table of `call_indirect`, or a constant's
    /// high 32 bits.
    pub aux: u32,
}

impl Node {
    /// A constant's bits, as `i64` for integers and IEEE bits for floats.
    pub fn constant(&self) -> u64 {
        (u64::from(self.aux) << 32) | u64::from(self.index)
    }
}

/// 20 bytes. Operand and result positions fit 16 bits: a type declares at
/// most 1,000 parameters and 1,000 results.
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub from: u32,
    pub to: u32,
    pub via_offset: u32,
    pub result: u16,
    pub operand: u16,
    pub kind: EdgeKind,
    pub via: Via,
}

const _: () = assert!(std::mem::size_of::<Node>() == 20);
const _: () = assert!(std::mem::size_of::<Edge>() == 20);

/// The address one memory cell stands for: `base` plus `offset`, or the
/// constant `offset` when `base` has no node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cell {
    pub memory: u32,
    pub base: Value,
    pub offset: u64,
    pub width: u8,
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
    pub omissions: Vec<String>,
    /// Header joins of loops still open where the simulation stopped: their
    /// back edges after the stop were never read, so they are incomplete.
    pub open_joins: HashSet<u32>,
    /// The address of each `memory_cell` node, by the node's `index`.
    pub cells: Vec<Cell>,
    /// Instructions in the whole body, simulated or not.
    pub body_instructions: u32,
    /// The prescan's prediction of what this simulation holds, in bytes.
    pub predicted_bytes: u64,
    pub adjacency: Adjacency,
}

/// Compressed adjacency over a simulation's edges.
pub struct Adjacency {
    in_start: Vec<u32>,
    in_edges: Vec<u32>,
    out_start: Vec<u32>,
    out_edges: Vec<u32>,
}

impl Adjacency {
    fn new(nodes: usize, edges: &[Edge]) -> Self {
        let mut in_count = vec![0u32; nodes + 1];
        let mut out_count = vec![0u32; nodes + 1];
        for edge in edges {
            in_count[edge.to as usize + 1] += 1;
            out_count[edge.from as usize + 1] += 1;
        }
        for index in 0..nodes {
            in_count[index + 1] += in_count[index];
            out_count[index + 1] += out_count[index];
        }
        let mut in_edges = vec![0u32; edges.len()];
        let mut out_edges = vec![0u32; edges.len()];
        let mut in_fill = in_count.clone();
        let mut out_fill = out_count.clone();
        for (position, edge) in edges.iter().enumerate() {
            in_edges[in_fill[edge.to as usize] as usize] = position as u32;
            in_fill[edge.to as usize] += 1;
            out_edges[out_fill[edge.from as usize] as usize] = position as u32;
            out_fill[edge.from as usize] += 1;
        }
        Self {
            in_start: in_count,
            in_edges,
            out_start: out_count,
            out_edges,
        }
    }
    /// Edges into `node`, in creation order.
    pub fn inputs(&self, node: u32) -> &[u32] {
        &self.in_edges
            [self.in_start[node as usize] as usize..self.in_start[node as usize + 1] as usize]
    }
    /// Edges out of `node`, in creation order.
    pub fn uses(&self, node: u32) -> &[u32] {
        &self.out_edges
            [self.out_start[node as usize] as usize..self.out_start[node as usize + 1] as usize]
    }
}

impl Simulation {
    /// What this simulation holds, for a cache bounded by bytes.
    pub fn bytes(&self) -> u64 {
        let words = self.instructions.len() * 2
            + self.input_start.len()
            + self.inputs.len() * 2
            + self.adjacency.in_start.len() * 2
            + self.edges.len() * 2;
        (self.nodes.len() * std::mem::size_of::<Node>()
            + self.edges.len() * std::mem::size_of::<Edge>()
            + self.instruction_live.len()
            + words * 4
            + self.cells.len() * std::mem::size_of::<Cell>()) as u64
    }
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

/// The constant base of an absolute address key.
const ABSOLUTE: Value = Value {
    node: NONE,
    result: NONE,
};

/// A store a later load of the same address may read exactly.
#[derive(Clone, Copy)]
struct Fact {
    /// Full-width type class (`i32`, `i64`, `f32`, `f64`, `v128`).
    class: u8,
    width: u8,
    value: Value,
    at: u32,
}

/// Exact store facts of the current basic block. A store through one base
/// may write any address another base or a constant names, so at most one
/// base (or the constant addresses) holds facts in each memory; stores
/// through the same base at other offsets keep each other's facts.
#[derive(Default)]
struct Facts {
    memories: Vec<(u32, Value, BTreeMap<u64, Fact>)>,
}

impl Facts {
    fn clear(&mut self) {
        self.memories.clear();
    }
    /// A store of `width` bytes at `base + offset`; a full-width one
    /// (`class`) is kept for later loads.
    fn store(
        &mut self,
        memory: u32,
        base: Value,
        offset: u64,
        width: u8,
        fact: Option<(u8, Value, u32)>,
    ) {
        self.memories
            .retain(|(other, held, _)| *other != memory || *held == base);
        let position = match self.memories.iter().position(|(other, _, _)| *other == memory) {
            Some(position) => position,
            None => {
                self.memories.push((memory, base, BTreeMap::new()));
                self.memories.len() - 1
            }
        };
        let facts = &mut self.memories[position].2;
        let end = offset.saturating_add(u64::from(width));
        let overwritten: Vec<u64> = facts
            .range(offset.saturating_sub(15)..end)
            .filter(|(start, held)| start.saturating_add(u64::from(held.width)) > offset)
            .map(|(start, _)| *start)
            .collect();
        for start in overwritten {
            facts.remove(&start);
        }
        if let Some((class, value, at)) = fact {
            facts.insert(
                offset,
                Fact {
                    class,
                    width,
                    value,
                    at,
                },
            );
        }
    }
    fn load(&self, memory: u32, base: Value, offset: u64, class: u8) -> Option<Fact> {
        self.memories
            .iter()
            .find(|(other, held, _)| *other == memory && *held == base)
            .and_then(|(_, _, facts)| facts.get(&offset))
            .filter(|fact| fact.class == class)
            .copied()
    }
}

/// One plain load or store, for memory cells.
struct Access {
    node: u32,
    instruction: u32,
    store: bool,
    cell: Cell,
    /// A store's value.
    value: Value,
    /// The outermost loop around the access, `NONE` outside loops.
    outer: u32,
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
    /// Locals each loop writes that are read again, by loop instruction.
    loop_writes: HashMap<u32, Vec<u32>>,
    /// Instruction index of each local's last `local.get`, `NONE` if none.
    last_get: Vec<u32>,
    /// Instruction index of each open loop, outermost first.
    loops: Vec<u32>,
    /// End instruction of each closed outermost loop, by its start.
    loop_ends: HashMap<u32, u32>,
    /// The instruction being simulated.
    at: u32,
    facts: Facts,
    /// The latest `global.set` of each global in this block.
    globals: HashMap<u32, (Value, u32)>,
    /// Address keys resolved so far, by node.
    keys: HashMap<u32, (Value, u64)>,
    /// `i32.add` and `i64.add` nodes with a constant operand: the other
    /// operand and the constant.
    adds: HashMap<u32, (Value, u64)>,
    accesses: Vec<Access>,
    settings: Settings,
    predicted: u64,
    ticks: u64,
    cancelled: &'m AtomicBool,
    progress: Option<&'m Progress>,
    /// Set once the request is cancelled inside an instruction; the main loop
    /// stops at that instruction.
    exhausted: Option<&'static str>,
    omissions: Vec<String>,
    underflow_noted: bool,
}

/// A plain load or store: whether it stores, its width, its full-width type
/// class (for exact forwarding), its memory and its static offset. Atomic
/// accesses take part in memory cells only.
fn access(op: &Operator<'_>) -> Option<(bool, u8, Option<u8>, u32, u64)> {
    use Operator as O;
    let (store, width, class, memarg) = match op {
        O::I32Load { memarg } => (false, 4, Some(0), memarg),
        O::I64Load { memarg } => (false, 8, Some(1), memarg),
        O::F32Load { memarg } => (false, 4, Some(2), memarg),
        O::F64Load { memarg } => (false, 8, Some(3), memarg),
        O::V128Load { memarg } => (false, 16, Some(4), memarg),
        O::I32Load8S { memarg }
        | O::I32Load8U { memarg }
        | O::I64Load8S { memarg }
        | O::I64Load8U { memarg }
        | O::I32AtomicLoad8U { memarg }
        | O::I64AtomicLoad8U { memarg } => (false, 1, None, memarg),
        O::I32Load16S { memarg }
        | O::I32Load16U { memarg }
        | O::I64Load16S { memarg }
        | O::I64Load16U { memarg }
        | O::I32AtomicLoad16U { memarg }
        | O::I64AtomicLoad16U { memarg } => (false, 2, None, memarg),
        O::I64Load32S { memarg }
        | O::I64Load32U { memarg }
        | O::I32AtomicLoad { memarg }
        | O::I64AtomicLoad32U { memarg } => (false, 4, None, memarg),
        O::I64AtomicLoad { memarg } => (false, 8, None, memarg),
        O::I32Store { memarg } => (true, 4, Some(0), memarg),
        O::I64Store { memarg } => (true, 8, Some(1), memarg),
        O::F32Store { memarg } => (true, 4, Some(2), memarg),
        O::F64Store { memarg } => (true, 8, Some(3), memarg),
        O::V128Store { memarg } => (true, 16, Some(4), memarg),
        O::I32Store8 { memarg }
        | O::I64Store8 { memarg }
        | O::I32AtomicStore8 { memarg }
        | O::I64AtomicStore8 { memarg } => (true, 1, None, memarg),
        O::I32Store16 { memarg }
        | O::I64Store16 { memarg }
        | O::I32AtomicStore16 { memarg }
        | O::I64AtomicStore16 { memarg } => (true, 2, None, memarg),
        O::I64Store32 { memarg }
        | O::I32AtomicStore { memarg }
        | O::I64AtomicStore32 { memarg } => (true, 4, None, memarg),
        O::I64AtomicStore { memarg } => (true, 8, None, memarg),
        _ => return None,
    };
    Some((store, width, class, memarg.memory, memarg.offset))
}

fn atomic(op: &Operator<'_>) -> bool {
    crate::wasm::mnemonic(op).contains(".atomic")
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
/// space; `cancelled` is the caller's request, which stops the simulation
/// once it goes away.
pub fn simulate(
    module: &Module<'_>,
    function: u32,
    body: &FunctionBody<'_>,
    cancelled: &AtomicBool,
) -> Result<Simulation> {
    simulate_with(module, function, body, cancelled, Settings::default(), None)
}

/// [`simulate`] with explicit settings and an optional progress reader.
pub fn simulate_with(
    module: &Module<'_>,
    function: u32,
    body: &FunctionBody<'_>,
    cancelled: &AtomicBool,
    settings: Settings,
    progress: Option<&Progress>,
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
        last_get: vec![NONE; local_count as usize],
        loops: Vec::new(),
        loop_ends: HashMap::new(),
        at: 0,
        facts: Facts::default(),
        globals: HashMap::new(),
        keys: HashMap::new(),
        adds: HashMap::new(),
        accesses: Vec::new(),
        settings,
        predicted: 0,
        ticks: 0,
        cancelled,
        progress,
        exhausted: None,
        omissions: Vec::new(),
        underflow_noted: false,
    };
    let (body_instructions, mut stopped_at) = sim.prescan(function, body)?;
    if let Some(progress) = progress {
        progress
            .total
            .store(u64::from(body_instructions), Ordering::Relaxed);
    }
    sim.nodes.reserve(body_instructions as usize);
    sim.instructions.reserve(body_instructions as usize);
    sim.instruction_nodes.reserve(body_instructions as usize);
    sim.instruction_live.reserve(body_instructions as usize);
    sim.input_start.reserve(body_instructions as usize);
    if stopped_at.is_none() {
        let mut reader = body.get_operators_reader().map_err(bad)?;
        let mut ended = false;
        while !reader.eof() {
            let position = reader.original_position() as u32;
            if sim.instructions.len() & 1023 == 0 {
                if cancelled.load(Ordering::Relaxed) {
                    sim.omissions.push(format!(
                        "Simulation cancelled at byte {position}; value flow after it is not computed."
                    ));
                    stopped_at = Some(position);
                    break;
                }
                if let Some(progress) = progress {
                    progress
                        .done
                        .store(sim.instructions.len() as u64, Ordering::Relaxed);
                }
            }
            let (op, offset) = reader.read_with_offset().map_err(bad)?;
            if ended {
                return Err(Error::protocol(
                    "WASM function has instructions after its end",
                ));
            }
            let index = sim.instructions.len() as u32;
            sim.at = index;
            sim.instructions.push(offset as u32);
            sim.instruction_nodes.push(NONE);
            sim.instruction_live.push(sim.reachable);
            sim.input_start.push(sim.inputs.len() as u32);
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
    if let Some(progress) = progress {
        progress
            .done
            .store(sim.instructions.len() as u64, Ordering::Relaxed);
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
    let mut cells = Vec::new();
    if settings.cells {
        cells = sim.memory_cells();
    }
    if settings.control && !cancelled.load(Ordering::Relaxed) {
        sim.control_edges(body)?;
    }
    let adjacency = Adjacency::new(sim.nodes.len(), &sim.edges);
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
        omissions: sim.omissions,
        open_joins,
        cells,
        body_instructions,
        predicted_bytes: sim.predicted,
        adjacency,
    })
}

/// One open frame of the prescan.
struct Scanned {
    /// Instruction index of a loop, `NONE` for any other frame.
    loop_start: u32,
    kind: Kind,
    /// Locals written inside the frame that are read again.
    written: HashSet<u32>,
    /// Paths that reach the frame's merge besides falling through its end.
    incoming: u64,
    params: u32,
    results: u32,
}

/// Bytes one simulated instruction holds: its node, about two edges, its
/// rows in the instruction tables, about two recorded inputs, its share of
/// the adjacency and of the control flow graph.
const INSTRUCTION_BYTES: u64 = 20 + 2 * 20 + 13 + 2 * 8 + 2 * 4 + 2 * 2 * 4 + 16;
/// A join's node and adjacency row; each incoming edge adds `EDGE_BYTES`.
const JOIN_BYTES: u64 = 20 + 8;
const EDGE_BYTES: u64 = 20 + 8;
/// One local's entry value recorded by an open frame.
const SAVED_BYTES: u64 = 24;
/// One local carried on a stored incoming path.
const STORED_BYTES: u64 = 16;

impl Sim<'_, '_> {
    /// Whether `local` is read again after instruction `at`: a `local.get`
    /// past `at`, or past the start of the outermost loop around `at`, since
    /// a back edge reaches every instruction of its loop. Once a local is not
    /// read again it never is, so a write, join or entry value of it is dead.
    fn live(&self, local: u32, at: u32) -> bool {
        let read = self.last_get[local as usize];
        read != NONE && read > self.loops.first().copied().unwrap_or(at)
    }

    /// Two passes before anything is simulated. The first finds each
    /// local's last read and counts the instructions. The second records
    /// which live locals each frame writes, so a loop's header joins exist
    /// before the back edges that feed them are read, and predicts the
    /// memory the simulation will hold from its instructions, joins, entry
    /// values and stored paths. A write lands in the innermost frame and a
    /// frame's set joins its parent's at `end`, so the pass costs one unit
    /// per write plus one per local a frame passes on: what the simulation's
    /// own entry values cost. A prediction over the budget refuses the body
    /// as soon as it is reached, so the prescan is bounded by it too.
    /// Returns the body's instruction count and a stop, for a cancelled
    /// request.
    fn prescan(&mut self, function: u32, body: &FunctionBody<'_>) -> Result<(u32, Option<u32>)> {
        let mut reader = body.get_operators_reader().map_err(bad)?;
        let mut index = 0u32;
        while !reader.eof() {
            if index & 4095 == 0 && self.cancelled.load(Ordering::Relaxed) {
                let position = reader.original_position() as u32;
                self.omissions.push(format!(
                    "Simulation cancelled at byte {position}; value flow is not computed."
                ));
                return Ok((index, Some(position)));
            }
            if let Operator::LocalGet { local_index } = reader.read().map_err(bad)?
                && let Some(read) = self.last_get.get_mut(local_index as usize)
            {
                *read = index;
            }
            index += 1;
        }
        let count = index;
        self.predicted = u64::from(count) * INSTRUCTION_BYTES;
        let mut reader = body.get_operators_reader().map_err(bad)?;
        let mut open: Vec<Scanned> = Vec::new();
        let mut tries = 0u64;
        let mut joins = 0u64;
        let mut index = 0u32;
        while !reader.eof() {
            if index & 4095 == 0 && self.cancelled.load(Ordering::Relaxed) {
                let position = reader.original_position() as u32;
                self.omissions.push(format!(
                    "Simulation cancelled at byte {position}; value flow is not computed."
                ));
                return Ok((count, Some(position)));
            }
            let op = reader.read().map_err(bad)?;
            let effect = wasm_stack::effect(&op);
            let target = |open: &Vec<Scanned>, depth: u32| open.len().checked_sub(depth as usize + 1);
            match effect {
                Effect::Open {
                    kind, block_type, ..
                } => {
                    let (params, results) =
                        self.module.types.block_arity(block_type).unwrap_or((0, 0));
                    if kind == Kind::Loop {
                        self.loops.push(index);
                    }
                    if matches!(kind, Kind::Try | Kind::TryTable) {
                        tries += 1;
                    }
                    open.push(Scanned {
                        loop_start: if kind == Kind::Loop { index } else { NONE },
                        kind,
                        written: HashSet::new(),
                        // An `if` also merges its other arm.
                        incoming: u64::from(kind == Kind::If),
                        params,
                        results,
                    });
                }
                Effect::Catch { .. } => {
                    if let Some(frame) = open.last_mut() {
                        frame.incoming += 1;
                    }
                }
                Effect::Branch { depth, .. } | Effect::BrOn { depth, .. } => {
                    if let Some(at) = target(&open, depth) {
                        open[at].incoming += 1;
                    }
                }
                Effect::BrTable(targets) => {
                    let mut depths: Vec<u32> = targets.targets().filter_map(|t| t.ok()).collect();
                    depths.push(targets.default());
                    depths.sort_unstable();
                    depths.dedup();
                    for depth in depths {
                        if let Some(at) = target(&open, depth) {
                            open[at].incoming += 1;
                        }
                    }
                }
                Effect::End | Effect::Delegate { .. } => {
                    if let Some(frame) = open.pop() {
                        if frame.kind == Kind::Loop {
                            self.loops.pop();
                        }
                        if matches!(frame.kind, Kind::Try | Kind::TryTable | Kind::Catch) {
                            tries = tries.saturating_sub(1);
                        }
                        let written = frame.written.len() as u64;
                        let frame_joins = if frame.loop_start != NONE {
                            written + u64::from(frame.params)
                        } else if frame.incoming >= 1 {
                            let live = frame
                                .written
                                .iter()
                                .filter(|local| self.live(**local, index))
                                .count() as u64;
                            live + u64::from(frame.results)
                        } else {
                            0
                        };
                        joins += frame_joins;
                        let paths = frame.incoming + 1;
                        self.predicted = self.predicted.saturating_add(
                            frame_joins * (JOIN_BYTES + paths * EDGE_BYTES)
                                + written * SAVED_BYTES
                                + if frame.loop_start == NONE {
                                    frame.incoming * written * STORED_BYTES
                                } else {
                                    0
                                },
                        );
                        if let Some(parent) = open.last_mut() {
                            parent.written.extend(frame.written.iter().copied());
                        }
                        if frame.loop_start != NONE {
                            let mut locals: Vec<u32> = frame.written.into_iter().collect();
                            locals.sort_unstable();
                            self.loop_writes.insert(frame.loop_start, locals);
                        }
                        self.refuse_past_budget(function, count, joins)?;
                    }
                }
                _ => {
                    if let Operator::LocalSet { local_index } | Operator::LocalTee { local_index } =
                        &op
                        && (*local_index as usize) < self.last_get.len()
                        && self.live(*local_index, index)
                        && let Some(frame) = open.last_mut()
                        && frame.written.insert(*local_index)
                    {
                        self.predicted = self
                            .predicted
                            .saturating_add(tries * STORED_BYTES + SAVED_BYTES);
                        if frame.written.len() & 4095 == 0 {
                            self.refuse_past_budget(function, count, joins)?;
                        }
                    }
                }
            }
            index += 1;
        }
        // A body that never closes its frames is malformed; the main pass
        // says so. Loops still open get their sets so their joins exist.
        while let Some(frame) = open.pop() {
            if let Some(parent) = open.last_mut() {
                parent.written.extend(frame.written.iter().copied());
            }
            if frame.loop_start != NONE {
                let mut locals: Vec<u32> = frame.written.into_iter().collect();
                locals.sort_unstable();
                self.loop_writes.insert(frame.loop_start, locals);
            }
        }
        self.loops.clear();
        self.refuse_past_budget(function, count, joins)?;
        Ok((count, None))
    }

    /// The one memory guard: a body whose predicted simulation exceeds what
    /// this machine can spare is refused before it allocates.
    fn refuse_past_budget(&self, function: u32, instructions: u32, joins: u64) -> Result<()> {
        if self.predicted <= self.settings.memory {
            return Ok(());
        }
        let gib = |bytes: u64| bytes as f64 / f64::from(1u32 << 30);
        Err(Error::new(
            400,
            format!(
                "Value flow of WASM function {function} would hold more than {:.1} GiB ({instructions} instructions, at least {joins} joins), past the {:.1} GiB this machine can spare for one simulation; nothing was simulated.",
                gib(self.predicted),
                gib(self.settings.memory)
            ),
        )
        .with_code(Code::ResourceLimit))
    }

    /// Counts work toward the next cancellation poll. False, with the reason
    /// kept for the main loop, once the request is cancelled.
    fn tick(&mut self, units: u64) -> bool {
        if self.exhausted.is_some() {
            return false;
        }
        let before = self.ticks;
        self.ticks += units;
        if before >> 12 != self.ticks >> 12 && self.cancelled.load(Ordering::Relaxed) {
            self.exhausted = Some("Simulation cancelled");
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
            join: Join::None,
            results: results as u16,
            offset,
            instruction,
            index,
            aux: 0,
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
            to,
            via_offset,
            result: from.result as u16,
            operand: operand as u16,
            kind,
            via,
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
        self.tick(values.len() as u64);
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
        // Nothing reads a dead local again: no merge, restore or handler
        // needs its entry value or this definition.
        if !self.live(local, self.at) {
            self.locals[local as usize] = value;
            return;
        }
        let old = self.locals[local as usize];
        let mut walked = 0u64;
        for frame in self.control.iter_mut().rev() {
            if frame.state.saved.contains_key(&local) {
                break;
            }
            walked += 1;
            frame.state.saved.insert(local, old);
        }
        self.tick(walked);
        if self.reachable {
            for position in 0..self.open_tries.len() {
                if !self.tick(1) {
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
        self.tick(locals.len() as u64);
        locals
    }

    fn returns(&mut self, offset: u32, index: u32, values: &[Value]) -> u32 {
        self.tick(values.len() as u64);
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
        if !self.tick(values.len() as u64) {
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
                    if !self.tick(1) {
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
            self.nodes[phi as usize].aux = slot as u32;
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
            if !self.tick(1) {
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
        self.tick(saved.len() as u64);
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
        // Handlers start here: a local nothing reads again needs no join.
        by_local.retain(|(local, _, _)| self.live(*local, self.at));
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
                if !self.tick(1) {
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
            if let Some(start) = self.loops.pop()
                && self.loops.is_empty()
            {
                self.loop_ends.insert(start, index);
            }
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
        self.tick(results as u64 * incomings.len() as u64);
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
            self.nodes[phi as usize].aux = slot as u32;
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
            if !self.tick(incomings.len() as u64) {
                break;
            }
            let value_in = |incoming: &Incoming| {
                incoming
                    .locals
                    .binary_search_by_key(&local, |(l, _)| *l)
                    .map_or(entry, |found| incoming.locals[found].1)
            };
            let first = value_in(&incomings[0]);
            // A local not read again needs no join: any incoming value will do.
            if !self.live(local, index)
                || incomings
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
        self.tick(count as u64);
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
            if !self.tick(u64::from(count) + 1) {
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
                        if !self.tick(1) {
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
                    self.tick(locals.len() as u64);
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
        path
    }

    /// A block boundary, call, fence or memory operation: no store or
    /// `global.set` before it stands for a load or `global.get` after it.
    fn clear_store(&mut self) {
        self.facts.clear();
        self.globals.clear();
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
                    Kind::Loop => {
                        self.loops.push(index);
                        self.enter_loop(offset, index);
                    }
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
                self.tick(depths.len() as u64);
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
            // The clause's own tag decides, not the index: `NONE` is this
            // simulation's catch-all tag, and a clause naming tag index
            // u32::MAX names a tag no module can declare.
            let Some(values) = clause.values else {
                let tag = clause.tag.unwrap_or(NONE);
                return Err(Stop::Unsupported(format!(
                    "A catch of undeclared tag {tag}"
                )));
            };
            let tag = clause.tag.unwrap_or(NONE);
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
                self.nodes[node as usize].aux = table;
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
        self.nodes[node as usize].results = results as u16;
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
                let node = self.consume(NodeKind::GlobalGet, index, *global_index, 1, &[], |_| {
                    EdgeKind::Operand
                });
                if let Some((value, at)) = self.globals.get(global_index).copied() {
                    self.edge(
                        value,
                        node,
                        0,
                        EdgeKind::ForwardedGlobal,
                        Via::GlobalSet,
                        at,
                    );
                }
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
                let value = self.materialize(value);
                self.globals.insert(*global_index, (value, offset));
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
            Operator::AtomicFence => self.facts.clear(),
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
                    NodeKind::Const => {
                        let bits = const_bits(other);
                        let constant = &mut self.nodes[node as usize];
                        constant.index = bits as u32;
                        constant.aux = (bits >> 32) as u32;
                    }
                    NodeKind::Operation => {
                        if let (Operator::I32Add | Operator::I64Add, [a, b]) =
                            (other, args.as_slice())
                        {
                            let constant = |value: &Value| {
                                (value.node != NONE
                                    && self.nodes[value.node as usize].kind == NodeKind::Const)
                                    .then(|| self.nodes[value.node as usize].constant())
                            };
                            if let Some(bits) = constant(b) {
                                self.adds.insert(node, (*a, bits));
                            } else if let Some(bits) = constant(a) {
                                self.adds.insert(node, (*b, bits));
                            }
                        }
                    }
                    NodeKind::Load | NodeKind::Store => {
                        self.memory_access(other, kind, node, index, offset, &args);
                    }
                    NodeKind::Atomic => self.facts.clear(),
                    NodeKind::Memory if !matches!(other, Operator::MemorySize { .. }) => {
                        self.facts.clear();
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// The address key of `value`: a base value and a displacement, or
    /// `ABSOLUTE` and the constant address. `local.get` and `local.tee` read
    /// through to the definition, and an add of a constant moves the
    /// displacement, so every `local.get regs; i32.load offset=16` of one
    /// definition of `regs` names one key. Keys are kept per node, so a chain
    /// is walked once.
    fn address_key(&mut self, value: Value) -> (Value, u64) {
        let mut chain: Vec<(u32, u64)> = Vec::new();
        let mut current = value;
        let mut total = 0u64;
        let key = loop {
            if current.node == NONE {
                break (current, total);
            }
            if let Some((base, displacement)) = self.keys.get(&current.node) {
                break (*base, total.wrapping_add(*displacement));
            }
            let node = self.nodes[current.node as usize];
            match node.kind {
                NodeKind::Const => break (ABSOLUTE, total.wrapping_add(node.constant())),
                NodeKind::LocalGet | NodeKind::LocalTee if node.instruction != NONE => {
                    chain.push((current.node, total));
                    current = self.inputs[self.input_start[node.instruction as usize] as usize];
                }
                NodeKind::Operation => match self.adds.get(&current.node).copied() {
                    Some((other, bits)) => {
                        chain.push((current.node, total));
                        total = total.wrapping_add(bits);
                        current = other;
                    }
                    None => break (current, total),
                },
                _ => break (current, total),
            }
        };
        for (node, before) in chain {
            self.keys.insert(node, (key.0, key.1.wrapping_sub(before)));
        }
        key
    }

    /// Exact forwarding and the cell record of one load or store node.
    fn memory_access(
        &mut self,
        op: &Operator<'_>,
        kind: NodeKind,
        node: u32,
        index: u32,
        offset: u32,
        args: &[Value],
    ) {
        let Some((store, width, class, memory, displacement)) = access(op) else {
            // A lane store or another shape no key describes may change any
            // address of its memory.
            if kind == NodeKind::Store {
                self.facts.clear();
            }
            return;
        };
        let Some(address) = args.first().copied() else {
            return;
        };
        let (base, at) = self.address_key(address);
        let cell = Cell {
            memory,
            base,
            offset: at.wrapping_add(displacement),
            width,
        };
        let atomic = atomic(op);
        let outer = self.loops.first().copied().unwrap_or(NONE);
        if store {
            let value = args.get(1).copied().map_or(ABSOLUTE, |v| self.materialize(v));
            if atomic {
                self.facts.clear();
            } else {
                self.facts.store(
                    memory,
                    base,
                    cell.offset,
                    width,
                    class.map(|class| (class, value, offset)),
                );
            }
            if self.settings.cells {
                self.accesses.push(Access {
                    node,
                    instruction: index,
                    store: true,
                    cell,
                    value,
                    outer,
                });
            }
            return;
        }
        if let Some(class) = class
            && !atomic
            && let Some(fact) = self.facts.load(memory, base, cell.offset, class)
        {
            // Proven: nothing between may have written these bytes.
            self.edge(
                fact.value,
                node,
                1,
                EdgeKind::ForwardedStore,
                Via::Store,
                fact.at,
            );
            return;
        }
        if self.settings.cells {
            self.accesses.push(Access {
                node,
                instruction: index,
                store: false,
                cell,
                value: ABSOLUTE,
                outer,
            });
        }
    }

    /// One `memory_cell` node per address key with both stores and loads.
    /// A load joins the cell only when one of the key's stores comes before
    /// it or sits in the same outermost loop, since otherwise no path from a
    /// store reaches it. The edges are `memory_may`: a store through another
    /// base can alias the same bytes, so a cell is possible flow.
    fn memory_cells(&mut self) -> Vec<Cell> {
        let mut groups: HashMap<Cell, Vec<u32>> = HashMap::new();
        for (position, access) in self.accesses.iter().enumerate() {
            groups.entry(access.cell).or_default().push(position as u32);
        }
        let mut keyed: Vec<(Cell, Vec<u32>)> = groups.into_iter().collect();
        // Creation order follows the body, so ids are deterministic.
        keyed.sort_by_key(|(_, members)| members[0]);
        let mut cells = Vec::new();
        for (cell, members) in keyed {
            if !self.tick(members.len() as u64) {
                break;
            }
            let stores: Vec<u32> = members
                .iter()
                .copied()
                .filter(|member| self.accesses[*member as usize].store)
                .collect();
            if stores.is_empty() {
                continue;
            }
            let first_store = self.accesses[stores[0] as usize].instruction;
            let store_at: Vec<u32> = stores
                .iter()
                .map(|member| self.accesses[*member as usize].instruction)
                .collect();
            let loads: Vec<u32> = members
                .iter()
                .copied()
                .filter(|member| {
                    let load = &self.accesses[*member as usize];
                    if load.store {
                        return false;
                    }
                    if first_store < load.instruction {
                        return true;
                    }
                    load.outer != NONE && {
                        let end = self.loop_ends.get(&load.outer).copied().unwrap_or(NONE);
                        let from = store_at.partition_point(|at| *at < load.outer);
                        store_at.get(from).is_some_and(|at| *at <= end)
                    }
                })
                .collect();
            if loads.is_empty() {
                continue;
            }
            let first = self.accesses[members[0] as usize].node;
            let offset = self.nodes[first as usize].offset;
            let node = self.node(NodeKind::MemoryCell, offset, NONE, cells.len() as u32, 1);
            cells.push(cell);
            for (position, member) in stores.iter().enumerate() {
                let store = &self.accesses[*member as usize];
                let (value, at) = (store.value, self.nodes[store.node as usize].offset);
                self.edge(
                    value,
                    node,
                    position.min(u16::MAX as usize) as u32,
                    EdgeKind::MemoryMay,
                    Via::Store,
                    at,
                );
            }
            for member in loads {
                let load = self.accesses[member as usize].node;
                self.edge(Value::of(node), load, 1, EdgeKind::MemoryMay, Via::None, NONE);
            }
        }
        cells
    }

    /// `control` edges: into each join from the decisions its incoming
    /// paths depend on (and from the incoming branch itself when it is
    /// conditional), and into each decision from the decisions it depends
    /// on, so a backward walk from a join reaches the selector that chose
    /// it and everything that decided that.
    fn control_edges(&mut self, body: &FunctionBody<'_>) -> Result<()> {
        let flow = crate::wasm_graph::control_flow(body, self.cancelled)?;
        let dependences = crate::control_dependence::dependences(&flow, self.cancelled)?;
        let simulated = self.instructions.len() as u32;
        let decision = |sim: &Self, instruction: u32| -> Option<u32> {
            let node = *sim.instruction_nodes.get(instruction as usize)?;
            (node != NONE && sim.nodes[node as usize].kind == NodeKind::Branch).then_some(node)
        };
        let last_of = |block: u32| -> u32 {
            flow.leaders
                .get(block as usize + 1)
                .map_or(simulated.saturating_sub(1), |next| next - 1)
        };
        let instruction_at = |sim: &Self, offset: u32| -> Option<u32> {
            sim.instructions.binary_search(&offset).ok().map(|i| i as u32)
        };
        let mut pairs: Vec<(u32, u32)> = Vec::new();
        for position in 0..self.edges.len() {
            if position & 4095 == 0 && self.cancelled.load(Ordering::Relaxed) {
                return Ok(());
            }
            let edge = self.edges[position];
            if edge.kind != EdgeKind::Merge || edge.via_offset == NONE {
                continue;
            }
            let Some(at) = instruction_at(self, edge.via_offset) else {
                continue;
            };
            // The path's last instruction: a fallthrough or loop entry ends
            // just before the `end` or `loop` that names it.
            let transfer = match edge.via {
                Via::Fallthrough | Via::Entry => at.saturating_sub(1),
                _ => at,
            };
            if transfer >= simulated {
                continue;
            }
            if matches!(edge.via, Via::BrIf | Via::BrTable | Via::IfFalse)
                && let Some(node) = decision(self, at)
            {
                pairs.push((edge.to, node));
            }
            for block in dependences.of(flow.block_of(transfer)) {
                if let Some(node) = decision(self, last_of(*block)) {
                    pairs.push((edge.to, node));
                }
            }
        }
        for block in 0..flow.leaders.len() as u32 {
            let Some(own) = decision(self, last_of(block)) else {
                continue;
            };
            for other in dependences.of(block) {
                if let Some(node) = decision(self, last_of(*other))
                    && node != own
                {
                    pairs.push((own, node));
                }
            }
        }
        pairs.sort_unstable();
        pairs.dedup();
        for (to, from) in pairs {
            let at = self.nodes[from as usize].offset;
            self.edge(Value::of(from), to, 0, EdgeKind::Control, Via::None, at);
        }
        Ok(())
    }
}
