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
//! Unifying this simulation with the readable lifted view's expression lifter
//! is planned follow-up work; neither depends on the other today.
use crate::error::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use wasmparser::{
    BlockType, CompositeInnerType, ContType, ElementItems, ExternalKind, FuncType, FunctionBody,
    HeapType, ModuleArity, Operator, Parser, Payload, RefType, SubType, TypeRef, UnpackedIndex,
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
    sub_types: Vec<SubType>,
    /// The type index of every function, imported functions first.
    pub func_types: Vec<u32>,
    pub imported_functions: u32,
    tags: Vec<u32>,
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
            sub_types: Vec::new(),
            func_types: Vec::new(),
            imported_functions: 0,
            tags: Vec::new(),
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
                        module.sub_types.extend(group.map_err(bad)?.into_types());
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader {
                        let import = import.map_err(bad)?;
                        match import.ty {
                            TypeRef::Func(ty) => {
                                module.func_types.push(ty);
                                module.imported_functions += 1;
                                module
                                    .imports
                                    .push((bounded(import.module), bounded(import.name)));
                            }
                            TypeRef::Tag(tag) => module.tags.push(tag.func_type_idx),
                            _ => {}
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for ty in reader {
                        module.func_types.push(ty.map_err(bad)?);
                    }
                }
                Payload::TagSection(reader) => {
                    for tag in reader {
                        module.tags.push(tag.map_err(bad)?.func_type_idx);
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
            != module.func_types.len() as u64
        {
            return Err(Error::protocol(
                "WASM function and code section counts differ",
            ));
        }
        Ok(module)
    }

    /// Parameter and result counts of a function type, `None` for another
    /// composite type or an index past the type section.
    pub fn type_arity(&self, ty: u32) -> Option<(u32, u32)> {
        let arity = Arity(self);
        arity.sub_type_arity(arity.sub_type_at(ty)?).filter(|_| {
            matches!(
                self.sub_types[ty as usize].composite_type.inner,
                CompositeInnerType::Func(_)
            )
        })
    }

    fn block_arity(&self, ty: BlockType) -> Option<(u32, u32)> {
        match ty {
            BlockType::Empty => Some((0, 0)),
            BlockType::Type(_) => Some((0, 1)),
            BlockType::FuncType(index) => self.type_arity(index),
        }
    }

    fn tag_params(&self, tag: u32) -> Option<u32> {
        self.type_arity(*self.tags.get(tag as usize)?)
            .map(|(params, _)| params)
    }
}

struct Arity<'m, 'a>(&'m Module<'a>);

impl ModuleArity for Arity<'_, '_> {
    fn sub_type_at(&self, type_idx: u32) -> Option<&SubType> {
        self.0.sub_types.get(type_idx as usize)
    }
    fn tag_type_arity(&self, at: u32) -> Option<(u32, u32)> {
        let ty = *self.0.tags.get(at as usize)?;
        self.sub_type_arity(self.sub_type_at(ty)?)
    }
    fn type_index_of_function(&self, function_idx: u32) -> Option<u32> {
        self.0.func_types.get(function_idx as usize).copied()
    }
    fn func_type_of_cont_type(&self, c: &ContType) -> Option<&FuncType> {
        match &self
            .sub_type_at(c.0.as_module_index()?)?
            .composite_type
            .inner
        {
            CompositeInnerType::Func(function) => Some(function),
            _ => None,
        }
    }
    fn sub_type_of_ref_type(&self, rt: &RefType) -> Option<&SubType> {
        match rt.heap_type() {
            HeapType::Concrete(UnpackedIndex::Module(index)) => self.sub_type_at(index),
            _ => None,
        }
    }
    // Control operators are simulated directly, so the generic arity is only
    // asked about operators that never consult the control stack.
    fn control_stack_height(&self) -> u32 {
        0
    }
    fn label_block(&self, _depth: u32) -> Option<(BlockType, wasmparser::FrameKind)> {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    Function,
    Block,
    Loop,
    If,
    Else,
    Try,
    Catch,
    TryTable,
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

struct Frame {
    kind: FrameKind,
    join: Join,
    offset: u32,
    instruction: u32,
    height: usize,
    params: u32,
    results: u32,
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

impl Frame {
    fn label_arity(&self) -> u32 {
        if self.kind == FrameKind::Loop {
            self.params
        } else {
            self.results
        }
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
    frames: Vec<Frame>,
    open_tries: Vec<usize>,
    reachable: bool,
    unknown: u32,
    loop_writes: HashMap<u32, Vec<u32>>,
    /// The latest full-width store to a constant address in this block.
    store: Option<StoreFact>,
    work: u64,
    limits: Limits,
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
    let type_index = *module
        .func_types
        .get(function as usize)
        .ok_or_else(|| Error::new(404, "WASM function is not declared"))?;
    let (params, results) = module.type_arity(type_index).ok_or_else(|| {
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
        frames: vec![Frame {
            kind: FrameKind::Function,
            join: Join::Block,
            offset: body_offset,
            instruction: NONE,
            height: 0,
            params: 0,
            results,
            param_values: Vec::new(),
            saved: HashMap::new(),
            incoming: Vec::new(),
            then_end: None,
            loop_param_phis: Vec::new(),
            loop_local_phis: Vec::new(),
            reachable_at_entry: true,
            try_writes: Vec::new(),
            catch_phis: None,
            catches: Vec::new(),
        }],
        open_tries: Vec::new(),
        reachable: true,
        unknown: NONE,
        loop_writes: HashMap::new(),
        store: None,
        work: 0,
        limits,
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
        for frame in sim
            .frames
            .iter()
            .filter(|frame| frame.kind == FrameKind::Loop)
        {
            let phis = frame
                .loop_param_phis
                .iter()
                .chain(frame.loop_local_phis.iter().map(|(_, phi)| phi));
            open_joins.extend(phis.copied());
            sim.omissions.push(format!(
                "The loop at byte {} was still open where simulation stopped at byte {stop}; values read in it may also arrive by back edges after the stop, and its header joins are incomplete.",
                frame.offset
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
            match op {
                Operator::Loop { .. } => {
                    loops.push(open.len());
                    open.push(Some((index, HashSet::new())));
                }
                Operator::Block { .. }
                | Operator::If { .. }
                | Operator::Try { .. }
                | Operator::TryTable { .. } => open.push(None),
                Operator::End | Operator::Delegate { .. } => {
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
                Operator::LocalSet { local_index } | Operator::LocalTee { local_index } => {
                    if let Some(Some((_, set))) = loops.last().map(|at| &mut open[*at]) {
                        set.insert(local_index);
                        if !self.spend(1) {
                            break;
                        }
                    }
                }
                _ => {}
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
        let height = self.frames.last().map_or(0, |frame| frame.height);
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
        let height = self.frames.last().map_or(0, |frame| frame.height);
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
        match self.frames.len().checked_sub(depth as usize + 1) {
            Some(target) => {
                let arity = self.frames[target].label_arity();
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
        for frame in self.frames.iter_mut().rev() {
            if frame.saved.contains_key(&local) {
                break;
            }
            walked += 1;
            frame.saved.insert(local, old);
        }
        self.spend(walked);
        if self.reachable {
            for position in 0..self.open_tries.len() {
                if !self.spend(1) {
                    break;
                }
                let frame = self.open_tries[position];
                self.frames[frame].try_writes.push((local, value, offset));
            }
        }
        self.locals[local as usize] = value;
    }

    fn snapshot(&mut self, frame: usize) -> Vec<(u32, Value)> {
        let mut locals: Vec<(u32, Value)> = self.frames[frame]
            .saved
            .keys()
            .map(|local| (*local, self.locals[*local as usize]))
            .collect();
        locals.sort_unstable_by_key(|(local, _)| *local);
        self.spend(locals.len() as u64);
        locals
    }

    fn returns(&mut self, offset: u32, index: u32, values: &[Value]) -> u32 {
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
    fn branch_to(&mut self, target: usize, values: Vec<Value>, via: Via, offset: u32, index: u32) {
        match self.frames[target].kind {
            FrameKind::Function => {
                let node = self.returns(offset, index, &values);
                if self.instruction_nodes[index as usize] == NONE {
                    self.instruction_nodes[index as usize] = node;
                }
            }
            FrameKind::Loop => {
                let params = self.frames[target].loop_param_phis.clone();
                for (slot, phi) in params.iter().enumerate() {
                    if let Some(value) = values.get(slot)
                        && !self.same(*value, Value::of(*phi))
                    {
                        self.edge(*value, *phi, slot as u32, EdgeKind::Merge, via, offset);
                    }
                }
                let locals = self.frames[target].loop_local_phis.clone();
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
                self.frames[target].incoming.push(Incoming {
                    via,
                    via_offset: offset,
                    values,
                    locals,
                });
            }
        }
    }

    fn branch(&mut self, depth: u32, via: Via, offset: u32, index: u32) {
        if !self.reachable {
            return;
        }
        let Some(target) = self.frames.len().checked_sub(depth as usize + 1) else {
            self.omissions.push(format!(
                "A branch at byte {offset} names a label past the open frames; its values are not followed."
            ));
            return;
        };
        let arity = self.frames[target].label_arity();
        let values = self.top(arity);
        self.branch_to(target, values, via, offset, index);
    }

    fn unreachable(&mut self) {
        let height = self.frames.last().map_or(0, |frame| frame.height);
        self.stack.truncate(height);
        self.reachable = false;
    }

    fn push_frame(
        &mut self,
        kind: FrameKind,
        join: Join,
        offset: u32,
        index: u32,
        ty: BlockType,
    ) -> std::result::Result<(), Stop> {
        let (params, results) = self.module.block_arity(ty).ok_or_else(|| {
            Stop::Unsupported("A block type that is not a function type".to_owned())
        })?;
        let param_values = self.top(params);
        let height = self
            .stack
            .len()
            .saturating_sub(params as usize)
            .max(self.frames.last().map_or(0, |frame| frame.height));
        self.frames.push(Frame {
            kind,
            join,
            offset,
            instruction: index,
            height,
            params,
            results,
            param_values,
            saved: HashMap::new(),
            incoming: Vec::new(),
            then_end: None,
            loop_param_phis: Vec::new(),
            loop_local_phis: Vec::new(),
            reachable_at_entry: self.reachable,
            try_writes: Vec::new(),
            catch_phis: None,
            catches: Vec::new(),
        });
        // A block's parameters stay on the stack as the values they are.
        self.stack.truncate(height);
        let values = self.frames.last().expect("pushed").param_values.clone();
        self.stack.extend(values);
        Ok(())
    }

    fn enter_loop(&mut self, offset: u32, index: u32) {
        // A loop no path reaches has no header joins: nothing can enter it.
        if !self.reachable {
            return;
        }
        let frame = self.frames.len() - 1;
        let params = self.frames[frame].param_values.clone();
        let height = self.frames[frame].height;
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
        self.frames[frame].loop_param_phis = phis;
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
        self.frames[frame].loop_local_phis = local_phis;
    }

    fn restore_locals(&mut self, frame: usize) {
        let saved: Vec<(u32, Value)> = self.frames[frame]
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
        if let Some(phis) = &self.frames[frame].catch_phis {
            return phis.clone();
        }
        let writes = std::mem::take(&mut self.frames[frame].try_writes);
        let offset = self.frames[frame].offset;
        let instruction = self.frames[frame].instruction;
        let mut by_local: Vec<(u32, Value, u32)> = writes;
        by_local.sort_by_key(|(local, _, _)| *local);
        let mut phis = Vec::new();
        let mut position = 0;
        while position < by_local.len() {
            let local = by_local[position].0;
            let entry = self.frames[frame]
                .saved
                .get(&local)
                .copied()
                .unwrap_or(self.locals[local as usize]);
            let phi = self.node(NodeKind::Phi, offset, instruction, local, 1);
            self.nodes[phi as usize].join = Join::Try;
            self.edge(entry, phi, 0, EdgeKind::Merge, Via::Entry, offset);
            while position < by_local.len() && by_local[position].0 == local {
                let (_, value, at) = by_local[position];
                self.spend(1);
                self.edge(value, phi, 0, EdgeKind::Merge, Via::Catch, at);
                position += 1;
            }
            phis.push((local, phi));
        }
        self.frames[frame].catch_phis = Some(phis.clone());
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
        let height = self.frames.last().map_or(0, |frame| frame.height);
        self.merge(offset, index);
        let results = self.stack.len().saturating_sub(height);
        if self.reachable && results > 0 {
            let values: Vec<Value> = self.stack[self.stack.len() - results..].to_vec();
            self.record(index, &values);
        }
    }

    fn merge(&mut self, offset: u32, index: u32) {
        let position = self.frames.len() - 1;
        if matches!(
            self.frames[position].kind,
            FrameKind::Try | FrameKind::TryTable
        ) {
            self.close_try_body(position);
        }
        if self.frames[position].kind == FrameKind::TryTable {
            self.route_try_table(position, offset, index);
        }
        if self.frames[position].kind == FrameKind::Loop {
            let frame = self.frames.pop().expect("loop frame");
            let results = frame.results;
            if self.reachable {
                let values = self.top_at(frame.height, results);
                self.stack.truncate(frame.height);
                self.stack.extend(values);
            } else {
                self.stack.truncate(frame.height);
                for _ in 0..results {
                    let unknown = self.unknown_value();
                    self.stack.push(unknown);
                }
            }
            return;
        }
        let results = self.frames[position].results;
        let mut incomings = std::mem::take(&mut self.frames[position].incoming);
        if let Some(then) = self.frames[position].then_end.take() {
            incomings.insert(0, then);
        }
        if self.reachable {
            let height = self.frames[position].height;
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
        if self.frames[position].kind == FrameKind::If && self.frames[position].reachable_at_entry {
            let entry = self.frames[position].offset;
            let values = self.frames[position].param_values.clone();
            let values = values.into_iter().map(|v| self.materialize(v)).collect();
            let mut locals: Vec<(u32, Value)> = self.frames[position]
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
        let frame = self.frames.pop().expect("frame");
        self.stack.truncate(frame.height);
        if incomings.is_empty() {
            self.reachable = false;
            for (local, value) in &frame.saved {
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
            self.nodes[phi as usize].join = frame.join;
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
            self.nodes[phi as usize].join = frame.join;
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
        if !self.frames[position].reachable_at_entry || self.frames[position].catches.is_empty() {
            return;
        }
        let phis = self.catch_phis(position);
        let entry_offset = self.frames[position].offset;
        let instruction = self.frames[position].instruction;
        let catches: Vec<(usize, u32, u32)> = self.frames[position]
            .catches
            .iter()
            .map(|catch| (catch.target, catch.tag, catch.values))
            .collect();
        let saved = self.frames[position].saved.clone();
        let _ = (offset, index);
        for (target, tag, count) in catches {
            let values = self.exception_values(entry_offset, instruction, tag, count, true);
            let local_value = |local: u32, current: Value| -> Value {
                if let Ok(found) = phis.binary_search_by_key(&local, |(l, _)| *l) {
                    Value::of(phis[found].1)
                } else {
                    saved.get(&local).copied().unwrap_or(current)
                }
            };
            match self.frames[target].kind {
                FrameKind::Function => {
                    self.returns(entry_offset, instruction, &values);
                }
                FrameKind::Loop => {
                    let params = self.frames[target].loop_param_phis.clone();
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
                    let locals = self.frames[target].loop_local_phis.clone();
                    for (local, phi) in locals {
                        let value = local_value(local, self.locals[local as usize]);
                        if !self.same(value, Value::of(phi)) {
                            self.edge(value, phi, 0, EdgeKind::Merge, Via::Catch, entry_offset);
                        }
                    }
                }
                _ => {
                    let mut locals: Vec<(u32, Value)> = self.frames[target]
                        .saved
                        .keys()
                        .map(|local| (*local, local_value(*local, self.locals[*local as usize])))
                        .collect();
                    locals.sort_unstable_by_key(|(local, _)| *local);
                    self.spend(locals.len() as u64);
                    self.frames[target].incoming.push(Incoming {
                        via: Via::Catch,
                        via_offset: entry_offset,
                        values,
                        locals,
                    });
                }
            }
        }
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
        // Code no declared path reaches creates no node: its values cannot
        // feed a slice and its calls cannot be reported as sinks. Structure
        // is still tracked so the frames stay aligned with the bytes.
        if !self.reachable
            && !matches!(
                op,
                Operator::Block { .. }
                    | Operator::Loop { .. }
                    | Operator::If { .. }
                    | Operator::Else
                    | Operator::End
                    | Operator::Try { .. }
                    | Operator::Catch { .. }
                    | Operator::CatchAll
                    | Operator::Delegate { .. }
                    | Operator::TryTable { .. }
            )
        {
            return Ok(false);
        }
        match op {
            Operator::Nop => {}
            Operator::Unreachable => {
                self.clear_store();
                self.unreachable();
            }
            Operator::Block { blockty } => {
                self.clear_store();
                self.push_frame(FrameKind::Block, Join::Block, offset, index, *blockty)?;
            }
            Operator::Loop { blockty } => {
                self.clear_store();
                self.push_frame(FrameKind::Loop, Join::Loop, offset, index, *blockty)?;
                self.enter_loop(offset, index);
            }
            Operator::If { blockty } => {
                self.clear_store();
                if self.reachable {
                    let condition = self.pop(offset);
                    self.selector(index, &[], condition);
                }
                self.push_frame(FrameKind::If, Join::If, offset, index, *blockty)?;
            }
            Operator::Else => {
                self.clear_store();
                let position = self.frames.len() - 1;
                if self.frames[position].kind != FrameKind::If {
                    return Err(Stop::Unsupported("An else without its if".to_owned()));
                }
                if self.reachable {
                    let height = self.frames[position].height;
                    let results = self.frames[position].results;
                    let values = self.top_at(height, results);
                    let values = values.into_iter().map(|v| self.materialize(v)).collect();
                    let locals = self.snapshot(position);
                    self.frames[position].then_end = Some(Incoming {
                        via: Via::ThenEnd,
                        via_offset: offset,
                        values,
                        locals,
                    });
                }
                let height = self.frames[position].height;
                self.stack.truncate(height);
                let params = self.frames[position].param_values.clone();
                self.stack.extend(params);
                self.restore_locals(position);
                self.reachable = self.frames[position].reachable_at_entry;
                self.frames[position].kind = FrameKind::Else;
            }
            Operator::End => {
                self.clear_store();
                if self.frames.len() == 1 {
                    let results = self.frames[0].results;
                    let mut node = NONE;
                    if self.reachable {
                        self.note_leftover(0, results, offset);
                        let values = self.top_at(0, results);
                        self.record(index, &values);
                        node = self.returns(offset, index, &values);
                    }
                    self.instruction_nodes[index as usize] = node;
                    self.frames.pop();
                    return Ok(true);
                }
                if self.frames.is_empty() {
                    return Err(Stop::Unsupported("An end without a block".to_owned()));
                }
                self.close(offset, index);
            }
            Operator::Br { relative_depth } => {
                self.clear_store();
                if let Some(target) = self.frames.len().checked_sub(*relative_depth as usize + 1) {
                    let arity = self.frames[target].label_arity();
                    let values = self.top(arity);
                    self.record(index, &values);
                }
                self.branch(*relative_depth, Via::Br, offset, index);
                self.unreachable();
            }
            Operator::BrIf { relative_depth } => {
                self.clear_store();
                let condition = self.pop(offset);
                let carried = self.carried(*relative_depth);
                self.selector(index, &carried, condition);
                self.branch(*relative_depth, Via::BrIf, offset, index);
            }
            Operator::BrTable { targets } => {
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
                    self.branch(depth, Via::BrTable, offset, index);
                }
                self.unreachable();
            }
            Operator::Return => {
                self.clear_store();
                if self.reachable {
                    let results = self.frames[0].results;
                    let values = self.top(results);
                    self.record(index, &values);
                    let node = self.returns(offset, index, &values);
                    self.instruction_nodes[index as usize] = node;
                }
                self.unreachable();
            }
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
            Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
                self.clear_store();
                let function = *function_index;
                let (params, results) = self
                    .module
                    .func_types
                    .get(function as usize)
                    .and_then(|ty| self.module.type_arity(*ty))
                    .ok_or_else(|| {
                        Stop::Unsupported(format!("A call to undeclared function {function}"))
                    })?;
                let tail = matches!(op, Operator::ReturnCall { .. });
                let args = self.pop_n(params, offset);
                let kind = if function < self.module.imported_functions {
                    NodeKind::ImportCall
                } else {
                    NodeKind::Call
                };
                let pushed = if tail { 0 } else { results };
                let node =
                    self.consume(kind, index, function, pushed, &args, |_| EdgeKind::Argument);
                self.nodes[node as usize].results = results;
                if tail {
                    self.unreachable();
                }
            }
            Operator::CallIndirect {
                type_index,
                table_index,
            }
            | Operator::ReturnCallIndirect {
                type_index,
                table_index,
            } => {
                self.clear_store();
                let (params, results) = self.module.type_arity(*type_index).ok_or_else(|| {
                    Stop::Unsupported(format!("call_indirect of non-function type {type_index}"))
                })?;
                let tail = matches!(op, Operator::ReturnCallIndirect { .. });
                let mut args = self.pop_n(params + 1, offset);
                let selector = args.pop().expect("selector operand");
                args.push(selector);
                let count = params as usize;
                let pushed = if tail { 0 } else { results };
                let node = self.consume(
                    NodeKind::CallIndirect,
                    index,
                    *type_index,
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
                self.nodes[node as usize].aux = *table_index as u64;
                self.nodes[node as usize].results = results;
                if tail {
                    self.unreachable();
                }
            }
            Operator::CallRef { type_index } | Operator::ReturnCallRef { type_index } => {
                self.clear_store();
                let (params, results) = self.module.type_arity(*type_index).ok_or_else(|| {
                    Stop::Unsupported(format!("call_ref of non-function type {type_index}"))
                })?;
                let tail = matches!(op, Operator::ReturnCallRef { .. });
                let args = self.pop_n(params + 1, offset);
                let count = params as usize;
                let pushed = if tail { 0 } else { results };
                let node = self.consume(
                    NodeKind::CallRef,
                    index,
                    *type_index,
                    pushed,
                    &args,
                    |operand| {
                        if operand == count {
                            EdgeKind::CalleeRef
                        } else {
                            EdgeKind::Argument
                        }
                    },
                );
                self.nodes[node as usize].results = results;
                if tail {
                    self.unreachable();
                }
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
            Operator::Try { blockty } => {
                self.clear_store();
                self.push_frame(FrameKind::Try, Join::Try, offset, index, *blockty)?;
                let frame = self.frames.len() - 1;
                if self.reachable {
                    self.open_tries.push(frame);
                }
            }
            Operator::Catch { .. } | Operator::CatchAll => {
                self.clear_store();
                let position = self.frames.len() - 1;
                if !matches!(
                    self.frames[position].kind,
                    FrameKind::Try | FrameKind::Catch
                ) {
                    return Err(Stop::Unsupported("A catch without its try".to_owned()));
                }
                if self.reachable {
                    let height = self.frames[position].height;
                    let results = self.frames[position].results;
                    let values = self.top_at(height, results);
                    let values = values.into_iter().map(|v| self.materialize(v)).collect();
                    let locals = self.snapshot(position);
                    self.frames[position].incoming.push(Incoming {
                        via: Via::Fallthrough,
                        via_offset: offset,
                        values,
                        locals,
                    });
                }
                self.close_try_body(position);
                let height = self.frames[position].height;
                self.stack.truncate(height);
                self.restore_locals(position);
                self.reachable = self.frames[position].reachable_at_entry;
                if self.reachable {
                    for (local, phi) in self.catch_phis(position) {
                        self.write_local(local, Value::of(phi), offset);
                    }
                }
                let (tag, count) = match op {
                    Operator::Catch { tag_index } => (
                        *tag_index,
                        self.module.tag_params(*tag_index).ok_or_else(|| {
                            Stop::Unsupported(format!("A catch of undeclared tag {tag_index}"))
                        })?,
                    ),
                    _ => (NONE, 0),
                };
                let live = self.reachable;
                let values = self.exception_values(offset, index, tag, count, live);
                self.stack.extend(values);
                self.frames[position].kind = FrameKind::Catch;
            }
            Operator::Delegate { .. } => {
                self.clear_store();
                if self.frames.last().map(|frame| frame.kind) != Some(FrameKind::Try) {
                    return Err(Stop::Unsupported("A delegate without its try".to_owned()));
                }
                self.close(offset, index);
            }
            Operator::TryTable { try_table } => {
                self.clear_store();
                let mut catches = Vec::new();
                let outer = self.frames.len();
                for catch in &try_table.catches {
                    let (label, tag, with_ref) = match catch {
                        wasmparser::Catch::One { tag, label } => (*label, *tag, false),
                        wasmparser::Catch::OneRef { tag, label } => (*label, *tag, true),
                        wasmparser::Catch::All { label } => (*label, NONE, false),
                        wasmparser::Catch::AllRef { label } => (*label, NONE, true),
                    };
                    let Some(target) = outer.checked_sub(label as usize + 1) else {
                        self.omissions.push(format!(
                            "A try_table catch at byte {offset} names a label past the open frames; it is not followed."
                        ));
                        continue;
                    };
                    let params = if tag == NONE {
                        0
                    } else {
                        self.module.tag_params(tag).ok_or_else(|| {
                            Stop::Unsupported(format!("A catch of undeclared tag {tag}"))
                        })?
                    };
                    catches.push(TryCatch {
                        target,
                        tag,
                        values: params + u32::from(with_ref),
                    });
                }
                self.push_frame(FrameKind::TryTable, Join::Try, offset, index, try_table.ty)?;
                let frame = self.frames.len() - 1;
                self.frames[frame].catches = catches;
                if self.reachable {
                    self.open_tries.push(frame);
                }
            }
            Operator::Throw { tag_index } => {
                self.clear_store();
                let count = self.module.tag_params(*tag_index).ok_or_else(|| {
                    Stop::Unsupported(format!("A throw of undeclared tag {tag_index}"))
                })?;
                let args = self.pop_n(count, offset);
                self.consume(NodeKind::Throw, index, *tag_index, 0, &args, |_| {
                    EdgeKind::Argument
                });
                self.unreachable();
            }
            Operator::ThrowRef => {
                self.clear_store();
                let value = self.pop(offset);
                self.consume(NodeKind::Throw, index, NONE, 0, &[value], |_| {
                    EdgeKind::Argument
                });
                self.unreachable();
            }
            Operator::Rethrow { .. } => {
                self.clear_store();
                self.unreachable();
            }
            Operator::BrOnNull { relative_depth }
            | Operator::BrOnNonNull { relative_depth }
            | Operator::BrOnCast { relative_depth, .. }
            | Operator::BrOnCastFail { relative_depth, .. } => {
                self.clear_store();
                let reference = self.pop(offset);
                let node = self.consume(NodeKind::Operation, index, NONE, 0, &[reference], |_| {
                    EdgeKind::Operand
                });
                self.nodes[node as usize].results = 1;
                let derived = Value::of(node);
                let Some(target) = self.frames.len().checked_sub(*relative_depth as usize + 1)
                else {
                    self.omissions.push(format!(
                        "A branch at byte {offset} names a label past the open frames; its values are not followed."
                    ));
                    return Ok(false);
                };
                let arity = self.frames[target].label_arity();
                let null = matches!(op, Operator::BrOnNull { .. });
                if self.reachable {
                    let mut values = self.top(if null { arity } else { arity.saturating_sub(1) });
                    if !null {
                        values.push(derived);
                    }
                    self.branch_to(target, values, Via::BrOn, offset, index);
                }
                if !matches!(op, Operator::BrOnNonNull { .. }) {
                    self.stack.push(derived);
                }
            }
            // The fence's mnemonic is `atomic_fence`, with no `.atomic`, so it
            // is matched here: it orders memory with other agents, and a store
            // before it no longer stands for a load after it.
            Operator::AtomicFence => self.clear_store(),
            Operator::Resume { .. }
            | Operator::ResumeThrow { .. }
            | Operator::Suspend { .. }
            | Operator::Switch { .. }
            | Operator::ContBind { .. }
            | Operator::ContNew { .. } => {
                return Err(Stop::Unsupported(format!(
                    "The stack-switching operator {}",
                    crate::wasm::mnemonic(op)
                )));
            }
            other => {
                let (params, results) =
                    other.operator_arity(&Arity(self.module)).ok_or_else(|| {
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
        Ok(false)
    }
}
