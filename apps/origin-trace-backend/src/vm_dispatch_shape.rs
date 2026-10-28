//! Structural dispatch-site classification, contract
//! `vm-dispatch-classification-v1`.
//!
//! Every record answers three questions before any opcode or decode logic
//! runs: how control picks the next handler (`dispatch_kind`), where the
//! selector value comes from (`selector_source`), and whether the dispatch is
//! re-derived each loop iteration or fires once per invocation (`repeats`).
//! A record is interpretation of stored bytes: `confidence` is always
//! `structural`. It never rewrites captured evidence and never raises a tier.
//!
//! Only `repeats=loop` with a cursor-like selector is an interpreter
//! candidate. A `once` dispatch on a call argument is a multiplexer: its
//! arms or constants route one call to one function and are not opcodes.
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};
use wasmparser::{
    ExternalKind, FuncValidator, FuncValidatorAllocations, FunctionBody, Operator, Parser, Payload,
    TypeRef, ValidPayload, Validator, ValidatorResources, WasmFeatures,
};

#[path = "vm_dispatch_shape_js.rs"]
pub(crate) mod javascript;

pub(crate) const CLASSIFICATION_VERSION: u32 = 1;
pub(crate) const MAX_LISTED_SITES: usize = 256;
/// Symbolic nodes per function. Past it, values become unknown, never guessed.
const MAX_NODES: usize = 1 << 16;
const MAX_TRACE_DEPTH: u8 = 8;
const MAX_EXPRESSION_CHARS: usize = 160;
/// Fewer equality tests are ordinary branching, not a selector ladder.
pub(crate) const MIN_COMPARE_ARMS: usize = 3;
const MAX_LISTED_SLOTS: usize = 32;
const MAX_DEFS_PER_LOCAL: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    SwitchOnValue,
    HandlerTable,
    CompareChain,
    ExportPerRole,
    Threaded,
}

impl Kind {
    const ALL: [Kind; 5] = [
        Kind::SwitchOnValue,
        Kind::HandlerTable,
        Kind::CompareChain,
        Kind::ExportPerRole,
        Kind::Threaded,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::SwitchOnValue => "switch_on_value",
            Self::HandlerTable => "handler_table",
            Self::CompareChain => "compare_chain",
            Self::ExportPerRole => "export_per_role",
            Self::Threaded => "threaded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    CursorIndex,
    CursorPointer,
    FrameSlot,
    CallArgument,
    HandlerAddress,
    Constant,
    Unknown,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::CursorIndex => "cursor_index",
            Self::CursorPointer => "cursor_pointer",
            Self::FrameSlot => "frame_slot",
            Self::CallArgument => "call_argument",
            Self::HandlerAddress => "handler_address",
            Self::Constant => "constant",
            Self::Unknown => "unknown",
        }
    }
    fn cursor_like(self) -> bool {
        matches!(
            self,
            Self::CursorIndex | Self::CursorPointer | Self::FrameSlot
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Repeats {
    Loop,
    Once,
    Unknown,
}

impl Repeats {
    pub fn label(self) -> &'static str {
        match self {
            Self::Loop => "loop",
            Self::Once => "once",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Role {
    InterpreterCandidate,
    Multiplexer,
    Other,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Self::InterpreterCandidate => "interpreter-candidate",
            Self::Multiplexer => "multiplexer",
            Self::Other => "other",
        }
    }
}

/// Derived from the three axes only. A threaded chain computes handler
/// addresses, not opcodes, so it is never an opcode interpreter candidate.
pub(crate) fn role(kind: Kind, source: Source, repeats: Repeats) -> Role {
    let selects = matches!(
        kind,
        Kind::SwitchOnValue | Kind::HandlerTable | Kind::CompareChain
    );
    if selects && repeats == Repeats::Loop && source.cursor_like() {
        Role::InterpreterCandidate
    } else if selects && repeats == Repeats::Once && source == Source::CallArgument {
        Role::Multiplexer
    } else {
        Role::Other
    }
}

pub(crate) struct Site {
    pub kind: Kind,
    pub source: Source,
    pub repeats: Repeats,
    pub instruction: &'static str,
    pub function_index: Option<u32>,
    pub function_body_offset: Option<usize>,
    pub byte_offset: usize,
    pub byte_size: usize,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub selector_expression: String,
    pub selector_offset: Option<usize>,
    pub arm_count: Option<u64>,
    pub loop_range: Option<(usize, usize)>,
    pub buffer_kind: Option<&'static str>,
    pub table: Option<Value>,
}

impl Site {
    pub fn role(&self) -> Role {
        role(self.kind, self.source, self.repeats)
    }
}

pub(crate) fn bounded_expression(text: &str) -> String {
    let mut text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return "?".into();
    }
    if text.len() > MAX_EXPRESSION_CHARS {
        let mut end = MAX_EXPRESSION_CHARS - 3;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
    text
}

/// The versioned classification object. Interpreter candidates and
/// multiplexers are listed first so the bound never hides them behind
/// ordinary branching; counts always cover every classified site.
pub(crate) fn document(artifact_id: &Value, mut sites: Vec<Site>) -> Value {
    let mut role_counts = BTreeMap::<&str, usize>::new();
    let mut kind_counts = BTreeMap::<&str, usize>::new();
    for role in [Role::InterpreterCandidate, Role::Multiplexer, Role::Other] {
        role_counts.insert(role.label(), 0);
    }
    for kind in Kind::ALL {
        kind_counts.insert(kind.label(), 0);
    }
    for site in &sites {
        *role_counts.get_mut(site.role().label()).expect("role") += 1;
        *kind_counts.get_mut(site.kind.label()).expect("kind") += 1;
    }
    let total = sites.len();
    sites.sort_by_key(|site| (site.role(), site.byte_offset));
    sites.truncate(MAX_LISTED_SITES);
    sites.sort_by_key(|site| site.byte_offset);
    let listed = sites
        .iter()
        .map(|site| {
            json!({
                "artifact_id": artifact_id,
                "dispatch_kind": site.kind.label(),
                "selector_source": site.source.label(),
                "repeats": site.repeats.label(),
                "role": site.role().label(),
                "confidence": "structural",
                "instruction": site.instruction,
                "location": {
                    "function_index": site.function_index,
                    "function_body_offset": site.function_body_offset,
                    "byte_offset": site.byte_offset,
                    "byte_size": site.byte_size.max(1),
                    "line": site.line,
                    "column": site.column,
                },
                "selector": {
                    "expression": bounded_expression(&site.selector_expression),
                    "byte_offset": site.selector_offset,
                },
                "arm_count": site.arm_count,
                "loop": site.loop_range.map(|(start, end)| json!({
                    "byte_offset": start,
                    "byte_size": end.saturating_sub(start).max(1),
                })),
                "buffer_kind": site.buffer_kind,
                "table": site.table,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "classification_version": CLASSIFICATION_VERSION,
        "site_count": total,
        "omitted_site_count": total - listed.len(),
        "role_counts": role_counts,
        "kind_counts": kind_counts,
        "sites": listed,
    })
}

/// Role of the listed site at an exact dispatch byte offset. Unlisted or
/// unclassified sites are never interpreter candidates.
pub(crate) fn role_at(classification: Option<&Value>, byte_offset: u64) -> Role {
    classification
        .and_then(|value| value["sites"].as_array())
        .and_then(|sites| {
            sites
                .iter()
                .find(|site| site["location"]["byte_offset"].as_u64() == Some(byte_offset))
        })
        .map_or(Role::Other, |site| match site["role"].as_str() {
            Some("interpreter-candidate") => Role::InterpreterCandidate,
            Some("multiplexer") => Role::Multiplexer,
            _ => Role::Other,
        })
}

type NodeId = usize;
const UNKNOWN: NodeId = 0;

#[derive(Clone, Debug)]
enum Node {
    Unknown,
    Const(i64),
    Local(u32),
    Global(u32),
    Load {
        op: &'static str,
        addr: NodeId,
        offset: u64,
        at: usize,
    },
    Bin {
        op: &'static str,
        a: NodeId,
        b: NodeId,
    },
    Un {
        op: &'static str,
        a: NodeId,
    },
    Call {
        callee: Option<u32>,
        at: usize,
    },
}

enum DispatchOp {
    BrTable { arms: u32 },
    CallIndirect { table: u32, ty: u32, tail: bool },
}

struct Dispatch {
    op: DispatchOp,
    offset: usize,
    size: usize,
    selector: NodeId,
}

struct Compare {
    subject: NodeId,
    constant: i64,
    offset: usize,
    size: usize,
}

struct Frame {
    height: usize,
    is_loop: bool,
    start: usize,
}

/// Symbolic facts of one function body: an operand-stack simulation typed
/// by validator arity, so an unmodeled operator consumes and produces the
/// right number of unknown values instead of wiping the stack.
struct Facts {
    params: u32,
    nodes: Vec<Node>,
    defs: BTreeMap<u32, Vec<(usize, NodeId)>>,
    /// (offset, address, memarg offset, stored value)
    stores: Vec<(usize, NodeId, u64, NodeId)>,
    loops: Vec<(usize, usize)>,
    dispatch: Vec<Dispatch>,
    compares: Vec<Compare>,
    local_memo: RefCell<BTreeMap<u32, Trace>>,
}

#[derive(Clone, Debug)]
struct Trace {
    source: Source,
    /// Locals whose writes advance a cursor or state variable.
    advancing: Vec<u32>,
    /// Memory slots (rendered base, byte offset) a frame_slot selector or
    /// its pc is reloaded from, with the reloaded local when there is one.
    slots: Vec<(Option<u32>, (String, u64))>,
    /// Offset of the closest producing write or load, when not at the site.
    anchor: Option<usize>,
    /// The single local definition used, rendered for evidence.
    definition: Option<NodeId>,
}

impl Trace {
    fn new(source: Source) -> Self {
        Self {
            source,
            advancing: Vec::new(),
            slots: Vec::new(),
            anchor: None,
            definition: None,
        }
    }
}

fn binary_op(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::I32Add => "i32.add",
        Operator::I32Sub => "i32.sub",
        Operator::I32Mul => "i32.mul",
        Operator::I32DivU => "i32.div_u",
        Operator::I32RemU => "i32.rem_u",
        Operator::I32And => "i32.and",
        Operator::I32Or => "i32.or",
        Operator::I32Xor => "i32.xor",
        Operator::I32Shl => "i32.shl",
        Operator::I32ShrU => "i32.shr_u",
        Operator::I32ShrS => "i32.shr_s",
        Operator::I32Eq => "i32.eq",
        Operator::I32Ne => "i32.ne",
        Operator::I64Add => "i64.add",
        Operator::I64Sub => "i64.sub",
        Operator::I64Mul => "i64.mul",
        Operator::I64And => "i64.and",
        Operator::I64Or => "i64.or",
        Operator::I64Xor => "i64.xor",
        Operator::I64Shl => "i64.shl",
        Operator::I64ShrU => "i64.shr_u",
        Operator::I64ShrS => "i64.shr_s",
        Operator::I64Eq => "i64.eq",
        Operator::I64Ne => "i64.ne",
        _ => return None,
    })
}

fn unary_op(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::I32Eqz => "i32.eqz",
        Operator::I64Eqz => "i64.eqz",
        Operator::I32WrapI64 => "i32.wrap_i64",
        Operator::I64ExtendI32U => "i64.extend_i32_u",
        Operator::I64ExtendI32S => "i64.extend_i32_s",
        Operator::I32Extend8S => "i32.extend8_s",
        Operator::I32Extend16S => "i32.extend16_s",
        _ => return None,
    })
}

fn load_op(op: &Operator<'_>) -> Option<(&'static str, u64)> {
    Some(match op {
        Operator::I32Load { memarg } => ("i32.load", memarg.offset),
        Operator::I32Load8U { memarg } => ("i32.load8_u", memarg.offset),
        Operator::I32Load8S { memarg } => ("i32.load8_s", memarg.offset),
        Operator::I32Load16U { memarg } => ("i32.load16_u", memarg.offset),
        Operator::I32Load16S { memarg } => ("i32.load16_s", memarg.offset),
        Operator::I64Load { memarg } => ("i64.load", memarg.offset),
        Operator::I64Load8U { memarg } => ("i64.load8_u", memarg.offset),
        Operator::I64Load16U { memarg } => ("i64.load16_u", memarg.offset),
        Operator::I64Load32U { memarg } => ("i64.load32_u", memarg.offset),
        _ => return None,
    })
}

fn store_offset(op: &Operator<'_>) -> Option<u64> {
    Some(match op {
        Operator::I32Store { memarg }
        | Operator::I32Store8 { memarg }
        | Operator::I32Store16 { memarg }
        | Operator::I64Store { memarg }
        | Operator::I64Store8 { memarg }
        | Operator::I64Store16 { memarg }
        | Operator::I64Store32 { memarg } => memarg.offset,
        _ => return None,
    })
}

fn ends_flow(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::Br { .. }
            | Operator::BrTable { .. }
            | Operator::Return
            | Operator::Unreachable
            | Operator::ReturnCall { .. }
            | Operator::ReturnCallIndirect { .. }
            | Operator::ReturnCallRef { .. }
            | Operator::Throw { .. }
            | Operator::ThrowRef
            | Operator::Rethrow { .. }
    )
}

impl Facts {
    fn node(&mut self, node: Node) -> NodeId {
        if self.nodes.len() >= MAX_NODES {
            return UNKNOWN;
        }
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    fn simulate(
        body: &FunctionBody<'_>,
        mut validator: Option<FuncValidator<ValidatorResources>>,
        params: u32,
    ) -> Option<Self> {
        let mut facts = Facts {
            params,
            nodes: vec![Node::Unknown],
            defs: BTreeMap::new(),
            stores: Vec::new(),
            loops: Vec::new(),
            dispatch: Vec::new(),
            compares: Vec::new(),
            local_memo: RefCell::new(BTreeMap::new()),
        };
        if let Some(v) = validator.as_mut() {
            let mut locals = body.get_locals_reader().ok()?;
            for _ in 0..locals.get_count() {
                let offset = locals.original_position();
                let (count, ty) = locals.read().ok()?;
                if v.define_locals(offset, count, ty).is_err() {
                    validator = None;
                    break;
                }
            }
        }
        let mut reader = body.get_operators_reader().ok()?;
        let mut stack: Vec<NodeId> = Vec::new();
        let mut frames: Vec<Frame> = Vec::new();
        while !reader.eof() {
            let start = reader.original_position();
            let op = reader.read().ok()?;
            let end = reader.original_position();
            let arity = validator.as_ref().and_then(|v| op.operator_arity(v));
            if let Some(v) = validator.as_mut()
                && v.op(start, &op).is_err()
            {
                validator = None;
            }
            let floor = frames.last().map_or(0, |frame| frame.height);
            let pop = |stack: &mut Vec<NodeId>| {
                if stack.len() > floor {
                    stack.pop().unwrap_or(UNKNOWN)
                } else {
                    UNKNOWN
                }
            };
            match &op {
                Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                    if matches!(op, Operator::If { .. }) {
                        let condition = pop(&mut stack);
                        facts.compare(condition, start, end - start);
                    }
                    let carried = arity.map_or(0, |(_, results)| results as usize);
                    for _ in 0..carried {
                        pop(&mut stack);
                    }
                    frames.push(Frame {
                        height: stack.len(),
                        is_loop: matches!(op, Operator::Loop { .. }),
                        start,
                    });
                    stack.extend(std::iter::repeat_n(UNKNOWN, carried));
                }
                Operator::Else => {
                    if let Some(frame) = frames.last() {
                        stack.truncate(frame.height);
                    }
                    let carried = arity.map_or(0, |(_, params)| params as usize);
                    stack.extend(std::iter::repeat_n(UNKNOWN, carried));
                }
                Operator::End => {
                    if let Some(frame) = frames.pop() {
                        stack.truncate(frame.height);
                        if frame.is_loop {
                            facts.loops.push((frame.start, end));
                        }
                        let results = arity.map_or(0, |(_, results)| results as usize);
                        stack.extend(std::iter::repeat_n(UNKNOWN, results));
                    }
                }
                Operator::LocalGet { local_index } => {
                    let id = facts.node(Node::Local(*local_index));
                    stack.push(id);
                }
                Operator::LocalSet { local_index } | Operator::LocalTee { local_index } => {
                    let value = pop(&mut stack);
                    facts
                        .defs
                        .entry(*local_index)
                        .or_default()
                        .push((start, value));
                    if matches!(op, Operator::LocalTee { .. }) {
                        stack.push(value);
                    }
                }
                Operator::GlobalGet { global_index } => {
                    let id = facts.node(Node::Global(*global_index));
                    stack.push(id);
                }
                Operator::I32Const { value } => {
                    let id = facts.node(Node::Const(i64::from(*value)));
                    stack.push(id);
                }
                Operator::I64Const { value } => {
                    let id = facts.node(Node::Const(*value));
                    stack.push(id);
                }
                Operator::BrIf { .. } => {
                    let condition = pop(&mut stack);
                    facts.compare(condition, start, end - start);
                }
                Operator::BrTable { targets } => {
                    let selector = pop(&mut stack);
                    facts.dispatch.push(Dispatch {
                        op: DispatchOp::BrTable {
                            arms: targets.len(),
                        },
                        offset: start,
                        size: end - start,
                        selector,
                    });
                    if let Some(frame) = frames.last() {
                        stack.truncate(frame.height);
                    } else {
                        stack.clear();
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
                    let selector = pop(&mut stack);
                    facts.dispatch.push(Dispatch {
                        op: DispatchOp::CallIndirect {
                            table: *table_index,
                            ty: *type_index,
                            tail: matches!(op, Operator::ReturnCallIndirect { .. }),
                        },
                        offset: start,
                        size: end - start,
                        selector,
                    });
                    let (params, results) = arity.unwrap_or((1, 0));
                    for _ in 1..params {
                        pop(&mut stack);
                    }
                    if ends_flow(&op) {
                        stack.truncate(floor);
                    } else {
                        for index in 0..results {
                            let id = if index == 0 {
                                facts.node(Node::Call {
                                    callee: None,
                                    at: start,
                                })
                            } else {
                                UNKNOWN
                            };
                            stack.push(id);
                        }
                    }
                }
                Operator::Call { function_index } => {
                    let (params, results) = arity.unwrap_or((0, 0));
                    for _ in 0..params {
                        pop(&mut stack);
                    }
                    for index in 0..results {
                        let id = if index == 0 {
                            facts.node(Node::Call {
                                callee: Some(*function_index),
                                at: start,
                            })
                        } else {
                            UNKNOWN
                        };
                        stack.push(id);
                    }
                }
                other => {
                    if let Some((name, offset)) = load_op(other) {
                        let addr = pop(&mut stack);
                        let id = facts.node(Node::Load {
                            op: name,
                            addr,
                            offset,
                            at: start,
                        });
                        stack.push(id);
                    } else if let Some(offset) = store_offset(other) {
                        let value = pop(&mut stack);
                        let addr = pop(&mut stack);
                        facts.stores.push((start, addr, offset, value));
                    } else if let Some(name) = binary_op(other) {
                        let b = pop(&mut stack);
                        let a = pop(&mut stack);
                        let id = facts.node(Node::Bin { op: name, a, b });
                        stack.push(id);
                    } else if let Some(name) = unary_op(other) {
                        let a = pop(&mut stack);
                        let id = facts.node(Node::Un { op: name, a });
                        stack.push(id);
                    } else if let Some((params, results)) = arity {
                        for _ in 0..params {
                            pop(&mut stack);
                        }
                        stack.extend(std::iter::repeat_n(UNKNOWN, results as usize));
                    } else {
                        // Without validator arity the effect is unknown; drop
                        // to the frame floor so no stale value becomes a selector.
                        stack.truncate(floor);
                    }
                    if ends_flow(other) {
                        stack.truncate(floor);
                    }
                }
            }
        }
        Some(facts)
    }

    fn compare(&mut self, condition: NodeId, offset: usize, size: usize) {
        let pair = match self.nodes[condition] {
            Node::Bin {
                op: "i32.eq" | "i32.ne" | "i64.eq" | "i64.ne",
                a,
                b,
            } => match (&self.nodes[a], &self.nodes[b]) {
                (_, Node::Const(value)) => Some((a, *value)),
                (Node::Const(value), _) => Some((b, *value)),
                _ => None,
            },
            Node::Un {
                op: "i32.eqz" | "i64.eqz",
                a,
            } => Some((a, 0)),
            _ => None,
        };
        if let Some((subject, constant)) = pair {
            self.compares.push(Compare {
                subject,
                constant,
                offset,
                size,
            });
        }
    }

    fn is_const(&self, id: NodeId) -> bool {
        matches!(self.nodes[id], Node::Const(_))
    }

    /// Remove masks, constant offsets and width conversions around a value.
    fn strip(&self, mut id: NodeId) -> NodeId {
        for _ in 0..16 {
            match self.nodes[id] {
                Node::Bin { op, a, b }
                    if self.is_const(b) && !op.ends_with(".eq") && !op.ends_with(".ne") =>
                {
                    id = a
                }
                Node::Bin { op, a, b }
                    if self.is_const(a)
                        && [".add", ".and", ".or", ".xor", ".mul"]
                            .iter()
                            .any(|suffix| op.ends_with(suffix)) =>
                {
                    id = b
                }
                Node::Un { op, a } if !op.ends_with("eqz") => id = a,
                _ => break,
            }
        }
        id
    }

    /// Non-constant address terms, marking ones scaled by a constant.
    fn terms(&self, id: NodeId, scaled: bool, out: &mut Vec<(NodeId, bool)>, depth: u8) {
        if depth > 8 || out.len() > 8 {
            out.push((UNKNOWN, scaled));
            return;
        }
        match self.nodes[id] {
            Node::Const(_) => (),
            Node::Bin { op, a, b } if op.ends_with(".add") => {
                self.terms(a, scaled, out, depth + 1);
                self.terms(b, scaled, out, depth + 1);
            }
            Node::Bin { op, a, b }
                if (op.ends_with(".shl") || op.ends_with(".mul")) && self.is_const(b) =>
            {
                self.terms(a, true, out, depth + 1)
            }
            Node::Bin { op, a, b } if op.ends_with(".mul") && self.is_const(a) => {
                self.terms(b, true, out, depth + 1)
            }
            Node::Bin { a, b, .. } if self.is_const(b) => self.terms(a, scaled, out, depth + 1),
            Node::Un { op, a } if !op.ends_with("eqz") => self.terms(a, scaled, out, depth + 1),
            _ => out.push((id, scaled)),
        }
    }

    fn references(&self, id: NodeId, local: u32, depth: u8) -> bool {
        if depth > 6 {
            return false;
        }
        match self.nodes[id] {
            Node::Local(l) => l == local,
            Node::Load { addr, .. } => self.references(addr, local, depth + 1),
            Node::Bin { a, b, .. } => {
                self.references(a, local, depth + 1) || self.references(b, local, depth + 1)
            }
            Node::Un { a, .. } => self.references(a, local, depth + 1),
            _ => false,
        }
    }

    fn definitions(&self, local: u32) -> &[(usize, NodeId)] {
        self.defs
            .get(&local)
            .map_or(&[], |defs| &defs[..defs.len().min(MAX_DEFS_PER_LOCAL)])
    }

    /// A local some write derives from itself (`pc = pc + n`).
    fn advanced(&self, local: u32) -> bool {
        self.definitions(local)
            .iter()
            .any(|(_, def)| self.references(*def, local, 0))
    }

    fn slot_key(&self, addr: NodeId, offset: u64) -> (String, u64) {
        let mut addend = 0i64;
        let mut base = addr;
        for _ in 0..8 {
            match self.nodes[base] {
                Node::Bin { op, a, b } if op.ends_with(".add") => {
                    if let Node::Const(value) = self.nodes[b] {
                        addend = addend.wrapping_add(value);
                        base = a;
                    } else if let Node::Const(value) = self.nodes[a] {
                        addend = addend.wrapping_add(value);
                        base = b;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        (self.render(base, 0), offset.wrapping_add(addend as u64))
    }

    /// The fixed memory slot a local is reloaded from: one write loads a
    /// field of a stable base (or a constant address), not an indexed or
    /// advancing position, so a loaded opcode is never mistaken for a pc.
    fn reloaded(&self, local: u32) -> Option<(String, u64)> {
        self.definitions(local).iter().find_map(|(_, def)| {
            let Node::Load { addr, offset, .. } = self.nodes[self.strip(*def)] else {
                return None;
            };
            let mut terms = Vec::new();
            self.terms(addr, false, &mut terms, 0);
            let stable = match terms.as_slice() {
                [] => true,
                [(term, false)] => match self.nodes[*term] {
                    Node::Local(base) => base != local && !self.advanced(base),
                    Node::Global(_) => true,
                    _ => false,
                },
                _ => false,
            };
            stable.then(|| self.slot_key(addr, offset))
        })
    }

    fn classify(&self, id: NodeId, depth: u8) -> Trace {
        if depth > MAX_TRACE_DEPTH {
            return Trace::new(Source::Unknown);
        }
        let core = self.strip(id);
        match self.nodes[core] {
            Node::Const(_) => Trace::new(Source::Constant),
            Node::Local(local) => self.local(local, depth),
            Node::Load { .. } => self.load(core, depth),
            Node::Call { callee: None, at } => {
                let mut trace = Trace::new(Source::HandlerAddress);
                trace.anchor = Some(at);
                trace
            }
            _ => Trace::new(Source::Unknown),
        }
    }

    fn local(&self, local: u32, depth: u8) -> Trace {
        if let Some(trace) = self.local_memo.borrow().get(&local) {
            return trace.clone();
        }
        // A cycle through this local resolves to unknown, never a guess.
        self.local_memo
            .borrow_mut()
            .insert(local, Trace::new(Source::Unknown));
        let trace = self.local_uncached(local, depth);
        self.local_memo.borrow_mut().insert(local, trace.clone());
        trace
    }

    fn local_uncached(&self, local: u32, depth: u8) -> Trace {
        let defs = self.definitions(local);
        let parameter = local < self.params;
        if defs.is_empty() {
            return Trace::new(if parameter {
                Source::CallArgument
            } else {
                Source::Constant
            });
        }
        let mut sources = Vec::new();
        for (at, def) in defs {
            if self.references(*def, local, 0) {
                continue;
            }
            let mut trace = self.classify(*def, depth + 1);
            if trace.anchor.is_none() {
                trace.anchor = Some(*at);
            }
            trace.definition = Some(*def);
            if trace.source == Source::Constant {
                trace.advancing.push(local);
                trace.anchor = Some(*at);
            }
            sources.push(trace);
        }
        if let Some(trace) = sources.iter().find(|trace| trace.source.cursor_like()) {
            return trace.clone();
        }
        if let Some(trace) = sources
            .iter()
            .find(|trace| trace.source == Source::HandlerAddress)
        {
            let mut trace = trace.clone();
            trace.advancing.push(local);
            return trace;
        }
        // Constant writes, optionally seeded by an argument, form a state
        // variable: control-flow flattening, not a cursor.
        if !sources.is_empty() && sources.iter().all(|trace| trace.source == Source::Constant) {
            let mut trace = Trace::new(Source::Constant);
            trace.advancing.push(local);
            trace.anchor = defs.iter().map(|(at, _)| *at).max();
            trace.definition = sources[0].definition;
            return trace;
        }
        Trace::new(Source::Unknown)
    }

    fn load(&self, core: NodeId, depth: u8) -> Trace {
        let Node::Load {
            addr, offset, at, ..
        } = self.nodes[core]
        else {
            return Trace::new(Source::Unknown);
        };
        let mut terms = Vec::new();
        self.terms(addr, false, &mut terms, 0);
        let mut trace = Trace::new(Source::Unknown);
        trace.anchor = Some(at);
        let locals = terms
            .iter()
            .filter_map(|(term, _)| match self.nodes[*term] {
                Node::Local(local) => Some(local),
                _ => None,
            })
            .collect::<Vec<_>>();
        // A scaled loaded value or non-advancing local indexes a table in
        // memory (a handler-pointer or remap table). The selector is that
        // inner value, so classify it instead.
        if let Some((inner, _)) = terms.iter().find(|(term, scaled)| {
            *scaled
                && match self.nodes[*term] {
                    Node::Load { .. } => true,
                    Node::Local(local) => !self.advanced(local),
                    _ => false,
                }
        }) {
            let inner = self.classify(*inner, depth + 1);
            if inner.source != Source::Unknown {
                return inner;
            }
        }
        if locals.iter().any(|local| self.advanced(*local)) {
            trace.source = if terms.len() >= 2 {
                Source::CursorIndex
            } else {
                Source::CursorPointer
            };
            trace.advancing = locals;
            return trace;
        }
        // A pc reloaded from a saved slot before each fetch: frame_slot.
        let reloaded = locals
            .iter()
            .filter_map(|local| Some((Some(*local), self.reloaded(*local)?)))
            .collect::<Vec<_>>();
        if !reloaded.is_empty() {
            trace.source = Source::FrameSlot;
            trace.slots = reloaded;
            return trace;
        }
        if let Some((term, _)) = terms
            .iter()
            .find(|(term, _)| matches!(self.nodes[*term], Node::Load { .. }))
            && let Node::Load {
                addr: inner,
                offset: inner_offset,
                ..
            } = self.nodes[*term]
        {
            // A pointer loaded from memory, then dereferenced.
            trace.source = Source::FrameSlot;
            trace.slots = vec![(None, self.slot_key(inner, inner_offset))];
            return trace;
        }
        if terms.len() >= 2 && !locals.is_empty() {
            trace.source = Source::CursorIndex;
            trace.advancing = locals;
            return trace;
        }
        if terms
            .iter()
            .all(|(term, _)| matches!(self.nodes[*term], Node::Local(_) | Node::Global(_)))
        {
            // A field of an object or a fixed memory slot.
            trace.source = Source::FrameSlot;
            trace.slots = vec![(None, self.slot_key(addr, offset))];
            return trace;
        }
        trace
    }

    /// A stored value that adds to or subtracts from the slot's prior value,
    /// following at most two local writes.
    fn slot_advance(
        &self,
        value: NodeId,
        slot: &(String, u64),
        carrier: Option<u32>,
        depth: u8,
    ) -> bool {
        match self.nodes[value] {
            Node::Bin { op, a, b } if op.ends_with(".add") || op.ends_with(".sub") => {
                self.slot_read(a, slot, carrier) || self.slot_read(b, slot, carrier)
            }
            Node::Local(local) if depth < 2 => self
                .definitions(local)
                .iter()
                .any(|(_, def)| self.slot_advance(*def, slot, carrier, depth + 1)),
            _ => false,
        }
    }

    fn slot_read(&self, value: NodeId, slot: &(String, u64), carrier: Option<u32>) -> bool {
        match self.nodes[value] {
            Node::Local(local) => {
                Some(local) == carrier || self.reloaded(local).as_ref() == Some(slot)
            }
            Node::Load { addr, offset, .. } => self.slot_key(addr, offset) == *slot,
            _ => false,
        }
    }

    fn repeats(&self, trace: &Trace, site: usize) -> (Repeats, Option<(usize, usize)>) {
        let mut loops = self
            .loops
            .iter()
            .filter(|(start, end)| *start < site && site < *end)
            .copied()
            .collect::<Vec<_>>();
        loops.sort_by_key(|(start, end)| end - start);
        let Some(innermost) = loops.first().copied() else {
            return (Repeats::Once, None);
        };
        for (start, end) in loops {
            let inside = |offset: usize| start < offset && offset < end;
            // The selector must be produced inside the loop body, not once
            // before it, to be re-derived per iteration.
            if trace.anchor.is_some_and(|anchor| !inside(anchor)) {
                continue;
            }
            let written = trace.advancing.iter().any(|local| {
                self.definitions(*local)
                    .iter()
                    .any(|(offset, _)| inside(*offset))
            });
            let advances = match trace.source {
                Source::CursorIndex | Source::CursorPointer => written,
                // The slot is reloaded in this loop (when a local carries it)
                // and this loop stores back arithmetic over its own prior
                // value (`pc + n`). A constant state write or a linked-list
                // step is not an advancing position.
                Source::FrameSlot => trace.slots.iter().any(|(local, slot)| {
                    local.is_none_or(|local| {
                        self.definitions(local)
                            .iter()
                            .any(|(offset, _)| inside(*offset))
                    }) && self
                        .stores
                        .iter()
                        .any(|(offset, addr, store_offset, value)| {
                            inside(*offset)
                                && self.slot_key(*addr, *store_offset) == *slot
                                && self.slot_advance(*value, slot, *local, 0)
                        })
                }),
                Source::Constant | Source::HandlerAddress => written,
                _ => false,
            };
            if advances {
                return (Repeats::Loop, Some((start, end)));
            }
        }
        (Repeats::Unknown, Some(innermost))
    }

    fn render(&self, id: NodeId, depth: u8) -> String {
        if depth > 4 {
            return "...".into();
        }
        match &self.nodes[id] {
            Node::Unknown => "?".into(),
            Node::Const(value) if *value < 0 => {
                format!("-{}", self.render_constant(value.unsigned_abs()))
            }
            Node::Const(value) => self.render_constant(value.unsigned_abs()),
            Node::Local(local) => self.render_local(*local),
            Node::Global(global) => format!("global{global}"),
            Node::Load {
                op, addr, offset, ..
            } => {
                let addr = self.render(*addr, depth + 1);
                if *offset > 0 {
                    format!("{op}[{addr} + {offset}]")
                } else {
                    format!("{op}[{addr}]")
                }
            }
            Node::Bin { op, a, b }
                if op.ends_with(".add")
                    && matches!(self.nodes[*b], Node::Const(value) if value < 0) =>
            {
                let Node::Const(value) = self.nodes[*b] else {
                    unreachable!("matched a negative constant")
                };
                format!(
                    "({} - {})",
                    self.render(*a, depth + 1),
                    self.render_constant(value.unsigned_abs())
                )
            }
            Node::Bin { op, a, b } => {
                let symbol = match op.split('.').nth(1).unwrap_or(op) {
                    "add" => "+",
                    "sub" => "-",
                    "mul" => "*",
                    "and" => "&",
                    "or" => "|",
                    "xor" => "^",
                    "shl" => "<<",
                    "shr_u" | "shr_s" => ">>",
                    "eq" => "==",
                    "ne" => "!=",
                    other => other,
                };
                format!(
                    "({} {symbol} {})",
                    self.render(*a, depth + 1),
                    self.render(*b, depth + 1)
                )
            }
            Node::Un { op, a } => format!("{op}({})", self.render(*a, depth + 1)),
            Node::Call {
                callee: Some(callee),
                ..
            } => format!("call f{callee}(...)"),
            Node::Call { callee: None, .. } => "call_indirect(...)".into(),
        }
    }

    fn selector_text(&self, selector: NodeId, trace: &Trace) -> String {
        let text = self.render(selector, 0);
        let core = self.strip(selector);
        let mut text = match (&self.nodes[core], trace.definition) {
            (Node::Local(local), Some(definition)) => {
                let assignment = format!(
                    "{} = {}",
                    self.render_local(*local),
                    self.render(definition, 0)
                );
                if core == selector {
                    assignment
                } else {
                    format!("{text}; {assignment}")
                }
            }
            _ => text,
        };
        if trace.source == Source::FrameSlot
            && let Some((local, (base, offset))) = trace.slots.first()
        {
            let carrier = local.map_or_else(|| "selector".into(), |local| self.render_local(local));
            text.push_str(&format!("; {carrier} reloaded from [{base} + {offset}]"));
        }
        text
    }

    fn render_constant(&self, value: u64) -> String {
        if value > 255 {
            format!("{value:#x}")
        } else {
            value.to_string()
        }
    }

    fn render_local(&self, local: u32) -> String {
        if local < self.params {
            format!("param{local}")
        } else {
            format!("local{local}")
        }
    }
}

/// Classify every `br_table`, `call_indirect`, `return_call_indirect` and
/// equality ladder in a module. None only when the module does not decode.
pub(crate) fn wasm(
    bytes: &[u8],
    tables: Option<&crate::vm::wasm_tables::Tables>,
) -> Option<Vec<Site>> {
    let mut validator = Some(Validator::new_with_features(WasmFeatures::all()));
    let mut imported = 0u32;
    let mut defined = 0u32;
    let mut sites = Vec::new();
    let mut exports = BTreeSet::new();
    let mut export_offset = None;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.ok()?;
        let function = match validator.as_mut().map(|v| v.payload(&payload)) {
            Some(Ok(ValidPayload::Func(function, _))) => Some(function),
            Some(Err(_)) => {
                // Unsupported or invalid structure: keep classifying untyped.
                validator = None;
                None
            }
            _ => None,
        };
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    if matches!(import.ok()?.ty, TypeRef::Func(_)) {
                        imported += 1;
                    }
                }
            }
            Payload::ExportSection(reader) => {
                export_offset = Some(reader.range().start);
                for export in reader {
                    let export = export.ok()?;
                    if export.kind == ExternalKind::Func {
                        exports.insert(export.index);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let index = imported + defined;
                defined += 1;
                let function =
                    function.map(|f| f.into_validator(FuncValidatorAllocations::default()));
                let params = match &function {
                    Some(v) => v.len_locals(),
                    None => tables
                        .and_then(|tables| {
                            let ty = tables.function_types.get(index as usize)?;
                            tables.signatures.get(*ty as usize)?.as_ref()
                        })
                        .map_or(0, |(params, _)| params.len() as u32),
                };
                let range = body.range();
                let Some(facts) = Facts::simulate(&body, function, params) else {
                    continue;
                };
                classify_function(&facts, index, range.start, tables, &mut sites);
            }
            _ => (),
        }
    }
    if sites.is_empty() && exports.len() >= 2 {
        sites.push(Site {
            kind: Kind::ExportPerRole,
            source: Source::Unknown,
            repeats: Repeats::Unknown,
            instruction: "export",
            function_index: None,
            function_body_offset: None,
            byte_offset: export_offset.unwrap_or(8),
            byte_size: 1,
            line: None,
            column: None,
            selector_expression:
                "The host selects an exported function by name; no in-module selector.".into(),
            selector_offset: None,
            arm_count: Some(exports.len() as u64),
            loop_range: None,
            buffer_kind: None,
            table: None,
        });
    }
    Some(sites)
}

fn classify_function(
    facts: &Facts,
    index: u32,
    body_offset: usize,
    tables: Option<&crate::vm::wasm_tables::Tables>,
    sites: &mut Vec<Site>,
) {
    for dispatch in &facts.dispatch {
        let trace = facts.classify(dispatch.selector, 0);
        let (repeats, loop_range) = facts.repeats(&trace, dispatch.offset);
        let (kind, instruction, arm_count, table) = match dispatch.op {
            DispatchOp::BrTable { arms } => {
                (Kind::SwitchOnValue, "br_table", Some(u64::from(arms)), None)
            }
            DispatchOp::CallIndirect {
                table: table_index,
                ty,
                tail,
            } => {
                let kind = if tail || trace.source == Source::HandlerAddress {
                    Kind::Threaded
                } else {
                    Kind::HandlerTable
                };
                let matching = tables.and_then(|tables| tables.matching_slots(table_index, ty));
                let table = json!({
                    "table_index": table_index,
                    "type_index": ty,
                    "populated_slot_count": matching.as_ref().map(|(_, populated)| populated),
                    "matching_slot_count": matching.as_ref().map(|(slots, _)| slots.len()),
                    "matching_slots": matching.as_ref().map(|(slots, _)| {
                        slots.iter().take(MAX_LISTED_SLOTS).copied().collect::<Vec<_>>()
                    }),
                });
                (
                    kind,
                    if tail {
                        "return_call_indirect"
                    } else {
                        "call_indirect"
                    },
                    matching.map(|(slots, _)| slots.len() as u64),
                    Some(table),
                )
            }
        };
        sites.push(Site {
            kind,
            source: trace.source,
            repeats,
            instruction,
            function_index: Some(index),
            function_body_offset: Some(body_offset),
            byte_offset: dispatch.offset,
            byte_size: dispatch.size,
            line: None,
            column: None,
            selector_expression: facts.selector_text(dispatch.selector, &trace),
            selector_offset: trace.anchor,
            arm_count,
            loop_range,
            buffer_kind: None,
            table,
        });
    }
    let mut ladders = BTreeMap::<String, Vec<&Compare>>::new();
    for compare in &facts.compares {
        let subject = facts.strip(compare.subject);
        if matches!(facts.nodes[subject], Node::Unknown | Node::Const(_)) {
            continue;
        }
        ladders
            .entry(facts.render(subject, 0))
            .or_default()
            .push(compare);
    }
    for (subject, compares) in ladders {
        let constants = compares
            .iter()
            .map(|compare| compare.constant)
            .collect::<BTreeSet<_>>();
        if constants.len() < MIN_COMPARE_ARMS {
            continue;
        }
        let first = compares[0];
        let trace = facts.classify(first.subject, 0);
        let (repeats, loop_range) = facts.repeats(&trace, first.offset);
        sites.push(Site {
            kind: Kind::CompareChain,
            source: trace.source,
            repeats,
            instruction: "i32.eq ladder",
            function_index: Some(index),
            function_body_offset: Some(body_offset),
            byte_offset: first.offset,
            byte_size: first.size,
            line: None,
            column: None,
            selector_expression: format!("{subject} == constant ({} comparisons)", compares.len()),
            selector_offset: trace.anchor,
            arm_count: Some(compares.len() as u64),
            loop_range,
            buffer_kind: None,
            table: None,
        });
    }
}
