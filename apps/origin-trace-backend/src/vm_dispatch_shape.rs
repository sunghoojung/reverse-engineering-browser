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
// Contract registry exercised against every embedded schema and the real UI.
#[cfg(test)]
pub(crate) const OMISSION_REASONS: &[&str] = &[
    "classification-work-limit",
    "classification-trace-limit",
    "classification-region-limit",
    "classification-unavailable",
    "parse-failed",
    "analysis-worker-failed",
    "handler-binding-unproven",
];

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap},
};
use wasmparser::{
    ExternalKind, FuncValidator, FuncValidatorAllocations, FunctionBody, Operator, Parser, Payload,
    TypeRef, ValidPayload, Validator, ValidatorResources, WasmFeatures,
};

#[path = "vm_dispatch_shape_js.rs"]
pub(crate) mod javascript;

pub(crate) const CLASSIFICATION_VERSION: u32 = 1;
pub(crate) const MAX_LISTED_SITES: usize = 256;
/// Symbolic nodes per function. Analysis already rejects modules over one
/// million instructions, so this is a memory guard; past it every site of the
/// function is an honest unknown with a counted omission.
const MAX_NODES: usize = 1 << 20;
const MAX_TRACE_DEPTH: u8 = 16;
const MAX_EXPRESSION_CHARS: usize = 160;
/// Fewer equality tests are ordinary branching, not a selector ladder.
pub(crate) const MIN_COMPARE_ARMS: usize = 3;
const MAX_LISTED_SLOTS: usize = 32;
/// Alternative reaching sources kept per local, after merging alternatives
/// that differ only in where a constant or handler value was written.
/// Exceeding it makes the site an honest, counted unknown.
const MAX_ALTERNATIVES: usize = 16;
/// Logical trace steps for one selector query. Memo hits replay what a fresh
/// computation would spend, so a query's result never depends on order.
const MAX_QUERY_STEPS: u64 = 4096;
/// Handlers checked for one indirect call's threaded chain. A larger table is
/// an honest, counted unknown rather than a guessed chain.
const MAX_CHAIN_HANDLERS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Kind {
    SwitchOnValue,
    HandlerTable,
    CompareChain,
    ExportPerRole,
    Threaded,
    /// Reserved: a dispatch whose selection mechanism is not recognized.
    Unknown,
}

impl Kind {
    const ALL: [Kind; 6] = [
        Kind::SwitchOnValue,
        Kind::HandlerTable,
        Kind::CompareChain,
        Kind::ExportPerRole,
        Kind::Threaded,
        Kind::Unknown,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::SwitchOnValue => "switch_on_value",
            Self::HandlerTable => "handler_table",
            Self::CompareChain => "compare_chain",
            Self::ExportPerRole => "export_per_role",
            Self::Threaded => "threaded",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

/// Derived from the three axes plus two recorded refinements. A threaded
/// dispatch is an interpreter only when its next-handler index is re-derived
/// from a cursor each step; a chain of computed handler addresses is not. A
/// cursor loop over text (`buffer_kind` string or arguments) reads
/// characters or argument values, not opcodes. A switch or ladder on a table
/// read keyed by a cursor-loaded value is a lookup-driven walk, such as a
/// worklist or graph traversal; only a handler table, threaded or not, reads
/// its handler through that one lookup by design.
pub(crate) fn role(
    kind: Kind,
    source: Source,
    repeats: Repeats,
    buffer_kind: Option<&str>,
    through_lookup: bool,
) -> Role {
    let selects = matches!(
        kind,
        Kind::SwitchOnValue | Kind::HandlerTable | Kind::CompareChain
    );
    let interprets = selects || kind == Kind::Threaded;
    let text = matches!(buffer_kind, Some("string" | "arguments"));
    let lookup = through_lookup && !matches!(kind, Kind::HandlerTable | Kind::Threaded);
    if interprets && repeats == Repeats::Loop && source.cursor_like() && !text && !lookup {
        Role::InterpreterCandidate
    } else if selects && repeats == Repeats::Once && source == Source::CallArgument {
        Role::Multiplexer
    } else {
        Role::Other
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Site {
    /// Structural scheduling strength, never a ranking score.
    pub strength: u8,
    pub kind: Kind,
    pub source: Source,
    pub repeats: Repeats,
    pub instruction: std::borrow::Cow<'static, str>,
    pub function_index: Option<u32>,
    pub function_body_offset: Option<usize>,
    pub byte_offset: usize,
    pub byte_size: usize,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub selector_expression: String,
    pub selector_offset: Option<usize>,
    /// The selector is a table read keyed by a cursor-loaded value.
    pub through_lookup: bool,
    /// The selector is the value a statically bound helper call returns.
    pub through_helper: bool,
    pub arm_count: Option<u64>,
    pub loop_range: Option<(usize, usize)>,
    pub buffer_kind: Option<std::borrow::Cow<'static, str>>,
    #[serde(skip)]
    pub table: Option<SiteTable>,
}

/// A `call_indirect` site's table facts. The matching slots are one list
/// shared by every site with the same table and type, so a site costs a
/// pointer, not a copy; JSON is rendered only for listed sites.
pub(crate) struct SiteTable {
    pub table_index: u32,
    pub type_index: u32,
    pub matching: crate::vm::wasm_tables::Matching,
}

impl SiteTable {
    fn json(&self) -> Value {
        let matching = self.matching.as_deref();
        json!({
            "table_index": self.table_index,
            "type_index": self.type_index,
            "populated_slot_count": matching.map(|matching| matching.1),
            "matching_slot_count": matching.map(|matching| matching.0.len()),
            "matching_slots": matching.map(|matching| {
                let slots = &matching.0;
                slots.iter().take(MAX_LISTED_SLOTS).copied().collect::<Vec<_>>()
            }),
        })
    }
}

impl Site {
    /// Bytes this record keeps until the document is written, charged to
    /// the artifact meter so a module of millions of sites stays bounded.
    pub fn retained_bytes(&self) -> u64 {
        (std::mem::size_of::<Self>() * 2 + self.selector_expression.capacity()) as u64
    }

    pub fn role(&self) -> Role {
        role(
            self.kind,
            self.source,
            self.repeats,
            self.buffer_kind.as_deref(),
            self.through_lookup,
        )
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
pub(crate) fn document(artifact_id: &Value, mut sites: Vec<Site>, omissions: Vec<Value>) -> Value {
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
    sites.sort_by_key(|site| {
        (
            site.role(),
            std::cmp::Reverse(site.strength),
            site.byte_offset,
        )
    });
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
                    "through_lookup": site.through_lookup,
                    "through_helper": site.through_helper,
                },
                "arm_count": site.arm_count,
                "loop": site.loop_range.map(|(start, end)| json!({
                    "byte_offset": start,
                    "byte_size": end.saturating_sub(start).max(1),
                })),
                "buffer_kind": site.buffer_kind,
                "table": site.table.as_ref().map(SiteTable::json),
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
        "omissions": omissions,
    })
}

/// The role of every classified site of one artifact, keyed by its exact
/// dispatch byte offset. Built from the full classification, never from the
/// bounded listed document, so the listing cap cannot hide a site.
pub(crate) struct Roles {
    pub javascript: Option<std::rc::Rc<javascript::Proofs>>,
    roles: HashMap<usize, Role>,
    _memory: Memory,
    limited: bool,
    pub meter: Meter,
}

impl Roles {
    pub fn new(classified: &Classified, meter: &Meter) -> Self {
        let memory = Memory::new(meter);
        let available = memory.keep(classified.sites.len() as u64 * 64)
            && meter.charge(classified.sites.len() as u64 * 64);
        Self {
            meter: meter.clone(),
            javascript: classified.javascript.clone(),
            _memory: memory,
            roles: if available {
                classified
                    .sites
                    .iter()
                    .map(|site| (site.byte_offset, site.role()))
                    .collect()
            } else {
                HashMap::new()
            },
            limited: classified.omissions.iter().any(|omission| {
                matches!(
                    omission["reason"].as_str(),
                    Some("classification-work-limit" | "classification-region-limit")
                )
            }),
        }
    }

    /// None when no classified site starts at this offset.
    pub fn get(&self, offset: usize) -> Option<Role> {
        self.roles.get(&offset).copied()
    }

    /// A work bound refused sites, so an absent site may be unclassified.
    pub fn limited(&self) -> bool {
        self.limited || self.meter.exhausted()
    }
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

struct Query {
    trace: Trace,
    repeats: Repeats,
    range: Option<(usize, usize)>,
    limited: bool,
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
struct Facts<'a> {
    meter: &'a Meter,
    memory: Memory,
    params: u32,
    nodes: Vec<Node>,
    defs: BTreeMap<u32, Vec<(usize, NodeId)>>,
    /// (offset, address, memarg offset, stored value)
    stores: Vec<(usize, NodeId, u64, NodeId)>,
    loops: Vec<(usize, usize)>,
    dispatch: Vec<Dispatch>,
    compares: Vec<Compare>,
    /// Writes of each global, in offset order.
    global_defs: BTreeMap<u32, Vec<(usize, NodeId)>>,
    /// Values left as the function's result at `return` or its final `end`.
    returns: Vec<NodeId>,
    /// Functions of the module whose result is a cursor fetch at a position
    /// they advance themselves, with that fetch's source.
    fetchers: std::rc::Rc<HashMap<u32, Source>>,
    /// Per (table, type) of an indirect call: the fetch source every
    /// reachable handler returns, or None when too many handlers to check.
    chains: std::rc::Rc<HashMap<(u32, u32), Option<Source>>>,
    local_memo: RefCell<BTreeMap<u32, Memo>>,
    in_progress: RefCell<Vec<u32>>,
    steps: Cell<u64>,
    step_limit: Cell<u64>,
    /// Deepest trace depth reached by the current computation.
    deepest: Cell<u8>,
    /// A bound cut the current query short: its result is an honest unknown.
    limited: Cell<bool>,
    /// The depth bound cut the current computation; it is never memoized,
    /// because a shallower query could complete it.
    depth_cut: Cell<bool>,
    /// The function ran out of symbolic nodes during simulation.
    nodes_exhausted: bool,
    /// Stores grouped by the memory slot they write, built once.
    stores_by_slot: OnceCell<HashMap<SlotKey, Vec<(usize, NodeId)>>>,
    advanced_memo: RefCell<BTreeMap<u32, bool>>,
    reloaded_memo: RefCell<BTreeMap<u32, Option<SlotKey>>>,
    /// Whether a local's writes advance a given slot, keyed by (local, slot,
    /// carrier); each (local, slot) is walked once.
    slot_advance_memo: RefCell<HashMap<SlotAdvanceKey, bool>>,
    /// Whether a loop stores an advance of a slot back, keyed by (slot,
    /// carrier, loop): every site reading that slot shares one walk.
    loop_store_memo: RefCell<HashMap<LoopStoreKey, Vec<usize>>>,
    /// Loops sorted by start with each one's enclosing loop, built once, so
    /// a containment query walks only the nesting chain.
    loop_tree: OnceCell<Intervals>,
}

/// (followed local, slot, carrier local).
type SlotAdvanceKey = (u32, SlotKey, Option<u32>);
/// (slot, carrier local, loop range).
type LoopStoreKey = (SlotKey, Option<u32>);

/// Structured interval index. A sweep records the active innermost interval
/// at every boundary. Binary lifting finds the first enclosing interval
/// satisfying a monotone predicate in at most 32 probes, independent of
/// nesting depth. Offsets and interval identities are bounded by u32.
pub(crate) struct Intervals {
    pub ranges: Vec<(usize, usize)>,
    jumps: Vec<[u32; 32]>,
    roots: Vec<u32>,
    points: Vec<(usize, u32)>,
    _memory: Memory,
}

impl Intervals {
    pub fn new(ranges: impl IntoIterator<Item = (usize, usize)>, meter: &Meter) -> Self {
        let memory = Memory::new(meter);
        let mut this = Self {
            ranges: Vec::new(),
            jumps: Vec::new(),
            roots: Vec::new(),
            points: Vec::new(),
            _memory: memory,
        };
        // Collect under the reservation, rather than accepting an unchecked
        // allocation from a regex iterator or a cloned Wasm loop vector.
        let mut collected = Vec::new();
        for range in ranges {
            if !meter.charge(1) || !this._memory.push(&mut collected, range) {
                return this;
            }
        }
        let mut ranges = collected;
        // Covers capacity, sorting and sweep temporaries as well as the index.
        if !meter.charge(ranges.len() as u64 * 64)
            || !this._memory.keep(ranges.len() as u64 * 256)
            || ranges.len() >= u32::MAX as usize
        {
            return this;
        }
        ranges.sort_unstable_by_key(|(start, end)| (*start, std::cmp::Reverse(*end)));
        ranges.dedup();
        this.jumps = Vec::with_capacity(ranges.len());
        this.roots = Vec::with_capacity(ranges.len());
        this.points = Vec::with_capacity(ranges.len() * 2);
        let mut open = Vec::<usize>::with_capacity(ranges.len());
        for (index, &(start, end)) in ranges.iter().enumerate() {
            while let Some(&top) = open.last() {
                if ranges[top].1 > start && ranges[top].1 >= end {
                    break;
                }
                let closing = ranges[open.pop().unwrap()].1.min(start);
                this.points
                    .push((closing, open.last().map_or(u32::MAX, |s| *s as u32)));
            }
            let mut jump = [u32::MAX; 32];
            jump[0] = open.last().map_or(u32::MAX, |s| *s as u32);
            for level in 1..32 {
                if jump[level - 1] != u32::MAX {
                    jump[level] = this.jumps[jump[level - 1] as usize][level - 1];
                }
            }
            this.roots
                .push(open.last().map_or(index as u32, |s| this.roots[*s]));
            this.jumps.push(jump);
            this.points.push((start, index as u32));
            open.push(index);
        }
        while let Some(top) = open.pop() {
            this.points
                .push((ranges[top].1, open.last().map_or(u32::MAX, |s| *s as u32)));
        }
        this.ranges = ranges;
        this
    }

    pub fn at(&self, at: usize) -> Option<usize> {
        let i = self
            .points
            .partition_point(|(offset, _)| *offset <= at)
            .checked_sub(1)?;
        let index = self.points[i].1;
        (index != u32::MAX).then_some(index as usize)
    }

    pub fn innermost(&self, at: usize) -> Option<(usize, usize)> {
        self.at(at).map(|i| self.ranges[i])
    }

    pub fn matching(
        &self,
        mut index: usize,
        mut matches: impl FnMut((usize, usize)) -> bool,
    ) -> Option<(usize, usize)> {
        let root = self.roots[index] as usize;
        if !matches(self.ranges[root]) {
            return None;
        }
        if matches(self.ranges[index]) {
            return Some(self.ranges[index]);
        }
        for level in (0..32).rev() {
            let parent = self.jumps[index][level];
            if parent != u32::MAX && !matches(self.ranges[parent as usize]) {
                index = parent as usize;
            }
        }
        let parent = self.jumps[index][0];
        (parent != u32::MAX).then(|| self.ranges[parent as usize])
    }
}

/// A local trace plus what computing it fresh costs: the steps it consumes
/// and how many levels below its own depth it reaches. A memo hit charges
/// both, so a result never depends on the order sites are queried. When the
/// step budget cut the computation, `cost` is a lower bound: a hit that
/// cannot afford it is limited, exactly as recomputing would be, and any
/// other hit recomputes.
#[derive(Clone)]
struct Memo {
    traces: Vec<Trace>,
    cost: u64,
    height: u8,
    exhausted: bool,
}

/// A memory slot as (rendered base, byte offset).
type SlotKey = (String, u64);

/// Sources ranked for a site that no loop re-derives.
fn priority(source: Source) -> u8 {
    match source {
        Source::CursorIndex | Source::CursorPointer | Source::FrameSlot => 5,
        Source::CallArgument => 4,
        Source::HandlerAddress => 3,
        Source::Constant => 2,
        Source::Unknown => 0,
    }
}

fn preferred(traces: &[Trace]) -> Trace {
    traces
        .iter()
        .max_by_key(|trace| (priority(trace.source), std::cmp::Reverse(trace.anchor)))
        .cloned()
        .unwrap_or_else(|| Trace::new(Source::Unknown))
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
    /// The selector is a table read keyed by a cursor-loaded value, not the
    /// fetched value itself.
    through_lookup: bool,
    /// Globals the function advances arithmetically, used as the cursor.
    globals: Vec<u32>,
    /// The function whose result is the fetched value, when the selector is
    /// a call to a helper that fetches at a cursor it advances itself.
    helper: Option<u32>,
    /// The selector is an earlier indirect call's result, and every handler
    /// that call can reach returns such a fetch: a threaded chain.
    chained: bool,
}

impl Trace {
    fn new(source: Source) -> Self {
        Self {
            source,
            advancing: Vec::new(),
            slots: Vec::new(),
            anchor: None,
            definition: None,
            through_lookup: false,
            globals: Vec::new(),
            helper: None,
            chained: false,
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

impl<'a> Facts<'a> {
    fn node(&mut self, node: Node) -> NodeId {
        if self.nodes.len() >= MAX_NODES {
            self.nodes_exhausted = true;
            return UNKNOWN;
        }
        if !self.memory.push(&mut self.nodes, node) {
            self.nodes_exhausted = true;
            return UNKNOWN;
        }
        self.nodes.len() - 1
    }

    /// None when the body does not decode or the meter runs out.
    fn simulate(
        body: &FunctionBody<'_>,
        mut validator: Option<FuncValidator<ValidatorResources>>,
        params: u32,
        meter: &'a Meter,
    ) -> Option<Self> {
        let mut facts = Facts {
            meter,
            memory: Memory::new(meter),
            params,
            nodes: vec![Node::Unknown],
            defs: BTreeMap::new(),
            stores: Vec::new(),
            loops: Vec::new(),
            dispatch: Vec::new(),
            compares: Vec::new(),
            global_defs: BTreeMap::new(),
            returns: Vec::new(),
            fetchers: std::rc::Rc::default(),
            chains: std::rc::Rc::default(),
            local_memo: RefCell::new(BTreeMap::new()),
            in_progress: RefCell::new(Vec::new()),
            steps: Cell::new(0),
            step_limit: Cell::new(MAX_QUERY_STEPS),
            deepest: Cell::new(0),
            limited: Cell::new(false),
            depth_cut: Cell::new(false),
            nodes_exhausted: false,
            stores_by_slot: OnceCell::new(),
            advanced_memo: RefCell::new(BTreeMap::new()),
            reloaded_memo: RefCell::new(BTreeMap::new()),
            slot_advance_memo: RefCell::new(HashMap::new()),
            loop_store_memo: RefCell::new(HashMap::new()),
            loop_tree: OnceCell::new(),
        };
        if !facts
            .memory
            .keep((std::mem::size_of::<Node>() + 128) as u64)
        {
            return None;
        }
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
        let temporary = Memory::new(meter);
        let mut reader = body.get_operators_reader().ok()?;
        let mut stack: Vec<NodeId> = Vec::new();
        let mut frames: Vec<Frame> = Vec::new();
        while !reader.eof() {
            if !meter.charge(1) {
                return None;
            }
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
                    temporary.push(
                        &mut frames,
                        Frame {
                            height: stack.len(),
                            is_loop: matches!(op, Operator::Loop { .. }),
                            start,
                        },
                    );
                    for _ in 0..carried {
                        if !meter.charge(1) || !temporary.push(&mut stack, UNKNOWN) {
                            return None;
                        }
                    }
                }
                Operator::Else => {
                    if let Some(frame) = frames.last() {
                        stack.truncate(frame.height);
                    }
                    let carried = arity.map_or(0, |(_, params)| params as usize);
                    for _ in 0..carried {
                        if !meter.charge(1) || !temporary.push(&mut stack, UNKNOWN) {
                            return None;
                        }
                    }
                }
                Operator::End => {
                    if let Some(frame) = frames.pop() {
                        stack.truncate(frame.height);
                        if frame.is_loop {
                            facts.memory.push(&mut facts.loops, (frame.start, end));
                        }
                        let results = arity.map_or(0, |(_, results)| results as usize);
                        for _ in 0..results {
                            if !meter.charge(1) || !temporary.push(&mut stack, UNKNOWN) {
                                return None;
                            }
                        }
                    } else if let Some(&value) = stack.last() {
                        // The function's final `end`: its result.
                        facts.memory.push(&mut facts.returns, value);
                    }
                }
                Operator::GlobalSet { global_index } => {
                    let value = pop(&mut stack);
                    if !facts.global_defs.contains_key(global_index) && !facts.memory.keep(96) {
                        return None;
                    }
                    facts.memory.push(
                        facts.global_defs.entry(*global_index).or_default(),
                        (start, value),
                    );
                }
                Operator::LocalGet { local_index } => {
                    let id = facts.node(Node::Local(*local_index));
                    temporary.push(&mut stack, id);
                }
                Operator::LocalSet { local_index } | Operator::LocalTee { local_index } => {
                    let value = pop(&mut stack);
                    if !facts.defs.contains_key(local_index) && !facts.memory.keep(96) {
                        return None;
                    }
                    facts
                        .memory
                        .push(facts.defs.entry(*local_index).or_default(), (start, value));
                    if matches!(op, Operator::LocalTee { .. }) {
                        temporary.push(&mut stack, value);
                    }
                }
                Operator::GlobalGet { global_index } => {
                    let id = facts.node(Node::Global(*global_index));
                    temporary.push(&mut stack, id);
                }
                Operator::I32Const { value } => {
                    let id = facts.node(Node::Const(i64::from(*value)));
                    temporary.push(&mut stack, id);
                }
                Operator::I64Const { value } => {
                    let id = facts.node(Node::Const(*value));
                    temporary.push(&mut stack, id);
                }
                Operator::BrIf { .. } => {
                    let condition = pop(&mut stack);
                    facts.compare(condition, start, end - start);
                }
                Operator::BrTable { targets } => {
                    let selector = pop(&mut stack);
                    facts.memory.push(
                        &mut facts.dispatch,
                        Dispatch {
                            op: DispatchOp::BrTable {
                                arms: targets.len(),
                            },
                            offset: start,
                            size: end - start,
                            selector,
                        },
                    );
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
                    facts.memory.push(
                        &mut facts.dispatch,
                        Dispatch {
                            op: DispatchOp::CallIndirect {
                                table: *table_index,
                                ty: *type_index,
                                tail: matches!(op, Operator::ReturnCallIndirect { .. }),
                            },
                            offset: start,
                            size: end - start,
                            selector,
                        },
                    );
                    let Some((params, results)) = arity else {
                        // Without arity the call's operands and results are
                        // unknown: drop to the frame floor, never guess.
                        stack.truncate(floor);
                        continue;
                    };
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
                            temporary.push(&mut stack, id);
                        }
                    }
                }
                Operator::Call { function_index } => {
                    let Some((params, results)) = arity else {
                        stack.truncate(floor);
                        continue;
                    };
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
                        temporary.push(&mut stack, id);
                    }
                }
                other => {
                    if matches!(other, Operator::Return) && stack.len() > floor {
                        let value = *stack.last().expect("returned value");
                        facts.memory.push(&mut facts.returns, value);
                    }
                    if let Some((name, offset)) = load_op(other) {
                        let addr = pop(&mut stack);
                        let id = facts.node(Node::Load {
                            op: name,
                            addr,
                            offset,
                            at: start,
                        });
                        temporary.push(&mut stack, id);
                    } else if let Some(offset) = store_offset(other) {
                        let value = pop(&mut stack);
                        let addr = pop(&mut stack);
                        facts
                            .memory
                            .push(&mut facts.stores, (start, addr, offset, value));
                    } else if let Some(name) = binary_op(other) {
                        let b = pop(&mut stack);
                        let a = pop(&mut stack);
                        let id = facts.node(Node::Bin { op: name, a, b });
                        temporary.push(&mut stack, id);
                    } else if let Some(name) = unary_op(other) {
                        let a = pop(&mut stack);
                        let id = facts.node(Node::Un { op: name, a });
                        temporary.push(&mut stack, id);
                    } else if let Some((params, results)) = arity {
                        for _ in 0..params {
                            pop(&mut stack);
                        }
                        for _ in 0..results {
                            if !meter.charge(1) || !temporary.push(&mut stack, UNKNOWN) {
                                return None;
                            }
                        }
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
        (!meter.exhausted()).then_some(facts)
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
            self.memory.push(
                &mut self.compares,
                Compare {
                    subject,
                    constant,
                    offset,
                    size,
                },
            );
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

    /// Every write of a local. Walking them is charged per step, so a local
    /// with many writes ends in an honest limit, never a silent prefix.
    fn definitions(&self, local: u32) -> &[(usize, NodeId)] {
        self.defs.get(&local).map_or(&[], Vec::as_slice)
    }

    /// Masks and width conversions only; constant offsets stay.
    fn strip_masks(&self, mut id: NodeId) -> NodeId {
        for _ in 0..16 {
            match self.nodes[id] {
                Node::Bin { op, a, b }
                    if self.is_const(b)
                        && [".and", ".or", ".xor", ".shr_u", ".shr_s", ".rem_u"]
                            .iter()
                            .any(|suffix| op.ends_with(suffix)) =>
                {
                    id = a
                }
                Node::Un { op, a } if !op.ends_with("eqz") => id = a,
                _ => break,
            }
        }
        id
    }

    /// `local = local ± n`, through masks or width casts. A linked-list step
    /// (`p = p->next`), a pop or a reload is not an arithmetic advance.
    fn advances_itself(&self, def: NodeId, local: u32) -> bool {
        match self.nodes[self.strip_masks(def)] {
            Node::Bin { op, a, b } if op.ends_with(".add") || op.ends_with(".sub") => [a, b]
                .iter()
                .any(|side| matches!(self.nodes[self.strip_masks(*side)], Node::Local(l) if l == local)),
            _ => false,
        }
    }

    /// A local some write advances arithmetically (`pc = pc + n`). Computed
    /// once per local over all of its writes.
    fn advanced(&self, local: u32) -> bool {
        if let Some(advanced) = self.advanced_memo.borrow().get(&local) {
            return *advanced;
        }
        let defs = self.definitions(local);
        self.meter.charge(defs.len() as u64);
        let advanced = defs
            .iter()
            .any(|(_, def)| self.advances_itself(*def, local));
        if self.memory.keep(64) {
            self.advanced_memo.borrow_mut().insert(local, advanced);
        }
        advanced
    }

    /// A global some write in this function advances arithmetically
    /// (`global.set g (global.get g + n)`): a program position that
    /// persists across calls.
    fn advanced_global(&self, global: u32) -> bool {
        let defs = self.global_defs.get(&global).map_or(&[][..], Vec::as_slice);
        self.meter.charge(defs.len() as u64);
        defs.iter().any(|(_, def)| {
            match self.nodes[self.strip_masks(*def)] {
                Node::Bin { op, a, b } if op.ends_with(".add") || op.ends_with(".sub") => [a, b]
                    .iter()
                    .any(|side| matches!(self.nodes[self.strip_masks(*side)], Node::Global(g) if g == global)),
                _ => false,
            }
        })
    }

    /// The advanced global an address term reads, directly or through a
    /// local every write of which copies it (`pc = global.get g`).
    fn global_cursor(&self, term: NodeId) -> Option<u32> {
        match self.nodes[term] {
            Node::Global(global) => self.advanced_global(global).then_some(global),
            Node::Local(local) if local >= self.params => {
                let defs = self.definitions(local);
                self.meter.charge(defs.len() as u64);
                let mut global = None;
                for (_, def) in defs.iter().take(64) {
                    match self.nodes[self.strip(*def)] {
                        Node::Global(g) if global.is_none_or(|known| known == g) => {
                            global = Some(g)
                        }
                        _ => return None,
                    }
                }
                global.filter(|global| defs.len() <= 64 && self.advanced_global(*global))
            }
            _ => None,
        }
    }

    fn global_written_inside(&self, global: u32, (start, end): (usize, usize)) -> bool {
        let defs = self.global_defs.get(&global).map_or(&[][..], Vec::as_slice);
        let first = defs.partition_point(|(offset, _)| *offset <= start);
        defs.get(first).is_some_and(|(offset, _)| *offset < end)
    }

    fn loop_index(&self) -> &Intervals {
        self.loop_tree
            .get_or_init(|| Intervals::new(self.loops.iter().copied(), self.meter))
    }

    fn in_any_loop(&self, offset: usize) -> bool {
        self.meter.charge(32);
        self.loop_index().at(offset).is_some()
    }

    fn innermost_loop(&self, offset: Option<usize>) -> Option<(usize, usize)> {
        self.meter.charge(32);
        self.loop_index().innermost(offset?)
    }

    /// One logical trace step against the query's budget, and one unit of
    /// real work on the artifact meter.
    fn step(&self) -> bool {
        let used = self.steps.get();
        if used >= self.step_limit.get() || !self.meter.charge(1) {
            self.limited.set(true);
            return false;
        }
        self.steps.set(used + 1);
        true
    }

    fn slot_key(&self, addr: NodeId, offset: u64) -> SlotKey {
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

    /// Stores grouped by the slot they write, built once per function.
    fn stores_for(&self, slot: &SlotKey) -> &[(usize, NodeId)] {
        let groups = self.stores_by_slot.get_or_init(|| {
            self.meter.charge(self.stores.len() as u64);
            let mut groups = HashMap::<SlotKey, Vec<(usize, NodeId)>>::new();
            for (offset, addr, store_offset, value) in &self.stores {
                let key = self.slot_key(*addr, *store_offset);
                if !groups.contains_key(&key) && !self.memory.keep(128 + key.0.len() as u64) {
                    break;
                }
                if !self
                    .memory
                    .push(groups.entry(key).or_default(), (*offset, *value))
                {
                    break;
                }
            }
            groups
        });
        groups.get(slot).map_or(&[], Vec::as_slice)
    }

    /// The fixed memory slot a local is reloaded from: one write loads a
    /// field of a stable base (or a constant address), not an indexed or
    /// advancing position, so a loaded opcode is never mistaken for a pc.
    /// Computed once per local.
    fn reloaded(&self, local: u32) -> Option<SlotKey> {
        if let Some(slot) = self.reloaded_memo.borrow().get(&local) {
            return slot.clone();
        }
        self.meter.charge(self.definitions(local).len() as u64);
        let slot = self.definitions(local).iter().find_map(|(_, def)| {
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
        });
        if self
            .memory
            .keep(96 + slot.as_ref().map_or(0, |slot| slot.0.len()) as u64)
        {
            self.reloaded_memo.borrow_mut().insert(local, slot.clone());
        }
        slot
    }

    fn reach(&self, depth: u8) {
        if depth > self.deepest.get() {
            self.deepest.set(depth);
        }
    }

    /// Every source that can reach a value, one alternative per producing
    /// write. The flag is true when a cycle cut the trace short; such
    /// results are never memoized. A depth, step or alternatives bound sets
    /// `limited`, which turns the whole query into an honest unknown.
    fn classify(&self, id: NodeId, depth: u8) -> (Vec<Trace>, bool) {
        self.reach(depth);
        if depth > MAX_TRACE_DEPTH {
            self.limited.set(true);
            self.depth_cut.set(true);
            return (vec![Trace::new(Source::Unknown)], true);
        }
        if !self.step() {
            return (vec![Trace::new(Source::Unknown)], true);
        }
        let core = self.strip(id);
        match self.nodes[core] {
            Node::Const(_) => (vec![Trace::new(Source::Constant)], false),
            Node::Local(local) => self.local(local, depth),
            Node::Load { .. } => self.load(core, depth),
            Node::Call { callee: None, at } => {
                let mut trace = Trace::new(Source::HandlerAddress);
                trace.anchor = Some(at);
                let call = self
                    .dispatch
                    .binary_search_by_key(&at, |dispatch| dispatch.offset)
                    .ok()
                    .and_then(|position| match self.dispatch[position].op {
                        DispatchOp::CallIndirect { table, ty, .. } => Some((table, ty)),
                        DispatchOp::BrTable { .. } => None,
                    });
                match call.and_then(|call| self.chains.get(&call)) {
                    Some(Some(source)) => {
                        trace.source = *source;
                        trace.chained = true;
                    }
                    // Too many reachable handlers to prove: an honest limit.
                    Some(None) => self.limited.set(true),
                    None => (),
                }
                (vec![trace], false)
            }
            Node::Call {
                callee: Some(callee),
                at,
            } => {
                let mut trace = Trace::new(Source::Unknown);
                if let Some(source) = self.fetchers.get(&callee) {
                    trace.source = *source;
                    trace.helper = Some(callee);
                    trace.anchor = Some(at);
                }
                (vec![trace], false)
            }
            _ => (vec![Trace::new(Source::Unknown)], false),
        }
    }

    fn local(&self, local: u32, depth: u8) -> (Vec<Trace>, bool) {
        let memo = self.local_memo.borrow().get(&local).cloned();
        if let Some(memo) = memo {
            // Replay what computing it fresh would cost here.
            self.reach(depth.saturating_add(memo.height));
            if depth.saturating_add(memo.height) > MAX_TRACE_DEPTH {
                self.limited.set(true);
                self.depth_cut.set(true);
                return (vec![Trace::new(Source::Unknown)], true);
            }
            let used = self.steps.get();
            if used.saturating_add(memo.cost) >= self.step_limit.get()
                && (memo.exhausted || used.saturating_add(memo.cost) > self.step_limit.get())
            {
                self.steps.set(self.step_limit.get());
                self.limited.set(true);
                return (vec![Trace::new(Source::Unknown)], true);
            }
            if !memo.exhausted {
                // The meter sees only the lookup this hit performs.
                self.meter.charge(1 + memo.traces.len() as u64);
                self.steps.set(used + memo.cost);
                return (memo.traces, false);
            }
        }
        if self.in_progress.borrow().contains(&local) {
            return (vec![Trace::new(Source::Unknown)], true);
        }
        let outer_deepest = self.deepest.replace(depth);
        let outer_limited = self.limited.replace(false);
        let outer_depth_cut = self.depth_cut.replace(false);
        let before = self.steps.get();
        self.in_progress.borrow_mut().push(local);
        let (traces, provisional) = self.local_uncached(local, depth);
        self.in_progress.borrow_mut().pop();
        let height = self.deepest.get() - depth;
        let limited = self.limited.get();
        let depth_cut = self.depth_cut.get();
        // A cycle or the depth bound depends on where the query started, so
        // only budget-independent outcomes and budget exhaustion are kept.
        if !depth_cut
            && (!provisional || limited)
            && self.memory.keep(
                128 + traces
                    .iter()
                    .map(|trace| {
                        256 + trace.advancing.capacity() as u64 * 4
                            + trace
                                .slots
                                .iter()
                                .map(|(_, slot)| 64 + slot.0.len() as u64)
                                .sum::<u64>()
                    })
                    .sum::<u64>(),
            )
        {
            self.local_memo.borrow_mut().insert(
                local,
                Memo {
                    traces: traces.clone(),
                    cost: self.steps.get() - before,
                    height,
                    exhausted: limited,
                },
            );
        }
        self.deepest.set(outer_deepest.max(self.deepest.get()));
        self.limited.set(outer_limited || limited);
        self.depth_cut.set(outer_depth_cut || depth_cut);
        (traces, provisional || limited)
    }

    fn local_uncached(&self, local: u32, depth: u8) -> (Vec<Trace>, bool) {
        let defs = self.definitions(local);
        let parameter = local < self.params;
        let mut traces: Vec<Trace> = Vec::new();
        let mut provisional = false;
        // The incoming argument reaches every use the function does not
        // overwrite first; without flow order it is always an alternative.
        if parameter {
            traces.push(Trace::new(Source::CallArgument));
        } else if defs.is_empty() {
            traces.push(Trace::new(Source::Constant));
        }
        for (at, def) in defs {
            if !self.step() {
                provisional = true;
                break;
            }
            // An advance (`pc + 1`), a normalization (`key & 255`) or another
            // self-derived write adds no new value source.
            if self.advances_itself(*def, local)
                || matches!(self.nodes[self.strip(*def)], Node::Local(l) if l == local)
                || self.references(*def, local, 0)
            {
                continue;
            }
            let (sources, cut) = self.classify(*def, depth + 1);
            provisional |= cut;
            for mut trace in sources {
                if trace.anchor.is_none() {
                    trace.anchor = Some(*at);
                }
                trace.definition = Some(*def);
                match trace.source {
                    Source::Constant => {
                        trace.advancing = vec![local];
                        trace.anchor = Some(*at);
                    }
                    Source::HandlerAddress => trace.advancing.push(local),
                    _ => (),
                }
                // Constant and handler writes differ only by where they land:
                // one per enclosing loop explains every repeat decision.
                let merges = matches!(trace.source, Source::Constant | Source::HandlerAddress);
                let duplicate = traces.iter().any(|known| {
                    known.source == trace.source
                        && known.through_lookup == trace.through_lookup
                        && if merges {
                            self.innermost_loop(known.anchor) == self.innermost_loop(trace.anchor)
                                && known.anchor.is_some() == trace.anchor.is_some()
                        } else {
                            known.anchor == trace.anchor
                        }
                });
                if duplicate {
                    continue;
                }
                if traces.len() >= MAX_ALTERNATIVES {
                    self.limited.set(true);
                    break;
                }
                traces.push(trace);
            }
        }
        // Constant writes inside a loop make the argument only the seed of a
        // flattened state machine. Outside loops they are guards or defaults.
        if parameter
            && traces.iter().any(|trace| {
                trace.source == Source::Constant
                    && trace.anchor.is_some_and(|at| self.in_any_loop(at))
            })
        {
            traces.retain(|trace| trace.source != Source::CallArgument);
        }
        if traces.is_empty() {
            traces.push(Trace::new(Source::Unknown));
        }
        (traces, provisional)
    }

    fn load(&self, core: NodeId, depth: u8) -> (Vec<Trace>, bool) {
        let Node::Load {
            addr, offset, at, ..
        } = self.nodes[core]
        else {
            return (vec![Trace::new(Source::Unknown)], false);
        };
        let mut terms = Vec::new();
        self.terms(addr, false, &mut terms, 0);
        let mut trace = Trace::new(Source::Unknown);
        trace.anchor = Some(at);
        let mut provisional = false;
        let locals = terms
            .iter()
            .filter_map(|(term, _)| match self.nodes[*term] {
                Node::Local(local) => Some(local),
                _ => None,
            })
            .collect::<Vec<_>>();
        // A scaled loaded value or non-advancing local indexes a table in
        // memory (a handler-pointer or remap table). The selector is that
        // inner value, read through a lookup.
        if let Some((inner, _)) = terms.iter().find(|(term, scaled)| {
            *scaled
                && match self.nodes[*term] {
                    Node::Load { .. } => true,
                    Node::Local(local) => !self.advanced(local),
                    _ => false,
                }
        }) {
            let (mut inner, cut) = self.classify(*inner, depth + 1);
            provisional |= cut;
            if inner.iter().any(|trace| trace.source != Source::Unknown) {
                for trace in &mut inner {
                    trace.through_lookup |= trace.source.cursor_like();
                }
                return (inner, provisional);
            }
        }
        let advanced = locals
            .iter()
            .copied()
            .filter(|local| self.advanced(*local))
            .collect::<Vec<_>>();
        if !advanced.is_empty() {
            trace.source = if terms.len() >= 2 {
                Source::CursorIndex
            } else {
                Source::CursorPointer
            };
            trace.advancing = advanced;
            return (vec![trace], provisional);
        }
        let globals = terms
            .iter()
            .filter_map(|(term, _)| self.global_cursor(*term))
            .collect::<Vec<_>>();
        if !globals.is_empty() {
            trace.source = if terms.len() >= 2 {
                Source::CursorIndex
            } else {
                Source::CursorPointer
            };
            trace.globals = globals;
            return (vec![trace], provisional);
        }
        // A pc reloaded from a saved slot before each fetch: frame_slot.
        let reloaded = locals
            .iter()
            .filter_map(|local| Some((Some(*local), self.reloaded(*local)?)))
            .collect::<Vec<_>>();
        if !reloaded.is_empty() {
            trace.source = Source::FrameSlot;
            trace.slots = reloaded;
            return (vec![trace], provisional);
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
            return (vec![trace], provisional);
        }
        if terms.len() >= 2 {
            // A table read at an index nothing advances is a lookup, not a
            // cursor: its source is the source of the index values. An index
            // loaded at a cursor makes a second-level lookup.
            let mut sources = Vec::new();
            for (term, _) in &terms {
                match self.nodes[*term] {
                    Node::Local(local) => {
                        let (alternatives, cut) = self.local(local, depth + 1);
                        provisional |= cut;
                        let best = preferred(&alternatives);
                        if best.source.cursor_like() {
                            let mut lookup = best;
                            lookup.through_lookup = true;
                            return (vec![lookup], provisional);
                        }
                        sources.push(best.source);
                    }
                    Node::Global(_) => (),
                    _ => sources.push(Source::Unknown),
                }
            }
            trace.source = if sources.iter().all(|source| *source == Source::CallArgument) {
                Source::CallArgument
            } else if sources
                .iter()
                .all(|source| matches!(source, Source::CallArgument | Source::Constant))
            {
                trace.advancing = locals;
                Source::Constant
            } else {
                Source::Unknown
            };
            if trace.source == Source::CallArgument {
                trace.anchor = None;
            }
            return (vec![trace], provisional);
        }
        if terms
            .iter()
            .all(|(term, _)| matches!(self.nodes[*term], Node::Local(_) | Node::Global(_)))
        {
            // A field of an object or a fixed memory slot.
            trace.source = Source::FrameSlot;
            trace.slots = vec![(None, self.slot_key(addr, offset))];
        }
        (vec![trace], provisional)
    }

    /// A stored value that adds to or subtracts from the slot's prior value,
    /// following at most two local writes. Every write of a followed local
    /// is examined, with no prefix cut; each (local, slot) walk is memoized
    /// and charged to the meter.
    fn slot_advance(&self, value: NodeId, slot: &SlotKey, carrier: Option<u32>, depth: u8) -> bool {
        match self.nodes[value] {
            Node::Bin { op, a, b } if op.ends_with(".add") || op.ends_with(".sub") => {
                self.slot_read(a, slot, carrier) || self.slot_read(b, slot, carrier)
            }
            Node::Local(local) if depth < 2 => {
                let key = (local, slot.clone(), carrier);
                if let Some(advances) = self.slot_advance_memo.borrow().get(&key) {
                    self.meter.charge(1);
                    return *advances;
                }
                // A cycle through this local contributes no advance.
                self.slot_advance_memo
                    .borrow_mut()
                    .insert(key.clone(), false);
                let defs = self.definitions(local);
                self.meter.charge(defs.len() as u64);
                let advances = defs
                    .iter()
                    .any(|(_, def)| self.slot_advance(*def, slot, carrier, depth + 1));
                if self.memory.keep(128 + slot.0.len() as u64) {
                    self.slot_advance_memo.borrow_mut().insert(key, advances);
                }
                advances
            }
            _ => false,
        }
    }

    /// Whether a loop stores an advance of `slot` back, walked once per
    /// (slot, carrier, loop) however many sites read the slot.
    fn stores_back(
        &self,
        slot: &SlotKey,
        carrier: Option<u32>,
        (start, end): (usize, usize),
    ) -> bool {
        let key = (slot.clone(), carrier);
        if !self.loop_store_memo.borrow().contains_key(&key) {
            let mut advanced = Vec::new();
            for (offset, value) in self.stores_for(slot) {
                if !self.meter.charge(1) {
                    break;
                }
                if self.slot_advance(*value, slot, carrier, 0) {
                    advanced.push(*offset);
                }
            }
            if !self
                .memory
                .keep((advanced.capacity() * 8 + 96 + slot.0.len()) as u64)
            {
                return false;
            }
            self.loop_store_memo
                .borrow_mut()
                .insert(key.clone(), advanced);
        }
        let memo = self.loop_store_memo.borrow();
        let offsets = &memo[&key];
        self.meter.charge(32);
        let first = offsets.partition_point(|offset| *offset <= start);
        offsets.get(first).is_some_and(|offset| *offset < end)
    }

    fn slot_read(&self, value: NodeId, slot: &SlotKey, carrier: Option<u32>) -> bool {
        match self.nodes[value] {
            Node::Local(local) => {
                Some(local) == carrier || self.reloaded(local).as_ref() == Some(slot)
            }
            Node::Load { addr, offset, .. } => self.slot_key(addr, offset) == *slot,
            _ => false,
        }
    }

    /// Whether a local has a write strictly inside a loop range. Writes are
    /// recorded in offset order, so this is a binary search.
    fn written_inside(&self, local: u32, (start, end): (usize, usize)) -> bool {
        let defs = self.definitions(local);
        let first = defs.partition_point(|(offset, _)| *offset <= start);
        defs.get(first).is_some_and(|(offset, _)| *offset < end)
    }

    fn repeats(&self, trace: &Trace, site: usize) -> (Repeats, Option<(usize, usize)>) {
        self.meter.charge(32);
        let loops = self.loop_index();
        let Some(index) = loops.at(site) else {
            return (Repeats::Once, None);
        };
        let innermost = loops.ranges[index];
        // A helper advances its own persistent cursor on every call, so a
        // loop around the call re-derives the selector each iteration.
        if trace.helper.is_some() || trace.chained {
            let matching = loops.matching(index, |(start, end)| {
                trace
                    .anchor
                    .is_some_and(|anchor| start < anchor && anchor < end)
            });
            return matching.map_or((Repeats::Unknown, Some(innermost)), |range| {
                (Repeats::Loop, Some(range))
            });
        }
        if !matches!(
            trace.source,
            Source::CursorIndex
                | Source::CursorPointer
                | Source::FrameSlot
                | Source::Constant
                | Source::HandlerAddress
        ) {
            return (Repeats::Unknown, Some(innermost));
        }
        if (trace.source == Source::FrameSlot && trace.slots.is_empty())
            || (trace.source != Source::FrameSlot
                && trace.advancing.is_empty()
                && trace.globals.is_empty())
        {
            return (Repeats::Unknown, Some(innermost));
        }
        let matching = loops.matching(index, |(start, end)| {
            self.meter.charge(32);
            if trace
                .anchor
                .is_some_and(|anchor| !(start < anchor && anchor < end))
            {
                return false;
            }
            match trace.source {
                Source::FrameSlot => trace.slots.iter().any(|(local, slot)| {
                    local.is_none_or(|local| self.written_inside(local, (start, end)))
                        && self.stores_back(slot, *local, (start, end))
                }),
                _ => {
                    trace
                        .advancing
                        .iter()
                        .any(|local| self.written_inside(*local, (start, end)))
                        || trace
                            .globals
                            .iter()
                            .any(|global| self.global_written_inside(*global, (start, end)))
                }
            }
        });
        matching.map_or((Repeats::Unknown, Some(innermost)), |range| {
            (Repeats::Loop, Some(range))
        })
    }

    /// The reaching source that best explains a site: one re-derived in a
    /// loop with a cursor-like selector, then any loop, then by source.
    fn choose(&self, traces: Vec<Trace>, site: usize) -> (Trace, Repeats, Option<(usize, usize)>) {
        let evaluated = traces
            .into_iter()
            .map(|trace| {
                let (repeats, range) = self.repeats(&trace, site);
                (trace, repeats, range)
            })
            .collect::<Vec<_>>();
        let position = evaluated
            .iter()
            .position(|(trace, repeats, _)| *repeats == Repeats::Loop && trace.source.cursor_like())
            .or_else(|| {
                evaluated
                    .iter()
                    .position(|(_, repeats, _)| *repeats == Repeats::Loop)
            })
            .unwrap_or_else(|| {
                let best = evaluated
                    .iter()
                    .map(|(trace, _, _)| priority(trace.source))
                    .max()
                    .unwrap_or(0);
                evaluated
                    .iter()
                    .position(|(trace, _, _)| priority(trace.source) == best)
                    .unwrap_or(0)
            });
        evaluated.into_iter().nth(position).unwrap_or((
            Trace::new(Source::Unknown),
            Repeats::Unknown,
            None,
        ))
    }

    /// Classify one selector under a fresh per-query step budget. A query a
    /// bound cut short, or one in a function that ran out of symbolic nodes,
    /// is an honest unknown, reported through the returned flag.
    /// None when the artifact meter ran out during the query: the site is
    /// then unclassified, not unknown.
    fn query(&self, selector: NodeId, site: usize) -> Option<Query> {
        let temporary = Memory::new(self.meter);
        if !temporary.keep(1 << 20) {
            return None;
        }
        self.steps.set(0);
        self.step_limit.set(MAX_QUERY_STEPS);
        self.deepest.set(0);
        self.limited.set(false);
        self.depth_cut.set(false);
        let (traces, _) = self.classify(selector, 0);
        let limited = self.limited.get() || self.nodes_exhausted;
        let (trace, repeats, range) = if limited {
            let trace = Trace::new(Source::Unknown);
            let (repeats, range) = self.repeats(&trace, site);
            (trace, repeats, range)
        } else {
            self.choose(traces, site)
        };
        if self.meter.exhausted() {
            return None;
        }
        Some(Query {
            trace,
            repeats,
            range,
            limited,
        })
    }

    /// The source of a cursor fetch this function returns at a position it
    /// advances itself: a global it advances, or a frame slot it stores back
    /// advanced. A cursor held only in a local starts fresh on every call,
    /// and a second-level lookup is a walk, so neither makes a fetch helper.
    fn fetch_summary(&self) -> Option<Source> {
        for &value in self.returns.iter().take(16) {
            self.steps.set(0);
            self.step_limit.set(MAX_QUERY_STEPS);
            self.deepest.set(0);
            self.limited.set(false);
            self.depth_cut.set(false);
            let (traces, _) = self.classify(value, 0);
            if self.limited.get() || self.nodes_exhausted {
                continue;
            }
            for trace in traces {
                if self.persistent(&trace) {
                    return Some(trace.source);
                }
            }
        }
        None
    }

    /// Every value this function returns is a constant: a handler that ends
    /// a threaded chain, such as halt. A function with more returns than a
    /// summary examines is not terminal.
    fn terminal(&self) -> bool {
        self.returns.len() <= 16
            && self
                .returns
                .iter()
                .all(|value| matches!(self.nodes[self.strip(*value)], Node::Const(_)))
    }

    /// A cursor fetch whose position outlives one call of this function: a
    /// global it advances, a frame slot it stores back advanced, or a fetch
    /// helper or threaded chain that advances its own.
    fn persistent(&self, trace: &Trace) -> bool {
        !trace.through_lookup
            && (trace.helper.is_some()
                || trace.chained
                || match trace.source {
                    Source::CursorIndex | Source::CursorPointer => !trace.globals.is_empty(),
                    Source::FrameSlot => trace
                        .slots
                        .iter()
                        .any(|(carrier, slot)| self.stores_back(slot, *carrier, (0, usize::MAX))),
                    _ => false,
                })
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
        if let Some(helper) = trace.helper {
            text.push_str(&format!(
                "; f{helper} returns a fetch at a cursor it advances"
            ));
        } else if trace.chained {
            text.push_str("; each reachable handler returns a fetch at a cursor it advances");
        } else if trace.source == Source::FrameSlot
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

/// Classified sites plus visible omissions for work the bounds refused.
pub(crate) struct Classified {
    pub javascript: Option<std::rc::Rc<javascript::Proofs>>,
    pub sites: Vec<Site>,
    pub omissions: Vec<Value>,
}

/// The one work meter for all classifier work on an artifact, JavaScript or
/// Wasm: every loop over bytes, writes, stores, sites or slots charges it with
/// the work it actually does, and retained index memory is charged against a
/// separate byte bound. Once either bound is reached, classification stops;
/// sites found but not classified and regions or functions not examined are
/// counted into a visible omission, never dropped silently.
///
/// The meter is distinct from each query's logical step budget, which
/// replays memoized cost so results never depend on query order. A memo hit
/// charges the meter only for the lookup it performs.
#[derive(Clone)]
pub(crate) struct Meter(std::rc::Rc<MeterState>);

impl std::ops::Deref for Meter {
    type Target = MeterState;
    fn deref(&self) -> &MeterState {
        &self.0
    }
}

pub(crate) struct MeterState {
    limit: u64,
    retained_limit: u64,
    used: Cell<u64>,
    retained: Cell<u64>,
    peak: Cell<u64>,
    parser_peak: Cell<u64>,
    exhausted: Cell<bool>,
    unclassified: Cell<u64>,
    unexamined: Cell<u64>,
    limited: Cell<u64>,
}

/// A reservation lives exactly as long as the allocation it covers. The
/// shared meter follows the artifact into the claim gate and workspace.
pub(crate) struct Memory {
    meter: Meter,
    bytes: Cell<u64>,
}

impl Memory {
    pub fn new(meter: &Meter) -> Self {
        Self {
            meter: meter.clone(),
            bytes: Cell::new(0),
        }
    }

    pub fn keep(&self, bytes: u64) -> bool {
        if !self.meter.retain(bytes) {
            return false;
        }
        self.bytes.set(self.bytes.get() + bytes);
        true
    }

    pub fn push<T>(&self, vector: &mut Vec<T>, item: T) -> bool {
        if vector.len() == vector.capacity() {
            let capacity = vector.capacity().max(4).saturating_mul(2);
            let extra = capacity - vector.capacity();
            if !self.keep((extra * std::mem::size_of::<T>()) as u64) {
                return false;
            }
            vector.reserve_exact(capacity - vector.len());
        }
        vector.push(item);
        true
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        self.meter.release(self.bytes.get());
    }
}

/// Work units per artifact. Each unit is a byte scanned, a write, store, slot
/// or site visited, or one trace step.
pub(crate) const MAX_ARTIFACT_WORK: u64 = 1_000_000_000;
/// Index and symbolic-trace memory retained at once per artifact.
pub(crate) const MAX_RETAINED_BYTES: u64 = 128 << 20;

impl Meter {
    pub fn new() -> Self {
        Self::with_limits(MAX_ARTIFACT_WORK, MAX_RETAINED_BYTES)
    }

    pub fn with_limits(limit: u64, retained_limit: u64) -> Self {
        Self(std::rc::Rc::new(MeterState {
            limit,
            retained_limit,
            used: Cell::new(0),
            retained: Cell::new(0),
            peak: Cell::new(0),
            parser_peak: Cell::new(0),
            exhausted: Cell::new(false),
            unclassified: Cell::new(0),
            unexamined: Cell::new(0),
            limited: Cell::new(0),
        }))
    }

    pub fn remaining_work(&self) -> u64 {
        self.limit.saturating_sub(self.used.get())
    }

    pub fn remaining_memory(&self) -> u64 {
        self.retained_limit.saturating_sub(self.retained.get())
    }

    #[cfg(test)]
    pub fn parser_peak(&self) -> u64 {
        self.parser_peak.get()
    }

    pub fn record_parser_peak(&self, bytes: u64) {
        self.parser_peak.set(self.parser_peak.get().max(bytes));
    }

    /// Charge work actually done. False once the bound is reached.
    pub fn charge(&self, work: u64) -> bool {
        if self.exhausted.get() {
            return false;
        }
        let used = self.used.get().saturating_add(work);
        if used > self.limit {
            self.used.set(self.limit);
            self.exhausted.set(true);
            return false;
        }
        self.used.set(used);
        crate::js_worker_alloc::record_work(used);
        true
    }

    /// Charge memory a structure keeps until it is released.
    pub fn retain(&self, bytes: u64) -> bool {
        if self.exhausted.get() {
            return false;
        }
        let retained = self.retained.get().saturating_add(bytes);
        if retained > self.retained_limit {
            self.exhausted.set(true);
            return false;
        }
        self.retained.set(retained);
        self.peak.set(self.peak.get().max(retained));
        true
    }

    pub fn release(&self, bytes: u64) {
        self.retained.set(self.retained.get().saturating_sub(bytes));
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted.get()
    }

    #[cfg(test)]
    pub fn used(&self) -> u64 {
        self.used.get()
    }

    #[cfg(test)]
    pub fn peak(&self) -> u64 {
        self.peak.get()
    }

    /// A dispatch site was found but not classified.
    pub fn count_unclassified(&self, sites: u64) {
        self.unclassified.set(self.unclassified.get() + sites);
    }

    /// A function region or Wasm function was not examined.
    pub fn count_unexamined(&self, units: u64) {
        self.unexamined.set(self.unexamined.get() + units);
    }

    pub fn count_limited(&self, limited: bool) {
        self.limited.set(self.limited.get() + u64::from(limited));
    }

    /// `unit` names what was not examined: function regions or functions.
    pub fn omissions(&self, unit: &str) -> Vec<Value> {
        let mut omissions = Vec::new();
        let (unclassified, unexamined) = (self.unclassified.get(), self.unexamined.get());
        if unclassified > 0 || unexamined > 0 || self.exhausted.get() {
            let mut omission = json!({
                "reason": "classification-work-limit",
                "detail": format!(
                    "A classification work, memory or site bound was reached: {unclassified} dispatch sites found were not classified and {unexamined} {unit} were not examined."
                ),
            });
            if unclassified > 0 {
                omission["omitted_records"] = json!(unclassified);
            }
            omissions.push(omission);
        }
        if self.limited.get() > 0 {
            omissions.push(json!({
                "reason": "classification-trace-limit",
                "detail": "A trace depth, step or alternative bound, or a symbolic node bound, cut these selector traces short; they are reported as unknown.",
                "omitted_records": self.limited.get(),
            }));
        }
        omissions
    }
}

/// Classify every `br_table`, `call_indirect`, `return_call_indirect` and
/// equality ladder in a module. None only when the module does not decode.
///
/// Every function is simulated first, under the meter. Sites are then ranked
/// module-wide by dispatch strength, loop-enclosed sites with a load-derived
/// selector first, and classified in that order, so trivial noise elsewhere
/// cannot exhaust the meter before a real interpreter is reached.
pub(crate) fn wasm(bytes: &[u8], meter: &Meter) -> Option<Classified> {
    let auxiliary = Memory::new(meter);
    // Validator metadata and parser-owned vectors are bounded by the encoded
    // module, separate from the explicitly reserved table and symbolic indexes.
    if !meter.charge(bytes.len() as u64) || !auxiliary.keep(bytes.len() as u64 * 4) {
        meter.count_unexamined(1);
        return Some(Classified {
            javascript: None,
            sites: Vec::new(),
            omissions: meter.omissions("functions"),
        });
    }
    let tables = crate::vm::wasm_tables::Tables::parse_under(bytes, meter);
    let tables = tables.as_ref();
    let mut validator = Some(Validator::new_with_features(WasmFeatures::all()));
    let mut imported = 0u32;
    let mut defined = 0u32;
    let mut functions = Vec::new();
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
                if meter.exhausted() {
                    meter.count_unexamined(1);
                    continue;
                }
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
                match Facts::simulate(&body, function, params, meter) {
                    Some(facts) => {
                        let pending = facts.dispatch.len() as u64;
                        if !auxiliary.push(&mut functions, (index, (range.start, range.end), facts))
                        {
                            meter.count_unclassified(pending);
                            meter.count_unexamined(1);
                        }
                    }
                    None if meter.exhausted() => meter.count_unexamined(1),
                    None => (),
                }
            }
            _ => (),
        }
    }
    // Helpers whose result is a cursor fetch they advance themselves. Only
    // callees of functions with dispatch sites are summarized, once each in
    // index order. Their memoized local traces are then discarded, so a site
    // query never depends on whether a summary ran first.
    let positions = functions
        .iter()
        .enumerate()
        .map(|(position, (index, _, _))| (*index, position))
        .collect::<HashMap<_, _>>();
    // Defined functions placed in each table with each call type, which an
    // indirect call of that (table, type) can reach; None when too many.
    let mut members = BTreeMap::<(u32, u32), Option<BTreeSet<u32>>>::new();
    let mut callees = BTreeSet::new();
    for (_, _, facts) in &functions {
        if facts.dispatch.is_empty() && facts.compares.is_empty() {
            continue;
        }
        if !meter.charge(facts.nodes.len() as u64) {
            break;
        }
        for node in &facts.nodes {
            if let Node::Call {
                callee: Some(callee),
                ..
            } = node
                && positions.contains_key(callee)
                && !callees.contains(callee)
                && auxiliary.keep(64)
            {
                callees.insert(*callee);
            }
        }
        for dispatch in &facts.dispatch {
            let (DispatchOp::CallIndirect { table, ty, .. }, Some(tables)) = (&dispatch.op, tables)
            else {
                continue;
            };
            if members.contains_key(&(*table, *ty)) || !auxiliary.keep(128) {
                continue;
            }
            // An expanded table too large to place is an honest limit.
            let reachable = if tables.oversized.contains(table) {
                None
            } else {
                let mut reachable = BTreeSet::new();
                let matching = tables.matching_slots(*table, *ty, meter);
                let placed = tables.slots.get(table).map_or(&[][..], Vec::as_slice);
                for slot in matching.iter().flat_map(|matching| matching.0.iter()) {
                    if !meter.charge(1) || reachable.len() > MAX_CHAIN_HANDLERS {
                        break;
                    }
                    if let Ok(at) = placed.binary_search_by_key(slot, |(slot, _)| *slot)
                        && let Some(function) = placed[at].1.function()
                        && positions.contains_key(&function)
                        && auxiliary.keep(32)
                    {
                        reachable.insert(function);
                    }
                }
                (reachable.len() <= MAX_CHAIN_HANDLERS).then_some(reachable)
            };
            members.insert((*table, *ty), reachable);
        }
    }
    for reachable in members.values().flatten() {
        callees.extend(reachable.iter().copied());
    }
    let mut fetchers = HashMap::new();
    let mut terminals = BTreeSet::new();
    for callee in callees {
        if meter.exhausted() {
            break;
        }
        let facts = &functions[positions[&callee]].2;
        if let Some(source) = facts.fetch_summary()
            && auxiliary.keep(64)
        {
            fetchers.insert(callee, source);
        } else if facts.terminal() && auxiliary.keep(32) {
            terminals.insert(callee);
        }
        facts.local_memo.borrow_mut().clear();
    }
    // A chain is threaded through a cursor when every handler its indirect
    // call can reach returns a fetch at a position it advances itself, or
    // only constants (a halt handler), and at least one fetches. None marks
    // a table too large to check, an honest limit.
    let mut chains = HashMap::new();
    for (call, reachable) in &members {
        let source = match reachable {
            None => None,
            Some(reachable) => {
                let mut source = None;
                let mut proven = true;
                for function in reachable {
                    match fetchers.get(function) {
                        Some(fetched) => source = source.or(Some(*fetched)),
                        None => proven &= terminals.contains(function),
                    }
                }
                match source.filter(|_| proven) {
                    Some(source) => Some(source),
                    None => continue,
                }
            }
        };
        if auxiliary.keep(32) {
            chains.insert(*call, source);
        }
    }
    let fetchers = std::rc::Rc::new(fetchers);
    let chains = std::rc::Rc::new(chains);
    for (_, _, facts) in &mut functions {
        facts.fetchers = fetchers.clone();
        facts.chains = chains.clone();
    }
    let mut candidates = Vec::new();
    for (position, (_, _, facts)) in functions.iter().enumerate() {
        for (dispatch, entry) in facts.dispatch.iter().enumerate() {
            let strength = facts.strength(entry.selector, entry.offset);
            if !auxiliary.push(
                &mut candidates,
                (
                    strength,
                    position,
                    entry.offset,
                    Candidate::Dispatch(dispatch),
                ),
            ) {
                meter.count_unclassified(1);
            }
        }
        for (subject, compares) in facts.ladders() {
            let first = &facts.compares[compares[0]];
            let strength = facts.strength(first.subject, first.offset);
            if !auxiliary.push(
                &mut candidates,
                (
                    strength,
                    position,
                    first.offset,
                    Candidate::Ladder(subject, compares),
                ),
            ) {
                meter.count_unclassified(1);
            }
        }
    }
    candidates.sort_unstable_by_key(|(strength, position, offset, _)| {
        (std::cmp::Reverse(*strength), *position, *offset)
    });
    let mut sites = Vec::new();
    for (_, position, _, candidate) in candidates {
        let (index, body, facts) = &functions[position];
        if meter.exhausted() {
            meter.count_unclassified(1);
            continue;
        }
        match classify_candidate(facts, *index, *body, tables, &members, candidate, meter) {
            Some(site) => {
                if meter.retain(site.retained_bytes()) {
                    sites.push(site);
                } else {
                    meter.count_unclassified(1);
                }
            }
            None => meter.count_unclassified(1),
        }
    }
    if sites.is_empty() && !meter.exhausted() && exports.len() >= 2 {
        sites.push(Site {
            strength: 0,
            kind: Kind::ExportPerRole,
            source: Source::Unknown,
            repeats: Repeats::Unknown,
            instruction: "export".into(),
            function_index: None,
            function_body_offset: None,
            byte_offset: export_offset.unwrap_or(8),
            byte_size: 1,
            line: None,
            column: None,
            selector_expression:
                "The host selects an exported function by name; no in-module selector.".into(),
            selector_offset: None,
            through_lookup: false,
            through_helper: false,
            arm_count: Some(exports.len() as u64),
            loop_range: None,
            buffer_kind: None,
            table: None,
        });
    }
    Some(Classified {
        javascript: None,
        sites,
        omissions: meter.omissions("functions"),
    })
}

enum Candidate {
    Dispatch(usize),
    /// A rendered ladder subject and the indexes of its comparisons.
    Ladder(String, Vec<usize>),
}

impl Facts<'_> {
    /// Cheap dispatch strength for ordering: inside a loop, and a selector
    /// that is a load or a local some write loads.
    fn strength(&self, selector: NodeId, offset: usize) -> u8 {
        let looped = self.in_any_loop(offset);
        let core = self.strip(selector);
        let loaded = match self.nodes[core] {
            Node::Load { .. } => true,
            Node::Call {
                callee: Some(callee),
                ..
            } => self.fetchers.contains_key(&callee),
            Node::Local(local) => self.definitions(local).iter().take(8).any(|(_, def)| {
                self.meter.charge(1);
                matches!(self.nodes[self.strip(*def)], Node::Load { .. })
            }),
            _ => false,
        };
        u8::from(looped) * 2 + u8::from(loaded)
    }

    /// Equality ladders: comparisons on one subject with enough constants.
    fn ladders(&self) -> Vec<(String, Vec<usize>)> {
        let mut ladders = BTreeMap::<String, Vec<usize>>::new();
        for (position, compare) in self.compares.iter().enumerate() {
            self.meter.charge(1);
            let subject = self.strip(compare.subject);
            if matches!(self.nodes[subject], Node::Unknown | Node::Const(_)) {
                continue;
            }
            ladders
                .entry(self.render(subject, 0))
                .or_default()
                .push(position);
        }
        ladders
            .into_iter()
            .filter(|(_, compares)| {
                compares
                    .iter()
                    .map(|position| self.compares[*position].constant)
                    .collect::<BTreeSet<_>>()
                    .len()
                    >= MIN_COMPARE_ARMS
            })
            .collect()
    }
}

fn classify_candidate(
    facts: &Facts,
    index: u32,
    (body_offset, body_end): (usize, usize),
    tables: Option<&crate::vm::wasm_tables::Tables>,
    members: &BTreeMap<(u32, u32), Option<BTreeSet<u32>>>,
    candidate: Candidate,
    meter: &Meter,
) -> Option<Site> {
    match candidate {
        Candidate::Dispatch(position) => {
            let dispatch = &facts.dispatch[position];
            let Query {
                trace,
                mut repeats,
                range: mut loop_range,
                limited,
            } = facts.query(dispatch.selector, dispatch.offset)?;
            meter.count_limited(limited);
            // A handler that dispatches the table it is placed in with a
            // cursor fetch that outlives one call re-enters that table each
            // step: a threaded cycle through the function body. Membership
            // alone is not threading, because a compiled module places every
            // address-taken function in one table. A tail call leaves its
            // function, so an enclosing loop never runs it again; outside a
            // cycle it fires once.
            let (cycle, tail) = match dispatch.op {
                DispatchOp::CallIndirect { table, ty, tail } => (
                    trace.source.cursor_like()
                        && facts.persistent(&trace)
                        && members
                            .get(&(table, ty))
                            .and_then(Option::as_ref)
                            .is_some_and(|reachable| reachable.contains(&index)),
                    tail,
                ),
                DispatchOp::BrTable { .. } => (false, false),
            };
            if cycle {
                if repeats != Repeats::Loop || tail {
                    repeats = Repeats::Loop;
                    loop_range = Some((body_offset, body_end));
                }
            } else if tail {
                repeats = Repeats::Once;
                loop_range = facts.innermost_loop(Some(dispatch.offset));
            }
            let (kind, instruction, arm_count, table) = match dispatch.op {
                DispatchOp::BrTable { arms } => {
                    (Kind::SwitchOnValue, "br_table", Some(u64::from(arms)), None)
                }
                DispatchOp::CallIndirect {
                    table: table_index,
                    ty,
                    tail,
                } => {
                    let kind =
                        if tail || cycle || trace.chained || trace.source == Source::HandlerAddress
                        {
                            Kind::Threaded
                        } else {
                            Kind::HandlerTable
                        };
                    let matching =
                        tables.and_then(|tables| tables.matching_slots(table_index, ty, meter));
                    (
                        kind,
                        if tail {
                            "return_call_indirect"
                        } else {
                            "call_indirect"
                        },
                        matching.as_ref().map(|matching| matching.0.len() as u64),
                        Some(SiteTable {
                            table_index,
                            type_index: ty,
                            matching,
                        }),
                    )
                }
            };
            Some(Site {
                strength: 0,
                kind,
                source: trace.source,
                repeats,
                instruction: instruction.into(),
                function_index: Some(index),
                function_body_offset: Some(body_offset),
                byte_offset: dispatch.offset,
                byte_size: dispatch.size,
                line: None,
                column: None,
                selector_expression: facts.selector_text(dispatch.selector, &trace),
                selector_offset: trace.anchor,
                through_lookup: trace.through_lookup,
                through_helper: trace.helper.is_some(),
                arm_count,
                loop_range,
                buffer_kind: None,
                table,
            })
        }
        Candidate::Ladder(subject, compares) => {
            let first = &facts.compares[compares[0]];
            let Query {
                trace,
                repeats,
                range: loop_range,
                limited,
            } = facts.query(first.subject, first.offset)?;
            meter.count_limited(limited);
            Some(Site {
                strength: 0,
                kind: Kind::CompareChain,
                source: trace.source,
                repeats,
                instruction: "i32.eq ladder".into(),
                function_index: Some(index),
                function_body_offset: Some(body_offset),
                byte_offset: first.offset,
                byte_size: first.size,
                line: None,
                column: None,
                selector_expression: format!(
                    "{subject} == constant ({} comparisons)",
                    compares.len()
                ),
                selector_offset: trace.anchor,
                through_lookup: trace.through_lookup,
                through_helper: trace.helper.is_some(),
                arm_count: Some(compares.len() as u64),
                loop_range,
                buffer_kind: None,
                table: None,
            })
        }
    }
}
