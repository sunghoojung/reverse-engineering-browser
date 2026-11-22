//! The complete value-flow slice of one seed: every node a value reaches
//! backward (what feeds it) and forward (where it goes), each with the edge
//! to its parent toward the seed, so any node's path to the seed is a walk
//! up the tree. There is no node, edge or depth cap: the walk is a breadth
//! first search over the def-use graphs of the functions it enters, linear
//! in the slice, and it runs until it is done or the request is cancelled.
//!
//! Edges have classes, and the walk runs in class order: proven value edges
//! first, then the address operands of memory reads, then `memory_may` edges
//! through memory cells, then (on request) `control` edges from joins and
//! decisions to what decided them. A node's class is the weakest edge on its
//! path to the seed, so a reader can tell a value that provably feeds the seed
//! from one that only computed an address, one that may be the value (through
//! memory), or one that only decided which path ran. Each node is discovered
//! once, by the strongest path: a phase runs to exhaustion before the next
//! begins.
//!
//! Calls are crossed, not stopped at. Forward, an argument enters the callee's
//! parameter and the walk continues inside the callee; the results that
//! parameter reaches ([`crate::wasm_summaries`]) carry the value on at the
//! call site over a `summary` edge, so the flow returns to the right caller.
//! Backward, a call's result enters the callee's returns, and the arguments
//! the result depends on continue in the caller. Inside a callee, a parameter
//! reached backward and a return reached forward are boundaries, not ends:
//! the summary edge at the call site already carries the value across them.
//!
//! Chains of `local.get`, `local.set` and `local.tee` move a value without
//! changing it; they are walked and counted but not listed, and the edge to a
//! listed node names the locals the value passed through.
use crate::error::{Result, check_cancelled};
use crate::wasm_def_use::{Edge, EdgeKind, NONE, NodeKind, Simulation, Value, Via};
use crate::wasm_summaries::{Bodies, Mask};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const WHAT: &str = "WASM value flow";
/// No slot: a queue entry whose node needs no result or argument slot.
const ANY: u16 = u16::MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Direction {
    Backward,
    Forward,
    Both,
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Backward => "backward",
            Self::Forward => "forward",
            Self::Both => "both",
        }
    }
    pub fn backward(self) -> bool {
        self != Self::Forward
    }
    pub fn forward(self) -> bool {
        self != Self::Backward
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Seed {
    /// One instruction, by its original byte offset, and optionally one of
    /// its operands in text order.
    Instruction {
        offset: u32,
        operand: Option<u32>,
    },
    Local(u32),
}

/// What one slice follows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Options {
    pub direction: Direction,
    /// Follow `control` edges backward from joins and decisions.
    pub control: bool,
    /// Enter the functions a call names.
    pub interprocedural: bool,
}

/// The weakest edge on a node's path to the seed, in walk order: a value
/// edge is exact, an address edge is exact structure that is not the value,
/// a `memory_may` edge is possible flow, and a `control` edge is a decision.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(u8)]
pub enum Class {
    Value,
    Address,
    MemoryMay,
    Control,
}

impl Class {
    pub const ALL: [Class; 4] = [Self::Value, Self::Address, Self::MemoryMay, Self::Control];
    pub fn name(self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::MemoryMay => "memory_may",
            Self::Address => "address",
            Self::Control => "control",
        }
    }
    fn of(edge: EdgeKind) -> Self {
        match edge {
            EdgeKind::MemoryMay => Self::MemoryMay,
            EdgeKind::Address => Self::Address,
            EdgeKind::Control => Self::Control,
            _ => Self::Value,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Seed,
    Backward,
    Forward,
}

impl Dir {
    pub fn name(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Backward => "backward",
            Self::Forward => "forward",
        }
    }
}

/// How a node is joined to its parent toward the seed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkKind {
    /// A def-use edge of the simulation.
    Edge(EdgeKind),
    /// A call's argument entering the callee's parameter.
    CallParam,
    /// A callee's return feeding the call's result.
    CallResult,
    /// A call's argument carried to one of its results by the callee's summary.
    Summary,
    /// A seed root.
    None,
}

impl LinkKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Edge(kind) => kind.name(),
            Self::CallParam => "call_param",
            Self::CallResult => "call_result",
            Self::Summary => "summary",
            Self::None => "seed",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Link {
    pub kind: LinkKind,
    pub operand: u16,
    pub result: u16,
    pub via: Via,
    pub via_offset: u32,
}

impl Link {
    const ROOT: Link = Link {
        kind: LinkKind::None,
        operand: 0,
        result: 0,
        via: Via::None,
        via_offset: NONE,
    };
    fn edge(edge: &Edge) -> Self {
        Self {
            kind: LinkKind::Edge(edge.kind),
            operand: edge.operand,
            result: edge.result,
            via: edge.via,
            via_offset: edge.via_offset,
        }
    }
    fn plain(kind: LinkKind, operand: u16, result: u16) -> Self {
        Self {
            kind,
            operand,
            result,
            via: Via::None,
            via_offset: NONE,
        }
    }
}

/// A function the slice entered.
pub struct Function {
    pub index: u32,
    pub sim: Arc<Simulation>,
    /// The parameter node of each parameter, `NONE` when it is never read.
    params: Vec<u32>,
    /// The `return` nodes, in body order.
    returns: Vec<u32>,
    /// Slice node of each simulation node, per direction (backward, forward).
    visited: [Vec<u32>; 2],
}

impl Function {
    fn new(index: u32, sim: Arc<Simulation>) -> Self {
        let mut params = vec![NONE; sim.params as usize];
        let mut returns = Vec::new();
        for (position, node) in sim.nodes.iter().enumerate() {
            match node.kind {
                NodeKind::Param => {
                    if let Some(slot) = params.get_mut(node.index as usize) {
                        *slot = position as u32;
                    }
                }
                NodeKind::Return => returns.push(position as u32),
                _ => {}
            }
        }
        Self {
            index,
            sim,
            params,
            returns,
            visited: [Vec::new(), Vec::new()],
        }
    }

    /// The backward slice node of a simulation node, if it was reached.
    pub fn backward_id(&self, node: u32) -> Option<u32> {
        self.visited[0]
            .get(node as usize)
            .copied()
            .filter(|id| *id != NONE)
    }
}

/// One node of the slice: a simulation node of one function, reached in one
/// direction, with the edge to its parent toward the seed.
#[derive(Clone, Copy, Debug)]
pub struct SliceNode {
    /// Index into [`Slice::functions`].
    pub function: u32,
    pub node: u32,
    /// Slice node toward the seed; `NONE` for a root.
    pub parent: u32,
    pub link: Link,
    pub dir: Dir,
    pub class: Class,
    /// A root of the walk: the seed instruction, a definition of the seed
    /// local, or the producer of a seed operand.
    pub seed: bool,
    /// The seed instruction itself, walked over every operand and result.
    /// A rooted producer is not: it follows the rules of its own kind.
    pub whole: bool,
    /// Where the value comes from: a producer with no followed inputs.
    pub source: bool,
    /// Where the value stops flowing as itself.
    pub sink: bool,
    /// A callee's parameter or return: the value crosses back to the call
    /// site, which the summary edge there already carries.
    pub boundary: bool,
    /// A `local.get`, `local.set` or `local.tee` the value passes through
    /// unchanged: walked and counted, not listed.
    pub transport: bool,
}

pub struct Slice {
    pub functions: Vec<Function>,
    pub nodes: Vec<SliceNode>,
    /// Ids of listed nodes (everything but transport), in walk order.
    pub listed: Vec<u32>,
    /// Walk position of each node, `NONE` for transport nodes.
    pub position: Vec<u32>,
    pub seeds: Vec<u32>,
}

/// What a slice needs from its caller: the simulation of any function (the
/// seed's or a callee's, cached by the caller) and function summaries.
pub trait Provider: Bodies {
    fn reach(&self, function: u32, param: u32) -> Result<Arc<Mask>>;
}

/// Where a walk starts, resolved by the caller from the seed.
pub struct Roots {
    /// Seed nodes: walked backward from all their inputs (or the operand's
    /// edge alone) and forward from all their results.
    pub nodes: Vec<u32>,
    /// Values the walk starts from when the seed is an operand or has no node
    /// of its own: backward from the value's producer and forward from the
    /// value, each rooted at the seed node when there is one.
    pub values: Vec<Value>,
    /// The seed operand's edge into the seed node, when both exist.
    pub operand_edge: Option<u32>,
}

/// A queue entry: a slice node, the slot its expansion is about (a call's
/// result backward, a call's argument forward, `ANY` otherwise) and the class
/// of the path that asked for it.
type Entry = (u32, u16, Class);

struct Walker<'p> {
    provider: &'p dyn Provider,
    options: Options,
    cancelled: &'p AtomicBool,
    slice: Slice,
    /// Function slot by function index.
    slots: HashMap<u32, u32>,
    /// Functions whose simulation was refused, each noted by the provider.
    refused: HashSet<u32>,
    /// Forward: the result slots a node carries the value out through, when
    /// not all of them (a call reached through an argument, a seed operand).
    carried: HashMap<u32, Mask>,
    /// Forward: call arguments entered, by slice node and argument slot.
    entered: HashSet<(u32, u16)>,
    /// Backward: call results and callee returns expanded, by slice node and
    /// result slot.
    expanded: HashSet<(u32, u16)>,
    /// Phase each node was discovered in.
    discovered: Vec<u8>,
    /// Phases each node's slot-free expansion ran in: bits 0-3 backward,
    /// 4-7 forward.
    done: Vec<u8>,
    steps: u64,
}

/// The function slot, node and link a discovery names.
struct Found {
    function: u32,
    node: u32,
    link: Link,
}

impl Slice {
    /// Computes the slice from `roots` in `function`, whose simulation is
    /// `sim`.
    pub fn compute(
        provider: &dyn Provider,
        function: u32,
        sim: Arc<Simulation>,
        roots: Roots,
        options: Options,
        cancelled: &AtomicBool,
    ) -> Result<Slice> {
        let mut walker = Walker {
            provider,
            options,
            cancelled,
            slice: Slice {
                functions: Vec::new(),
                nodes: Vec::new(),
                listed: Vec::new(),
                position: Vec::new(),
                seeds: Vec::new(),
            },
            slots: HashMap::new(),
            refused: HashSet::new(),
            carried: HashMap::new(),
            entered: HashSet::new(),
            expanded: HashSet::new(),
            discovered: Vec::new(),
            done: Vec::new(),
            steps: 0,
        };
        let slot = walker.slot_for(function, sim);
        walker.walk(slot, roots)?;
        let mut slice = walker.slice;
        slice.position = vec![NONE; slice.nodes.len()];
        for (id, node) in slice.nodes.iter().enumerate() {
            if !node.transport {
                slice.position[id] = slice.listed.len() as u32;
                slice.listed.push(id as u32);
            }
        }
        Ok(slice)
    }

    /// The listed parent of `id` with the chain between them condensed: the
    /// node's own edge, the edge that enters the parent when transport nodes
    /// were skipped (how the parent consumed or produced the value), and the
    /// locals the value passed through on the way, nearest first.
    pub fn listed_parent(&self, id: u32) -> (u32, Link, Option<Link>, Vec<u32>) {
        let own = self.nodes[id as usize].link;
        let mut through = None;
        let mut locals = Vec::new();
        let mut parent = self.nodes[id as usize].parent;
        while parent != NONE && self.nodes[parent as usize].transport {
            let node = &self.nodes[parent as usize];
            let local = self.functions[node.function as usize].sim.nodes[node.node as usize].index;
            if locals.last() != Some(&local) {
                locals.push(local);
            }
            through = Some(node.link);
            parent = node.parent;
        }
        (parent, own, through, locals)
    }

    /// Listed ancestors of `id` toward the seed, nearest first.
    pub fn ancestors(&self, id: u32) -> Vec<u32> {
        let mut path = Vec::new();
        let (mut parent, _, _, _) = self.listed_parent(id);
        while parent != NONE {
            path.push(parent);
            parent = self.listed_parent(parent).0;
        }
        path
    }

    /// Listed depth: listed ancestors between `id` and its root.
    pub fn depth(&self, id: u32) -> u32 {
        self.ancestors(id).len() as u32
    }

    pub fn transport_count(&self) -> usize {
        self.nodes.len() - self.listed.len()
    }

    /// What the slice holds, for a cache bounded by bytes. Simulations are
    /// shared with their own cache and not counted here.
    pub fn bytes(&self) -> u64 {
        (self.nodes.len() * std::mem::size_of::<SliceNode>()
            + self.listed.len() * 4
            + self.position.len() * 4
            + self
                .functions
                .iter()
                .map(|function| {
                    (function.params.len() + function.returns.len()) * 4
                        + function.visited.iter().map(|v| v.len() * 4).sum::<usize>()
                })
                .sum::<usize>()) as u64
    }
}

/// Whether a value reaching `kind` over `edge` keeps flowing on as itself.
fn carries(kind: NodeKind, edge: EdgeKind) -> bool {
    match kind {
        NodeKind::Operation
        | NodeKind::LocalSet
        | NodeKind::LocalTee
        | NodeKind::LocalGet
        | NodeKind::Phi
        | NodeKind::MemoryCell => true,
        NodeKind::Select => edge == EdgeKind::Operand,
        NodeKind::Load => matches!(edge, EdgeKind::ForwardedStore | EdgeKind::MemoryMay),
        NodeKind::GlobalGet => edge == EdgeKind::ForwardedGlobal,
        _ => false,
    }
}

/// The class of an edge followed forward: a control edge never carries a
/// value, a `memory_may` edge carries it as possible flow, and every other
/// edge (an address operand included: the value reaches that read or write)
/// carries it as the value itself.
fn forward_class(edge: EdgeKind) -> Option<Class> {
    match edge {
        EdgeKind::Control => None,
        EdgeKind::MemoryMay => Some(Class::MemoryMay),
        _ => Some(Class::Value),
    }
}

/// Kinds whose value has no producer inside this function's data flow; a
/// defined call is one only when calls are not entered.
fn leaf(kind: NodeKind, calls_opaque: bool) -> bool {
    match kind {
        NodeKind::Param
        | NodeKind::LocalInit
        | NodeKind::Const
        | NodeKind::GlobalGet
        | NodeKind::ExceptionValue
        | NodeKind::Unknown
        | NodeKind::ImportCall
        | NodeKind::CallIndirect
        | NodeKind::CallRef
        | NodeKind::Memory
        | NodeKind::Load
        | NodeKind::Atomic
        | NodeKind::Table => true,
        NodeKind::Call => calls_opaque,
        _ => false,
    }
}

impl Walker<'_> {
    fn slot_for(&mut self, function: u32, sim: Arc<Simulation>) -> u32 {
        if let Some(slot) = self.slots.get(&function) {
            return *slot;
        }
        let slot = self.slice.functions.len() as u32;
        self.slice.functions.push(Function::new(function, sim));
        self.slots.insert(function, slot);
        slot
    }

    /// The slot of a callee, entering it if its body can be simulated. A
    /// refusal is noted by the provider and the call stays opaque.
    fn callee(&mut self, function: u32) -> Result<Option<u32>> {
        if let Some(slot) = self.slots.get(&function) {
            return Ok(Some(*slot));
        }
        if self.refused.contains(&function) {
            return Ok(None);
        }
        match self.provider.simulation(function)? {
            Some(sim) => Ok(Some(self.slot_for(function, sim))),
            None => {
                self.refused.insert(function);
                Ok(None)
            }
        }
    }

    fn sim(&self, slot: u32) -> &Arc<Simulation> {
        &self.slice.functions[slot as usize].sim
    }

    fn defined(&self, function: u32) -> bool {
        function >= self.provider.imported_functions()
    }

    fn tick(&mut self) -> Result<()> {
        self.steps += 1;
        if self.steps & 4095 == 0 {
            check_cancelled(self.cancelled, WHAT)?;
        }
        Ok(())
    }

    /// Records a node reached in `dir` in `phase` unless it was reached
    /// already; returns its id and whether it is new.
    fn discover(
        &mut self,
        dir: Dir,
        found: Found,
        parent: u32,
        class: Class,
        phase: Class,
    ) -> (u32, bool) {
        let side = usize::from(dir == Dir::Forward);
        {
            let function = &mut self.slice.functions[found.function as usize];
            if function.visited[side].is_empty() {
                function.visited[side] = vec![NONE; function.sim.nodes.len()];
            }
            let known = function.visited[side][found.node as usize];
            if known != NONE {
                return (known, false);
            }
        }
        let id = self.slice.nodes.len() as u32;
        self.slice.functions[found.function as usize].visited[side][found.node as usize] = id;
        let kind = self.sim(found.function).nodes[found.node as usize].kind;
        let transport = matches!(
            kind,
            NodeKind::LocalGet | NodeKind::LocalSet | NodeKind::LocalTee
        ) && parent != NONE;
        self.slice.nodes.push(SliceNode {
            function: found.function,
            node: found.node,
            parent,
            link: found.link,
            dir,
            class,
            seed: parent == NONE,
            whole: false,
            source: false,
            sink: false,
            boundary: false,
            transport,
        });
        self.discovered.push(phase as u8);
        self.done.push(0);
        if parent == NONE {
            self.slice.seeds.push(id);
        }
        (id, true)
    }

    fn walk(&mut self, seed_slot: u32, roots: Roots) -> Result<()> {
        let backward = self.options.direction.backward();
        let forward = self.options.direction.forward();
        let mut back: VecDeque<Entry> = VecDeque::new();
        let mut fore: VecDeque<Entry> = VecDeque::new();
        let sim = self.sim(seed_slot).clone();
        for node in &roots.nodes {
            let found = Found {
                function: seed_slot,
                node: *node,
                link: Link::ROOT,
            };
            let (id, _) = self.discover(Dir::Seed, found, NONE, Class::Value, Class::Value);
            // Walked as a whole instruction unless one operand was named.
            self.slice.nodes[id as usize].whole = roots.values.is_empty();
            // A local seed's parameter or zero value is also where the local's
            // value comes from.
            if matches!(
                sim.nodes[*node as usize].kind,
                NodeKind::Param | NodeKind::LocalInit
            ) {
                self.slice.nodes[id as usize].source = true;
            }
            if roots.values.is_empty() {
                if backward {
                    back.push_back((id, ANY, Class::Value));
                }
                if forward {
                    fore.push_back((id, ANY, Class::Value));
                }
            } else {
                // An operand seed: the walk starts from the operand's value
                // alone, never from the instruction's other operands or its
                // own results.
                self.done[id as usize] = 0xff;
                if backward && let Some(edge) = roots.operand_edge {
                    let edge = sim.edges[edge as usize];
                    self.reach_backward(id, &edge, Class::Value, Class::Value, &mut back);
                }
            }
        }
        // Rooted values: the operand's producer, or the producers of a
        // nodeless instruction's operands. Without a seed node they are the
        // seeds themselves.
        let root = self.slice.seeds.first().copied().unwrap_or(NONE);
        for value in &roots.values {
            let link = Link::plain(LinkKind::Edge(EdgeKind::Operand), 0, value.result as u16);
            if backward {
                let found = Found {
                    function: seed_slot,
                    node: value.node,
                    link,
                };
                let (id, new) =
                    self.discover(Dir::Backward, found, root, Class::Value, Class::Value);
                if new {
                    self.ends_backward(id);
                    back.push_back((id, value.result as u16, Class::Value));
                }
            }
            if forward {
                let found = Found {
                    function: seed_slot,
                    node: value.node,
                    link,
                };
                let (id, new) =
                    self.discover(Dir::Forward, found, root, Class::Value, Class::Value);
                if new {
                    let mut mask = Mask::empty(0);
                    mask.set(value.result);
                    self.carried.insert(id, mask);
                    fore.push_back((id, ANY, Class::Value));
                }
            }
        }
        for phase in Class::ALL {
            if phase == Class::Control && !self.options.control {
                break;
            }
            if backward {
                self.phase_backward(phase, &mut back)?;
            }
            // Forward, an address operand carries the value to its read or
            // write as the value itself: only may edges open a later phase.
            if forward && matches!(phase, Class::Value | Class::MemoryMay) {
                self.phase_forward(phase, &mut fore)?;
            }
        }
        Ok(())
    }

    /// One backward phase: every node reached so far expands its edges of
    /// `phase`'s class; nodes reached in this phase expand every class up to
    /// it. Each (node, class) pair is expanded once over the whole walk.
    fn phase_backward(&mut self, phase: Class, queue: &mut VecDeque<Entry>) -> Result<()> {
        if phase != Class::Value {
            for id in 0..self.slice.nodes.len() as u32 {
                let node = self.slice.nodes[id as usize];
                if node.dir != Dir::Forward {
                    queue.push_back((id, ANY, node.class));
                }
            }
        }
        while let Some((id, slot, class)) = queue.pop_front() {
            self.tick()?;
            if slot == ANY {
                let bit = 1u8 << (phase as u8);
                if self.done[id as usize] & bit != 0 {
                    continue;
                }
                self.done[id as usize] |= bit;
            }
            self.expand_backward(id, slot, class, phase, queue)?;
        }
        Ok(())
    }

    fn phase_forward(&mut self, phase: Class, queue: &mut VecDeque<Entry>) -> Result<()> {
        if phase != Class::Value {
            for id in 0..self.slice.nodes.len() as u32 {
                let node = self.slice.nodes[id as usize];
                if node.dir != Dir::Backward {
                    queue.push_back((id, ANY, node.class));
                }
            }
        }
        while let Some((id, slot, class)) = queue.pop_front() {
            self.tick()?;
            if slot == ANY {
                let bit = 16u8 << (phase as u8);
                if self.done[id as usize] & bit != 0 {
                    continue;
                }
                self.done[id as usize] |= bit;
            }
            self.expand_forward(id, slot, class, phase, queue)?;
        }
        Ok(())
    }

    /// An operand seed's instruction starts the walk from that operand alone.
    /// Reached again backward as a producer, it opens for expansion like any
    /// node reached in this phase. True the first time.
    fn reopen(&mut self, id: u32, phase: Class) -> bool {
        let node = self.slice.nodes[id as usize];
        if !node.seed || node.whole || self.done[id as usize] & 0x0f != 0x0f {
            return false;
        }
        self.done[id as usize] &= 0xf0;
        self.discovered[id as usize] = phase as u8;
        true
    }

    /// Whether an edge of `class` is followed from node `id` in `phase`: a
    /// node reached in this phase follows every class up to it, an older
    /// node only the phase's own.
    fn follows(&self, id: u32, phase: Class, class: Class) -> bool {
        if self.discovered[id as usize] == phase as u8 {
            class <= phase
        } else {
            class == phase
        }
    }

    /// Marks the ends of a node reached backward from its kind.
    fn ends_backward(&mut self, id: u32) {
        let entry = self.slice.nodes[id as usize];
        let sim = self.sim(entry.function).clone();
        let node = sim.nodes[entry.node as usize];
        let in_callee = entry.function != 0;
        let has_input = |kind: EdgeKind| {
            sim.adjacency
                .inputs(entry.node)
                .iter()
                .any(|edge| sim.edges[*edge as usize].kind == kind)
        };
        let interprocedural = self.options.interprocedural;
        let refused = self.refused.contains(&node.index);
        let slice_node = &mut self.slice.nodes[id as usize];
        match node.kind {
            NodeKind::Param => {
                if in_callee && interprocedural {
                    slice_node.boundary = true;
                } else {
                    slice_node.source = true;
                }
            }
            NodeKind::LocalInit
            | NodeKind::Const
            | NodeKind::ExceptionValue
            | NodeKind::Unknown
            | NodeKind::ImportCall
            | NodeKind::CallIndirect
            | NodeKind::CallRef
            | NodeKind::Memory
            | NodeKind::Atomic
            | NodeKind::Table => slice_node.source = true,
            NodeKind::GlobalGet => slice_node.source = !has_input(EdgeKind::ForwardedGlobal),
            NodeKind::Load => slice_node.source = !has_input(EdgeKind::ForwardedStore),
            NodeKind::Call => slice_node.source = !interprocedural || refused,
            _ => {}
        }
    }

    /// Follows one input edge of node `id` backward; the child's class is
    /// the weakest of the path so far and the edge.
    fn reach_backward(
        &mut self,
        id: u32,
        edge: &Edge,
        class: Class,
        phase: Class,
        queue: &mut VecDeque<Entry>,
    ) {
        let function = self.slice.nodes[id as usize].function;
        let class = class.max(Class::of(edge.kind));
        let found = Found {
            function,
            node: edge.from,
            link: Link::edge(edge),
        };
        let (child, new) = self.discover(Dir::Backward, found, id, class, phase);
        let kind = self.sim(function).nodes[edge.from as usize].kind;
        if new {
            self.ends_backward(child);
        } else if self.reopen(child, phase) {
            // The seed instruction met again as a producer (its value fed the
            // operand around a loop): from here on it is an ordinary node of
            // its kind, every operand followed.
            self.ends_backward(child);
            queue.push_back((child, ANY, class));
            return;
        }
        if kind == NodeKind::Call {
            // A call is expanded per result reached: its returns for that
            // result and the arguments the result depends on.
            queue.push_back((child, edge.result, class));
        } else if new {
            queue.push_back((child, ANY, class));
        }
    }

    fn expand_backward(
        &mut self,
        id: u32,
        slot: u16,
        class: Class,
        phase: Class,
        queue: &mut VecDeque<Entry>,
    ) -> Result<()> {
        let entry = self.slice.nodes[id as usize];
        let sim = self.sim(entry.function).clone();
        let node = sim.nodes[entry.node as usize];
        let seed = entry.whole;
        let inputs: Vec<Edge> = sim
            .adjacency
            .inputs(entry.node)
            .iter()
            .map(|edge| sim.edges[*edge as usize])
            .collect();
        match node.kind {
            NodeKind::Call if !seed && self.options.interprocedural && self.defined(node.index) => {
                // Reached through result `slot`: entered once per slot, in
                // the phase that reached it.
                if slot == ANY || !self.expanded.insert((id, slot)) {
                    return Ok(());
                }
                let Some(callee) = self.callee(node.index)? else {
                    self.slice.nodes[id as usize].source = true;
                    return Ok(());
                };
                let returns = self.slice.functions[callee as usize].returns.clone();
                let callee_sim = self.sim(callee).clone();
                for ret in returns {
                    let carries = callee_sim.adjacency.inputs(ret).iter().any(|edge| {
                        let edge = callee_sim.edges[*edge as usize];
                        edge.kind == EdgeKind::Return && edge.operand == slot
                    });
                    if !carries {
                        continue;
                    }
                    let found = Found {
                        function: callee,
                        node: ret,
                        link: Link::plain(LinkKind::CallResult, 0, slot),
                    };
                    let (child, new) = self.discover(Dir::Backward, found, id, class, phase);
                    if new {
                        self.slice.nodes[child as usize].boundary = true;
                    }
                    queue.push_back((child, slot, class));
                }
                for edge in inputs.iter().filter(|edge| edge.kind == EdgeKind::Argument) {
                    let mask = self.provider.reach(node.index, u32::from(edge.operand))?;
                    if !mask.get(u32::from(slot)) {
                        continue;
                    }
                    let mut summary = *edge;
                    // The link names the call's argument and result; the
                    // producer's result slot stays the edge's.
                    summary.kind = EdgeKind::Operand;
                    let found = Found {
                        function: entry.function,
                        node: edge.from,
                        link: Link {
                            kind: LinkKind::Summary,
                            operand: edge.operand,
                            result: slot,
                            via: Via::None,
                            via_offset: NONE,
                        },
                    };
                    let (child, new) = self.discover(Dir::Backward, found, id, class, phase);
                    if new {
                        self.ends_backward(child);
                    }
                    if sim.nodes[edge.from as usize].kind == NodeKind::Call {
                        queue.push_back((child, summary.result, class));
                    } else if new {
                        queue.push_back((child, ANY, class));
                    }
                }
                Ok(())
            }
            NodeKind::Call if !seed => Ok(()),
            NodeKind::Return if !seed => {
                // A callee's return entered for one result slot.
                if slot == ANY || !self.expanded.insert((id, slot)) {
                    return Ok(());
                }
                for edge in &inputs {
                    if edge.kind == EdgeKind::Return && edge.operand == slot {
                        self.reach_backward(id, edge, class, phase, queue);
                    }
                }
                Ok(())
            }
            NodeKind::Branch if !seed => {
                // A decision reached as control dependence: what decided it.
                if !self.follows(id, phase, Class::Control) {
                    return Ok(());
                }
                for edge in &inputs {
                    if matches!(edge.kind, EdgeKind::Selector | EdgeKind::Control) {
                        self.reach_backward(id, edge, Class::Control, phase, queue);
                    }
                }
                Ok(())
            }
            _ => {
                let addressed = matches!(
                    node.kind,
                    NodeKind::Load | NodeKind::Atomic | NodeKind::Table
                );
                if !seed
                    && node.kind != NodeKind::Phi
                    && node.kind != NodeKind::MemoryCell
                    && leaf(node.kind, !self.options.interprocedural)
                    && !addressed
                    && node.kind != NodeKind::GlobalGet
                {
                    return Ok(());
                }
                for edge in &inputs {
                    let edge_class = match (node.kind, edge.kind) {
                        // A read-modify-write returns the old memory value:
                        // the stored operand does not feed it.
                        (NodeKind::Atomic, EdgeKind::StoredValue) if !seed => continue,
                        // Only `table.get` depends on its (one) index.
                        (NodeKind::Table, _)
                            if !seed && (inputs.len() != 1 || node.results != 1) =>
                        {
                            continue;
                        }
                        (NodeKind::Table, _) if !seed => Class::Address,
                        (NodeKind::GlobalGet, kind) if kind != EdgeKind::ForwardedGlobal => {
                            continue;
                        }
                        (_, kind) => Class::of(kind),
                    };
                    if !self.follows(id, phase, edge_class) {
                        continue;
                    }
                    self.reach_backward(id, edge, class.max(edge_class), phase, queue);
                }
                Ok(())
            }
        }
    }

    /// Marks a node reached forward over an edge the value does not pass
    /// through as a sink or boundary.
    fn arrive_forward(&mut self, id: u32, kind: NodeKind, edge: EdgeKind) {
        let entry = self.slice.nodes[id as usize];
        let in_callee = entry.function != 0;
        let interprocedural = self.options.interprocedural;
        let function = self.sim(entry.function).nodes[entry.node as usize].index;
        let defined = self.defined(function);
        let slice_node = &mut self.slice.nodes[id as usize];
        match kind {
            NodeKind::Return if in_callee && interprocedural => slice_node.boundary = true,
            // Decided when the callee is entered: a sink only when the
            // callee cannot be followed or never reads the parameter.
            NodeKind::Call if interprocedural && defined && edge == EdgeKind::Argument => {}
            _ => slice_node.sink = true,
        }
    }

    fn expand_forward(
        &mut self,
        id: u32,
        slot: u16,
        class: Class,
        phase: Class,
        queue: &mut VecDeque<Entry>,
    ) -> Result<()> {
        let entry = self.slice.nodes[id as usize];
        let sim = self.sim(entry.function).clone();
        let node = sim.nodes[entry.node as usize];
        let entered_call = node.kind == NodeKind::Call
            && self.defined(node.index)
            && self.options.interprocedural
            && !entry.whole;
        if slot != ANY {
            if !entered_call || !self.entered.insert((id, slot)) {
                return Ok(());
            }
            // An argument reached this call: enter the callee and carry the
            // value to the results the parameter reaches.
            let Some(callee) = self.callee(node.index)? else {
                self.slice.nodes[id as usize].sink = true;
                return Ok(());
            };
            let param = self.slice.functions[callee as usize]
                .params
                .get(slot as usize)
                .copied()
                .unwrap_or(NONE);
            let mask = self.provider.reach(node.index, u32::from(slot))?;
            if param == NONE && mask.is_empty() {
                // The callee never reads the parameter: the value stops here.
                self.slice.nodes[id as usize].sink = true;
            }
            if param != NONE {
                let found = Found {
                    function: callee,
                    node: param,
                    link: Link::plain(LinkKind::CallParam, slot, 0),
                };
                let (child, new) = self.discover(Dir::Forward, found, id, class, phase);
                if new {
                    queue.push_back((child, ANY, class));
                }
            }
            let carried = self.carried.entry(id).or_insert_with(|| Mask::empty(0));
            let mut grew = Vec::new();
            for bit in mask.bits() {
                if !carried.get(bit) {
                    carried.set(bit);
                    grew.push(bit as u16);
                }
            }
            for edge in sim.adjacency.uses(entry.node) {
                let edge = sim.edges[*edge as usize];
                let Some(edge_class) = forward_class(edge.kind) else {
                    continue;
                };
                if !grew.contains(&edge.result) {
                    continue;
                }
                let link = Link {
                    kind: LinkKind::Summary,
                    operand: slot,
                    result: edge.result,
                    via: edge.via,
                    via_offset: edge.via_offset,
                };
                self.reach_forward(id, &edge, link, class.max(edge_class), phase, queue);
            }
            return Ok(());
        }
        // The result slots this node carries the value out through.
        let results: Vec<u16> = if let Some(mask) = self.carried.get(&id) {
            mask.bits().map(|bit| bit as u16).collect()
        } else if entered_call {
            Vec::new()
        } else if entry.whole {
            (0..node.results).collect()
        } else {
            (0..node.results.max(1)).collect()
        };
        for edge in sim.adjacency.uses(entry.node) {
            let edge = sim.edges[*edge as usize];
            if !results.contains(&edge.result) {
                continue;
            }
            let Some(edge_class) = forward_class(edge.kind) else {
                continue;
            };
            if !self.follows(id, phase, edge_class) {
                continue;
            }
            let link = Link::edge(&edge);
            self.reach_forward(id, &edge, link, class.max(edge_class), phase, queue);
        }
        Ok(())
    }

    /// Follows one use edge of node `id` forward.
    fn reach_forward(
        &mut self,
        id: u32,
        edge: &Edge,
        link: Link,
        class: Class,
        phase: Class,
        queue: &mut VecDeque<Entry>,
    ) {
        let function = self.slice.nodes[id as usize].function;
        let found = Found {
            function,
            node: edge.to,
            link,
        };
        let (child, _) = self.discover(Dir::Forward, found, id, class, phase);
        let target = self.sim(function).nodes[edge.to as usize];
        // A node can be reached over a carrying edge and a stopping one (a
        // select's operand and its selector), in either order: it is a sink
        // and it continues.
        if carries(target.kind, edge.kind) {
            queue.push_back((child, ANY, class));
        } else {
            self.arrive_forward(child, target.kind, edge.kind);
        }
        if target.kind == NodeKind::Call
            && edge.kind == EdgeKind::Argument
            && self.options.interprocedural
            && self.defined(target.index)
        {
            // Each argument slot enters the callee once.
            queue.push_back((child, edge.operand, class));
        }
    }
}
