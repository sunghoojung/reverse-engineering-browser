//! A bounded intra-function value-flow slice for one Wasm instruction operand
//! or one local, `wasm-value-flow-v1` (protocol/wasm-value-flow-v1.md).
//!
//! The def-use graph comes from [`crate::wasm_def_use`]; this module chooses a
//! seed, walks that graph backward to the values that feed the seed and forward
//! to where they go, within node, edge, depth and time caps, and writes the
//! document. Structure (kinds, byte offsets, indices, edge kinds) is separate
//! from content: `text` and `expression` carry instruction text derived from
//! captured bytes and are the only content fields. Nothing here runs the
//! module, and raw evidence is never modified.
use crate::{
    error::{Code, Error, Result},
    wasm,
    wasm_def_use::{self, EdgeKind, Module, NONE, NodeKind, Simulation, Value as Def},
    wasm_graph,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Write as _,
    path::Path,
    time::{Duration, Instant},
};
use wasmparser::Operator;

pub const DEFAULT_NODES: usize = 256;
/// Node caps keep a full slice inside one bounded response; an agent narrows
/// the seed or the direction instead of paging a graph.
pub const MAX_NODES: usize = 4096;
pub const DEFAULT_DEPTH: u32 = 32;
pub const MAX_DEPTH: u32 = 256;
/// Edges and join entries per node of the cap.
const EDGES_PER_NODE: usize = 4;
const MAX_EXPRESSION_BYTES: usize = 160;
const MAX_TEXT_BYTES: usize = 160;
/// Catch clauses an instruction's text lists before a count.
const MAX_LISTED_CLAUSES: usize = 8;
const EXPRESSION_DEPTH: u32 = 3;
const MAX_STEPS: usize = 64;
/// Call sites recorded per callee scan; past it the list is marked partial.
const MAX_CALL_SITES: usize = 256;
/// Web engines reject a body above this size, so a longer one cannot have run.
const MAX_BODY_BYTES: usize = 7_654_321;
const DEADLINE: Duration = Duration::from_secs(4);
/// Incoming edges listed per join; `incoming_count` keeps the total. A
/// dispatcher's exit join can have thousands.
const MAX_JOIN_ENTRIES: usize = 64;
const MAX_OMISSIONS: usize = 32;
/// `reb-api mcp` inlines a result only when its compact and pretty-printed
/// forms both fit `x-reb-mcp.inline_json_limit_bytes` (131,072), and content
/// omission can make it larger. The document is cut to fit this budget in
/// every form, leaving room for the tool envelope.
pub const MAX_RESPONSE_BYTES: usize = 120_000;
const QUERY_KEYS: [&str; 9] = [
    "artifact_id",
    "function",
    "offset",
    "operand",
    "local",
    "direction",
    "max_nodes",
    "max_depth",
    "interprocedural",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Backward,
    Forward,
    Both,
}

impl Direction {
    fn name(self) -> &'static str {
        match self {
            Self::Backward => "backward",
            Self::Forward => "forward",
            Self::Both => "both",
        }
    }
    fn backward(self) -> bool {
        self != Self::Forward
    }
    fn forward(self) -> bool {
        self != Self::Backward
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Seed {
    /// One instruction, by its original byte offset, and optionally one of
    /// its operands in text order.
    Instruction {
        offset: u32,
        operand: Option<u32>,
    },
    Local(u32),
}

#[derive(Clone, Debug)]
pub struct Request {
    pub artifact_id: Option<String>,
    pub function: u32,
    pub seed: Seed,
    pub direction: Direction,
    pub max_nodes: usize,
    pub max_depth: u32,
    pub interprocedural: bool,
}

fn integer<T: std::str::FromStr>(name: &str, text: &str) -> Result<T> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(Error::bad(format!(
            "{name} is a canonical unsigned integer"
        )));
    }
    text.parse()
        .map_err(|_| Error::bad(format!("{name} is out of range")))
}

/// Parses the route's query. Unknown or repeated parameters are refused so a
/// misspelled seed never widens into a different slice.
pub fn parse_query(raw: &str) -> Result<Request> {
    let mut values: HashMap<String, String> = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !QUERY_KEYS.contains(&key.as_ref()) {
            return Err(Error::bad(format!(
                "WASM value flow takes {}; {key} is not one of them",
                QUERY_KEYS.join(", ")
            )));
        }
        if values.insert(key.to_string(), value.to_string()).is_some() {
            return Err(Error::bad(format!("{key} is given more than once")));
        }
    }
    let function = integer::<u32>(
        "function",
        values
            .get("function")
            .ok_or_else(|| Error::bad("function is required"))?,
    )?;
    let seed = match (values.get("offset"), values.get("local")) {
        (Some(offset), None) => Seed::Instruction {
            offset: integer("offset", offset)?,
            operand: values
                .get("operand")
                .map(|operand| integer("operand", operand))
                .transpose()?,
        },
        (None, Some(local)) => {
            if values.contains_key("operand") {
                return Err(Error::bad("operand applies only to an offset seed"));
            }
            Seed::Local(integer("local", local)?)
        }
        _ => return Err(Error::bad("Give exactly one of offset or local")),
    };
    let direction = match values.get("direction").map(String::as_str) {
        None | Some("both") => Direction::Both,
        Some("backward") => Direction::Backward,
        Some("forward") => Direction::Forward,
        Some(_) => return Err(Error::bad("direction is backward, forward or both")),
    };
    let max_nodes = values
        .get("max_nodes")
        .map(|text| integer::<usize>("max_nodes", text))
        .transpose()?
        .unwrap_or(DEFAULT_NODES);
    if !(1..=MAX_NODES).contains(&max_nodes) {
        return Err(Error::bad(format!("max_nodes is 1 to {MAX_NODES}")));
    }
    let max_depth = values
        .get("max_depth")
        .map(|text| integer::<u32>("max_depth", text))
        .transpose()?
        .unwrap_or(DEFAULT_DEPTH);
    if !(1..=MAX_DEPTH).contains(&max_depth) {
        return Err(Error::bad(format!("max_depth is 1 to {MAX_DEPTH}")));
    }
    let interprocedural = match values.get("interprocedural").map(String::as_str) {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(Error::bad("interprocedural is true or false")),
    };
    Ok(Request {
        artifact_id: values.get("artifact_id").cloned(),
        function,
        seed,
        direction,
        max_nodes,
        max_depth,
        interprocedural,
    })
}

/// A node's place in the slice.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Seed,
    Source,
    Sink,
    Interior,
    /// Reached at the depth cap; its own inputs or uses were not followed.
    Frontier,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Source => "source",
            Self::Sink => "sink",
            Self::Interior => "interior",
            Self::Frontier => "frontier",
        }
    }
}

/// One node of the slice. Its ends are flags, not one role: a call can be
/// where the value comes from and where it goes in the same loop, and the
/// seed instruction can feed itself around a back edge.
struct Included {
    node: u32,
    seed: bool,
    source: bool,
    sink: bool,
    frontier: bool,
    backward: bool,
    forward: bool,
    depth: u32,
}

impl Included {
    /// The one label a reader sees first: seed, then source, sink, frontier.
    fn role(&self) -> Role {
        if self.seed {
            Role::Seed
        } else if self.source {
            Role::Source
        } else if self.sink {
            Role::Sink
        } else if self.frontier {
            Role::Frontier
        } else {
            Role::Interior
        }
    }
}

#[derive(Default)]
struct Truncated {
    nodes: bool,
    edges: bool,
    depth: bool,
    deadline: bool,
    joins: bool,
}

/// Compressed adjacency over the simulation's edges.
struct Adjacency {
    in_start: Vec<u32>,
    in_edges: Vec<u32>,
    out_start: Vec<u32>,
    out_edges: Vec<u32>,
}

impl Adjacency {
    fn new(sim: &Simulation) -> Self {
        let count = sim.nodes.len();
        let mut in_count = vec![0u32; count + 1];
        let mut out_count = vec![0u32; count + 1];
        for edge in &sim.edges {
            in_count[edge.to as usize + 1] += 1;
            out_count[edge.from as usize + 1] += 1;
        }
        for index in 0..count {
            in_count[index + 1] += in_count[index];
            out_count[index + 1] += out_count[index];
        }
        let mut in_edges = vec![0u32; sim.edges.len()];
        let mut out_edges = vec![0u32; sim.edges.len()];
        let mut in_fill = in_count.clone();
        let mut out_fill = out_count.clone();
        for (position, edge) in sim.edges.iter().enumerate() {
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
    fn inputs(&self, node: u32) -> &[u32] {
        &self.in_edges
            [self.in_start[node as usize] as usize..self.in_start[node as usize + 1] as usize]
    }
    fn uses(&self, node: u32) -> &[u32] {
        &self.out_edges
            [self.out_start[node as usize] as usize..self.out_start[node as usize + 1] as usize]
    }
}

/// Kinds whose value has no producer inside this function's data flow.
fn backward_leaf(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Param
            | NodeKind::LocalInit
            | NodeKind::Const
            | NodeKind::GlobalGet
            | NodeKind::ExceptionValue
            | NodeKind::Unknown
            | NodeKind::Call
            | NodeKind::ImportCall
            | NodeKind::CallIndirect
            | NodeKind::CallRef
            | NodeKind::Memory
    )
}

/// A value read from memory or a table: a source whose address is followed.
fn addressed_source(kind: NodeKind) -> bool {
    matches!(kind, NodeKind::Load | NodeKind::Atomic | NodeKind::Table)
}

/// Which inputs of a memory or table source its value depends on. A load's
/// result depends on its address (and a lane load's vector); an atomic
/// read-modify-write returns the old memory value, so only its address feeds
/// it; `table.get` depends on its index, and other table results (sizes) on
/// nothing followed here.
fn follows_backward(node: &wasm_def_use::Node, edge: EdgeKind, inputs: usize) -> bool {
    match node.kind {
        NodeKind::Atomic => edge == EdgeKind::Address,
        NodeKind::Table => inputs == 1 && node.results == 1,
        _ => true,
    }
}

/// Whether a value reaching `kind` over `edge` keeps flowing on.
fn forward_continues(kind: NodeKind, edge: EdgeKind) -> bool {
    match kind {
        NodeKind::Operation
        | NodeKind::LocalSet
        | NodeKind::LocalTee
        | NodeKind::LocalGet
        | NodeKind::Phi => true,
        NodeKind::Select => edge == EdgeKind::Operand,
        NodeKind::Load => edge == EdgeKind::ForwardedStore,
        _ => false,
    }
}

struct Slicer<'s> {
    sim: &'s Simulation,
    adjacency: Adjacency,
    included: Vec<Included>,
    id_of: HashMap<u32, u32>,
    edges: Vec<u32>,
    edge_seen: HashSet<u32>,
    max_nodes: usize,
    max_edges: usize,
    max_depth: u32,
    truncated: Truncated,
    deadline: Instant,
}

impl Slicer<'_> {
    fn include(&mut self, node: u32, depth: u32, backward: bool) -> Option<u32> {
        if let Some(id) = self.id_of.get(&node).copied() {
            let entry = &mut self.included[id as usize];
            if backward {
                entry.backward = true;
            } else {
                entry.forward = true;
            }
            return Some(id);
        }
        if self.included.len() >= self.max_nodes {
            self.truncated.nodes = true;
            return None;
        }
        let id = self.included.len() as u32;
        self.included.push(Included {
            node,
            seed: false,
            source: false,
            sink: false,
            frontier: false,
            backward,
            forward: !backward,
            depth,
        });
        self.id_of.insert(node, id);
        Some(id)
    }

    fn entry(&mut self, node: u32) -> Option<&mut Included> {
        let id = *self.id_of.get(&node)?;
        Some(&mut self.included[id as usize])
    }

    fn seed(&mut self, node: u32) -> Option<u32> {
        let id = self.include(node, 0, true)?;
        self.included[id as usize].seed = true;
        Some(id)
    }

    /// The producer of a seed operand that no consuming node records: an
    /// ordinary node one step from the seed, so the leaf and address rules
    /// apply to it as to any other producer.
    fn producer(&mut self, node: u32) -> Option<u32> {
        let id = self.include(node, 1, true)?;
        let kind = self.sim.nodes[node as usize].kind;
        if backward_leaf(kind) || addressed_source(kind) {
            self.included[id as usize].source = true;
        }
        Some(id)
    }

    fn keep_edge(&mut self, edge: u32) {
        if self.edge_seen.contains(&edge) {
            return;
        }
        if self.edges.len() >= self.max_edges {
            self.truncated.edges = true;
            return;
        }
        self.edge_seen.insert(edge);
        self.edges.push(edge);
    }

    /// Walks producers from `expand` (nodes and their depth) and from `edges`
    /// into an included start node. Only a start node at depth zero (the seed
    /// instruction itself) follows every input; any other node, the seed's
    /// own value met again around a loop included, follows the leaf and
    /// address rules.
    fn backward(&mut self, expand: &[(u32, u32)], edges: &[u32]) {
        let mut queue: VecDeque<(u32, u32)> = expand.iter().copied().collect();
        let mut expanded: HashSet<u32> = HashSet::new();
        let mut pending: Vec<(u32, u32)> = edges.iter().map(|edge| (*edge, 0)).collect();
        let mut steps = 0u32;
        loop {
            for (edge, depth) in pending.drain(..) {
                let from = self.sim.edges[edge as usize].from;
                if self.include(from, depth + 1, true).is_none() {
                    continue;
                }
                self.keep_edge(edge);
                let kind = self.sim.nodes[from as usize].kind;
                if (backward_leaf(kind) || addressed_source(kind))
                    && let Some(entry) = self.entry(from)
                {
                    entry.source = true;
                }
                if !expanded.contains(&from) {
                    queue.push_back((from, depth + 1));
                }
            }
            let Some((node, depth)) = queue.pop_front() else {
                break;
            };
            steps += 1;
            if steps & 255 == 0 && Instant::now() > self.deadline {
                self.truncated.deadline = true;
                break;
            }
            if !expanded.insert(node) {
                continue;
            }
            let kind = self.sim.nodes[node as usize].kind;
            let start = depth == 0 && self.entry(node).is_some_and(|entry| entry.seed);
            if !start && backward_leaf(kind) {
                continue;
            }
            if depth >= self.max_depth {
                if !self.adjacency.inputs(node).is_empty() {
                    self.truncated.depth = true;
                    if !start
                        && !addressed_source(kind)
                        && let Some(entry) = self.entry(node)
                    {
                        entry.frontier = true;
                    }
                }
                continue;
            }
            for edge in self.adjacency.inputs(node).to_vec() {
                if !start
                    && !follows_backward(
                        &self.sim.nodes[node as usize],
                        self.sim.edges[edge as usize].kind,
                        self.adjacency.inputs(node).len(),
                    )
                {
                    continue;
                }
                pending.push((edge, depth));
            }
        }
    }

    /// Walks uses from `starts`, values whose consumers are followed. A
    /// consumer the value does not flow through is a sink, whatever else it
    /// is in the slice.
    fn forward(&mut self, starts: &[(Def, u32)]) {
        let mut queue: VecDeque<(Def, u32)> = starts.iter().copied().collect();
        let mut expanded: HashSet<Def> = HashSet::new();
        let mut steps = 0u32;
        while let Some((value, depth)) = queue.pop_front() {
            steps += 1;
            if steps & 255 == 0 && Instant::now() > self.deadline {
                self.truncated.deadline = true;
                break;
            }
            if !expanded.insert(value) {
                continue;
            }
            let uses: Vec<u32> = self
                .adjacency
                .uses(value.node)
                .iter()
                .copied()
                .filter(|edge| self.sim.edges[*edge as usize].result == value.result)
                .collect();
            if depth >= self.max_depth {
                if !uses.is_empty() {
                    self.truncated.depth = true;
                    if let Some(entry) = self.entry(value.node)
                        && !entry.seed
                    {
                        entry.frontier = true;
                    }
                }
                continue;
            }
            for edge in uses {
                let target = self.sim.edges[edge as usize];
                let node = &self.sim.nodes[target.to as usize];
                let continues = forward_continues(node.kind, target.kind);
                if self.include(target.to, depth + 1, false).is_none() {
                    continue;
                }
                self.keep_edge(edge);
                if !continues {
                    if let Some(entry) = self.entry(target.to) {
                        entry.sink = true;
                    }
                    continue;
                }
                for result in 0..node.results.max(1) {
                    queue.push_back((
                        Def {
                            node: target.to,
                            result,
                        },
                        depth + 1,
                    ));
                }
            }
        }
    }
}

/// Instruction text for the requested instruction indices, decoded again from
/// the original body so no text is retained for nodes outside the slice.
fn instruction_text(
    body: &wasmparser::FunctionBody<'_>,
    wanted: &HashSet<u32>,
) -> Result<HashMap<u32, String>> {
    let mut texts = HashMap::new();
    if wanted.is_empty() {
        return Ok(texts);
    }
    let last = wanted.iter().copied().max().unwrap_or(0);
    let mut reader = body.get_operators_reader().map_err(wasm_def_use::bad)?;
    let mut index = 0u32;
    while !reader.eof() && index <= last {
        let op = reader.read().map_err(wasm_def_use::bad)?;
        if wanted.contains(&index) {
            texts.insert(index, operator_text(&op));
        }
        index += 1;
    }
    Ok(texts)
}

/// Whether the instruction at `index` opens a `try_table` or a `try`, whose
/// catch values exist only once the simulation reaches its handlers.
fn opens_handler(body: &wasmparser::FunctionBody<'_>, index: u32) -> Result<bool> {
    let mut reader = body.get_operators_reader().map_err(wasm_def_use::bad)?;
    for _ in 0..index {
        reader.read().map_err(wasm_def_use::bad)?;
    }
    Ok(matches!(
        reader.read().map_err(wasm_def_use::bad)?,
        Operator::TryTable { .. } | Operator::Try { .. }
    ))
}

/// One instruction as `mnemonic operands`, the same spelling as graph rows.
/// Exception handlers name their clauses instead of a parser dump.
fn operator_text(op: &Operator<'_>) -> String {
    let mut text = wasm::mnemonic(op);
    let operands = match op {
        Operator::TryTable { try_table } => {
            let mut listed = try_table
                .catches
                .iter()
                .take(MAX_LISTED_CLAUSES)
                .map(|catch| match catch {
                    wasmparser::Catch::One { tag, label } => format!("(catch {tag} {label})"),
                    wasmparser::Catch::OneRef { tag, label } => {
                        format!("(catch_ref {tag} {label})")
                    }
                    wasmparser::Catch::All { label } => format!("(catch_all {label})"),
                    wasmparser::Catch::AllRef { label } => format!("(catch_all_ref {label})"),
                })
                .collect::<Vec<_>>()
                .join(" ");
            if try_table.catches.len() > MAX_LISTED_CLAUSES {
                let _ = write!(listed, " ... {} clauses", try_table.catches.len());
            }
            listed
        }
        Operator::Try { .. } => String::new(),
        Operator::Catch { tag_index } => tag_index.to_string(),
        _ => wasm_graph::operands(op),
    };
    if !operands.is_empty() {
        text.push(' ');
        text.push_str(&operands);
    }
    text
}

/// Like `expression`, a node's text is capped so no single node can fill the
/// response budget.
fn capped(mut text: String) -> String {
    if text.len() > MAX_TEXT_BYTES {
        let mut cut = MAX_TEXT_BYTES;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("...");
    }
    text
}

struct Texts<'s> {
    sim: &'s Simulation,
    adjacency: &'s Adjacency,
    instructions: HashMap<u32, String>,
}

impl Texts<'_> {
    fn synthetic(&self, node: u32) -> String {
        let n = &self.sim.nodes[node as usize];
        match n.kind {
            NodeKind::Param => format!("param {}", n.index),
            NodeKind::LocalInit => format!("local {} (zero at entry)", n.index),
            NodeKind::Phi if n.index != NONE => format!("join of local {}", n.index),
            NodeKind::Phi => format!("join of result {}", n.aux),
            NodeKind::ExceptionValue => "exception values".to_owned(),
            NodeKind::Unknown => "unknown (no operand was on the stack)".to_owned(),
            NodeKind::Return => "return".to_owned(),
            _ => String::new(),
        }
    }

    fn text(&self, node: u32) -> String {
        let n = &self.sim.nodes[node as usize];
        if n.kind == NodeKind::Return
            && n.instruction != NONE
            && let Some(text) = self.instructions.get(&n.instruction)
            && text != "end"
        {
            return text.clone();
        }
        match n.kind {
            NodeKind::Param
            | NodeKind::LocalInit
            | NodeKind::Phi
            | NodeKind::Unknown
            | NodeKind::Return => self.synthetic(node),
            NodeKind::ExceptionValue => {
                let tag = if n.index == NONE {
                    "any tag".to_owned()
                } else {
                    format!("tag {}", n.index)
                };
                match self.instructions.get(&n.instruction) {
                    Some(handler) => format!("exception values of {tag} at {handler}"),
                    None => format!("exception values of {tag}"),
                }
            }
            _ => self
                .instructions
                .get(&n.instruction)
                .cloned()
                .unwrap_or_else(|| self.synthetic(node)),
        }
    }

    /// A bounded nested rendering of the value a node produces.
    fn expression(&self, node: u32, result: u32, depth: u32, out: &mut String) {
        if out.len() > MAX_EXPRESSION_BYTES {
            return;
        }
        let n = &self.sim.nodes[node as usize];
        match n.kind {
            NodeKind::Param => {
                let _ = write!(out, "param {}", n.index);
            }
            NodeKind::LocalInit => {
                let _ = write!(out, "0 /* local {} */", n.index);
            }
            NodeKind::Phi => {
                let _ = write!(out, "join@0x{:x}", n.offset);
            }
            NodeKind::LocalGet => {
                let _ = write!(out, "local {}", n.index);
            }
            NodeKind::GlobalGet => {
                let _ = write!(out, "global {}", n.index);
            }
            NodeKind::Unknown => out.push('?'),
            NodeKind::ExceptionValue => {
                let _ = write!(out, "exception[{result}]");
            }
            NodeKind::Const => {
                let text = self.text(node);
                out.push_str(
                    text.split_once(' ')
                        .map_or(text.as_str(), |(_, value)| value),
                );
            }
            _ => {
                let text = self.text(node);
                out.push_str(&text);
                let inputs: Vec<u32> = self
                    .adjacency
                    .inputs(node)
                    .iter()
                    .copied()
                    .filter(|edge| {
                        self.sim.edges[*edge as usize].kind != EdgeKind::Merge
                            && self.sim.edges[*edge as usize].kind != EdgeKind::ForwardedStore
                    })
                    .collect();
                if inputs.is_empty() {
                    return;
                }
                if depth == 0 {
                    out.push_str("(...)");
                    return;
                }
                out.push('(');
                for (position, edge) in inputs.iter().enumerate() {
                    if position > 0 {
                        out.push_str(", ");
                    }
                    let edge = self.sim.edges[*edge as usize];
                    self.expression(edge.from, edge.result, depth - 1, out);
                    if out.len() > MAX_EXPRESSION_BYTES {
                        return;
                    }
                }
                out.push(')');
            }
        }
    }

    fn bounded_expression(&self, node: u32) -> String {
        let mut out = String::new();
        self.expression(node, 0, EXPRESSION_DEPTH, &mut out);
        if out.len() > MAX_EXPRESSION_BYTES {
            let mut cut = MAX_EXPRESSION_BYTES;
            while !out.is_char_boundary(cut) {
                cut -= 1;
            }
            out.truncate(cut);
            out.push_str("...");
        }
        out
    }
}

/// Direct call sites of one callee: (caller, call offset) pairs, whether the
/// scan reached the module's end, and whether a `ref.func` names the callee.
struct CallSites {
    sites: Vec<(u32, u32)>,
    finished: bool,
    referenced: bool,
    /// Bodies that do not decode; their calls are not listed.
    undecoded: Vec<u32>,
}

/// Every direct call site of `callee` in the module, bounded by the deadline
/// and a site cap.
fn call_sites(module: &Module<'_>, callee: u32, deadline: Instant) -> CallSites {
    let mut found = CallSites {
        sites: Vec::new(),
        finished: true,
        referenced: false,
        undecoded: Vec::new(),
    };
    let mut steps = 0u64;
    'bodies: for (position, body) in module.bodies.iter().enumerate() {
        let caller = module.imported_functions + position as u32;
        // Another function's bytes need not decode; that body is skipped and
        // named, and the seed's own function is unaffected.
        let Ok(mut reader) = body.get_operators_reader() else {
            found.undecoded.push(caller);
            continue;
        };
        while !reader.eof() {
            steps += 1;
            if steps & 4095 == 0 && Instant::now() > deadline {
                found.finished = false;
                break 'bodies;
            }
            let Ok((op, offset)) = reader.read_with_offset() else {
                found.undecoded.push(caller);
                continue 'bodies;
            };
            match op {
                Operator::Call { function_index } | Operator::ReturnCall { function_index }
                    if function_index == callee =>
                {
                    if found.sites.len() >= MAX_CALL_SITES {
                        found.finished = false;
                        break 'bodies;
                    }
                    found.sites.push((caller, offset as u32));
                }
                Operator::RefFunc { function_index } if function_index == callee => {
                    found.referenced = true
                }
                _ => {}
            }
        }
    }
    if !found.undecoded.is_empty() {
        found.finished = false;
    }
    found
}

/// The native helper's entry point: the route's query without its artifact_id.
pub fn value_flow_query(root: &Path, id: &str, query: &str) -> Result<Value> {
    let request = parse_query(query)?;
    if request.artifact_id.is_some() {
        return Err(Error::bad(
            "Pass the artifact with --artifact-id, not in the query",
        ));
    }
    value_flow(root, id, &request)
}

/// The value-flow document for one request, or a provider error.
pub fn value_flow(root: &Path, id: &str, request: &Request) -> Result<Value> {
    let artifact = wasm_graph::artifact(root, id)?;
    value_flow_of(&artifact, request)
}

/// The document for verified artifact bytes already in memory.
pub(crate) fn value_flow_of(artifact: &wasm_graph::Artifact, request: &Request) -> Result<Value> {
    value_flow_with(artifact, request, wasm_def_use::Limits::default())
}

/// [`value_flow_of`] with explicit simulation budgets, so tests reach each stop.
pub(crate) fn value_flow_with(
    artifact: &wasm_graph::Artifact,
    request: &Request,
    limits: wasm_def_use::Limits,
) -> Result<Value> {
    let started = Instant::now();
    let deadline = started + DEADLINE;
    let module = Module::read(&artifact.bytes)?;
    let function = request.function;
    if function < module.imported_functions {
        return Err(Error::new(
            404,
            format!("WASM function {function} is imported and has no body in this module"),
        ));
    }
    let body = module
        .bodies
        .get((function - module.imported_functions) as usize)
        .ok_or_else(|| {
            Error::new(
                404,
                format!("WASM function {function} is not defined by this module"),
            )
        })?;
    let range = body.range();
    if range.len() > MAX_BODY_BYTES {
        return Err(Error::bad(format!(
            "WASM function {function} is {} bytes, past the {MAX_BODY_BYTES}-byte body limit web engines enforce",
            range.len()
        )));
    }
    let sim = wasm_def_use::simulate_with(&module, function, body, deadline, limits)?;
    let adjacency = Adjacency::new(&sim);
    let max_nodes = request.max_nodes;
    let mut slicer = Slicer {
        sim: &sim,
        adjacency,
        included: Vec::new(),
        id_of: HashMap::new(),
        edges: Vec::new(),
        edge_seen: HashSet::new(),
        max_nodes,
        max_edges: max_nodes * EDGES_PER_NODE,
        max_depth: request.max_depth,
        truncated: Truncated::default(),
        deadline,
    };
    let mut omissions = sim.omissions.clone();
    let mut seed_values: Vec<Def> = Vec::new();
    let mut seed_nodes: Vec<u32> = Vec::new();
    let (seed_offset, seed_operand, seed_local, operand_count) = match request.seed {
        Seed::Instruction { offset, operand } => {
            let Some(instruction) = sim.instruction_at(offset) else {
                // Past the last simulated instruction, or no instruction was
                // simulated at all: the stop, not the offset, is the answer.
                let simulated_to = sim.instructions.last().copied();
                if let Some(stopped) = sim.stopped_at
                    && (offset as usize) < range.end
                    && (offset >= stopped || simulated_to.is_none_or(|last| offset > last))
                {
                    return Err(Error::new(
                        400,
                        format!("Value flow stopped at byte {stopped}, before the seed at byte {offset}: {}", omissions.join(" ")),
                    )
                    .with_code(Code::ResourceLimit));
                }
                return Err(Error::new(
                    404,
                    format!("No instruction of WASM function {function} starts at byte {offset}"),
                ));
            };
            if let Some(stopped) = sim.stopped_at
                && offset >= stopped
            {
                return Err(Error::new(
                    400,
                    format!(
                        "Value flow stopped at byte {stopped}, at or before the seed at byte {offset}: {}",
                        sim.omissions.join(" ")
                    ),
                )
                .with_code(Code::ResourceLimit));
            }
            if !sim.instruction_live[instruction as usize] {
                return Err(Error::bad(format!(
                    "The instruction at byte {offset} is unreachable in declared control flow, so no value flows through it"
                )));
            }
            let inputs = sim.inputs(instruction).to_vec();
            let node = sim.instruction_nodes[instruction as usize];
            match operand {
                Some(position) => {
                    let Some(value) = inputs.get(position as usize).copied() else {
                        return Err(Error::bad(format!(
                            "The instruction at byte {offset} has {} operands; operand {position} does not exist",
                            inputs.len()
                        )));
                    };
                    let mut starts = Vec::new();
                    if node != NONE {
                        slicer.seed(node);
                        seed_nodes.push(node);
                        if let Some(edge) =
                            slicer.adjacency.inputs(node).iter().copied().find(|edge| {
                                let edge = sim.edges[*edge as usize];
                                edge.operand == position
                                    && edge.kind != EdgeKind::Merge
                                    && edge.from == value.node
                                    && edge.result == value.result
                            })
                        {
                            starts.push(edge);
                        }
                    }
                    // The producer is always listed, one step from the seed,
                    // so a forward-only slice still shows where it starts.
                    slicer.producer(value.node);
                    if let Some(edge) = starts.first() {
                        slicer.keep_edge(*edge);
                    }
                    if request.direction.backward() {
                        slicer.backward(&[(value.node, 1)], &[]);
                    }
                    if request.direction.forward() {
                        slicer.forward(&[(value, 1)]);
                    }
                }
                None => {
                    if node == NONE && inputs.is_empty() {
                        // A try_table's catch values are made at its end; a
                        // stop inside its body never reached them.
                        if let Some(stopped) = sim.stopped_at
                            && opens_handler(body, instruction)?
                        {
                            return Err(Error::new(
                                400,
                                format!(
                                    "Value flow stopped at byte {stopped}, inside the handler at byte {offset}, before its catch values were made: {}",
                                    sim.omissions.join(" ")
                                ),
                            )
                            .with_code(Code::ResourceLimit));
                        }
                        return Err(Error::bad(format!(
                            "The instruction at byte {offset} neither produces nor consumes a value"
                        )));
                    }
                    if node != NONE {
                        // A try_table makes one exception node per catch
                        // clause; the whole instruction seeds every one.
                        let mut nodes = vec![node];
                        if sim.nodes[node as usize].kind == NodeKind::ExceptionValue {
                            nodes.extend((0..sim.nodes.len() as u32).filter(|other| {
                                *other != node
                                    && sim.nodes[*other as usize].kind == NodeKind::ExceptionValue
                                    && sim.nodes[*other as usize].instruction == instruction
                            }));
                        }
                        for node in nodes {
                            if slicer.seed(node).is_none() {
                                break;
                            }
                            seed_nodes.push(node);
                            if request.direction.backward() {
                                let edges: Vec<u32> = slicer.adjacency.inputs(node).to_vec();
                                slicer.backward(&[], &edges);
                            }
                            let results = sim.nodes[node as usize].results;
                            if request.direction.forward() {
                                let starts: Vec<(Def, u32)> = (0..results)
                                    .map(|result| (Def { node, result }, 0))
                                    .collect();
                                slicer.forward(&starts);
                            }
                        }
                    } else {
                        // A block end or a branch has no node of its own: its
                        // operands' producers are ordinary nodes one step away.
                        for value in &inputs {
                            slicer.producer(value.node);
                        }
                        if request.direction.backward() {
                            let expand: Vec<(u32, u32)> =
                                inputs.iter().map(|value| (value.node, 1)).collect();
                            slicer.backward(&expand, &[]);
                        }
                        if request.direction.forward() {
                            let starts: Vec<(Def, u32)> =
                                inputs.iter().map(|value| (*value, 1)).collect();
                            slicer.forward(&starts);
                        }
                    }
                }
            }
            (Some(offset), operand, None, Some(inputs.len()))
        }
        Seed::Local(local) => {
            if local >= sim.locals {
                return Err(Error::bad(format!(
                    "WASM function {function} has {} locals; local {local} does not exist",
                    sim.locals
                )));
            }
            let defs: Vec<u32> = sim
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| {
                    node.index == local
                        && matches!(
                            node.kind,
                            NodeKind::Param
                                | NodeKind::LocalInit
                                | NodeKind::LocalSet
                                | NodeKind::LocalTee
                                | NodeKind::Phi
                        )
                })
                .map(|(position, _)| position as u32)
                .collect();
            if defs.is_empty() {
                // Nothing simulated says nothing about the local.
                omissions.push(match sim.stopped_at {
                    Some(stopped) if sim.instructions.is_empty() => format!(
                        "Simulation stopped at byte {stopped} before any instruction, so local {local} was not traced."
                    ),
                    Some(stopped) => format!(
                        "Local {local} is not read or written before simulation stopped at byte {stopped}."
                    ),
                    None => format!("Local {local} is never read or written in this function."),
                });
            }
            for def in &defs {
                if let Some(id) = slicer.seed(*def) {
                    // A parameter or a local's zero value is also where the
                    // local's value comes from.
                    if backward_leaf(sim.nodes[*def as usize].kind) {
                        slicer.included[id as usize].source = true;
                    }
                    seed_nodes.push(*def);
                    seed_values.push(Def {
                        node: *def,
                        result: 0,
                    });
                }
            }
            if request.direction.backward() {
                let mut edges = Vec::new();
                for def in &seed_nodes {
                    edges.extend_from_slice(slicer.adjacency.inputs(*def));
                }
                slicer.backward(&[], &edges);
            }
            if request.direction.forward() {
                let starts: Vec<(Def, u32)> = seed_values.iter().map(|value| (*value, 0)).collect();
                slicer.forward(&starts);
            }
            (None, None, Some(local), None)
        }
    };
    // Instruction text for included nodes and the inputs of their expressions.
    let mut wanted: HashSet<u32> = HashSet::new();
    let mut frontier: Vec<(u32, u32)> = slicer
        .included
        .iter()
        .map(|entry| (entry.node, EXPRESSION_DEPTH + 1))
        .collect();
    while let Some((node, depth)) = frontier.pop() {
        let n = &sim.nodes[node as usize];
        if n.instruction != NONE && !wanted.insert(n.instruction) {
            continue;
        }
        if depth == 0 || wanted.len() > max_nodes * 8 {
            continue;
        }
        for edge in slicer.adjacency.inputs(node) {
            let edge = sim.edges[*edge as usize];
            if edge.kind != EdgeKind::Merge {
                frontier.push((edge.from, depth - 1));
            }
        }
    }
    let texts = Texts {
        sim: &sim,
        adjacency: &slicer.adjacency,
        instructions: instruction_text(body, &wanted)?,
    };
    // Nodes, edges, joins and steps are built once. The response keeps the
    // longest prefix of nodes in walk order (nearest the seed first) that fits
    // the byte budget, with every edge, join and step among them.
    let mut nodes = Vec::with_capacity(slicer.included.len());
    for (id, entry) in slicer.included.iter().enumerate() {
        let n = &sim.nodes[entry.node as usize];
        let mut object = Map::new();
        object.insert("id".into(), json!(id));
        object.insert("kind".into(), json!(n.kind.name()));
        object.insert("byte_offset".into(), json!(n.offset));
        object.insert("role".into(), json!(entry.role().name()));
        object.insert("source".into(), json!(entry.source));
        object.insert("sink".into(), json!(entry.sink));
        object.insert(
            "direction".into(),
            json!(match (entry.seed, entry.backward, entry.forward) {
                (true, _, _) => "seed",
                (_, true, true) => "both",
                (_, true, false) => "backward",
                _ => "forward",
            }),
        );
        object.insert("depth".into(), json!(entry.depth));
        object.insert("results".into(), json!(n.results));
        match n.kind {
            NodeKind::Param
            | NodeKind::LocalInit
            | NodeKind::LocalGet
            | NodeKind::LocalSet
            | NodeKind::LocalTee => {
                object.insert("local".into(), json!(n.index));
            }
            NodeKind::Phi => {
                if n.index != NONE {
                    object.insert("local".into(), json!(n.index));
                } else {
                    object.insert("slot".into(), json!(n.aux));
                }
                object.insert("join".into(), json!(n.join.name()));
            }
            NodeKind::GlobalGet | NodeKind::GlobalSet => {
                object.insert("global".into(), json!(n.index));
            }
            NodeKind::Call | NodeKind::ImportCall => {
                object.insert("function".into(), json!(n.index));
                if n.kind == NodeKind::ImportCall
                    && let Some((module_name, field)) = module.imports.get(n.index as usize)
                {
                    object.insert(
                        "import".into(),
                        json!({"module": module_name, "name": field}),
                    );
                }
            }
            NodeKind::CallIndirect => {
                object.insert("type".into(), json!(n.index));
                object.insert("table".into(), json!(n.aux));
            }
            NodeKind::CallRef => {
                object.insert("type".into(), json!(n.index));
            }
            NodeKind::ExceptionValue | NodeKind::Throw if n.index != NONE => {
                object.insert("tag".into(), json!(n.index));
            }
            _ => {}
        }
        object.insert("text".into(), json!(capped(texts.text(entry.node))));
        if n.results > 0 && !matches!(n.kind, NodeKind::Return | NodeKind::LocalSet) {
            object.insert(
                "expression".into(),
                json!(texts.bounded_expression(entry.node)),
            );
        }
        nodes.push(Value::Object(object));
    }
    let mut edges: Vec<(usize, usize, Map<String, Value>)> = Vec::with_capacity(slicer.edges.len());
    for edge in &slicer.edges {
        let e = &sim.edges[*edge as usize];
        let (Some(from), Some(to)) = (slicer.id_of.get(&e.from), slicer.id_of.get(&e.to)) else {
            continue;
        };
        let mut object = Map::new();
        object.insert("kind".into(), json!(e.kind.name()));
        object.insert("operand".into(), json!(e.operand));
        object.insert("result".into(), json!(e.result));
        if let Some(via) = e.via.name() {
            object.insert("via".into(), json!(via));
            object.insert("via_offset".into(), json!(e.via_offset));
        }
        edges.push((*from as usize, *to as usize, object));
    }
    // Every join lists its incoming edges, in the slice or not, up to a cap.
    struct JoinRow {
        node: usize,
        object: Map<String, Value>,
        incoming: Vec<(Option<usize>, Map<String, Value>)>,
    }
    let mut joins: Vec<JoinRow> = Vec::new();
    let mut join_entries = 0usize;
    for (id, entry) in slicer.included.iter().enumerate() {
        let n = &sim.nodes[entry.node as usize];
        if n.kind != NodeKind::Phi {
            continue;
        }
        let inputs = slicer.adjacency.inputs(entry.node);
        let mut incoming = Vec::new();
        for edge in inputs.iter().take(MAX_JOIN_ENTRIES) {
            if join_entries >= slicer.max_edges {
                break;
            }
            join_entries += 1;
            let e = &sim.edges[*edge as usize];
            let from = &sim.nodes[e.from as usize];
            let mut item = Map::new();
            item.insert("from_kind".into(), json!(from.kind.name()));
            item.insert("from_offset".into(), json!(from.offset));
            item.insert("via".into(), json!(e.via.name()));
            item.insert("via_offset".into(), json!(e.via_offset));
            incoming.push((slicer.id_of.get(&e.from).map(|id| *id as usize), item));
        }
        if incoming.len() < inputs.len() {
            slicer.truncated.joins = true;
        }
        let mut object = Map::new();
        object.insert("node".into(), json!(id));
        object.insert("join".into(), json!(n.join.name()));
        object.insert("byte_offset".into(), json!(n.offset));
        if n.index != NONE {
            object.insert("local".into(), json!(n.index));
        } else {
            object.insert("slot".into(), json!(n.aux));
        }
        object.insert("incoming_count".into(), json!(inputs.len()));
        if sim.open_joins.contains(&entry.node) {
            object.insert("incomplete".into(), json!(true));
        }
        joins.push(JoinRow {
            node: id,
            object,
            incoming,
        });
    }
    let interprocedural = interprocedural_steps(
        request,
        &module,
        function,
        &sim,
        &slicer,
        &mut omissions,
        deadline,
    )?;
    let truncated = &slicer.truncated;
    if truncated.nodes {
        omissions.push(format!(
            "Node cap of {max_nodes} reached; the slice continues past the nodes listed."
        ));
    }
    if truncated.edges {
        omissions.push(format!(
            "Edge cap of {} reached; some edges between listed nodes are not listed.",
            slicer.max_edges
        ));
    }
    if truncated.depth {
        omissions.push(format!(
            "Depth cap of {} reached; frontier nodes were not followed further.",
            request.max_depth
        ));
    }
    if truncated.deadline {
        omissions.push("Slice deadline reached; the slice is the part walked before it.".into());
    }
    if truncated.joins {
        omissions.push(format!(
            "A join lists at most {MAX_JOIN_ENTRIES} incoming edges ({} in all); incoming_count gives each join's total.",
            slicer.max_edges
        ));
    }
    if omissions.len() > MAX_OMISSIONS {
        let more = omissions.len() - (MAX_OMISSIONS - 1);
        omissions.truncate(MAX_OMISSIONS - 1);
        omissions.push(format!("{more} more omissions are not listed."));
    }
    let limits = json!({
        "max_input_bytes": wasm_graph::MAX_BYTES,
        "max_body_bytes": MAX_BODY_BYTES,
        "max_locals": wasm_def_use::MAX_LOCALS,
        "max_instructions": wasm_def_use::MAX_INSTRUCTIONS,
        "max_work": wasm_def_use::MAX_WORK,
        "max_nodes": max_nodes,
        "max_edges": max_nodes * EDGES_PER_NODE,
        "max_join_entries": MAX_JOIN_ENTRIES,
        "max_depth": request.max_depth,
        "max_expression_bytes": MAX_EXPRESSION_BYTES,
        "max_text_bytes": MAX_TEXT_BYTES,
        "max_interprocedural_steps": MAX_STEPS,
        "max_call_sites": MAX_CALL_SITES,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "deadline_ms": DEADLINE.as_millis() as u64,
    });
    let total = nodes.len();
    // When the budget cuts nodes, the seed goes first, then the slice's
    // sources and sinks, then joins, then the steps between them nearest the
    // seed. Kept nodes are renumbered in walk order.
    let rank = |id: usize| -> u8 {
        let entry = &slicer.included[id];
        match entry.role() {
            // A block end or branch seed has no node: its operands' producers,
            // one step away, stand for it.
            _ if entry.seed || entry.depth <= 1 => 0,
            _ if entry.source || entry.sink => 1,
            _ if sim.nodes[slicer.included[id].node as usize].kind == NodeKind::Phi => 2,
            _ => 3,
        }
    };
    let mut ranked: Vec<usize> = (0..total).collect();
    ranked.sort_by_key(|id| (rank(*id), *id));
    let assemble = |keep: usize| -> Value {
        let cut = keep < total;
        let mut chosen = vec![false; total];
        for id in &ranked[..keep] {
            chosen[*id] = true;
        }
        let mut renumber = vec![None; total];
        let mut next = 0usize;
        for id in 0..total {
            if chosen[id] {
                renumber[id] = Some(next);
                next += 1;
            }
        }
        let mut notes = omissions.clone();
        if cut {
            notes.push(format!(
                "Response budget of {MAX_RESPONSE_BYTES} bytes reached; {keep} of {total} nodes are listed: the seed, sources, sinks and joins first, then the nearest steps."
            ));
        }
        let kept_nodes: Vec<Value> = (0..total)
            .filter(|id| chosen[*id])
            .map(|id| {
                let mut node = nodes[id].clone();
                node["id"] = json!(renumber[id]);
                node
            })
            .collect();
        let kept_edges: Vec<Value> = edges
            .iter()
            .filter_map(|(from, to, object)| {
                let (from, to) = (renumber[*from]?, renumber[*to]?);
                let mut object = object.clone();
                object.insert("from".into(), json!(from));
                object.insert("to".into(), json!(to));
                Some(Value::Object(object))
            })
            .collect();
        let kept_joins: Vec<Value> = joins
            .iter()
            .filter_map(|join| {
                let node = renumber[join.node]?;
                let mut object = join.object.clone();
                object.insert("node".into(), json!(node));
                let incoming = join
                    .incoming
                    .iter()
                    .map(|(from, item)| {
                        let mut item = item.clone();
                        item.insert("from".into(), json!(from.and_then(|id| renumber[id])));
                        Value::Object(item)
                    })
                    .collect();
                object.insert("incoming".into(), Value::Array(incoming));
                Some(Value::Object(object))
            })
            .collect();
        let ends = |end: fn(&Included) -> bool| -> Vec<usize> {
            (0..total)
                .filter(|id| end(&slicer.included[*id]))
                .filter_map(|id| renumber[id])
                .collect()
        };
        let mut steps_value = interprocedural.clone();
        if let Some(steps) = steps_value["steps"].as_array_mut() {
            steps.retain_mut(|step| {
                match step["node"]
                    .as_u64()
                    .and_then(|node| renumber.get(node as usize).copied().flatten())
                {
                    Some(node) => {
                        step["node"] = json!(node);
                        true
                    }
                    None => false,
                }
            });
        }
        let partial = !notes.is_empty() || sim.stopped_at.is_some();
        let truncated_value = json!({
            "nodes": truncated.nodes,
            "edges": truncated.edges,
            "depth": truncated.depth,
            "deadline": truncated.deadline,
            "joins": truncated.joins,
            "simulation": sim.stopped_at.is_some(),
            "bytes": cut,
        });
        json!({
            "schema": "wasm-value-flow-v1",
            "artifact_id": artifact.artifact_id,
            "sha256": artifact.sha256,
            "byte_size": artifact.bytes.len(),
            "function_index": function,
            "type_index": sim.type_index,
            "byte_offset": range.start,
            "byte_end": range.end,
            "params": sim.params,
            "locals": sim.locals,
            "results": sim.results,
            "evidence": "declared_static",
            "complete": false,
            "status": if partial { "partial" } else { "computed" },
            "request": {
                "direction": request.direction.name(),
                "max_nodes": max_nodes,
                "max_depth": request.max_depth,
                "interprocedural": request.interprocedural,
            },
            "seed": {
                "kind": if seed_local.is_some() { "local" } else { "instruction" },
                "byte_offset": seed_offset,
                "operand": seed_operand,
                "operand_count": operand_count,
                "local": seed_local,
                "nodes": seed_nodes.iter().filter_map(|node| slicer.id_of.get(node)).filter_map(|id| renumber[*id as usize]).collect::<Vec<_>>(),
            },
            "instructions_simulated": sim.instructions.len(),
            "simulation_stopped_at": sim.stopped_at,
            "node_count": kept_nodes.len(),
            "edge_count": kept_edges.len(),
            "nodes": kept_nodes,
            "edges": kept_edges,
            "joins": kept_joins,
            "sources": ends(|entry| entry.source),
            "sinks": ends(|entry| entry.sink),
            "interprocedural": steps_value,
            "truncated": truncated_value,
            "omissions": notes,
            "limits": limits,
            "notice": "Declared static value flow inside one function, from the module bytes. Memory is a source unless a same-block store to the same constant address is proven; nothing was executed.",
        })
    };
    let whole = assemble(total);
    if fits_response(&whole) {
        return Ok(whole);
    }
    // The longest ranked prefix that fits; fewer nodes never make the document
    // larger. The seed ranks first, and every node's text is capped, so one
    // node is far under the budget and the seed is always listed.
    let (mut low, mut high) = (1usize.min(total - 1), total - 1);
    while low < high {
        let middle = (low + high).div_ceil(2);
        if fits_response(&assemble(middle)) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    Ok(assemble(low))
}

/// Whether a document fits the response budget pretty-printed both as it is
/// and as `reb-api mcp` projects it below Full access, where a content string
/// becomes a larger omission object.
pub fn fits_response(document: &Value) -> bool {
    let pretty =
        |value: &Value| serde_json::to_string_pretty(value).map_or(usize::MAX, |text| text.len());
    pretty(document) <= MAX_RESPONSE_BYTES
        && pretty(&content_omitted(document, None)) <= MAX_RESPONSE_BYTES
}

/// The `--omit-content` projection of this document's fields: `text`,
/// `expression` and any string over 160 characters become an omission object.
pub fn content_omitted(value: &Value, key: Option<&str>) -> Value {
    match value {
        Value::String(text)
            if matches!(key, Some("text" | "expression")) || text.chars().count() > 160 =>
        {
            json!({"omitted": "string", "chars": text.chars().count(), "bytes": text.len()})
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| content_omitted(item, key))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, child)| (name.clone(), content_omitted(child, Some(name))))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn interprocedural_steps(
    request: &Request,
    module: &Module<'_>,
    function: u32,
    sim: &Simulation,
    slicer: &Slicer<'_>,
    omissions: &mut Vec<String>,
    deadline: Instant,
) -> Result<Value> {
    if !request.interprocedural {
        return Ok(json!({"requested": false, "steps": [], "direct_callers": null}));
    }
    let mut steps = Vec::new();
    let mut capped = false;
    let mut push = |steps: &mut Vec<Value>, step: Value| {
        if steps.len() >= MAX_STEPS {
            capped = true;
        } else {
            steps.push(step);
        }
    };
    let mut params = Vec::new();
    let mut returns = Vec::new();
    for (id, entry) in slicer.included.iter().enumerate() {
        let n = &sim.nodes[entry.node as usize];
        match n.kind {
            NodeKind::Param => params.push((id, n.index)),
            NodeKind::Return if entry.forward => returns.push(id),
            NodeKind::Call if entry.source || entry.seed => push(
                &mut steps,
                json!({"kind": "callee_return", "node": id, "function": n.index, "byte_offset": n.offset, "slot": null}),
            ),
            _ => {}
        }
    }
    for edge in &slicer.edges {
        let e = &sim.edges[*edge as usize];
        let to = &sim.nodes[e.to as usize];
        if e.kind == EdgeKind::Argument && to.kind == NodeKind::Call {
            push(
                &mut steps,
                json!({"kind": "callee_param", "node": slicer.id_of[&e.to], "function": to.index, "byte_offset": to.offset, "slot": e.operand}),
            );
        }
    }
    let mut direct = Value::Null;
    if !params.is_empty() || !returns.is_empty() {
        let CallSites {
            sites,
            finished,
            referenced,
            undecoded,
        } = call_sites(module, function, deadline);
        if !undecoded.is_empty() {
            let listed: Vec<String> = undecoded.iter().take(8).map(u32::to_string).collect();
            omissions.push(format!(
                "The direct call site scan could not decode {} function bodies (first: {}); calls in them are not listed.",
                undecoded.len(),
                listed.join(", ")
            ));
        }
        let indirect = referenced
            || module.exported.contains(&function)
            || module.element_functions.contains(&function)
            || module.start == Some(function);
        for (caller, offset) in &sites {
            for (id, param) in &params {
                push(
                    &mut steps,
                    json!({"kind": "caller_argument", "node": id, "function": caller, "byte_offset": offset, "slot": param}),
                );
            }
            for id in &returns {
                push(
                    &mut steps,
                    json!({"kind": "caller_result", "node": id, "function": caller, "byte_offset": offset, "slot": null}),
                );
            }
        }
        if !finished {
            omissions.push(
                "The direct call site scan stopped at its cap or deadline; more callers may exist."
                    .into(),
            );
        }
        direct = json!({
            "sites": sites.len(),
            "scan_complete": finished,
            "also_reachable_indirectly": indirect,
        });
    }
    if capped {
        omissions.push(format!("Interprocedural step cap of {MAX_STEPS} reached."));
    }
    Ok(json!({"requested": true, "steps": steps, "direct_callers": direct}))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_WAT: &str =
        include_str!("../../../tools/fixtures/wasm-value-flow/value-flow.wat");
    const FIXTURE_WASM: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/fixtures/wasm-value-flow/value-flow.wasm"
    );

    fn fixture() -> Vec<u8> {
        wat::parse_str(FIXTURE_WAT).expect("value-flow fixture")
    }

    fn store(bytes: &[u8]) -> tempfile::TempDir {
        use sha2::{Digest, Sha256};
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("blobs")).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        std::fs::write(directory.path().join(format!("blobs/{hash}.bin")), bytes).unwrap();
        let record = json!({"protocol_version":1,"artifact_id":"7","session_id":"1","navigation_id":"1","frame_id":"1",
            "parent_artifact_id":"0","creator_event_id":"0","kind":"wasm","url":"https://example.test/module.wasm",
            "mime_type":"application/wasm","byte_size":bytes.len(),"sha256":hash,"sensitive":false,"content_path":format!("blobs/{hash}.bin")});
        std::fs::write(
            directory.path().join("manifest.jsonl"),
            format!("{record}\n"),
        )
        .unwrap();
        directory
    }

    fn flow(bytes: &[u8], query: &str) -> Result<Value> {
        let directory = store(bytes);
        value_flow_query(directory.path(), "7", query)
    }

    /// Byte offset of the `nth` instruction of `function` whose mnemonic is `name`.
    fn offset_of(bytes: &[u8], function: u32, name: &str, nth: usize) -> u32 {
        let module = Module::read(bytes).unwrap();
        let body = &module.bodies[(function - module.imported_functions) as usize];
        let mut reader = body.get_operators_reader().unwrap();
        let mut seen = 0;
        while !reader.eof() {
            let (op, offset) = reader.read_with_offset().unwrap();
            if wasm::mnemonic(&op) == name {
                if seen == nth {
                    return offset as u32;
                }
                seen += 1;
            }
        }
        panic!("no {name} #{nth} in function {function}");
    }

    fn kinds_of<'a>(document: &'a Value, ids: &str) -> Vec<&'a str> {
        document[ids]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| {
                document["nodes"][id.as_u64().unwrap() as usize]["kind"]
                    .as_str()
                    .unwrap()
            })
            .collect()
    }

    fn node<'a>(document: &'a Value, kind: &str) -> Vec<&'a Value> {
        document["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["kind"] == kind)
            .collect()
    }

    fn edge_kinds(document: &Value) -> HashSet<String> {
        document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn checked_in_fixture_is_built_from_its_wat_source() {
        let bytes = fixture();
        if std::env::var_os("REB_WRITE_VALUE_FLOW_FIXTURE").is_some() {
            std::fs::write(FIXTURE_WASM, &bytes).unwrap();
        }
        let checked_in = std::fs::read(FIXTURE_WASM).expect("checked-in value-flow.wasm");
        assert!(
            checked_in == bytes,
            "tools/fixtures/wasm-value-flow/value-flow.wasm differs from its .wat; rebuild with REB_WRITE_VALUE_FLOW_FIXTURE=1"
        );
    }

    #[test]
    fn backward_slice_reaches_params_loads_imports_and_names_every_join() {
        let bytes = fixture();
        let send = offset_of(&bytes, 2, "call", 1);
        let document = flow(
            &bytes,
            &format!("function=2&offset={send}&operand=0&direction=backward"),
        )
        .unwrap();
        assert_eq!(document["schema"], "wasm-value-flow-v1");
        assert_eq!(document["status"], "computed", "{}", document["omissions"]);
        assert_eq!(document["seed"]["operand"], 0);
        let sources = kinds_of(&document, "sources");
        for kind in ["param", "load", "import_call", "const", "local_init"] {
            assert!(sources.contains(&kind), "{kind} in {sources:?}");
        }
        assert!(document["sinks"].as_array().unwrap().is_empty());
        let params: Vec<u64> = node(&document, "param")
            .iter()
            .map(|n| n["local"].as_u64().unwrap())
            .collect();
        assert!(params.contains(&0) && params.contains(&1), "{params:?}");
        // The memory load at offset=8 is a source whose address slice is param 1.
        let load = node(&document, "load")
            .into_iter()
            .find(|n| n["text"].as_str().unwrap().contains("offset=8"))
            .unwrap();
        assert!(
            load["expression"].as_str().unwrap().contains("local 1"),
            "{load}"
        );
        assert!(edge_kinds(&document).contains("address"));
        // The load from constant 64 follows the store just before it.
        assert!(edge_kinds(&document).contains("forwarded_store"));
        let joins = document["joins"].as_array().unwrap();
        let loop_acc = joins
            .iter()
            .find(|j| j["join"] == "loop" && j["local"] == 2)
            .expect("loop join of acc");
        let vias: Vec<&str> = loop_acc["incoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["via"].as_str().unwrap())
            .collect();
        assert_eq!(vias, ["entry", "br"], "{loop_acc}");
        let if_join = joins
            .iter()
            .find(|j| j["join"] == "if")
            .expect("if result join");
        let vias: Vec<&str> = if_join["incoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["via"].as_str().unwrap())
            .collect();
        assert_eq!(vias, ["then_end", "fallthrough"], "{if_join}");
        for incoming in if_join["incoming"].as_array().unwrap() {
            assert!(incoming["from"].is_u64(), "{incoming}");
        }
        // Every offset is a real position in the module.
        for n in document["nodes"].as_array().unwrap() {
            assert!(n["byte_offset"].as_u64().unwrap() < bytes.len() as u64);
        }
    }

    #[test]
    fn forward_slice_of_a_param_reaches_every_sink_kind() {
        let bytes = fixture();
        let document = flow(&bytes, "function=2&local=0&direction=forward").unwrap();
        assert_eq!(document["seed"]["kind"], "local");
        let sinks = kinds_of(&document, "sinks");
        for kind in ["import_call", "global_set", "store", "return", "branch"] {
            assert!(sinks.contains(&kind), "{kind} in {sinks:?}");
        }
        let edges = edge_kinds(&document);
        for kind in [
            "argument",
            "global_set",
            "address",
            "stored_value",
            "return",
            "local",
            "merge",
        ] {
            assert!(edges.contains(kind), "{kind} in {edges:?}");
        }
        let import = node(&document, "import_call")[0];
        assert_eq!(import["import"], json!({"module": "env", "name": "send"}));
    }

    #[test]
    fn memory_is_conservative_across_a_call_and_branch_values_join() {
        let bytes = fixture();
        let load = offset_of(&bytes, 4, "i32.load", 0);
        let document = flow(
            &bytes,
            &format!("function=4&offset={load}&direction=backward"),
        )
        .unwrap();
        assert!(
            !edge_kinds(&document).contains("forwarded_store"),
            "{}",
            document["edges"]
        );
        let end = offset_of(&bytes, 4, "end", 1);
        let document = flow(
            &bytes,
            &format!("function=4&offset={end}&direction=backward"),
        )
        .unwrap();
        let join = &document["joins"][0];
        assert_eq!(join["join"], "block");
        let vias: Vec<&str> = join["incoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["via"].as_str().unwrap())
            .collect();
        assert_eq!(vias, ["br_if", "fallthrough"]);
        let froms: Vec<&str> = join["incoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["from_kind"].as_str().unwrap())
            .collect();
        assert_eq!(froms, ["const", "local_get"]);
    }

    #[test]
    fn call_results_feed_br_table_and_call_indirect_selectors() {
        let bytes = fixture();
        let call = offset_of(&bytes, 3, "call", 0);
        let document = flow(
            &bytes,
            &format!("function=3&offset={call}&direction=forward"),
        )
        .unwrap();
        let edges = edge_kinds(&document);
        assert!(
            edges.contains("selector") && edges.contains("callee_index"),
            "{edges:?}"
        );
        let sinks = kinds_of(&document, "sinks");
        assert!(
            sinks.contains(&"branch") && sinks.contains(&"call_indirect"),
            "{sinks:?}"
        );
        let indirect = node(&document, "call_indirect")[0];
        assert_eq!(indirect["type"], 0);
        assert_eq!(indirect["table"], 0);
    }

    #[test]
    fn one_interprocedural_step_maps_params_and_returns_to_call_sites() {
        let bytes = fixture();
        let call = offset_of(&bytes, 3, "call", 0);
        let document = flow(
            &bytes,
            "function=2&local=0&direction=backward&interprocedural=true",
        )
        .unwrap();
        let steps = document["interprocedural"]["steps"].as_array().unwrap();
        assert!(
            steps.iter().any(|s| s["kind"] == "caller_argument"
                && s["function"] == 3
                && s["byte_offset"] == call
                && s["slot"] == 0),
            "{steps:?}"
        );
        assert_eq!(
            document["interprocedural"]["direct_callers"]["also_reachable_indirectly"],
            true
        );
        let document = flow(
            &bytes,
            "function=3&local=0&direction=forward&interprocedural=true",
        )
        .unwrap();
        let steps = document["interprocedural"]["steps"].as_array().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| s["kind"] == "callee_param" && s["function"] == 2 && s["slot"] == 0),
            "{steps:?}"
        );
        let document = flow(
            &bytes,
            &format!("function=3&offset={call}&direction=forward&interprocedural=true"),
        )
        .unwrap();
        let steps = document["interprocedural"]["steps"].as_array().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| s["kind"] == "callee_return" && s["function"] == 2),
            "{steps:?}"
        );
        let document = flow(
            &bytes,
            "function=2&local=2&direction=forward&interprocedural=true",
        )
        .unwrap();
        let steps = document["interprocedural"]["steps"].as_array().unwrap();
        assert!(
            steps.iter().any(|s| s["kind"] == "caller_result"
                && s["function"] == 3
                && s["byte_offset"] == call),
            "{steps:?}"
        );
        let plain = flow(&bytes, "function=2&local=0").unwrap();
        assert_eq!(
            plain["interprocedural"],
            json!({"requested": false, "steps": [], "direct_callers": null})
        );
    }

    #[test]
    fn caps_truncate_explicitly() {
        let bytes = fixture();
        let send = offset_of(&bytes, 2, "call", 1);
        let capped = flow(&bytes, &format!("function=2&offset={send}&max_nodes=3")).unwrap();
        assert_eq!(capped["status"], "partial");
        assert_eq!(capped["truncated"]["nodes"], true);
        assert_eq!(capped["node_count"], 3);
        assert!(
            capped["omissions"][0]
                .as_str()
                .unwrap()
                .contains("Node cap")
        );
        let shallow = flow(
            &bytes,
            &format!("function=2&offset={send}&max_depth=1&direction=backward"),
        )
        .unwrap();
        assert_eq!(shallow["truncated"]["depth"], true);
        assert!(
            node(&shallow, "local_get")
                .iter()
                .any(|n| n["role"] == "frontier"),
            "{}",
            shallow["nodes"]
        );
        assert!(
            shallow["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|n| n["depth"].as_u64().unwrap() <= 1)
        );
    }

    #[test]
    fn requests_and_modules_fail_with_named_errors() {
        let bytes = fixture();
        let send = offset_of(&bytes, 2, "call", 1);
        for (query, status) in [
            ("offset=1", 400),
            ("function=2", 400),
            ("function=2&offset=1&local=0", 400),
            ("function=2&local=0&operand=0", 400),
            ("function=2&local=0&extra=1", 400),
            ("function=2&local=0&local=1", 400),
            ("function=02&local=0", 400),
            ("function=2&local=0&direction=up", 400),
            ("function=2&local=0&max_nodes=0", 400),
            ("function=2&local=0&max_nodes=4097", 400),
            ("function=2&local=0&max_depth=257", 400),
            ("function=2&local=0&interprocedural=1", 400),
            ("function=2&local=9", 400),
            ("function=0&local=0", 404),
            ("function=9&local=0", 404),
            ("function=2&offset=0", 404),
            ("artifact_id=7&function=2&local=0", 400),
        ] {
            let error = flow(&bytes, query).unwrap_err();
            assert_eq!(error.status, status, "{query}: {}", error.message);
        }
        let error = flow(&bytes, &format!("function=2&offset={send}&operand=2")).unwrap_err();
        assert_eq!(error.status, 400, "{}", error.message);
        let block = offset_of(&bytes, 2, "block", 0);
        assert_eq!(
            flow(&bytes, &format!("function=2&offset={block}"))
                .unwrap_err()
                .status,
            400
        );
        // A body whose final end became a nop is malformed.
        let mut bad =
            wat::parse_str("(module (func (param i32) (result i32) local.get 0))").unwrap();
        let last = bad.len() - 1;
        assert_eq!(bad[last], 0x0b);
        bad[last] = 0x01;
        assert_eq!(flow(&bad, "function=0&local=0").unwrap_err().status, 422);
        let many = format!("(module (func (local {})))", "i32 ".repeat(50_001));
        let error = flow(&wat::parse_str(many).unwrap(), "function=0&local=0").unwrap_err();
        assert_eq!(error.status, 400, "{}", error.message);
        let directory = store(&bytes);
        assert_eq!(
            value_flow_query(directory.path(), "8", "function=2&local=0")
                .unwrap_err()
                .status,
            404
        );
    }

    #[test]
    fn exception_handlers_join_body_definitions() {
        let bytes = wat::parse_str(
            r#"(module (tag $e (param i32)) (import "env" "f" (func $f))
              (func (param $p i32) (result i32) (local $x i32)
                (local.set $x (i32.const 5))
                (block $h (result i32)
                  (try_table (catch $e $h)
                    (local.set $x (local.get $p))
                    (call $f))
                  (return (local.get $x)))
                (i32.add (local.get $x)))
              (func (param $p i32) (result i32) (local $x i32)
                try (result i32)
                  (local.set $x (local.get $p)) (call $f) (i32.const 1)
                catch $e
                  (drop) (local.get $x)
                end))"#,
        )
        .unwrap();
        let add = offset_of(&bytes, 1, "i32.add", 0);
        let document = flow(
            &bytes,
            &format!("function=1&offset={add}&direction=backward"),
        )
        .unwrap();
        assert_eq!(document["status"], "computed", "{}", document["omissions"]);
        let sources = kinds_of(&document, "sources");
        assert!(
            sources.contains(&"exception_value")
                && sources.contains(&"param")
                && sources.contains(&"const"),
            "{sources:?}"
        );
        let join = document["joins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|j| j["join"] == "try")
            .expect("try join");
        let vias: Vec<&str> = join["incoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["via"].as_str().unwrap())
            .collect();
        assert_eq!(vias, ["entry", "catch"], "{join}");
        let end = offset_of(&bytes, 2, "end", 1);
        let document = flow(
            &bytes,
            &format!("function=2&offset={end}&direction=backward"),
        )
        .unwrap();
        let sources = kinds_of(&document, "sources");
        assert!(
            sources.contains(&"param") && sources.contains(&"local_init"),
            "{sources:?}"
        );
    }

    /// Every instruction of every function, seeded whole and by each operand
    /// it reports, in both directions: a module that does not validate gets a
    /// document or a named error, never a panic or a 500.
    fn sweep(bytes: &[u8]) {
        let module = Module::read(bytes).unwrap();
        for position in 0..module.bodies.len() {
            let function = module.imported_functions + position as u32;
            let mut reader = module.bodies[position].get_operators_reader().unwrap();
            while !reader.eof() {
                let (_, offset) = reader.read_with_offset().unwrap();
                for direction in ["backward", "forward"] {
                    let query = format!(
                        "function={function}&offset={offset}&direction={direction}&interprocedural=true"
                    );
                    match flow(bytes, &query) {
                        Ok(document) => {
                            let count = document["seed"]["operand_count"].as_u64().unwrap_or(0);
                            for operand in 0..count {
                                if let Err(error) =
                                    flow(bytes, &format!("{query}&operand={operand}"))
                                {
                                    assert_ne!(
                                        error.status, 500,
                                        "{query}&operand={operand}: {}",
                                        error.message
                                    );
                                }
                            }
                        }
                        Err(error) => assert_ne!(error.status, 500, "{query}: {}", error.message),
                    }
                }
            }
            if let Err(error) = flow(bytes, &format!("function={function}&local=0")) {
                assert_ne!(error.status, 500, "{}", error.message);
            }
        }
    }

    fn joins_of<'a>(document: &'a Value, join: &str) -> Vec<&'a Value> {
        document["joins"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|j| j["join"] == join)
            .collect()
    }

    fn vias(join: &Value) -> Vec<&str> {
        join["incoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["via"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn paths_carrying_the_wrong_value_count_are_padded_and_named() {
        // An if without else whose arm leaves a value, and a catch whose tag
        // carries one value into a block that declares two: both do not
        // validate, and both used to index past the incoming values.
        let short_if = wat::parse_str(
            "(module (func (result i32) i32.const 1 if (result i32) i32.const 2 end))",
        )
        .unwrap();
        let end = offset_of(&short_if, 0, "end", 0);
        let document = flow(&short_if, &format!("function=0&offset={end}")).unwrap();
        assert_eq!(document["status"], "partial");
        assert!(
            document["omissions"].as_array().unwrap().iter().any(|o| o
                .as_str()
                .unwrap()
                .contains("carries 0 values where the block declares 1")),
            "{}",
            document["omissions"]
        );
        assert!(kinds_of(&document, "sources").contains(&"unknown"));
        let short_catch = wat::parse_str(
            r#"(module (tag $e (param i32))
              (func (result i32 i32)
                block $h (result i32 i32)
                  try_table (catch $e $h) nop end
                  i32.const 1 i32.const 2
                end))"#,
        )
        .unwrap();
        let end = offset_of(&short_catch, 0, "end", 1);
        let document = flow(&short_catch, &format!("function=0&offset={end}")).unwrap();
        assert!(
            document["omissions"].as_array().unwrap().iter().any(|o| o
                .as_str()
                .unwrap()
                .contains("carries 1 values where the block declares 2")),
            "{}",
            document["omissions"]
        );
        let past = wat::parse_str(
            "(module (func (param i32) (result i32) block (result i32) local.get 0 br 0 end))",
        )
        .unwrap();
        for bytes in [short_if, short_catch, past] {
            sweep(&bytes);
        }
        sweep(&fixture());
    }

    #[test]
    fn dead_code_feeds_no_slice() {
        let bytes = wat::parse_str(
            r#"(module (import "env" "send" (func $send (param i32)))
              (func (param i32) (result i32)
                local.get 0 drop
                i32.const 0 return
                local.get 0 call $send
                i32.const 1)
              (func (param i32)
                block
                  local.get 0 call $send
                  br 0
                  local.get 0 call $send
                end))"#,
        )
        .unwrap();
        let after_return = flow(&bytes, "function=1&local=0&direction=forward").unwrap();
        assert!(
            node(&after_return, "import_call").is_empty(),
            "{}",
            after_return["nodes"]
        );
        assert_eq!(
            after_return["status"], "computed",
            "{}",
            after_return["omissions"]
        );
        let after_br = flow(&bytes, "function=2&local=0&direction=forward").unwrap();
        let calls = node(&after_br, "import_call");
        assert_eq!(calls.len(), 1, "{}", after_br["nodes"]);
        assert_eq!(calls[0]["byte_offset"], offset_of(&bytes, 2, "call", 0));
        let dead = offset_of(&bytes, 2, "call", 1);
        let error = flow(&bytes, &format!("function=2&offset={dead}")).unwrap_err();
        assert_eq!(error.status, 400);
        assert!(error.message.contains("unreachable"), "{}", error.message);
    }

    fn nested_loops(depth: usize, locals: usize) -> Vec<u8> {
        let mut text = format!(
            "(module (func (param i32) (result i32) (local{})",
            " i32".repeat(locals)
        );
        text.push_str(&" loop".repeat(depth));
        for local in 1..=locals {
            text.push_str(&format!(" local.get 0 local.set {local}"));
        }
        text.push_str(&" end".repeat(depth));
        text.push_str(" local.get 1))");
        wat::parse_str(text).unwrap()
    }

    fn simulate_first(bytes: &[u8], limits: wasm_def_use::Limits, deadline: Instant) -> Simulation {
        let module = Module::read(bytes).unwrap();
        wasm_def_use::simulate_with(&module, 0, &module.bodies[0], deadline, limits).unwrap()
    }

    #[test]
    fn nested_loops_stay_inside_the_work_budget_and_the_deadline() {
        let later = Instant::now() + Duration::from_secs(60);
        // One write under 20,000 loops: the prescan is linear in the bytes.
        let deep = nested_loops(20_000, 1);
        let sim = simulate_first(&deep, wasm_def_use::Limits::default(), later);
        assert_eq!(sim.stopped_at, None, "{:?}", sim.omissions);
        assert!(sim.work < 6 * 20_000, "work {}", sim.work);
        // Every loop really writes every local: a quadratic number of joins,
        // cut at the work budget, which the loops inside one instruction check.
        let wide = nested_loops(400, 400);
        let limits = wasm_def_use::Limits {
            max_instructions: wasm_def_use::MAX_INSTRUCTIONS,
            max_work: 50_000,
        };
        let sim = simulate_first(&wide, limits, later);
        assert!(sim.stopped_at.is_some());
        assert!(sim.work <= 50_000 + 400, "work {}", sim.work);
        assert!(
            sim.omissions.iter().any(|o| o.contains("work budget")),
            "{:?}",
            sim.omissions
        );
        let prescan = wasm_def_use::Limits {
            max_instructions: wasm_def_use::MAX_INSTRUCTIONS,
            max_work: 1_000,
        };
        let sim = simulate_first(&wide, prescan, later);
        assert!(
            sim.omissions
                .iter()
                .any(|o| o.contains("while recording loop writes")),
            "{:?}",
            sim.omissions
        );
        let sim = simulate_first(&wide, wasm_def_use::Limits::default(), Instant::now());
        assert!(sim.stopped_at.is_some());
        assert!(
            sim.omissions.iter().any(|o| o.contains("deadline")),
            "{:?}",
            sim.omissions
        );
        // The default budget stops the 2,000 by 2,000 shape quickly, with a name.
        let started = Instant::now();
        let document = flow(&nested_loops(2_000, 2_000), "function=0&local=1").unwrap();
        assert_eq!(document["truncated"]["simulation"], true);
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    fn assert_fits(document: &Value) {
        let pretty = serde_json::to_string_pretty(document).unwrap().len();
        let omitted = serde_json::to_string_pretty(&content_omitted(document, None))
            .unwrap()
            .len();
        assert!(
            pretty <= 131_072 && omitted <= 131_072,
            "pretty {pretty}, omitted {omitted}"
        );
        assert!(fits_response(document));
    }

    #[test]
    fn responses_fit_the_inline_limit_in_every_form() {
        let mut text = String::from("(module (func (param i32) (result i32) (block (result i32)");
        for k in 0..1100 {
            text.push_str(&format!(" (drop (br_if 0 (i32.const {k}) (local.get 0)))"));
        }
        text.push_str(" (i32.const -1))))");
        let wide = wat::parse_str(text).unwrap();
        let end = offset_of(&wide, 0, "end", 0);
        let document = flow(&wide, &format!("function=0&offset={end}")).unwrap();
        assert_fits(&document);
        let join = &document["joins"][0];
        assert_eq!(join["incoming_count"], 1101);
        assert_eq!(join["incoming"].as_array().unwrap().len(), MAX_JOIN_ENTRIES);
        assert_eq!(document["truncated"]["joins"], true);
        // A long chain through a parameter with 64 interprocedural steps.
        let mut text = String::from("(module (func $chain (param i32) (result i32) local.get 0");
        text.push_str(&" i32.const 3 i32.add".repeat(120));
        text.push_str(") (func (param i32)");
        text.push_str(&" local.get 0 call $chain drop".repeat(80));
        text.push_str("))");
        let chain = wat::parse_str(text).unwrap();
        let ret = offset_of(&chain, 0, "end", 0);
        let document = flow(
            &chain,
            &format!(
                "function=0&offset={ret}&direction=backward&max_depth=256&interprocedural=true"
            ),
        )
        .unwrap();
        assert_eq!(
            document["truncated"]["nodes"], false,
            "{}",
            document["omissions"]
        );
        assert_eq!(
            document["interprocedural"]["steps"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_fits(&document);
        let document = flow(&chain, &format!("function=0&offset={ret}&direction=backward&max_nodes=4096&max_depth=256&interprocedural=true")).unwrap();
        assert_fits(&document);
        assert_eq!(document["truncated"]["bytes"], true);
        assert!(
            document["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o.as_str().unwrap().contains("Response budget"))
        );
        let count = document["node_count"].as_u64().unwrap() as usize;
        for edge in document["edges"].as_array().unwrap() {
            assert!(
                edge["from"].as_u64().unwrap() < count as u64
                    && edge["to"].as_u64().unwrap() < count as u64
            );
        }
    }

    #[test]
    fn joins_list_every_definition_and_memory_needs_the_same_constant_address() {
        let bytes = wat::parse_str(
            r#"(module (memory 1)
              (func (param i32) (result i32) (local i32)
                local.get 0
                if i32.const 1 local.set 1 else i32.const 2 local.set 1 end
                local.get 1)
              (func (param i32 i32) (result i32)
                (i32.store (i32.const 64) (local.get 0))
                (i32.store (i32.const 128) (local.get 1))
                (i32.load (i32.const 64)))
              (func (param i32 i32) (result i32)
                (i32.store (i32.const 64) (local.get 0))
                (i32.store (local.get 1) (local.get 1))
                (i32.load (i32.const 64)))
              (func (param i32) (result i32)
                (i32.store (i32.const 64) (local.get 0))
                (i32.load (i32.const 68)))
              (func (param i32) (result i32)
                (i32.store (i32.const 64) (local.get 0))
                (i32.load (i32.const 64))))"#,
        )
        .unwrap();
        let get = offset_of(&bytes, 0, "local.get", 1);
        let document = flow(
            &bytes,
            &format!("function=0&offset={get}&direction=backward"),
        )
        .unwrap();
        let join = joins_of(&document, "if")[0];
        assert_eq!(join["local"], 1);
        assert_eq!(vias(join), ["then_end", "fallthrough"]);
        let offsets: HashSet<u64> = join["incoming"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["from_offset"].as_u64().unwrap())
            .collect();
        assert_eq!(offsets.len(), 2, "{join}");
        assert!(
            join["incoming"]
                .as_array()
                .unwrap()
                .iter()
                .all(|i| i["from_kind"] == "local_set")
        );
        for function in [1, 2, 3] {
            let load = offset_of(&bytes, function, "i32.load", 0);
            let document = flow(
                &bytes,
                &format!("function={function}&offset={load}&direction=backward"),
            )
            .unwrap();
            assert!(
                !edge_kinds(&document).contains("forwarded_store"),
                "function {function}: {}",
                document["edges"]
            );
        }
        let load = offset_of(&bytes, 4, "i32.load", 0);
        let document = flow(
            &bytes,
            &format!("function=4&offset={load}&direction=backward"),
        )
        .unwrap();
        assert!(edge_kinds(&document).contains("forwarded_store"));
    }

    #[test]
    fn branch_operands_are_the_carried_values_then_the_selector() {
        let bytes = wat::parse_str(
            "(module (func (param i32) (result i32) (block (result i32) (drop (br_if 0 (i32.const 7) (local.get 0))) (i32.const 8))))",
        )
        .unwrap();
        let br_if = offset_of(&bytes, 0, "br_if", 0);
        let whole = flow(
            &bytes,
            &format!("function=0&offset={br_if}&direction=backward"),
        )
        .unwrap();
        assert_eq!(whole["seed"]["operand_count"], 2);
        let carried = flow(&bytes, &format!("function=0&offset={br_if}&operand=0")).unwrap();
        // The branch is the seed; the carried value's producer is an ordinary
        // node one step away, a source by the leaf rule.
        assert_eq!(carried["nodes"][0]["kind"], "branch");
        assert!(
            node(&carried, "const")
                .iter()
                .any(|n| n["role"] == "source" && n["depth"] == 1 && n["text"] == "i32.const 7"),
            "{}",
            carried["nodes"]
        );
        assert!(
            !joins_of(&carried, "block").is_empty(),
            "the carried value reaches the block join"
        );
        let condition = flow(
            &bytes,
            &format!("function=0&offset={br_if}&operand=1&direction=backward"),
        )
        .unwrap();
        assert!(node(&condition, "param").iter().any(|n| n["local"] == 0));
        assert!(edge_kinds(&condition).contains("selector"));
    }

    #[test]
    fn short_stacks_and_leftover_values_are_named() {
        let bytes = wat::parse_str("(module (func (result i32) block (result i32) br 0 end) (func i32.const 1 i32.const 2 drop))").unwrap();
        let end = offset_of(&bytes, 0, "end", 1);
        let document = flow(
            &bytes,
            &format!("function=0&offset={end}&direction=backward"),
        )
        .unwrap();
        assert!(
            document["omissions"].as_array().unwrap().iter().any(|o| o
                .as_str()
                .unwrap()
                .contains("carries 1 values but the operand stack holds 0")),
            "{}",
            document["omissions"]
        );
        let unknown = node(&document, "unknown");
        assert_eq!(unknown[0]["text"], "unknown (no operand was on the stack)");
        let document = flow(
            &bytes,
            "function=1&offset="
                .to_owned()
                .as_str()
                .to_owned()
                .replace(
                    "offset=",
                    &format!("offset={}", offset_of(&bytes, 1, "drop", 0)),
                )
                .as_str(),
        )
        .unwrap();
        assert!(
            document["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o.as_str().unwrap().contains("left on the operand stack")),
            "{}",
            document["omissions"]
        );
    }

    #[test]
    fn atomic_results_follow_only_their_address() {
        let bytes = wat::parse_str(
            "(module (memory 1 1 shared) (func (param i32 i32) (result i32) (i32.atomic.rmw.add (local.get 0) (local.get 1))))",
        )
        .unwrap();
        let end = offset_of(&bytes, 0, "end", 0);
        let document = flow(
            &bytes,
            &format!("function=0&offset={end}&direction=backward"),
        )
        .unwrap();
        let params: Vec<u64> = node(&document, "param")
            .iter()
            .map(|n| n["local"].as_u64().unwrap())
            .collect();
        assert_eq!(params, [0], "{}", document["nodes"]);
        let rmw = offset_of(&bytes, 0, "i32.atomic.rmw.add", 0);
        let seeded = flow(
            &bytes,
            &format!("function=0&offset={rmw}&direction=backward"),
        )
        .unwrap();
        assert_eq!(
            node(&seeded, "param").len(),
            2,
            "the seed's own operands are all listed"
        );
    }

    #[test]
    fn handlers_read_as_instructions_and_stops_are_resource_limits() {
        let bytes = wat::parse_str(
            r#"(module (tag $e (param i32))
              (func (result i32)
                (block $h (result i32)
                  (try_table (catch $e $h) nop)
                  (i32.const 0))))"#,
        )
        .unwrap();
        let end = offset_of(&bytes, 0, "end", 1);
        let document = flow(
            &bytes,
            &format!("function=0&offset={end}&direction=backward"),
        )
        .unwrap();
        let exception = node(&document, "exception_value")[0];
        assert_eq!(
            exception["text"],
            "exception values of tag 0 at try_table (catch 0 0)"
        );
        let switching = wat::parse_str(
            "(module (type $f (func)) (type $c (cont $f)) (func $g) (elem declare func $g)
              (func (param i32) (result i32) local.get 0 drop ref.func $g cont.new $c drop local.get 0))",
        )
        .unwrap();
        let stop = offset_of(&switching, 1, "cont_new", 0);
        let error = flow(&switching, &format!("function=1&offset={stop}")).unwrap_err();
        assert_eq!(error.status, 400);
        assert!(
            error.message.contains("stopped at byte"),
            "{}",
            error.message
        );
    }

    fn artifact_of(bytes: &[u8]) -> wasm_graph::Artifact {
        wasm_graph::Artifact {
            bytes: bytes.to_vec(),
            artifact_id: json!("7"),
            sha256: json!("0".repeat(64)),
        }
    }

    fn limited(bytes: &[u8], query: &str, limits: wasm_def_use::Limits) -> Result<Value> {
        value_flow_with(&artifact_of(bytes), &parse_query(query).unwrap(), limits)
    }

    fn source_kinds(document: &Value) -> Vec<String> {
        let mut kinds: Vec<String> = kinds_of(document, "sources")
            .into_iter()
            .map(str::to_owned)
            .collect();
        kinds.sort();
        kinds
    }

    #[test]
    fn producers_of_nodeless_seeds_follow_the_leaf_and_address_rules() {
        let bytes = wat::parse_str(
            r#"(module (import "env" "imp" (func $imp (param i32) (result i32)))
              (memory 1 1 shared)
              (func (param i32 i32) (result i32)
                block (result i32) local.get 1 call $imp end)
              (func (param i32 i32) (result i32)
                block (result i32) local.get 1 call $imp local.get 0 br_if 0 end)
              (func (param i32 i32) (result i32)
                block (result i32) (i32.atomic.rmw.add (local.get 0) (local.get 1)) end))"#,
        )
        .unwrap();
        let block_end = offset_of(&bytes, 1, "end", 0);
        let function_end = offset_of(&bytes, 1, "end", 1);
        for offset in [block_end, function_end] {
            let document = flow(
                &bytes,
                &format!("function=1&offset={offset}&operand=0&direction=backward"),
            )
            .unwrap();
            assert_eq!(
                source_kinds(&document),
                ["import_call"],
                "end at {offset}: {}",
                document["nodes"]
            );
        }
        let br_if = offset_of(&bytes, 2, "br_if", 0);
        let carried = flow(
            &bytes,
            &format!("function=2&offset={br_if}&operand=0&direction=backward"),
        )
        .unwrap();
        assert_eq!(
            source_kinds(&carried),
            ["import_call"],
            "{}",
            carried["nodes"]
        );
        let atomic_end = offset_of(&bytes, 3, "end", 0);
        let atomic = flow(
            &bytes,
            &format!("function=3&offset={atomic_end}&direction=backward"),
        )
        .unwrap();
        assert_eq!(
            source_kinds(&atomic),
            ["atomic", "param"],
            "{}",
            atomic["nodes"]
        );
        assert!(
            node(&atomic, "param").iter().all(|n| n["local"] == 0),
            "only the address feeds the old value"
        );
    }

    #[test]
    fn handlers_of_bodies_that_end_in_a_branch_get_exception_values() {
        let bytes = wat::parse_str(
            r#"(module (tag $e (param i32))
              (import "env" "f" (func $f (param i32) (result i32)))
              (import "env" "send" (func $send (param i32)))
              (func (param i32) (result i32)
                block $done (result i32)
                  block $h (result i32)
                    try_table (catch $e $h) local.get 0 call $f br $done end
                    unreachable
                  end
                  call $send
                  i32.const -1
                end))"#,
        )
        .unwrap();
        let send = offset_of(&bytes, 2, "call", 1);
        let document = flow(
            &bytes,
            &format!("function=2&offset={send}&operand=0&direction=backward"),
        )
        .unwrap();
        assert_eq!(document["status"], "computed", "{}", document["omissions"]);
        assert_eq!(
            source_kinds(&document),
            ["exception_value"],
            "{}",
            document["nodes"]
        );
    }

    #[test]
    fn carried_values_count_against_the_work_budget() {
        let mut text = format!(
            "(module (type $big (func (result{}))) (func (param i32) (result i32) block (type $big)",
            " i32".repeat(1000)
        );
        text.push_str(&" i32.const 1".repeat(1000));
        text.push_str(&" local.get 0 br_if 0".repeat(5000));
        text.push_str(" end");
        text.push_str(&" drop".repeat(999));
        text.push_str("))");
        let bytes = wat::parse_str(text).unwrap();
        let started = Instant::now();
        let document = flow(&bytes, "function=0&local=0").unwrap();
        assert_eq!(
            document["truncated"]["simulation"], true,
            "{}",
            document["omissions"]
        );
        assert!(
            document["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o.as_str().unwrap().contains("work budget")),
            "{}",
            document["omissions"]
        );
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    #[test]
    fn a_node_can_be_both_a_source_and_a_sink() {
        let bytes = wat::parse_str(
            r#"(module (import "env" "imp" (func $imp (param i32) (result i32)))
              (memory 1)
              (func (param i32) (result i32) (local i32)
                loop local.get 1 call $imp local.set 1 local.get 0 br_if 0 end
                local.get 1)
              (func (param i32) (result i32)
                loop local.get 0 i32.load local.set 0 local.get 0 br_if 0 end
                local.get 0))"#,
        )
        .unwrap();
        for (function, kind) in [(1, "import_call"), (2, "load")] {
            let get = offset_of(&bytes, function, "local.get", 0);
            for direction in ["both", "forward"] {
                let document = flow(
                    &bytes,
                    &format!("function={function}&offset={get}&direction={direction}"),
                )
                .unwrap();
                let ends: Vec<&Value> = node(&document, kind);
                assert_eq!(ends.len(), 1, "{direction}: {}", document["nodes"]);
                assert_eq!(
                    ends[0]["sink"], true,
                    "function {function} {direction}: the {kind} consumes the value"
                );
                assert!(
                    kinds_of(&document, "sinks").contains(&kind),
                    "{direction}: {}",
                    document["sinks"]
                );
                if direction == "both" {
                    assert_eq!(
                        ends[0]["source"], true,
                        "function {function}: the {kind} also produces it"
                    );
                    assert!(kinds_of(&document, "sources").contains(&kind));
                }
            }
        }
    }

    #[test]
    fn loops_open_at_a_stop_and_capped_bodies_say_so() {
        let mut text = String::from(
            "(module (func (param i32) (result i32) (local i32) loop local.get 1 drop",
        );
        text.push_str(&" nop".repeat(40));
        text.push_str(" local.get 0 local.set 1 local.get 0 br_if 0 end i32.const 0))");
        let bytes = wat::parse_str(text).unwrap();
        let limits = wasm_def_use::Limits {
            max_instructions: 20,
            max_work: wasm_def_use::MAX_WORK,
        };
        let get = offset_of(&bytes, 0, "local.get", 0);
        let document = limited(
            &bytes,
            &format!("function=0&offset={get}&direction=backward"),
            limits,
        )
        .unwrap();
        assert_eq!(document["truncated"]["simulation"], true);
        let join = joins_of(&document, "loop")[0];
        assert_eq!(join["incomplete"], true, "{join}");
        assert!(
            document["omissions"].as_array().unwrap().iter().any(|o| o
                .as_str()
                .unwrap()
                .contains("still open where simulation stopped")),
            "{}",
            document["omissions"]
        );
        assert!(
            document["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o.as_str().unwrap().contains("instruction cap of 20")),
            "{}",
            document["omissions"]
        );
        let late = offset_of(&bytes, 0, "local.set", 0);
        let error = limited(&bytes, &format!("function=0&offset={late}"), limits).unwrap_err();
        assert_eq!(
            (error.status, error.reason.code),
            (400, Code::ResourceLimit),
            "{}",
            error.message
        );
        let complete = flow(
            &bytes,
            &format!("function=0&offset={get}&direction=backward"),
        )
        .unwrap();
        assert!(joins_of(&complete, "loop")[0].get("incomplete").is_none());
    }

    #[test]
    fn an_undecodable_body_elsewhere_only_narrows_the_call_site_scan() {
        let mut bytes = wat::parse_str(
            "(module (func $callee (param i32) (result i32) local.get 0) (func (param i32) (result i32) local.get 0 call $callee) (func nop nop nop))",
        )
        .unwrap();
        let module = Module::read(&bytes).unwrap();
        let broken = module.bodies[2].range();
        drop(module);
        let at = (broken.start..broken.end)
            .find(|at| bytes[*at] == 0x01)
            .unwrap();
        bytes[at] = 0xff;
        let document = flow(
            &bytes,
            "function=0&local=0&direction=backward&interprocedural=true",
        )
        .unwrap();
        assert_eq!(
            document["interprocedural"]["direct_callers"]["scan_complete"],
            false
        );
        assert!(
            document["interprocedural"]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["kind"] == "caller_argument" && s["function"] == 1)
        );
        assert!(
            document["omissions"].as_array().unwrap().iter().any(|o| o
                .as_str()
                .unwrap()
                .contains("could not decode 1 function bodies (first: 2)")),
            "{}",
            document["omissions"]
        );
    }

    #[test]
    fn dead_loops_get_no_header_joins() {
        let bytes = wat::parse_str(
            "(module (func (param i32) (result i32) (local i32) i32.const 0 return loop local.get 0 local.set 1 br 0 end local.get 1))",
        )
        .unwrap();
        let module = Module::read(&bytes).unwrap();
        let sim = wasm_def_use::simulate(
            &module,
            0,
            &module.bodies[0],
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert!(
            sim.nodes.iter().all(|n| n.kind != NodeKind::Phi),
            "a loop no path reaches has no joins"
        );
    }

    /// Every edge, join and role of a document refers to the nodes it names:
    /// kinds and offsets agree, as they must after the byte cut renumbers.
    fn assert_consistent(document: &Value) {
        let nodes = document["nodes"].as_array().unwrap();
        let target = |kind: &str| -> &[&str] {
            match kind {
                "local" => &["local_get"],
                "merge" => &["phi"],
                "local_set" => &["local_set", "local_tee"],
                "argument" => &["call", "import_call", "call_indirect", "call_ref", "throw"],
                "return" => &["return"],
                "address" => &["load", "store", "atomic"],
                "stored_value" => &["store", "atomic"],
                "operand" => &[
                    "operation",
                    "select",
                    "load",
                    "memory",
                    "table",
                    "local_get",
                ],
                _ => &[],
            }
        };
        for (id, n) in nodes.iter().enumerate() {
            assert_eq!(n["id"], id);
        }
        for edge in document["edges"].as_array().unwrap() {
            let (from, to) = (
                &nodes[edge["from"].as_u64().unwrap() as usize],
                &nodes[edge["to"].as_u64().unwrap() as usize],
            );
            let allowed = target(edge["kind"].as_str().unwrap());
            if !allowed.is_empty() {
                assert!(
                    allowed.contains(&to["kind"].as_str().unwrap()),
                    "{edge} ends at {to}"
                );
            }
            if edge["kind"] != "merge" {
                assert!(
                    from["byte_offset"].as_u64() <= to["byte_offset"].as_u64(),
                    "{edge}: {from} after {to}"
                );
            }
        }
        for join in document["joins"].as_array().unwrap() {
            let n = &nodes[join["node"].as_u64().unwrap() as usize];
            assert_eq!(
                (n["kind"].as_str(), &n["byte_offset"]),
                (Some("phi"), &join["byte_offset"])
            );
            for incoming in join["incoming"].as_array().unwrap() {
                if let Some(from) = incoming["from"].as_u64() {
                    let f = &nodes[from as usize];
                    assert_eq!(
                        (&f["kind"], &f["byte_offset"]),
                        (&incoming["from_kind"], &incoming["from_offset"]),
                        "{incoming}"
                    );
                }
            }
        }
        for id in document["sources"].as_array().unwrap() {
            assert_eq!(nodes[id.as_u64().unwrap() as usize]["source"], true);
        }
        for id in document["sinks"].as_array().unwrap() {
            assert_eq!(nodes[id.as_u64().unwrap() as usize]["sink"], true);
        }
    }

    #[test]
    fn a_cut_document_still_names_its_own_nodes() {
        // Each level adds a load from a constant address: the load and its
        // address are both sources, kept by the cut far from the seed, with
        // the edge between them, so their ids must be renumbered.
        let mut text =
            String::from("(module (memory 1) (func $chain (param i32) (result i32) local.get 0");
        text.push_str(&" i32.const 3 i32.load i32.add".repeat(1500));
        text.push_str("))");
        let chain = wat::parse_str(text).unwrap();
        let ret = offset_of(&chain, 0, "end", 0);
        let document = flow(
            &chain,
            &format!("function=0&offset={ret}&direction=backward&max_nodes=4096&max_depth=256"),
        )
        .unwrap();
        assert_eq!(document["truncated"]["bytes"], true);
        assert_consistent(&document);
        let address_edges = document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "address")
            .count();
        assert!(address_edges > 20, "{address_edges} address edges kept");

        let fixture = fixture();
        let send = offset_of(&fixture, 2, "call", 1);
        assert_consistent(&flow(&fixture, &format!("function=2&offset={send}")).unwrap());
    }

    #[test]
    fn forward_operand_seeds_list_their_producer() {
        let bytes = wat::parse_str(
            r#"(module (import "env" "s" (func $s (param i32)))
              (func (param i32) (result i32) (local i32)
                local.get 0 local.tee 1 call $s local.get 1 call $s local.get 1))"#,
        )
        .unwrap();
        let call = offset_of(&bytes, 1, "call", 0);
        let document = flow(
            &bytes,
            &format!("function=1&offset={call}&operand=0&direction=forward"),
        )
        .unwrap();
        let tee = node(&document, "local_tee");
        assert_eq!(tee.len(), 1, "{}", document["nodes"]);
        let tee_id = tee[0]["id"].clone();
        let seed = document["seed"]["nodes"][0].clone();
        assert!(
            document["edges"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["from"] == tee_id && e["to"] == seed && e["kind"] == "argument"),
            "{}",
            document["edges"]
        );
        assert_consistent(&document);
    }

    #[test]
    fn a_fence_ends_store_to_load_forwarding() {
        let bytes = wat::parse_str(
            "(module (memory 1 1 shared)
              (func (param i32) (result i32) (i32.store (i32.const 64) (local.get 0)) atomic.fence (i32.load (i32.const 64)))
              (func (param i32) (result i32) (i32.store (i32.const 64) (local.get 0)) (i32.load (i32.const 64))))",
        )
        .unwrap();
        for (function, forwarded) in [(0, false), (1, true)] {
            let load = offset_of(&bytes, function, "i32.load", 0);
            let document = flow(
                &bytes,
                &format!("function={function}&offset={load}&direction=backward"),
            )
            .unwrap();
            assert_eq!(
                edge_kinds(&document).contains("forwarded_store"),
                forwarded,
                "function {function}: {}",
                document["edges"]
            );
        }
    }

    fn results_type(count: usize) -> String {
        format!("(type $r (func (result{})))", " i32".repeat(count))
    }

    fn simulate_limited(bytes: &[u8], function: u32, max_work: u64) -> Simulation {
        let module = Module::read(bytes).unwrap();
        let body = &module.bodies[(function - module.imported_functions) as usize];
        let limits = wasm_def_use::Limits {
            max_instructions: wasm_def_use::MAX_INSTRUCTIONS,
            max_work,
        };
        wasm_def_use::simulate_with(
            &module,
            function,
            body,
            Instant::now() + Duration::from_secs(60),
            limits,
        )
        .unwrap()
    }

    /// The stop is named and nothing retained outgrows the budget: a fan-out
    /// that kept building after the budget ran out allocates per target.
    fn assert_bounded(sim: &Simulation, max_work: u64, slack: u64) {
        assert!(sim.stopped_at.is_some(), "{:?}", sim.omissions);
        assert!(
            sim.omissions.iter().any(|o| o.contains("work budget")),
            "{:?}",
            sim.omissions
        );
        assert!(
            sim.work <= max_work + slack,
            "work {} past {max_work}",
            sim.work
        );
        assert!(
            (sim.nodes.len() + sim.edges.len()) as u64 <= max_work + slack,
            "{} nodes, {} edges",
            sim.nodes.len(),
            sim.edges.len()
        );
        assert!(
            sim.stored <= max_work + slack,
            "{} carried values stored on paths",
            sim.stored
        );
    }

    #[test]
    fn br_table_fan_out_stops_inside_the_budget() {
        let (depth, results) = (2_000, 50);
        let mut text = format!(
            "(module {} (func (param i32) (result i32)",
            results_type(results)
        );
        text.push_str(&" block (type $r)".repeat(depth));
        text.push_str(&" i32.const 1".repeat(results));
        let targets: Vec<String> = (0..depth).map(|d| d.to_string()).collect();
        text.push_str(&format!(" local.get 0 br_table {} 0", targets.join(" ")));
        text.push_str(&" end".repeat(depth));
        text.push_str(&" drop".repeat(results - 1));
        text.push_str("))");
        let bytes = wat::parse_str(text).unwrap();
        let sim = simulate_limited(&bytes, 0, 20_000);
        assert_bounded(&sim, 20_000, results as u64 + 1);
    }

    #[test]
    fn try_table_clause_fan_out_stops_inside_the_budget() {
        let (clauses, values) = (3_000, 50);
        let mut text = format!(
            "(module {} (tag $e (param{})) (import \"env\" \"f\" (func $f)) (func (result i32) block $h (type $r) try_table",
            results_type(values),
            " i32".repeat(values)
        );
        text.push_str(&" (catch $e $h)".repeat(clauses));
        text.push_str(" call $f end unreachable end");
        text.push_str(&" drop".repeat(values - 1));
        text.push_str("))");
        let bytes = wat::parse_str(text).unwrap();
        let sim = simulate_limited(&bytes, 1, 20_000);
        assert_bounded(&sim, 20_000, values as u64 + 1);
    }

    #[test]
    fn every_carried_copy_and_merge_slot_is_charged() {
        // N br_if carry A values each to one block: per branch the carried
        // read, its record, the branch's own copy and the stored path, and A
        // merge slots per incoming path at the end. Dropping any one of these
        // charges brings the total under the sum.
        let (results, branches) = (100u64, 50u64);
        let mut text = format!(
            "(module {} (func (param i32) (result i32) block (type $r)",
            results_type(results as usize)
        );
        text.push_str(&" i32.const 1".repeat(results as usize));
        text.push_str(&" local.get 0 br_if 0".repeat(branches as usize));
        text.push_str(" end");
        text.push_str(&" drop".repeat(results as usize - 1));
        text.push_str("))");
        let bytes = wat::parse_str(text).unwrap();
        let sim = simulate_limited(&bytes, 0, wasm_def_use::MAX_WORK);
        assert_eq!(sim.stopped_at, None);
        let charged = branches * (4 * results) + results * (branches + 1);
        assert!(
            sim.work >= charged,
            "work {} under the {charged} the copies and merge slots cost",
            sim.work
        );
    }

    #[test]
    fn handler_text_is_capped_and_the_seed_survives_the_cut() {
        let mut text = String::from(
            "(module (tag $e (param i32)) (import \"env\" \"f\" (func $f)) (func (result i32) block $h (result i32) try_table",
        );
        text.push_str(&" (catch $e $h)".repeat(10_000));
        text.push_str(" call $f end unreachable end))");
        let bytes = wat::parse_str(text).unwrap();
        let try_table = offset_of(&bytes, 1, "try_table", 0);
        let document = flow(&bytes, &format!("function=1&offset={try_table}")).unwrap();
        assert!(
            document["node_count"].as_u64().unwrap() >= 1,
            "{}",
            document["omissions"]
        );
        assert!(!document["seed"]["nodes"].as_array().unwrap().is_empty());
        for n in document["nodes"].as_array().unwrap() {
            assert!(
                n["text"].as_str().unwrap().len() <= MAX_TEXT_BYTES + 3,
                "{}",
                n["text"]
            );
        }
        let handler = node(&document, "exception_value")[0]["text"]
            .as_str()
            .unwrap();
        assert!(
            handler.contains("try_table (catch 0 0)") && handler.ends_with("... 10000 clauses"),
            "{handler}"
        );
        // Eight long clauses alone pass the cap: deep labels need no count.
        let mut text =
            String::from("(module (import \"env\" \"f\" (func $f)) (func (result exnref)");
        text.push_str(&" block (result exnref)".repeat(10_000));
        text.push_str(" try_table");
        text.push_str(&" (catch_all_ref 9999)".repeat(8));
        text.push_str(" call $f end unreachable");
        text.push_str(&" end".repeat(10_000));
        text.push_str("))");
        let deep = wat::parse_str(text).unwrap();
        let try_table = offset_of(&deep, 1, "try_table", 0);
        let document = flow(&deep, &format!("function=1&offset={try_table}")).unwrap();
        for n in document["nodes"].as_array().unwrap() {
            assert!(
                n["text"].as_str().unwrap().len() <= MAX_TEXT_BYTES + 3,
                "{}",
                n["text"]
            );
        }
    }

    #[test]
    fn a_handler_seed_follows_every_catch_clause() {
        let bytes = wat::parse_str(
            r#"(module (tag $a (param i32)) (tag $b (param i32))
              (import "env" "sa" (func $sa (param i32))) (import "env" "sb" (func $sb (param i32))) (import "env" "f" (func $f))
              (func (result i32)
                (block $outer (result i32)
                  (block $inner (result i32)
                    (try_table (catch $a $inner) (catch $b $outer) (call $f))
                    (return (i32.const 0)))
                  (call $sa)
                  (return (i32.const 1)))
                (call $sb)
                (i32.const 2)))"#,
        )
        .unwrap();
        let try_table = offset_of(&bytes, 3, "try_table", 0);
        let document = flow(
            &bytes,
            &format!("function=3&offset={try_table}&direction=forward"),
        )
        .unwrap();
        let mut reached: Vec<u64> = node(&document, "import_call")
            .iter()
            .filter(|n| n["sink"] == true)
            .map(|n| n["function"].as_u64().unwrap())
            .collect();
        reached.sort_unstable();
        assert_eq!(
            reached,
            [0, 1],
            "both clauses' values are followed: {}",
            document["nodes"]
        );
        assert_eq!(document["seed"]["nodes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_handler_seed_cut_off_by_the_stop_is_a_resource_limit() {
        let mut text = String::from(
            "(module (tag $e (param i32)) (func (result i32) block $h (result i32) try_table (catch $e $h)",
        );
        text.push_str(&" nop".repeat(50));
        text.push_str(" end i32.const 0 end))");
        let bytes = wat::parse_str(text).unwrap();
        let try_table = offset_of(&bytes, 0, "try_table", 0);
        let limits = wasm_def_use::Limits {
            max_instructions: 20,
            max_work: wasm_def_use::MAX_WORK,
        };
        let error = limited(&bytes, &format!("function=0&offset={try_table}"), limits).unwrap_err();
        assert_eq!(
            (error.status, error.reason.code),
            (400, Code::ResourceLimit),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("inside the handler"),
            "{}",
            error.message
        );
        let complete = flow(&bytes, &format!("function=0&offset={try_table}")).unwrap();
        assert!(!node(&complete, "exception_value").is_empty());
    }

    #[test]
    fn long_float_constants_keep_their_value_under_the_text_cap() {
        let bytes = wat::parse_str(
            "(module (func (result f64) (f64.add (f64.const -2.2250738585072014e-308) (f64.const 1.5))) (func (result f32) (f32.const 1e-40)))",
        )
        .unwrap();
        let end = offset_of(&bytes, 0, "end", 0);
        let document = flow(
            &bytes,
            &format!("function=0&offset={end}&direction=backward"),
        )
        .unwrap();
        let texts: Vec<&str> = node(&document, "const")
            .iter()
            .map(|n| n["text"].as_str().unwrap())
            .collect();
        assert!(
            texts.contains(&"f64.const -2.2250738585072014e-308"),
            "{texts:?}"
        );
        assert!(texts.contains(&"f64.const 1.5"), "{texts:?}");
        let end = offset_of(&bytes, 1, "end", 0);
        let document = flow(
            &bytes,
            &format!("function=1&offset={end}&direction=backward"),
        )
        .unwrap();
        assert_eq!(node(&document, "const")[0]["text"], "f32.const 1e-40");
    }

    #[test]
    fn a_prescan_stop_does_not_claim_a_local_is_unused() {
        let bytes = nested_loops(400, 400);
        let limits = wasm_def_use::Limits {
            max_instructions: wasm_def_use::MAX_INSTRUCTIONS,
            max_work: 1_000,
        };
        let document = limited(&bytes, "function=0&local=1", limits).unwrap();
        let omissions = document["omissions"].to_string();
        assert!(!omissions.contains("never read or written"), "{omissions}");
        assert!(omissions.contains("was not traced"), "{omissions}");
    }
}
