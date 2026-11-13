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
const EXPRESSION_DEPTH: u32 = 3;
const MAX_STEPS: usize = 64;
/// Call sites recorded per callee scan; past it the list is marked partial.
const MAX_CALL_SITES: usize = 256;
/// Web engines reject a body above this size, so a longer one cannot have run.
const MAX_BODY_BYTES: usize = 7_654_321;
const DEADLINE: Duration = Duration::from_secs(4);
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

struct Included {
    node: u32,
    role: Role,
    backward: bool,
    forward: bool,
    depth: u32,
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
    fn include(&mut self, node: u32, role: Role, depth: u32, backward: bool) -> Option<u32> {
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
            role,
            backward,
            forward: !backward,
            depth,
        });
        self.id_of.insert(node, id);
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

    fn set_role(&mut self, node: u32, role: Role) {
        if let Some(id) = self.id_of.get(&node)
            && self.included[*id as usize].role != Role::Seed
        {
            self.included[*id as usize].role = role;
        }
    }

    /// Walks producers from `starts`, each an edge into an already included
    /// node or a node to expand from depth zero.
    fn backward(&mut self, expand: &[u32], edges: &[u32]) {
        let mut queue: VecDeque<(u32, u32)> = VecDeque::new();
        let mut expanded: HashSet<u32> = HashSet::new();
        for node in expand {
            queue.push_back((*node, 0));
        }
        let mut pending: Vec<(u32, u32)> = edges.iter().map(|edge| (*edge, 0)).collect();
        let mut steps = 0u32;
        loop {
            for (edge, depth) in pending.drain(..) {
                let from = self.sim.edges[edge as usize].from;
                if self
                    .include(from, Role::Interior, depth + 1, true)
                    .is_none()
                {
                    continue;
                }
                self.keep_edge(edge);
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
            let seed = self
                .id_of
                .get(&node)
                .is_some_and(|id| self.included[*id as usize].role == Role::Seed);
            if !seed {
                if backward_leaf(kind) {
                    self.set_role(node, Role::Source);
                    continue;
                }
                if addressed_source(kind) {
                    self.set_role(node, Role::Source);
                }
            }
            if depth >= self.max_depth {
                if !self.adjacency.inputs(node).is_empty() {
                    self.truncated.depth = true;
                    if !seed && !addressed_source(kind) {
                        self.set_role(node, Role::Frontier);
                    }
                }
                continue;
            }
            for edge in self.adjacency.inputs(node).to_vec() {
                pending.push((edge, depth));
            }
        }
    }

    /// Walks uses from `starts`, values whose consumers are followed.
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
                    let seed = self
                        .id_of
                        .get(&value.node)
                        .is_some_and(|id| self.included[*id as usize].role == Role::Seed);
                    if !seed {
                        self.set_role(value.node, Role::Frontier);
                    }
                }
                continue;
            }
            for edge in uses {
                let target = self.sim.edges[edge as usize];
                let node = &self.sim.nodes[target.to as usize];
                let continues = forward_continues(node.kind, target.kind);
                let known = self.id_of.contains_key(&target.to);
                let role = if continues {
                    Role::Interior
                } else {
                    Role::Sink
                };
                if self.include(target.to, role, depth + 1, false).is_none() {
                    continue;
                }
                self.keep_edge(edge);
                if !continues {
                    if known {
                        let id = self.id_of[&target.to] as usize;
                        if self.included[id].role == Role::Interior {
                            self.included[id].role = Role::Sink;
                        }
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
            let operands = wasm_graph::operands(&op);
            let mut text = wasm::mnemonic(&op);
            if !operands.is_empty() {
                text.push(' ');
                text.push_str(&operands);
            }
            texts.insert(index, text);
        }
        index += 1;
    }
    Ok(texts)
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
            NodeKind::Unknown => "unknown (empty stack in unreachable code)".to_owned(),
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

/// Every direct call site of `callee` in the module, bounded by the deadline
/// and a site cap. Returns the sites and whether the scan finished.
fn call_sites(
    module: &Module<'_>,
    callee: u32,
    deadline: Instant,
) -> Result<(Vec<(u32, u32)>, bool, bool)> {
    let mut sites = Vec::new();
    let mut referenced = false;
    let mut steps = 0u64;
    for (position, body) in module.bodies.iter().enumerate() {
        let caller = module.imported_functions + position as u32;
        let mut reader = body.get_operators_reader().map_err(wasm_def_use::bad)?;
        while !reader.eof() {
            steps += 1;
            if steps & 4095 == 0 && Instant::now() > deadline {
                return Ok((sites, false, referenced));
            }
            let (op, offset) = reader.read_with_offset().map_err(wasm_def_use::bad)?;
            match op {
                Operator::Call { function_index } | Operator::ReturnCall { function_index }
                    if function_index == callee =>
                {
                    if sites.len() >= MAX_CALL_SITES {
                        return Ok((sites, false, referenced));
                    }
                    sites.push((caller, offset as u32));
                }
                Operator::RefFunc { function_index } if function_index == callee => {
                    referenced = true
                }
                _ => {}
            }
        }
    }
    Ok((sites, true, referenced))
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
    let sim = wasm_def_use::simulate(&module, function, body, deadline)?;
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
    let (seed_offset, seed_operand, seed_local) = match request.seed {
        Seed::Instruction { offset, operand } => {
            let Some(instruction) = sim.instruction_at(offset) else {
                if let Some(stopped) = sim.stopped_at
                    && offset >= stopped
                    && (offset as usize) < range.end
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
                        slicer.include(node, Role::Seed, 0, true);
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
                    if starts.is_empty() {
                        slicer.include(value.node, Role::Seed, 0, true);
                        seed_nodes.push(value.node);
                    }
                    seed_values.push(value);
                    if request.direction.backward() {
                        let expand = if starts.is_empty() {
                            vec![value.node]
                        } else {
                            Vec::new()
                        };
                        slicer.backward(&expand, &starts);
                    }
                    if request.direction.forward() {
                        slicer.forward(&[(value, 1)]);
                    }
                }
                None => {
                    if node == NONE && inputs.is_empty() {
                        return Err(Error::bad(format!(
                            "The instruction at byte {offset} neither produces nor consumes a value"
                        )));
                    }
                    if node != NONE {
                        slicer.include(node, Role::Seed, 0, true);
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
                    } else {
                        for value in &inputs {
                            slicer.include(value.node, Role::Seed, 0, true);
                            seed_nodes.push(value.node);
                            seed_values.push(*value);
                        }
                        if request.direction.backward() {
                            let expand: Vec<u32> = inputs.iter().map(|value| value.node).collect();
                            slicer.backward(&expand, &[]);
                        }
                        if request.direction.forward() {
                            let starts: Vec<(Def, u32)> =
                                inputs.iter().map(|value| (*value, 0)).collect();
                            slicer.forward(&starts);
                        }
                    }
                }
            }
            (Some(offset), operand, None)
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
                omissions.push(format!(
                    "Local {local} is never read or written in the simulated instructions."
                ));
            }
            for def in &defs {
                if slicer.include(*def, Role::Seed, 0, true).is_some() {
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
            (None, None, Some(local))
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
    let mut nodes = Vec::with_capacity(slicer.included.len());
    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    for (id, entry) in slicer.included.iter().enumerate() {
        let n = &sim.nodes[entry.node as usize];
        let mut object = Map::new();
        object.insert("id".into(), json!(id));
        object.insert("kind".into(), json!(n.kind.name()));
        object.insert("byte_offset".into(), json!(n.offset));
        object.insert("role".into(), json!(entry.role.name()));
        object.insert(
            "direction".into(),
            json!(match (entry.role, entry.backward, entry.forward) {
                (Role::Seed, _, _) => "seed",
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
        object.insert("text".into(), json!(texts.text(entry.node)));
        if n.results > 0 && !matches!(n.kind, NodeKind::Return | NodeKind::LocalSet) {
            object.insert(
                "expression".into(),
                json!(texts.bounded_expression(entry.node)),
            );
        }
        match entry.role {
            Role::Source => sources.push(id),
            Role::Sink => sinks.push(id),
            _ => {}
        }
        nodes.push(Value::Object(object));
    }
    let edge_object = |edge: &wasm_def_use::Edge, from: Value, to: Value| {
        let mut object = Map::new();
        object.insert("from".into(), from);
        object.insert("to".into(), to);
        object.insert("kind".into(), json!(edge.kind.name()));
        object.insert("operand".into(), json!(edge.operand));
        object.insert("result".into(), json!(edge.result));
        if let Some(via) = edge.via.name() {
            object.insert("via".into(), json!(via));
            object.insert("via_offset".into(), json!(edge.via_offset));
        }
        Value::Object(object)
    };
    let mut edges = Vec::with_capacity(slicer.edges.len());
    for edge in &slicer.edges {
        let e = &sim.edges[*edge as usize];
        let (Some(from), Some(to)) = (slicer.id_of.get(&e.from), slicer.id_of.get(&e.to)) else {
            continue;
        };
        edges.push(edge_object(e, json!(from), json!(to)));
    }
    // Every join in the slice lists every incoming edge, in the slice or not.
    let mut joins = Vec::new();
    let mut join_entries = 0usize;
    for (id, entry) in slicer.included.iter().enumerate() {
        let n = &sim.nodes[entry.node as usize];
        if n.kind != NodeKind::Phi {
            continue;
        }
        let mut incoming = Vec::new();
        for edge in slicer.adjacency.inputs(entry.node) {
            if join_entries >= slicer.max_edges {
                slicer.truncated.joins = true;
                break;
            }
            join_entries += 1;
            let e = &sim.edges[*edge as usize];
            let from = &sim.nodes[e.from as usize];
            incoming.push(json!({
                "from": slicer.id_of.get(&e.from),
                "from_kind": from.kind.name(),
                "from_offset": from.offset,
                "via": e.via.name(),
                "via_offset": e.via_offset,
            }));
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
        object.insert("incoming".into(), Value::Array(incoming));
        joins.push(Value::Object(object));
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
        omissions.push(
            "Join entry cap reached; later joins list only part of their incoming edges.".into(),
        );
    }
    let partial = !omissions.is_empty() || sim.stopped_at.is_some();
    Ok(json!({
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
            "local": seed_local,
            "nodes": seed_nodes.iter().filter_map(|node| slicer.id_of.get(node)).collect::<Vec<_>>(),
        },
        "instructions_simulated": sim.instructions.len(),
        "simulation_stopped_at": sim.stopped_at,
        "node_count": nodes.len(),
        "edge_count": edges.len(),
        "nodes": nodes,
        "edges": edges,
        "joins": joins,
        "sources": sources,
        "sinks": sinks,
        "interprocedural": interprocedural,
        "truncated": {
            "nodes": truncated.nodes,
            "edges": truncated.edges,
            "depth": truncated.depth,
            "deadline": truncated.deadline,
            "joins": truncated.joins,
            "simulation": sim.stopped_at.is_some(),
        },
        "omissions": omissions,
        "limits": {
            "max_input_bytes": wasm_graph::MAX_BYTES,
            "max_body_bytes": MAX_BODY_BYTES,
            "max_locals": wasm_def_use::MAX_LOCALS,
            "max_instructions": wasm_def_use::MAX_INSTRUCTIONS,
            "max_work": wasm_def_use::MAX_WORK,
            "max_nodes": max_nodes,
            "max_edges": max_nodes * EDGES_PER_NODE,
            "max_depth": request.max_depth,
            "max_expression_bytes": MAX_EXPRESSION_BYTES,
            "max_interprocedural_steps": MAX_STEPS,
            "max_call_sites": MAX_CALL_SITES,
            "deadline_ms": DEADLINE.as_millis() as u64,
        },
        "notice": "Declared static value flow inside one function, from the module bytes. Memory is a source unless a same-block store to the same constant address is proven; nothing was executed.",
    }))
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
            NodeKind::Call if matches!(entry.role, Role::Source | Role::Seed) => push(
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
        let (sites, finished, referenced) = call_sites(module, function, deadline)?;
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

    #[test]
    fn unreachable_operands_are_unknown_values() {
        let bytes = wat::parse_str("(module (func (result i32) unreachable i32.add))").unwrap();
        let add = offset_of(&bytes, 0, "i32.add", 0);
        let document = flow(&bytes, &format!("function=0&offset={add}")).unwrap();
        assert!(kinds_of(&document, "sources").contains(&"unknown"));
    }
}
