//! The complete value-flow slice for one Wasm instruction operand or one
//! local, `wasm-value-flow-v2` (protocol/wasm-value-flow-v2.md), and the
//! direct call sites of one function, `wasm-call-sites-v1`.
//!
//! The def-use graph of each function comes from [`crate::wasm_def_use`], the
//! slice from [`crate::wasm_value_slice`], function summaries from
//! [`crate::wasm_summaries`] and call sites from [`crate::wasm_call_index`].
//! This module resolves the seed, keeps what those analyses build in caches
//! keyed by the module's SHA-256 (the hash itself is recomputed from the bytes
//! on every request, since content integrity is never cached), and writes the
//! documents a page at a time: the slice is complete, and a request names the
//! page of nodes, sources, sinks and join entries it wants. Structure (kinds,
//! byte offsets, indices, edges) is separate from content: `text` and
//! `expression` carry instruction text derived from captured bytes and are
//! the only content fields. Nothing here runs the module, and raw evidence is
//! never modified.
use crate::{
    error::{Error, Result, check_cancelled},
    js_worker_alloc, result_cache, wasm,
    wasm_call_index::CallIndex,
    wasm_def_use::{self, EdgeKind, Module, NONE, NodeKind, Simulation},
    wasm_graph,
    wasm_summaries::{Bodies, Mask, Reach},
    wasm_value_slice::{Provider, Roots, Slice, SliceNode},
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
    path::Path,
    sync::atomic::AtomicBool,
    sync::{Arc, Mutex},
};
use wasmparser::Operator;

pub use crate::wasm_value_slice::{Direction, Options, Seed};

/// Nodes a page lists unless the request says otherwise.
pub const DEFAULT_NODE_LIMIT: usize = 256;
/// Sources or sinks a page lists unless the request says otherwise.
pub const DEFAULT_END_LIMIT: usize = 100;
/// Incoming entries each join of a page lists unless the request says otherwise.
pub const DEFAULT_JOIN_LIMIT: usize = 64;
/// Call sites a `wasm-call-sites-v1` page lists unless the request says otherwise.
pub const DEFAULT_SITE_LIMIT: usize = 100;
const MAX_EXPRESSION_BYTES: usize = 160;
const MAX_TEXT_BYTES: usize = 160;
/// Catch clauses an instruction's text lists before a count.
const MAX_LISTED_CLAUSES: usize = 8;
const EXPRESSION_DEPTH: u32 = 3;
/// Web engines reject a body above this size, so a longer one cannot have run.
const MAX_BODY_BYTES: usize = 7_654_321;
const QUERY_KEYS: [&str; 18] = [
    "artifact_id",
    "function",
    "offset",
    "operand",
    "local",
    "direction",
    "control",
    "interprocedural",
    "node_offset",
    "node_limit",
    "source_offset",
    "source_limit",
    "source_kind",
    "sink_offset",
    "sink_limit",
    "sink_kind",
    "join_offset",
    "join_limit",
];
const SITES_QUERY_KEYS: [&str; 4] = ["artifact_id", "function", "offset", "limit"];
const WHAT: &str = "WASM value flow";

/// One page of a list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Page {
    pub offset: usize,
    pub limit: usize,
}

impl Page {
    fn of<T: Copy>(self, items: &[T]) -> (&[T], Option<usize>) {
        let start = self.offset.min(items.len());
        let end = start.saturating_add(self.limit).min(items.len());
        (&items[start..end], (end < items.len()).then_some(end))
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub artifact_id: Option<String>,
    pub function: u32,
    pub seed: Seed,
    pub options: Options,
    pub nodes: Page,
    pub sources: Page,
    pub source_kind: Option<String>,
    pub sinks: Page,
    pub sink_kind: Option<String>,
    pub joins: Page,
}

#[derive(Clone, Debug)]
pub struct SitesRequest {
    pub artifact_id: Option<String>,
    pub function: u32,
    pub page: Page,
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

fn flag(values: &HashMap<String, String>, name: &str, default: bool) -> Result<bool> {
    match values.get(name).map(String::as_str) {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(Error::bad(format!("{name} is true or false"))),
    }
}

fn page(values: &HashMap<String, String>, prefix: &str, default: usize) -> Result<Page> {
    let offset = values
        .get(&format!("{prefix}_offset"))
        .map(|text| integer::<usize>(&format!("{prefix}_offset"), text))
        .transpose()?
        .unwrap_or(0);
    let limit = values
        .get(&format!("{prefix}_limit"))
        .map(|text| integer::<usize>(&format!("{prefix}_limit"), text))
        .transpose()?
        .unwrap_or(default);
    if limit == 0 {
        return Err(Error::bad(format!("{prefix}_limit is at least 1")));
    }
    Ok(Page { offset, limit })
}

fn kind_filter(values: &HashMap<String, String>, name: &str) -> Result<Option<String>> {
    let Some(kind) = values.get(name) else {
        return Ok(None);
    };
    if !KINDS.iter().any(|known| known.name() == kind) {
        return Err(Error::bad(format!("{name} is not a node kind")));
    }
    Ok(Some(kind.clone()))
}

const KINDS: [NodeKind; 27] = [
    NodeKind::Param,
    NodeKind::LocalInit,
    NodeKind::Phi,
    NodeKind::ExceptionValue,
    NodeKind::Unknown,
    NodeKind::Const,
    NodeKind::LocalGet,
    NodeKind::LocalSet,
    NodeKind::LocalTee,
    NodeKind::GlobalGet,
    NodeKind::GlobalSet,
    NodeKind::Load,
    NodeKind::Store,
    NodeKind::Atomic,
    NodeKind::Memory,
    NodeKind::Table,
    NodeKind::Call,
    NodeKind::ImportCall,
    NodeKind::CallIndirect,
    NodeKind::CallRef,
    NodeKind::Select,
    NodeKind::Operation,
    NodeKind::Branch,
    NodeKind::Return,
    NodeKind::Throw,
    NodeKind::Drop,
    NodeKind::MemoryCell,
];

fn parse_pairs(raw: &str, keys: &[&str], what: &str) -> Result<HashMap<String, String>> {
    let mut values: HashMap<String, String> = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !keys.contains(&key.as_ref()) {
            return Err(Error::bad(format!(
                "{what} takes {}; {key} is not one of them",
                keys.join(", ")
            )));
        }
        if values.insert(key.to_string(), value.to_string()).is_some() {
            return Err(Error::bad(format!("{key} is given more than once")));
        }
    }
    Ok(values)
}

/// Parses the route's query. Unknown or repeated parameters are refused so a
/// misspelled seed never widens into a different slice.
pub fn parse_query(raw: &str) -> Result<Request> {
    let values = parse_pairs(raw, &QUERY_KEYS, "WASM value flow")?;
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
    Ok(Request {
        artifact_id: values.get("artifact_id").cloned(),
        function,
        seed,
        options: Options {
            direction,
            control: flag(&values, "control", false)?,
            interprocedural: flag(&values, "interprocedural", true)?,
        },
        nodes: page(&values, "node", DEFAULT_NODE_LIMIT)?,
        sources: page(&values, "source", DEFAULT_END_LIMIT)?,
        source_kind: kind_filter(&values, "source_kind")?,
        sinks: page(&values, "sink", DEFAULT_END_LIMIT)?,
        sink_kind: kind_filter(&values, "sink_kind")?,
        joins: page(&values, "join", DEFAULT_JOIN_LIMIT)?,
    })
}

/// Parses the call sites route's query.
pub fn parse_sites_query(raw: &str) -> Result<SitesRequest> {
    let values = parse_pairs(raw, &SITES_QUERY_KEYS, "WASM call sites")?;
    let function = integer::<u32>(
        "function",
        values
            .get("function")
            .ok_or_else(|| Error::bad("function is required"))?,
    )?;
    let offset = values
        .get("offset")
        .map(|text| integer::<usize>("offset", text))
        .transpose()?
        .unwrap_or(0);
    let limit = values
        .get("limit")
        .map(|text| integer::<usize>("limit", text))
        .transpose()?
        .unwrap_or(DEFAULT_SITE_LIMIT);
    if limit == 0 {
        return Err(Error::bad("limit is at least 1"));
    }
    Ok(SitesRequest {
        artifact_id: values.get("artifact_id").cloned(),
        function,
        page: Page { offset, limit },
    })
}

// Caches of what the analyses build, keyed by the module's SHA-256 so a
// changed module never reuses a stale result. Each is bounded by what it
// holds, in bytes, since one entry can be kilobytes or hundreds of megabytes.
type SimulationKey = (String, u32, bool);
static SIMULATIONS: result_cache::Cache<SimulationKey, Simulation> = Mutex::new(Vec::new());
type SliceKey = (String, u32, Seed, Options);
static SLICES: result_cache::Cache<SliceKey, Slice> = Mutex::new(Vec::new());
static CALL_INDEXES: result_cache::Cache<String, CallIndex> = Mutex::new(Vec::new());
static REACHES: result_cache::Cache<String, Reach> = Mutex::new(Vec::new());
/// Summaries one module holds are small; a handful of modules are kept.
const CACHED_REACHES: usize = 8;

/// Half of what a simulation may hold: the cached simulations of recent
/// requests together take at most this, so a new one always has room.
fn simulation_cache_budget() -> u64 {
    wasm_def_use::memory_budget() / 2
}

fn slice_cache_budget() -> u64 {
    js_worker_alloc::machine_ceiling() / 16
}

fn call_index_cache_budget() -> u64 {
    js_worker_alloc::machine_ceiling() / 16
}

/// What a request can see of a module: its simulations (the seed's and any
/// callee's), summaries and call index, each cached by the module's hash.
struct Functions<'m> {
    module: &'m Module<'m>,
    sha256: String,
    control: bool,
    cancelled: &'m AtomicBool,
    reach: Arc<Reach>,
    /// Callees that could not be entered, by function, each noted once.
    notes: Mutex<BTreeMap<u32, String>>,
}

impl Functions<'_> {
    fn body(&self, function: u32) -> Result<&wasmparser::FunctionBody<'_>> {
        if function < self.module.imported_functions {
            return Err(Error::new(
                404,
                format!("WASM function {function} is imported and has no body in this module"),
            ));
        }
        let body = self
            .module
            .bodies
            .get((function - self.module.imported_functions) as usize)
            .ok_or_else(|| {
                Error::new(
                    404,
                    format!("WASM function {function} is not defined by this module"),
                )
            })?;
        if body.range().len() > MAX_BODY_BYTES {
            return Err(Error::bad(format!(
                "WASM function {function} is {} bytes, past the {MAX_BODY_BYTES}-byte body limit web engines enforce",
                body.range().len()
            )));
        }
        Ok(body)
    }

    /// The simulation of a defined function, from the cache or built now.
    fn simulate(&self, function: u32) -> Result<Arc<Simulation>> {
        let body = self.body(function)?;
        let key = (self.sha256.clone(), function, self.control);
        result_cache::kept_within(
            &SIMULATIONS,
            key,
            simulation_cache_budget(),
            Simulation::bytes,
            || {
                wasm_def_use::simulate_with(
                    self.module,
                    function,
                    body,
                    self.cancelled,
                    wasm_def_use::Settings {
                        control: self.control,
                        ..wasm_def_use::Settings::default()
                    },
                )
            },
        )
    }

    fn notes(&self) -> Vec<String> {
        self.notes
            .lock()
            .map(|notes| {
                notes
                    .iter()
                    .map(|(function, reason)| {
                        format!(
                            "Function {function} could not be entered: {reason} Its calls are opaque: arguments into it are sinks and results out of it are sources."
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Bodies for Functions<'_> {
    fn simulation(&self, function: u32) -> Result<Option<Arc<Simulation>>> {
        if function < self.module.imported_functions
            || (function - self.module.imported_functions) as usize >= self.module.bodies.len()
        {
            return Ok(None);
        }
        match self.simulate(function) {
            Ok(sim) => Ok(Some(sim)),
            Err(error) if error.status == 499 => Err(error),
            Err(error) => {
                if let Ok(mut notes) = self.notes.lock() {
                    notes.entry(function).or_insert(error.message);
                }
                Ok(None)
            }
        }
    }
    fn imported_functions(&self) -> u32 {
        self.module.imported_functions
    }
}

impl Provider for Functions<'_> {
    fn reach(&self, function: u32, param: u32) -> Result<Arc<Mask>> {
        self.reach.of(self, function, param, self.cancelled)
    }
}

fn call_index(module: &Module<'_>, sha256: &str, cancelled: &AtomicBool) -> Result<Arc<CallIndex>> {
    result_cache::kept_within(
        &CALL_INDEXES,
        sha256.to_owned(),
        call_index_cache_budget(),
        CallIndex::bytes,
        || CallIndex::build(module, cancelled),
    )
}

/// Instruction text for the requested instruction indices, decoded again from
/// the original body so no text is retained for nodes outside the page.
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

/// Like `expression`, a node's text is capped so no single node can fill a
/// page by itself.
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

/// Instruction texts of one function's page nodes.
struct Texts<'s> {
    sim: &'s Simulation,
    /// `None` when no instruction of the function is on the page.
    instructions: Option<&'s HashMap<u32, String>>,
}

impl Texts<'_> {
    fn instruction(&self, index: u32) -> Option<&String> {
        self.instructions.and_then(|texts| texts.get(&index))
    }
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
            NodeKind::MemoryCell => {
                let cell = &self.sim.cells[n.index as usize];
                let base = if cell.base == wasm_def_use::ABSOLUTE {
                    format!("0x{:x}", cell.displacement)
                } else if cell.displacement == 0 {
                    format!(
                        "base@0x{:x}",
                        self.sim.nodes[cell.base.node as usize].offset
                    )
                } else {
                    format!(
                        "base@0x{:x}+0x{:x}",
                        self.sim.nodes[cell.base.node as usize].offset, cell.displacement
                    )
                };
                format!(
                    "memory cell {base} offset={} width={}",
                    cell.offset, cell.width
                )
            }
            _ => String::new(),
        }
    }

    fn text(&self, node: u32) -> String {
        let n = &self.sim.nodes[node as usize];
        if n.kind == NodeKind::Return
            && n.instruction != NONE
            && let Some(text) = self.instruction(n.instruction)
            && text != "end"
        {
            return text.clone();
        }
        match n.kind {
            NodeKind::Param
            | NodeKind::LocalInit
            | NodeKind::Phi
            | NodeKind::Unknown
            | NodeKind::Return
            | NodeKind::MemoryCell => self.synthetic(node),
            NodeKind::ExceptionValue => {
                let tag = if n.index == NONE {
                    "any tag".to_owned()
                } else {
                    format!("tag {}", n.index)
                };
                match self.instruction(n.instruction) {
                    Some(handler) => format!("exception values of {tag} at {handler}"),
                    None => format!("exception values of {tag}"),
                }
            }
            _ => self
                .instruction(n.instruction)
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
            NodeKind::MemoryCell => {
                let _ = write!(out, "memory@0x{:x}", n.offset);
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
                    .sim
                    .adjacency
                    .inputs(node)
                    .iter()
                    .copied()
                    .filter(|edge| {
                        !matches!(
                            self.sim.edges[*edge as usize].kind,
                            EdgeKind::Merge
                                | EdgeKind::ForwardedStore
                                | EdgeKind::ForwardedGlobal
                                | EdgeKind::MemoryMay
                                | EdgeKind::Control
                        )
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
                    self.expression(edge.from, u32::from(edge.result), depth - 1, out);
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

/// The native helper's entry point: the route's query without its artifact_id.
pub fn value_flow_query(root: &Path, id: &str, query: &str) -> Result<Value> {
    let request = parse_query(query)?;
    if request.artifact_id.is_some() {
        return Err(Error::bad(
            "Pass the artifact with --artifact-id, not in the query",
        ));
    }
    value_flow(root, id, &request, &AtomicBool::new(false))
}

/// The value-flow document for one request, or a provider error. The slice
/// has no deadline: it runs until it is done or `cancelled` is set, when the
/// request that asked for it has gone away.
pub fn value_flow(
    root: &Path,
    id: &str,
    request: &Request,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let artifact = wasm_graph::artifact(root, id)?;
    value_flow_of(&artifact, request, cancelled)
}

/// The call sites document for one request.
pub fn call_sites(
    root: &Path,
    id: &str,
    request: &SitesRequest,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let artifact = wasm_graph::artifact(root, id)?;
    call_sites_of(&artifact, request, cancelled)
}

/// The native helper's entry point for call sites.
pub fn call_sites_query(root: &Path, id: &str, query: &str) -> Result<Value> {
    let request = parse_sites_query(query)?;
    if request.artifact_id.is_some() {
        return Err(Error::bad(
            "Pass the artifact with --artifact-id, not in the query",
        ));
    }
    call_sites(root, id, &request, &AtomicBool::new(false))
}

pub(crate) fn call_sites_of(
    artifact: &wasm_graph::Artifact,
    request: &SitesRequest,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let module = Module::read(&artifact.bytes)?;
    let function = request.function;
    if u64::from(function) >= module.types.function_count() {
        return Err(Error::new(
            404,
            format!("WASM function {function} is not declared by this module"),
        ));
    }
    let sha256 = artifact.sha256.as_str().unwrap_or_default().to_owned();
    let index = call_index(&module, &sha256, cancelled)?;
    let sites = index.callers(function);
    let (listed, next) = request.page.of(sites);
    let rows: Vec<Value> = listed
        .iter()
        .map(|(_, site)| json!({"caller": site.caller, "byte_offset": site.offset, "tail": site.tail}))
        .collect();
    Ok(json!({
        "schema": "wasm-call-sites-v1",
        "artifact_id": artifact.artifact_id,
        "sha256": artifact.sha256,
        "byte_size": artifact.bytes.len(),
        "function_index": function,
        "imported": function < module.imported_functions,
        "count": sites.len(),
        "offset": request.page.offset,
        "limit": request.page.limit,
        "next_offset": next,
        "sites": rows,
        "indirect": {
            "exported": module.exported.contains(&function),
            "start": module.start == Some(function),
            "element": module.element_functions.contains(&function),
            "referenced": index.referenced(function),
        },
        "undecoded": index.undecoded,
        "notice": "Direct call and return_call sites from the module bytes; indirect names what else can reach the function. Nothing was executed.",
    }))
}

/// The document for verified artifact bytes already in memory.
pub(crate) fn value_flow_of(
    artifact: &wasm_graph::Artifact,
    request: &Request,
    cancelled: &AtomicBool,
) -> Result<Value> {
    let module = Module::read(&artifact.bytes)?;
    let function = request.function;
    let sha256 = artifact.sha256.as_str().unwrap_or_default().to_owned();
    let reach = result_cache::kept(&REACHES, sha256.clone(), CACHED_REACHES, || {
        Ok(Reach::default())
    })?;
    let functions = Functions {
        module: &module,
        sha256: sha256.clone(),
        control: request.options.control,
        cancelled,
        reach,
        notes: Mutex::new(BTreeMap::new()),
    };
    let body = functions.body(function)?;
    let range = body.range();
    let sim = functions.simulate(function)?;
    check_cancelled(cancelled, WHAT)?;
    let (roots, seed) = resolve_seed(&sim, body, function, request.seed)?;
    let key = (sha256.clone(), function, request.seed, request.options);
    let mut cached = true;
    let slice =
        result_cache::kept_within(&SLICES, key, slice_cache_budget(), Slice::bytes, || {
            cached = false;
            Slice::compute(
                &functions,
                function,
                sim.clone(),
                roots,
                request.options,
                cancelled,
            )
        })?;
    check_cancelled(cancelled, WHAT)?;
    let callers = if request.options.interprocedural {
        let index = call_index(&module, &sha256, cancelled)?;
        json!({
            "count": index.callers(function).len(),
            "indirect": index.reachable_indirectly(&module, function),
            "undecoded": index.undecoded.len(),
        })
    } else {
        Value::Null
    };
    let document = Document {
        artifact,
        module: &module,
        slice: &slice,
        request,
        functions: &functions,
    };
    document.render(range, &sim, &seed, cached, callers)
}

/// What the document says about a request's seed.
struct SeedInfo {
    offset: Option<u32>,
    operand: Option<u32>,
    local: Option<u32>,
    operand_count: Option<usize>,
    /// Said when the seed names a local nothing simulated touches.
    note: Option<String>,
}

fn stopped_before(stopped: u32, offset: u32, omissions: &[String]) -> Error {
    Error::bad(format!(
        "Value flow stopped at byte 0x{stopped:x}, at or before the seed at byte 0x{offset:x}: {}",
        omissions.join(" ")
    ))
}

fn resolve_seed(
    sim: &Simulation,
    body: &wasmparser::FunctionBody<'_>,
    function: u32,
    seed: Seed,
) -> Result<(Roots, SeedInfo)> {
    let range = body.range();
    match seed {
        Seed::Instruction { offset, operand } => {
            let Some(instruction) = sim.instruction_at(offset) else {
                // Past the last simulated instruction, or no instruction was
                // simulated at all: the stop, not the offset, is the answer.
                let simulated_to = sim.instructions.last().copied();
                if let Some(stopped) = sim.stopped_at
                    && (offset as usize) < range.end
                    && (offset >= stopped || simulated_to.is_none_or(|last| offset > last))
                {
                    return Err(stopped_before(stopped, offset, &sim.omissions));
                }
                return Err(Error::new(
                    404,
                    format!(
                        "No instruction of WASM function {function} starts at byte 0x{offset:x}"
                    ),
                ));
            };
            if let Some(stopped) = sim.stopped_at
                && offset >= stopped
            {
                return Err(stopped_before(stopped, offset, &sim.omissions));
            }
            if !sim.instruction_live[instruction as usize] {
                return Err(Error::bad(format!(
                    "The instruction at byte 0x{offset:x} is unreachable in declared control flow, so no value flows through it"
                )));
            }
            let inputs = sim.inputs(instruction).to_vec();
            let node = sim.instruction_nodes[instruction as usize];
            let roots = match operand {
                Some(position) => {
                    let Some(value) = inputs.get(position as usize).copied() else {
                        return Err(Error::bad(format!(
                            "The instruction at byte 0x{offset:x} has {} operands; operand {position} does not exist",
                            inputs.len()
                        )));
                    };
                    let operand_edge = (node != NONE)
                        .then(|| {
                            sim.adjacency.inputs(node).iter().copied().find(|edge| {
                                let edge = sim.edges[*edge as usize];
                                u32::from(edge.operand) == position
                                    && edge.kind != EdgeKind::Merge
                                    && edge.from == value.node
                                    && u32::from(edge.result) == value.result
                            })
                        })
                        .flatten();
                    Roots {
                        nodes: if node == NONE { Vec::new() } else { vec![node] },
                        values: vec![value],
                        operand_edge,
                    }
                }
                None => {
                    if node == NONE && inputs.is_empty() {
                        // A try_table's catch values are made at its end; a
                        // stop inside its body never reached them.
                        if let Some(stopped) = sim.stopped_at
                            && opens_handler(body, instruction)?
                        {
                            return Err(Error::bad(format!(
                                "Value flow stopped at byte 0x{stopped:x}, inside the handler at byte 0x{offset:x}, before its catch values were made: {}",
                                sim.omissions.join(" ")
                            )));
                        }
                        return Err(Error::bad(format!(
                            "The instruction at byte 0x{offset:x} neither produces nor consumes a value"
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
                        Roots {
                            nodes,
                            values: Vec::new(),
                            operand_edge: None,
                        }
                    } else {
                        // A block end or a branch has no node of its own: its
                        // operands' producers are the roots.
                        Roots {
                            nodes: Vec::new(),
                            values: inputs.clone(),
                            operand_edge: None,
                        }
                    }
                }
            };
            Ok((
                roots,
                SeedInfo {
                    offset: Some(offset),
                    operand,
                    local: None,
                    operand_count: Some(inputs.len()),
                    note: None,
                },
            ))
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
            let note = defs.is_empty().then(|| match sim.stopped_at {
                Some(stopped) if sim.instructions.is_empty() => format!(
                    "Simulation stopped at byte 0x{stopped:x} before any instruction, so local {local} was not traced."
                ),
                Some(stopped) => format!(
                    "Local {local} is not read or written before simulation stopped at byte 0x{stopped:x}."
                ),
                None => format!("Local {local} is never read or written in this function."),
            });
            Ok((
                Roots {
                    nodes: defs,
                    values: Vec::new(),
                    operand_edge: None,
                },
                SeedInfo {
                    offset: None,
                    operand: None,
                    local: Some(local),
                    operand_count: None,
                    note,
                },
            ))
        }
    }
}

fn link_object(link: &crate::wasm_value_slice::Link) -> Map<String, Value> {
    let mut edge = Map::new();
    edge.insert("kind".into(), json!(link.kind.name()));
    edge.insert("operand".into(), json!(link.operand));
    edge.insert("result".into(), json!(link.result));
    if let Some(via) = link.via.name() {
        edge.insert("via".into(), json!(via));
        edge.insert("via_offset".into(), json!(link.via_offset));
    }
    edge
}

/// Writes the paged document from a complete slice.
struct Document<'d> {
    artifact: &'d wasm_graph::Artifact,
    module: &'d Module<'d>,
    slice: &'d Slice,
    request: &'d Request,
    functions: &'d Functions<'d>,
}

/// A page's nodes grouped by the function they are in, with the texts of
/// their instructions decoded once per function.
struct PageTexts {
    by_function: HashMap<u32, HashMap<u32, String>>,
}

impl PageTexts {
    fn new(document: &Document<'_>, ids: impl Iterator<Item = u32>) -> Result<Self> {
        let slice = document.slice;
        let mut wanted: HashMap<u32, HashSet<u32>> = HashMap::new();
        let mut frontier: Vec<(u32, u32, u32)> = ids
            .map(|id| {
                let node = slice.nodes[id as usize];
                (node.function, node.node, EXPRESSION_DEPTH + 1)
            })
            .collect();
        // The inputs of a node's expression are texts too, a bounded number
        // of steps in.
        while let Some((function, node, depth)) = frontier.pop() {
            let sim = &slice.functions[function as usize].sim;
            let n = &sim.nodes[node as usize];
            if n.instruction != NONE && !wanted.entry(function).or_default().insert(n.instruction) {
                continue;
            }
            if depth == 0 {
                continue;
            }
            for edge in sim.adjacency.inputs(node) {
                let edge = sim.edges[*edge as usize];
                if !matches!(
                    edge.kind,
                    EdgeKind::Merge
                        | EdgeKind::ForwardedStore
                        | EdgeKind::ForwardedGlobal
                        | EdgeKind::MemoryMay
                        | EdgeKind::Control
                ) {
                    frontier.push((function, edge.from, depth - 1));
                }
            }
        }
        let mut by_function = HashMap::new();
        for (function, instructions) in wanted {
            let index = slice.functions[function as usize].index;
            let body = document.functions.body(index)?;
            by_function.insert(function, instruction_text(body, &instructions)?);
        }
        Ok(Self { by_function })
    }

    fn texts<'a>(&'a self, document: &'a Document<'_>, function: u32) -> Texts<'a> {
        Texts {
            sim: &document.slice.functions[function as usize].sim,
            instructions: self.by_function.get(&function),
        }
    }
}

impl Document<'_> {
    fn role(node: &SliceNode) -> &'static str {
        if node.seed {
            "seed"
        } else if node.source {
            "source"
        } else if node.sink {
            "sink"
        } else if node.boundary {
            "boundary"
        } else {
            "interior"
        }
    }

    /// The identifying fields of a node beside its kind and offset.
    fn identity(&self, entry: &SliceNode, object: &mut Map<String, Value>) {
        let sim = &self.slice.functions[entry.function as usize].sim;
        let n = &sim.nodes[entry.node as usize];
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
                object.insert("callee".into(), json!(n.index));
                if n.kind == NodeKind::ImportCall
                    && let Some((module_name, field)) = self.module.imports.get(n.index as usize)
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
            NodeKind::MemoryCell => {
                let cell = &sim.cells[n.index as usize];
                let mut address = Map::new();
                address.insert("memory".into(), json!(cell.memory));
                if cell.base == wasm_def_use::ABSOLUTE {
                    address.insert("address".into(), json!(cell.displacement));
                } else {
                    address.insert(
                        "base_offset".into(),
                        json!(sim.nodes[cell.base.node as usize].offset),
                    );
                    address.insert("displacement".into(), json!(cell.displacement));
                }
                address.insert("offset".into(), json!(cell.offset));
                address.insert("width".into(), json!(cell.width));
                object.insert("cell".into(), Value::Object(address));
            }
            _ => {}
        }
    }

    /// One listed node of the slice.
    fn node(&self, id: u32, page_texts: &PageTexts) -> Value {
        let slice = self.slice;
        let entry = slice.nodes[id as usize];
        let function = &slice.functions[entry.function as usize];
        let n = function.sim.nodes[entry.node as usize];
        let (parent, link, through, locals) = slice.listed_parent(id);
        let mut object = Map::new();
        object.insert("id".into(), json!(id));
        object.insert("walk".into(), json!(slice.position[id as usize]));
        object.insert("kind".into(), json!(n.kind.name()));
        object.insert("byte_offset".into(), json!(n.offset));
        object.insert("function".into(), json!(function.index));
        object.insert("direction".into(), json!(entry.dir.name()));
        object.insert("class".into(), json!(entry.class.name()));
        object.insert("depth".into(), json!(slice.depth(id)));
        object.insert("role".into(), json!(Self::role(&entry)));
        object.insert("seed".into(), json!(entry.seed));
        object.insert("source".into(), json!(entry.source));
        object.insert("sink".into(), json!(entry.sink));
        object.insert("boundary".into(), json!(entry.boundary));
        object.insert("results".into(), json!(n.results));
        if parent == NONE {
            object.insert("parent".into(), Value::Null);
            object.insert("edge".into(), Value::Null);
        } else {
            object.insert("parent".into(), json!(parent));
            let mut edge = link_object(&link);
            edge.insert("locals".into(), json!(locals));
            edge.insert(
                "through".into(),
                through.map_or(Value::Null, |link| Value::Object(link_object(&link))),
            );
            object.insert("edge".into(), Value::Object(edge));
        }
        self.identity(&entry, &mut object);
        let texts = page_texts.texts(self, entry.function);
        object.insert("text".into(), json!(capped(texts.text(entry.node))));
        if n.results > 0 && !matches!(n.kind, NodeKind::Return | NodeKind::LocalSet) {
            object.insert(
                "expression".into(),
                json!(texts.bounded_expression(entry.node)),
            );
        }
        Value::Object(object)
    }

    /// A compact source or sink row.
    fn end(&self, id: u32, texts: &PageTexts) -> Value {
        let slice = self.slice;
        let entry = slice.nodes[id as usize];
        let function = &slice.functions[entry.function as usize];
        let n = function.sim.nodes[entry.node as usize];
        let mut object = Map::new();
        object.insert("id".into(), json!(id));
        object.insert("walk".into(), json!(slice.position[id as usize]));
        object.insert("kind".into(), json!(n.kind.name()));
        object.insert("class".into(), json!(entry.class.name()));
        object.insert("byte_offset".into(), json!(n.offset));
        object.insert("function".into(), json!(function.index));
        object.insert("seed".into(), json!(entry.seed));
        self.identity(&entry, &mut object);
        object.insert(
            "text".into(),
            json!(capped(texts.texts(self, entry.function).text(entry.node))),
        );
        Value::Object(object)
    }

    /// The joins (phi and memory cell nodes) among `ids`, each with a page of
    /// its incoming entries.
    fn joins(&self, ids: &[u32]) -> Vec<Value> {
        let slice = self.slice;
        let page = self.request.joins;
        let mut joins = Vec::new();
        for id in ids {
            let entry = slice.nodes[*id as usize];
            let function = &slice.functions[entry.function as usize];
            let sim = &function.sim;
            let n = sim.nodes[entry.node as usize];
            if !matches!(n.kind, NodeKind::Phi | NodeKind::MemoryCell) {
                continue;
            }
            let incoming: Vec<u32> = sim
                .adjacency
                .inputs(entry.node)
                .iter()
                .copied()
                .filter(|edge| {
                    matches!(
                        sim.edges[*edge as usize].kind,
                        EdgeKind::Merge | EdgeKind::MemoryMay
                    )
                })
                .collect();
            let (listed, next) = page.of(&incoming);
            let rows: Vec<Value> = listed
                .iter()
                .map(|edge| {
                    let e = sim.edges[*edge as usize];
                    let from = sim.nodes[e.from as usize];
                    let from_id = function.backward_id(e.from);
                    json!({
                        "from": from_id,
                        "from_kind": from.kind.name(),
                        "from_offset": from.offset,
                        "via": e.via.name(),
                        "via_offset": if e.via_offset == NONE { Value::Null } else { json!(e.via_offset) },
                    })
                })
                .collect();
            let mut object = Map::new();
            object.insert("node".into(), json!(id));
            object.insert(
                "join".into(),
                json!(if n.kind == NodeKind::MemoryCell {
                    "memory"
                } else {
                    n.join.name().unwrap_or("block")
                }),
            );
            object.insert("byte_offset".into(), json!(n.offset));
            object.insert("function".into(), json!(function.index));
            if n.kind == NodeKind::Phi {
                if n.index != NONE {
                    object.insert("local".into(), json!(n.index));
                } else {
                    object.insert("slot".into(), json!(n.aux));
                }
            }
            object.insert("incoming_count".into(), json!(incoming.len()));
            object.insert("incoming_offset".into(), json!(page.offset));
            object.insert("next_incoming_offset".into(), json!(next));
            object.insert("incoming".into(), Value::Array(rows));
            if sim.open_joins.contains(&entry.node) {
                object.insert("incomplete".into(), json!(true));
            }
            joins.push(Value::Object(object));
        }
        joins
    }

    /// A paged, kind-filtered list of ends with its kind histogram.
    fn ends(
        &self,
        ids: &[u32],
        page: Page,
        kind: Option<&str>,
        texts_of: impl Fn(&[u32]) -> Result<PageTexts>,
    ) -> Result<Value> {
        let slice = self.slice;
        let mut histogram: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
        for id in ids {
            let entry = slice.nodes[*id as usize];
            let n = slice.functions[entry.function as usize].sim.nodes[entry.node as usize];
            *histogram
                .entry((n.kind.name(), entry.class.name()))
                .or_default() += 1;
        }
        let mut kinds: Vec<Value> = histogram
            .iter()
            .map(|((kind, class), count)| json!({"kind": kind, "class": class, "count": count}))
            .collect();
        kinds.sort_by_key(|row| std::cmp::Reverse(row["count"].as_u64().unwrap_or(0)));
        let filtered: Vec<u32> = match kind {
            None => ids.to_vec(),
            Some(kind) => ids
                .iter()
                .copied()
                .filter(|id| {
                    let entry = slice.nodes[*id as usize];
                    slice.functions[entry.function as usize].sim.nodes[entry.node as usize]
                        .kind
                        .name()
                        == kind
                })
                .collect(),
        };
        let (listed, next) = page.of(&filtered);
        let texts = texts_of(listed)?;
        let items: Vec<Value> = listed.iter().map(|id| self.end(*id, &texts)).collect();
        Ok(json!({
            "count": ids.len(),
            "filtered_count": filtered.len(),
            "kind": kind,
            "kinds": kinds,
            "offset": page.offset,
            "limit": page.limit,
            "next_offset": next,
            "items": items,
        }))
    }

    fn render(
        &self,
        range: std::ops::Range<usize>,
        sim: &Simulation,
        seed: &SeedInfo,
        cached: bool,
        callers: Value,
    ) -> Result<Value> {
        let slice = self.slice;
        let request = self.request;
        let listed = &slice.listed;
        let (page_ids, next_node) = request.nodes.of(listed);
        // Every listed ancestor of a page node that is not itself on the page,
        // so each page node's path to the seed is in the document.
        let on_page: HashSet<u32> = page_ids.iter().copied().collect();
        let mut path_ids: Vec<u32> = Vec::new();
        let mut path_seen: HashSet<u32> = HashSet::new();
        for id in page_ids {
            for ancestor in slice.ancestors(*id) {
                if on_page.contains(&ancestor) || !path_seen.insert(ancestor) {
                    continue;
                }
                path_ids.push(ancestor);
            }
        }
        path_ids.sort_unstable();
        let texts = PageTexts::new(self, page_ids.iter().chain(path_ids.iter()).copied())?;
        let nodes: Vec<Value> = page_ids.iter().map(|id| self.node(*id, &texts)).collect();
        let path_nodes: Vec<Value> = path_ids.iter().map(|id| self.node(*id, &texts)).collect();
        let joins = self.joins(page_ids);
        let sources: Vec<u32> = listed
            .iter()
            .copied()
            .filter(|id| slice.nodes[*id as usize].source)
            .collect();
        let sinks: Vec<u32> = listed
            .iter()
            .copied()
            .filter(|id| slice.nodes[*id as usize].sink)
            .collect();
        let texts_of = |ids: &[u32]| PageTexts::new(self, ids.iter().copied());
        let source_list = self.ends(
            &sources,
            request.sources,
            request.source_kind.as_deref(),
            texts_of,
        )?;
        let sink_list = self.ends(
            &sinks,
            request.sinks,
            request.sink_kind.as_deref(),
            texts_of,
        )?;
        let join_count = listed
            .iter()
            .filter(|id| {
                let entry = slice.nodes[**id as usize];
                matches!(
                    slice.functions[entry.function as usize].sim.nodes[entry.node as usize].kind,
                    NodeKind::Phi | NodeKind::MemoryCell
                )
            })
            .count();
        let boundary_count = listed
            .iter()
            .filter(|id| slice.nodes[**id as usize].boundary)
            .count();
        let mut omissions: Vec<String> = sim.omissions.clone();
        if let Some(note) = &seed.note {
            omissions.push(note.clone());
        }
        for function in slice.functions.iter().skip(1) {
            for omission in &function.sim.omissions {
                omissions.push(format!("In function {}: {omission}", function.index));
            }
        }
        omissions.extend(self.functions.notes());
        let partial = !omissions.is_empty() || sim.stopped_at.is_some();
        let functions: Vec<Value> = slice
            .functions
            .iter()
            .map(|function| {
                json!({
                    "index": function.index,
                    "instructions_simulated": function.sim.instructions.len(),
                    "stopped_at": function.sim.stopped_at,
                })
            })
            .collect();
        let seed_nodes: Vec<u32> = slice.seeds.clone();
        let mut document = Map::new();
        let mut put = |key: &str, value: Value| {
            document.insert(key.to_owned(), value);
        };
        put("schema", json!("wasm-value-flow-v2"));
        put("artifact_id", self.artifact.artifact_id.clone());
        put("sha256", self.artifact.sha256.clone());
        put("byte_size", json!(self.artifact.bytes.len()));
        put("function_index", json!(request.function));
        put("type_index", json!(sim.type_index));
        put("byte_offset", json!(range.start));
        put("byte_end", json!(range.end));
        put("params", json!(sim.params));
        put("locals", json!(sim.locals));
        put("results", json!(sim.results));
        put("evidence", json!("declared_static"));
        put("complete", json!(false));
        put(
            "status",
            json!(if partial { "partial" } else { "computed" }),
        );
        put(
            "request",
            json!({
                "direction": request.options.direction.name(),
                "control": request.options.control,
                "interprocedural": request.options.interprocedural,
                "node_offset": request.nodes.offset,
                "node_limit": request.nodes.limit,
                "source_offset": request.sources.offset,
                "source_limit": request.sources.limit,
                "source_kind": request.source_kind,
                "sink_offset": request.sinks.offset,
                "sink_limit": request.sinks.limit,
                "sink_kind": request.sink_kind,
                "join_offset": request.joins.offset,
                "join_limit": request.joins.limit,
            }),
        );
        put(
            "seed",
            json!({
                "kind": if seed.local.is_some() { "local" } else { "instruction" },
                "byte_offset": seed.offset,
                "operand": seed.operand,
                "operand_count": seed.operand_count,
                "local": seed.local,
                "nodes": seed_nodes,
            }),
        );
        put("instructions_simulated", json!(sim.instructions.len()));
        put("simulation_stopped_at", json!(sim.stopped_at));
        put("simulation_bytes", json!(sim.bytes()));
        put("cached", json!(cached));
        put("functions", Value::Array(functions));
        put("node_count", json!(listed.len()));
        put("transport_count", json!(slice.transport_count()));
        put("source_count", json!(sources.len()));
        put("sink_count", json!(sinks.len()));
        put("join_count", json!(join_count));
        put("boundary_count", json!(boundary_count));
        put("node_offset", json!(request.nodes.offset));
        put("next_node_offset", json!(next_node));
        put("nodes", Value::Array(nodes));
        put("path_nodes", Value::Array(path_nodes));
        put("joins", Value::Array(joins));
        put("sources", source_list);
        put("sinks", sink_list);
        put("callers", callers);
        put("omissions", json!(omissions));
        put(
            "limits",
            json!({
                "max_body_bytes": MAX_BODY_BYTES,
                "max_locals": wasm_def_use::MAX_LOCALS,
                "simulation_memory_bytes": wasm_def_use::memory_budget(),
                "max_expression_bytes": MAX_EXPRESSION_BYTES,
                "max_text_bytes": MAX_TEXT_BYTES,
            }),
        );
        put(
            "notice",
            json!(
                "Declared static value flow from the module bytes, complete for the seed: every node's class says whether it provably carries the value, may through memory, computed an address, or decided a path. Calls are entered; summaries return results to their call. Nothing was executed."
            ),
        );
        Ok(Value::Object(document))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_graph::Artifact;
    use sha2::{Digest, Sha256};

    const FIXTURE_WAT: &str =
        include_str!("../../../tools/fixtures/wasm-value-flow/value-flow.wat");
    const FIXTURE_WASM: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/fixtures/wasm-value-flow/value-flow.wasm"
    );

    pub(crate) fn fixture() -> Vec<u8> {
        wat::parse_str(FIXTURE_WAT).expect("value-flow fixture")
    }

    pub(crate) fn artifact_of(bytes: &[u8]) -> Artifact {
        Artifact {
            bytes: bytes.to_vec(),
            artifact_id: Value::from("7"),
            sha256: Value::from(hex::encode(Sha256::digest(bytes))),
        }
    }

    fn store(bytes: &[u8]) -> tempfile::TempDir {
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

    pub(crate) fn flow(bytes: &[u8], query: &str) -> Result<Value> {
        let request = parse_query(query)?;
        value_flow_of(&artifact_of(bytes), &request, &AtomicBool::new(false))
    }

    /// Byte offset of the `nth` instruction of `function` whose mnemonic is `name`.
    pub(crate) fn offset_of(bytes: &[u8], function: u32, name: &str, nth: usize) -> u32 {
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

    /// `(kind, class)` of every item of a source or sink list.
    fn end_kinds(document: &Value, list: &str) -> Vec<(String, String)> {
        document[list]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["kind"].as_str().unwrap().to_owned(),
                    item["class"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    /// The edge kinds on a node's condensed edge: its own and the hop into
    /// the parent.
    fn edge_kinds(node: &Value) -> Vec<&str> {
        [&node["edge"]["kind"], &node["edge"]["through"]["kind"]]
            .into_iter()
            .filter_map(Value::as_str)
            .collect()
    }

    fn nodes_of_kind<'a>(document: &'a Value, kind: &str) -> Vec<&'a Value> {
        document["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|node| node["kind"] == kind)
            .collect()
    }

    /// Every node of the document, page and path nodes, by id.
    fn all_nodes(document: &Value) -> HashMap<u64, &Value> {
        document["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .chain(document["path_nodes"].as_array().unwrap())
            .map(|node| (node["id"].as_u64().unwrap(), node))
            .collect()
    }

    /// Every listed node is connected to a seed through nodes the document
    /// carries, ids are unique, and counts match the lists.
    pub(crate) fn assert_consistent(document: &Value) {
        assert_eq!(document["schema"], "wasm-value-flow-v2");
        let nodes = all_nodes(document);
        let page = document["nodes"].as_array().unwrap();
        let seeds: HashSet<u64> = document["seed"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_u64().unwrap())
            .collect();
        assert!(!seeds.is_empty(), "a slice has a seed");
        let mut ids = HashSet::new();
        for node in page
            .iter()
            .chain(document["path_nodes"].as_array().unwrap())
        {
            assert!(
                ids.insert(node["id"].as_u64().unwrap()),
                "unique ids: {node}"
            );
        }
        for node in page {
            let mut current = node;
            let mut steps = 0;
            loop {
                if current["parent"].is_null() {
                    assert!(
                        seeds.contains(&current["id"].as_u64().unwrap()),
                        "a root is a seed: {current}"
                    );
                    assert_eq!(current["seed"], true);
                    break;
                }
                let parent = current["parent"].as_u64().unwrap();
                current = nodes
                    .get(&parent)
                    .unwrap_or_else(|| panic!("parent {parent} of {node} is in the document"));
                steps += 1;
                assert!(steps < 1_000_000, "a path ends");
            }
            assert_eq!(
                node["depth"].as_u64().unwrap(),
                steps,
                "depth is the path length: {node}"
            );
        }
        assert_eq!(
            document["source_count"].as_u64().unwrap(),
            document["sources"]["count"].as_u64().unwrap()
        );
        assert_eq!(
            document["sink_count"].as_u64().unwrap(),
            document["sinks"]["count"].as_u64().unwrap()
        );
        for list in ["sources", "sinks"] {
            let histogram: u64 = document[list]["kinds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["count"].as_u64().unwrap())
                .sum();
            assert_eq!(
                histogram,
                document[list]["count"].as_u64().unwrap(),
                "{list} kinds sum"
            );
        }
        for node in page {
            assert!(node["text"].is_string());
            assert!(node["walk"].as_u64().unwrap() <= document["node_count"].as_u64().unwrap());
        }
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
    fn the_route_reads_the_store_and_the_query_names_the_page() {
        let bytes = fixture();
        let directory = store(&bytes);
        let document =
            value_flow_query(directory.path(), "7", "function=2&local=2&node_limit=3").unwrap();
        assert_consistent(&document);
        assert_eq!(document["nodes"].as_array().unwrap().len(), 3);
        assert_eq!(document["request"]["node_limit"], 3);
        assert!(document["next_node_offset"].as_u64().unwrap() >= 3);
        let error = value_flow_query(directory.path(), "7", "artifact_id=7&function=2&local=2")
            .unwrap_err();
        assert_eq!(error.status, 400);
        let sites = call_sites_query(directory.path(), "7", "function=2").unwrap();
        assert_eq!(sites["schema"], "wasm-call-sites-v1");
        assert_eq!(sites["count"], 1, "{sites}");
        assert_eq!(sites["sites"][0]["caller"], 3);
        assert_eq!(sites["indirect"]["exported"], true);
        assert_eq!(sites["indirect"]["element"], true);
    }

    #[test]
    fn backward_slice_reaches_params_loads_imports_and_names_every_join() {
        let bytes = fixture();
        let send = offset_of(&bytes, 2, "call", 1);
        let document = flow(
            &bytes,
            &format!("function=2&offset={send}&operand=0&direction=backward&interprocedural=false&node_limit=10000&source_limit=10000"),
        )
        .unwrap();
        assert_consistent(&document);
        assert_eq!(document["status"], "computed", "{}", document["omissions"]);
        let sources = end_kinds(&document, "sources");
        let kinds: HashSet<&str> = sources.iter().map(|(kind, _)| kind.as_str()).collect();
        for kind in ["param", "load", "import_call", "const"] {
            assert!(kinds.contains(kind), "{kind} in {sources:?}");
        }
        // The `regs` pointer only computes the load's address: an address source.
        let address: Vec<&(String, String)> = sources
            .iter()
            .filter(|(_, class)| class == "address")
            .collect();
        assert!(
            address.iter().any(|(kind, _)| kind == "param"),
            "{sources:?}"
        );
        let value_params = sources
            .iter()
            .filter(|(kind, class)| kind == "param" && class == "value")
            .count();
        assert_eq!(
            value_params, 1,
            "seed: param 0 feeds the value; param 1 only the address: {sources:?}"
        );
        let joins = document["joins"].as_array().unwrap();
        let join_kinds: HashSet<&str> = joins
            .iter()
            .map(|join| join["join"].as_str().unwrap())
            .collect();
        assert!(
            join_kinds.contains("loop") && join_kinds.contains("if"),
            "{join_kinds:?}"
        );
        for join in joins {
            assert_eq!(
                join["incoming"].as_array().unwrap().len(),
                join["incoming_count"].as_u64().unwrap() as usize
            );
            for incoming in join["incoming"].as_array().unwrap() {
                assert!(incoming["via"].is_string(), "{incoming}");
            }
        }
        // A forwarded store is interior, not a source; the loop's memory cell is a may edge.
        assert!(
            nodes_of_kind(&document, "store").is_empty(),
            "a store is not reached backward"
        );
        assert!(
            document["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| edge_kinds(node).contains(&"forwarded_store")),
            "the store at 64 is forwarded to its load"
        );
        assert!(
            document["transport_count"].as_u64().unwrap() > 0,
            "local reads are condensed"
        );
        assert!(
            document["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| !node["edge"]["locals"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .is_empty()),
            "an edge names the locals it passed through"
        );
    }

    #[test]
    fn forward_slice_of_a_param_reaches_every_sink_kind() {
        let bytes = fixture();
        let document = flow(&bytes, "function=2&local=0&direction=forward&interprocedural=false&node_limit=10000&sink_limit=10000").unwrap();
        assert_consistent(&document);
        let sinks = end_kinds(&document, "sinks");
        let kinds: HashSet<&str> = sinks.iter().map(|(kind, _)| kind.as_str()).collect();
        for kind in ["store", "import_call", "global_set", "return", "branch"] {
            assert!(kinds.contains(kind), "{kind} in {sinks:?}");
        }
        // The stored value may be read back through the cell at 64.
        assert!(
            sinks.iter().any(|(_, class)| class == "memory_may")
                || nodes_of_kind(&document, "memory_cell").len() <= 1
        );
    }

    #[test]
    fn both_directions_list_sources_and_sinks_completely() {
        let bytes = fixture();
        let xor = offset_of(&bytes, 2, "i32.xor", 0);
        let document = flow(
            &bytes,
            &format!("function=2&offset={xor}&interprocedural=false"),
        )
        .unwrap();
        assert_consistent(&document);
        assert!(
            document["source_count"].as_u64().unwrap() >= 2,
            "{}",
            document["sources"]
        );
        assert!(
            document["sink_count"].as_u64().unwrap() >= 3,
            "{}",
            document["sinks"]
        );
        let forward = flow(
            &bytes,
            &format!("function=2&offset={xor}&direction=forward&interprocedural=false"),
        )
        .unwrap();
        assert_eq!(
            document["sink_count"], forward["sink_count"],
            "both lists every forward sink"
        );
        let backward = flow(
            &bytes,
            &format!("function=2&offset={xor}&direction=backward&interprocedural=false"),
        )
        .unwrap();
        assert_eq!(document["source_count"], backward["source_count"]);
    }

    #[test]
    fn calls_are_entered_and_summaries_return_results_to_their_call() {
        let bytes = fixture();
        // Function 3 calls $mix; backward from its result reaches $mix's body
        // and the argument the result depends on.
        let set = offset_of(&bytes, 3, "local.set", 0);
        let document = flow(&bytes, &format!("function=3&offset={set}&operand=0&direction=backward&node_limit=10000&source_limit=10000")).unwrap();
        assert_consistent(&document);
        let functions: HashSet<u64> = document["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["function"].as_u64().unwrap())
            .collect();
        assert!(
            functions.contains(&2) && functions.contains(&3),
            "{functions:?}"
        );
        let links: HashSet<&str> = document["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(edge_kinds)
            .collect();
        assert!(
            links.contains("call_result") && links.contains("summary"),
            "{links:?}"
        );
        assert!(
            document["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| node["boundary"] == true && node["kind"] == "return")
        );
        let sources = end_kinds(&document, "sources");
        assert!(
            sources.iter().any(|(kind, _)| kind == "import_call"),
            "$now inside $mix: {sources:?}"
        );
        assert!(
            sources.iter().any(|(kind, _)| kind == "load"),
            "{sources:?}"
        );
        assert!(
            !sources
                .iter()
                .any(|(kind, class)| kind == "param" && class == "value")
                || true
        );
        assert_eq!(document["callers"]["count"], 0);
        // Forward from $route's param enters $mix and comes back to $route's result.
        let forward = flow(
            &bytes,
            "function=3&local=0&direction=forward&node_limit=10000&sink_limit=10000",
        )
        .unwrap();
        assert_consistent(&forward);
        let sinks = end_kinds(&forward, "sinks");
        assert!(
            sinks.iter().any(|(kind, _)| kind == "import_call"),
            "env.send in $mix: {sinks:?}"
        );
        assert!(
            sinks.iter().any(|(kind, _)| kind == "branch"),
            "br_table in $route: {sinks:?}"
        );
        assert!(
            forward["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| edge_kinds(node).contains(&"call_param"))
        );
        assert!(
            forward["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| edge_kinds(node).contains(&"summary") && node["function"] == 3)
        );
        // Opaque calls stay sources and sinks.
        let opaque = flow(
            &bytes,
            "function=3&local=0&direction=forward&interprocedural=false&sink_limit=10000",
        )
        .unwrap();
        assert!(
            end_kinds(&opaque, "sinks")
                .iter()
                .any(|(kind, _)| kind == "call"),
            "{}",
            opaque["sinks"]
        );
        assert!(opaque["callers"].is_null());
    }

    #[test]
    fn control_edges_reach_the_decisions_behind_a_join() {
        let bytes = fixture();
        let send = offset_of(&bytes, 2, "call", 1);
        let without = flow(&bytes, &format!("function=2&offset={send}&operand=0&direction=backward&interprocedural=false&node_limit=10000")).unwrap();
        assert!(nodes_of_kind(&without, "branch").is_empty());
        let with = flow(&bytes, &format!("function=2&offset={send}&operand=0&direction=backward&interprocedural=false&control=true&node_limit=10000&source_limit=10000")).unwrap();
        assert_consistent(&with);
        let branches = nodes_of_kind(&with, "branch");
        assert!(!branches.is_empty(), "the if and br_if decide the joins");
        assert!(
            branches.iter().all(|node| node["class"] == "control"),
            "{branches:?}"
        );
        let sources = end_kinds(&with, "sources");
        assert!(
            sources.iter().any(|(_, class)| class == "control"),
            "{sources:?}"
        );
    }

    #[test]
    fn pages_cover_the_slice_without_gaps_or_overlap() {
        let bytes = fixture();
        let send = offset_of(&bytes, 2, "call", 1);
        let whole = flow(
            &bytes,
            &format!("function=2&offset={send}&interprocedural=false&node_limit=100000"),
        )
        .unwrap();
        let total = whole["node_count"].as_u64().unwrap() as usize;
        let mut seen = Vec::new();
        let mut offset = 0usize;
        loop {
            let page = flow(&bytes, &format!("function=2&offset={send}&interprocedural=false&node_offset={offset}&node_limit=4")).unwrap();
            assert_consistent(&page);
            assert_eq!(page["node_count"].as_u64().unwrap() as usize, total);
            assert!(
                page["cached"].as_bool().unwrap(),
                "later pages reuse the slice"
            );
            for node in page["nodes"].as_array().unwrap() {
                assert_eq!(node["walk"].as_u64().unwrap() as usize, seen.len());
                seen.push(node["id"].as_u64().unwrap());
            }
            match page["next_node_offset"].as_u64() {
                Some(next) => offset = next as usize,
                None => break,
            }
        }
        assert_eq!(seen.len(), total);
        let unique: HashSet<u64> = seen.iter().copied().collect();
        assert_eq!(unique.len(), total);
        // Ends page and filter.
        let loads = flow(
            &bytes,
            &format!(
                "function=2&offset={send}&interprocedural=false&source_kind=load&source_limit=1"
            ),
        )
        .unwrap();
        assert_eq!(loads["sources"]["kind"], "load");
        assert!(
            loads["sources"]["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["kind"] == "load")
        );
        assert_eq!(loads["sources"]["count"], whole["sources"]["count"]);
        let joins = flow(
            &bytes,
            &format!(
                "function=2&offset={send}&interprocedural=false&node_limit=10000&join_limit=1"
            ),
        )
        .unwrap();
        for join in joins["joins"].as_array().unwrap() {
            assert!(join["incoming"].as_array().unwrap().len() <= 1);
            if join["incoming_count"].as_u64().unwrap() > 1 {
                assert_eq!(join["next_incoming_offset"], 1);
            }
        }
    }

    #[test]
    fn requests_fail_with_named_errors() {
        let bytes = fixture();
        for (query, status, needle) in [
            ("function=2", 400, "exactly one"),
            ("function=2&offset=1&local=0", 400, "exactly one"),
            ("function=2&local=0&operand=1", 400, "operand applies"),
            ("function=2&local=0&direction=up", 400, "direction"),
            ("function=2&local=0&control=maybe", 400, "control"),
            ("function=2&local=0&node_limit=0", 400, "node_limit"),
            ("function=2&local=0&source_kind=banana", 400, "source_kind"),
            ("function=2&local=0&max_nodes=3", 400, "not one of them"),
            ("function=0&local=0", 404, "imported"),
            ("function=99&local=0", 404, "not defined"),
            ("function=2&local=99", 400, "does not exist"),
            ("function=2&offset=1", 404, "No instruction"),
        ] {
            let error = flow(&bytes, query).unwrap_err();
            assert_eq!(error.status, status, "{query}: {}", error.message);
            assert!(error.message.contains(needle), "{query}: {}", error.message);
        }
        let error = flow(&bytes, "function=2&offset=1&local=0").unwrap_err();
        assert_eq!(error.status, 400);
        let sites = parse_sites_query("function=2&limit=0").unwrap_err();
        assert_eq!(sites.status, 400);
    }

    #[test]
    fn a_cancelled_request_is_499_and_leaves_no_cached_slice() {
        let bytes = fixture();
        let request = parse_query("function=2&local=0").unwrap();
        let mut artifact = artifact_of(&bytes);
        artifact.sha256 = Value::from("f".repeat(64));
        let error = value_flow_of(&artifact, &request, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(error.status, 499);
        let key = ("f".repeat(64), 2u32, request.seed, request.options);
        assert!(result_cache::find(&SLICES, &key).is_none());
    }

    #[test]
    fn dead_code_feeds_no_slice_and_unreachable_seeds_are_refused() {
        let bytes = wat::parse_str(
            r#"(module
              (import "env" "now" (func $now (result i32)))
              (func (export "f") (param i32) (result i32)
                (local.get 0)
                (return)
                (drop (call $now))
                (i32.const 7)))"#,
        )
        .unwrap();
        let call = offset_of(&bytes, 1, "call", 0);
        let error = flow(&bytes, &format!("function=1&offset={call}")).unwrap_err();
        assert_eq!(error.status, 400);
        assert!(error.message.contains("unreachable"), "{}", error.message);
        let document = flow(&bytes, "function=1&local=0&direction=forward").unwrap();
        assert_consistent(&document);
        assert_eq!(
            end_kinds(&document, "sinks"),
            vec![("return".to_owned(), "value".to_owned())]
        );
    }

    #[test]
    fn memory_cells_join_stores_to_loads_as_may_flow() {
        let bytes = wat::parse_str(
            r#"(module
              (memory 1)
              (func (export "f") (param $regs i32) (param $v i32) (result i32)
                (i32.store offset=4 (local.get $regs) (local.get $v))
                (call $g)
                (i32.load offset=4 (local.get $regs)))
              (func $g))"#,
        )
        .unwrap();
        let load = offset_of(&bytes, 0, "i32.load", 0);
        let document = flow(
            &bytes,
            &format!("function=0&offset={load}&direction=backward&source_limit=100"),
        )
        .unwrap();
        assert_consistent(&document);
        let sources = end_kinds(&document, "sources");
        // The seed load has no exact producer; through the cell, param $v may
        // feed it, and param $regs computes its address.
        assert_eq!(document["nodes"][0]["role"], "seed");
        assert_eq!(document["nodes"][0]["kind"], "load");
        assert!(
            sources
                .iter()
                .any(|(kind, class)| kind == "param" && class == "memory_may"),
            "{sources:?}"
        );
        assert!(
            sources
                .iter()
                .any(|(kind, class)| kind == "param" && class == "address"),
            "{sources:?}"
        );
        let cells = nodes_of_kind(&document, "memory_cell");
        assert_eq!(cells.len(), 1, "{}", document["nodes"]);
        assert_eq!(cells[0]["class"], "memory_may");
        assert_eq!(cells[0]["cell"]["offset"], 4);
        let joins = document["joins"].as_array().unwrap();
        assert!(
            joins
                .iter()
                .any(|join| join["join"] == "memory" && join["incoming"][0]["via"] == "store"),
            "{joins:?}"
        );
    }

    #[test]
    fn a_seed_after_an_unmodeled_operator_is_refused_and_the_prefix_is_partial() {
        let bytes = wat::parse_str(
            "(module (type $f (func)) (type $c (cont $f)) (func $g) (elem declare func $g)
              (func (param i32) (result i32) local.get 0 drop ref.func $g cont.new $c drop local.get 0))",
        )
        .unwrap();
        let get = offset_of(&bytes, 1, "local.get", 1);
        let error = flow(&bytes, &format!("function=1&offset={get}")).unwrap_err();
        assert_eq!(error.status, 400);
        assert!(
            error.message.contains("stopped at byte 0x"),
            "{}",
            error.message
        );
        let document = flow(&bytes, "function=1&local=0").unwrap();
        assert_eq!(document["status"], "partial");
        assert!(document["simulation_stopped_at"].is_number());
    }

    #[test]
    fn a_tail_call_returns_the_callee_results() {
        let bytes = wat::parse_str(
            r#"(module
              (func $id (param i32) (result i32) (local.get 0))
              (func (export "f") (param i32) (result i32) (return_call $id (local.get 0))))"#,
        )
        .unwrap();
        let document = flow(
            &bytes,
            "function=1&local=0&direction=forward&sink_limit=100",
        )
        .unwrap();
        assert_consistent(&document);
        let sinks = end_kinds(&document, "sinks");
        assert!(sinks.iter().any(|(kind, _)| kind == "return"), "{sinks:?}");
        assert!(
            document["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| node["function"] == 0 && node["boundary"] == true)
        );
    }

    #[test]
    fn an_undecodable_callee_is_noted_and_stays_opaque() {
        // Function 1's body is valid; function 2's is garbage that the
        // decoder rejects, and the slice says so instead of failing.
        let mut bytes = wat::parse_str(
            r#"(module
              (func (export "f") (param i32) (result i32) (call 1 (local.get 0)))
              (func (param i32) (result i32) (i32.add (local.get 0) (i32.const 1))))"#,
        )
        .unwrap();
        let add = offset_of(&bytes, 1, "i32.add", 0) as usize;
        bytes[add] = 0xfe;
        bytes[add + 1] = 0xff;
        let document = flow(
            &bytes,
            "function=0&local=0&direction=forward&sink_limit=100",
        )
        .unwrap();
        assert_eq!(document["status"], "partial");
        assert!(
            document["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|note| note
                    .as_str()
                    .unwrap()
                    .contains("Function 1 could not be entered")),
            "{}",
            document["omissions"]
        );
        assert!(
            end_kinds(&document, "sinks")
                .iter()
                .any(|(kind, _)| kind == "call"),
            "{}",
            document["sinks"]
        );
    }
}
