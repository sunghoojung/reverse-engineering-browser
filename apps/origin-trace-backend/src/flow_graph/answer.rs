//! The fold as JSON (protocol/flow-graph-v2.md), written member by member
//! from typed values. Contexts, nodes and edges are written once per graph
//! generation and set of researcher names; each answer adds its own head,
//! since coverage and timing are the request's. Only what some stack walks is
//! written: a node or edge left behind when its stacks were planned again
//! has no stack left, and the IDs are dense over what is written. A paths
//! answer names the same IDs.
use super::{
    FxMap, PATHS_SCHEMA, PathQuery, SCHEMA, Source, State,
    build::{CROSSES_DYNAMIC, CROSSES_FRAME, CROSSES_LANGUAGE, Function, LABELS, NodeKind},
    records::{self, Identity, NO_SHA, Sink},
};
use crate::{
    error::{Error, Result},
    request_stack,
    wasm_names::Names,
};
use axum::body::Bytes;
use serde::Serialize;
use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

/// Not written: no stack walks it.
const NONE: u32 = u32::MAX;

/// What one generation's answers share.
pub(super) struct Body {
    /// The answer ID of each graph node and edge, or `NONE`.
    node_ids: Vec<u32>,
    edge_ids: Vec<u32>,
    /// The graph node of each answer node. Nodes are grouped by context, so
    /// a context's nodes are one run of IDs.
    nodes: Vec<u32>,
    /// The graph edge of each answer edge. Edges are ordered by their later
    /// end, so a page that ends at a node carries every edge between the
    /// nodes it and the pages before it hold.
    edges: Vec<u32>,
    /// The graph context of each answer context, and its first node.
    contexts: Vec<(u32, u32)>,
    /// The first edge whose later end is each node; the edge count last.
    edge_starts: Vec<u32>,
    encoded: Option<Encoded>,
}

/// The members as JSON, for the names they were joined with. Nodes and edges
/// are each one run of items, every item followed by a comma, so any run of
/// IDs is one slice.
struct Encoded {
    names: Arc<Names>,
    contexts: Bytes,
    nodes: Bytes,
    node_offsets: Vec<usize>,
    edges: Bytes,
    edge_offsets: Vec<usize>,
    analyst_names: Bytes,
}

impl Encoded {
    fn run(bytes: &Bytes, offsets: &[usize], from: u32, to: u32) -> Bytes {
        let (start, end) = (offsets[from as usize], offsets[to as usize]);
        // Leave out the comma after the run's last item.
        bytes.slice(start..end.saturating_sub(1).max(start))
    }
}

fn ids(state: &State) -> Body {
    let graph = &state.graph;
    let mut nodes: Vec<u32> = (0..graph.nodes.len() as u32)
        .filter(|&node| graph.nodes[node as usize].stacks != 0)
        .collect();
    // Contexts in first-seen order; within one, nodes in first-seen order.
    nodes.sort_by_key(|&node| graph.nodes[node as usize].context);
    let mut node_ids = vec![NONE; graph.nodes.len()];
    let mut contexts: Vec<(u32, u32)> = Vec::new();
    for (id, &node) in nodes.iter().enumerate() {
        node_ids[node as usize] = id as u32;
        let context = graph.nodes[node as usize].context;
        if contexts.last().is_none_or(|&(last, _)| last != context) {
            contexts.push((context, id as u32));
        }
    }
    let later = |edge: u32| {
        let edge = &graph.edges[edge as usize];
        node_ids[edge.from as usize].max(node_ids[edge.to as usize])
    };
    let mut edges: Vec<u32> = (0..graph.edges.len() as u32)
        .filter(|&edge| graph.edges[edge as usize].stacks != 0)
        .collect();
    edges.sort_by_key(|&edge| later(edge));
    let mut edge_ids = vec![NONE; graph.edges.len()];
    let mut edge_starts = vec![0u32; nodes.len() + 1];
    for (id, &edge) in edges.iter().enumerate() {
        edge_ids[edge as usize] = id as u32;
        edge_starts[later(edge) as usize + 1] += 1;
    }
    for node in 0..nodes.len() {
        edge_starts[node + 1] += edge_starts[node];
    }
    Body {
        node_ids,
        edge_ids,
        nodes,
        edges,
        contexts,
        edge_starts,
        encoded: None,
    }
}

fn body(state: &mut State) -> &mut Body {
    if state.body.is_none() {
        state.body = Some(ids(state));
    }
    state.body.as_mut().unwrap()
}

#[derive(Serialize)]
struct Head<'a> {
    schema: &'static str,
    session_id: String,
    generation: &'a str,
    evidence: &'static str,
    complete: bool,
    coverage: Coverage<'a>,
    stacks: Stacks<'a>,
    not_shown: Vec<&'static str>,
    node_count: usize,
    edge_count: usize,
    cursor: u32,
    next_cursor: Option<u32>,
}

#[derive(Serialize)]
struct Coverage<'a> {
    caught_up: bool,
    folded_bytes: String,
    store_end: String,
    artifacts_caught_up: bool,
    malformed_records: u64,
    index_damage: Option<&'a str>,
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct Stacks<'a> {
    records: &'a BTreeMap<&'static str, u64>,
    occurrences: u64,
    distinct: usize,
    decoded: u64,
    not_walked: &'a BTreeMap<&'static str, u64>,
    unresolved: &'a BTreeMap<&'static str, u64>,
}

/// What the read records cannot contain. Records from before the stack scope
/// walked the document main thread only and carried no message callers;
/// later ones walk workers and carry messages across threads and processes.
fn not_shown(state: &State) -> Vec<&'static str> {
    const UNSCOPED: [&str; 3] = [
        "worker and worklet stacks (stacks are walked on the document main thread only)",
        "MessagePort and worker messages",
        "cross-process frames (an out-of-process iframe is another renderer; only its own stacks \
         appear)",
    ];
    const SCOPED: [&str; 3] = [
        "worklet stacks (worklets have no stack tables), and stacks of a worker past the \
         renderer's 32 stack tables",
        "ServiceWorker.postMessage and Client.postMessage, and window.postMessage to or from \
         another process",
        "frames of another renderer process: its stacks are their own realms, joined to this \
         page's only by MessagePort, BroadcastChannel and worker message task edges",
    ];
    const MIXED: [&str; 3] = [
        "in records from builds before request stack version 3: worker stacks, and MessagePort \
         and worker messages",
        "worklet stacks (worklets have no stack tables), and stacks of a worker past the \
         renderer's 32 stack tables",
        "ServiceWorker.postMessage and Client.postMessage, and window.postMessage to or from \
         another process",
    ];
    let mut out: Vec<&'static str> = match (state.scan.unscoped_records, state.scan.scoped_records)
    {
        (true, false) => UNSCOPED.to_vec(),
        (true, true) => MIXED
            .iter()
            .copied()
            .chain(std::iter::once(SCOPED[2]))
            .collect(),
        _ => SCOPED.to_vec(),
    };
    out.insert(
        out.len() - 1,
        "calls that never reached a recorded request, navigation, task or cookie write",
    );
    out
}

/// One page of the answer: this request's head, every context, the nodes
/// from `cursor` on and the edges that end among them, as slices of the
/// generation's encoding. A page holds at least one node, and as many more as
/// keep it within `limit` nodes and edges.
pub(super) fn graph(
    state: &mut State,
    names: &Arc<Names>,
    elapsed_ms: u64,
    cursor: u32,
    limit: usize,
) -> Result<Vec<Bytes>> {
    let stale = body(state)
        .encoded
        .as_ref()
        .is_none_or(|encoded| !Arc::ptr_eq(&encoded.names, names));
    if stale {
        let encoded = encode(state, names)?;
        body(state).encoded = Some(encoded);
    }
    let body = state.body.as_ref().unwrap();
    let count = body.nodes.len() as u32;
    if cursor > count {
        return Err(Error::bad("cursor is past the last node of this graph"));
    }
    let mut end = cursor;
    let mut items = 0usize;
    while end < count {
        let edges = (body.edge_starts[end as usize + 1] - body.edge_starts[end as usize]) as usize;
        if end > cursor && items + 1 + edges > limit {
            break;
        }
        items += 1 + edges;
        end += 1;
    }
    let complete = state.caught_up && state.artifacts_caught_up;
    let head = Head {
        schema: SCHEMA,
        session_id: state.session.to_string(),
        generation: &state.generation,
        evidence: "observed",
        complete,
        coverage: Coverage {
            caught_up: state.caught_up,
            folded_bytes: if state.caught_up {
                state.covered_to.max(state.folded_to)
            } else {
                state.folded_to
            }
            .to_string(),
            store_end: state.store_end.to_string(),
            artifacts_caught_up: state.artifacts_caught_up,
            malformed_records: state.scan.malformed,
            index_damage: state.store_damage.as_deref(),
            elapsed_ms,
        },
        stacks: Stacks {
            records: &state.scan.records,
            occurrences: state.scan.walks.iter().map(|walk| walk.occurrences).sum(),
            distinct: state.scan.walks.len(),
            decoded: state.graph.decoded,
            not_walked: &state.scan.not_walked,
            unresolved: &state.graph.unresolved,
        },
        not_shown: not_shown(state),
        node_count: body.nodes.len(),
        edge_count: body.edges.len(),
        cursor,
        next_cursor: (end < count).then_some(end),
    };
    let mut head = serde_json::to_vec(&head)?;
    head.pop();
    head.extend_from_slice(b",\"contexts\":");
    let encoded = body.encoded.as_ref().unwrap();
    let (first_edge, last_edge) = (
        body.edge_starts[cursor as usize],
        body.edge_starts[end as usize],
    );
    Ok(vec![
        head.into(),
        encoded.contexts.clone(),
        Bytes::from_static(b",\"nodes\":["),
        Encoded::run(&encoded.nodes, &encoded.node_offsets, cursor, end),
        Bytes::from_static(b"],\"edges\":["),
        Encoded::run(&encoded.edges, &encoded.edge_offsets, first_edge, last_edge),
        Bytes::from_static(b"],\"analyst_names\":"),
        encoded.analyst_names.clone(),
        Bytes::from_static(b"}"),
    ])
}

/// Items written one after another, each followed by a comma, and where
/// each starts; the end is last.
fn run<T: Serialize>(items: impl Iterator<Item = T>) -> Result<(Bytes, Vec<usize>)> {
    let mut out = Vec::new();
    let mut offsets = vec![0];
    for item in items {
        serde_json::to_writer(&mut out, &item)?;
        out.push(b',');
        offsets.push(out.len());
    }
    Ok((out.into(), offsets))
}

#[derive(Serialize)]
struct ContextOut<'a> {
    id: u32,
    process_id: u32,
    isolate_key: Option<String>,
    execution_context_id: Option<String>,
    origin: Option<&'a str>,
    origins: Vec<OriginOut<'a>>,
    frame_ids: Vec<FrameOut>,
    tab_ids: Vec<u64>,
    counts: BTreeMap<&'static str, u64>,
    first_node: u32,
}

#[derive(Serialize)]
struct OriginOut<'a> {
    origin: &'a str,
    functions: u64,
}

#[derive(Serialize)]
struct FrameOut {
    frame_id: String,
    records: u64,
}

#[derive(Serialize)]
struct ChainEnd {
    reason: &'static str,
    task: &'static str,
    count: u64,
}

#[derive(Serialize)]
struct NodeOut<'a> {
    id: u32,
    kind: &'static str,
    context: u32,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    script_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_column: Option<u64>,
    /// Some(None) is written as null: top-level code has no function start.
    #[serde(skip_serializing_if = "Option::is_none")]
    function_position: Option<Option<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_level: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analyst_name: Option<&'a str>,
    hits: u64,
    stacks: u64,
    entries: u64,
    leaves: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    schedules: BTreeMap<&'static str, u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    chain_cut: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    chain_ends: Vec<ChainEnd>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum SiteOut {
    Line { line: u64, column: u64 },
    Module { module_offset: u64 },
}

#[derive(Serialize)]
struct EdgeOut {
    from: u32,
    to: u32,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    crosses: Vec<&'static str>,
    count: u64,
    stacks: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sites: Vec<SiteOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    via: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    omitted: Option<u32>,
}

fn origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    match parsed.origin() {
        url::Origin::Tuple(..) => Some(parsed.origin().ascii_serialization()),
        url::Origin::Opaque(_) => Some(format!("{}:", parsed.scheme())),
    }
}

/// A frame's retained source, or the first reason there is none
/// (`request_stack::find_source`).
fn find_source<'a>(
    identity: Option<&'a Identity>,
    sources: &'a FxMap<u32, Source>,
) -> std::result::Result<(&'a Identity, &'a Source, &'a super::SourceRow), &'static str> {
    let identity = identity.ok_or("script_identity_missing")?;
    if identity.sha == NO_SHA {
        return Err("source_unavailable");
    }
    sources
        .get(&identity.sha)
        .and_then(|source| source.row.as_ref().map(|row| (identity, source, row)))
        .ok_or(if identity.wasm || identity.retained {
            "source_artifact_missing"
        } else {
            "source_not_retained"
        })
}

/// Where a function node's frame is and what it is called, or why its
/// source does not say.
fn function_out<'a>(
    out: &mut NodeOut<'a>,
    kind: NodeKind,
    function: &'a Function,
    state: &'a State,
    names: &'a Names,
) {
    out.script_id = Some(function.script_id);
    let source = find_source(function.identity.as_ref(), &state.sources);
    let reason = match source {
        Ok((_, source, _)) => source.reason,
        Err(reason) => Some(reason),
    };
    if let Ok((_, _, row)) = source {
        out.artifact_id = Some(&row.artifact_id);
        out.url = Some(&row.url);
    }
    let usable = source.ok().filter(|_| reason.is_none());
    if kind == NodeKind::Wasm {
        out.function_index = Some(function.detail);
        // The module digest is the function's identity across sessions;
        // researcher names join to it.
        if let Some(identity) = function.identity.filter(|identity| identity.sha != NO_SHA) {
            let sha = hex::encode(state.scan.shas.get(identity.sha));
            out.analyst_name = names.function(&sha, function.detail);
            out.sha256 = Some(sha);
        }
        if let Ok((_, source, _)) = source
            && let Some(name) = source.names.get(&function.detail)
        {
            out.name = Some(Cow::Borrowed(&**name));
        }
        if usable.is_some() {
            out.status = "resolved";
        }
    } else {
        let at = (!function.top_level).then_some(function.detail);
        out.top_level = Some(function.top_level);
        out.function_position = Some(at);
        if let Some((identity, source, _)) = usable {
            out.status = "resolved";
            if let Some(&(line, column)) = at.and_then(|at| source.lines.get(&at)) {
                // Sources numbers the artifact itself; line and column add
                // the script's start in its document.
                let (document_line, document_column) = identity.document_position(line, column);
                out.artifact_line = Some(line);
                out.artifact_column = Some(column);
                out.line = Some(document_line);
                out.column = Some(document_column);
            } else if function.top_level {
                let (line, column) = identity.document_position(1, 1);
                out.line = Some(line);
                out.column = Some(column);
            } else {
                out.status = "unresolved";
                out.reason = Some("position_outside_source");
            }
            if let Some(name) = at.and_then(|at| source.names.get(&at)) {
                out.name = Some(Cow::Borrowed(&**name));
            }
        }
    }
    if let Some(reason) = reason {
        out.reason = Some(reason);
    }
}

/// The contexts, nodes, edges and `analyst_names` members.
fn encode(state: &State, names: &Arc<Names>) -> Result<Encoded> {
    let body = state.body.as_ref().unwrap();
    let graph = &state.graph;
    let mut joined = 0usize;
    let mut context_ids = vec![NONE; graph.contexts.len()];
    for (id, &(context, _)) in body.contexts.iter().enumerate() {
        context_ids[context as usize] = id as u32;
    }
    // Node kinds and script origins of each written context.
    let mut counts: Vec<BTreeMap<&'static str, u64>> = vec![BTreeMap::new(); body.contexts.len()];
    let mut origins: Vec<BTreeMap<&str, u64>> = vec![BTreeMap::new(); body.contexts.len()];
    let mut origin_of: FxMap<u32, Option<String>> = FxMap::default();
    for &node in &body.nodes {
        let node = &graph.nodes[node as usize];
        let context = context_ids[node.context as usize] as usize;
        *counts[context].entry(node.kind.name()).or_default() += 1;
        if let Some(function) = &node.function
            && let Ok((identity, _, row)) = find_source(function.identity.as_ref(), &state.sources)
        {
            origin_of
                .entry(identity.sha)
                .or_insert_with(|| origin(&row.url));
        }
    }
    for &node in &body.nodes {
        let node = &graph.nodes[node as usize];
        if let Some(origin) = node
            .function
            .as_ref()
            .and_then(|function| function.identity)
            .and_then(|identity| origin_of.get(&identity.sha))
            .and_then(Option::as_deref)
        {
            *origins[context_ids[node.context as usize] as usize]
                .entry(origin)
                .or_default() += 1;
        }
    }
    let contexts = serde_json::to_vec(
        &body
            .contexts
            .iter()
            .enumerate()
            .map(|(id, &(context, first_node))| {
                let context = &graph.contexts[context as usize];
                let mut by_count: Vec<OriginOut> = origins[id]
                    .iter()
                    .map(|(origin, functions)| OriginOut {
                        origin,
                        functions: *functions,
                    })
                    .collect();
                by_count.sort_by(|a, b| b.functions.cmp(&a.functions).then(a.origin.cmp(b.origin)));
                let mut frames: Vec<FrameOut> = context
                    .frames
                    .iter()
                    .filter(|(frame, _)| **frame != 0)
                    .map(|(frame, records)| FrameOut {
                        frame_id: frame.to_string(),
                        records: *records,
                    })
                    .collect();
                frames.sort_by_key(|frame| std::cmp::Reverse(frame.records));
                ContextOut {
                    id: id as u32,
                    process_id: context.process,
                    isolate_key: (context.isolate != 0)
                        .then(|| format!("{:016x}", context.isolate)),
                    execution_context_id: (context.realm != 0).then(|| context.realm.to_string()),
                    origin: by_count.first().map(|origin| origin.origin),
                    origins: by_count,
                    frame_ids: frames,
                    tab_ids: context.tabs.keys().copied().collect(),
                    counts: std::mem::take(&mut counts[id]),
                    first_node,
                }
            })
            .collect::<Vec<_>>(),
    )?;
    let (nodes, node_offsets) = run(body.nodes.iter().enumerate().map(|(id, &index)| {
        let node = &graph.nodes[index as usize];
        let mut out = NodeOut {
            id: id as u32,
            kind: node.kind.name(),
            context: context_ids[node.context as usize],
            status: "unresolved",
            reason: None,
            name: None,
            script_id: None,
            artifact_id: None,
            url: None,
            line: None,
            column: None,
            artifact_line: None,
            artifact_column: None,
            function_position: None,
            function_index: None,
            top_level: None,
            sha256: None,
            analyst_name: None,
            hits: node.hits,
            stacks: node.stacks,
            entries: node.entries,
            leaves: node.leaves,
            schedules: node
                .schedules
                .iter()
                .map(|&(task, count)| (request_stack::task_kind(task), count))
                .collect(),
            chain_cut: node.chain_cut != 0,
            chain_ends: Vec::new(),
        };
        let mut ends: Vec<ChainEnd> = node
            .chain_ends
            .iter()
            .map(|&((segment, task), count)| ChainEnd {
                reason: request_stack::segment_state(segment),
                task: request_stack::task_kind(task),
                count,
            })
            .collect();
        ends.sort_by(|a, b| a.reason.cmp(b.reason).then(a.task.cmp(b.task)));
        out.chain_ends = ends;
        match &node.function {
            Some(function) => {
                function_out(&mut out, node.kind, function, state, names);
                joined += usize::from(out.analyst_name.is_some());
            }
            None => {
                out.status = "resolved";
                out.name = Some(match state.scan.sinks.get(node.sink) {
                    Sink::Request(label) => Cow::Borrowed(state.scan.label_text.get(*label)),
                    Sink::Navigation(kind) => Cow::Owned(kind.replace('_', " ")),
                    Sink::Cookie(api) => Cow::Borrowed(*api),
                });
            }
        }
        out
    }))?;
    let (edges, edge_offsets) = run(body.edges.iter().map(|&edge| {
        let edge = &graph.edges[edge as usize];
        let mut crosses = Vec::new();
        for (bit, name) in [
            (CROSSES_FRAME, "frame"),
            (CROSSES_LANGUAGE, "language"),
            (CROSSES_DYNAMIC, "dynamic"),
        ] {
            if edge.crosses & bit != 0 {
                crosses.push(name);
            }
        }
        // Sites as one-based document positions, or module offsets,
        // in order; a site whose source does not resolve it is not a
        // position.
        let mut sites: Vec<(u64, u64)> = edge
            .sites
            .iter()
            .filter_map(|site| {
                if site.sha == NO_SHA {
                    return Some((0, u64::from(site.position)));
                }
                let &(line, column) = state.sources.get(&site.sha)?.lines.get(&site.position)?;
                Some(records::document_position(
                    site.start_line,
                    site.start_column,
                    line,
                    column,
                ))
            })
            .collect();
        sites.sort_unstable();
        sites.dedup();
        let mut via: Vec<&'static str> = (0u8..16)
            .filter(|kind| edge.via & (1u16 << kind) != 0)
            .map(request_stack::task_kind)
            .collect();
        via.sort_unstable();
        let mut labels: Vec<&str> = LABELS
            .iter()
            .enumerate()
            .filter(|(bit, _)| edge.labels & (1 << bit) != 0)
            .map(|(_, label)| *label)
            .collect();
        labels.sort_unstable();
        EdgeOut {
            from: body.node_ids[edge.from as usize],
            to: body.node_ids[edge.to as usize],
            kind: edge.kind.name(),
            task: (edge.kind == super::build::EdgeKind::Task)
                .then(|| request_stack::task_kind(edge.task)),
            crosses,
            count: edge.count,
            stacks: edge.stacks,
            sites: sites
                .into_iter()
                .map(|(line, column)| {
                    if line == 0 {
                        SiteOut::Module {
                            module_offset: column,
                        }
                    } else {
                        SiteOut::Line { line, column }
                    }
                })
                .collect(),
            via,
            label: (!labels.is_empty()).then(|| labels.join(" / ")),
            omitted: (edge.omitted != 0).then_some(edge.omitted),
        }
    }))?;
    Ok(Encoded {
        names: names.clone(),
        contexts: contexts.into(),
        nodes,
        node_offsets,
        edges,
        edge_offsets,
        analyst_names: serde_json::to_vec(&names.summary(joined))?.into(),
    })
}

#[derive(Serialize)]
struct PathsOut<'a> {
    schema: &'static str,
    session_id: String,
    generation: &'a str,
    /// Stacks that match, and their records.
    total: usize,
    occurrences: u64,
    /// Every node and edge any matching stack walks.
    nodes: Vec<u32>,
    edges: Vec<u32>,
    cursor: usize,
    next_cursor: Option<usize>,
    paths: Vec<PathOut>,
}

#[derive(Serialize)]
struct PathOut {
    process_id: u32,
    isolate_key: Option<String>,
    digest: String,
    occurrences: u64,
    retained: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    requests: usize,
    nodes: Vec<u32>,
    edges: Vec<u32>,
}

/// One page of the stacks that match `query`, with every node and edge of
/// all of them, so one answer lights them all.
pub(super) fn paths(
    state: &mut State,
    query: &PathQuery,
    cursor: usize,
    limit: usize,
) -> Result<Bytes> {
    body(state);
    let state = &*state;
    let body = state.body.as_ref().unwrap();
    let target = match *query {
        PathQuery::Node(id) => Some(
            *body
                .nodes
                .get(id as usize)
                .ok_or_else(|| Error::bad("node is not a node of this graph"))?,
        ),
        _ => None,
    };
    let matches: Vec<usize> = state
        .scan
        .walks
        .iter()
        .enumerate()
        .filter(|(index, walk)| {
            let Some(plan) = state.plans.get(*index).and_then(Option::as_ref) else {
                return false;
            };
            match *query {
                PathQuery::Node(_) => {
                    let node = target.unwrap();
                    plan.members.binary_search(&node).is_ok()
                        || plan.sinks.iter().any(|&(_, sink, _)| sink == node)
                }
                PathQuery::Request { process, request } => {
                    walk.process == process && walk.requests.contains(&request)
                }
                PathQuery::Digest { digest, process } => {
                    walk.digest == digest && process.is_none_or(|process| walk.process == process)
                }
            }
        })
        .map(|(index, _)| index)
        .collect();
    let path = |index: usize| {
        let plan = state.plans[index].as_ref().unwrap();
        let mut nodes: Vec<u32> = plan
            .members
            .iter()
            .chain(plan.sinks.iter().map(|(_, node, _)| node))
            .map(|&node| body.node_ids[node as usize])
            .collect();
        nodes.sort_unstable();
        let mut edges: Vec<u32> = plan
            .edges
            .iter()
            .chain(plan.sinks.iter().map(|(_, _, edge)| edge))
            .map(|&edge| body.edge_ids[edge as usize])
            .collect();
        edges.sort_unstable();
        (nodes, edges)
    };
    let (mut nodes, mut edges) = (Vec::new(), Vec::new());
    let mut occurrences = 0;
    for &index in &matches {
        let (walk_nodes, walk_edges) = path(index);
        nodes.extend(walk_nodes);
        edges.extend(walk_edges);
        occurrences += state.scan.walks[index].occurrences;
    }
    nodes.sort_unstable();
    nodes.dedup();
    edges.sort_unstable();
    edges.dedup();
    let end = cursor.saturating_add(limit).min(matches.len());
    let page = matches.get(cursor..end).unwrap_or(&[]);
    let answer = PathsOut {
        schema: PATHS_SCHEMA,
        session_id: state.session.to_string(),
        generation: &state.generation,
        total: matches.len(),
        occurrences,
        nodes,
        edges,
        cursor,
        next_cursor: (end < matches.len()).then_some(end),
        paths: page
            .iter()
            .map(|&index| {
                let (walk, plan) = (
                    &state.scan.walks[index],
                    state.plans[index].as_ref().unwrap(),
                );
                let (nodes, edges) = path(index);
                PathOut {
                    process_id: walk.process,
                    isolate_key: (walk.isolate != 0).then(|| format!("{:016x}", walk.isolate)),
                    digest: hex::encode(walk.digest),
                    occurrences: walk.occurrences,
                    retained: plan.retained,
                    reason: plan.reason,
                    requests: walk.requests.len(),
                    nodes,
                    edges,
                }
            })
            .collect(),
    };
    Ok(serde_json::to_vec(&answer)?.into())
}
