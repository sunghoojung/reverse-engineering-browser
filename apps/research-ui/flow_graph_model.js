/* The session flow graph's data (protocol/flow-graph-v2.md): the model of
 * one generation's pages, the fold that draws pass-through frames as chain
 * cards and requests as rows, what each card says and how big it is, and the
 * compact form a fold crosses from the worker to the page in. Both the page
 * (flow_graph.js) and the Graph pane's worker (flow_graph_worker.js) load it;
 * nothing here touches the DOM. request_stack.js is loaded first. */
'use strict';

const FLOW_GRAPH_KIND_LABELS = Object.freeze({javascript: 'JavaScript', eval: 'eval · dynamic', wasm: 'Wasm', request: 'Request',
  navigation: 'Navigation', cookie_write: 'Cookie write', chain: 'Chain'});
const FLOW_GRAPH_KIND_TAGS = Object.freeze({javascript: 'js', eval: 'eval', wasm: 'wasm', request: 'request', navigation: 'nav', cookie_write: 'cookie', chain: 'chain'});
/* Row mnemonics: short enough to align in a column. */
const FLOW_GRAPH_OPS = Object.freeze({call: 'call', await: 'await', omitted: 'omitted', request: 'request', navigation: 'navigate', cookie_write: 'cookie',
  set_timeout: 'setTimeout', set_interval: 'setInterval', request_animation_frame: 'rAF', request_idle_callback: 'idle', post_message: 'postMessage',
  xhr_send: 'xhr.send', post_task: 'postTask', event: 'event', microtask: 'microtask'});
/* Why a frame is unresolved: the request stack reasons. */
const FLOW_GRAPH_REASONS = REQUEST_STACK_REASONS;
/* Why a task chain ends at a node without a cut (flow-graph-v2 `chain_ends`). */
const FLOW_GRAPH_CHAIN_ENDS = Object.freeze({no_script: 'no script scheduled it', origin_rejected: 'its message origin was rejected'});
/* Record types that carry a walked stack; the others only label or resolve one. */
const FLOW_GRAPH_STACK_RECORDS = ['request_initiator_stack', 'navigation_initiator_stack', 'async_task_stack'];
const FLOW_GRAPH_SINKS = new Set(['request', 'navigation', 'cookie_write']);
/* Card geometry, in graph units at zoom 1: a tinted header (name, stack
 * badge, kind pill), the location, then the rows, `page` at a time. A card
 * with more rows pages through them on its last row, so it stays one size
 * and every row stays on it. Text is monospace, so widths come from
 * character counts and one measured advance per font; the kind pill is
 * measured per tag. */
const FLOW_GRAPH_CARD = Object.freeze({head: 32, location: 22, gap: 2, row: 19, foot: 9, pad: 12, radius: 8, minW: 184, maxW: 440, page: 8});
const FLOW_GRAPH_MEASURE = Object.freeze({row: 6.93, head: 7.53, badge: 6.32, pill: 7});
/* Crossing bits of a folded edge, in the order its notes name them. */
const FLOW_GRAPH_CROSSES = Object.freeze(['frame', 'language', 'dynamic']);

/** Validates a `flow-graph-v2` document, its pages joined, into a model, or
 * throws. `valid` lists the edges that name two nodes of the document; the
 * others are dropped and counted, never drawn. */
function flowGraphModel(doc) {
  if (doc?.schema !== 'flow-graph-v2' || !Array.isArray(doc.nodes) || !Array.isArray(doc.edges) || !Array.isArray(doc.contexts))
    throw Error('The flow graph provider returned an invalid document.');
  const nodes = doc.nodes, count = nodes.length;
  const inRange = index => Number.isInteger(index) && index >= 0 && index < count;
  const valid = [];
  doc.edges.forEach((edge, index) => { if (inRange(edge?.from) && inRange(edge?.to)) valid.push(index); });
  const contexts = doc.contexts.map((context, index) => ({...context, index, label: flowGraphContextLabel(context, index)}));
  nodes.forEach(node => { if (!contexts[node.context]) node.context = 0; });
  return {doc, nodes, edges: doc.edges, valid, contexts, dropped: doc.edges.length - valid.length};
}

function flowGraphContextLabel(context, index) {
  const origin = context?.origin;
  if (context?.execution_context_id == null) return {title: 'Unidentified realm', detail: `process ${context?.process_id ?? '?'} · no script identity`};
  let title = origin ?? `Realm ${index + 1}`;
  try { if (origin && origin.includes('://')) title = new URL(origin).host || origin; } catch {}
  const frame = context.frame_ids?.[0]?.frame_id;
  const parts = [`realm ${context.execution_context_id}`];
  if (frame) parts.push(`frame ${frame}${context.frame_ids.length > 1 ? ` +${context.frame_ids.length - 1}` : ''}`);
  parts.push(`process ${context.process_id}`);
  return {title, detail: parts.join(' · '), origin};
}

/** The researcher name of a Wasm node's function (wasm_function_names.js),
 * keyed by its module SHA-256 and function index; null for anything else.
 * It is drawn beside the captured name, never instead of it. */
function flowGraphAnalystName(node) {
  if (node?.kind !== 'wasm' || typeof node.sha256 !== 'string') return null;
  return globalThis.RebWasmFunctionNames?.nameOf(node.sha256, node.function_index) ?? null;
}

function flowGraphNodeName(node) {
  if (!node) return '';
  if (node.kind === 'chain') return node.name;
  if (FLOW_GRAPH_SINKS.has(node.kind)) return node.name ?? node.kind;
  if (node.kind === 'wasm') return node.name ?? `wasm-function[${node.function_index}]`;
  if (node.top_level) return '(top level)';
  return node.name ?? (node.status === 'resolved' ? '(anonymous)' : `(script ${node.script_id})`);
}

/** The file a script node names: `VM<id>` for eval code, as DevTools
 * does, else its URL, or that URL's file name when `short`. */
function flowGraphNodeFile(node, short = false) {
  if (node.kind === 'eval') return `VM${node.script_id}`;
  return short ? requestStackFile(node.url) : node.url ?? '';
}

function flowGraphNodeDetail(node) {
  if (!node) return '';
  if (node.kind === 'chain') return `${node.members.length} functions · Space expands`;
  if (FLOW_GRAPH_SINKS.has(node.kind)) return `${node.hits.toLocaleString()} ${node.hits === 1 ? 'time' : 'times'}`;
  if (node.status !== 'resolved') return FLOW_GRAPH_REASONS[node.reason] ?? node.reason ?? 'unresolved';
  if (node.kind === 'wasm') return `func ${node.function_index} · ${requestStackFile(node.url)}`;
  const file = flowGraphNodeFile(node, true);
  return node.line ? `${file}:${node.line}:${node.column}` : file;
}

/** Why task chains end at a node without a cut, with the task kinds. */
function flowGraphChainEnds(node) {
  return (node.chain_ends ?? []).map(end => `${FLOW_GRAPH_CHAIN_ENDS[end.reason] ?? end.reason} (${REQUEST_STACK_TASKS[end.task] ?? end.task} ×${end.count.toLocaleString()})`).join(', ');
}

/** The full location a researcher copies: URL, line and column. */
function flowGraphNodeLocation(node) {
  if (!node || node.kind === 'chain') return '';
  if (FLOW_GRAPH_SINKS.has(node.kind)) return node.name ?? '';
  if (node.status !== 'resolved') return '';
  if (node.kind === 'wasm') return `${node.url ?? ''} func ${node.function_index}`.trim();
  const file = flowGraphNodeFile(node);
  return node.line ? `${file}:${node.line}:${node.column}` : file;
}

/** The same function across two generations of one session: node ids are
 * positions and change when the graph does. */
function flowGraphNodeKey(node) {
  if (!node) return '';
  return [node.kind, node.context, node.script_id ?? '', node.function_position ?? node.function_index ?? '', node.top_level ? 'top' : '', node.name ?? '', node.line ?? '', node.column ?? ''].join('|');
}

/** A node with one call in and one call out, inside one realm, that every path
 * through it continues the same way: a frame of a wrapper or a framework that
 * adds nothing to read. Runs of two or more fold into one chain card. A
 * request, navigation or cookie write is a row of each function that made it,
 * the way a disassembly lists a call to an import, unless nothing calls it. */
function flowGraphDisplay(model, expanded = new Set(), collapse = true) {
  const {nodes, edges, valid} = model, count = nodes.length;
  const ins = Array.from({length: count}, () => []), outs = Array.from({length: count}, () => []), recursive = new Uint8Array(count);
  for (const index of valid) {
    const edge = edges[index];
    if (edge.from === edge.to) { recursive[edge.from] = 1; continue; }
    outs[edge.from].push(edge);
    ins[edge.to].push(edge);
  }
  const quiet = edge => edge.kind === 'call' && !edge.crosses?.length;
  const passes = new Uint8Array(count);
  if (collapse) for (let v = 0; v < count; v += 1) {
    const node = nodes[v];
    // Recursion stays visible: a function that calls itself is never folded.
    if (!['javascript', 'eval', 'wasm'].includes(node.kind) || node.chain_cut || recursive[v] || ins[v].length !== 1 || outs[v].length !== 1) continue;
    const [inbound] = ins[v], [outbound] = outs[v];
    if (quiet(inbound) && quiet(outbound) && inbound.count === outbound.count && nodes[inbound.from].context === node.context && nodes[outbound.to].context === node.context) passes[v] = 1;
  }
  const group = new Int32Array(count).fill(-1), groups = [], visited = new Uint8Array(count), foldKey = new Map();
  for (let v = 0; v < count; v += 1) {
    if (!passes[v] || visited[v]) continue;
    // Walk to the first member of this run, then collect it forward.
    let first = v;
    for (let guard = 0; guard < count; guard += 1) { const previous = ins[first][0].from; if (!passes[previous] || previous === v) break; first = previous; }
    const members = [];
    for (let at = first; passes[at] && !visited[at] && members.length < count; at = outs[at][0].to) { members.push(at); visited[at] = 1; }
    if (members.length < 2) continue;
    if (expanded.has(String(members[0]))) { members.forEach(member => foldKey.set(member, String(members[0]))); continue; }
    members.forEach(member => { group[member] = groups.length; });
    groups.push(members);
  }
  const display = [], displayOf = new Int32Array(count);
  for (let v = 0; v < count; v += 1) {
    if (group[v] >= 0) {
      const members = groups[group[v]];
      if (members[0] !== v) { displayOf[v] = displayOf[members[0]]; continue; }
      displayOf[v] = display.length;
      display.push(flowGraphChainNode(model, members));
    } else {
      displayOf[v] = display.length;
      display.push({...nodes[v], members: [v], key: String(v)});
    }
  }
  // Groups are contiguous runs, so a member reached before its head still maps.
  for (const members of groups) for (const member of members) displayOf[member] = displayOf[members[0]];
  const merged = new Map(), list = [];
  for (const index of valid) {
    const edge = edges[index], from = displayOf[edge.from], to = displayOf[edge.to];
    if (from === to && edge.from !== edge.to) continue;
    const key = `${from}:${to}:${edge.kind}:${edge.task ?? ''}`;
    let item = merged.get(key);
    if (!item) { item = {from, to, kind: edge.kind, task: edge.task, via: edge.via, label: edge.label, omitted: edge.omitted, crosses: new Set(), count: 0, members: []}; merged.set(key, item); list.push(item); }
    edge.crosses?.forEach(cross => item.crosses.add(cross));
    item.count += edge.count ?? 0;
    item.members.push(index);
  }
  list.forEach(item => { item.crosses = FLOW_GRAPH_CROSSES.filter(cross => item.crosses.has(cross)); });
  const called = new Uint8Array(display.length);
  for (const item of list) called[item.to] = 1;
  const keep = display.map((node, index) => !(FLOW_GRAPH_SINKS.has(node.kind) && called[index]));
  const remap = new Int32Array(display.length).fill(-1);
  let kept = 0;
  keep.forEach((yes, index) => { if (yes) remap[index] = kept++; });
  const sinkRows = Array.from({length: kept}, () => []), drawn = [];
  for (const item of list) {
    if (!keep[item.to]) { if (keep[item.from]) sinkRows[remap[item.from]].push({...item, from: remap[item.from], to: -1, sink: display[item.to]}); continue; }
    if (keep[item.from]) drawn.push({...item, from: remap[item.from], to: remap[item.to]});
  }
  for (let v = 0; v < count; v += 1) displayOf[v] = remap[displayOf[v]];
  const shown = display.filter((node, index) => keep[index]);
  return flowGraphIndexDisplay({nodes: shown, edges: drawn, sinkRows, displayOf, groups: groups.length, foldKey}, edges.length);
}

/** A chain card: the members of a pass-through run, named by its ends. */
function flowGraphChainNode(model, members) {
  const head = model.nodes[members[0]], tail = model.nodes[members.at(-1)];
  return {kind: 'chain', key: String(members[0]), members, context: head.context, hits: head.hits, entries: 0, leaves: 0,
    name: `${flowGraphNodeName(head)} → ${flowGraphNodeName(tail)}`, status: 'resolved'};
}

/** Each card's drawn edges in and out, the drawn edge each document edge is
 * in, and the heaviest edge. */
function flowGraphIndexDisplay(display, documentEdges) {
  const inbound = display.nodes.map(() => []), outbound = display.nodes.map(() => []), edgeOf = new Int32Array(documentEdges).fill(-1);
  let maxCount = 1;
  display.edges.forEach((edge, index) => {
    outbound[edge.from].push(index);
    inbound[edge.to].push(index);
    for (const member of edge.members) edgeOf[member] = index;
    if (edge.count > maxCount) maxCount = edge.count;
  });
  return {...display, ins: inbound, outs: outbound, edgeOf, maxCount};
}

/** What colours an edge: a crossing (frame, JavaScript and Wasm, into eval)
 * first, then an await or task, a request, navigation or cookie write, frames
 * omitted, else a plain call. */
const flowGraphEdgeFamily = edge => edge.crosses?.length ? 'cross' : edge.kind === 'await' || edge.kind === 'task' ? 'async'
  : FLOW_GRAPH_SINKS.has(edge.kind) ? 'sink' : edge.kind === 'omitted' ? 'omitted' : 'call';

/** What an edge's row says after the callee: the boundary it crosses, the
 * hops it went through and what was dropped. */
function flowGraphEdgeNote(model, display, edge) {
  const parts = [];
  if (edge.crosses?.includes('frame')) parts.push(`→ ${model.contexts[display.nodes[edge.to]?.context]?.label.title ?? 'realm'}`);
  if (edge.crosses?.includes('language')) parts.push(`${display.nodes[edge.from]?.kind === 'wasm' ? 'Wasm' : 'JS'} → ${display.nodes[edge.to]?.kind === 'wasm' ? 'Wasm' : 'JS'}`);
  if (edge.crosses?.includes('dynamic')) parts.push('into eval');
  if (edge.label) parts.push(edge.label);
  if (edge.via?.length) parts.push(`via ${edge.via.join(', ')}`);
  if (edge.kind === 'omitted') parts.push(`${(edge.omitted ?? 0).toLocaleString()} frames`);
  if (edge.from === edge.to) parts.push('recursion');
  return parts.join(' · ');
}

/** Call sites of a display edge, from the document's edges it merges. */
function flowGraphEdgeSites(model, edge) {
  const sites = [];
  for (const member of edge.members ?? []) for (const site of model.edges[member]?.sites ?? []) {
    const text = site.module_offset !== undefined ? `+0x${Number(site.module_offset).toString(16)}` : `${site.line}:${site.column}`;
    if (!sites.includes(text)) sites.push(text);
  }
  return sites;
}

/** Distinct stacks through a card: its node's, or for a chain the most of
 * any member's, since every stack through a pass-through frame walks its
 * neighbours too. */
function flowGraphStacks(model, node) {
  let most = 0;
  for (const member of node.members) most = Math.max(most, model.nodes[member]?.stacks ?? 0);
  return most;
}

/* Rows read in source order: by kind, then line and column (or module
 * offset), then the order the edges were drawn in. */
const FLOW_GRAPH_ROW_RANK = Object.freeze({call: 0, await: 1, task: 2, omitted: 3, request: 4, navigation: 4, cookie_write: 4});
const FLOW_GRAPH_SINK_NOUNS = Object.freeze({request: ['request', 'requests'], navigation: ['navigation', 'navigations'], cookie_write: ['cookie write', 'cookie writes']});

/** The row a call gives its card: `edge` is a drawn edge with its display
 * `index`, or a sink row with index -1. */
function flowGraphCardRow(model, display, edge, index) {
  const sites = flowGraphEdgeSites(model, edge);
  const first = edge.members.map(member => model.edges[member]?.sites?.[0]).find(Boolean);
  const order = [FLOW_GRAPH_ROW_RANK[edge.kind] ?? 5, first ? first.line ?? 0 : 1e15, first ? first.column ?? first.module_offset ?? 0 : 0, index < 0 ? 1e9 : index];
  return {
    site: sites[0] ? `${sites[0]}${sites.length > 1 ? `+${sites.length - 1}` : ''}` : '',
    op: FLOW_GRAPH_OPS[edge.kind === 'task' ? edge.task : edge.kind] ?? edge.task ?? edge.kind,
    target: flowGraphNodeName(edge.sink ?? display.nodes[edge.to]),
    note: edge.sink ? '' : flowGraphEdgeNote(model, display, edge),
    count: edge.count > 1 ? `×${edge.count.toLocaleString()}` : '',
    edge: index,
    sink: edge.sink ?? null,
    members: edge.members,
    family: edge.sink ? 'sink' : flowGraphEdgeFamily(edge),
    order
  };
}
const flowGraphRowOrder = (a, b) => a.order[0] - b.order[0] || a.order[1] - b.order[1] || a.order[2] - b.order[2] || a.order[3] - b.order[3];

/** A chain card's rows: its folded members, numbered. */
const flowGraphChainRows = (model, node) => node.members.map((member, i) => ({site: String(i + 1), op: '', target: flowGraphNodeName(model.nodes[member]), note: flowGraphNodeDetail(model.nodes[member]), count: '', edge: -1}));

/** What card `v` says: its name, a badge with the distinct stacks through
 * it, its kind tag and location, then one row per call it made (site,
 * mnemonic, callee and a note), the way a disassembly block lists its
 * instructions. Its size follows from the text: wide enough for every row,
 * and tall enough for one page of them and the pager row when there are
 * more. `measure` holds the font advances and each tag's pill width. */
function flowGraphCard(model, display, v, measure = FLOW_GRAPH_MEASURE) {
  const C = FLOW_GRAPH_CARD, node = display.nodes[v];
  const chain = node.kind === 'chain', sink = FLOW_GRAPH_SINKS.has(node.kind);
  const rows = chain ? flowGraphChainRows(model, node) : [
    ...display.outs[v].map(index => flowGraphCardRow(model, display, display.edges[index], index)),
    ...display.sinkRows[v].map(edge => flowGraphCardRow(model, display, edge, -1))
  ].sort(flowGraphRowOrder);
  const location = sink ? `${node.hits.toLocaleString()} ${FLOW_GRAPH_SINK_NOUNS[node.kind][node.hits === 1 ? 0 : 1]}` : chain ? `${node.members.length} pass-through frames, folded` : flowGraphNodeDetail(node);
  const stacks = flowGraphStacks(model, node);
  const title = flowGraphNodeName(node), tag = FLOW_GRAPH_KIND_TAGS[node.kind] ?? node.kind, badge = stacks.toLocaleString();
  const siteW = rows.reduce((max, row) => Math.max(max, row.site.length), 0), opW = rows.reduce((max, row) => Math.max(max, row.op.length), 0);
  const pillW = Math.ceil((measure.pills?.[tag] ?? tag.length * measure.pill) + 12), badgeW = Math.ceil(badge.length * measure.badge + 10);
  const headW = C.pad * 2 + title.length * measure.head + 12 + badgeW + 6 + pillW;
  const paged = rows.length > C.page, pager = paged ? flowGraphPagerText(rows.length - C.page, rows.length, C.page) : '';
  let rowW = C.pad * 2 + Math.max(location.length, pager.length + 4) * measure.badge;
  for (const row of rows) {
    rowW = Math.max(rowW, C.pad * 2 + (siteW ? siteW * measure.row + 12 : 0) + (opW ? opW * measure.row + 10 : 0) + row.target.length * measure.row
      + (row.note ? 10 + (row.note.length + 2) * measure.row : 0) + (row.count ? 12 + row.count.length * measure.row : 0));
  }
  const w = Math.round(Math.max(C.minW, Math.min(C.maxW, Math.max(headW, rowW))));
  const h = C.head + C.location + C.gap + (Math.min(rows.length, C.page) + (paged ? 1 : 0)) * C.row + C.foot;
  return {title, tag, badge, stacks, badgeW, pillW, location, rows, paged, siteW: siteW * measure.row, opW: opW * measure.row, w, h};
}

/** The pager row of a card whose rows start at `first`: which rows show,
 * of how many. */
function flowGraphPagerText(first, total, page = FLOW_GRAPH_CARD.page) {
  return `${(first + 1).toLocaleString()}-${Math.min(total, first + page).toLocaleString()} of ${total.toLocaleString()}`;
}

/** Every card's size, as the layout needs them. */
function flowGraphCardSizes(model, display, measure) {
  const count = display.nodes.length, w = new Float32Array(count), h = new Float32Array(count);
  for (let v = 0; v < count; v += 1) { const card = flowGraphCard(model, display, v, measure); w[v] = card.w; h[v] = card.h; }
  return {w, h};
}

/** The arrays the layout needs. */
function flowGraphLayoutInput(display, sizes = null) {
  const count = display.nodes.length;
  const input = {count, lane: Int32Array.from(display.nodes, node => node.context), weight: Float64Array.from(display.nodes, node => node.hits ?? 0),
    from: Int32Array.from(display.edges, edge => edge.from), to: Int32Array.from(display.edges, edge => edge.to)};
  if (sizes) { input.w = sizes.w; input.h = sizes.h; }
  return input;
}

/** How many drawn edges cross a frame, JavaScript and Wasm, or into eval. */
function flowGraphCrossings(display) {
  const counts = {frame: 0, language: 0, dynamic: 0};
  for (const edge of display?.edges ?? []) for (const cross of edge.crosses) if (cross in counts) counts[cross] += 1;
  return counts;
}

/** What Find matches on card `index`: its names, file, host, folded
 * members and the requests it made. */
function flowGraphFindText(model, display, index) {
  const node = display.nodes[index];
  return [flowGraphNodeName(node), flowGraphNodeDetail(node), node.url ?? '', model.contexts[node.context]?.label.title ?? '',
    ...(node.kind === 'chain' ? node.members.map(member => flowGraphNodeName(model.nodes[member])) : []), ...display.sinkRows[index].map(row => flowGraphNodeName(row.sink))].join(' ').toLowerCase();
}

/** Highlight sets from a paths answer (flow-graph-paths-v1): the cards and
 * drawn edges its stacks walk, with the document edges for the rows. */
function flowGraphHighlight(display, answer) {
  const nodes = new Set(), edges = new Set(), originalEdges = new Set(answer.edges);
  for (const node of answer.nodes) { const at = display.displayOf[node]; if (at >= 0) nodes.add(at); }
  for (const edge of answer.edges) { const at = display.edgeOf[edge]; if (at >= 0) edges.add(at); }
  return {nodes, edges, originalEdges, paths: answer.total, occurrences: answer.occurrences};
}

/* A fold crosses from the worker to the page as typed arrays, so neither
 * side copies an object per card or edge through structured clone. Lists
 * are compressed rows: `start` has one more entry than items. */
const flowGraphRows = (lists, index = list => list) => {
  const start = new Uint32Array(lists.length + 1);
  lists.forEach((list, i) => { start[i + 1] = start[i] + index(list).length; });
  const items = new Int32Array(start[lists.length]);
  lists.forEach((list, i) => items.set(index(list), start[i]));
  return {start, items};
};
const flowGraphCrossBits = crosses => crosses.reduce((bits, cross) => bits | (1 << FLOW_GRAPH_CROSSES.indexOf(cross)), 0);

/** The transferable form of a fold. */
function flowGraphPack(display, modelNodes) {
  const sinks = display.sinkRows.flatMap(rows => rows);
  const foldOf = new Int32Array(modelNodes).fill(-1);
  display.foldKey.forEach((key, member) => { foldOf[member] = Number(key); });
  const packed = {
    count: display.nodes.length, groups: display.groups, maxCount: display.maxCount,
    chain: Uint8Array.from(display.nodes, node => (node.kind === 'chain' ? 1 : 0)), members: flowGraphRows(display.nodes, node => node.members),
    from: Int32Array.from(display.edges, edge => edge.from), to: Int32Array.from(display.edges, edge => edge.to),
    edgeCount: Float64Array.from(display.edges, edge => edge.count), cross: Uint8Array.from(display.edges, edge => flowGraphCrossBits(edge.crosses)),
    edgeMembers: flowGraphRows(display.edges, edge => edge.members),
    sinkFrom: Int32Array.from(sinks, row => row.from), sinkNode: Int32Array.from(sinks, row => row.sink.members[0]), sinkCount: Float64Array.from(sinks, row => row.count),
    sinkCross: Uint8Array.from(sinks, row => flowGraphCrossBits(row.crosses)), sinkMembers: flowGraphRows(sinks, row => row.members),
    displayOf: display.displayOf.slice(), edgeOf: display.edgeOf.slice(), foldOf
  };
  return packed;
}
const flowGraphPackTransfer = packed => [packed.chain, packed.members.start, packed.members.items, packed.from, packed.to, packed.edgeCount, packed.cross,
  packed.edgeMembers.start, packed.edgeMembers.items, packed.sinkFrom, packed.sinkNode, packed.sinkCount, packed.sinkCross, packed.sinkMembers.start,
  packed.sinkMembers.items, packed.displayOf, packed.edgeOf, packed.foldOf].map(array => array.buffer);

/** A packed fold back into the display flowGraphDisplay returns, over the
 * page's copy of the model. It runs in slices of `slice` items, awaiting
 * `pause` between them, so a large graph never holds the page for long. */
async function flowGraphUnpack(model, packed, {slice = 16384, pause = async () => {}} = {}) {
  const rows = (list, i) => Array.from(list.items.subarray(list.start[i], list.start[i + 1]));
  const crosses = bits => FLOW_GRAPH_CROSSES.filter((cross, i) => bits & (1 << i));
  const edgeOf = (members, from, to, count, bits) => {
    const first = model.edges[members[0]];
    return {from, to, kind: first.kind, task: first.task, via: first.via, label: first.label, omitted: first.omitted, crosses: crosses(bits), count, members};
  };
  const nodes = new Array(packed.count), edges = new Array(packed.from.length), sinkRows = Array.from({length: packed.count}, () => []);
  for (let v = 0; v < packed.count; v += 1) {
    if (v && v % slice === 0) await pause();
    const members = rows(packed.members, v);
    nodes[v] = packed.chain[v] ? flowGraphChainNode(model, members) : {...model.nodes[members[0]], members, key: String(members[0])};
  }
  for (let e = 0; e < edges.length; e += 1) {
    if (e && e % slice === 0) await pause();
    edges[e] = edgeOf(rows(packed.edgeMembers, e), packed.from[e], packed.to[e], packed.edgeCount[e], packed.cross[e]);
  }
  for (let s = 0; s < packed.sinkFrom.length; s += 1) {
    if (s && s % slice === 0) await pause();
    const sink = packed.sinkNode[s];
    sinkRows[packed.sinkFrom[s]].push({...edgeOf(rows(packed.sinkMembers, s), packed.sinkFrom[s], -1, packed.sinkCount[s], packed.sinkCross[s]),
      sink: {...model.nodes[sink], members: [sink], key: String(sink)}});
  }
  const foldKey = new Map();
  packed.foldOf.forEach((key, member) => { if (key >= 0) foldKey.set(member, String(key)); });
  const display = {nodes, edges, sinkRows, displayOf: packed.displayOf, groups: packed.groups, foldKey};
  const ins = nodes.map(() => []), outs = nodes.map(() => []);
  edges.forEach((edge, index) => { outs[edge.from].push(index); ins[edge.to].push(index); });
  return {...display, ins, outs, edgeOf: packed.edgeOf, maxCount: packed.maxCount};
}
