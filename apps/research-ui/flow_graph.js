/* Session flow graph (protocol/flow-graph-v1.md): every recorded stack of one
 * session as one graph of functions, read top to bottom like a disassembler's
 * CFG. Realms are full-width bands stacked in call order. A card lists the
 * calls its function made, one row each, the way a disassembly block lists its
 * instructions; its header is tinted by its kind (JavaScript, Wasm, eval, a
 * request), and edges are coloured by what they are: a call, an await or task,
 * a crossing (a frame, JavaScript and Wasm, a call into eval) or a request. A
 * call into a same-process iframe, a posted task into one, a JavaScript to
 * Wasm call and a call into eval code also say so on their row. The drawing is
 * one canvas and layout runs in flow_graph_layout.js as a Web Worker. Captured
 * names and URLs are painted as glyphs or inserted as text. */
const FLOW_GRAPH_KIND_LABELS = Object.freeze({javascript: 'JavaScript', eval: 'eval · dynamic', wasm: 'Wasm', request: 'Request',
  navigation: 'Navigation', cookie_write: 'Cookie write', chain: 'Chain'});
const FLOW_GRAPH_KIND_TAGS = Object.freeze({javascript: 'js', eval: 'eval', wasm: 'wasm', request: 'request', navigation: 'nav', cookie_write: 'cookie', chain: 'chain'});
/* The CSS custom property stem of each kind: --flow-<stem> is its hue and
 * --flow-<stem>-ink its text colour. */
const FLOW_GRAPH_KIND_TOKENS = Object.freeze({javascript: 'js', eval: 'eval', wasm: 'wasm', request: 'request', navigation: 'navigation', cookie_write: 'cookie', chain: 'chain'});
const FLOW_GRAPH_EDGE_FAMILIES = Object.freeze(['call', 'async', 'cross', 'sink', 'omitted']);
/* Realm bands cycle --flow-realm-0 to -5. */
const FLOW_GRAPH_REALM_HUES = 6;
const FLOW_GRAPH_TASKS = Object.freeze({set_timeout: 'setTimeout', set_interval: 'setInterval', request_animation_frame: 'requestAnimationFrame',
  request_idle_callback: 'requestIdleCallback', post_message: 'postMessage', xhr_send: 'XMLHttpRequest.send', post_task: 'scheduler.postTask',
  event: 'event', microtask: 'microtask'});
/* Row mnemonics: short enough to align in a column. */
const FLOW_GRAPH_OPS = Object.freeze({call: 'call', await: 'await', omitted: 'omitted', request: 'request', navigation: 'navigate', cookie_write: 'cookie',
  set_timeout: 'setTimeout', set_interval: 'setInterval', request_animation_frame: 'rAF', request_idle_callback: 'idle', post_message: 'postMessage',
  xhr_send: 'xhr.send', post_task: 'postTask', event: 'event', microtask: 'microtask'});
const FLOW_GRAPH_REASONS = Object.freeze({script_identity_missing: 'no script identity record', source_unavailable: 'source unavailable',
  source_not_retained: 'source not retained', source_artifact_missing: 'source artifact missing', source_artifact_unreadable: 'source artifact unreadable',
  source_not_utf8: 'source is not UTF-8', source_budget: 'source read budget reached', source_deadline: 'read deadline reached before this source',
  position_outside_source: 'position outside the retained source'});
/* Record types that carry a walked stack; the others only label or resolve one. */
const FLOW_GRAPH_STACK_RECORDS = ['request_initiator_stack', 'navigation_initiator_stack', 'async_task_stack'];
const FLOW_GRAPH_LIMITS = 'Observed stacks only. A call that never reached a recorded request, navigation, task or cookie write is not drawn.';
const FLOW_GRAPH_CANVAS_BYTES = 32 * 1024 * 1024;
/* At and above this zoom a card shows its rows; below it, its name is painted
 * at screen size over a sketch of the rows, and below the sketch zoom only
 * boxes remain. */
const FLOW_GRAPH_TEXT_ZOOM = 0.85;
const FLOW_GRAPH_SKETCH_ZOOM = 0.2;
/* The first view fits the whole graph when its rows stay legible; a taller
 * or wider one opens at reading size at its top, never as an unreadable
 * overview: the minimap is the overview. Below this zoom it centres on the
 * busiest entry of the first band instead of the whole width. */
const FLOW_GRAPH_START_ZOOM = 0.92;
const FLOW_GRAPH_SINKS = new Set(['request', 'navigation', 'cookie_write']);
/* Card geometry, in graph units at zoom 1: a tinted header (name, stack
 * badge, kind pill), the location, then the rows. Text is monospace, so widths
 * come from character counts and one measured advance per font; the kind pill
 * is measured per tag. */
const FLOW_GRAPH_CARD = Object.freeze({head: 32, location: 22, gap: 2, row: 19, foot: 9, pad: 12, radius: 8, minW: 184, maxW: 440, rows: 8});
const FLOW_GRAPH_MEASURE = Object.freeze({row: 6.93, head: 7.53, badge: 6.32, pill: 7});

function flowGraphFile(url) {
  const text = String(url ?? '');
  try {
    const parsed = new URL(text);
    return parsed.pathname.split('/').filter(Boolean).pop() || parsed.host || text;
  } catch { return text; }
}

/** Validates a `flow-graph-v1` document into a model, or throws. Edges that
 * name a node outside the document are dropped and counted, never drawn. */
function flowGraphModel(doc) {
  if (doc?.schema !== 'flow-graph-v1' || !Array.isArray(doc.nodes) || !Array.isArray(doc.edges) || !Array.isArray(doc.contexts) || !Array.isArray(doc.paths))
    throw Error('The flow graph provider returned an invalid document.');
  const nodes = doc.nodes, count = nodes.length;
  const valid = index => Number.isInteger(index) && index >= 0 && index < count;
  let dropped = 0;
  const edges = [];
  doc.edges.forEach((edge, index) => { if (valid(edge?.from) && valid(edge?.to)) edges.push({...edge, index}); else dropped += 1; });
  const contexts = doc.contexts.map((context, index) => ({...context, index, label: flowGraphContextLabel(context, index)}));
  nodes.forEach(node => { if (!contexts[node.context]) node.context = 0; });
  return {doc, nodes, edges, contexts, paths: doc.paths, dropped};
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

function flowGraphNodeName(node) {
  if (!node) return '';
  if (node.kind === 'chain') return node.name;
  if (FLOW_GRAPH_SINKS.has(node.kind)) return node.name ?? node.kind;
  if (node.kind === 'wasm') return node.name ?? `wasm-function[${node.function_index}]`;
  if (node.top_level) return '(top level)';
  return node.name ?? (node.status === 'resolved' ? '(anonymous)' : `(script ${node.script_id})`);
}

function flowGraphNodeDetail(node) {
  if (!node) return '';
  if (node.kind === 'chain') return `${node.members.length} functions · Space expands`;
  if (FLOW_GRAPH_SINKS.has(node.kind)) return `${node.hits.toLocaleString()} ${node.hits === 1 ? 'time' : 'times'}`;
  if (node.status !== 'resolved') return FLOW_GRAPH_REASONS[node.reason] ?? node.reason ?? 'unresolved';
  if (node.kind === 'wasm') return `func ${node.function_index} · ${flowGraphFile(node.url)}`;
  const file = node.kind === 'eval' ? `VM${node.script_id}` : flowGraphFile(node.url);
  return node.line ? `${file}:${node.line}:${node.column}` : file;
}

/** The full location a researcher copies: URL, line and column. */
function flowGraphNodeLocation(node) {
  if (!node || node.kind === 'chain') return '';
  if (FLOW_GRAPH_SINKS.has(node.kind)) return node.name ?? '';
  if (node.status !== 'resolved') return '';
  if (node.kind === 'wasm') return `${node.url ?? ''} func ${node.function_index}`.trim();
  const file = node.kind === 'eval' ? `VM${node.script_id}` : node.url ?? '';
  return node.line ? `${file}:${node.line}:${node.column}` : file;
}

/** The same function across two answers of one session: node ids are
 * positions and change when new stacks arrive. */
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
  const {nodes, edges} = model, count = nodes.length;
  const ins = Array.from({length: count}, () => []), outs = Array.from({length: count}, () => []), recursive = new Uint8Array(count);
  for (const edge of edges) { if (edge.from === edge.to) { recursive[edge.from] = 1; continue; } outs[edge.from].push(edge); ins[edge.to].push(edge); }
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
      const head = nodes[members[0]], tail = nodes[members.at(-1)];
      displayOf[v] = display.length;
      display.push({kind: 'chain', key: String(members[0]), members, context: head.context, hits: head.hits, entries: 0, leaves: 0,
        name: `${flowGraphNodeName(head)} → ${flowGraphNodeName(tail)}`, status: 'resolved'});
    } else {
      displayOf[v] = display.length;
      display.push({...nodes[v], members: [v], key: String(v)});
    }
  }
  // Groups are contiguous runs, so a member reached before its head still maps.
  for (const members of groups) for (const member of members) displayOf[member] = displayOf[members[0]];
  const merged = new Map(), list = [];
  for (const edge of edges) {
    const from = displayOf[edge.from], to = displayOf[edge.to];
    if (from === to && edge.from !== edge.to) continue;
    const key = `${from}:${to}:${edge.kind}:${edge.task ?? ''}`;
    let item = merged.get(key);
    if (!item) { item = {from, to, kind: edge.kind, task: edge.task, via: edge.via, label: edge.label, omitted: edge.omitted, crosses: new Set(), count: 0, members: []}; merged.set(key, item); list.push(item); }
    edge.crosses?.forEach(cross => item.crosses.add(cross));
    item.count += edge.count ?? 0; item.members.push(edge.index);
  }
  list.forEach(item => { item.crosses = [...item.crosses]; });
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
  return {nodes: display.filter((node, index) => keep[index]), edges: drawn, sinkRows, displayOf, groups: groups.length, foldKey};
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
  for (const member of edge.members ?? []) for (const site of model.doc.edges[member]?.sites ?? []) {
    const text = site.module_offset !== undefined ? `+0x${Number(site.module_offset).toString(16)}` : `${site.line}:${site.column}`;
    if (!sites.includes(text)) sites.push(text);
  }
  return sites;
}

/** Distinct stacks (paths) through each display node, each counted once. */
function flowGraphDistinctStacks(model, display) {
  const counts = new Uint32Array(display.nodes.length), seen = new Int32Array(display.nodes.length).fill(-1);
  model.paths.forEach((path, index) => {
    for (const node of path.nodes ?? []) { const at = display.displayOf[node]; if (at >= 0 && seen[at] !== index) { seen[at] = index; counts[at] += 1; } }
  });
  return counts;
}

/** What each card says: its name, a badge with the distinct stacks through
 * it, its kind tag and location, then one row per call it made (site,
 * mnemonic, callee and a note), the way a disassembly block lists its
 * instructions. Sizes follow from the text. */
function flowGraphCards(model, display, measure = FLOW_GRAPH_MEASURE) {
  const C = FLOW_GRAPH_CARD, outs = display.nodes.map(() => []);
  display.edges.forEach((edge, index) => outs[edge.from].push(index));
  const stacks = flowGraphDistinctStacks(model, display);
  const rank = {call: 0, await: 1, task: 2, omitted: 3, request: 4, navigation: 4, cookie_write: 4};
  return display.nodes.map((node, v) => {
    const chain = node.kind === 'chain', sink = FLOW_GRAPH_SINKS.has(node.kind);
    let rows = [];
    if (chain) rows = node.members.map((member, i) => ({site: String(i + 1), op: '', target: flowGraphNodeName(model.nodes[member]), note: flowGraphNodeDetail(model.nodes[member]), count: '', edge: -1}));
    else rows = [...outs[v].map(index => ({edge: display.edges[index], index})), ...(display.sinkRows?.[v] ?? []).map(edge => ({edge, index: -1}))].map(({edge, index}) => {
      const sites = flowGraphEdgeSites(model, edge), first = edge.members.map(member => model.doc.edges[member]?.sites?.[0]).find(Boolean);
      // Rows read in source order: by kind, then line and column (or module offset).
      const order = [rank[edge.kind] ?? 5, first ? first.line ?? 0 : 1e15, first ? first.column ?? first.module_offset ?? 0 : 0];
      return {site: sites[0] ? `${sites[0]}${sites.length > 1 ? `+${sites.length - 1}` : ''}` : '', op: FLOW_GRAPH_OPS[edge.kind === 'task' ? edge.task : edge.kind] ?? edge.task ?? edge.kind,
        target: edge.sink ? flowGraphNodeName(edge.sink) : flowGraphNodeName(display.nodes[edge.to]), note: edge.sink ? '' : flowGraphEdgeNote(model, display, edge),
        count: edge.count > 1 ? `×${edge.count.toLocaleString()}` : '', edge: index, sink: edge.sink ?? null, members: edge.members, family: edge.sink ? 'sink' : flowGraphEdgeFamily(edge), order: order.concat(index < 0 ? 1e9 : index)};
    }).sort((a, b) => a.order[0] - b.order[0] || a.order[1] - b.order[1] || a.order[2] - b.order[2] || a.order[3] - b.order[3]);
    let more = 0;
    if (rows.length > C.rows) { more = rows.length - (C.rows - 1); rows = rows.slice(0, C.rows - 1); }
    const nouns = {request: ['request', 'requests'], navigation: ['navigation', 'navigations'], cookie_write: ['cookie write', 'cookie writes']};
    const location = sink ? `${node.hits.toLocaleString()} ${nouns[node.kind][node.hits === 1 ? 0 : 1]}` : chain ? `${node.members.length} pass-through frames, folded` : flowGraphNodeDetail(node);
    const title = flowGraphNodeName(node), tag = FLOW_GRAPH_KIND_TAGS[node.kind] ?? node.kind, badge = stacks[v].toLocaleString();
    const siteW = rows.reduce((max, row) => Math.max(max, row.site.length), 0), opW = rows.reduce((max, row) => Math.max(max, row.op.length), 0);
    const pillW = Math.ceil((measure.pillWidth ? measure.pillWidth(tag) : tag.length * measure.pill) + 12), badgeW = Math.ceil(badge.length * measure.badge + 10);
    const headW = C.pad * 2 + title.length * measure.head + 12 + badgeW + 6 + pillW;
    let rowW = C.pad * 2 + location.length * measure.badge;
    for (const row of rows) {
      rowW = Math.max(rowW, C.pad * 2 + (siteW ? siteW * measure.row + 12 : 0) + (opW ? opW * measure.row + 10 : 0) + row.target.length * measure.row
        + (row.note ? 10 + (row.note.length + 2) * measure.row : 0) + (row.count ? 12 + row.count.length * measure.row : 0));
    }
    const w = Math.round(Math.max(C.minW, Math.min(C.maxW, Math.max(headW, rowW))));
    const h = C.head + C.location + C.gap + (rows.length + (more ? 1 : 0)) * C.row + C.foot;
    return {title, tag, badge, stacks: stacks[v], badgeW, pillW, location, rows, more, siteW: siteW * measure.row, opW: opW * measure.row, w, h};
  });
}

/** The arrays the layout worker needs. */
function flowGraphLayoutInput(display, cards = null) {
  const count = display.nodes.length;
  const input = {count, lane: Int32Array.from(display.nodes, node => node.context), weight: Float64Array.from(display.nodes, node => node.hits ?? 0),
    from: Int32Array.from(display.edges, edge => edge.from), to: Int32Array.from(display.edges, edge => edge.to)};
  if (cards) { input.w = Float32Array.from(cards, card => card.w); input.h = Float32Array.from(cards, card => card.h); }
  return input;
}

/** Paths (one per distinct stack) through any of the given original nodes. */
function flowGraphPathsThrough(model, members) {
  const wanted = new Set(members);
  return model.paths.filter(path => path.nodes.some(node => wanted.has(node)));
}

/** Highlight sets for a set of paths, as display node and edge indexes. */
function flowGraphHighlight(model, display, paths) {
  const nodes = new Set(), edges = new Set(), originalEdges = new Set();
  for (const path of paths) {
    path.nodes.forEach(node => { const at = display.displayOf[node]; if (at >= 0) nodes.add(at); });
    path.edges.forEach(edge => originalEdges.add(edge));
  }
  display.edges.forEach((edge, index) => { if (edge.members.some(member => originalEdges.has(member))) edges.add(index); });
  return {nodes, edges, originalEdges, paths: paths.length, occurrences: paths.reduce((sum, path) => sum + (path.occurrences ?? 0), 0)};
}

function createFlowGraphRunner() {
  let worker = null, serial = 0, reject = null;
  const cancel = () => { serial += 1; worker?.terminate(); worker = null; reject?.(new DOMException('Cancelled', 'AbortError')); reject = null; };
  return {
    cancel,
    layout(graph, metrics, engine = 'layered') {
      cancel();
      const id = serial;
      return new Promise((resolve, fail) => {
        reject = fail;
        const local = async () => {
          // A shell that cannot start workers still lays out, on this thread.
          try {
            const layout = await flowGraphLayout.runAsync({graph, metrics, engine});
            if (id !== serial) return;
            reject = null; resolve(layout);
          } catch (error) { if (id === serial) { reject = null; fail(error); } }
        };
        try { worker = new Worker('flow_graph_layout.js'); } catch { worker = null; local(); return; }
        worker.onmessage = event => {
          if (event.data.id !== id) return;
          worker?.terminate(); worker = null; reject = null;
          if (event.data.ok) resolve(event.data.layout); else fail(Error(event.data.error));
        };
        worker.onerror = event => { if (id === serial) { worker?.terminate(); worker = null; local(); event.preventDefault?.(); } };
        worker.postMessage({id, graph, metrics, engine});
      });
    }
  };
}

/** Parses a colour token (#rgb, #rrggbb, rgb() or rgba()) into a canvas
 * colour at `alpha`, for shadows, which take no global alpha of their own. */
function flowGraphAlpha(color, alpha) {
  const text = String(color ?? '').trim();
  let r, g, b;
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})([0-9a-f]{2})?$/i.exec(text);
  if (hex) {
    const digits = hex[1].length === 3 ? [...hex[1]].map(digit => digit + digit).join('') : hex[1];
    [r, g, b] = [0, 2, 4].map(at => parseInt(digits.slice(at, at + 2), 16));
  } else {
    const rgb = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(text);
    if (!rgb) return text || 'transparent';
    [r, g, b] = rgb.slice(1, 4).map(Number);
  }
  return `rgba(${r}, ${g}, ${b}, ${Math.max(0, Math.min(1, alpha))})`;
}

/**
 * The flow graph view: the Graph pane of the Flow workspace.
 * `open(node)` reveals a resolved function in Sources; `available()` says
 * whether this shell serves the route. `onSelect(info | null, {requested})`
 * hears every change of the selected card or row, clears included, with
 * `requested` true when the graph changed it for the host; `onFollow(info)`, when
 * given, takes Enter or a double-click on a Wasm card instead of Sources. The
 * README's Flow graph section documents `info` and the returned methods.
 */
function createFlowGraphPanel({host, open = () => {}, available = () => true, onSelect = null, onFollow = null}) {
  const make = (tag, className = '', text = '') => { const element = document.createElement(tag); if (className) element.className = className; if (text) element.textContent = text; return element; };
  const button = (label, action, aria, className = 'flow-graph-tool') => { const element = make('button', className, label); element.type = 'button'; element.setAttribute('aria-label', aria ?? label); element.addEventListener('click', action); return element; };
  host.classList.add('flow-graph');
  host.hidden = true;
  const body = make('div', 'flow-graph-body');
  const stage = make('div', 'flow-graph-stage');
  const canvas = make('canvas', 'flow-graph-canvas');
  canvas.tabIndex = 0; canvas.setAttribute('role', 'application');
  canvas.setAttribute('aria-label', 'Flow graph of every recorded stack');
  const help = make('p', 'flow-graph-help', 'Arrow keys move between functions. J and K step through the selected function\u2019s calls; Enter follows the call or opens the function (in Sources, or for a Wasm function in the pane beside the graph when there is one); Backspace goes back. Space expands a chain, U goes to a caller, O opens in Sources, S copies the call site, the context menu key or Shift F10 opens actions, I shows details, F centers, C and L copy the name and location, M hides the minimap, slash finds, Escape clears the selection or closes details, plus and minus zoom, 0 fits, Shift and arrows pan.');
  help.id = `flow-graph-help-${Math.random().toString(36).slice(2, 8)}`; help.hidden = true;
  canvas.setAttribute('aria-describedby', help.id);

  // Heading and tools float over the top of the canvas.
  const heading = make('div', 'flow-graph-heading');
  const title = make('strong', 'flow-graph-title', 'Flow graph');
  const stats = make('span', 'flow-graph-stats', '');
  const evidence = make('span', 'flow-graph-evidence', '');
  heading.append(title, stats, evidence);
  const tools = make('div', 'flow-graph-tools');
  const filterLabel = make('label', 'flow-graph-filter');
  const filter = make('input'); filter.type = 'search'; filter.maxLength = 256; filter.placeholder = 'Find function or host'; filter.setAttribute('aria-label', 'Find in the flow graph'); filter.autocomplete = 'off'; filter.spellcheck = false;
  filterLabel.append(filter);
  const matchLabel = make('span', 'flow-graph-matches', ''); matchLabel.setAttribute('aria-live', 'polite');
  const find = make('div', 'flow-graph-find'); find.hidden = true;
  find.append(button('\u25b2', () => stepMatch(-1), 'Previous match'), matchLabel, button('\u25bc', () => stepMatch(1), 'Next match'));
  // Folded or every frame: one radio group, one tab stop, arrows switch.
  const segment = make('div', 'flow-graph-segment'); segment.setAttribute('role', 'radiogroup'); segment.setAttribute('aria-label', 'Pass-through frames');
  const setCollapse = (value, focus = false) => {
    for (const [item, on] of [[folded, value], [every, !value]]) { item.setAttribute('aria-checked', String(on)); item.setAttribute('aria-pressed', String(on)); item.tabIndex = on ? 0 : -1; }
    if (focus) (value ? folded : every).focus();
    if (collapse === value) return;
    collapse = value; rebuild();
  };
  const folded = button('Folded', () => setCollapse(true), 'Fold pass-through frames into chains', 'flow-graph-segment-item');
  const every = button('Every frame', () => setCollapse(false), 'Draw every frame', 'flow-graph-segment-item');
  folded.title = 'Fold frames that only pass one call through, inside one realm, into a chain card';
  for (const item of [folded, every]) item.setAttribute('role', 'radio');
  segment.addEventListener('keydown', event => { if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) { event.preventDefault(); setCollapse(!collapse, true); } });
  segment.append(folded, every);
  for (const [item, on] of [[folded, true], [every, false]]) { item.setAttribute('aria-checked', String(on)); item.setAttribute('aria-pressed', String(on)); item.tabIndex = on ? 0 : -1; }
  const zoomBar = make('div', 'flow-graph-zoom-bar');
  const zoomLabel = make('span', 'flow-graph-zoom', '100%');
  zoomBar.append(button('−', () => zoomAt(0.8), 'Zoom out'), zoomLabel, button('+', () => zoomAt(1.25), 'Zoom in'), button('Fit', fit, 'Fit graph to view'));
  const refresh = button('Refresh', () => load(true), 'Reload the flow graph');
  tools.append(filterLabel, find, segment, zoomBar, refresh);
  // The banner holds what stays true until dealt with (a failed refresh);
  // passing feedback (a copy) uses the toast, so it never hides a warning.
  const banner = make('div', 'flow-graph-banner'); banner.setAttribute('role', 'status'); banner.hidden = true;
  const bannerText = make('span', '', ''), bannerRetry = make('button', 'secondary-button', 'Retry'); bannerRetry.type = 'button'; bannerRetry.hidden = true;
  bannerRetry.addEventListener('click', () => load(true));
  banner.append(bannerText, bannerRetry);
  const toast = make('div', 'flow-graph-toast'); toast.setAttribute('role', 'status'); toast.hidden = true;
  const stateBox = make('div', 'flow-graph-state'); stateBox.setAttribute('role', 'status'); stateBox.setAttribute('aria-live', 'polite');
  const stateTitle = make('strong', '', ''), stateText = make('p', '', ''), retry = make('button', 'secondary-button', 'Retry'); retry.type = 'button'; retry.hidden = true;
  retry.addEventListener('click', () => load(true));
  stateBox.append(stateTitle, stateText, retry);
  const minimap = make('canvas', 'flow-graph-minimap'); minimap.setAttribute('aria-hidden', 'true');
  const tooltip = make('div', 'flow-graph-tooltip'); tooltip.setAttribute('role', 'tooltip'); tooltip.hidden = true;
  const menu = make('div', 'flow-graph-menu'); menu.setAttribute('role', 'menu'); menu.setAttribute('aria-label', 'Card actions'); menu.hidden = true;
  // Heading and tools come first in tab order; they float over the canvas.
  stage.append(heading, tools, canvas, help, banner, toast, minimap, tooltip, menu, stateBox);
  const inspector = make('aside', 'flow-graph-inspector'); inspector.setAttribute('aria-label', 'Flow graph details'); inspector.hidden = true;
  body.append(stage, inspector);

  // Status bar: the selection, the evidence behind the graph, the key.
  const status = make('div', 'flow-graph-status');
  const selectionText = make('span', 'flow-graph-selection', ''); selectionText.setAttribute('aria-live', 'polite');
  const summary = make('span', 'flow-graph-summary', '');
  const engineLabel = make('span', 'flow-graph-engine', '');
  const limits = make('span', 'flow-graph-limits', FLOW_GRAPH_LIMITS);
  const legend = make('div', 'flow-graph-legend'); legend.id = `flow-graph-legend-${Math.random().toString(36).slice(2, 8)}`;
  const requestAgain = button('Request stack', () => { if (requestKey) highlightRequest(requestKey); canvas.focus({preventScroll: true}); }, 'Light the stack of the chosen request again', 'flow-graph-tool flow-graph-request-again');
  requestAgain.hidden = true;
  const keyToggle = button('Key', () => setKey(!status.hasAttribute('data-key-open')), 'Show the key', 'flow-graph-tool flow-graph-key-toggle');
  keyToggle.setAttribute('aria-expanded', 'false'); keyToggle.setAttribute('aria-controls', legend.id);
  const setKey = isOpen => { status.toggleAttribute('data-key-open', isOpen); keyToggle.setAttribute('aria-expanded', String(isOpen)); };
  status.addEventListener('keydown', event => { if (event.key === 'Escape' && status.hasAttribute('data-key-open')) { event.stopPropagation(); setKey(false); keyToggle.focus(); } });
  status.addEventListener('focusout', event => { if (event.relatedTarget && !status.contains(event.relatedTarget)) setKey(false); });
  // WebKit does not focus a clicked button, so focus alone never closes the
  // key there: any press outside it, or Escape anywhere in the view, does.
  host.ownerDocument?.addEventListener?.('pointerdown', event => { if (status.hasAttribute('data-key-open') && !legend.contains(event.target) && event.target !== keyToggle) setKey(false); }, true);
  host.addEventListener('keydown', event => { if (event.key === 'Escape' && status.hasAttribute('data-key-open')) { event.stopPropagation(); setKey(false); } }, true);
  const keyRow = (mark, label) => { const item = make('span', 'flow-graph-key'); item.append(mark, make('span', '', label)); legend.append(item); };
  const keyTag = (text, tone, kind) => { const tag = make('b', 'flow-graph-key-tag', text); if (tone) tag.dataset.tone = tone; if (kind) tag.dataset.kind = kind; return tag; };
  legend.append(make('h4', '', 'Edges'));
  for (const [family, label] of [['call', 'call'], ['async', 'await or posted task'], ['cross', 'crosses a frame, JS ↔ Wasm or into eval'], ['sink', 'request, navigation or cookie write'], ['omitted', 'frames omitted']]) keyRow(make('i', `flow-graph-key-line flow-graph-key-${family}`), label);
  keyRow(make('i', 'flow-graph-key-line flow-graph-key-glow'), 'the lit stack glows; edges off it fade');
  legend.append(make('h4', '', 'Rows'));
  keyRow(keyTag('call', 'call'), 'a mnemonic in its edge\u2019s colour');
  keyRow(keyTag('setTimeout', 'async'), 'an await or a posted task');
  keyRow(keyTag('; → frame', 'cross'), 'what a call crosses, after its callee');
  keyRow(keyTag('request', 'sink'), 'a request, navigation or cookie write it made');
  legend.append(make('h4', '', 'Cards'));
  // The kinds in one wrapped row: each tints its card's header and names
  // its pill.
  const kinds = make('div', 'flow-graph-key-kinds');
  for (const kind of ['javascript', 'eval', 'wasm', 'request', 'chain']) { const item = make('span', 'flow-graph-key-kind'); item.append(keyTag(FLOW_GRAPH_KIND_TAGS[kind].toUpperCase(), null, kind), make('span', '', FLOW_GRAPH_KIND_LABELS[kind])); kinds.append(item); }
  kinds.append(make('span', 'flow-graph-key-kinds-note', 'each tints its card\u2019s header'));
  legend.append(kinds);
  keyRow(keyTag('18', 'badge'), 'distinct stacks that passed through the card');
  keyRow(make('i', 'flow-graph-key-mark'), 'dashed: an unresolved frame');
  keyRow(make('i', 'flow-graph-key-stub'), 'a dashed stub above: earlier async callers not recorded');
  keyRow(make('i', 'flow-graph-key-sample'), 'a dashed ring around it: the function a timeline sample is in');
  legend.append(make('h4', '', 'Realms'));
  keyRow(make('i', 'flow-graph-key-band'), 'a band each, stacked in call order: a realm that calls or posts into another sits above it');
  legend.append(make('h4', '', 'Keys'));
  for (const [keys, label] of [['\u2190\u2191\u2192\u2193', 'move between cards'], ['J K', 'step through calls'], ['\u21a9', 'follow the call, or open'], ['\u232b', 'go back'], ['U', 'go to the caller'], ['O  S', 'open in Sources, copy call site'],
    ['I  F  M', 'details, center, minimap'], ['C  L', 'copy name, location'], ['/', 'find'], ['0  +  \u2212', 'fit and zoom']]) keyRow(keyTag(keys, 'call'), label);
  const keyLimits = make('p', '', FLOW_GRAPH_LIMITS); legend.append(keyLimits);
  const detailsToggle = button('Details', () => setDetails(!detailsOpen), 'Show details', 'flow-graph-tool flow-graph-details-toggle');
  detailsToggle.setAttribute('aria-pressed', 'false');
  status.append(selectionText, requestAgain, summary, engineLabel, limits, keyToggle, legend, detailsToggle);
  host.append(body, status);

  const ctx = canvas.getContext?.('2d');
  const miniCtx = minimap.getContext?.('2d');
  const tokenNames = {bg: '--graph-canvas', card: '--flow-card', cardLine: '--flow-card-line', cardRule: '--flow-card-rule', shadow: '--flow-card-shadow',
    badgeFill: '--flow-badge-fill', badge: '--flow-badge', tagFill: '--flow-tag-fill', rowFill: '--flow-row-fill', box: '--flow-box', mini: '--flow-minimap',
    text: '--text', muted: '--muted', faint: '--faint', accent: '--accent', soft: '--accent-soft', mono: '--mono', sans: '--sans',
    site: '--flow-site', note: '--flow-note', mark: '--flow-mark', viewport: '--flow-viewport'};
  const alphaNames = {head: '--flow-tint-head', tag: '--flow-tint-tag', tagLine: '--flow-tint-tag-line', row: '--flow-tint-row', band: '--flow-tint-band', bandLine: '--flow-tint-band-line', border: '--flow-tint-border'};
  let tokens = {kind: {}, ink: {}, edge: {}, rowInk: {}, realm: [], alpha: {}};
  // Without a 2D context (an offline DOM) cards take the default advances.
  let measure = FLOW_GRAPH_MEASURE;
  const pillWidths = new Map();
  const readTokens = () => {
    const style = getComputedStyle(host);
    const read = name => style.getPropertyValue(name).trim();
    const next = {kind: {}, ink: {}, edge: {}, rowInk: {}, alpha: {}};
    for (const [key, name] of Object.entries(tokenNames)) next[key] = read(name);
    // A kind's hue tints its card; its ink is the text in that colour.
    for (const [kind, stem] of Object.entries(FLOW_GRAPH_KIND_TOKENS)) { next.kind[kind] = read(`--flow-${stem}`); next.ink[kind] = read(`--flow-${stem}-ink`); }
    for (const family of FLOW_GRAPH_EDGE_FAMILIES) { next.edge[family] = read(`--flow-edge-${family}`); next.rowInk[family] = read(`--flow-ink-${family}`); }
    next.realm = Array.from({length: FLOW_GRAPH_REALM_HUES}, (_, index) => read(`--flow-realm-${index}`));
    for (const [key, name] of Object.entries(alphaNames)) next.alpha[key] = Number.parseFloat(read(name));
    tokens = next; miniKey = ''; labelSides = null; pillWidths.clear();
    if (ctx) {
      // Monospace: one advance per font sizes every card.
      const advance = font => { ctx.font = font; return ctx.measureText('0000000000').width / 10; };
      measure = {row: advance(`11.5px ${tokens.mono}`), head: advance(`600 12.5px ${tokens.mono}`), badge: advance(`10.5px ${tokens.mono}`), pill: FLOW_GRAPH_MEASURE.pill, pillWidth};
    }
  };
  /** The kind pill's text width: small capitals, letter-spaced. */
  function pillWidth(tag) {
    if (!pillWidths.has(tag)) { setPillFont(); pillWidths.set(tag, ctx.measureText(tag.toUpperCase()).width); clearLetterSpacing(); }
    return pillWidths.get(tag);
  }
  const setPillFont = () => { ctx.font = `600 9.5px ${tokens.sans}`; if ('letterSpacing' in ctx) ctx.letterSpacing = '0.6px'; };
  const clearLetterSpacing = () => { if ('letterSpacing' in ctx) ctx.letterSpacing = '0px'; };
  if (typeof MutationObserver === 'function') new MutationObserver(() => { readTokens(); requestDraw(); }).observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']});
  globalThis.matchMedia?.('(prefers-color-scheme: dark)')?.addEventListener?.('change', () => { readTokens(); requestDraw(); });

  const runner = createFlowGraphRunner();
  let session = null, requested = null, status_ = 'idle', error = '', model = null, display = null, cards = null, layout = null, generation = 0, controller = null;
  let collapse = true, expanded = new Set(), selected = -1, selectedRow = -1, highlight = null, highlightLabel = '', matches = [], matchSet = new Set(), matchIndex = -1, requestKey = null, shownRequest = '', visible = false;
  // The workspace's timeline mark: a Wasm function (and row) a sample points
  // to, apart from the selection. The selection last reported to onSelect.
  let mark = null, markTarget = null, reported = '', pendingKey = null, keyIndex = null, labelSides = null;
  // True while the graph changes its selection for the host rather than the
  // researcher: a key `select` queued before layout, the stack of the request
  // `show` names, a refresh keeping the selection or a new session clearing
  // it. onSelect then says `requested`, so the host does not count a pick.
  let hostDriven = false;
  const forHost = run => { const was = hostDriven; hostDriven = true; try { return run(); } finally { hostDriven = was; } };
  // A layout the view was hidden during is redone when it shows again.
  let layoutStale = false, layingOut = false, highlightFromRequest = false, detailsOpen = false, minimapOn = true, pendingSelect = null, pendingRequest = false;
  // Cards visited by following calls, for Backspace.
  const history = [];
  let hover = {node: -1, row: -1, edge: -1}, edgeBounds = null, edgeFlat = [];
  let view = {x: 0, y: 0, z: 1}, cssW = 0, cssH = 0, dpr = 1, frame = 0, needsStart = false, miniKey = '', miniBase = null, miniFit = null;
  const metrics = flowGraphLayout.METRICS, ROUTE = flowGraphLayout.ROUTE;

  const requestDraw = () => { if (visible && !frame) frame = requestAnimationFrame(() => { frame = 0; draw(); }); };
  function resize() {
    if (!visible) return;
    const rect = stage.getBoundingClientRect?.() ?? {width: 0, height: 0};
    cssW = Math.max(1, Math.floor(rect.width)); cssH = Math.max(1, Math.floor(rect.height));
    dpr = Math.min(window.devicePixelRatio || 1, Math.sqrt(FLOW_GRAPH_CANVAS_BYTES / (4 * cssW * cssH)), 3);
    const pw = Math.round(cssW * dpr), ph = Math.round(cssH * dpr);
    if (canvas.width !== pw || canvas.height !== ph) { canvas.width = pw; canvas.height = ph; canvas.style.width = `${cssW}px`; canvas.style.height = `${cssH}px`; }
    miniKey = '';
    // The heading gives way to the tools by their measured width.
    host.style?.setProperty?.('--flow-tools-w', `${Math.ceil(tools.offsetWidth || 0)}px`);
    if (needsStart && layout && cssW > 1) { needsStart = false; start(); return; }
    requestDraw();
  }
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(resize).observe(stage);
    // Find opening widens the tools; the heading gives way at once.
    new ResizeObserver(() => host.style?.setProperty?.('--flow-tools-w', `${Math.ceil(tools.offsetWidth || 0)}px`)).observe(tools);
  }
  window.addEventListener('resize', resize);

  function setState(kind, headingText = '', message = '', canRetry = false, retryLabel = 'Retry') {
    status_ = kind;
    stateBox.hidden = kind === 'ready';
    stateBox.dataset.kind = kind;
    stateTitle.textContent = headingText; stateText.textContent = message; retry.hidden = !canRetry; retry.textContent = retryLabel;
    host.dataset.state = kind;
  }
  let flashTimer = 0;
  /** Passing feedback, in its own toast: a warning in the banner stays. */
  function flash(text, kind = 'info') {
    toast.hidden = false; toast.dataset.kind = kind; toast.textContent = text;
    clearTimeout(flashTimer); flashTimer = setTimeout(() => { toast.hidden = true; }, 1800);
  }
  function setBanner(kind, text) {
    banner.hidden = !kind; banner.dataset.kind = kind ?? ''; bannerText.textContent = text ?? ''; bannerRetry.hidden = kind !== 'error';
  }
  function setDetails(isOpen) {
    if (isOpen) setKey(false);
    detailsOpen = isOpen;
    inspector.hidden = !isOpen; host.toggleAttribute('data-details', isOpen);
    detailsToggle.setAttribute('aria-pressed', String(isOpen));
    detailsToggle.setAttribute('aria-label', isOpen ? 'Hide details' : 'Show details');
    if (isOpen) renderInspector();
    // A Details sheet over the bottom of a narrow canvas must not hide the
    // card it describes.
    if (isOpen && selected >= 0 && layout) requestAnimationFrame(() => { if (detailsOpen && selected >= 0) ensureVisible(selected); });
  }

  const sessionKey = () => session ? String(session) : null;
  async function load(force = false) {
    if (!available()) {
      setState('unavailable', 'Flow graph needs the live backend', 'This stored-evidence window has no flow graph route. Open the session in the live workspace or with make ui.');
      return;
    }
    if (!session) { setState('empty', 'No capture session', 'Capture requests in a live session, then return here to see every recorded stack as one graph.'); return; }
    if (!force && requested === sessionKey() && (model || status_ === 'loading')) return;
    requested = sessionKey();
    controller?.abort(); controller = new AbortController();
    const mine = ++generation;
    if (!model) setState('loading', 'Building the flow graph…', 'Folding every recorded stack of this session.');
    else setBanner('loading', 'Refreshing the flow graph…');
    refresh.disabled = true;
    try {
      const response = await fetch(`/api/flow-graph?${new URLSearchParams({session_id: requested})}`, {cache: 'no-store', signal: AbortSignal.any ? AbortSignal.any([controller.signal, AbortSignal.timeout(45000)]) : controller.signal});
      if (!response.ok) { let message = `The flow graph route returned ${response.status}.`; try { message = (await response.json()).error ?? message; } catch {} throw Error(message); }
      const doc = await response.json();
      if (mine !== generation) return;
      const next = flowGraphModel(doc);
      // A refresh keeps the selection, the expanded chains and the view
      // wherever the same functions are still in the graph.
      const keepSelected = selected >= 0 && display ? flowGraphNodeKey(model.nodes[display.nodes[selected].members[0]]) : null;
      const keepExpanded = model ? [...expanded].map(id => flowGraphNodeKey(model.nodes[Number(id)])) : [];
      const keepRow = selectedRow, keepHighlight = highlightFromRequest;
      const first = !model;
      model = next; selected = -1; selectedRow = -1; highlight = null; highlightLabel = '';
      const byKey = new Map(next.nodes.map((node, index) => [flowGraphNodeKey(node), index]));
      expanded = new Set(keepExpanded.map(key => byKey.get(key)).filter(index => index !== undefined).map(String));
      pendingSelect = keepSelected && byKey.has(keepSelected) && !keepHighlight ? {original: byKey.get(keepSelected), row: keepRow} : null;
      pendingRequest = keepHighlight;
      setBanner(null);
      await rebuild(first);
    } catch (problem) {
      if (mine !== generation || problem?.name === 'AbortError') return;
      error = problem?.message ?? 'The flow graph could not be loaded.';
      if (model) setBanner('error', `Refresh failed. Showing the previous graph. ${error}`);
      else setState('error', 'Could not build the flow graph', error, true);
    } finally {
      if (mine === generation) refresh.disabled = false;
    }
  }

  async function rebuild(fresh = false) {
    if (!model) return;
    const keep = pendingSelect ? pendingSelect.original : selected >= 0 ? display?.nodes[selected]?.members?.[0] : null;
    const keepRow = pendingSelect ? pendingSelect.row : -1, reselect = Boolean(pendingSelect), rehighlight = pendingRequest;
    pendingSelect = null; pendingRequest = false;
    // The drawn display, cards and layout change together, only when the new
    // layout is ready, so a card is never drawn at another card's position.
    const next = flowGraphDisplay(model, expanded, collapse);
    if (!next.nodes.length) {
      display = next; cards = []; layout = null; layoutStale = false; keyIndex = null; markTarget = null;
      selected = -1; selectedRow = -1; highlight = null; highlightFromRequest = false; selectionText.textContent = ''; requestAgain.hidden = true;
      notify();
      const records = model.doc.stacks?.records ?? {}, walked = Object.values(model.doc.stacks?.not_walked ?? {}).reduce((sum, value) => sum + value, 0);
      const stacks = FLOW_GRAPH_STACK_RECORDS.reduce((sum, type) => sum + (records[type] ?? 0), 0);
      setState('empty', 'No recorded stacks in this session', stacks > walked
        ? 'Stack records were found, but none could be decoded into frames. Details lists why.'
        : walked
          ? 'Every recorded request in this session started with no script on the stack: the parser, a preload, or a deferred start.'
          : 'Request stacks are recorded when the session runs with request stacks on (the packaged app does when Network and Artifact capture are on). Refresh once the page has made requests.', true, 'Refresh');
      renderSummary(); renderInspector();
      return;
    }
    const mine = generation;
    if (fresh || !layout) setState('loading', 'Laying out…', `${next.nodes.length.toLocaleString()} cards in ${model.contexts.length} ${model.contexts.length === 1 ? 'realm' : 'realms'}.`);
    layingOut = true;
    readTokens();
    const nextCards = flowGraphCards(model, next, measure);
    try {
      // Triskel runs in the backend; a shell without the route lays out here.
      const result = await runner.layout(flowGraphLayoutInput(next, nextCards), metrics, available() ? 'triskel' : 'layered');
      layingOut = false;
      if (mine !== generation) return;
      display = next; cards = nextCards; layout = result; layoutStale = false; keyIndex = null; labelSides = null;
      edgeBounds = null; edgeFlat = []; miniKey = ''; hover = {node: -1, row: -1, edge: -1};
      findMark();
      selected = keep === null || keep === undefined ? -1 : display.displayOf[keep] ?? -1;
      selectedRow = selected >= 0 && keepRow >= 0 && keepRow < cards[selected].rows.length ? keepRow : -1;
      if (highlight && highlight.source) applyHighlight(highlight.source, highlightLabel, false);
      renderSummary(); applyFilter(); renderInspector(); renderSelection();
      setState('ready');
      if (fresh) { needsStart = cssW <= 1; start(); } else if (selected >= 0 && !reselect) ensureVisible(selected); else requestDraw();
      forHost(() => {
        if (reselect && selected >= 0) select(selected, {reveal: false, row: selectedRow});
        if (requestKey && (fresh || rehighlight)) highlightRequest(requestKey, {reveal: fresh});
        if (pendingKey) { const wanted = pendingKey; pendingKey = null; selectKey(wanted.key, {reveal: wanted.reveal}); }
      });
      notify();
    } catch (problem) {
      layingOut = false;
      if (problem?.name === 'AbortError') { layoutStale = true; return; }
      setState('error', 'Could not lay out the flow graph', problem?.message ?? 'Layout failed.', true);
    }
  }

  function renderSummary() {
    const doc = model?.doc;
    if (!doc) { stats.textContent = ''; evidence.textContent = ''; summary.textContent = ''; return; }
    const functions = doc.nodes.filter(node => !FLOW_GRAPH_SINKS.has(node.kind)).length, sinks = doc.nodes.length - functions;
    const parts = [`${doc.stacks.distinct.toLocaleString()} distinct ${doc.stacks.distinct === 1 ? 'stack' : 'stacks'}`, `${functions.toLocaleString()} ${functions === 1 ? 'function' : 'functions'}`,
      `${sinks.toLocaleString()} ${sinks === 1 ? 'sink' : 'sinks'}`, `${model.contexts.length} ${model.contexts.length === 1 ? 'realm' : 'realms'}`];
    if (display?.groups) parts.push(`${display.groups} ${display.groups === 1 ? 'chain' : 'chains'} folded`);
    stats.textContent = parts.join(' · ');
    evidence.textContent = doc.complete ? 'observed' : 'observed · partial';
    evidence.dataset.partial = String(!doc.complete);
    const crossing = display ? display.edges.filter(edge => edge.crosses.length) : [];
    const frames = crossing.filter(edge => edge.crosses.includes('frame')).length, languages = crossing.filter(edge => edge.crosses.includes('language')).length, dynamic = crossing.filter(edge => edge.crosses.includes('dynamic')).length;
    const crossings = [[frames, 'frame'], [languages, 'JS ↔ Wasm'], [dynamic, 'into eval']].filter(([count]) => count).map(([count, label]) => `${count} ${label}`);
    summary.textContent = `${(doc.stacks?.occurrences ?? 0).toLocaleString()} stack records · ${crossings.length ? `crossings: ${crossings.join(', ')}` : 'no crossings'}`;
    const notes = [];
    if (doc.coverage?.stopped === 'deadline') notes.push('The scan stopped at its deadline.');
    if (doc.stacks?.over_budget) notes.push(`${doc.stacks.over_budget} stacks past the ${doc.limits?.stacks?.toLocaleString?.() ?? ''} distinct-stack budget are counted, not drawn.`);
    for (const [key, label] of [['nodes', 'nodes'], ['edges', 'edges'], ['paths', 'paths']]) if (doc.truncated?.[key]) notes.push(`${doc.truncated[key]} ${label} past the budget are not drawn.`);
    if (model.dropped) notes.push(`${model.dropped} malformed edges are not drawn.`);
    renderEngine();
    // The status bar names only what cut this graph; what no graph shows is
    // in the key.
    limits.textContent = notes.join(' ');
    limits.title = notes.join(' ');
    keyLimits.textContent = `${FLOW_GRAPH_LIMITS}${doc.not_shown?.length ? ` Stacks cannot show ${doc.not_shown.join('; ')}.` : ''}`;
  }

  /** Which engine laid out the realms, and why a realm kept the layered one. */
  function renderEngine() {
    const engine = layout?.engine, realms = engine?.realms ?? [];
    if (!engine) { engineLabel.textContent = ''; engineLabel.title = ''; return; }
    const sized = realms.filter(item => item.reason !== 'one card'), triskel = sized.filter(item => item.engine === 'triskel').length;
    engineLabel.textContent = triskel ? `Triskel layout${triskel < sized.length ? ` · ${triskel} of ${sized.length} realms` : ''}` : engine.failure ? 'Layered layout · Triskel unavailable' : 'Layered layout';
    engineLabel.dataset.engine = triskel ? 'triskel' : 'layered';
    engineLabel.title = [triskel ? `Triskel ${engine.revision ? engine.revision.slice(0, 7) : ''} lays out each realm that fits its limits; a realm it would draw far wider than the stacked layered layout keeps that one.`.trim() : 'Laid out in the app with the layered layout.',
      ...realms.filter(item => item.reason && item.reason !== 'one card').map(item => `${model?.contexts[item.key]?.label.title ?? 'Realm'}: layered, ${item.reason}.`), engine.failure ?? ''].filter(Boolean).join('\n');
  }

  // Geometry ---------------------------------------------------------------
  const nodeBox = index => ({x: layout.x[index], y: layout.y[index], w: layout.w[index], h: layout.h[index]});
  const visibleBox = (x, y, w, h) => x < view.x + cssW / view.z && x + w > view.x && y < view.y + cssH / view.z && y + h > view.y;
  const rowTop = (box, row) => box.y + FLOW_GRAPH_CARD.head + FLOW_GRAPH_CARD.location + FLOW_GRAPH_CARD.gap + row * FLOW_GRAPH_CARD.row;
  function boundsOfEdges() {
    if (edgeBounds) return edgeBounds;
    const count = display.edges.length, bounds = new Float32Array(count * 4), P = layout.routes, S = layout.routeStart;
    for (let e = 0; e < count; e += 1) {
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (let i = S[e]; i < S[e + 1]; i += 1) { const x = P[2 * i], y = P[2 * i + 1]; if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
      bounds.set([x0, y0, x1, y1], e * 4);
    }
    return (edgeBounds = bounds);
  }
  /** Points along a route, curves flattened, for hit tests. */
  function flatRoute(e) {
    if (edgeFlat[e]) return edgeFlat[e];
    const P = layout.routes, T = layout.routeTypes, S = layout.routeStart, out = [];
    for (let i = S[e]; i < S[e + 1]; i += 1) {
      const x = P[2 * i], y = P[2 * i + 1];
      if (i > S[e] && T[i] === ROUTE.CURVE) { const py = P[2 * i - 1], mid = (py + y) / 2; out.push(P[2 * i - 2], mid, x, mid, x, y); }
      else out.push(x, y);
    }
    return (edgeFlat[e] = out);
  }
  /** The canvas path of an edge's route: curves with vertical tangents
   * between layers, straight runs past waypoints, rounded corners. */
  function tracePath(e) {
    const P = layout.routes, T = layout.routeTypes, S = layout.routeStart, start = S[e], end = S[e + 1];
    for (let i = start; i < end; i += 1) {
      const x = P[2 * i], y = P[2 * i + 1];
      if (i === start) { ctx.moveTo(x, y); continue; }
      const px = P[2 * i - 2], py = P[2 * i - 1];
      if (T[i] === ROUTE.CURVE) {
        // Down, across at mid-gap and down again, corners rounded: the same
        // shape Triskel's waypoints take.
        if (Math.abs(x - px) < 0.5) { ctx.lineTo(x, y); continue; }
        const mid = (py + y) / 2, radius = Math.max(0.1, Math.min(12, Math.abs(x - px) / 2, Math.abs(y - py) / 4));
        ctx.arcTo(px, mid, x, mid, radius); ctx.arcTo(x, mid, x, y, radius); ctx.lineTo(x, y);
      }
      else if (T[i] === ROUTE.CORNER && i + 1 < end) {
        const nx = P[2 * i + 2], ny = P[2 * i + 3];
        const radius = Math.max(0.1, Math.min(10, Math.hypot(x - px, y - py) / 2, Math.hypot(nx - x, ny - y) / 2));
        ctx.arcTo(x, y, nx, ny, radius);
      } else ctx.lineTo(x, y);
    }
  }
  /** The direction an edge arrives in, for its arrowhead. */
  function arrival(e) {
    const P = layout.routes, T = layout.routeTypes, end = layout.routeStart[e + 1] - 1;
    const x = P[2 * end], y = P[2 * end + 1], px = P[2 * end - 2], py = P[2 * end - 1];
    if (T[end] === ROUTE.CURVE) return {x, y, dx: 0, dy: Math.sign(y - py) || 1};
    const length = Math.hypot(x - px, y - py) || 1;
    return {x, y, dx: (x - px) / length, dy: (y - py) / length};
  }

  // Drawing ----------------------------------------------------------------
  const lodNow = () => view.z >= FLOW_GRAPH_TEXT_ZOOM ? 2 : view.z >= FLOW_GRAPH_SKETCH_ZOOM ? 1 : 0;
  const realmHue = key => tokens.realm[((Number(key) || 0) % FLOW_GRAPH_REALM_HUES + FLOW_GRAPH_REALM_HUES) % FLOW_GRAPH_REALM_HUES] ?? tokens.faint;
  function draw() {
    if (!ctx || !visible) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.fillStyle = tokens.bg; ctx.fillRect(0, 0, cssW, cssH);
    if (!layout || !display || !cards || layout.x.length !== display.nodes.length) return;
    ctx.setTransform(dpr * view.z, 0, 0, dpr * view.z, -view.x * view.z * dpr, -view.y * view.z * dpr);
    const lod = lodNow();
    drawBands();
    drawEdges();
    // A realm's name sits under the cards at its home corner, and over them
    // while it is pinned under the heading.
    if (lod === 2) drawBandLabels(false);
    const shown = [];
    let lift = 0;
    for (let index = 0; index < display.nodes.length; index += 1) { const box = nodeBox(index); if (visibleBox(box.x - 8, box.y - 26, box.w + 16, box.h + 34)) { shown.push(index); lift += 1; } }
    // A soft lift under each card while few are in view; a dense view skips it.
    for (const index of shown) drawCard(index, nodeBox(index), lod, lod === 2 && lift <= 160);
    if (lod === 2) drawBandLabels(true);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (lod === 1) drawScreenTitles(shown);
    if (lod < 2) drawScreenBandLabels();
    zoomLabel.textContent = `${Math.round(view.z * 100)}%`;
    drawMinimap();
  }

  /** Each realm is a full-width band with a faint tint of its own. */
  function drawBands() {
    layout.lanes.forEach(lane => {
      if (!visibleBox(lane.x, lane.y, lane.w, lane.h)) return;
      const hue = realmHue(lane.key);
      ctx.beginPath(); roundedRect(lane.x, lane.y, lane.w, lane.h, 14);
      ctx.globalAlpha = tokens.alpha.band; ctx.fillStyle = hue; ctx.fill();
      ctx.globalAlpha = tokens.alpha.bandLine; ctx.strokeStyle = hue; ctx.lineWidth = 1 / view.z; ctx.stroke();
      ctx.globalAlpha = 1;
    });
  }
  /** The band label: realm name and its process, frame and realm IDs, in the
   * top corner of the band that no edge crosses (the right one when both are
   * clear), so it never sits on the spine. */
  const LABEL = Object.freeze({inset: 18, top: 14, height: 24});
  function bandLabelText(lane) {
    const context = model.contexts[lane.key]?.label;
    return {title: context?.title ?? 'Realm', detail: context?.detail ?? ''};
  }
  function bandLabelWidth(lane) {
    const {title, detail} = bandLabelText(lane);
    ctx.font = `600 12.5px ${tokens.sans}`; const titleW = ctx.measureText(title).width;
    ctx.font = `11px ${tokens.sans}`; const detailW = detail ? ctx.measureText(detail).width + 10 : 0;
    return Math.min(lane.w - LABEL.inset * 2, 16 + titleW + detailW + 4);
  }
  function chooseLabelSides() {
    labelSides = new Map();
    if (!ctx) return;
    layout.lanes.forEach(lane => {
      const width = bandLabelWidth(lane), y0 = lane.y + LABEL.top - 2, y1 = lane.y + LABEL.top + LABEL.height + 2;
      const crossings = (x0, x1) => {
        let found = 0;
        for (let e = 0; e < display.edges.length; e += 1) {
          const points = flatRoute(e);
          for (let i = 2; i < points.length; i += 2) {
            const ax = Math.min(points[i - 2], points[i]), bx = Math.max(points[i - 2], points[i]), ay = Math.min(points[i - 1], points[i + 1]), by = Math.max(points[i - 1], points[i + 1]);
            if (bx >= x0 && ax <= x1 && by >= y0 && ay <= y1) { found += 1; break; }
          }
        }
        return found;
      };
      const right = crossings(lane.x + lane.w - LABEL.inset - width, lane.x + lane.w - LABEL.inset), left = right ? crossings(lane.x + LABEL.inset, lane.x + LABEL.inset + width) : 0;
      labelSides.set(lane.key, right && left < right ? 'left' : 'right');
    });
  }
  function drawBandLabels(pinnedPass) {
    if (!labelSides) chooseLabelSides();
    ctx.textBaseline = 'alphabetic';
    layout.lanes.forEach(lane => {
      if (!visibleBox(lane.x, lane.y, lane.w, lane.h)) return;
      // Pinned under the heading while its band is in view, so panning down
      // a tall band never loses which realm a card is in.
      const home = lane.y + LABEL.top, top = Math.min(Math.max(home, view.y + (topInset() - 4) / view.z), lane.y + lane.h - LABEL.height - 10);
      const pinned = top > home + 0.5;
      if (pinned !== pinnedPass) return;
      const {title, detail} = bandLabelText(lane), width = bandLabelWidth(lane), hue = realmHue(lane.key);
      // A label level with the minimap stops short of it.
      const screenTop = (top - view.y) * view.z, mini = minimapOn && !host.hasAttribute('data-all-in-view') && minimap.offsetWidth ? minimap : null;
      const miniLeft = mini && screenTop + LABEL.height * view.z > (mini.offsetTop ?? cssH) ? (mini.offsetLeft ?? cssW) - 8 : cssW;
      const viewLeft = Math.max(lane.x, view.x), viewRight = Math.min(lane.x + lane.w, view.x + miniLeft / view.z);
      const left = labelSides?.get(lane.key) === 'left' ? viewLeft + LABEL.inset : Math.max(lane.x + LABEL.inset, viewRight - LABEL.inset - width);
      // A plate keeps an edge passing under the name from striking it out.
      ctx.globalAlpha = 0.9; ctx.fillStyle = tokens.bg; ctx.beginPath(); roundedRect(left - 8, top, width + 16, LABEL.height, 6); ctx.fill(); ctx.globalAlpha = 1;
      ctx.fillStyle = hue; ctx.beginPath(); ctx.arc(left + 4, top + LABEL.height / 2, 4, 0, Math.PI * 2); ctx.fill();
      ctx.font = `600 12.5px ${tokens.sans}`; ctx.fillStyle = tokens.text;
      const titleText = fitText(title, width - 16), titleW = ctx.measureText(titleText).width;
      ctx.fillText(titleText, left + 14, top + 16.5);
      if (detail && width - 16 - titleW > 40) { ctx.font = `11px ${tokens.sans}`; ctx.fillStyle = tokens.muted; ctx.fillText(fitText(detail, width - 26 - titleW), left + 24 + titleW, top + 16.5); }
    });
  }
  /** Zoomed out, each band keeps its realm's name at screen size, on a
   * plate, since its top pad is too small to hold it. */
  function drawScreenBandLabels() {
    ctx.textBaseline = 'alphabetic'; ctx.font = `600 11px ${tokens.sans}`;
    layout.lanes.forEach(lane => {
      const x = (lane.x - view.x) * view.z, y = (lane.y - view.y) * view.z, w = lane.w * view.z, h = lane.h * view.z;
      if (x > cssW || x + w < 0 || y > cssH || y + h < 0 || w < 24 || h < 18) return;
      const left = Math.max(x + 6, 6), base = Math.min(Math.max(y + 14, topInset() + 8), y + h - 4);
      const text = fitText(model.contexts[lane.key]?.label.title ?? 'Realm', Math.min(x + w, cssW) - left - 22), width = ctx.measureText(text).width;
      ctx.globalAlpha = 0.88; ctx.fillStyle = tokens.bg; ctx.beginPath(); roundedRect(left - 2, base - 12, width + 20, 16, 4); ctx.fill(); ctx.globalAlpha = 1;
      ctx.fillStyle = realmHue(lane.key); ctx.beginPath(); ctx.arc(left + 5, base - 4, 3, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = tokens.muted; ctx.fillText(text, left + 13, base);
    });
  }

  function fitText(text, room) {
    if (!text || room <= 0) return '';
    if (ctx.measureText(text).width <= room) return text;
    let low = 0, high = text.length;
    while (low < high) { const mid = (low + high + 1) >> 1; if (ctx.measureText(`${text.slice(0, mid)}…`).width <= room) low = mid; else high = mid - 1; }
    return low ? `${text.slice(0, low)}…` : '';
  }

  const edgeColor = edge => tokens.edge[flowGraphEdgeFamily(edge)] ?? tokens.edge.call;
  let maxEdgeCount = 1;
  function drawEdges() {
    maxEdgeCount = display.edges.reduce((max, edge) => Math.max(max, edge.count), 1);
    const bounds = boundsOfEdges(), dim = Boolean(highlight), rowEdge = selectedRow >= 0 ? cards[selected]?.rows[selectedRow]?.edge ?? -1 : -1;
    const hot = new Set([hover.edge, hover.row >= 0 ? cards[hover.node]?.rows[hover.row]?.edge ?? -1 : -1, rowEdge].filter(index => index >= 0));
    const lit = index => !dim || highlight.edges.has(index) || hot.has(index);
    const order = [];
    display.edges.forEach((edge, index) => { if (!lit(index)) order.push(index); });
    display.edges.forEach((edge, index) => { if (lit(index) && !hot.has(index)) order.push(index); });
    hot.forEach(index => order.push(index));
    // The lit stack glows: a heavier stroke and a soft shadow of its colour.
    // A huge lit set skips the shadow, which costs a blur per edge.
    const casing = view.z >= 0.3, log = Math.log(maxEdgeCount + 1), glows = dim && view.z >= 0.25 && highlight.edges.size <= 600;
    ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    for (const index of order) {
      const at = index * 4;
      if (!visibleBox(bounds[at] - 6, bounds[at + 1] - 6, bounds[at + 2] - bounds[at] + 12, bounds[at + 3] - bounds[at + 1] + 12)) continue;
      const edge = display.edges[index], on = lit(index), strong = hot.has(index), color = edgeColor(edge), family = flowGraphEdgeFamily(edge);
      // Zoomed out to boxes, plain calls recede to hairlines so crossings
      // and tasks carry the picture; dimmed edges stay traceable.
      const boxes = view.z < FLOW_GRAPH_SKETCH_ZOOM && family !== 'cross' && family !== 'async' && !strong;
      const glow = dim && on;
      const weight = boxes ? 1 / view.z : (1.4 + 1.6 * Math.log(edge.count + 1) / log + (strong ? 1.2 : 0) + (glow ? 1 : 0)) * Math.max(1, 0.7 / view.z);
      ctx.globalAlpha = (on ? 1 : family === 'cross' ? 0.4 : 0.26) * (boxes ? 0.6 : 1);
      ctx.beginPath(); tracePath(index);
      if (casing) { ctx.strokeStyle = tokens.bg; ctx.lineWidth = weight + 3.4; ctx.setLineDash([]); ctx.stroke(); }
      if (glow && glows) { ctx.shadowColor = flowGraphAlpha(color, 0.6); ctx.shadowBlur = 9 * dpr; }
      ctx.strokeStyle = color; ctx.lineWidth = weight;
      ctx.setLineDash(edge.kind === 'omitted' ? [1.5, 4.5] : []);
      ctx.stroke(); ctx.setLineDash([]);
      ctx.shadowBlur = 0; ctx.shadowColor = 'transparent';
      if (view.z >= 0.25) arrowHead(index, color, Math.max(6.5, 4 + weight * 1.5));
    }
    ctx.globalAlpha = 1;
  }
  function arrowHead(index, color, size) {
    const {x, y, dx, dy} = arrival(index), nx = -dy, ny = dx, half = size * 0.48;
    ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x - dx * size + nx * half, y - dy * size + ny * half); ctx.lineTo(x - dx * size - nx * half, y - dy * size - ny * half); ctx.closePath();
    if (view.z >= 0.3) { ctx.strokeStyle = tokens.bg; ctx.lineWidth = 2; ctx.stroke(); }
    ctx.fillStyle = color; ctx.fill();
  }

  /** The family a row's mnemonic is coloured by: its edge's, or a sink's. */
  const rowFamily = item => item?.family ?? (item?.sink ? 'sink' : 'call');
  /** A row band: the surface, a tint of `hue` and a bar on the left. */
  function rowBand(x, top, w, hue, strength) {
    const C = FLOW_GRAPH_CARD;
    ctx.globalAlpha = 1; ctx.fillStyle = tokens.rowFill; ctx.fillRect(x + 1, top, w - 2, C.row);
    ctx.globalAlpha = tokens.alpha.row * strength; ctx.fillStyle = hue; ctx.fillRect(x + 1, top, w - 2, C.row);
    ctx.globalAlpha = strength; ctx.fillRect(x + 1, top, 2, C.row); ctx.globalAlpha = 1;
  }
  function drawCard(index, box, lod, lift) {
    const node = display.nodes[index], card = cards[index], picked = index === selected, C = FLOW_GRAPH_CARD;
    const matched = matchSet.has(index), hue = tokens.kind[node.kind] ?? tokens.faint, ink = tokens.ink[node.kind] ?? tokens.muted;
    // Off the lit stack, a card keeps its place and fill; its tint, outline
    // and colours fade, and its text turns muted (still 4.5:1). A match of
    // Find is never dimmed.
    const dim = Boolean(highlight) && !highlight.nodes.has(index) && !matched, marked = markTarget?.index === index;
    const {x, y, w, h} = box, r = C.radius, hair = 1 / view.z;
    ctx.globalAlpha = 1;
    if (node.kind === 'chain') {
      // A folded chain reads as a stack of cards behind it, down and right.
      ctx.fillStyle = tokens.card; ctx.strokeStyle = hue; ctx.lineWidth = hair;
      for (const offset of [6, 3]) { ctx.beginPath(); roundedRect(x + offset, y + offset, w, h, r); ctx.fill(); ctx.globalAlpha = dim ? 0.25 : tokens.alpha.border; ctx.stroke(); ctx.globalAlpha = 1; }
    }
    if (node.chain_cut && lod > 0) {
      // Earlier async callers were not recorded: a stub with no edge.
      ctx.strokeStyle = tokens.faint; ctx.lineWidth = 1.4 / Math.max(view.z, 0.5); ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x + 16, y - 20); ctx.lineTo(x + 16, y); ctx.stroke(); ctx.setLineDash([]);
    }
    if (picked && lod > 0) {
      // Selected: a soft ring and a glow in the card's colour.
      ctx.globalAlpha = 0.2; ctx.fillStyle = hue; ctx.beginPath(); roundedRect(x - 4, y - 4, w + 8, h + 8, r + 4); ctx.fill(); ctx.globalAlpha = 1;
      ctx.shadowColor = flowGraphAlpha(hue, 0.35); ctx.shadowBlur = 30 * dpr;
    } else if (lift && !dim) { ctx.shadowColor = tokens.shadow; ctx.shadowBlur = 14 * dpr; ctx.shadowOffsetY = 5 * dpr * view.z; }
    // A dimmed card's fill fades toward its band, so it recedes while its
    // muted text keeps its contrast; no edge runs under a card.
    ctx.globalAlpha = dim ? 0.5 : 1; ctx.fillStyle = tokens.card; ctx.beginPath(); roundedRect(x, y, w, h, r); ctx.fill(); ctx.globalAlpha = 1;
    ctx.shadowBlur = 0; ctx.shadowOffsetY = 0; ctx.shadowColor = 'transparent';
    if (lod === 0) {
      // Boxes: filled with the kind's colour, like the minimap.
      ctx.globalAlpha = dim ? 0.18 : 0.5; ctx.fillStyle = hue; ctx.fill(); ctx.globalAlpha = 1;
      if (picked || marked) { ctx.strokeStyle = picked ? hue : tokens.mark; ctx.lineWidth = 2 / view.z; ctx.stroke(); }
      return;
    }
    // Header strip, tinted by the kind, ruled off from the body.
    ctx.save(); ctx.beginPath(); roundedRect(x, y, w, h, r); ctx.clip();
    ctx.globalAlpha = tokens.alpha.head * (dim ? 0.35 : 1); ctx.fillStyle = hue; ctx.fillRect(x, y, w, C.head);
    ctx.globalAlpha = dim ? 0.15 : 0.38; ctx.fillRect(x, y + C.head - hair, w, hair);
    ctx.restore(); ctx.globalAlpha = 1;
    // Outline: the kind's colour, heavier when selected; dashed for an
    // unresolved frame or a match of Find.
    ctx.beginPath(); roundedRect(x, y, w, h, r);
    ctx.strokeStyle = matched && !picked ? tokens.accent : hue;
    ctx.globalAlpha = picked || matched ? 1 : dim ? 0.3 : highlight ? 0.85 : tokens.alpha.border;
    ctx.lineWidth = (picked ? 2 : matched ? 1.5 : 1) / view.z;
    if ((node.status !== 'resolved' && !picked) || (matched && !picked)) ctx.setLineDash(matched && !picked ? [5 / view.z, 3 / view.z] : [4, 3]);
    ctx.stroke(); ctx.setLineDash([]); ctx.globalAlpha = 1;
    if (marked) {
      // A timeline sample's function: a dashed ring outside the card.
      ctx.strokeStyle = tokens.mark; ctx.lineWidth = 2 / view.z; ctx.setLineDash([6 / view.z, 4 / view.z]);
      ctx.beginPath(); roundedRect(x - 6, y - 6, w + 12, h + 12, r + 6); ctx.stroke(); ctx.setLineDash([]);
    }
    if (lod === 1) {
      // A sketch of the rows, coloured by what each row does; the name is
      // painted at screen size later.
      ctx.globalAlpha = dim ? 0.35 : 0.8;
      const rows = card.rows.length + (card.more ? 1 : 0);
      for (let row = -1; row < rows; row += 1) {
        const item = row >= 0 ? card.rows[row] : null;
        ctx.fillStyle = item ? tokens.rowInk[rowFamily(item)] ?? tokens.cardLine : tokens.cardLine;
        const top = row < 0 ? y + C.head + 7 : rowTop(box, row) + 7, width = row < 0 ? card.location.length * measure.badge : card.siteW + card.opW + 22 + (item?.target.length ?? 6) * measure.row;
        ctx.fillRect(x + C.pad, top, Math.min(w - C.pad * 2, width), 5);
      }
      ctx.globalAlpha = 1;
      return;
    }
    ctx.save(); ctx.beginPath(); ctx.rect(x, y, w, h); ctx.clip();
    ctx.textBaseline = 'alphabetic';
    // Header: name, then the stack badge, then the kind pill.
    const pillX = x + w - C.pad - card.pillW, badgeX = pillX - 6 - card.badgeW;
    ctx.fillStyle = tokens.tagFill; ctx.beginPath(); roundedRect(pillX, y + 8, card.pillW, 16, 4); ctx.fill();
    if (tokens.alpha.tag > 0) { ctx.globalAlpha = tokens.alpha.tag * (dim ? 0.4 : 1); ctx.fillStyle = hue; ctx.fill(); }
    if (tokens.alpha.tagLine > 0) { ctx.globalAlpha = tokens.alpha.tagLine * (dim ? 0.4 : 1); ctx.strokeStyle = hue; ctx.lineWidth = hair; ctx.stroke(); }
    ctx.globalAlpha = 1;
    setPillFont(); ctx.fillStyle = dim ? tokens.muted : ink; ctx.textAlign = 'center';
    ctx.fillText(card.tag.toUpperCase(), pillX + card.pillW / 2, y + 19.5); ctx.textAlign = 'left'; clearLetterSpacing();
    ctx.fillStyle = tokens.badgeFill; ctx.strokeStyle = tokens.badge; ctx.lineWidth = hair; ctx.beginPath(); roundedRect(badgeX, y + 8, card.badgeW, 16, 4); ctx.fill(); ctx.stroke();
    ctx.font = `10.5px ${tokens.mono}`; ctx.fillStyle = tokens.muted; ctx.fillText(card.badge, badgeX + 5, y + 19.5);
    ctx.font = `600 12.5px ${tokens.mono}`; ctx.fillStyle = node.status === 'resolved' && !dim ? tokens.text : tokens.muted;
    ctx.fillText(fitText(card.title, badgeX - x - C.pad - 8), x + C.pad, y + 21);
    ctx.font = `11px ${tokens.mono}`; ctx.fillStyle = tokens.site;
    ctx.fillText(fitText(card.location, w - C.pad * 2), x + C.pad, y + C.head + 15);
    // Rows: site, mnemonic, callee, then the note and the count.
    ctx.font = `11.5px ${tokens.mono}`;
    const opX = x + C.pad + (card.siteW ? card.siteW + 12 : 0), targetX = opX + (card.opW ? card.opW + 10 : 0);
    const rowCount = card.rows.length + (card.more ? 1 : 0);
    for (let row = 0; row < rowCount; row += 1) {
      const top = rowTop(box, row), base = top + 13.5, item = card.rows[row];
      const isHover = hover.node === index && hover.row === row, isPicked = picked && selectedRow === row, isMarked = marked && markTarget.row === row;
      if (isPicked) rowBand(x, top, w, hue, 1); else if (isMarked) rowBand(x, top, w, tokens.mark, 1); else if (isHover) rowBand(x, top, w, hue, 0.55);
      if (!item) { ctx.fillStyle = tokens.muted; ctx.fillText(`… ${card.more.toLocaleString()} more ${node.kind === 'chain' ? 'frames' : 'calls'}, in Details`, x + C.pad, base); continue; }
      const family = rowFamily(item), tone = dim ? tokens.muted : tokens.rowInk[family] ?? tokens.muted;
      if (highlight && !dim && !isHover && !isPicked && item.members?.some(member => highlight.originalEdges.has(member))) { ctx.fillStyle = tokens.edge[family] ?? hue; ctx.fillRect(x + 4, top + 4, 2, C.row - 8); }
      ctx.fillStyle = tokens.site; ctx.fillText(item.site, x + C.pad, base);
      const edge = item.edge >= 0 ? display.edges[item.edge] : null;
      ctx.fillStyle = tone; ctx.fillText(item.op, opX, base);
      const countW = item.count ? ctx.measureText(item.count).width + 10 : 0, room = x + w - C.pad - countW - targetX;
      const target = fitText(item.target, room);
      ctx.fillStyle = dim || (edge && display.nodes[edge.to]?.status !== 'resolved') ? tokens.muted : tokens.text; ctx.fillText(target, targetX, base);
      if (item.note) {
        const used = ctx.measureText(target).width + 10;
        if (room - used > 30) { ctx.fillStyle = family === 'call' || dim ? tokens.note : tone; ctx.fillText(fitText(`; ${item.note}`, room - used), targetX + used, base); }
      }
      if (item.count) { ctx.fillStyle = tokens.muted; ctx.fillText(item.count, x + w - C.pad - countW + 10, base); }
    }
    ctx.restore();
    ctx.globalAlpha = 1;
  }

  /** Between the sketch and text zooms, each card keeps a legible name. */
  function drawScreenTitles(indexes) {
    ctx.font = `600 10.5px ${tokens.mono}`; ctx.textBaseline = 'middle';
    for (const index of indexes) {
      const box = nodeBox(index), sx = (box.x - view.x) * view.z, sy = (box.y - view.y) * view.z, sw = box.w * view.z;
      if (sw < 28) continue;
      const node = display.nodes[index], dim = Boolean(highlight) && !highlight.nodes.has(index) && !matchSet.has(index);
      ctx.fillStyle = node.status === 'resolved' && !dim ? tokens.text : tokens.muted;
      // A name may run a little past a narrow card, into the gap beside it.
      ctx.fillText(fitText(cards[index].title, sw - 10 + Math.min(24, 26 * view.z)), sx + 6, sy + Math.max(8, FLOW_GRAPH_CARD.head * view.z / 2));
    }
    ctx.textBaseline = 'alphabetic';
  }

  function roundedRect(x, y, w, h, r) {
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }

  // Minimap ----------------------------------------------------------------
  function drawMinimap() {
    // The minimap is for a graph larger than the view.
    const inView = view.x <= 0 && view.y <= 0 && view.x + cssW / view.z >= layout.width && view.y + cssH / view.z >= layout.height;
    host.toggleAttribute('data-all-in-view', inView);
    if (!miniCtx || !minimapOn || !layout || inView) return;
    // The minimap takes the graph's shape: a tall graph gets a tall column,
    // like a disassembler's overview, a wide one a short strip.
    const shape = layout.width / Math.max(1, layout.height), maxW = Math.max(72, Math.min(170, cssW * 0.16)), maxH = Math.max(80, Math.min(440, cssH * 0.55, cssH - topInset() - 40));
    const wantW = Math.round(Math.max(72, Math.min(maxW, maxH * shape))), wantH = Math.round(Math.max(60, Math.min(maxH, wantW / shape)));
    if (minimap.style.width !== `${wantW}px`) minimap.style.width = `${wantW}px`;
    if (minimap.style.height !== `${wantH}px`) minimap.style.height = `${wantH}px`;
    const mw = minimap.clientWidth || wantW, mh = minimap.clientHeight || wantH;
    if (!mw || !mh) return;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    if (minimap.width !== Math.round(mw * ratio) || minimap.height !== Math.round(mh * ratio)) { minimap.width = Math.round(mw * ratio); minimap.height = Math.round(mh * ratio); miniKey = ''; }
    const key = `${selected}:${highlight ? highlight.nodes.size + highlight.paths : 0}:${matches.length}:${markTarget ? markTarget.index : -1}:${layout.width}:${display.nodes.length}`;
    const scale = Math.min((mw - 12) / layout.width, (mh - 12) / layout.height), ox = (mw - layout.width * scale) / 2, oy = (mh - layout.height * scale) / 2;
    miniFit = {scale, ox, oy};
    if (key !== miniKey || !miniBase) {
      miniKey = key;
      miniBase ??= document.createElement('canvas');
      miniBase.width = minimap.width; miniBase.height = minimap.height;
      const g = miniBase.getContext?.('2d');
      if (!g) return;
      g.setTransform(ratio, 0, 0, ratio, 0, 0); g.clearRect(0, 0, mw, mh);
      layout.lanes.forEach(lane => {
        const hue = realmHue(lane.key);
        g.globalAlpha = Math.min(1, tokens.alpha.band * 2); g.fillStyle = hue; g.fillRect(ox + lane.x * scale, oy + lane.y * scale, lane.w * scale, lane.h * scale);
        g.globalAlpha = Math.min(1, tokens.alpha.bandLine + 0.1); g.strokeStyle = hue; g.lineWidth = 1; g.strokeRect(ox + lane.x * scale, oy + lane.y * scale, lane.w * scale, lane.h * scale);
      });
      g.lineWidth = 1;
      display.edges.forEach((edge, index) => {
        const on = !highlight || highlight.edges.has(index), points = flatRoute(index);
        g.globalAlpha = highlight ? (on ? 0.95 : 0.15) : 0.5; g.strokeStyle = edgeColor(edge); g.lineWidth = highlight && on ? 1.6 : 1;
        g.beginPath();
        for (let i = 0; i < points.length; i += 2) { const px = ox + points[i] * scale, py = oy + points[i + 1] * scale; if (i) g.lineTo(px, py); else g.moveTo(px, py); }
        g.stroke();
      });
      for (let index = 0; index < display.nodes.length; index += 1) {
        const box = nodeBox(index), on = !highlight || highlight.nodes.has(index) || matchSet.has(index);
        g.fillStyle = tokens.kind[display.nodes[index].kind] ?? tokens.faint;
        g.globalAlpha = index === selected ? 0.95 : highlight ? (on ? 0.7 : 0.18) : 0.5;
        g.fillRect(ox + box.x * scale, oy + box.y * scale, Math.max(1.5, box.w * scale), Math.max(1.5, box.h * scale));
        if (index === selected || markTarget?.index === index || matchSet.has(index)) {
          g.globalAlpha = 1; g.strokeStyle = index === selected ? tokens.kind[display.nodes[index].kind] ?? tokens.accent : markTarget?.index === index ? tokens.mark : tokens.accent; g.lineWidth = 1.2;
          g.strokeRect(ox + box.x * scale - 1, oy + box.y * scale - 1, Math.max(1.5, box.w * scale) + 2, Math.max(1.5, box.h * scale) + 2);
        }
      }
      g.globalAlpha = 1;
    }
    miniCtx.setTransform(1, 0, 0, 1, 0, 0); miniCtx.clearRect(0, 0, minimap.width, minimap.height); miniCtx.drawImage(miniBase, 0, 0);
    miniCtx.setTransform(ratio, 0, 0, ratio, 0, 0);
    // The view box, clipped to the graph so a view wider or taller than the
    // graph still shows as a box.
    const x0 = Math.max(ox - 3, ox + view.x * scale), y0 = Math.max(oy - 3, oy + view.y * scale);
    const x1 = Math.min(ox + layout.width * scale + 3, ox + (view.x + cssW / view.z) * scale), y1 = Math.min(oy + layout.height * scale + 3, oy + (view.y + cssH / view.z) * scale);
    const vx = Math.min(x0, x1 - 4), vy = Math.min(y0, y1 - 4), vw = Math.max(4, x1 - x0), vh = Math.max(4, y1 - y0);
    miniCtx.fillStyle = tokens.viewport; miniCtx.globalAlpha = 0.08; miniCtx.fillRect(vx, vy, vw, vh); miniCtx.globalAlpha = 1;
    miniCtx.strokeStyle = tokens.viewport; miniCtx.lineWidth = 1.5; miniCtx.strokeRect(vx + 0.75, vy + 0.75, Math.max(2, vw - 1.5), Math.max(2, vh - 1.5));
  }
  const miniPointer = {down: false};
  const miniJump = event => {
    if (!miniFit || !layout) return;
    const rect = minimap.getBoundingClientRect(), gx = (event.clientX - rect.left - miniFit.ox) / miniFit.scale, gy = (event.clientY - rect.top - miniFit.oy) / miniFit.scale;
    view.x = gx - cssW / view.z / 2; view.y = gy - cssH / view.z / 2; requestDraw();
  };
  minimap.addEventListener('pointerdown', event => { miniPointer.down = true; minimap.setPointerCapture?.(event.pointerId); miniJump(event); event.preventDefault(); });
  minimap.addEventListener('pointermove', event => { if (miniPointer.down) miniJump(event); });
  minimap.addEventListener('pointerup', () => { miniPointer.down = false; canvas.focus({preventScroll: true}); });

  // View -------------------------------------------------------------------
  /** Screen room the floating heading and tools take at the top. */
  const topInset = () => Math.max(56, (tools.offsetTop ?? 0) + (tools.offsetHeight ?? 0), (heading.offsetTop ?? 0) + (heading.offsetHeight ?? 0)) + 12;
  /** The zoom and position that show the whole graph under the heading,
   * centred. */
  function fitted(cap = 1) {
    const inset = topInset(), room = Math.max(40, cssH - inset - 16);
    const z = Math.min(cap, Math.max(0.02, Math.min((cssW - 32) / layout.width, room / layout.height)));
    return {z, x: (layout.width - cssW / z) / 2, y: (layout.height - room / z) / 2 - inset / z};
  }
  /** The part of the stage a card can be shown in: under the heading, above
   * a Details sheet, and clear of the minimap. */
  function freeArea() {
    // In a narrow panel Details is a drawer over the right of the canvas.
    const drawer = detailsOpen && globalThis.getComputedStyle?.(inspector)?.position === 'absolute' ? inspector.offsetWidth ?? 0 : 0;
    const mini = minimapOn && !host.hasAttribute('data-all-in-view') && minimap.offsetWidth ? {w: minimap.offsetWidth + 14, h: minimap.offsetHeight + 14} : null;
    return {top: topInset(), bottom: cssH - 8, left: 8, right: cssW - drawer - 8, mini: drawer ? null : mini};
  }
  /** First view: the whole graph when its rows stay legible; else reading
   * size at the top of the first band, the full width in view when it fits,
   * so a tall session reads from its top down like a CFG. */
  function start() {
    if (!layout || cssW <= 1) { needsStart = true; return; }
    const whole = fitted();
    if (whole.z >= FLOW_GRAPH_TEXT_ZOOM) { view = whole; requestDraw(); return; }
    const room = Math.max(120, cssW - 32 - (minimapOn ? Math.max(72, Math.min(170, cssW * 0.16)) + 14 : 0)), first = layout.lanes[0];
    view.z = Math.min(1, room / layout.width);
    if (view.z >= FLOW_GRAPH_START_ZOOM) view.x = layout.width / 2 - (16 + room / 2) / view.z;
    else {
      view.z = FLOW_GRAPH_START_ZOOM;
      let best = -1;
      display.nodes.forEach((node, index) => {
        if (node.context !== first?.key || layout.layer[index] !== 0) return;
        if (best < 0 || (node.hits ?? 0) > (display.nodes[best].hits ?? 0)) best = index;
      });
      const at = best >= 0 ? layout.x[best] + layout.w[best] / 2 : layout.width / 2;
      view.x = Math.max(-16, Math.min(at - (16 + room / 2) / view.z, layout.width - cssW / view.z));
    }
    view.y = (first ? first.y : 0) - (topInset() + 4) / view.z;
    requestDraw();
  }
  function fit() {
    if (!layout || cssW <= 1) return;
    view = fitted(1.2); requestDraw();
  }
  function zoomAt(factor, cx = cssW / 2, cy = cssH / 2) {
    const z = Math.min(2.5, Math.max(0.02, view.z * factor)), gx = view.x + cx / view.z, gy = view.y + cy / view.z;
    view.z = z; view.x = gx - cx / z; view.y = gy - cy / z; hideTooltip(); requestDraw();
  }
  function centerOn(index) {
    const box = nodeBox(index), area = freeArea();
    if (view.z < FLOW_GRAPH_TEXT_ZOOM) view.z = 0.95;
    const midX = (area.left + area.right - (area.mini ? area.mini.w : 0)) / 2, midY = (area.top + area.bottom) / 2;
    view.x = box.x + box.w / 2 - midX / view.z; view.y = box.y + Math.min(box.h, (area.bottom - area.top) / view.z * 0.6) / 2 - midY / view.z; requestDraw();
  }
  function ensureVisible(index) {
    const box = nodeBox(index), area = freeArea(), margin = 24;
    const sx = (box.x - view.x) * view.z, sy = (box.y - view.y) * view.z, sw = box.w * view.z, sh = Math.min(box.h, 120) * view.z;
    const underMini = area.mini && sx + sw > cssW - area.mini.w && sy + sh > area.bottom - area.mini.h;
    if (sx - margin < area.left || sy - margin < area.top || sx + sw + margin > area.right || sy + sh + margin > area.bottom || underMini) centerOn(index);
    else requestDraw();
  }
  function showRealm(key) {
    const members = display ? display.nodes.map((node, index) => node.context === key ? index : -1).filter(index => index >= 0) : [];
    if (members.length) { showCards(members); canvas.focus({preventScroll: true}); }
  }
  /** Fits a set of cards when they fit at a legible zoom and says so; else
   * shows the top of the set at reading size and returns false, so a caller
   * can centre the card that matters instead. */
  function showCards(indexes) {
    if (!indexes.length) return false;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const index of indexes) { const box = nodeBox(index); x0 = Math.min(x0, box.x); y0 = Math.min(y0, box.y); x1 = Math.max(x1, box.x + box.w); y1 = Math.max(y1, box.y + box.h); }
    const area = freeArea(), roomW = area.right - area.left - 32 - (area.mini ? area.mini.w : 0), roomH = area.bottom - area.top - 24;
    const z = Math.min(1, roomW / (x1 - x0 + 40), roomH / (y1 - y0 + 40));
    if (z >= 0.66) { view.z = z; view.x = (x0 + x1) / 2 - (area.left + roomW / 2 + 16) / z; view.y = (y0 + y1) / 2 - (area.top + roomH / 2 + 12) / z; requestDraw(); return true; }
    view.z = FLOW_GRAPH_START_ZOOM; view.x = (x0 + x1) / 2 - (area.left + roomW / 2 + 16) / view.z; view.y = y0 - (area.top + 24) / view.z;
    requestDraw();
    return false;
  }

  // Selection and highlight ---------------------------------------------------
  function applyHighlight(paths, label, reveal = true) {
    if (!paths?.length) { highlight = null; highlightLabel = ''; requestDraw(); return; }
    highlight = {...flowGraphHighlight(model, display, paths), source: paths};
    highlightLabel = label;
    if (reveal) requestDraw();
  }
  const requestPaths = key => key && model ? model.paths.filter(path => String(path.process_id) === String(key.process) && path.requests?.includes(String(key.request))) : [];
  function renderSelection() {
    // A chosen request whose stack another selection replaced can be lit again.
    requestAgain.hidden = !(requestKey && !highlightFromRequest && requestPaths(requestKey).length);
    if (selected < 0 || !display?.nodes[selected]) { if (!requestKey) selectionText.textContent = ''; return; }
    const node = display.nodes[selected], card = cards?.[selected], row = selectedRow >= 0 ? card?.rows[selectedRow] : null;
    const parts = [flowGraphNodeName(node)];
    if (row) parts.push(`${row.op} ${row.target}${row.note ? ` (${row.note})` : ''}`);
    else parts.push(card?.location ?? flowGraphNodeDetail(node));
    parts.push(model.contexts[node.context]?.label.title ?? '');
    if (highlight) parts.push(`${highlight.paths} distinct ${highlight.paths === 1 ? 'stack' : 'stacks'}`);
    selectionText.textContent = parts.filter(Boolean).join(' · ');
  }
  function select(index, {reveal = true, focusPaths = true, row = -1} = {}) {
    if (!display || index < 0 || index >= display.nodes.length) return;
    selected = index; selectedRow = row;
    const node = display.nodes[index];
    if (focusPaths) {
      highlightFromRequest = false;
      const paths = flowGraphPathsThrough(model, node.members);
      applyHighlight(paths, `${paths.length.toLocaleString()} ${paths.length === 1 ? 'stack passes' : 'stacks pass'} through ${flowGraphNodeName(node)}`, false);
    }
    renderSelection(); renderInspector();
    if (reveal) ensureVisible(index); else requestDraw();
    notify();
  }
  function clearSelection() {
    selected = -1; selectedRow = -1; highlight = null; highlightLabel = ''; highlightFromRequest = false; selectionText.textContent = '';
    renderSelection(); renderInspector(); requestDraw();
    notify();
  }

  // Workspace API ---------------------------------------------------------------
  /** What a host is told about a card and its chosen row. A chain card is
   * keyed by its first member, and `select(key)` with any member's key finds
   * the chain. Realm facts come from the node's context. */
  function selectionInfo(index, rowIndex = -1) {
    const node = display?.nodes[index];
    if (!node || !model) return null;
    const context = model.contexts[node.context], first = model.nodes[node.members[0]], item = rowIndex >= 0 ? cards?.[index]?.rows[rowIndex] : null;
    return {key: flowGraphNodeKey(node.kind === 'chain' ? first : node), kind: node.kind, name: flowGraphNodeName(node), location: flowGraphNodeLocation(node) || null,
      process_id: context?.process_id ?? null, execution_context_id: context?.execution_context_id ?? null, url: node.url ?? null, artifact_id: node.artifact_id ?? null,
      function_index: node.function_index ?? null, row: item ? {index: rowIndex, site: item.site, op: item.op, target: item.target} : null,
      request: highlightFromRequest && requestKey ? {process: requestKey.process, request: requestKey.request} : null,
      callers: neighbours(index, 'to', 'from'), callees: neighbours(index, 'from', 'to')};
  }
  /** Up to eight cards on drawn edges into or out of a card, most stacks first. */
  function neighbours(index, side, other) {
    const seen = new Map();
    for (const edge of display?.edges ?? []) {
      if (edge[side] !== index || edge[other] === index) continue;
      const peer = display.nodes[edge[other]];
      if (!peer) continue;
      const key = flowGraphNodeKey(peer.kind === 'chain' ? model.nodes[peer.members[0]] : peer);
      const entry = seen.get(key) ?? {key, name: flowGraphNodeName(peer), kind: peer.kind, note: edge.kind, count: 0};
      entry.count += edge.count ?? 1; seen.set(key, entry);
    }
    return [...seen.values()].sort((a, b) => b.count - a.count).slice(0, 8);
  }
  /** Tells the host when the selected card, row or lit request changed. */
  function notify() {
    const info = selected >= 0 ? selectionInfo(selected, selectedRow) : null;
    const signature = info ? JSON.stringify([info.key, info.row?.index ?? -1, info.request]) : '';
    if (signature === reported) return;
    reported = signature;
    if (typeof onSelect !== 'function') return;
    try { onSelect(info, {requested: hostDriven}); } catch (problem) { console.error(problem); }
  }
  /** Display index by the key of every model node a card holds. */
  function indexOfKey(key) {
    if (!display || !model) return -1;
    if (!keyIndex) {
      keyIndex = new Map();
      display.nodes.forEach((node, index) => node.members.forEach(member => { const text = flowGraphNodeKey(model.nodes[member]); if (!keyIndex.has(text)) keyIndex.set(text, index); }));
    }
    return keyIndex.get(String(key)) ?? -1;
  }
  function selectKey(key, {reveal = true} = {}) {
    if (key === null || key === undefined) return false;
    // Before the graph is drawn the key waits for it.
    if (!layout || layingOut) { pendingKey = {key: String(key), reveal}; return false; }
    const index = indexOfKey(key);
    if (index < 0) return false;
    select(index, {reveal: false});
    if (reveal) centerOn(index);
    return true;
  }
  /** The card (and row) a timeline sample's {artifact_id, function_index,
   * offset} names: a Wasm function of that module and index, and its row
   * whose call site is at that module offset, when one is. */
  function findMark() {
    markTarget = null;
    if (!mark || !display || !cards) return;
    for (let index = 0; index < display.nodes.length && !markTarget; index += 1) {
      const node = display.nodes[index];
      const hit = node.members.findIndex(member => { const item = model.nodes[member]; return item?.kind === 'wasm' && String(item.artifact_id ?? '') === mark.artifact_id && Number(item.function_index) === mark.function_index; });
      if (hit < 0) continue;
      let row = -1;
      if (node.kind === 'chain') row = hit < cards[index].rows.length ? hit : -1;
      else if (mark.offset !== null) row = cards[index].rows.findIndex(item => (item.members ?? []).some(edge => (model.doc.edges[edge]?.sites ?? []).some(site => site.module_offset !== undefined && Number(site.module_offset) === mark.offset)));
      markTarget = {index, row};
    }
  }
  function setMark(next) {
    mark = next && typeof next === 'object' && next.artifact_id !== undefined && next.artifact_id !== null && Number.isFinite(Number(next.function_index))
      ? {artifact_id: String(next.artifact_id), function_index: Number(next.function_index), offset: next.offset === undefined || next.offset === null || !Number.isFinite(Number(next.offset)) ? null : Number(next.offset)} : null;
    findMark(); miniKey = ''; requestDraw();
    return Boolean(markTarget);
  }
  function toggleChain(index) {
    const node = display?.nodes[index];
    if (!node) return;
    if (node.kind === 'chain') expanded.add(node.key);
    else {
      // A member of an expanded chain folds it again.
      const key = display.foldKey.get(node.members[0]);
      if (!key) return;
      expanded.delete(key);
    }
    selected = index; rebuild();
  }
  function highlightRequest(key, {reveal = true} = {}) {
    requestKey = key;
    if (!model || !display || !key) return false;
    const paths = requestPaths(key);
    if (!paths.length) {
      // The previous request's stack must not stay lit for this one.
      clearSelection();
      requestKey = key; requestAgain.hidden = true;
      selectionText.textContent = 'The selected request has no recorded stack in this graph.';
      return false;
    }
    applyHighlight(paths, 'Stack of the selected request');
    highlightFromRequest = true;
    // The request is a row of the function that made it, or its own card
    // when nothing recorded calls it.
    const sinks = new Set(paths.flatMap(path => path.nodes.filter(node => FLOW_GRAPH_SINKS.has(model.nodes[node]?.kind))));
    let target = null;
    cards.forEach((card, index) => { if (target || !highlight.nodes.has(index)) return; const row = card.rows.findIndex(item => item.sink?.members.some(member => sinks.has(member))); if (row >= 0) target = {index, row}; });
    if (!target) { const own = [...sinks].map(node => display.displayOf[node]).find(index => index >= 0); if (own !== undefined) target = {index: own, row: -1}; }
    if (target) select(target.index, {focusPaths: false, row: target.row, reveal: false});
    // The whole stack in view when it fits legibly, else its top.
    if (reveal && !showCards([...highlight.nodes]) && target) centerOn(target.index);
    const caller = target ? display.nodes[target.index] : null, sink = target && target.row >= 0 ? cards[target.index].rows[target.row] : null;
    selectionText.textContent = [`Selected request${sink ? ` ${sink.target}` : ''}`, caller ? `\u2190 ${flowGraphNodeName(caller)} ${cards[target.index].location}` : '', caller ? model.contexts[caller.context]?.label.title : '',
      `${highlight.paths} distinct ${highlight.paths === 1 ? 'stack' : 'stacks'}`, `${highlight.nodes.size} cards`].filter(Boolean).join(' · ');
    requestAgain.hidden = true;
    return true;
  }
  const canOpen = node => Boolean(node?.artifact_id && node.status === 'resolved' && !FLOW_GRAPH_SINKS.has(node.kind));
  function activate(index) {
    const node = display?.nodes[index];
    if (!node) return;
    if (node.kind === 'chain') toggleChain(index);
    // A Wasm function follows into the host's pane when it has one.
    else if (node.kind === 'wasm' && typeof onFollow === 'function') { try { onFollow(selectionInfo(index, index === selected ? selectedRow : -1)); } catch (problem) { console.error(problem); } }
    else if (canOpen(node)) open(node);
  }
  /** Follows a row's call to the card it reaches; Backspace comes back. */
  function follow(index, row) {
    const edge = display.edges[cards[index]?.rows[row]?.edge];
    if (!edge) { if (cards[index]?.rows[row]?.sink) setDetails(true); return; }
    if (edge.to === index) return;
    remember();
    select(edge.to);
  }
  function remember() {
    if (selected < 0) return;
    history.push({key: flowGraphNodeKey(model.nodes[display.nodes[selected].members[0]]), row: selectedRow, view: {...view}});
    if (history.length > 64) history.shift();
  }
  function back() {
    const entry = history.pop();
    if (!entry) { flash('Nothing to go back to'); return; }
    const index = display.nodes.findIndex(node => flowGraphNodeKey(model.nodes[node.members[0]]) === entry.key);
    if (index < 0) { back(); return; }
    view = {...entry.view}; select(index, {reveal: false, row: entry.row});
  }
  /** Goes to the caller that reached this card most often. */
  function toCaller(index) {
    let best = null;
    for (const edge of display.edges) if (edge.to === index && edge.from !== index && (!best || edge.count > best.count)) best = edge;
    if (!best) { flash('No recorded caller'); return; }
    remember();
    select(best.from, {row: cards[best.from].rows.findIndex(row => row.edge === display.edges.indexOf(best))});
  }
  /** J and K step through the selected card's calls. */
  function stepRow(direction) {
    if (selected < 0) return;
    const count = cards[selected]?.rows.length ?? 0;
    if (!count) return;
    const next = selectedRow < 0 ? (direction > 0 ? 0 : count - 1) : Math.max(0, Math.min(count - 1, selectedRow + direction));
    if (next === selectedRow) return;
    select(selected, {reveal: false, focusPaths: false, row: next});
  }
  function copy(text, what) {
    if (!text) return;
    const clipboard = globalThis.navigator?.clipboard;
    if (!clipboard?.writeText) { flash(`Copy is not available here. ${what}: ${text}`, 'error'); return; }
    clipboard.writeText(text).then(() => flash(`Copied ${what.toLowerCase()}`), () => flash(`Could not copy the ${what.toLowerCase()}`, 'error'));
  }

  function applyFilter() {
    const needle = filter.value.trim().toLowerCase();
    matches = [];
    if (needle && display) display.nodes.forEach((node, index) => {
      const context = model.contexts[node.context]?.label;
      const haystack = [flowGraphNodeName(node), flowGraphNodeDetail(node), node.url ?? '', context?.title ?? '', ...(node.kind === 'chain' ? node.members.map(member => flowGraphNodeName(model.nodes[member])) : []),
        ...(display.sinkRows?.[index] ?? []).map(row => flowGraphNodeName(row.sink))].join(' ').toLowerCase();
      if (haystack.includes(needle)) matches.push(index);
    });
    matchSet = new Set(matches);
    matchIndex = -1;
    find.hidden = !needle;
    renderMatches();
    miniKey = '';
    requestDraw();
  }
  function renderMatches() {
    matchLabel.textContent = !matches.length ? 'no matches' : matchIndex < 0 ? `${matches.length.toLocaleString()} ${matches.length === 1 ? 'match' : 'matches'}` : `${(matchIndex + 1).toLocaleString()} of ${matches.length.toLocaleString()}`;
  }
  function stepMatch(direction) {
    if (!matches.length) return;
    matchIndex = (matchIndex + direction + matches.length) % matches.length;
    renderMatches();
    // A match is shown at reading size, and the other matches stay undimmed.
    select(matches[matchIndex], {reveal: false}); centerOn(matches[matchIndex]);
  }
  let filterTimer = 0;
  filter.addEventListener('input', () => { clearTimeout(filterTimer); filterTimer = setTimeout(applyFilter, 120); });
  filter.addEventListener('keydown', event => {
    if (event.key === 'Enter' && matches.length) { event.preventDefault(); stepMatch(event.shiftKey ? -1 : 1); }
    else if (event.key === 'Escape' && filter.value) { event.stopPropagation(); filter.value = ''; applyFilter(); }
  });

  // Details -------------------------------------------------------------------
  function renderInspector() {
    host.toggleAttribute('data-selected', selected >= 0);
    inspector.replaceChildren();
    if (!model) return;
    const close = button('Close', () => { setDetails(false); canvas.focus({preventScroll: true}); }, 'Hide details', 'flow-graph-tool flow-graph-inspector-close');
    inspector.append(close);
    if (selected < 0 || !display?.nodes[selected]) { renderOverview(); return; }
    const node = display.nodes[selected], context = model.contexts[node.context];
    const titleRow = make('div', 'flow-inspector-head');
    const tag = make('span', 'flow-kind-tag', FLOW_GRAPH_KIND_LABELS[node.kind] ?? node.kind); tag.dataset.kind = node.kind;
    titleRow.append(make('h3', 'flow-inspector-title', flowGraphNodeName(node)), tag);
    inspector.append(titleRow);
    const facts = make('dl', 'flow-inspector-facts');
    const fact = (label, value) => { if (value === undefined || value === null || value === '') return; facts.append(make('dt', '', label), make('dd', '', String(value))); };
    if (node.kind === 'chain') {
      fact('Folded', `${node.members.length} pass-through functions in one realm`);
      fact('Realm', `${context?.label.title ?? ''}\n${context?.label.detail ?? ''}`);
      inspector.append(facts);
      const list = make('ol', 'flow-inspector-list');
      node.members.forEach(member => list.append(make('li', '', `${flowGraphNodeName(model.nodes[member])} · ${flowGraphNodeDetail(model.nodes[member])}`)));
      inspector.append(list);
      const expand = make('button', 'secondary-button', 'Expand chain'); expand.type = 'button'; expand.addEventListener('click', () => { toggleChain(selected); canvas.focus({preventScroll: true}); });
      inspector.append(expand);
      return;
    }
    const foldable = display.foldKey.get(node.members[0]);
    if (!FLOW_GRAPH_SINKS.has(node.kind)) {
      fact('Location', node.url ?? null);
      if (node.line) fact('Line', `${node.line}:${node.column}${node.kind === 'eval' ? ` in VM${node.script_id}` : ''}`);
    }
    fact('Realm', `${context?.label.title ?? ''}\n${context?.label.detail ?? ''}`);
    if (node.kind === 'wasm') fact('Function index', node.function_index);
    if (node.script_id !== undefined) fact('Script ID', node.kind === 'eval' ? `${node.script_id} (eval or new Function)` : node.script_id);
    fact('Records', `${node.hits.toLocaleString()} ${FLOW_GRAPH_SINKS.has(node.kind) ? (node.hits === 1 ? 'occurrence' : 'occurrences') : `stack ${node.hits === 1 ? 'record passes' : 'records pass'} through it`}`);
    fact('Distinct stacks', (cards?.[selected]?.stacks ?? 0).toLocaleString());
    if (node.entries) fact('Task entry', `${node.entries.toLocaleString()} ${node.entries === 1 ? 'time' : 'times'}`);
    if (node.leaves) fact('Innermost', `${node.leaves.toLocaleString()} ${node.leaves === 1 ? 'time' : 'times'}`);
    if (node.schedules) fact('Scheduled', Object.entries(node.schedules).map(([task, count]) => `${FLOW_GRAPH_TASKS[task] ?? task} ×${count}`).join(', '));
    if (node.status !== 'resolved') fact('Unresolved', FLOW_GRAPH_REASONS[node.reason] ?? node.reason);
    inspector.append(facts);
    if (node.chain_cut) inspector.append(make('p', 'flow-inspector-note', 'Earlier async callers were not recorded: a scheduling stack in its task chain was not retained, or a microtask hop names no recorded task.'));
    const actions = make('div', 'flow-inspector-actions');
    if (canOpen(node)) {
      const openButton = make('button', 'secondary-button', 'Open in Sources'); openButton.type = 'button';
      openButton.addEventListener('click', () => open(node)); actions.append(openButton);
    }
    if (foldable) {
      const fold = make('button', 'secondary-button', 'Fold chain'); fold.type = 'button';
      fold.addEventListener('click', () => { toggleChain(selected); canvas.focus({preventScroll: true}); }); actions.append(fold);
    }
    if (actions.children.length) inspector.append(actions);
    const neighbours = (incoming) => display.edges.map((edge, index) => ({edge, index})).filter(({edge}) => (incoming ? edge.to : edge.from) === selected && edge.from !== edge.to);
    for (const [label, incoming] of [['Called by', true], ['Calls', false]]) {
      const items = neighbours(incoming);
      if (!items.length) continue;
      inspector.append(make('h4', 'flow-inspector-heading', `${label} · ${items.length}`));
      const list = make('ul', 'flow-inspector-list');
      items.sort((a, b) => b.edge.count - a.edge.count).slice(0, 64).forEach(({edge}) => {
        const other = incoming ? edge.from : edge.to, item = make('li');
        const link = make('button', 'flow-inspector-link', flowGraphNodeName(display.nodes[other])); link.type = 'button';
        link.addEventListener('click', () => { select(other); canvas.focus({preventScroll: true}); });
        const sites = flowGraphEdgeSites(model, edge);
        const meta = [edge.kind === 'task' ? FLOW_GRAPH_TASKS[edge.task] ?? edge.task : edge.kind, ...edge.crosses.map(cross => ({frame: 'frame boundary', language: 'JS ↔ Wasm', dynamic: 'into eval'})[cross]),
          ...(sites.length ? [`at ${sites.slice(0, 4).join(', ')}${sites.length > 4 ? '…' : ''}`] : []), `×${edge.count.toLocaleString()}`];
        item.append(link, make('span', 'flow-inspector-meta', meta.join(' · ')));
        list.append(item);
      });
      inspector.append(list);
      if (items.length > 64) inspector.append(make('p', 'flow-inspector-note', `${items.length - 64} more are in the graph.`));
    }
    const made = display.sinkRows?.[selected] ?? [];
    if (made.length) {
      inspector.append(make('h4', 'flow-inspector-heading', `Requests, navigations and cookie writes · ${made.length}`));
      const list = make('ul', 'flow-inspector-list');
      [...made].sort((a, b) => b.count - a.count).slice(0, 64).forEach(row => {
        const item = make('li'), sites = flowGraphEdgeSites(model, row);
        item.append(make('span', 'flow-inspector-sink', flowGraphNodeName(row.sink)), make('span', 'flow-inspector-meta', [FLOW_GRAPH_KIND_LABELS[row.sink.kind] ?? row.sink.kind, ...(sites.length ? [`at ${sites.slice(0, 4).join(', ')}`] : []), `×${row.count.toLocaleString()}`].join(' · ')));
        list.append(item);
      });
      inspector.append(list);
      if (made.length > 64) inspector.append(make('p', 'flow-inspector-note', `${made.length - 64} more.`));
    }
  }

  function renderOverview() {
    const doc = model.doc;
    inspector.append(make('h3', 'flow-inspector-title', 'Realms'));
    const list = make('ul', 'flow-inspector-realms');
    model.contexts.forEach(context => {
      const item = make('li');
      const counts = Object.entries(context.counts ?? {}).map(([kind, count]) => `${count} ${FLOW_GRAPH_KIND_TAGS[kind] ?? kind}`).join(' · ');
      // A realm jumps to its cluster.
      const name = make('button', 'flow-inspector-link flow-inspector-realm', context.label.title); name.type = 'button';
      name.addEventListener('click', () => showRealm(context.index));
      const engine = layout?.engine?.realms?.find(entry => entry.key === context.index);
      const laidBy = !engine || engine.reason === 'one card' ? '' : engine.engine === 'triskel' ? 'laid out by Triskel' : `layered layout: ${engine.reason}`;
      item.append(name, make('span', '', context.label.detail), make('span', 'flow-inspector-meta', counts));
      if (laidBy) item.append(make('span', 'flow-inspector-meta', laidBy));
      list.append(item);
    });
    inspector.append(list);
    const crossing = display ? display.edges.filter(edge => edge.crosses.length) : [];
    if (crossing.length) {
      const frames = crossing.filter(edge => edge.crosses.includes('frame')).length, languages = crossing.filter(edge => edge.crosses.includes('language')).length, dynamic = crossing.filter(edge => edge.crosses.includes('dynamic')).length;
      inspector.append(make('p', 'flow-inspector-note', `Crossings: ${frames} frame, ${languages} JS ↔ Wasm, ${dynamic} into eval.`));
    }
    const decoded = doc.stacks?.decoded ?? 0, distinct = doc.stacks?.distinct ?? 0;
    inspector.append(make('p', 'flow-inspector-note', `${(doc.stacks?.occurrences ?? 0).toLocaleString()} stack records, ${distinct.toLocaleString()} distinct, ${decoded.toLocaleString()} with retained frames.`));
    const unresolved = Object.entries(doc.stacks?.unresolved ?? {});
    if (unresolved.length) inspector.append(make('p', 'flow-inspector-note', `Not decoded: ${unresolved.map(([reason, count]) => `${count} ${reason.replaceAll('_', ' ')}`).join(', ')}.`));
    const notWalked = Object.entries(doc.stacks?.not_walked ?? {});
    if (notWalked.length) inspector.append(make('p', 'flow-inspector-note', `No script on the stack: ${notWalked.map(([reason, count]) => `${count} ${reason.replaceAll('_', ' ')}`).join(', ')}.`));
    inspector.append(make('h4', 'flow-inspector-heading', 'Not shown'));
    const missing = make('ul', 'flow-inspector-list'); (doc.not_shown ?? []).forEach(item => missing.append(make('li', '', item))); inspector.append(missing);
    inspector.append(make('p', 'flow-inspector-hint', 'Select a card to light every stack through it. Choose a request above to light its own stack.'));
  }

  // Tooltip -------------------------------------------------------------------
  function hideTooltip() { tooltip.hidden = true; }
  function showTooltip(px, py) {
    const facts = [];
    let heading = '', kind = '';
    if (hover.node >= 0 && hover.row < 0) {
      const node = display.nodes[hover.node], context = model.contexts[node.context]?.label;
      heading = flowGraphNodeName(node); kind = node.kind;
      facts.push(['kind', FLOW_GRAPH_KIND_LABELS[node.kind] ?? node.kind, 'kind']);
      const location = flowGraphNodeLocation(node);
      if (location && !FLOW_GRAPH_SINKS.has(node.kind)) facts.push(['at', location, 'location']);
      facts.push(['realm', `${context?.title ?? ''} · ${context?.detail ?? ''}`, '']);
      facts.push(['stacks', `${(cards[hover.node]?.stacks ?? 0).toLocaleString()} distinct`, 'count']);
      facts.push(['records', `${(node.hits ?? 0).toLocaleString()}`, 'count']);
      if (node.entries) facts.push(['task entry', node.entries.toLocaleString(), 'count']);
      if (node.status !== 'resolved') facts.push(['unresolved', FLOW_GRAPH_REASONS[node.reason] ?? node.reason ?? '', '']);
      if (node.chain_cut) facts.push(['callers', 'earlier async callers not recorded', '']);
    } else if (hover.row >= 0 && cards[hover.node]?.rows[hover.row]?.sink) {
      const row = cards[hover.node].rows[hover.row], sink = row.sink, context = model.contexts[sink.context]?.label;
      heading = flowGraphNodeName(sink); kind = sink.kind;
      facts.push(['kind', FLOW_GRAPH_KIND_LABELS[sink.kind] ?? sink.kind, 'kind']);
      facts.push(['from', flowGraphNodeName(display.nodes[hover.node]), '']);
      if (row.site) facts.push(['site', flowGraphEdgeSites(model, {members: row.members}).slice(0, 6).join(', '), 'location']);
      facts.push(['realm', context?.title ?? '', '']);
      facts.push(['seen', `${(sink.hits ?? 0).toLocaleString()} in this session, ${row.count ? row.count.slice(1) : '1'} from here`, 'count']);
    } else {
      const edgeIndex = hover.row >= 0 ? cards[hover.node]?.rows[hover.row]?.edge : hover.edge, edge = display.edges[edgeIndex];
      if (!edge) { hideTooltip(); return; }
      heading = `${edge.kind === 'task' ? FLOW_GRAPH_TASKS[edge.task] ?? edge.task : edge.kind}`; kind = flowGraphEdgeFamily(edge);
      facts.push(['from', flowGraphNodeName(display.nodes[edge.from]), '']);
      facts.push(['to', flowGraphNodeName(display.nodes[edge.to]), '']);
      const note = flowGraphEdgeNote(model, display, edge);
      if (note) facts.push(['crosses', note, 'cross']);
      const sites = flowGraphEdgeSites(model, edge);
      if (sites.length) facts.push(['site', sites.slice(0, 6).join(', ') + (sites.length > 6 ? ' …' : ''), 'location']);
      facts.push(['walked', `${edge.count.toLocaleString()} ${edge.count === 1 ? 'time' : 'times'}`, '']);
    }
    tooltip.replaceChildren();
    const head = make('strong', 'flow-graph-tooltip-title', heading); head.dataset.kind = kind; tooltip.append(head);
    const list = make('dl');
    for (const [label, value, tone] of facts) { const dd = make('dd', '', value); if (tone) dd.dataset.tone = tone; list.append(make('dt', '', label), dd); }
    tooltip.append(list);
    tooltip.hidden = false;
    const tw = tooltip.offsetWidth || 240, th = tooltip.offsetHeight || 100;
    // Beside the card, at the row, so it never covers what it describes or
    // the callee about to be followed; at the pointer only for an edge.
    let left = px + 16, top = py + 18;
    if (hover.node >= 0) {
      const box = nodeBox(hover.node), right = (box.x + box.w - view.x) * view.z + 12, leftSide = (box.x - view.x) * view.z - 12 - tw;
      left = right + tw <= cssW - 8 ? right : leftSide >= 8 ? leftSide : left;
      top = ((hover.row >= 0 ? rowTop(box, hover.row) : box.y) - view.y) * view.z - 4;
    }
    left = Math.max(8, Math.min(left, cssW - tw - 8)); top = Math.max(8, Math.min(top, cssH - th - 8));
    tooltip.style.left = `${left}px`; tooltip.style.top = `${top}px`;
  }

  // Context menu --------------------------------------------------------------
  let menuItems = [];
  function closeMenu(refocus = true) {
    if (menu.hidden) return;
    menu.hidden = true; menuItems = [];
    if (refocus) canvas.focus({preventScroll: true});
  }
  /** A call site as a researcher pastes it: file:line:column, or the module
   * and its offset. */
  function callSite(index, row) {
    const node = display.nodes[index], item = cards[index]?.rows[row], site = item?.site?.replace(/\+\d+$/, '');
    if (!site) return '';
    const file = node.kind === 'eval' ? `VM${node.script_id}` : node.url ?? '';
    return site.startsWith('+0x') ? `${file} ${site}`.trim() : `${file}:${site}`;
  }
  const hasCaller = index => display.edges.some(edge => edge.to === index && edge.from !== index);
  function openMenu(index, px, py, row = -1) {
    if (!display?.nodes[index]) return;
    if (selected !== index || selectedRow !== row) select(index, {reveal: false, row, focusPaths: selected !== index});
    hideTooltip();
    const node = display.nodes[index], foldable = node.kind === 'chain' || display.foldKey.get(node.members[0]), item = row >= 0 ? cards[index].rows[row] : null;
    const entries = [
      ...(item ? [...(item.edge >= 0 ? [['Follow call', '↩', true, () => follow(index, row)]] : []), ['Copy call site', 'S', Boolean(callSite(index, row)), () => copy(callSite(index, row), 'Call site')], null] : []),
      ['Open in Sources', item ? 'O' : '↩', canOpen(node), () => open(node)],
      ...(foldable ? [[node.kind === 'chain' ? 'Expand chain' : 'Fold chain', 'Space', true, () => toggleChain(index)]] : []),
      null,
      ['Go to caller', 'U', hasCaller(index), () => toCaller(index)],
      ['Center on card', 'F', true, () => centerOn(index)],
      ['Show details', 'I', true, () => setDetails(true)],
      null,
      ['Copy name', 'C', true, () => copy(flowGraphNodeName(node), 'Name')],
      ['Copy location', 'L', Boolean(flowGraphNodeLocation(node)), () => copy(flowGraphNodeLocation(node), 'Location')],
    ];
    menu.replaceChildren(); menuItems = [];
    for (const entry of entries) {
      if (!entry) { const rule = make('div', 'flow-graph-menu-rule'); rule.setAttribute('role', 'separator'); menu.append(rule); continue; }
      const [label, shortcut, enabled, action] = entry;
      const item = make('button', 'flow-graph-menu-item'); item.type = 'button'; item.setAttribute('role', 'menuitem'); item.tabIndex = -1; item.disabled = !enabled;
      item.append(make('span', '', label), make('kbd', '', shortcut));
      item.addEventListener('click', () => { closeMenu(); action(); });
      menu.append(item);
      if (enabled) menuItems.push({item, shortcut, action});
    }
    menu.hidden = false;
    const mw = menu.offsetWidth || 220, mh = menu.offsetHeight || 220;
    menu.style.left = `${Math.max(6, Math.min(px, cssW - mw - 6))}px`; menu.style.top = `${Math.max(6, Math.min(py, cssH - mh - 6))}px`;
    menuItems[0]?.item.focus({preventScroll: true});
  }
  menu.addEventListener('keydown', event => {
    const at = menuItems.findIndex(entry => entry.item === document.activeElement);
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); const next = (at + (event.key === 'ArrowDown' ? 1 : -1) + menuItems.length) % menuItems.length; menuItems[next]?.item.focus(); }
    else if (event.key === 'Home' || event.key === 'End') { event.preventDefault(); menuItems[event.key === 'Home' ? 0 : menuItems.length - 1]?.item.focus(); }
    else if (event.key === 'Escape' || event.key === 'Tab') { event.preventDefault(); event.stopPropagation(); closeMenu(); }
    else if (event.key.length === 1 && !event.metaKey && !event.ctrlKey) {
      const entry = menuItems.find(item => item.shortcut.toLowerCase() === event.key.toLowerCase());
      if (entry) { event.preventDefault(); closeMenu(); entry.action(); }
    }
  });
  menu.addEventListener('focusout', event => { if (!menu.contains(event.relatedTarget)) closeMenu(false); });

  // Input ----------------------------------------------------------------------
  const toGraph = (px, py) => [view.x + px / view.z, view.y + py / view.z];
  function hitTest(px, py) {
    if (!layout) return {node: -1, row: -1, edge: -1};
    const [gx, gy] = toGraph(px, py);
    for (let index = display.nodes.length - 1; index >= 0; index -= 1) {
      const box = nodeBox(index);
      if (gx < box.x || gx > box.x + box.w || gy < box.y || gy > box.y + box.h) continue;
      const card = cards[index], first = rowTop(box, 0);
      const row = lodNow() === 2 && gy >= first ? Math.floor((gy - first) / FLOW_GRAPH_CARD.row) : -1;
      return {node: index, row: row >= 0 && row < card.rows.length && (card.rows[row].edge >= 0 || card.rows[row].sink) ? row : -1, edge: -1};
    }
    if (view.z < 0.25) return {node: -1, row: -1, edge: -1};
    const bounds = boundsOfEdges(), tolerance = 5 / view.z;
    let best = -1, bestDistance = tolerance;
    for (let e = 0; e < display.edges.length; e += 1) {
      const at = e * 4;
      if (gx < bounds[at] - tolerance || gx > bounds[at + 2] + tolerance || gy < bounds[at + 1] - tolerance || gy > bounds[at + 3] + tolerance) continue;
      const points = flatRoute(e);
      for (let i = 2; i < points.length; i += 2) {
        const ax = points[i - 2], ay = points[i - 1], bx = points[i], by = points[i + 1], dx = bx - ax, dy = by - ay, length = dx * dx + dy * dy;
        const t = length ? Math.max(0, Math.min(1, ((gx - ax) * dx + (gy - ay) * dy) / length)) : 0;
        const distance = Math.hypot(gx - ax - t * dx, gy - ay - t * dy);
        if (distance < bestDistance) { bestDistance = distance; best = e; }
      }
    }
    return {node: -1, row: -1, edge: best};
  }
  const pointer = {down: false, x: 0, y: 0, moved: false};
  const local = event => { const rect = canvas.getBoundingClientRect(); return [event.clientX - rect.left, event.clientY - rect.top]; };
  canvas.addEventListener('pointerdown', event => {
    if (event.button === 2) return;
    pointer.down = true; pointer.x = event.clientX; pointer.y = event.clientY; pointer.moved = false;
    canvas.setPointerCapture?.(event.pointerId); canvas.focus({preventScroll: true}); hideTooltip(); closeMenu(false);
  });
  canvas.addEventListener('pointermove', event => {
    if (!layout) return;
    if (pointer.down) {
      if (Math.abs(event.clientX - pointer.x) + Math.abs(event.clientY - pointer.y) > 2) pointer.moved = true;
      view.x -= (event.clientX - pointer.x) / view.z; view.y -= (event.clientY - pointer.y) / view.z; pointer.x = event.clientX; pointer.y = event.clientY; requestDraw();
      return;
    }
    const [px, py] = local(event), next = hitTest(px, py);
    const changed = next.node !== hover.node || next.row !== hover.row || next.edge !== hover.edge;
    hover = next;
    canvas.style.cursor = next.row >= 0 || next.edge >= 0 ? 'pointer' : '';
    if (next.node < 0 && next.edge < 0) hideTooltip(); else if (menu.hidden) showTooltip(px, py);
    if (changed) requestDraw();
  });
  canvas.addEventListener('pointerleave', () => { if (pointer.down) return; hover = {node: -1, row: -1, edge: -1}; hideTooltip(); requestDraw(); });
  canvas.addEventListener('pointerup', event => {
    if (!pointer.down) return;
    pointer.down = false;
    if (pointer.moved || !layout) return;
    const [px, py] = local(event), hit = hitTest(px, py);
    if (hit.node >= 0) { select(hit.node, {reveal: false, row: hit.row}); return; }
    if (hit.edge >= 0) { const edge = display.edges[hit.edge]; select(edge.from, {reveal: false, row: cards[edge.from].rows.findIndex(row => row.edge === hit.edge)}); return; }
    clearSelection();
  });
  canvas.addEventListener('dblclick', event => {
    const [px, py] = local(event), hit = hitTest(px, py);
    if (hit.node < 0) return;
    if (hit.row >= 0) follow(hit.node, hit.row); else activate(hit.node);
  });
  canvas.addEventListener('contextmenu', event => {
    const [px, py] = local(event), hit = hitTest(px, py);
    if (hit.node < 0) return;
    event.preventDefault();
    openMenu(hit.node, px, py, hit.row);
  });
  canvas.addEventListener('wheel', event => {
    if (!layout) return;
    event.preventDefault(); hideTooltip(); closeMenu(false);
    if (event.ctrlKey || event.metaKey) { const [px, py] = local(event); zoomAt(Math.exp(-event.deltaY * 0.01), px, py); }
    else { view.x += event.deltaX / view.z; view.y += event.deltaY / view.z; requestDraw(); }
  }, {passive: false});
  function move(dx, dy) {
    if (!display?.nodes.length) return;
    if (selected < 0) { let first = 0; display.nodes.forEach((node, index) => { if (layout.y[index] < layout.y[first] || (layout.y[index] === layout.y[first] && layout.x[index] < layout.x[first])) first = index; }); return select(first); }
    const from = nodeBox(selected), cx = from.x + from.w / 2, cy = from.y + from.h / 2;
    let best = -1, bestScore = Infinity;
    display.nodes.forEach((node, index) => {
      if (index === selected) return;
      const box = nodeBox(index), ddx = box.x + box.w / 2 - cx, ddy = box.y + box.h / 2 - cy;
      const along = dx ? ddx * dx : ddy * dy, across = dx ? Math.abs(ddy) : Math.abs(ddx);
      if (along <= 1) return;
      const score = along + across * 2.5;
      if (score < bestScore) { bestScore = score; best = index; }
    });
    if (best >= 0) select(best);
  }
  canvas.addEventListener('keydown', event => {
    if (!layout) return;
    const key = event.key, panStep = 80 / view.z, plain = !event.metaKey && !event.ctrlKey && !event.altKey; let handled = true;
    hideTooltip();
    // An open key closes before Escape does anything else.
    if (key === 'Escape' && status.hasAttribute('data-key-open')) { setKey(false); event.preventDefault(); event.stopPropagation(); return; }
    // Shift+Backspace is left to the Flow workspace, which walks its trail forward.
    if ((key === 'Backspace' && plain && !event.shiftKey) || (key === 'ArrowLeft' && event.altKey)) back();
    else if (event.shiftKey && key.startsWith('Arrow')) { view.x += key === 'ArrowLeft' ? -panStep : key === 'ArrowRight' ? panStep : 0; view.y += key === 'ArrowUp' ? -panStep : key === 'ArrowDown' ? panStep : 0; requestDraw(); }
    else if (key === 'ArrowDown') move(0, 1); else if (key === 'ArrowUp') move(0, -1); else if (key === 'ArrowLeft') move(-1, 0); else if (key === 'ArrowRight') move(1, 0);
    else if (key === '+' || key === '=') zoomAt(1.25); else if (key === '-' || key === '_') zoomAt(0.8); else if (key === '0') fit();
    else if (key === 'Escape' && (selected >= 0 || highlight)) clearSelection();
    else if (key === 'Escape' && detailsOpen) setDetails(false);
    else if (key === ' ' && selected >= 0) toggleChain(selected);
    // Enter follows the chosen call, as in a disassembler; on the card
    // itself it opens the function or expands the chain.
    else if (key === 'Enter' && selected >= 0) { if (selectedRow >= 0 && cards[selected].rows[selectedRow]?.edge >= 0) follow(selected, selectedRow); else activate(selected); }
    else if (plain && (key === 'j' || key === 'J' || key === 'k' || key === 'K') && selected >= 0) stepRow(key.toLowerCase() === 'j' ? 1 : -1);
    else if (plain && (key === 'u' || key === 'U') && selected >= 0) toCaller(selected);
    else if (plain && (key === 'o' || key === 'O') && selected >= 0 && canOpen(display.nodes[selected])) open(display.nodes[selected]);
    else if (plain && (key === 's' || key === 'S') && selected >= 0 && selectedRow >= 0) copy(callSite(selected, selectedRow), 'Call site');
    else if ((key === 'ContextMenu' || (key === 'F10' && event.shiftKey)) && selected >= 0) {
      const box = nodeBox(selected), rowY = selectedRow >= 0 ? rowTop(box, selectedRow) + FLOW_GRAPH_CARD.row : box.y + 24;
      openMenu(selected, (box.x + Math.min(box.w, 140) - view.x) * view.z, (rowY - view.y) * view.z, selectedRow);
    }
    else if (key === '/') { filter.focus(); filter.select(); }
    else if (plain && (key === 'i' || key === 'I')) setDetails(!detailsOpen);
    else if (plain && (key === 'm' || key === 'M')) { minimapOn = !minimapOn; host.toggleAttribute('data-minimap-off', !minimapOn); miniKey = ''; requestDraw(); }
    else if (plain && (key === 'f' || key === 'F') && selected >= 0) centerOn(selected);
    else if (plain && !event.shiftKey && (key === 'c' || key === 'C') && selected >= 0) copy(flowGraphNodeName(display.nodes[selected]), 'Name');
    else if (plain && !event.shiftKey && (key === 'l' || key === 'L') && selected >= 0) copy(flowGraphNodeLocation(display.nodes[selected]), 'Location');
    else handled = false;
    if (handled) { event.preventDefault(); event.stopPropagation(); }
  });

  return {
    /** Shows the view for one session; loads it the first time or when the session changes. */
    show({session: next, request = null}) {
      visible = true; host.hidden = false;
      readTokens();
      const changed = String(next ?? '') !== String(session ?? ''), first = session === null;
      session = next ?? null;
      // A key asked for before the first session waits for it; one asked for
      // in another session does not carry over.
      if (changed) { model = null; display = null; cards = null; layout = null; selected = -1; selectedRow = -1; highlight = null; keyIndex = null; markTarget = null; if (!first) pendingKey = null; generation += 1; runner.cancel(); forHost(notify); }
      // Evidence polls re-render Flow; only a newly chosen request moves
      // the highlight, so a card the researcher picked stays lit.
      const requestText = request ? `${request.process}:${request.request}` : '';
      const newRequest = requestText !== shownRequest;
      shownRequest = requestText;
      requestKey = request;
      resize();
      if (!model || (status_ === 'empty' && !layingOut)) load(Boolean(model));
      // Polls call show() often; a layout already running is left to finish.
      else if (!layingOut && (layoutStale || !layout)) rebuild(!layout);
      else if (newRequest && request) forHost(() => highlightRequest(request));
      else if (newRequest && highlightFromRequest) forHost(clearSelection);
      requestDraw();
    },
    hide() {
      visible = false; host.hidden = true;
      controller?.abort(); runner.cancel(); hideTooltip(); closeMenu(false);
      if (status_ === 'loading' && !layout) { requested = null; status_ = 'idle'; }
    },
    highlightRequest,
    focus() { canvas.focus({preventScroll: true}); },
    /** Selects (and by default centres) the card that holds `key`, a
     * flowGraphNodeKey(); says whether it is in the graph. */
    select: (key, options) => selectKey(key, options),
    /** The selection as onSelect last described it, or null. */
    selection: () => selected >= 0 ? selectionInfo(selected, selectedRow) : null,
    /** Re-measures the stage after the host resized it. */
    resize: () => resize(),
    /** Marks the Wasm card (and row) a timeline sample points to, apart from
     * the selection; null clears it. Says whether a card took the mark. */
    setMark
  };
}
