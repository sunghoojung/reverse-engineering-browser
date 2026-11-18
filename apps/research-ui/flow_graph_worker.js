/* The Graph pane's pipeline, off the page's thread: it reads one
 * generation of the flow graph page by page (protocol/flow-graph-v2.md),
 * builds the model, folds it, sizes the cards and lays them out, sends the
 * layered drawing first and then swaps in each realm Triskel lays out, in the
 * background. It keeps the graph it built, so the page asks it for a refold
 * (a chain expanded, every frame drawn), which lays out again only the bands
 * it changed, for a request's lineage on its own, and for Find. The page runs
 * the same pipeline on its own thread where no worker starts.
 *
 * Page to pipeline, each with an `id` its answers carry:
 *   {op: 'load', session, measure, collapse, expanded: [node key], triskel}
 *   {op: 'refold', generation, collapse, expanded: [node index], measure}
 *   {op: 'lineage', nodes: [card], edges: [drawn edge]}
 *   {op: 'find', needle}
 *   {op: 'abort'}
 * Pipeline to page: {id, type} with type progress, doc, nodes, edges (the
 * document in slices), fold (flowGraphPack), layout, engine, lineage, find or
 * error. A lineage and a Find carry `fold`, the id of the job whose fold they
 * answer for, since the page may still be drawing an earlier one. */
'use strict';

/* Nodes or edges per message: each slice deserializes on the page in a few
 * milliseconds, however large the graph. */
const FLOW_GRAPH_SLICE = 16384;
/* Realms laid out by Triskel at once. Each is its own request, so no realm
 * waits behind another's size or is refused for sharing a request. */
const FLOW_GRAPH_TRISKEL_PARALLEL = 2;
/* The least time between two Triskel swaps, so a session of many realms
 * redraws a few times, not once per realm. */
const FLOW_GRAPH_SWAP_MS = 400;
/* A page answers within one fold slice (10 s), and a cached page in far
 * less; this only notices a backend that stopped answering. */
const FLOW_GRAPH_PAGE_TIMEOUT_MS = 120000;

/** A layout the page can take ownership of: the arrays the pipeline's state
 * shares with it are copied, the rest are transferred. */
function flowGraphSendable(layout) {
  const sent = {...layout, w: layout.w.slice(), h: layout.h.slice(), layer: layout.layer.slice(), back: layout.back.slice()};
  return [sent, flowGraphLayout.transfer(sent)];
}

/** What every realm's band is drawn from, as the Engine label reads it. */
function flowGraphEngine(state, outcomes, report) {
  const realms = outcomes.map((outcome, lane) => ({key: state.local.content.bands[lane].key, engine: outcome.result ? 'triskel' : 'layered', reason: outcome.reason ?? null}));
  const triskel = realms.some(realm => realm.engine === 'triskel');
  return {name: triskel ? 'triskel' : 'layered', revision: report.revision, triskel, realms, failure: report.failure};
}

/** Each band's identity: its cards (first member, folded or not, size) and
 * the calls inside it, in order. A refold lays out again only the bands
 * whose identity changed. */
function flowGraphLaneSignatures(display, sizes) {
  const parts = new Map(), local = new Int32Array(display.nodes.length);
  const of = key => { if (!parts.has(key)) parts.set(key, {cards: [], calls: []}); return parts.get(key); };
  display.nodes.forEach((node, v) => {
    const part = of(node.context);
    local[v] = part.cards.length;
    part.cards.push(`${node.members[0]}${node.kind === 'chain' ? 'c' : ''}:${sizes.w[v]}x${sizes.h[v]}`);
  });
  display.edges.forEach(edge => {
    const a = display.nodes[edge.from].context;
    if (a === display.nodes[edge.to].context) of(a).calls.push(`${local[edge.from]}>${local[edge.to]}`);
  });
  const signatures = new Map();
  parts.forEach((part, key) => signatures.set(key, `${part.cards.join(',')}|${part.calls.join(',')}`));
  return signatures;
}

function createFlowGraphPipeline(post) {
  // Every job that replaces the graph or its layout takes a new epoch; work
  // of an older one stops at its next check and is never sent. A read has its
  // own count, so a refold of the graph on screen never stops a refresh.
  let epoch = 0, reads = 0, current = null, controller = null;

  async function getPage(query) {
    const signal = AbortSignal.any ? AbortSignal.any([controller.signal, AbortSignal.timeout(FLOW_GRAPH_PAGE_TIMEOUT_MS)]) : controller.signal;
    const response = await fetch(`/api/flow-graph?${new URLSearchParams(query)}`, {cache: 'no-store', signal});
    if (response.status === 409) return null;
    if (!response.ok) {
      let detail = '';
      try { detail = (await response.json())?.error?.message ?? ''; } catch {}
      throw Object.assign(Error(detail || `The flow graph route returned ${response.status}.`), {status: response.status});
    }
    return response.json();
  }

  /** One generation's pages, joined: page 0 asked until the fold has read
   * every record, then each next page with its generation. A graph that
   * moved on while it was read is read again from the start. */
  async function readPages(id, session, live) {
    for (;;) {
      let first = null;
      while (!first?.complete) {
        if (first) post({id, type: 'progress', stage: 'folding', coverage: first.coverage, stacks: first.stacks});
        first = await getPage({session_id: session});
        if (!live()) return null;
        if (!first) throw Error('The flow graph route answered 409 to a request without a generation.');
        if (first.schema !== 'flow-graph-v2') throw Error('The flow graph provider returned an invalid document.');
      }
      const nodes = first.nodes.slice(), edges = first.edges.slice();
      let next = first.next_cursor, moved = false;
      while (next !== null && next !== undefined) {
        post({id, type: 'progress', stage: 'reading', read: nodes.length, total: first.node_count});
        const page = await getPage({session_id: session, generation: first.generation, cursor: next});
        if (!live()) return null;
        if (!page) { moved = true; break; }
        if (page.generation !== first.generation || page.cursor !== nodes.length) throw Error('A flow graph page did not continue the page before it.');
        for (const node of page.nodes) nodes.push(node);
        for (const edge of page.edges) edges.push(edge);
        next = page.next_cursor;
      }
      if (moved) continue;
      if (nodes.length !== first.node_count || edges.length !== first.edge_count) throw Error('The flow graph pages did not add up to the graph they describe.');
      return {...first, nodes, edges, cursor: 0, next_cursor: null};
    }
  }

  async function load({id, session, measure, collapse, expanded = [], triskel = false}) {
    const read = ++reads, live = () => read === reads;
    controller?.abort(); controller = new AbortController();
    const doc = await readPages(id, session, live);
    if (!doc) return;
    const mine = ++epoch;
    const model = flowGraphModel(doc);
    const {nodes, edges, ...head} = doc;
    post({id, type: 'doc', head});
    for (let at = 0; at < nodes.length; at += FLOW_GRAPH_SLICE) post({id, type: 'nodes', at, items: nodes.slice(at, at + FLOW_GRAPH_SLICE)});
    for (let at = 0; at < edges.length; at += FLOW_GRAPH_SLICE) post({id, type: 'edges', at, items: edges.slice(at, at + FLOW_GRAPH_SLICE)});
    // Chains stay expanded across generations by the function, not the id.
    const byKey = new Map(model.nodes.map((node, index) => [flowGraphNodeKey(node), index]));
    const open = new Set(expanded.map(key => byKey.get(key)).filter(index => index !== undefined).map(String));
    current = {session, generation: doc.generation, model, measure, collapse, expanded: open, triskel, display: null, graph: null, state: null, lanes: null, findText: null};
    post({id, type: 'expanded', expanded: [...open]});
    layOut(id, mine, false);
  }

  /** Folds the current model, sends the fold and its layered layout, then
   * asks Triskel for each realm. `again` lays out only the bands the fold
   * changed. */
  function layOut(id, mine, again) {
    const c = current;
    const display = flowGraphDisplay(c.model, c.expanded, c.collapse);
    const sizes = flowGraphCardSizes(c.model, display, c.measure);
    const graph = flowGraphLayoutInput(display, sizes);
    const packed = flowGraphPack(display, c.model.nodes.length);
    post({id, type: 'fold', packed}, flowGraphPackTransfer(packed));
    c.display = display; c.graph = graph; c.findText = null; c.fold = id;
    if (!display.nodes.length) { c.state = null; c.lanes = null; post({id, type: 'layout', layout: null}); return; }
    const lanes = flowGraphLaneSignatures(display, sizes);
    let result;
    if (again && c.state && c.lanes) {
      const keep = new Set([...lanes].filter(([key, signature]) => c.lanes.get(key) === signature).map(([key]) => key));
      result = keep.size ? flowGraphLayout.relayout(graph, c.state, keep) : flowGraphLayout.layered(graph);
    } else result = flowGraphLayout.layered(graph);
    if (mine !== epoch) return;
    c.state = result.state; c.lanes = lanes;
    const [layout, transfer] = flowGraphSendable(result.layout);
    post({id, type: 'layout', layout}, transfer);
    if (c.triskel) triskel(id, mine);
  }

  /** Lays out each realm within the route's limits, a request each, and
   * swaps the accepted ones in. Only Triskel's answer says whether it keeps a
   * realm: no cheap measure of a realm bounds how narrow Triskel draws it,
   * since Triskel ranks each region of it on its own. */
  async function triskel(id, mine) {
    const c = current, state = c.state, graph = c.graph;
    const live = () => mine === epoch && current === c && c.state === state;
    const {LIMITS} = graphLayoutClient, outcomes = state.outcomes.slice(), report = {...state.report}, queue = [];
    for (const item of flowGraphLayout.realmGraphs(graph, state)) {
      if (!['not_served', 'pending'].includes(outcomes[item.lane].reason?.code)) continue;
      const tooLarge = item.graph.nodes.length > LIMITS.graphNodes || item.graph.edges.length > LIMITS.graphEdges;
      outcomes[item.lane] = {reason: {code: tooLarge ? 'too_large' : 'pending'}};
      if (!tooLarge) queue.push(item);
    }
    // Smallest first: Triskel answers those soonest, so no large realm, which
    // may run to the route's deadline, holds the rest back.
    queue.sort((a, b) => a.graph.nodes.length - b.graph.nodes.length);
    // What the drawn layout shows: an accepted realm waits for its swap.
    const drawn = Uint8Array.from(outcomes, outcome => (outcome.result ? 1 : 0));
    const shown = () => flowGraphEngine(state, outcomes.map((outcome, lane) => (outcome.result && !drawn[lane] ? {reason: {code: 'pending'}} : outcome)), report);
    let changed = false, sent = 0;
    const swap = (last = false) => {
      if (!live()) return;
      // The state keeps every answer, so a refold reuses a kept band's.
      state.outcomes = outcomes.slice(); state.report = {...report};
      if (changed && (last || Date.now() - sent >= FLOW_GRAPH_SWAP_MS)) {
        changed = false; sent = Date.now();
        outcomes.forEach((outcome, lane) => { if (outcome.result) drawn[lane] = 1; });
        const [layout, transfer] = flowGraphSendable(flowGraphLayout.withRealms(graph, state, outcomes.slice(), {...report}));
        post({id, type: 'layout', layout, swap: true}, transfer);
      } else post({id, type: 'engine', engine: shown()});
    };
    swap();
    const run = async () => {
      while (queue.length && live()) {
        const item = queue.shift();
        const answer = await graphLayoutClient.layOut([item.graph]);
        if (!live()) return;
        outcomes[item.lane] = answer.outcomes[0];
        report.revision = answer.revision ?? report.revision;
        if (answer.failure) report.failure = answer.failure;
        if (outcomes[item.lane].result) changed = true;
        swap();
      }
    };
    await Promise.all(Array.from({length: FLOW_GRAPH_TRISKEL_PARALLEL}, run));
    swap(true);
  }

  function refold({id, generation, collapse, expanded, measure}) {
    if (!current) throw Error('No flow graph is loaded to fold again.');
    // Node indexes are a generation's: a refold asked of the graph a
    // refresh just replaced is the page's to ask again once it lands.
    if (generation !== current.generation) return;
    const mine = ++epoch;
    current.collapse = collapse; current.expanded = new Set(expanded.map(String));
    if (measure) current.measure = measure;
    layOut(id, mine, true);
  }

  /** The lineage of the cards and edges a stack lights, laid out alone, in
   * arrays over every card and edge: a card outside it has no position and
   * an edge outside it no route. */
  function lineage({id, nodes, edges}) {
    const c = current;
    if (!c?.graph) throw Error('No flow graph is loaded to draw a lineage of.');
    const count = c.graph.count, at = new Int32Array(count).fill(-1);
    nodes.forEach((v, i) => { at[v] = i; });
    const inside = edges.filter(e => at[c.graph.from[e]] >= 0 && at[c.graph.to[e]] >= 0);
    const sub = {count: nodes.length, lane: Int32Array.from(nodes, v => c.graph.lane[v]), weight: Float64Array.from(nodes, v => c.graph.weight[v]),
      from: Int32Array.from(inside, e => at[c.graph.from[e]]), to: Int32Array.from(inside, e => at[c.graph.to[e]]),
      w: Float32Array.from(nodes, v => c.graph.w[v]), h: Float32Array.from(nodes, v => c.graph.h[v])};
    const drawn = flowGraphLayout.lineage(sub);
    // Every column comes back as tall as the widest band, a layered layout's
    // shared band width; each is cut to its own cards and the routes in it.
    const {lanePadBottom, margin} = flowGraphLayout.METRICS, columns = drawn.lanes.slice().sort((a, b) => a.x - b.x);
    const bottom = new Map(columns.map(lane => [lane.key, lane.y]));
    for (let i = 0; i < sub.count; i += 1) bottom.set(sub.lane[i], Math.max(bottom.get(sub.lane[i]), drawn.y[i] + drawn.h[i]));
    let lowest = 0;
    for (let k = 0; k < drawn.routes.length; k += 2) {
      const rx = drawn.routes[k], ry = drawn.routes[k + 1];
      lowest = Math.max(lowest, ry);
      let lo = 0, hi = columns.length - 1;
      while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (columns[mid].x <= rx) lo = mid; else hi = mid - 1; }
      const lane = columns[lo];
      if (lane && rx >= lane.x && rx <= lane.x + lane.w) bottom.set(lane.key, Math.max(bottom.get(lane.key), ry));
    }
    drawn.lanes = drawn.lanes.map(lane => ({...lane, h: Math.min(lane.h, bottom.get(lane.key) - lane.y + lanePadBottom)}));
    drawn.height = drawn.lanes.reduce((most, lane) => Math.max(most, lane.y + lane.h), lowest) + margin;
    const x = new Float32Array(count).fill(NaN), y = new Float32Array(count).fill(NaN), layer = new Int32Array(count).fill(-1);
    nodes.forEach((v, i) => { x[v] = drawn.x[i]; y[v] = drawn.y[i]; layer[v] = drawn.layer[i]; });
    const edgeCount = c.graph.from.length, routeOf = new Int32Array(edgeCount).fill(-1);
    inside.forEach((e, i) => { routeOf[e] = i; });
    const routeStart = new Uint32Array(edgeCount + 1), points = [], types = [];
    for (let e = 0; e < edgeCount; e += 1) {
      routeStart[e] = types.length;
      const i = routeOf[e];
      if (i < 0) continue;
      for (let k = drawn.routeStart[i]; k < drawn.routeStart[i + 1]; k += 1) { points.push(drawn.routes[2 * k], drawn.routes[2 * k + 1]); types.push(drawn.routeTypes[k]); }
    }
    routeStart[edgeCount] = types.length;
    const back = new Uint8Array(edgeCount);
    inside.forEach((e, i) => { back[e] = drawn.back[i]; });
    const layout = {...drawn, x, y, w: c.graph.w.slice(), h: c.graph.h.slice(), layer, back, routes: Float32Array.from(points), routeTypes: Uint8Array.from(types), routeStart};
    post({id, type: 'lineage', fold: c.fold, layout}, flowGraphLayout.transfer(layout));
  }

  function find({id, needle}) {
    const c = current, text = needle.trim().toLowerCase(), matches = [];
    if (c?.display && text) {
      c.findText ??= c.display.nodes.map((node, index) => flowGraphFindText(c.model, c.display, index));
      c.findText.forEach((line, index) => { if (line.includes(text)) matches.push(index); });
    }
    const found = Int32Array.from(matches);
    post({id, type: 'find', fold: c?.fold ?? null, needle, matches: found}, [found.buffer]);
  }

  const ops = {load, refold, lineage, find, abort: () => { epoch += 1; reads += 1; controller?.abort(); }};
  return {
    async handle(message) {
      try {
        await ops[message.op]?.(message);
      } catch (error) {
        if (error?.name === 'AbortError') return;
        post({id: message.id, type: 'error', error: error?.message ?? 'The flow graph could not be built.', status: error?.status ?? null});
      }
    }
  };
}

if (typeof importScripts === 'function' && typeof document === 'undefined') {
  // flow_graph_layout.js loads graph_layout_client.js and installs its own
  // handler for the layout-only worker; this one replaces it.
  importScripts('request_stack.js', 'flow_graph_model.js', 'flow_graph_layout.js');
  const pipeline = createFlowGraphPipeline((message, transfer = []) => self.postMessage(message, transfer));
  self.onmessage = event => pipeline.handle(event.data);
}
