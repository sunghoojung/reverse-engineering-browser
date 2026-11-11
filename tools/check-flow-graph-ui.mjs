#!/usr/bin/env node
// Backtraces Flow graph: the flow-graph-v1 model, chain folding, card rows,
// the vertical layout (realm bands stacked in call order) and its routes, and
// the panel's selection, highlight, details, menu and failure states in a DOM
// model. Offline: no rendered pixels are claimed here.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {performance} from 'node:perf_hooks';
import {createContext, runInContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const require = createRequire(import.meta.url);
const layoutModule = require('../apps/research-ui/flow_graph_layout.js');
const model = require('../apps/research-ui/flow_graph.js');
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');

// A session in the shape the backend serves: a top page posts into a
// same-process iframe, whose handler calls an eval'd helper and a Wasm export.
const node = (kind, context, name, extra = {}) => ({kind, context, name, status: 'resolved', hits: 1, entries: 0, leaves: 0, ...extra});
const edge = (from, to, kind = 'call', extra = {}) => ({from, to, kind, crosses: [], count: 1, stacks: 1, sites: [], ...extra});
function sessionDoc() {
  const nodes = [
    node('javascript', 0, 'boot', {url: 'https://top.test/app.js', line: 2, column: 14, artifact_id: '1', artifact_line: 2, artifact_column: 14, script_id: 10, hits: 5}), // 0
    node('javascript', 0, 'init', {url: 'https://top.test/app.js', line: 5, column: 14, artifact_id: '1', script_id: 10, hits: 5}), // 1
    node('javascript', 1, 'onMessage', {url: 'https://frame.test/inner.js', line: 2, column: 54, artifact_id: '2', script_id: 20, hits: 4}), // 2
    node('javascript', 1, 'bridge', {url: 'https://frame.test/inner.js', line: 5, column: 16, artifact_id: '2', script_id: 20, hits: 4}), // 3
    node('eval', 1, '<img src=x onerror=alert(1)>', {url: 'https://frame.test/', line: 1, column: 17, artifact_id: '3', script_id: 31, hits: 1}), // 4
    node('wasm', 1, 'run', {function_index: 1, url: 'https://frame.test/m.wasm', artifact_id: '4', script_id: 30, hits: 3}), // 5
    node('javascript', 1, 'send', {url: 'https://frame.test/inner.js', line: 10, column: 14, artifact_id: '2', script_id: 20, hits: 3}), // 6
    node('request', 1, 'POST collect.frame.test', {hits: 3}), // 7
    node('request', 1, 'GET frame.test', {hits: 1}), // 8
    node('javascript', 2, null, {status: 'unresolved', reason: 'script_identity_missing', script_id: 77, hits: 1}), // 9
  ];
  const edges = [
    edge(0, 1, 'call', {count: 5}), // 0
    edge(1, 2, 'task', {task: 'post_message', crosses: ['frame'], count: 4}), // 1
    edge(2, 3, 'call', {count: 4}), // 2
    edge(3, 4, 'call', {crosses: ['dynamic']}), // 3
    edge(3, 5, 'call', {crosses: ['language'], count: 3}), // 4
    edge(5, 6, 'call', {crosses: ['language'], count: 3}), // 5
    edge(6, 7, 'request', {count: 3}), // 6
    edge(4, 8, 'request'), // 7
    edge(9, 1), // 8
    edge(0, 99), // 9: names no node
  ];
  const contexts = [
    {id: 0, process_id: 41, execution_context_id: '11', origin: 'https://top.test', origins: [], frame_ids: [{frame_id: '3', stacks: 5}], tab_ids: [5], counts: {javascript: 2}},
    {id: 1, process_id: 41, execution_context_id: '12', origin: 'https://frame.test', origins: [], frame_ids: [{frame_id: '4', stacks: 4}], tab_ids: [5], counts: {javascript: 3, eval: 1, wasm: 1, request: 2}},
    {id: 2, process_id: 41, execution_context_id: null, origin: null, origins: [], frame_ids: [], tab_ids: [], counts: {javascript: 1}},
  ];
  const paths = [
    {process_id: 41, digest: 'a'.repeat(64), occurrences: 3, retained: true, requests: ['70', '71', '72'], nodes: [0, 1, 2, 3, 5, 6, 7], edges: [0, 1, 2, 4, 5, 6]},
    {process_id: 41, digest: 'b'.repeat(64), occurrences: 1, retained: true, requests: ['73'], nodes: [0, 1, 2, 3, 4, 8], edges: [0, 1, 2, 3, 7]},
    {process_id: 41, digest: 'c'.repeat(64), occurrences: 1, retained: true, requests: ['74'], nodes: [9, 1, 2, 3, 5, 6, 7], edges: [8, 1, 2, 4, 5, 6]},
  ];
  return {schema: 'flow-graph-v1', session_id: '7', evidence: 'observed', complete: true,
    coverage: {stopped: 'end', scanned_bytes: '1', store_end: '1', malformed_records: 0, elapsed_ms: 1},
    stacks: {records: {request_initiator_stack: 4}, occurrences: 4, distinct: 2, decoded: 2, not_walked: {}, unresolved: {}, over_budget: 0},
    truncated: {nodes: 0, edges: 0, paths: 0, identities: 0, request_labels: false, request_ids: 0, source_budget: false},
    limits: {stacks: 16384}, not_shown: ['worker and worklet stacks', 'MessagePort and worker messages'], contexts, nodes, edges, paths};
}

const overlaps = (layout, count) => {
  let found = 0;
  for (let a = 0; a < count; a += 1) for (let b = a + 1; b < count; b += 1) {
    if (layout.x[a] < layout.x[b] + layout.w[b] && layout.x[b] < layout.x[a] + layout.w[a] && layout.y[a] < layout.y[b] + layout.h[b] && layout.y[b] < layout.y[a] + layout.h[a]) found += 1;
  }
  return found;
};
/** Each route's points, as [x, y, type]. */
const route = (layout, e) => { const points = []; for (let i = layout.routeStart[e]; i < layout.routeStart[e + 1]; i += 1) points.push([layout.routes[2 * i], layout.routes[2 * i + 1], layout.routeTypes[i]]); return points; };
const inside = (layout, count, x, y) => { for (let v = 0; v < count; v += 1) if (x > layout.x[v] + 0.5 && x < layout.x[v] + layout.w[v] - 0.5 && y > layout.y[v] + 0.5 && y < layout.y[v] + layout.h[v] - 0.5) return v; return -1; };
/** A route's straight runs, a curve flattened the way the canvas draws it:
 * down to mid-gap, across, and down. */
const segments = (layout, e) => {
  const out = [], P = layout.routes, T = layout.routeTypes, S = layout.routeStart;
  let px = P[2 * S[e]], py = P[2 * S[e] + 1];
  for (let i = S[e] + 1; i < S[e + 1]; i += 1) {
    const x = P[2 * i], y = P[2 * i + 1];
    if (T[i] === layoutModule.ROUTE.CURVE && Math.abs(x - px) > 0.5) { const mid = (py + y) / 2; out.push([px, py, px, mid], [px, mid, x, mid], [x, mid, x, y]); }
    else out.push([px, py, x, y]);
    px = x; py = y;
  }
  return out;
};
/** The first card a run passes through, or -1. Every run is horizontal or
 * vertical, and a route only touches its own cards at their edges. */
const crossedCard = (layout, count, [x0, y0, x1, y1]) => {
  const [left, right, top, bottom] = [Math.min(x0, x1), Math.max(x0, x1), Math.min(y0, y1), Math.max(y0, y1)];
  for (let v = 0; v < count; v += 1) if (right > layout.x[v] + 0.5 && left < layout.x[v] + layout.w[v] - 0.5 && bottom > layout.y[v] + 0.5 && top < layout.y[v] + layout.h[v] - 0.5) return v;
  return -1;
};
const axisAligned = ([x0, y0, x1, y1]) => Math.abs(x0 - x1) < 0.01 || Math.abs(y0 - y1) < 0.01;
/** Bands are full width and stacked top to bottom in order, never overlapping. */
const stackedBands = (layout, label) => {
  layout.lanes.forEach((lane, index) => {
    assert.equal(lane.x, layout.lanes[0].x, `${label}: every band starts at the same x`);
    assert.equal(lane.w, layout.lanes[0].w, `${label}: every band is full width`);
    if (index) assert(layout.lanes[index - 1].y + layout.lanes[index - 1].h <= lane.y, `${label}: band ${index} sits below band ${index - 1}`);
  });
  assert(layout.lanes.every(lane => lane.x + lane.w <= layout.width && lane.y + lane.h <= layout.height), `${label}: the graph holds every band`);
};

{
  // The model refuses another shape and drops an edge that names no node.
  assert.throws(() => model.flowGraphModel({schema: 'flow-graph-v2', nodes: [], edges: [], contexts: [], paths: []}), /invalid document/);
  assert.throws(() => model.flowGraphModel(null), /invalid document/);
  const m = model.flowGraphModel(sessionDoc());
  assert.equal(m.edges.length, 9);
  assert.equal(m.dropped, 1, 'the edge to a missing node is counted, not drawn');
  assert.equal(m.contexts[0].label.title, 'top.test');
  assert.match(m.contexts[1].label.detail, /realm 12 · frame 4 · process 41/);
  assert.equal(m.contexts[2].label.title, 'Unidentified realm', 'a realm without identity says so');
  assert.equal(model.flowGraphNodeName(m.nodes[9]), '(script 77)');
  assert.equal(model.flowGraphNodeDetail(m.nodes[9]), 'no script identity record');
  assert.equal(model.flowGraphNodeDetail(m.nodes[4]), 'VM31:1:17', 'eval code is named by its script, like DevTools');
  assert.equal(model.flowGraphNodeDetail(m.nodes[5]), 'func 1 · m.wasm');
}
{
  // Chains: pass-through frames in one realm fold; crossings, recursion,
  // fan-out and differing counts do not.
  const nodes = [0, 1, 2, 3, 4, 5].map(index => node('javascript', 0, `f${index}`));
  nodes.push(node('request', 0, 'GET a.test'));
  const chainDoc = {...sessionDoc(), nodes, contexts: [sessionDoc().contexts[0]], paths: [],
    edges: [edge(0, 1), edge(1, 2), edge(2, 3), edge(3, 4), edge(4, 5), edge(5, 6, 'request')]};
  let m = model.flowGraphModel(chainDoc), display = model.flowGraphDisplay(m);
  assert.equal(display.groups, 1);
  const chain = display.nodes.find(item => item.kind === 'chain');
  assert.deepEqual(chain.members, [1, 2, 3, 4], 'f1..f4 pass one call through; f0 is the root and f5 calls the sink');
  assert.equal(chain.name, 'f1 → f4');
  assert.equal(display.nodes.length, 3, 'f0, the chain and f5; the request is a row of f5');
  assert.equal(display.edges.length, 2, 'edges inside the chain are folded with it');
  assert.equal(display.sinkRows[2].length, 1);
  assert.equal(model.flowGraphDisplay(m, new Set(), false).groups, 0, 'Chains off draws every frame');
  const opened = model.flowGraphDisplay(m, new Set(['1']));
  assert.equal(opened.groups, 0);
  assert.equal(opened.foldKey.get(3), '1', 'an expanded member knows which chain folds it again');
  // Recursion stays visible.
  m = model.flowGraphModel({...chainDoc, edges: [...chainDoc.edges, edge(2, 2)]});
  display = model.flowGraphDisplay(m);
  assert(!display.nodes.find(item => item.kind === 'chain')?.members.includes(2), 'a recursive frame is never folded');
  // A boundary breaks a chain.
  m = model.flowGraphModel({...chainDoc, edges: chainDoc.edges.map((item, index) => index === 2 ? {...item, crosses: ['language']} : item)});
  assert(model.flowGraphDisplay(m).nodes.every(item => item.kind !== 'chain' || !item.members.includes(3) || !item.members.includes(2)), 'a language crossing is never folded away');
  // Different counts mean some path leaves: no fold across it.
  m = model.flowGraphModel({...chainDoc, edges: chainDoc.edges.map((item, index) => index === 3 ? {...item, count: 2} : item)});
  assert(model.flowGraphDisplay(m).nodes.every(item => item.kind !== 'chain' || !(item.members.includes(3) && item.members.includes(4))));
}
{
  // The session fixture's crossings are all kept; requests are rows of the
  // function that made them.
  const m = model.flowGraphModel(sessionDoc()), session = model.flowGraphDisplay(m);
  assert.equal(session.groups, 0, 'every frame of the session fixture is a crossing, a fan-out or a sink caller');
  assert(!session.nodes.some(item => item.kind === 'request'), 'a request somebody called is a row, not a card');
  assert.equal(session.displayOf[7], -1);
  assert.equal(session.edges.length, 7, 'the two request edges become rows');
  const cards = model.flowGraphCards(m, session), at = name => session.nodes.findIndex(item => item.name === name);
  const rows = name => cards[at(name)].rows.map(row => `${row.site} ${row.op} ${row.target}${row.note ? ` ; ${row.note}` : ''}${row.count ? ` ${row.count}` : ''}`.trim());
  assert.deepEqual(rows('bridge'), ['call <img src=x onerror=alert(1)> ; into eval', 'call run ; JS → Wasm ×3'], 'a card lists its calls and what each crosses');
  assert.deepEqual(rows('init'), ['postMessage onMessage ; → frame.test ×4'], 'a posted task names the realm it enters');
  assert.deepEqual(rows('send'), ['request POST collect.frame.test ×3'], 'the request is a row of the frame that sent it');
  assert.equal(cards[at('run')].location, 'func 1 · m.wasm');
  for (const card of cards) {
    assert(card.w >= 176 && card.w <= 420, 'card widths stay in their bounds');
    assert.equal(card.h, 30 + 18 + 4 + (card.rows.length + (card.more ? 1 : 0)) * 18 + 8, 'card heights follow their rows');
  }
  // A sink nothing calls keeps its own card rather than vanish.
  const lonely = sessionDoc(); lonely.edges = lonely.edges.filter(item => item.to !== 8);
  const alone = model.flowGraphDisplay(model.flowGraphModel(lonely));
  assert(alone.nodes.some(item => item.name === 'GET frame.test'), 'an uncalled sink is still drawn');
  // Many calls fold into a last row.
  const wide = sessionDoc();
  for (let index = 0; index < 12; index += 1) { wide.nodes.push(node('javascript', 1, `leaf${index}`, {url: 'https://frame.test/inner.js', line: 40 + index, column: 1, artifact_id: '2', script_id: 20})); wide.edges.push(edge(3, wide.nodes.length - 1, 'call', {sites: [{line: 50 + index, column: 3}]})); }
  const wideModel = model.flowGraphModel(wide), wideDisplay = model.flowGraphDisplay(wideModel), bridgeCard = model.flowGraphCards(wideModel, wideDisplay)[wideDisplay.nodes.findIndex(item => item.name === 'bridge')];
  assert.equal(bridgeCard.rows.length, 7, 'a card shows seven rows and a count of the rest');
  assert.equal(bridgeCard.more, 7);
}
{
  // Layout: realms are full-width bands stacked top to bottom in call order,
  // callers above the realm they call or post into; nothing overlaps, no edge
  // runs through a card, and a straight chain stays straight.
  const m = model.flowGraphModel(sessionDoc()), display = model.flowGraphDisplay(m), cards = model.flowGraphCards(m, display), input = model.flowGraphLayoutInput(display, cards);
  const layout = layoutModule.layoutGraph(input);
  assert.equal(overlaps(layout, display.nodes.length), 0, 'no card overlaps another');
  assert.deepEqual([...layout.w], cards.map(card => card.w), 'cards keep the size their text needs');
  const laneOf = key => layout.lanes.findIndex(lane => lane.key === key);
  assert(laneOf(0) < laneOf(1), 'the top page band precedes the iframe it posts into');
  assert(laneOf(2) < laneOf(0), 'a realm that only calls into the page sits above it');
  stackedBands(layout, 'layered');
  assert(layout.lanes[laneOf(0)].y + layout.lanes[laneOf(0)].h <= layout.lanes[laneOf(1)].y, 'the iframe band is below its parent');
  assert(layout.height > layout.width, 'the session grows tall, not wide');
  display.nodes.forEach((item, index) => {
    const lane = layout.lanes[laneOf(item.context)];
    assert(layout.x[index] >= lane.x && layout.x[index] + layout.w[index] <= lane.x + lane.w && layout.y[index] >= lane.y && layout.y[index] + layout.h[index] <= lane.y + lane.h, `${item.name} sits inside its realm band`);
  });
  const at = name => display.nodes.findIndex(item => item.name === name), center = index => layout.x[index] + layout.w[index] / 2;
  assert(layout.y[at('boot')] < layout.y[at('init')] && layout.y[at('init')] < layout.y[at('onMessage')], 'callers sit above callees');
  assert(Math.abs(center(at('onMessage')) - center(at('bridge'))) < 0.5, 'a single call stays a straight vertical line');
  assert(layout.y[at('send')] > layout.y[at('run')], 'Wasm calls back into JavaScript below itself');
  assert.equal(layout.layer[at('onMessage')], 0, 'a realm entered from another starts at its own top row');
  // Band order matches call order: every call between bands runs down,
  // except a back edge, which the layout says is one.
  display.edges.forEach((item, e) => {
    const a = laneOf(display.nodes[item.from].context), b = laneOf(display.nodes[item.to].context);
    if (a !== b) assert.equal(layout.back[e], b < a ? 1 : 0, 'a call between bands is a back edge exactly when it runs up');
    if (a !== b && !layout.back[e]) assert(a < b, 'a call between bands runs down');
  });
  // Routes: out of the caller's bottom, into the callee's top, never
  // through another card, in straight runs with rounded corners.
  display.edges.forEach((item, e) => {
    const points = route(layout, e), [first, last] = [points[0], points.at(-1)];
    if (item.from === item.to) { assert(first[0] >= layout.x[item.from] + layout.w[item.from] - 0.5, 'recursion loops off the right edge'); return; }
    assert(Math.abs(first[1] - (layout.y[item.from] + layout.h[item.from])) < 0.5 && first[0] >= layout.x[item.from] && first[0] <= layout.x[item.from] + layout.w[item.from], 'a route leaves its caller at the bottom');
    assert(Math.abs(last[1] - layout.y[item.to]) < 0.5 && last[0] >= layout.x[item.to] && last[0] <= layout.x[item.to] + layout.w[item.to], 'a route enters its callee at the top');
    for (const [x, y] of points.slice(1, -1)) assert.equal(inside(layout, display.nodes.length, x, y), -1, 'a waypoint never sits inside a card');
    for (const run of segments(layout, e)) {
      assert(axisAligned(run), 'every run is horizontal or vertical');
      assert.equal(crossedCard(layout, display.nodes.length, run), -1, `the edge ${display.nodes[item.from].name} → ${display.nodes[item.to].name} never crosses a card`);
    }
  });
  // The call into the iframe runs down across the band boundary.
  const post = display.edges.findIndex(item => item.crosses.includes('frame')), postRoute = route(layout, post);
  const boundary = layout.lanes[laneOf(0)].y + layout.lanes[laneOf(0)].h;
  assert(postRoute[0][1] < boundary && postRoute.at(-1)[1] > boundary, 'the posted task crosses from the page band into the iframe band');
  assert(postRoute.every(([, y], index) => !index || y >= postRoute[index - 1][1] - 0.5), 'and only ever runs down');
  // A busier session: several realms that call down a chain of frames, with
  // calls that skip a band and one that runs back up; still no run crosses
  // a card and the bands keep call order.
  const busy = {count: 0, lane: [], from: [], to: [], w: [], h: []};
  const add = (lane, w = 200, h = 60 + (busy.count % 3) * 19) => { busy.lane.push(lane); busy.w.push(w); busy.h.push(h); return busy.count++; };
  const link = (a, b) => { busy.from.push(a); busy.to.push(b); };
  const tops = [0, 1, 2, 3].map(lane => add(lane));
  for (let lane = 0; lane < 4; lane += 1) {
    let previous = tops[lane];
    for (let index = 0; index < 9; index += 1) { const next = add(lane, 160 + (index % 4) * 60); link(index % 3 ? previous : tops[lane], next); previous = next; }
    if (lane < 3) link(previous, tops[lane + 1]);
  }
  link(tops[0] + 1, tops[2]);
  link(busy.count - 1, tops[1] + 2);
  const busyLayout = layoutModule.layoutGraph({count: busy.count, lane: Int32Array.from(busy.lane), from: Int32Array.from(busy.from), to: Int32Array.from(busy.to), w: Float32Array.from(busy.w), h: Float32Array.from(busy.h)});
  stackedBands(busyLayout, 'busy');
  assert.deepEqual(busyLayout.lanes.map(lane => lane.key), [0, 1, 2, 3], 'bands follow the chain of calls');
  assert.equal(overlaps(busyLayout, busy.count), 0);
  for (let e = 0; e < busy.from.length; e += 1) for (const run of segments(busyLayout, e)) {
    assert(axisAligned(run));
    assert.equal(crossedCard(busyLayout, busy.count, run), -1, `busy edge ${e} never crosses a card`);
  }
  assert.equal(busyLayout.back[busy.from.length - 1], 1, 'the call back up into an earlier band is a back edge');
  const upRoute = route(busyLayout, busy.from.length - 1);
  assert(upRoute.some(([x]) => x > Math.max(...Array.from(busyLayout.x, (value, v) => value + busyLayout.w[v]))), 'it runs up the right gutter, right of every card');
}
{
  // Cycles and wide layers.
  const count = 40, from = [], to = [];
  for (let index = 1; index < count; index += 1) { from.push(0); to.push(index); }
  from.push(5, 7); to.push(0, 7);
  const layout = layoutModule.layoutGraph({count, lane: new Int32Array(count), from: Int32Array.from(from), to: Int32Array.from(to)});
  assert.equal(overlaps(layout, count), 0, 'a wide fan stacks without overlap');
  const perLayer = new Map(); for (let v = 0; v < count; v += 1) perLayer.set(layout.layer[v], (perLayer.get(layout.layer[v]) ?? 0) + 1);
  assert(Math.max(...perLayer.values()) <= layoutModule.METRICS.wrap, `a realm holds at most ${layoutModule.METRICS.wrap} cards per layer`);
  assert(layout.waypoints > 0, 'calls to cards moved down get waypoints');
  for (let e = 0; e < from.length; e += 1) for (const [x, y] of route(layout, e).slice(1, -1)) assert.equal(inside(layout, count, x, y), -1, 'a long edge passes between cards');
  assert.equal(layout.back[from.length - 2], 1, 'the edge back to the root is a back edge');
  assert.equal(layout.back[from.length - 1], 1, 'a self call is a back edge');
  const loop = route(layout, from.length - 2), gutter = layout.lanes[0].gutter;
  assert(loop.some(([x]) => x > gutter), 'a back edge runs up the gutter, right of every card');
  for (let v = 0; v < count; v += 1) assert(layout.x[v] + layout.w[v] <= gutter, 'the gutter is clear of cards');
}
{
  // Triskel per realm: a realm it lays out takes its coordinates and routes;
  // one it would draw much wider, one past its limits and every realm when the
  // route fails keep the layered layout. Bands stack in the same call order
  // either way, and calls between bands are routed here, never through a card.
  const m = model.flowGraphModel(sessionDoc()), display = model.flowGraphDisplay(m), cards = model.flowGraphCards(m, display), input = model.flowGraphLayoutInput(display, cards);
  // A stand-in engine: each realm as one column, edges straight down its left.
  const column = graph => {
    let top = 0; const nodes = graph.nodes.map(([w, h]) => { const at = [0, top]; top += h + 80; return at; });
    return {status: 'laid_out', nodes, width: Math.max(...graph.nodes.map(([w]) => w)), height: top - 80,
      edges: graph.edges.map(([a, b]) => [10, nodes[a][1] + graph.nodes[a][1], 10, nodes[b][1]])};
  };
  const engine = override => async body => ({schema: 'graph-layout-v1', engine: {name: 'triskel', revision: '196ba112'}, graphs: body.graphs.map((graph, index) => override?.(graph, index) ?? column(graph))});
  let layout = await layoutModule.layoutWithTriskel(input, layoutModule.METRICS, engine());
  const realms = new Map(layout.engine.realms.map(item => [item.key, item]));
  assert.equal(realms.get(0).engine, 'triskel'); assert.equal(realms.get(1).engine, 'triskel');
  assert.equal(realms.get(2).reason, 'one card', 'a one-card realm needs no engine');
  assert.equal(overlaps(layout, display.nodes.length), 0, 'no card overlaps another');
  stackedBands(layout, 'Triskel');
  assert.deepEqual(layout.lanes.map(lane => lane.key), layoutModule.layoutGraph(input).lanes.map(lane => lane.key), 'Triskel bands keep the layered call order');
  display.nodes.forEach((item, index) => {
    const lane = layout.lanes.find(entry => entry.key === item.context);
    assert(layout.x[index] >= lane.x && layout.x[index] + layout.w[index] <= lane.x + lane.w && layout.y[index] >= lane.y && layout.y[index] + layout.h[index] <= lane.y + lane.h, `${item.name} sits inside its band`);
  });
  assert(!('content' in layout), 'the band contents the layout worked from are not sent to the page');
  const at = name => display.nodes.findIndex(item => item.name === name);
  assert.equal(layout.x[at('onMessage')], layout.x[at('bridge')], 'Triskel coordinates are used as given');
  display.edges.forEach((item, e) => {
    const points = route(layout, e);
    assert(points.every(([x, y]) => Number.isFinite(x) && Number.isFinite(y)));
    if (item.from === item.to) return;
    assert(Math.abs(points[0][1] - (layout.y[item.from] + layout.h[item.from])) < 0.5, 'a route leaves its caller at the bottom');
    assert(Math.abs(points.at(-1)[1] - layout.y[item.to]) < 0.5 && points.at(-1)[0] >= layout.x[item.to] && points.at(-1)[0] <= layout.x[item.to] + layout.w[item.to], 'a route enters its callee at the top');
  });
  const post = display.edges.findIndex(item => item.crosses.includes('frame')), postRoute = route(layout, post);
  const topLane = layout.lanes.find(entry => entry.key === 0);
  assert(postRoute[0][1] < topLane.y + topLane.h && postRoute.at(-1)[1] > topLane.y + topLane.h, 'a call into another realm runs down across the band boundary');
  // The stand-in draws calls straight down its column, so only the routes
  // this layout makes, between bands, are held to never crossing a card.
  display.edges.forEach((item, e) => {
    if (display.nodes[item.from].context === display.nodes[item.to].context) return;
    for (const run of segments(layout, e)) { assert(axisAligned(run)); assert.equal(crossedCard(layout, display.nodes.length, run), -1, 'a call between Triskel bands never crosses a card'); }
  });
  // Much wider than the layered layout: kept layered, and the reason is given.
  layout = await layoutModule.layoutWithTriskel(input, layoutModule.METRICS, engine((graph, index) => index === 0 ? {...column(graph), width: 99999} : null));
  assert.equal(layout.engine.realms.find(item => item.key === 0).engine, 'layered');
  assert.match(layout.engine.realms.find(item => item.key === 0).reason, /wider/);
  assert.equal(layout.engine.realms.find(item => item.key === 1).engine, 'triskel', 'the other realm still uses Triskel');
  layout = await layoutModule.layoutWithTriskel(input, layoutModule.METRICS, engine((graph, index) => index === 1 ? {...column(graph), height: 999999} : null));
  assert.match(layout.engine.realms.find(item => item.key === 1).reason, /taller/, 'a far taller Triskel drawing keeps the layered layout');
  layout = await layoutModule.layoutWithTriskel(input, layoutModule.METRICS, engine(() => ({status: 'too_large', reason: 'limit'})));
  assert(layout.engine.realms.every(item => item.engine === 'layered'));
  layout = await layoutModule.layoutWithTriskel(input, layoutModule.METRICS, engine(graph => ({...column(graph), nodes: column(graph).nodes.slice(1)})));
  assert(layout.engine.realms.filter(item => item.reason !== 'one card').every(item => /did not match/.test(item.reason)), 'an answer of the wrong shape is never drawn');
  layout = await layoutModule.layoutWithTriskel(input, layoutModule.METRICS, async () => { throw Error('connection refused'); });
  assert.equal(layout.engine.failure, 'connection refused');
  assert.equal(overlaps(layout, display.nodes.length), 0, 'without the route the layered layout stands');
  assert.deepEqual(layoutModule.waypointRoute([0, 0, 0, 0, 0, 10, 0, 20, 5, 20], 1, 2), [1, 2, 1, 22, 6, 22], 'repeated and straight-through waypoints are dropped');
}
{
  // A large session lays out off the main thread in bounded time. The budget
  // is generous: this guards a quadratic regression, not a benchmark.
  const count = 6000, lanes = 12, from = [], to = [];
  for (let index = 1; index < count; index += 1) { from.push(Math.floor((index - 1) / 3)); to.push(index); if (index % 7 === 0) { from.push(index); to.push(Math.floor(index / 2)); } }
  const lane = Int32Array.from({length: count}, (_, index) => Math.floor(index / (count / lanes)));
  const started = performance.now();
  const layout = layoutModule.layoutGraph({count, lane, from: Int32Array.from(from), to: Int32Array.from(to)});
  const elapsed = performance.now() - started;
  assert.equal(layout.x.length, count);
  assert(elapsed < 20000, `6,000 cards lay out in ${elapsed.toFixed(0)} ms`);
  console.log(`flow graph layout: ${count} cards, ${from.length} edges in ${elapsed.toFixed(0)} ms`);
}
{
  // Highlight: every stack through a node, as display indexes.
  const m = model.flowGraphModel(sessionDoc()), display = model.flowGraphDisplay(m);
  const through = model.flowGraphPathsThrough(m, [4]);
  assert.equal(through.length, 1, 'only one stack passes through the eval helper');
  const lit = model.flowGraphHighlight(m, display, through);
  assert(lit.nodes.has(display.displayOf[2]) && lit.nodes.has(display.displayOf[4]) && !lit.nodes.has(display.displayOf[5]));
  assert(!lit.nodes.has(-1), 'a request row is never a lit card index');
  assert(lit.edges.has(3) && !lit.edges.has(4), 'only the edges that stack walked are lit');
  assert(lit.originalEdges.has(7), 'the request row that stack ended at is lit');
  assert.equal(model.flowGraphHighlight(m, display, model.flowGraphPathsThrough(m, [5])).occurrences, 4);
  const both = model.flowGraphHighlight(m, display, model.flowGraphPathsThrough(m, [2]));
  assert.equal(both.paths, 3, 'every stack enters the iframe through onMessage');
}

// The panel in a DOM model: no canvas, so drawing is skipped and the state,
// inspector and keyboard handling are what is checked.
const {window, document} = parseHTML('<!doctype html><html><body><section id="host"></section></body></html>');
const answers = [], opened = [];
const context = createContext({window, document, console, setTimeout, clearTimeout, AbortController, AbortSignal, URLSearchParams, DOMException,
  requestAnimationFrame: callback => setTimeout(callback, 0), Event: window.Event, KeyboardEvent: window.KeyboardEvent ?? window.Event,
  location: {protocol: 'http:'}, Map, Set, Int32Array, Float64Array, Float32Array, Uint8Array, Uint32Array, Math, JSON, Promise, Error, Number, String, Object, Array, Symbol});
context.globalThis = context;
const ui = new URL('../apps/research-ui/', import.meta.url);
for (const name of ['flow_graph_layout.js', 'flow_graph.js']) runInContext(await readFile(new URL(name, ui), 'utf8'), context, {filename: name});
context.__answers = answers; context.__opened = opened;
runInContext(`var panel = createFlowGraphPanel({host: document.querySelector('#host'), open: node => __opened.push(node.name),
  fetchGraph: async session => { const next = __answers.shift(); if (next instanceof Error) throw next; return next; }});`, context);
const panel = name => runInContext(`panel.${name}`, context);
const settle = async () => { for (let index = 0; index < 6; index += 1) await nextTurn(); };
const host = document.querySelector('#host');
const text = selector => host.querySelector(selector)?.textContent ?? '';
{
  answers.push(sessionDoc());
  runInContext(`panel.show({session: '7', request: null})`, context);
  await settle();
  let snapshot = panel('snapshot()');
  assert.equal(snapshot.status, 'ready');
  assert.match(text('.flow-graph-stats'), /2 distinct stacks · 8 functions · 2 sinks · 3 realms/, 'counts come from the document');
  assert.match(text('.flow-graph-inspector'), /top\.test[\s\S]*frame\.test[\s\S]*Unidentified realm/, 'the overview lists every realm');
  assert.match(text('.flow-graph-inspector'), /Crossings: 1 frame, 2 JS ↔ Wasm, 1 into eval/);
  assert.match(text('.flow-graph-inspector'), /MessagePort and worker messages/, 'what is not walked is said');
  // Keyboard: arrows select, Enter opens a resolved function in Sources.
  const canvas = host.querySelector('.flow-graph-canvas');
  const key = name => canvas.dispatchEvent(Object.assign(new window.Event('keydown', {bubbles: true, cancelable: true}), {key: name}));
  key('ArrowDown');
  snapshot = panel('snapshot()');
  assert(snapshot.selected >= 0, 'the first arrow selects the top card');
  assert(snapshot.highlight?.paths >= 1, 'selecting lights the stacks through it');
  assert.equal(snapshot.display.nodes[snapshot.selected].status, 'unresolved', 'the top-left card is the unidentified caller');
  key('Enter');
  assert.deepEqual(opened, [], 'an unresolved frame has nothing to open');
  for (let step = 0; step < 8 && panel('snapshot()').display.nodes[panel('snapshot()').selected].status !== 'resolved'; step += 1) key('ArrowRight');
  const picked = panel('snapshot()').display.nodes[panel('snapshot()').selected];
  assert.equal(picked.status, 'resolved', 'ArrowRight reaches the next lane');
  key('Enter');
  assert.deepEqual(opened, [picked.name], 'Enter opens the selected function in Sources');
  key('Escape');
  assert.equal(panel('snapshot()').selected, -1, 'Escape clears the selection');
  assert.equal(panel('snapshot()').highlight, null);
  // A selected request lights only its own stack.
  assert.equal(runInContext(`panel.highlightRequest({process: 41, request: '73'})`, context), true);
  snapshot = panel('snapshot()');
  assert.equal(snapshot.highlight.paths, 1);
  assert.equal(snapshot.display.nodes[snapshot.selected].kind, 'eval', 'the function that made the request is selected');
  assert.equal(snapshot.cards[snapshot.selected].rows[snapshot.selectedRow].target, 'GET frame.test', 'on the row of that request');
  assert.match(text('.flow-graph-inspector'), /Called by · 1/);
  assert.match(text('.flow-graph-inspector'), /Requests, navigations and cookie writes · 1[\s\S]*GET frame\.test/);
  assert.match(text('.flow-graph-selection'), /^Selected request GET frame\.test · ← <img src=x onerror=alert\(1\)> VM31:1:17 · .*frame\.test · 1 distinct stack · 5 cards$/, 'the status names the request and the function that made it');
  // Details open and close from the keyboard; the menu opens on the selection.
  assert.equal(host.querySelector('.flow-graph-inspector').hidden, true, 'details stay closed until asked for');
  key('i');
  assert.equal(panel('snapshot()').details, true);
  assert.equal(host.querySelector('.flow-graph-inspector').hidden, false);
  key('i');
  assert.equal(host.querySelector('.flow-graph-inspector').hidden, true);
  key('ContextMenu');
  assert.equal(panel('snapshot()').menu, true, 'the context menu key opens the card menu');
  const menu = host.querySelector('.flow-graph-menu');
  assert.equal(menu.getAttribute('role'), 'menu');
  const items = [...menu.querySelectorAll('[role="menuitem"]')].map(item => `${item.firstChild.textContent}${item.disabled ? ' (off)' : ''}`);
  assert.deepEqual(items, ['Copy call site (off)', 'Open in Sources', 'Go to caller', 'Center on card', 'Show details', 'Copy name', 'Copy location'], 'the menu on a request row offers what the row and the card can do; a row with no recorded site cannot be copied');
  menu.dispatchEvent(Object.assign(new window.Event('keydown', {bubbles: true, cancelable: true}), {key: 'Escape'}));
  assert.equal(panel('snapshot()').menu, false, 'Escape closes the menu');
  key('c');
  assert.match(text('.flow-graph-toast'), /Copy is not available here\. Name: <img src=x onerror=alert\(1\)>/, 'copy says so when the shell has no clipboard, in a toast');
  // Rows from the keyboard: J steps calls, U goes to the caller, Enter
  // follows a call and Backspace comes back.
  key('u');
  snapshot = panel('snapshot()');
  assert.equal(snapshot.display.nodes[snapshot.selected].name, 'bridge', 'U goes to the caller');
  assert.equal(snapshot.cards[snapshot.selected].rows[snapshot.selectedRow].op, 'call', 'on the row of the call it came from');
  key('j');
  snapshot = panel('snapshot()');
  assert.equal(snapshot.cards[snapshot.selected].rows[snapshot.selectedRow].target, 'run', 'J steps to the next call');
  key('j');
  assert.equal(panel('snapshot()').cards[panel('snapshot()').selected].rows[panel('snapshot()').selectedRow].target, 'run', 'J stops at the last call');
  key('Enter');
  assert.equal(panel('snapshot()').display.nodes[panel('snapshot()').selected].name, 'run', 'Enter follows the call');
  key('Backspace');
  assert.equal(panel('snapshot()').display.nodes[panel('snapshot()').selected].name, 'bridge', 'Backspace returns');
  key('Backspace');
  assert.equal(panel('snapshot()').display.nodes[panel('snapshot()').selected].kind, 'eval', 'and again, to where U started');
  // The key closes on Escape from anywhere in the view, and when Details opens.
  host.querySelector('.flow-graph-key-toggle').click();
  assert(host.querySelector('.flow-graph-status').hasAttribute('data-key-open'));
  key('Escape');
  assert(!host.querySelector('.flow-graph-status').hasAttribute('data-key-open'), 'Escape closes the key');
  host.querySelector('.flow-graph-key-toggle').click(); key('i');
  assert(!host.querySelector('.flow-graph-status').hasAttribute('data-key-open'), 'opening Details closes the key');
  key('i');
  // Escape clears the selection, then closes Details.
  key('i'); key('Escape'); assert.equal(panel('snapshot()').selected, -1); assert.equal(panel('snapshot()').details, true);
  key('Escape'); assert.equal(panel('snapshot()').details, false, 'a second Escape closes Details');
  // The chosen request can be lit again after another selection.
  assert.equal(host.querySelector('.flow-graph-request-again').hidden, false, 'Request stack offers the chosen request again');
  host.querySelector('.flow-graph-request-again').click();
  assert.equal(panel('snapshot()').highlight.paths, 1);
  assert.equal(host.querySelector('.flow-graph-request-again').hidden, true);
  assert.equal(runInContext(`panel.highlightRequest({process: 41, request: '999'})`, context), false, 'a request with no stack says so');
  // Captured names are inert text.
  runInContext(`panel.highlightRequest({process: 41, request: '73'})`, context);
  const evalIndex = panel('snapshot()').display.nodes.findIndex(item => item.kind === 'eval');
  assert(evalIndex >= 0);
  assert.equal(host.querySelectorAll('img').length, 0, 'a hostile function name never becomes markup');
  // Find narrows to matches.
  const filter = host.querySelector('.flow-graph-filter input');
  filter.value = 'bridge'; filter.dispatchEvent(new window.Event('input'));
  await new Promise(resolve => setTimeout(resolve, 160));
  assert.equal(panel('snapshot()').matches.length, 1);
  assert.equal(text('.flow-graph-matches'), '1 match');
  filter.dispatchEvent(Object.assign(new window.Event('keydown', {bubbles: true, cancelable: true}), {key: 'Enter'}));
  assert.equal(text('.flow-graph-matches'), '1 of 1', 'Enter steps to a match and says which');
  assert.equal(panel('snapshot()').display.nodes[panel('snapshot()').selected].name, 'bridge');
  // A failed refresh keeps the last graph and says so.
  answers.push(new Error('store unavailable'));
  host.querySelector('.flow-graph-tools button[aria-label="Reload the flow graph"]').click();
  await settle();
  snapshot = panel('snapshot()');
  assert.equal(snapshot.status, 'ready', 'the previous graph stays');
  assert.match(text('.flow-graph-banner'), /Refresh failed\. Showing the previous graph\. store unavailable/);
  assert.equal(host.querySelector('.flow-graph-banner button').hidden, false, 'the warning offers Retry and stays');
  assert.equal(panel('snapshot()').display.nodes[panel('snapshot()').selected]?.name, 'bridge', 'a failed refresh keeps the selection');
  // A refresh that succeeds keeps the selection on the same function.
  answers.push(sessionDoc());
  host.querySelector('.flow-graph-tools button[aria-label="Reload the flow graph"]').click();
  await settle();
  assert.equal(panel('snapshot()').display.nodes[panel('snapshot()').selected]?.name, 'bridge', 'a refresh keeps the selection');
  assert.equal(host.querySelector('.flow-graph-banner').hidden, true);
  // A new session with no stacks is an explained empty state.
  answers.push({...sessionDoc(), nodes: [], edges: [], paths: [], contexts: [], stacks: {...sessionDoc().stacks, records: {}, distinct: 0, decoded: 0, occurrences: 0}});
  runInContext(`panel.show({session: '8', request: null})`, context);
  await settle();
  assert.equal(panel('snapshot()').status, 'empty');
  assert.match(text('.flow-graph-state'), /No recorded stacks in this session/);
  assert.equal(host.querySelector('.flow-graph-state button').textContent, 'Refresh', 'the empty state can ask again');
  // Reopening an empty graph asks again rather than keeping the old answer.
  answers.push(sessionDoc());
  runInContext(`panel.hide(); panel.show({session: '8', request: null})`, context);
  await settle();
  assert.equal(panel('snapshot()').status, 'ready', 'stacks recorded since the empty answer appear');
  // A first load that fails offers Retry.
  answers.push(new Error('route missing'));
  runInContext(`panel.show({session: '9', request: null})`, context);
  await settle();
  assert.equal(panel('snapshot()').status, 'error');
  assert.equal(host.querySelector('.flow-graph-state button').hidden, false, 'Retry is offered');
  runInContext(`panel.hide()`, context);
  assert.equal(host.hidden, true);
}
{
  // A layout interrupted by leaving the view is redone on return, polls do not
  // restart a running one, and a request with no stack clears the last one.
  const {window: w3, document: d3} = parseHTML('<!doctype html><html><body><section id="host"></section></body></html>');
  const workers = [];
  class FakeWorker {
    constructor() { this.terminated = false; workers.push(this); }
    postMessage(message) { this.message = message; }
    terminate() { this.terminated = true; }
    respond() { const layout = this.layoutModule.layoutGraph(this.message.graph, this.message.metrics); this.onmessage({data: {id: this.message.id, ok: true, layout}}); }
  }
  FakeWorker.prototype.layoutModule = layoutModule;
  const live = createContext({window: w3, document: d3, console, setTimeout, clearTimeout, AbortController, AbortSignal, URLSearchParams, DOMException,
    requestAnimationFrame: callback => setTimeout(callback, 0), location: {protocol: 'http:'}, Worker: FakeWorker});
  live.globalThis = live;
  for (const name of ['flow_graph_layout.js', 'flow_graph.js']) runInContext(await readFile(new URL(name, ui), 'utf8'), live, {filename: name});
  live.__doc = sessionDoc();
  runInContext(`var panel = createFlowGraphPanel({host: document.querySelector('#host'), fetchGraph: async () => __doc});`, live);
  const state = () => runInContext('panel.snapshot()', live);
  runInContext(`panel.show({session: '7'})`, live);
  await settle();
  assert.equal(workers.length, 1, 'one layout job started');
  runInContext(`panel.show({session: '7'})`, live);
  await settle();
  assert.equal(workers.length, 1, 'a poll does not restart the running layout');
  runInContext(`panel.hide()`, live);
  assert.equal(workers[0].terminated, true, 'leaving the view stops the layout');
  await settle();
  runInContext(`panel.show({session: '7'})`, live);
  await settle();
  assert.equal(workers.length, 2, 'returning redoes the interrupted layout');
  workers[1].respond();
  await settle();
  assert.equal(state().status, 'ready', 'the view does not stay on Laying out');
  assert.equal(state().layout.x.length, state().display.nodes.length, 'the drawn layout belongs to the drawn cards');
  runInContext(`panel.show({session: '7', request: {process: 41, request: '73'}})`, live);
  assert.equal(state().highlight.paths, 1);
  runInContext(`panel.show({session: '7', request: {process: 41, request: '999'}})`, live);
  assert.equal(state().highlight, null, 'a request with no stack does not keep the last one lit');
  assert.equal(state().selected, -1);
  runInContext(`panel.show({session: '7', request: {process: 41, request: '73'}})`, live);
  runInContext(`panel.show({session: '7', request: null})`, live);
  assert.equal(state().highlight, null, 'choosing no request clears its highlight');
}
{
  // The stored-evidence window has no route: an explanation, not a request.
  const {window: w2, document: d2} = parseHTML('<!doctype html><html><body><section id="host"></section></body></html>');
  const local = createContext({window: w2, document: d2, console, setTimeout, clearTimeout, AbortController, AbortSignal, URLSearchParams, DOMException,
    requestAnimationFrame: callback => setTimeout(callback, 0), location: {protocol: 'reb:'}});
  local.globalThis = local;
  for (const name of ['flow_graph_layout.js', 'flow_graph.js']) runInContext(await readFile(new URL(name, ui), 'utf8'), local, {filename: name});
  let fetched = 0; local.__count = () => { fetched += 1; };
  runInContext(`var panel = createFlowGraphPanel({host: document.querySelector('#host'), available: () => false, fetchGraph: async () => { __count(); }}); panel.show({session: '7'});`, local);
  await settle();
  assert.equal(fetched, 0);
  assert.match(d2.querySelector('.flow-graph-state').textContent, /needs the live backend/);
}
{
  // Shipped-source rules.
  const [view, layoutSource, css, html, app] = await Promise.all(['flow_graph.js', 'flow_graph_layout.js', 'flow_graph.css', 'index.html', 'app.js'].map(name => readFile(new URL(name, ui), 'utf8')));
  assert(!/innerHTML|insertAdjacentHTML|document\.write|outerHTML/.test(view + layoutSource), 'captured text is never inserted as HTML');
  assert(!/setInterval\(/.test(view), 'the view runs no repeating timers');
  assert(!/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/.test(css), 'colors come from design tokens');
  const tokens = /:root \{([^}]*)\}/.exec(css)[1];
  assert(/--flow-edge-cross:/.test(tokens) && !/color-mix|calc\(/.test(tokens), 'canvas tokens are plain values the canvas can parse');
  assert(!/\u2014/.test(view + layoutSource + css), 'no em dash characters');
  assert(/flowGraphEdgeNote\(model, display, edge\)/.test(view) && /'cross', 'crosses a frame, JS ↔ Wasm or into eval'/.test(view), 'a crossing is written on its row and in the key, not only colored');
  assert(/setAttribute\('role', 'menuitem'\)/.test(view), 'the card menu is a menu to assistive technology');
  assert(html.includes('id="trace-mode-graph"') && html.includes('id="flow-graph-host"'), 'Backtraces offers Flow graph beside Steps');
  assert(html.indexOf('flow_graph_layout.js') < html.indexOf('flow_graph.js"') && html.indexOf('flow_graph.js"') < html.indexOf('app.js"'), 'the layout and view load before app.js');
  assert(/typeof flowGraphPanel !== 'undefined'/.test(app), 'extracted app.js sections run without the panel');
  for (const [path, assets] of [['scripts/build-research-app.sh', ['flow_graph.js', 'flow_graph_layout.js', 'flow_graph.css']], ['apps/origin-trace-backend/src/app.rs', ['"flow_graph.js"', '"flow_graph_layout.js"', '"flow_graph.css"']],
    ['apps/research-ui/macos/OriginTraceApp.swift', ['/flow_graph.js', '/flow_graph_layout.js', '/flow_graph.css']]]) {
    const source = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    for (const asset of assets) assert(source.includes(asset), `${path} ships ${asset}`);
  }
}
console.log('PASS flow graph model, layout and panel (offline; rendered acceptance is the packaged-app gate)');
