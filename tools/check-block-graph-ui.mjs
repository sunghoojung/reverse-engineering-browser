#!/usr/bin/env node
// Block graph model and layout. Offline: no rendered layout or focus is claimed.
// Rendered acceptance is test25BlockGraphInSources in the packaged-app gate.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {performance} from 'node:perf_hooks';
import {runInThisContext} from 'node:vm';
const require = createRequire(import.meta.url);
// The layout worker loads the Triskel client with importScripts; here it is a global first.
runInThisContext(await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8'));
const layoutModule = require('../apps/research-ui/block_graph_layout.js');
const {vmStaticBlockGraph, vmObservedBlockGraph, BLOCK_GRAPH_KIND: KIND} = require('../apps/research-ui/block_graph.js');
const vmStatic = require('../apps/research-ui/vm_static.js');
const {vmStaticOwnedExample} = require('../apps/research-ui/vm_static_view.js');
const semantics = require('../apps/research-ui/vm_semantics.js');

const fixture = (count, edges, extra = {}) => {
  const rows = Array.from({length: count}, (_, index) => `${(index * 8).toString(16)} i32.const ${index}\n`).join('');
  return {count, offsets: Float64Array.from({length: count}, (_, index) => index * 8), ends: new Float64Array(count),
    firstRow: Uint32Array.from({length: count}, (_, index) => index), rowCount: new Uint32Array(count).fill(1),
    instructionCount: new Uint32Array(count).fill(1), flags: new Uint32Array(count).fill(2),
    from: Int32Array.from(edges.map(edge => edge[0])), to: Int32Array.from(edges.map(edge => edge[1])),
    kind: Uint8Array.from(edges.map(edge => edge[2] ?? 0)), labels: edges.map(edge => edge[3] ?? null), rows, roots: [0], ...extra};
};
const lay = graph => {
  const starts = layoutModule.rowStarts(graph.rows), sizes = layoutModule.nodeSizes(graph, starts, layoutModule.METRICS);
  return layoutModule.layoutGraph(graph, sizes, layoutModule.METRICS);
};
const overlaps = (layout, count) => {
  let found = 0;
  const order = [...Array(count).keys()].sort((a, b) => layout.y[a] - layout.y[b]);
  for (let i = 0; i < count; i += 1) for (let j = i + 1; j < count; j += 1) {
    const a = order[i], b = order[j];
    if (layout.y[b] >= layout.y[a] + layout.h[a]) break;
    if (layout.x[a] < layout.x[b] + layout.w[b] && layout.x[b] < layout.x[a] + layout.w[a]) found += 1;
  }
  return found;
};
const pointsOf = (layout, edge) => {
  const out = [];
  for (let index = layout.pointStart[edge]; index < layout.pointStart[edge + 1]; index += 1) out.push([layout.points[index * 2], layout.points[index * 2 + 1]]);
  return out;
};

{
  // A flattened dispatcher must not become a hairball: a wrapped grid, one
  // rail for every back edge, and buses instead of one line per arm.
  const arms = 300, edges = [[0, 1, KIND.fallthrough]];
  for (let arm = 0; arm < arms; arm += 1) { edges.push([1, 2 + arm, KIND.table, String(arm)]); edges.push([2 + arm, 0, KIND.branch, 'br']); }
  edges.push([1, 2 + arms, KIND.table_default, 'default']);
  const graph = fixture(3 + arms, edges), layout = lay(graph);
  assert.equal(overlaps(layout, graph.count), 0, 'no card overlaps another');
  const perRow = new Map();
  for (let arm = 0; arm < arms; arm += 1) perRow.set(layout.y[2 + arm], (perRow.get(layout.y[2 + arm]) ?? 0) + 1);
  const widest = Math.max(...perRow.values());
  assert(widest <= 24 && perRow.size >= 12, `dispatcher arms wrap into a grid: ${widest} per row, ${perRow.size} rows`);
  assert(layout.width < layout.height * 4 && layout.width < 8000, `dispatcher stays compact: ${layout.width}x${layout.height}`);
  const rails = new Set();
  edges.forEach(([from, to, kind], index) => { if (kind === KIND.branch) { const points = pointsOf(layout, index); rails.add(points[points.length - 2][0]); } });
  assert.equal(rails.size, 1, 'every back edge shares one rail beside the loop header');
  edges.forEach(([from, to], index) => {
    const points = pointsOf(layout, index), [x, y] = points[0], [endX, endY] = points.at(-1);
    assert(x >= layout.x[from] && x <= layout.x[from] + layout.w[from] && Math.abs(y - (layout.y[from] + layout.h[from])) < 1, `edge ${index} starts at its source's bottom`);
    assert(Math.abs(endX - (to === 0 ? layout.x[to] : layout.x[to] + layout.w[to] / 2)) < 1, `edge ${index} ends at its target`);
    assert(endY >= layout.y[to] - 1 && endY <= layout.y[to] + layout.h[to], `edge ${index} reaches its target`);
  });
  assert.equal(layout.direct, 0, 'a reducible dispatcher needs no direct edges');
  // Feeding wrapped rows takes one rail, not one per arm.
  const feeders = new Set();
  edges.forEach(([from, , kind], index) => { if (kind === KIND.table) { const points = pointsOf(layout, index); if (points.length > 4) feeders.add(points[2][0]); } });
  assert(feeders.size <= 1, `wrapped arms share one feeder rail: ${feeders.size}`);
}
{
  // A long chain of guards stays narrow: terminal arms stack and rails reuse columns.
  const count = 6000, edges = [];
  for (let index = 0; index < count - 1; index += 1) { edges.push([index, index + 1, KIND.not_taken]); if (index % 2 === 0) edges.push([index, count - 1, KIND.taken]); }
  const started = performance.now(), layout = lay(fixture(count, edges)), elapsed = performance.now() - started;
  assert.equal(overlaps(layout, count), 0, 'no card overlaps in a guard chain');
  assert(layout.width < 2000, `guard chain stays narrow: ${layout.width}`);
  assert(elapsed < 30000, `several thousand blocks lay out in bounded time: ${elapsed}ms`);
}
{
  // Early-return arms stack onto the spine instead of widening each row.
  const depth = 400, edges = [];
  for (let level = 0; level < depth; level += 1) { const head = level * 3; edges.push([head, head + 1, KIND.taken], [head, head + 3, KIND.not_taken], [head + 1, head + 2, KIND.fallthrough]); }
  const count = depth * 3 + 1, layout = lay(fixture(count, edges));
  assert.equal(overlaps(layout, count), 0, 'nested early returns do not overlap');
  assert(layout.width < 2000, `nested early returns stay narrow: ${layout.width}`);
}
{
  // An edge into the middle of another subtree cannot route around; it is drawn directly and counted.
  const layout = lay(fixture(4, [[0, 1], [1, 2], [2, 3], [0, 2], [3, 1, KIND.branch]]));
  assert.equal(overlaps(layout, 4), 0);
  const unreached = lay(fixture(3, [[0, 1]]));
  assert.equal(overlaps(unreached, 3), 0, 'a declared-unreached block is placed beneath the entry graph');
  assert(unreached.y[2] > unreached.y[0], 'unreached blocks sit below the reachable graph');
}
{
  // An unresolved target is a labeled stub, never a node or an invented target.
  const graph = fixture(1, [[0, -1, KIND.unresolved, 'indirect tail call']]);
  const layout = lay(graph), stub = pointsOf(layout, 0);
  assert.equal(stub.length, 2, 'stub edge has its own short segment');
  assert.equal(graph.count, 1, 'an unresolved target adds no block');
}
assert.throws(() => layoutModule.wasmGraph({schema: 'other'}), /invalid document/, 'an unknown provider document is refused');
{
  // VM adapter: same drawing, still declared, cfg.complete untouched.
  const {definition, image} = vmStaticOwnedExample();
  const report = await vmStatic.analyze(JSON.stringify(definition), JSON.stringify(image));
  assert.equal(report.cfg.complete, false);
  const graph = vmStaticBlockGraph(report);
  assert.equal(report.cfg.complete, false, 'the adapter never touches cfg.complete');
  assert.equal(graph.evidence, 'declared');
  assert.equal(graph.instructions, 16);
  assert(graph.count > 1 && graph.count < 16, `instructions group into basic blocks: ${graph.count}`);
  const rows = graph.rows.split('\n').filter(Boolean);
  assert.equal(rows.length, 16, 'every instruction keeps its row');
  assert(graph.from.length >= 2 && [...graph.kind].includes(KIND.taken) && [...graph.kind].includes(KIND.not_taken), 'conditional arms stay separate edge kinds');
  assert(lay(graph).width > 0);
  // Unresolved flow stays a labeled stub.
  const altered = JSON.parse(JSON.stringify(report));
  altered.cfg.edges.push({from_offset: report.instructions.at(-1).offset, to_offset: null, kind: 'unknown', status: 'unknown', evidence: 'declared_static'});
  const stubbed = vmStaticBlockGraph(altered);
  assert([...stubbed.to].includes(-1) && stubbed.labels.includes('unknown target'), 'an unknown destination is labeled, not invented');
}
{
  // Observed layer: retained occurrences, no edge across a gap, and no static block identity.
  const step = (sequence, pc) => ({sequence, opcode: '01', operands: [0], instruction_size: 1, before: {pc, halted: false, registers: [0], stack: [], memory: []}, after: {pc: pc + 1, halted: false, registers: [0], stack: [], memory: []}, evidence_refs: ['fixture']});
  const trace = {format: 'reb-vm-trace-v1', identity: {trace_id: 'owned-trace', investigation_id: 'owned-investigation', finding_id: 'owned-finding', artifact_id: 'owned-artifact', artifact_sha256: 'a'.repeat(64), scope_id: 'owned-scope', backend: 'fixture'}, architecture: 'register', coverage: {complete: false, dropped_steps: 3, limitations: []}, steps: [step(1, 0), step(2, 1), step(6, 40), step(7, 41)]};
  const path = semantics.observedPath(trace), graph = vmObservedBlockGraph(path);
  assert.equal(graph.evidence, 'observed');
  assert.equal(graph.count, 5, 'four occurrences and one gap card');
  assert.equal(graph.from.length, 2, 'edges join consecutive recorded sequences only');
  const gap = [...graph.flags].findIndex(flags => flags & 16);
  assert(gap > 0, 'the gap has a visible card');
  for (let edge = 0; edge < graph.from.length; edge += 1) assert(graph.from[edge] !== gap && graph.to[edge] !== gap, 'no edge touches a gap card');
  assert(graph.stackedRoots && graph.roots.length === 3, 'each retained run and the gap is its own root');
  const layout = lay(graph);
  assert(layout.y[gap] > layout.y[1] && layout.y[gap] < layout.y[gap + 1], 'the gap sits between the runs it separates');
  assert.equal(path.static_cfg_complete, false);
}
{
  // Shipped-source rules: inert captured text, no animation timers, tokens only.
  const ui = new URL('../apps/research-ui/', import.meta.url);
  const [view, css, html] = await Promise.all(['block_graph.js', 'block_graph.css', 'index.html'].map(name => readFile(new URL(name, ui), 'utf8')));
  assert(!/innerHTML|insertAdjacentHTML|document\.write|outerHTML/.test(view), 'captured text is never inserted as HTML');
  assert(!/setInterval|setTimeout/.test(view), 'the view runs no timers, so nothing fires while it is hidden');
  assert(!/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/.test(css), 'colors come from design tokens');
  assert(!/linear-gradient|radial-gradient/.test(css), 'no decorative gradients');
  for (const token of ['--graph-edge-taken', '--graph-edge-not-taken', '--graph-edge-table', '--graph-edge-unresolved']) assert(css.includes(`${token}:`), `${token} is defined`);
  assert(/\[\s*6,\s*3\s*\]/.test(view), 'the false arm has its own dash pattern, not only a color');
  assert(!/—/.test(view + css), 'no em dash characters');
  assert(html.includes('id="source-graph"') && html.includes('block_graph.js'), 'Sources offers Graph as a sibling view mode');
  assert(/function start\(\)[\s\S]{0,200}view\.z = 1;/.test(view), 'a graph opens at actual size, not at Fit');
  assert(/:is\(#source-window, #source-search-status\) \{ display: none/.test(css), 'text-window rows are hidden while Graph is active');
  assert(/BLOCK_GRAPH_ROW_ZOOM/.test(view) && /drawScreenLabels/.test(view), 'below row zoom, cards keep screen-size labels');
}
{
  // Triskel through the backend route: its coordinates and waypoints replace
  // the region layout, an unresolved edge keeps its stub, and the region
  // layout stays when Triskel would draw much wider or the route fails.
  const graph = fixture(4, [[0, 1, KIND.taken], [0, 2, KIND.not_taken], [1, 3], [2, 3], [3, -1, KIND.unresolved, 'unknown target']]);
  const starts = layoutModule.rowStarts(graph.rows), sizes = layoutModule.nodeSizes(graph, starts, layoutModule.METRICS);
  // The client caches Triskel's answer per graph, so each case grows one block to be a new graph.
  const base = () => { sizes.w[3] += 1; return {graph, starts, layout: layoutModule.layoutGraph(graph, sizes, layoutModule.METRICS)}; };
  const answers = [];
  globalThis.fetch = async (url, init) => {
    assert.equal(url, '/api/graph-layout'); assert.equal(init.method, 'POST');
    const body = JSON.parse(init.body);
    assert.equal(body.graphs.length, 1); assert.equal(body.graphs[0].nodes.length, 4);
    assert.deepEqual(body.graphs[0].edges, [[0, 1], [0, 2], [1, 3], [2, 3]], 'an unresolved edge is not sent');
    const next = answers.shift();
    if (next instanceof Error) throw next;
    return {ok: next.status === undefined || next.status === 200, status: next.status ?? 200, json: async () => next.body};
  };
  const laid = (width = 400) => ({schema: 'graph-layout-v1', engine: {name: 'triskel', revision: 'abc1234def'}, graphs: [{status: 'laid_out', width, height: 300,
    nodes: [[100, 0], [0, 100], [200, 100], [100, 200]], edges: [[150, 30, 150, 60, 50, 60, 50, 100], [160, 30, 160, 60, 250, 60, 250, 100], [50, 130, 50, 170, 150, 170, 150, 200], [250, 130, 250, 170, 160, 170, 160, 200]]}]});
  answers.push({body: laid()});
  let result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  const m = layoutModule.METRICS.margin;
  assert.equal(result.layout.engine.name, 'triskel');
  assert.deepEqual([result.layout.x[0], result.layout.y[0]], [m + 100, m], 'Triskel places the blocks');
  assert.deepEqual(pointsOf(result.layout, 0).at(-1), [m + 50, m + 100], 'and routes the edges');
  const stub = pointsOf(result.layout, 4);
  assert.equal(stub.length, 2); assert.equal(stub[0][1], result.layout.y[3] + result.layout.h[3], 'an unresolved edge keeps its stub under its block');
  assert.equal(overlaps(result.layout, 4), 0);
  answers.push({body: laid(100000)});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.name, 'layered'); assert.equal(result.layout.engine.reason.code, 'wider', 'a much wider Triskel drawing keeps the region layout');
  answers.push({body: {...laid(), graphs: [{...laid().graphs[0], height: 999999}]}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.code, 'taller', 'a far taller Triskel drawing keeps the region layout');
  answers.push(new Error('connection refused'));
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.code, 'route_failed', 'a missing route keeps the region layout');
  answers.push({status: 404, body: {}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.status, 404);
  answers.push({body: {...laid(), graphs: [{status: 'too_large', reason: 'over the per-graph limit'}]}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.code, 'too_large');
  answers.push({body: {...laid(), graphs: [{...laid().graphs[0], nodes: [[0, 0]]}]}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.code, 'mismatch', 'an answer of the wrong shape is never drawn');
  result = await layoutModule.runAsync({type: 'graph', graph, metrics: layoutModule.METRICS, engine: 'layered'});
  assert.equal(result.layout.engine.name, 'layered', 'a shell without the route never calls it');
  delete globalThis.fetch;
}
console.log('PASS block graph model and layout (offline; rendered acceptance is the packaged-app gate)');
