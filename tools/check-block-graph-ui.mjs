#!/usr/bin/env node
// Block graph model and layout. Offline: no rendered layout or focus is claimed.
// Rendered acceptance is test25BlockGraphInSources and, for the measured
// shapes, test25bBlockGraphShapes in the packaged-app gate.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {performance} from 'node:perf_hooks';
import {runInNewContext, runInThisContext} from 'node:vm';
const require = createRequire(import.meta.url);
const {parseHTML} = createRequire(new URL('ui-startup-deps/', import.meta.url))('linkedom');
// The layout worker loads the Triskel client with importScripts; here it is a global first.
runInThisContext(await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8'));
const layoutModule = require('../apps/research-ui/block_graph_layout.js');
const {BLOCK_GRAPH_KIND: KIND, blockGraphFailure, blockGraphClipSegment, blockGraphRowInView, blockGraphBoundView} = require('../apps/research-ui/block_graph.js');
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
  // An unresolved target is a labeled exit, never a node or an invented
  // target: a row in its card, sized there, with a short tick out of the
  // card's right side at that row.
  const graph = fixture(2, [[0, 1], [0, -1, KIND.unresolved, 'indirect tail call'], [0, -1, KIND.unresolved, 'throw: may escape']]);
  const starts = layoutModule.rowStarts(graph.rows), sizes = layoutModule.nodeSizes(graph, starts, layoutModule.METRICS), M = layoutModule.METRICS;
  assert.deepEqual([...sizes.exits], [2, 0], 'a card counts its exits');
  assert.equal(sizes.h[0], sizes.h[1] + M.padY + 2 * M.rowH, 'and its height holds a row for each under a separator');
  assert(sizes.w[0] >= '→ throw: may escape'.length * M.charW + 2 * M.padX, 'and its width the widest exit');
  const layout = layoutModule.layoutGraph(graph, sizes, M), right = layout.x[0] + layout.w[0], bottom = layout.y[0] + layout.h[0] - M.padY;
  assert.deepEqual(pointsOf(layout, 1), [[right, bottom - 1.5 * M.rowH], [right + 8, bottom - 1.5 * M.rowH]], 'the first exit leaves at its row');
  assert.deepEqual(pointsOf(layout, 2), [[right, bottom - 0.5 * M.rowH], [right + 8, bottom - 0.5 * M.rowH]], 'the second at the row below');
  assert.equal(graph.count, 2, 'an unresolved target adds no block');
}
{
  // Dominators come from the reachable blocks only: dead code that jumps into
  // live code is an exit of its card, and never moves the live drawing.
  const live = [[0, 1], [1, 2, KIND.taken], [1, 3, KIND.not_taken], [2, 3]];
  const alone = lay(fixture(4, live)), dead = fixture(6, [...live, [4, 5], [5, 2, KIND.branch]]);
  dead.flags[4] = dead.flags[5] = 0;
  const withDead = lay(dead);
  for (let block = 0; block < 4; block += 1) assert.equal(withDead.y[block], alone.y[block], `live block ${block} keeps its row`);
  assert(withDead.y[4] > withDead.y[3] && withDead.y[5] > withDead.y[3], 'unreached blocks sit below the reachable graph');
  assert.equal(withDead.stub[5], 1, 'an edge from dead code into live code is a stub');
  assert.equal(pointsOf(withDead, 5)[0][0], withDead.x[5] + withDead.w[5], 'drawn as an exit of its card, not a route');
  assert.equal(withDead.stub[4], 0, 'an edge inside the dead component is routed');
  // A dead switch whose unchosen arm (6) is an entry of its own: that entry
  // is entered from the block before it, so the join the arms share (8)
  // stays under the switch instead of every entry hanging from the root.
  const deadSwitch = fixture(10, [[0, 1], [1, 2], [2, 3], [4, 5, KIND.table, '0'], [4, 7, KIND.table_default], [5, 8, KIND.branch], [6, 8, KIND.branch], [7, 8, KIND.branch], [8, 9]]);
  for (let block = 4; block < 10; block += 1) deadSwitch.flags[block] = 0;
  const nested = lay(deadSwitch);
  assert.equal(overlaps(nested, 10), 0, 'no card of a dead switch overlaps');
  assert(nested.y[6] >= nested.y[5] + nested.h[5], 'a later entry sits under the block before it, as its text nests');
  assert(nested.y[8] >= Math.max(...[5, 6, 7].map(arm => nested.y[arm] + nested.h[arm])), 'the join its arms share sits below all of them');
  assert(nested.y[9] > nested.y[8], 'and the rest of the arm follows it');
}
{
  // A switch ladder (a guard per case, each case leaving to one exit) is one
  // column: the rest of the ladder outweighs each case, so it continues the
  // spine and the case sits beside it.
  const depth = 400, edges = [], exit = depth * 2;
  for (let level = 0; level < depth; level += 1) {
    const guard = level * 2, arm = guard + 1, next = level + 1 < depth ? guard + 2 : exit;
    edges.push([guard, arm, KIND.taken], [guard, next, KIND.not_taken], [arm, exit]);
  }
  const count = exit + 1, layout = lay(fixture(count, edges));
  assert.equal(overlaps(layout, count), 0, 'no card overlaps in a ladder');
  // The last guard's rest is one case, no heavier than its own, so it sits beside.
  const guards = new Set(Array.from({length: depth - 1}, (_, level) => layout.x[level * 2] + layout.w[level * 2] / 2));
  assert.equal(guards.size, 1, `every guard is on one spine: ${guards.size} columns`);
  assert(layout.width < 1200, `a ladder stays narrow: ${layout.width}`);
  let bends = 0;
  for (let edge = 0; edge < edges.length; edge += 1) bends += pointsOf(layout, edge).length - 2;
  assert(bends / edges.length < 3, `a ladder's edges bend little: ${(bends / edges.length).toFixed(2)} per edge`);
}
{
  // Blocks of only end, block, loop or similar run nothing: each folds into
  // the block it falls into as one summary row; the document keeps its rows.
  const rows = '0 block\n1 loop\n2 i32.const 1\n4 br_if 0\n6 end\n7 end\n8 return\n';
  const doc = {schema: 'wasm-block-graph-v1', function_index: 3, byte_offset: 100, byte_end: 109, status: 'decoded', instruction_count: 7, omissions: [], notice: '',
    edge_kinds: ['fallthrough', 'branch', 'taken', 'not_taken', 'table', 'table_default', 'exception', 'unresolved'],
    blocks: [[0, 2, 0, 2, 2, 3], [2, 6, 2, 2, 2, 2], [6, 8, 4, 2, 2, 2], [8, 9, 6, 1, 1, 6]],
    edges: [[0, 1, 0, null], [1, 1, 2, null], [1, 2, 3, null], [2, 3, 0, null]], rows};
  const graph = layoutModule.wasmGraph(doc);
  assert.equal(graph.count, 2, 'two structural blocks fold away');
  assert.equal(graph.foldedBlocks, 2);
  assert.deepEqual([...graph.offsets], [0, 6], 'a folded block keeps the first offset, where branches land');
  assert.deepEqual([...graph.firstRow], [0, 4]); assert.deepEqual([...graph.rowCount], [4, 3], 'and every row');
  assert.deepEqual([...graph.instructionCount], [4, 3]); assert.deepEqual([...graph.folded], [2, 2]);
  assert.deepEqual(graph.foldNote, ['block, loop', 'end \u00d72'], 'its summary row says what folded');
  assert.equal(graph.flags[0] & 1, 1, 'the entry stays the entry');
  assert.deepEqual([[...graph.from], [...graph.to], [...graph.kind]], [[0, 0], [0, 1], [KIND.taken, KIND.not_taken]], 'edges join the folded blocks');
  assert.deepEqual([0, 1].map(block => layoutModule.shownRows(graph, block)), [3, 2], 'a card draws the summary and its own rows');
  const layout = lay(graph);
  assert.equal(overlaps(layout, 2), 0);
  // A block with real work, or with any other edge, is never folded.
  const kept = layoutModule.wasmGraph({...doc, rows: rows.replace('0 block', '0 nop').replace('1 loop', '1 drop')});
  assert.equal(kept.count, 3, 'only rows that run nothing fold');
}
assert.throws(() => layoutModule.wasmGraph({schema: 'other'}), /invalid document/, 'an unknown provider document is refused');
{
  // VM adapter: same drawing, still declared, cfg.complete untouched.
  const {definition, image} = vmStaticOwnedExample();
  const report = await vmStatic.analyze(JSON.stringify(definition), JSON.stringify(image));
  assert.equal(report.cfg.complete, false);
  const graph = layoutModule.vmStaticGraph(report);
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
  const stubbed = layoutModule.vmStaticGraph(altered);
  assert([...stubbed.to].includes(-1) && stubbed.labels.includes('unknown target'), 'an unknown destination is labeled, not invented');
}
{
  // Observed layer: retained occurrences, no edge across a gap, and no static block identity.
  const step = (sequence, pc) => ({sequence, opcode: '01', operands: [0], instruction_size: 1, before: {pc, halted: false, registers: [0], stack: [], memory: []}, after: {pc: pc + 1, halted: false, registers: [0], stack: [], memory: []}, evidence_refs: ['fixture']});
  const trace = {format: 'reb-vm-trace-v1', identity: {trace_id: 'owned-trace', investigation_id: 'owned-investigation', finding_id: 'owned-finding', artifact_id: 'owned-artifact', artifact_sha256: 'a'.repeat(64), scope_id: 'owned-scope', backend: 'fixture'}, architecture: 'register', coverage: {complete: false, dropped_steps: 3, limitations: []}, steps: [step(1, 0), step(2, 1), step(6, 40), step(7, 41)]};
  const path = semantics.observedPath(trace), graph = layoutModule.vmObservedGraph(path);
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
  assert(!/--graph-edge-[a-z-]+: var\(--accent\)/.test(css) && /--graph-selection: var\(--accent\)/.test(css), 'the selection owns the accent; no edge kind is drawn in it');
  const container = css.indexOf('@container (max-width: 600px) or (max-height: 280px)');
  assert(container > 0 && !/@media \(max-width/.test(css), 'the stage, not the window, decides the minimap size');
  for (const base of ['.block-graph-minimap {', '.block-graph-minimap-canvas {', '.block-graph-hud {'])
    assert(container > css.indexOf(base), `the small-stage rules follow ${base}, so they win the cascade`);
  assert(/new Path2D\(\)/.test(view) && /drawOverview/.test(view), 'overview cards and edges are drawn one path per kind');
}
{
  // The Functions list keeps the keyboard's row whole in view, whatever
  // height the list has: ten rows of 24 px here, then a shorter list.
  assert.equal(blockGraphRowInView(9, 0, 240, 24), 0, 'the tenth row shows without scrolling');
  assert.equal(blockGraphRowInView(10, 0, 240, 24), 24, 'the eleventh row scrolls one row');
  assert.equal(blockGraphRowInView(12, 24, 240, 24), 72, 'each step down past the end moves one row');
  assert.equal(blockGraphRowInView(3, 72, 240, 24), 72, 'a row already in view does not scroll');
  assert.equal(blockGraphRowInView(2, 72, 240, 24), 48, 'a row above the view scrolls to the top');
  assert.equal(blockGraphRowInView(5, 0, 100, 24), 44, 'a list four rows tall shows the sixth row whole at its bottom');
  assert.equal(blockGraphRowInView(1, 0, 0, 24), 24, 'an unmeasured list is one row tall');
}
{
  // A view stays on its drawing: half the stage of a large one on each axis,
  // all of a small one, and a view already on it does not move.
  assert.deepEqual(blockGraphBoundView({x: 5000, y: -5000, z: 1}, 2000, 3000, 1000, 600), {x: 1500, y: -300, z: 1}, 'a large drawing keeps half the stage');
  assert.deepEqual(blockGraphBoundView({x: 400, y: -900, z: 0.5}, 300, 200, 1000, 600), {x: 0, y: -900, z: 0.5}, 'a small one stays whole, anywhere on the stage');
  assert.deepEqual(blockGraphBoundView({x: 100, y: 200, z: 2}, 2000, 3000, 1000, 600), {x: 100, y: 200, z: 2}, 'a view on the drawing is kept');
}
{
  // Failures say why, and offer Retry only where trying again can help.
  const memory = blockGraphFailure(Object.assign(Error('Invalid typed array length: 4294967296'), {name: 'RangeError'}));
  assert.equal(memory.retry, false); assert.match(memory.message, /more memory than the layout could allocate \(Invalid typed array length/);
  assert.equal(blockGraphFailure(new TypeError('Load failed')).retry, true, 'an unreachable service can come back');
  assert.equal(blockGraphFailure(Object.assign(Error('busy'), {status: 503})).retry, true);
  assert.equal(blockGraphFailure(Object.assign(Error('no such function'), {status: 404})).retry, false, 'a refused read is refused again');
  assert.equal(blockGraphFailure(Error('The WASM graph provider returned an invalid document.')).retry, false);
  assert.equal(blockGraphFailure(Object.assign(Error('The layout worker stopped before it answered.'), {transient: true})).retry, true);
}
{
  // Triskel through the backend route: its coordinates and waypoints make a
  // second drawing, kept whatever its size with how it compares, an
  // unresolved edge keeps its exit row, and the region layout stays when the
  // route fails.
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
  assert.equal(stub.length, 2); const {padY, rowH} = layoutModule.METRICS;
  assert.deepEqual(stub[0], [result.layout.x[3] + result.layout.w[3], result.layout.y[3] + result.layout.h[3] - padY - rowH / 2], 'an unresolved edge keeps its exit row');
  assert.equal(overlaps(result.layout, 4), 0);
  const region = base(), regionWidth = region.layout.width - 2 * m;
  answers.push({body: laid(100000)});
  result = await layoutModule.withTriskel(region, layoutModule.METRICS);
  assert.equal(result.layout.engine.name, 'triskel', 'a Triskel drawing asked for is kept however wide');
  assert(Math.abs(result.layout.engine.ratio.width - 100000 / regionWidth) < 1e-6, 'and says how much wider it is');
  answers.push({body: {...laid(), graphs: [{...laid().graphs[0], height: 999999}]}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.name, 'triskel'); assert(result.layout.engine.ratio.height > 100, 'or how much taller');
  answers.push(new Error('connection refused'));
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.code, 'route_failed', 'a missing route keeps the region layout');
  answers.push({status: 404, body: {}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.status, 404);
  answers.push({body: {...laid(), graphs: [{status: 'failed', reason: 'Triskel placed nodes 1 and 2 on top of each other'}]}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.deepEqual(result.layout.engine.reason, {code: 'failed', status: 'failed', detail: 'Triskel placed nodes 1 and 2 on top of each other'}, 'a failed layout keeps the region layout and says why');
  // Progress is heard once a request is sent; a stopped request keeps the
  // region layout as `cancelled`.
  const heard = [];
  answers.push({body: laid()});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS, {progress: stage => heard.push(stage)});
  assert.deepEqual(heard, [{stage: 'triskel'}]);
  assert.equal(result.layout.engine.name, 'triskel');
  const stop = new AbortController();
  // Like fetch: an aborted signal rejects at once, a later abort when it comes.
  const answering = globalThis.fetch;
  globalThis.fetch = async (url, init) => new Promise((resolve, reject) => {
    const abort = () => reject(new DOMException('Aborted', 'AbortError'));
    if (init.signal.aborted) abort(); else init.signal.addEventListener('abort', abort);
  });
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS, {signal: stop.signal, progress: () => queueMicrotask(() => stop.abort())});
  assert.deepEqual(result.layout.engine, {name: 'layered', reason: {code: 'cancelled'}}, 'a stopped Triskel request keeps the region layout');
  globalThis.fetch = answering;
  answers.push({body: {...laid(), graphs: [{...laid().graphs[0], nodes: [[0, 0]]}]}});
  result = await layoutModule.withTriskel(base(), layoutModule.METRICS);
  assert.equal(result.layout.engine.reason.code, 'mismatch', 'an answer of the wrong shape is never drawn');
  result = await layoutModule.runAsync({type: 'graph', graph, metrics: layoutModule.METRICS});
  assert.deepEqual(result.layout.engine, {name: 'layered'}, 'a region layout never calls the route');
  delete globalThis.fetch;
}
{
  // The region layout is drawn first and alone, at any size; nothing is sent
  // until Triskel is asked for. A Triskel job carries only the graph's count
  // and edges and the drawn layout's sizes, and sends a graph of any size whole.
  const {AUTOMATIC} = graphLayoutClient;
  const count = AUTOMATIC.graphNodes + 1, edges = Array.from({length: count - 1}, (_, index) => [index, index + 1]);
  const graph = fixture(count, edges);
  const sent = [];
  globalThis.fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    sent.push(body.graphs[0].nodes.length);
    return {ok: true, status: 200, json: async () => ({schema: 'graph-layout-v1', engine: {name: 'triskel', revision: 'abc1234def'},
      graphs: [{status: 'failed', reason: 'Triskel placed nodes 7 and 8 on top of each other'}]})};
  };
  const region = await layoutModule.runAsync({type: 'graph', graph, metrics: layoutModule.METRICS});
  assert.deepEqual(region.layout.engine, {name: 'layered'}, 'a large graph is drawn in its region layout');
  assert.deepEqual(sent, [], 'and sends nothing');
  const {w, h, width, height, stub} = region.layout;
  const result = await layoutModule.runAsync({type: 'triskel', graph: {count, from: graph.from, to: graph.to}, layout: {w, h, width, height, stub}, metrics: layoutModule.METRICS});
  assert.deepEqual(sent, [count], 'asked, any size is sent');
  assert.deepEqual(result.layout.engine.reason, {code: 'failed', status: 'failed', detail: 'Triskel placed nodes 7 and 8 on top of each other'});
  delete globalThis.fetch;
  const client = await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8');
  assert(!/setTimeout|AbortSignal\.timeout|LIMITS|too_large|request_budget/.test(client), 'the layout client has no timeout and no size limit');
}
{
  // The region layout draws structured control flow of any size: 100,000
  // blocks of nested branches, loops and early returns.
  let seed = 7;
  const next = bound => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % bound; };
  const edges = [];
  let count = 1;
  const block = () => count++;
  const region = (entry, budget, depth) => {
    let current = entry;
    while (budget > 0 && count < 100000) {
      const pick = depth < 12 ? next(10) : 0;
      if (pick < 4) { const after = block(); edges.push([current, after]); current = after; budget -= 1; }
      else if (pick < 6) { const a = block(), b = block(), join = block(), share = Math.max(1, budget / 6 | 0); edges.push([current, a, KIND.taken], [current, b, KIND.not_taken]);
        edges.push([region(a, share, depth + 1), join], [region(b, share, depth + 1), join]); current = join; budget -= 3 + 2 * share; }
      else if (pick < 8) { const head = block(), body = block(), out = block(); edges.push([current, head], [head, body, KIND.taken], [head, out, KIND.not_taken]);
        edges.push([region(body, Math.max(1, budget / 5 | 0), depth + 1), head]); current = out; budget -= 3 + (budget / 5 | 0); }
      else { const done = block(), after = block(); edges.push([current, done, KIND.taken], [current, after, KIND.not_taken]); current = after; budget -= 2; }
    }
    return current;
  };
  region(0, 100000, 0);
  const started = performance.now(), layout = lay(fixture(count, edges)), elapsed = performance.now() - started;
  assert(count >= 99000, `${count} blocks`);
  assert.equal(overlaps(layout, count), 0, 'no card overlaps in a large structured function');
  assert(elapsed < 60000, `${count} blocks lay out in bounded time: ${elapsed}ms`);
}
{
  // The view over a stand-in runner. The region layout is drawn at once.
  // Lay out with Triskel keeps it drawn while Triskel runs, is Cancel
  // meanwhile, and draws the answer with the selection kept and how it
  // compares; both drawings stay, one switch apart.
  const {document, window, Event} = parseHTML('<!doctype html><html><body><div id="host"></div></body></html>');
  let frames = [];
  const context = {document, window, Event, location: {protocol: 'http:'}, performance, getComputedStyle: () => ({getPropertyValue: () => ''}),
    requestAnimationFrame: fn => { frames.push(fn); return frames.length; }, cancelAnimationFrame: () => {}, devicePixelRatio: 1, console};
  runInNewContext(`${await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph_layout.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph.js', import.meta.url), 'utf8')}
globalThis.create = createBlockGraphView;`, context);
  const calls = [], skips = [], found = [];
  let answer = null;
  const runner = {run: (message, transfer, options) => { calls.push(message); return new Promise(resolve => { answer = resolve; }); }, skip: () => skips.push(true), cancel: () => {}};
  const host = document.querySelector('#host');
  const view = context.create(host, {runner, onFind: status => found.push(status)});
  view.activate();
  const $ = selector => host.querySelector(selector);
  const shown = element => element && !element.hidden;
  view.setState('loading', 'Laying out the graph\u2026');
  assert(!shown($('.block-graph-zoom-bar')) && !shown($('.block-graph-lod')), 'zoom and the overview cue wait for a drawing');
  const graph = fixture(3, [[0, 1, KIND.taken], [1, 2]], {title: 'func 1', status: 'decoded', instructions: 3, omissions: [], evidence: 'declared'});
  const drawn = () => ({graph, starts: layoutModule.rowStarts(graph.rows), layout: {...lay(graph), engine: {name: 'layered'}}});
  view.setResult(drawn());
  assert(shown($('.block-graph-zoom-bar')), 'a drawing has zoom');
  const triskel = $('.block-graph-triskel');
  assert(shown(triskel) && triskel.textContent === 'Lay out with Triskel', 'Triskel is offered for any drawn graph');
  assert.equal($('.block-graph-stats').textContent, '3 blocks \u00b7 3 instructions', 'the region layout needs no note until there is another');
  view.select(1);
  assert.match($('.block-graph-selection').textContent, /^loc_8 \u00b7 1 instruction \u00b7 1 successor$/, 'counts are singular when one');
  triskel.click();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].type, 'triskel');
  assert.equal(calls[0].graph.count, 3); assert.equal(calls[0].graph.from, graph.from, 'the drawn graph\'s edges, not its rows');
  assert.equal(calls[0].graph.rows, undefined);
  assert.equal(triskel.textContent, 'Cancel', 'while it runs the button stops it');
  assert(shown($('.block-graph-engine-run')) && $('.block-graph-engine-run').textContent.startsWith('Laying out with Triskel'), 'and the header counts its seconds');
  assert(!shown($('.block-graph-state')), 'the region layout stays drawn meanwhile');
  triskel.click();
  assert.equal(skips.length, 1, 'Cancel stops Triskel');
  answer({graph: {count: 3}, starts: null, layout: {...lay(graph), engine: {name: 'triskel', revision: '196ba112eba992c1460af3097c038defcf7a7e45', ratio: {width: 1.46, height: 0.8}}}});
  await new Promise(resolve => setImmediate(resolve));
  assert.match($('.block-graph-stats').textContent, /Triskel layout \u00b7 1\.5\u00d7 as wide, 0\.8\u00d7 as tall$/, 'any Triskel answer is drawn, with how it compares');
  assert.match($('.block-graph-stats').title, /Laid out by Triskel 196ba11/);
  assert(!shown($('.block-graph-engine-run')));
  assert.match($('.block-graph-selection').textContent, /^loc_8 /, 'the selected block stays selected');
  assert.equal(triskel.textContent, 'Show region layout');
  triskel.click();
  assert.match($('.block-graph-stats').textContent, /region layout$/);
  assert.equal(triskel.textContent, 'Show Triskel layout', 'both drawings stay');
  assert.equal(calls.length, 1, 'switching runs nothing');
  view.setResult(drawn());
  triskel.click();
  answer({graph: {count: 3}, starts: null, layout: {engine: {name: 'layered', reason: {code: 'cancelled'}}}});
  await new Promise(resolve => setImmediate(resolve));
  assert(shown(triskel) && triskel.textContent === 'Lay out with Triskel' && /Triskel stopped$/.test($('.block-graph-stats').textContent), 'a stopped run is offered again');
  // Find in the drawn rows: a new query shows the first matched block, Enter
  // steps on and wraps, and a Find typed before a graph runs once one is drawn.
  assert.equal(view.search('i32.const 1'), '1 of 1 block \u00b7 1 row match');
  assert.match($('.block-graph-selection').textContent, /^loc_8 /, 'the matched block is shown');
  assert.equal(view.search('I32'), '2 of 3 blocks \u00b7 3 rows match', 'case-insensitive, from the first block at or after the selection');
  assert.equal(view.search('I32', 1), '3 of 3 blocks \u00b7 3 rows match');
  assert.equal(view.search('I32', 1), '1 of 3 blocks \u00b7 3 rows match', 'and wraps');
  assert.equal(view.search('I32', -1), '3 of 3 blocks \u00b7 3 rows match', 'both ways');
  assert.equal(view.search('nothing here'), 'No row matches in 3 blocks.');
  assert.match($('.block-graph-find').textContent, /^Find: No row matches/);
  view.setTitle('func 2');
  view.search('const 2');
  assert.equal(view.search('const 2'), 'Find runs once the graph is drawn.');
  view.setResult(drawn());
  assert.deepEqual(found, ['1 block \u00b7 1 row match'], 'and the host hears when it does');
  // Alt+Arrow follows edges: Down to a successor, Up back along the same edge.
  const canvas = $('.block-graph-canvas');
  const press = (key, alt = true) => canvas.dispatchEvent(Object.assign(new Event('keydown', {bubbles: true, cancelable: true}), {key, altKey: alt, shiftKey: false, ctrlKey: false, metaKey: false}));
  view.select(0);
  press('ArrowDown');
  assert.match($('.block-graph-selection').textContent, /^loc_8 .* edge \u2190 loc_0, Alt\+Up follows$/, 'Alt+Down follows an edge out');
  press('ArrowUp');
  assert.match($('.block-graph-selection').textContent, /^loc_0 .* edge \u2192 loc_8, Alt\+Down follows$/, 'Alt+Up returns along it');
  press(']', false);
  assert.match($('.block-graph-selection').textContent, /^loc_8 /, '] steps to the next block in address order');
  view.setState('loading', 'Decoding basic blocks\u2026');
  assert(!shown(triskel), 'never over a load in progress');
  frames = [];
}
{
  // Exits drawn in their cards: a click on a stub's row goes to the block it
  // reaches, a click on an unresolved one focuses that edge. A no-op 2D
  // context lets the view draw, so the rows it hits are the ones it drew.
  const {document, window, Event} = parseHTML('<!doctype html><html><body><div id="host"></div></body></html>');
  const noop = new Proxy({}, {get: (_, key) => (key === 'measureText' ? () => ({width: 6.6}) : () => {}), set: () => true});
  window.HTMLCanvasElement.prototype.getContext = () => noop;
  const rect = {left: 0, top: 0, width: 1000, height: 700, right: 1000, bottom: 700};
  let frames = [];
  const context = {document, window, Event, location: {protocol: 'http:'}, performance, getComputedStyle: () => ({getPropertyValue: () => ''}), Path2D: class { rect() {} moveTo() {} lineTo() {} arcTo() {} closePath() {} },
    requestAnimationFrame: fn => { frames.push(fn); return frames.length; }, cancelAnimationFrame: () => {}, devicePixelRatio: 1, console, ResizeObserver: class { observe() {} disconnect() {} }};
  runInNewContext(`${await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph_layout.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph.js', import.meta.url), 'utf8')}
globalThis.create = createBlockGraphView;`, context);
  const host = document.querySelector('#host');
  host.getBoundingClientRect = () => rect;
  const view = context.create(host, {runner: {run: async () => null, skip() {}, cancel() {}}});
  for (const element of host.querySelectorAll('*')) element.getBoundingClientRect = () => (element.matches('.block-graph-stage, .block-graph-canvas') ? rect : {left: 0, top: 0, width: 0, height: 0, right: 0, bottom: 0});
  view.activate();
  const graph = fixture(4, [[0, 1], [1, -1, KIND.unresolved, 'throw'], [2, 3], [3, 1, KIND.exception, 'catch 0']], {title: 'func 1', status: 'decoded', instructions: 4, omissions: [], evidence: 'declared'});
  graph.flags[2] = graph.flags[3] = 0;
  const layout = {...lay(graph), engine: {name: 'layered'}};
  view.setResult({graph, starts: layoutModule.rowStarts(graph.rows), layout});
  const flush = () => { while (frames.length) frames.shift()(); };
  flush();
  const {padY, rowH} = layoutModule.METRICS, ox = layout.width / 2 - rect.width / 2, oy = layout.height / 2 - rect.height / 2;
  const canvas = host.querySelector('.block-graph-canvas');
  // linkedom has no :focus-visible; a pointer press never selects through it.
  canvas.focus = () => {};
  const click = (gx, gy) => {
    canvas.dispatchEvent(Object.assign(new Event('pointerdown'), {clientX: gx - ox, clientY: gy - oy, pointerId: 1}));
    canvas.dispatchEvent(Object.assign(new Event('pointerup'), {clientX: gx - ox, clientY: gy - oy, pointerId: 1}));
    flush();
  };
  const exitRow = block => [layout.x[block] + layout.w[block] / 2, layout.y[block] + layout.h[block] - padY - rowH / 2];
  click(...exitRow(3));
  assert.match(host.querySelector('.block-graph-selection').textContent, /^loc_8 .*edge \u2190 loc_18/, 'a stub\'s row goes to the block it reaches');
  click(...exitRow(1));
  assert.match(host.querySelector('.block-graph-selection').textContent, /^loc_8 .*edge \u2192 unresolved/, 'an unresolved row focuses its edge');
  frames = [];
}
{
  // However far Shift+Arrow, a drag or a scroll pushes the view past an edge,
  // it stops on the drawing, so the stage never goes blank. Each frame's view
  // is read back from the transform it draws the graph at.
  const {document, window, Event} = parseHTML('<!doctype html><html><body><div id="host"></div></body></html>');
  const transforms = [];
  const recording = new Proxy({}, {get: (_, key) => key === 'measureText' ? () => ({width: 6.6}) : key === 'setTransform' ? (...a) => transforms.push(a) : () => {}, set: () => true});
  window.HTMLCanvasElement.prototype.getContext = () => recording;
  const rect = {left: 0, top: 0, width: 1000, height: 700, right: 1000, bottom: 700};
  let frames = [];
  const context = {document, window, Event, location: {protocol: 'http:'}, performance, getComputedStyle: () => ({getPropertyValue: () => ''}), Path2D: class { rect() {} moveTo() {} lineTo() {} arcTo() {} closePath() {} },
    requestAnimationFrame: fn => { frames.push(fn); return frames.length; }, cancelAnimationFrame: () => {}, devicePixelRatio: 1, console, ResizeObserver: class { observe() {} disconnect() {} }};
  runInNewContext(`${await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph_layout.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph.js', import.meta.url), 'utf8')}
globalThis.create = createBlockGraphView;`, context);
  const host = document.querySelector('#host');
  host.getBoundingClientRect = () => rect;
  const view = context.create(host, {runner: {run: async () => null, skip() {}, cancel() {}}});
  for (const element of host.querySelectorAll('*')) element.getBoundingClientRect = () => (element.matches('.block-graph-stage, .block-graph-canvas') ? rect : {left: 0, top: 0, width: 0, height: 0, right: 0, bottom: 0});
  view.activate();
  // A chain far taller than the stage and narrower than half of it.
  const graph = fixture(60, Array.from({length: 59}, (_, index) => [index, index + 1]), {title: 'func 0', status: 'decoded', instructions: 60, omissions: [], evidence: 'declared'});
  const layout = {...lay(graph), engine: {name: 'layered'}};
  assert(layout.height > 2 * rect.height && layout.width < rect.width / 2, `a tall, narrow chain: ${layout.width}x${layout.height}`);
  view.setResult({graph, starts: layoutModule.rowStarts(graph.rows), layout});
  const canvas = host.querySelector('.block-graph-canvas');
  canvas.focus = () => {};
  // draw() clears at the identity, then sets the view's transform; 0 - keeps
  // a zero offset +0 for the strict comparisons.
  const drawn = () => { transforms.length = 0; while (frames.length) frames.shift()(); const [z, , , , e, f] = transforms[1]; return {x: 0 - e / z, y: 0 - f / z, z}; };
  const opened = drawn();
  assert.equal(opened.z, 1, 'the chain opens at actual size');
  const shift = (key, times) => { for (let i = 0; i < times; i += 1) canvas.dispatchEvent(Object.assign(new Event('keydown', {bubbles: true, cancelable: true}), {key, shiftKey: true, altKey: false, ctrlKey: false, metaKey: false})); return drawn(); };
  assert.deepEqual(shift('ArrowRight', 200), {...opened, x: 0}, 'Shift+Right stops with the narrow chain whole at the left edge');
  assert.deepEqual(shift('ArrowDown', 500), {x: 0, y: layout.height - rect.height / 2, z: 1}, 'Shift+Down stops with half the stage still showing its end');
  canvas.dispatchEvent(Object.assign(new Event('pointerdown'), {clientX: 500, clientY: 350, pointerId: 1}));
  canvas.dispatchEvent(Object.assign(new Event('pointermove'), {clientX: 50500, clientY: 50350, pointerId: 1}));
  canvas.dispatchEvent(Object.assign(new Event('pointerup'), {clientX: 50500, clientY: 50350, pointerId: 1}));
  assert.deepEqual(drawn(), {x: layout.width - rect.width, y: -rect.height / 2, z: 1}, 'a drag past the top left stops with the chain whole at the right edge and its start mid-stage');
  canvas.dispatchEvent(Object.assign(new Event('wheel', {cancelable: true}), {deltaX: 1e6, deltaY: 1e6, ctrlKey: false, metaKey: false}));
  assert.deepEqual(drawn(), {x: 0, y: layout.height - rect.height / 2, z: 1}, 'so does a scroll past the bottom right');
  frames = [];
}
{
  // A dashed edge as tall as a large function, drawn at actual size from its
  // middle: only a run around the view is added to the path, since a canvas
  // dashes a whole path before it clips, and the run starts where the whole
  // edge's dash pattern restarts, so every visible dash sits where it would
  // on the whole edge and none moves as the view pans.
  const {document, window, Event} = parseHTML('<!doctype html><html><body><div id="host"></div></body></html>');
  const strokes = [];
  let dash = [];
  const recording = new Proxy({}, {get: (_, key) => key === 'measureText' ? () => ({width: 6.6}) : key === 'setLineDash' ? list => { dash = list; }
    : key === 'stroke' ? path => { if (path) strokes.push({ops: path.ops, dash}); } : () => {}, set: () => true});
  window.HTMLCanvasElement.prototype.getContext = () => recording;
  const rect = {left: 0, top: 0, width: 1000, height: 700, right: 1000, bottom: 700};
  let frames = [];
  const context = {document, window, Event, location: {protocol: 'http:'}, performance, getComputedStyle: () => ({getPropertyValue: () => ''}),
    Path2D: class { constructor() { this.ops = []; } rect() {} moveTo(...a) { this.ops.push(['M', ...a]); } lineTo(...a) { this.ops.push(['L', ...a]); } arcTo(...a) { this.ops.push(['A', ...a]); } closePath() {} },
    requestAnimationFrame: fn => { frames.push(fn); return frames.length; }, cancelAnimationFrame: () => {}, devicePixelRatio: 1, console, ResizeObserver: class { observe() {} disconnect() {} }};
  runInNewContext(`${await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph_layout.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph.js', import.meta.url), 'utf8')}
globalThis.create = createBlockGraphView;`, context);
  const host = document.querySelector('#host');
  host.getBoundingClientRect = () => rect;
  const view = context.create(host, {runner: {run: async () => null, skip() {}, cancel() {}}});
  for (const element of host.querySelectorAll('*')) element.getBoundingClientRect = () => (element.matches('.block-graph-stage, .block-graph-canvas') ? rect : {left: 0, top: 0, width: 0, height: 0, right: 0, bottom: 0});
  view.activate();
  const graph = fixture(3, [[0, 2, KIND.table, '0-9'], [0, 1], [1, 2]], {title: 'func 0', status: 'decoded', instructions: 3, omissions: [], evidence: 'declared'});
  const layout = {...lay(graph), engine: {name: 'layered'}, width: 1300, height: 200200};
  [[440, 0], [300, 100000], [1040, 200040]].forEach(([x, y], block) => { layout.x[block] = x; layout.y[block] = y; });
  const tall = [[500, 40], [500, 60], [800, 60], [800, 200000], [1100, 200000], [1100, 200040]];
  const polylines = [tall, [[480, 40], [480, 100000]], [[340, 100040], [1060, 200040]]];
  layout.pointStart = Uint32Array.from([0, 6, 8, 10]);
  layout.points = Float32Array.from(polylines.flat(2));
  layout.box = Float32Array.from(polylines.flatMap(points => [Math.min(...points.map(p => p[0])), Math.min(...points.map(p => p[1])), Math.max(...points.map(p => p[0])), Math.max(...points.map(p => p[1]))]));
  view.setResult({graph, starts: layoutModule.rowStarts(graph.rows), layout});
  const flush = () => { while (frames.length) frames.shift()(); };
  flush();
  view.select(1);
  strokes.length = 0;
  flush();
  // Lengths along a path as a canvas strokes it: arcTo runs straight to its
  // first tangent point, then along the arc to the second.
  const along = ops => {
    const pieces = [];
    let x = 0, y = 0, walked = 0;
    const line = (tx, ty) => { pieces.push({x0: x, y0: y, x1: tx, y1: ty, from: walked}); walked += Math.hypot(tx - x, ty - y); x = tx; y = ty; };
    for (const [op, ...a] of ops) {
      if (op === 'M') { [x, y] = a; walked = 0; pieces.length = 0; }
      else if (op === 'L') line(a[0], a[1]);
      else {
        const [x1, y1, x2, y2, r] = a, ux = x1 - x, uy = y1 - y, vx = x2 - x1, vy = y2 - y1, lu = Math.hypot(ux, uy), lv = Math.hypot(vx, vy);
        const turn = Math.atan2(Math.abs(ux * vy - uy * vx), ux * vx + uy * vy), d = r * Math.tan(turn / 2);
        line(x1 - ux / lu * d, y1 - uy / lu * d); walked += r * turn; x = x1 + vx / lv * d; y = y1 + vy / lv * d;
      }
    }
    return {pieces, length: walked, at: (px, py) => { for (const p of pieces) if (blockGraphClipSegment([p.x0, p.y0, p.x1, p.y1], 0, {l: px - 1e-3, t: py - 1e-3, r: px + 1e-3, b: py + 1e-3})) return p.from + Math.hypot(px - p.x0, py - p.y0); return NaN; }};
  };
  const whole = along([['M', ...tall[0]], ...tall.slice(1, -1).map((p, i) => ['A', ...p, ...tall[i + 2], 6]), ['L', ...tall.at(-1)]]);
  const table = strokes.filter(stroke => stroke.dash.join() === '2,3' && stroke.ops.some(op => op[1] === 800));
  assert.equal(table.length, 1, 'the table edge is stroked with its dash');
  const runs = [];
  for (const op of table[0].ops) { if (op[0] === 'M') runs.push([]); runs.at(-1).push(op); }
  assert.equal(runs.length, 1, 'one run of the tall edge meets the view');
  const run = along(runs[0]), top = layout.y[1] + layout.h[1] / 2 - 350;
  assert(run.length < 700 + 2 * 50, `only the run around the view is added: ${run.length}`);
  assert(run.at(800, top) >= 0 && run.at(800, top + 700) >= 0, 'the run covers the view');
  for (let y = top; y <= top + 700; y += 37.25) {
    const phase = (((whole.at(800, y) - run.at(800, y)) % 5) + 5) % 5;
    assert(phase < 1e-3 || 5 - phase < 1e-3, `a visible dash at y ${y} sits where it does on the whole edge: ${phase}`);
  }
  frames = [];
}
{
  // The opening view, at actual size, frames the entry and the successors on
  // its first screen in the part of the stage the minimap leaves clear: a
  // wide branch beside the entry's spine does not open under the minimap.
  const {document, window, Event} = parseHTML('<!doctype html><html><body><div id="host"></div></body></html>');
  let shift = null;
  const recording = new Proxy({}, {get: (_, key) => key === 'measureText' ? () => ({width: 6.6}) : key === 'setTransform' ? (a, b, c, d, e, f) => { if (e || f) shift = {x: -e / a, y: -f / d}; } : () => {}, set: () => true});
  window.HTMLCanvasElement.prototype.getContext = () => recording;
  const rect = {left: 0, top: 0, width: 1000, height: 700, right: 1000, bottom: 700}, mini = {left: 750, top: 480, width: 250, height: 220, right: 1000, bottom: 700};
  let frames = [];
  const context = {document, window, Event, location: {protocol: 'http:'}, performance, getComputedStyle: () => ({getPropertyValue: () => ''}), Path2D: class { rect() {} moveTo() {} lineTo() {} arcTo() {} closePath() {} },
    requestAnimationFrame: fn => { frames.push(fn); return frames.length; }, cancelAnimationFrame: () => {}, devicePixelRatio: 1, console, ResizeObserver: class { observe() {} disconnect() {} }};
  runInNewContext(`${await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph_layout.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph.js', import.meta.url), 'utf8')}
globalThis.create = createBlockGraphView;`, context);
  const host = document.querySelector('#host');
  host.getBoundingClientRect = () => rect;
  const view = context.create(host, {runner: {run: async () => null, skip() {}, cancel() {}}});
  const none = {left: 0, top: 0, width: 0, height: 0, right: 0, bottom: 0};
  for (const element of host.querySelectorAll('*')) element.getBoundingClientRect = () => (element.matches('.block-graph-stage, .block-graph-canvas') ? rect : element.matches('.block-graph-minimap') ? mini : none);
  view.activate();
  // A diamond with wide arms, then a chain too tall to fit at actual size.
  const count = 40, edges = [[0, 1, KIND.taken], [0, 2, KIND.not_taken], [1, 3], [2, 3]];
  for (let block = 3; block + 1 < count; block += 1) edges.push([block, block + 1]);
  const graph = fixture(count, edges, {title: 'func 0', status: 'decoded', instructions: count, omissions: [], evidence: 'declared',
    rows: Array.from({length: count}, (_, index) => `${(index * 8).toString(16)} i32.const ${index < 3 ? '7'.repeat(36) : index}\n`).join('')});
  const layout = {...lay(graph), engine: {name: 'layered'}};
  assert(layout.height > rect.height && layout.y[1] === layout.y[2], 'the arms sit side by side and the graph is taller than the stage');
  view.setResult({graph, starts: layoutModule.rowStarts(graph.rows), layout});
  while (frames.length) frames.shift()();
  assert(shift, 'the view drew at actual size');
  for (const block of [0, 1, 2]) {
    assert(layout.x[block] >= shift.x && layout.x[block] + layout.w[block] <= shift.x + mini.left, `block ${block} opens left of the minimap: ${layout.x[block]}..${layout.x[block] + layout.w[block]} in ${shift.x}..${shift.x + mini.left}`);
  }
  frames = [];
}
{
  // The minimap marks the viewport where one can find it. A screen of a
  // chain thousands of screens tall gets an outline grown around its centre;
  // at the chain's ends, and at Fit, the outline stays whole on the minimap.
  const {document, window, Event} = parseHTML('<!doctype html><html><body><div id="host"></div></body></html>');
  const marks = [];
  const recording = new Proxy({}, {get: (_, key) => key === 'measureText' ? () => ({width: 6.6}) : () => {}, set: () => true});
  const outline = new Proxy({}, {get: (_, key) => key === 'strokeRect' ? (...box) => marks.push(box) : () => {}, set: () => true});
  window.HTMLCanvasElement.prototype.getContext = function getContext() { return this.classList.contains('block-graph-minimap-canvas') ? outline : recording; };
  const rect = {left: 0, top: 0, width: 1000, height: 700, right: 1000, bottom: 700}, mini = {left: 840, top: 580, width: 150, height: 110, right: 990, bottom: 690};
  const frames = [];
  const context = {document, window, Event, location: {protocol: 'http:'}, performance, getComputedStyle: () => ({getPropertyValue: () => ''}), Path2D: class { rect() {} moveTo() {} lineTo() {} arcTo() {} closePath() {} },
    requestAnimationFrame: fn => { frames.push(fn); return frames.length; }, cancelAnimationFrame: () => {}, devicePixelRatio: 1, console, ResizeObserver: class { observe() {} disconnect() {} }};
  runInNewContext(`${await readFile(new URL('../apps/research-ui/graph_layout_client.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph_layout.js', import.meta.url), 'utf8')}
${await readFile(new URL('../apps/research-ui/block_graph.js', import.meta.url), 'utf8')}
globalThis.create = createBlockGraphView;`, context);
  const host = document.querySelector('#host');
  host.getBoundingClientRect = () => rect;
  const view = context.create(host, {runner: {run: async () => null, skip() {}, cancel() {}}});
  const none = {left: 0, top: 0, width: 0, height: 0, right: 0, bottom: 0};
  for (const element of host.querySelectorAll('*')) element.getBoundingClientRect = () => (element.matches('.block-graph-stage, .block-graph-canvas') ? rect : element.matches('.block-graph-minimap') ? mini : none);
  view.activate();
  const count = 3000, edges = Array.from({length: count - 1}, (_, block) => [block, block + 1]);
  const graph = fixture(count, edges, {title: 'func 0', status: 'decoded', instructions: count, omissions: [], evidence: 'declared',
    rows: Array.from({length: count}, (_, index) => `${(index * 8).toString(16)} i32.const ${index}\n`).join('')});
  const layout = {...lay(graph), engine: {name: 'layered'}};
  view.setResult({graph, starts: layoutModule.rowStarts(graph.rows), layout});
  const drawn = () => { marks.length = 0; while (frames.length) frames.shift()(); return marks.at(-1); };
  const scale = Math.min(300 / layout.width, 220 / layout.height), oy = (220 - layout.height * scale) / 2;
  assert(700 * scale < 1, 'one screen is under a minimap pixel tall');
  const whole = ([x, y, w, h]) => x >= 1 && y >= 1 && x + w <= 299 + 1e-9 && y + h <= 219 + 1e-9 && w >= 16 && h >= 16;
  let mark = drawn();
  assert(mark && whole(mark) && mark[1] === 1 && mark[3] === 16, `the opening screen is marked whole at the top: ${mark}`);
  view.select(1500); mark = drawn();
  const middle = oy + (layout.y[1500] + layout.h[1500] / 2) * scale;
  assert(whole(mark) && mark[3] === 16 && Math.abs(mark[1] + 8 - middle) < 0.5, `a screen midway is marked around its centre ${middle}: ${mark}`);
  view.select(count - 1); mark = drawn();
  assert(whole(mark) && mark[1] + mark[3] === 219, `the last screen is marked whole at the bottom: ${mark}`);
  const canvas = host.querySelector('.block-graph-canvas');
  canvas.dispatchEvent(Object.assign(new Event('keydown', {bubbles: true, cancelable: true}), {key: '0'})); mark = drawn();
  const ox = (300 - layout.width * scale) / 2, holds = ([x, y, w, h]) => x <= ox && x + w >= ox + layout.width * scale && y <= Math.max(1, oy) && y + h >= Math.min(219, oy + layout.height * scale);
  assert(whole(mark) && holds(mark), `the outline at Fit holds the whole drawing and stays on the minimap: ${mark}`);
}
{
  // The flow graph over a realm past the size Triskel runs on unasked: a call
  // tree of 2,047 cards, which nothing folds. The layered layout is drawn
  // with nothing sent; Lay out with Triskel sends the realm, counts its
  // seconds beside Cancel, a stopped run is offered again, and an answer
  // replaces the layered layout.
  const {document, window, Event} = parseHTML('<!doctype html><html><body><div id="flow"></div></body></html>');
  window.HTMLElement.prototype.scrollIntoView ??= function scrollIntoView() {};
  const count = 2047, SHA = 'a'.repeat(64);
  const nodes = Array.from({length: count}, (_, id) => ({id, kind: 'wasm', context: 0, status: 'resolved', function_index: id, sha256: SHA, artifact_id: '9', url: 'https://wasm.test/m.wasm', script_id: 3, hits: 1, entries: id ? 0 : 1, leaves: 2 * id + 1 < count ? 0 : 1}));
  const edges = [];
  for (let id = 1; id < count; id += 1) edges.push({from: (id - 1) >> 1, to: id, kind: 'call', count: 1, crosses: []});
  const doc = {schema: 'flow-graph-v1', session_id: '1', evidence: 'observed', complete: true, coverage: {stopped: 'end'},
    stacks: {records: {request_initiator_stack: 1}, not_walked: {}, distinct: 1, occurrences: 1}, truncated: {}, limits: {}, not_shown: {},
    contexts: [{id: 0, process_id: 1, execution_context_id: '7', origin: 'https://wasm.test', origins: [], frame_ids: [], tab_ids: [], counts: {}}], nodes, edges, paths: []};
  const layouts = [];
  const fetch = async (url, init = {}) => {
    if (String(url).startsWith('/api/flow-graph')) return {ok: true, status: 200, json: async () => doc};
    assert.equal(url, '/api/graph-layout');
    const body = JSON.parse(init.body);
    return new Promise((resolve, reject) => {
      const abort = () => reject(new DOMException('Aborted', 'AbortError'));
      if (init.signal?.aborted) abort(); else init.signal?.addEventListener('abort', abort);
      layouts.push({body, answer: graphs => resolve({ok: true, status: 200, json: async () => ({schema: 'graph-layout-v1', engine: {name: 'triskel', revision: 'abc1234def'}, graphs})})});
    });
  };
  const context = {document, window, Event, location: {protocol: 'http:'}, addEventListener: () => {}, fetch, performance, console,
    requestAnimationFrame: fn => setTimeout(() => fn(performance.now()), 0), cancelAnimationFrame: clearTimeout, setTimeout, clearTimeout, queueMicrotask,
    getComputedStyle: () => ({getPropertyValue: () => ''}), innerHeight: 800, innerWidth: 1180, devicePixelRatio: 1, dispatchEvent: () => true,
    URLSearchParams, AbortController, AbortSignal, DOMException};
  const scripts = ['graph_layout_client.js', 'block_graph.js', 'request_stack.js', 'flow_graph_layout.js', 'flow_graph.js'];
  runInNewContext(`${(await Promise.all(scripts.map(name => readFile(new URL(`../apps/research-ui/${name}`, import.meta.url), 'utf8')))).join('\n')}
globalThis.create = createFlowGraphPanel;`, context);
  const settle = () => new Promise(resolve => setTimeout(resolve, 0));
  const host = document.querySelector('#flow');
  const flow = context.create({host, open: () => {}, available: () => true});
  flow.show({session: '1'});
  const $ = selector => host.querySelector(selector);
  for (let i = 0; i < 200 && !/layout/i.test($('.flow-graph-engine')?.textContent ?? ''); i++) await settle();
  assert.equal($('.flow-graph-engine').textContent, 'Layered layout', `${$('.flow-graph-state')?.textContent}`);
  assert.equal(layouts.length, 0, 'a realm past the automatic size sends nothing unasked');
  const triskel = $('.flow-graph-triskel');
  assert(!triskel.hidden && triskel.textContent === 'Lay out with Triskel', 'and is offered Triskel');
  assert.match($('.flow-graph-engine').title, /over 2,000 cards or 8,000 calls, where Triskel runs only when asked/);
  triskel.click();
  for (let i = 0; i < 200 && !layouts.length; i++) await settle();
  assert.equal(layouts.length, 1);
  assert.equal(layouts[0].body.graphs[0].nodes.length, count, 'asked, the whole realm is sent');
  assert.equal(triskel.textContent, 'Cancel');
  assert.match($('.flow-graph-engine-run').textContent, /^Laying out with Triskel \u00b7 \d+ s$/);
  assert($('.flow-graph-state').hidden, 'the layered layout stays drawn meanwhile');
  triskel.click();
  for (let i = 0; i < 200 && triskel.textContent !== 'Lay out with Triskel'; i++) await settle();
  assert(!triskel.hidden && triskel.textContent === 'Lay out with Triskel', 'a stopped run is offered again');
  assert($('.flow-graph-engine-run').hidden);
  assert.match($('.flow-graph-engine').title, /Triskel was stopped/);
  triskel.click();
  for (let i = 0; i < 200 && layouts.length < 2; i++) await settle();
  layouts[1].answer([{status: 'laid_out', width: 25600, height: 1600, elapsed_ms: 1,
    nodes: Array.from({length: count}, (_, i) => [(i % 128) * 200, Math.floor(i / 128) * 100]),
    edges: layouts[1].body.graphs[0].edges.map(([from, to]) => [(from % 128) * 200, Math.floor(from / 128) * 100, (to % 128) * 200, Math.floor(to / 128) * 100])}]);
  for (let i = 0; i < 200 && !/^Triskel/.test($('.flow-graph-engine').textContent); i++) await settle();
  assert.equal($('.flow-graph-engine').textContent, 'Triskel layout', 'the answer replaces the layered layout');
  assert(triskel.hidden && $('.flow-graph-engine-run').hidden);
}
console.log('PASS block graph model and layout (offline; rendered acceptance is the packaged-app gate)');
