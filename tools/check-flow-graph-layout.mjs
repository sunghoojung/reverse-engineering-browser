#!/usr/bin/env node
// Flow graph layout engine (flow_graph_layout.js), offline: drawing invariants
// on seeded call graphs from empty to 20,000 cards. No rendered output is
// claimed; the packaged-app gate draws the Graph pane.
//
// The scripts run in this realm, as the page and the worker load them: in a
// separate vm context every global lookup (Math, Array) goes through the
// context's interceptor and the engine runs several times slower than it does
// in a page or a worker.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {performance} from 'node:perf_hooks';
import {runInThisContext} from 'node:vm';

for (const file of ['graph_layout_client.js', 'flow_graph_layout.js']) {
  const url = new URL(`../apps/research-ui/${file}`, import.meta.url);
  runInThisContext(await readFile(url, 'utf8'), {filename: url.pathname});
}
const engine = runInThisContext('flowGraphLayout');
const {CURVE} = engine.ROUTE;

/** A seeded call graph: realms of call trees with chains, fan-in, calls
 * that skip layers, recursion, cycles and calls between realms. */
function callGraph(cards, realms, seed) {
  let state = seed >>> 0 || 1;
  const random = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 4294967296; };
  const lane = new Int32Array(cards), weight = new Float64Array(cards), w = new Float32Array(cards), h = new Float32Array(cards);
  const from = [], to = [], members = Array.from({length: realms}, () => []);
  for (let v = 0; v < cards; v += 1) {
    const realm = v < realms ? v : Math.floor(random() ** 1.6 * realms);
    lane[v] = realm; weight[v] = Math.floor(random() * 50); w[v] = 160 + Math.floor(random() * 160); h[v] = 34 + 18 * Math.floor(random() * 7);
    const own = members[realm];
    if (own.length) {
      // A caller near the end makes chains, one anywhere makes fan-out and
      // calls that pass layers.
      const callers = 1 + (random() < 0.3 ? 1 : 0) + (random() < 0.08 ? 2 : 0);
      for (let k = 0; k < callers; k += 1) {
        const near = random() < 0.6, at = near ? own.length - 1 - Math.floor(random() * Math.min(4, own.length)) : Math.floor(random() * own.length);
        from.push(own[at]); to.push(v);
      }
    }
    own.push(v);
    if (own.length > 3 && random() < 0.04) { from.push(v); to.push(own[Math.floor(random() * (own.length - 1))]); }
    if (random() < 0.02) { from.push(v); to.push(v); }
    if (realms > 1 && random() < 0.05) { const other = members[Math.floor(random() * realms)]; if (other.length) { from.push(v); to.push(other[Math.floor(random() * other.length)]); } }
  }
  return {count: cards, lane, weight, from: Int32Array.from(from), to: Int32Array.from(to), w, h};
}

const layOut = graph => engine.runAsync({graph, metrics: engine.METRICS, engine: 'layered'});

/** Route points with curves flattened the way flow_graph.js draws them. */
function points(layout, e) {
  const P = layout.routes, T = layout.routeTypes, out = [];
  for (let i = layout.routeStart[e]; i < layout.routeStart[e + 1]; i += 1) {
    const x = P[2 * i], y = P[2 * i + 1];
    if (i > layout.routeStart[e] && T[i] === CURVE) { const mid = (P[2 * i - 1] + y) / 2; out.push(P[2 * i - 2], mid, x, mid, x, y); }
    else out.push(x, y);
  }
  return out;
}

/** Every invariant of one drawing; returns its measures. */
function verify(name, graph, layout) {
  const {count, from, to} = graph, edges = from.length, near = (a, b) => Math.abs(a - b) <= 0.5;
  assert.equal(layout.x.length, count, `${name}: one box per card`);
  assert.equal(layout.routeStart.length, edges + 1, `${name}: one route per call`);
  assert.equal(layout.routes.length, 2 * layout.routeStart[edges], `${name}: two coordinates per route point`);
  assert.equal(layout.routeTypes.length, layout.routeStart[edges], `${name}: one type per route point`);
  for (let v = 0; v < count; v += 1) {
    assert(Number.isFinite(layout.x[v]) && Number.isFinite(layout.y[v]), `${name}: card ${v} is placed`);
    assert(layout.x[v] >= 0 && layout.y[v] >= 0 && layout.x[v] + layout.w[v] <= layout.width && layout.y[v] + layout.h[v] <= layout.height, `${name}: card ${v} is inside the drawing`);
  }
  // Bands: one per realm, apart, each holding its own cards.
  const laneOf = new Map(layout.lanes.map(lane => [lane.key, lane]));
  assert.equal(laneOf.size, new Set(graph.lane).size, `${name}: one band per realm`);
  for (let a = 0; a < layout.lanes.length; a += 1) for (let b = a + 1; b < layout.lanes.length; b += 1) {
    const A = layout.lanes[a], B = layout.lanes[b];
    assert(A.x + A.w <= B.x || B.x + B.w <= A.x || A.y + A.h <= B.y || B.y + B.h <= A.y, `${name}: bands ${A.key} and ${B.key} do not overlap`);
  }
  for (let v = 0; v < count; v += 1) {
    const lane = laneOf.get(graph.lane[v]);
    assert(layout.x[v] >= lane.x && layout.x[v] + layout.w[v] <= lane.x + lane.w && layout.y[v] >= lane.y && layout.y[v] + layout.h[v] <= lane.y + lane.h, `${name}: card ${v} is inside its band`);
  }
  // Cards never overlap: a sweep down the drawing.
  const byTop = [...Array(count).keys()].sort((a, b) => layout.y[a] - layout.y[b]);
  for (let i = 0; i < count; i += 1) for (let j = i + 1; j < count; j += 1) {
    const a = byTop[i], b = byTop[j];
    if (layout.y[b] >= layout.y[a] + layout.h[a]) break;
    assert(layout.x[a] + layout.w[a] <= layout.x[b] || layout.x[b] + layout.w[b] <= layout.x[a], `${name}: cards ${a} and ${b} do not overlap`);
  }
  // Routes: orthogonal, from the caller's bottom to the callee's top (a
  // recursion loop on its card's right edge), through no other card.
  const H = new Map(), V = new Map(), ends = [];
  const line = (map, key, run) => { let list = map.get(key); if (!list) map.set(key, list = []); list.push(run); };
  let bends = 0;
  for (let e = 0; e < edges; e += 1) {
    const p = points(layout, e), a = from[e], b = to[e], last = p.length - 2;
    assert(p.length >= 4, `${name}: call ${e} has a route`);
    if (a === b) {
      assert(near(p[0], layout.x[a] + layout.w[a]) && near(p[last], layout.x[a] + layout.w[a]), `${name}: loop ${e} starts and ends on its card's right edge`);
    } else {
      assert(near(p[1], layout.y[a] + layout.h[a]) && p[0] > layout.x[a] && p[0] < layout.x[a] + layout.w[a], `${name}: call ${e} leaves its caller's bottom`);
      assert(near(p[last + 1], layout.y[b]) && p[last] > layout.x[b] && p[last] < layout.x[b] + layout.w[b], `${name}: call ${e} enters its callee's top`);
    }
    let previous = '';
    for (let i = 0; i < p.length; i += 2) {
      ends.push(p[i], p[i + 1], e);
      if (!i) continue;
      const x0 = p[i - 2], y0 = p[i - 1], x1 = p[i], y1 = p[i + 1];
      if (near(x0, x1) && near(y0, y1)) continue;
      assert(near(x0, x1) || near(y0, y1), `${name}: call ${e} runs orthogonally (${x0},${y0} to ${x1},${y1})`);
      const direction = near(y0, y1) ? 'h' : 'v';
      if (previous && direction !== previous) bends += 1;
      previous = direction;
      if (direction === 'h') line(H, Math.round(y0 * 2), [Math.min(x0, x1), Math.max(x0, x1), e]);
      else line(V, Math.round(x0 * 2), [Math.min(y0, y1), Math.max(y0, y1), e]);
    }
  }
  const cell = 512, grid = new Map();
  for (let v = 0; v < count; v += 1) {
    for (let cx = Math.floor(layout.x[v] / cell); cx <= Math.floor((layout.x[v] + layout.w[v]) / cell); cx += 1)
      for (let cy = Math.floor(layout.y[v] / cell); cy <= Math.floor((layout.y[v] + layout.h[v]) / cell); cy += 1) line(grid, cx * 1048576 + cy, v);
  }
  const through = (e, x0, y0, x1, y1) => {
    for (let cx = Math.floor(x0 / cell); cx <= Math.floor(x1 / cell); cx += 1) for (let cy = Math.floor(y0 / cell); cy <= Math.floor(y1 / cell); cy += 1) {
      for (const v of grid.get(cx * 1048576 + cy) ?? []) {
        if (v === from[e] || v === to[e]) continue;
        assert(!(x1 > layout.x[v] && x0 < layout.x[v] + layout.w[v] && y1 > layout.y[v] && y0 < layout.y[v] + layout.h[v]), `${name}: call ${e} does not cross card ${v}`);
      }
    }
  };
  for (const [key, list] of H) for (const [x0, x1, e] of list) through(e, x0, key / 2, x1, key / 2);
  for (const [key, list] of V) for (const [y0, y1, e] of list) through(e, key / 2, y0, key / 2, y1);
  // Edges never share a line: no two runs of different calls overlap on one
  // line, and no bend or end of one lies inside another's run.
  for (const map of [H, V]) for (const list of map.values()) {
    list.sort((a, b) => a[0] - b[0]);
    let reach = -Infinity, owner = -1;
    for (const [lo, hi, e] of list) {
      assert(!(lo < reach - 0.5 && e !== owner), `${name}: call ${e} does not share a line with call ${owner}`);
      if (hi > reach) { reach = hi; owner = e; }
    }
  }
  const inside = (map, key, at, e) => {
    for (const k of [key - 1, key, key + 1]) for (const [lo, hi, other] of map.get(k) ?? []) {
      if (other !== e && at > lo + 0.5 && at < hi - 0.5) return other;
    }
    return -1;
  };
  for (let i = 0; i < ends.length; i += 3) {
    const x = ends[i], y = ends[i + 1], e = ends[i + 2];
    const other = Math.max(inside(H, Math.round(y * 2), x, e), inside(V, Math.round(x * 2), y, e));
    assert.equal(other, -1, `${name}: a bend or end of call ${e} at ${x},${y} is not on call ${other}`);
  }
  // A call inside its realm goes down a layer or more, unless it closes a cycle.
  for (let e = 0; e < edges; e += 1) {
    if (graph.lane[from[e]] !== graph.lane[to[e]] || layout.back[e]) continue;
    assert(layout.layer[to[e]] > layout.layer[from[e]] && layout.y[to[e]] > layout.y[from[e]] + layout.h[from[e]], `${name}: call ${e} runs down to a later layer`);
  }
  return {bendsPerEdge: edges ? bends / edges : 0, aspect: layout.width / layout.height};
}

const run = async (name, graph) => {
  const started = performance.now(), layout = await layOut(graph), ms = performance.now() - started;
  return {layout, ms, measures: verify(name, graph, layout)};
};

{
  // Nothing to draw, and the smallest drawings.
  const empty = await layOut({count: 0, lane: new Int32Array(0), weight: new Float64Array(0), from: new Int32Array(0), to: new Int32Array(0)});
  assert.equal(empty.x.length, 0);
  assert.equal(empty.lanes.length, 0);
  assert.equal(empty.routeStart.length, 1);
  const one = {count: 1, lane: Int32Array.from([3]), weight: new Float64Array(1), from: Int32Array.from([0]), to: Int32Array.from([0])};
  await run('one recursive card', one);
  const sizes = {count: 3, lane: Int32Array.from([0, 0, 1]), weight: new Float64Array(3), from: Int32Array.from([0, 1, 2]), to: Int32Array.from([1, 2, 0])};
  const {layout} = await run('cards without sizes', sizes);
  assert.equal(layout.w[0], engine.METRICS.nodeW, 'a card without a size takes the default width');
  console.log('PASS flow graph layout: an empty graph, one recursive card, cards without sizes');
}

{
  // The same input lays out the same drawing.
  const graph = callGraph(1500, 5, 7), a = await layOut(graph), b = await layOut(graph);
  for (const key of ['x', 'y', 'routes', 'routeTypes', 'routeStart', 'layer', 'back']) assert.deepEqual(a[key], b[key], `the ${key} of a layout repeats exactly`);
  assert.deepEqual(a.lanes, b.lanes, 'the bands of a layout repeat exactly');
  console.log('PASS flow graph layout: a layout repeats exactly');
}

{
  // Parallel chains with calls between them that pass many layers: with
  // every call kept straight the band is a staircase many layers wide, so
  // placement bends calls to hold it near its bound.
  const chains = 24, depth = 60, count = chains * depth, from = [], to = [];
  let state = 12345;
  const random = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return (state >>> 0) / 4294967296; };
  for (let c = 0; c < chains; c += 1) for (let d = 1; d < depth; d += 1) { from.push(c * depth + d - 1); to.push(c * depth + d); }
  for (let k = 0; k < count / 2; k += 1) {
    const d = Math.floor(random() * depth / 2), a = Math.floor(random() * chains) * depth + d, far = d + 2 + Math.floor(random() * depth / 2);
    const b = Math.floor(random() * chains) * depth + far;
    if (far < depth) { from.push(a); to.push(b); }
  }
  const graph = {count, lane: new Int32Array(count), weight: new Float64Array(count), from: Int32Array.from(from), to: Int32Array.from(to)};
  const {layout, measures} = await run('a staircase', graph);
  const straight = await engine.runAsync({graph, metrics: {...engine.METRICS, slack: 1e6}, engine: 'layered'});
  const band = layout.lanes[0], rigid = straight.lanes[0];
  assert(band.w < rigid.w / 2, `a staircase is held under half its straight width: ${Math.round(band.w)} against ${Math.round(rigid.w)}`);
  assert(measures.bendsPerEdge < 6, `a staircase's calls bend ${measures.bendsPerEdge.toFixed(2)} times each`);
  console.log(`PASS flow graph layout: a staircase is ${Math.round(band.w)} px wide, straight ${Math.round(rigid.w)}, ${measures.bendsPerEdge.toFixed(2)} bends per call`);
}

{
  // Seeded sessions up to 20,000 cards: every invariant, nothing capped, and
  // time that grows with the graph rather than with how far calls reach.
  const rows = [];
  for (const [cards, realms, seed] of [[60, 3, 1], [800, 6, 2], [5000, 12, 3], [20000, 24, 4]]) {
    const graph = callGraph(cards, realms, seed), {layout, ms, measures} = await run(`${cards} cards`, graph);
    const {stats} = layout;
    assert(stats.tracks > 0 && Number.isInteger(stats.crossings), `${cards} cards: the layout reports its tracks and crossings`);
    assert(measures.aspect > 0.25 && measures.aspect < 8, `${cards} cards: bands are packed toward a landscape drawing, ${measures.aspect.toFixed(2)}`);
    rows.push({cards, edges: graph.from.length, ms: Math.round(ms), aspect: +measures.aspect.toFixed(2), bends: +measures.bendsPerEdge.toFixed(2), crossings: stats.crossings, jogs: stats.jogs});
    if (cards === 20000) assert(ms < 60000, `20,000 cards lay out in under a minute: ${Math.round(ms)} ms`);
  }
  console.log(`PASS flow graph layout: seeded sessions, every call routed between cards on lines of its own ${JSON.stringify(rows)}`);
}

console.log('PASS flow graph layout engine (offline; rendered acceptance is the packaged-app gate)');
