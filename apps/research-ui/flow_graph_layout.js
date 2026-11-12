/* Vertical layout for the session flow graph. Runs off the main thread as a
 * Web Worker, and on the page where a shell cannot start one.
 *
 * The graph reads top to bottom like a disassembler's CFG: each realm is a
 * full-width band, and the bands are stacked in call order, so a realm that
 * calls or posts into another sits above it (an iframe below its parent) and a
 * call between realms runs down across the band boundary. Inside a band, rows
 * are call depth: cycles (recursion, re-entrant handlers) are broken by a
 * depth-first walk over the realm's own calls, nodes take their longest-path
 * layer, and a root is pulled down next to its first callee. A call into
 * another realm never pushes a card down, so every band starts at its own top.
 * An edge longer than one layer gets a waypoint in every layer it passes, so it
 * is routed between cards, never through one. Within a band and layer, cards
 * and waypoints are ordered by the mean position of their neighbours
 * (alternating down and up sweeps), then placed as near that mean as the
 * spacing allows (a weighted isotonic fit), which keeps a chain of calls one
 * straight vertical line. A band holds at most `wrap` cards per layer: the
 * rest move down a layer, leaves first, so a busy session grows tall, not
 * wide. Bands share one width and are shifted sideways so the calls between
 * them run as straight as the cards allow. Back edges run up the band's right
 * gutter; a call between bands drops straight down when nothing is in its way,
 * else it runs down the side gutter beside every band. Card sizes come from
 * the caller. No dependency is linked. */
'use strict';

const flowGraphLayout = (() => {
  const METRICS = {nodeW: 220, nodeH: 34, gapX: 30, gapY: 64, laneGap: 56, lanePadX: 22, lanePadTop: 52, lanePadBottom: 26,
    margin: 40, top: 0, wrap: 5, dummyW: 3, dummyGap: 12, busGap: 4, portGap: 18, gutter: 18, gutterStep: 7, gutterSlots: 6, crossSlots: 8, maxDummies: 200000};
  const SWEEPS = 9;
  /* Route point types: the segment that arrives at the point. A corner is
   * rounded toward the next point. */
  const MOVE = 0, CURVE = 1, LINE = 2, CORNER = 3;

  /** Out and in adjacency as compressed rows over edge indexes. */
  function adjacency(count, from, to) {
    const outStart = new Uint32Array(count + 1), inStart = new Uint32Array(count + 1);
    for (let e = 0; e < from.length; e += 1) { outStart[from[e] + 1] += 1; inStart[to[e] + 1] += 1; }
    for (let v = 0; v < count; v += 1) { outStart[v + 1] += outStart[v]; inStart[v + 1] += inStart[v]; }
    const outEdges = new Uint32Array(from.length), inEdges = new Uint32Array(from.length);
    const outFill = outStart.slice(0, count), inFill = inStart.slice(0, count);
    for (let e = 0; e < from.length; e += 1) { outEdges[outFill[from[e]]++] = e; inEdges[inFill[to[e]]++] = e; }
    return {outStart, outEdges, inStart, inEdges};
  }

  /** Marks the edges a depth-first walk finds closing a cycle, iteratively,
   * so a deep chain cannot overflow the stack. Roots go first, by weight. */
  function backEdges(count, from, to, adj, weight) {
    const back = new Uint8Array(from.length), color = new Uint8Array(count), cursor = new Uint32Array(count);
    const order = [...Array(count).keys()].sort((a, b) => {
      const ra = adj.inStart[a + 1] === adj.inStart[a], rb = adj.inStart[b + 1] === adj.inStart[b];
      return ra !== rb ? (ra ? -1 : 1) : (weight?.[b] ?? 0) - (weight?.[a] ?? 0) || a - b;
    });
    const stack = new Uint32Array(count);
    for (const start of order) {
      if (color[start]) continue;
      let depth = 0; stack[depth++] = start; color[start] = 1; cursor[start] = adj.outStart[start];
      while (depth) {
        const v = stack[depth - 1];
        if (cursor[v] < adj.outStart[v + 1]) {
          const e = adj.outEdges[cursor[v]++], w = to[e];
          if (w === v || color[w] === 1) back[e] = 1;
          else if (!color[w]) { color[w] = 1; cursor[w] = adj.outStart[w]; stack[depth++] = w; }
        } else { color[v] = 2; depth -= 1; }
      }
    }
    return back;
  }

  /** Longest-path layers over forward edges, then roots pulled down. */
  function layers(count, from, to, adj, back) {
    const layer = new Int32Array(count), indegree = new Uint32Array(count);
    for (let e = 0; e < from.length; e += 1) if (!back[e]) indegree[to[e]] += 1;
    const queue = new Uint32Array(count); let head = 0, tail = 0;
    for (let v = 0; v < count; v += 1) if (!indegree[v]) queue[tail++] = v;
    const topo = new Uint32Array(count);
    let seen = 0;
    while (head < tail) {
      const v = queue[head++]; topo[seen++] = v;
      for (let i = adj.outStart[v]; i < adj.outStart[v + 1]; i += 1) {
        const e = adj.outEdges[i]; if (back[e]) continue;
        const w = to[e]; if (layer[v] + 1 > layer[w]) layer[w] = layer[v] + 1;
        if (--indegree[w] === 0) queue[tail++] = w;
      }
    }
    // Reverse topological order: a root (or chain of roots) sits right above
    // its nearest callee.
    for (let i = seen - 1; i >= 0; i -= 1) {
      const v = topo[i];
      let hasIn = false;
      for (let k = adj.inStart[v]; k < adj.inStart[v + 1]; k += 1) if (!back[adj.inEdges[k]]) { hasIn = true; break; }
      if (hasIn) continue;
      let nearest = Infinity;
      for (let k = adj.outStart[v]; k < adj.outStart[v + 1]; k += 1) { const e = adj.outEdges[k]; if (!back[e]) nearest = Math.min(nearest, layer[to[e]]); }
      if (nearest !== Infinity && nearest - 1 > layer[v]) layer[v] = nearest - 1;
    }
    return layer;
  }

  /** At most `cap` cards of one band in a layer, more in a big band so it
   * stays near square: the excess moves down one layer, cards with the
   * fewest layers below them first (leaves cost nothing), and their callees
   * move with them. */
  function boundLayers(count, layer, laneOf, adj, to, back, weight, cap) {
    if (!(cap > 0)) return;
    const sizes = new Map();
    for (let v = 0; v < count; v += 1) sizes.set(laneOf[v], (sizes.get(laneOf[v]) ?? 0) + 1);
    const capOf = key => Math.max(cap, Math.min(cap * 2 + 2, Math.ceil(Math.sqrt(sizes.get(key) / 4))));
    const below = new Int32Array(count), order = [...Array(count).keys()].sort((a, b) => layer[b] - layer[a]);
    for (const v of order) for (let k = adj.outStart[v]; k < adj.outStart[v + 1]; k += 1) { const e = adj.outEdges[k]; if (!back[e]) below[v] = Math.max(below[v], below[to[e]] + 1); }
    const push = start => {
      const stack = [start];
      while (stack.length) {
        const v = stack.pop();
        for (let k = adj.outStart[v]; k < adj.outStart[v + 1]; k += 1) {
          const e = adj.outEdges[k]; if (back[e]) continue;
          const w = to[e]; if (layer[w] <= layer[v]) { layer[w] = layer[v] + 1; stack.push(w); }
        }
      }
    };
    // Nodes only ever move down, so one pass over the layers in order sees
    // every node at its final layer.
    let maxLayer = 0; for (let v = 0; v < count; v += 1) maxLayer = Math.max(maxLayer, layer[v]);
    for (let l = 0; l <= maxLayer; l += 1) {
      const byLane = new Map();
      for (let v = 0; v < count; v += 1) if (layer[v] === l) { if (!byLane.has(laneOf[v])) byLane.set(laneOf[v], []); byLane.get(laneOf[v]).push(v); }
      for (const [key, group] of byLane) {
        const room = capOf(key);
        if (group.length <= room) continue;
        group.sort((a, b) => below[b] - below[a] || (weight?.[b] ?? 0) - (weight?.[a] ?? 0) || a - b);
        for (const v of group.slice(room)) { layer[v] = l + 1; push(v); maxLayer = Math.max(maxLayer, l + 1 + below[v]); }
      }
    }
  }

  /** Bands top to bottom: realms that call into each other sit together,
   * callers above the realms they call or post into (an iframe below its
   * parent), the busiest connected group first, then shallower first. */
  function laneOrder(count, graph, from, to, back, layer) {
    const laneKeys = [...new Set(graph.lane)];
    const laneSum = new Map(), laneCount = new Map(), laneFirst = new Map(), laneWeight = new Map();
    for (let v = 0; v < count; v += 1) {
      const key = graph.lane[v];
      laneSum.set(key, (laneSum.get(key) ?? 0) + layer[v]); laneCount.set(key, (laneCount.get(key) ?? 0) + 1);
      laneWeight.set(key, (laneWeight.get(key) ?? 0) + (graph.weight?.[v] ?? 1));
      if (!laneFirst.has(key)) laneFirst.set(key, v);
    }
    const parent = new Map(laneKeys.map(key => [key, key]));
    const root = key => { while (parent.get(key) !== key) { parent.set(key, parent.get(parent.get(key))); key = parent.get(key); } return key; };
    const laneOut = new Map(laneKeys.map(key => [key, new Set()])), laneIn = new Map(laneKeys.map(key => [key, 0]));
    for (let e = 0; e < from.length; e += 1) {
      const a = graph.lane[from[e]], b = graph.lane[to[e]];
      if (a === b) continue;
      parent.set(root(a), root(b));
      if (!back[e] && !laneOut.get(a).has(b)) { laneOut.get(a).add(b); laneIn.set(b, laneIn.get(b) + 1); }
    }
    const groupWeight = new Map();
    for (const key of laneKeys) groupWeight.set(root(key), (groupWeight.get(root(key)) ?? 0) + laneWeight.get(key));
    const depth = key => laneSum.get(key) / laneCount.get(key);
    const rank = (a, b) => groupWeight.get(root(b)) - groupWeight.get(root(a)) || laneFirst.get(root(a)) - laneFirst.get(root(b)) || depth(a) - depth(b) || laneFirst.get(a) - laneFirst.get(b);
    const ready = laneKeys.filter(key => laneIn.get(key) === 0), ordered = [], placed = new Set();
    while (ordered.length < laneKeys.length) {
      if (!ready.length) {
        // A cycle between realms: take the best ranked remaining band.
        const rest = laneKeys.filter(key => !placed.has(key)).sort(rank);
        laneIn.set(rest[0], 0); ready.push(rest[0]);
      }
      ready.sort(rank);
      const next = ready.shift();
      if (placed.has(next)) continue;
      placed.add(next); ordered.push(next);
      for (const target of laneOut.get(next)) { laneIn.set(target, laneIn.get(target) - 1); if (laneIn.get(target) === 0) ready.push(target); }
    }
    return ordered;
  }

  /** Centres as near `desired` as the order and spacing allow: the weighted
   * least-squares fit of a nondecreasing sequence (pool adjacent violators). */
  function fitRow(items, desired, weight, width, gapOf) {
    const n = items.length, offset = new Float64Array(n), value = new Float64Array(n);
    for (let i = 1; i < n; i += 1) offset[i] = offset[i - 1] + (width[items[i - 1]] + width[items[i]]) / 2 + gapOf(items[i - 1], items[i]);
    const sum = new Float64Array(n), mass = new Float64Array(n), start = new Uint32Array(n);
    let top = -1;
    for (let i = 0; i < n; i += 1) {
      top += 1; sum[top] = (desired[i] - offset[i]) * weight[i]; mass[top] = weight[i]; start[top] = i;
      while (top > 0 && sum[top - 1] / mass[top - 1] > sum[top] / mass[top]) { sum[top - 1] += sum[top]; mass[top - 1] += mass[top]; top -= 1; }
    }
    for (let b = 0; b <= top; b += 1) {
      const end = b < top ? start[b + 1] : n, level = sum[b] / mass[b];
      for (let i = start[b]; i < end; i += 1) value[i] = level + offset[i];
    }
    return value;
  }

  /** Each band's sideways offset inside the shared width, so the calls between
   * bands run as straight as they can: first in band order against the bands
   * above, then a few passes against all of them. pairs: {a, ca, b, cb} with
   * band indexes and local centres. */
  function alignBands(widths, pairs) {
    const n = widths.length, offset = new Float64Array(n), placed = new Uint8Array(n);
    let shared = 0; for (const width of widths) shared = Math.max(shared, width);
    const byBand = Array.from({length: n}, () => []);
    pairs.forEach((pair, index) => { byBand[pair.a].push(index); if (pair.b !== pair.a) byBand[pair.b].push(index); });
    const want = (band, any) => {
      let sum = 0, mass = 0;
      for (const index of byBand[band]) {
        const pair = pairs[index], self = pair.a === band, other = self ? pair.b : pair.a;
        if (!any && !placed[other]) continue;
        sum += offset[other] + (self ? pair.cb - pair.ca : pair.ca - pair.cb); mass += 1;
      }
      return mass ? sum / mass : null;
    };
    const clamp = (band, value) => Math.max(0, Math.min(shared - widths[band], value));
    for (let band = 0; band < n; band += 1) { const value = want(band, false); offset[band] = value === null ? 0 : clamp(band, value); placed[band] = 1; }
    for (let pass = 0; pass < 3; pass += 1) for (let band = 0; band < n; band += 1) { const value = want(band, true); if (value !== null) offset[band] = clamp(band, value); }
    return offset;
  }

  /** A route through corner points: repeats and straight-through points are
   * dropped, the first point moves, the last is a line, the rest are
   * rounded corners. */
  function orthogonal(flat) {
    const points = [];
    for (let i = 0; i + 1 < flat.length; i += 2) {
      const x = flat[i], y = flat[i + 1], last = points.length - 2;
      if (last >= 0 && Math.abs(points[last] - x) < 0.01 && Math.abs(points[last + 1] - y) < 0.01) continue;
      if (last >= 2) {
        const ax = points[last - 2], ay = points[last - 1], bx = points[last], by = points[last + 1];
        if ((Math.abs(ax - bx) < 0.01 && Math.abs(bx - x) < 0.01) || (Math.abs(ay - by) < 0.01 && Math.abs(by - y) < 0.01)) points.length = last;
      }
      points.push(x, y);
    }
    const last = points.length / 2 - 1;
    return {points, types: Array.from({length: last + 1}, (_, k) => k === 0 ? MOVE : k === last ? LINE : CORNER)};
  }

  /**
   * Places band contents top to bottom and routes the calls between bands.
   * content: {bands: [{key, w, h, cards}], bandOf, lx, ly (local top-left),
   * routes (per edge {points, types} in band-local units, or null for a call
   * between bands), outPort, inPort (band-local x, NaN when unknown), offsets?}.
   */
  function stackBands(graph, nodeW, nodeH, content, m) {
    const {count, from, to} = graph, edgeCount = from.length, bands = content.bands.length, {bandOf, lx, ly} = content;
    const widths = content.bands.map(band => band.w);
    const cross = [];
    for (let e = 0; e < edgeCount; e += 1) if (bandOf[from[e]] !== bandOf[to[e]]) cross.push(e);
    const offsets = content.offsets ?? alignBands(widths, cross.map(e => ({a: bandOf[from[e]], ca: lx[from[e]] + nodeW[from[e]] / 2, b: bandOf[to[e]], cb: lx[to[e]] + nodeW[to[e]] / 2})));
    let shared = m.nodeW; for (const width of widths) shared = Math.max(shared, width);
    // Rows of bands, in a frame whose content starts at x = 0; shifted at the end.
    const top = new Float64Array(bands), contentTop = new Float64Array(bands), bottom = new Float64Array(bands), members = Array.from({length: bands}, () => []);
    let cursor = m.margin + m.top;
    content.bands.forEach((band, index) => {
      top[index] = cursor; contentTop[index] = cursor + m.lanePadTop; bottom[index] = contentTop[index] + band.h + m.lanePadBottom;
      cursor = bottom[index] + m.laneGap;
    });
    const x = new Float32Array(count), y = new Float32Array(count);
    for (let v = 0; v < count; v += 1) { const band = bandOf[v]; x[v] = offsets[band] + lx[v]; y[v] = contentTop[band] + ly[v]; members[band].push(v); }
    const routes = new Array(edgeCount).fill(null);
    for (let e = 0; e < edgeCount; e += 1) {
      const local = content.routes[e];
      if (!local) continue;
      const band = bandOf[from[e]], dx = offsets[band], dy = contentTop[band], points = local.points.slice();
      for (let i = 0; i < points.length; i += 2) { points[i] += dx; points[i + 1] += dy; }
      routes[e] = {points, types: local.types.slice()};
    }
    // Ports of calls between bands: the content's, else spread over the card
    // in the order of where the other end is.
    const outX = new Float64Array(edgeCount).fill(NaN), inX = new Float64Array(edgeCount).fill(NaN);
    {
      const outs = new Map(), ins = new Map(), otherX = v => x[v] + nodeW[v] / 2;
      for (const e of cross) {
        const a = from[e], b = to[e];
        if (Number.isFinite(content.outPort?.[e])) outX[e] = offsets[bandOf[a]] + content.outPort[e]; else { if (!outs.has(a)) outs.set(a, []); outs.get(a).push(e); }
        if (Number.isFinite(content.inPort?.[e])) inX[e] = offsets[bandOf[b]] + content.inPort[e]; else { if (!ins.has(b)) ins.set(b, []); ins.get(b).push(e); }
      }
      const spread = (v, list, key, target) => {
        list.sort((p, q) => key(p) - key(q) || p - q);
        const step = list.length > 1 ? Math.min(m.portGap, nodeW[v] * 0.5 / (list.length - 1)) : 0, mid = x[v] + nodeW[v] / 2;
        list.forEach((e, i) => { target[e] = mid + (i - (list.length - 1) / 2) * step; });
      };
      outs.forEach((list, v) => spread(v, list, e => otherX(to[e]), outX));
      ins.forEach((list, v) => spread(v, list, e => otherX(from[e]), inX));
    }
    // Nothing of a card in [y0, y1] at x, other than the edge's own ends.
    const clearColumn = (cx, y0, y1, a, b) => {
      const low = Math.min(y0, y1), high = Math.max(y0, y1);
      for (let band = 0; band < bands; band += 1) {
        if (bottom[band] < low || top[band] > high) continue;
        for (const v of members[band]) {
          if (v === a || v === b) continue;
          if (cx > x[v] - 4 && cx < x[v] + nodeW[v] + 4 && high > y[v] - 2 && low < y[v] + nodeH[v] + 2) return false;
        }
      }
      return true;
    };
    // A height in the gap under (or over) a card's row that a run across
    // [x0, x1] can take without touching a card of its band.
    const rowGap = (band, v, down, x0, x1, slot) => {
      let at = down ? y[v] + nodeH[v] + 14 + slot * 3 : y[v] - 14 - slot * 3;
      const low = Math.min(x0, x1) - 6, high = Math.max(x0, x1) + 6;
      for (let guard = 0; guard < 32; guard += 1) {
        let moved = false;
        for (const u of members[band]) {
          if (u === v || high <= x[u] || low >= x[u] + nodeW[u] || at <= y[u] - 8 || at >= y[u] + nodeH[u] + 8) continue;
          at = down ? y[u] + nodeH[u] + 14 : y[u] - 14; moved = true;
        }
        if (!moved) break;
      }
      return down ? Math.min(at, bottom[band] + m.laneGap / 2 - 4) : Math.max(at, top[band] - m.laneGap / 2 + 4);
    };
    // Calls between bands. Down: straight from the caller to the gap over the
    // callee's band and into it when no card is in the way; else along the gap
    // under the caller's row, down the nearer side gutter beside every band,
    // and into the callee from the gap over its band or over its row. Up (a
    // back edge): the same, always by the right gutter.
    const gapSlot = new Uint32Array(bands + 1), sideSlot = [0, 0], sideUsed = [0, 0];
    const gutterX = (side, slot) => side === 0 ? -(m.gutter * 0.75 + slot * m.gutterStep) : shared + m.gutter * 0.75 + slot * m.gutterStep;
    for (const e of cross) {
      const a = from[e], b = to[e], A = bandOf[a], B = bandOf[b];
      const sx = outX[e], sy = y[a] + nodeH[a], tx = inX[e], ty = y[b];
      const above = B > 0 ? top[B] - m.laneGap / 2 + ((gapSlot[B]++ % 7) - 3) * 4 : top[B] - 12;
      if (B > A && clearColumn(sx, sy, above, a, b) && clearColumn(tx, above, ty, a, b)) {
        routes[e] = orthogonal([sx, sy, sx, above, tx, above, tx, ty]);
        continue;
      }
      const side = B > A && (sx + tx) / 2 < shared / 2 ? 0 : 1, slot = sideSlot[side]++ % m.crossSlots;
      sideUsed[side] = Math.max(sideUsed[side], slot + 1);
      const gx = gutterX(side, slot);
      const under = bottom[A] + m.laneGap / 2 + ((gapSlot[A + 1]++ % 7) - 3) * 4;
      const y1 = clearColumn(sx, sy, under, a, b) ? under : rowGap(A, a, true, sx, gx, slot % 6);
      const y2 = clearColumn(tx, above, ty, a, b) ? above : rowGap(B, b, false, tx, gx, slot % 6);
      routes[e] = orthogonal([sx, sy, sx, y1, gx, y1, gx, y2, tx, y2, tx, ty]);
    }
    // Shift right of the left gutter, then the boxes.
    const leftW = sideUsed[0] ? m.gutter * 1.5 + (sideUsed[0] - 1) * m.gutterStep : 0, rightW = sideUsed[1] ? m.gutter * 1.5 + (sideUsed[1] - 1) * m.gutterStep : 0;
    const shift = m.margin + m.lanePadX + leftW;
    for (let v = 0; v < count; v += 1) x[v] += shift;
    const points = [], kinds = [], routeStart = new Uint32Array(edgeCount + 1);
    for (let e = 0; e < edgeCount; e += 1) {
      routeStart[e] = kinds.length;
      const route = routes[e];
      for (let i = 0; i < route.points.length; i += 2) points.push(route.points[i] + shift, route.points[i + 1]);
      kinds.push(...route.types);
    }
    routeStart[edgeCount] = kinds.length;
    const laneW = m.lanePadX * 2 + leftW + shared + rightW;
    const lanes = content.bands.map((band, index) => {
      const box = {key: band.key, x: m.margin, y: top[index], w: laneW, h: bottom[index] - top[index], gutter: shift + offsets[index] + band.cards + m.lanePadX / 2, top: contentTop[index]};
      if (band.engine) { box.engine = band.engine; box.reason = band.reason; }
      return box;
    });
    let height = (bands ? bottom[bands - 1] : m.margin + m.lanePadTop) + m.margin;
    for (let i = 1; i < points.length; i += 2) height = Math.max(height, points[i] + m.margin);
    return {x, y, lanes, width: m.margin * 2 + laneW, height, routes: Float32Array.from(points), routeTypes: Uint8Array.from(kinds), routeStart};
  }

  /**
   * graph: {count, lane: Int32Array (lane key per node), from, to, weight?, w?, h?}
   * Returns node boxes (top-left, with per-node w and h), band boxes in
   * order, which edges were treated as back edges, and one route per edge.
   */
  function layoutGraph(graph, metrics = METRICS) {
    const m = {...METRICS, ...metrics};
    const {count, from, to} = graph;
    const edgeCount = from.length;
    const nodeW = Float32Array.from({length: count}, (_, v) => graph.w?.[v] ?? m.nodeW);
    const nodeH = Float32Array.from({length: count}, (_, v) => graph.h?.[v] ?? m.nodeH);
    // Layers come from the calls inside each realm.
    const intra = [];
    for (let e = 0; e < edgeCount; e += 1) if (graph.lane[from[e]] === graph.lane[to[e]]) intra.push(e);
    const innerFrom = Int32Array.from(intra, e => from[e]), innerTo = Int32Array.from(intra, e => to[e]);
    const adj = adjacency(count, innerFrom, innerTo);
    const innerBack = backEdges(count, innerFrom, innerTo, adj, graph.weight);
    const layer = layers(count, innerFrom, innerTo, adj, innerBack);
    boundLayers(count, layer, graph.lane, adj, innerTo, innerBack, graph.weight, m.wrap);
    const back = new Uint8Array(edgeCount);
    intra.forEach((e, i) => { back[e] = innerBack[i]; });
    const laneKeys = laneOrder(count, graph, from, to, back, layer);
    const laneIndex = new Map(laneKeys.map((key, index) => [key, index]));
    const bands = laneKeys.length;
    const bandOf = Int32Array.from({length: count}, (_, v) => laneIndex.get(graph.lane[v]));
    // A call into a band drawn above its caller runs back up.
    for (let e = 0; e < edgeCount; e += 1) if (bandOf[from[e]] !== bandOf[to[e]]) back[e] = bandOf[to[e]] < bandOf[from[e]] ? 1 : 0;
    const maxLayerOf = new Int32Array(bands);
    for (let v = 0; v < count; v += 1) maxLayerOf[bandOf[v]] = Math.max(maxLayerOf[bandOf[v]], layer[v]);
    let maxLayer = 0; for (const value of maxLayerOf) maxLayer = Math.max(maxLayer, value);

    // Items: cards 0..count-1, then one waypoint per layer a long edge passes.
    const itemBand = [], itemLayer = [];
    for (let v = 0; v < count; v += 1) { itemBand.push(bandOf[v]); itemLayer.push(layer[v]); }
    const firstDummy = new Int32Array(edgeCount).fill(-1), dummyCount = new Uint32Array(edgeCount);
    const links = [];
    let budget = m.maxDummies;
    for (let e = 0; e < edgeCount; e += 1) {
      const a = from[e], b = to[e];
      // A card in another band pulls sideways, the upper end first.
      if (bandOf[a] !== bandOf[b]) { if (bandOf[a] < bandOf[b]) links.push(a, b); else links.push(b, a); continue; }
      if (back[e]) continue;
      const span = layer[b] - layer[a];
      if (span > 1 && span - 1 <= budget) {
        budget -= span - 1; firstDummy[e] = itemBand.length; dummyCount[e] = span - 1;
        let previous = a;
        for (let l = layer[a] + 1; l < layer[b]; l += 1) {
          const id = itemBand.length;
          itemBand.push(itemBand[a]); itemLayer.push(l);
          links.push(previous, id); previous = id;
        }
        links.push(previous, b);
      } else links.push(a, b);
    }
    const items = itemBand.length, isDummy = id => id >= count;
    const width = new Float64Array(items), height = new Float64Array(items);
    for (let id = 0; id < items; id += 1) { width[id] = isDummy(id) ? m.dummyW : nodeW[id]; height[id] = isDummy(id) ? 0 : nodeH[id]; }
    // Neighbours above and below each item.
    const upStart = new Uint32Array(items + 1), downStart = new Uint32Array(items + 1);
    for (let k = 0; k < links.length; k += 2) { downStart[links[k] + 1] += 1; upStart[links[k + 1] + 1] += 1; }
    for (let id = 0; id < items; id += 1) { upStart[id + 1] += upStart[id]; downStart[id + 1] += downStart[id]; }
    const upList = new Uint32Array(links.length / 2), downList = new Uint32Array(links.length / 2);
    { const upFill = upStart.slice(0, items), downFill = downStart.slice(0, items);
      for (let k = 0; k < links.length; k += 2) { downList[downFill[links[k]]++] = links[k + 1]; upList[upFill[links[k + 1]]++] = links[k]; } }

    // Cells, first in depth-first discovery order from the heaviest roots.
    const discovery = new Int32Array(items).fill(-1);
    { let next = 0; const stack = [];
      const roots = [];
      for (let id = 0; id < items; id += 1) if (upStart[id + 1] === upStart[id]) roots.push(id);
      roots.sort((a, b) => (graph.weight?.[b] ?? 0) - (graph.weight?.[a] ?? 0) || a - b);
      const visit = start => {
        if (discovery[start] >= 0) return;
        stack.push(start);
        while (stack.length) {
          const id = stack.pop();
          if (discovery[id] >= 0) continue;
          discovery[id] = next++;
          for (let k = downStart[id + 1]; k > downStart[id]; k -= 1) if (discovery[downList[k - 1]] < 0) stack.push(downList[k - 1]);
        }
      };
      roots.forEach(visit);
      for (let id = 0; id < items; id += 1) visit(id);
    }
    const cells = Array.from({length: bands}, (_, band) => Array.from({length: maxLayerOf[band] + 1}, () => []));
    for (let id = 0; id < items; id += 1) cells[itemBand[id]][itemLayer[id]].push(id);
    cells.forEach(bandCells => bandCells.forEach(cell => cell.sort((a, b) => discovery[a] - discovery[b])));

    // Rows of each band, from the band's own top.
    const layerH = cells.map(bandCells => new Float64Array(bandCells.length)), layerTop = cells.map(bandCells => new Float64Array(bandCells.length + 1));
    for (let v = 0; v < count; v += 1) layerH[bandOf[v]][layer[v]] = Math.max(layerH[bandOf[v]][layer[v]], height[v]);
    for (let band = 0; band < bands; band += 1) for (let l = 0; l < cells[band].length; l += 1) layerTop[band][l + 1] = layerTop[band][l] + layerH[band][l] + m.gapY;

    // Horizontal placement: centres local to each band, bands shifted to line
    // up the calls between them.
    const local = new Float64Array(items), bandX = new Float64Array(bands), bandW = new Float64Array(bands);
    const gutterOf = new Float64Array(bands), backIn = new Uint32Array(bands);
    for (let e = 0; e < edgeCount; e += 1) if (back[e] && from[e] !== to[e] && bandOf[from[e]] === bandOf[to[e]]) backIn[bandOf[from[e]]] += 1;
    for (let band = 0; band < bands; band += 1) gutterOf[band] = backIn[band] ? m.lanePadX / 2 + m.gutter + Math.min(backIn[band], m.gutterSlots) * m.gutterStep : 0;
    const crossEdges = [];
    for (let e = 0; e < edgeCount; e += 1) if (bandOf[from[e]] !== bandOf[to[e]]) crossEdges.push(e);
    // Waypoints of a bundle of long edges run close together, like a bus.
    const gapOf = (a, b) => isDummy(a) && isDummy(b) ? m.busGap : isDummy(a) || isDummy(b) ? m.dummyGap : m.gapX;
    const center = id => bandX[itemBand[id]] + local[id];
    const placeBands = () => {
      for (let band = 0; band < bands; band += 1) {
        let left = Infinity, right = -Infinity;
        for (const cell of cells[band]) for (const id of cell) { left = Math.min(left, local[id] - width[id] / 2); right = Math.max(right, local[id] + width[id] / 2); }
        if (left === Infinity) { left = 0; right = 0; }
        for (const cell of cells[band]) for (const id of cell) local[id] -= left;
        bandW[band] = right - left;
      }
      const offsets = alignBands(Array.from(bandW, (value, band) => value + gutterOf[band]),
        crossEdges.map(e => ({a: bandOf[from[e]], ca: local[from[e]], b: bandOf[to[e]], cb: local[to[e]]})));
      bandX.set(offsets);
    };
    const placeCell = (band, l, desired, weight) => {
      const cell = cells[band][l];
      if (!cell.length) return;
      const fitted = fitRow(cell, desired, weight, width, gapOf);
      cell.forEach((id, i) => { local[id] = fitted[i] - bandX[band]; });
    };
    // Start packed left to right.
    cells.forEach(bandCells => bandCells.forEach(cell => { let at = 0; cell.forEach((id, i) => { if (i) at += (width[cell[i - 1]] + width[id]) / 2 + gapOf(cell[i - 1], id); local[id] = at; }); }));
    placeBands();
    const sweep = (down, both = false) => {
      for (let step = 0; step <= maxLayer; step += 1) {
        for (let band = 0; band < bands; band += 1) {
          const l = down ? step : maxLayerOf[band] - step;
          if (l < 0 || l > maxLayerOf[band]) continue;
          const cell = cells[band][l];
          if (!cell.length) continue;
          const desired = new Float64Array(cell.length), weight = new Float64Array(cell.length), keyed = new Array(cell.length);
          const left = bandX[band], right = bandX[band] + bandW[band];
          cell.forEach((id, i) => {
            let sum = 0, n = 0;
            // A neighbour in another band pulls toward the nearer edge of
            // this one, never past it: otherwise two bands chase each other
            // apart.
            const add = (startArr, list) => {
              for (let k = startArr[id]; k < startArr[id + 1]; k += 1) {
                const other = list[k];
                if (itemBand[other] === band) { sum += center(other); n += 1; } else { sum += 0.35 * Math.max(left, Math.min(right, center(other))); n += 0.35; }
              }
            };
            if (down || both) add(upStart, upList);
            if (!down || both) add(downStart, downList);
            const at = center(id);
            desired[i] = n ? sum / n : at;
            weight[i] = n ? (isDummy(id) ? 3 : 1) * Math.min(1, n) : 0.05;
            keyed[i] = i;
          });
          // A card with no neighbour this way packs beside the ones that
          // have one, instead of holding the band open.
          let connected = 0, mass = 0;
          for (let i = 0; i < cell.length; i += 1) if (weight[i] > 0.05) { connected += desired[i]; mass += 1; }
          if (mass) for (let i = 0; i < cell.length; i += 1) if (weight[i] <= 0.05) desired[i] = connected / mass;
          keyed.sort((a, b) => desired[a] - desired[b] || discovery[cell[a]] - discovery[cell[b]]);
          const sorted = keyed.map(i => cell[i]), sortedDesired = Float64Array.from(keyed, i => desired[i]), sortedWeight = Float64Array.from(keyed, i => weight[i]);
          cells[band][l] = sorted;
          placeCell(band, l, sortedDesired, sortedWeight);
        }
      }
      placeBands();
    };
    for (let pass = 0; pass < SWEEPS; pass += 1) sweep(pass % 2 === 0);
    // A last down sweep keeps single calls straight under their caller.
    sweep(true);

    // Band-local boxes.
    const lx = new Float64Array(count), ly = new Float64Array(count);
    for (let v = 0; v < count; v += 1) { lx[v] = local[v] - width[v] / 2; ly[v] = layerTop[bandOf[v]][layer[v]]; }
    const lc = id => local[id];

    // Ports: a card's edges leave its bottom and enter its top in the order of
    // where they go, so bundles do not cross at the card. Back edges take the
    // right end, toward the gutter they run up.
    const outPort = new Float64Array(edgeCount), inPort = new Float64Array(edgeCount);
    const nextX = e => firstDummy[e] >= 0 ? center(firstDummy[e]) : center(to[e]);
    const previousX = e => firstDummy[e] >= 0 ? center(firstDummy[e] + dummyCount[e] - 1) : center(from[e]);
    const spread = (v, list, key, target) => {
      if (!list.length) return;
      list.sort((a, b) => key(a) - key(b) || a - b);
      const step = list.length > 1 ? Math.min(m.portGap, nodeW[v] * 0.6 / (list.length - 1)) : 0, mid = lc(v);
      list.forEach((e, i) => { target[e] = mid + (i - (list.length - 1) / 2) * step; });
    };
    {
      const outs = Array.from({length: count}, () => []), ins = Array.from({length: count}, () => []);
      for (let e = 0; e < edgeCount; e += 1) { if (from[e] === to[e]) continue; outs[from[e]].push(e); ins[to[e]].push(e); }
      // A self call has its own loop on the card's right edge.
      for (let v = 0; v < count; v += 1) {
        spread(v, outs[v], e => back[e] && bandOf[to[e]] === bandOf[v] ? Infinity : nextX(e), outPort);
        spread(v, ins[v], e => back[e] && bandOf[from[e]] === bandOf[v] ? Infinity : previousX(e), inPort);
      }
    }

    // Routes inside each band, in band-local units.
    const routes = new Array(edgeCount).fill(null), bandSlot = new Uint32Array(bands);
    for (let e = 0; e < edgeCount; e += 1) {
      const a = from[e], b = to[e], band = bandOf[a];
      if (band !== bandOf[b]) continue;
      const points = [], types = [], push = (px, py, type) => { points.push(px, py); types.push(type); };
      const sx = outPort[e], sy = ly[a] + nodeH[a], rows = layerTop[band], heights = layerH[band];
      if (a === b) {
        // Recursion: out of the right edge low, up through the gap beside
        // the card and back in at its right edge under the header.
        const right = lx[a] + nodeW[a], loop = Math.min(m.gapX * 0.66, 20), low = ly[a] + Math.max(30, nodeH[a] - 14);
        push(right, low, MOVE); push(right + loop, low, CORNER); push(right + loop, ly[a] + 15, CORNER); push(right, ly[a] + 15, LINE);
      } else if (back[e]) {
        // Down out of the source, along the gap under its layer, up the
        // band's gutter, along the gap over the target's layer and down in.
        const slot = bandSlot[band]++ % m.gutterSlots;
        const gx = bandW[band] + m.lanePadX / 2 + m.gutter / 2 + slot * m.gutterStep;
        const below = rows[layer[a]] + heights[layer[a]] + m.gapY * 0.3 + slot * 3, above = ly[b] - m.gapY * 0.3 - slot * 3;
        push(sx, sy, MOVE); push(sx, below, CORNER); push(gx, below, CORNER); push(gx, above, CORNER); push(inPort[e], above, CORNER); push(inPort[e], ly[b], LINE);
      } else {
        // Straight down to the bottom of the caller's row first, so the bend
        // into the next row is in the gap, clear of a taller card beside it.
        const rowBottom = rows[layer[a]] + heights[layer[a]];
        push(sx, sy, MOVE);
        if (rowBottom > sy + 0.5) push(sx, rowBottom, LINE);
        for (let d = 0; d < dummyCount[e]; d += 1) {
          const id = firstDummy[e] + d, l = itemLayer[id], dx = lc(id);
          push(dx, rows[l], CURVE); push(dx, rows[l] + heights[l], LINE);
        }
        push(inPort[e], ly[b], CURVE);
      }
      routes[e] = {points, types};
    }
    // A back edge into a first-row card runs over it through the band's top
    // pad, which the band already has.
    const contentBands = laneKeys.map((key, band) => {
      const rowsTop = layerTop[band], last = cells[band].length - 1;
      return {key, w: bandW[band] + gutterOf[band], h: last >= 0 ? rowsTop[last] + layerH[band][last] : 0, cards: bandW[band]};
    });
    const content = {bands: contentBands, bandOf, lx, ly, routes, outPort: crossPorts(outPort, crossEdges, edgeCount), inPort: crossPorts(inPort, crossEdges, edgeCount), offsets: Float64Array.from(bandX)};
    const stacked = stackBands(graph, nodeW, nodeH, content, m);
    return {...stacked, w: nodeW, h: nodeH, layer, back, top: m.margin, waypoints: items - count, content};
  }
  /** Ports of calls between bands only; the rest are in their routes. */
  function crossPorts(ports, crossEdges, edgeCount) {
    const out = new Float64Array(edgeCount).fill(NaN);
    for (const e of crossEdges) out[e] = ports[e];
    return out;
  }

  /* Triskel (graph-layout-v1, POST /api/graph-layout) lays out each realm
   * that fits its limits, the way a CFG tool lays out a function. A realm
   * Triskel would draw much wider than the layered layout above (a wide fan
   * of calls, which Triskel does not stack) keeps the layered one; so does
   * every realm when the route is missing or fails. Bands keep the layered
   * layout's order, so the page still sits above the frames it calls into,
   * and calls between bands are routed the same way for either engine. */
  const TRISKEL = {maxNodes: 2000, maxEdges: 8000, maxTotal: 8000, widen: 1.6, freeWidth: 1400, freeHeight: 1600};

  /** Waypoints as a route: corners rounded, repeats and straight-through
   * points dropped. */
  function waypointRoute(flat, dx, dy) {
    const points = [];
    for (let i = 0; i + 1 < flat.length; i += 2) {
      const x = flat[i] + dx, y = flat[i + 1] + dy, last = points.length - 2;
      if (last >= 0 && Math.abs(points[last] - x) < 0.01 && Math.abs(points[last + 1] - y) < 0.01) continue;
      if (last >= 2) {
        const ax = points[last - 2], ay = points[last - 1], bx = points[last], by = points[last + 1];
        if ((Math.abs(ax - bx) < 0.01 && Math.abs(bx - x) < 0.01) || (Math.abs(ay - by) < 0.01 && Math.abs(by - y) < 0.01)) { points.length = last; }
      }
      points.push(x, y);
    }
    return points;
  }

  /** The request body for the realms worth sending, and how to read it back. */
  function triskelRequest(graph, local) {
    const {count, from, to} = graph, laneOf = new Map(local.lanes.map((lane, index) => [lane.key, index]));
    const members = local.lanes.map(() => []), localIndex = new Int32Array(count);
    for (let v = 0; v < count; v += 1) { const lane = laneOf.get(graph.lane[v]); localIndex[v] = members[lane].length; members[lane].push(v); }
    const inner = local.lanes.map(() => []);
    for (let e = 0; e < from.length; e += 1) { const a = laneOf.get(graph.lane[from[e]]); if (a === laneOf.get(graph.lane[to[e]])) inner[a].push(e); }
    const sent = [], graphs = [];
    let total = 0;
    local.lanes.forEach((lane, index) => {
      const nodes = members[index].length;
      if (nodes < 2 || nodes > TRISKEL.maxNodes || inner[index].length > TRISKEL.maxEdges || total + nodes > TRISKEL.maxTotal) return;
      total += nodes; sent.push(index);
      graphs.push({nodes: members[index].map(v => [Math.round(local.w[v] * 100) / 100, Math.round(local.h[v] * 100) / 100]), edges: inner[index].map(e => [localIndex[from[e]], localIndex[to[e]]])});
    });
    return {sent, graphs, members, inner, localIndex};
  }

  /** Places each band from Triskel's answer or the layered layout, stacks
   * the bands top to bottom and routes the calls between them. */
  function assemble(graph, local, plan, answer, metrics) {
    const m = {...METRICS, ...metrics};
    const {from, to} = graph, edgeCount = from.length, lanes = local.lanes.length;
    const engines = local.lanes.map(() => ({engine: 'layered', reason: 'one card'}));
    const results = local.lanes.map(() => null);
    plan.sent.forEach((lane, position) => {
      const result = answer?.graphs?.[position], members = plan.members[lane];
      const band = local.content.bands[lane], layeredW = band.w, layeredH = band.h;
      if (!result) { engines[lane] = {engine: 'layered', reason: 'Triskel gave no answer'}; return; }
      if (result.status !== 'laid_out') { engines[lane] = {engine: 'layered', reason: result.status === 'too_large' ? 'over Triskel’s size limit' : `Triskel ${result.status}${result.reason ? `: ${result.reason}` : ''}`}; return; }
      const ok = Array.isArray(result.nodes) && result.nodes.length === members.length && Array.isArray(result.edges) && result.edges.length === plan.inner[lane].length
        && result.nodes.every(point => Number.isFinite(point?.[0]) && Number.isFinite(point?.[1])) && result.edges.every(list => Array.isArray(list) && list.length >= 4 && list.every(Number.isFinite));
      if (!ok) { engines[lane] = {engine: 'layered', reason: 'Triskel answer did not match the realm'}; return; }
      if (result.width > Math.max(layeredW * TRISKEL.widen, TRISKEL.freeWidth)) { engines[lane] = {engine: 'layered', reason: `Triskel would draw it ${(result.width / Math.max(1, layeredW)).toFixed(1)}× wider`}; return; }
      // Triskel stacks loop bodies, so a realm full of back edges can come
      // out far taller than it is wide; that, too, keeps the layered layout.
      if (result.height > Math.max(layeredH * TRISKEL.widen, layeredH + TRISKEL.freeHeight)) { engines[lane] = {engine: 'layered', reason: `Triskel would draw it ${(result.height / Math.max(1, layeredH)).toFixed(1)}× taller`}; return; }
      engines[lane] = {engine: 'triskel'};
      results[lane] = result;
    });
    plan.members.forEach((members, lane) => { if (members.length >= 2 && !plan.sent.includes(lane) && engines[lane].reason === 'one card') engines[lane] = {engine: 'layered', reason: 'over Triskel’s size limit'}; });
    // A Triskel band replaces its content: card positions, routes inside it
    // and its size. Calls out of or into it get fresh ports.
    const base = local.content, lx = Float64Array.from(base.lx), ly = Float64Array.from(base.ly), routes = base.routes.slice();
    const outPort = Float64Array.from(base.outPort), inPort = Float64Array.from(base.inPort);
    const bands = base.bands.map((band, index) => ({...band, engine: engines[index].engine, reason: engines[index].reason}));
    for (let lane = 0; lane < lanes; lane += 1) {
      const result = results[lane];
      if (!result) continue;
      const members = plan.members[lane];
      let minX = 0;
      for (const list of result.edges) for (let i = 0; i < list.length; i += 2) minX = Math.min(minX, list[i]);
      for (const point of result.nodes) minX = Math.min(minX, point[0]);
      // Everything of the band from x = 0, its routes included.
      const shift = -minX;
      let right = result.width + shift, cards = 0, bottom = result.height;
      members.forEach((v, i) => { lx[v] = shift + result.nodes[i][0]; ly[v] = result.nodes[i][1]; cards = Math.max(cards, lx[v] + local.w[v]); bottom = Math.max(bottom, ly[v] + local.h[v]); });
      plan.inner[lane].forEach((e, i) => {
        if (from[e] === to[e]) {
          // Recursion: a tight loop on the card's right edge, not
          // Triskel's loop around the whole row.
          const v = from[e], edge = lx[v] + local.w[v], low = ly[v] + Math.max(30, local.h[v] - 14);
          routes[e] = {points: [edge, low, edge + 16, low, edge + 16, ly[v] + 15, edge, ly[v] + 15], types: [MOVE, CORNER, CORNER, LINE]};
          right = Math.max(right, edge + 16);
          return;
        }
        const points = waypointRoute(result.edges[i], shift, 0), last = points.length / 2 - 1;
        for (let k = 0; k < points.length; k += 2) { right = Math.max(right, points[k]); bottom = Math.max(bottom, points[k + 1]); }
        routes[e] = {points, types: Array.from({length: last + 1}, (_, k) => k === 0 ? MOVE : k === last ? LINE : CORNER)};
      });
      bands[lane] = {...bands[lane], w: Math.max(right, cards), h: bottom, cards};
      for (let e = 0; e < edgeCount; e += 1) {
        if (base.bandOf[from[e]] === base.bandOf[to[e]]) continue;
        if (base.bandOf[from[e]] === lane) outPort[e] = NaN;
        if (base.bandOf[to[e]] === lane) inPort[e] = NaN;
      }
    }
    const content = {bands, bandOf: base.bandOf, lx, ly, routes, outPort, inPort, offsets: results.some(Boolean) ? undefined : base.offsets};
    const stacked = stackBands(graph, local.w, local.h, content, m);
    const laid = engines.filter(item => item.engine === 'triskel').length;
    const {content: unused, ...rest} = local;
    return {...rest, ...stacked,
      engine: {name: laid ? 'triskel' : 'layered', revision: answer?.engine?.revision ?? null, triskel: laid, realms: engines.map((item, index) => ({key: local.lanes[index].key, ...item}))}};
  }

  /** Layered layout, then Triskel for the realms it can take. `request`
   * posts a graph-layout-v1 body and resolves to the parsed answer. */
  async function layoutWithTriskel(graph, metrics, request) {
    const local = layoutGraph(graph, metrics);
    const plan = triskelRequest(graph, local);
    if (!plan.graphs.length) return assemble(graph, local, plan, null, metrics);
    let answer = null, failure = '';
    try {
      answer = await request({graphs: plan.graphs});
      if (answer?.schema !== 'graph-layout-v1' || !Array.isArray(answer.graphs) || answer.graphs.length !== plan.graphs.length) { failure = 'The layout route returned an unexpected answer.'; answer = null; }
    } catch (error) { failure = error?.message ?? 'The layout route failed.'; }
    const layout = assemble(graph, local, plan, answer, metrics);
    if (failure) { layout.engine.failure = failure; layout.engine.realms.forEach(item => { if (item.engine === 'layered' && item.reason !== 'one card') item.reason = 'the layout route was unavailable'; }); }
    return layout;
  }

  /** The browser's request for the Triskel route, bounded in time. */
  const fetchTriskel = async body => {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch('/api/graph-layout', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body), signal: controller.signal, cache: 'no-store'});
      if (!response.ok) throw Error(`The layout route returned ${response.status}.`);
      return await response.json();
    } finally { clearTimeout(timer); }
  };

  /** The layered layout alone, with the same engine report as when Triskel
   * takes part. */
  function run(message) {
    const graph = message.graph, metrics = message.metrics ?? METRICS, local = layoutGraph(graph, metrics);
    const layout = assemble(graph, local, {...triskelRequest(graph, local), sent: []}, null, metrics);
    layout.engine.realms.forEach(item => { if (item.reason !== 'one card') item.reason = 'the layout route is not served here'; });
    return layout;
  }
  async function runAsync(message) {
    if (message.engine === 'triskel' && typeof fetch === 'function') return layoutWithTriskel(message.graph, message.metrics ?? METRICS, fetchTriskel);
    return run(message);
  }
  const transfer = layout => [layout.x.buffer, layout.y.buffer, layout.w.buffer, layout.h.buffer, layout.layer.buffer, layout.back.buffer,
    layout.routes.buffer, layout.routeTypes.buffer, layout.routeStart.buffer];
  return {METRICS, ROUTE: {MOVE, CURVE, LINE, CORNER}, runAsync, transfer};
})();

if (typeof importScripts === 'function') {
  self.onmessage = async event => {
    try {
      const layout = await flowGraphLayout.runAsync(event.data);
      self.postMessage({id: event.data.id, ok: true, layout}, flowGraphLayout.transfer(layout));
    } catch (error) {
      self.postMessage({id: event.data.id, ok: false, error: error?.message ?? 'Layout failed.'});
    }
  };
}
