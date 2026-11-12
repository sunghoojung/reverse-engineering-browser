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
          const w = to[e]; if (layer[w] <= layer[v]) { layer[w] = layer[v] + 1; bucket(w); stack.push(w); }
        }
      }
    };
    const buckets = [];
    const bucket = v => (buckets[layer[v]] ??= []).push(v);
    for (let v = 0; v < count; v += 1) bucket(v);
    // Nodes only ever move down, so one pass over the layers in order sees
    // every node at its final layer. Each layer's nodes are bucketed once: a
    // node moved down joins its new layer's bucket and is skipped in the old.
    for (let l = 0; l < buckets.length; l += 1) {
      const byLane = new Map();
      for (const v of buckets[l] ?? []) {
        if (layer[v] !== l) continue;
        if (!byLane.has(laneOf[v])) byLane.set(laneOf[v], []);
        byLane.get(laneOf[v]).push(v);
      }
      for (const [key, group] of byLane) {
        const room = capOf(key);
        if (group.length <= room) continue;
        group.sort((a, b) => below[b] - below[a] || (weight?.[b] ?? 0) - (weight?.[a] ?? 0) || a - b);
        for (const v of group.slice(room)) {
          layer[v] = l + 1;
          bucket(v);
          push(v);
        }
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

  /** A route through corner points (graphLayoutClient.routePoints drops
   * repeats and straight-through points): the first point moves, the last is
   * a line, the rest are rounded corners. */
  function orthogonal(flat, dx = 0) {
    const points = graphLayoutClient.routePoints(flat, dx), last = points.length / 2 - 1;
    return {points, types: Array.from({length: last + 1}, (_, k) => (k === 0 ? MOVE : k === last ? LINE : CORNER))};
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
    // Each band's cards by left edge, and its widest card, to find the
    // cards over an x range by binary search.
    const byX = members.map(list => Int32Array.from(list).sort((a, b) => x[a] - x[b]));
    const widest = members.map(list => list.reduce((max, v) => Math.max(max, nodeW[v]), 0));
    /** The cards of `band` whose left edge is within its widest card of
     * [x0, x1]: every card that can overlap a narrow range, and a few more. */
    function cardsNear(band, x0, x1) {
      const list = byX[band], from = x0 - widest[band];
      let low = 0, high = list.length;
      while (low < high) {
        const mid = (low + high) >> 1;
        if (x[list[mid]] < from) low = mid + 1;
        else high = mid;
      }
      const found = [];
      for (let i = low; i < list.length && x[list[i]] <= x1; i += 1) found.push(list[i]);
      return found;
    }
    // Nothing of a card in [y0, y1] at x, other than the edge's own ends.
    const clearColumn = (cx, y0, y1, a, b) => {
      const low = Math.min(y0, y1), high = Math.max(y0, y1);
      for (let band = 0; band < bands; band += 1) {
        if (bottom[band] < low || top[band] > high) continue;
        for (const v of cardsNear(band, cx - 4, cx + 4)) {
          if (v === a || v === b) continue;
          if (cx > x[v] - 4 && cx < x[v] + nodeW[v] + 4 && high > y[v] - 2 && low < y[v] + nodeH[v] + 2) return false;
        }
      }
      return true;
    };
    // A height in the gap under (or over) a card's row that a run across
    // [x0, x1] can take without touching a card of its band. The run reaches
    // a side gutter, so its cards are found once, in card order, as each
    // step moves past the first one in the way.
    const rowGap = (band, v, down, x0, x1, slot) => {
      let at = down ? y[v] + nodeH[v] + 14 + slot * 3 : y[v] - 14 - slot * 3;
      const low = Math.min(x0, x1) - 6, high = Math.max(x0, x1) + 6;
      const across = members[band].filter(u => u !== v && high > x[u] && low < x[u] + nodeW[u]);
      for (let guard = 0; guard < 32; guard += 1) {
        let moved = false;
        for (const u of across) {
          if (at <= y[u] - 8 || at >= y[u] + nodeH[u] + 8) continue;
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
      return {key: band.key, x: m.margin, y: top[index], w: laneW, h: bottom[index] - top[index], gutter: shift + offsets[index] + band.cards + m.lanePadX / 2, top: contentTop[index]};
    });
    let height = (bands ? bottom[bands - 1] : m.margin + m.lanePadTop) + m.margin;
    for (let i = 1; i < points.length; i += 2) height = Math.max(height, points[i] + m.margin);
    return {x, y, lanes, width: m.margin * 2 + laneW, height, routes: Float32Array.from(points), routeTypes: Uint8Array.from(kinds), routeStart};
  }

  /** Layers inside each realm, from its own calls: cycles broken by a
   * depth-first walk, longest-path layers with roots pulled down, wide layers
   * wrapped. `back` marks the calls inside a realm that close a cycle; calls
   * between realms are set by band order. */
  function layerCards(graph, m) {
    const {count, from, to} = graph;
    const intra = [];
    for (let e = 0; e < from.length; e += 1) if (graph.lane[from[e]] === graph.lane[to[e]]) intra.push(e);
    const innerFrom = Int32Array.from(intra, e => from[e]), innerTo = Int32Array.from(intra, e => to[e]);
    const adj = adjacency(count, innerFrom, innerTo);
    const innerBack = backEdges(count, innerFrom, innerTo, adj, graph.weight);
    const layer = layers(count, innerFrom, innerTo, adj, innerBack);
    boundLayers(count, layer, graph.lane, adj, innerTo, innerBack, graph.weight, m.wrap);
    const back = new Uint8Array(from.length);
    intra.forEach((e, i) => { back[e] = innerBack[i]; });
    return {layer, back};
  }

  /** Bands in call order: each card's band, each band's last layer, and the
   * calls between bands that run back up. */
  function orderBands(graph, cards) {
    const {count, from, to, layer, back} = cards;
    const keys = laneOrder(count, graph, from, to, back, layer);
    const index = new Map(keys.map((key, band) => [key, band]));
    const bandOf = Int32Array.from({length: count}, (_, v) => index.get(graph.lane[v]));
    // A call into a band drawn above its caller runs back up.
    for (let e = 0; e < from.length; e += 1) if (bandOf[from[e]] !== bandOf[to[e]]) back[e] = bandOf[to[e]] < bandOf[from[e]] ? 1 : 0;
    const lastLayer = new Int32Array(keys.length);
    for (let v = 0; v < count; v += 1) lastLayer[bandOf[v]] = Math.max(lastLayer[bandOf[v]], layer[v]);
    let maxLayer = 0;
    for (const value of lastLayer) maxLayer = Math.max(maxLayer, value);
    return {count: keys.length, keys, bandOf, lastLayer, maxLayer};
  }

  /** The items to place: cards 0..count-1, then one waypoint per layer a long
   * call passes inside its band, at most m.maxDummies in all, and the links
   * between items. A call between bands links its two cards, the upper end
   * first, so a card in another band pulls sideways. */
  function insertWaypoints(cards, bands, m) {
    const {count, from, to, layer, back, w} = cards, {bandOf} = bands;
    const band = Array.from(bandOf), itemLayer = Array.from(layer);
    const firstDummy = new Int32Array(from.length).fill(-1), dummyCount = new Uint32Array(from.length);
    const linkFrom = [], linkTo = [];
    const link = (a, b) => { linkFrom.push(a); linkTo.push(b); };
    let budget = m.maxDummies;
    for (let e = 0; e < from.length; e += 1) {
      const a = from[e], b = to[e];
      if (bandOf[a] !== bandOf[b]) {
        if (bandOf[a] < bandOf[b]) link(a, b); else link(b, a);
        continue;
      }
      if (back[e]) continue;
      const span = layer[b] - layer[a];
      if (span <= 1 || span - 1 > budget) { link(a, b); continue; }
      budget -= span - 1;
      firstDummy[e] = band.length;
      dummyCount[e] = span - 1;
      let previous = a;
      for (let l = layer[a] + 1; l < layer[b]; l += 1) {
        const id = band.length;
        band.push(bandOf[a]);
        itemLayer.push(l);
        link(previous, id);
        previous = id;
      }
      link(previous, b);
    }
    const total = band.length, width = new Float64Array(total), height = new Float64Array(total);
    for (let id = 0; id < total; id += 1) {
      width[id] = id >= count ? m.dummyW : w[id];
      height[id] = id >= count ? 0 : cards.h[id];
    }
    const source = Int32Array.from(linkFrom), target = Int32Array.from(linkTo);
    return {count: total, cards: count, band, layer: itemLayer, width, height, firstDummy, dummyCount, from: source, to: target, adj: adjacency(total, source, target)};
  }

  /** Each band's layers as cells of items, first in depth-first discovery
   * order from the heaviest roots. */
  function orderCells(items, bands, weight) {
    const {adj, to: linkTo} = items, discovery = new Int32Array(items.count).fill(-1), stack = [];
    let next = 0;
    const visit = start => {
      if (discovery[start] >= 0) return;
      stack.push(start);
      while (stack.length) {
        const id = stack.pop();
        if (discovery[id] >= 0) continue;
        discovery[id] = next++;
        for (let k = adj.outStart[id + 1]; k > adj.outStart[id]; k -= 1) {
          const child = linkTo[adj.outEdges[k - 1]];
          if (discovery[child] < 0) stack.push(child);
        }
      }
    };
    const roots = [];
    for (let id = 0; id < items.count; id += 1) if (adj.inStart[id + 1] === adj.inStart[id]) roots.push(id);
    roots.sort((a, b) => (weight?.[b] ?? 0) - (weight?.[a] ?? 0) || a - b);
    roots.forEach(visit);
    for (let id = 0; id < items.count; id += 1) visit(id);
    const cells = Array.from({length: bands.count}, (_, band) => Array.from({length: bands.lastLayer[band] + 1}, () => []));
    for (let id = 0; id < items.count; id += 1) cells[items.band[id]][items.layer[id]].push(id);
    for (const bandCells of cells) for (const cell of bandCells) cell.sort((a, b) => discovery[a] - discovery[b]);
    return {cells, discovery};
  }

  /** Each band's rows, from the band's own top: a layer's height and top. */
  function bandRows(cells, items, bands, m) {
    const height = cells.map(bandCells => new Float64Array(bandCells.length)), top = cells.map(bandCells => new Float64Array(bandCells.length + 1));
    for (let v = 0; v < items.cards; v += 1) {
      const band = bands.bandOf[v], l = items.layer[v];
      height[band][l] = Math.max(height[band][l], items.height[v]);
    }
    for (let band = 0; band < bands.count; band += 1) for (let l = 0; l < cells[band].length; l += 1) top[band][l + 1] = top[band][l] + height[band][l] + m.gapY;
    return {height, top};
  }

  /** Item centres local to each band and the bands' offsets: alternating
   * sweeps order each cell by its neighbours' mean position and place it by
   * a weighted isotonic fit, and the bands shift to line up the calls
   * between them. */
  function placeItems(cards, items, bands, order, m) {
    const {from, to, back} = cards, {bandOf} = bands, {cells, discovery} = order;
    const {band: itemBand, width, adj, from: linkFrom, to: linkTo} = items;
    const local = new Float64Array(items.count), bandX = new Float64Array(bands.count), bandW = new Float64Array(bands.count);
    const gutter = new Float64Array(bands.count), backIn = new Uint32Array(bands.count);
    for (let e = 0; e < from.length; e += 1) if (back[e] && from[e] !== to[e] && bandOf[from[e]] === bandOf[to[e]]) backIn[bandOf[from[e]]] += 1;
    for (let band = 0; band < bands.count; band += 1) gutter[band] = backIn[band] ? m.lanePadX / 2 + m.gutter + Math.min(backIn[band], m.gutterSlots) * m.gutterStep : 0;
    const crossEdges = [];
    for (let e = 0; e < from.length; e += 1) if (bandOf[from[e]] !== bandOf[to[e]]) crossEdges.push(e);
    const isDummy = id => id >= items.cards;
    // Waypoints of a bundle of long edges run close together, like a bus.
    const gapOf = (a, b) => (isDummy(a) && isDummy(b) ? m.busGap : isDummy(a) || isDummy(b) ? m.dummyGap : m.gapX);
    const center = id => bandX[itemBand[id]] + local[id];
    /** Each band from x = 0, then shifted to line up the calls between bands. */
    function alignAll() {
      for (let band = 0; band < bands.count; band += 1) {
        let left = Infinity, right = -Infinity;
        for (const cell of cells[band]) for (const id of cell) { left = Math.min(left, local[id] - width[id] / 2); right = Math.max(right, local[id] + width[id] / 2); }
        if (left === Infinity) { left = 0; right = 0; }
        for (const cell of cells[band]) for (const id of cell) local[id] -= left;
        bandW[band] = right - left;
      }
      const pairs = crossEdges.map(e => ({a: bandOf[from[e]], ca: local[from[e]], b: bandOf[to[e]], cb: local[to[e]]}));
      bandX.set(alignBands(Array.from(bandW, (value, band) => value + gutter[band]), pairs));
    }
    /** Orders one cell by where its neighbours on the side swept from sit,
     * then places it as near there as the spacing allows. */
    function placeCell(band, l, down) {
      const cell = cells[band][l];
      const desired = new Float64Array(cell.length), weight = new Float64Array(cell.length), keyed = cell.map((id, i) => i);
      const left = bandX[band], right = bandX[band] + bandW[band];
      cell.forEach((id, i) => {
        let sum = 0, n = 0;
        // A neighbour in another band pulls toward the nearer edge of this
        // one, never past it: otherwise two bands chase each other apart.
        const pull = other => {
          if (itemBand[other] === band) { sum += center(other); n += 1; }
          else { sum += 0.35 * Math.max(left, Math.min(right, center(other))); n += 0.35; }
        };
        if (down) for (let k = adj.inStart[id]; k < adj.inStart[id + 1]; k += 1) pull(linkFrom[adj.inEdges[k]]);
        else for (let k = adj.outStart[id]; k < adj.outStart[id + 1]; k += 1) pull(linkTo[adj.outEdges[k]]);
        desired[i] = n ? sum / n : center(id);
        weight[i] = n ? (isDummy(id) ? 3 : 1) * Math.min(1, n) : 0.05;
      });
      // A card with no neighbour this way packs beside the ones that have
      // one, instead of holding the band open.
      let connected = 0, mass = 0;
      for (let i = 0; i < cell.length; i += 1) if (weight[i] > 0.05) { connected += desired[i]; mass += 1; }
      if (mass) for (let i = 0; i < cell.length; i += 1) if (weight[i] <= 0.05) desired[i] = connected / mass;
      keyed.sort((a, b) => desired[a] - desired[b] || discovery[cell[a]] - discovery[cell[b]]);
      const sorted = keyed.map(i => cell[i]);
      cells[band][l] = sorted;
      const fitted = fitRow(sorted, Float64Array.from(keyed, i => desired[i]), Float64Array.from(keyed, i => weight[i]), width, gapOf);
      sorted.forEach((id, i) => { local[id] = fitted[i] - bandX[band]; });
    }
    /** Every band's layers once, top down or bottom up. */
    function sweep(down) {
      for (let step = 0; step <= bands.maxLayer; step += 1) {
        for (let band = 0; band < bands.count; band += 1) {
          const l = down ? step : bands.lastLayer[band] - step;
          if (l >= 0 && l <= bands.lastLayer[band] && cells[band][l].length) placeCell(band, l, down);
        }
      }
      alignAll();
    }
    // Start packed left to right.
    for (const bandCells of cells) {
      for (const cell of bandCells) {
        let at = 0;
        cell.forEach((id, i) => { if (i) at += (width[cell[i - 1]] + width[id]) / 2 + gapOf(cell[i - 1], id); local[id] = at; });
      }
    }
    alignAll();
    for (let pass = 0; pass < SWEEPS; pass += 1) sweep(pass % 2 === 0);
    // A last down sweep keeps single calls straight under their caller.
    sweep(true);
    return {local, bandX, bandW, gutter, crossEdges, center};
  }

  /** Ports: a card's calls leave its bottom and enter its top in the order
   * of where they go, so bundles do not cross at the card. Back edges take
   * the right end, toward the gutter they run up; a self call has its own
   * loop on the card's right edge instead. */
  function assignPorts(cards, bands, items, place, m) {
    const {count, from, to, w, back} = cards, {bandOf} = bands, {local, center} = place;
    const outPort = new Float64Array(from.length), inPort = new Float64Array(from.length);
    const nextX = e => (items.firstDummy[e] >= 0 ? center(items.firstDummy[e]) : center(to[e]));
    const previousX = e => (items.firstDummy[e] >= 0 ? center(items.firstDummy[e] + items.dummyCount[e] - 1) : center(from[e]));
    const spread = (v, list, key, target) => {
      if (!list.length) return;
      list.sort((a, b) => key(a) - key(b) || a - b);
      const step = list.length > 1 ? Math.min(m.portGap, w[v] * 0.6 / (list.length - 1)) : 0;
      list.forEach((e, i) => { target[e] = local[v] + (i - (list.length - 1) / 2) * step; });
    };
    const outs = Array.from({length: count}, () => []), ins = Array.from({length: count}, () => []);
    for (let e = 0; e < from.length; e += 1) {
      if (from[e] === to[e]) continue;
      outs[from[e]].push(e);
      ins[to[e]].push(e);
    }
    for (let v = 0; v < count; v += 1) {
      spread(v, outs[v], e => (back[e] && bandOf[to[e]] === bandOf[v] ? Infinity : nextX(e)), outPort);
      spread(v, ins[v], e => (back[e] && bandOf[from[e]] === bandOf[v] ? Infinity : previousX(e)), inPort);
    }
    return {outPort, inPort};
  }

  /** Routes of the calls inside each band, in band-local units; a call
   * between bands is routed by stackBands and is null here. */
  function routeBands(cards, bands, items, rows, place, ports, box, m) {
    const {from, to, w, h, layer, back} = cards, {bandOf} = bands, {lx, ly} = box;
    const routes = new Array(from.length).fill(null), slots = new Uint32Array(bands.count);
    for (let e = 0; e < from.length; e += 1) {
      const a = from[e], b = to[e], band = bandOf[a];
      if (band !== bandOf[b]) continue;
      const points = [], types = [], push = (px, py, type) => { points.push(px, py); types.push(type); };
      const sx = ports.outPort[e], sy = ly[a] + h[a], top = rows.top[band], height = rows.height[band];
      if (a === b) {
        // Recursion: out of the right edge low, up through the gap beside
        // the card and back in at its right edge under the header.
        const right = lx[a] + w[a], loop = Math.min(m.gapX * 0.66, 20), low = ly[a] + Math.max(30, h[a] - 14);
        push(right, low, MOVE); push(right + loop, low, CORNER); push(right + loop, ly[a] + 15, CORNER); push(right, ly[a] + 15, LINE);
      } else if (back[e]) {
        // Down out of the source, along the gap under its layer, up the
        // band's gutter, along the gap over the target's layer and down in.
        const slot = slots[band]++ % m.gutterSlots;
        const gx = place.bandW[band] + m.lanePadX / 2 + m.gutter / 2 + slot * m.gutterStep;
        const below = top[layer[a]] + height[layer[a]] + m.gapY * 0.3 + slot * 3, above = ly[b] - m.gapY * 0.3 - slot * 3;
        push(sx, sy, MOVE); push(sx, below, CORNER); push(gx, below, CORNER); push(gx, above, CORNER); push(ports.inPort[e], above, CORNER); push(ports.inPort[e], ly[b], LINE);
      } else {
        // Straight down to the bottom of the caller's row first, so the bend
        // into the next row is in the gap, clear of a taller card beside it.
        const rowBottom = top[layer[a]] + height[layer[a]];
        push(sx, sy, MOVE);
        if (rowBottom > sy + 0.5) push(sx, rowBottom, LINE);
        for (let d = 0; d < items.dummyCount[e]; d += 1) {
          const id = items.firstDummy[e] + d, l = items.layer[id], dx = place.local[id];
          push(dx, top[l], CURVE); push(dx, top[l] + height[l], LINE);
        }
        push(ports.inPort[e], ly[b], CURVE);
      }
      routes[e] = {points, types};
    }
    return routes;
  }

  /**
   * graph: {count, lane: Int32Array (lane key per node), from, to, weight?, w?, h?}
   * Returns node boxes (top-left, with per-node w and h), band boxes in
   * order, which edges were treated as back edges, and one route per edge.
   */
  function layoutGraph(graph, metrics = METRICS) {
    const m = {...METRICS, ...metrics};
    const {count, from, to} = graph;
    const w = Float32Array.from({length: count}, (_, v) => graph.w?.[v] ?? m.nodeW);
    const h = Float32Array.from({length: count}, (_, v) => graph.h?.[v] ?? m.nodeH);
    const cards = {count, from, to, w, h, ...layerCards(graph, m)};
    const bands = orderBands(graph, cards);
    const items = insertWaypoints(cards, bands, m);
    const order = orderCells(items, bands, graph.weight);
    const rows = bandRows(order.cells, items, bands, m);
    const place = placeItems(cards, items, bands, order, m);
    // Band-local boxes.
    const lx = new Float64Array(count), ly = new Float64Array(count);
    for (let v = 0; v < count; v += 1) {
      lx[v] = place.local[v] - w[v] / 2;
      ly[v] = rows.top[bands.bandOf[v]][cards.layer[v]];
    }
    const ports = assignPorts(cards, bands, items, place, m);
    const routes = routeBands(cards, bands, items, rows, place, ports, {lx, ly}, m);
    // A back edge into a first-row card runs over it through the band's top
    // pad, which the band already has.
    const contentBands = bands.keys.map((key, band) => {
      const last = order.cells[band].length - 1;
      return {key, w: place.bandW[band] + place.gutter[band], h: last >= 0 ? rows.top[band][last] + rows.height[band][last] : 0, cards: place.bandW[band]};
    });
    const content = {bands: contentBands, bandOf: bands.bandOf, lx, ly, routes, outPort: crossPorts(ports.outPort, place.crossEdges, from.length),
      inPort: crossPorts(ports.inPort, place.crossEdges, from.length), offsets: Float64Array.from(place.bandX)};
    const stacked = stackBands(graph, w, h, content, m);
    return {...stacked, w, h, layer: cards.layer, back: cards.back, top: m.margin, waypoints: items.count - count, content};
  }
  /** Ports of calls between bands only; the rest are in their routes. */
  function crossPorts(ports, crossEdges, edgeCount) {
    const out = new Float64Array(edgeCount).fill(NaN);
    for (const e of crossEdges) out[e] = ports[e];
    return out;
  }

  /* Triskel, through graphLayoutClient, lays out each realm of two or more
   * cards the way a CFG tool lays out a function. A realm keeps the layered
   * layout above where the client says why: Triskel would draw it much wider
   * (a wide fan of calls, which Triskel does not stack) or taller, it is past
   * the route's limits, or the route is missing or fails. Bands keep the
   * layered layout's order, so the page still sits above the frames it calls
   * into, and calls between bands are routed the same way for either engine. */

  /** Each realm's cards, the calls inside it, and each card's index in it. */
  function realms(graph, local) {
    const {count, from, to} = graph, {bandOf} = local.content;
    const members = local.lanes.map(() => []), inner = local.lanes.map(() => []), localIndex = new Int32Array(count);
    for (let v = 0; v < count; v += 1) {
      localIndex[v] = members[bandOf[v]].length;
      members[bandOf[v]].push(v);
    }
    for (let e = 0; e < from.length; e += 1) if (bandOf[from[e]] === bandOf[to[e]]) inner[bandOf[from[e]]].push(e);
    return {members, inner, localIndex};
  }

  /** Places each band from its Triskel result or the layered layout, stacks
   * the bands top to bottom and routes the calls between them. `outcomes`
   * holds per realm {result} or {reason}. */
  function assemble(graph, local, realm, outcomes, report, metrics) {
    const m = {...METRICS, ...metrics};
    const {from, to} = graph, edgeCount = from.length;
    // A Triskel band replaces its content: card positions, routes inside it
    // and its size. Calls out of or into it get fresh ports. Its drawing
    // starts at 0, 0 (graph-layout-v1), its waypoints included.
    const base = local.content, lx = Float64Array.from(base.lx), ly = Float64Array.from(base.ly), routes = base.routes.slice();
    const outPort = Float64Array.from(base.outPort), inPort = Float64Array.from(base.inPort);
    const bands = base.bands.slice();
    outcomes.forEach(({result}, lane) => {
      if (!result) return;
      let right = result.width, cards = 0, bottom = result.height;
      realm.members[lane].forEach((v, i) => {
        lx[v] = result.nodes[i][0];
        ly[v] = result.nodes[i][1];
        cards = Math.max(cards, lx[v] + local.w[v]);
        bottom = Math.max(bottom, ly[v] + local.h[v]);
      });
      realm.inner[lane].forEach((e, i) => {
        if (from[e] === to[e]) {
          // Recursion: a tight loop on the card's right edge, not
          // Triskel's loop around the whole row.
          const v = from[e], edge = lx[v] + local.w[v], low = ly[v] + Math.max(30, local.h[v] - 14);
          routes[e] = {points: [edge, low, edge + 16, low, edge + 16, ly[v] + 15, edge, ly[v] + 15], types: [MOVE, CORNER, CORNER, LINE]};
          right = Math.max(right, edge + 16);
          return;
        }
        routes[e] = orthogonal(result.edges[i]);
        const points = routes[e].points;
        for (let k = 0; k < points.length; k += 2) { right = Math.max(right, points[k]); bottom = Math.max(bottom, points[k + 1]); }
      });
      bands[lane] = {...bands[lane], w: Math.max(right, cards), h: bottom, cards};
      for (let e = 0; e < edgeCount; e += 1) {
        if (base.bandOf[from[e]] === base.bandOf[to[e]]) continue;
        if (base.bandOf[from[e]] === lane) outPort[e] = NaN;
        if (base.bandOf[to[e]] === lane) inPort[e] = NaN;
      }
    });
    const laid = outcomes.filter(outcome => outcome.result).length;
    const content = {bands, bandOf: base.bandOf, lx, ly, routes, outPort, inPort, offsets: laid ? undefined : base.offsets};
    const stacked = stackBands(graph, local.w, local.h, content, m);
    const {content: unused, ...rest} = local;
    const realmReport = outcomes.map((outcome, lane) => ({key: local.lanes[lane].key, engine: outcome.result ? 'triskel' : 'layered', reason: outcome.reason ?? null}));
    return {...rest, ...stacked, engine: {name: laid ? 'triskel' : 'layered', revision: report.revision, triskel: laid, realms: realmReport, failure: report.failure}};
  }

  /** The layered layout, then Triskel for the realms the client keeps when
   * `engine` is triskel; the engine report says why each other realm stayed. */
  async function runAsync({graph, metrics = METRICS, engine}) {
    const local = layoutGraph(graph, metrics), realm = realms(graph, local);
    const outcomes = realm.members.map(list => ({reason: {code: list.length < 2 ? 'one_card' : 'not_served'}}));
    const report = {revision: null, failure: null};
    if (engine === 'triskel') {
      const lanes = [], graphs = [];
      realm.members.forEach((list, lane) => {
        if (list.length < 2) return;
        const band = local.content.bands[lane];
        lanes.push(lane);
        graphs.push({nodes: list.map(v => [local.w[v], local.h[v]]), edges: realm.inner[lane].map(e => [realm.localIndex[graph.from[e]], realm.localIndex[graph.to[e]]]), width: band.w, height: band.h});
      });
      const answer = await graphLayoutClient.layOut(graphs);
      lanes.forEach((lane, index) => { outcomes[lane] = answer.outcomes[index]; });
      report.revision = answer.revision;
      report.failure = answer.failure;
    }
    return assemble(graph, local, realm, outcomes, report, metrics);
  }
  const transfer = layout => [layout.x.buffer, layout.y.buffer, layout.w.buffer, layout.h.buffer, layout.layer.buffer, layout.back.buffer,
    layout.routes.buffer, layout.routeTypes.buffer, layout.routeStart.buffer];
  return {METRICS, ROUTE: {MOVE, CURVE, LINE, CORNER}, runAsync, transfer};
})();

if (typeof importScripts === 'function') {
  importScripts('graph_layout_client.js');
  self.onmessage = async event => {
    try {
      const result = await flowGraphLayout.runAsync(event.data);
      self.postMessage({id: event.data.id, ok: true, result}, flowGraphLayout.transfer(result));
    } catch (error) {
      self.postMessage({id: event.data.id, ok: false, error: error?.message ?? 'Layout failed.'});
    }
  };
}
