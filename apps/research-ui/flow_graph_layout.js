/* Layered layout for the session flow graph. Runs off the main thread as a
 * Web Worker; also loads as CommonJS for the offline checks.
 *
 * Each realm is a cluster with its own columns, so a call that crosses into
 * an iframe, or a posted task that does, is an edge between clusters and reads
 * as such. Rows are call depth: cycles (recursion, re-entrant handlers) are
 * broken by a depth-first walk, nodes take their longest-path layer, and a
 * root is pulled down next to its first callee. An edge longer than one layer
 * gets a waypoint in every layer it passes, so it is routed between cards,
 * never through one. Within a cluster and layer, cards and waypoints are
 * ordered by the mean position of their neighbours (alternating down and up
 * sweeps), then placed as near that mean as the spacing allows (a weighted
 * isotonic fit), which keeps a chain of calls one straight vertical line. A
 * realm holds at most `wrap` cards per layer: the rest move down a layer,
 * leaves first, so a wide fan of calls stacks instead of running off to the
 * side. Back edges run up the cluster's right gutter. Card sizes come from
 * the caller. No dependency is linked. */
'use strict';

const flowGraphLayout = (() => {
  const METRICS = {nodeW: 220, nodeH: 34, gapX: 30, gapY: 72, laneGap: 56, lanePadX: 22, lanePadTop: 48, lanePadBottom: 22,
    margin: 40, top: 0, wrap: 5, dummyW: 3, dummyGap: 12, busGap: 4, portGap: 18, gutter: 18, gutterStep: 7, gutterSlots: 6, maxDummies: 200000};
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

  /** At most `cap` cards of one lane in a layer, more in a big lane so it
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

  /** Lanes left to right: realms that call into each other sit together,
   * callers before the realms they call into (an iframe after its parent),
   * the busiest connected group first, then shallower first. */
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
        // A cycle between realms: take the best ranked remaining lane.
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

  /**
   * graph: {count, lane: Int32Array (lane key per node), from, to, weight?, w?, h?}
   * Returns node boxes (top-left, with per-node w and h), lane boxes, which
   * edges were treated as back edges, and one route per edge.
   */
  function layoutGraph(graph, metrics = METRICS) {
    const m = {...METRICS, ...metrics};
    const {count, from, to} = graph;
    const edgeCount = from.length;
    const nodeW = Float32Array.from({length: count}, (_, v) => graph.w?.[v] ?? m.nodeW);
    const nodeH = Float32Array.from({length: count}, (_, v) => graph.h?.[v] ?? m.nodeH);
    const adj = adjacency(count, from, to);
    const back = backEdges(count, from, to, adj, graph.weight);
    const layer = layers(count, from, to, adj, back);
    boundLayers(count, layer, graph.lane, adj, to, back, graph.weight, m.wrap);
    let maxLayer = 0; for (let v = 0; v < count; v += 1) maxLayer = Math.max(maxLayer, layer[v]);
    const laneKeys = laneOrder(count, graph, from, to, back, layer);
    const laneIndex = new Map(laneKeys.map((key, index) => [key, index]));
    const lanes = laneKeys.length;

    // Items: cards 0..count-1, then one waypoint per layer a long edge passes.
    const itemLane = [], itemLayer = [], itemEdge = [];
    for (let v = 0; v < count; v += 1) { itemLane.push(laneIndex.get(graph.lane[v])); itemLayer.push(layer[v]); itemEdge.push(-1); }
    const firstDummy = new Int32Array(edgeCount).fill(-1), dummyCount = new Uint32Array(edgeCount);
    const links = [];
    let budget = m.maxDummies;
    for (let e = 0; e < edgeCount; e += 1) {
      if (back[e]) continue;
      const a = from[e], b = to[e], span = layer[b] - layer[a];
      if (span > 1 && span - 1 <= budget) {
        budget -= span - 1; firstDummy[e] = itemLane.length; dummyCount[e] = span - 1;
        let previous = a;
        for (let l = layer[a] + 1; l < layer[b]; l += 1) {
          const id = itemLane.length;
          itemLane.push(itemLane[a]); itemLayer.push(l); itemEdge.push(e);
          links.push(previous, id); previous = id;
        }
        links.push(previous, b);
      } else links.push(a, b);
    }
    const items = itemLane.length, isDummy = id => id >= count;
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
    const cells = Array.from({length: lanes}, () => Array.from({length: maxLayer + 1}, () => []));
    for (let id = 0; id < items; id += 1) cells[itemLane[id]][itemLayer[id]].push(id);
    cells.forEach(laneCells => laneCells.forEach(cell => cell.sort((a, b) => discovery[a] - discovery[b])));

    const layerH = new Float64Array(maxLayer + 1);
    for (let v = 0; v < count; v += 1) layerH[layer[v]] = Math.max(layerH[layer[v]], height[v]);
    const layerTop = new Float64Array(maxLayer + 2);
    layerTop[0] = m.margin + m.top + m.lanePadTop;
    for (let l = 0; l <= maxLayer; l += 1) layerTop[l + 1] = layerTop[l] + layerH[l] + m.gapY;

    // Horizontal placement: centres local to each lane, lanes side by side.
    const local = new Float64Array(items), laneX = new Float64Array(lanes), laneW = new Float64Array(lanes);
    const gutterOf = new Float64Array(lanes), backIn = new Uint32Array(lanes);
    for (let e = 0; e < edgeCount; e += 1) if (back[e] && from[e] !== to[e]) backIn[itemLane[from[e]]] += 1;
    for (let lane = 0; lane < lanes; lane += 1) gutterOf[lane] = backIn[lane] ? m.gutter + Math.min(backIn[lane], m.gutterSlots) * m.gutterStep : 0;
    // Waypoints of a bundle of long edges run close together, like a bus.
    const gapOf = (a, b) => isDummy(a) && isDummy(b) ? m.busGap : isDummy(a) || isDummy(b) ? m.dummyGap : m.gapX;
    const center = id => laneX[itemLane[id]] + local[id];
    const placeLanes = () => {
      let cursor = m.margin + m.lanePadX;
      for (let lane = 0; lane < lanes; lane += 1) {
        let left = Infinity, right = -Infinity;
        for (const cell of cells[lane]) for (const id of cell) { left = Math.min(left, local[id] - width[id] / 2); right = Math.max(right, local[id] + width[id] / 2); }
        if (left === Infinity) { left = 0; right = 0; }
        for (const cell of cells[lane]) for (const id of cell) local[id] -= left;
        laneW[lane] = right - left; laneX[lane] = cursor;
        cursor += laneW[lane] + gutterOf[lane] + m.lanePadX * 2 + m.laneGap;
      }
    };
    const placeCell = (lane, l, desired, weight) => {
      const cell = cells[lane][l];
      if (!cell.length) return;
      const fitted = fitRow(cell, desired, weight, width, gapOf);
      cell.forEach((id, i) => { local[id] = fitted[i] - laneX[lane]; });
    };
    // Start packed left to right.
    cells.forEach(laneCells => laneCells.forEach(cell => { let x = 0; cell.forEach((id, i) => { if (i) x += (width[cell[i - 1]] + width[id]) / 2 + gapOf(cell[i - 1], id); local[id] = x; }); }));
    placeLanes();
    const sweep = (down, both = false) => {
      for (let step = 0; step <= maxLayer; step += 1) {
        const l = down ? step : maxLayer - step;
        for (let lane = 0; lane < lanes; lane += 1) {
          const cell = cells[lane][l];
          if (!cell.length) continue;
          const desired = new Float64Array(cell.length), weight = new Float64Array(cell.length), keyed = new Array(cell.length);
          const left = laneX[lane], right = laneX[lane] + laneW[lane];
          cell.forEach((id, i) => {
            let sum = 0, n = 0;
            // A neighbour in another realm pulls toward the nearer edge of
            // this one, never past it: otherwise two clusters chase each
            // other apart.
            const add = (startArr, list) => {
              for (let k = startArr[id]; k < startArr[id + 1]; k += 1) {
                const other = list[k];
                if (itemLane[other] === lane) { sum += center(other); n += 1; } else { sum += 0.35 * Math.max(left, Math.min(right, center(other))); n += 0.35; }
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
          // have one, instead of holding the lane open.
          let connected = 0, mass = 0;
          for (let i = 0; i < cell.length; i += 1) if (weight[i] > 0.05) { connected += desired[i]; mass += 1; }
          if (mass) for (let i = 0; i < cell.length; i += 1) if (weight[i] <= 0.05) desired[i] = connected / mass;
          keyed.sort((a, b) => desired[a] - desired[b] || discovery[cell[a]] - discovery[cell[b]]);
          const sorted = keyed.map(i => cell[i]), sortedDesired = Float64Array.from(keyed, i => desired[i]), sortedWeight = Float64Array.from(keyed, i => weight[i]);
          cells[lane][l] = sorted;
          placeCell(lane, l, sortedDesired, sortedWeight);
        }
      }
      placeLanes();
    };
    for (let pass = 0; pass < SWEEPS; pass += 1) sweep(pass % 2 === 0);
    // A last down sweep keeps single calls straight under their caller.
    sweep(true);

    // Boxes.
    const x = new Float32Array(count), y = new Float32Array(count);
    cells.forEach((laneCells, lane) => laneCells.forEach((cell, l) => {
      for (const id of cell) if (!isDummy(id)) { x[id] = center(id) - width[id] / 2; y[id] = layerTop[l]; }
    }));
    const laneBoxes = laneKeys.map((key, lane) => {
      let top = Infinity, bottom = -Infinity;
      for (const cell of cells[lane]) for (const id of cell) if (!isDummy(id)) { top = Math.min(top, y[id]); bottom = Math.max(bottom, y[id] + nodeH[id]); }
      if (top === Infinity) { top = layerTop[0]; bottom = top; }
      return {key, x: laneX[lane] - m.lanePadX, y: top - m.lanePadTop, w: laneW[lane] + m.lanePadX * 2 + gutterOf[lane], h: bottom - top + m.lanePadTop + m.lanePadBottom, gutter: laneX[lane] + laneW[lane] + m.lanePadX / 2};
    });

    // Ports: a card's edges leave its bottom and enter its top in the order of
    // where they go, so bundles do not cross at the card. Back edges take the
    // right end, toward the gutter they run up.
    const outPort = new Float64Array(edgeCount), inPort = new Float64Array(edgeCount);
    const nextX = e => firstDummy[e] >= 0 ? center(firstDummy[e]) : x[to[e]] + nodeW[to[e]] / 2;
    const previousX = e => firstDummy[e] >= 0 ? center(firstDummy[e] + dummyCount[e] - 1) : x[from[e]] + nodeW[from[e]] / 2;
    const spread = (v, list, key, target) => {
      if (!list.length) return;
      list.sort((a, b) => key(a) - key(b) || a - b);
      const step = list.length > 1 ? Math.min(m.portGap, nodeW[v] * 0.6 / (list.length - 1)) : 0, mid = x[v] + nodeW[v] / 2;
      list.forEach((e, i) => { target[e] = mid + (i - (list.length - 1) / 2) * step; });
    };
    for (let v = 0; v < count; v += 1) {
      const outs = [], ins = [];
      for (let k = adj.outStart[v]; k < adj.outStart[v + 1]; k += 1) outs.push(adj.outEdges[k]);
      for (let k = adj.inStart[v]; k < adj.inStart[v + 1]; k += 1) ins.push(adj.inEdges[k]);
      // A self call has its own loop on the card's right edge.
      spread(v, outs.filter(e => to[e] !== v), e => back[e] ? Infinity : nextX(e), outPort);
      spread(v, ins.filter(e => from[e] !== v), e => back[e] ? Infinity : previousX(e), inPort);
    }

    // Routes.
    const points = [], types = [], routeStart = new Uint32Array(edgeCount + 1);
    const push = (px, py, type) => { points.push(px, py); types.push(type); };
    const laneSlot = new Uint32Array(lanes);
    for (let e = 0; e < edgeCount; e += 1) {
      routeStart[e] = types.length;
      const a = from[e], b = to[e], sx = outPort[e], sy = y[a] + nodeH[a];
      if (a === b) {
        // Recursion: out of the right edge low, up through the gap beside
        // the card and back in at its right edge under the header.
        const right = x[a] + nodeW[a], loop = Math.min(m.gapX * 0.66, 20), low = y[a] + Math.max(30, nodeH[a] - 14);
        push(right, low, MOVE); push(right + loop, low, CORNER); push(right + loop, y[a] + 15, CORNER); push(right, y[a] + 15, LINE);
      } else if (back[e]) {
        // Down out of the source, along the gap under its layer, up the
        // lane's gutter, along the gap over the target's layer and down in.
        const lane = itemLane[a], slot = laneSlot[lane]++ % m.gutterSlots;
        const gx = laneBoxes[lane].gutter + m.gutter / 2 + slot * m.gutterStep;
        const below = layerTop[layer[a]] + layerH[layer[a]] + m.gapY * 0.3 + slot * 3, above = y[b] - m.gapY * 0.3 - slot * 3;
        push(sx, sy, MOVE); push(sx, below, CORNER); push(gx, below, CORNER); push(gx, above, CORNER); push(inPort[e], above, CORNER); push(inPort[e], y[b], LINE);
      } else {
        push(sx, sy, MOVE);
        for (let d = 0; d < dummyCount[e]; d += 1) {
          const id = firstDummy[e] + d, l = itemLayer[id], dx = center(id);
          push(dx, layerTop[l], CURVE); push(dx, layerTop[l] + layerH[l], LINE);
        }
        push(inPort[e], y[b], CURVE);
      }
    }
    routeStart[edgeCount] = types.length;

    let totalW = m.margin * 2 + m.nodeW, totalH = layerTop[0] + m.margin;
    for (const box of laneBoxes) { totalW = Math.max(totalW, box.x + box.w + m.margin); totalH = Math.max(totalH, box.y + box.h + m.margin); }
    return {x, y, w: nodeW, h: nodeH, layer, back, lanes: laneBoxes, width: totalW, height: totalH, top: m.margin,
      routes: Float32Array.from(points), routeTypes: Uint8Array.from(types), routeStart, waypoints: items - count};
  }

  /* Triskel (graph-layout-v1, POST /api/graph-layout) lays out each realm
   * that fits its limits, the way a CFG tool lays out a function. A realm
   * Triskel would draw much wider than the layered layout above (a wide fan
   * of calls, which Triskel does not stack) keeps the layered one; so does
   * every realm when the route is missing or fails. Realms keep the layered
   * layout's order and top, so the page still sits above the frames it calls
   * into, and calls between realms run down the gap beside their cluster. */
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

  /** Places each realm from Triskel's answer or the layered layout, packs
   * the realms left to right and routes calls between realms. */
  function assemble(graph, local, plan, answer, metrics) {
    const m = {...METRICS, ...metrics};
    const {count, from, to} = graph, edgeCount = from.length, lanes = local.lanes.length;
    const x = new Float32Array(count), y = new Float32Array(count);
    const engines = local.lanes.map(() => ({engine: 'layered', reason: 'one card'}));
    const content = local.lanes.map(() => null);
    plan.sent.forEach((lane, position) => {
      const result = answer?.graphs?.[position], members = plan.members[lane];
      const box = local.lanes[lane], layeredW = box.w - m.lanePadX * 2;
      if (!result) { engines[lane] = {engine: 'layered', reason: 'Triskel gave no answer'}; return; }
      if (result.status !== 'laid_out') { engines[lane] = {engine: 'layered', reason: result.status === 'too_large' ? 'over Triskel’s size limit' : `Triskel ${result.status}${result.reason ? `: ${result.reason}` : ''}`}; return; }
      const ok = Array.isArray(result.nodes) && result.nodes.length === members.length && Array.isArray(result.edges) && result.edges.length === plan.inner[lane].length
        && result.nodes.every(point => Number.isFinite(point?.[0]) && Number.isFinite(point?.[1])) && result.edges.every(list => Array.isArray(list) && list.length >= 4 && list.every(Number.isFinite));
      if (!ok) { engines[lane] = {engine: 'layered', reason: 'Triskel answer did not match the realm'}; return; }
      if (result.width > Math.max(layeredW * TRISKEL.widen, TRISKEL.freeWidth)) { engines[lane] = {engine: 'layered', reason: `Triskel would draw it ${(result.width / Math.max(1, layeredW)).toFixed(1)}× wider`}; return; }
      // Triskel stacks loop bodies, so a realm full of back edges can come
      // out far taller than it is wide; that, too, keeps the layered layout.
      const layeredH = box.h - m.lanePadTop - m.lanePadBottom;
      if (result.height > Math.max(layeredH * TRISKEL.widen, layeredH + TRISKEL.freeHeight)) { engines[lane] = {engine: 'layered', reason: `Triskel would draw it ${(result.height / Math.max(1, layeredH)).toFixed(1)}\u00d7 taller`}; return; }
      engines[lane] = {engine: 'triskel'};
      content[lane] = result;
    });
    plan.members.forEach((members, lane) => { if (members.length >= 2 && !plan.sent.includes(lane) && engines[lane].reason === 'one card') engines[lane] = {engine: 'layered', reason: 'over Triskel’s size limit'}; });
    // Each realm's own content box, at the layered layout's top.
    const routes = new Array(edgeCount).fill(null), types = new Array(edgeCount).fill(null);
    const boxes = local.lanes.map((lane, index) => {
      const members = plan.members[index];
      let top = Infinity; for (const v of members) top = Math.min(top, local.y[v]);
      if (top === Infinity) top = lane.y + m.lanePadTop;
      if (content[index]) {
        const result = content[index];
        let minX = 0, maxX = result.width;
        for (const list of result.edges) for (let i = 0; i < list.length; i += 2) { minX = Math.min(minX, list[i]); maxX = Math.max(maxX, list[i]); }
        return {top, width: maxX - minX, height: result.height, shift: -minX, triskel: result};
      }
      const left = lane.x + m.lanePadX;
      // The layered realm keeps its width, back-edge gutter included.
      return {top, width: lane.w - m.lanePadX * 2, left};
    });
    // Every cluster starts on one line, so realm labels share a baseline over
    // the first row and no edge runs through one.
    const commonTop = Math.min(...boxes.map(box => box.top));
    let cursor = m.margin;
    const laneBoxes = local.lanes.map((lane, index) => {
      const box = boxes[index], members = plan.members[index], originX = cursor + m.lanePadX;
      let bottom = -Infinity;
      if (box.triskel) {
        members.forEach((v, i) => { x[v] = originX + box.shift + box.triskel.nodes[i][0]; y[v] = box.top + box.triskel.nodes[i][1]; bottom = Math.max(bottom, y[v] + local.h[v]); });
        plan.inner[index].forEach((e, i) => {
          if (from[e] === to[e]) {
            // Recursion: a tight loop on the card's right edge, not
            // Triskel's loop around the whole row.
            const v = from[e], right = x[v] + local.w[v], low = y[v] + Math.max(30, local.h[v] - 14);
            routes[e] = [right, low, right + 16, low, right + 16, y[v] + 15, right, y[v] + 15]; types[e] = [MOVE, CORNER, CORNER, LINE];
            return;
          }
          const points = waypointRoute(box.triskel.edges[i], originX + box.shift, box.top), last = points.length / 2 - 1;
          routes[e] = points; types[e] = Array.from({length: last + 1}, (_, k) => k === 0 ? MOVE : k === last ? LINE : CORNER);
        });
      } else {
        const dx = originX - box.left;
        for (const v of members) { x[v] = local.x[v] + dx; y[v] = local.y[v]; bottom = Math.max(bottom, y[v] + local.h[v]); }
        plan.inner[index].forEach(e => {
          const points = [], kinds = [];
          for (let i = local.routeStart[e]; i < local.routeStart[e + 1]; i += 1) { points.push(local.routes[2 * i] + dx, local.routes[2 * i + 1]); kinds.push(local.routeTypes[i]); }
          routes[e] = points; types[e] = kinds;
        });
      }
      const width = box.width, w = width + m.lanePadX * 2;
      const result = {key: lane.key, x: cursor, y: commonTop - m.lanePadTop, w, h: (bottom === -Infinity ? 0 : bottom - commonTop) + m.lanePadTop + m.lanePadBottom, gutter: cursor + w - m.lanePadX / 2, engine: engines[index].engine, reason: engines[index].reason};
      // Every route of this realm stays inside its cluster.
      for (const e of plan.inner[index]) for (let i = 0; i < routes[e].length; i += 2) { result.h = Math.max(result.h, routes[e][i + 1] - result.y + m.lanePadBottom); }
      cursor += w + m.laneGap;
      return result;
    });
    // Calls between realms: down out of the caller, along the gap under its
    // row, through the gap beside the realm toward the callee, along the gap
    // above the callee's row and down in.
    const laneIndex = new Map(local.lanes.map((lane, index) => [lane.key, index]));
    const byLane = plan.members;
    const rowClear = (lane, yValue, below) => {
      // The nearest y past every card of the realm that spans yValue.
      let result = yValue;
      for (let guard = 0; guard < 8; guard += 1) {
        let moved = false;
        for (const v of byLane[lane]) if (result > y[v] - 6 && result < y[v] + local.h[v] + 6) { result = below ? y[v] + local.h[v] + 16 : y[v] - 16; moved = true; }
        if (!moved) break;
      }
      return result;
    };
    const outSlot = new Uint32Array(count), inSlot = new Uint32Array(count), gapSlot = new Uint32Array(lanes + 1);
    for (let e = 0; e < edgeCount; e += 1) {
      if (routes[e]) continue;
      const a = from[e], b = to[e], la = laneIndex.get(graph.lane[a]), lb = laneIndex.get(graph.lane[b]);
      const sx = x[a] + local.w[a] / 2 + (outSlot[a]++ % 5 - 2) * 7, sy = y[a] + local.h[a];
      const tx = x[b] + local.w[b] / 2 + (inSlot[b]++ % 5 - 2) * 7 + 10, ty = y[b];
      const right = lb >= la, gap = right ? la + 1 : la, slot = gapSlot[gap]++ % 6;
      const gx = right ? laneBoxes[la].x + laneBoxes[la].w + m.laneGap / 2 - 15 + slot * 6 : laneBoxes[la].x - m.laneGap / 2 + 15 - slot * 6;
      const ya = rowClear(la, sy + 16 + slot * 3, true);
      // Into the callee's row from just above it; a callee in the realm's
      // first row is entered from above the cluster, past its label.
      let yb = rowClear(lb, ty - 16 - slot * 3, false);
      if (yb < laneBoxes[lb].y + m.lanePadTop - 4) yb = laneBoxes[lb].y - 12 - slot * 3;
      if (Math.abs(lb - la) === 1) {
        routes[e] = [sx, sy, sx, ya, gx, ya, gx, yb, tx, yb, tx, ty];
        types[e] = [MOVE, CORNER, CORNER, CORNER, CORNER, LINE];
      } else {
        // Realms in between are never crossed: up the gap beside the
        // caller's cluster, over the top of every cluster, and down the gap
        // beside the callee's.
        const targetGap = right ? lb : lb + 1, targetSlot = gapSlot[targetGap]++ % 6;
        const gx2 = right ? laneBoxes[lb].x - m.laneGap / 2 + 15 - targetSlot * 6 : laneBoxes[lb].x + laneBoxes[lb].w + m.laneGap / 2 - 15 + targetSlot * 6;
        const over = Math.min(...laneBoxes.map(box => box.y)) - 14 - slot * 5;
        routes[e] = [sx, sy, sx, ya, gx, ya, gx, over, gx2, over, gx2, yb, tx, yb, tx, ty];
        types[e] = [MOVE, CORNER, CORNER, CORNER, CORNER, CORNER, CORNER, LINE];
      }
    }
    const points = [], kinds = [], routeStart = new Uint32Array(edgeCount + 1);
    for (let e = 0; e < edgeCount; e += 1) { routeStart[e] = kinds.length; points.push(...routes[e]); kinds.push(...types[e]); }
    routeStart[edgeCount] = kinds.length;
    let totalW = m.margin * 2 + m.nodeW, totalH = 0;
    for (const box of laneBoxes) { totalW = Math.max(totalW, box.x + box.w + m.margin); totalH = Math.max(totalH, box.y + box.h + m.margin); }
    for (let i = 1; i < points.length; i += 2) totalH = Math.max(totalH, points[i] + m.margin);
    const laid = engines.filter(item => item.engine === 'triskel').length;
    return {...local, x, y, lanes: laneBoxes, width: totalW, height: totalH, routes: Float32Array.from(points), routeTypes: Uint8Array.from(kinds), routeStart,
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

  /** The layered layout alone, with calls between realms routed the same
   * way as when Triskel takes part. */
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
  return {METRICS, ROUTE: {MOVE, CURVE, LINE, CORNER}, TRISKEL, layoutGraph, layoutWithTriskel, assemble, triskelRequest, waypointRoute, fetchTriskel, run, runAsync, transfer, adjacency};
})();

if (typeof module === 'object' && module?.exports) module.exports = flowGraphLayout;
else if (typeof self !== 'undefined' && typeof document === 'undefined') {
  self.onmessage = async event => {
    try {
      const layout = await flowGraphLayout.runAsync(event.data);
      self.postMessage({id: event.data.id, ok: true, layout}, flowGraphLayout.transfer(layout));
    } catch (error) {
      self.postMessage({id: event.data.id, ok: false, error: error?.message ?? 'Layout failed.'});
    }
  };
}
