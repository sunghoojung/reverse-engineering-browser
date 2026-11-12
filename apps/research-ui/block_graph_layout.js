/* Layered single-entry-region layout for basic-block graphs. Runs off the main
 * thread as a Web Worker; also loads as CommonJS for the offline check, which
 * loads graph_layout_client.js first.
 *
 * A dominator subtree is entered only at its root, so each subtree becomes a
 * collapsed box laid out on its own: its members are stacked in layers, a layer
 * of one member continues the spine, and a wider layer becomes side-by-side
 * boxes, wrapped into a grid once it is wide. A dispatcher's arms are one such
 * layer, so its fan is a grid fed by a shared bus and its back edges collect on
 * one rail beside the loop header. Edges leaving a box merge into its bottom
 * port, so a flattened function stays legible. No new dependency is linked. */
'use strict';

const blockGraphLayout = (() => {
  const METRICS = {charW: 6.6, rowH: 16, headerH: 22, padX: 10, padY: 7, minW: 132, gapX: 32, gapY: 36, lane: 8, side: 8, margin: 48};
  const KIND = {fallthrough: 0, branch: 1, taken: 2, not_taken: 3, table: 4, table_default: 5, exception: 6, unresolved: 7, call: 8, assumed: 9, sequence: 10};
  const MAX_ROW_CHARS = 120;
  const WRAP_AT = 6;

  /** Normalizes a `wasm-block-graph-v1` document. Refuses an unknown shape. */
  function wasmGraph(doc) {
    if (doc?.schema !== 'wasm-block-graph-v1' || !Array.isArray(doc.blocks) || !Array.isArray(doc.edges) || typeof doc.rows !== 'string')
      throw Error('The WASM graph provider returned an invalid document.');
    const count = doc.blocks.length, edgeCount = doc.edges.length;
    const offsets = new Float64Array(count), ends = new Float64Array(count), firstRow = new Uint32Array(count),
      rowCount = new Uint32Array(count), instructionCount = new Uint32Array(count), flags = new Uint32Array(count);
    doc.blocks.forEach((block, index) => {
      offsets[index] = block[0]; ends[index] = block[1]; firstRow[index] = block[2]; rowCount[index] = block[3];
      instructionCount[index] = block[4]; flags[index] = block[5];
    });
    const names = doc.edge_kinds;
    const from = new Int32Array(edgeCount), to = new Int32Array(edgeCount), kind = new Uint8Array(edgeCount), labels = new Array(edgeCount).fill(null);
    doc.edges.forEach((edge, index) => {
      from[index] = edge[0]; to[index] = edge[1] === null ? -1 : edge[1];
      const known = KIND[names[edge[2]]];
      kind[index] = known === undefined ? KIND.unresolved : known;
      labels[index] = edge[3];
    });
    return {count, offsets, ends, firstRow, rowCount, instructionCount, flags, from, to, kind, labels, rows: doc.rows, roots: [0],
      title: `func ${doc.function_index}`, status: doc.status, instructions: doc.instruction_count, omissions: doc.omissions, notice: doc.notice,
      evidence: 'declared', functionIndex: doc.function_index, byteOffset: doc.byte_offset, byteEnd: doc.byte_end};
  }

  function rowStarts(rows) {
    let lines = 0;
    for (let index = 0; index < rows.length; index += 1) if (rows.charCodeAt(index) === 10) lines += 1;
    if (rows.length && rows.charCodeAt(rows.length - 1) !== 10) lines += 1;
    const starts = new Uint32Array(lines + 1);
    let line = 0;
    for (let index = 0; index < rows.length; index += 1) if (index === 0 || rows.charCodeAt(index - 1) === 10) starts[line++] = index;
    starts[lines] = rows.length;
    return starts;
  }

  function nodeSizes(graph, starts, m) {
    const w = new Float32Array(graph.count), h = new Float32Array(graph.count);
    for (let node = 0; node < graph.count; node += 1) {
      let chars = 0;
      const first = graph.firstRow[node], last = first + graph.rowCount[node];
      for (let row = first; row < last; row += 1) {
        // Matches the drawn row: offset, mnemonic padded to ten, then operands.
        const start = starts[row], end = starts[row + 1] - 1;
        let a = start; while (a < end && graph.rows.charCodeAt(a) !== 32) a += 1;
        let b = a + 1; while (b < end && graph.rows.charCodeAt(b) !== 32) b += 1;
        const mnemonic = Math.max(0, b - a - 1), rest = Math.max(0, end - b - 1);
        chars = Math.max(chars, (a - start) + 1 + (rest ? Math.max(mnemonic, 10) + 1 + rest : mnemonic));
      }
      const label = 9 + Math.ceil(Math.log10(Math.max(graph.offsets[node], 1) + 1));
      w[node] = Math.max(m.minW, Math.ceil(Math.min(chars, MAX_ROW_CHARS) * m.charW + m.padX * 2), Math.ceil(label * m.charW + 44));
      h[node] = m.headerH + m.padY * 2 + Math.max(1, graph.rowCount[node]) * m.rowH;
    }
    return {w, h};
  }

  function csr(count, pairs) {
    const start = new Int32Array(count + 2);
    for (const [from] of pairs) start[from + 1] += 1;
    for (let i = 0; i < count + 1; i += 1) start[i + 1] += start[i];
    const fill = start.slice(), list = new Int32Array(pairs.length);
    for (const [from, to] of pairs) list[fill[from]++] = to;
    return {start, list};
  }

  /** Lays out one graph. Returns typed node boxes and stitched edge polylines. */
  function layoutGraph(graph, sizes, metrics) {
    const m = {...METRICS, ...metrics};
    const n = graph.count, edgeCount = graph.from.length;
    if (!n) return {x: new Float32Array(0), y: new Float32Array(0), w: new Float32Array(0), h: new Float32Array(0), pointStart: new Uint32Array(1), points: new Float32Array(0), box: new Float32Array(0), back: new Uint8Array(0), width: 0, height: 0};
    const V = n;
    const out = csr(n, Array.from({length: edgeCount}, (_, e) => [graph.from[e], e]));
    const succ = (node, each) => { for (let i = out.start[node]; i < out.start[node + 1]; i += 1) each(out.list[i]); };
    const back = new Uint8Array(edgeCount);
    // Iterative DFS classifies retreat edges; reversed post-order is a
    // topological order of what remains, so one dominator pass is exact.
    const color = new Uint8Array(n + 1), postorder = [], roots = [];
    const dfs = root => {
      roots.push(root); color[root] = 1;
      const stack = [[root, out.start[root]]];
      while (stack.length) {
        const top = stack[stack.length - 1], node = top[0];
        if (top[1] < out.start[node + 1]) {
          const edge = out.list[top[1]++], target = graph.to[edge];
          if (target < 0) continue;
          if (color[target] === 1) back[edge] = 1;
          else if (color[target] === 0) { color[target] = 1; stack.push([target, out.start[target]]); }
        } else { color[node] = 2; postorder.push(node); stack.pop(); }
      }
    };
    for (const root of graph.roots ?? [0]) if (root >= 0 && root < n && !color[root]) dfs(root);
    for (let node = 0; node < n; node += 1) if (!color[node]) dfs(node);
    const order = postorder.reverse(), pos = new Int32Array(n + 1);
    pos[V] = 0;
    order.forEach((node, index) => { pos[node] = index + 1; });
    const preds = csr(n, Array.from({length: edgeCount}, (_, e) => [graph.to[e] < 0 ? -1 : graph.to[e], e]).filter(([to, e]) => to >= 0 && !back[e]).map(([to, e]) => [to, graph.from[e]]));
    const idom = new Int32Array(n + 1).fill(-1); idom[V] = V;
    const isRoot = new Uint8Array(n); for (const root of roots) isRoot[root] = 1;
    const intersect = (a, b) => {
      while (a !== b) {
        while (pos[a] > pos[b]) a = idom[a];
        while (pos[b] > pos[a]) b = idom[b];
      }
      return a;
    };
    for (const node of order) {
      let current = -1;
      for (let i = preds.start[node]; i < preds.start[node + 1]; i += 1) {
        const p = preds.list[i];
        current = current < 0 ? p : intersect(current, p);
      }
      if (isRoot[node]) current = current < 0 ? V : intersect(current, V);
      idom[node] = current < 0 ? V : current;
    }
    const kidPairs = [];
    for (let node = 0; node < n; node += 1) kidPairs.push([idom[node], node]);
    const kids = csr(n, kidPairs);
    const tin = new Int32Array(n + 1), tout = new Int32Array(n + 1);
    {
      let clock = 0;
      const stack = [[V, kids.start[V]]]; tin[V] = clock++;
      while (stack.length) {
        const top = stack[stack.length - 1], node = top[0];
        if (top[1] < kids.start[node + 1]) { const child = kids.list[top[1]++]; tin[child] = clock++; stack.push([child, kids.start[child]]); }
        else { tout[node] = clock; stack.pop(); }
      }
    }
    const dominates = (a, b) => tin[a] <= tin[b] && tout[b] <= tout[a];
    const childContaining = (parent, node) => {
      let low = kids.start[parent], high = kids.start[parent + 1] - 1;
      while (low < high) {
        const mid = (low + high + 1) >> 1;
        if (tin[kids.list[mid]] <= tin[node]) low = mid; else high = mid - 1;
      }
      return kids.list[low];
    };
    // Sibling precedence collapses each child's subtree to one layer member.
    const hPairs = [];
    for (let e = 0; e < edgeCount; e += 1) {
      if (graph.to[e] < 0 || back[e]) continue;
      const parent = idom[graph.to[e]], source = graph.from[e];
      if (source !== parent && parent !== V) hPairs.push([graph.to[e], childContaining(parent, source)]);
    }
    const hPreds = csr(n, hPairs);
    const layerOf = new Int32Array(n);
    const layersOf = parent => {
      const members = Array.from(kids.list.subarray(kids.start[parent], kids.start[parent + 1])).sort((a, b) => pos[a] - pos[b]);
      if (!members.length) return [];
      const layers = [];
      for (const child of members) {
        let layer = 0;
        for (let i = hPreds.start[child]; i < hPreds.start[child + 1]; i += 1) layer = Math.max(layer, layerOf[hPreds.list[i]] + 1);
        layerOf[child] = layer;
        (layers[layer] ??= []).push(child);
      }
      const shaped = [];
      for (const layer of layers) {
        if (layer.length < 2) { shaped.push(layer); continue; }
        layer.sort((a, b) => a - b);
        const terminal = layer.filter(child => exits[child] === 0), others = layer.filter(child => exits[child] !== 0);
        if (!terminal.length || terminal.length > 3 && !others.length) { shaped.push(layer); continue; }
        if (terminal.length <= 3) for (const child of terminal) shaped.push([child]); else shaped.push(terminal);
        if (others.length) shaped.push(others);
      }
      return shaped;
    };
    // Edges leaving each child's subtree, in O(n + E): +1 at the source, -1 at
    // the edge's lowest common dominator, summed up each subtree. A terminal
    // arm (an early return) has no way out, so it stacks on the spine instead
    // of widening every enclosing row into a staircase.
    const diff = new Int32Array(n + 1);
    for (let e = 0; e < edgeCount; e += 1) {
      const source = graph.from[e], target = graph.to[e];
      if (target < 0) continue;
      diff[source] += 1;
      diff[back[e] ? (dominates(target, source) ? target : intersect(source, target)) : idom[target]] -= 1;
    }
    const exits = new Int32Array(n + 1);
    for (let index = order.length - 1; index >= 0; index -= 1) {
      const node = order[index];
      exits[node] += diff[node];
      if (idom[node] !== V) exits[idom[node]] += exits[node];
    }
    const stackedRoots = Boolean(graph.stackedRoots);
    const virtualLayers = () => {
      const members = Array.from(kids.list.subarray(kids.start[V], kids.start[V + 1]));
      const entry = members.indexOf(graph.roots?.[0] ?? 0);
      const first = entry >= 0 ? members.splice(entry, 1)[0] : members.shift();
      if (stackedRoots) return [first, ...members].filter(item => item !== undefined).map(item => [item]);
      return members.length ? [[first], members] : [[first]];
    };

    const boxes = [], nodeBox = new Int32Array(n).fill(-1), nodeRow = new Int32Array(n), nodeItem = new Int32Array(n);
    const makeBox = (root, parent, parentRow, parentItem) => {
      const box = {id: boxes.length, root, rows: [], parent, parentRow, parentItem, routes: new Map(), left: 0, right: 0, gaps: [], w: 0, h: 0, x: 0, y: 0, cx: 0};
      boxes.push(box); return box;
    };
    const pending = [makeBox(V, -1, 0, 0)];
    while (pending.length) {
      const box = pending.pop();
      const stack = [];
      const place = node => {
        box.rows.push({items: [{node}]});
        nodeBox[node] = box.id; nodeRow[node] = box.rows.length - 1; nodeItem[node] = 0;
        stack.push({layers: layersOf(node), next: 0});
      };
      if (box.root === V) stack.push({layers: virtualLayers(), next: 0}); else place(box.root);
      while (stack.length) {
        const top = stack[stack.length - 1];
        if (top.next >= top.layers.length) { stack.pop(); continue; }
        const layer = top.layers[top.next++];
        if (layer.length === 1) { place(layer[0]); continue; }
        // Every member of a layer is independent of the others, so wrapping
        // one wide layer never reorders an edge. A dispatcher's arms land here.
        const columns = layer.length > WRAP_AT ? Math.max(2, Math.ceil(Math.sqrt(layer.length) * 1.15)) : layer.length;
        const group = box.rows.length;
        for (let start = 0; start < layer.length; start += columns) {
          const row = {items: [], group};
          box.rows.push(row);
          layer.slice(start, start + columns).forEach((child, itemIndex) => {
            const sub = makeBox(child, box.id, box.rows.length - 1, itemIndex);
            row.items.push({box: sub.id}); pending.push(sub);
          });
        }
      }
    }

    // Routes are per-box pieces shared by every edge taking the same path, so
    // a fan of edges is drawn from one set of segments, not one per edge.
    const edgeRoutes = new Array(edgeCount);
    const portOf = kind => kind === KIND.taken ? -1 : kind === KIND.not_taken ? 1 : 0;
    const route = (box, row, item, port, destKey, dest) => {
      const key = `${row}:${item}:${port}:${destKey}`;
      let found = box.routes.get(key);
      if (!found) { found = {key, box, row, item, port, destKey, dest, gapFrom: row + 1, gapTo: -1, rail: -1, side: 0}; box.routes.set(key, found); }
      return found;
    };
    let direct = 0;
    for (let e = 0; e < edgeCount; e += 1) {
      const from = graph.from[e], to = graph.to[e];
      if (to < 0) continue;
      const retreat = back[e];
      if (retreat && !dominates(to, from)) { edgeRoutes[e] = null; direct += 1; continue; }
      const targetBox = nodeBox[to], rooted = !retreat && boxes[targetBox].root === to && boxes[targetBox].parent >= 0;
      const destBox = rooted ? boxes[targetBox].parent : targetBox;
      const list = [];
      let cur = nodeBox[from], row = nodeRow[from], item = nodeItem[from], port = portOf(graph.kind[e]);
      while (cur !== destBox && cur >= 0) {
        list.push(route(boxes[cur], row, item, port, retreat ? 'B' : 'T', {type: retreat ? 'bottomBack' : 'bottom'}));
        const box = boxes[cur];
        row = box.parentRow; item = box.parentItem; cur = box.parent; port = 0;
      }
      if (cur < 0) { edgeRoutes[e] = null; direct += 1; continue; }
      const dest = retreat ? {type: 'rail', node: to} : rooted ? {type: 'sub', box: targetBox} : {type: 'node', node: to};
      list.push(route(boxes[cur], row, item, port, retreat ? `r${to}` : rooted ? `b${targetBox}` : `n${to}`, dest));
      edgeRoutes[e] = list;
    }

    // Lanes. A gap belongs to the row beneath it; gap R is below the last row.
    for (const box of boxes) {
      const gapCount = box.rows.length + 1;
      box.gaps = Array.from({length: gapCount}, () => new Map());
      const groups = new Map();
      const counted = (kind, gap, key) => {
        const id = `${kind}${gap}:${key}`;
        groups.set(id, (groups.get(id) ?? 0) + 1);
      };
      const destRow = r => r.dest.type === 'bottom' || r.dest.type === 'bottomBack' ? box.rows.length
        : r.dest.type === 'sub' ? boxes[r.dest.box].parentRow : nodeRow[r.dest.node];
      const routes = [...box.routes.values()];
      for (const r of routes) {
        const target = destRow(r);
        r.gapTo = target; r.destRow = target;
        r.far = r.dest.type === 'rail' || target > r.gapFrom;
        counted('s', r.gapFrom, `${r.row}:${r.item}:${r.port}`); counted('d', r.gapFrom, r.destKey);
        if (r.far && r.dest.type !== 'rail') { counted('s', r.gapTo, `${r.row}:${r.item}:${r.port}`); counted('d', r.gapTo, r.destKey); }
      }
      const laneKey = (r, gap) => {
        const source = `${r.row}:${r.item}:${r.port}`;
        return (groups.get(`s${gap}:${source}`) ?? 0) >= (groups.get(`d${gap}:${r.destKey}`) ?? 0) ? `s${source}` : `d${r.destKey}`;
      };
      const lane = (map, key) => { let index = map.get(key); if (index === undefined) { index = map.size; map.set(key, index); } return index; };
      for (const r of routes) {
        r.laneFrom = lane(box.gaps[r.gapFrom], laneKey(r, r.gapFrom));
        if (r.far && r.dest.type !== 'rail') r.laneTo = lane(box.gaps[r.gapTo], laneKey(r, r.gapTo));
      }
      // Rails are colored like intervals: a rail only needs its own column
      // while its rows overlap another's, so a long guard chain stays narrow.
      // A fan-out shares one feeder rail per source; a fan-in, such as every
      // exit to a box's bottom port, shares one rail per destination.
      const farSources = new Map(), farDests = new Map();
      for (const r of routes) {
        if (!r.far || r.dest.type === 'rail') continue;
        const source = `${r.row}:${r.item}:${r.port}`;
        farSources.set(source, (farSources.get(source) ?? 0) + 1); farDests.set(r.destKey, (farDests.get(r.destKey) ?? 0) + 1);
      }
      const railKey = r => {
        if (r.dest.type === 'rail') return r.destKey;
        const source = `${r.row}:${r.item}:${r.port}`;
        return (farSources.get(source) ?? 0) > (farDests.get(r.destKey) ?? 0) ? `s${source}` : `d${r.destKey}`;
      };
      const colorRails = (side, spanOf) => {
        const spans = new Map();
        for (const r of routes) {
          if (r.side !== side) continue;
          const key = railKey(r), span = spanOf(r);
          const known = spans.get(key);
          if (known) { known.low = Math.min(known.low, span.low); known.high = Math.max(known.high, span.high); known.routes.push(r); }
          else spans.set(key, {low: span.low, high: span.high, routes: [r]});
        }
        const ends = [];
        for (const span of [...spans.values()].sort((a, b) => a.low - b.low || a.high - b.high)) {
          let column = ends.findIndex(end => end < span.low);
          if (column < 0) { column = ends.length; ends.push(span.high); } else ends[column] = span.high;
          for (const r of span.routes) r.rail = column;
        }
        return ends.length;
      };
      for (const r of routes) r.side = r.dest.type === 'rail' ? -1 : r.far ? 1 : 0;
      box.hasForwardExit = routes.some(r => r.dest.type === 'bottom');
      box.left = colorRails(-1, r => ({low: Math.min(r.destRow, r.gapFrom), high: Math.max(r.destRow, r.gapFrom)}));
      box.right = colorRails(1, r => ({low: r.gapFrom, high: r.gapTo}));
    }
    const gapHeight = (box, g) => {
      const lanes = box.gaps[g]?.size ?? 0;
      // An edge-free gap still separates rows, such as observed runs and gaps.
      if (!lanes) return g > 0 && g < box.rows.length ? m.gapY : 0;
      return Math.max(m.gapY, 16 + lanes * m.lane + 12);
    };

    // Sizes bottom-up: a box's children appear later in `boxes`, so a reverse
    // walk sizes every child first.
    const nodeW = sizes.w, nodeH = sizes.h;
    for (let index = boxes.length - 1; index >= 0; index -= 1) {
      const box = boxes[index];
      const columnWidths = new Map();
      for (const row of box.rows) {
        if (row.group === undefined) continue;
        const widths = columnWidths.get(row.group) ?? [];
        row.items.forEach((item, column) => { widths[column] = Math.max(widths[column] ?? 0, boxes[item.box].w); });
        columnWidths.set(row.group, widths);
      }
      const itemWidth = item => item.node !== undefined ? nodeW[item.node] : boxes[item.box].w;
      const itemHeight = item => item.node !== undefined ? nodeH[item.node] : boxes[item.box].h;
      let contentW = 0;
      for (const row of box.rows) {
        const widths = row.group !== undefined ? columnWidths.get(row.group) : null;
        row.w = row.items.reduce((sum, item, column) => sum + (widths ? widths[column] : itemWidth(item)), 0) + m.gapX * (row.items.length - 1);
        row.widths = widths;
        contentW = Math.max(contentW, row.w);
      }
      const leftW = box.left ? box.left * m.lane + m.side * 2 : 0;
      const rightW = box.right ? box.right * m.lane + m.side * 2 : 0;
      box.w = contentW + leftW + rightW;
      box.cx = leftW + contentW / 2;
      box.leftW = leftW; box.rightW = rightW; box.contentW = contentW;
      let y = 0;
      box.rows.forEach((row, index2) => {
        const gap = gapHeight(box, index2);
        y += gap; row.gapTop = y - gap; row.y = y; row.h = 0;
        let x = leftW + (contentW - row.w) / 2;
        row.items.forEach((item, column) => {
          const width = row.widths ? row.widths[column] : itemWidth(item);
          item.x = x + (width - itemWidth(item)) / 2; item.y = y;
          row.h = Math.max(row.h, itemHeight(item));
          x += width + m.gapX;
        });
        y += row.h;
      });
      box.bottomGapTop = y;
      y += gapHeight(box, box.rows.length);
      box.h = y;
    }
    const absX = new Float32Array(boxes.length), absY = new Float32Array(boxes.length);
    const root = boxes[0];
    absX[0] = m.margin; absY[0] = m.margin;
    const x = new Float32Array(n), y = new Float32Array(n);
    for (let index = 0; index < boxes.length; index += 1) {
      const box = boxes[index];
      for (const row of box.rows) {
        for (const item of row.items) {
          if (item.node !== undefined) { x[item.node] = absX[index] + item.x; y[item.node] = absY[index] + item.y; }
          else { absX[item.box] = absX[index] + item.x; absY[item.box] = absY[index] + item.y; }
        }
      }
    }

    // Polylines per route, then stitch per edge from innermost to outermost.
    const gapLaneY = (box, gapIndex, laneIndex) => {
      const top = gapIndex >= box.rows.length ? box.bottomGapTop : box.rows[gapIndex].gapTop;
      return absY[box.id] + top + 12 + laneIndex * m.lane;
    };
    // Back edges only get their own port when a forward exit shares this box.
    const bottomPort = (box, kind) => ({x: absX[box.id] + box.cx + (kind === 'back' && box.hasForwardExit ? -m.lane : 0), y: absY[box.id] + box.h});
    const destTop = dest => dest.type === 'sub'
      ? {x: x[boxes[dest.box].root] + nodeW[boxes[dest.box].root] / 2, y: y[boxes[dest.box].root]}
      : {x: x[dest.node] + nodeW[dest.node] / 2, y: y[dest.node]};
    const portOffset = (width, port) => port * Math.min(width / 4, 26);
    for (const box of boxes) {
      for (const r of box.routes.values()) {
        const row = box.rows[r.row], item = row.items[r.item];
        let sx, sy;
        if (item.node !== undefined) { sx = x[item.node] + nodeW[item.node] / 2 + portOffset(nodeW[item.node], r.port); sy = y[item.node] + nodeH[item.node]; }
        else {
          const sub = boxes[item.box], port = r.destKey === 'B' || r.dest.type === 'bottomBack' ? bottomPort(sub, 'back') : bottomPort(sub, 'exit');
          sx = port.x; sy = port.y;
        }
        const points = [sx, sy];
        const ly1 = gapLaneY(box, r.gapFrom, r.laneFrom);
        if (r.dest.type === 'rail') {
          const lx = absX[box.id] + m.side + r.rail * m.lane, node = r.dest.node;
          const hy = y[node] + Math.min(14, nodeH[node] / 2), hx = x[node];
          points.push(sx, ly1, lx, ly1, lx, hy, hx, hy);
        } else if (r.dest.type === 'bottom' || r.dest.type === 'bottomBack') {
          const port = bottomPort(box, r.dest.type === 'bottomBack' ? 'back' : 'exit');
          if (r.far) {
            const rx = absX[box.id] + box.w - m.side - r.rail * m.lane - 2, ly2 = gapLaneY(box, r.gapTo, r.laneTo);
            points.push(sx, ly1, rx, ly1, rx, ly2, port.x, ly2, port.x, port.y);
          } else points.push(sx, ly1, port.x, ly1, port.x, port.y);
        } else {
          const target = destTop(r.dest);
          if (r.far) {
            const rx = absX[box.id] + box.w - m.side - r.rail * m.lane - 2, ly2 = gapLaneY(box, r.gapTo, r.laneTo);
            points.push(sx, ly1, rx, ly1, rx, ly2, target.x, ly2, target.x, target.y);
          } else points.push(sx, ly1, target.x, ly1, target.x, target.y);
        }
        r.points = points;
      }
    }
    const stubCount = new Int32Array(n);
    const pointStart = new Uint32Array(edgeCount + 1);
    const flat = [];
    const box = new Float32Array(edgeCount * 4);
    let edgeAnchor = 0;
    const pushPoint = (px, py) => {
      const length = flat.length;
      if (length - edgeAnchor >= 2 && flat[length - 2] === px && flat[length - 1] === py) return;
      if (length - edgeAnchor >= 4) {
        const ax = flat[length - 4], ay = flat[length - 3], bx = flat[length - 2], by = flat[length - 1];
        if ((ax === bx && bx === px) || (ay === by && by === py)) { flat[length - 2] = px; flat[length - 1] = py; return; }
      }
      flat.push(px, py);
    };
    for (let e = 0; e < edgeCount; e += 1) {
      pointStart[e] = flat.length / 2;
      const from = graph.from[e], to = graph.to[e];
      const anchor = edgeAnchor = flat.length;
      if (to < 0) {
        const slot = stubCount[from]++;
        const sx = x[from] + nodeW[from] / 2 + (slot === 0 ? 0 : (slot % 2 ? 1 : -1) * Math.ceil(slot / 2) * 28);
        pushPoint(sx, y[from] + nodeH[from]); pushPoint(sx, y[from] + nodeH[from] + 18);
      } else {
        const list = edgeRoutes[e];
        if (!list) {
          pushPoint(x[from] + nodeW[from] / 2, y[from] + nodeH[from]);
          pushPoint(x[to] + nodeW[to] / 2, y[to]);
        } else {
          for (const piece of list) {
            const pts = piece.points;
            for (let i = 0; i < pts.length; i += 2) pushPoint(pts[i], pts[i + 1]);
          }
        }
      }
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      for (let i = anchor; i < flat.length; i += 2) {
        minX = Math.min(minX, flat[i]); maxX = Math.max(maxX, flat[i]); minY = Math.min(minY, flat[i + 1]); maxY = Math.max(maxY, flat[i + 1]);
      }
      box[e * 4] = minX; box[e * 4 + 1] = minY; box[e * 4 + 2] = maxX; box[e * 4 + 3] = maxY;
    }
    pointStart[edgeCount] = flat.length / 2;
    return {x, y, w: nodeW, h: nodeH, pointStart, points: Float32Array.from(flat), box, back,
      direct, width: root.w + m.margin * 2, height: root.h + m.margin * 2};
  }

  /** Worker entry: parses, normalizes and lays out, off the main thread. */
  function run(message) {
    const metrics = {...METRICS, ...message.metrics};
    let graph;
    if (message.type === 'wasm') graph = wasmGraph(JSON.parse(new TextDecoder().decode(message.buffer)));
    else if (message.type === 'graph') graph = message.graph;
    else throw Error('Unknown layout request.');
    const starts = rowStarts(graph.rows);
    const sizes = nodeSizes(graph, starts, metrics);
    const layout = layoutGraph(graph, sizes, metrics);
    return {graph, starts, layout};
  }

  /* Triskel, through graphLayoutClient, is a CFG layout engine built on
   * single-entry single-exit regions. When the backend serves it, it lays
   * out the function; the region layout above stays where the client says
   * why: Triskel would draw it much wider (a dispatcher's fan, which that
   * layout stacks into a grid) or taller, the function is past Triskel's
   * limits, or the route is missing or fails. */
  async function withTriskel(result, metrics) {
    const m = {...METRICS, ...metrics}, {graph, layout} = result, n = graph.count;
    const keep = reason => { layout.engine = {name: 'layered', reason}; return result; };
    if (n < 2) return keep({code: 'one_block'});
    const resolved = [];
    for (let e = 0; e < graph.from.length; e += 1) if (graph.to[e] >= 0) resolved.push(e);
    const {outcomes: [outcome], revision} = await graphLayoutClient.layOut([{nodes: Array.from({length: n}, (_, v) => [layout.w[v], layout.h[v]]),
      edges: resolved.map(e => [graph.from[e], graph.to[e]]), width: layout.width - m.margin * 2, height: layout.height - m.margin * 2}]);
    if (!outcome.result) return keep(outcome.reason);
    const laid = outcome.result, x = new Float32Array(n), y = new Float32Array(n);
    for (let v = 0; v < n; v += 1) { x[v] = m.margin + laid.nodes[v][0]; y[v] = m.margin + laid.nodes[v][1]; }
    const routeOf = new Map(resolved.map((e, i) => [e, laid.edges[i]]));
    const edgeCount = graph.from.length, pointStart = new Uint32Array(edgeCount + 1), flat = [], box = new Float32Array(edgeCount * 4), stubs = new Int32Array(n);
    let maxX = m.margin + laid.width, maxY = m.margin + laid.height;
    for (let e = 0; e < edgeCount; e += 1) {
      pointStart[e] = flat.length / 2;
      const anchor = flat.length, from = graph.from[e];
      if (graph.to[e] < 0) {
        // An edge with no resolved target keeps its stub under the block.
        const slot = stubs[from]++, sx = x[from] + layout.w[from] / 2 + (slot === 0 ? 0 : (slot % 2 ? 1 : -1) * Math.ceil(slot / 2) * 28);
        flat.push(sx, y[from] + layout.h[from], sx, y[from] + layout.h[from] + 18);
      } else flat.push(...graphLayoutClient.routePoints(routeOf.get(e), m.margin, m.margin));
      let minX = Infinity, minY = Infinity, hiX = -Infinity, hiY = -Infinity;
      for (let i = anchor; i < flat.length; i += 2) { minX = Math.min(minX, flat[i]); hiX = Math.max(hiX, flat[i]); minY = Math.min(minY, flat[i + 1]); hiY = Math.max(hiY, flat[i + 1]); }
      box[e * 4] = minX; box[e * 4 + 1] = minY; box[e * 4 + 2] = hiX; box[e * 4 + 3] = hiY;
      maxX = Math.max(maxX, hiX); maxY = Math.max(maxY, hiY);
    }
    pointStart[edgeCount] = flat.length / 2;
    result.layout = {...layout, x, y, pointStart, points: Float32Array.from(flat), box, direct: 0, width: maxX + m.margin, height: maxY + m.margin,
      engine: {name: 'triskel', revision}};
    return result;
  }
  async function runAsync(message) {
    const result = run(message);
    if (message.engine === 'triskel') return withTriskel(result, message.metrics);
    result.layout.engine = {name: 'layered', reason: {code: 'not_served'}};
    return result;
  }

  const transfer = ({graph, starts, layout}) => [graph.offsets, graph.ends, graph.firstRow, graph.rowCount, graph.instructionCount, graph.flags, graph.from, graph.to, graph.kind,
    starts, layout.x, layout.y, layout.w, layout.h, layout.pointStart, layout.points, layout.box, layout.back].map(array => array.buffer);

  return {METRICS, wasmGraph, rowStarts, nodeSizes, layoutGraph, runAsync, withTriskel, transfer};
})();

if (typeof module === 'object' && module?.exports) module.exports = blockGraphLayout;
else if (typeof importScripts === 'function') {
  importScripts('graph_layout_client.js');
  self.onmessage = async event => {
    try {
      const result = await blockGraphLayout.runAsync(event.data);
      self.postMessage({id: event.data.id, ok: true, result}, blockGraphLayout.transfer(result));
    } catch (error) {
      self.postMessage({id: event.data.id, ok: false, error: error?.message ?? 'Layout failed.'});
    }
  };
}
