/* Layout for the session flow graph. Runs off the main thread as a Web
 * Worker, and on the page where a shell cannot start one.
 *
 * Each realm is a band, drawn as a layered (Sugiyama) drawing that reads top
 * to bottom like a disassembler's CFG:
 *
 * - Layers. Cycles inside a realm (recursion, re-entrant handlers) are broken
 *   by a depth-first walk over its own calls. Cards are scheduled in
 *   depth-first order from the heaviest roots, each into the first layer
 *   under all its callers that has room, so a chain of calls stays a column.
 *   A layer holds about as many cards as makes the band square (never fewer
 *   than `wrap`); then a card with more callees than callers sinks toward
 *   them, and one with more callers rises, while a layer has room, which
 *   shortens the calls. A call into another realm never pushes a card down.
 * - Order. A call that passes layers is one segment item with a slot in
 *   every layer it passes (Eiglsperger, Siebenhaller and Kaufmann), so the
 *   order and placement cost grows with cards and calls, not with how far
 *   calls reach. Alternating barycentre sweeps keep each layer in an ordered
 *   tree; each sweep is followed by a transpose pass, and the order with the
 *   fewest crossings (counted with Barth, Jünger and Mutzel's accumulator)
 *   is kept.
 * - Placement. A band is bounded at `slack` over its widest layer. A call
 *   is placed as one node per layer it passes; joints are inserted where
 *   the rigid drawing's critical chains of separations pass the bound (jog
 *   insertion, as in VLSI layout compaction), within a fixed amount of work
 *   per node. Brandes and Köpf's four alignments are compacted under the
 *   bound and balanced, and each call is then joined into as few straight
 *   runs as its neighbours leave room for.
 * - Routes. Every call is orthogonal: down from a port on its caller's
 *   bottom, across the gap under the caller's row, down its segment, across
 *   the gap over its callee's row, and down into the callee's top. Each gap
 *   is a channel: every run in it gets a line of its own, so runs never
 *   share or touch a line and edges never merge, and the lines are ordered
 *   to avoid crossings. A gap grows to fit its lines. Back edges run up the
 *   band's right gutter, also one line each. No route crosses a card.
 *
 * Bands are packed into columns, in call order (callers first, an iframe
 * after its parent), toward the `aspect` the caller asks for. A call between
 * bands leaves its caller along the gap under its row to a corridor beside
 * the band, runs along the corridor (and along the highway over the columns
 * when it passes a column), and enters its callee along the gap over the
 * callee's row. Card sizes come from the caller. No dependency is linked. */
'use strict';

const flowGraphLayout = (() => {
  const METRICS = {nodeW: 220, nodeH: 34, gapX: 30, gapY: 64, segGap: 14, trackGap: 8, trackPad: 20, runGap: 24, laneGap: 56,
    lanePadX: 22, lanePadTop: 52, lanePadBottom: 26, margin: 40, top: 0, wrap: 5, bandAspect: 1, aspect: 1.6, portGap: 18, portInset: 14,
    gutter: 18, loop: 20, sweeps: 12, transpose: true, slack: 1, straighten: 3, jogWork: 16};
  /* Route point types: the segment that arrives at the point. A corner is
   * rounded toward the next point. */
  const MOVE = 0, CURVE = 1, LINE = 2, CORNER = 3;
  /* The far end of a run that leaves a band for a corridor, in band units. */
  const FAR = 1e7;
  const now = () => (typeof performance === 'object' ? performance.now() : Date.now());

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

  /** A binary min-heap of ids ordered by `less`. */
  function minHeap(less) {
    const items = [];
    const swap = (i, j) => { const t = items[i]; items[i] = items[j]; items[j] = t; };
    return {
      get size() { return items.length; },
      push(v) {
        items.push(v);
        for (let i = items.length - 1; i > 0;) { const p = (i - 1) >> 1; if (!less(items[i], items[p])) break; swap(i, p); i = p; }
      },
      pop() {
        const top = items[0], last = items.pop();
        if (items.length) {
          items[0] = last;
          for (let i = 0; ;) {
            const l = 2 * i + 1, r = l + 1;
            let s = i;
            if (l < items.length && less(items[l], items[s])) s = l;
            if (r < items.length && less(items[r], items[s])) s = r;
            if (s === i) break;
            swap(i, s); i = s;
          }
        }
        return top;
      },
    };
  }

  /* Fenwick trees over positions 0..n-1, in Int32Arrays of n + 1. */
  const fenAdd = (tree, n, i, d) => { for (i += 1; i <= n; i += i & -i) tree[i] += d; };
  const fenSum = (tree, i) => { let s = 0; for (i += 1; i > 0; i -= i & -i) s += tree[i]; return s; };
  const fenRange = (tree, lo, hi) => (hi < lo ? 0 : fenSum(tree, hi) - (lo > 0 ? fenSum(tree, lo - 1) : 0));
  /** The position of the k-th (from 1) counted position. */
  function fenSelect(tree, n, k) {
    let pos = 0;
    for (let mask = 1 << (31 - Math.clz32(Math.max(1, n))); mask; mask >>= 1) {
      const next = pos + mask;
      if (next <= n && tree[next] < k) { pos = next; k -= tree[next]; }
    }
    return pos;
  }

  // Layers -------------------------------------------------------------------

  /** Cards per layer in each band: as many as make the band `bandAspect`
   * wide for its height once card sizes and gaps count, and at least `wrap`. */
  function layerCaps(graph, w, h, m) {
    const sums = new Map();
    for (let v = 0; v < graph.count; v += 1) {
      const key = graph.lane[v];
      let sum = sums.get(key);
      if (!sum) sums.set(key, sum = {n: 0, w: 0, h: 0});
      sum.n += 1; sum.w += w[v]; sum.h += h[v];
    }
    const caps = new Map();
    for (const [key, sum] of sums) {
      const row = sum.h / sum.n + m.gapY, column = sum.w / sum.n + m.gapX;
      caps.set(key, Math.max(m.wrap, Math.round(Math.sqrt(sum.n * row * m.bandAspect / column))));
    }
    return caps;
  }

  /** Each card's layer in its band, from the calls inside its realm. */
  function layerCards(graph, w, h, m) {
    const {count, from, to, lane} = graph;
    const intra = [];
    for (let e = 0; e < from.length; e += 1) if (lane[from[e]] === lane[to[e]]) intra.push(e);
    const F = Int32Array.from(intra, e => from[e]), T = Int32Array.from(intra, e => to[e]);
    const adj = adjacency(count, F, T), back = backEdges(count, F, T, adj, graph.weight);
    const waiting = new Uint32Array(count);
    for (let i = 0; i < F.length; i += 1) if (!back[i]) waiting[T[i]] += 1;
    // Depth-first preorder from the heaviest roots: the scheduling priority.
    const pre = new Int32Array(count).fill(-1), stack = [], roots = [];
    let next = 0;
    for (let v = 0; v < count; v += 1) if (!waiting[v]) roots.push(v);
    roots.sort((a, b) => (graph.weight?.[b] ?? 0) - (graph.weight?.[a] ?? 0) || a - b);
    for (const root of roots) {
      stack.push(root);
      while (stack.length) {
        const v = stack.pop();
        if (pre[v] >= 0) continue;
        pre[v] = next++;
        for (let k = adj.outStart[v + 1]; k > adj.outStart[v]; k -= 1) { const i = adj.outEdges[k - 1]; if (!back[i] && pre[T[i]] < 0) stack.push(T[i]); }
      }
    }
    const caps = layerCaps(graph, w, h, m), fill = new Map([...caps.keys()].map(key => [key, []]));
    const used = (key, l) => fill.get(key)[l] ?? 0;
    const add = (key, l, d) => { const list = fill.get(key); list[l] = (list[l] ?? 0) + d; };
    const layer = new Int32Array(count), topo = new Int32Array(count), ready = minHeap((a, b) => pre[a] < pre[b]);
    for (const root of roots) ready.push(root);
    let placed = 0;
    while (ready.size) {
      const v = ready.pop(), key = lane[v], cap = caps.get(key);
      topo[placed++] = v;
      let lo = 0;
      for (let k = adj.inStart[v]; k < adj.inStart[v + 1]; k += 1) { const i = adj.inEdges[k]; if (!back[i]) lo = Math.max(lo, layer[F[i]] + 1); }
      while (used(key, lo) >= cap) lo += 1;
      layer[v] = lo; add(key, lo, 1);
      for (let k = adj.outStart[v]; k < adj.outStart[v + 1]; k += 1) { const i = adj.outEdges[k]; if (!back[i] && --waiting[T[i]] === 0) ready.push(T[i]); }
    }
    // Moves that shorten calls: a card sinks as far toward its callees as a
    // layer has room when it has more of them than callers (each layer it
    // moves shortens its calls out more than it lengthens its calls in), and
    // rises toward its callers in the opposite case.
    for (let pass = 0; pass < 4; pass += 1) {
      let moved = 0;
      for (let i = count - 1; i >= 0; i -= 1) {
        const v = topo[i], key = lane[v];
        let callers = 0, callees = 0, hi = Infinity;
        for (let k = adj.inStart[v]; k < adj.inStart[v + 1]; k += 1) if (!back[adj.inEdges[k]]) callers += 1;
        for (let k = adj.outStart[v]; k < adj.outStart[v + 1]; k += 1) { const e = adj.outEdges[k]; if (!back[e]) { callees += 1; hi = Math.min(hi, layer[T[e]] - 1); } }
        if (callees <= callers || hi === Infinity || hi <= layer[v]) continue;
        for (let l = hi; l > layer[v]; l -= 1) if (used(key, l) < caps.get(key)) { add(key, layer[v], -1); layer[v] = l; add(key, l, 1); moved += 1; break; }
      }
      for (let i = 0; i < count; i += 1) {
        const v = topo[i], key = lane[v];
        let callers = 0, callees = 0, lo = 0;
        for (let k = adj.inStart[v]; k < adj.inStart[v + 1]; k += 1) { const e = adj.inEdges[k]; if (!back[e]) { callers += 1; lo = Math.max(lo, layer[F[e]] + 1); } }
        for (let k = adj.outStart[v]; k < adj.outStart[v + 1]; k += 1) if (!back[adj.outEdges[k]]) callees += 1;
        if (callers <= callees || lo >= layer[v]) continue;
        for (let l = lo; l < layer[v]; l += 1) if (used(key, l) < caps.get(key)) { add(key, layer[v], -1); layer[v] = l; add(key, l, 1); moved += 1; break; }
      }
      if (!moved) break;
    }
    // A layer the moves emptied closes up.
    for (const [key, list] of fill) {
      const remap = [];
      let k = 0;
      for (let l = 0; l < list.length; l += 1) { remap[l] = k; if (list[l] > 0) k += 1; }
      fill.set(key, remap);
    }
    for (let v = 0; v < count; v += 1) layer[v] = fill.get(lane[v])[layer[v]];
    return layer;
  }

  /** Bands top to bottom: realms that call into each other sit together,
   * callers above the realms they call or post into (an iframe below its
   * parent), the busiest connected group first, then shallower first. */
  function laneOrder(count, graph, from, to, layer) {
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
      if (!laneOut.get(a).has(b)) { laneOut.get(a).add(b); laneIn.set(b, laneIn.get(b) + 1); }
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

  // Items --------------------------------------------------------------------

  /* Edge kinds: a call one layer down, a call passing layers (a segment), a
   * call back up the band (its gutter), a self call, a call between bands. */
  const SHORT = 0, LONG = 1, BACK = 2, LOOP = 3, CROSS = 4;

  /**
   * The items to order and place: cards 0..count-1, then one segment per
   * call that passes a layer, spanning layers first..last. Item edges join
   * an item to the one under it: a short call's two cards, and a long call's
   * caller to its segment and its segment to its callee. Each band lists
   * its items by layer.
   */
  function buildItems(graph, w, h, layer, keys, m) {
    const {count, from, to} = graph, edges = from.length;
    const bandIndex = new Map(keys.map((key, band) => [key, band]));
    const bandOf = Int32Array.from({length: count}, (_, v) => bandIndex.get(graph.lane[v]));
    const kind = new Uint8Array(edges), segOf = new Int32Array(edges).fill(-1);
    let segments = 0, itemEdges = 0;
    for (let e = 0; e < edges; e += 1) {
      const a = from[e], b = to[e];
      if (bandOf[a] !== bandOf[b]) kind[e] = CROSS;
      else if (a === b) kind[e] = LOOP;
      else if (layer[b] <= layer[a]) kind[e] = BACK;
      else if (layer[b] - layer[a] === 1) { kind[e] = SHORT; itemEdges += 1; }
      else { kind[e] = LONG; segOf[e] = count + segments++; itemEdges += 2; }
    }
    const total = count + segments;
    const first = new Int32Array(total), last = new Int32Array(total), itemBand = new Int32Array(total), segEdge = new Int32Array(segments);
    const left = new Float64Array(total), right = new Float64Array(total), isCard = new Uint8Array(total);
    const loops = new Uint32Array(count);
    for (let e = 0; e < edges; e += 1) if (kind[e] === LOOP) loops[from[e]] += 1;
    for (let v = 0; v < count; v += 1) {
      first[v] = last[v] = layer[v]; itemBand[v] = bandOf[v]; isCard[v] = 1;
      left[v] = w[v] / 2; right[v] = w[v] / 2 + (loops[v] ? m.loop + (loops[v] - 1) * m.trackGap + 4 : 0);
    }
    const upper = new Int32Array(itemEdges), lower = new Int32Array(itemEdges);
    let k = 0;
    for (let e = 0; e < edges; e += 1) {
      if (kind[e] === SHORT) { upper[k] = from[e]; lower[k] = to[e]; k += 1; }
      else if (kind[e] === LONG) {
        const s = segOf[e];
        segEdge[s - count] = e; first[s] = layer[from[e]] + 1; last[s] = layer[to[e]] - 1; itemBand[s] = bandOf[from[e]];
        upper[k] = from[e]; lower[k] = s; k += 1;
        upper[k] = s; lower[k] = to[e]; k += 1;
      }
    }
    // Item edges by the item under them (up) and over them (down).
    const upStart = new Int32Array(total + 1), downStart = new Int32Array(total + 1);
    for (let i = 0; i < itemEdges; i += 1) { upStart[lower[i] + 1] += 1; downStart[upper[i] + 1] += 1; }
    for (let v = 0; v < total; v += 1) { upStart[v + 1] += upStart[v]; downStart[v + 1] += downStart[v]; }
    const upList = new Int32Array(itemEdges), downList = new Int32Array(itemEdges);
    {
      const upFill = upStart.slice(0, total), downFill = downStart.slice(0, total);
      for (let i = 0; i < itemEdges; i += 1) { upList[upFill[lower[i]]++] = i; downList[downFill[upper[i]]++] = i; }
    }
    const bands = keys.map((key, index) => ({index, key, items: [], cards: [], L: 0, cardsAt: [], segFirstAt: [], segLastAt: [], enterDown: [], enterUp: [],
      forward: [], backs: [], loops: [], crossOut: [], crossIn: []}));
    for (let v = 0; v < count; v += 1) { const band = bands[bandOf[v]]; band.cards.push(v); band.L = Math.max(band.L, layer[v] + 1); }
    for (const band of bands) {
      for (let l = 0; l < band.L; l += 1) { band.cardsAt.push([]); band.segFirstAt.push([]); band.segLastAt.push([]); band.enterDown.push([]); band.enterUp.push([]); }
      for (const v of band.cards) { band.items.push(v); band.cardsAt[layer[v]].push(v); band.enterDown[layer[v]].push(v); band.enterUp[layer[v]].push(v); }
    }
    for (let s = count; s < total; s += 1) {
      const band = bands[itemBand[s]];
      band.items.push(s); band.segFirstAt[first[s]].push(s); band.segLastAt[last[s]].push(s); band.enterDown[first[s]].push(s); band.enterUp[last[s]].push(s);
    }
    for (let e = 0; e < edges; e += 1) {
      const band = bands[bandOf[from[e]]];
      if (kind[e] === CROSS) { band.crossOut.push(e); bands[bandOf[to[e]]].crossIn.push(e); }
      else if (kind[e] === LOOP) band.loops.push(e);
      else if (kind[e] === BACK) band.backs.push(e);
      else band.forward.push(e);
    }
    const localOf = new Int32Array(total);
    for (const band of bands) band.items.forEach((item, i) => { localOf[item] = i; });
    return {count, total, segments, edges, from, to, w, h, layer, bandOf, kind, segOf, segEdge, first, last, itemBand, left, right, isCard, loops,
      upper, lower, upStart, upList, downStart, downList, localOf, bands, gx: new Int32Array(total), x: new Float64Array(total)};
  }

  // Order --------------------------------------------------------------------

  /* An order-statistic treap over one layer's items, in order. Nodes are
   * item ids; a node knows its parent, so an item's position is a walk up.
   * Priorities come from a fixed generator, so a layout repeats exactly. */
  function treap(total) {
    const L = new Int32Array(total).fill(-1), R = new Int32Array(total).fill(-1), P = new Int32Array(total).fill(-1);
    const size = new Int32Array(total).fill(1), priority = new Uint32Array(total);
    let seed = 0x9e3779b9;
    for (let i = 0; i < total; i += 1) { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; priority[i] = seed >>> 0; }
    const sz = n => (n < 0 ? 0 : size[n]);
    const pull = n => { size[n] = 1 + sz(L[n]) + sz(R[n]); };
    function merge(a, b) {
      if (a < 0) return b;
      if (b < 0) return a;
      if (priority[a] > priority[b]) { const c = merge(R[a], b); R[a] = c; P[c] = a; pull(a); return a; }
      const c = merge(a, L[b]); L[b] = c; P[c] = b; pull(b); return b;
    }
    let splitLeft = -1, splitRight = -1;
    function split(n, k) {
      if (n < 0) { splitLeft = splitRight = -1; return; }
      if (k <= sz(L[n])) {
        split(L[n], k); L[n] = splitRight; if (splitRight >= 0) P[splitRight] = n; pull(n); splitRight = n;
      } else {
        split(R[n], k - sz(L[n]) - 1); R[n] = splitLeft; if (splitLeft >= 0) P[splitLeft] = n; pull(n); splitLeft = n;
      }
    }
    return {
      size: sz,
      rank(n) {
        let r = sz(L[n]);
        for (let c = n, p = P[n]; p >= 0; c = p, p = P[p]) if (R[p] === c) r += sz(L[p]) + 1;
        return r;
      },
      kth(root, k) {
        for (let n = root; ;) {
          const ls = sz(L[n]);
          if (k < ls) n = L[n];
          else if (k === ls) return n;
          else { k -= ls + 1; n = R[n]; }
        }
      },
      insert(root, n, k) {
        L[n] = R[n] = P[n] = -1; size[n] = 1;
        split(root, k);
        const a = splitLeft, b = splitRight;
        if (a >= 0) P[a] = -1;
        if (b >= 0) P[b] = -1;
        const joined = merge(merge(a, n), b);
        P[joined] = -1;
        return joined;
      },
      remove(root, n) {
        const c = merge(L[n], R[n]), p = P[n];
        if (c >= 0) P[c] = p;
        if (p >= 0) {
          if (L[p] === n) L[p] = c; else R[p] = c;
          for (let q = p; q >= 0; q = P[q]) pull(q);
        } else root = c;
        L[n] = R[n] = P[n] = -1; size[n] = 1;
        return root;
      },
    };
  }

  /** Each band's first order: depth-first discovery from the heaviest roots. */
  function discoveryOrder(I, band, weight) {
    const {gx, upStart, downStart, downList, lower, localOf} = I, n = band.items.length;
    const seen = new Uint8Array(n), stack = [];
    let next = 0;
    const visit = start => {
      stack.push(start);
      while (stack.length) {
        const v = stack.pop();
        if (seen[localOf[v]]) continue;
        seen[localOf[v]] = 1; gx[v] = next++;
        for (let k = downStart[v + 1]; k > downStart[v]; k -= 1) { const child = lower[downList[k - 1]]; if (!seen[localOf[child]]) stack.push(child); }
      }
    };
    const roots = band.items.filter(v => upStart[v + 1] === upStart[v]);
    roots.sort((a, b) => (weight?.[b] ?? 0) - (weight?.[a] ?? 0) || a - b);
    roots.forEach(visit);
    band.items.forEach(visit);
  }

  /**
   * One barycentre sweep over a band, down (each layer by the one above) or
   * up, after Eiglsperger, Siebenhaller and Kaufmann. The layer passed holds
   * its items in an ordered tree. Moving to the next layer, the items that
   * end there leave; a segment that goes on keeps its place and its order. A
   * new item's measure is the mean position of its neighbours in the layer
   * passed, and it goes in among the segments that go on by that measure.
   * The sweep writes the new order as one global order of the band's items,
   * gx, which every layer's order is a sub-sequence of.
   */
  function sweep(I, band, tree, down, scratch) {
    const {gx} = I, {L} = band;
    if (!L) return;
    const enter = down ? band.enterDown : band.enterUp, leave = down ? band.enterUp : band.enterDown;
    const nStart = down ? I.upStart : I.downStart, nList = down ? I.upList : I.downList, other = down ? I.upper : I.lower;
    const {pos, measure, slot, next, prev} = scratch;
    let head = -1, tail = -1, root = -1;
    const append = v => { prev[v] = tail; next[v] = -1; if (tail >= 0) next[tail] = v; else head = v; tail = v; };
    const before = (v, x) => { const p = prev[x]; prev[v] = p; next[v] = x; prev[x] = v; if (p >= 0) next[p] = v; else head = v; };
    const after = (v, x) => { const n = next[x]; next[v] = n; prev[v] = x; next[x] = v; if (n >= 0) prev[n] = v; else tail = v; };
    const byOld = (a, b) => gx[a] - gx[b];
    const step = down ? 1 : -1, start = down ? 0 : L - 1;
    for (const v of enter[start].slice().sort(byOld)) { root = tree.insert(root, v, tree.size(root)); append(v); }
    for (let l = start + step; l >= 0 && l < L; l += step) {
      const leaving = leave[l - step], news = enter[l].slice().sort(byOld);
      // Positions in the layer passed, before its leaving items go.
      const left = new Float64Array(leaving.length);
      leaving.forEach((u, i) => { pos[u] = tree.rank(u); left[i] = pos[u]; });
      left.sort();
      for (const v of news) {
        let sum = 0, d = 0;
        for (let k = nStart[v]; k < nStart[v + 1]; k += 1) { sum += pos[other[nList[k]]]; d += 1; }
        measure[v] = d ? sum / d : NaN;
      }
      // An item with no neighbour there stays beside the ones that were its
      // neighbours in the old order.
      let held = NaN;
      for (const v of news) { if (Number.isNaN(measure[v])) measure[v] = held; else held = measure[v]; }
      held = NaN;
      for (let i = news.length - 1; i >= 0; i -= 1) { const v = news[i]; if (Number.isNaN(measure[v])) measure[v] = held; else held = measure[v]; }
      // Its slot: how many segments that go on are before its measure.
      for (const v of news) {
        const value = measure[v];
        if (Number.isNaN(value) || value < 0) { slot[v] = 0; continue; }
        let lo = 0, hi = left.length;
        while (lo < hi) { const mid = (lo + hi) >> 1; if (left[mid] < value) lo = mid + 1; else hi = mid; }
        slot[v] = Math.ceil(value) - lo;
      }
      for (const u of leaving) root = tree.remove(root, u);
      news.sort((a, b) => slot[a] - slot[b] || measure[a] - measure[b] || gx[a] - gx[b]);
      const going = tree.size(root);
      let inserted = 0;
      for (let i = 0; i < news.length;) {
        const s = slot[news[i]];
        let j = i;
        while (j < news.length && slot[news[j]] === s) j += 1;
        // Where the run goes in the global order: before the segment that
        // follows it, or after the last segment, or at the end.
        const anchor = s < going ? tree.kth(root, s + inserted) : going ? tree.kth(root, going - 1 + inserted) : -1;
        let previous = anchor;
        for (let k = i; k < j; k += 1) {
          const v = news[k];
          root = tree.insert(root, v, s + inserted);
          inserted += 1;
          if (s < going) before(v, anchor);
          else if (anchor >= 0) { after(v, previous); previous = v; }
          else append(v);
        }
        i = j;
      }
    }
    let k = 0;
    for (let v = head; v >= 0; v = next[v]) gx[v] = k++;
  }

  /** The band's crossings under gx: for each two consecutive layers, the
   * inversions among the calls between them (Barth, Jünger and Mutzel's
   * accumulation over a Fenwick tree) and, for each such call, the segments
   * passing both layers between its two ends. */
  function crossings(I, band, scratch) {
    const {gx, upStart, upList, upper, first, last} = I, n = band.items.length, {L} = band;
    const passing = scratch.fenA, seen = scratch.fenB;
    passing.fill(0, 0, n + 1); seen.fill(0, 0, n + 1);
    let total = 0;
    for (let t = 1; t < L; t += 1) {
      for (const s of band.segFirstAt[t - 1]) if (last[s] >= t) fenAdd(passing, n, gx[s], 1);
      for (const s of band.segLastAt[t - 1]) if (first[s] < t - 1) fenAdd(passing, n, gx[s], -1);
      let count = 0;
      for (const v of band.enterDown[t]) count += upStart[v + 1] - upStart[v];
      if (!count) continue;
      const keys = count <= scratch.keys.length ? scratch.keys.subarray(0, count) : (scratch.keys = new Float64Array(count * 2)).subarray(0, count);
      let k = 0;
      for (const v of band.enterDown[t]) {
        const g = gx[v];
        for (let i = upStart[v]; i < upStart[v + 1]; i += 1) {
          const u = gx[upper[upList[i]]];
          keys[k++] = u * n + g;
          total += u < g ? fenRange(passing, u + 1, g - 1) : fenRange(passing, g + 1, u - 1);
        }
      }
      keys.sort();
      let added = 0;
      for (let i = 0; i < count; i += 1) {
        const g = keys[i] % n;
        total += added - fenSum(seen, g);
        fenAdd(seen, n, g, 1); added += 1;
      }
      for (let i = 0; i < count; i += 1) fenAdd(seen, n, keys[i] % n, -1);
    }
    return total;
  }

  /** Crossings between two items' calls up and down when a is left of b,
   * and when b is left of a. */
  function pairCrossings(I, a, b, out) {
    const {gx, upStart, upList, upper, downStart, downList, lower} = I;
    let ab = 0, ba = 0;
    const side = (start, list, end) => {
      for (let i = start[a]; i < start[a + 1]; i += 1) {
        const x = gx[end[list[i]]];
        for (let j = start[b]; j < start[b + 1]; j += 1) { const y = gx[end[list[j]]]; if (x > y) ab += 1; else if (x < y) ba += 1; }
      }
    };
    side(upStart, upList, upper);
    side(downStart, downList, lower);
    out[0] = ab; out[1] = ba;
  }

  /** Swaps side-by-side items that live in one layer while that removes
   * crossings with the layers above and below (the transpose step). Two
   * items are side by side when no other item of their layer, segments
   * included, is between them. */
  function transpose(I, band, scratch) {
    const {gx, first, last} = I, n = band.items.length, {L} = band, out = [0, 0];
    const passing = scratch.fenA;
    let swaps = 0;
    for (let round = 0; round < 8; round += 1) {
      let improved = false;
      passing.fill(0, 0, n + 1);
      for (let l = 0; l < L; l += 1) {
        if (l > 0) for (const s of band.segLastAt[l - 1]) if (first[s] < last[s]) fenAdd(passing, n, gx[s], -1);
        for (const s of band.segFirstAt[l]) if (first[s] < last[s]) fenAdd(passing, n, gx[s], 1);
        const row = band.cardsAt[l].slice();
        for (const s of band.segFirstAt[l]) if (first[s] === last[s]) row.push(s);
        row.sort((a, b) => gx[a] - gx[b]);
        for (let i = 0; i + 1 < row.length; i += 1) {
          const a = row[i], b = row[i + 1];
          if (gx[b] - gx[a] > 1 && fenRange(passing, gx[a] + 1, gx[b] - 1) > 0) continue;
          pairCrossings(I, a, b, out);
          if (out[0] <= out[1]) continue;
          const t = gx[a]; gx[a] = gx[b]; gx[b] = t;
          row[i] = b; row[i + 1] = a;
          improved = true; swaps += 1;
        }
      }
      if (!improved) break;
    }
    return swaps;
  }

  /** Sweeps down and up, each followed by a transpose pass, keeping the
   * order with the fewest crossings. */
  function orderBand(I, band, tree, scratch, weight, m) {
    const {gx} = I, {items} = band;
    discoveryOrder(I, band, weight);
    let best = crossings(I, band, scratch), sweeps = 0, swaps = 0, stale = 0;
    const kept = Int32Array.from(items, v => gx[v]);
    for (let i = 0; i < m.sweeps && best > 0; i += 1) {
      sweep(I, band, tree, i % 2 === 0, scratch);
      if (m.transpose) swaps += transpose(I, band, scratch);
      sweeps += 1;
      const found = crossings(I, band, scratch);
      if (found < best) { best = found; items.forEach((v, k) => { kept[k] = gx[v]; }); stale = 0; } else if (++stale >= 4) break;
    }
    items.forEach((v, k) => { gx[v] = kept[k]; });
    return {crossings: best, sweeps, swaps};
  }

  // Placement ----------------------------------------------------------------

  /**
   * Coordinates for one band. A call that passes layers is ordered as one
   * segment but placed as one node per layer it passes, so placement can
   * bend it where keeping it straight would push its neighbours sideways.
   * Kept straight everywhere, as Brandes and Köpf keep inner segments, the
   * calls of a busy band push each other into a staircase many times wider
   * than its widest layer; so the band gets a width bound, `slack` over its
   * widest layer, and each layer packed on its own says how far from the
   * band's near edge each of its nodes can go and still leave room for the
   * rest of the layer.
   *
   * Joints are found first (cutJoints), then Brandes and Köpf's four
   * alignments are compacted under the bound (alignPass) and balanced, and
   * each call is joined into as few straight runs as its neighbours leave
   * room for (straighten). Returns the band's width.
   */
  function placeBand(I, band, m) {
    if (!band.items.length) return 0;
    const P = placementNodes(I, band, m), T = P.widest * (1 + m.slack), {total} = P;
    const cut = cutJoints(band, P, T, m);
    const W = {root: new Int32Array(total), above: new Int32Array(total), below: new Int32Array(total), indegree: new Int32Array(total), order: new Int32Array(total),
      outStart: new Int32Array(total + 1), outTo: new Int32Array(total), fill: new Int32Array(total), members: new Int32Array(total), groupStart: new Int32Array(total + 1),
      x: new Float64Array(total)};
    const coords = [];
    for (let pass = 0; pass < 4; pass += 1) {
      const coord = new Float64Array(total);
      alignPass(I, band, P, cut.joint, T, pass < 2, pass % 2 === 0, W, coord);
      coords.push(coord);
    }
    band.rounds = cut.rounds; band.stopped = cut.stopped;
    return straighten(I, band, P, balance(P, coords), m);
  }

  /**
   * Placement nodes for one band: item i's nodes are spanAt[i] .. spanAt[i +
   * 1] - 1, one per layer from first[item]. Each layer lists its nodes in
   * position order, so a node has one neighbour on each side and keeps
   * sepLeft from the one on its left; head and tail are its distances from
   * the two ends of its layer packed tight. Also sorts each item's
   * neighbours by position, for medians, and marks the calls alignment
   * skips.
   */
  function placementNodes(I, band, m) {
    const {gx, upStart, upList, upper, downStart, downList, lower, first, last, left, right, isCard, marked} = I, {items, L} = band, n = items.length;
    const posOf = new Int32Array(n), localAt = new Int32Array(n);
    for (let i = 0; i < n; i += 1) { posOf[i] = gx[items[i]]; localAt[posOf[i]] = i; }
    const sortSlice = (start, list, end, v) => {
      const a = start[v], b = start[v + 1];
      if (b - a > 1) list.subarray(a, b).sort((p, q) => gx[end[p]] - gx[end[q]]);
    };
    for (const v of items) { sortSlice(upStart, upList, upper, v); sortSlice(downStart, downList, lower, v); }
    // Type 1 conflicts: a call that crosses a segment passing both its
    // layers is not aligned, so segments stay straight where they can.
    {
      const passing = new Int32Array(n + 1);
      for (let t = 1; t < L; t += 1) {
        for (const s of band.segFirstAt[t - 1]) if (last[s] >= t) fenAdd(passing, n, gx[s], 1);
        for (const s of band.segLastAt[t - 1]) if (first[s] < t - 1) fenAdd(passing, n, gx[s], -1);
        for (const v of band.enterDown[t]) for (let i = upStart[v]; i < upStart[v + 1]; i += 1) {
          const k = upList[i], u = gx[upper[k]], g = gx[v];
          if (fenRange(passing, Math.min(u, g) + 1, Math.max(u, g) - 1) > 0) marked[k] = 1;
        }
      }
    }
    const spanAt = new Int32Array(n + 1);
    for (let i = 0; i < n; i += 1) spanAt[i + 1] = spanAt[i] + last[items[i]] - first[items[i]] + 1;
    const total = spanAt[n];
    const owner = new Int32Array(total), layerOf = new Int32Array(total);
    for (let i = 0; i < n; i += 1) for (let k = spanAt[i], l = first[items[i]]; k < spanAt[i + 1]; k += 1, l += 1) { owner[k] = i; layerOf[k] = l; }
    const layerStart = new Int32Array(L + 1), layerList = new Int32Array(total);
    for (let i = 0; i < n; i += 1) { layerStart[first[items[i]] + 1] += 1; if (last[items[i]] + 2 <= L) layerStart[last[items[i]] + 2] -= 1; }
    for (let l = 1; l <= L; l += 1) layerStart[l] += layerStart[l - 1];
    for (let l = 0; l < L; l += 1) layerStart[l + 1] += layerStart[l];
    {
      const fill = layerStart.slice(0, L);
      for (let g = 0; g < n; g += 1) { const i = localAt[g]; for (let k = spanAt[i]; k < spanAt[i + 1]; k += 1) layerList[fill[layerOf[k]]++] = k; }
    }
    const leftOf = new Int32Array(total).fill(-1), rightOf = new Int32Array(total).fill(-1), sepLeft = new Float64Array(total);
    const lw = new Float64Array(total), rw = new Float64Array(total), head = new Float64Array(total), tail = new Float64Array(total);
    let widest = 0;
    for (let l = 0; l < L; l += 1) {
      const a = layerStart[l], b = layerStart[l + 1];
      let xs = 0;
      for (let k = a; k < b; k += 1) {
        const v = layerList[k], it = items[owner[v]];
        lw[v] = left[it]; rw[v] = right[it];
        if (k > a) {
          const u = layerList[k - 1], ut = items[owner[u]];
          leftOf[v] = u; rightOf[u] = v;
          sepLeft[v] = rw[u] + lw[v] + (isCard[ut] && isCard[it] ? m.gapX : isCard[ut] || isCard[it] ? m.segGap : m.trackGap);
          xs += sepLeft[v];
        } else xs = lw[v];
        head[v] = xs;
      }
      const width = b > a ? xs + rw[layerList[b - 1]] : 0;
      widest = Math.max(widest, width);
      for (let k = a; k < b; k += 1) tail[layerList[k]] = width - head[layerList[k]];
    }
    return {posOf, localAt, spanAt, total, owner, layerOf, layerStart, layerList, leftOf, rightOf, sepLeft, lw, rw, head, tail, widest};
  }

  /** How far left the rigid piece a .. e - 1 can sit, given the nodes on its
   * left; via[a] is the node whose left neighbour holds it there, or -1. */
  function leftmost(a, e, leftOf, sepLeft, lw, x, via) {
    let want = lw[a], from = -1;
    for (let k = a; k < e; k += 1) {
      const u = leftOf[k];
      if (u >= 0 && x[u] + sepLeft[k] > want) { want = x[u] + sepLeft[k]; from = k; }
    }
    via[a] = from;
    return want;
  }

  /**
   * Where each call may bend: joint[k] starts a new piece of its call at
   * node k. With nothing aligned and every piece rigid, every piece is
   * placed in position order as far left as its neighbours allow. Then,
   * while a layer ends past the bound, the chains of separations that put
   * those layer ends there are walked back, farthest first: a piece a chain
   * enters in one layer and leaves in another is what makes the chain
   * longer than any layer, so each such piece gets a joint between the two
   * layers, nearest the middle, and the pieces whose place that moves are
   * placed again, in position order. This is the jog insertion of symbolic
   * VLSI layout compaction.
   *
   * It stops when the rigid drawing fits, when no chain has a piece to
   * split, or after placing pieces of `jogWork` times the band's nodes in
   * all; a band stopped that way keeps the rest of its width rather than
   * taking time that grows with its depth. Returns {joint, rounds, stopped}.
   */
  function cutJoints(band, P, T, m) {
    const {L} = band, {posOf, localAt, spanAt, total, owner, layerOf, layerStart, layerList, leftOf, rightOf, sepLeft, lw, rw} = P, n = posOf.length;
    const joint = new Uint8Array(total), pieceOf = new Int32Array(total), pieceEnd = new Int32Array(total), via = new Int32Array(total);
    const queued = new Uint8Array(total), pending = new Uint8Array(n), bridges = new Int32Array(total), walked = new Uint8Array(total), x = new Float64Array(total);
    for (let i = 0; i < n; i += 1) {
      const a = spanAt[i], b = spanAt[i + 1];
      joint[a] = 1; pieceEnd[a] = b;
      for (let k = a; k < b; k += 1) pieceOf[k] = a;
    }
    for (let g = 0; g < n; g += 1) {
      const a = spanAt[localAt[g]], e = pieceEnd[a], want = leftmost(a, e, leftOf, sepLeft, lw, x, via);
      for (let k = a; k < e; k += 1) x[k] = want;
    }
    const budget = m.jogWork * total, ends = [];
    let rounds = 0, work = 0, fits = false;
    while (work <= budget) {
      ends.length = 0;
      for (let l = 0; l < L; l += 1) {
        if (layerStart[l + 1] === layerStart[l]) continue;
        const k = layerList[layerStart[l + 1] - 1];
        if (x[k] + rw[k] > T) ends.push(k);
      }
      if (!ends.length) { fits = true; break; }
      ends.sort((p, q) => x[q] + rw[q] - x[p] - rw[p]);
      let found = 0;
      for (const end of ends) for (let c = end; ;) {
        const piece = pieceOf[c], k = via[piece];
        if (k < 0 || walked[piece]) break;
        walked[piece] = 1;
        const lc = layerOf[c], lk = layerOf[k];
        if (lc !== lk) bridges[found++] = piece + Math.round((Math.min(lc, lk) + 1 + Math.max(lc, lk)) / 2) - layerOf[piece];
        c = leftOf[k];
      }
      for (const end of ends) for (let c = end; ;) {
        const piece = pieceOf[c], k = via[piece];
        if (!walked[piece]) break;
        walked[piece] = 0;
        if (k < 0) break;
        c = leftOf[k];
      }
      if (!found) break;
      rounds += 1;
      let from = n;
      for (let f = 0; f < found; f += 1) {
        const j = bridges[f], a = pieceOf[j], e = pieceEnd[a], g = posOf[owner[a]];
        joint[j] = 1; pieceEnd[a] = j; pieceEnd[j] = e;
        for (let k = j; k < e; k += 1) pieceOf[k] = j;
        queued[a] = 1; queued[j] = 1; pending[g] = 1;
        if (g < from) from = g;
      }
      // A piece moves only when a neighbour on its left did, and that
      // neighbour is earlier in position order.
      for (let g = from; g < n; g += 1) {
        if (!pending[g]) continue;
        pending[g] = 0;
        const i = localAt[g];
        for (let a = spanAt[i], b = spanAt[i + 1]; a < b; a = pieceEnd[a]) {
          if (!queued[a]) continue;
          queued[a] = 0;
          const e = pieceEnd[a], want = leftmost(a, e, leftOf, sepLeft, lw, x, via);
          work += e - a;
          if (want === x[a]) continue;
          for (let k = a; k < e; k += 1) {
            x[k] = want;
            const r = rightOf[k];
            if (r >= 0 && !queued[pieceOf[r]]) { queued[pieceOf[r]] = 1; pending[posOf[owner[r]]] = 1; }
          }
        }
      }
    }
    return {joint, rounds, stopped: !fits && work > budget};
  }

  /**
   * One of Brandes and Köpf's four alignments, `upward` to the median
   * neighbour above (else below) and `leftward` from the left (else the
   * right), never across a joint; compacted over its blocks in an order
   * where a block's near neighbours come first. A block sits as far toward
   * the near edge as they allow and, where that is past a member's limit
   * (the bound less the room the rest of its layer needs), it is cut there
   * into groups that fit, though never between two nodes of one piece. Each
   * group is then pulled toward its far neighbours where there is room.
   * Writes the centres into coord; W holds scratch arrays.
   */
  function alignPass(I, band, P, joint, T, upward, leftward, W, coord) {
    const {upStart, upList, upper, downStart, downList, lower, isCard, localOf, marked} = I, {items, L} = band;
    const {posOf, spanAt, total, owner, layerStart, layerList, leftOf, rightOf, sepLeft, lw, rw, head, tail} = P;
    const {root, above, below, indegree, order, outStart, outTo, fill, members, groupStart, x} = W, n = posOf.length;
    for (let v = 0; v < total; v += 1) { root[v] = v; above[v] = -1; below[v] = -1; }
    const start = upward ? upStart : downStart, list = upward ? upList : downList, end = upward ? upper : lower, step = leftward ? 1 : -1;
    for (let s = 0; s < L; s += 1) {
      const l = upward ? s : L - 1 - s, a0 = layerStart[l], a1 = layerStart[l + 1];
      let r = leftward ? -1 : n;
      for (let j = leftward ? a0 : a1 - 1; j >= a0 && j < a1; j += step) {
        const v = layerList[j], i = owner[v], it = items[i];
        let u = -1;
        if (!isCard[it] && (upward ? v > spanAt[i] : v < spanAt[i + 1] - 1)) {
          // The node above (or below) on its own call, unless a joint is
          // between them.
          const w = upward ? v - 1 : v + 1, g = posOf[i];
          if (!joint[upward ? v : w] && (leftward ? r < g : r > g)) u = w;
        } else {
          const a = start[it], d = start[it + 1] - a;
          if (!d) continue;
          const mLo = a + ((d - 1) >> 1), mHi = a + (d >> 1);
          for (let t = 0; t < 2; t += 1) {
            const k = list[leftward === (t === 0) ? mLo : mHi], far = end[k], f = localOf[far];
            // A card's neighbour is the far card, or the near end of a
            // segment.
            const w = upward && !isCard[far] ? spanAt[f + 1] - 1 : spanAt[f], g = posOf[f];
            if (!marked[k] && (leftward ? r < g : r > g)) { u = w; break; }
            if (mLo === mHi) break;
          }
        }
        if (u < 0) continue;
        root[v] = root[u]; r = posOf[owner[u]];
        if (upward) { above[v] = u; below[u] = v; } else { below[v] = u; above[u] = v; }
      }
    }
    // Blocks in an order where every block's near neighbours come first.
    const nearOf = leftward ? leftOf : rightOf, farOf = leftward ? rightOf : leftOf;
    outStart.fill(0); indegree.fill(0);
    for (let v = 0; v < total; v += 1) if (farOf[v] >= 0) { outStart[root[v] + 1] += 1; indegree[root[farOf[v]]] += 1; }
    for (let v = 0; v < total; v += 1) outStart[v + 1] += outStart[v];
    fill.set(outStart.subarray(0, total));
    for (let v = 0; v < total; v += 1) if (farOf[v] >= 0) outTo[fill[root[v]]++] = root[farOf[v]];
    let headAt = 0, blocks = 0;
    for (let v = 0; v < total; v += 1) if (root[v] === v && !indegree[v]) order[blocks++] = v;
    while (headAt < blocks) {
      const a = order[headAt++];
      for (let k = outStart[a]; k < outStart[a + 1]; k += 1) if (--indegree[outTo[k]] === 0) order[blocks++] = outTo[k];
    }
    // Compaction, each block top member down; x is measured from the near
    // edge, on the mirror image going right.
    const nearW = leftward ? lw : rw, limitW = leftward ? tail : head;
    let groups = 0, filled = 0;
    for (let b = 0; b < blocks; b += 1) {
      let top = order[b];
      while (above[top] >= 0) top = above[top];
      let first = filled, want = -Infinity, room = Infinity;
      for (let v = top; v >= 0; v = below[v]) {
        const near = nearOf[v], lim = T - limitW[v];
        const need = near >= 0 ? Math.max(nearW[v], x[near] + (leftward ? sepLeft[v] : sepLeft[near])) : nearW[v];
        if (filled > first && owner[above[v]] !== owner[v] && Math.max(want, need) > Math.min(room, lim)) {
          groupStart[groups++] = first;
          for (let k = first; k < filled; k += 1) x[members[k]] = want;
          first = filled; want = -Infinity; room = Infinity;
        }
        members[filled++] = v;
        if (need > want) want = need;
        if (lim < room) room = lim;
      }
      groupStart[groups++] = first;
      for (let k = first; k < filled; k += 1) x[members[k]] = want;
    }
    groupStart[groups] = filled;
    // Last placed first, so a group's far neighbours are already pulled.
    for (let gi = groups - 1; gi >= 0; gi -= 1) {
      let room = Infinity, any = false;
      for (let k = groupStart[gi]; k < groupStart[gi + 1]; k += 1) {
        const v = members[k], w = farOf[v];
        room = Math.min(room, T - limitW[v]);
        if (w >= 0) { any = true; room = Math.min(room, x[w] - (leftward ? sepLeft[w] : sepLeft[v])); }
      }
      if (any && room > x[members[groupStart[gi]]]) for (let k = groupStart[gi]; k < groupStart[gi + 1]; k += 1) x[members[k]] = room;
    }
    for (let v = 0; v < total; v += 1) coord[v] = leftward ? x[v] : T - x[v];
  }

  /** Brandes and Köpf's balance: the four alignments lined up on the
   * narrowest (left ones by their left edge, right ones by their right
   * edge), and each node at the mean of its two middle values, which keeps
   * every separation. */
  function balance(P, coords) {
    const {total, lw, rw} = P, low = new Float64Array(4), high = new Float64Array(4);
    let narrowest = 0;
    for (let p = 0; p < 4; p += 1) {
      const c = coords[p];
      let a = Infinity, b = -Infinity;
      for (let v = 0; v < total; v += 1) { if (c[v] - lw[v] < a) a = c[v] - lw[v]; if (c[v] + rw[v] > b) b = c[v] + rw[v]; }
      low[p] = a; high[p] = b;
      if (b - a < high[narrowest] - low[narrowest]) narrowest = p;
    }
    const [c0, c1, c2, c3] = coords, x = new Float64Array(total);
    const s0 = low[narrowest] - low[0], s1 = high[narrowest] - high[1], s2 = low[narrowest] - low[2], s3 = high[narrowest] - high[3];
    for (let v = 0; v < total; v += 1) {
      const a = c0[v] + s0, b = c1[v] + s1, c = c2[v] + s2, d = c3[v] + s3;
      // The middle two of four: the larger pair minimum and the smaller
      // pair maximum.
      x[v] = (Math.max(Math.min(a, b), Math.min(c, d)) + Math.min(Math.max(a, b), Math.max(c, d))) / 2;
    }
    return x;
  }

  /**
   * Each call joined into as few straight runs as its neighbours leave room
   * for: top down, a run goes on while some line fits every layer it passes
   * (the fewest stabbing points of the call's per-layer intervals), and
   * takes the line nearest the run above it (the caller's centre for the
   * first, the callee's for the last when it fits). `straighten` rounds,
   * since a call that straightens can free room for its neighbours. Writes
   * band-local centres (left edge 0) into I.x and each segment's runs into
   * I.pieceAt, pieceCount, pieceLo and pieceX, and returns the band's width.
   */
  function straighten(I, band, P, x, m) {
    const {upStart, upList, upper, downStart, downList, lower, isCard, localOf} = I, {items} = band, n = items.length;
    const {spanAt, total, layerOf, leftOf, rightOf, sepLeft, lw, rw} = P, rounds = Math.max(1, m.straighten);
    let minL = Infinity, maxR = -Infinity, jogs = 0;
    for (let v = 0; v < total; v += 1) { if (x[v] - lw[v] < minL) minL = x[v] - lw[v]; if (x[v] + rw[v] > maxR) maxR = x[v] + rw[v]; }
    for (let round = 0; round < rounds; round += 1) {
      const final = round === rounds - 1;
      for (let i = 0; i < n; i += 1) {
        const it = items[i];
        if (isCard[it]) continue;
        const a = spanAt[i], b = spanAt[i + 1], s = it - I.count;
        const caller = x[spanAt[localOf[upper[upList[upStart[it]]]]]], callee = x[spanAt[localOf[lower[downList[downStart[it]]]]]];
        if (final) I.pieceAt[s] = I.pieceX.length;
        let from = -Infinity, to = Infinity, startAt = a, anchor = caller;
        for (let k = a; k <= b; k += 1) {
          let lo = 0, hi = 0;
          if (k < b) {
            lo = leftOf[k] >= 0 ? x[leftOf[k]] + sepLeft[k] : minL + lw[k];
            hi = rightOf[k] >= 0 ? x[rightOf[k]] - sepLeft[rightOf[k]] : maxR - rw[k];
            if (k === a || Math.max(from, lo) <= Math.min(to, hi)) { from = Math.max(from, lo); to = Math.min(to, hi); continue; }
          }
          const line = k === b && callee >= from && callee <= to ? callee : Math.min(to, Math.max(from, anchor));
          for (let q = startAt; q < k; q += 1) x[q] = line;
          if (final) { I.pieceLo.push(layerOf[startAt]); I.pieceX.push(line - minL); }
          anchor = line; startAt = k; from = lo; to = hi;
        }
        if (final) { I.pieceCount[s] = I.pieceX.length - I.pieceAt[s]; jogs += I.pieceCount[s] - 1; }
      }
    }
    for (let i = 0; i < n; i += 1) { const it = items[i]; I.x[it] = isCard[it] ? x[spanAt[i]] - minL : I.pieceX[I.pieceAt[it - I.count]]; }
    band.jogs = jogs;
    return maxR - minL;
  }

  // Channels -----------------------------------------------------------------

  /** A growable set of horizontal runs: x1 < x2, the direction each end's
   * vertical leaves the run's line (-1 up, +1 down), whether an end is far
   * (in a corridor, so it meets no other end), the edge and which of its
   * runs it is. */
  function runSet() {
    let capacity = 64;
    const R = {length: 0};
    const fields = {x1: Float64Array, x2: Float64Array, key: Float64Array, d1: Int8Array, d2: Int8Array, far: Uint8Array, gap: Int32Array, edge: Int32Array, which: Uint8Array, track: Int32Array};
    for (const [name, Type] of Object.entries(fields)) R[name] = new Type(capacity);
    R.add = (gap, xa, da, xb, db, far, edge, which) => {
      if (R.length === capacity) {
        capacity *= 2;
        for (const [name, Type] of Object.entries(fields)) { const grown = new Type(capacity); grown.set(R[name]); R[name] = grown; }
      }
      const i = R.length++;
      const swap = xb < xa;
      R.x1[i] = swap ? xb : xa; R.x2[i] = swap ? xa : xb; R.d1[i] = swap ? db : da; R.d2[i] = swap ? da : db;
      R.far[i] = swap ? ((far & 1) << 1) | ((far & 2) >> 1) : far;
      R.gap[i] = gap; R.edge[i] = edge; R.which[i] = which;
      return i;
    };
    return R;
  }

  let treeMax = new Int32Array(0), treeLazy = new Int32Array(0);
  function treeQuery(node, l, r, ql, qr) {
    if (qr < l || r < ql) return -1;
    if (ql <= l && r <= qr) return treeMax[node];
    treePush(node);
    const mid = (l + r) >> 1;
    return Math.max(treeQuery(2 * node, l, mid, ql, qr), treeQuery(2 * node + 1, mid + 1, r, ql, qr));
  }
  function treeSet(node, l, r, ql, qr, value) {
    if (qr < l || r < ql) return;
    if (ql <= l && r <= qr) { treeMax[node] = value; treeLazy[node] = value; return; }
    treePush(node);
    const mid = (l + r) >> 1;
    treeSet(2 * node, l, mid, ql, qr, value); treeSet(2 * node + 1, mid + 1, r, ql, qr, value);
    treeMax[node] = Math.max(treeMax[2 * node], treeMax[2 * node + 1]);
  }
  function treePush(node) {
    const value = treeLazy[node];
    if (value < 0) return;
    treeMax[2 * node] = treeMax[2 * node + 1] = treeLazy[2 * node] = treeLazy[2 * node + 1] = value;
    treeLazy[node] = -1;
  }

  /**
   * Lines for the runs `list` of one channel, top first. Each run takes the
   * line under the lowest earlier run it overlaps (a skyline over a segment
   * tree), so overlapping runs never share a line and runs on one line keep
   * `runGap` apart. The order avoids crossings: runs whose two verticals go
   * up come first, inner ones first; then runs that come down from above
   * and go on down, a rightward one higher the further right it starts and
   * a leftward one higher the further left it starts (either way its
   * verticals then miss the other runs); then runs whose verticals both go
   * down, outer ones first. Whatever that order says, a run with a vertical
   * coming down from above within trackGap / 2 of another run's vertical
   * going on down is above that run, so the two never overlap; a cycle of
   * such constraints (two calls that swap places) is broken and counted.
   * Returns {tracks, broken}.
   */
  function assignTracks(R, list, m) {
    const k = list.length;
    if (!k) return {tracks: 0, broken: 0};
    for (const i of list) {
      const up1 = R.d1[i] < 0, up2 = R.d2[i] < 0, length = R.x2[i] - R.x1[i];
      R.key[i] = up1 && up2 ? length : !up1 && !up2 ? 2e9 - length : 1e9 + (up1 ? -R.x1[i] : R.x2[i]);
    }
    const ordered = list.slice().sort((a, b) => R.key[a] - R.key[b] || a - b);
    // Constraints between ends that meet: up end above down end.
    const ends = [];
    for (const i of list) {
      if (!(R.far[i] & 1)) ends.push([R.x1[i], R.d1[i], i]);
      if (!(R.far[i] & 2)) ends.push([R.x2[i], R.d2[i], i]);
    }
    ends.sort((a, b) => a[0] - b[0]);
    const tolerance = m.trackGap / 2, after = new Map();
    let constraints = 0;
    for (let a = 0, lo = 0; a < ends.length; a += 1) {
      if (ends[a][1] >= 0) continue;
      while (ends[lo][0] < ends[a][0] - tolerance) lo += 1;
      for (let b = lo; b < ends.length && ends[b][0] <= ends[a][0] + tolerance; b += 1) {
        if (ends[b][1] <= 0 || ends[b][2] === ends[a][2]) continue;
        if (!after.has(ends[a][2])) after.set(ends[a][2], []);
        after.get(ends[a][2]).push(ends[b][2]); constraints += 1;
      }
    }
    let sequence = ordered, broken = 0;
    if (constraints) {
      const waiting = new Map();
      for (const targets of after.values()) for (const b of targets) waiting.set(b, (waiting.get(b) ?? 0) + 1);
      const rank = new Map(ordered.map((i, r) => [i, r]));
      const ready = minHeap((a, b) => rank.get(a) < rank.get(b)), done = new Set();
      for (const i of ordered) if (!waiting.get(i)) ready.push(i);
      sequence = [];
      let cursor = 0;
      while (sequence.length < k) {
        let i;
        if (ready.size) i = ready.pop();
        else {
          // A cycle: force the first run left in the preferred order.
          while (done.has(ordered[cursor])) cursor += 1;
          i = ordered[cursor]; broken += 1;
        }
        if (done.has(i)) continue;
        done.add(i); sequence.push(i);
        for (const b of after.get(i) ?? []) {
          const left = waiting.get(b) - 1;
          waiting.set(b, left);
          if (left === 0 && !done.has(b)) ready.push(b);
        }
      }
    }
    // Skyline over the runs' padded extents.
    const coords = new Float64Array(2 * k);
    list.forEach((i, j) => { coords[2 * j] = R.x1[i] - m.runGap / 2; coords[2 * j + 1] = R.x2[i] + m.runGap / 2; });
    coords.sort();
    let unique = 0;
    for (let j = 0; j < coords.length; j += 1) if (!j || coords[j] !== coords[unique - 1]) coords[unique++] = coords[j];
    const index = value => { let lo = 0, hi = unique - 1; while (lo < hi) { const mid = (lo + hi) >> 1; if (coords[mid] < value) lo = mid + 1; else hi = mid; } return lo; };
    if (treeMax.length < 4 * unique) { treeMax = new Int32Array(4 * unique); treeLazy = new Int32Array(4 * unique); }
    treeMax.fill(-1, 0, 4 * unique); treeLazy.fill(-1, 0, 4 * unique);
    let tracks = 0;
    for (const i of sequence) {
      const lo = index(R.x1[i] - m.runGap / 2), hi = index(R.x2[i] + m.runGap / 2);
      const track = treeQuery(1, 0, unique - 1, lo, hi) + 1;
      treeSet(1, 0, unique - 1, lo, hi, track);
      R.track[i] = track;
      tracks = Math.max(tracks, track + 1);
    }
    return {tracks, broken};
  }

  /** Height of a gap with `tracks` lines, and the y of line t in it. */
  const gapHeight = (tracks, inner, m) => {
    const need = tracks ? 2 * m.trackPad + (tracks - 1) * m.trackGap : 0;
    return inner ? Math.max(m.gapY, need) : need;
  };
  const lineY = (top, height, tracks, t, m) => top + (height - (tracks - 1) * m.trackGap) / 2 + t * m.trackGap;

  /**
   * Ports, runs, lines and rows of one layered band, and the routes of the
   * calls inside it, band-local (x from the band content's left edge, y from
   * the band's top). `side[e]` is where a call between bands leaves or
   * enters this band: -1 left, +1 right. A call between bands is routed to
   * the band's edge here: its exit and entry are recorded for the corridors.
   */
  function routeBand(I, band, side, out, m) {
    const {from, to, w, h, layer, kind, segOf, x} = I, {L} = band;
    // Rows and the gutter.
    const rowH = new Float64Array(L);
    for (const v of band.cards) rowH[layer[v]] = Math.max(rowH[layer[v]], h[v]);
    const contentW = band.width ?? 0, {pieceAt, pieceCount, pieceLo, pieceX} = I;
    const topX = e => pieceX[pieceAt[segOf[e] - I.count]], bottomX = e => pieceX[pieceAt[segOf[e] - I.count] + pieceCount[segOf[e] - I.count] - 1];
    // Gutter lines for the back edges: inner lines for the shorter ones, so a
    // back edge nested in another never crosses it; lines are shared only by
    // back edges that share no gap.
    const gutterTrack = new Map(), lines = [];
    const backs = band.backs.slice().sort((a, b) => (layer[from[a]] - layer[to[a]]) - (layer[from[b]] - layer[to[b]]) || layer[to[a]] - layer[to[b]] || a - b);
    for (const e of backs) {
      const lo = layer[to[e]], hi = layer[from[e]] + 1;
      let t = 0;
      while (t < lines.length && lines[t].some(([a, b]) => lo <= b && a <= hi)) t += 1;
      if (t === lines.length) lines.push([]);
      lines[t].push([lo, hi]); gutterTrack.set(e, t);
    }
    const gutterW = lines.length ? m.gutter + (lines.length - 1) * m.trackGap : 0;
    const gutterX = e => contentW + m.gutter + gutterTrack.get(e) * m.trackGap;
    // Ports: a card's calls leave its bottom and enter its top in the order
    // of where their other end goes, so bundles do not cross at the card. A
    // call drawn straight down (its other end right over or under the card's
    // centre) takes the centre and the others spread from it; back edges take
    // the right end, toward the gutter, and calls between bands the end on
    // their side.
    const nextX = e => (kind[e] === LONG ? topX(e) : kind[e] === BACK ? gutterX(e) : kind[e] === CROSS ? side[e] * FAR + e * 1e-3 : x[to[e]]);
    const prevX = e => (kind[e] === LONG ? bottomX(e) : kind[e] === BACK ? gutterX(e) : kind[e] === CROSS ? side[e] * FAR + e * 1e-3 : x[from[e]]);
    const outs = new Map(), ins = new Map();
    const listOf = (map, v) => { let list = map.get(v); if (!list) map.set(v, list = []); return list; };
    for (const e of band.forward) { listOf(outs, from[e]).push(e); listOf(ins, to[e]).push(e); }
    for (const e of band.backs) { listOf(outs, from[e]).push(e); listOf(ins, to[e]).push(e); }
    for (const e of band.crossOut) listOf(outs, from[e]).push(e);
    for (const e of band.crossIn) listOf(ins, to[e]).push(e);
    const spread = (v, list, key, target) => {
      const k = list.length, cx = x[v], half = Math.max(0, w[v] / 2 - m.portInset);
      if (k === 1) { target[list[0]] = cx; return; }
      list.sort((a, b) => key(a) - key(b) || a - b);
      let straight = -1;
      for (let i = 0; i < k && straight < 0; i += 1) if ((kind[list[i]] === SHORT || kind[list[i]] === LONG) && Math.abs(key(list[i]) - cx) < 0.5) straight = i;
      const origin = straight >= 0 ? straight : (k - 1) / 2;
      const reach = Math.max(origin, k - 1 - origin), step = Math.min(m.portGap, half / reach);
      list.forEach((e, i) => { target[e] = cx + (i - origin) * step; });
    };
    outs.forEach((list, v) => spread(v, list, nextX, out.outX));
    ins.forEach((list, v) => spread(v, list, prevX, out.inX));
    // Runs per gap: gap g is over layer g (gap L under the last layer).
    const R = runSet();
    const jog = (gap, xa, da, xb, db, far, e, which) => {
      if (!far && Math.abs(xa - xb) < 0.5) { out.jog[2 * e + which] = -1; return; }
      out.jog[2 * e + which] = R.add(gap, xa, da, xb, db, far, e, which);
    };
    for (const e of band.forward) {
      const a = from[e], b = to[e];
      if (kind[e] === SHORT) jog(layer[a] + 1, out.outX[e], -1, out.inX[e], 1, 0, e, 0);
      else {
        // Down the call's pieces, jogging between them in the gap over each.
        const k0 = pieceAt[segOf[e] - I.count], k1 = k0 + pieceCount[segOf[e] - I.count] - 1;
        jog(layer[a] + 1, out.outX[e], -1, pieceX[k0], 1, 0, e, 0);
        for (let k = k0 + 1; k <= k1; k += 1) out.joint[k] = R.add(pieceLo[k], pieceX[k - 1], -1, pieceX[k], 1, 0, e, 2);
        jog(layer[b], pieceX[k1], -1, out.inX[e], 1, 0, e, 1);
      }
    }
    for (const e of band.backs) { jog(layer[from[e]] + 1, out.outX[e], -1, gutterX(e), -1, 0, e, 0); jog(layer[to[e]], gutterX(e), 1, out.inX[e], 1, 0, e, 1); }
    for (const e of band.crossOut) jog(layer[from[e]] + 1, out.outX[e], -1, side[e] * FAR, out.exitDir[e], 2, e, 0);
    for (const e of band.crossIn) jog(layer[to[e]], side[e] * FAR, out.entryDir[e], out.inX[e], 1, 1, e, 1);
    const byGap = Array.from({length: L + 1}, () => []);
    for (let i = 0; i < R.length; i += 1) byGap[R.gap[i]].push(i);
    const gapTracks = new Int32Array(L + 1), gapTop = new Float64Array(L + 1), gapH = new Float64Array(L + 1), rowTop = new Float64Array(L);
    let broken = 0, tracksTotal = 0;
    for (let g = 0; g <= L; g += 1) { const result = assignTracks(R, byGap[g], m); gapTracks[g] = result.tracks; broken += result.broken; tracksTotal += result.tracks; }
    let cursor = m.lanePadTop;
    for (let g = 0; g <= L; g += 1) {
      gapTop[g] = cursor; gapH[g] = gapHeight(gapTracks[g], g > 0 && g < L, m); cursor += gapH[g];
      if (g < L) { rowTop[g] = cursor; cursor += rowH[g]; }
    }
    const height = cursor + m.lanePadBottom;
    const runY = i => lineY(gapTop[R.gap[i]], gapH[R.gap[i]], gapTracks[R.gap[i]], R.track[i], m);
    for (const v of band.cards) out.cardY[v] = rowTop[layer[v]];
    // Routes inside the band; the band's own frame, shifted when placed.
    const route = (e, flat) => { out.routes[e] = orthogonal(flat); };
    for (const e of band.forward) {
      const a = from[e], b = to[e], sx = out.outX[e], tx = out.inX[e], sy = rowTop[layer[a]] + h[a], ty = rowTop[layer[b]];
      // A run skipped as under half a pixel keeps the vertical where it is.
      const flat = [sx, sy];
      let cx = sx;
      const along = (run, nx) => { if (run >= 0) { const y = runY(run); flat.push(cx, y, nx, y); cx = nx; } };
      if (kind[e] === SHORT) along(out.jog[2 * e], tx);
      else {
        const k0 = pieceAt[segOf[e] - I.count], k1 = k0 + pieceCount[segOf[e] - I.count] - 1;
        along(out.jog[2 * e], pieceX[k0]);
        for (let k = k0 + 1; k <= k1; k += 1) along(out.joint[k], pieceX[k]);
        along(out.jog[2 * e + 1], tx);
      }
      flat.push(cx, ty);
      route(e, flat);
    }
    for (const e of band.backs) {
      const a = from[e], b = to[e], gx = gutterX(e), down = runY(out.jog[2 * e]), up = runY(out.jog[2 * e + 1]);
      route(e, [out.outX[e], rowTop[layer[a]] + h[a], out.outX[e], down, gx, down, gx, up, out.inX[e], up, out.inX[e], rowTop[layer[b]]]);
    }
    // Recursion: out of the right edge low, through the room kept beside the
    // card, and back in at its right edge under the header; a second self
    // call loops outside the first.
    const loopIndex = new Map();
    for (const e of band.loops) {
      const v = from[e], k = loopIndex.get(v) ?? 0, edge = x[v] + w[v] / 2, reach = m.loop + k * m.trackGap;
      loopIndex.set(v, k + 1);
      const y0 = rowTop[layer[v]], low = y0 + Math.max(30, h[v] - 14) - k * 3, high = y0 + 15 + k * 3;
      out.routes[e] = {points: [edge, low, edge + reach, low, edge + reach, high, edge, high], types: [MOVE, CORNER, CORNER, LINE]};
    }
    for (const e of band.crossOut) {
      const a = from[e], i = out.jog[2 * e], g = R.gap[i];
      out.exit[e] = {x: out.outX[e], y0: rowTop[layer[a]] + h[a], y: runY(i), lo: gapTop[g], hi: gapTop[g] + gapH[g]};
    }
    for (const e of band.crossIn) {
      const b = to[e], i = out.jog[2 * e + 1], g = R.gap[i];
      out.entry[e] = {x: out.inX[e], y1: rowTop[layer[b]], y: runY(i), lo: gapTop[g], hi: gapTop[g] + gapH[g]};
    }
    return {contentW, contentH: height - m.lanePadTop - m.lanePadBottom, gutterW, w: 2 * m.lanePadX + contentW + gutterW, h: height, tracks: tracksTotal, broken};
  }

  /** A route through corner points (graphLayoutClient.routePoints drops
   * repeats and straight-through points): the first point moves, the last is
   * a line, the rest are rounded corners. */
  function orthogonal(flat, dx = 0) {
    const points = graphLayoutClient.routePoints(flat, dx), last = points.length / 2 - 1;
    return {points, types: Array.from({length: last + 1}, (_, k) => (k === 0 ? MOVE : k === last ? LINE : CORNER))};
  }

  // Triskel bands --------------------------------------------------------------

  /** A Triskel band's segments and card boxes, to route calls between bands
   * out of it without touching a card or running along one of its lines. */
  function freeSpace(lx, ly, w, h, members, routes) {
    const boxes = members.map(v => [lx[v], ly[v], lx[v] + w[v], ly[v] + h[v], v]), horizontal = [], vertical = [];
    for (const route of routes) {
      if (!route) continue;
      const p = route.points;
      for (let i = 2; i < p.length; i += 2) {
        if (Math.abs(p[i + 1] - p[i - 1]) < 0.01) horizontal.push([p[i - 1], Math.min(p[i - 2], p[i]), Math.max(p[i - 2], p[i])]);
        else if (Math.abs(p[i] - p[i - 2]) < 0.01) vertical.push([p[i], Math.min(p[i - 1], p[i + 1]), Math.max(p[i - 1], p[i + 1])]);
      }
    }
    return {boxes, horizontal, vertical};
  }

  /** A way out of (or into) a card of a Triskel band to the band's `side`:
   * a vertical from the card's bottom (or to its top) at a port, and a run
   * along the free height under (or over) it to the band's edge, with no
   * card in the way and clear of the band's lines and earlier ways out.
   * Returns {x, y} (the port and the run's height) or null. */
  function escape(space, v, box, exit, side, edgeX, m) {
    const [x0, y0, x1, y1] = box, clear = m.trackGap / 2, pad = 6;
    const blocked = (ax, ay, bx, by) => {
      const lx = Math.min(ax, bx), hx = Math.max(ax, bx), ly = Math.min(ay, by), hy = Math.max(ay, by);
      for (const [cx0, cy0, cx1, cy1, u] of space.boxes) if (u !== v && hx > cx0 - pad && lx < cx1 + pad && hy > cy0 - pad && ly < cy1 + pad) return true;
      if (Math.abs(ay - by) < 0.01) { for (const [y, a, b] of space.horizontal) if (Math.abs(y - ay) < clear && hx > a - clear && lx < b + clear) return true; }
      else for (const [x, a, b] of space.vertical) if (Math.abs(x - ax) < clear && hy > a - clear && ly < b + clear) return true;
      return false;
    };
    const ports = [0];
    for (let k = 1; k * m.portGap < (x1 - x0) / 2 - m.portInset; k += 1) ports.push(k * m.portGap, -k * m.portGap);
    for (let step = 0; step < 24; step += 1) {
      const y = exit ? y1 + m.trackPad + step * m.trackGap : y0 - m.trackPad - step * m.trackGap;
      for (const offset of ports) {
        const px = (x0 + x1) / 2 + offset;
        if (blocked(px, exit ? y1 : y0, px, y) || blocked(px, y, edgeX, y)) continue;
        space.vertical.push([px, Math.min(y, exit ? y1 : y0), Math.max(y, exit ? y1 : y0)]);
        space.horizontal.push([y, Math.min(px, edgeX), Math.max(px, edgeX)]);
        return {x: px, y};
      }
    }
    return null;
  }

  // Bands, columns and corridors ---------------------------------------------

  /** Columns of bands, in band order, as tall as makes the whole drawing
   * nearest `aspect` (width over height); the next band starts a new column
   * when the current one would grow past that height. */
  function packColumns(sizes, m) {
    const n = sizes.length;
    if (!n) return [];
    let tallest = 0, total = 0;
    for (const {h} of sizes) { tallest = Math.max(tallest, h); total += h; }
    total += (n - 1) * m.laneGap;
    const columnsFor = limit => {
      const columns = [];
      let current = null;
      sizes.forEach(({h}, band) => {
        if (!current || current.h + m.laneGap + h > limit + 0.5) columns.push(current = {bands: [], h: -m.laneGap, w: 0});
        current.bands.push(band); current.h += m.laneGap + h; current.w = Math.max(current.w, sizes[band].w);
      });
      return columns;
    };
    const score = columns => {
      let width = 2 * m.margin + (columns.length - 1) * m.laneGap, height = 0;
      for (const column of columns) { width += column.w; height = Math.max(height, column.h); }
      height += 2 * m.margin;
      return Math.abs(Math.log(width / height / m.aspect)) + 1e-9 * width * height;
    };
    let best = null, bestScore = Infinity;
    const candidates = new Set([tallest, total]);
    if (n <= 48) for (let i = 0; i < n; i += 1) { let sum = -m.laneGap; for (let j = i; j < n; j += 1) { sum += m.laneGap + sizes[j].h; if (sum >= tallest) candidates.add(sum); } }
    else for (let k = 0; k <= 256; k += 1) candidates.add(tallest * Math.pow(total / tallest, k / 256));
    for (const limit of candidates) {
      const columns = columnsFor(limit), value = score(columns);
      if (value < bestScore) { bestScore = value; best = columns; }
    }
    return best;
  }

  /** Corridor lines for the calls between bands that run along one corridor:
   * calls whose two runs come from the column on its left take the inner
   * lines on that side (shorter ones nearer), calls from the right column
   * the lines on the right, and the rest the lines between; one line holds
   * calls whose heights keep `runGap` apart. A run from the left column
   * ends at its line and a run from the right column starts at its own, so
   * where two of the middle calls have such runs at one height (within
   * trackGap / 2), the line of the run from the left goes left of the other
   * line, or the two runs would overlap; a cycle of those is broken and
   * counted. Returns {tracks, broken}. */
  function corridorLines(uses, m) {
    const groups = [[], [], []];
    for (const use of uses) groups[use.group].push(use);
    const assign = (list, order) => {
      list.sort(order);
      const lines = [];
      for (const use of list) {
        let t = 0;
        while (t < lines.length && lines[t].some(([a, b]) => use.lo <= b + m.runGap && a <= use.hi + m.runGap)) t += 1;
        if (t === lines.length) lines.push([]);
        lines[t].push([use.lo, use.hi]); use.line = t;
      }
      return lines.length;
    };
    const byLength = (a, b) => (a.hi - a.lo) - (b.hi - b.lo) || a.lo - b.lo || a.edge - b.edge;
    const leftLines = assign(groups[0], byLength), middleLines = assign(groups[1], (a, b) => a.lo - b.lo || a.hi - b.hi || a.edge - b.edge), rightLines = assign(groups[2], byLength);
    const ends = [];
    for (const use of groups[1]) {
      if (!Number.isNaN(use.leftY)) ends.push([use.leftY, -1, use.line]);
      if (!Number.isNaN(use.rightY)) ends.push([use.rightY, 1, use.line]);
    }
    ends.sort((a, b) => a[0] - b[0]);
    const after = Array.from({length: middleLines}, () => []), waiting = new Int32Array(middleLines), tolerance = m.trackGap / 2;
    for (let a = 0, lo = 0; a < ends.length; a += 1) {
      if (ends[a][1] > 0) continue;
      while (ends[lo][0] < ends[a][0] - tolerance) lo += 1;
      for (let b = lo; b < ends.length && ends[b][0] <= ends[a][0] + tolerance; b += 1) {
        if (ends[b][1] < 0 || ends[b][2] === ends[a][2]) continue;
        after[ends[a][2]].push(ends[b][2]); waiting[ends[b][2]] += 1;
      }
    }
    // Lines in their first order where no constraint says otherwise.
    const place = new Int32Array(middleLines), done = new Uint8Array(middleLines), ready = minHeap((a, b) => a < b);
    for (let t = 0; t < middleLines; t += 1) if (!waiting[t]) ready.push(t);
    let placed = 0, cursor = 0, broken = 0;
    while (placed < middleLines) {
      let t;
      if (ready.size) t = ready.pop();
      else { while (done[cursor]) cursor += 1; t = cursor; broken += 1; }
      if (done[t]) continue;
      done[t] = 1; place[t] = placed++;
      for (const b of after[t]) if (--waiting[b] === 0 && !done[b]) ready.push(b);
    }
    for (const use of groups[1]) use.line = leftLines + place[use.line];
    for (const use of groups[2]) use.line = leftLines + middleLines + rightLines - 1 - use.line;
    return {tracks: leftLines + middleLines + rightLines, broken};
  }

  // Engine -------------------------------------------------------------------

  /** The layered layout of every band, before the bands are placed. */
  function layered(graph, m) {
    const t0 = now(), {count, from, to} = graph;
    const w = Float32Array.from({length: count}, (_, v) => graph.w?.[v] ?? m.nodeW);
    const h = Float32Array.from({length: count}, (_, v) => graph.h?.[v] ?? m.nodeH);
    const layer = layerCards(graph, w, h, m);
    const keys = laneOrder(count, graph, from, to, layer);
    const I = buildItems(graph, w, h, layer, keys, m);
    const t1 = now();
    const tree = treap(I.total), largest = I.bands.reduce((max, band) => Math.max(max, band.items.length), 0);
    const scratch = {pos: new Float64Array(I.total), measure: new Float64Array(I.total), slot: new Int32Array(I.total), next: new Int32Array(I.total), prev: new Int32Array(I.total),
      fenA: new Int32Array(largest + 1), fenB: new Int32Array(largest + 1), keys: new Float64Array(1024)};
    const stats = {cards: count, edges: from.length, segments: I.segments, crossings: 0, sweeps: 0, swaps: 0, jogs: 0, rounds: 0, stopped: 0, tracks: 0, broken: 0, ms: {}};
    for (const band of I.bands) {
      const result = orderBand(I, band, tree, scratch, graph.weight, m);
      stats.crossings += result.crossings; stats.sweeps = Math.max(stats.sweeps, result.sweeps); stats.swaps += result.swaps;
    }
    const t2 = now();
    I.marked = new Uint8Array(I.upper.length);
    I.pieceAt = new Int32Array(I.segments); I.pieceCount = new Int32Array(I.segments); I.pieceLo = []; I.pieceX = [];
    for (const band of I.bands) {
      band.width = placeBand(I, band, m);
      stats.jogs += band.jogs ?? 0; stats.rounds = Math.max(stats.rounds, band.rounds ?? 0); stats.stopped += band.stopped ? 1 : 0;
    }
    const t3 = now();
    stats.ms.layers = Math.round(t1 - t0); stats.ms.order = Math.round(t2 - t1); stats.ms.place = Math.round(t3 - t2);
    return {I, w, h, keys, stats};
  }

  /** Per-edge route state shared by the band routes and the corridors. */
  function routeState(I) {
    return {outX: new Float64Array(I.edges), inX: new Float64Array(I.edges), jog: new Int32Array(2 * I.edges).fill(-1), joint: new Int32Array(I.pieceX.length).fill(-1), cardY: new Float64Array(I.count),
      routes: new Array(I.edges).fill(null), exit: new Array(I.edges).fill(null), entry: new Array(I.edges).fill(null),
      exitDir: new Int8Array(I.edges).fill(1), entryDir: new Int8Array(I.edges).fill(-1)};
  }

  /**
   * The calls between bands, given each band's column: which side of its
   * band a call leaves and enters by, which corridors it runs along, and
   * whether it takes the highway over the columns.
   */
  function crossPlan(I, colOf, rowOf, out) {
    const {from, to, bandOf, kind, x} = I, plan = new Map();
    for (let e = 0; e < I.edges; e += 1) {
      if (kind[e] !== CROSS) continue;
      const A = bandOf[from[e]], B = bandOf[to[e]], ca = colOf[A], cb = colOf[B];
      let exitSide, entrySide, highway = false;
      if (ca === cb) {
        // Down a column: the nearer corridor; up it: the right one.
        const below = rowOf[B] > rowOf[A];
        const lean = (x[from[e]] / Math.max(1, I.bandWidth[A]) + x[to[e]] / Math.max(1, I.bandWidth[B])) / 2;
        exitSide = entrySide = below && lean < 0.5 ? -1 : 1;
      } else if (cb > ca) { exitSide = 1; entrySide = -1; highway = cb > ca + 1; }
      else { exitSide = -1; entrySide = 1; highway = cb < ca - 1; }
      const exitCorridor = exitSide < 0 ? ca : ca + 1, entryCorridor = entrySide < 0 ? cb : cb + 1;
      plan.set(e, {exitSide, entrySide, highway, exitCorridor, entryCorridor});
      out.exitDir[e] = highway || (ca === cb && rowOf[B] < rowOf[A]) ? -1 : 1;
      out.entryDir[e] = highway || ca !== cb || rowOf[B] > rowOf[A] ? -1 : 1;
    }
    return plan;
  }

  /** Side of each call between bands at each of its ends. */
  function sidesOf(I, plan) {
    const outSide = new Int8Array(I.edges), inSide = new Int8Array(I.edges);
    for (const [e, p] of plan) { outSide[e] = p.exitSide; inSide[e] = p.entrySide; }
    return {outSide, inSide};
  }

  /**
   * Places each band from its Triskel result or the layered layout, packs
   * the bands into columns, and routes the calls between bands. `outcomes`
   * holds per band {result} or {reason}.
   */
  function assemble(graph, state, outcomes, report, m) {
    const {I, w, keys, stats} = state, {count, from, to, edges, bandOf, kind} = I, bandsN = I.bands.length;
    const started = now();
    // Bands Triskel lays out take its drawing; a band whose calls to other
    // bands cannot leave it cleanly keeps the layered one.
    const triskel = outcomes.map(outcome => outcome.result ?? null);
    const reasons = outcomes.map(outcome => outcome.reason ?? null);
    I.bandWidth = new Float64Array(bandsN);
    let out = null, info = null, plan = null, colOf = null, rowOf = null, columns = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      out = routeState(I);
      info = new Array(bandsN);
      // First pass: sides from band order, to size the bands.
      const guess = new Int8Array(edges);
      for (let e = 0; e < edges; e += 1) if (kind[e] === CROSS) guess[e] = bandOf[to[e]] > bandOf[from[e]] ? 1 : -1;
      const sizeBands = (outSide, inSide) => {
        for (const band of I.bands) {
          const b = band.index;
          if (triskel[b]) { info[b] = triskelBand(I, band, triskel[b], out, m); I.bandWidth[b] = info[b].contentW; continue; }
          const side = new Int8Array(edges);
          for (const e of band.crossOut) side[e] = outSide[e];
          for (const e of band.crossIn) side[e] = inSide[e];
          info[b] = routeBand(I, band, side, out, m);
          I.bandWidth[b] = info[b].contentW;
        }
      };
      const firstGuess = {outSide: guess, inSide: Int8Array.from(guess, value => -value)};
      for (let e = 0; e < edges; e += 1) if (kind[e] === CROSS) { out.exitDir[e] = 1; out.entryDir[e] = -1; }
      sizeBands(firstGuess.outSide, firstGuess.inSide);
      columns = packColumns(info.map(band => ({w: band.w, h: band.h})), m);
      colOf = new Int32Array(bandsN); rowOf = new Int32Array(bandsN);
      columns.forEach((column, c) => column.bands.forEach((band, r) => { colOf[band] = c; rowOf[band] = r; }));
      out = routeState(I);
      plan = crossPlan(I, colOf, rowOf, out);
      const sides = sidesOf(I, plan);
      sizeBands(sides.outSide, sides.inSide);
      // Triskel bands route their calls between bands through free space.
      let failed = false;
      for (const band of I.bands) {
        const b = band.index;
        if (!triskel[b] || !(band.crossOut.length || band.crossIn.length)) continue;
        if (!triskelEscapes(I, band, info[b], sides, out, m)) { triskel[b] = null; reasons[b] = {code: 'cross_route'}; failed = true; }
      }
      if (!failed) break;
    }
    // Columns: each as wide as its widest band; bands stacked in it.
    for (const column of columns) column.w = 0;
    for (const band of I.bands) {
      const b = band.index;
      columns[colOf[b]].w = Math.max(columns[colOf[b]].w, info[b].w);
    }
    // Corridors: corridor c is left of column c (corridor C right of the last).
    const C = columns.length, corridorUses = Array.from({length: C + 1}, () => []), highwayRuns = [];
    // Heights first with no highway: the corridor lines only need the order.
    const bandY = new Float64Array(bandsN);
    for (const column of columns) {
      let y = m.margin + m.top;
      for (const b of column.bands) { bandY[b] = y; y += info[b].h + m.laneGap; }
    }
    for (const [e, p] of plan) {
      const ex = out.exit[e], en = out.entry[e], A = bandOf[from[e]], B = bandOf[to[e]];
      const exitLo = bandY[A] + ex.lo, exitHi = bandY[A] + ex.hi, entryLo = bandY[B] + en.lo, entryHi = bandY[B] + en.hi;
      const groupOf = (corridor, a, b) => (a === corridor - 1 && b === corridor - 1 ? 0 : a === corridor && b === corridor ? 2 : 1);
      // The heights of its runs from the columns left and right of the corridor.
      const exitY = bandY[A] + ex.y, entryY = bandY[B] + en.y;
      const sideY = (use, corridor) => {
        use.leftY = use.rightY = NaN;
        if (use.end !== 'entry') { if (colOf[A] < corridor) use.leftY = exitY; else use.rightY = exitY; }
        if (use.end !== 'exit') { if (colOf[B] < corridor) use.leftY = entryY; else use.rightY = entryY; }
        return use;
      };
      if (!p.highway) {
        const use = sideY({edge: e, lo: Math.min(exitLo, entryLo), hi: Math.max(exitHi, entryHi), group: groupOf(p.exitCorridor, colOf[A], colOf[B]), end: 'both'}, p.exitCorridor);
        corridorUses[p.exitCorridor].push(use); p.uses = [use];
      } else {
        const a = sideY({edge: e, lo: -Infinity, hi: exitHi, group: 1, end: 'exit'}, p.exitCorridor), b = sideY({edge: e, lo: -Infinity, hi: entryHi, group: 1, end: 'entry'}, p.entryCorridor);
        corridorUses[p.exitCorridor].push(a); corridorUses[p.entryCorridor].push(b); p.uses = [a, b];
      }
    }
    const corridorLined = corridorUses.map(uses => corridorLines(uses, m)), corridorTracks = corridorLined.map(lined => lined.tracks);
    const corridorW = corridorTracks.map((t, c) => {
      const need = t ? 2 * m.trackPad + (t - 1) * m.trackGap : 0;
      return c === 0 || c === C ? need : Math.max(m.laneGap, need);
    });
    const corridorX = new Float64Array(C + 1), colX = new Float64Array(C);
    let cursor = m.margin;
    for (let c = 0; c <= C; c += 1) { corridorX[c] = cursor; cursor += corridorW[c]; if (c < C) { colX[c] = cursor; cursor += columns[c].w; } }
    const width = cursor + m.margin;
    const corridorLineX = (c, line) => corridorX[c] + (corridorW[c] - (corridorTracks[c] - 1) * m.trackGap) / 2 + line * m.trackGap;
    for (const [, p] of plan) for (const use of p.uses) use.x = corridorLineX(use.end === 'entry' ? p.entryCorridor : p.exitCorridor, use.line);
    // The highway over the columns, for calls that pass a column.
    const H = runSet();
    for (const [e, p] of plan) if (p.highway) p.run = H.add(0, p.uses[0].x, 1, p.uses[1].x, 1, 0, e, 0);
    const highway = assignTracks(H, Array.from({length: H.length}, (_, i) => i), m);
    const highwayH = highway.tracks ? 2 * m.trackPad + (highway.tracks - 1) * m.trackGap : 0;
    for (let b = 0; b < bandsN; b += 1) bandY[b] += highwayH;
    const highwayY = i => lineY(m.margin + m.top, highwayH, highway.tracks, H.track[i], m);
    // Card boxes and lanes.
    const x = new Float32Array(count), y = new Float32Array(count), lanes = new Array(bandsN), offsetX = new Float64Array(bandsN);
    let height = m.margin + m.top + highwayH;
    for (const band of I.bands) {
      const b = band.index, c = colOf[b], own = info[b];
      // A band keeps its own width, centred in its column.
      const laneX = colX[c] + (columns[c].w - own.w) / 2;
      offsetX[b] = laneX + m.lanePadX;
      for (const v of band.cards) {
        x[v] = offsetX[b] + (triskel[b] ? own.lx[v] : I.x[v] - w[v] / 2);
        y[v] = bandY[b] + (triskel[b] ? own.ly[v] : out.cardY[v]);
      }
      lanes[b] = {key: keys[b], x: laneX, y: bandY[b], w: own.w, h: own.h, gutter: offsetX[b] + own.contentW + m.lanePadX / 2, top: bandY[b] + m.lanePadTop};
      height = Math.max(height, bandY[b] + own.h + m.margin);
    }
    // Routes: the bands' own, moved into place, then the calls between bands.
    const routes = new Array(edges).fill(null);
    for (let e = 0; e < edges; e += 1) {
      const local = out.routes[e];
      if (!local) continue;
      const b = bandOf[from[e]], dx = offsetX[b], dy = bandY[b], points = local.points.slice();
      for (let i = 0; i < points.length; i += 2) { points[i] += dx; points[i + 1] += dy; }
      routes[e] = {points, types: local.types.slice()};
    }
    for (const [e, p] of plan) {
      const A = bandOf[from[e]], B = bandOf[to[e]], ex = out.exit[e], en = out.entry[e];
      const sx = offsetX[A] + ex.x, sy0 = bandY[A] + ex.y0, sy = bandY[A] + ex.y, tx = offsetX[B] + en.x, ty = bandY[B] + en.y, ty1 = bandY[B] + en.y1;
      const flat = [sx, sy0, sx, sy];
      if (p.highway) { const hy = highwayY(p.run); flat.push(p.uses[0].x, sy, p.uses[0].x, hy, p.uses[1].x, hy, p.uses[1].x, ty); }
      else flat.push(p.uses[0].x, sy, p.uses[0].x, ty);
      flat.push(tx, ty, tx, ty1);
      routes[e] = orthogonal(flat);
    }
    const points = [], kinds = [], routeStart = new Uint32Array(edges + 1);
    for (let e = 0; e < edges; e += 1) {
      routeStart[e] = kinds.length;
      const route = routes[e];
      for (let i = 0; i < route.points.length; i += 1) points.push(route.points[i]);
      for (const type of route.types) kinds.push(type);
      for (let i = 1; i < route.points.length; i += 2) height = Math.max(height, route.points[i] + m.margin);
    }
    routeStart[edges] = kinds.length;
    const back = new Uint8Array(edges);
    for (let e = 0; e < edges; e += 1) back[e] = kind[e] === BACK || kind[e] === LOOP || (kind[e] === CROSS && bandOf[to[e]] < bandOf[from[e]]) ? 1 : 0;
    stats.tracks = info.reduce((sum, band) => sum + (band.tracks ?? 0), 0) + corridorTracks.reduce((sum, t) => sum + t, 0) + highway.tracks;
    stats.broken = info.reduce((sum, band) => sum + (band.broken ?? 0), 0) + corridorLined.reduce((sum, lined) => sum + lined.broken, 0) + highway.broken;
    stats.columns = C;
    stats.ms.route = Math.round(now() - started);
    const laid = triskel.filter(Boolean).length;
    const realmReport = keys.map((key, b) => ({key, engine: triskel[b] ? 'triskel' : 'layered', reason: triskel[b] ? null : reasons[b] ?? null}));
    return {x, y, w, h: state.h, layer: I.layer, back, lanes, width, height, top: m.margin, routes: Float32Array.from(points), routeTypes: Uint8Array.from(kinds), routeStart, stats,
      engine: {name: laid ? 'triskel' : 'layered', revision: report.revision, triskel: laid, realms: realmReport, failure: report.failure}};
  }

  /** A band laid out by Triskel: its card boxes and the routes inside it,
   * band-local like a layered band's. Its drawing starts at 0, 0
   * (graph-layout-v1), its waypoints included. */
  function triskelBand(I, band, result, out, m) {
    const {from, to, w, h} = I;
    const lx = new Map(), ly = new Map();
    let right = result.width, cards = 0, bottom = result.height;
    band.cards.forEach((v, i) => {
      lx.set(v, result.nodes[i][0]); ly.set(v, result.nodes[i][1] + m.lanePadTop);
      cards = Math.max(cards, result.nodes[i][0] + w[v]); bottom = Math.max(bottom, result.nodes[i][1] + h[v]);
    });
    const inner = [...band.forward, ...band.backs, ...band.loops].sort((a, b) => a - b);
    const local = band.triskelEdges ?? inner;
    local.forEach((e, i) => {
      if (from[e] === to[e]) {
        // Recursion: a tight loop on the card's right edge, not Triskel's
        // loop around the whole row.
        const v = from[e], edge = lx.get(v) + w[v], low = ly.get(v) + Math.max(30, h[v] - 14);
        out.routes[e] = {points: [edge, low, edge + 16, low, edge + 16, ly.get(v) + 15, edge, ly.get(v) + 15], types: [MOVE, CORNER, CORNER, LINE]};
        right = Math.max(right, edge + 16);
        return;
      }
      out.routes[e] = orthogonal(result.edges[i], 0);
      const points = out.routes[e].points;
      for (let k = 0; k < points.length; k += 2) { points[k + 1] += m.lanePadTop; right = Math.max(right, points[k]); bottom = Math.max(bottom, points[k + 1] - m.lanePadTop); }
    });
    const contentW = Math.max(right, cards), boxes = {lx: new Float64Array(I.count), ly: new Float64Array(I.count)};
    for (const v of band.cards) { boxes.lx[v] = lx.get(v); boxes.ly[v] = ly.get(v); }
    return {triskel: true, lx: boxes.lx, ly: boxes.ly, contentW, contentH: bottom, gutterW: 0, w: 2 * m.lanePadX + contentW, h: m.lanePadTop + bottom + m.lanePadBottom, tracks: 0, broken: 0};
  }

  /** Ways out of and into a Triskel band for its calls between bands. */
  function triskelEscapes(I, band, own, sides, out, m) {
    const {from, to, w, h} = I;
    const space = freeSpace(own.lx, own.ly, w, h, band.cards, [...band.forward, ...band.backs, ...band.loops].map(e => out.routes[e]));
    const edgeX = s => (s < 0 ? -m.lanePadX : own.contentW + m.lanePadX);
    for (const e of band.crossOut) {
      const v = from[e], found = escape(space, v, [own.lx[v], own.ly[v], own.lx[v] + w[v], own.ly[v] + h[v]], true, sides.outSide[e], edgeX(sides.outSide[e]), m);
      if (!found) return false;
      out.exit[e] = {x: found.x, y0: own.ly[v] + h[v], y: found.y, lo: found.y - m.trackGap, hi: found.y + m.trackGap};
    }
    for (const e of band.crossIn) {
      const v = to[e], found = escape(space, v, [own.lx[v], own.ly[v], own.lx[v] + w[v], own.ly[v] + h[v]], false, sides.inSide[e], edgeX(sides.inSide[e]), m);
      if (!found) return false;
      out.entry[e] = {x: found.x, y1: own.ly[v], y: found.y, lo: found.y - m.trackGap, hi: found.y + m.trackGap};
    }
    return true;
  }

  /** The layered layout, then Triskel for the realms the client keeps when
   * `engine` is triskel; the engine report says why each other realm stayed. */
  async function runAsync({graph, metrics = METRICS, engine}) {
    const m = {...METRICS, ...metrics}, state = layered(graph, m), {I} = state;
    const outcomes = I.bands.map(band => ({reason: {code: band.cards.length < 2 ? 'one_card' : 'not_served'}}));
    const report = {revision: null, failure: null};
    if (engine === 'triskel') {
      // Triskel is asked for each band of two or more cards, against the
      // layered drawing's size with calls between bands on their usual sides.
      const probe = routeState(I), sized = [];
      for (const band of I.bands) {
        if (band.cards.length < 2) continue;
        const side = new Int8Array(I.edges);
        for (const e of band.crossOut) side[e] = 1;
        for (const e of band.crossIn) side[e] = -1;
        const own = routeBand(I, band, side, probe, m);
        const localIndex = new Map(band.cards.map((v, i) => [v, i]));
        band.triskelEdges = [...band.forward, ...band.backs, ...band.loops].sort((a, b) => a - b);
        sized.push({band, graph: {nodes: band.cards.map(v => [state.w[v], state.h[v]]), edges: band.triskelEdges.map(e => [localIndex.get(graph.from[e]), localIndex.get(graph.to[e])]),
          width: own.contentW + own.gutterW, height: own.contentH}});
      }
      const answer = await graphLayoutClient.layOut(sized.map(item => item.graph));
      sized.forEach((item, index) => { outcomes[item.band.index] = answer.outcomes[index]; });
      report.revision = answer.revision;
      report.failure = answer.failure;
    }
    return assemble(graph, state, outcomes, report, m);
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
