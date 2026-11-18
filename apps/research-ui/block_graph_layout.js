/* Layered single-entry-region layout for basic-block graphs. Runs off the main
 * thread as a Web Worker; also loads as CommonJS for the offline check, which
 * loads graph_layout_client.js first.
 *
 * A dominator subtree is entered only at its root, so each subtree becomes a
 * collapsed box laid out on its own: its members are stacked in layers, a layer
 * of one member continues the spine, and a wider layer becomes side-by-side
 * boxes, wrapped into a grid once it is wide. When one member of a layer
 * outweighs the rest, as the rest of a switch ladder or an else-if chain
 * outweighs its case, that member continues the spine and the others sit
 * beside it, so a chain of any length stays one column. A dispatcher's arms are
 * one layer, so its fan is a grid fed by a shared bus and its back edges collect
 * on one rail beside the loop header. Edges leaving a box merge into its bottom
 * port, so a flattened function stays legible. No new dependency is linked.
 *
 * Dominance is computed over the blocks reachable from the declared entries
 * only. Each set of connected unreachable blocks is its own component below the
 * reachable graph, and an edge from it into reachable code is a labeled stub:
 * dead code never changes how live code is drawn. */
'use strict';

const blockGraphLayout = (() => {
  const METRICS = {charW: 6.6, rowH: 16, headerH: 22, padX: 10, padY: 7, minW: 132, gapX: 32, gapY: 36, lane: 8, side: 8, margin: 48};
  const KIND = {fallthrough: 0, branch: 1, taken: 2, not_taken: 3, table: 4, table_default: 5, exception: 6, unresolved: 7, call: 8, assumed: 9, sequence: 10};
  const MAX_ROW_CHARS = 120;
  const WRAP_AT = 6;
  /* A member continues the spine when its subtree holds this many times the
   * blocks of the members beside it. Members of one layer share no edge, so
   * any placement among them is valid; this one keeps a long chain straight. */
  const SPINE_WEIGHT = 4;
  /* Instructions that only open or close structure. A block of nothing else
   * runs no instruction, so the drawing folds it into the block it falls into
   * and shows its rows as one summary row; the document keeps every block. */
  const STRUCTURAL = new Set(['end', 'block', 'loop', 'nop', 'try', 'try_table', 'delegate']);
  const REACHABLE = 2, EXIT = 4, TRAP = 8, GAP = 16, ROWS_CUT = 32;

  /** Normalizes a `wasm-block-graph-v1` document. Refuses an unknown shape. */
  function wasmGraph(doc, starts = null) {
    if (doc?.schema !== 'wasm-block-graph-v1' || !Array.isArray(doc.blocks) || !Array.isArray(doc.edges) || typeof doc.rows !== 'string')
      throw Error('The WASM graph provider returned an invalid document.');
    const total = doc.blocks.length, edgeTotal = doc.edges.length, rows = doc.rows;
    const lines = starts ?? rowStarts(rows);
    const block = doc.blocks;
    const names = doc.edge_kinds;
    const kindOf = edge => { const known = KIND[names[edge[2]]]; return known === undefined ? KIND.unresolved : known; };
    // A structural block folds when its one edge falls into the next block,
    // both have the same reachability and its rows run straight into the next.
    const degree = new Uint32Array(total), only = new Int32Array(total).fill(-1);
    doc.edges.forEach((edge, index) => { degree[edge[0]] += 1; only[edge[0]] = index; });
    const mnemonic = row => {
      let a = lines[row]; const end = lines[row + 1] - 1;
      while (a < end && rows.charCodeAt(a) !== 32) a += 1;
      let b = a + 1; while (b < end && rows.charCodeAt(b) !== 32) b += 1;
      return rows.slice(a + 1, b);
    };
    const folds = new Uint8Array(total);
    for (let index = 0; index + 1 < total; index += 1) {
      const [, byteEnd, first, count, , flags] = block[index], next = block[index + 1];
      if (degree[index] !== 1 || !count || flags & (EXIT | TRAP | ROWS_CUT)) continue;
      const edge = doc.edges[only[index]];
      if (edge[1] !== index + 1 || kindOf(edge) !== KIND.fallthrough || (flags & REACHABLE) !== (next[5] & REACHABLE)) continue;
      if (first + count !== next[2] || byteEnd !== next[0]) continue;
      let structural = true;
      for (let row = first; row < first + count && structural; row += 1) structural = STRUCTURAL.has(mnemonic(row));
      folds[index] = structural ? 1 : 0;
    }
    const keep = new Int32Array(total);
    let count = 0;
    for (let index = 0; index < total; index += 1) { keep[index] = count; if (!folds[index]) count += 1; }
    const offsets = new Float64Array(count), ends = new Float64Array(count), firstRow = new Uint32Array(count), rowCount = new Uint32Array(count),
      instructionCount = new Uint32Array(count), flags = new Uint32Array(count), folded = new Uint32Array(count), foldNote = new Array(count).fill(null);
    let run = 0;
    for (let index = 0; index < total; index += 1) {
      const [byteOffset, byteEnd, first, rowsHere, instructions, bits] = block[index], at = keep[index];
      if (run === 0) { offsets[at] = byteOffset; firstRow[at] = first; }
      run += 1;
      rowCount[at] += rowsHere; instructionCount[at] += instructions; flags[at] |= bits;
      if (folds[index]) { folded[at] += rowsHere; continue; }
      ends[at] = byteEnd;
      if (folded[at]) foldNote[at] = foldSummary(rows, lines, firstRow[at], folded[at], mnemonic);
      run = 0;
    }
    const from = [], to = [], kind = [], labels = [];
    doc.edges.forEach(edge => {
      if (folds[edge[0]]) return;
      from.push(keep[edge[0]]); to.push(edge[1] === null ? -1 : keep[edge[1]]); kind.push(kindOf(edge)); labels.push(edge[3]);
    });
    return {count, offsets, ends, firstRow, rowCount, instructionCount, flags, folded, foldNote, foldedBlocks: total - count,
      from: Int32Array.from(from), to: Int32Array.from(to), kind: Uint8Array.from(kind), labels, rows, roots: [0],
      title: `func ${doc.function_index}`, status: doc.status, instructions: doc.instruction_count, omissions: doc.omissions, notice: doc.notice,
      evidence: 'declared', functionIndex: doc.function_index, byteOffset: doc.byte_offset, byteEnd: doc.byte_end};
  }
  /** `end ×3, block ×2`: what a run of folded rows held, in first-seen order. */
  function foldSummary(rows, lines, first, count, mnemonic) {
    const seen = new Map();
    for (let row = first; row < first + count; row += 1) {
      const name = mnemonic(row), text = rows.slice(lines[row], lines[row + 1] - 1), times = /\sx(\d+)$/.exec(text);
      seen.set(name, (seen.get(name) ?? 0) + (times ? Number(times[1]) : 1));
    }
    return [...seen].map(([name, times]) => (times > 1 ? `${name} ×${times}` : name)).join(', ');
  }

  /** Basic blocks for a `reb-vm-static-analysis-v1` report, as declared edges. */
  function vmStaticGraph(report) {
    const instructions = report.instructions, edges = report.cfg.edges;
    const hex = value => value.toString(16);
    const byOffset = new Map(instructions.map((instruction, index) => [instruction.offset, index]));
    const reachable = new Set(report.cfg.nodes.filter(node => node.reachable).map(node => node.offset));
    const leaders = new Set();
    if (instructions.length) leaders.add(instructions[0].offset);
    for (const entry of report.cfg.entries) if (entry.status === 'resolved' && byOffset.has(entry.offset)) leaders.add(entry.offset);
    const fallsThrough = new Set();
    for (const edge of edges) if (edge.kind === 'fallthrough') fallsThrough.add(edge.from_offset);
    for (const edge of edges) {
      if (edge.status === 'resolved' && edge.to_offset !== null && edge.kind !== 'fallthrough') leaders.add(edge.to_offset);
    }
    instructions.forEach((instruction, index) => {
      const next = instructions[index + 1];
      if (next && !fallsThrough.has(instruction.offset)) leaders.add(next.offset);
    });
    const blocks = [], blockOf = new Map();
    let current = null;
    for (const instruction of instructions) {
      if (leaders.has(instruction.offset) || !current) {
        current = {start: instruction.offset, end: instruction.offset + instruction.size, list: []}; blocks.push(current);
      }
      current.list.push(instruction); current.end = instruction.offset + instruction.size;
      blockOf.set(instruction.offset, blocks.length - 1);
    }
    const kinds = {fallthrough: KIND.fallthrough, jump: KIND.branch, branch_taken: KIND.taken,
      branch_not_taken: KIND.not_taken, call: KIND.call, call_continuation: KIND.assumed};
    const labels = {branch_taken: 'taken', branch_not_taken: 'not taken', call: 'call', call_continuation: 'assumed continuation', return: 'return: unknown destination', unknown: 'unknown target'};
    const from = [], to = [], kind = [], edgeLabels = [];
    for (const edge of edges) {
      const source = blockOf.get(edge.from_offset);
      // Every non-fallthrough instruction ends a block, so only fallthroughs
      // inside a block are left out.
      if (source === undefined || blocks[source].list.at(-1).offset !== edge.from_offset) continue;
      const resolved = edge.status === 'resolved' && edge.to_offset !== null && blockOf.has(edge.to_offset) && kinds[edge.kind] !== undefined;
      from.push(source);
      if (resolved) { to.push(blockOf.get(edge.to_offset)); kind.push(kinds[edge.kind]); edgeLabels.push(labels[edge.kind] ?? null); }
      else {
        to.push(-1); kind.push(KIND.unresolved);
        edgeLabels.push(edge.to_offset === null ? (labels[edge.kind] ?? 'unresolved') : `${edge.kind} ${edge.status} 0x${hex(edge.to_offset)}`);
      }
    }
    const parts = [];
    let rowIndex = 0;
    const firstRow = new Uint32Array(blocks.length), rowCount = new Uint32Array(blocks.length), counts = new Uint32Array(blocks.length), flags = new Uint32Array(blocks.length),
      offsets = new Float64Array(blocks.length), ends = new Float64Array(blocks.length);
    blocks.forEach((item, index) => {
      firstRow[index] = rowIndex; rowCount[index] = item.list.length; counts[index] = item.list.length; offsets[index] = item.start; ends[index] = item.end;
      if (index === 0) flags[index] |= 1;
      if (reachable.has(item.start)) flags[index] |= REACHABLE;
      for (const instruction of item.list) {
        const operands = instruction.operands.map(operand => `${operand.name}=${operand.value}`).join(' ');
        parts.push(`${hex(instruction.offset)} ${instruction.mnemonic}${operands ? ` ${operands}` : ''}\n`); rowIndex += 1;
      }
    });
    const roots = [...new Set(report.cfg.entries.filter(entry => entry.status === 'resolved' && blockOf.has(entry.offset)).map(entry => blockOf.get(entry.offset)))];
    return {count: blocks.length, offsets, ends, firstRow, rowCount, instructionCount: counts, flags,
      from: Int32Array.from(from), to: Int32Array.from(to), kind: Uint8Array.from(kind), labels: edgeLabels, rows: parts.join(''), roots: roots.length ? roots : [0],
      title: report.image.image_id, status: 'decoded', instructions: instructions.length, omissions: [], evidence: 'declared',
      notice: 'cfg.complete is false. Declared edges are not observed execution.'};
  }

  /** Occurrence graph of a VM trace's retained steps (vm_semantics.js
   * observedPath). A gap card has no edge on either side. */
  function vmObservedGraph(path) {
    const cards = [], from = [], to = [], kind = [], labels = [], parts = [];
    const indexOf = new Map(), gapAfter = new Map(path.gaps.map(gap => [gap.after_sequence, gap]));
    path.nodes.forEach((node, index) => {
      const gap = index ? gapAfter.get(node.sequence) : undefined;
      if (gap) { cards.push({gap}); parts.push(`${gap.missing_steps} gap missing execution unknown\n`); }
      indexOf.set(node.sequence, cards.length);
      cards.push({node}); parts.push(`${node.sequence.toString(16)} pc 0x${node.pc_before.toString(16)} op ${node.opcode}\n`);
    });
    for (const edge of path.edges) { from.push(indexOf.get(edge.from_sequence)); to.push(indexOf.get(edge.to_sequence)); kind.push(KIND.sequence); labels.push(null); }
    const count = cards.length;
    const offsets = new Float64Array(count), flags = new Uint32Array(count), firstRow = new Uint32Array(count), rowCount = new Uint32Array(count).fill(1);
    cards.forEach((card, index) => {
      firstRow[index] = index; offsets[index] = card.node ? card.node.sequence : 0;
      flags[index] = card.node ? REACHABLE : GAP;
      if (index === 0) flags[index] |= 1;
    });
    // Each run of consecutive sequences and each gap card is its own stacked
    // root, so the layout can never draw an edge across a missing step.
    const roots = cards.map((card, index) => (index === 0 || card.gap || cards[index - 1].gap) ? index : -1).filter(index => index >= 0);
    return {count, offsets, ends: offsets.slice(), firstRow, rowCount, instructionCount: rowCount.slice(), flags,
      from: Int32Array.from(from), to: Int32Array.from(to), kind: Uint8Array.from(kind), labels, rows: parts.join(''), roots, stackedRoots: true,
      title: path.identity.trace_id, status: path.coverage.complete ? 'decoded' : 'partial', instructions: path.nodes.length, omissions: [...path.warnings], evidence: 'observed',
      notice: 'Retained steps only. No edge crosses a gap. Not a static control-flow graph.', gaps: path.gaps.length};
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

  /** Rows a card draws: a folded run is one summary row above the block's own. */
  const shownRows = (graph, node) => graph.rowCount[node] - (graph.folded?.[node] ?? 0) + (graph.folded?.[node] ? 1 : 0);

  function nodeSizes(graph, starts, m) {
    const w = new Float32Array(graph.count), h = new Float32Array(graph.count);
    for (let node = 0; node < graph.count; node += 1) {
      let chars = 0;
      const folded = graph.folded?.[node] ?? 0, first = graph.firstRow[node] + folded, last = graph.firstRow[node] + graph.rowCount[node];
      if (folded) {
        const start = starts[graph.firstRow[node]];
        let a = start; while (graph.rows.charCodeAt(a) !== 32 && a < starts[graph.firstRow[node] + 1] - 1) a += 1;
        chars = (a - start) + 1 + graph.foldNote[node].length;
      }
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
      h[node] = m.headerH + m.padY * 2 + Math.max(1, shownRows(graph, node)) * m.rowH;
    }
    return {w, h};
  }

  /** Edge indices grouped by `key(e)`, which skips an edge by returning -1. */
  function grouped(count, edges, key) {
    const start = new Int32Array(count + 1);
    for (let e = 0; e < edges; e += 1) { const k = key(e); if (k >= 0) start[k + 1] += 1; }
    for (let i = 0; i < count; i += 1) start[i + 1] += start[i];
    const fill = start.slice(0, count), list = new Int32Array(start[count]);
    for (let e = 0; e < edges; e += 1) { const k = key(e); if (k >= 0) list[fill[k]++] = e; }
    return {start, list};
  }

  /** A binary min-heap ordered by `compare`, which returns a negative number
   * when its first argument comes first. */
  function heap(compare) {
    const items = [];
    const before = (a, b) => compare(items[a], items[b]) < 0;
    return {
      get size() { return items.length; }, peek: () => items[0],
      push(value) {
        let i = items.push(value) - 1;
        while (i > 0) { const up = (i - 1) >> 1; if (!before(i, up)) break; [items[i], items[up]] = [items[up], items[i]]; i = up; }
      },
      pop() {
        const first = items[0], last = items.pop();
        if (items.length) {
          items[0] = last;
          for (let i = 0; ;) {
            const l = i * 2 + 1, r = l + 1; let best = i;
            if (l < items.length && before(l, best)) best = l;
            if (r < items.length && before(r, best)) best = r;
            if (best === i) break;
            [items[i], items[best]] = [items[best], items[i]]; i = best;
          }
        }
        return first;
      }
    };
  }

  const emptyLayout = () => ({x: new Float32Array(0), y: new Float32Array(0), w: new Float32Array(0), h: new Float32Array(0), pointStart: new Uint32Array(1), points: new Float32Array(0),
    box: new Float32Array(0), back: new Uint8Array(0), stub: new Uint8Array(0), direct: 0, width: 0, height: 0});

  /** Lays out one graph. Returns typed node boxes and stitched edge polylines. */
  function layoutGraph(graph, sizes, metrics) {
    const m = {...METRICS, ...metrics};
    const n = graph.count, edgeCount = graph.from.length, from = graph.from, to = graph.to;
    if (!n) return emptyLayout();
    const V = n, N = n + 1;
    const out = grouped(n, edgeCount, e => from[e]);

    // Depth-first walk from a virtual root V: the declared entries first, then
    // each block not yet reached, in block order. Preorder numbers drive the
    // dominators; an edge to a block still on the stack is a retreat edge.
    const pre = new Int32Array(N).fill(-1), vertex = new Int32Array(N), parent = new Int32Array(N), post = new Int32Array(n);
    const retreat = new Uint8Array(edgeCount), onStack = new Uint8Array(n), live = new Uint8Array(n), isRoot = new Uint8Array(n);
    const stackNode = new Int32Array(n), stackEdge = new Int32Array(n);
    let clock = 1, finished = 0;
    pre[V] = 0; vertex[0] = V;
    const walk = root => {
      isRoot[root] = 1;
      pre[root] = clock; vertex[clock] = root; parent[clock] = 0; clock += 1;
      let top = 0; stackNode[0] = root; stackEdge[0] = out.start[root]; onStack[root] = 1;
      while (top >= 0) {
        const node = stackNode[top];
        if (stackEdge[top] < out.start[node + 1]) {
          const e = out.list[stackEdge[top]++], target = to[e];
          if (target < 0) continue;
          if (pre[target] < 0) {
            pre[target] = clock; vertex[clock] = target; parent[clock] = pre[node]; clock += 1;
            top += 1; stackNode[top] = target; stackEdge[top] = out.start[target]; onStack[target] = 1;
          } else if (onStack[target]) retreat[e] = 1;
        } else { onStack[node] = 0; post[finished++] = node; top -= 1; }
      }
    };
    for (const root of graph.roots ?? [0]) if (root >= 0 && root < n && pre[root] < 0) walk(root);
    for (let v = 0; v < n; v += 1) if (pre[v] >= 0) live[v] = 1;
    for (let v = 0; v < n; v += 1) if (pre[v] < 0) walk(v);
    // An edge from unreachable code into reachable code is a stub.
    const stub = new Uint8Array(edgeCount);
    for (let e = 0; e < edgeCount; e += 1) if (to[e] >= 0 && !live[from[e]] && live[to[e]]) stub[e] = 1;
    const counted = e => to[e] >= 0 && !stub[e];

    // Semi-NCA dominators (Georgiadis): semidominators by path-compressed
    // evaluation, then each immediate dominator as the nearest common ancestor
    // of its DFS parent and semidominator. Near-linear on every shape.
    const into = grouped(n, edgeCount, e => (counted(e) ? to[e] : -1));
    const semi = new Int32Array(N), label = new Int32Array(N), ancestor = new Int32Array(N).fill(-1), idomPre = new Int32Array(N), path = new Int32Array(N);
    for (let i = 0; i < N; i += 1) { semi[i] = i; label[i] = i; }
    const evaluate = v => {
      if (ancestor[v] < 0) return v;
      let depth = 0, x = v;
      while (ancestor[ancestor[x]] >= 0) { path[depth++] = x; x = ancestor[x]; }
      while (depth > 0) {
        const y = path[--depth], a = ancestor[y];
        if (semi[label[a]] < semi[label[y]]) label[y] = label[a];
        ancestor[y] = ancestor[a];
      }
      return label[v];
    };
    for (let i = N - 1; i >= 1; i -= 1) {
      const w = vertex[i];
      let s = isRoot[w] ? 0 : semi[i];
      for (let k = into.start[w]; k < into.start[w + 1]; k += 1) {
        const c = semi[evaluate(pre[from[into.list[k]]])];
        if (c < s) s = c;
      }
      semi[i] = s;
      ancestor[i] = parent[i];
    }
    for (let i = 1; i < N; i += 1) {
      let j = parent[i];
      while (j > semi[i]) j = idomPre[j];
      idomPre[i] = j;
    }
    const idom = new Int32Array(N); idom[V] = V;
    for (let i = 1; i < N; i += 1) idom[vertex[i]] = vertex[idomPre[i]];

    // Reverse post-order is a topological order of every non-retreat edge.
    const rpo = new Int32Array(n), pos = new Int32Array(N);
    for (let k = 0; k < n; k += 1) { rpo[k] = post[n - 1 - k]; pos[rpo[k]] = k; }
    pos[V] = -1;
    // Dominator tree children in reverse post-order, and subtree intervals.
    const kidStart = new Int32Array(N + 1);
    for (let v = 0; v < n; v += 1) kidStart[idom[v] + 1] += 1;
    for (let i = 0; i < N; i += 1) kidStart[i + 1] += kidStart[i];
    const kidList = new Int32Array(n);
    { const fill = kidStart.slice(0, N); for (let k = 0; k < n; k += 1) kidList[fill[idom[rpo[k]]]++] = rpo[k]; }
    const tin = new Int32Array(N), tout = new Int32Array(N), domOrder = new Int32Array(N);
    {
      let time = 0, top = 0;
      const nodes = new Int32Array(N), cursor = new Int32Array(N);
      nodes[0] = V; cursor[0] = kidStart[V]; tin[V] = time; domOrder[time++] = V;
      while (top >= 0) {
        const v = nodes[top];
        if (cursor[top] < kidStart[v + 1]) {
          const kid = kidList[cursor[top]++];
          tin[kid] = time; domOrder[time++] = kid; top += 1; nodes[top] = kid; cursor[top] = kidStart[kid];
        } else { tout[v] = time; top -= 1; }
      }
    }
    const dominates = (a, b) => tin[a] <= tin[b] && tout[b] <= tout[a];
    const weight = v => tout[v] - tin[v];
    const kidsOf = v => Array.from(kidList.subarray(kidStart[v], kidStart[v + 1]));
    const childContaining = (p, v) => {
      let low = kidStart[p], high = kidStart[p + 1] - 1;
      while (low < high) {
        const mid = (low + high + 1) >> 1;
        if (tin[kidList[mid]] <= tin[v]) low = mid; else high = mid - 1;
      }
      return kidList[low];
    };

    // Sibling precedence collapses each child's subtree to one layer member.
    // `prefer` orders a member its parent enters: a taken arm to the left of a
    // not-taken one, br_table arms by case.
    const hPred = new Int32Array(edgeCount).fill(-1), prefer = new Float64Array(n), caseOf = new Float64Array(n).fill(-1);
    for (let e = 0; e < edgeCount; e += 1) {
      if (!counted(e) || retreat[e]) continue;
      const v = to[e], p = idom[v], u = from[e];
      if (u === p) {
        const kind = graph.kind[e];
        if (kind === KIND.taken) prefer[v] = -0.5; else if (kind === KIND.not_taken) prefer[v] = 0.5;
        if (kind === KIND.table || kind === KIND.table_default) {
          const first = kind === KIND.table ? Number.parseInt(graph.labels[e], 10) : Number.POSITIVE_INFINITY;
          caseOf[v] = Number.isNaN(first) ? Number.POSITIVE_INFINITY : caseOf[v] < 0 ? first : Math.min(caseOf[v], first);
        }
      } else if (dominates(p, u)) hPred[e] = childContaining(p, u);
    }
    const hp = grouped(n, edgeCount, e => (hPred[e] >= 0 ? to[e] : -1));
    // Edges leaving each child's subtree, in O(n + E): +1 at the source, -1 at
    // the edge's lowest common dominator, summed up each subtree. A terminal
    // arm (an early return) has no way out.
    const exits = new Int32Array(N);
    for (let e = 0; e < edgeCount; e += 1) {
      if (!counted(e)) continue;
      const u = from[e], v = to[e];
      let lca = idom[v];
      if (retreat[e]) {
        if (dominates(v, u)) lca = v;
        else { lca = u; while (!dominates(lca, v)) lca = idom[lca]; }
      }
      exits[u] += 1; exits[lca] -= 1;
    }
    for (let k = N - 1; k >= 1; k -= 1) exits[idom[domOrder[k]]] += exits[domOrder[k]];

    // Layers of a parent's children, each ordered by its predecessors' places
    // (one barycenter sweep) and shaped: a heavy member continues the spine,
    // a few terminal members stack, the rest are side by side.
    const layerOf = new Int32Array(n), slot = new Float64Array(n);
    const ordered = layer => {
      const key = new Map();
      for (const child of layer) {
        let sum = 0, seen = 0;
        for (let k = hp.start[child]; k < hp.start[child + 1]; k += 1) { sum += slot[hPred[hp.list[k]]]; seen += 1; }
        key.set(child, caseOf[child] >= 0 ? caseOf[child] : seen ? sum / seen : prefer[child]);
      }
      const byCase = layer.every(child => caseOf[child] >= 0);
      return layer.sort((a, b) => (byCase || (caseOf[a] < 0) === (caseOf[b] < 0) ? key.get(a) - key.get(b) : caseOf[a] < 0 ? -1 : 1) || pos[a] - pos[b]);
    };
    const layersOf = members => {
      const layers = [];
      for (const child of members) {
        let layer = 0;
        for (let k = hp.start[child]; k < hp.start[child + 1]; k += 1) layer = Math.max(layer, layerOf[hPred[hp.list[k]]] + 1);
        layerOf[child] = layer;
        (layers[layer] ??= []).push(child);
      }
      const shaped = [];
      for (const layer of layers) {
        if (layer.length > 1) ordered(layer);
        layer.forEach((child, index) => { slot[child] = layer.length > 1 ? (2 * index + 1) / layer.length - 1 : 0; });
        if (layer.length < 2) { shaped.push(layer); continue; }
        let heavy = layer[0], rest = 0;
        for (const child of layer) if (weight(child) > weight(heavy)) heavy = child;
        for (const child of layer) if (child !== heavy) rest += weight(child);
        if (weight(heavy) >= 2 && weight(heavy) >= SPINE_WEIGHT * rest && layer.length - 1 <= WRAP_AT) {
          shaped.push({spine: heavy, side: layer.filter(child => child !== heavy)});
          continue;
        }
        const terminal = layer.filter(child => exits[child] === 0), others = layer.filter(child => exits[child] !== 0);
        if (!terminal.length || terminal.length > 3 && !others.length) { shaped.push(layer); continue; }
        if (terminal.length <= 3) for (const child of terminal) shaped.push([child]); else shaped.push(terminal);
        if (others.length) shaped.push(others);
      }
      return shaped;
    };
    // The virtual root's reachable children lay out like any parent's, the
    // entry first; observed runs stack in order. Unreachable children are
    // grouped into components by the edges among them, one box each.
    const rootLayers = () => {
      const kids = kidsOf(V), reached = kids.filter(kid => live[kid]), dead = kids.filter(kid => !live[kid]);
      // Declared entries come first, in the order they are declared.
      const entries = new Map();
      for (const root of graph.roots ?? [0]) if (root >= 0 && root < n && live[root] && !entries.has(root)) entries.set(root, entries.size);
      for (const [root, index] of entries) prefer[root] = index - n - 2;
      const layers = graph.stackedRoots
        ? reached.sort((a, b) => (entries.get(a) ?? n) - (entries.get(b) ?? n) || pos[a] - pos[b]).map(kid => [kid])
        : layersOf(reached);
      if (!dead.length) return layers;
      const find = new Int32Array(n).map((_, index) => index);
      const root = v => { while (find[v] !== v) { find[v] = find[find[v]]; v = find[v]; } return v; };
      for (let e = 0; e < edgeCount; e += 1) if (counted(e) && !live[from[e]]) { const a = root(from[e]), b = root(to[e]); if (a !== b) find[Math.max(a, b)] = Math.min(a, b); }
      const components = new Map();
      for (const kid of dead) { const id = root(kid); if (!components.has(id)) components.set(id, []); components.get(id).push(kid); }
      // In block order: the component of the lowest block first.
      layers.push({components: [...components.entries()].sort((a, b) => a[0] - b[0]).map(entry => entry[1])});
      return layers;
    };

    const boxes = [], nodeBox = new Int32Array(n).fill(-1), nodeRow = new Int32Array(n), nodeItem = new Int32Array(n);
    const makeBox = (root, parentBox, parentRow, parentItem, members = null) => {
      const box = {id: boxes.length, root, members, rows: [], parent: parentBox, parentRow, parentItem, routes: new Map(), routeList: [], left: 0, right: 0, gaps: [], w: 0, h: 0, cx: 0};
      boxes.push(box); return box;
    };
    const pending = [makeBox(V, -1, 0, 0)];
    while (pending.length) {
      const box = pending.pop();
      const stack = [];
      const place = node => {
        box.rows.push({items: [{node}]});
        nodeBox[node] = box.id; nodeRow[node] = box.rows.length - 1; nodeItem[node] = 0;
        stack.push({layers: layersOf(kidsOf(node)), next: 0});
      };
      if (box.root === V) stack.push({layers: rootLayers(), next: 0});
      else if (box.root < 0) stack.push({layers: layersOf(box.members), next: 0});
      else place(box.root);
      while (stack.length) {
        const top = stack[stack.length - 1];
        if (top.next >= top.layers.length) { stack.pop(); continue; }
        const layer = top.layers[top.next++];
        if (layer.spine !== undefined) {
          // The heavy member stays on this box's axis, the others beside it.
          const row = {items: [{node: layer.spine}], spine: true};
          box.rows.push(row);
          const at = box.rows.length - 1;
          nodeBox[layer.spine] = box.id; nodeRow[layer.spine] = at; nodeItem[layer.spine] = 0;
          for (const child of layer.side) {
            const sub = makeBox(child, box.id, at, row.items.length);
            row.items.push({box: sub.id}); pending.push(sub);
          }
          stack.push({layers: layersOf(kidsOf(layer.spine)), next: 0});
          continue;
        }
        const members = layer.components ?? layer;
        if (!layer.components && members.length === 1) { place(members[0]); continue; }
        // Every member of a layer is independent of the others, so wrapping
        // one wide layer never reorders an edge. A dispatcher's arms land here.
        const columns = members.length > WRAP_AT ? Math.max(2, Math.ceil(Math.sqrt(members.length) * 1.15)) : members.length;
        const group = box.rows.length;
        for (let start = 0; start < members.length; start += columns) {
          const row = {items: [], group};
          box.rows.push(row);
          members.slice(start, start + columns).forEach((member, itemIndex) => {
            const sub = layer.components ? makeBox(-1, box.id, box.rows.length - 1, itemIndex, member) : makeBox(member, box.id, box.rows.length - 1, itemIndex);
            row.items.push({box: sub.id}); pending.push(sub);
          });
        }
      }
    }

    // Routes are per-box pieces shared by every edge taking the same path, so
    // a fan of edges is drawn from one set of segments, not one per edge. A
    // piece's destination is the box bottom (T), the bottom back port (B), a
    // loop rail into a block's side, a sub-box, a block, or a rail into the
    // top of a sub-box.
    const DEST_T = 0, DEST_B = 1, RAIL = 0, SUB = 1, NODE = 2, RAIL_TOP = 3;
    const destCode = (type, id) => 2 + id * 4 + type;
    const codeType = code => (code < 2 ? -1 : (code - 2) % 4), codeId = code => (code - 2 - codeType(code)) / 4;
    const leftward = code => codeType(code) === RAIL || codeType(code) === RAIL_TOP;
    // Box intervals, so a climb knows when it holds a target.
    const boxIn = new Int32Array(boxes.length), boxOut = new Int32Array(boxes.length);
    {
      const kids = boxes.map(() => []);
      for (const box of boxes) if (box.parent >= 0) kids[box.parent].push(box.id);
      let time = 0;
      const stack = [[0, 0]]; boxIn[0] = time++;
      while (stack.length) {
        const top = stack[stack.length - 1];
        if (top[1] < kids[top[0]].length) { const kid = kids[top[0]][top[1]++]; boxIn[kid] = time++; stack.push([kid, 0]); }
        else { boxOut[top[0]] = time; stack.pop(); }
      }
    }
    const holds = (outer, inner) => boxIn[outer] <= boxIn[inner] && boxOut[inner] <= boxOut[outer];
    const chains = new Array(edgeCount);
    let direct = 0;
    for (let e = 0; e < edgeCount; e += 1) {
      if (!counted(e)) continue;
      const u = from[e], v = to[e];
      const back = retreat[e];
      // A retreat edge climbs to the box that holds its target and rises on
      // that box's left rail into the target's side. When the target roots a
      // box beside its source's (a loop with two entries in unreachable code),
      // the rail turns into that box from above. One into the middle of a box
      // it cannot reach either way is drawn directly and counted.
      const targetBox = nodeBox[v];
      const rooted = boxes[targetBox].root === v && boxes[targetBox].parent >= 0;
      const destBox = !back ? (rooted ? boxes[targetBox].parent : targetBox) : -1;
      const pieces = [];
      let cur = nodeBox[u], row = nodeRow[u], item = nodeItem[u];
      while (cur >= 0 && (back ? !holds(cur, targetBox) : cur !== destBox)) {
        pieces.push(cur, row, item, back ? DEST_B : DEST_T);
        const box = boxes[cur];
        row = box.parentRow; item = box.parentItem; cur = box.parent;
      }
      let code = -1;
      if (cur >= 0 && !back) code = rooted ? destCode(SUB, targetBox) : destCode(NODE, v);
      else if (cur >= 0 && cur === targetBox) code = destCode(RAIL, v);
      else if (cur >= 0 && rooted && boxes[targetBox].parent === cur && boxes[targetBox].parentRow < row) code = destCode(RAIL_TOP, targetBox);
      if (code < 0) { direct += 1; continue; }
      pieces.push(cur, row, item, code);
      chains[e] = pieces;
    }
    // Where an edge first heads from its block: left to a loop rail, right to
    // a far rail, or toward the item it enters next. It picks the port.
    const destRowOf = (box, code) => {
      if (code < 2) return box.rows.length;
      const type = codeType(code), id = codeId(code);
      return type === SUB || type === RAIL_TOP ? boxes[id].parentRow : nodeRow[id];
    };
    const heading = e => {
      const pieces = chains[e], box = boxes[pieces[0]], row = pieces[1], code = pieces[3];
      if (leftward(code)) return -2;
      const target = destRowOf(box, code);
      if (target > row + 1 || code === DEST_B) return code === DEST_B ? -1 : 2;
      if (codeType(code) === SUB) {
        const sub = boxes[codeId(code)], within = box.rows[sub.parentRow];
        return within.spine ? 1 : within.items.length > 1 ? (2 * sub.parentItem + 1) / within.items.length - 1 : 0;
      }
      return 0;
    };
    const port = new Int8Array(edgeCount);
    for (let u = 0; u < n; u += 1) {
      const mine = [];
      for (let k = out.start[u]; k < out.start[u + 1]; k += 1) if (chains[out.list[k]]) mine.push(out.list[k]);
      if (mine.length < 2 || mine.length > 2) continue;
      const [a, b] = mine, ha = heading(a), hb = heading(b);
      if (ha === 0 && hb !== 0) port[b] = Math.sign(hb);
      else if (hb === 0 && ha !== 0) port[a] = Math.sign(ha);
      else if (ha !== hb) { port[a] = ha < hb ? -1 : 1; port[b] = -port[a]; }
      else {
        const side = kind => (kind === KIND.taken ? -1 : kind === KIND.not_taken ? 1 : 0);
        port[a] = side(graph.kind[a]); port[b] = side(graph.kind[b]);
        if (port[a] === port[b]) { port[a] = -1; port[b] = 1; }
      }
    }
    // A route is keyed by its source (row, item, port) and its destination.
    const edgeRoutes = new Array(edgeCount);
    for (let e = 0; e < edgeCount; e += 1) {
      const pieces = chains[e];
      if (!pieces) continue;
      const list = [];
      for (let k = 0; k < pieces.length; k += 4) {
        const box = boxes[pieces[k]], row = pieces[k + 1], item = pieces[k + 2], code = pieces[k + 3], p = k === 0 ? port[e] : 0;
        if (!box.itemBase) { box.itemBase = new Int32Array(box.rows.length + 1); box.rows.forEach((at, index) => { box.itemBase[index + 1] = box.itemBase[index] + at.items.length; }); }
        const source = (box.itemBase[row] + item) * 3 + p + 1;
        let byDest = box.routes.get(source);
        if (!byDest) box.routes.set(source, byDest = new Map());
        let found = byDest.get(code);
        if (!found) { found = {row, item, port: p, source, code, gapFrom: row + 1, gapTo: -1, destRow: -1, far: false, rail: -1, side: 0}; byDest.set(code, found); box.routeList.push(found); }
        list.push(found);
      }
      edgeRoutes[e] = list;
    }

    // Lanes. A gap belongs to the row beneath it; gap R is below the last row.
    for (const box of boxes) {
      const gapCount = box.rows.length + 1;
      box.gaps = Array.from({length: gapCount}, () => new Map());
      const routes = box.routeList;
      const sources = new Map(), dests = new Map();
      for (const r of routes) {
        r.destRow = destRowOf(box, r.code);
        r.gapTo = r.destRow;
        r.far = leftward(r.code) || r.destRow > r.gapFrom;
        r.side = leftward(r.code) ? -1 : r.far ? 1 : 0;
        // A far route has a second lane where it turns toward its target,
        // except a loop rail, which enters its target's side.
        r.second = r.far && codeType(r.code) !== RAIL;
        if (!sources.has(r.source)) sources.set(r.source, sources.size);
        if (!dests.has(r.code)) dests.set(r.code, dests.size);
        r.sourceId = sources.get(r.source); r.destId = dests.get(r.code);
      }
      const sourceCount = Math.max(1, sources.size), destCount = Math.max(1, dests.size);
      const groups = new Map();
      const count = key => groups.set(key, (groups.get(key) ?? 0) + 1);
      const sKey = (gap, r) => (gap * sourceCount + r.sourceId) * 2, dKey = (gap, r) => (gap * destCount + r.destId) * 2 + 1;
      for (const r of routes) {
        count(sKey(r.gapFrom, r)); count(dKey(r.gapFrom, r));
        if (r.second) { count(sKey(r.gapTo, r)); count(dKey(r.gapTo, r)); }
      }
      // A lane is shared by a fan-out from one source or a fan-in to one
      // destination, whichever is larger in that gap.
      const laneKey = (r, gap) => ((groups.get(sKey(gap, r)) ?? 0) >= (groups.get(dKey(gap, r)) ?? 0) ? r.sourceId * 2 : r.destId * 2 + 1);
      // Each lane records whether a route drops into it from the row above
      // and whether one leaves it down into the row below; their order is
      // chosen once positions are known.
      const lane = (map, key) => {
        let found = map.get(key);
        if (!found) map.set(key, found = {top: false, bottom: false, side: 0, low: Infinity, high: -Infinity, index: map.size});
        return found;
      };
      for (const r of routes) {
        const first = r.laneFrom = lane(box.gaps[r.gapFrom], laneKey(r, r.gapFrom));
        first.top = true;
        if (!r.far) first.bottom = true; else first.side = r.side;
        if (r.second) { r.laneTo = lane(box.gaps[r.gapTo], laneKey(r, r.gapTo)); r.laneTo.bottom = true; r.laneTo.side = r.side; }
      }
      // Rails are colored like intervals: a rail only needs its own column
      // while its rows overlap another's, so a long guard chain stays narrow.
      // A fan-out shares one feeder rail per source; a fan-in, such as every
      // exit to a box's bottom port, shares one rail per destination.
      const farSources = new Map(), farDests = new Map();
      for (const r of routes) {
        if (r.side <= 0) continue;
        farSources.set(r.sourceId, (farSources.get(r.sourceId) ?? 0) + 1); farDests.set(r.destId, (farDests.get(r.destId) ?? 0) + 1);
      }
      const railKey = r => (r.side < 0 ? r.destId * 2 + 1 : (farSources.get(r.sourceId) ?? 0) > (farDests.get(r.destId) ?? 0) ? r.sourceId * 2 : r.destId * 2 + 1);
      const colorRails = (side, spanOf) => {
        const spans = new Map();
        for (const r of routes) {
          if (r.side !== side) continue;
          const key = railKey(r), span = spanOf(r), known = spans.get(key);
          if (known) { known.low = Math.min(known.low, span.low); known.high = Math.max(known.high, span.high); known.routes.push(r); }
          else spans.set(key, {low: span.low, high: span.high, routes: [r]});
        }
        // Greedy interval coloring with the lowest free column, in O(k log k).
        // Column 0 is outermost, and of two spans from one row the longer
        // takes it, so nested spans nest their rails.
        const sorted = [...spans.values()].sort((a, b) => a.low - b.low || b.high - a.high);
        const busy = heap((a, b) => a.high - b.high || a.column - b.column), free = heap((a, b) => a - b);
        let columns = 0;
        for (const span of sorted) {
          while (busy.size && busy.peek().high < span.low) free.push(busy.pop().column);
          span.column = free.size ? free.pop() : columns++;
          busy.push(span);
          for (const r of span.routes) r.rail = span.column;
        }
        return columns;
      };
      box.hasForwardExit = routes.some(r => r.code === DEST_T);
      box.left = colorRails(-1, r => ({low: Math.min(r.destRow, r.gapFrom), high: Math.max(r.destRow, r.gapFrom)}));
      box.right = colorRails(1, r => ({low: r.gapFrom, high: r.gapTo}));
      // A lane that turns onto a rail takes its routes' outermost one.
      for (const r of routes) {
        if (!r.far) continue;
        r.laneFrom.rail = Math.min(r.laneFrom.rail ?? Infinity, r.rail);
        if (r.laneTo) r.laneTo.rail = Math.min(r.laneTo.rail ?? Infinity, r.rail);
      }
    }
    const gapHeight = (box, g) => {
      const lanes = box.gaps[g]?.size ?? 0;
      // An edge-free gap still separates rows, such as observed runs and gaps.
      if (!lanes) return g > 0 && g < box.rows.length ? m.gapY : 0;
      return Math.max(m.gapY, 16 + lanes * m.lane + 12);
    };

    // Sizes bottom-up: a box's children appear later in `boxes`, so a reverse
    // walk sizes every child first. Every block sits on its box's axis: a
    // spine row extends to the right of it, any other row is centered on it.
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
      const itemWidth = item => (item.node !== undefined ? nodeW[item.node] : boxes[item.box].w);
      const itemHeight = item => (item.node !== undefined ? nodeH[item.node] : boxes[item.box].h);
      let axisLeft = 0, axisRight = 0;
      for (const row of box.rows) {
        const widths = row.group !== undefined ? columnWidths.get(row.group) : null;
        row.w = row.items.reduce((sum, item, column) => sum + (widths ? widths[column] : itemWidth(item)), 0) + m.gapX * (row.items.length - 1);
        row.widths = widths;
        if (row.items[0].node !== undefined) {
          const half = nodeW[row.items[0].node] / 2;
          row.left = half; row.right = row.w - half;
        } else { row.left = row.w / 2; row.right = row.w / 2; }
        axisLeft = Math.max(axisLeft, row.left); axisRight = Math.max(axisRight, row.right);
      }
      const leftW = box.left ? box.left * m.lane + m.side * 2 : 0;
      const rightW = box.right ? box.right * m.lane + m.side * 2 : 0;
      box.w = leftW + axisLeft + axisRight + rightW;
      box.cx = leftW + axisLeft;
      let y = 0;
      box.rows.forEach((row, index2) => {
        const gap = gapHeight(box, index2);
        y += gap; row.gapTop = y - gap; row.y = y; row.h = 0;
        let x = box.cx - row.left;
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
    const rootBox = boxes[0];
    absX[0] = m.margin; absY[0] = m.margin;
    const x = new Float32Array(n), y = new Float32Array(n);
    for (let index = 0; index < boxes.length; index += 1) {
      for (const row of boxes[index].rows) {
        for (const item of row.items) {
          if (item.node !== undefined) { x[item.node] = absX[index] + item.x; y[item.node] = absY[index] + item.y; }
          else { absX[item.box] = absX[index] + item.x; absY[item.box] = absY[index] + item.y; }
        }
      }
    }

    // Each route's ends, then its lanes' order, then its polyline.
    const gapLaneY = (box, gapIndex, lane) => {
      const at = gapIndex >= box.rows.length ? box.bottomGapTop : box.rows[gapIndex].gapTop;
      return absY[box.id] + at + 12 + lane.index * m.lane;
    };
    // Back edges only get their own port when a forward exit shares this box.
    const bottomPort = (box, back) => ({x: absX[box.id] + box.cx + (back && box.hasForwardExit ? -m.lane : 0), y: absY[box.id] + box.h});
    const portOffset = (width, p) => p * Math.min(width / 4, 26);
    const isRail = code => codeType(code) === RAIL;
    const span = (lane, a, b) => { lane.low = Math.min(lane.low, a, b); lane.high = Math.max(lane.high, a, b); };
    for (const box of boxes) {
      for (const r of box.routeList) {
        const item = box.rows[r.row].items[r.item];
        if (item.node !== undefined) { r.sx = x[item.node] + nodeW[item.node] / 2 + portOffset(nodeW[item.node], r.port); r.sy = y[item.node] + nodeH[item.node]; }
        else { const p = bottomPort(boxes[item.box], r.code === DEST_B || isRail(r.code)); r.sx = p.x; r.sy = p.y; }
        if (isRail(r.code)) {
          const node = codeId(r.code);
          r.tx = x[node]; r.ty = y[node] + Math.min(14, nodeH[node] / 2);
        } else if (r.code < 2) { const p = bottomPort(box, r.code === DEST_B); r.tx = p.x; r.ty = p.y; }
        else {
          const type = codeType(r.code), id = codeId(r.code), node = type === SUB || type === RAIL_TOP ? boxes[id].root : id;
          r.tx = x[node] + nodeW[node] / 2; r.ty = y[node];
        }
        r.rx = r.side < 0 ? absX[box.id] + m.side + r.rail * m.lane : absX[box.id] + box.w - m.side - r.rail * m.lane - 2;
        span(r.laneFrom, r.sx, r.far ? r.rx : r.tx);
        if (r.laneTo) span(r.laneTo, r.rx, r.tx);
      }
      // Lanes that only leave the row above go first, so no departure crosses
      // a drop into the row below; arrivals go last. A departure to an outer
      // rail runs above one to an inner rail, and then the nearer source runs
      // lower; an arrival from an outer rail runs below, and then the farther
      // target runs higher.
      for (const gap of box.gaps) {
        if (gap.size < 2) continue;
        const rank = lane => (lane.top && !lane.bottom ? (lane.side < 0 ? 0 : 1) : lane.top ? 2 : lane.side < 0 ? 3 : 4);
        const order = (a, b) => {
          const group = rank(a);
          if (group === 0) return a.rail - b.rail || a.high - b.high;
          if (group === 1) return a.rail - b.rail || b.low - a.low;
          if (group === 3) return b.rail - a.rail || b.high - a.high;
          if (group === 4) return b.rail - a.rail || a.low - b.low;
          return 0;
        };
        [...gap.values()].sort((a, b) => rank(a) - rank(b) || order(a, b) || a.index - b.index).forEach((lane, index) => { lane.index = index; });
      }
      for (const r of box.routeList) {
        const ly1 = gapLaneY(box, r.gapFrom, r.laneFrom);
        const points = [r.sx, r.sy, r.sx, ly1];
        if (isRail(r.code)) points.push(r.rx, ly1, r.rx, r.ty, r.tx, r.ty);
        else if (r.second) { const ly2 = gapLaneY(box, r.gapTo, r.laneTo); points.push(r.rx, ly1, r.rx, ly2, r.tx, ly2, r.tx, r.ty); }
        else points.push(r.tx, ly1, r.tx, r.ty);
        r.points = points;
      }
    }
    const stubCount = new Int32Array(n);
    const pointStart = new Uint32Array(edgeCount + 1);
    const flat = [];
    const bounds = new Float32Array(edgeCount * 4);
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
      const u = from[e], v = to[e];
      const anchor = edgeAnchor = flat.length;
      if (v < 0 || stub[e]) {
        const slotIndex = stubCount[u]++;
        const sx = x[u] + nodeW[u] / 2 + (slotIndex === 0 ? 0 : (slotIndex % 2 ? 1 : -1) * Math.ceil(slotIndex / 2) * 28);
        pushPoint(sx, y[u] + nodeH[u]); pushPoint(sx, y[u] + nodeH[u] + 18);
      } else if (!edgeRoutes[e]) {
        pushPoint(x[u] + nodeW[u] / 2, y[u] + nodeH[u]);
        pushPoint(x[v] + nodeW[v] / 2, y[v]);
      } else {
        for (const piece of edgeRoutes[e]) {
          const pts = piece.points;
          for (let i = 0; i < pts.length; i += 2) pushPoint(pts[i], pts[i + 1]);
        }
      }
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      for (let i = anchor; i < flat.length; i += 2) {
        minX = Math.min(minX, flat[i]); maxX = Math.max(maxX, flat[i]); minY = Math.min(minY, flat[i + 1]); maxY = Math.max(maxY, flat[i + 1]);
      }
      bounds[e * 4] = minX; bounds[e * 4 + 1] = minY; bounds[e * 4 + 2] = maxX; bounds[e * 4 + 3] = maxY;
    }
    pointStart[edgeCount] = flat.length / 2;
    return {x, y, w: nodeW, h: nodeH, pointStart, points: Float32Array.from(flat), box: bounds, back: retreat, stub,
      direct, width: rootBox.w + m.margin * 2, height: rootBox.h + m.margin * 2};
  }

  /** Worker entry: parses, normalizes and lays out, off the main thread. */
  function run(message) {
    const metrics = {...METRICS, ...message.metrics};
    let graph, starts = null;
    if (message.type === 'wasm') {
      const doc = JSON.parse(new TextDecoder().decode(message.buffer));
      starts = typeof doc?.rows === 'string' ? rowStarts(doc.rows) : null;
      graph = wasmGraph(doc, starts);
    } else if (message.type === 'vm') graph = vmStaticGraph(message.report);
    else if (message.type === 'observed') graph = vmObservedGraph(message.path);
    else if (message.type === 'graph') graph = message.graph;
    else throw Error('Unknown layout request.');
    starts ??= rowStarts(graph.rows);
    const sizes = nodeSizes(graph, starts, metrics);
    const layout = layoutGraph(graph, sizes, metrics);
    layout.engine = {name: 'layered'};
    return {graph, starts, layout};
  }

  /* Triskel, through graphLayoutClient, is a CFG layout engine built on
   * single-entry single-exit regions. It runs only when the researcher asks,
   * over a region layout already drawn, and its answer is drawn whatever its
   * size, with how much wider and taller it is than the region layout. The
   * region layout stays where the client says why: the function is one block,
   * it was stopped, or the route is missing or fails. `progress` hears
   * {stage: 'triskel'} once a request is sent; `signal` stops it. Stubs stay
   * stubs: an edge from unreachable code is not sent. */
  async function withTriskel(result, metrics, {signal = null, progress = null} = {}) {
    const m = {...METRICS, ...metrics}, {graph, layout} = result, n = graph.count;
    const keep = reason => { layout.engine = {name: 'layered', reason}; return result; };
    if (n < 2) return keep({code: 'one_block'});
    const resolved = [];
    for (let e = 0; e < graph.from.length; e += 1) if (graph.to[e] >= 0 && !layout.stub?.[e]) resolved.push(e);
    const width = layout.width - m.margin * 2, height = layout.height - m.margin * 2;
    const {outcomes: [outcome], revision} = await graphLayoutClient.layOut([{nodes: Array.from({length: n}, (_, v) => [layout.w[v], layout.h[v]]),
      edges: resolved.map(e => [graph.from[e], graph.to[e]]), width, height}],
    {all: true, keep: true, signal, onSend: () => progress?.({stage: 'triskel'})});
    if (!outcome.result) return keep(outcome.reason);
    const laid = outcome.result, x = new Float32Array(n), y = new Float32Array(n);
    for (let v = 0; v < n; v += 1) { x[v] = m.margin + laid.nodes[v][0]; y[v] = m.margin + laid.nodes[v][1]; }
    const routeOf = new Map(resolved.map((e, i) => [e, laid.edges[i]]));
    const edgeCount = graph.from.length, pointStart = new Uint32Array(edgeCount + 1), flat = [], bounds = new Float32Array(edgeCount * 4), stubs = new Int32Array(n);
    let maxX = m.margin + laid.width, maxY = m.margin + laid.height;
    for (let e = 0; e < edgeCount; e += 1) {
      pointStart[e] = flat.length / 2;
      const anchor = flat.length, from = graph.from[e];
      if (!routeOf.has(e)) {
        // An edge with no resolved target, or from unreachable code, keeps its stub under the block.
        const slot = stubs[from]++, sx = x[from] + layout.w[from] / 2 + (slot === 0 ? 0 : (slot % 2 ? 1 : -1) * Math.ceil(slot / 2) * 28);
        flat.push(sx, y[from] + layout.h[from], sx, y[from] + layout.h[from] + 18);
      } else flat.push(...graphLayoutClient.routePoints(routeOf.get(e), m.margin, m.margin));
      let minX = Infinity, minY = Infinity, hiX = -Infinity, hiY = -Infinity;
      for (let i = anchor; i < flat.length; i += 2) { minX = Math.min(minX, flat[i]); hiX = Math.max(hiX, flat[i]); minY = Math.min(minY, flat[i + 1]); hiY = Math.max(hiY, flat[i + 1]); }
      bounds[e * 4] = minX; bounds[e * 4 + 1] = minY; bounds[e * 4 + 2] = hiX; bounds[e * 4 + 3] = hiY;
      maxX = Math.max(maxX, hiX); maxY = Math.max(maxY, hiY);
    }
    pointStart[edgeCount] = flat.length / 2;
    const ratio = {width: laid.width / Math.max(1, width), height: laid.height / Math.max(1, height)};
    result.layout = {...layout, x, y, pointStart, points: Float32Array.from(flat), box: bounds, direct: 0, width: maxX + m.margin, height: maxY + m.margin,
      engine: {name: 'triskel', revision, ratio}};
    return result;
  }
  /** A region layout, or (type `triskel`) Triskel over a region layout
   * already drawn: the message carries only the graph's count and edges and
   * that layout's card sizes, extent and stubs, and the answer only a layout. */
  async function runAsync(message, {signal = null, progress = null} = {}) {
    if (message.type === 'triskel') return withTriskel({graph: message.graph, starts: null, layout: message.layout}, message.metrics, {signal, progress});
    return run(message);
  }

  const transfer = ({graph, starts, layout}) => [graph.offsets, graph.ends, graph.firstRow, graph.rowCount, graph.instructionCount, graph.flags, graph.folded, graph.from, graph.to, graph.kind,
    starts, layout.x, layout.y, layout.w, layout.h, layout.pointStart, layout.points, layout.box, layout.back, layout.stub].filter(Boolean).map(array => array.buffer);

  return {METRICS, wasmGraph, vmStaticGraph, vmObservedGraph, rowStarts, nodeSizes, shownRows, layoutGraph, runAsync, withTriskel, transfer};
})();

if (typeof module === 'object' && module?.exports) module.exports = blockGraphLayout;
else if (typeof importScripts === 'function') {
  importScripts('graph_layout_client.js');
  // {cancel: id} stops Triskel for that job, which still answers with its
  // region layout; {id, progress} reports a stage before the answer.
  const running = new Map();
  self.onmessage = async event => {
    const {id, cancel} = event.data;
    if (cancel !== undefined) { running.get(cancel)?.abort(); return; }
    const controller = new AbortController();
    running.set(id, controller);
    try {
      const result = await blockGraphLayout.runAsync(event.data, {signal: controller.signal, progress: stage => self.postMessage({id, progress: stage})});
      self.postMessage({id, ok: true, result}, blockGraphLayout.transfer(result));
    } catch (error) {
      self.postMessage({id, ok: false, error: error?.message ?? 'Layout failed.', name: error?.name ?? 'Error'});
    } finally {
      running.delete(id);
    }
  };
}
