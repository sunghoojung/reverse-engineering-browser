/* Basic-block graph view: one function or bytecode image at a time. The drawing
 * is a single canvas, so nothing here scales DOM with graph size. Layout runs in
 * block_graph_layout.js as a Web Worker. Captured text is painted as glyphs. */
const BLOCK_GRAPH_KIND = {fallthrough: 0, branch: 1, taken: 2, not_taken: 3, table: 4, table_default: 5, exception: 6, unresolved: 7, call: 8, assumed: 9, sequence: 10};
const BLOCK_GRAPH_LIMITS = 'Declared flow, not observed execution. A complete drawing is not a proof.';
/* Rows are drawn only where 11 px text stays readable; below it, labels are
 * painted at screen size and a cue says rows are hidden. */
const BLOCK_GRAPH_ROW_ZOOM = 0.6;
/* Layouts are retained in a small byte budget, never a whole-module set. */
const BLOCK_GRAPH_CACHE_BYTES = 16 * 1024 * 1024;
/* The backing store is the view's one allocation that scales with window size. */
const BLOCK_GRAPH_CANVAS_BYTES = 32 * 1024 * 1024;
const GRAPH_ZOOM = Object.freeze({min: 0.02, max: 2.5});

/* Helpers this view shares with the flow graph (flow_graph.js, which loads
 * after this file). A view is {x, y, z}: the graph point at the canvas's top
 * left and the zoom. */

/** A rounded rectangle path on `ctx`; the caller fills or strokes it. */
function graphRoundedRect(ctx, x, y, w, h, r) {
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

/** Sizes `canvas` to `stage` at the device pixel ratio, lowered so the
 * backing store stays within BLOCK_GRAPH_CANVAS_BYTES. Returns the stage's
 * CSS size and the ratio used. */
function graphFitCanvas(canvas, stage) {
  const rect = stage.getBoundingClientRect();
  const cssW = Math.max(1, Math.floor(rect.width)), cssH = Math.max(1, Math.floor(rect.height));
  const dpr = Math.min(window.devicePixelRatio || 1, Math.sqrt(BLOCK_GRAPH_CANVAS_BYTES / (4 * cssW * cssH)), 3);
  const pw = Math.round(cssW * dpr), ph = Math.round(cssH * dpr);
  if (canvas.width !== pw || canvas.height !== ph) {
    canvas.width = pw;
    canvas.height = ph;
    canvas.style.width = `${cssW}px`;
    canvas.style.height = `${cssH}px`;
  }
  return {cssW, cssH, dpr};
}

/** `view` zoomed by `factor` about the screen point (cx, cy), which stays
 * over the same graph point. */
function graphZoomAt(view, factor, cx, cy) {
  const z = Math.min(GRAPH_ZOOM.max, Math.max(GRAPH_ZOOM.min, view.z * factor));
  const gx = view.x + cx / view.z, gy = view.y + cy / view.z;
  return {x: gx - cx / z, y: gy - cy / z, z};
}

/* Reads Sources and the Flow workspace's CFG pane share. Each throws an Error
 * whose message can be shown; an aborted read throws an AbortError. */

/** The error a failed response carries: its JSON `error`, else `fallback`. */
async function responseError(response, fallback) {
  try { return Error((await response.json()).error || fallback); } catch { return Error(fallback); }
}

/** What a failed read tells the researcher. */
const graphReadMessage = error => (error instanceof TypeError ? 'The evidence service is unreachable. Check that the session is still running.' : error.message);

/** A module's function index (wasm-function-index-v1): function indexes in
 * order, each body's size and name, and the index's status and omissions. */
async function readWasmFunctionIndex(artifactId, signal) {
  const response = await fetch(`/api/wasm/functions?artifact_id=${encodeURIComponent(artifactId)}`, {cache: 'no-store', signal});
  if (!response.ok) throw await responseError(response, `The function index read returned ${response.status}.`);
  const doc = await response.json();
  if (doc?.schema !== 'wasm-function-index-v1' || String(doc.artifact_id) !== String(artifactId) || !Array.isArray(doc.functions) || !Array.isArray(doc.names))
    throw Error('The function index returned an invalid document.');
  const named = doc.names.filter(entry => Array.isArray(entry) && Number.isSafeInteger(entry[0]) && typeof entry[1] === 'string');
  return {index: doc.functions.map(row => row[0]), size: new Map(doc.functions.map(row => [row[0], row[2] - row[1]])), names: new Map(named),
    status: doc.status, omissions: doc.omissions ?? []};
}

/** One function's basic blocks (wasm-block-graph-v1), decoded and laid out
 * by `runner` with `view`'s measurements; `view` says when layout starts. */
async function loadWasmFunctionGraph({artifactId, functionIndex, view, runner, signal}) {
  const response = await fetch(`/api/wasm/graph?artifact_id=${encodeURIComponent(artifactId)}&function=${functionIndex}`, {cache: 'no-store', signal});
  if (!response.ok) throw await responseError(response, `The block graph read returned ${response.status}.`);
  const buffer = await response.arrayBuffer();
  signal?.throwIfAborted();
  view.setState('loading', 'Laying out the graph…');
  const result = await runner.run({type: 'wasm', buffer, metrics: view.measurements(), engine: blockGraphEngine()}, [buffer]);
  signal?.throwIfAborted();
  result.graph.functionIndex = functionIndex;
  return result;
}

/** Why the region layout stayed (a graphLayoutClient reason, or one_block
 * and not_served from the layout worker), as the header's tooltip words it. */
function blockGraphLayoutReason(reason) {
  switch (reason?.code) {
    case 'one_block': return 'one block';
    case 'too_large': return 'over Triskel\u2019s size limit';
    case 'request_budget': return 'past what one layout request holds';
    case 'wider': return `Triskel would draw it ${reason.ratio.toFixed(1)}\u00d7 wider`;
    case 'taller': return `Triskel would draw it ${reason.ratio.toFixed(1)}\u00d7 taller`;
    case 'mismatch': return 'the Triskel answer did not match the function';
    case 'failed': return `Triskel ${reason.status}${reason.detail ? `: ${reason.detail}` : ''}`;
    case 'status': return `the layout route returned ${reason.status}`;
    case 'route_failed': return `the layout route was unavailable (${reason.detail})`;
    case 'not_served': return 'the layout route is not served here';
    default: return '';
  }
}

/** What the header adds about the layout engine, if anything. */
function blockGraphEngineNote(engine) {
  if (engine?.name === 'triskel') return 'Triskel layout';
  const code = engine?.reason?.code;
  if (code === 'wider' || code === 'taller') return `region layout: Triskel ${engine.reason.ratio.toFixed(1)}\u00d7 ${code}`;
  if (code === 'too_large') return 'region layout: over Triskel\u2019s limit';
  return '';
}

/** Basic blocks for a `reb-vm-static-analysis-v1` report, as declared edges. */
function vmStaticBlockGraph(report) {
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
  const kinds = {fallthrough: BLOCK_GRAPH_KIND.fallthrough, jump: BLOCK_GRAPH_KIND.branch, branch_taken: BLOCK_GRAPH_KIND.taken,
    branch_not_taken: BLOCK_GRAPH_KIND.not_taken, call: BLOCK_GRAPH_KIND.call, call_continuation: BLOCK_GRAPH_KIND.assumed};
  const labels = {branch_taken: 'taken', branch_not_taken: 'not taken', call: 'call', call_continuation: 'assumed continuation', return: 'return: unknown destination', unknown: 'unknown target'};
  const from = [], to = [], kind = [], edgeLabels = [];
  for (const edge of edges) {
    const source = blockOf.get(edge.from_offset);
    if (source === undefined || blocks[source].list.at(-1).offset !== edge.from_offset) continue;
    const resolved = edge.status === 'resolved' && edge.to_offset !== null && blockOf.has(edge.to_offset) && kinds[edge.kind] !== undefined;
    from.push(source);
    if (resolved) { to.push(blockOf.get(edge.to_offset)); kind.push(kinds[edge.kind]); edgeLabels.push(labels[edge.kind] ?? null); }
    else {
      to.push(-1); kind.push(BLOCK_GRAPH_KIND.unresolved);
      edgeLabels.push(edge.to_offset === null ? (labels[edge.kind] ?? 'unresolved') : `${edge.kind} ${edge.status} 0x${hex(edge.to_offset)}`);
    }
  }
  let rows = '';
  let rowIndex = 0;
  const firstRow = new Uint32Array(blocks.length), rowCount = new Uint32Array(blocks.length), counts = new Uint32Array(blocks.length), flags = new Uint32Array(blocks.length),
    offsets = new Float64Array(blocks.length), ends = new Float64Array(blocks.length);
  blocks.forEach((block, index) => {
    firstRow[index] = rowIndex; rowCount[index] = block.list.length; counts[index] = block.list.length; offsets[index] = block.start; ends[index] = block.end;
    if (index === 0) flags[index] |= 1;
    if (reachable.has(block.start)) flags[index] |= 2;
    for (const instruction of block.list) {
      const operands = instruction.operands.map(operand => `${operand.name}=${operand.value}`).join(' ');
      rows += `${hex(instruction.offset)} ${instruction.mnemonic}${operands ? ` ${operands}` : ''}\n`; rowIndex += 1;
    }
  });
  const roots = [...new Set(report.cfg.entries.filter(entry => entry.status === 'resolved' && blockOf.has(entry.offset)).map(entry => blockOf.get(entry.offset)))];
  return {count: blocks.length, offsets, ends, firstRow, rowCount, instructionCount: counts, flags,
    from: Int32Array.from(from), to: Int32Array.from(to), kind: Uint8Array.from(kind), labels: edgeLabels, rows, roots: roots.length ? roots : [0],
    title: report.image.image_id, status: 'decoded', instructions: instructions.length, omissions: [], evidence: 'declared',
    notice: 'cfg.complete is false. Declared edges are not observed execution.'};
}

/** Occurrence graph of retained steps. A gap card has no edge on either side. */
function vmObservedBlockGraph(path) {
  const cards = [], from = [], to = [], kind = [], labels = [];
  const indexOf = new Map();
  let rows = '';
  path.nodes.forEach((node, index) => {
    if (index) {
      const gap = path.gaps.find(item => item.after_sequence === node.sequence);
      if (gap) { cards.push({gap, text: `${gap.missing_steps} steps not retained`}); rows += `${gap.missing_steps} gap missing execution unknown\n`; }
    }
    indexOf.set(node.sequence, cards.length);
    cards.push({node}); rows += `${node.sequence.toString(16)} pc 0x${node.pc_before.toString(16)} op ${node.opcode}\n`;
  });
  for (const edge of path.edges) { from.push(indexOf.get(edge.from_sequence)); to.push(indexOf.get(edge.to_sequence)); kind.push(BLOCK_GRAPH_KIND.sequence); labels.push(null); }
  const count = cards.length;
  const offsets = new Float64Array(count), flags = new Uint32Array(count), firstRow = new Uint32Array(count), rowCount = new Uint32Array(count).fill(1);
  cards.forEach((card, index) => {
    firstRow[index] = index; offsets[index] = card.node ? card.node.sequence : 0;
    flags[index] = card.node ? 2 : 16;
    if (index === 0) flags[index] |= 1;
  });
  // Each run of consecutive sequences and each gap card is its own stacked
  // root, so the layout can never draw an edge across a missing step.
  const roots = cards.map((card, index) => (index === 0 || card.gap || cards[index - 1].gap) ? index : -1).filter(index => index >= 0);
  return {count, offsets, ends: offsets.slice(), firstRow, rowCount, instructionCount: rowCount.slice(), flags,
    from: Int32Array.from(from), to: Int32Array.from(to), kind: Uint8Array.from(kind), labels, rows, roots, stackedRoots: true,
    title: path.identity.trace_id, status: path.coverage.complete ? 'decoded' : 'partial', instructions: path.nodes.length, omissions: [...path.warnings], evidence: 'observed',
    notice: 'Retained steps only. No edge crosses a gap. Not a static control-flow graph.', gaps: path.gaps.length};
}

let blockGraphViews = 0;
function createBlockGraphView(root, options = {}) {
  const node = (tag, className = '', text = '') => { const element = document.createElement(tag); if (className) element.className = className; if (text) element.textContent = text; return element; };
  root.classList.add('block-graph');
  const head = node('div', 'block-graph-head');
  const title = node('strong', 'block-graph-title', 'No function');
  // A researcher name sits beside the captured title and never replaces it.
  const analyst = node('span', 'researcher-name block-graph-analyst-name'); analyst.hidden = true;
  const stats = node('span', 'block-graph-stats', '');
  const tools = node('div', 'block-graph-tools');
  const tool = (label, action, aria) => { const element = node('button', 'source-tool block-graph-tool', label); element.type = 'button'; element.setAttribute('aria-label', aria ?? label); element.addEventListener('click', action); return element; };
  const zoomOut = tool('−', () => zoomAt(0.8), 'Zoom out'), zoomLabel = node('span', 'block-graph-zoom', '100%'), zoomIn = tool('+', () => zoomAt(1.25), 'Zoom in'), fitButton = tool('Fit', fit, 'Fit graph to view');
  const zoomBar = node('div', 'block-graph-zoom-bar'); zoomBar.append(zoomOut, zoomLabel, zoomIn, fitButton);
  tools.append(zoomBar);
  const stage = node('div', 'block-graph-stage');
  const canvas = node('canvas', 'block-graph-canvas');
  canvas.tabIndex = 0; canvas.setAttribute('role', 'application'); canvas.setAttribute('aria-label', 'Basic-block graph. Arrow keys move between blocks, plus and minus zoom, 0 fits, Shift plus arrows pan, Enter shows the selected block in the disassembly and hex.');
  const miniWrap = node('div', 'block-graph-minimap'); const minimap = node('canvas', 'block-graph-minimap-canvas'); minimap.width = 300; minimap.height = 220; minimap.setAttribute('aria-hidden', 'true'); miniWrap.append(minimap);
  const stateBox = node('div', 'block-graph-state'); stateBox.setAttribute('role', 'status'); stateBox.setAttribute('aria-live', 'polite'); stateBox.hidden = true;
  const stateText = node('p', '', ''); const retry = node('button', 'secondary-button', 'Retry'); retry.type = 'button'; retry.hidden = true; stateBox.append(stateText, retry);
  const hud = node('div', 'block-graph-hud');
  const selection = node('span', 'block-graph-selection', ''); selection.setAttribute('role', 'status'); selection.setAttribute('aria-live', 'polite');
  const lodCue = node('span', 'block-graph-lod', 'Overview: zoom in to read instructions'); lodCue.hidden = true;
  hud.append(lodCue, selection);
  stage.append(canvas, miniWrap, hud, stateBox);
  const foot = node('div', 'block-graph-foot');
  const limits = node('span', 'block-graph-limits', BLOCK_GRAPH_LIMITS);
  const legend = node('div', 'block-graph-legend'); legend.id = `block-graph-legend-${++blockGraphViews}`;
  // Narrow views fold the legend behind Key so the footer stays one line.
  const keyToggle = node('button', 'source-tool block-graph-tool block-graph-key-toggle', 'Key'); keyToggle.type = 'button';
  keyToggle.setAttribute('aria-expanded', 'false'); keyToggle.setAttribute('aria-controls', legend.id); keyToggle.setAttribute('aria-label', 'Edge key');
  const setKey = open => { foot.toggleAttribute('data-key-open', open); keyToggle.setAttribute('aria-expanded', String(open)); };
  keyToggle.addEventListener('click', () => setKey(!foot.hasAttribute('data-key-open')));
  foot.addEventListener('keydown', event => { if (event.key === 'Escape' && foot.hasAttribute('data-key-open')) { event.stopPropagation(); setKey(false); keyToggle.focus(); } });
  foot.addEventListener('focusout', event => { if (!foot.contains(event.relatedTarget)) setKey(false); });
  foot.append(limits, keyToggle, legend);
  const evidence = node('span', 'block-graph-evidence', '');
  head.append(title, analyst, stats, evidence, tools);
  root.append(head, stage, foot);
  const legendItems = [['fallthrough', 'fall'], ['taken', 'true'], ['not-taken', 'false'], ['table', 'table'], ['exception', 'catch'], ['unresolved', 'unresolved']];
  for (const [kind, label] of legendItems) {
    const item = node('span', 'block-graph-key');
    const sample = document.createElementNS?.('http://www.w3.org/2000/svg', 'svg');
    if (sample?.setAttribute) { sample.setAttribute('width', '22'); sample.setAttribute('height', '6'); sample.setAttribute('aria-hidden', 'true'); sample.classList.add(`block-graph-key-${kind}`); const line = document.createElementNS('http://www.w3.org/2000/svg', 'line'); line.setAttribute('x1', '0'); line.setAttribute('y1', '3'); line.setAttribute('x2', '22'); line.setAttribute('y2', '3'); sample.append(line); item.append(sample); }
    item.append(node('span', '', label)); legend.append(item);
  }
  const ctx = canvas.getContext?.('2d'), miniCtx = minimap.getContext?.('2d');
  const tokenNames = {bg: '--graph-canvas', card: '--graph-card', head: '--graph-card-head', line: '--graph-card-line', text: '--text', muted: '--muted', faint: '--faint', accent: '--accent', soft: '--accent-soft', mono: '--mono', control: '--syntax-control', fn: '--syntax-function', num: '--syntax-number',
    fallthrough: '--graph-edge-fallthrough', branch: '--graph-edge-branch', taken: '--graph-edge-taken', notTaken: '--graph-edge-not-taken', table: '--graph-edge-table', exception: '--graph-edge-exception', unresolved: '--graph-edge-unresolved', call: '--graph-edge-call', assumed: '--graph-edge-assumed', sequence: '--graph-edge-sequence', dead: '--graph-card-unreached', gap: '--graph-card-gap'};
  let tokens = {};
  const readTokens = () => { const style = getComputedStyle(root); const result = {}; for (const [key, name] of Object.entries(tokenNames)) result[key] = style.getPropertyValue(name).trim(); tokens = result; miniDirty = true; };
  let view = {x: 0, y: 0, z: 1}, graph = null, starts = null, layout = null, selectedBlock = -1, selectedRow = -1, frame = 0, active = false, cssW = 0, cssH = 0, dpr = 1, miniDirty = true, onError = null;
  const edgeStyles = {
    [BLOCK_GRAPH_KIND.fallthrough]: ['fallthrough', []], [BLOCK_GRAPH_KIND.branch]: ['branch', []], [BLOCK_GRAPH_KIND.taken]: ['taken', []], [BLOCK_GRAPH_KIND.not_taken]: ['notTaken', [6, 3]],
    [BLOCK_GRAPH_KIND.table]: ['table', [2, 3]], [BLOCK_GRAPH_KIND.table_default]: ['table', [2, 3]], [BLOCK_GRAPH_KIND.exception]: ['exception', [8, 4]], [BLOCK_GRAPH_KIND.unresolved]: ['unresolved', [4, 2, 1, 2]],
    [BLOCK_GRAPH_KIND.call]: ['call', [1, 3]], [BLOCK_GRAPH_KIND.assumed]: ['assumed', [1, 3]], [BLOCK_GRAPH_KIND.sequence]: ['sequence', []]};
  const m = {charW: 6.6, rowH: 16, headerH: 22, padX: 10, padY: 7};
  const measure = () => { if (!ctx) return; ctx.font = `11px ${tokens.mono || 'monospace'}`; m.charW = ctx.measureText('0').width || 6.6; };
  let needsFit = false;
  const requestDraw = () => { if (active && !frame) frame = requestAnimationFrame(() => { frame = 0; draw(); }); };
  /** The view that shows the whole graph in a canvas of `width` by `height`. */
  function fitView(width, height) {
    const z = Math.min(1, Math.max(GRAPH_ZOOM.min, Math.min(width / layout.width, height / layout.height)));
    return {x: (layout.width - width / z) / 2, y: (layout.height - height / z) / 2, z};
  }
  const sameView = (a, b) => Math.abs(a.z - b.z) < 1e-9 && Math.abs(a.x - b.x) < 1e-6 && Math.abs(a.y - b.y) < 1e-6;
  function resize() {
    if (!active) return;
    // A fitted view stays fitted when the pane resizes (Linear hidden or a
    // divider dragged), however it came to be fitted.
    const fitted = Boolean(layout) && cssW > 1 && sameView(view, fitView(cssW, cssH));
    ({cssW, cssH, dpr} = graphFitCanvas(canvas, stage));
    if (needsFit && layout && cssW > 1) { needsFit = false; start(); return; }
    if (fitted) { fit(); return; }
    requestDraw();
  }
  const visible = (x, y, w, h) => { const r = view.x + cssW / view.z, b = view.y + cssH / view.z; return x < r && x + w > view.x && y < b && y + h > view.y; };
  function draw() {
    if (!ctx || !active) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.fillStyle = tokens.bg; ctx.fillRect(0, 0, cssW, cssH);
    if (!layout) { drawMinimap(); return; }
    ctx.setTransform(dpr * view.z, 0, 0, dpr * view.z, -view.x * view.z * dpr, -view.y * view.z * dpr);
    const lod = view.z < 0.18 ? 0 : view.z < BLOCK_GRAPH_ROW_ZOOM ? 1 : 2, rv = view.x + cssW / view.z, bv = view.y + cssH / view.z;
    drawEdges(rv, bv, lod);
    const shown = [];
    for (let block = 0; block < graph.count; block += 1) {
      const x = layout.x[block], y = layout.y[block], w = layout.w[block], h = layout.h[block];
      if (x >= rv || x + w <= view.x || y >= bv || y + h <= view.y) continue;
      drawCard(block, x, y, w, h, lod);
      if (lod < 2) shown.push(block);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (lod < 2) drawScreenLabels(shown);
    lodCue.hidden = lod === 2;
    zoomLabel.textContent = `${Math.round(view.z * 100)}%`;
    drawMinimap();
  }
  /** Below row zoom, each card that has room keeps a legible label and count. */
  function drawScreenLabels(blocks) {
    ctx.font = `11px ${tokens.mono}`; ctx.textBaseline = 'middle';
    for (const block of blocks) {
      const sx = (layout.x[block] - view.x) * view.z, sy = (layout.y[block] - view.y) * view.z, sw = layout.w[block] * view.z, sh = layout.h[block] * view.z;
      if (sw < 48 || sh < 15) continue;
      const room = Math.floor((sw - 12) / m.charW);
      const label = blockLabel(block), count = `${graph.instructionCount[block]} ${graph.evidence === 'observed' ? 'step' : 'ins'}`;
      ctx.save(); ctx.beginPath(); ctx.rect(sx, sy, sw, sh); ctx.clip();
      ctx.fillStyle = block === selectedBlock ? tokens.text : tokens.muted;
      ctx.fillText(label.length > room ? `${label.slice(0, Math.max(1, room - 1))}…` : label, sx + 6, sy + Math.min(sh / 2, 11));
      if (sh >= 34 && count.length <= room) { ctx.fillStyle = tokens.faint; ctx.fillText(count, sx + 6, sy + 28); }
      ctx.restore();
    }
  }
  function edgePath(edge, lod) {
    const start = layout.pointStart[edge], end = layout.pointStart[edge + 1];
    const pts = layout.points, corner = lod === 2 ? 6 : 0;
    ctx.beginPath(); ctx.moveTo(pts[start * 2], pts[start * 2 + 1]);
    for (let i = start + 1; i < end; i += 1) {
      const x = pts[i * 2], y = pts[i * 2 + 1];
      if (corner && i < end - 1) ctx.arcTo(x, y, pts[(i + 1) * 2], pts[(i + 1) * 2 + 1], corner);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
  }
  function arrow(edge) {
    const end = layout.pointStart[edge + 1] - 1, pts = layout.points, x = pts[end * 2], y = pts[end * 2 + 1];
    const px = pts[(end - 1) * 2], py = pts[(end - 1) * 2 + 1], angle = Math.atan2(y - py, x - px), size = 6;
    ctx.setLineDash([]); ctx.beginPath(); ctx.moveTo(x, y);
    ctx.lineTo(x - size * Math.cos(angle - 0.45), y - size * Math.sin(angle - 0.45));
    ctx.lineTo(x - size * Math.cos(angle + 0.45), y - size * Math.sin(angle + 0.45)); ctx.closePath(); ctx.fill();
  }
  function drawEdges(rv, bv, lod) {
    const groups = new Map(), selected = [];
    const count = graph.from.length;
    for (let edge = 0; edge < count; edge += 1) {
      const minX = layout.box[edge * 4], minY = layout.box[edge * 4 + 1], maxX = layout.box[edge * 4 + 2], maxY = layout.box[edge * 4 + 3];
      if (minX > rv || maxX < view.x || minY > bv || maxY < view.y) continue;
      if (graph.from[edge] === selectedBlock || graph.to[edge] === selectedBlock) { selected.push(edge); continue; }
      const kind = graph.kind[edge]; if (!groups.has(kind)) groups.set(kind, []); groups.get(kind).push(edge);
    }
    ctx.lineJoin = 'round';
    const styleFor = kind => {
      const [token, dash] = edgeStyles[kind] ?? edgeStyles[BLOCK_GRAPH_KIND.branch];
      ctx.strokeStyle = tokens[token]; ctx.fillStyle = tokens[token]; ctx.setLineDash(lod === 2 ? dash : []);
    };
    ctx.lineWidth = lod === 2 ? 1.8 : 1 / Math.max(view.z, 0.2);
    for (const [kind, edges] of groups) {
      styleFor(kind);
      for (const edge of edges) { edgePath(edge, lod); if (lod >= 1 && graph.to[edge] >= 0) { arrow(edge); styleFor(kind); } }
    }
    if (selected.length) {
      ctx.lineWidth = 2.6 / Math.max(view.z, 0.4);
      for (const edge of selected) { styleFor(graph.kind[edge]); ctx.strokeStyle = tokens.accent; ctx.fillStyle = tokens.accent; edgePath(edge, lod); if (graph.to[edge] >= 0) arrow(edge); }
    }
    if (lod === 2) drawLabels(rv, bv, groups, selected);
  }
  function drawLabels(rv, bv, groups, selected) {
    ctx.setLineDash([]); ctx.font = `10px ${tokens.mono}`; ctx.textBaseline = 'alphabetic';
    const paint = (edge) => {
      const label = graph.labels[edge]; if (!label) return;
      const kind = graph.kind[edge], text = label.length > 24 ? `${label.slice(0, 23)}…` : label;
      const start = layout.pointStart[edge], end = layout.pointStart[edge + 1] - 1, pts = layout.points;
      let x, y;
      if (kind === BLOCK_GRAPH_KIND.table) { x = pts[end * 2] + 3; y = pts[end * 2 + 1] - 6; }
      else if (kind === BLOCK_GRAPH_KIND.unresolved) { x = pts[end * 2] + 4; y = pts[end * 2 + 1] + 2; }
      else { x = pts[start * 2] + 3; y = pts[start * 2 + 1] + 11; }
      if (x > rv || y > bv || x < view.x - 100 || y < view.y) return;
      ctx.fillStyle = tokens[(edgeStyles[kind] ?? edgeStyles[1])[0]]; ctx.fillText(text, x, y);
    };
    for (const edges of groups.values()) edges.forEach(paint);
    selected.forEach(paint);
  }
  function drawCard(block, x, y, w, h, lod) {
    const flags = graph.flags[block], unreached = !(flags & 2), gapCard = (flags & 16) !== 0, picked = block === selectedBlock;
    ctx.setLineDash([]);
    ctx.fillStyle = gapCard ? tokens.gap : tokens.card; ctx.strokeStyle = picked ? tokens.accent : tokens.line;
    ctx.lineWidth = picked ? 2 / Math.max(view.z, 0.5) : 1 / Math.max(view.z, 0.5);
    ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, 4); ctx.fill(); ctx.stroke();
    if (lod === 0) return;
    ctx.save(); ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, 4); ctx.clip();
    if (!gapCard && lod === 2) { ctx.fillStyle = unreached ? tokens.dead : picked ? tokens.soft : tokens.head; ctx.fillRect(x, y, w, m.headerH); }
    else if (unreached) { ctx.fillStyle = tokens.dead; ctx.fillRect(x, y, w, h); }
    if (lod === 2) {
      ctx.textBaseline = 'middle'; ctx.font = `11px ${tokens.mono}`; ctx.fillStyle = tokens.muted;
      if (gapCard) ctx.fillText('gap', x + m.padX, y + m.headerH / 2);
      else {
        ctx.fillText(blockLabel(block), x + m.padX, y + m.headerH / 2);
        const badge = String(graph.instructionCount[block]), bw = badge.length * m.charW + 8;
        // A filled count badge, as in the Flow graph.
        ctx.fillStyle = tokens.head; ctx.fillRect(x + w - bw - 7.5, y + 4.5, bw, 13);
        ctx.strokeStyle = tokens.line; ctx.lineWidth = 1; ctx.strokeRect(x + w - bw - 7.5, y + 4.5, bw, 13); ctx.fillStyle = tokens.muted; ctx.fillText(badge, x + w - bw - 3, y + m.headerH / 2);
      }
    }
    if (lod === 2) drawRows(block, x, y, w, h);
    ctx.restore();
  }
  function drawRows(block, x, y, w, h) {
    const first = graph.firstRow[block], count = graph.rowCount[block], top = y + m.headerH + m.padY;
    ctx.font = `11px ${tokens.mono}`; ctx.textBaseline = 'alphabetic';
    const firstVisible = Math.max(0, Math.floor((view.y - top) / m.rowH)), lastVisible = Math.min(count, Math.ceil((view.y + cssH / view.z - top) / m.rowH));
    for (let row = firstVisible; row < lastVisible; row += 1) {
      const text = graph.rows.slice(starts[first + row], starts[first + row + 1] - 1);
      const ry = top + row * m.rowH;
      if (selectedRow === first + row) { ctx.fillStyle = tokens.soft; ctx.fillRect(x + 1, ry, w - 2, m.rowH); ctx.fillStyle = tokens.accent; ctx.fillRect(x + 1, ry + 2, 2, m.rowH - 4); }
      const a = text.indexOf(' '), b = text.indexOf(' ', a + 1);
      const offset = text.slice(0, a), mnemonic = b < 0 ? text.slice(a + 1) : text.slice(a + 1, b), rest = b < 0 ? '' : text.slice(b + 1);
      const line = ry + m.rowH - 4;
      ctx.fillStyle = tokens.faint; ctx.fillText(offset, x + m.padX, line);
      const mnemonicX = x + m.padX + (offset.length + 1) * m.charW;
      ctx.fillStyle = /^(br|if|else|end|loop|block|return|try|catch|throw|unreachable)/.test(mnemonic) ? tokens.control : /^call/.test(mnemonic) ? tokens.fn : tokens.text;
      ctx.fillText(mnemonic, mnemonicX, line);
      if (rest) { ctx.fillStyle = tokens.muted; ctx.fillText(rest, mnemonicX + (Math.max(mnemonic.length, 10) + 1) * m.charW, line); }
    }
    if (graph.flags[block] & 32) { ctx.fillStyle = tokens.faint; ctx.fillText(count ? 'more rows past the byte budget' : 'rows past the byte budget', x + m.padX, top + count * m.rowH + m.rowH - 4); }
  }
  const blockLabel = block => graph.flags[block] & 16 ? 'gap' : options.blockLabel?.(graph, block) ?? `loc_${graph.offsets[block].toString(16)}`;
  function drawMinimap() {
    if (!miniCtx) return;
    miniWrap.hidden = !layout;
    if (!layout) return;
    const w = minimap.width, h = minimap.height, scale = Math.min(w / layout.width, h / layout.height);
    if (miniDirty) {
      miniCtx.fillStyle = tokens.bg; miniCtx.fillRect(0, 0, w, h);
      miniCtx.fillStyle = tokens.faint;
      const ox = (w - layout.width * scale) / 2, oy = (h - layout.height * scale) / 2;
      for (let block = 0; block < graph.count; block += 1) miniCtx.fillRect(ox + layout.x[block] * scale, oy + layout.y[block] * scale, Math.max(1, layout.w[block] * scale), Math.max(1, layout.h[block] * scale));
      miniImage = miniCtx.getImageData?.(0, 0, w, h) ?? null;
      miniDirty = false;
    }
    if (miniImage) miniCtx.putImageData(miniImage, 0, 0);
    miniCtx.strokeStyle = tokens.accent; miniCtx.lineWidth = 2;
    const ox = (w - layout.width * scale) / 2, oy = (h - layout.height * scale) / 2;
    // The viewport can be larger than the whole graph; keep its outline on the minimap.
    const left = Math.max(1, ox + view.x * scale), top = Math.max(1, oy + view.y * scale);
    const right = Math.min(w - 1, ox + (view.x + cssW / view.z) * scale), bottom = Math.min(h - 1, oy + (view.y + cssH / view.z) * scale);
    miniCtx.strokeRect(left, top, Math.max(3, right - left), Math.max(3, bottom - top));
  }
  let miniImage = null;
  function setState(kind, message = '', canRetry = false) {
    stateBox.hidden = kind === 'ready';
    stateBox.dataset.kind = kind;
    stateBox.dataset.overlay = kind === 'error' && layout ? 'banner' : 'center';
    stateText.textContent = message; retry.hidden = !canRetry; onError = canRetry ? options.retry : null;
    miniWrap.hidden = !layout;
  }
  retry.addEventListener('click', () => onError?.());
  function setResult(result) {
    graph = result.graph; starts = result.starts; layout = result.layout;
    selectedBlock = -1; selectedRow = -1; view.z = 1; miniDirty = true;
    title.textContent = options.titleOf?.(graph) ?? graph.title;
    const parts = [`${graph.count.toLocaleString()} ${graph.count === 1 ? 'block' : 'blocks'}`, `${graph.instructions.toLocaleString()} ${graph.evidence === 'observed' ? 'retained steps' : 'instructions'}`];
    // Which engine laid it out is said in the header, not only on hover.
    parts.push(blockGraphEngineNote(layout.engine));
    stats.textContent = [options.statsPrefix?.(graph), ...parts].filter(Boolean).join(' · ');
    const revision = layout.engine?.revision ? ` ${layout.engine.revision.slice(0, 7)}` : '';
    const reason = blockGraphLayoutReason(layout.engine?.reason);
    stats.title = layout.engine?.name === 'triskel' ? `Laid out by Triskel${revision}, a CFG layout engine built on single-entry single-exit regions.` : reason ? `Region layout: ${reason}.` : '';
    evidence.textContent = graph.status === 'partial' ? `${graph.evidence} · partial` : graph.evidence;
    limits.textContent = graph.evidence === 'observed' ? graph.notice : BLOCK_GRAPH_LIMITS;
    limits.title = graph.evidence === 'observed' ? graph.notice : 'Declared static flow. Reachable here is not observed execution, and a complete drawing is not a proof.';
    if (graph.omissions?.length) limits.title += ` ${graph.omissions.join(' ')}`;
    selection.textContent = graph.omissions?.length ? graph.omissions[0] : '';
    setState('ready');
    needsFit = cssW <= 1;
    start();
  }
  /** First view: actual size, centered on the selected block or the entry.
   * A graph that fits at actual size is centered whole. Fit is one key away. */
  function start() {
    if (!layout || !cssW) return;
    view.z = 1;
    if (layout.width <= cssW && layout.height <= cssH) { view.x = (layout.width - cssW) / 2; view.y = (layout.height - cssH) / 2; requestDraw(); return; }
    const block = selectedBlock >= 0 ? selectedBlock : Math.max(0, graph.roots?.[0] ?? 0);
    view.x = layout.x[block] + layout.w[block] / 2 - cssW / 2;
    view.y = layout.y[block] - 24;
    requestDraw();
  }
  function fit() {
    if (!layout || !cssW) return;
    view = fitView(cssW, cssH);
    requestDraw();
  }
  function zoomAt(factor, cx = cssW / 2, cy = cssH / 2) {
    view = graphZoomAt(view, factor, cx, cy);
    requestDraw();
  }
  function centerOn(block, zoom = null) {
    if (zoom) view.z = zoom;
    view.x = layout.x[block] + layout.w[block] / 2 - cssW / view.z / 2;
    view.y = layout.y[block] + layout.h[block] / 2 - cssH / view.z / 2;
    requestDraw();
  }
  /** Selects a block (and a row of it) and keeps it in view. A pick tells
   * onSelect, or onReveal when `reveal`; a `silent` selection is the host's
   * own and tells neither. */
  function select(block, row = -1, {reveal = false, silent = false} = {}) {
    if (!layout || block < 0 || block >= graph.count) return;
    selectedBlock = block; selectedRow = row;
    const flags = graph.flags[block];
    if (flags & 16) selection.textContent = `Gap: ${graph.rows.slice(starts[graph.firstRow[block]], starts[graph.firstRow[block] + 1] - 1).split(' ')[0]} steps not retained. No edge crosses it.`;
    else {
      const succ = []; for (let e = 0; e < graph.from.length; e += 1) if (graph.from[e] === block) succ.push(graph.to[e]);
      selection.textContent = `${blockLabel(block)} · ${graph.instructionCount[block]} ${graph.evidence === 'observed' ? 'steps' : 'instructions'} · ${succ.length} ${succ.length === 1 ? 'successor' : 'successors'}${flags & 2 ? '' : ' · not reached by declared edges'}${succ.includes(-1) ? ' · unresolved target' : ''}`;
    }
    const x = layout.x[block], y = layout.y[block], w = layout.w[block], h = layout.h[block];
    if (!visible(x, y, w, h) || x < view.x || y < view.y || x + w > view.x + cssW / view.z || y + h > view.y + cssH / view.z) centerOn(block);
    requestDraw();
    if (silent) return;
    if (reveal) options.onReveal?.(graph.offsets[block], block, graph);
    else options.onSelect?.(graph.offsets[block], block, graph);
  }
  const blockAt = (px, py) => {
    const gx = view.x + px / view.z, gy = view.y + py / view.z;
    for (let block = 0; block < graph.count; block += 1) if (gx >= layout.x[block] && gx <= layout.x[block] + layout.w[block] && gy >= layout.y[block] && gy <= layout.y[block] + layout.h[block]) return block;
    return -1;
  };
  const pointer = {down: false, x: 0, y: 0, moved: false};
  canvas.addEventListener('pointerdown', event => { pointer.down = true; pointer.x = event.clientX; pointer.y = event.clientY; pointer.moved = false; canvas.setPointerCapture?.(event.pointerId); canvas.focus({preventScroll: true}); });
  canvas.addEventListener('pointermove', event => {
    if (!pointer.down || !layout) return;
    if (Math.abs(event.clientX - pointer.x) + Math.abs(event.clientY - pointer.y) > 2) pointer.moved = true;
    view.x -= (event.clientX - pointer.x) / view.z; view.y -= (event.clientY - pointer.y) / view.z; pointer.x = event.clientX; pointer.y = event.clientY; requestDraw();
  });
  canvas.addEventListener('pointerup', event => {
    if (!pointer.down) return;
    pointer.down = false;
    if (pointer.moved || !layout) return;
    const rect = canvas.getBoundingClientRect(), block = blockAt(event.clientX - rect.left, event.clientY - rect.top);
    if (block < 0) { selectedBlock = -1; selectedRow = -1; requestDraw(); return; }
    const gy = view.y + (event.clientY - rect.top) / view.z - layout.y[block] - m.headerH - m.padY;
    const row = gy >= 0 && graph.rowCount[block] ? Math.min(graph.rowCount[block] - 1, Math.floor(gy / m.rowH)) : -1;
    select(block, row >= 0 ? graph.firstRow[block] + row : -1, {reveal: true});
  });
  canvas.addEventListener('wheel', event => {
    if (!layout) return;
    event.preventDefault();
    if (event.ctrlKey || event.metaKey) { const rect = canvas.getBoundingClientRect(); zoomAt(Math.exp(-event.deltaY * 0.01), event.clientX - rect.left, event.clientY - rect.top); }
    else { view.x += event.deltaX / view.z; view.y += event.deltaY / view.z; requestDraw(); }
  }, {passive: false});
  function move(dx, dy) {
    if (selectedBlock < 0) return select(0);
    const cx = layout.x[selectedBlock] + layout.w[selectedBlock] / 2, cy = layout.y[selectedBlock] + layout.h[selectedBlock] / 2;
    let best = -1, bestScore = Infinity;
    for (let block = 0; block < graph.count; block += 1) {
      if (block === selectedBlock) continue;
      const ddx = layout.x[block] + layout.w[block] / 2 - cx, ddy = layout.y[block] + layout.h[block] / 2 - cy;
      const along = ddx * dx + ddy * dy; if (along <= 0) continue;
      const across = Math.abs(ddx * dy) + Math.abs(ddy * dx), score = along + across * 2.5;
      if (score < bestScore) { bestScore = score; best = block; }
    }
    if (best >= 0) select(best);
  }
  canvas.addEventListener('keydown', event => {
    if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey || !layout) return;
    const panStep = 96 / view.z;
    const key = event.key; let handled = true;
    if (event.shiftKey && key.startsWith('Arrow')) { view.x += key === 'ArrowLeft' ? -panStep : key === 'ArrowRight' ? panStep : 0; view.y += key === 'ArrowUp' ? -panStep : key === 'ArrowDown' ? panStep : 0; requestDraw(); }
    else if (key === 'ArrowDown') move(0, 1); else if (key === 'ArrowUp') move(0, -1); else if (key === 'ArrowLeft') move(-1, 0); else if (key === 'ArrowRight') move(1, 0);
    else if (key === '+' || key === '=') zoomAt(1.25); else if (key === '-' || key === '_') zoomAt(0.8); else if (key === '0') fit();
    else if (key === 'Home') { select(0); centerOn(0); }
    else if (key === ']' || key === '[') { const order = [...Array(graph.count).keys()].sort((a, b) => graph.offsets[a] - graph.offsets[b]), index = order.indexOf(selectedBlock), next = order[key === ']' ? index + 1 : Math.max(0, index - 1)] ?? order.at(-1); if (next !== undefined) select(next); }
    else if (key === 'Enter' && selectedBlock >= 0) select(selectedBlock, selectedRow, {reveal: true});
    else handled = false;
    if (handled) event.preventDefault();
  });
  canvas.addEventListener('focus', () => { if (layout && selectedBlock < 0 && canvas.matches?.(':focus-visible')) select(0); });
  minimap.addEventListener('pointerdown', event => {
    if (!layout) return;
    const rect = minimap.getBoundingClientRect(), scale = Math.min(minimap.width / layout.width, minimap.height / layout.height);
    const ox = (minimap.width - layout.width * scale) / 2, oy = (minimap.height - layout.height * scale) / 2;
    view.x = ((event.clientX - rect.left) * (minimap.width / rect.width) - ox) / scale - cssW / view.z / 2;
    view.y = ((event.clientY - rect.top) * (minimap.height / rect.height) - oy) / scale - cssH / view.z / 2;
    requestDraw();
  });
  let observer = null;
  const themeObserver = typeof MutationObserver !== 'undefined' ? new MutationObserver(() => { if (active) { readTokens(); requestDraw(); } }) : null;
  return {
    activate() {
      active = true; root.hidden = false; readTokens(); measure();
      themeObserver?.observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']});
      if (typeof ResizeObserver !== 'undefined') { observer = new ResizeObserver(resize); observer.observe(stage); }
      resize(); requestDraw();
    },
    /** Drops every drawing resource; only the page's root stays mounted. */
    release() {
      active = false; root.hidden = true;
      if (frame) { cancelAnimationFrame(frame); frame = 0; }
      observer?.disconnect(); observer = null; themeObserver?.disconnect();
      graph = starts = layout = null; miniImage = null; selectedBlock = -1;
      canvas.width = 0; canvas.height = 0; minimap.width = 300; minimap.height = 220;
      setState('empty', '');
    },
    measurements: () => ({...m}), setResult, setState,
    /** The host's selection: it never reports back through onSelect. */
    select: (block, row = -1) => select(block, row, {silent: true}),
    focus: () => canvas.focus(), hasGraph: () => Boolean(layout), tools, setTitle(text) { title.textContent = text; stats.textContent = ''; },
    setAnalystName(name) { analyst.textContent = name ?? ''; analyst.hidden = !name; analyst.title = name ? `${name} (researcher name)` : ''; }
  };
}

/** Triskel lays out when this shell's backend serves the layout route. */
const blockGraphEngine = () => /^https?:$/.test(globalThis.location?.protocol ?? '') ? 'triskel' : 'layered';

/**
 * Runs layout jobs one at a time in a worker that answers {id, ok, result}
 * or {id, ok: false, error}. A new job cancels the one running; the worker
 * stays between jobs and is terminated only to cancel one. `script` is the
 * worker; `local`, when given, runs a job on this thread where no worker
 * starts. The flow graph uses it with its own worker and fallback.
 */
function createBlockGraphRunner({script = 'block_graph_layout.js', local = null} = {}) {
  let worker = null, serial = 0, job = null;
  function finish(id, ok, value) {
    if (job?.id !== id) return;
    const {resolve, reject} = job;
    job = null;
    if (ok) resolve(value); else reject(value);
  }
  const runLocal = (id, message) => local(message).then(result => finish(id, true, result), error => finish(id, false, error));
  function start() {
    try { worker = new Worker(script); } catch { worker = null; return false; }
    worker.onmessage = event => finish(event.data.id, event.data.ok, event.data.ok ? event.data.result : Error(event.data.error));
    worker.onerror = event => {
      event.preventDefault?.();
      worker?.terminate();
      worker = null;
      // A worker that cannot run leaves its job to this thread when it can.
      if (job && local) runLocal(job.id, job.message);
      else if (job) finish(job.id, false, Error(event.message || 'Layout failed.'));
    };
    return true;
  }
  function cancel() {
    worker?.terminate();
    worker = null;
    const cancelled = job;
    job = null;
    cancelled?.reject(new DOMException('Cancelled', 'AbortError'));
  }
  return {
    run(message, transfer = []) {
      if (job) cancel();
      const id = ++serial;
      return new Promise((resolve, reject) => {
        job = {id, message: local ? message : null, resolve, reject};
        if (worker || start()) worker.postMessage({...message, id}, transfer);
        else if (local) runLocal(id, message);
        else finish(id, false, Error('The layout worker could not start.'));
      });
    },
    cancel
  };
}

/* Sources view mode for one captured WASM artifact. */
function createSourceGraphPanel({host, editor, button, closeOn, revealOffset}) {
  const view = createBlockGraphView(host, {
    // Showing a block's offset in the linear listing focuses that row; a
    // reveal started from the Graph (a click or Enter on a block) keeps focus
    // on the Graph, so F2 and the arrow keys still act on the function drawn.
    onReveal: (offset) => {
      const fromGraph = host.contains(document.activeElement);
      revealOffset?.(offset);
      if (fromGraph && host.isConnected && !host.hidden) view.focus();
    },
    onSelect: () => {},
    retry: () => loadFunction(functionIndex, true),
    titleOf: graph => names.get(graph.functionIndex) ?? `func ${graph.functionIndex}`,
    statsPrefix: graph => names.has(graph.functionIndex) ? `func ${graph.functionIndex}` : ''
  });
  const runner = createBlockGraphRunner();
  host.hidden = true;
  let source = null, isOpen = false, functions = null, names = new Map(), functionIndex = null, generation = 0, abort = null, indexStatus = 'idle', screenVisible = true;
  const key = () => `${source?.artifact_id}:${source?.sha256}`;
  const cache = new Map(); let cacheBytes = 0;
  const entryBytes = result => {
    const {graph, starts, layout} = result;
    return graph.offsets.byteLength * 6 + graph.from.byteLength * 3 + graph.rows.length + starts.byteLength + layout.x.byteLength * 4 + layout.points.byteLength + layout.pointStart.byteLength + layout.box.byteLength;
  };
  const remember = (cacheKey, result) => {
    const bytes = entryBytes(result);
    if (bytes > BLOCK_GRAPH_CACHE_BYTES) return;
    cache.set(cacheKey, {result, bytes}); cacheBytes += bytes;
    while (cacheBytes > BLOCK_GRAPH_CACHE_BYTES) { const first = cache.keys().next().value; cacheBytes -= cache.get(first).bytes; cache.delete(first); }
  };
  const release = () => { cache.clear(); cacheBytes = 0; functions = null; names = new Map(); functionIndex = null; abort?.abort(); abort = null; runner.cancel(); generation += 1; };
  const isWasmSource = candidate => candidate?.kind === 'wasm' && candidate?.source_type === 'artifact';
  function displayName(index) { const name = names.get(index); return name ? `${name} (func ${index})` : `func ${index}`; }
  // Researcher names (wasm_function_names.js), keyed by module SHA-256 and
  // function index. The panel works unchanged without that module.
  const researcher = () => globalThis.RebWasmFunctionNames;
  const analystName = index => researcher()?.nameOf(source?.sha256, index) ?? null;
  let renameButton = null, repaintMenu = null;
  function showAnalystName() {
    const current = isOpen && source && functionIndex !== null;
    view.setAnalystName?.(current ? analystName(functionIndex) : null);
    if (current) researcher()?.mark(host, source.sha256, functionIndex, displayName(functionIndex)); else researcher()?.unmark(host);
    if (renameButton) renameButton.disabled = !current || !researcher();
  }
  researcher()?.subscribe(() => { showAnalystName(); repaintMenu?.(); });
  let toolsBuilt = false, linearChoice = false;
  function renderTools() {
    if (toolsBuilt) return;
    toolsBuilt = true;
    const wrap = document.createElement('div'); wrap.className = 'block-graph-fn-wrap';
    const opener = document.createElement('button'); opener.type = 'button'; opener.className = 'source-tool block-graph-tool'; opener.setAttribute('aria-haspopup', 'listbox'); opener.setAttribute('aria-expanded', 'false'); opener.textContent = 'Functions';
    wrap.append(opener);
    const previous = document.createElement('button'); previous.type = 'button'; previous.className = 'source-tool block-graph-tool'; previous.textContent = '‹'; previous.setAttribute('aria-label', 'Previous function');
    const next = document.createElement('button'); next.type = 'button'; next.className = 'source-tool block-graph-tool'; next.textContent = '›'; next.setAttribute('aria-label', 'Next function');
    previous.addEventListener('click', () => stepFunction(-1)); next.addEventListener('click', () => stepFunction(1));
    wrap.prepend(previous); wrap.append(next);
    view.tools.prepend(wrap);
    opener.addEventListener('click', () => toggleMenu(opener, wrap));
    const linear = document.createElement('button'); linear.type = 'button'; linear.className = 'source-tool block-graph-tool'; linear.textContent = 'Linear';
    linear.setAttribute('aria-pressed', String(!editor.hasAttribute('data-graph-linear-hidden')));
    linear.title = 'Show or hide the linear disassembly and hex';
    linear.addEventListener('click', () => { linearChoice = true; const hidden = !editor.hasAttribute('data-graph-linear-hidden'); editor.toggleAttribute('data-graph-linear-hidden', hidden); linear.setAttribute('aria-pressed', String(!hidden)); dispatchEvent(new Event('resize')); });
    view.tools.append(linear);
    if (researcher()) {
      renameButton = document.createElement('button'); renameButton.type = 'button'; renameButton.className = 'source-tool block-graph-tool block-graph-rename';
      renameButton.textContent = 'Rename'; renameButton.setAttribute('aria-label', 'Rename this function'); renameButton.title = 'Rename this function (F2)';
      renameButton.addEventListener('click', () => researcher()?.beginFrom(host));
      wrap.append(renameButton);
    }
    showAnalystName();
  }
  function stepFunction(direction) {
    if (!functions) return;
    const list = functions.index, position = list.findIndex(index => index === functionIndex);
    const target = list[Math.max(0, Math.min(list.length - 1, (position < 0 ? 0 : position) + direction))];
    if (target !== undefined) loadFunction(target);
  }
  let menu = null, menuOpener = null;
  // Focus inside the closing popover returns to its trigger rather than
  // staying on a removed entry or falling to the body.
  function closeMenu(opener = menuOpener) {
    const inside = Boolean(menu?.contains(document.activeElement));
    menu?.remove(); menu = null; repaintMenu = null; opener?.setAttribute('aria-expanded', 'false');
    if (inside && opener?.isConnected) opener.focus({preventScroll: true});
    menuOpener = null;
  }
  function toggleMenu(opener, wrap) {
    if (menu) { closeMenu(opener); opener.focus(); return; }
    if (!functions) return;
    opener.setAttribute('aria-expanded', 'true'); menuOpener = opener;
    menu = document.createElement('div'); menu.className = 'block-graph-fn-menu'; menu.setAttribute('role', 'dialog'); menu.setAttribute('aria-label', 'Choose a function');
    const input = document.createElement('input'); input.type = 'search'; input.placeholder = 'Filter by index, name or size'; input.setAttribute('aria-label', 'Filter functions');
    const list = document.createElement('div'); list.className = 'block-graph-fn-list'; list.setAttribute('role', 'listbox'); list.setAttribute('aria-label', 'Functions'); list.tabIndex = 0;
    const count = document.createElement('p'); count.className = 'block-graph-fn-count';
    menu.append(input, list, count); wrap.append(menu);
    const rowH = 24; let filtered = functions.index.slice(), scroll = 0, cursor = Math.max(0, filtered.indexOf(functionIndex));
    const spacer = document.createElement('div'); spacer.className = 'block-graph-fn-spacer'; list.append(spacer);
    const paint = () => {
      spacer.style.height = `${filtered.length * rowH}px`;
      const start = Math.floor(scroll / rowH), end = Math.min(filtered.length, start + 14);
      for (const row of [...list.querySelectorAll('.block-graph-fn-row')]) row.remove();
      for (let i = start; i < end; i += 1) {
        const index = filtered[i], row = document.createElement('button');
        row.type = 'button'; row.className = 'block-graph-fn-row'; row.setAttribute('role', 'option'); row.setAttribute('aria-selected', String(i === cursor));
        row.style.top = `${i * rowH}px`;
        const name = document.createElement('span'); name.className = 'block-graph-fn-name'; name.textContent = displayName(index);
        const size = document.createElement('span'); size.className = 'block-graph-fn-size'; size.textContent = formatBytes(functions.size.get(index) ?? 0);
        row.append(name);
        const analyst = analystName(index);
        if (analyst) row.append(researcher().nameNode(analyst, 'block-graph-fn-analyst'));
        // An identification suggestion for this function, when one was read (wasm_identification.js).
        const badge = typeof wasmIdentificationBadge === 'function' ? wasmIdentificationBadge(source, index) : null;
        if (badge) { const tag = document.createElement('span'); tag.className = 'block-graph-fn-badge'; tag.textContent = badge.text; tag.title = badge.title; row.append(tag); }
        row.append(size); row.addEventListener('click', () => choose(index));
        // F2 on the highlighted row renames that function.
        researcher()?.mark(row, source?.sha256, index, displayName(index));
        list.append(row);
      }
      // Badges come from the identification report's first page of suggestions.
      const coverage = typeof wasmIdentificationBadgeCoverage === 'function' ? wasmIdentificationBadgeCoverage(source) : null;
      const badgeNote = coverage && coverage.rows < coverage.total ? ` · badges from the first ${coverage.rows.toLocaleString()} of ${coverage.total.toLocaleString()} suggestions` : '';
      count.textContent = `${filtered.length.toLocaleString()} of ${functions.index.length.toLocaleString()}${functions.status === 'partial' ? ' · list partial' : ''}${badgeNote}`;
    };
    const applyFilter = () => {
      const query = input.value.trim().toLowerCase();
      const badgeText = index => (typeof wasmIdentificationBadge === 'function' ? wasmIdentificationBadge(source, index)?.search ?? '' : '');
      filtered = query ? functions.index.filter(index => `${index} ${names.get(index) ?? ''} ${analystName(index) ?? ''} ${functions.size.get(index) ?? 0} ${badgeText(index)}`.toLowerCase().includes(query)) : functions.index.slice();
      cursor = 0; scroll = 0; list.scrollTop = 0; paint();
    };
    const choose = index => { closeMenu(opener); opener.focus(); loadFunction(index); };
    input.addEventListener('input', applyFilter);
    list.addEventListener('scroll', () => { scroll = list.scrollTop; paint(); });
    repaintMenu = paint;
    const keys = event => {
      if (event.key === 'Escape') { event.stopPropagation(); closeMenu(opener); opener.focus(); return; }
      if (event.key === 'F2' && filtered[cursor] !== undefined && researcher()) {
        // The filter field keeps typing; F2 names the highlighted function.
        const row = [...list.querySelectorAll('.block-graph-fn-row')].find(item => item.getAttribute('aria-selected') === 'true');
        if (row && researcher().beginFrom(row)) { event.preventDefault(); event.stopPropagation(); }
        return;
      }
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'PageDown' || event.key === 'PageUp') {
        event.preventDefault(); const step = event.key.startsWith('Page') ? 10 : 1; cursor = Math.max(0, Math.min(filtered.length - 1, cursor + (event.key.endsWith('Down') ? step : -step)));
        list.scrollTop = scroll = Math.max(0, Math.min(cursor * rowH, Math.max(scroll, (cursor - 12) * rowH))); paint();
      } else if (event.key === 'Enter' && filtered[cursor] !== undefined) { event.preventDefault(); choose(filtered[cursor]); }
    };
    input.addEventListener('keydown', keys); list.addEventListener('keydown', keys);
    paint(); input.focus();
    const outside = event => { if (menu && !menu.contains(event.target) && event.target !== opener) { closeMenu(opener); document.removeEventListener('pointerdown', outside, true); } };
    document.addEventListener('pointerdown', outside, true);
  }
  const formatBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`;
  /** Starts a read that replaces the one in flight; says whether it is still current. */
  function claim() {
    const owner = ++generation;
    abort?.abort();
    abort = new AbortController();
    return () => owner === generation;
  }
  async function loadIndex() {
    if (!source) return;
    const current = claim();
    view.setState('loading', 'Listing functions from immutable module bytes…'); indexStatus = 'loading';
    try {
      // The Functions menu badges come from the identification report.
      if (typeof wasmIdentificationLoad === 'function') wasmIdentificationLoad(source);
      const index = await readWasmFunctionIndex(source.artifact_id, abort.signal);
      if (!current()) return;
      names = index.names;
      functions = index;
      indexStatus = 'ready'; renderTools();
      if (!functions.index.length) { view.setState('empty', index.omissions[0] || 'This module declares no function bodies.'); return; }
      const largest = functions.index.reduce((best, candidate) => (index.size.get(candidate) > index.size.get(best) ? candidate : best), functions.index[0]);
      loadFunction(largest);
    } catch (error) {
      if (current() && error.name !== 'AbortError') {
        indexStatus = 'error';
        view.setState('error', graphReadMessage(error), true);
      }
    }
  }
  async function loadFunction(index, retry = false) {
    if (!source || !isOpen) return;
    if (index === null) { loadIndex(); return; }
    if (retry && indexStatus !== 'ready') { loadIndex(); return; }
    functionIndex = index; renderTools(); showAnalystName();
    // A cached function also replaces a read still in flight.
    const current = claim(), cacheKey = `${key()}:${index}`;
    const hit = cache.get(cacheKey);
    if (hit) { cache.delete(cacheKey); cache.set(cacheKey, hit); applyResult(hit.result); return; }
    view.setTitle(displayName(index));
    view.setState('loading', 'Decoding basic blocks…');
    try {
      const result = await loadWasmFunctionGraph({artifactId: source.artifact_id, functionIndex: index, view, runner, signal: abort.signal});
      if (!current()) return;
      remember(cacheKey, result); applyResult(result);
    } catch (error) {
      if (current() && error.name !== 'AbortError') view.setState('error', graphReadMessage(error), true);
    }
  }
  function applyResult(result) { view.setResult(result); renderTools(); showAnalystName(); }
  function open() { isOpen = true; host.hidden = false; editor.setAttribute('data-graph', 'true'); button.setAttribute('aria-pressed', 'true'); if (!linearChoice && innerHeight < 600) { editor.setAttribute('data-graph-linear-hidden', ''); } view.activate(); if (functions) { if (functionIndex !== null) loadFunction(functionIndex); else view.setState('empty', 'Select a function.'); } else loadIndex(); }
  function close() { isOpen = false; showAnalystName(); host.hidden = true; editor.removeAttribute('data-graph'); button.setAttribute('aria-pressed', 'false'); closeMenu(); view.release(); release(); }
  const toggle = () => { if (isOpen) close(); else if (isWasmSource(source)) open(); };
  button.addEventListener('click', toggle);
  closeOn?.addEventListener('click', () => { if (isOpen) close(); });
  return {
    /** Called when the selected source may have changed. */
    sync(next) {
      const valid = isWasmSource(next);
      button.hidden = !valid; button.disabled = !valid;
      const changed = !next || next.artifact_id !== source?.artifact_id || next.sha256 !== source?.sha256;
      source = next ?? null;
      if (isOpen && (!valid || changed)) close();
    },
    setScreenVisible(visible) { if (screenVisible === visible) return; screenVisible = visible; if (!visible && isOpen) close(); },
    isOpen: () => isOpen
  };
}

/* Static bytecode view mode. Declared and Observed are separate drawings that
 * share a renderer and never a node set, so they cannot merge into one CFG. */
function createVmBlockGraph({host, button, getReport, getObservedPath, onReveal}) {
  const view = createBlockGraphView(host, {onReveal: offset => onReveal?.(offset), onSelect: offset => onReveal?.(offset), retry: () => render(), titleOf: graph => graph.title,
    blockLabel: (graph, block) => graph.evidence === 'observed' ? `step ${graph.offsets[block]}` : `loc_${graph.offsets[block].toString(16)}`});
  const runner = createBlockGraphRunner();
  host.hidden = true;
  let isOpen = false, layer = 'declared', generation = 0;
  const switcher = document.createElement('div'); switcher.className = 'block-graph-layers'; switcher.setAttribute('role', 'group'); switcher.setAttribute('aria-label', 'Graph layer');
  const buttons = {};
  for (const [key, label] of [['declared', 'Declared'], ['observed', 'Observed path']]) {
    const element = document.createElement('button'); element.type = 'button'; element.className = 'source-tool block-graph-tool'; element.textContent = label; element.setAttribute('aria-pressed', String(key === layer));
    element.addEventListener('click', () => setLayer(key)); buttons[key] = element; switcher.append(element);
  }
  view.tools.prepend(switcher);
  function setLayer(next) { layer = next; for (const [key, element] of Object.entries(buttons)) element.setAttribute('aria-pressed', String(key === layer)); render(); }
  async function render() {
    if (!isOpen) return;
    const owner = ++generation;
    if (layer === 'observed') {
      const path = getObservedPath?.();
      if (!path) { runner.cancel(); view.setTitle('Observed path'); view.setState('empty', 'Import a retained trace in Execution to draw its observed path. It stays a separate layer from declared flow.'); return; }
      await lay(vmObservedBlockGraph(path), owner);
    } else {
      const report = getReport();
      if (!report?.instructions.length) { runner.cancel(); view.setTitle('Static bytecode'); view.setState('empty', report ? 'No instructions decoded. See Inputs and limits.' : 'Analyze a bytecode image to draw its declared blocks.'); return; }
      await lay(vmStaticBlockGraph(report), owner);
    }
  }
  async function lay(graph, owner) {
    view.setState('loading', 'Laying out the graph…');
    try {
      const result = await runner.run({type: 'graph', graph, metrics: view.measurements(), engine: blockGraphEngine()});
      if (owner === generation) view.setResult(result);
    } catch (error) { if (owner === generation && error.name !== 'AbortError') view.setState('error', error.message, true); }
  }
  function open() { isOpen = true; host.hidden = false; button.setAttribute('aria-pressed', 'true'); view.activate(); render(); }
  function close() { isOpen = false; generation += 1; host.hidden = true; button.setAttribute('aria-pressed', 'false'); runner.cancel(); view.release(); }
  return {toggle: () => (isOpen ? close() : open()), close, refresh: () => render()};
}

// The offline check reads the graph builders.
if (typeof module === 'object' && module?.exports) module.exports = {vmStaticBlockGraph, vmObservedBlockGraph, BLOCK_GRAPH_KIND};
