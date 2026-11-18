/* Basic-block graph view: one function or bytecode image at a time. The drawing
 * is a single canvas, so nothing here scales DOM with graph size. Graphs are
 * built and laid out in block_graph_layout.js as a Web Worker. Captured text
 * is painted as glyphs. */
const BLOCK_GRAPH_KIND = {fallthrough: 0, branch: 1, taken: 2, not_taken: 3, table: 4, table_default: 5, exception: 6, unresolved: 7, call: 8, assumed: 9, sequence: 10};
const BLOCK_GRAPH_LIMITS = 'Declared flow, not observed execution. A complete drawing is not a proof.';
/* Rows are drawn only where 11 px text stays readable; below it, labels are
 * painted at screen size and a cue says rows are hidden. */
const BLOCK_GRAPH_ROW_ZOOM = 0.6;
/* Below this zoom a card is a filled box, and every card of one kind is drawn
 * as one path, so a graph of any size stays one fill per kind. */
const BLOCK_GRAPH_OVERVIEW_ZOOM = 0.18;
/* Layouts are retained in a small byte budget, never a whole-module set. */
const BLOCK_GRAPH_CACHE_BYTES = 16 * 1024 * 1024;
/* The backing store is the view's one allocation that scales with window size. */
const BLOCK_GRAPH_CANVAS_BYTES = 32 * 1024 * 1024;
/* The flow graph's zoom range. The block graph zooms out as far as Fit needs. */
const GRAPH_ZOOM = Object.freeze({min: 0.02, max: 2.5});
/* Kinds whose label says what the stroke cannot (a case list, why a target is
 * unknown), drawn always. A true or false arm says it by color and dash, so
 * its label is drawn for the selected block's edges only. */
const BLOCK_GRAPH_LABELED = new Set([BLOCK_GRAPH_KIND.table, BLOCK_GRAPH_KIND.table_default, BLOCK_GRAPH_KIND.exception, BLOCK_GRAPH_KIND.unresolved, BLOCK_GRAPH_KIND.call, BLOCK_GRAPH_KIND.assumed]);

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
 * over the same graph point, within [min, GRAPH_ZOOM.max]. */
function graphZoomAt(view, factor, cx, cy, min = GRAPH_ZOOM.min) {
  const z = Math.min(GRAPH_ZOOM.max, Math.max(min, view.z * factor));
  const gx = view.x + cx / view.z, gy = view.y + cy / view.z;
  return {x: gx - cx / z, y: gy - cy / z, z};
}

/** Writes `Laying out with Triskel · N s` as seconds pass. They count on
 * animation frames, which stop while the page is hidden, so a hidden view
 * runs nothing. Returns the function that stops it. */
function graphTriskelElapsed(write) {
  const started = performance.now();
  let second = -1, frame = 0, running = true;
  const tick = () => {
    if (!running) return;
    const now = Math.floor((performance.now() - started) / 1000);
    if (now !== second) { second = now; write(`Laying out with Triskel · ${now} s`); }
    frame = requestAnimationFrame(tick);
  };
  tick();
  return () => { running = false; cancelAnimationFrame(frame); };
}

/* Reads Sources and the Flow workspace's CFG pane share. Each throws an Error
 * whose message can be shown; an aborted read throws an AbortError. */

/** The error a failed response carries: its JSON `error`, else `fallback`,
 * with the response's `status`. */
async function responseError(response, fallback) {
  let message = fallback;
  try { message = (await response.json()).error || fallback; } catch { /* the fallback stands */ }
  return Object.assign(Error(message), {status: response.status});
}

/** What a failed read or layout tells the researcher, and whether Retry can
 * help. Only a failure that can pass offers it: the service unreachable or
 * busy, or the layout worker stopped. A refused read, an invalid document or
 * a graph past the memory the layout could allocate fails the same way again. */
function blockGraphFailure(error) {
  if (error instanceof TypeError) return {message: 'The evidence service is unreachable. Check that the session is still running.', retry: true};
  const text = String(error?.message || 'The graph could not be drawn.');
  if (error?.name === 'RangeError' || /out of memory|allocation failed|invalid (typed )?array length|invalid string length/i.test(text))
    return {message: `Drawing this graph needs more memory than the layout could allocate (${text}).`, retry: false};
  if (Number.isInteger(error?.status)) return {message: text, retry: error.status >= 500 || error.status === 408 || error.status === 429};
  return {message: text, retry: error?.transient === true};
}

/** What a failed read tells the researcher. */
const graphReadMessage = error => blockGraphFailure(error).message;

/** `count` and its noun: `1 block`, `2 blocks`. */
const blockGraphCount = (count, one, many = `${one}s`) => `${count.toLocaleString()} ${count === 1 ? one : many}`;

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
 * by `runner` with `view`'s measurements; `view` says when layout starts.
 * The region layout is the answer: Triskel runs only when asked. */
async function loadWasmFunctionGraph({artifactId, functionIndex, view, runner, signal}) {
  const response = await fetch(`/api/wasm/graph?artifact_id=${encodeURIComponent(artifactId)}&function=${functionIndex}`, {cache: 'no-store', signal});
  if (!response.ok) throw await responseError(response, `The block graph read returned ${response.status}.`);
  const buffer = await response.arrayBuffer();
  signal?.throwIfAborted();
  view.setState('loading', 'Laying out the graph…');
  const result = await runner.run({type: 'wasm', buffer, metrics: view.measurements()}, [buffer]);
  signal?.throwIfAborted();
  result.graph.functionIndex = functionIndex;
  return result;
}

/** Why Triskel's drawing is not shown (a graphLayoutClient reason, or
 * one_block from the layout worker), as the header's tooltip words it. */
function blockGraphLayoutReason(reason) {
  switch (reason?.code) {
    case 'one_block': return 'the function is one block';
    case 'cancelled': return 'Triskel was stopped';
    case 'mismatch': return 'the Triskel answer did not match the function';
    case 'failed': return `Triskel ${reason.status}${reason.detail ? `: ${reason.detail}` : ''}`;
    case 'status': return `the layout route returned ${reason.status}`;
    case 'route_failed': return `the layout route was unavailable (${reason.detail})`;
    case 'not_served': return 'the layout route is not served here';
    case 'error': return reason.detail;
    default: return '';
  }
}

/** `2.4`: a size ratio as the header prints it. */
const blockGraphRatio = ratio => ratio.toFixed(ratio < 10 ? 1 : 0);

/** Edge indices grouped by `key(e)`, which skips an edge by returning -1. */
function blockGraphGroups(count, edges, key) {
  const start = new Int32Array(count + 1);
  for (let e = 0; e < edges; e += 1) { const k = key(e); if (k >= 0) start[k + 1] += 1; }
  for (let i = 0; i < count; i += 1) start[i + 1] += start[i];
  const fill = start.slice(0, count), list = new Int32Array(start[count]);
  for (let e = 0; e < edges; e += 1) { const k = key(e); if (k >= 0) list[fill[k]++] = e; }
  return {start, list};
}

/** Distance from (px, py) to the segment (ax, ay)-(bx, by). */
function blockGraphSegmentDistance(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay, length = dx * dx + dy * dy;
  const t = length ? Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / length)) : 0;
  return Math.hypot(px - ax - t * dx, py - ay - t * dy);
}

let blockGraphViews = 0;
function createBlockGraphView(root, options = {}) {
  const K = BLOCK_GRAPH_KIND;
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
  const zoomBar = node('div', 'block-graph-zoom-bar'); zoomBar.append(zoomOut, zoomLabel, zoomIn, fitButton); zoomBar.hidden = true;
  // Triskel runs only when asked. The button lays out with it, is Cancel
  // while it runs, then switches between the two drawings.
  const triskelButton = tool('Lay out with Triskel', triskelAction);
  triskelButton.classList.add('block-graph-triskel'); triskelButton.hidden = true;
  tools.append(triskelButton, zoomBar);
  const engineRun = node('span', 'block-graph-engine-run', ''); engineRun.setAttribute('role', 'status'); engineRun.setAttribute('aria-live', 'polite'); engineRun.hidden = true;
  const stage = node('div', 'block-graph-stage');
  const canvas = node('canvas', 'block-graph-canvas');
  canvas.tabIndex = 0; canvas.setAttribute('role', 'application');
  canvas.setAttribute('aria-label', 'Basic-block graph. Arrow keys move between blocks; ] and [ step through them in address order. Alt with Left and Right picks an edge of the selected block, Alt with Down follows it to its target and Alt with Up to its source. Plus and minus zoom, 0 fits, Shift with the arrows pans, Enter shows the selected block in the disassembly and hex.');
  const miniWrap = node('div', 'block-graph-minimap'); const minimap = node('canvas', 'block-graph-minimap-canvas'); minimap.width = 300; minimap.height = 220; minimap.setAttribute('aria-hidden', 'true'); miniWrap.append(minimap); miniWrap.hidden = true;
  const stateBox = node('div', 'block-graph-state'); stateBox.setAttribute('role', 'status'); stateBox.setAttribute('aria-live', 'polite'); stateBox.hidden = true;
  const stateText = node('p', '', ''); const retry = node('button', 'secondary-button', 'Retry'); retry.type = 'button'; retry.hidden = true;
  stateBox.append(stateText, retry);
  const hud = node('div', 'block-graph-hud');
  const selection = node('span', 'block-graph-selection', ''); selection.setAttribute('role', 'status'); selection.setAttribute('aria-live', 'polite');
  const findCue = node('span', 'block-graph-find', ''); findCue.hidden = true;
  const lodCue = node('span', 'block-graph-lod', 'Overview: zoom in to read instructions'); lodCue.hidden = true;
  hud.append(lodCue, findCue, selection);
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
  head.append(title, analyst, stats, engineRun, evidence, tools);
  root.append(head, stage, foot);
  const ctx = canvas.getContext?.('2d'), miniCtx = minimap.getContext?.('2d');
  const tokenNames = {bg: '--graph-canvas', card: '--graph-card', head: '--graph-card-head', line: '--graph-card-line', text: '--text', muted: '--muted', faint: '--faint', mono: '--mono', control: '--syntax-control', fn: '--syntax-function',
    selection: '--graph-selection', selectionSoft: '--graph-selection-soft', match: '--graph-match', overview: '--graph-card-overview', overviewDead: '--graph-card-overview-unreached',
    fallthrough: '--graph-edge-fallthrough', branch: '--graph-edge-branch', taken: '--graph-edge-taken', notTaken: '--graph-edge-not-taken', table: '--graph-edge-table', exception: '--graph-edge-exception', unresolved: '--graph-edge-unresolved', call: '--graph-edge-call', assumed: '--graph-edge-assumed', sequence: '--graph-edge-sequence', dead: '--graph-card-unreached', gap: '--graph-card-gap'};
  let tokens = {};
  const readTokens = () => { const style = getComputedStyle(root); const result = {}; for (const [key, name] of Object.entries(tokenNames)) result[key] = style.getPropertyValue(name).trim(); tokens = result; miniDirty = true; };
  /* `current` is the drawn result: {graph, starts, layout} from the layout
   * worker, the region layout, plus `triskel` once Triskel answers, `shown`
   * (which of the two is drawn) and each drawing's last view. */
  let view = {x: 0, y: 0, z: 1}, current = null, graph = null, starts = null, layout = null, selectedBlock = -1, selectedRow = -1, focusEdge = -1;
  let frame = 0, active = false, cssW = 0, cssH = 0, dpr = 1, miniDirty = true, miniImage = null, onError = null, needsFit = false, fitted = false;
  // Per graph: edges out of and into each block, blocks in address order, and
  // each stub's slot under its block, so a key press never scans the graph.
  let outs = null, ins = null, order = null, rank = null, byFirstRow = null, stubSlot = null, lowerRows = null;
  // The Find in the drawn rows: matched rows and blocks, and the one shown.
  let find = null;
  // Label chips drawn in the last frame, in graph units, for pointer hits.
  let chips = [];
  const edgeStyles = {
    [K.fallthrough]: ['fallthrough', []], [K.branch]: ['branch', []], [K.taken]: ['taken', []], [K.not_taken]: ['notTaken', [6, 3]],
    [K.table]: ['table', [2, 3]], [K.table_default]: ['table', [2, 3]], [K.exception]: ['exception', [8, 4]], [K.unresolved]: ['unresolved', [4, 2, 1, 2]],
    [K.call]: ['call', [1, 3]], [K.assumed]: ['assumed', [1, 3]], [K.sequence]: ['sequence', []]};
  const styleOf = kind => edgeStyles[kind] ?? edgeStyles[K.branch];
  const m = {charW: 6.6, rowH: 16, headerH: 22, padX: 10, padY: 7};
  let chipCharW = 6;
  const measure = () => {
    if (!ctx) return;
    ctx.font = `11px ${tokens.mono || 'monospace'}`; m.charW = ctx.measureText('0').width || 6.6;
    ctx.font = `10px ${tokens.mono || 'monospace'}`; chipCharW = ctx.measureText('0').width || 6;
  };
  const requestDraw = () => { if (active && !frame) frame = requestAnimationFrame(() => { frame = 0; draw(); }); };
  /** Rows a card draws: a folded run of structural rows is one summary row. */
  const shownRows = block => graph.rowCount[block] - (graph.folded?.[block] ?? 0) + (graph.folded?.[block] ? 1 : 0);
  /** The absolute row a card's `shown` row draws, and back. */
  const rowOfShown = (block, shown) => { const folded = graph.folded?.[block] ?? 0; return graph.firstRow[block] + (folded ? (shown === 0 ? 0 : folded + shown - 1) : shown); };
  const shownOfRow = (block, row) => { const folded = graph.folded?.[block] ?? 0, local = row - graph.firstRow[block]; return folded ? (local < folded ? 0 : local - folded + 1) : local; };
  const rowText = row => graph.rows.slice(starts[row], starts[row + 1] - 1);

  /** The part of the stage the minimap and the HUD leave clear, which Fit
   * fills: beside the minimap or above it, whichever leaves more room. */
  function clearArea() {
    const box = stage.getBoundingClientRect?.(), mini = miniWrap.hidden ? null : miniWrap.getBoundingClientRect?.(), cue = hud.getBoundingClientRect?.();
    if (!box?.width) return {w: cssW, h: cssH};
    const miniW = mini?.width ? box.right - mini.left : 0, miniH = mini?.height ? box.bottom - mini.top : 0;
    const hudH = cue?.height ? box.bottom - cue.top : 0;
    const beside = {w: cssW - miniW, h: cssH - hudH}, above = {w: cssW, h: cssH - Math.max(miniH, hudH)};
    const area = ({w, h}) => Math.max(0, w) * Math.max(0, h);
    const best = area(beside) >= area(above) ? beside : above;
    return {w: Math.max(1, best.w), h: Math.max(1, best.h)};
  }
  /** The view that shows the whole drawing in the clear part of the stage. */
  function fitView() {
    const {w, h} = clearArea();
    const z = Math.min(1, w / layout.width, h / layout.height);
    return {x: layout.width / 2 - w / 2 / z, y: layout.height / 2 - h / 2 / z, z};
  }
  /** How far out the view zooms: past Fit for no graph, to Fit for any. */
  const zoomFloor = () => (layout ? Math.min(GRAPH_ZOOM.min, fitView().z) : GRAPH_ZOOM.min);
  function resize() {
    if (!active) return;
    ({cssW, cssH, dpr} = graphFitCanvas(canvas, stage));
    if (needsFit && layout && cssW > 1) { needsFit = false; start(); return; }
    // A fitted view stays fitted when the pane resizes (Linear hidden or a
    // divider dragged).
    if (fitted && layout) view = fitView();
    requestDraw();
  }
  const visible = (x, y, w, h) => { const r = view.x + cssW / view.z, b = view.y + cssH / view.z; return x < r && x + w > view.x && y < b && y + h > view.y; };
  const touches = edge => selectedBlock >= 0 && (graph.from[edge] === selectedBlock || graph.to[edge] === selectedBlock);
  const isStub = edge => graph.to[edge] < 0 || layout.stub?.[edge] === 1;

  function draw() {
    if (!ctx || !active) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.fillStyle = tokens.bg; ctx.fillRect(0, 0, cssW, cssH);
    chips = [];
    if (!layout) { lodCue.hidden = true; drawMinimap(); return; }
    const z = view.z;
    ctx.setTransform(dpr * z, 0, 0, dpr * z, -view.x * z * dpr, -view.y * z * dpr);
    const lod = z < BLOCK_GRAPH_OVERVIEW_ZOOM ? 0 : z < BLOCK_GRAPH_ROW_ZOOM ? 1 : 2, rv = view.x + cssW / z, bv = view.y + cssH / z;
    const labeled = drawEdges(rv, bv, lod);
    const shown = [];
    if (lod === 0) drawOverview(rv, bv, shown);
    else {
      for (let block = 0; block < graph.count; block += 1) {
        const x = layout.x[block], y = layout.y[block], w = layout.w[block], h = layout.h[block];
        if (x >= rv || x + w <= view.x || y >= bv || y + h <= view.y) continue;
        drawCard(block, x, y, w, h, lod);
        if (lod < 2) shown.push(block);
      }
    }
    if (lod === 2) drawChips(labeled, rv, bv);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (lod < 2) drawScreenLabels(shown);
    lodCue.hidden = lod === 2;
    zoomLabel.textContent = `${z >= 0.1 ? Math.round(z * 100) : Number((z * 100).toPrecision(1))}%`;
    drawMinimap();
  }
  /** Below row zoom, each card that has room keeps a legible label and count. */
  function drawScreenLabels(blocks) {
    ctx.font = `11px ${tokens.mono}`; ctx.textBaseline = 'middle';
    for (const block of blocks) {
      const sx = (layout.x[block] - view.x) * view.z, sy = (layout.y[block] - view.y) * view.z, sw = layout.w[block] * view.z, sh = layout.h[block] * view.z;
      if (sw < 48 || sh < 15) continue;
      const room = Math.floor((sw - 12) / m.charW), count = graph.instructionCount[block];
      const label = blockLabel(block), counted = graph.evidence === 'observed' ? blockGraphCount(count, 'step') : `${count.toLocaleString()} ins`;
      ctx.save(); ctx.beginPath(); ctx.rect(sx, sy, sw, sh); ctx.clip();
      // A label cut to a few characters names nothing; it is left out.
      if (label.length > room && room < 10) { ctx.restore(); continue; }
      ctx.fillStyle = block === selectedBlock ? tokens.text : tokens.muted;
      ctx.fillText(label.length > room ? `${label.slice(0, room - 1)}…` : label, sx + 6, sy + Math.min(sh / 2, 11));
      if (sh >= 34 && counted.length <= room) { ctx.fillStyle = tokens.faint; ctx.fillText(counted, sx + 6, sy + 28); }
      ctx.restore();
    }
  }
  /** Adds edge `edge`'s polyline to `path`, its corners rounded by `corner`
   * where the segments beside a corner leave room. */
  function trace(path, edge, corner) {
    const start = layout.pointStart[edge], end = layout.pointStart[edge + 1], pts = layout.points;
    path.moveTo(pts[start * 2], pts[start * 2 + 1]);
    for (let i = start + 1; i < end; i += 1) {
      const x = pts[i * 2], y = pts[i * 2 + 1];
      if (corner && i < end - 1) {
        const nx = pts[(i + 1) * 2], ny = pts[(i + 1) * 2 + 1];
        const r = Math.min(corner, Math.hypot(x - pts[(i - 1) * 2], y - pts[(i - 1) * 2 + 1]) / 2, Math.hypot(nx - x, ny - y) / 2);
        if (r > 0.5) { path.arcTo(x, y, nx, ny, r); continue; }
      }
      path.lineTo(x, y);
    }
  }
  /** Adds the arrowhead at edge `edge`'s end to `path`. */
  function arrowhead(path, edge) {
    const end = layout.pointStart[edge + 1] - 1, pts = layout.points;
    if (end <= layout.pointStart[edge]) return;
    const x = pts[end * 2], y = pts[end * 2 + 1], angle = Math.atan2(y - pts[end * 2 - 1], x - pts[end * 2 - 2]), size = 6;
    path.moveTo(x, y);
    path.lineTo(x - size * Math.cos(angle - 0.45), y - size * Math.sin(angle - 0.45));
    path.lineTo(x - size * Math.cos(angle + 0.45), y - size * Math.sin(angle + 0.45)); path.closePath();
  }
  /** Draws the visible edges, one stroke per kind; the selected block's
   * edges over the rest, then the focused edge. Returns the edges to label. */
  function drawEdges(rv, bv, lod) {
    const plain = new Map(), picked = new Map(), labeled = [], corner = lod === 2 ? 6 : 0, count = graph.from.length, box = layout.box;
    const batch = (map, kind) => { let entry = map.get(kind); if (!entry) map.set(kind, entry = {path: new Path2D(), heads: new Path2D()}); return entry; };
    let focused = false;
    for (let edge = 0; edge < count; edge += 1) {
      if (box[edge * 4] > rv || box[edge * 4 + 2] < view.x || box[edge * 4 + 1] > bv || box[edge * 4 + 3] < view.y) continue;
      const kind = graph.kind[edge], near = touches(edge);
      if (lod === 2 && chipText(edge) && (near || edge === focusEdge || isStub(edge) || BLOCK_GRAPH_LABELED.has(kind))) labeled.push(edge);
      if (edge === focusEdge) { focused = true; continue; }
      const entry = batch(near ? picked : plain, kind);
      trace(entry.path, edge, corner);
      if (lod >= 1 && graph.to[edge] >= 0) arrowhead(entry.heads, edge);
    }
    ctx.lineJoin = 'round'; ctx.lineCap = 'butt';
    const paint = (map, width, color) => {
      for (const [kind, entry] of map) {
        const [token, dash] = styleOf(kind);
        ctx.strokeStyle = ctx.fillStyle = color ?? tokens[token]; ctx.lineWidth = width; ctx.setLineDash(lod === 2 ? dash : []);
        ctx.stroke(entry.path); ctx.setLineDash([]); ctx.fill(entry.heads);
      }
    };
    paint(plain, lod === 2 ? 1.8 : 1 / view.z);
    paint(picked, lod === 2 ? 2.6 : 2.2 / view.z, tokens.selection);
    if (focused) {
      // The focused edge: a soft halo under a full-width selection stroke.
      const path = new Path2D(), heads = new Path2D();
      trace(path, focusEdge, corner); if (graph.to[focusEdge] >= 0) arrowhead(heads, focusEdge);
      ctx.setLineDash([]); ctx.strokeStyle = tokens.selectionSoft; ctx.lineWidth = lod === 2 ? 8 : 7 / view.z; ctx.stroke(path);
      ctx.strokeStyle = ctx.fillStyle = tokens.selection; ctx.lineWidth = lod === 2 ? 3.2 : 3 / view.z; ctx.setLineDash(lod === 2 ? styleOf(graph.kind[focusEdge])[1] : []);
      ctx.stroke(path); ctx.setLineDash([]); ctx.fill(heads);
    }
    return labeled;
  }
  /** What an edge's chip says: a stub names the block it reaches. */
  function chipText(edge) {
    const label = graph.labels[edge];
    if (graph.to[edge] >= 0 && layout.stub?.[edge]) return `→ ${blockLabel(graph.to[edge])}${label ? ` (${label})` : ''}`;
    if (graph.to[edge] < 0) return label || 'unresolved';
    return label || '';
  }
  /** Each label is a chip beside its stroke, never over it: a stub's below
   * the stub, any other where the edge arrives, beside its last segment and
   * clear of the card it enters. Edges arriving at one point stack their
   * chips away from the card. */
  function drawChips(edges, rv, bv) {
    ctx.setLineDash([]); ctx.font = `10px ${tokens.mono}`; ctx.textBaseline = 'middle';
    const h = 14, taken = new Map(), pts = layout.points;
    const stack = key => { const n = taken.get(key) ?? 0; taken.set(key, n + 1); return n * (h + 2); };
    for (const edge of edges) {
      const full = chipText(edge), text = full.length > 32 ? `${full.slice(0, 31)}…` : full, w = text.length * chipCharW + 8;
      const end = layout.pointStart[edge + 1] - 1, kind = graph.kind[edge], tx = pts[end * 2], ty = pts[end * 2 + 1];
      let x, y;
      if (isStub(edge)) { x = tx - w / 2; y = ty + 4 + stubSlot[edge] * (h + 2); }
      else {
        const dx = tx - pts[end * 2 - 2], dy = ty - pts[end * 2 - 1], shift = stack(`${tx},${ty}`);
        if (Math.abs(dy) >= Math.abs(dx)) { x = tx + 5; y = dy >= 0 ? ty - h - 4 - shift : ty + 4 + shift; }
        else { x = dx > 0 ? tx - w - 6 : tx + 6; y = ty - h - 3 - shift; }
      }
      if (x > rv || y > bv || x + w < view.x || y + h < view.y) continue;
      const near = touches(edge) || edge === focusEdge;
      ctx.fillStyle = tokens.card; ctx.strokeStyle = near ? tokens.selection : tokens[styleOf(kind)[0]]; ctx.lineWidth = near ? 1.5 : 1;
      ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, 3); ctx.fill(); ctx.stroke();
      ctx.fillStyle = near ? tokens.text : tokens.muted; ctx.fillText(text, x + 4, y + h / 2 + 0.5);
      chips.push({x, y, w, h, edge});
    }
  }
  /** Overview: every visible card of one kind in one path. A card keeps at
   * least a pixel, and the selection and the shown match a ring of ten, so
   * neither disappears at any zoom. */
  function drawOverview(rv, bv, shown) {
    const live = new Path2D(), dead = new Path2D(), gaps = new Path2D(), found = new Path2D(), z = view.z, least = 1 / z;
    for (let block = 0; block < graph.count; block += 1) {
      const x = layout.x[block], y = layout.y[block], w = Math.max(layout.w[block], least), h = Math.max(layout.h[block], least);
      if (x >= rv || x + w <= view.x || y >= bv || y + h <= view.y) continue;
      const flags = graph.flags[block];
      (flags & 16 ? gaps : flags & 2 ? live : dead).rect(x, y, w, h);
      if (find?.hit[block]) found.rect(x, y, w, h);
      if (w * z >= 48 && h * z >= 15) shown.push(block);
    }
    ctx.fillStyle = tokens.overview; ctx.fill(live);
    ctx.fillStyle = tokens.overviewDead; ctx.fill(dead);
    ctx.fillStyle = tokens.gap; ctx.fill(gaps);
    if (find) { ctx.fillStyle = tokens.match; ctx.fill(found); }
    const ring = (block, color) => {
      if (block < 0) return;
      const w = Math.max(layout.w[block], 10 / z), h = Math.max(layout.h[block], 10 / z), x = layout.x[block] + layout.w[block] / 2 - w / 2, y = layout.y[block] + layout.h[block] / 2 - h / 2;
      ctx.setLineDash([]); ctx.strokeStyle = color; ctx.lineWidth = 2 / z; ctx.strokeRect(x - 2 / z, y - 2 / z, w + 4 / z, h + 4 / z);
    };
    if (find?.current >= 0) ring(find.blocks[find.current], tokens.match);
    ring(selectedBlock, tokens.selection);
  }
  function drawCard(block, x, y, w, h, lod) {
    const flags = graph.flags[block], unreached = !(flags & 2), gapCard = (flags & 16) !== 0, picked = block === selectedBlock;
    // Outlines stay one screen pixel at every zoom.
    const matched = find?.hit[block] === 1, shownMatch = find?.current >= 0 && find.blocks[find.current] === block, hair = 1 / view.z;
    ctx.setLineDash([]);
    ctx.fillStyle = gapCard ? tokens.gap : tokens.card; ctx.strokeStyle = picked ? tokens.selection : matched ? tokens.match : tokens.line;
    ctx.lineWidth = picked || shownMatch ? 2 * hair : matched ? 1.5 * hair : hair;
    ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, 4); ctx.fill(); ctx.stroke();
    if (picked && shownMatch) { ctx.strokeStyle = tokens.match; ctx.lineWidth = hair; ctx.beginPath(); graphRoundedRect(ctx, x - 3 * hair, y - 3 * hair, w + 6 * hair, h + 6 * hair, 6); ctx.stroke(); }
    ctx.save(); ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, 4); ctx.clip();
    if (!gapCard && lod === 2) { ctx.fillStyle = unreached ? tokens.dead : picked ? tokens.selectionSoft : tokens.head; ctx.fillRect(x, y, w, m.headerH); }
    else if (unreached) { ctx.fillStyle = tokens.dead; ctx.fillRect(x, y, w, h); }
    if (lod === 2) {
      ctx.textBaseline = 'middle'; ctx.font = `11px ${tokens.mono}`; ctx.fillStyle = tokens.muted;
      if (gapCard) ctx.fillText('gap', x + m.padX, y + m.headerH / 2);
      else {
        ctx.fillText(blockLabel(block), x + m.padX, y + m.headerH / 2);
        const badge = graph.instructionCount[block].toLocaleString(), bw = badge.length * m.charW + 8;
        // A filled count badge, as in the Flow graph.
        ctx.fillStyle = tokens.head; ctx.fillRect(x + w - bw - 7.5, y + 4.5, bw, 13);
        ctx.strokeStyle = tokens.line; ctx.lineWidth = 1; ctx.strokeRect(x + w - bw - 7.5, y + 4.5, bw, 13); ctx.fillStyle = tokens.muted; ctx.fillText(badge, x + w - bw - 3, y + m.headerH / 2);
      }
      drawRows(block, x, y, w);
    }
    ctx.restore();
  }
  function drawRows(block, x, y, w) {
    const folded = graph.folded?.[block] ?? 0, count = shownRows(block), top = y + m.headerH + m.padY;
    ctx.font = `11px ${tokens.mono}`; ctx.textBaseline = 'alphabetic';
    const firstVisible = Math.max(0, Math.floor((view.y - top) / m.rowH)), lastVisible = Math.min(count, Math.ceil((view.y + cssH / view.z - top) / m.rowH));
    const pickedShown = selectedBlock === block && selectedRow >= 0 ? shownOfRow(block, selectedRow) : -1;
    for (let shown = firstVisible; shown < lastVisible; shown += 1) {
      const row = rowOfShown(block, shown), ry = top + shown * m.rowH, line = ry + m.rowH - 4;
      if (pickedShown === shown) { ctx.fillStyle = tokens.selectionSoft; ctx.fillRect(x + 1, ry, w - 2, m.rowH); ctx.fillStyle = tokens.selection; ctx.fillRect(x + 1, ry + 2, 2, m.rowH - 4); }
      const text = rowText(row), a = text.indexOf(' ');
      if (folded && shown === 0) {
        // The structural rows folded in: the first one's offset and what they were.
        // A header-tinted band sets it apart from the rows that run.
        let hit = false; for (let r = row; r < row + folded && !hit; r += 1) hit = find?.rowHit[r] === 1;
        if (pickedShown !== shown) { ctx.fillStyle = tokens.head; ctx.fillRect(x + 1, ry + 1, w - 2, m.rowH - 2); }
        if (hit) { ctx.globalAlpha = 0.16; ctx.fillStyle = tokens.match; ctx.fillRect(x + 1, ry, w - 2, m.rowH); ctx.globalAlpha = 1; }
        ctx.fillStyle = tokens.faint; ctx.fillText(`${text.slice(0, a)} ${graph.foldNote[block]}`, x + m.padX, line);
        continue;
      }
      const spaced = text.indexOf(' ', a + 1), b = spaced < 0 ? text.length : spaced;
      const offset = text.slice(0, a), mnemonic = text.slice(a + 1, b), rest = spaced < 0 ? '' : text.slice(b + 1);
      const mnemonicX = x + m.padX + (offset.length + 1) * m.charW, restX = mnemonicX + (Math.max(mnemonic.length, 10) + 1) * m.charW;
      if (find?.rowHit[row]) {
        // A matched row is banded, and each match boxed under its glyphs.
        ctx.globalAlpha = 0.14; ctx.fillStyle = tokens.match; ctx.fillRect(x + 1, ry, w - 2, m.rowH);
        ctx.globalAlpha = 0.42;
        const lower = text.toLowerCase(), charX = c => (c < a ? x + m.padX + c * m.charW : c <= b ? mnemonicX + (c - a - 1) * m.charW : restX + (c - b - 1) * m.charW);
        if (lower.length === text.length) {
          for (let at = lower.indexOf(find.needle); at >= 0; at = lower.indexOf(find.needle, at + find.needle.length))
            for (let c = at; c < at + find.needle.length; c += 1) ctx.fillRect(charX(c), ry + 2, m.charW, m.rowH - 3);
        }
        ctx.globalAlpha = 1;
      }
      ctx.fillStyle = tokens.faint; ctx.fillText(offset, x + m.padX, line);
      ctx.fillStyle = /^(br|if|else|end|loop|block|return|try|catch|throw|rethrow|delegate|unreachable)/.test(mnemonic) ? tokens.control : /^call/.test(mnemonic) ? tokens.fn : tokens.text;
      ctx.fillText(mnemonic, mnemonicX, line);
      if (rest) { ctx.fillStyle = tokens.muted; ctx.fillText(rest, restX, line); }
    }
    if (graph.flags[block] & 32) { ctx.fillStyle = tokens.faint; ctx.fillText(count ? 'more rows past the byte budget' : 'rows past the byte budget', x + m.padX, top + count * m.rowH + m.rowH - 4); }
  }
  const blockLabel = block => graph.flags[block] & 16 ? 'gap' : options.blockLabel?.(graph, block) ?? `loc_${graph.offsets[block].toString(16)}`;
  function drawMinimap() {
    if (!miniCtx) return;
    miniWrap.hidden = !layout;
    if (!layout) return;
    const w = minimap.width, h = minimap.height, scale = Math.min(w / layout.width, h / layout.height);
    const ox = (w - layout.width * scale) / 2, oy = (h - layout.height * scale) / 2;
    if (miniDirty) {
      miniCtx.fillStyle = tokens.bg; miniCtx.fillRect(0, 0, w, h);
      miniCtx.fillStyle = tokens.overview;
      for (let block = 0; block < graph.count; block += 1) miniCtx.fillRect(ox + layout.x[block] * scale, oy + layout.y[block] * scale, Math.max(1, layout.w[block] * scale), Math.max(1, layout.h[block] * scale));
      if (find) {
        miniCtx.fillStyle = tokens.match;
        for (const block of find.blocks) miniCtx.fillRect(ox + layout.x[block] * scale - 1, oy + layout.y[block] * scale - 1, Math.max(3, layout.w[block] * scale + 2), Math.max(3, layout.h[block] * scale + 2));
      }
      miniImage = miniCtx.getImageData?.(0, 0, w, h) ?? null;
      miniDirty = false;
    }
    if (miniImage) miniCtx.putImageData(miniImage, 0, 0);
    miniCtx.strokeStyle = tokens.selection; miniCtx.lineWidth = 2;
    // The viewport can be larger than the whole graph; keep its outline on the minimap.
    const left = Math.max(1, ox + view.x * scale), top = Math.max(1, oy + view.y * scale);
    const right = Math.min(w - 1, ox + (view.x + cssW / view.z) * scale), bottom = Math.min(h - 1, oy + (view.y + cssH / view.z) * scale);
    miniCtx.strokeRect(left, top, Math.max(3, right - left), Math.max(3, bottom - top));
  }
  function setState(kind, message = '', canRetry = false) {
    stateBox.hidden = kind === 'ready';
    stateBox.dataset.kind = kind;
    // Over a drawing, a state is a banner and the drawing stays readable.
    stateBox.dataset.overlay = layout ? 'banner' : 'center';
    stateText.textContent = message; retry.hidden = !canRetry; onError = canRetry ? options.retry : null;
    // Zoom and the overview cue describe a drawing; with none they are hidden.
    miniWrap.hidden = zoomBar.hidden = !layout;
    if (!layout) lodCue.hidden = true;
    renderTriskel(); requestDraw();
  }
  retry.addEventListener('click', () => onError?.());

  // Triskel has no deadline: while it runs, elapsed seconds and Cancel.
  let waiting = null, triskelJob = null;
  function stopWait() { waiting?.(); waiting = null; }
  const triskelServed = () => Boolean(options.runner) && blockGraphEngine() === 'triskel';
  function renderTriskel() {
    const offered = triskelServed() && Boolean(current) && graph.count >= 2 && stateBox.hidden && current.triskelReason?.code !== 'not_served';
    const focused = document.activeElement === triskelButton;
    triskelButton.hidden = !offered && !triskelJob;
    const showing = current?.shown === 'triskel';
    triskelButton.textContent = triskelJob ? 'Cancel' : current?.triskel ? (showing ? 'Show region layout' : 'Show Triskel layout') : 'Lay out with Triskel';
    triskelButton.setAttribute('aria-label', triskelJob ? 'Stop Triskel and keep the region layout' : current?.triskel ? (showing ? 'Show the region layout' : 'Show the Triskel layout') : 'Lay out this graph with Triskel');
    triskelButton.title = triskelJob ? 'Stop Triskel and keep the region layout.'
      : current?.triskel ? 'Both layouts are kept; this switches between them.'
        : 'Triskel, a CFG layout engine built on single-entry single-exit regions, lays out this graph beside the region layout. It has no size limit and no deadline: about a minute at 16,000 blocks.';
    if (focused && triskelButton.hidden) canvas.focus({preventScroll: true});
  }
  function triskelAction() {
    if (triskelJob) options.runner?.skip();
    else if (current?.triskel) showLayout(current.shown === 'triskel' ? 'region' : 'triskel');
    else layOutWithTriskel();
  }
  /** Lays out the drawn graph with Triskel. The region layout stays drawn
   * while it runs; its answer is drawn whatever its size, with how it
   * compares, and both stay to switch between. */
  async function layOutWithTriskel() {
    if (!current || triskelJob || !options.runner) return;
    const target = current, job = triskelJob = {}, region = target.layout;
    renderTriskel(); renderHeader();
    engineRun.hidden = false;
    stopWait(); waiting = graphTriskelElapsed(text => { engineRun.textContent = text; });
    const finish = () => {
      if (triskelJob !== job) return false;
      triskelJob = null; stopWait(); engineRun.textContent = ''; engineRun.hidden = true;
      return true;
    };
    try {
      const answer = await options.runner.run({type: 'triskel', graph: {count: target.graph.count, from: target.graph.from, to: target.graph.to},
        layout: {w: region.w, h: region.h, width: region.width, height: region.height, stub: region.stub}, metrics: {...m}});
      if (!finish() || current !== target) return;
      if (answer.layout.engine?.name === 'triskel') { target.triskel = answer.layout; target.triskelReason = null; showLayout('triskel'); }
      else { target.triskelReason = answer.layout.engine?.reason ?? null; renderHeader(); renderTriskel(); }
      options.onLayout?.(target);
    } catch (error) {
      if (!finish() || current !== target || error.name === 'AbortError') return;
      target.triskelReason = {code: 'error', detail: blockGraphFailure(error).message};
      renderHeader(); renderTriskel();
    }
  }
  /** Draws the region or the Triskel layout of the current graph, each at
   * the view it was last left at; the selection stays. */
  function showLayout(which) {
    if (!current || (which === 'triskel' && !current.triskel)) return;
    current.views ??= {};
    if (layout) current.views[current.shown ?? 'region'] = {...view, fitted};
    current.shown = which; layout = which === 'triskel' ? current.triskel : current.layout; miniDirty = true;
    renderHeader(); renderTriskel();
    const saved = current.views[which];
    if (saved) { view = {x: saved.x, y: saved.y, z: saved.z}; fitted = saved.fitted; if (fitted) view = fitView(); requestDraw(); }
    else if (selectedBlock >= 0) centerOn(selectedBlock);
    else start();
  }
  /** What the header says about the layout drawn. */
  function engineNote() {
    if (!current || triskelJob) return '';
    if (current.shown === 'triskel') {
      const {width, height} = current.triskel.engine.ratio;
      return `Triskel layout · ${blockGraphRatio(width)}× as wide, ${blockGraphRatio(height)}× as tall`;
    }
    if (current.triskel) return 'region layout';
    const code = current.triskelReason?.code;
    if (code === 'cancelled') return 'region layout · Triskel stopped';
    if (code && code !== 'one_block' && code !== 'not_served') return 'region layout · Triskel failed';
    return '';
  }
  function renderHeader() {
    if (!graph) return;
    title.textContent = options.titleOf?.(graph) ?? graph.title;
    const blocks = `${blockGraphCount(graph.count, 'block')}${graph.foldedBlocks ? ` (${graph.foldedBlocks.toLocaleString()} folded)` : ''}`;
    const parts = [options.statsPrefix?.(graph), blocks, blockGraphCount(graph.instructions, graph.evidence === 'observed' ? 'retained step' : 'instruction'), engineNote()];
    stats.textContent = parts.filter(Boolean).join(' · ');
    const notes = [];
    if (graph.foldedBlocks) notes.push(`${blockGraphCount(graph.foldedBlocks, 'block')} of only end, block, loop, try or nop ${graph.foldedBlocks === 1 ? 'is' : 'are'} drawn as the first row of the block ${graph.foldedBlocks === 1 ? 'it falls' : 'they fall'} into.`);
    if (current?.shown === 'triskel') {
      const {revision, ratio} = current.triskel.engine;
      notes.push(`Laid out by Triskel${revision ? ` ${revision.slice(0, 7)}` : ''}, a CFG layout engine built on single-entry single-exit regions: ${blockGraphRatio(ratio.width)} times as wide and ${blockGraphRatio(ratio.height)} times as tall as the region layout.`);
    } else if (current?.triskelReason) notes.push(`Region layout: ${blockGraphLayoutReason(current.triskelReason)}.`);
    stats.title = notes.join(' ');
  }
  /** Draws `result`, a new graph or the same one laid out anew, in its
   * region layout unless it says it showed Triskel's. */
  function setResult(result) {
    if (triskelJob) { triskelJob = null; stopWait(); engineRun.textContent = ''; engineRun.hidden = true; }
    current = result; graph = result.graph; starts = result.starts;
    if (current.shown === 'triskel' && !current.triskel) current.shown = 'region';
    current.shown ??= 'region';
    layout = current.shown === 'triskel' ? current.triskel : current.layout;
    selectedBlock = -1; selectedRow = -1; focusEdge = -1; view.z = 1; miniDirty = true;
    indexGraph();
    renderHeader(); renderLegend();
    evidence.textContent = graph.status === 'partial' ? `${graph.evidence} · partial` : graph.evidence;
    limits.textContent = graph.evidence === 'observed' ? graph.notice : BLOCK_GRAPH_LIMITS;
    limits.title = graph.evidence === 'observed' ? graph.notice : 'Declared static flow. Reachable here is not observed execution, and a complete drawing is not a proof.';
    if (graph.omissions?.length) limits.title += ` ${graph.omissions.join(' ')}`;
    selection.textContent = graph.omissions?.length ? graph.omissions[0] : '';
    if (find) { runFind(find.query); renderFind(); options.onFind?.(findStatus()); }
    setState('ready');
    current.views = {};
    needsFit = cssW <= 1;
    start();
  }
  function indexGraph() {
    const n = graph.count, edges = graph.from.length;
    outs = blockGraphGroups(n, edges, e => graph.from[e]);
    ins = blockGraphGroups(n, edges, e => graph.to[e]);
    order = Int32Array.from({length: n}, (_, i) => i).sort((a, b) => graph.offsets[a] - graph.offsets[b] || a - b);
    rank = new Int32Array(n); order.forEach((block, i) => { rank[block] = i; });
    byFirstRow = Int32Array.from({length: n}, (_, i) => i).sort((a, b) => graph.firstRow[a] - graph.firstRow[b] || a - b);
    // A block's stubs sit side by side in edge order, as the layout placed them.
    stubSlot = new Int32Array(edges); const slots = new Int32Array(n);
    for (let e = 0; e < edges; e += 1) if (graph.to[e] < 0 || current.layout.stub?.[e]) stubSlot[e] = slots[graph.from[e]]++;
    lowerRows = null;
  }
  /** The key lists the edge kinds this graph has, in this graph's words. */
  function renderLegend() {
    const wasm = graph.functionIndex !== undefined;
    const words = [[K.fallthrough, 'fallthrough', 'fall'], [K.branch, 'branch', 'br'], [K.taken, 'taken', wasm ? 'true' : 'taken'], [K.not_taken, 'not-taken', wasm ? 'false' : 'not taken'],
      [K.table, 'table', 'table'], [K.exception, 'exception', 'exception'], [K.call, 'call', 'call'], [K.assumed, 'assumed', 'assumed'], [K.sequence, 'sequence', 'step'], [K.unresolved, 'unresolved', 'unresolved']];
    const present = new Set(graph.kind);
    if (present.has(K.table_default)) present.add(K.table);
    legend.replaceChildren();
    for (const [kind, key, label] of words) {
      if (!present.has(kind)) continue;
      const item = node('span', 'block-graph-key');
      const sample = document.createElementNS?.('http://www.w3.org/2000/svg', 'svg');
      if (sample?.setAttribute) { sample.setAttribute('width', '22'); sample.setAttribute('height', '6'); sample.setAttribute('aria-hidden', 'true'); sample.classList.add(`block-graph-key-${key}`); const line = document.createElementNS('http://www.w3.org/2000/svg', 'line'); line.setAttribute('x1', '0'); line.setAttribute('y1', '3'); line.setAttribute('x2', '22'); line.setAttribute('y2', '3'); sample.append(line); item.append(sample); }
      item.append(node('span', '', label)); legend.append(item);
    }
    keyToggle.hidden = !legend.childElementCount;
  }
  /** First view: actual size, centered on the selected block or the entry.
   * A graph that fits at actual size is centered whole. Fit is one key away. */
  function start() {
    if (!layout || !cssW) return;
    view.z = 1;
    const whole = fitView();
    if (whole.z >= 1) { view = whole; fitted = true; requestDraw(); return; }
    fitted = false;
    const block = selectedBlock >= 0 ? selectedBlock : Math.max(0, graph.roots?.[0] ?? 0);
    view.x = layout.x[block] + layout.w[block] / 2 - cssW / 2;
    view.y = layout.y[block] - 24;
    requestDraw();
  }
  function fit() {
    if (!layout || !cssW) return;
    view = fitView(); fitted = true;
    requestDraw();
  }
  function zoomAt(factor, cx = cssW / 2, cy = cssH / 2) {
    if (!layout) return;
    view = graphZoomAt(view, factor, cx, cy, zoomFloor()); fitted = false;
    requestDraw();
  }
  function centerOn(block, row = -1) {
    view.x = layout.x[block] + layout.w[block] / 2 - cssW / view.z / 2;
    const tall = layout.h[block] > cssH / view.z;
    // A block taller than the view is centered on its row, or its header.
    view.y = row >= 0 && tall ? layout.y[block] + m.headerH + m.padY + (shownOfRow(block, row) + 0.5) * m.rowH - cssH / view.z / 2
      : tall ? layout.y[block] - 24 : layout.y[block] + layout.h[block] / 2 - cssH / view.z / 2;
    fitted = false;
    requestDraw();
  }
  /** One edge in words, from the selected block's side. */
  function edgeText(edge) {
    const out = graph.from[edge] === selectedBlock, label = graph.labels[edge];
    const far = out ? (graph.to[edge] >= 0 ? `→ ${blockLabel(graph.to[edge])}` : '→ unresolved') : `← ${blockLabel(graph.from[edge])}`;
    const follow = out ? (graph.to[edge] >= 0 ? ', Alt+Down follows' : '') : ', Alt+Up follows';
    return `edge ${far}${label ? ` (${label})` : ''}${follow}`;
  }
  function describe() {
    const block = selectedBlock, flags = graph.flags[block];
    if (flags & 16) { selection.textContent = `Gap: ${rowText(graph.firstRow[block]).split(' ')[0]} steps not retained. No edge crosses it.`; return; }
    const successors = outs.start[block + 1] - outs.start[block];
    let unresolved = false; for (let i = outs.start[block]; i < outs.start[block + 1]; i += 1) if (graph.to[outs.list[i]] < 0) unresolved = true;
    const count = graph.instructionCount[block];
    const parts = [blockLabel(block), blockGraphCount(count, graph.evidence === 'observed' ? 'step' : 'instruction'), blockGraphCount(successors, 'successor')];
    if (graph.folded?.[block]) parts.push(`opens with ${graph.foldNote[block]}`);
    if (!(flags & 2)) parts.push('not reached by declared edges');
    if (unresolved) parts.push('unresolved target');
    if (focusEdge >= 0) parts.push(edgeText(focusEdge));
    selection.textContent = parts.join(' · ');
  }
  /** Selects a block (and a row of it, and an edge of it) and keeps it in
   * view. A pick tells onSelect, or onReveal when `reveal`; a `silent`
   * selection is the host's own and tells neither. */
  function select(block, row = -1, {reveal = false, silent = false, edge = -1} = {}) {
    if (!layout || block < 0 || block >= graph.count) return;
    selectedBlock = block; selectedRow = row; focusEdge = edge;
    describe();
    const x = layout.x[block], y = layout.y[block], w = layout.w[block], h = layout.h[block];
    const rowY = row >= 0 ? y + m.headerH + m.padY + shownOfRow(block, row) * m.rowH : y;
    if (!visible(x, y, w, h) || x < view.x || x + w > view.x + cssW / view.z || rowY < view.y || Math.min(y + h, rowY + m.rowH * 2) > view.y + cssH / view.z) centerOn(block, row);
    requestDraw();
    if (silent) return;
    if (reveal) options.onReveal?.(graph.offsets[block], block, graph);
    else options.onSelect?.(graph.offsets[block], block, graph);
  }
  const blockAt = (gx, gy) => {
    for (let block = 0; block < graph.count; block += 1) if (gx >= layout.x[block] && gx <= layout.x[block] + layout.w[block] && gy >= layout.y[block] && gy <= layout.y[block] + layout.h[block]) return block;
    return -1;
  };
  /** The edge drawn nearest (gx, gy), within `reach` graph units. */
  function edgeAt(gx, gy, reach) {
    let best = -1, nearest = reach;
    const box = layout.box, pts = layout.points;
    for (let edge = 0; edge < graph.from.length; edge += 1) {
      if (gx < box[edge * 4] - reach || gx > box[edge * 4 + 2] + reach || gy < box[edge * 4 + 1] - reach || gy > box[edge * 4 + 3] + reach) continue;
      for (let i = layout.pointStart[edge]; i + 1 < layout.pointStart[edge + 1]; i += 1) {
        const distance = blockGraphSegmentDistance(gx, gy, pts[i * 2], pts[i * 2 + 1], pts[i * 2 + 2], pts[i * 2 + 3]);
        if (distance < nearest) { nearest = distance; best = edge; }
      }
    }
    return best;
  }
  /** A click on an edge goes to its far end: the target when the click was
   * nearer the source, else the source. A stub's chip goes to the block the
   * stub reaches; an unresolved edge has only its source. */
  function followClick(edge, gx, gy, chip = false) {
    const from = graph.from[edge], to = graph.to[edge];
    if (to < 0) { select(from, -1, {reveal: true, edge}); return; }
    const start = layout.pointStart[edge], end = layout.pointStart[edge + 1] - 1, pts = layout.points;
    const nearSource = Math.hypot(gx - pts[start * 2], gy - pts[start * 2 + 1]) <= Math.hypot(gx - pts[end * 2], gy - pts[end * 2 + 1]);
    select(chip && isStub(edge) ? to : nearSource ? to : from, -1, {reveal: true, edge});
  }
  const pointer = {down: false, x: 0, y: 0, moved: false};
  canvas.addEventListener('pointerdown', event => { pointer.down = true; pointer.x = event.clientX; pointer.y = event.clientY; pointer.moved = false; canvas.setPointerCapture?.(event.pointerId); canvas.focus({preventScroll: true}); });
  canvas.addEventListener('pointermove', event => {
    if (!pointer.down || !layout) return;
    if (Math.abs(event.clientX - pointer.x) + Math.abs(event.clientY - pointer.y) > 2) pointer.moved = true;
    view.x -= (event.clientX - pointer.x) / view.z; view.y -= (event.clientY - pointer.y) / view.z; pointer.x = event.clientX; pointer.y = event.clientY; fitted = false; requestDraw();
  });
  canvas.addEventListener('pointerup', event => {
    if (!pointer.down) return;
    pointer.down = false;
    if (pointer.moved || !layout) return;
    const rect = canvas.getBoundingClientRect(), gx = view.x + (event.clientX - rect.left) / view.z, gy = view.y + (event.clientY - rect.top) / view.z;
    const chip = chips.find(item => gx >= item.x && gx <= item.x + item.w && gy >= item.y && gy <= item.y + item.h);
    if (chip) { followClick(chip.edge, gx, gy, true); return; }
    const block = blockAt(gx, gy);
    if (block >= 0) {
      const local = gy - layout.y[block] - m.headerH - m.padY;
      const shown = local >= 0 && shownRows(block) ? Math.min(shownRows(block) - 1, Math.floor(local / m.rowH)) : -1;
      select(block, shown >= 0 && graph.rowCount[block] ? rowOfShown(block, shown) : -1, {reveal: true});
      return;
    }
    const edge = edgeAt(gx, gy, 5 / view.z);
    if (edge >= 0) { followClick(edge, gx, gy); return; }
    selectedBlock = -1; selectedRow = -1; focusEdge = -1; selection.textContent = ''; requestDraw();
  });
  canvas.addEventListener('wheel', event => {
    if (!layout) return;
    event.preventDefault();
    if (event.ctrlKey || event.metaKey) { const rect = canvas.getBoundingClientRect(); zoomAt(Math.exp(-event.deltaY * 0.01), event.clientX - rect.left, event.clientY - rect.top); }
    else { view.x += event.deltaX / view.z; view.y += event.deltaY / view.z; fitted = false; requestDraw(); }
  }, {passive: false});
  function move(dx, dy) {
    if (selectedBlock < 0) return select(Math.max(0, graph.roots?.[0] ?? 0));
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
  /** The selected block's edges in the order Alt+Left and Alt+Right step:
   * out by where they leave, then in by where they arrive. */
  function edgesOfSelected() {
    const block = selectedBlock, list = [], pts = layout.points;
    const x = (edge, at) => pts[(at === 'start' ? layout.pointStart[edge] : layout.pointStart[edge + 1] - 1) * 2];
    const out = Array.from(outs.list.subarray(outs.start[block], outs.start[block + 1])).sort((a, b) => x(a, 'start') - x(b, 'start') || a - b);
    const into = Array.from(ins.list.subarray(ins.start[block], ins.start[block + 1])).filter(edge => graph.from[edge] !== block).sort((a, b) => x(a, 'end') - x(b, 'end') || a - b);
    list.push(...out, ...into);
    return list;
  }
  /** Alt+Arrow: Left and Right pick an edge of the selected block, Down
   * follows an edge out of it to its target and Up one into it to its
   * source. The edge followed stays picked, so the opposite key returns. */
  function edgeKey(key) {
    if (selectedBlock < 0) { select(Math.max(0, graph.roots?.[0] ?? 0)); return; }
    const edges = edgesOfSelected();
    if (!edges.length) return;
    if (key === 'ArrowLeft' || key === 'ArrowRight') {
      const at = edges.indexOf(focusEdge), next = at < 0 ? (key === 'ArrowRight' ? 0 : edges.length - 1) : (at + (key === 'ArrowRight' ? 1 : -1) + edges.length) % edges.length;
      focusEdge = edges[next]; describe(); requestDraw();
      return;
    }
    const out = key === 'ArrowDown';
    const fits = edge => (out ? graph.from[edge] === selectedBlock && graph.to[edge] >= 0 : graph.to[edge] === selectedBlock);
    const edge = focusEdge >= 0 && fits(focusEdge) ? focusEdge : edges.find(fits);
    if (edge === undefined) return;
    select(out ? graph.to[edge] : graph.from[edge], -1, {edge});
  }
  canvas.addEventListener('keydown', event => {
    if (event.isComposing || event.ctrlKey || event.metaKey || !layout) return;
    const key = event.key;
    if (event.altKey) {
      if (!key.startsWith('Arrow')) return;
      event.preventDefault(); edgeKey(key);
      return;
    }
    const panStep = 96 / view.z;
    let handled = true;
    if (event.shiftKey && key.startsWith('Arrow')) { view.x += key === 'ArrowLeft' ? -panStep : key === 'ArrowRight' ? panStep : 0; view.y += key === 'ArrowUp' ? -panStep : key === 'ArrowDown' ? panStep : 0; fitted = false; requestDraw(); }
    else if (key === 'ArrowDown') move(0, 1); else if (key === 'ArrowUp') move(0, -1); else if (key === 'ArrowLeft') move(-1, 0); else if (key === 'ArrowRight') move(1, 0);
    else if (key === '+' || key === '=') zoomAt(1.25); else if (key === '-' || key === '_') zoomAt(0.8); else if (key === '0') fit();
    else if (key === 'Home') { const entry = Math.max(0, graph.roots?.[0] ?? 0); select(entry); centerOn(entry); }
    else if (key === ']' || key === '[') { const at = selectedBlock < 0 ? -1 : rank[selectedBlock]; select(order[Math.max(0, Math.min(graph.count - 1, at + (key === ']' ? 1 : -1)))]); }
    else if (key === 'Enter' && selectedBlock >= 0) select(selectedBlock, selectedRow, {reveal: true, edge: focusEdge});
    else handled = false;
    if (handled) event.preventDefault();
  });
  canvas.addEventListener('focus', () => { if (layout && selectedBlock < 0 && canvas.matches?.(':focus-visible')) select(Math.max(0, graph.roots?.[0] ?? 0)); });
  minimap.addEventListener('pointerdown', event => {
    if (!layout) return;
    const rect = minimap.getBoundingClientRect(), scale = Math.min(minimap.width / layout.width, minimap.height / layout.height);
    const ox = (minimap.width - layout.width * scale) / 2, oy = (minimap.height - layout.height * scale) / 2;
    view.x = ((event.clientX - rect.left) * (minimap.width / rect.width) - ox) / scale - cssW / view.z / 2;
    view.y = ((event.clientY - rect.top) * (minimap.height / rect.height) - oy) / scale - cssH / view.z / 2;
    fitted = false; requestDraw();
  });

  /** The row holding character `at` of the rows text. */
  function rowOfChar(at) {
    let low = 0, high = starts.length - 2;
    while (low < high) { const mid = (low + high + 1) >> 1; if (starts[mid] <= at) low = mid; else high = mid - 1; }
    return low;
  }
  /** Marks every row holding `query`, a case-insensitive literal, as Find
   * in the text view does, and every block holding such a row. */
  function runFind(query) {
    find = null; miniDirty = true;
    if (!query || !graph) { if (query) find = {query, needle: query.toLowerCase(), rowHit: new Uint8Array(0), hit: new Uint8Array(0), blocks: new Int32Array(0), rows: 0, current: -1, pending: true}; return; }
    const needle = query.toLowerCase(), total = starts.length - 1, rowHit = new Uint8Array(total), rows = graph.rows;
    let matched = 0;
    lowerRows ??= rows.toLowerCase();
    if (lowerRows.length === rows.length) {
      for (let at = lowerRows.indexOf(needle); at >= 0;) {
        const row = rowOfChar(at);
        if (at + needle.length <= starts[row + 1] - 1 && !rowHit[row]) { rowHit[row] = 1; matched += 1; }
        at = lowerRows.indexOf(needle, starts[row + 1]);
      }
    } else {
      // Lowercasing changed the text's length: match row by row instead.
      for (let row = 0; row < total; row += 1) if (rowText(row).toLowerCase().includes(needle)) { rowHit[row] = 1; matched += 1; }
    }
    const hit = new Uint8Array(graph.count), blocks = [];
    for (const block of order) {
      for (let row = graph.firstRow[block], end = row + graph.rowCount[block]; row < end; row += 1) if (rowHit[row]) { hit[block] = 1; break; }
      if (hit[block]) blocks.push(block);
    }
    find = {query, needle, rowHit, hit, blocks: Int32Array.from(blocks), rows: matched, current: -1};
  }
  function findStatus() {
    if (!find) return '';
    if (find.pending) return 'Find runs once the graph is drawn.';
    if (!find.blocks.length) return `No row matches in ${blockGraphCount(graph.count, 'block')}.`;
    const at = find.current >= 0 ? `${(find.current + 1).toLocaleString()} of ` : '';
    return `${at}${blockGraphCount(find.blocks.length, 'block')} · ${blockGraphCount(find.rows, 'row')} match`;
  }
  function renderFind() { findCue.textContent = find ? `Find: ${findStatus()}` : ''; findCue.hidden = !find; }
  /** Shows match `index`: its block selected, centered on its first matched row. */
  function showMatch(index) {
    find.current = index;
    const block = find.blocks[index];
    let row = graph.firstRow[block];
    for (let end = row + graph.rowCount[block]; row < end && !find.rowHit[row]; row += 1);
    select(block, row, {silent: true});
  }
  /** Find from the host: a new `query` shows the first matched block at or
   * after the selection; the same one moves `direction` blocks, wrapping.
   * Returns the status line. */
  function search(query, direction = 0) {
    if (query !== (find?.query ?? '')) {
      runFind(query);
      if (find?.blocks.length) {
        const from = selectedBlock >= 0 ? rank[selectedBlock] : 0;
        let index = find.blocks.findIndex(block => rank[block] >= from);
        if (index < 0) index = 0;
        showMatch(index);
      }
    } else if (find?.blocks.length && direction) showMatch((Math.max(0, find.current) + (find.current < 0 && direction > 0 ? 0 : direction) + find.blocks.length) % find.blocks.length);
    renderFind(); miniDirty = true; requestDraw();
    const status = findStatus();
    return status;
  }

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
      current = graph = starts = layout = null; outs = ins = order = rank = byFirstRow = stubSlot = lowerRows = find = null; miniImage = null; selectedBlock = -1; focusEdge = -1;
      triskelJob = null; stopWait(); engineRun.textContent = ''; engineRun.hidden = true; renderFind();
      canvas.width = 0; canvas.height = 0; minimap.width = 300; minimap.height = 220;
      setState('empty', '');
    },
    measurements: () => ({...m}), setResult, setState, search,
    /** The host's selection: it never reports back through onSelect. */
    select: (block, row = -1) => select(block, row, {silent: true}),
    focus: () => canvas.focus(), hasGraph: () => Boolean(layout), tools,
    /** A new title is another graph: the drawn one, and any Triskel run for it, are dropped. */
    setTitle(text) {
      if (triskelJob) { options.runner?.cancel(); triskelJob = null; stopWait(); engineRun.textContent = ''; engineRun.hidden = true; }
      current = graph = starts = layout = null; selectedBlock = selectedRow = focusEdge = -1;
      if (find) { find = {...find, pending: true, blocks: new Int32Array(0), current: -1}; renderFind(); }
      title.textContent = text; stats.textContent = ''; stats.title = ''; evidence.textContent = ''; selection.textContent = '';
      requestDraw();
    },
    setAnalystName(name) { analyst.textContent = name ?? ''; analyst.hidden = !name; analyst.title = name ? `${name} (researcher name)` : ''; }
  };
}

/** Triskel lays out when this shell's backend serves the layout route. */
const blockGraphEngine = () => /^https?:$/.test(globalThis.location?.protocol ?? '') ? 'triskel' : 'layered';

/**
 * Runs layout jobs one at a time in a worker that answers {id, ok, result}
 * or {id, ok: false, error, name}, and may first send {id, progress}. A new
 * job cancels the one running; the worker stays between jobs and is
 * terminated only to cancel one. `skip` stops Triskel for the running job,
 * which then answers without it. `script` is the worker; `local`, when
 * given, runs a job on this thread where no worker starts, as local(message,
 * {signal, progress}). The flow graph uses it with its own worker and
 * fallback. A worker that stops before it answers rejects with a
 * `transient` error: trying again can succeed.
 */
function createBlockGraphRunner({script = 'block_graph_layout.js', local = null} = {}) {
  let worker = null, serial = 0, job = null;
  function finish(id, ok, value) {
    if (job?.id !== id) return;
    const {resolve, reject} = job;
    job = null;
    if (ok) resolve(value); else reject(value);
  }
  function runLocal(id, message) {
    const controller = new AbortController();
    if (job?.id === id) job.controller = controller;
    const progress = stage => { if (job?.id === id) job.onProgress?.(stage); };
    local(message, {signal: controller.signal, progress}).then(result => finish(id, true, result), error => finish(id, false, error));
  }
  function start() {
    try { worker = new Worker(script); } catch { worker = null; return false; }
    worker.onmessage = event => {
      const {id, progress} = event.data;
      if (progress) { if (job?.id === id) job.onProgress?.(progress); return; }
      finish(id, event.data.ok, event.data.ok ? event.data.result : Object.assign(Error(event.data.error), {name: event.data.name || 'Error'}));
    };
    worker.onerror = event => {
      event.preventDefault?.();
      worker?.terminate();
      worker = null;
      // A worker that cannot run leaves its job to this thread when it can.
      if (job && local) runLocal(job.id, job.message);
      else if (job) finish(job.id, false, Object.assign(Error(event.message || 'The layout worker stopped before it answered.'), {transient: true}));
    };
    return true;
  }
  function cancel() {
    worker?.terminate();
    worker = null;
    const cancelled = job;
    job = null;
    cancelled?.controller?.abort();
    cancelled?.reject(new DOMException('Cancelled', 'AbortError'));
  }
  return {
    run(message, transfer = [], {onProgress = null} = {}) {
      if (job) cancel();
      const id = ++serial;
      return new Promise((resolve, reject) => {
        job = {id, message: local ? message : null, resolve, reject, onProgress, controller: null};
        if (worker || start()) worker.postMessage({...message, id}, transfer);
        else if (local) runLocal(id, message);
        else finish(id, false, Error('The layout worker could not start.'));
      });
    },
    skip() {
      if (job?.controller) job.controller.abort();
      else if (job && worker) worker.postMessage({cancel: job.id});
    },
    cancel
  };
}

/* Sources view mode for one captured WASM artifact. */
function createSourceGraphPanel({host, editor, button, closeOn, revealOffset, findQuery = null, onFind = null}) {
  const runner = createBlockGraphRunner();
  const view = createBlockGraphView(host, {
    runner, onFind,
    // A Triskel layout asked for is cached beside the region layout.
    onLayout: result => { if (functionIndex !== null) remember(`${key()}:${functionIndex}`, result); },
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
  host.hidden = true;
  let source = null, isOpen = false, functions = null, names = new Map(), functionIndex = null, generation = 0, abort = null, indexStatus = 'idle', screenVisible = true;
  /* A function another view asked for, drawn once the index lists it. */
  let requested = null;
  const key = () => `${source?.artifact_id}:${source?.sha256}`;
  const cache = new Map(); let cacheBytes = 0;
  const layoutBytes = layout => (layout ? layout.x.byteLength * 4 + layout.points.byteLength + layout.pointStart.byteLength + layout.box.byteLength : 0);
  const entryBytes = result => {
    const {graph, starts, layout, triskel} = result;
    return graph.offsets.byteLength * 7 + graph.from.byteLength * 3 + graph.rows.length + starts.byteLength + layoutBytes(layout) + layoutBytes(triskel);
  };
  const remember = (cacheKey, result) => {
    const old = cache.get(cacheKey);
    if (old) { cacheBytes -= old.bytes; cache.delete(cacheKey); }
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
      const wanted = requested !== null && functions.index.includes(requested) ? requested : largest;
      requested = null;
      loadFunction(wanted);
    } catch (error) {
      if (current() && error.name !== 'AbortError') {
        indexStatus = 'error';
        const failure = blockGraphFailure(error);
        view.setState('error', failure.message, failure.retry);
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
      if (current() && error.name !== 'AbortError') { const failure = blockGraphFailure(error); view.setState('error', failure.message, failure.retry); }
    }
  }
  function applyResult(result) { view.setResult(result); renderTools(); showAnalystName(); }
  function open() {
    isOpen = true; host.hidden = false; editor.setAttribute('data-graph', 'true'); button.setAttribute('aria-pressed', 'true'); if (!linearChoice && innerHeight < 600) { editor.setAttribute('data-graph-linear-hidden', ''); }
    view.activate();
    const query = findQuery?.();
    if (query) view.search(query);
    if (functions) { if (functionIndex !== null) loadFunction(functionIndex); else view.setState('empty', 'Select a function.'); } else loadIndex();
  }
  function close() { isOpen = false; showAnalystName(); host.hidden = true; editor.removeAttribute('data-graph'); button.setAttribute('aria-pressed', 'false'); closeMenu(); view.release(); release(); }
  const toggle = () => { if (isOpen) close(); else if (isWasmSource(source)) open(); };
  button.addEventListener('click', toggle);
  for (const other of [closeOn].flat()) other?.addEventListener('click', () => { if (isOpen) close(); });
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
    /** Opens the graph on one function of the selected module. */
    openFunction(index) {
      if (!isWasmSource(source) || !Number.isSafeInteger(index)) return false;
      if (isOpen && functions) { loadFunction(index); return true; }
      requested = index;
      if (!isOpen) open();
      return true;
    },
    isOpen: () => isOpen,
    /** Find in the drawn function's rows (see the view's search); its status line. */
    find: (query, direction = 0) => (isOpen ? view.search(query, direction) : ''),
    /** The function the graph last showed, for a view that follows it. */
    functionIndex: () => functionIndex
  };
}

/* Static bytecode view mode. Declared and Observed are separate drawings that
 * share a renderer and never a node set, so they cannot merge into one CFG. */
function createVmBlockGraph({host, button, getReport, getObservedPath, onReveal}) {
  const runner = createBlockGraphRunner();
  const view = createBlockGraphView(host, {runner, onReveal: offset => onReveal?.(offset), onSelect: offset => onReveal?.(offset), retry: () => render(), titleOf: graph => graph.title,
    blockLabel: (graph, block) => graph.evidence === 'observed' ? `step ${graph.offsets[block]}` : `loc_${graph.offsets[block].toString(16)}`});
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
      await lay({type: 'observed', path}, owner);
    } else {
      const report = getReport();
      if (!report?.instructions.length) { runner.cancel(); view.setTitle('Static bytecode'); view.setState('empty', report ? 'No instructions decoded. See Inputs and limits.' : 'Analyze a bytecode image to draw its declared blocks.'); return; }
      await lay({type: 'vm', report}, owner);
    }
  }
  /** Builds and lays out the graph `message` names in the layout worker. */
  async function lay(message, owner) {
    view.setState('loading', 'Laying out the graph…');
    try {
      const result = await runner.run({...message, metrics: view.measurements()});
      if (owner === generation) view.setResult(result);
    } catch (error) { if (owner === generation && error.name !== 'AbortError') { const failure = blockGraphFailure(error); view.setState('error', failure.message, failure.retry); } }
  }
  function open() { isOpen = true; host.hidden = false; button.setAttribute('aria-pressed', 'true'); view.activate(); render(); }
  function close() { isOpen = false; generation += 1; host.hidden = true; button.setAttribute('aria-pressed', 'false'); runner.cancel(); view.release(); }
  return {toggle: () => (isOpen ? close() : open()), close, refresh: () => render()};
}

// The offline check reads the edge kinds and how failures are worded.
if (typeof module === 'object' && module?.exports) module.exports = {BLOCK_GRAPH_KIND, blockGraphFailure};
