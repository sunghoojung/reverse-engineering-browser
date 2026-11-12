/* Flow workspace: the Flow screen's four linked panes. Graph (the session flow
 * graph), CFG (one Wasm function's basic blocks), Lineage (the selected
 * request's recorded predecessors) and Timeline (tracked calls in record
 * order) share one selection and one trail. Every pane keeps its own zoom and
 * scroll; changing pane or layout never changes the selection. Layout widths
 * come from CSS container queries in flow_workspace.css; this file reads the
 * result and decides which panes are shown. Nothing here reads captured
 * content beyond what the panes already show. */
const FLOW_PANES = ['graph', 'cfg', 'lineage', 'timeline'];
const FLOW_PANE_NAMES = {graph: 'Graph', cfg: 'CFG', lineage: 'Lineage', timeline: 'Timeline'};
const FLOW_WORKSPACE_STORAGE = 'origin-trace.flow-workspace.v1';
const FLOW_WORKSPACE_LIMITS = Object.freeze({history: 64, sessions: 16, related: 8, relatedSamples: 32});
/* Pane sizes in CSS pixels: CFG and Lineage widths, the Timeline dock height. */
const FLOW_SIZE_BOUNDS = Object.freeze({cfg: [280, 1400], lineage: [280, 640], timeline: [120, 720]});
const FLOW_SIZE_DEFAULTS = Object.freeze({cfg: 460, lineage: 340, timeline: 280});
const FLOW_GRAPH_MIN = 320;

const flowIsObject = value => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
const flowHexOffset = value => `+0x${Number(value).toString(16)}`;

/** Saved pane sizes and toggles per evidence session; a bounded local preference. */
function flowWorkspacePrefs(storage) {
  try {
    const value = JSON.parse(storage?.getItem?.(FLOW_WORKSPACE_STORAGE) ?? 'null');
    if (!flowIsObject(value) || value.version !== 1 || !flowIsObject(value.sessions)) return {version: 1, sessions: {}, last: null};
    return {version: 1, sessions: value.sessions, last: flowIsObject(value.last) ? value.last : null};
  } catch { return {version: 1, sessions: {}, last: null}; }
}
function flowWorkspaceSavePrefs(storage, prefs) {
  try { storage?.setItem?.(FLOW_WORKSPACE_STORAGE, JSON.stringify(prefs)); } catch { /* Preferences are optional, including in private native sessions. */ }
}
/** Sizes from a stored entry, each within its bound, else the default. */
function flowWorkspaceSizes(entry) {
  const sizes = {...FLOW_SIZE_DEFAULTS};
  for (const [name, [low, high]] of Object.entries(FLOW_SIZE_BOUNDS)) {
    const value = entry?.sizes?.[name];
    if (typeof value === 'number' && Number.isFinite(value) && value >= low && value <= high) sizes[name] = Math.round(value);
  }
  return sizes;
}
function flowWorkspacePanes(entry) {
  const panes = {cfg: false, lineage: true, timeline: true};
  for (const name of Object.keys(panes)) if (typeof entry?.panes?.[name] === 'boolean') panes[name] = entry.panes[name];
  return panes;
}

/** The block of a decoded Wasm graph that holds a module byte offset, or -1. */
function flowBlockAt(graph, offset) {
  if (!graph || !Number.isFinite(offset)) return -1;
  for (let block = 0; block < graph.count; block += 1) if (graph.offsets[block] <= offset && offset < graph.ends[block]) return block;
  return -1;
}
/** The absolute row of that block whose instruction starts at the offset, or -1. */
function flowRowAt(graph, starts, block, offset) {
  if (block < 0 || !graph?.rows || !starts) return -1;
  for (let row = graph.firstRow[block]; row < graph.firstRow[block] + graph.rowCount[block]; row += 1) {
    const text = graph.rows.slice(starts[row], starts[row + 1] - 1);
    if (Number.parseInt(text.slice(0, text.indexOf(' ')), 16) === offset) return row;
  }
  return -1;
}

/** Trail crumbs, outermost first. Each names the pane that explains it. */
function flowTrailCrumbs(selection) {
  const crumbs = [];
  if (selection.request) crumbs.push({kind: 'request', pane: 'lineage', label: selection.request.label});
  if (selection.call) crumbs.push({kind: 'call', pane: 'timeline', label: selection.call.label});
  if (selection.fn) crumbs.push({kind: 'fn', pane: selection.fn.function_index !== null && selection.fn.function_index !== undefined && selection.fn.artifact_id ? 'cfg' : 'graph', label: selection.fn.label});
  if (selection.site) crumbs.push({kind: 'site', pane: 'cfg', label: selection.site.label});
  if (selection.sample) crumbs.push({kind: 'sample', pane: 'timeline', label: selection.sample.label});
  return crumbs;
}
const flowSelectionKey = selection => JSON.stringify([selection.request?.id ?? null, selection.call?.key ?? null, selection.fn?.key ?? null, selection.site?.offset ?? null, selection.sample?.key ?? null, selection.step ?? null, selection.graphKey ?? null]);

/** The workspace's own chords, which the flow graph canvas leaves to it
 * (its hostKeys option): Shift+C, Shift+L and Shift+T toggle panes,
 * Shift+Backspace walks the trail forward, Z toggles focus mode and 1 to 4
 * switch panes, none with Command, Control or Option. */
function flowWorkspaceKey(event) {
  if (event.metaKey || event.ctrlKey || event.altKey) return false;
  const key = event.key, code = event.code ?? '';
  if (event.shiftKey) return ['KeyC', 'KeyL', 'KeyT'].includes(code) || ['C', 'L', 'T', 'Backspace'].includes(key);
  return code === 'KeyZ' || key === 'z' || key === 'Z' || /^Digit[1-4]$/.test(code) || /^[1-4]$/.test(key);
}

/* A lineage link's colour says what it is, from the step's relation; its
 * line style says how sure it is, from the confidence, which reads as shared
 * identifiers when unknown, as traceLinkClass does. */
const FLOW_LINK_KINDS = {parent_event: 'call', trace_target: 'request', request_initiator: 'request', request_lifecycle: 'request',
  temporal_adjacency: 'cross', issued_during_invocation: 'tracked', invocation_settlement: 'tracked', invocation_value_flow: 'data', artifact_request: 'plain'};
const FLOW_LINK_LINES = {observed: 'observed', correlated: 'correlated', time_adjacent: 'adjacent'};
/** The `data-kind` and `data-line` of a lineage link's sample; a gap is a cut. */
function flowLinkKind(model) {
  if (!model?.step) return {line: 'cut', kind: 'plain'};
  return {line: FLOW_LINK_LINES[model.step.confidence] ?? 'correlated', kind: FLOW_LINK_KINDS[model.step.relation] ?? 'plain'};
}

/**
 * Builds the workspace on `root` (the Flow screen) and its Graph pane, the
 * flow graph panel; `openFrame(node)` and `graphAvailable()` are that
 * panel's `open` and `available`. The app's callbacks: `getRequest()` the
 * request it shows, `selectRequest(id)`, `findRendererRequest(process,
 * request)` the captured row a renderer request names, `selectTraceRow(model)`
 * and `focusTraceRow()` in Lineage, and `openSource({artifact_id, offset})`.
 * Every setter the workspace calls, on the app, a pane or the graph, is
 * silent: only the researcher's own picks come back as callbacks.
 */
function createFlowWorkspace({root, openFrame, graphAvailable, storage = null, getRequest, selectRequest, findRendererRequest, selectTraceRow, focusTraceRow, openSource}) {
  const doc = document;
  const $ = selector => root.querySelector(selector);
  const make = (tag, className = '', text = '') => { const element = doc.createElement(tag); if (className) element.className = className; if (text) element.textContent = text; return element; };
  const button = (className, text, label) => { const element = make('button', className, text); element.type = 'button'; if (label) element.setAttribute('aria-label', label); return element; };
  const graph = createFlowGraphPanel({
    host: $('#flow-graph-host'), open: openFrame, available: graphAvailable,
    onSelect: (info, {cause}) => graphPicked(info, {cause}),
    onFollow: info => graphPicked(info, {followed: true}),
    hostKeys: flowWorkspaceKey
  });

  const body = $('#flow-body');
  const panes = Object.fromEntries(FLOW_PANES.map(name => [name, $(`#flow-pane-${name}`)]));
  const tabs = $('#flow-tabs'), trail = $('#flow-trail'), related = $('#flow-related');
  const backButton = $('#flow-back'), forwardButton = $('#flow-forward'), splitButton = $('#flow-split');
  const toggles = {cfg: $('#flow-toggle-cfg'), lineage: $('#flow-toggle-lineage'), timeline: $('#flow-toggle-timeline')};
  const togglesGroup = $('#flow-pane-toggles');
  const sideTabs = {lineage: $('#flow-tab-lineage-list'), details: $('#flow-tab-lineage-details'), cfg: $('#flow-tab-lineage-cfg')};
  const lineagePanels = {lineage: $('#flow-lineage-list'), details: $('#flow-lineage-details')};
  const cfgHost = $('#flow-cfg-host'), cfgEmpty = $('#flow-cfg-empty'), cfgSamples = $('#flow-cfg-samples'), cfgMeta = $('#flow-cfg-meta'), cfgHead = $('#flow-cfg-head');
  const graphMeta = $('#flow-graph-meta'), requestMeta = $('#flow-request-meta'), requestTag = $('#flow-request-tag');
  const lineageSelected = $('#flow-lineage-selected');
  const timelineRoot = $('#flow-timeline'), timelineMeta = $('#flow-timeline-meta'), timelineSlot = $('#flow-timeline-process'), timelineRefresh = $('#flow-timeline-refresh'), timelineOpenButton = $('#flow-timeline-open');
  const status = $('#flow-status');

  // Layout state. `split` is what the split shows; focus mode and the narrow
  // single-pane layout leave it untouched, so returning restores it exactly.
  let session = null, visible = false, layout = 'wide', mode = 'split', focusPane = 'graph', active = 'graph', singlePane = null;
  let split = {cfg: false, lineage: true, timeline: true}, cfgUserHidden = false, sideTab = 'lineage', lineageTab = 'lineage', timelineOpen = false;
  // The pane that was active when focus mode opened, for Z to return to.
  let returnPane = 'graph';
  let sizes = {...FLOW_SIZE_DEFAULTS}, prefs = flowWorkspacePrefs(storage);
  // Selection, trail and history.
  let selection = {request: null, call: null, fn: null, site: null, sample: null, step: null, graphKey: null};
  let history = [], cursor = -1, graphInfo = null, lineageModels = [];
  // Above zero while the workspace makes a change of its own: a pick that
  // changes several things, which is one trail entry, or a trail entry being
  // restored. A request revision the app makes meanwhile is that change's.
  let changing = 0;
  // The app's request revision this workspace has accounted for.
  let requestRevision = null;
  // Short feedback for a key that did nothing visible; it clears itself.
  let flashTimer = 0;
  const flash = text => {
    status.textContent = text; status.hidden = false;
    clearTimeout(flashTimer);
    flashTimer = setTimeout(() => { status.textContent = ''; status.hidden = true; }, 4000);
  };

  // CFG pane: one Wasm function's basic blocks, read and drawn as Sources
  // does. Each function's read is idle (not in `reads`), loading, ready or
  // failed. A read starts only while the pane is shown, the read of a
  // function already loading is reused, and the last few results are kept,
  // so returning to a function needs no read. A pick from the graph waits a
  // moment first, so moving across cards reads only the card it stops on.
  const cfg = {fn: null, mark: null, reads: new Map(), shown: null, active: false, abort: null, timer: 0, view: null, runner: null, names: new Map()};
  const cfgKey = fn => `${fn.artifact_id}:${fn.function_index}`;
  function cfgView() {
    if (cfg.view) return cfg.view;
    cfg.view = createBlockGraphView(cfgHost, {
      onSelect: (offset, block, graphDoc) => cfgPicked(offset, block, graphDoc),
      onReveal: (offset, block, graphDoc) => cfgPicked(offset, block, graphDoc),
      retry: () => { cfg.reads.delete(cfgKey(cfg.fn)); ensureCfg(); },
      titleOf: graphDoc => cfg.fn?.name || `func ${graphDoc.functionIndex}`,
      statsPrefix: graphDoc => (cfg.fn?.name ? `func ${graphDoc.functionIndex}` : '')
    });
    cfg.runner = createBlockGraphRunner();
    // The view's own head is the pane head: the identity mark, Sources and focus.
    const head = cfg.view.tools.parentElement;
    const mark = make('span', 'flow-pane-mark'); mark.setAttribute('aria-hidden', 'true'); head.prepend(mark); head.dataset.flowHead = 'cfg';
    const open = button('source-tool block-graph-tool flow-cfg-source', 'Sources', 'Open this function in Sources');
    open.title = 'Open the module in Sources at this function';
    open.addEventListener('click', () => { if (cfg.fn) openSource({artifact_id: cfg.fn.artifact_id, offset: cfgFirstByte()}); });
    cfg.view.tools.append(open, focusButton('cfg'));
    renderCfgChrome();
    return cfg.view;
  }
  /** The shown function's laid-out graph while the view draws it, else null. */
  function cfgDrawn() {
    const key = cfg.fn ? cfgKey(cfg.fn) : null;
    return key && cfg.shown === `${key}:ready` ? cfg.reads.get(key).result : null;
  }
  /** The function's first byte: its body's start in the module, which the
   * graph document names, else its lowest block start; null before a read. */
  function cfgFirstByte() {
    const graph = cfgDrawn()?.graph;
    if (!graph) return null;
    if (Number.isSafeInteger(graph.byteOffset)) return graph.byteOffset;
    let first = null;
    for (let block = 0; block < graph.count; block += 1) if (first === null || graph.offsets[block] < first) first = graph.offsets[block];
    return first;
  }
  function cfgPicked(offset, block, graphDoc) {
    const start = graphDoc?.offsets?.[block] ?? offset;
    const keepSample = selection.sample && selection.site && flowBlockAt(graphDoc, selection.site.offset) === block;
    setSelection({site: {offset: keepSample ? selection.site.offset : start, kind: keepSample ? selection.site.kind : 'block', label: keepSample ? selection.site.label : `loc_${Number(start).toString(16)}`},
      sample: keepSample ? selection.sample : null});
    if (!keepSample) graph.setMark(cfg.fn ? {artifact_id: cfg.fn.artifact_id, function_index: cfg.fn.function_index, offset: start} : null);
    renderCfgSamples();
  }
  /** Function names from the module's name section, read once per module as
   * Sources does; a module without names, or a failed read, names nothing. */
  const nameReads = new Map();
  function functionNames(artifactId) {
    if (!nameReads.has(artifactId)) {
      if (nameReads.size >= 8) nameReads.delete(nameReads.keys().next().value);
      nameReads.set(artifactId, readWasmFunctionIndex(artifactId).then(index => index.names, () => new Map()));
    }
    return nameReads.get(artifactId);
  }
  /** Names a Wasm function once its module's names are read; a read from an
   * earlier session names nothing. Resolves when the name is applied. */
  function nameCfgFunction(fn) {
    if (fn.name) return Promise.resolve();
    const names = functionNames(fn.artifact_id);
    return names.then(found => { if (nameReads.get(fn.artifact_id) === names) nameFunction(fn, found.get(fn.function_index)?.slice(0, 128)); });
  }
  function nameFunction(fn, name) {
    if (!name || cfg.names.get(cfgKey(fn)) === name) return;
    cfg.names.set(cfgKey(fn), name);
    if (cfg.fn?.key === fn.key) { cfg.fn = {...cfg.fn, name, label: name}; renderCfgChrome(); }
    // A name changes no selection key, so the trail is redrawn here.
    if (selection.fn?.key === fn.key) { selection = {...selection, fn: {...selection.fn, name, label: name}}; renderTrail(); renderTabs(); }
  }
  /** Shows a function in the CFG pane, marking the block that holds
   * `offset`. In the split the pane opens beside the graph when `open`,
   * unless the researcher hid it; `wait` delays the read for a graph pick. */
  function showCfg(fn, offset = null, {open = false, wait = false} = {}) {
    const opened = open && !cfgUserHidden && !split.cfg;
    if (opened) { split.cfg = true; savePrefs(); }
    // Only the shown function's read runs: another one in flight stops.
    if (!cfg.fn || cfgKey(cfg.fn) !== cfgKey(fn)) cancelCfgRead();
    cfg.fn = fn; cfg.mark = Number.isFinite(offset) ? offset : null;
    nameCfgFunction(fn);
    clearTimeout(cfg.timer);
    cfg.timer = wait && !cfgDrawn() ? setTimeout(() => { cfg.timer = 0; ensureCfg(); }, 150) : 0;
    renderCfgChrome(); renderCfgSamples(); renderTabs();
    if (cfgDrawn()) markCfg();
    if (opened) applyLayout(); else ensureCfg();
  }
  /** Draws the shown function while the pane is shown: a kept result, the
   * read in flight or its failure, else a new read. */
  function ensureCfg() {
    if (!cfg.fn || !visible || !paneVisible('cfg')) return;
    const key = cfgKey(cfg.fn), view = cfgView();
    if (!cfg.active) { view.activate(); cfg.active = true; }
    if (!cfg.reads.has(key) && !cfg.timer) readCfg(key, cfg.fn);
    // A pick still waiting reads as loading.
    const read = cfg.reads.get(key) ?? {status: 'loading'};
    if (cfg.shown === `${key}:${read.status}`) return;
    cfg.shown = `${key}:${read.status}`;
    if (read.status === 'ready') {
      cfg.reads.delete(key); cfg.reads.set(key, read);
      view.setResult(read.result);
      markCfg();
      return;
    }
    view.setTitle(cfg.fn.name || `func ${cfg.fn.function_index}`);
    if (read.status === 'error') view.setState('error', read.error, true);
    else view.setState('loading', 'Decoding basic blocks…');
  }
  async function readCfg(key, fn) {
    const read = {status: 'loading'}, abort = new AbortController();
    cfg.reads.set(key, read); cfg.abort = abort;
    try {
      const [result] = await Promise.all([loadWasmFunctionGraph({artifactId: fn.artifact_id, functionIndex: fn.function_index, view: cfg.view, runner: cfg.runner, signal: abort.signal}), nameCfgFunction(fn)]);
      Object.assign(read, {status: 'ready', result});
    } catch (error) {
      Object.assign(read, error?.name === 'AbortError' ? {status: 'aborted'} : {status: 'error', error: graphReadMessage(error)});
    } finally {
      if (cfg.abort === abort) cfg.abort = null;
    }
    // A read cancelled, or forgotten with its session, changes nothing.
    if (cfg.reads.get(key) !== read) return;
    if (read.status === 'aborted') { cfg.reads.delete(key); return; }
    // Keep the last four results and failures, the most recent last.
    const settled = [...cfg.reads.keys()].filter(item => cfg.reads.get(item).status !== 'loading');
    for (const old of settled.slice(0, -4)) cfg.reads.delete(old);
    ensureCfg();
  }
  /** Stops the read in flight and a pick still waiting; neither is kept. */
  function cancelCfgRead() {
    clearTimeout(cfg.timer); cfg.timer = 0;
    cfg.abort?.abort(); cfg.abort = null; cfg.runner?.cancel();
  }
  /** Marks the block (and row) that holds the shown mark, silently. */
  function markCfg() {
    const result = cfgDrawn();
    if (!result || cfg.mark === null) return;
    const block = flowBlockAt(result.graph, cfg.mark);
    if (block >= 0) cfg.view.select(block, flowRowAt(result.graph, result.starts, block, cfg.mark));
  }
  /** Leaves the view: the canvas and drawing resources go, the kept results
   * stay, so returning needs no read. */
  function releaseCfg() {
    cancelCfgRead();
    cfg.view?.release();
    cfg.active = false; cfg.shown = null;
  }
  /** A new session: nothing read in the old one is drawn or reused. */
  function forgetCfg() {
    releaseCfg();
    cfg.reads.clear(); cfg.names.clear(); nameReads.clear();
    cfg.fn = null; cfg.mark = null;
    renderCfgChrome();
  }
  function renderCfgChrome() {
    const hasFn = Boolean(cfg.fn);
    cfgEmpty.hidden = hasFn;
    cfgHost.hidden = !hasFn;
    cfgHead.dataset.hasView = String(hasFn && Boolean(cfg.view));
    cfgMeta.textContent = hasFn ? `${cfg.fn.name || `func ${cfg.fn.function_index}`} · func ${cfg.fn.function_index}` : 'no function';
  }
  /** The sampled sites of the CFG's function, and a stepper for the chosen sample. */
  function renderCfgSamples() {
    const sites = cfg.fn ? timeline.samplesFor(cfg.fn.artifact_id, cfg.fn.function_index) : [];
    const chosen = timeline.selection();
    cfgSamples.hidden = !sites.length;
    if (!sites.length) { cfgSamples.replaceChildren(); return; }
    const nodes = [];
    if (chosen?.type === 'sample' && chosen.sample.function_index === cfg.fn.function_index && chosen.sample.artifact_id === cfg.fn.artifact_id) {
      const sample = chosen.sample;
      const text = make('span', 'flow-cfg-sample-text');
      text.append(make('b', '', chosen.count ?? `sample ${sample.ordinal} of ${chosen.site.samples.length} read`),
        make('span', '', [chosen.track ? `call #${chosen.track.invocation}` : 'outside a tracked call', `seq ${sample.seq.toLocaleString('en-US')}`,
          sample.kind === 'br_table' ? `selector ${sample.selector ?? 'unknown'}` : `callee ${sample.resolution === 'resolved' ? `func ${sample.callee}` : sample.resolution ?? 'unknown'}`].join(' · ')));
      const keys = make('span', 'flow-keys'); keys.append(make('kbd', '', 'K'), make('kbd', '', 'J'), make('span', '', 'step samples'));
      const previous = button('secondary-button', 'Previous', 'Previous sample at this site'); previous.disabled = sample.ordinal <= 1;
      const next = button('secondary-button', 'Next', 'Next sample at this site'); next.disabled = sample.ordinal >= chosen.site.samples.length;
      previous.addEventListener('click', () => timeline.stepSample(-1));
      next.addEventListener('click', () => timeline.stepSample(1));
      nodes.push(text, keys, previous, next);
    } else {
      nodes.push(make('span', 'flow-cfg-sample-text', 'Sampled here:'));
      for (const site of sites.slice(0, 6)) {
        const jump = button('flow-chip', `${flowHexOffset(site.offset)} ${site.kind} ×${site.samples.length}`, `Pick the first ${site.kind} sample at ${flowHexOffset(site.offset)}`);
        jump.addEventListener('click', () => { const first = site.samples[0]; if (first) timeline.select(`sample:${first.key}`, {silent: false}); });
        nodes.push(jump);
      }
      if (sites.length > 6) nodes.push(make('span', 'flow-more', `${sites.length - 6} more sites`));
    }
    cfgSamples.replaceChildren(...nodes);
  }

  // Timeline pane.
  const timeline = createFlowTimeline({
    root: timelineRoot,
    describeRequest: findRendererRequest,
    onSelect: info => timelinePicked(info),
    onFollow: info => { timelinePicked(info); follow(); },
    onPartial: () => renderTabs()
  });
  timelineSlot.replaceWith(timeline.processSelect);
  timelineRefresh.addEventListener('click', () => timeline.refresh());
  timelineOpenButton.addEventListener('click', () => { timelineOpen = !timelineOpen; applyLayout(); if (timelineOpen) focusPaneContent('timeline'); });
  // Every pick keeps only the crumbs that are recorded relationships of the
  // new item: a sample keeps its call, function and site; a call or a request
  // chip keeps the call it names; a card keeps its function and row. The
  // request stays as the app selected it, and its lineage step with it.
  const noCrumbs = {call: null, fn: null, site: null, sample: null, graphKey: null};
  function timelinePicked(info) {
    if (!info) {
      // The sample's function and site go with it, unless a graph card holds them.
      setSelection({call: null, sample: null, ...(selection.graphKey ? {} : {fn: null, site: null})});
      graph.setMark(null); renderCfgSamples(); renderLineageSelected(); return;
    }
    const callCrumb = info.track ? {key: `call:${info.track.key}`, label: `call #${info.track.invocation}`} : null;
    if (info.type === 'sample') {
      const sample = info.sample;
      const fn = fnFor(sample.artifact_id, sample.function_index);
      // The selected graph card stays only when it is the sample's function.
      const sameCard = graphInfo?.key && graphInfo.key === selection.graphKey && String(graphInfo.artifact_id) === String(sample.artifact_id) && graphInfo.function_index === sample.function_index;
      setSelection({...noCrumbs, call: callCrumb, fn, site: {offset: sample.offset, kind: sample.kind, label: `${flowHexOffset(sample.offset)} ${sample.kind}`}, sample: {key: info.key, label: `sample ${sample.ordinal}`},
        graphKey: sameCard ? selection.graphKey : null});
      graph.setMark({artifact_id: sample.artifact_id, function_index: sample.function_index, offset: sample.offset});
      showCfg(fn, sample.offset, {open: true});
    } else if (info.type === 'call') {
      setSelection({...noCrumbs, call: callCrumb});
      graph.setMark(null);
    } else {
      // The chip's request is the request crumb now, in the same trail entry.
      const known = findRendererRequest(info.process, info.request.request);
      change(() => setSelection({...noCrumbs, call: callCrumb, ...(known ? requestPatch(showAppRequest(known.id), known.id) : {})}));
      graph.setMark(null);
      if (!known) flash('This request is not in the captured request list, so Lineage cannot open it.');
    }
    renderCfgSamples(); renderLineageSelected(); renderRelated();
  }
  /** The trail crumb of the request the app shows. */
  const requestCrumb = request => (request ? {id: request.id, label: request.label, renderer: request.renderer?.request ?? null} : null);
  /** Asks the app to show a request, inside a change of the workspace's own
   * so the revision it makes is not an app pick, and returns the crumb of
   * the request the app now shows. */
  function showAppRequest(id) {
    selectRequest(id);
    return requestCrumb(getRequest());
  }
  /** The selection patch for the request the app shows, when it is the one
   * asked for; a new request drops the old one's lineage step. */
  function requestPatch(shown, wanted) {
    if (shown?.id !== wanted) return {};
    return shown.id === selection.request?.id ? {request: shown} : {request: shown, step: null};
  }
  /** A function crumb for a Wasm function, named from the graph when it knows. */
  function fnFor(artifactId, functionIndex) {
    const named = graphInfo && String(graphInfo.artifact_id) === String(artifactId) && graphInfo.function_index === functionIndex ? graphInfo.name : null;
    const name = named || cfg.names.get(`${artifactId}:${functionIndex}`) || null;
    if (name) cfg.names.set(`${artifactId}:${functionIndex}`, name);
    return {key: `wasm:${artifactId}:${functionIndex}`, artifact_id: String(artifactId), function_index: functionIndex, name, label: name || `func ${functionIndex}`};
  }

  // Graph pane.
  /** What the graph selects, shown in the Related rail and the pane head. */
  function graphShown(info) {
    graphInfo = info ?? null;
    renderRelated(); renderTabs();
  }
  /** A setter's answer: the card it selected, else what the graph selects
   * now. A setter called before the graph is drawn answers null and is
   * reported with cause `host` once the graph lands. */
  const graphAnswer = info => info ?? graph.selection();
  /** A change of the graph's selection. Only the researcher's own (cause
   * `pick`) is a pick; what the graph selects for the host or puts back
   * (`host`, `replay`) is only shown. */
  function graphPicked(info, {followed = false, cause = 'pick'} = {}) {
    if (cause !== 'pick') { graphShown(info); return; }
    graphInfo = info ?? null;
    // A card replaces a picked sample, so the timeline lets go of it too.
    if (info && selection.sample) { timeline.clear(); graph.setMark(null); }
    // Clearing the card clears its own crumbs; a sample's stay.
    if (!info) { setSelection(selection.graphKey ? {graphKey: null, fn: null, site: null} : {graphKey: null}); renderRelated(); return; }
    const wasm = info.kind === 'wasm' && info.artifact_id && Number.isSafeInteger(info.function_index);
    if (wasm) {
      const fn = fnFor(info.artifact_id, info.function_index);
      const site = /^\+0x[0-9a-f]+$/i.test(info.row?.site ?? '') ? {offset: Number.parseInt(info.row.site.slice(3), 16), kind: info.row.op ?? 'site', label: `${info.row.site} ${info.row.op ?? ''}`.trim()} : null;
      setSelection({...noCrumbs, graphKey: info.key ?? null, fn, site});
      showCfg(fn, site?.offset ?? null, {open: true, wait: !followed});
      if (followed) reveal('cfg', {focus: true});
    } else {
      setSelection({...noCrumbs, graphKey: info.key ?? null, fn: info.key ? {key: info.key, artifact_id: null, function_index: null, name: info.name ?? null, label: info.name || info.kind || 'card'} : null});
      if (followed && info.request) reveal('lineage', {focus: true});
    }
    renderRelated();
  }

  // Lineage pane.
  function lineagePicked(model) {
    // The step, the card its request lights and its call are one pick and
    // one trail entry.
    change(() => {
      setSelection({step: model.key});
      const step = model.step;
      if (!step) return;
      // A renderer request record names the stack that made it; the
      // request's own browser records follow the selected request's stack.
      const own = getRequest();
      const rendererKey = step.operation === 'request_initiated' && step.request_id && step.request_id !== '0'
        ? {process: step.event.process_id, request: String(step.request_id)} : own?.renderer ?? null;
      if (rendererKey && step.category === 'network') graphPicked(graphAnswer(graph.highlightRequest(rendererKey)));
      // A tracked call's start or settle record selects that call's track.
      const tracked = timeline.callAt(`${step.event.process_id}:${step.event.sequence_number}`);
      // A step that names neither a card nor a call is a detail of the
      // request and leaves the trail as it is.
      if (!tracked) return;
      if (selection.sample) graph.setMark(null);
      timeline.select(tracked.key, {silent: true});
      setSelection({...noCrumbs, call: {key: tracked.key, label: tracked.label}});
    });
    renderLineageSelected(); renderRelated();
  }
  function setLineageTab(name, {focus = false} = {}) {
    lineageTab = name === 'details' ? 'details' : 'lineage';
    applyLayout();
    if (focus) (lineageTab === 'details' ? sideTabs.details : sideTabs.lineage).focus({focusVisible: true});
  }
  function renderLineageSelected() {
    const chosen = timeline.selection();
    if (chosen?.type !== 'sample') { lineageSelected.hidden = true; lineageSelected.replaceChildren(); return; }
    const {sample, site} = chosen;
    const heading = make('h3', '', 'Selected');
    heading.append(make('span', 'flow-lineage-selected-site', ` · func ${sample.function_index} ${flowHexOffset(sample.offset)} ${sample.kind}`));
    const line = make('p', 'flow-lineage-selected-line', [chosen.count ?? `sample ${sample.ordinal} of ${site.samples.length} read`, chosen.track ? `call #${chosen.track.invocation}` : 'outside a tracked call',
      sample.kind === 'br_table' ? `selector ${sample.selector ?? 'unknown'}` : `callee ${sample.resolution === 'resolved' ? `func ${sample.callee}` : sample.resolution ?? 'unknown'}`].join(' · '));
    const nodes = [heading, line];
    if (sample.kind === 'br_table' && site.histogram.size) nodes.push(selectorHistogram(site, sample.selector));
    lineageSelected.replaceChildren(...nodes);
    lineageSelected.hidden = false;
  }
  /** Selector counts at one br_table site, as bars; the chosen value is marked. */
  function selectorHistogram(site, chosen) {
    const entries = [...site.histogram.entries()].sort((a, b) => a[0] - b[0]);
    const top = Math.max(1, ...entries.map(([, count]) => count));
    const list = make('ol', 'flow-histogram');
    list.setAttribute('aria-label', `Selector counts at ${flowHexOffset(site.offset)}: ${entries.map(([value, count]) => `${value} ×${count}`).join(', ')}`);
    for (const [value, count] of entries.slice(0, 24)) {
      const item = make('li', value === chosen ? 'flow-histogram-on' : '');
      const bar = make('span', 'flow-histogram-bar'); bar.style.height = `${Math.max(3, Math.round(count / top * 44))}px`;
      item.append(make('span', 'flow-histogram-count', String(count)), bar, make('span', 'flow-histogram-value', String(value)));
      list.append(item);
    }
    if (entries.length > 24) list.append(make('li', 'flow-more', `+${entries.length - 24}`));
    return list;
  }

  // Selection and history.
  /** Every change is a trail entry in the pane the researcher is working in;
   * Back returns there. */
  function setSelection(patch, {record = true} = {}) {
    const before = flowSelectionKey(selection);
    selection = {...selection, ...patch};
    if (flowSelectionKey(selection) === before) return;
    renderTrail();
    if (record && !changing) pushHistory(active);
    renderTabs();
  }
  /** Runs one change of the workspace's own: a pick that changes several
   * things, recorded as one trail entry, or with `record: false` a restore. */
  function change(run, {record = true} = {}) {
    changing += 1;
    try { run(); } finally { changing -= 1; }
    if (record && !changing) pushHistory(active);
  }
  function snapshot(pane) { return {selection: {...selection}, pane, sample: timeline.selection()?.key ?? null}; }
  function pushHistory(pane) {
    const entry = snapshot(pane);
    const last = history[cursor];
    if (last && flowSelectionKey(last.selection) === flowSelectionKey(entry.selection) && last.pane === entry.pane) return;
    history = history.slice(0, cursor + 1);
    history.push(entry);
    if (history.length > FLOW_WORKSPACE_LIMITS.history) history.shift();
    cursor = history.length - 1;
    renderHistoryButtons();
  }
  function renderHistoryButtons() {
    backButton.disabled = cursor <= 0;
    forwardButton.disabled = cursor >= history.length - 1;
  }
  /** Restores one trail entry: its selection in every pane, then its pane. */
  function restore(entry) {
    change(() => {
      const target = entry.selection;
      // The app keeps its own request when the entry had none or its request
      // is no longer listed. It made no new revision, so its next render is
      // not a pick and Forward stays.
      const wanted = target.request?.id ?? null;
      const shown = (wanted ? showAppRequest(wanted) : requestCrumb(getRequest()))?.id ?? null;
      if (shown !== wanted) flash(!wanted ? 'This trail entry had no request; Lineage still shows the selected one.'
        : `This trail entry\u2019s request is no longer in the request list${shown === null ? '' : '; Lineage still shows the selected request'}.`);
      selection = {...target};
      const step = target.step && lineageModels.find(model => model.key === target.step);
      if (step) selectTraceRow(step);
      if (target.sample) timeline.select(target.sample.key);
      else if (target.call) timeline.select(target.call.key);
      else timeline.clear();
      if (target.fn?.function_index !== null && target.fn?.function_index !== undefined && target.fn.artifact_id) showCfg(target.fn, target.site?.offset ?? null);
      if (target.graphKey) graphShown(graphAnswer(graph.select(target.graphKey)));
      graph.setMark(target.sample && target.fn?.artifact_id ? {artifact_id: target.fn.artifact_id, function_index: target.fn.function_index, offset: target.site?.offset ?? null} : null);
      reveal(entry.pane, {focus: true, record: false});
    }, {record: false});
    renderTrail(); renderHistoryButtons(); renderCfgSamples(); renderLineageSelected(); renderRelated();
  }
  function back() { if (cursor <= 0) { flash('This is the start of the trail.'); return false; } cursor -= 1; restore(history[cursor]); return true; }
  function forward() { if (cursor >= history.length - 1) { flash('This is the end of the trail.'); return false; } cursor += 1; restore(history[cursor]); return true; }
  backButton.addEventListener('click', back);
  forwardButton.addEventListener('click', forward);

  function renderTrail() {
    const crumbs = flowTrailCrumbs(selection);
    if (!crumbs.length) { trail.replaceChildren(make('span', 'flow-trail-empty', 'Select a request, card or sample')); return; }
    const nodes = [];
    crumbs.forEach((crumb, index) => {
      const last = index === crumbs.length - 1;
      const item = button(`flow-crumb flow-crumb-${crumb.kind}`, crumb.label, `${crumb.label}: show it in ${FLOW_PANE_NAMES[crumb.pane]}`);
      item.title = `${crumb.label} · ${FLOW_PANE_NAMES[crumb.pane]}`;
      if (last) item.setAttribute('aria-current', 'true');
      item.addEventListener('click', () => jump(crumb));
      nodes.push(item);
      if (!last) { const separator = make('span', 'flow-crumb-separator', '›'); separator.setAttribute('aria-hidden', 'true'); nodes.push(separator); }
    });
    trail.replaceChildren(...nodes);
    // The most specific crumb stays in view when the trail scrolls.
    trail.scrollLeft = trail.scrollWidth;
  }
  /** A crumb or Related entry jumps to its item in its pane. */
  function jump(crumb) {
    if (crumb.kind === 'site' || (crumb.kind === 'fn' && crumb.pane === 'cfg')) { if (selection.fn) showCfg(selection.fn, selection.site?.offset ?? null); }
    if (crumb.kind === 'fn' && crumb.pane === 'graph' && selection.fn?.key) graphShown(graphAnswer(graph.select(selection.fn.key)));
    if (crumb.kind === 'call' && selection.call) timeline.select(selection.call.key);
    if (crumb.kind === 'sample' && selection.sample) timeline.select(selection.sample.key);
    if (crumb.pane === 'timeline') timelineOpen = true;
    reveal(crumb.pane, {focus: true});
  }

  /** Enter: follow the selection into the pane that explains it. */
  function follow() {
    if (selection.sample || (selection.fn?.artifact_id && Number.isSafeInteger(selection.fn.function_index))) {
      if (selection.fn) showCfg(selection.fn, selection.site?.offset ?? null);
      reveal('cfg', {focus: true});
      return 'cfg';
    }
    if (selection.request) { reveal('lineage', {focus: true}); return 'lineage'; }
    flash('Nothing to follow yet: select a request, a Wasm card or a sample.');
    return null;
  }

  // Panes, modes and layout.
  function readLayout() {
    const value = getComputedStyle(body).getPropertyValue('--flow-layout').trim();
    return value === 'laptop' || value === 'compact' || value === 'wide' ? value : 'wide';
  }
  function defaultSingle() { return getRequest() ? 'lineage' : 'graph'; }
  function mainPane() { return layout === 'compact' ? (singlePane ?? defaultSingle()) : mode === 'focus' ? focusPane : null; }
  /** The panes this layout shows. */
  function shownPanes() {
    const main = mainPane();
    if (main) return new Set([main]);
    const shown = new Set(['graph']);
    if (layout === 'wide') {
      if (split.cfg) shown.add('cfg');
      if (split.lineage) shown.add('lineage');
    } else {
      const side = currentSideTab();
      if (side === 'cfg' || side === 'cfg-only') shown.add('cfg');
      if (side !== 'cfg-only' && side !== null) shown.add('lineage');
    }
    if (split.timeline) shown.add('timeline');
    return shown;
  }
  /** In the laptop split the CFG is a tab beside Lineage. */
  function currentSideTab() {
    if (!split.lineage && !split.cfg) return null;
    if (!split.lineage) return 'cfg-only';
    if (sideTab === 'cfg' && split.cfg) return 'cfg';
    return 'lineage';
  }
  function applyLayout() {
    layout = readLayout();
    const shown = shownPanes(), main = mainPane();
    const effectiveMode = layout === 'compact' ? 'single' : mode;
    body.dataset.mode = effectiveMode;
    body.dataset.layout = layout;
    body.dataset.cfg = split.cfg ? 'on' : 'off';
    body.dataset.lineage = split.lineage ? 'on' : 'off';
    body.dataset.timeline = split.timeline ? 'on' : 'off';
    const side = layout === 'laptop' && effectiveMode === 'split' ? currentSideTab() : null;
    if (side) body.dataset.sideTab = side; else delete body.dataset.sideTab;
    body.dataset.timelineOpen = String(layout !== 'laptop' || effectiveMode !== 'split' || timelineOpen);
    for (const name of FLOW_PANES) {
      const pane = panes[name];
      pane.dataset.shown = String(shown.has(name));
      pane.toggleAttribute('data-active', name === active && effectiveMode === 'split');
    }
    // Lineage and Details are tabs of one column; in the laptop split CFG joins them.
    const lineageSide = side === 'cfg' ? 'cfg' : lineageTab;
    for (const [name, tab] of Object.entries(sideTabs)) {
      const on = name === lineageSide;
      tab.setAttribute('aria-selected', String(on)); tab.tabIndex = on ? 0 : -1;
      if (name === 'cfg') tab.hidden = !(layout === 'laptop' && effectiveMode === 'split' && split.cfg);
    }
    for (const [name, panel] of Object.entries(lineagePanels)) panel.hidden = name !== lineageTab;
    // Sizes: the split's tracks, each within what the body can hold.
    applySizes();
    // Head controls: toggles in the split, Split view in focus, neither single.
    togglesGroup.hidden = effectiveMode !== 'split';
    splitButton.hidden = effectiveMode !== 'focus';
    for (const [name, toggle] of Object.entries(toggles)) toggle.setAttribute('aria-pressed', String(split[name]));
    timelineOpenButton.hidden = !(layout === 'laptop' && effectiveMode === 'split');
    timelineOpenButton.textContent = timelineOpen ? 'Close' : 'Open';
    timelineOpenButton.setAttribute('aria-expanded', String(timelineOpen));
    tabs.hidden = !main;
    renderTabs();
    related.hidden = effectiveMode !== 'focus';
    if (effectiveMode === 'focus') renderRelated();
    // The canvases resize with their panes; the graph also observes its own.
    graph.resize();
    ensureCfg();
  }
  function applySizes() {
    const width = body.clientWidth || 0, height = body.clientHeight || 0;
    const clamp = (name, value, high) => Math.max(FLOW_SIZE_BOUNDS[name][0], Math.min(FLOW_SIZE_BOUNDS[name][1], high, value));
    let lineage = split.lineage || split.cfg ? sizes.lineage : 0;
    let cfgWidth = layout === 'wide' && split.cfg ? sizes.cfg : 0;
    if (width) {
      if (layout === 'wide') {
        if (lineage) lineage = clamp('lineage', lineage, width - FLOW_GRAPH_MIN - (cfgWidth ? FLOW_SIZE_BOUNDS.cfg[0] : 0));
        if (cfgWidth) cfgWidth = clamp('cfg', cfgWidth, width - FLOW_GRAPH_MIN - (split.lineage ? lineage : 0));
        if (!split.lineage) lineage = 0;
      } else if (lineage) lineage = clamp('lineage', lineage, width - 360);
    }
    const dock = !split.timeline ? 0 : layout === 'laptop' && !timelineOpen ? 33 : height ? clamp('timeline', sizes.timeline, height - 160) : sizes.timeline;
    body.style.setProperty('--flow-cfg-track', `${cfgWidth}px`);
    body.style.setProperty('--flow-lineage-track', `${layout === 'wide' ? lineage : 0}px`);
    body.style.setProperty('--flow-side-track', `${layout === 'laptop' ? lineage : 0}px`);
    body.style.setProperty('--flow-dock-track', `${dock}px`);
  }
  function renderTabs() {
    const main = mainPane();
    const meta = {
      graph: graphInfo?.name || (session ? 'session' : ''),
      cfg: cfg.fn ? (cfg.fn.name || `func ${cfg.fn.function_index}`) : 'none',
      lineage: selection.request?.renderer ? `#${selection.request.renderer}` : selection.request ? 'request' : 'none',
      timeline: timeline.summary().split(' · ').slice(0, 2).join(' · ') || ''
    };
    for (const tab of tabs.querySelectorAll('[role="tab"]')) {
      const name = tab.dataset.pane, on = name === main;
      tab.setAttribute('aria-selected', String(on)); tab.tabIndex = on ? 0 : -1;
      const label = tab.querySelector('.flow-tab-meta'); if (label) label.textContent = meta[name] ?? '';
    }
    graphMeta.textContent = graphInfo ? [graphInfo.name, graphInfo.kind].filter(Boolean).join(' · ') : '';
    timelineMeta.textContent = timeline.summary();
  }
  /** Makes a pane visible in the current layout, then optionally focuses it. */
  function reveal(name, {focus = false, record = true} = {}) {
    if (!FLOW_PANES.includes(name)) return false;
    const before = active;
    if (layout === 'compact') singlePane = name;
    else if (mode === 'focus') focusPane = name;
    else {
      if (name === 'cfg') { split.cfg = true; cfgUserHidden = false; if (layout === 'laptop') sideTab = 'cfg'; }
      if (name === 'lineage') { split.lineage = true; if (layout === 'laptop') sideTab = 'lineage'; }
      if (name === 'timeline') { split.timeline = true; timelineOpen = true; }
    }
    active = name;
    applyLayout();
    if (focus) focusPaneContent(name);
    if (record && before !== name && !changing) pushHistory(name);
    return true;
  }
  /** Keyboard focus on the pane's working control, else the pane itself. */
  function focusPaneContent(name) {
    let done = false;
    if (name === 'graph') { graph.focus(); done = true; }
    else if (name === 'cfg' && cfg.view?.hasGraph()) { cfg.view.focus(); done = true; }
    else if (name === 'lineage') done = Boolean(focusTraceRow());
    else if (name === 'timeline') done = Boolean(timeline.focus());
    if (!done) panes[name].focus({preventScroll: true, focusVisible: true});
    // Focus never stays on the page itself.
    const focused = doc.activeElement;
    if ((!focused || focused === doc.body) && name !== 'graph') { focusPaneContent('graph'); return; }
    active = name;
    for (const pane of FLOW_PANES) panes[pane].toggleAttribute('data-active', pane === name && body.dataset.mode === 'split');
  }
  /** Whether a pane can take focus in this layout: shown, and in the laptop
   * split not the closed timeline strip or the Lineage list behind the CFG tab. */
  function paneVisible(name) {
    if (!shownPanes().has(name)) return false;
    if (layout !== 'laptop' || mode !== 'split') return true;
    if (name === 'timeline') return timelineOpen;
    return name !== 'lineage' || currentSideTab() !== 'cfg';
  }
  function setMode(next, pane = active) {
    if (layout === 'compact') { flash('One pane at a time at this width; 1 to 4 switch panes.'); return; }
    if (next === 'focus') { if (mode !== 'focus') returnPane = active; focusPane = FLOW_PANES.includes(pane) ? pane : 'graph'; mode = 'focus'; active = focusPane; }
    else mode = 'split';
    applyLayout();
    // Back in the split, the pane focus mode showed may be one the split hides:
    // focus goes to the pane focused before focus mode, else the graph.
    focusPaneContent(mode === 'focus' ? focusPane : paneVisible(active) ? active : paneVisible(returnPane) ? returnPane : 'graph');
  }
  const toggleFocus = (pane = active) => setMode(mode === 'focus' ? 'split' : 'focus', pane);
  function togglePane(name) {
    if (mode !== 'split' || layout === 'compact') { flash('Pane toggles change the split; press Z to return to it.'); return; }
    if (layout === 'laptop' && name === 'cfg' && split.cfg && currentSideTab() !== 'cfg') { sideTab = 'cfg'; applyLayout(); return; }
    split[name] = !split[name];
    if (name === 'cfg') { cfgUserHidden = !split.cfg; if (split.cfg && layout === 'laptop') sideTab = 'cfg'; }
    if (name === 'lineage' && split.lineage && layout === 'laptop') sideTab = 'lineage';
    if (name === 'timeline' && split.timeline && layout === 'laptop') timelineOpen = false;
    if (!split[name] && active === name) active = 'graph';
    savePrefs();
    applyLayout();
    flash(`${FLOW_PANE_NAMES[name]} ${split[name] ? 'shown' : 'hidden'} in the split.`);
  }
  for (const [name, toggle] of Object.entries(toggles)) toggle.addEventListener('click', () => togglePane(name));
  splitButton.addEventListener('click', () => setMode('split'));
  function focusButton(name) {
    const element = button('flow-focus-button', '', `Open ${FLOW_PANE_NAMES[name]} on its own`);
    element.dataset.focus = name; element.title = `Open ${FLOW_PANE_NAMES[name]} on its own, or return to the split (Z)`;
    element.append(flowIcon('M3 8V3h5M12 3h5v5M17 12v5h-5M8 17H3v-5'));
    element.addEventListener('click', () => (mode === 'focus' && focusPane === name ? setMode('split') : setMode('focus', name)));
    return element;
  }
  function flowIcon(path) {
    const svg = doc.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 20 20'); svg.setAttribute('aria-hidden', 'true');
    const line = doc.createElementNS('http://www.w3.org/2000/svg', 'path'); line.setAttribute('d', path); svg.append(line);
    return svg;
  }
  for (const element of root.querySelectorAll('.flow-focus-button[data-focus]')) {
    element.addEventListener('click', () => {
      const name = element.dataset.focus === 'side' ? (currentSideTab() === 'cfg' ? 'cfg' : 'lineage') : element.dataset.focus;
      if (mode === 'focus' && focusPane === name) setMode('split'); else setMode('focus', name);
    });
  }
  // Double-clicking a pane head opens that pane on its own, or returns.
  root.addEventListener('dblclick', event => {
    const head = event.target?.closest?.('.flow-pane-head, [data-flow-head]');
    if (!head || event.target.closest('button, select, input, a')) return;
    const pane = head.closest('.flow-pane')?.dataset.pane;
    if (pane) toggleFocus(pane === 'lineage' && currentSideTab() === 'cfg' ? 'cfg' : pane);
  });
  // Focus mode tabs and the narrow pane switch share one tab bar.
  tabs.addEventListener('click', event => { const tab = event.target?.closest?.('[role="tab"][data-pane]'); if (tab) reveal(tab.dataset.pane, {focus: false}); });
  tabs.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const list = [...tabs.querySelectorAll('[role="tab"][data-pane]')];
    const at = list.indexOf(event.target?.closest?.('[role="tab"]'));
    if (at < 0) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? list.length - 1 : (at + (event.key === 'ArrowRight' ? 1 : -1) + list.length) % list.length;
    reveal(list[next].dataset.pane); list[next].focus({focusVisible: true});
  });
  for (const [name, tab] of Object.entries(sideTabs)) {
    tab.addEventListener('click', () => {
      if (name === 'cfg') { sideTab = 'cfg'; active = 'cfg'; applyLayout(); return; }
      sideTab = 'lineage'; setLineageTab(name);
    });
  }
  $('.flow-inspector-tabs').addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    const list = Object.values(sideTabs).filter(tab => !tab.hidden);
    const at = list.indexOf(event.target);
    if (at < 0) return;
    event.preventDefault();
    const next = list[(at + (event.key === 'ArrowRight' ? 1 : -1) + list.length) % list.length];
    next.click(); next.focus({focusVisible: true});
  });
  // The active pane is the one the keyboard or pointer last worked in.
  root.addEventListener('focusin', event => {
    const pane = event.target?.closest?.('.flow-pane')?.dataset.pane;
    if (pane && pane !== active) { active = pane; for (const name of FLOW_PANES) panes[name].toggleAttribute('data-active', name === pane && body.dataset.mode === 'split'); }
  });
  root.addEventListener('pointerdown', event => {
    const pane = event.target?.closest?.('.flow-pane')?.dataset.pane;
    if (pane) active = pane === 'lineage' && currentSideTab() === 'cfg' && event.target.closest('#flow-pane-cfg') ? 'cfg' : pane;
  });

  // Related rail (focus mode): what is linked to the selection, each entry a
  // jump. It is rebuilt only when what it lists changes, so an evidence poll
  // neither redraws it nor moves keyboard focus out of it.
  let relatedKey = null;
  function renderRelated() {
    if (related.hidden) { relatedKey = null; return; }
    const key = JSON.stringify([lineageModels.map(model => model.key), flowSelectionKey(selection), selection.request?.label ?? null, graphInfo,
      timeline.selection()?.key ?? null, timeline.summary(), cfg.fn?.key ?? null, cfg.fn?.label ?? null]);
    if (key === relatedKey) return;
    relatedKey = key;
    const sections = [];
    const section = (title, pane, entries, action) => {
      const block = make('section', 'flow-related-section');
      block.dataset.pane = pane;
      const head = make('div', 'flow-related-head');
      const name = make('h3', '', title); name.prepend(make('span', 'flow-pane-mark'));
      head.append(name);
      if (action) {
        const open = button('flow-related-open', action.label, action.aria);
        open.append(make('kbd', '', action.key));
        open.addEventListener('click', action.run);
        head.append(open);
      }
      block.append(head, ...entries);
      sections.push(block);
    };
    const entry = (text, note, run, className = '') => {
      const item = button(`flow-related-item ${className}`.trim(), '');
      item.append(make('span', 'flow-related-text', text));
      if (note) item.append(make('span', 'flow-related-note', note));
      item.addEventListener('click', run);
      return item;
    };
    const title = selection.sample?.label ? `${selection.site?.label ?? ''} ${selection.sample.label}`.trim() : selection.site?.label ?? selection.fn?.label ?? selection.request?.label ?? 'nothing yet';
    const heading = make('p', 'flow-related-title', 'Related to ');
    heading.append(make('b', '', title));
    // Lineage of the selected request.
    const steps = lineageModels.filter(model => model.step).slice(0, FLOW_WORKSPACE_LIMITS.related);
    if (lineageModels.length) {
      const entries = steps.map(model => {
        // A link here is picked as its Lineage row is.
        const item = entry(model.title, model.confidence, () => { if (selectTraceRow(model)) lineagePicked(model); reveal('lineage', {focus: true}); }, 'flow-related-link');
        const sample = make('span', 'flow-link-line'); sample.setAttribute('aria-hidden', 'true');
        Object.assign(sample.dataset, flowLinkKind(model));
        item.prepend(sample);
        return item;
      });
      const more = lineageModels.filter(model => model.step).length - steps.length;
      if (more > 0) entries.push(make('p', 'flow-more', `${more} more steps in Lineage`));
      section(`Lineage${selection.request?.renderer ? ` · #${selection.request.renderer}` : ''}`, 'lineage', entries, {label: 'Open', key: '3', aria: 'Open Lineage', run: () => reveal('lineage', {focus: true})});
    }
    // Samples of the selected call, or at the selected site.
    const chosen = timeline.selection();
    const sampleList = chosen?.type === 'sample' ? chosen.site.samples : chosen?.track ? chosen.track.samples : [];
    if (sampleList.length) {
      const strip = make('div', 'flow-related-strip');
      strip.setAttribute('role', 'group'); strip.setAttribute('aria-label', 'Samples');
      for (const sample of sampleList.slice(0, FLOW_WORKSPACE_LIMITS.relatedSamples)) {
        const dot = button('flow-related-sample', sample.kind === 'br_table' ? String(sample.selector ?? '?') : 'ci', `Sample ${sample.ordinal}${sample.kind === 'br_table' ? `, selector ${sample.selector}` : ''}${sample.invocation ? `, call #${sample.invocation}` : ''}`);
        dot.setAttribute('aria-pressed', String(chosen?.sample?.key === sample.key));
        dot.addEventListener('click', () => timeline.select(`sample:${sample.key}`, {silent: false}));
        strip.append(dot);
      }
      const entries = [strip];
      if (sampleList.length > FLOW_WORKSPACE_LIMITS.relatedSamples) entries.push(make('p', 'flow-more', `${sampleList.length - FLOW_WORKSPACE_LIMITS.relatedSamples} more samples in Timeline`));
      section(chosen?.type === 'sample' ? `Timeline · ${chosen.count ?? `sample ${chosen.sample.ordinal} of ${chosen.site.samples.length} read`}` : `Timeline · ${chosen.label}`, 'timeline', entries,
        {label: 'Open', key: '4', aria: 'Open Timeline', run: () => { timelineOpen = true; reveal('timeline', {focus: true}); }});
    }
    // Sampled sites of the selected function.
    if (cfg.fn) {
      const sites = timeline.samplesFor(cfg.fn.artifact_id, cfg.fn.function_index);
      if (sites.length) section(`CFG · ${cfg.fn.label}`, 'cfg', sites.slice(0, FLOW_WORKSPACE_LIMITS.related).map(site => entry(`${flowHexOffset(site.offset)} ${site.kind}`, `×${site.samples.length}`, () => {
        setSelection({site: {offset: site.offset, kind: site.kind, label: `${flowHexOffset(site.offset)} ${site.kind}`}});
        showCfg(cfg.fn, site.offset); reveal('cfg', {focus: true});
      })), {label: 'Open', key: '2', aria: 'Open CFG', run: () => reveal('cfg', {focus: true})});
    }
    // The graph card: its row, and its callers and callees when the graph says.
    if (graphInfo) {
      // Each card entry is a pick: the graph selects it and the workspace
      // follows. A graph still laying out selects it once drawn, as the host's.
      const pickCard = key => change(() => {
        const info = key ? graph.select(key) : null;
        if (info) graphPicked(info);
        else if (key) flash('The graph has not drawn this card yet; it is selected once the graph is drawn.');
        reveal('graph', {focus: true});
      });
      const entries = [entry(graphInfo.name || graphInfo.kind || 'card', [graphInfo.kind, graphInfo.location].filter(Boolean).join(' · '), () => pickCard(graphInfo.key))];
      if (graphInfo.row) entries.push(entry(`${graphInfo.row.op ?? 'call'} ${graphInfo.row.target ?? ''}`.trim(), graphInfo.row.site ?? '', () => reveal('graph', {focus: true})));
      for (const [label, list] of [['called by', graphInfo.callers], ['calls', graphInfo.callees]]) {
        if (!Array.isArray(list)) continue;
        for (const item of list.slice(0, 4)) entries.push(entry(`${label} ${item.name ?? item.key ?? ''}`.trim(), item.note ?? '', () => pickCard(item.key)));
      }
      if (graphInfo.request) {
        const known = findRendererRequest(graphInfo.request.process, graphInfo.request.request);
        entries.push(entry(known?.label ?? `request #${graphInfo.request.request}`, known ? 'trace its lineage' : 'not in the request list', () => {
          // The card made this request, so its crumbs stay beside it.
          if (known) change(() => { setSelection(requestPatch(showAppRequest(known.id), known.id)); reveal('lineage', {focus: true}); });
          else flash('This request is not in the captured request list.');
        }));
      }
      section('Graph', 'graph', entries, {label: 'In graph', key: '1', aria: 'Open the graph', run: () => reveal('graph', {focus: true})});
    }
    if (!sections.length) sections.push(make('p', 'flow-related-empty', 'Select a request, a card or a sample; what links to it is listed here, one key or click away.'));
    related.replaceChildren(heading, ...sections);
  }

  // Dividers: drag, arrow keys (Shift for a larger step), Home or double-click resets.
  for (const handle of root.querySelectorAll('.flow-divider[data-size]')) {
    const axis = handle.dataset.axis === 'y' ? 'y' : 'x';
    const sizeName = () => (handle.dataset.size === 'cfg' && layout === 'laptop' ? 'lineage' : handle.dataset.size);
    let drag = null;
    const set = value => {
      const name = sizeName();
      sizes[name] = Math.round(Math.max(FLOW_SIZE_BOUNDS[name][0], Math.min(FLOW_SIZE_BOUNDS[name][1], value)));
      applySizes(); describeHandle(); graph.resize();
    };
    const describeHandle = () => {
      const name = sizeName();
      handle.setAttribute('aria-valuemin', String(FLOW_SIZE_BOUNDS[name][0]));
      handle.setAttribute('aria-valuemax', String(FLOW_SIZE_BOUNDS[name][1]));
      handle.setAttribute('aria-valuenow', String(sizes[name]));
      handle.setAttribute('aria-valuetext', `${sizes[name]} pixels`);
    };
    describeHandle();
    handle.addEventListener('pointerdown', event => {
      if (event.button !== 0) return;
      event.preventDefault(); handle.focus(); handle.setPointerCapture(event.pointerId);
      drag = {pointer: event.pointerId, start: axis === 'x' ? event.clientX : event.clientY, size: sizes[sizeName()], previous: sizes[sizeName()]};
      body.classList.add('flow-resizing');
    });
    handle.addEventListener('pointermove', event => {
      if (!drag || drag.pointer !== event.pointerId) return;
      // Every handle sits on the leading edge of the pane it sizes.
      set(drag.size - ((axis === 'x' ? event.clientX : event.clientY) - drag.start));
    });
    const finish = commit => {
      if (!drag) return;
      if (!commit) set(drag.previous);
      drag = null; body.classList.remove('flow-resizing');
      if (commit) savePrefs();
    };
    handle.addEventListener('pointerup', () => finish(true));
    handle.addEventListener('pointercancel', () => finish(false));
    handle.addEventListener('dblclick', () => { sizes[sizeName()] = FLOW_SIZE_DEFAULTS[sizeName()]; applySizes(); describeHandle(); savePrefs(); graph.resize(); });
    handle.addEventListener('keydown', event => {
      if (event.key === 'Escape' && drag) { event.preventDefault(); event.stopPropagation(); finish(false); return; }
      if (event.key === 'Home') { event.preventDefault(); event.stopPropagation(); sizes[sizeName()] = FLOW_SIZE_DEFAULTS[sizeName()]; applySizes(); describeHandle(); savePrefs(); return; }
      const keys = axis === 'x' ? ['ArrowRight', 'ArrowLeft'] : ['ArrowDown', 'ArrowUp'];
      const direction = keys.indexOf(event.key);
      if (direction < 0) return;
      event.preventDefault(); event.stopPropagation();
      // Left (or Up) grows the pane after the divider.
      set(sizes[sizeName()] + (direction ? 1 : -1) * (event.shiftKey ? 50 : 10));
      savePrefs();
    });
  }
  function savePrefs() {
    const entry = {sizes: {...sizes}, panes: {...split}, cfgHidden: cfgUserHidden, at: Date.now()};
    prefs.last = entry;
    if (session) {
      prefs.sessions[session] = entry;
      const keys = Object.keys(prefs.sessions);
      if (keys.length > FLOW_WORKSPACE_LIMITS.sessions) {
        keys.sort((a, b) => (prefs.sessions[a]?.at ?? 0) - (prefs.sessions[b]?.at ?? 0));
        for (const key of keys.slice(0, keys.length - FLOW_WORKSPACE_LIMITS.sessions)) delete prefs.sessions[key];
      }
    }
    flowWorkspaceSavePrefs(storage, prefs);
  }
  function loadPrefs(next) {
    const entry = (next && prefs.sessions[next]) || prefs.last;
    sizes = flowWorkspaceSizes(entry);
    split = flowWorkspacePanes(entry);
    cfgUserHidden = entry?.cfgHidden === true && !split.cfg;
  }

  // Keys. They never fire while typing, never with Command, Control or
  // Option (the app's shortcuts), and the graph and block graph canvases keep
  // every key they handle (they stop it or mark it handled first).
  const typing = target => Boolean(target?.closest?.('input, textarea, select, [contenteditable="true"], [contenteditable=""]'));
  // Opening Flow from the sidebar leaves focus on its button, so keys also
  // come from the page itself and the sidebar while Flow is shown; docks such
  // as the Console and the agent keep their own keys.
  const inScope = target => !target || target === doc.body || target === doc.documentElement || root.contains(target) || Boolean(target.closest?.('.sidebar'));
  doc.addEventListener('keydown', event => {
    if (!visible || root.hidden || !inScope(event.target)) return;
    if (event.defaultPrevented || event.isComposing || event.metaKey || event.ctrlKey || event.altKey || typing(event.target)) return;
    // A modal dialog keeps the keyboard.
    if (doc.querySelector('dialog:modal')) return;
    const key = event.key, code = event.code ?? '';
    const digit = /^Digit([1-4])$/.exec(code)?.[1] ?? (/^[1-4]$/.test(key) ? key : null);
    let handled = true;
    if (digit && !event.shiftKey) {
      const name = FLOW_PANES[Number(digit) - 1];
      reveal(name, {focus: true});
    } else if ((code === 'KeyZ' || key === 'z' || key === 'Z') && !event.shiftKey && !event.repeat) toggleFocus();
    else if (event.shiftKey && !event.repeat && (code === 'KeyC' || key === 'C')) togglePane('cfg');
    else if (event.shiftKey && !event.repeat && (code === 'KeyL' || key === 'L')) togglePane('lineage');
    else if (event.shiftKey && !event.repeat && (code === 'KeyT' || key === 'T')) togglePane('timeline');
    else if (key === 'Backspace') { if (event.shiftKey) forward(); else back(); }
    else if (key === 'Enter' && !event.target?.closest?.('button, a, summary, [role="tab"], canvas, [role="application"]')) follow();
    else if ((key === 'j' || key === 'k' || key === 'J' || key === 'K') && !event.shiftKey && event.target?.closest?.('#flow-pane-cfg')) { if (!timeline.stepSample(key.toLowerCase() === 'j' ? 1 : -1)) flash('No sample to step: pick one in the timeline.'); }
    else handled = false;
    if (handled) { event.preventDefault(); event.stopPropagation(); }
  });

  new ResizeObserver(() => { if (visible) applyLayout(); }).observe(body);
  applyLayout();
  renderTrail(); renderHistoryButtons(); renderCfgChrome();

  return {
    /** Called whenever the Flow screen renders: visibility, session, the
     * app's selected request and how many captured requests a script
     * started, which the graph asks again for when it grows. */
    sync({visible: shown, session: nextSession = null, request = null, revision = null, stacks = null}) {
      const wasVisible = visible;
      visible = Boolean(shown);
      if (!visible) { graph.hide(); if (wasVisible) releaseCfg(); return; }
      if (String(nextSession ?? '') !== String(session ?? '')) {
        session = nextSession ? String(nextSession) : null;
        loadPrefs(session);
        forgetCfg();
        // The app's request in this session is a pick of its own.
        history = []; cursor = -1; requestRevision = null; graphInfo = null;
        selection = {request: null, call: null, fn: null, site: null, sample: null, step: null, graphKey: null};
      }
      const crumb = requestCrumb(request);
      // A revision the app made while the workspace changed something is
      // that change's own; any other is the app's pick, unless it chose the
      // request the trail already shows.
      const fresh = revision !== requestRevision;
      requestRevision = revision;
      if (fresh && !changing && crumb?.id !== selection.request?.id) {
        // Nothing below the old request is a recorded relationship of the new one.
        if (selection.sample) { timeline.clear(); graph.setMark(null); }
        setSelection({...noCrumbs, request: crumb, step: null}, {record: Boolean(crumb)});
      } else if (crumb && crumb.id === selection.request?.id && (crumb.label !== selection.request.label || crumb.renderer !== selection.request.renderer)) {
        // The same request, named afresh: no pick, so no trail entry; the
        // entry that holds it takes the new name too.
        selection = {...selection, request: crumb};
        if (history[cursor]?.selection.request?.id === crumb.id) history[cursor] = {...history[cursor], selection: {...history[cursor].selection, request: crumb}};
        renderTrail(); renderTabs();
      }
      requestTag.hidden = !request;
      const parts = request ? [request.renderer?.request ? `#${request.renderer.request}` : null, request.status ? String(request.status) : null, request.renderer ? `renderer ${request.renderer.process}` : null].filter(Boolean) : [];
      requestMeta.textContent = parts.join(' · '); requestMeta.hidden = !parts.length;
      graph.show({session, request: request?.renderer ?? null, stacks});
      timeline.sync(session);
      if (!wasVisible) applyLayout();
      else renderTabs();
    },
    /** The lineage rows renderBacktrace just drew, for the Related rail. */
    setLineage(models) { lineageModels = models.slice(0, 256); if (!related.hidden) renderRelated(); },
    /** A Lineage row the researcher picked. */
    lineageSelected: lineagePicked,
    reveal
  };
}
