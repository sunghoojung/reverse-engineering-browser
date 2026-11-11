// Flow workspace: the tracked-call timeline model and its bounds, paging and
// states, and the workspace controller on the shipped index.html markup with
// a stub flow graph panel and a stub block graph view: pane toggles, focus
// mode and its exact restore, tabs and number keys, the trail and its history,
// linking between panes, storage, and the shipped-source rules. Offline DOM
// model only (LinkeDOM); rendered acceptance is the packaged-app gate.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createContext, runInContext} from 'node:vm';

const require = createRequire(import.meta.url);
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const ui = new URL('../apps/research-ui/', import.meta.url);
const read = name => readFile(new URL(name, ui), 'utf8');
// Values made in the DOM model's realm compare by structure.
const same = (actual, expected, message) => assert.deepEqual(JSON.parse(JSON.stringify(actual)), JSON.parse(JSON.stringify(expected)), message);
const settle = async (rounds = 6) => { for (let i = 0; i < rounds; i += 1) await new Promise(resolve => setImmediate(resolve)); };
const timeline = require('../apps/research-ui/flow_timeline.js');
const workspaceModule = require('../apps/research-ui/flow_workspace.js');

// Synthetic records: renderer 41, two tracked calls (#12, #13), br_table
// samples inside them, one call_indirect outside, invocation requests.
let seq = 0;
const base = (type, extra = {}) => ({type, process_id: 41, sequence_number: String(++seq), artifact_id: '0', request_id: '0', ...extra});
const wasm = (selector, invocation, state = 2, type = 'wasm_dispatch_observation', offset = 69) => base(type, {artifact_id: '4',
  wasm_observation: {status: 'decoded', function_index: 1, module_byte_offset: offset, selector, table_count: 3, sample_index: seq % 16, js_invocation_state: state, js_invocation_id: state === 2 ? invocation : 0}});
const js = (type, fields) => base(type, {js_invocation: {status: 'decoded', ...fields}});
function sessionRecords({decoded = true} = {}) {
  seq = 100;
  const strip = event => { if (!decoded && event.js_invocation) { const {js_invocation: _drop, ...rest} = event; return rest; } return event; };
  return [
    js('js_invocation_start', {kind: 'start', site_slot: 0, invocation_id: 12, parent_invocation_id: 0, parent_unknown: false, argument_count: 2}),
    js('js_invocation_request', {kind: 'request', invocation_id: 12, inside: true, request_id: '71'}),
    js('js_invocation_start', {kind: 'start', site_slot: 0, invocation_id: 13, parent_invocation_id: 0, parent_unknown: false, argument_count: 2}),
    wasm(3, 12), wasm(0, 12), wasm(3, 12),
    js('js_invocation_settle', {kind: 'settle', site_slot: 0, invocation_id: 12, fulfilled: true, value_kind: 3, value_length: 2148, via: 3}),
    wasm(1, 13), wasm(3, 13),
    js('js_invocation_request', {kind: 'request', invocation_id: 13, inside: true, request_id: '73'}),
    js('js_invocation_settle', {kind: 'settle', site_slot: 0, invocation_id: 13, fulfilled: true, value_kind: 5, value_length: 0, via: 1}),
    wasm(null, 0, 1, 'wasm_indirect_observation', 90),
    js('js_invocation_request', {kind: 'request', invocation_id: null, inside: false, request_id: '73'})
  ].map(strip);
}

{
  // The model with the backend's decoded invocation objects.
  const model = timeline.flowTimelineModel(sessionRecords());
  assert.equal(model.decoded, true);
  assert.equal(model.processes.length, 1);
  const view = model.processes[0];
  assert.deepEqual(view.tracks.map(track => track.invocation), ['12', '13'], 'one track per invocation, in record order');
  const [call12, call13] = view.tracks;
  assert.equal(call12.start.seq, 101n); assert.equal(call12.settle.seq, 107n);
  assert.equal(timeline.flowTrackOutcome(call12), 'fulfilled · string · 2,148 UTF-16 units', 'a settle names kind and length, never content');
  assert.equal(timeline.flowTrackOutcome(call13), 'fulfilled · undefined');
  assert.equal(call13.settle.via, 1, 'a synchronous settle is kept so the span can be drawn as running');
  assert.deepEqual(call12.samples.map(sample => sample.selector), [3, 0, 3]);
  assert.deepEqual(call12.requests.map(request => request.request), ['71']);
  assert.equal(view.outside.length, 1, 'a sample outside any tracked call is kept in its own lane, not dropped');
  assert.equal(view.requests.length, 3);
  assert.equal(view.requests.at(-1).invocation, null, 'a request with an unknown call keeps no invocation');
  const site = view.sites.get('4:1:69:br_table');
  assert.equal(site.samples.length, 5, 'samples group by module, function, offset and kind across calls');
  assert.deepEqual([...site.samples.map(sample => sample.ordinal)], [1, 2, 3, 4, 5]);
  assert.deepEqual([...site.histogram.entries()].sort(), [[0, 1], [1, 1], [3, 3]]);
  assert.equal(call13.samples[0].callOrdinal, 1);
  assert.deepEqual(model.counts, {records: 13, starts: 2, settles: 2, requests: 3, samples: 6, outside: 1, invalid: 0, undecoded: 0, duplicates: 0, conflicts: 0});
}
{
  // Without the backend's decode: tracks come from Wasm records only.
  const model = timeline.flowTimelineModel(sessionRecords({decoded: false}));
  const view = model.processes[0];
  assert.equal(model.decoded, false);
  assert.equal(model.counts.undecoded, 7, 'every invocation record is counted as undecoded');
  assert.deepEqual(view.tracks.map(track => track.invocation), ['12', '13']);
  assert(view.tracks.every(track => !track.start && !track.settle && !track.requests.length), 'no start, settle or request markers without the decode');
  assert.equal(timeline.flowTrackOutcome(view.tracks[0]), 'start and settle not read');
}
{
  // Malformed, invalid, duplicate and repeated records are counted.
  seq = 0;
  const records = [wasm(3, 5), {...wasm(3, 5), sequence_number: '1'}, base('wasm_dispatch_observation', {wasm_observation: {status: 'invalid'}}),
    base('js_invocation_start', {sequence_number: '01'}), js('js_invocation_settle', {status: 'invalid'}),
    js('js_invocation_start', {kind: 'start', invocation_id: 5}), js('js_invocation_start', {kind: 'start', invocation_id: 5}), {type: 'request_initiated', sequence_number: '9', process_id: 41}, null];
  const model = timeline.flowTimelineModel(records);
  assert.equal(model.counts.duplicates, 1);
  assert.equal(model.counts.invalid, 3);
  assert.equal(model.counts.conflicts, 1);
  assert.equal(model.processes[0].tracks.length, 1);
  assert.equal(timeline.flowSeq('18446744073709551616'), null); assert.equal(timeline.flowSeq('0'), null); assert.equal(timeline.flowSeq('7'), 7n);
}
{
  // Bounds: tracks, samples and requests past their budget are counted, never silently dropped.
  seq = 0;
  const records = [];
  for (let call = 1; call <= 5; call += 1) for (let sample = 0; sample < 4; sample += 1) records.push(wasm(sample, call));
  for (let request = 0; request < 6; request += 1) records.push(js('js_invocation_request', {kind: 'request', invocation_id: 1, inside: true, request_id: String(200 + request)}));
  const limits = {...timeline.FLOW_TIMELINE_LIMITS, maxTracks: 3, maxSamples: 10, maxRequests: 4};
  const view = timeline.flowTimelineModel(records, limits).processes[0];
  assert.equal(view.drawn.length, 3);
  assert.deepEqual(view.hidden, {tracks: 2, samples: 10, requests: 2}, '8 samples of hidden tracks plus 2 over the drawing budget');
  assert.equal(view.drawn.reduce((sum, track) => sum + track.drawnSamples.length, 0), 10);
}
{
  // Record order as x: long runs compress to a marked break, order is exact.
  const axis = timeline.flowTimelineAxis([10n, 11n, 13n, 500n, 501n], {unit: 10, gapCap: 4, labelEvery: 30});
  assert.deepEqual(axis.points.map(point => point.x), [0, 10, 30, 70, 80]);
  assert.equal(axis.breaks.length, 1); assert.equal(axis.breaks[0].skipped, 486n);
  assert(axis.ticks.some(tick => tick.seq === 500n), 'the first record after a break is labelled');
  assert.equal(axis.x(12n), 20, 'a sequence between two points interpolates');
}

// The DOM model: the shipped Flow screen.
const html = await read('index.html');
const {window, document} = parseHTML(html);
const screen = document.querySelector('#screen-backtrace');
screen.removeAttribute('hidden');
let layout = 'wide';
const storage = new Map();
const storageApi = {getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, String(value))};
const context = createContext({window, document, console, TextDecoder, TextEncoder, URLSearchParams, AbortController, DOMException, Map, Set, JSON,
  setTimeout: (fn, ms) => { const timer = setTimeout(fn, ms); timer.unref?.(); return timer; }, clearTimeout,
  getComputedStyle: () => ({getPropertyValue: name => (name === '--flow-layout' ? ` ${layout}` : '')})});
context.globalThis = context;
for (const name of ['flow_timeline.js', 'flow_workspace.js']) runInContext(await read(name), context, {filename: name});

const graphCalls = [];
const graph = {};
for (const method of ['select', 'setMark', 'highlightRequest', 'resize', 'focus']) graph[method] = (...args) => { graphCalls.push([method, ...args]); return true; };
const viewCalls = [];
let viewOptions = null;
const makeView = (host, options) => {
  viewOptions = options;
  const head = document.createElement('div'); head.className = 'block-graph-head';
  const tools = document.createElement('div'); head.append(tools); host.append(head);
  let result = null;
  return {tools, activate: () => viewCalls.push(['activate']), release: () => { result = null; viewCalls.push(['release']); }, measurements: () => ({charW: 6.6}),
    setResult: next => { result = next; viewCalls.push(['setResult']); }, setState: (kind, message) => viewCalls.push(['setState', kind, message]),
    select: (block, row) => viewCalls.push(['select', block, row]), focus: () => viewCalls.push(['focus']), hasGraph: () => Boolean(result), setTitle() {}, fit() {}};
};
// One function: three blocks, the br_table at 0x45 in block 1.
const rows = '37 block\n39 loop\n43 local.get 0\n45 br_table [3 targets] default 3\n4b end\n';
const starts = [0]; for (const line of rows.split('\n').slice(0, -1)) starts.push(starts.at(-1) + line.length + 1);
const cfgResult = () => ({graph: {count: 3, offsets: [0x37, 0x39, 0x4b], ends: [0x39, 0x4b, 0x50], firstRow: [0, 1, 4], rowCount: [1, 3, 1], rows}, starts, layout: {}});
let runs = 0;
const runner = () => ({run: async message => { runs += 1; assert.equal(message.type, 'wasm'); assert(message.metrics && message.engine); return cfgResult(); }, cancel() {}});
let eventPages = [], graphFailure = false;
const fetches = [];
const fetchStub = async (url, init) => {
  fetches.push(url);
  if (url.startsWith('/api/wasm/graph')) {
    if (graphFailure) return {ok: false, status: 404, json: async () => ({error: 'function 9 is imported'})};
    return {ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(8)};
  }
  if (url.startsWith('/api/wasm/functions')) return {ok: true, status: 200, json: async () => ({schema: 'wasm-function-index-v1', names: [[1, 'run'], [2, 'send'], ['x', 'bad']]})};
  if (url.startsWith('/api/events')) {
    const page = eventPages.shift();
    if (page instanceof Error) throw page;
    const bytes = new TextEncoder().encode(JSON.stringify(page));
    return {ok: true, status: 200, arrayBuffer: async () => bytes.buffer};
  }
  throw Error(`unexpected ${url} ${init}`);
};
const appCalls = [];
let appRequest = {id: 'r1', label: 'POST collect.frame.test #73', method: 'POST', path: '/c', status: 200, renderer: {process: 41, request: '73'}};
const known = {'41:71': {id: 'r0', label: 'GET frame.test'}, '41:73': {id: 'r1', label: 'POST collect.frame.test'}};
const page = (events, query = {}) => ({events, query: {limited: false, budget_exhausted: false, next_after: '9000', store_end: '9000', ...query}});
eventPages = [page(sessionRecords())];
const workspace = context.createFlowWorkspace({
  root: screen, graph, storage: storageApi, fetch: fetchStub, createBlockGraphView: makeView, createBlockGraphRunner: runner, blockGraphEngine: () => 'layered',
  getRequest: () => appRequest,
  selectRequest: id => appCalls.push(['selectRequest', id]),
  findRendererRequest: (process, request) => known[`${process}:${request}`] ?? null,
  selectTraceRow: key => { appCalls.push(['selectTraceRow', key]); return true; },
  focusTraceRow: () => { appCalls.push(['focusTraceRow']); return true; },
  openSource: target => appCalls.push(['openSource', target.artifact_id])
});
const $ = selector => document.querySelector(selector);
const shown = () => [...document.querySelectorAll('.flow-pane')].filter(pane => pane.dataset.shown === 'true').map(pane => pane.dataset.pane);
const key = (key, {shift = false, code = null, target = $('#flow-pane-graph'), meta = false} = {}) => {
  const event = new window.Event('keydown', {bubbles: true, cancelable: true});
  Object.assign(event, {key, code: code ?? (key.length === 1 ? (/\d/.test(key) ? `Digit${key}` : `Key${key.toUpperCase()}`) : key), shiftKey: shift, metaKey: meta, ctrlKey: false, altKey: false, repeat: false, isComposing: false});
  target.dispatchEvent(event);
  return event;
};

{
  // First show: the timeline reads the session's records forward from the start.
  workspace.sync({visible: true, session: '7', request: appRequest});
  await settle();
  const read = new URL(fetches.find(url => url.startsWith('/api/events')), 'http://fixture.invalid');
  assert.equal(read.searchParams.get('session_id'), '7');
  assert.equal(read.searchParams.get('after'), '0', 'the read starts at the store start, in record order');
  assert.equal(read.searchParams.get('type'), 'wasm_dispatch_observation,wasm_indirect_observation,js_invocation_start,js_invocation_settle,js_invocation_request');
  assert.equal(read.searchParams.get('limit'), '1000');
  assert.equal(workspace.timeline.status(), 'ready');
  assert.match(workspace.timeline.summary(), /^2 calls · 6 samples · renderer 41 record order$/);
  assert.equal(document.querySelectorAll('#flow-timeline .flow-tl-sample').length, 6);
  assert.equal(document.querySelectorAll('#flow-timeline .flow-tl-chip').length, 3);
  assert.equal(document.querySelectorAll('#flow-timeline .flow-tl-run').length, 1, 'only the synchronous settle draws a running span');
  same(workspace.trail().map(crumb => crumb.label), ['POST collect.frame.test #73']);
  assert.equal($('#flow-request-meta').textContent, '#73 · 200 · renderer 41');
  same(shown(), ['graph', 'lineage', 'timeline'], 'the CFG waits for a function');
  assert.equal($('#flow-cfg-empty').hidden, false, 'the empty CFG says how to fill it');
}
{
  // Pane toggles show and hide panes in the split, from the head and from the keys.
  key('T', {shift: true, code: 'KeyT'});
  same(shown(), ['graph', 'lineage']);
  assert.equal($('#flow-toggle-timeline').getAttribute('aria-pressed'), 'false');
  $('#flow-toggle-timeline').dispatchEvent(new window.Event('click'));
  same(shown(), ['graph', 'lineage', 'timeline']);
  key('L', {shift: true, code: 'KeyL'});
  same(shown(), ['graph', 'timeline']);
  key('L', {shift: true, code: 'KeyL'});
  key('C', {shift: true, code: 'KeyC'});
  same(shown(), ['graph', 'cfg', 'lineage', 'timeline']);
  key('C', {shift: true, code: 'KeyC'});
  same(shown(), ['graph', 'lineage', 'timeline']);
  // Typing, modifiers and handled keys never reach the workspace.
  const input = document.createElement('input'); $('#flow-pane-lineage').append(input);
  key('T', {shift: true, code: 'KeyT', target: input});
  key('z', {target: $('#trace-request')});
  key('1', {meta: true});
  same(shown(), ['graph', 'lineage', 'timeline']);
  const handled = new window.Event('keydown', {bubbles: true, cancelable: true});
  Object.assign(handled, {key: 'z', code: 'KeyZ'}); handled.preventDefault();
  $('#flow-pane-graph').dispatchEvent(handled);
  assert.equal(workspace.state().mode, 'split', 'a key a canvas already handled is left alone');
  input.remove();
}
{
  // A timeline sample links every pane: the trail, the CFG block, the graph mark.
  graphCalls.length = 0; viewCalls.length = 0;
  const sample = document.querySelectorAll('#flow-timeline .flow-tl-sample')[1];
  sample.dispatchEvent(new window.Event('click'));
  await settle();
  same(workspace.trail().map(crumb => crumb.label), ['POST collect.frame.test #73', 'call #12', 'run', '+0x45 br_table', 'sample 2'], 'the function is named from its module, once read');
  assert.equal(fetches.filter(url => url.startsWith('/api/wasm/functions')).length, 1);
  assert([...document.querySelectorAll('#flow-trail .flow-crumb')].some(crumb => crumb.textContent === 'run'), 'the drawn trail shows the name');
  same(graphCalls.find(call => call[0] === 'setMark'), ['setMark', {artifact_id: '4', function_index: 1, offset: 69}]);
  assert(fetches.some(url => url === '/api/wasm/graph?artifact_id=4&function=1'), 'the CFG reads the sample function as Sources does');
  same(viewCalls.find(call => call[0] === 'select'), ['select', 1, 3], 'the block and row holding the byte offset are marked');
  same(shown(), ['graph', 'lineage', 'timeline'], 'a CFG the researcher hid with Shift C stays hidden when a sample is picked');
  assert.equal(workspace.follow(), 'cfg', 'Enter follows a sample into the CFG');
  same(shown(), ['graph', 'cfg', 'lineage', 'timeline'], 'and following opens it beside the graph');
  assert.equal($('#flow-cfg-samples').hidden, false);
  assert.match($('#flow-cfg-samples').textContent, /sample 2 of 5/);
  assert.match($('#flow-lineage-selected').textContent, /sample 2 of 5 · call #12 · selector 0/);
  assert.equal(document.querySelectorAll('#flow-lineage-selected .flow-histogram li').length, 3, 'the selector histogram has one bar per value');
  // K and J in the CFG step samples at the site.
  key('j', {target: $('#flow-pane-cfg')});
  assert.equal(workspace.selection().sample.label, 'sample 3');
  key('k', {target: $('#flow-pane-cfg')});
  assert.equal(workspace.selection().sample.label, 'sample 2');
  assert.equal(runs, 1, 'stepping within one function reuses its layout');
}
{
  // Trail and history: Back and Forward walk selections and pane jumps.
  const before = workspace.history();
  key('Backspace', {target: $('#flow-pane-cfg')});
  assert.equal(workspace.selection().sample.label, 'sample 3');
  key('Backspace', {shift: true, target: $('#flow-pane-cfg')});
  assert.equal(workspace.selection().sample.label, 'sample 2');
  assert.equal(workspace.history().entries, before.entries, 'walking the trail adds no entries');
  // A crumb jumps to its item in its pane and records the jump.
  const callCrumb = [...document.querySelectorAll('#flow-trail .flow-crumb')].find(crumb => crumb.textContent === 'call #12');
  callCrumb.dispatchEvent(new window.Event('click'));
  assert.equal(workspace.state().active, 'timeline');
  $('#flow-back').dispatchEvent(new window.Event('click'));
  assert.notEqual(workspace.state().active, 'timeline', 'Back undoes a jump between panes');
  assert.equal(workspace.selection().sample.label, 'sample 2', 'and a pane jump never changes the selection');
}
{
  // Focus mode: one pane, its tab, the Related rail; Z restores the split exactly.
  const split = workspace.state();
  key('2');
  assert.equal(workspace.state().active, 'cfg', '2 moves keyboard focus to the CFG in the split');
  assert.equal(workspace.state().mode, 'split');
  key('z', {target: $('#flow-pane-cfg')});
  assert.equal(workspace.state().mode, 'focus');
  same(shown(), ['cfg']);
  assert.equal($('#flow-tabs').hidden, false);
  assert.equal($('#flow-tab-cfg').getAttribute('aria-selected'), 'true');
  assert.equal($('#flow-tab-cfg .flow-tab-meta').textContent, 'run');
  assert.equal($('#flow-pane-toggles').hidden, true); assert.equal($('#flow-split').hidden, false);
  assert.equal($('#flow-related').hidden, false);
  assert.match($('#flow-related').textContent, /Timeline · sample 2 of 5/);
  assert.match($('#flow-related').textContent, /\+0x45 br_table/);
  key('3');
  same(shown(), ['lineage'], '3 switches the focused pane');
  key('4');
  same(shown(), ['timeline']);
  key('z');
  assert.equal(workspace.state().mode, 'split');
  same(workspace.state().split, split.split, 'the split returns with the same panes');
  same(workspace.state().sizes, split.sizes, 'and the same sizes');
  // A pane's focus button and a double-click on its head do the same.
  $('#flow-pane-lineage .flow-focus-button').dispatchEvent(new window.Event('click'));
  same(shown(), ['lineage']);
  $('#flow-split').dispatchEvent(new window.Event('click'));
  $('#flow-pane-graph .flow-pane-head').dispatchEvent(new window.Event('dblclick', {bubbles: true}));
  same(shown(), ['graph']);
  key('z');
}
{
  // The graph's selection API: a Wasm card opens its CFG; follow reveals it.
  graphCalls.length = 0; viewCalls.length = 0;
  workspace.graphSelected({key: 'wasm|12||2||send|||', kind: 'wasm', name: 'send', artifact_id: '4', function_index: 2, row: {index: 0, site: '+0x4b', op: 'call', target: 'hash'}, request: null});
  await settle();
  same(workspace.trail().slice(2).map(crumb => crumb.label), ['send', '+0x4b call']);
  assert(fetches.includes('/api/wasm/graph?artifact_id=4&function=2'));
  workspace.graphFollowed({key: 'wasm|12||2||send|||', kind: 'wasm', name: 'send', artifact_id: '4', function_index: 2, row: null, request: null});
  await settle();
  assert.equal(workspace.state().active, 'cfg');
  // A CFG error is explicit and offers Retry.
  graphFailure = true;
  workspace.graphSelected({key: 'k9', kind: 'wasm', name: 'imp', artifact_id: '4', function_index: 9, row: null, request: null});
  await settle();
  same(viewCalls.filter(call => call[0] === 'setState').at(-1), ['setState', 'error', 'function 9 is imported']);
  graphFailure = false;
  // A user block pick sets the site; the graph card is marked at its start.
  viewOptions.onSelect(0x39, 1, cfgResult().graph);
  assert.equal(workspace.selection().site.label, 'loc_39');
  // A JavaScript card is a crumb but opens no CFG.
  workspace.graphSelected({key: 'js|1|10|5|||init|||', kind: 'javascript', name: 'init', row: null, request: {process: 41, request: '71'}});
  assert.equal(workspace.trail().at(-1).label, 'init');
  assert.equal(workspace.trail().at(-1).pane, 'graph');
  // Enter on the pane (not a control) follows the selection.
  workspace.graphSelected(null);
  key('Enter', {target: $('#flow-pane-graph')});
  assert.equal(workspace.state().active, 'lineage', 'with no Wasm function chosen, Enter follows the request into Lineage');
  // Lineage: a renderer request step lights that request in the graph.
  graphCalls.length = 0;
  workspace.lineageSelected({key: '41:9', step: {relation: 'request_initiator', confidence: 'observed', category: 'network', operation: 'request_initiated', request_id: '73', event: {process_id: 41, sequence_number: '9'}}});
  same(graphCalls.find(call => call[0] === 'highlightRequest'), ['highlightRequest', {process: 41, request: '73'}]);
  // A tracked call's start step selects its track.
  workspace.lineageSelected({key: '41:101', step: {relation: 'issued_during_invocation', confidence: 'observed', category: 'vm', operation: 'js_invocation_start', request_id: '0', event: {process_id: 41, sequence_number: '101'}}});
  assert.equal(workspace.selection().call.label, 'call #12');
  // A request chip selects its request in the app.
  appCalls.length = 0;
  document.querySelector('#flow-timeline .flow-tl-chip').dispatchEvent(new window.Event('click'));
  same(appCalls, [['selectRequest', 'r0']]);
}
{
  // Without the selection API the workspace still runs.
  const bare = context.createFlowWorkspace({root: parseHTML(html).document.querySelector('#screen-backtrace'), graph: {show() {}, hide() {}}, fetch: fetchStub,
    createBlockGraphView: makeView, createBlockGraphRunner: runner, getRequest: () => null});
  assert.doesNotThrow(() => { bare.graphSelected({key: 'a', kind: 'wasm', name: 'f', artifact_id: '4', function_index: 1, row: null, request: null}); bare.relayout(); bare.back(); });
  assert.doesNotThrow(() => context.createFlowWorkspace({root: parseHTML(html).document.querySelector('#screen-backtrace'), graph: null, storage: {getItem() { throw Error('blocked'); }, setItem() { throw Error('blocked'); }}}).togglePane('cfg'),
    'storage that throws is optional');
}
{
  // Laptop: the CFG is a tab beside Lineage and the timeline is a strip that opens on demand.
  layout = 'laptop';
  workspace.relayout();
  assert.equal(workspace.state().layout, 'laptop');
  workspace.reveal('lineage');
  assert.equal($('#flow-tab-lineage-cfg').hidden, false);
  assert.equal($('#flow-timeline-open').hidden, false, 'the laptop strip has an Open and Close control');
  if ($('#flow-body').dataset.timelineOpen === 'true') $('#flow-timeline-open').dispatchEvent(new window.Event('click'));
  assert.equal($('#flow-body').dataset.timelineOpen, 'false');
  assert.equal($('#flow-timeline-open').textContent, 'Open');
  workspace.reveal('cfg');
  assert.equal($('#flow-body').dataset.sideTab, 'cfg');
  same(shown(), ['graph', 'cfg', 'lineage', 'timeline'], 'the lineage head keeps the tabs above the CFG');
  $('#flow-tab-lineage-details').dispatchEvent(new window.Event('click'));
  assert.equal($('#flow-lineage-details').hidden, false); assert.equal($('#flow-lineage-list').hidden, true);
  $('#flow-tab-lineage-list').dispatchEvent(new window.Event('click'));
  key('4');
  assert.equal($('#flow-body').dataset.timelineOpen, 'true');
  // Narrow: one pane at a time behind the pane switch; the selection stays.
  layout = 'compact';
  const selection = workspace.selection();
  workspace.relayout();
  assert.equal($('#flow-body').dataset.mode, 'single');
  assert.equal(shown().length, 1);
  assert.equal($('#flow-tabs').hidden, false);
  $('#flow-tab-graph').dispatchEvent(new window.Event('click', {bubbles: true}));
  same(shown(), ['graph']);
  key('3');
  same(shown(), ['lineage']);
  same(workspace.selection(), selection, 'switching pane or layout never changes the selection');
  layout = 'wide';
  workspace.relayout();
  assert.equal($('#flow-body').dataset.mode, 'split');
}
{
  // Sizes and toggles are remembered per session, bounded, and ignore bad input.
  const divider = $('#flow-pane-lineage .flow-divider');
  const press = (name, shift = false) => { const event = new window.Event('keydown', {bubbles: true, cancelable: true}); Object.assign(event, {key: name, shiftKey: shift}); divider.dispatchEvent(event); };
  press('ArrowLeft', true);
  assert.equal(workspace.state().sizes.lineage, 390);
  const saved = JSON.parse(storage.get(workspaceModule.FLOW_WORKSPACE_STORAGE));
  assert.equal(saved.sessions['7'].sizes.lineage, 390);
  press('Home');
  assert.equal(workspace.state().sizes.lineage, workspaceModule.FLOW_SIZE_DEFAULTS.lineage);
  same(workspaceModule.flowWorkspaceSizes({sizes: {cfg: 'x', lineage: 9999, timeline: 300}}), {...workspaceModule.FLOW_SIZE_DEFAULTS, timeline: 300});
  same(workspaceModule.flowWorkspacePrefs({getItem: () => '{not json'}).sessions, {});
  for (let index = 0; index < 20; index += 1) { workspace.sync({visible: true, session: String(100 + index), request: null}); workspace.togglePane('timeline'); workspace.togglePane('timeline'); }
  assert.equal(Object.keys(JSON.parse(storage.get(workspaceModule.FLOW_WORKSPACE_STORAGE)).sessions).length, 16, 'at most 16 sessions are remembered');
}
{
  // Timeline states: paging, partial, error with and without a previous model, empty.
  const root = document.createElement('div');
  const pages = [];
  const view = context.createFlowTimeline({root, fetchJSON: async url => { const next = pages.shift(); if (next instanceof Error) throw next; next.url = url; return next; }});
  pages.push(page(sessionRecords().slice(0, 5), {limited: true, next_after: '500'}), page(sessionRecords().slice(5), {limited: false}));
  await view.load('7');
  assert.equal(view.status(), 'ready'); assert.equal(view.isPartial(), false);
  assert.equal(view.model().counts.records, 13, 'two pages are read in order');
  const limits = {...timeline.FLOW_TIMELINE_LIMITS, pagesPerRead: 1};
  const partial = context.createFlowTimeline({root: document.createElement('div'), limits, fetchJSON: async () => page(sessionRecords(), {limited: true, next_after: '700'})});
  await partial.load('7');
  assert.equal(partial.isPartial(), true);
  assert.match(partial.summary(), /partial$/);
  const failing = context.createFlowTimeline({root: document.createElement('div'), fetchJSON: async () => { throw Error('Event store returned 503'); }});
  await failing.load('7');
  assert.equal(failing.status(), 'error');
  pages.push(new Error('Event store returned 500'));
  await view.load('7');
  assert.equal(view.status(), 'ready', 'a failed refresh keeps the last records');
  assert.match(root.querySelector('.flow-tl-banner').textContent, /Could not refresh tracked calls: Event store returned 500/);
  pages.push(page([]));
  await view.load('8');
  assert.equal(view.status(), 'empty');
  assert.match(root.querySelector('.flow-tl-state').textContent, /No tracked calls in this session/);
  pages.push({events: 'nope'});
  const malformed = context.createFlowTimeline({root: document.createElement('div'), fetchJSON: async () => ({events: 'nope'})});
  await malformed.load('7');
  assert.equal(malformed.status(), 'error', 'a malformed page is an error, not an empty session');
}
{
  // Shipped-source rules.
  const [js1, js2, css, app] = await Promise.all(['flow_timeline.js', 'flow_workspace.js', 'flow_workspace.css', 'app.js'].map(read));
  assert(!/innerHTML|insertAdjacentHTML|document\.write|outerHTML/.test(js1 + js2), 'captured text is never inserted as HTML');
  assert(!/\u2014/.test(js1 + js2 + css + html), 'no em dash characters');
  assert(!/setInterval\(/.test(js1 + js2), 'no repeating timers');
  const outsideRoot = css.replace(/:root(\[data-theme="light"\])? \{[^}]*\}/g, '');
  assert(!/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/.test(outsideRoot), 'colours are tokens defined in the :root blocks');
  assert(/@container flow-screen \(min-width: 900px\)/.test(css) && /@container flow-screen \(min-width: 1240px\)/.test(css), 'the layout adapts by container queries');
  const order = ['block_graph.js', 'flow_graph.js', 'flow_timeline.js', 'flow_workspace.js', 'app.js'].map(name => html.indexOf(`src="${name}"`));
  assert(order.every((at, index) => at > 0 && (!index || at > order[index - 1])), 'the panes load after their views and before app.js');
  assert(html.includes('href="flow_workspace.css"'));
  assert(/data-screen="backtrace" aria-label="Flow"[^>]*title="Flow \(⌘ \/ Ctrl \+ 5\)"/.test(html), 'the screen is Flow in the sidebar');
  assert(!/Backtraces?\b/.test(html.replace(/<!--[\s\S]*?-->/g, '')), 'no visible Backtraces label remains');
  assert(/typeof flowWorkspace !== 'undefined'/.test(app), 'extracted app.js sections run without the workspace');
  assert(!/trace-mode-steps|state\.traceMode/.test(app), 'the Steps and Flow graph toggle is gone');
  for (const [path, assets] of [['scripts/build-research-app.sh', ['flow_timeline.js', 'flow_workspace.js', 'flow_workspace.css']], ['apps/origin-trace-backend/src/app.rs', ['"flow_timeline.js"', '"flow_workspace.js"', '"flow_workspace.css"']],
    ['apps/research-ui/macos/OriginTraceApp.swift', ['/flow_timeline.js', '/flow_workspace.js', '/flow_workspace.css']]]) {
    const source = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    for (const asset of assets) assert(source.includes(asset), `${path} ships ${asset}`);
  }
}
console.log('PASS Flow workspace: timeline model with and without decoded invocations, bounds and counts, paging and states, pane toggles, focus and exact restore, tabs and number keys, trail and history, graph, CFG, lineage and timeline linking, adaptive layouts, per-session sizes (offline DOM model, not rendered QA)');
