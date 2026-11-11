// Flow workspace: the tracked-call timeline model and its bounds, paging and
// states, and the workspace controller on the shipped index.html markup with
// a stub flow graph panel and a stub block graph view: pane toggles, focus
// mode and its exact restore, tabs and number keys, the trail and its history,
// linking between panes, storage, and the shipped-source rules. Offline DOM
// model only (LinkeDOM); rendered acceptance is the packaged-app gate.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
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
// The decode's own shape (protocol/native-js-invocation-v1.md): names, not stored integers.
const SITE_SHA = 'a'.repeat(64);
function sessionRecords({decoded = true} = {}) {
  seq = 100;
  const strip = event => { if (!decoded && event.js_invocation) { const {js_invocation: _drop, ...rest} = event; return rest; } return event; };
  return [
    js('js_invocation_start', {kind: 'start', site_slot: 0, invocation_id: 12, parent_invocation_id: 0, parent_unknown: false, argument_count: 2, source_sha256: SITE_SHA, anchor_offset: 2380}),
    js('js_invocation_request', {kind: 'request', invocation_id: 12, inside: true, request_id: '71'}),
    js('js_invocation_start', {kind: 'start', site_slot: 0, invocation_id: 13, parent_invocation_id: 0, parent_unknown: false, argument_count: 2, source_sha256: SITE_SHA, anchor_offset: 2380}),
    wasm(3, 12), wasm(0, 12), wasm(3, 12),
    js('js_invocation_settle', {kind: 'settle', site_slot: 0, invocation_id: 12, fulfilled: true, value_kind: 'string', value_length: 2148, via: 'promise'}),
    wasm(1, 13), wasm(3, 13),
    js('js_invocation_request', {kind: 'request', invocation_id: 13, inside: true, request_id: '73'}),
    js('js_invocation_settle', {kind: 'settle', site_slot: 0, invocation_id: 13, fulfilled: true, value_kind: 'undefined', value_length: 0, via: 'sync_return'}),
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
  assert.equal(call13.settle.via, 'sync_return', 'a synchronous settle is kept so the span can be drawn as running');
  assert.equal(timeline.flowValueLabel('array_buffer_view', 4), 'typed array · 4 bytes', 'decoded kind names read as the panel words');
  assert.ok(timeline.flowValueLabel('bigint', null).startsWith('BigInt'));
  assert.ok(timeline.flowValueLabel(8, null).startsWith('BigInt'), 'the stored integer still reads for an older decode');
  // The site route names no session, so its labels are never applied: a
  // track is its invocation, and its slot and site key stay in the detail.
  assert.equal(timeline.flowTrackName(call12), 'call #12');
  assert.equal(timeline.flowTimelineLabel, undefined, 'no slot or site label is joined from the armed site list');
  same(call12.start.site, {sha256: SITE_SHA, anchor: 2380});
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
  assert.deepEqual(model.counts, {records: 13, starts: 2, settles: 2, requests: 3, samples: 6, outside: 1, invalid: 0, undecoded: 0, duplicates: 0, conflicts: 0, gaps: 0, overflow: 0});
  assert.equal(view.gaps.records, 0);
  assert.equal(timeline.flowSampleCount(site.samples[2], site), 'sample 3 of 5 read', 'a count names the records read, nothing more');
}
// Budget refusals and losses: gap markers (named and queue drops) and overflow
// identities, in the session's vm records.
const hex = text => Buffer.from(text, 'latin1').toString('hex');
const gapEvent = payload => base('gap', {category: 'vm', payload: hex(payload), payload_truncated: false});
const overflow = (row, type = 'wasm_dispatch_overflow') => base(type, {wasm_overflow: {status: 'decoded', ...row}});
function gapRecords() {
  const records = sessionRecords();
  return [...records,
    gapEvent('native_wasm_dispatch_budget_incomplete'), gapEvent('native_js_invocation_budget_incomplete'), gapEvent('3'),
    overflow({kind: 'identity', ring_index: 0, function_index: 1, module_byte_offset: 69, selector: 2, arm_count: 3}),
    overflow({kind: 'omitted', omitted_count: 40}), {...overflow({kind: 'omitted', omitted_count: 25}), sequence_number: '900'},
    base('wasm_indirect_overflow', {})];
}
{
  const model = timeline.flowTimelineModel(gapRecords());
  const view = model.processes[0];
  assert.equal(model.counts.gaps, 3); assert.equal(model.counts.overflow, 4);
  same(view.gaps.named.map(entry => [entry.reason, entry.stream, entry.count]), [['native_wasm_dispatch_budget_incomplete', 'br_table', 1], ['native_js_invocation_budget_incomplete', 'calls', 1]]);
  assert.equal(view.gaps.dropped, 3n, 'a decimal gap payload weighs its count');
  same(view.gaps.overflow.br_table, {identities: 1, omitted: 40, undecoded: 0}, 'several omitted records are a floor, never a sum');
  same(view.gaps.overflow.call_indirect, {identities: 0, omitted: 0, undecoded: 1}, 'an overflow record the backend does not decode still counts');
  const site = view.sites.get('4:1:69:br_table');
  assert.equal(site.refused, 1, 'an overflow identity counts against the site at its function and offset');
  assert.equal(timeline.flowSampleCount(site.samples[2], site), 'sample 3 of 5 read, more refused here');
  const indirect = view.sites.get('4:1:90:call_indirect');
  assert.equal(timeline.flowSampleCount(indirect.samples[0], indirect), 'sample 1 of 1 read, not every execution', 'a stream with refusals never reads as complete');
  assert.equal(view.drawnGaps.length, 7, 'every gap and overflow record is a mark at its sequence');
  const notes = timeline.flowGapNotes(view.gaps).join('; ');
  assert.match(notes, /native_wasm_dispatch_budget_incomplete \u00d71 \(a sampling budget filled/);
  assert.match(notes, /native_js_invocation_budget_incomplete \u00d71 \(the 256-call budget filled; later calls were not recorded\)/);
  assert.match(notes, /br_table executions the sample budget refused: 1 named in overflow records, at least 40 more omitted/);
  assert.match(notes, /call_indirect executions the sample budget refused: 1 overflow record this backend does not decode/);
  assert.match(notes, /3 records dropped by a full queue/);
  same(timeline.flowGapRecord({payload: hex('Not A Reason'), category: 'vm'}, 'k', 1n).reason, null, 'only an identifier payload names a reason');
  same(timeline.flowGapRecord({payload: hex('native_wasm_dispatch_budget_incomplete'), payload_truncated: true, category: 'vm'}, 'k', 1n).reason, null, 'a cut payload names nothing');
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
  assert.deepEqual(view.hidden, {tracks: 2, samples: 10, requests: 2, gaps: 0}, '8 samples of hidden tracks plus 2 over the drawing budget');
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
// The function body starts at 0x35 (its locals); the entry block at 0x37.
const cfgResult = () => ({graph: {count: 3, offsets: [0x37, 0x39, 0x4b], ends: [0x39, 0x4b, 0x50], firstRow: [0, 1, 4], rowCount: [1, 3, 1], rows, byteOffset: 0x35}, starts, layout: {}});
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
  openSource: target => appCalls.push(['openSource', target.artifact_id, target.offset])
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
  assert.equal(read.searchParams.get('type'), 'wasm_dispatch_observation,wasm_indirect_observation,wasm_dispatch_overflow,wasm_indirect_overflow,js_invocation_start,js_invocation_settle,js_invocation_request,gap',
    'the read takes the budget refusals and gap markers beside the observations');
  assert.equal(read.searchParams.get('category'), 'vm', 'and only vm records, so other producers\u2019 gap markers stay out');
  assert.equal($('#flow-timeline .flow-tl-gaps').hidden, true, 'a session without gaps shows no gap notice');
  assert.equal(read.searchParams.get('limit'), '1000');
  assert.equal(workspace.timeline.status(), 'ready');
  assert.match(workspace.timeline.summary(), /^2 calls · 6 samples · renderer 41 record order$/);
  assert.equal(document.querySelectorAll('#flow-timeline .flow-tl-sample').length, 6);
  assert.equal(document.querySelectorAll('#flow-timeline .flow-tl-chip').length, 3);
  assert.equal(document.querySelectorAll('#flow-timeline .flow-tl-run').length, 1, 'only the synchronous settle draws a running span');
  const run = document.querySelector('#flow-timeline .flow-tl-run');
  assert.match(run.title, /^Settled synchronously: it returned or threw without a promise/);
  assert.match(run.title, /Samples and requests on this track were recorded inside it/, 'the span says records inside it were made while it ran');
  assert(!/before any other record/.test(run.title), 'and never that nothing else was recorded');
  assert(!fetches.some(url => url.startsWith('/api/js-invocation-sites')), 'the armed site list, which names no session, is not read for labels');
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
  assert.match($('#flow-lineage-selected').textContent, /sample 2 of 5 read · call #12 · selector 0/);
  assert.equal(document.querySelectorAll('#flow-lineage-selected .flow-histogram li').length, 3, 'the selector histogram has one bar per value');
  // K and J in the CFG step samples at the site.
  key('j', {target: $('#flow-pane-cfg')});
  assert.equal(workspace.selection().sample.label, 'sample 3');
  key('k', {target: $('#flow-pane-cfg')});
  assert.equal(workspace.selection().sample.label, 'sample 2');
  assert.equal(runs, 1, 'stepping within one function reuses its layout');
  // Sources opens the module at the function's first byte, not the marked block.
  appCalls.length = 0;
  $('#flow-pane-cfg .flow-cfg-source').dispatchEvent(new window.Event('click'));
  same(appCalls, [['openSource', '4', 0x35]], 'the CFG\u2019s Sources button names the function body\u2019s first byte');
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
  // A new pick keeps only the crumbs that are its recorded relationships:
  // call #13 after a sample in #12 drops #12's function, site and sample.
  document.querySelector('#flow-timeline [data-key="call:41:13"]').dispatchEvent(new window.Event('click'));
  same(workspace.trail().map(crumb => crumb.label), ['POST collect.frame.test #73', 'call #13'], 'a call keeps only itself under the request');
  same([workspace.selection().fn, workspace.selection().site, workspace.selection().sample, workspace.selection().graphKey], [null, null, null, null]);
  // Back to the sample, for the checks that follow.
  document.querySelectorAll('#flow-timeline .flow-tl-sample')[1].dispatchEvent(new window.Event('click'));
  await settle();
  same(workspace.trail().map(crumb => crumb.label), ['POST collect.frame.test #73', 'call #12', 'run', '+0x45 br_table', 'sample 2']);
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
  // Z never leaves focus in a pane the split hides: a pane switched to in
  // focus mode that the split does not show hands focus back to the pane
  // focused before focus mode.
  key('T', {shift: true, code: 'KeyT'});
  same(shown(), ['graph', 'cfg', 'lineage'], 'Shift T hides the timeline');
  key('3');
  assert.equal(workspace.state().active, 'lineage');
  key('z', {target: $('#flow-pane-lineage')});
  key('4');
  same(shown(), ['timeline'], 'focus mode shows the timeline the split hides');
  assert.equal(workspace.state().active, 'timeline');
  appCalls.length = 0;
  key('z', {target: $('#flow-pane-timeline')});
  same(shown(), ['graph', 'cfg', 'lineage'], 'the split returns without the timeline');
  assert.equal(workspace.state().active, 'lineage', 'and the pane focused before focus mode is active again');
  same(appCalls, [['focusTraceRow']], 'with keyboard focus on its working row');
  key('T', {shift: true, code: 'KeyT'});
  same(shown(), ['graph', 'cfg', 'lineage', 'timeline'], 'Shift T shows it again');
}
{
  // The graph's selection API: a Wasm card opens its CFG; follow reveals it.
  graphCalls.length = 0; viewCalls.length = 0;
  workspace.graphSelected({key: 'wasm|12||2||send|||', kind: 'wasm', name: 'send', artifact_id: '4', function_index: 2, row: {index: 0, site: '+0x4b', op: 'call', target: 'hash'}, request: null});
  await settle();
  same(workspace.trail().map(crumb => crumb.label), ['POST collect.frame.test #73', 'send', '+0x4b call'], 'a card keeps its function and row and drops the earlier sample\u2019s call, function, site and sample');
  assert.equal(workspace.timeline.selection(), null, 'and the timeline lets go of the sample');
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
  // A JavaScript card has no recorded relationship to that call.
  workspace.graphSelected({key: 'js|1|10|5|||init|||', kind: 'javascript', name: 'init', row: null, request: null});
  same(workspace.trail().map(crumb => crumb.label), ['POST collect.frame.test #73', 'init'], 'a JavaScript card drops the old call crumb');
  // A request chip selects its request in the app, keeps the call it was
  // issued in and drops the card; with a sample picked, the sample goes too.
  document.querySelectorAll('#flow-timeline .flow-tl-sample')[1].dispatchEvent(new window.Event('click'));
  await settle();
  appCalls.length = 0;
  document.querySelector('#flow-timeline .flow-tl-chip').dispatchEvent(new window.Event('click'));
  same(appCalls, [['selectRequest', 'r0']]);
  same(workspace.trail().map(crumb => crumb.label), ['GET frame.test #71', 'call #12'], 'the chip\u2019s request and call, and no old sample');
  assert.equal(workspace.selection().step, null, 'the old request\u2019s lineage step goes with it');
  assert.equal(workspace.timeline.selection()?.type, 'request');
  // The app catching up with the same request renames it without a trail entry.
  const named = workspace.history().entries;
  appRequest = {id: 'r0', label: 'GET frame.test #71', method: 'GET', path: '/', status: 200, renderer: {process: 41, request: '71'}};
  workspace.sync({visible: true, session: '7', request: appRequest});
  assert.equal(workspace.history().entries, named, 'the same request again is not a new pick');
}
{
  // A key the workspace queued before layout comes back `requested`: it is
  // not a pick, so a restored sample, the history and Forward all stay.
  const sampleKey = document.querySelectorAll('#flow-timeline .flow-tl-sample')[0].dataset.key;
  workspace.timeline.select(sampleKey, {silent: false});
  const held = workspace.selection(), entries = workspace.history();
  workspace.graphSelected({key: 'wasm|queued', kind: 'wasm', name: 'send', artifact_id: '4', function_index: 2, row: null, request: null}, {requested: true});
  same(workspace.selection(), held, 'a requested graph selection changes no workspace selection');
  same(workspace.history(), entries, 'and records no trail entry');
  assert.equal(workspace.timeline.selection()?.key, sampleKey, 'and keeps the sample selected');
}
{
  // A lineage step that lights its request picks the card the graph selects
  // in answer: the trail, the CFG and one history entry follow it, and the
  // echo during the call cannot loop back into the graph.
  const before = workspace.history().entries;
  graphCalls.length = 0;
  const lit = {key: 'wasm|lit', kind: 'wasm', name: 'send', artifact_id: '4', function_index: 2, row: {index: 0, site: '+0x4b', op: 'call', target: 'hash'}, request: {process: 41, request: '73'}};
  graph.highlightRequest = key => { graphCalls.push(['highlightRequest', key]); workspace.graphSelected(lit); return true; };
  workspace.lineageSelected({key: '41:9', step: {relation: 'request_initiator', confidence: 'observed', category: 'network', operation: 'request_initiated', request_id: '73', event: {process_id: 41, sequence_number: '9'}}});
  await settle();
  assert.equal(workspace.selection().graphKey, 'wasm|lit', 'the lit card is the selection');
  assert.equal(workspace.selection().fn.key, 'wasm:4:2');
  assert.equal(workspace.selection().site.label, '+0x4b call');
  assert.equal(workspace.cfg().fn?.function_index, 2, 'its CFG opens');
  assert.equal(workspace.history().entries, before + 1, 'the step and its card are one trail entry');
  assert.equal(graphCalls.filter(call => call[0] === 'select').length, 0, 'nothing selects back into the graph');
  // A caller in the Related rail is a pick too: the graph selects it, and the
  // workspace follows with its CFG and a trail entry.
  graph.select = (key, options) => {
    graphCalls.push(['select', key, options]);
    workspace.graphSelected({key, kind: 'wasm', name: 'bridge', artifact_id: '4', function_index: 1, row: null, request: null, callers: [], callees: []});
    return true;
  };
  workspace.graphSelected({...lit, callers: [{key: 'wasm|bridge', name: 'bridge', kind: 'wasm', note: 'call', count: 2}], callees: []});
  key('z', {target: $('#flow-pane-graph')});
  const entries = workspace.history().entries;
  const caller = [...document.querySelectorAll('#flow-related .flow-related-item')].find(item => item.textContent.startsWith('called by bridge'));
  assert(caller, 'the Related rail lists the caller');
  graphCalls.length = 0;
  caller.dispatchEvent(new window.Event('click'));
  await settle();
  same(graphCalls.filter(call => call[0] === 'select').map(call => call[1]), ['wasm|bridge'], 'the graph is asked once, and its answer does not loop');
  assert.equal(workspace.selection().graphKey, 'wasm|bridge', 'the caller is the selection');
  assert.equal(workspace.selection().fn.key, 'wasm:4:1');
  assert.equal(workspace.cfg().fn?.function_index, 1, 'its CFG opens');
  assert.equal(workspace.history().entries, entries + 1, 'and one trail entry records the pick');
  key('z');
  graph.select = (...args) => { graphCalls.push(['select', ...args]); return true; };
  graph.highlightRequest = (...args) => { graphCalls.push(['highlightRequest', ...args]); return true; };
}
{
  // Switching sessions cancels a CFG read in flight: its graph, names and
  // decoded result never land in, or are reused by, the new session.
  let release = null, layouts = 0;
  const gate = new Promise(resolve => { release = resolve; });
  const drawn = [];
  const own = context.createFlowWorkspace({root: parseHTML(html).document.querySelector('#screen-backtrace'), graph: null, fetch: fetchStub, getRequest: () => null,
    createBlockGraphRunner: () => ({run: async () => { layouts += 1; await gate; return cfgResult(); }, cancel() {}}),
    createBlockGraphView: (host, options) => { const view = makeView(host, options); const set = view.setResult; view.setResult = next => { drawn.push(next); set(next); }; return view; }});
  eventPages.push(page([]), page([]));
  own.sync({visible: true, session: '7', request: null});
  const card = {key: 'wasm|own', kind: 'wasm', name: null, artifact_id: '4', function_index: 1, row: null, request: null};
  own.graphSelected(card);
  await settle();
  assert.equal(layouts, 1, 'the CFG layout is running');
  own.sync({visible: true, session: '8', request: null});
  release(); await settle();
  assert.equal(drawn.length, 0, 'the old session\u2019s graph is never drawn in the new one');
  same(own.cfg(), {fn: null, mark: null, loaded: false, error: null});
  own.graphSelected(card);
  await settle();
  assert.equal(layouts, 2, 'the same function in the new session is read and laid out again');
  assert.equal(drawn.length, 1);
}
{
  // Back to an entry with no request, or with one no longer listed: the app
  // keeps its request, and its next render is not a pick that truncates Forward.
  let shownRequest = null;
  const requestR = {id: 'rR', label: 'GET r.test #5', method: 'GET', path: '/r', renderer: {process: 41, request: '5'}};
  const selects = [];
  const own = context.createFlowWorkspace({root: parseHTML(html).document.querySelector('#screen-backtrace'), graph: null, fetch: fetchStub,
    createBlockGraphView: makeView, createBlockGraphRunner: runner, getRequest: () => shownRequest, selectRequest: id => selects.push(id)});
  eventPages.push(page([]));
  own.sync({visible: true, session: '7', request: null});
  own.graphSelected({key: 'js|a', kind: 'javascript', name: 'a', row: null, request: null});
  shownRequest = requestR;
  own.sync({visible: true, session: '7', request: shownRequest});
  own.graphSelected({key: 'js|b', kind: 'javascript', name: 'b', row: null, request: null});
  same(own.trail().map(crumb => crumb.label), ['GET r.test #5', 'b']);
  const full = own.history();
  own.back(); own.back();
  same(own.trail().map(crumb => crumb.label), ['a'], 'Back reaches the entry that had no request');
  own.sync({visible: true, session: '7', request: shownRequest});
  same(own.history(), {entries: full.entries, cursor: full.cursor - 2}, 'the app still showing its request records nothing and keeps Forward');
  same(own.trail().map(crumb => crumb.label), ['a'], 'and leaves the restored entry as it was');
  own.forward(); own.forward();
  same(own.trail().map(crumb => crumb.label), ['GET r.test #5', 'b'], 'Forward still reaches the end of the trail');
  // An entry whose request the app can no longer select holds the app's own.
  shownRequest = {id: 'rS', label: 'GET s.test #6', method: 'GET', path: '/s', renderer: {process: 41, request: '6'}};
  own.sync({visible: true, session: '7', request: shownRequest});
  own.back();
  assert.equal(selects.at(-1), 'rR', 'Back asks the app for the entry\u2019s request');
  const restored = own.history();
  own.sync({visible: true, session: '7', request: shownRequest});
  assert.equal(own.selection().request?.id, 'rR', 'the request the app could not select is kept in the entry');
  same(own.history(), restored, 'and the app\u2019s own request is not a pick');
  // Once the app selects another request, that is a pick again.
  own.sync({visible: true, session: '7', request: {...requestR, id: 'rT', label: 'GET t.test #7'}});
  assert.equal(own.selection().request?.id, 'rT');
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
  // A quiet refresh after Read more reads at least as far again: the view
  // never shrinks and a selection from the later page stays.
  {
    const reads = [];
    let clock = 0;
    const moreRoot = document.createElement('div');
    const paged = context.createFlowTimeline({root: moreRoot, limits, now: () => clock, fetchJSON: async url => {
      const after = new URL(url, 'http://fixture.invalid').searchParams.get('after');
      reads.push(after);
      return after === '0' ? page(sessionRecords().slice(0, 5), {limited: true, next_after: '500'}) : page(sessionRecords().slice(5), {limited: false, next_after: '900'});
    }});
    await paged.load('7');
    assert.equal(paged.isPartial(), true);
    assert.equal(moreRoot.querySelector('.flow-tl-banner-action').textContent, 'Read more');
    moreRoot.querySelector('.flow-tl-banner-action').onclick();
    await settle();
    assert.equal(paged.isPartial(), false); assert.equal(paged.model().counts.records, 13);
    const later = paged.select('sample:41:109');
    assert.equal(later?.sample.seq, 109n, 'a sample from the second page is selected');
    reads.length = 0; clock = 60000;
    paged.sync('7', {visible: true, staleAfter: 15000});
    await settle();
    same(reads, ['0', '500'], 'the quiet refresh reads from the start through every page held');
    assert.equal(paged.isPartial(), false, 'and stays complete');
    assert.equal(paged.model().counts.records, 13, 'with every record it held');
    assert.equal(paged.selection()?.key, 'sample:41:109', 'and the selection it could read');
  }
  // A selected sample past the drawing budget keeps one tab stop, on the
  // drawn item nearest it, and the detail line says why it is not drawn.
  {
    const budgetRoot = document.createElement('div');
    const budgeted = context.createFlowTimeline({root: budgetRoot, limits: {...timeline.FLOW_TIMELINE_LIMITS, maxSamples: 3}, fetchJSON: async () => page(sessionRecords())});
    await budgeted.load('7');
    // LinkeDOM reflects tabindex as an attribute only.
    const stops = () => [...budgetRoot.querySelectorAll('[data-key]')].filter(item => item.getAttribute('tabindex') === '0');
    assert.equal(stops().length, 1, 'one tab stop before anything is selected');
    budgeted.select('sample:41:106', {silent: false});
    assert.equal(budgeted.stepSample(1)?.key, 'sample:41:108', 'J steps to the next sample at the site, drawn or not');
    assert.equal(budgetRoot.querySelector('[data-key="sample:41:108"]'), null, 'that sample is past the drawing budget');
    assert.equal(stops().length, 1, 'exactly one item keeps the tab stop');
    assert.equal(stops()[0].dataset.key, 'sample:41:106', 'the drawn sample nearest the selected one in record order');
    assert.match(budgetRoot.querySelector('.flow-tl-detail-text').textContent, /seq 108 · renderer 41 · not drawn: past the 3 samples drawn for this renderer$/);
    assert.equal(budgeted.focus(), true, 'focus lands on the tab stop');
  }
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
  // Gaps: the notice names this renderer's refusals and losses and the
  // scanned range's counters; a lane marks them in record order; samples
  // and the break mark never claim more than the records say.
  const gapRoot = document.createElement('div');
  const gapped = context.createFlowTimeline({root: gapRoot, fetchJSON: async () => ({...page(gapRecords()), sequence_gaps: '4', sequence_gaps_saturated: false, queue_drops: '2', queue_drops_saturated: true,
    named_gaps: [{category: 'vm', reason: 'native_wasm_dispatch_budget_incomplete', count: '1'}]})});
  await gapped.load('7');
  const notice = gapRoot.querySelector('.flow-tl-gaps');
  assert.equal(notice.hidden, false);
  assert.match(notice.textContent, /^Gaps in renderer 41: native_wasm_dispatch_budget_incomplete \u00d71/);
  assert.match(notice.textContent, /In the store range read, across every session and record type: 4 sequence numbers missing, 2 or more records dropped by a full queue\./);
  const counters = gapped.scanGaps();
  assert.deepEqual([counters.sequence, counters.sequenceSaturated, counters.drops, counters.dropsSaturated], [4n, false, 2n, true], 'the page counters are summed as exact integers');
  assert.match(gapped.summary(), / · gaps$/, 'the pane head says the renderer has gaps');
  const lane = gapRoot.querySelector('.flow-tl-row-gaps');
  assert(lane, 'a Gaps lane is drawn');
  assert.equal(lane.querySelectorAll('.flow-tl-gap').length, 7);
  assert.match(lane.querySelector('.flow-tl-gap').title, /^native_wasm_dispatch_budget_incomplete \(/);
  const refusedSample = [...gapRoot.querySelectorAll('.flow-tl-sample')].find(item => item.dataset.key.endsWith(':104'));
  assert.match(refusedSample.getAttribute('aria-label'), /^br_table sample 1 of 5 read \(1 more execution at this offset refused\)/);
  const breakMark = gapRoot.querySelector('.flow-tl-break');
  assert(breakMark, 'the fixture has a compressed run');
  assert.match(breakMark.title, /sequence numbers? between .* hold no record drawn here: records of other types, or numbers with no stored record/, 'a break never counts its numbers as records that exist');
  assert(!/records of this renderer lie between/.test(breakMark.title));
  pages.push({events: 'nope'});
  const malformed = context.createFlowTimeline({root: document.createElement('div'), fetchJSON: async () => ({events: 'nope'})});
  await malformed.load('7');
  assert.equal(malformed.status(), 'error', 'a malformed page is an error, not an empty session');
}
{
  // The app opens that byte: the shipped scripts in the offline DOM model,
  // a retained module whose hex view holds it, and the Sources reveal.
  const {loadShippedUi} = require('./check-native-only-startup.cjs');
  const timers = {setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout};
  const {window: shell, context: app, release} = loadShippedUi();
  try {
    // Layout leaves the DOM model lacks, as the Sources search check supplies them.
    Object.assign(shell, {NodeFilter: shell.NodeFilter ?? {SHOW_TEXT: 4}});
    shell.document.createRange = () => ({setStart() {}, setEnd() {}, getBoundingClientRect: () => ({left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0})});
    const bytes = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...Array(56).fill(0x0b)]);
    const hexText = runInContext('formatWasmHex', app)(new Uint8Array(bytes));
    app.flowModule = {protocol_version: 1, artifact_id: '301', session_id: '7', navigation_id: '1', frame_id: '1', parent_artifact_id: '0', creator_event_id: '0',
      execution_context_id: '0', capture_origin: 'network_response', kind: 'wasm', url: 'wasm://wasm/0a1b2c3d', mime_type: 'application/wasm', byte_size: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'), sensitive: false, origin: 'demo', content: hexText, sourceTextLength: hexText.length, wasmHexBytes: bytes.length,
      contentLossy: false, contentTruncated: false, contentVerified: true};
    runInContext(`state.artifacts = [flowModule]; showScreen('backtrace');`, app);
    assert.equal(runInContext(`flowWorkspaceOpenSource({artifact_id: '301', offset: 0x23})`, app), true);
    assert.equal(runInContext('state.selectedArtifactId', app), '301');
    assert.equal(runInContext('state.sourceReveal', app), null, 'the byte reveal is consumed once the module is held');
    assert.equal(runInContext('elements.sourcePosition.textContent', app), 'Byte 0x23 · hex row 0x20', 'Sources shows the hex row that holds the function\u2019s first byte');
    runInContext(`flowWorkspaceOpenSource({artifact_id: '301', offset: 0x400})`, app);
    assert.match(runInContext('elements.sourcePosition.textContent', app), /^Byte 0x400 is past the first/, 'a byte the view cannot show says so');
  } finally { release(); Object.assign(globalThis, timers); }
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
