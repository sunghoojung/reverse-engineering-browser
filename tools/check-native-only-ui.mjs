#!/usr/bin/env node
// Native-only shipped UI contract. Static source checks plus every shipped
// script executed in an offline DOM model; not rendered browser QA. Rendered
// layout/focus acceptance is the separate packaged-app WebKit gate.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile, readdir, access} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {runInContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const root = fileURLToPath(new URL('..', import.meta.url));
const ui = join(root, 'apps/research-ui');
const html = await readFile(join(ui, 'index.html'), 'utf8');
const css = await readFile(join(ui, 'app.css'), 'utf8');

// State that only a CDP debugger session ever populated. Reading it is dead
// code at best and a silent "unavailable" branch in the shipped UI at worst.
const removedState = ['debuggerSession', 'debuggerError', 'liveScriptContent', 'staleScriptIds', 'selectedScriptId',
  'openScriptIds', 'selectedRuntimeHookRequest', 'selectedCallFrameId', 'pendingSourceLine'];
const removedCalls = ['debuggerAction', 'refreshDebugger', 'scheduleDebuggerRefresh', 'loadScriptContent', 'toggleLineBreakpoint',
  'runExperimentAction', 'runMemoryOriginTrace', 'runCollectionRequest', 'installCapturedClientWorkflow', 'runtimeHooksState',
  'renderRuntimeHookTraffic', 'bindRuntimeFieldTest', 'renderWebSocketInspector', 'webSocketModel', 'selectScript',
  'markLiveSourceStale', 'breakpointLinesForSource', 'memoryOriginTraceActive', 'selectedCallFrame',
  'requestsFromDebuggerNetwork', 'trafficRowsForLiveCapture', 'isDebuggerResponse', 'isDebuggerNetwork', 'installApiObservationCatalog',
  'installTrafficCaptureExport', 'installPassiveSecurityReport', 'evidenceDebuggerRequest', 'devtoolsJoinedNativeEvents',
  // Native rows carry no CDP request/response exchange, call sites or live script catalog.
  'trafficExchange', 'createTrafficPane', 'trafficBodyModel', 'trafficHtmlPreview', 'trafficPaneSignature', 'renderTrafficComparison',
  'createTrafficComparisonController', 'syncTrafficComparison', 'trafficCompareRequests', 'openFieldProvenance', 'renderFieldProvenance',
  'decodedFieldCandidate', 'searchDecodedFieldSources', 'renderDecoderFieldOrigin', 'isFieldCallSites', 'vmLiveCatalogMatchesSession', 'vmLiveScriptRank'];
// Data shapes only a CDP session produced. Saved-capture documents keep their
// own captureRecord fields; these are reads of the live Traffic row or catalog.
const removedShapes = [[/\b(?:request|baseline|selected|left|right|value)\??\.exchange\b/, 'a CDP request/response exchange'],
  [/\brequest\??\.initiator\??\.sites\b/, 'CDP initiator call sites'], [/cdp-script|scriptParsed/, 'the live Debugger.scriptParsed catalog'],
  [/source_type\s*===\s*['"]script['"]/, 'a live debugger script source'], [/liveSessionJoined|Live scripts/, 'live script analysis'],
  [/requestSearchScope|Include headers and bodies/, 'request content search']];
const sources = [];
for (const file of (await readdir(ui)).filter(name => name.endsWith('.js')).sort()) {
  sources.push([file, await readFile(join(ui, file), 'utf8')]);
}
for (const [file, source] of sources) {
  assert(!/fetch(?:er)?\s*\(\s*['"`]\/api\/debugger/.test(source), `${file} must not call the removed debugger API`);
  assert(!/new\s+WebSocket\s*\(/.test(source), `${file} must not open a debugger websocket`);
  for (const key of removedState) assert(!new RegExp(`\\bstate\\s*(?:\\?\\.|\\.)\\s*${key}\\b|\\b${key}\\s*:`).test(source), `${file} must not read or declare removed state ${key}`);
  for (const name of removedCalls) assert(!new RegExp(`\\b${name}\\s*\\(`).test(source), `${file} must not call or define removed live control ${name}`);
  for (const [pattern, label] of removedShapes) assert(!pattern.test(source), `${file} must not depend on ${label}`);
}
// Self-test the scanner so a regex typo cannot turn this gate into a no-op.
assert(/\bstate\s*(?:\?\.|\.)\s*debuggerSession\b/.test("x = state.debuggerSession?.network"));
assert(/\bstate\s*(?:\?\.|\.)\s*debuggerSession\b/.test("state?.debuggerSession"));
assert(removedShapes[0][0].test('if (request?.exchange) return request.exchange;') && removedShapes[1][0].test('request.initiator.sites'));
assert(!removedShapes[0][0].test('record.initiator?.sites') && !removedShapes[1][0].test('record.initiator?.sites'), 'saved-capture records stay exportable');

const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
for (const id of ['screen-memory', 'screen-experiments', 'debug-resume', 'watch-form', 'source-tab-page', 'source-hook-pivot',
  'collection-run', 'collection-create-context', 'captured-client-review', 'websocket-inspector', 'runtime-hook-traffic',
  'request-memory-pivot', 'open-api-catalog', 'api-catalog', 'passive-security', 'passive-security-open', 'traffic-capture-export',
  'request-search-scope', 'request-search-status',
  'inspector-tab-compare', 'traffic-comparison', 'screen-field-provenance', 'decoder-field-origin', 'decoder-find-sources']) {
  assert(!ids.has(id), `${id} must be removed, not hidden`);
}
for (const id of ['screen-sources', 'source-code', 'source-sidebar', 'screen-api-collection', 'screen-vm', 'vm-owned-debugger',
  'native-console-panel', 'captured-export-dialog', 'console-experiment-traffic', 'investigation-source-search',
  'inspector-tab-general', 'exchange-inspector', 'open-captured-export', 'xrefs-dock', 'xrefs-toggle']) {
  assert(ids.has(id), `native/static feature ${id} must remain`);
}
for (const selector of ['.websocket-inspector', '.websocket-frames', '.runtime-hook-traffic', '.element-screenshot', '#screen-memory',
  '#screen-experiments', '.source-line.breakpoint', 'data-hooks-open', '.api-catalog', '#api-catalog', '#traffic-capture-export',
  '.traffic-comparison', '.request-search-scope', '.request-search-status', '.field-provenance', '#screen-field-provenance', '.exchange-pane',
  '.exchange-html-preview', '.exchange-tab']) {
  assert(!css.includes(selector), `stylesheet must not keep removed ${selector} rules`);
}
for (const match of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)) await access(join(ui, match[1]));
for (const file of ['element_screenshot.js', 'local_override_manager.js', 'captured_vm_lab.js', 'request_value_test.js', 'api_catalog.js', 'passive_security.js',
  'traffic_comparison.js', 'field_provenance.js']) {
  await assert.rejects(access(join(ui, file)), {code: 'ENOENT'}, `removed executable asset ${file} must not ship`);
}
const coordinator = await readFile(join(ui, 'macos/LiveSessionCoordinator.swift'), 'utf8');
assert(!/OriginTraceDebuggerTransport|REB_DEBUGGER_TRANSPORT_BINARY|REB_CDP_NETWORK_CAPTURE/.test(coordinator));
console.log('PASS native-only static contract: no removed state reads, live-control calls, markup ids or stylesheet rules');

// Behavior: execute the actual shipped scripts, trap every removed state key,
// then drive each screen and inspect the controls a researcher can reach.
const {loadShippedUi} = createRequire(import.meta.url)('./check-native-only-startup.cjs');
const {window, context, forbidden, asyncErrors, release} = loadShippedUi();
context.removedState = removedState;
context.removedReads = [];
assert.equal(runInContext('removedState.filter(key => Object.hasOwn(state, key)).length', context), 0,
  'removed state must not be declared in app_state.js');
runInContext(`for (const key of removedState) Object.defineProperty(state, key, {configurable: true,
  get() { removedReads.push(key); return undefined; }, set() { removedReads.push(key + '='); }});`, context);
const screens = [...new Set([...html.matchAll(/data-screen="([^"]+)"/g)].map(match => match[1]))];
assert(screens.includes('traffic') && screens.includes('sources') && screens.includes('vm'));
for (const screen of screens) runInContext(`showScreen(${JSON.stringify(screen)})`, context, {timeout: 10000});
runInContext(`renderRequests(); renderSources(); renderInspector();
  renderNativeWasmObservations({native_guest_sample_count: 1, native_guest_samples: [{event: {session_id: '1', process_id: 1, sequence_number: '2'},
    instruction_pointer: 0, opcode: 1, instance_id: '1', interpretation: 'explicit-adapter'}], native_wasm_observation_count: 0, native_wasm_observations: []});`,
context, {timeout: 10000});
await nextTurn();
await nextTurn();
assert.deepEqual(context.removedReads, [], 'shipped UI must not read removed debugger/live-script state');

const document = window.document;
// "Request call stack" is the native initiator stack (protocol/native-network-v3.md).
const removedFeature = /breakpoint|paused frame|(?<!request )call stack|step over|step into|websocket (?:message|inspector|connection)|websockets ·|cookie import|import cookies|element screenshot|screenshot markup|marker (?:execution|run|fuzz)|run marker|local override|runtime hook|hook pivot|live script|page scripts|find in memory|memory origin/i;
// The pausing vocabulary has one native meaning: the debugger sidebar's
// statement of the availability get_native_debugger reports. That statement
// is text, never a control, and is the only place the words may appear.
const nativeAvailability = '[data-debugger-native="availability"]';
const reachable = node => {
  let text = node.textContent;
  for (const statement of node.querySelectorAll?.(nativeAvailability) ?? []) text = text.replace(statement.textContent, '');
  return [text, node.getAttribute('aria-label'), node.getAttribute('title')].filter(Boolean).join(' ');
};
for (const id of ['screen-traffic', 'screen-sources', 'screen-vm', 'investigation-navigation']) {
  const screen = document.getElementById(id);
  assert(screen, `missing ${id}`);
  // Hidden descendants count: removed controls must be gone, not hidden.
  for (const control of screen.querySelectorAll('button, summary, [role="tab"], [role="button"], label, h1, h2, h3, h4, section, details, a')) {
    assert(!removedFeature.test(reachable(control)), `${id} exposes a removed CDP control: ${reachable(control).slice(0, 160)}`);
  }
}
for (const button of document.querySelectorAll('nav button, .nav-button')) {
  assert(!removedFeature.test(reachable(button)), `navigation exposes a removed CDP feature: ${reachable(button)}`);
}
// Traffic offers only what native rows carry: Headers and Cookies from native
// header and cookie records, Payload from the native target and request_body
// records, Preview and Response from native response_body records and
// artifacts (protocol/native-network-v3.md), no Compare, content search or
// field trace. Removed globals are absent, not stubbed.
assert.deepEqual([...document.querySelectorAll('#screen-traffic .inspector-tab')].map(tab => tab.dataset.inspectorTab),
  ['general', 'headers', 'payload', 'preview', 'response', 'cookies', 'initiator', 'timing', 'signals', 'evidence']);
for (const control of document.getElementById('screen-traffic').querySelectorAll('button, summary, [role="tab"], label, select, option')) {
  assert(!/\bCompare\b|baseline|Include headers and bodies|Field trace/i.test(reachable(control)),
    `Traffic exposes a CDP-only control: ${reachable(control).slice(0, 160)}`);
}
assert.equal(runInContext('typeof renderTrafficRows', context), 'function', 'self-test: shipped globals are visible');
for (const name of ['trafficExchange', 'renderTrafficComparison', 'openFieldProvenance', 'vmLiveCatalogMatchesSession', 'isFieldCallSites']) {
  assert.equal(runInContext(`typeof ${name}`, context), 'undefined', `${name} must not ship`);
}
// A legacy CDP exchange on a row is never rendered or searched.
runInContext(`state.requests = [{id: 'legacy', path: 'legacy.invalid', method: 'GET', status: 200, type: 'xhr', origin: 'live',
  hostOnly: true, tabId: '0', events: [], operation: 'request_completed', time: 1,
  exchange: {response: {state: 'available', text: 'cdp-body-needle', headers: [['x-cdp', 'cdp-header-needle']]}}}];
  state.selectedRequestId = 'legacy'; state.trafficDetailOpen = true; state.inspectorTab = 'compare'; renderInspector();`, context);
assert.equal(runInContext('state.inspectorTab', context), 'general', 'unknown restored tabs fall back to General');
const general = document.getElementById('exchange-inspector').textContent;
assert.match(general, /Response bodies are on the Response tab\./);
assert.doesNotMatch(general, /cdp-body-needle|cdp-header-needle/);
// Response and Preview read native records only, never a CDP exchange.
for (const tab of ['response', 'preview']) {
  runInContext(`state.inspectorTab = ${JSON.stringify(tab)}; renderInspector();`, context);
  const panel = document.getElementById('response-inspector');
  assert.equal(panel.hidden, false, `${tab} shows its panel`);
  assert.equal(panel.getAttribute('aria-labelledby'), `inspector-tab-${tab}`);
  assert.match(panel.textContent, /recorded no response for this request/);
  assert.doesNotMatch(panel.textContent, /cdp-body-needle|cdp-header-needle/);
}
// The Headers tab reads native header records only, never a CDP exchange.
runInContext(`state.inspectorTab = 'headers'; renderInspector();`, context);
const headersPanel = document.getElementById('headers-inspector');
assert.equal(headersPanel.hidden, false);
assert.match(headersPanel.textContent, /This row has no native header record/);
assert.doesNotMatch(headersPanel.textContent, /cdp-header-needle/);
// The Cookies tab reads native cookie records only.
runInContext(`state.inspectorTab = 'cookies'; renderInspector();`, context);
const cookiesPanel = document.getElementById('cookies-inspector');
assert.equal(cookiesPanel.hidden, false);
assert.equal(headersPanel.hidden, true);
assert.match(cookiesPanel.textContent, /This row has no native cookie record/);
assert.doesNotMatch(cookiesPanel.textContent, /cdp-header-needle/);
// Payload reads the native body record and target only, never a CDP exchange.
runInContext(`state.inspectorTab = 'payload'; renderInspector();`, context);
const payload = document.getElementById('payload-inspector');
assert.equal(payload.hidden, false);
assert.equal(document.getElementById('exchange-inspector').hidden, true);
assert.match(payload.textContent, /No body record for this request/);
assert.doesNotMatch(payload.textContent, /cdp-body-needle|cdp-header-needle/);
runInContext(`state.inspectorTab = 'general'; renderInspector();`, context);
assert.equal(payload.hidden, true);
assert.equal(document.getElementById('response-inspector').hidden, true);
assert.equal(headersPanel.hidden, true);
assert.equal(cookiesPanel.hidden, true);
assert.equal(runInContext("trafficSearchRequests(state.requests, 'cdp-body-needle').matches.size", context), 0);
// One code view: Payload, Response, Native Console and Analyst share the Sources lexer, theme and layouts.
for (const name of ['createCodeView', 'codeViewColor', 'createCodeLayouts', 'mountCodeEditor']) {
  assert.equal(runInContext(`typeof ${name}`, context), 'function', `${name} ships`);
}
for (const [file, pattern] of [['traffic_payload.js', /createCodeView\(/], ['traffic_response.js', /createCodeView\(/],
  ['native_console.js', /codeViewColor\(/], ['app.js', /mountCodeEditor\(/]]) {
  assert(pattern.test(sources.find(([name]) => name === file)[1]), `${file} uses the shared code view`);
}
const analystContent = document.getElementById('analyst-content');
assert.equal(analystContent.tagName, 'TEXTAREA', 'Analyst keeps editing in a textarea');
assert(analystContent.parentElement.classList.contains('code-edit'));
assert.equal(document.getElementById('analyst-content-colors').getAttribute('aria-hidden'), 'true', 'the colored mirror is not read twice');
// Traffic mounts only the rows near the view of the list it reads.
runInContext(`state.requests = Array.from({length: 300}, (_, index) => ({id: 'row-' + index, path: 'row-' + index + '.invalid', method: 'GET',
  status: 200, type: 'xhr', origin: 'live', hostOnly: true, tabId: '0', events: [], operation: 'request_completed', time: 1}));
  state.selectedRequestId = null; showScreen('traffic'); renderRequests();`, context);
const mountedRows = document.querySelectorAll('#request-rows .request-row').length;
const listedRows = Number(document.querySelector('#request-rows .request-row')?.getAttribute('aria-setsize') ?? 0);
assert.equal(listedRows, 300);
assert(mountedRows > 0 && mountedRows <= runInContext('TRAFFIC_ROW_UNMEASURED + 2 * TRAFFIC_ROW_OVERSCAN', context), `${mountedRows} of ${listedRows} rows mounted`);
// Guest bytecode buffers are binary: hex view, never decoded text.
assert.equal(runInContext("sourceHexArtifact({kind: 'bytecode_buffer'}) && sourceHexArtifact({kind: 'wasm'}) && !sourceHexArtifact({kind: 'wasm_guest_adapter'})", context), true);
assert.equal(runInContext("sourceSyntaxLabel(sourceSyntaxLanguage({kind: 'bytecode_buffer', mime_type: 'application/octet-stream', url: 'fixture://guest'}))", context), 'Guest bytecode hex');
assert.equal(runInContext("formatWasmHex(new Uint8Array([0, 0x42, 0, 0, 0x3c, 0xff]))", context), '00000000  00 42 00 00 3c ff' + ' '.repeat(32) + '|.B..<.|');
const app = sources.find(([file]) => file === 'app.js')[1];
assert(/const content = sourceHexArtifact\(artifact\)\s*\?\s*formatWasmHex/.test(app), 'the artifact loader formats every hex artifact kind');
for (const [file, source] of sources.filter(([file]) => ['evidence_package.js', 'investigation_navigation.js', 'investigation_notebook.js'].includes(file))) {
  assert(/['"]bytecode_buffer['"]/.test(source), `${file} must offer the Sources hex view for guest bytecode`);
}
// The launcher's URL says what this session retains. The packaged app starts
// content capture without a dialog, so the titlebar labels it for the session.
const contentLabel = document.getElementById('session-content');
const shell = (mode, requestContent, canvasImages) => runInContext(`state.sessionMode = ${JSON.stringify(mode)};
  state.broker = 'connected'; state.requestContentCaptureEnabled = ${requestContent};
  state.canvasImageCaptureEnabled = ${canvasImages}; renderShellStatus();`, context);
shell('live', true, true);
assert.equal(contentLabel.hidden, false);
assert.equal(contentLabel.textContent, 'Content capture');
assert.match(contentLabel.getAttribute('title'), /request paths, queries and bodies, and response bodies, up to 16 MiB each, request and response headers, cookies and Canvas images/);
shell('live', false, true);
assert.equal(contentLabel.hidden, false);
assert.match(contentLabel.getAttribute('aria-label'), /^Content capture: Canvas images$/);
shell('live', false, false);
assert.equal(contentLabel.hidden, true, 'a metadata-only session shows no content label');
shell('demo', true, true);
assert.equal(contentLabel.hidden, true, 'only a live session is labeled');
// Cross-references dock: no work while closed, inert captured names, one window
// of rows, and a stored-evidence window that says it cannot read the backend.
{
  const dock = document.querySelector('#xrefs-dock'), toggle = document.querySelector('#xrefs-toggle');
  assert.equal(dock.hidden, true, 'the cross-references dock starts closed');
  const rows = document.querySelector('#xrefs-rows');
  Object.defineProperty(rows, 'clientHeight', {value: 400}); rows.scrollTop = 0;
  context.__xrefRequests = [];
  context.__xrefDocument = {contract_version: 1, document_kind: 'reb-xrefs', selection: {kind: 'request', status: 'resolved', label: null}, filter: '', snapshot: '42',
    counts: {in: {total: 1, matching: 1}, out: {total: 200, matching: 200}}, gaps: {in: [{reason: 'no-initiator-stack', name: 'No initiator recorded', detail: 'No caller is inferred.'}], out: []},
    pages: {in: {offset: 0, limit: 128, returned: 1, rows: [{direction: 'in', kind: 'parent_event', name: '<img id=xref-injected src=x>', detail: '<b>detail</b>', source: 'network', operation: 'request_started', state: 'observed',
      evidence: {type: 'event', session_id: '7', process_id: 1, sequence_number: '1'}, ids: {session_id: '7', process_id: 1, sequence_number: '1'}, time_ns: '1'}]}, out: {offset: 0, limit: 128, returned: 0, rows: []}},
    coverage: {status: 'complete', scanned_bytes: '42', snapshot_bytes: '42', malformed_records: 0}};
  runInContext(`const __priorFetch = fetch; globalThis.fetch = async (input, init) => {
    if (String(input).startsWith('/api/xrefs')) { __xrefRequests.push(String(input)); return new Response(JSON.stringify(__xrefDocument), {status: 200}); }
    return __priorFetch(input, init); };`, context);
  await nextTurn();
  assert.equal(context.__xrefRequests.length, 0, 'a closed dock must not query cross-references');
  toggle.click();
  await nextTurn();
  assert.equal(dock.hidden, false, 'the toggle opens the dock');
  assert.equal(context.__xrefRequests.length, 0, 'the offline file window has no backend to query');
  assert.match(dock.textContent, /Open Traffic|stored-evidence|no exact retained identity|Select a request/, 'an unavailable selection stays visible text');
  toggle.click();
  await nextTurn();
  assert.equal(dock.hidden, true, 'the toggle closes the dock');
  window.location.protocol = 'http:';
  runInContext(`showScreen('traffic'); state.requests = [{id: 'r1', origin: 'live', method: 'GET', path: 'x.test', hostOnly: true, traceable: false}]; state.selectedRequestId = 'r1'; investigationRequestIdentity = () => ({type: 'captured-request', session: '7', process: '1', sequence: '1', request: '5'});`, context);
  toggle.click();
  for (let turn = 0; turn < 8; turn += 1) await nextTurn();
  assert.equal(context.__xrefRequests.length, 1, 'one query for one selection');
  assert.match(context.__xrefRequests[0], /kind=request&session_id=7&process_id=1&sequence_number=1&request_id=5/, context.__xrefRequests[0]);
  assert.match(context.__xrefRequests[0], /limit=128/, 'the first page is bounded');
  const mounted = [...dock.querySelectorAll('.xrefs-row')];
  assert(mounted.length > 0 && mounted.length < 200, `only visible rows mount: ${mounted.length}`);
  assert(mounted.some(row => row.textContent.includes('<img id=xref-injected')), 'captured names render as literal text');
  assert.equal(dock.querySelector('#xref-injected'), null, 'captured names never become elements');
  assert(mounted.some(row => row.textContent.includes('No initiator recorded')), 'a missing link is an explicit gap row');
  toggle.click();
  await nextTurn();
  assert.equal(dock.querySelectorAll('.xrefs-row').length, 0, 'closing releases the rows');
  await nextTurn();
  assert.equal(context.__xrefRequests.length, 1, 'closed dock stays idle');
  window.location.protocol = 'file:';
}

// Debugger sidebar (debugger_sidebar.js, docs/product/native-debugger-v1.md):
// a closed sidebar asks nothing, its labels come from get_native_debugger,
// pausing is one stated availability and never a control, captured names stay
// text, only rows in view mount, and an observed frame scopes the Sources tree.
{
  for (const [path, assets] of [['scripts/build-research-app.sh', ['debugger_sidebar.js', 'debugger_sidebar.css']],
    ['apps/origin-trace-backend/src/app.rs', ['"debugger_sidebar.js"', '"debugger_sidebar.css"']],
    ['apps/research-ui/macos/OriginTraceApp.swift', ['/debugger_sidebar.js', '/debugger_sidebar.css']]]) {
    const text = await readFile(join(root, path), 'utf8');
    for (const asset of assets) assert(text.includes(asset), `${path} ships ${asset}`);
  }
  const sidebar = document.querySelector('#debugger-sidebar'), toggle = document.querySelector('#source-debugger-toggle');
  assert.equal(sidebar.hidden, true, 'the debugger sidebar starts closed');
  context.__debuggerRequests = [];
  const site = {script_id: 7, position: 40, function_start: 40};
  const record = (index, type, detail, extra = {}) => ({type, session_id: '1', process_id: 42, frame_id: index % 2 ? '7101' : '200',
    sequence_number: String(5000 - index), parent_event_id: '0', request_id: '0', monotonic_time_ns: String(1e9 + index), detail,
    stack: {state: 'no_script', total_depth: 0, recorded: 0, async_frames: 0, digest: null, innermost: null}, ...extra});
  const records = Array.from({length: 128}, (_, index) => index === 3
    ? record(index, 'listener_dispatch', {rule: 0, target: 'element', node_type: 1, listener: site, event_type: '<img/src=x/onerror=f()>'})
    : index === 5 ? record(index, 'request_watch_match', {rule: 0, method_matched: true}, {request_id: '77', parent_event_id: '4000'})
      : record(index, 'timer_observation', {phase: 'fired', kind: 'timeout', string_callback: false, timer_id: index, delay_ms: 0, callback: site}));
  const observed = Array.from({length: 40}, (_, index) => ({session_id: '1', process_id: 42, frame_id: String(index ? 7100 + index : 200),
    last_sequence: String(9000 - index), records: 60}));
  const answer = (overrides = {}) => ({contract_version: 1, availability: 'unsupported', reason: 'browser_debugger_unsupported',
    experiment_flag: '--reb-native-debugger', policy: 'proposed_pending_approval', detectable: true, lease_limit_ms: 60000, lease: null,
    paused: false, breakpoints: [], threads: {console: 'idle', frames: [{target_id: '22', label: 'top #22', origin: 'https://a.test', frame: 'top', out_of_process: false}],
      workers: [{kind: 'dedicated_worker', session_id: '1', process_id: 42, context_id: '9001', last_sequence: '12', requests: 3}], observed},
    watch: {state: 'none', armed: null}, observations: records, observations_malformed: 2,
    observations_query: {type: null, thread: null, scope: 'bounded_range', direction: 'backward', limit: 128, returned: 128, store_end: '9000',
      next_after: '9000', next_before: '4000', limited: true, budget_exhausted: false},
    observation_budget_gaps: [{session_id: '1', process_id: 42, frame_id: '7101', sequence_number: '9001'}], ...overrides});
  context.__debuggerAnswer = () => answer();
  context.__stackAnswer = () => ({status: 'recorded', request: {session_id: '1', process_id: 42, sequence_number: '4997'}, state: 'no_script', frames: [],
    observation: {type: 'listener_dispatch', detail: {}, site: {index: 0, kind: 'javascript', script_id: 7, position: 40, function_position: 40,
      resolution: {status: 'resolved', artifact_id: '350', url: 'https://app.test/handlers.js', artifact_line: 2, artifact_column: 9, line: 2, column: 9, function_name: 'onTap'}}}});
  runInContext(`const __debuggerPriorFetch = fetch; globalThis.fetch = async (input, init) => {
    const url = String(input);
    if (!url.startsWith('/api/native-debugger') && !url.startsWith('/api/request-stack')) return __debuggerPriorFetch(input, init);
    __debuggerRequests.push(url);
    const body = url.startsWith('/api/native-debugger') ? __debuggerAnswer() : __stackAnswer();
    if (body instanceof Error) throw body;
    return new Response(JSON.stringify(body), {status: 200});
  };`, context);
  const settle = async () => { for (let turn = 0; turn < 10; turn += 1) await nextTurn(); };
  window.AbortSignal ??= AbortSignal;
  const click = node => node.dispatchEvent(new window.Event('click', {bubbles: true}));
  runInContext(`showScreen('sources')`, context);
  await settle();
  assert.equal(context.__debuggerRequests.length, 0, 'a closed sidebar makes no requests');
  toggle.click();
  await settle();
  assert.equal(sidebar.hidden, false, 'the toggle opens the sidebar');
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  assert.equal(document.querySelector('#source-sidebar').hidden, true, 'Details and the debugger share one column');
  assert.equal(context.__debuggerRequests.length, 0, 'the offline file window has no backend to ask');
  assert.match(sidebar.querySelector('.debugger-sidebar-status').textContent, /No backend serves this window/);
  toggle.click();
  window.location.protocol = 'http:';
  toggle.click();
  await settle();
  assert.match(context.__debuggerRequests[0], /^\/api\/native-debugger\?limit=128$/, context.__debuggerRequests[0]);
  assert.deepEqual([...sidebar.querySelectorAll('.debugger-section')].map(node => node.dataset.debuggerSection), ['threads', 'watch', 'observations', 'pausing']);
  const rows = [...sidebar.querySelectorAll('#debugger-observations .debugger-list-row')];
  assert(rows.length > 0 && rows.length < 40, `only rows in view mount: ${rows.length} of 128`);
  assert.equal(rows[0].getAttribute('aria-setsize'), '128');
  assert(rows.some(row => row.textContent.includes('<img/src=x/onerror=f()> listener on element')), 'a captured event type renders as text');
  assert.equal(sidebar.querySelector('img'), null, 'captured names never become elements');
  for (const text of [/2 records in the newest read were malformed/, /Renderer 42 reached 1,024 observation records in frame 7101/]) {
    assert.match(sidebar.querySelector('.debugger-observation-notes').textContent, text);
  }
  const threadRows = sidebar.querySelectorAll('#debugger-threads .debugger-list-row');
  assert(threadRows.length > 0 && threadRows.length < 42, `thread rows mount by view: ${threadRows.length} of 42`);
  // Pausing is one statement of the reported availability, with no control.
  const statement = sidebar.querySelector(nativeAvailability);
  assert.equal(statement.dataset.availability, 'unsupported');
  assert.equal(statement.closest('[data-debugger-section]').dataset.debuggerSection, 'pausing');
  assert.match(statement.textContent, /^Unsupported\. No Brave build serves the pausing debugger \(browser_debugger_unsupported\)/);
  assert.equal(statement.querySelectorAll('button, input, select, textarea, a, summary, [tabindex]').length, 0, 'the pausing state is text');
  assert.equal(document.querySelectorAll(nativeAvailability).length, 1, 'the availability statement appears once');
  for (const control of sidebar.querySelectorAll('button, summary, [role="option"], label, h1, h2, h3, h4, section, details, a')) {
    assert(!removedFeature.test(reachable(control)), `the debugger sidebar implies a CDP control: ${reachable(control).slice(0, 160)}`);
  }
  for (const button of sidebar.querySelectorAll('button')) {
    assert(!/\b(?:pause|resume|step|breakpoint)/i.test(`${button.textContent} ${button.getAttribute('aria-label') ?? ''}`), `no pausing control: ${button.textContent}`);
  }
  // A record opens its own resolved frame in Sources.
  context.__opened = [];
  runInContext(`var __selectArtifact = selectArtifact; selectArtifact = (...args) => { __opened.push(args); return true; };`, context);
  click(sidebar.querySelector('#debugger-observations .debugger-list-row[data-kind="listener_dispatch"]'));
  await settle();
  assert.match(context.__debuggerRequests.at(-1), /^\/api\/request-stack\?session_id=1&process_id=42&observation_sequence=4997$/);
  const open = sidebar.querySelector('.debugger-open-source');
  assert.equal(open?.textContent, 'Open onTap @ handlers.js:2:9');
  for (const text of ['Operation', 'listener_dispatch', 'Category', 'runtime', 'Time', 'Source', 'renderer process 42, frame 7101', 'sequence 4997']) {
    assert(sidebar.querySelector('.debugger-detail').textContent.includes(text), `details name ${text}`);
  }
  open.click();
  assert.equal(JSON.stringify(context.__opened), JSON.stringify([['350', 1, {column: 8}]]), 'Sources opens at the one-based resolved line and column');
  runInContext(`selectArtifact = __selectArtifact;`, context);
  // A watched request opens its Traffic row only when that exact row is loaded.
  click(sidebar.querySelector('#debugger-observations .debugger-list-row[data-kind="request_watch_match"]'));
  await settle();
  [...sidebar.querySelectorAll('.debugger-detail button')].find(button => button.textContent === 'Open request in Traffic').click();
  await settle();
  assert.match(sidebar.querySelector('.debugger-detail').textContent, /Request 77 of renderer 42 is not among the Traffic rows loaded now/);
  // An observed frame scopes Observations and the Sources tree by exact identity.
  click(sidebar.querySelector('#debugger-threads .debugger-list-row[data-key="F:1:42:200"]'));
  await settle();
  assert.match(context.__debuggerRequests.at(-1), /^\/api\/native-debugger\?limit=128&session_id=1&process_id=42&frame_id=200$/, context.__debuggerRequests.at(-1));
  const scope = runInContext('RebDebuggerSidebar.sourceScope()', context);
  assert.equal(scope.includes({session_id: '1', frame_id: '200'}), true);
  assert.equal(scope.includes({session_id: '1', frame_id: '2000'}), false);
  assert.equal(scope.includes({session_id: '2', frame_id: '200'}), false);
  assert.match(document.querySelector('#source-tree').textContent, /Frame 200 of session 1, selected in Debugger Threads/);
  // A malformed or failed read keeps the last understandable evidence.
  for (const [body, text] of [[{contract_version: 2}, /malformed \(an unknown contract version\) and was not used/], [new Error('offline'), /Disconnected: offline/]]) {
    context.__debuggerAnswer = () => body;
    click(sidebar.querySelector('.debugger-kind[data-kind="timer_observation"]'));
    await settle();
    assert.match(sidebar.querySelector('.debugger-sidebar-status').textContent, text);
    assert(sidebar.querySelectorAll('#debugger-observations .debugger-list-row').length > 0, 'rows stay after a failed read');
    assert.equal(sidebar.querySelector('[data-debugger-section="threads"]').dataset.stale, 'true', 'a stale section says so');
  }
  // Arming goes through the Console's live document only, and invalid rules send nothing.
  context.__debuggerAnswer = () => answer();
  context.__watchCalls = [];
  runInContext(`globalThis.RebNativeConsole = {liveDocument: () => ({session_id: '5', target_id: '22', label: 'top #22'}),
    watch: async rules => { __watchCalls.push(JSON.stringify(rules)); return {status: 'ok', text: 'Armed'}; }};`, context);
  click(sidebar.querySelector('.debugger-kind[data-kind="all"]'));
  await settle();
  const form = sidebar.querySelector('.debugger-watch-form');
  assert(form, 'a live Console document offers the rules form');
  assert.equal(form.querySelector('.debugger-arm').textContent, 'Arm on document 22');
  form.querySelector('textarea').value = 'POST /api/x\n/collect';
  form.querySelector('input[type="text"]').value = 'click, submit';
  form.querySelector('input[type="checkbox"]').checked = true;
  form.querySelector('select').value = 'uncaught';
  form.dispatchEvent(new window.Event('submit', {cancelable: true}));
  await settle();
  assert.deepEqual(context.__watchCalls.map(text => JSON.parse(text)), [{requests: [{method: 'POST', url_contains: '/api/x'}, {url_contains: '/collect'}],
    events: ['click', 'submit'], timers: true, csp: false, exceptions: 'uncaught', dom: []}]);
  assert.match(form.querySelector('.debugger-watch-result').textContent, /Armed on document 22/);
  form.querySelector('input[type="text"]').value = 'x'.repeat(28);
  form.dispatchEvent(new window.Event('submit', {cancelable: true}));
  await settle();
  assert.equal(context.__watchCalls.length, 1, 'invalid rules send nothing');
  assert.match(form.querySelector('.debugger-watch-result').textContent, /At most 16 event types/);
  runInContext(`delete globalThis.RebNativeConsole;`, context);
  // The registry: later sections join in order; malformed ones are refused.
  assert.throws(() => runInContext(`RebDebuggerSidebar.addSection({id: 'Bad id', title: 'x', order: 1, render() {}})`, context), /lowercase/);
  const remove = runInContext(`RebDebuggerSidebar.addSection({id: 'later', title: 'Later section', order: 35, render(body) { body.textContent = 'from the registry'; }})`, context);
  assert.deepEqual([...sidebar.querySelectorAll('.debugger-section')].map(node => node.dataset.debuggerSection), ['threads', 'watch', 'observations', 'later', 'pausing']);
  assert.match(sidebar.querySelector('[data-debugger-section="later"]').textContent, /from the registry/);
  remove();
  assert.equal(sidebar.querySelector('[data-debugger-section="later"]'), null, 'a removed section leaves');
  // Closing stops every read and releases rows and the tree scope.
  toggle.click();
  await settle();
  const asked = context.__debuggerRequests.length;
  await settle();
  assert.equal(context.__debuggerRequests.length, asked, 'a closed sidebar stays idle');
  assert.equal(sidebar.querySelectorAll('.debugger-list-row').length, 0, 'closing releases the rows');
  assert.equal(runInContext('RebDebuggerSidebar.sourceScope()', context), null, 'a closed sidebar scopes nothing');
  assert.doesNotMatch(document.querySelector('#source-tree').textContent, /selected in Debugger Threads/);
  window.location.protocol = 'file:';
}

// Sources Map: production controller driven through scripted responses.
assert.match(html, /id="source-map"/, 'Sources offers the Map view');
for (const [path, assets] of [['scripts/build-research-app.sh', ['entropy_map.js', 'entropy_map.css']], ['apps/origin-trace-backend/src/app.rs', ['"entropy_map.js"', '"entropy_map.css"']],
  ['apps/research-ui/macos/OriginTraceApp.swift', ['/entropy_map.js', '/entropy_map.css']]]) {
  const text = await readFile(join(root, path), 'utf8');
  for (const asset of assets) assert(text.includes(asset), `${path} ships ${asset}`);
}
const mapCss = await readFile(join(ui, 'entropy_map.css'), 'utf8');
assert.equal((mapCss.replace(/:root(\[data-theme="light"\])? \{[^}]*\}/g, '').match(/#[0-9a-f]{3,8}\b/gi) ?? []).length, 0, 'map colors are tokens in both themes');
for (const block of [/:root \{([^}]*)\}/, /:root\[data-theme="light"\] \{([^}]*)\}/]) {
  const tokens = [...block.exec(mapCss)[1].matchAll(/--map-[a-z0-9-]+/g)].map(match => match[0]);
  assert.equal(tokens.length, 14, 'both themes define the whole ramp and every kind');
}
for (const [side, ...rest] of [[1], [2], [8], [64], [128]]) {
  const round = `Array.from({length: ${side * side}}, (_, i) => entropyMapHilbertIndex(${side}, ...entropyMapHilbertPoint(${side}, i)) === i).every(Boolean)`;
  assert.equal(runInContext(round, context), true, `Hilbert order round-trips at side ${side}`);
}
assert.deepEqual(JSON.parse(runInContext("JSON.stringify(entropyMapTextPosition('ab\\nc', 3))", context)), {line: 1, column: 0});
assert.equal(runInContext("entropyMapTextPosition('ab', 9)", context), null, 'an offset past the text is not placed');
const mapDocument = (id, cells, side) => ({version: 1, schema: 'artifact-map-v1', artifact_id: id, session_id: '1', sha256: 'a'.repeat(64),
  artifact_kind: 'wasm', byte_length: 1024 * side * side, integrity: 'verified',
  grid: {order: 'hilbert', side, cell_count: side * side, window_bytes: 1024, min_window_bytes: 256, below_min_window: false},
  entropy: {encoding: 'base64', units_per_bit: 30, cells, mean_bits: 3.25, max_bits: 7.5},
  high_entropy: {threshold_bits: 7, threshold_units: 210, windows: 1, bytes: 1024},
  kind_map: {encoding: 'base64', mixed_flag: 128, cells: Buffer.alloc(side * side).toString('base64'),
    kinds: [{id: 'section_code', label: '<b>code section</b>', group: 'code', bytes: 1024, windows: 1}]},
  facts: {source: 'wasm_section_frames', complete: true, sections: 3, data_segments: 1, notes: ['<img src=x onerror=alert(1)> note']},
  highest_ranges: [{start: 0, end: 1024, peak_bits: 7.5, high: true}]});
const mapSource = (id = '901', size = 4096) => ({artifact_id: id, sha256: 'a'.repeat(64), byte_size: size, source_type: 'artifact', kind: 'wasm'});
context.mapReady = mapDocument('901', Buffer.from([225, 0, 0, 0]).toString('base64'), 2);
context.mapMalformed = {...mapDocument('901', Buffer.from([225, 0, 0, 0]).toString('base64'), 2), grid: {order: 'hilbert', side: 3, cell_count: 9, window_bytes: 1024, min_window_bytes: 256, below_min_window: false}};
context.mapEmpty = {...mapDocument('901', '', 0), byte_length: 4096, grid: {order: 'hilbert', side: 0, cell_count: 0, window_bytes: 0, min_window_bytes: 256, below_min_window: false}};
context.mapSourceValue = mapSource();
runInContext(`var mapFixture = (() => {
  const make = tag => { const node = document.createElement(tag); document.body.append(node); return node; };
  const button = make('button'), root = make('section'), codeWrap = make('div'), viewKind = make('span'), toolbar = make('div');
  button.classList.add('source-tool'); viewKind.textContent = 'Original · truncated';
  root.hidden = true; let source = mapSourceValue; let revealed = [];
  const controller = createEntropyMap({button, root, codeWrap, viewKind, toolbar, getSource: () => source, identityOf: value => value ? value.artifact_id + ':' + value.sha256 : null,
    reveal: (value, offset, leave) => { revealed.push(offset); return offset > 2048 ? 'Past the hex view.' : (leave(), ''); }});
  return {controller, button, root, codeWrap, viewKind, revealed, setSource(value) { source = value; }};
})();`, context);
const mapRoot = runInContext('mapFixture.root', context), mapWrap = runInContext('mapFixture.codeWrap', context);
const openMap = async response => {
  context.mapFetch = response;
  runInContext(`fetch = async () => mapFetch(); mapFixture.controller.close(); mapFixture.controller.open();`, context);
  await nextTurn(); await nextTurn(); await nextTurn();
};
const mapText = selector => mapRoot.querySelector(selector)?.textContent ?? '';
const mapHidden = selector => mapRoot.querySelector(selector)?.hidden;
let pendingMap; context.mapFetch = () => new Promise(resolve => { pendingMap = resolve; });
runInContext(`fetch = async () => mapFetch(); mapFixture.controller.open();`, context);
assert.equal(mapRoot.hidden, false); assert.equal(mapWrap.hidden, true, 'the map replaces the code view');
assert.match(mapText('.map-state-text'), /Reading the whole artifact/, 'loading is stated');
pendingMap(new context.Response('null', {status: 500}));
await nextTurn(); await nextTurn();
assert.equal(mapHidden('.map-retry'), false, 'an unusable response offers Retry');
for (const [body, status, expected] of [[JSON.stringify({error: 'Artifact not found'}), 404, /Artifact not found/],
  [JSON.stringify(context.mapMalformed), 200, /invalid artifact map/], [JSON.stringify({version: 2}), 200, /invalid artifact map/],
  [JSON.stringify(context.mapEmpty), 200, /no bytes/]]) {
  await openMap(() => new context.Response(body, {status, headers: {'content-type': 'application/json'}}));
  assert.match(mapText('.map-state-text'), expected, `${status} ${body.slice(0, 40)}`);
  assert.equal(mapHidden('.map-body'), true, 'no stale map remains visible');
}
await openMap(() => { throw new TypeError('offline'); });
assert.match(mapText('.map-state-text'), /evidence store is unavailable/, 'a disconnected store is stated');
assert.equal(mapHidden('.map-retry'), false, 'disconnection offers Retry');
await openMap(() => new context.Response(JSON.stringify(context.mapReady), {status: 200, headers: {'content-type': 'application/json'}}));
assert.equal(mapHidden('.map-body'), false, `the map renders: ${mapText('.map-state-text')}`);
assert.match(mapText('.map-stats'), /Hilbert 2×2 · 1\.0 KB per cell/, 'the header states grid and cell size');
assert.match(mapText('.map-facts'), /≥ 7\.0 bits\/byte/, 'the threshold is stated beside the map');
assert.equal(mapRoot.querySelectorAll('img, b').length, 0, 'captured-derived text stays inert');
assert.match(mapText('.map-notes'), /onerror/, 'notes are shown as text');
assert.doesNotMatch(mapRoot.textContent, /packed|encrypted/i, 'the map draws no such conclusion');
const mapViewKind = () => runInContext('mapFixture.viewKind.textContent', context);
assert.equal(mapViewKind(), 'Whole-artifact map · original bytes', 'the status bar names the map while it shows');
mapRoot.querySelector('.map-range').click();
assert.equal(runInContext('mapFixture.controller.isOpen()', context), false, 'opening a reachable byte leaves the map');
assert.equal(mapViewKind(), 'Original · truncated', 'closing the map restores the evidence state');
assert.deepEqual([...runInContext('mapFixture.revealed', context)], [0], 'a range row opens its first byte');
assert.equal(mapWrap.hidden, false, 'the code view returns');
await openMap(() => new context.Response(JSON.stringify(context.mapReady), {status: 200, headers: {'content-type': 'application/json'}}));
// A render for the new selection writes its own evidence state before the map retires.
runInContext(`mapFixture.setSource({...mapSourceValue, artifact_id: '902'}); mapFixture.viewKind.textContent = 'Derived'; mapFixture.controller.sync();`, context);
assert.equal(runInContext('mapFixture.controller.isOpen()', context), false, 'a new selection retires the map');
assert.equal(mapViewKind(), 'Derived', 'the new selection keeps the evidence state its render wrote');
assert.equal(mapRoot.hidden, true, 'the retired map is hidden');
assert.equal(mapRoot.querySelector('.map-facts').children.length, 0, 'the retired summary is released');

// Sources Graph: Inspect, Graph and Map sit together, and Graph and Map exclude each other.
assert.match(html, /id="source-wasm"[^>]*>Inspect<\/button>\s*<button id="source-graph"[^>]*>Graph<\/button>\s*<button id="source-map"/, 'Inspect, Graph and Map are adjacent in that order');
for (const [path, assets] of [['scripts/build-research-app.sh', ['block_graph.js', 'block_graph_layout.js', 'block_graph.css']], ['apps/origin-trace-backend/src/app.rs', ['"block_graph.js"', '"block_graph_layout.js"', '"block_graph.css"']],
  ['apps/research-ui/macos/OriginTraceApp.swift', ['/block_graph.js', '/block_graph_layout.js', '/block_graph.css']]]) {
  const text = await readFile(join(root, path), 'utf8');
  for (const asset of assets) assert(text.includes(asset), `${path} ships ${asset}`);
}
runInContext(`var graphFixture = (() => {
  const make = (tag, parent = document.body) => { const node = document.createElement(tag); parent.append(node); return node; };
  const toolbar = make('div'), editor = make('div'), split = make('div', editor), host = make('div', split), codeWrap = make('div', split);
  const graphButton = make('button', toolbar), mapButton = make('button', toolbar), mapRoot = make('section', editor), viewKind = make('span');
  graphButton.classList.add('source-tool'); mapButton.classList.add('source-tool'); mapRoot.hidden = true;
  const source = {artifact_id: '903', sha256: 'b'.repeat(64), byte_size: 64, source_type: 'artifact', kind: 'wasm'};
  const graph = createSourceGraphPanel({host, editor, button: graphButton, closeOn: mapButton, revealOffset() {}});
  const map = createEntropyMap({button: mapButton, root: mapRoot, codeWrap, viewKind, toolbar, getSource: () => source,
    identityOf: value => value ? value.artifact_id + ':' + value.sha256 : null, reveal: () => ''});
  graph.sync(source);
  return {graph, map, graphButton, mapButton, host, codeWrap, editor};
})();`, context);
runInContext(`fetch = () => new Promise(() => {});`, context);
const graphFixture = name => runInContext(`graphFixture.${name}`, context);
graphFixture('graphButton').click();
assert.equal(runInContext('graphFixture.graph.isOpen()', context), true, 'Graph opens on a captured WASM artifact');
assert.equal(graphFixture('editor').getAttribute('data-graph'), 'true');
graphFixture('mapButton').click();
assert.equal(runInContext('graphFixture.map.isOpen()', context), true, 'Map opens');
assert.equal(runInContext('graphFixture.graph.isOpen()', context), false, 'opening Map closes Graph');
assert.equal(graphFixture('host').hidden, true, 'the closed graph is hidden and released');
assert.equal(graphFixture('codeWrap').hidden, true, 'Map replaces the linear view under the closed graph');
graphFixture('graphButton').click();
assert.equal(runInContext('graphFixture.graph.isOpen()', context), true, 'Graph opens again');
assert.equal(runInContext('graphFixture.map.isOpen()', context), false, 'opening Graph closes Map');
assert.equal(graphFixture('codeWrap').hidden, false, 'the linear view returns with the graph');
assert.deepEqual(forbidden, [], 'startup/navigation must not attempt CDP transport');
assert.deepEqual(asyncErrors, [], 'all asynchronous startup failures must be handled');
release();
console.log(`PASS native-only behavior: ${screens.length} screens rendered from shipped scripts without removed state reads or CDP controls; Traffic General plus native Headers, Payload, Preview, Response and Cookies, no exchange/search/compare, one shared code view, mounted Traffic rows bounded by the view, guest bytecode hex (offline DOM model; no rendered layout claimed)`);
