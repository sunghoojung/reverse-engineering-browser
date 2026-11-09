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
  'request-search-scope', 'request-search-status', 'inspector-tab-payload', 'inspector-tab-preview', 'inspector-tab-response',
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
const removedFeature = /breakpoint|paused frame|call stack|step over|step into|websocket (?:message|inspector|connection)|websockets ·|cookie import|import cookies|element screenshot|screenshot markup|marker (?:execution|run|fuzz)|run marker|local override|runtime hook|hook pivot|live script|page scripts|find in memory|memory origin/i;
const reachable = node => [node.textContent, node.getAttribute('aria-label'), node.getAttribute('title')].filter(Boolean).join(' ');
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
// Traffic offers only what native rows carry: no body/header tabs, Compare,
// content search or field trace. Removed globals are absent, not stubbed.
assert.deepEqual([...document.querySelectorAll('#screen-traffic .inspector-tab')].map(tab => tab.dataset.inspectorTab),
  ['general', 'initiator', 'timing', 'signals', 'evidence']);
for (const control of document.getElementById('screen-traffic').querySelectorAll('button, summary, [role="tab"], label, select, option')) {
  assert(!/\bCompare\b|baseline|Include headers and bodies|\bPayload\b|\bPreview\b|Field trace/i.test(reachable(control)),
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
  state.selectedRequestId = 'legacy'; state.trafficDetailOpen = true; state.inspectorTab = 'payload'; renderInspector();`, context);
assert.equal(runInContext('state.inspectorTab', context), 'general', 'unknown restored tabs fall back to General');
const general = document.getElementById('exchange-inspector').textContent;
assert.match(general, /headers and response bodies are not captured/);
assert.doesNotMatch(general, /cdp-body-needle|cdp-header-needle/);
assert.equal(runInContext("trafficSearchRequests(state.requests, 'cdp-body-needle').matches.size", context), 0);
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
assert.match(contentLabel.getAttribute('title'), /request paths, queries and bodies up to 256 KiB each and Canvas images/);
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
assert.deepEqual(forbidden, [], 'startup/navigation must not attempt CDP transport');
assert.deepEqual(asyncErrors, [], 'all asynchronous startup failures must be handled');
release();
console.log(`PASS native-only behavior: ${screens.length} screens rendered from shipped scripts without removed state reads or CDP controls; Traffic General-only, no exchange/search/compare, guest bytecode hex (offline DOM model; no rendered layout claimed)`);
