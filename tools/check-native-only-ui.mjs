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
  'installTrafficCaptureExport', 'installPassiveSecurityReport', 'evidenceDebuggerRequest', 'devtoolsJoinedNativeEvents'];
const sources = [];
for (const file of (await readdir(ui)).filter(name => name.endsWith('.js')).sort()) {
  sources.push([file, await readFile(join(ui, file), 'utf8')]);
}
for (const [file, source] of sources) {
  assert(!/fetch(?:er)?\s*\(\s*['"`]\/api\/debugger/.test(source), `${file} must not call the removed debugger API`);
  assert(!/new\s+WebSocket\s*\(/.test(source), `${file} must not open a debugger websocket`);
  for (const key of removedState) assert(!new RegExp(`\\bstate\\s*(?:\\?\\.|\\.)\\s*${key}\\b|\\b${key}\\s*:`).test(source), `${file} must not read or declare removed state ${key}`);
  for (const name of removedCalls) assert(!new RegExp(`\\b${name}\\s*\\(`).test(source), `${file} must not call or define removed live control ${name}`);
}
// Self-test the scanner so a regex typo cannot turn this gate into a no-op.
assert(/\bstate\s*(?:\?\.|\.)\s*debuggerSession\b/.test("x = state.debuggerSession?.network"));
assert(/\bstate\s*(?:\?\.|\.)\s*debuggerSession\b/.test("state?.debuggerSession"));

const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
for (const id of ['screen-memory', 'screen-experiments', 'debug-resume', 'watch-form', 'source-tab-page', 'source-hook-pivot',
  'collection-run', 'collection-create-context', 'captured-client-review', 'websocket-inspector', 'runtime-hook-traffic',
  'request-memory-pivot', 'open-api-catalog', 'api-catalog', 'passive-security', 'passive-security-open', 'traffic-capture-export']) {
  assert(!ids.has(id), `${id} must be removed, not hidden`);
}
for (const id of ['screen-sources', 'source-code', 'source-sidebar', 'screen-api-collection', 'screen-vm', 'vm-owned-debugger',
  'native-console-panel', 'captured-export-dialog', 'console-experiment-traffic', 'investigation-source-search']) {
  assert(ids.has(id), `native/static feature ${id} must remain`);
}
for (const selector of ['.websocket-inspector', '.websocket-frames', '.runtime-hook-traffic', '.element-screenshot', '#screen-memory',
  '#screen-experiments', '.source-line.breakpoint', 'data-hooks-open', '.api-catalog', '#api-catalog', '#traffic-capture-export']) {
  assert(!css.includes(selector), `stylesheet must not keep removed ${selector} rules`);
}
for (const match of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)) await access(join(ui, match[1]));
for (const file of ['element_screenshot.js', 'local_override_manager.js', 'captured_vm_lab.js', 'request_value_test.js', 'api_catalog.js', 'passive_security.js']) {
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
assert.deepEqual(forbidden, [], 'startup/navigation must not attempt CDP transport');
assert.deepEqual(asyncErrors, [], 'all asynchronous startup failures must be handled');
release();
console.log(`PASS native-only behavior: ${screens.length} screens rendered from shipped scripts without removed state reads or CDP controls (offline DOM model; no rendered layout claimed)`);
