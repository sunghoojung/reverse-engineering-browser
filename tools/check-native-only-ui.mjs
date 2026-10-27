#!/usr/bin/env node
// Static shipped-asset contract, not rendered browser QA.
import assert from 'node:assert/strict';
import {readFile, readdir, access} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {Script} from 'node:vm';
const root = fileURLToPath(new URL('..', import.meta.url));
const ui = join(root, 'apps/research-ui');
const html = await readFile(join(ui, 'index.html'), 'utf8');
const app = await readFile(join(ui, 'app.js'), 'utf8');
const state = await readFile(join(ui, 'app_state.js'), 'utf8');
new Script(app, {filename: 'app.js'});
new Script(state, {filename: 'app_state.js'});
for (const file of await readdir(ui)) {
  if (!file.endsWith('.js')) continue;
  const source = await readFile(join(ui, file), 'utf8');
  assert(!/fetch(?:er)?\s*\(\s*['"`]\/api\/debugger/.test(source), `${file} must not call the removed debugger API`);
  assert(!/\b(?:runExperimentAction|debuggerAction|loadScriptContent|runtimeHooksState|renderRuntimeHookTraffic|bindRuntimeFieldTest)\s*\(/.test(source), `${file} must not call removed live controls`);
  assert(!/new\s+WebSocket\s*\(/.test(source), `${file} must not open a debugger websocket`);
}
for (const name of ['debuggerAction', 'refreshDebugger', 'scheduleDebuggerRefresh', 'loadScriptContent', 'toggleLineBreakpoint',
  'runExperimentAction', 'runMemoryOriginTrace', 'runCollectionRequest', 'installCapturedClientWorkflow']) {
  assert(!new RegExp(`\\bfunction\\s+${name}\\b`).test(app), `removed action ${name} must not survive as an inert stub`);
}
const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
for (const id of ['screen-memory', 'screen-experiments', 'debug-resume', 'watch-form', 'source-tab-page',
  'source-hook-pivot', 'collection-run', 'collection-create-context', 'captured-client-review']) {
  assert(!ids.has(id), `${id} must be removed, not hidden`);
}
for (const id of ['screen-sources', 'source-code', 'source-sidebar', 'screen-api-collection', 'screen-vm',
  'vm-owned-debugger', 'native-console-panel', 'captured-export-dialog']) assert(ids.has(id), `native/static feature ${id} must remain`);
for (const match of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)) await access(join(ui, match[1]));
for (const file of ['element_screenshot.js', 'local_override_manager.js', 'captured_vm_lab.js', 'request_value_test.js']) {
  await assert.rejects(access(join(ui, file)), {code: 'ENOENT'}, `removed executable asset ${file} must not ship`);
}
const coordinator = await readFile(join(ui, 'macos/LiveSessionCoordinator.swift'), 'utf8');
assert(!/OriginTraceDebuggerTransport|REB_DEBUGGER_TRANSPORT_BINARY|REB_CDP_NETWORK_CAPTURE/.test(coordinator));
assert(app.includes('const nodes = window.rows.map('), 'static source line rendering must remain');
assert(app.includes('const sourceFactsPanel = createSourceFactsPanel('), 'static source facts must remain');
assert(app.includes('installCapturedExportDialog('), 'local evidence export must remain');
assert(app.includes('renderNativeWasmObservations'), 'native Wasm observation viewer must remain');
console.log('PASS native-only shipped UI contract (static checks; no browser render claimed)');
