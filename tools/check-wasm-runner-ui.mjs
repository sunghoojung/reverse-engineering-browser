// The shipped Run offline dialog (apps/research-ui/wasm_runner.js) in a DOM
// model: it is offered only for Wasm artifacts, sends nothing until the
// researcher confirms, sends the confirmation and the chosen inputs, renders
// the outcome and import calls, and inserts captured names and values as text.
// Not rendered QA; rendered acceptance is test42 in the packaged-app gate.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {runInContext, createContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const require = createRequire(import.meta.url);
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const source = await readFile(new URL('../apps/research-ui/wasm_runner.js', import.meta.url), 'utf8');
const {wasmRunValues, wasmRunPairs, wasmRunOutcomeText} = require('../apps/research-ui/wasm_runner.js');

assert.deepEqual(wasmRunValues('i32 7, f64 -1.5 ,  v128 0x1'), [{type: 'i32', value: '7'}, {type: 'f64', value: '-1.5'}, {type: 'v128', value: '0x1'}]);
assert.deepEqual(wasmRunValues(''), []);
assert.throws(() => wasmRunValues('i32'), /Argument 1/);
assert.throws(() => wasmRunValues('i33 1'), /Argument 1/);
assert.deepEqual(wasmRunPairs('0:32, 16:ab', 'Memory read', 'length'), [[0, '32'], [16, 'ab']]);
assert.throws(() => wasmRunPairs('x:1', 'Memory read', 'length'), /Memory read 1/);
assert.equal(wasmRunOutcomeText({outcome: {status: 'trap', trap_kind: 'unreachable', phase: 'call'}}), 'Trapped (unreachable) · call phase');

const {window, document} = parseHTML('<!doctype html><body><button id="run">Run offline…</button></body>');
const proto = window.HTMLElement.prototype;
proto.showModal ??= function () { this.open = true; };
proto.close ??= function () { this.open = false; this.dispatchEvent(new window.Event('close')); };
proto.focus ??= function () {};
// linkedom has no select.value; a browser returns the selected, else first, option's value.
if (document.createElement('select').value === undefined) {
  Object.defineProperty(window.HTMLSelectElement.prototype, 'value', {get() {
    const options = [...this.querySelectorAll('option')];
    return (options.find(option => option.hasAttribute('selected')) ?? options[0])?.value ?? '';
  }});
}
const posts = [];
let answer = null;
const sha = 'a'.repeat(64);
const markup = '<img src=x onerror=alert(1)>';
const context = createContext({
  window, document, console, AbortController, setTimeout, clearTimeout, JSON, Number, String, Map, Error, TypeError,
  fetch: async (url, init = {}) => {
    if (url.startsWith('/api/wasm/functions?')) {
      return new Response(JSON.stringify({schema: 'wasm-function-index-v1', artifact_id: '9', status: 'decoded',
        functions: [[1, 10, 20, 0], [2, 20, 40, 1]], names: [[2, markup]]}));
    }
    posts.push({url, init});
    return new Response(JSON.stringify(answer.body), {status: answer.status});
  }
});
runInContext(`${source};globalThis.api = {createWasmRunDialog};`, context);
let selected = {kind: 'javascript', source_type: 'artifact', artifact_id: '9', sha256: sha};
const button = document.getElementById('run');
const dialog = context.api.createWasmRunDialog({button, getSource: () => selected});
dialog.sync(selected);
assert.equal(button.hidden, true, 'Run offline is offered only for a Wasm artifact');
selected = {...selected, kind: 'wasm'};
dialog.sync(selected);
assert.equal(button.hidden, false);
button.dispatchEvent(new window.Event('click'));
for (let i = 0; i < 10; i += 1) await nextTurn();
const node = document.querySelector('.wasm-run-dialog');
assert.equal(node.open, true);
assert.match(node.querySelector('.wasm-run-banner').textContent, /local sandbox.*every import stubbed.*Nothing runs until you confirm/s);
const options = [...node.querySelectorAll('option')];
assert.deepEqual(options.map(option => option.value), ['2', '1'], 'Named functions lead the list');
assert.equal(options[0].textContent, `${markup} (func 2)`);
assert.equal(node.querySelector('img'), null, 'A captured name stays text');
const runButton = [...node.querySelectorAll('button')].find(element => element.textContent === 'Run');
assert.equal(runButton.disabled, true, 'Run waits for the confirmation');
runButton.dispatchEvent(new window.Event('click'));
for (let i = 0; i < 5; i += 1) await nextTurn();
assert.equal(posts.length, 0, 'Nothing is sent without the confirmation');

const fields = [...node.querySelectorAll('input, textarea, select')];
const byLabel = label => [...node.querySelectorAll('.wasm-run-field')].find(field => field.querySelector('.wasm-run-label')?.textContent === label).querySelector('input, textarea, select');
byLabel('Arguments').value = 'i32 7, i32 5';
byLabel('Import stubs (JSON)').value = '[{"module":"env","field":"now","results":[{"type":"f64","value":"0"}]}]';
byLabel('Memory reads after the call').value = '0:4';
byLabel('Fuel').value = '5000';
const confirm = node.querySelector('.wasm-run-confirm input');
confirm.checked = true;
confirm.dispatchEvent(new window.Event('change'));
assert.equal(runButton.disabled, false);
assert.ok(fields.length >= 9);
answer = {status: 200, body: {schema: 'wasm-run-v1', run_id: 'wr-1', provenance: {module_sha256: sha, limits: {fuel: 5000}},
  outcome: {status: 'import_trap', phase: 'call', trap_kind: null, message: `Import ${markup}.x was called`},
  function: {index: 2, export: markup, byte_offset: 20, byte_end: 40}, results: null, fuel_consumed: 12, elapsed_ms: 1,
  import_calls_total: 1, import_calls_truncated: false, stored: true,
  import_calls: [{sequence: 0, function_index: 0, module: markup, field: 'now', args: [{type: 'i32', value: markup}], args_truncated: false, outcome: 'trapped', results: null}],
  memory_reads: [{offset: 0, length: 4, status: 'read', sha256: 'b'.repeat(64), hex: '0a000000'}]}};
runButton.dispatchEvent(new window.Event('click'));
for (let i = 0; i < 10; i += 1) await nextTurn();
assert.equal(posts.length, 1);
assert.equal(posts[0].url, '/api/wasm/runs');
assert.equal(posts[0].init.method, 'POST');
const body = JSON.parse(posts[0].init.body);
assert.deepEqual(body, {artifact_id: '9', sha256: sha, function_index: 2, args: [{type: 'i32', value: '7'}, {type: 'i32', value: '5'}],
  imports: [{module: 'env', field: 'now', results: [{type: 'f64', value: '0'}]}], memory_reads: [{offset: 0, length: 4}],
  limits: {fuel: 5000}, confirm_offline_execution: true});
const output = node.querySelector('.wasm-run-output');
assert.equal(output.hidden, false);
assert.equal(node.querySelector('.wasm-run-outcome').textContent, 'Import trapped · call phase');
assert.match(output.textContent, /Import calls · 1 attempted/);
assert.match(output.textContent, /trapped \(no stub value\)/);
assert.match(output.textContent, /0:4 · read · 0a000000/);
assert.equal(node.querySelector('img'), null, 'Captured values in the record stay text');

// A refusal is shown as the server words it; nothing is rendered as a result.
answer = {status: 409, body: {error: 'The artifact’s SHA-256 differs from the request; nothing ran'}};
runButton.dispatchEvent(new window.Event('click'));
for (let i = 0; i < 10; i += 1) await nextTurn();
const error = node.querySelector('.wasm-run-error');
assert.equal(error.hidden, false);
assert.match(error.textContent, /nothing ran/);
// A bad field is named before anything is sent.
byLabel('Arguments').value = 'seven';
runButton.dispatchEvent(new window.Event('click'));
for (let i = 0; i < 5; i += 1) await nextTurn();
assert.equal(posts.length, 2);
assert.match(error.textContent, /Argument 1/);
console.log('Run offline dialog: confirmation gate, request, outcome and inert captured text verified');
