// The shipped Trace value panel (apps/research-ui/value_flow_view.js) in a DOM
// model: the operand list from the chosen row, loading and error states that
// keep the last trace, Graph hiding and restoring the panel, the header tied
// to the trace shown after a reveal, and captured text inserted as text. Not
// rendered QA; rendered acceptance is test41TraceValueInInspect.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createContext, runInContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const require = createRequire(import.meta.url);
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const source = await readFile(new URL('../apps/research-ui/value_flow_view.js', import.meta.url), 'utf8');
const {window, document} = parseHTML(`<!doctype html><button id="source-wasm"></button>
  <section class="sources-editor"><div id="source-view-split"><code id="source-code"></code></div></section>`);

// linkedom has no HTMLSelectElement.value; the panel reads and writes it.
Object.defineProperty(window.HTMLSelectElement.prototype, 'value', {
  configurable: true,
  get() {
    const options = [...this.querySelectorAll('option')];
    return (options.find(option => option.hasAttribute('selected')) ?? options[0])?.getAttribute('value') ?? '';
  },
  set(value) {
    for (const option of this.querySelectorAll('option')) {
      if (option.getAttribute('value') === String(value)) option.setAttribute('selected', '');
      else option.removeAttribute('selected');
    }
  },
});
Object.defineProperty(window.HTMLSelectElement.prototype, 'options', {configurable: true, get() { return [...this.querySelectorAll('option')]; }});

const rows = [
  {kind: 'section', byte_offset: 0x60, text: 'code section'},
  {kind: 'instruction', function_index: 2, byte_offset: 0x7e, text: 'i32.load { memarg: MemArg { offset: 8 } }'},
  {kind: 'instruction', function_index: 2, byte_offset: 0x89, text: 'i32.store { memarg: MemArg { offset: 0 } }'},
  {kind: 'instruction', function_index: 2, byte_offset: 0xd0, text: 'call { function_index: 0 }'},
];
const code = document.getElementById('source-code');
const mount = () => code.replaceChildren(...rows.map((row, line) => {
  const element = document.createElement('span');
  element.className = 'source-line';
  element.dataset.localLine = String(line);
  const gutter = document.createElement('button');
  gutter.className = 'source-gutter';
  const text = document.createElement('span');
  text.className = 'source-text';
  text.textContent = row.text;
  element.append(gutter, text);
  return element;
}));
mount();

const state = {sourceWasm: true, sourceEditorView: {view: {wasmRows: rows}}};
const moved = [];
const pending = [];
const fetches = [];
const context = createContext({
  window, document, console, URLSearchParams, AbortController, setTimeout, clearTimeout, Map, Set, Number, String, Boolean, Error,
  MutationObserver: window.MutationObserver,
  requestAnimationFrame: callback => setTimeout(callback, 0),
  state,
  selectedSource: () => ({kind: 'wasm', source_type: 'artifact', artifact_id: '7', sha256: 'a'.repeat(64)}),
  moveSourceWindow: (line, column, options) => { moved.push(line); mount(); return true; },
  fetch: (url, options) => {
    fetches.push(String(url));
    return new Promise((resolve, reject) => pending.push({resolve, reject, options}));
  },
});
runInContext(source, context);
const panel = document.getElementById('value-flow');
const $ = id => document.getElementById(id);
const settle = async () => { for (let turn = 0; turn < 6; turn += 1) { await nextTurn(); await new Promise(done => setTimeout(done, 1)); } };
const click = element => element.dispatchEvent(new window.Event('click', {bubbles: true}));
const line = offset => code.querySelector(`[data-local-line="${rows.findIndex(row => row.byte_offset === offset)}"]`);
const answer = (body, status = 200) => pending.shift().resolve({ok: status < 400, status, json: async () => body});
const node = (id, kind, offset, extra = {}) => ({id, kind, byte_offset: offset, role: 'interior', source: false, sink: false, direction: 'backward', depth: 1, results: 1, text: kind, ...extra});
const trace = (seed, nodes, extra = {}) => ({schema: 'wasm-value-flow-v1', artifact_id: '7', sha256: 'a'.repeat(64), function_index: 2, status: 'computed',
  node_count: nodes.length, nodes, edges: [], joins: [], sources: nodes.filter(n => n.source).map(n => n.id), sinks: nodes.filter(n => n.sink).map(n => n.id),
  omissions: [], seed: {kind: 'instruction', byte_offset: seed, operand: null, operand_count: 1, local: null, nodes: [0]}, ...extra});

await settle();
assert.equal(panel.hidden, false, 'Inspect rows show the panel');
assert.equal($('value-flow-run').disabled, true, 'nothing to trace before a row');
assert.equal($('value-flow-target').textContent, 'Select an instruction row');

// A store lists its two operands before any trace; a call lists none until one.
click(line(0x89).querySelector('.source-text'));
assert.deepEqual($('value-flow-operand').options.map(option => option.textContent), ['Whole instruction', 'Operand 0', 'Operand 1']);
click(line(0xd0).querySelector('.source-text'));
assert.deepEqual($('value-flow-operand').options.map(option => option.textContent), ['Whole instruction']);
assert.match($('value-flow-target').textContent, /0xd0/);
console.log('PASS Trace value operands: fixed-arity rows list their operands before a trace, calls wait for operand_count');

// Loading, then a trace with an end that is both a source and a sink and
// captured markup in its text.
click($('value-flow-run'));
assert.match($('value-flow-status').textContent, /Tracing 0xd0/);
assert.match(fetches[0], /function=2&offset=208&direction=both&max_nodes=512/);
answer(trace(0xd0, [
  node(0, 'import_call', 0xd0, {role: 'seed', source: true, direction: 'seed', depth: 0, import: {module: 'env', name: 'send'}}),
  node(1, 'load', 0x7e, {role: 'source', source: true, sink: true, text: '<img src=x onerror=alert(1)>'}),
]));
await settle();
const items = [...$('value-flow-list').querySelectorAll('.value-flow-row')];
assert.equal(items.length, 2);
assert.equal(items[1].querySelector('.value-flow-role').textContent, 'source · sink', 'both ends are shown');
assert.equal($('value-flow-list').querySelectorAll('img').length, 0, 'captured text is text');
assert.match(items[1].querySelector('.value-flow-text').textContent, /<img src=x/);
assert.match($('value-flow-status').textContent, /2 nodes · 2 sources · 1 sinks/);
assert.equal(code.querySelector('[data-value-flow="seed"]') !== null, true, 'the seed row is marked');
console.log('PASS Trace value loading and slice: status while tracing, rows with both ends, marks, inert captured text');

// A failed read keeps the last trace.
click($('value-flow-run'));
answer({error: 'boom'}, 500);
await settle();
assert.match($('value-flow-status').textContent, /boom.*last trace is unchanged/);
assert.equal($('value-flow-list').querySelectorAll('.value-flow-row').length, 2, 'the rows stay');
console.log('PASS Trace value error: a failed read names the error and keeps the last trace');

// Revealing a row from the list selects it, but the header keeps naming the
// trace shown; the button names the row it would trace next.
click(items[1].querySelector('.value-flow-link'));
assert.deepEqual(moved, [1]);
line(0x7e).querySelector('.source-gutter').dispatchEvent(new window.Event('focusin', {bubbles: true}));
assert.match($('value-flow-target').textContent, /0xd0/, 'the header names the trace shown');
assert.equal($('value-flow-run').textContent, 'Trace 0x7e');
console.log('PASS Trace value header: a reveal leaves the header on the trace shown and names the next seed on the button');

// Graph hides the panel and its marks; closing Graph restores both.
document.querySelector('.sources-editor').setAttribute('data-graph', 'true');
await settle();
assert.equal(panel.hidden, true, 'Graph hides the panel');
assert.equal(code.querySelector('[data-value-flow]'), null, 'and its marks');
document.querySelector('.sources-editor').removeAttribute('data-graph');
await settle();
assert.equal(panel.hidden, false);
assert.equal($('value-flow-list').querySelectorAll('.value-flow-row').length, 2, 'the same trace returns');
assert.notEqual(code.querySelector('[data-value-flow]'), null);
// Hex drops the panel and the trace.
state.sourceWasm = false;
mount();
await settle();
assert.equal(panel.hidden, true);
console.log('PASS Trace value Graph and Hex: Graph hides and restores the trace, Hex drops it');
