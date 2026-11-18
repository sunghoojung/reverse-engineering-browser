// The shipped Trace value panel (apps/research-ui/value_flow_view.js) in a DOM
// model over wasm-value-flow-v2 documents: the operand list from the chosen
// row, elapsed seconds and Cancel instead of a deadline, loading and error
// states that keep the last trace, the seed-rooted tree with sources and
// sinks grouped by kind and exact counts, a path read on demand with its
// connectors named, a virtual window over a group of thousands with pages
// read as they scroll into view, callers read from the call sites route,
// omissions in full, Graph hiding and restoring the panel, the header tied to
// the trace shown after a reveal, and captured text inserted as text. Not
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
// linkedom checkboxes carry no checked state; the panel reads it.
Object.defineProperty(window.HTMLInputElement.prototype, 'checked', {
  configurable: true,
  get() { return this.hasAttribute('checked'); },
  set(value) { if (value) this.setAttribute('checked', ''); else this.removeAttribute('checked'); },
});

const rows = [
  {kind: 'section', byte_offset: 0x60, text: 'code section'},
  {kind: 'instruction', function_index: 2, byte_offset: 0x7e, text: 'i32.load { memarg: MemArg { offset: 8 } }'},
  {kind: 'instruction', function_index: 2, byte_offset: 0x89, text: 'i32.store { memarg: MemArg { offset: 0 } }'},
  {kind: 'instruction', function_index: 2, byte_offset: 0xd0, text: 'call { function_index: 0 }'},
  {kind: 'instruction', function_index: 3, byte_offset: 0xf0, text: 'call { function_index: 2 }'},
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

// Inspect mounts one page of rows; row(line) reads one of them.
const state = {sourceWasm: true, sourceEditorView: {view: {wasm: {row: line => rows[line] ?? null}}}};
const moved = [];
const pending = [];
const fetches = [];
const context = createContext({
  window, document, console, URLSearchParams, URL, AbortController, setTimeout, clearTimeout, Map, Set, Number, String, Boolean, Error, Math,
  MutationObserver: window.MutationObserver,
  requestAnimationFrame: callback => setTimeout(callback, 0),
  state,
  selectedSource: () => ({kind: 'wasm', source_type: 'artifact', artifact_id: '7', sha256: 'a'.repeat(64)}),
  // The backend finds the row for a byte; Sources moves to its page.
  revealWasmInspectionByte: async (source, offset) => {
    const line = rows.findIndex(row => row.byte_offset === offset);
    if (line < 0) return false;
    moved.push(line);
    mount();
    return true;
  },
  fetch: (url, options) => {
    fetches.push(String(url));
    return new Promise((resolve, reject) => pending.push({resolve, reject, options, url: String(url)}));
  },
});
runInContext(source, context);
const panel = document.getElementById('value-flow');
const $ = id => document.getElementById(id);
const settle = async () => { for (let turn = 0; turn < 6; turn += 1) { await nextTurn(); await new Promise(done => setTimeout(done, 1)); } };
const click = element => element.dispatchEvent(new window.Event('click', {bubbles: true}));
const line = offset => code.querySelector(`[data-local-line="${rows.findIndex(row => row.byte_offset === offset)}"]`);
const answer = (body, status = 200) => pending.shift().resolve({ok: status < 400, status, json: async () => body});
const listRows = () => [...$('value-flow-list').querySelectorAll('.value-flow-row')];
// The query of a read, by name: parameter order is the URL's own business.
const query = url => Object.fromEntries(new URL(url, 'http://local').searchParams);
// A row's visible parts, space separated, as a reader would list them.
const texts = () => listRows().map(row => [...row.querySelectorAll('.value-flow-caret, .value-flow-toggle-label, .value-flow-offset, .value-flow-role, .value-flow-kind, .value-flow-text, .value-flow-edge, .value-flow-join, .value-flow-note')]
  .map(part => part.textContent.trim()).filter(Boolean).join(' '));

// wasm-value-flow-v2 documents, as the backend writes them.
const end = (id, walk, kind, offset, extra = {}) => ({id, walk, kind, class: 'value', byte_offset: offset, function: 2, seed: false, text: kind, ...extra});
const nodeRow = (id, walk, kind, offset, extra = {}) => ({id, walk, kind, byte_offset: offset, function: 2, direction: 'backward', class: 'value', depth: 1,
  role: 'interior', seed: false, source: false, sink: false, boundary: false, results: 1, parent: 0,
  edge: {kind: 'operand', operand: 0, result: 0, locals: [], through: null}, text: kind, ...extra});
const histogram = (items, count) => {
  const kinds = new Map();
  for (const item of items) kinds.set(`${item.kind}\n${item.class}`, (kinds.get(`${item.kind}\n${item.class}`) ?? 0) + 1);
  const rows = [...kinds].map(([key, n]) => { const [kind, klass] = key.split('\n'); return {kind, class: klass, count: n}; });
  if (count !== undefined && rows.length) rows[0].count += count - items.length;
  return rows;
};
const ends = (items, count = items.length, kind = null) => ({count, filtered_count: count, kind, kinds: histogram(items, count), offset: 0, limit: 100,
  next_offset: count > items.length ? items.length : null, items});
const trace = ({seed = 0xd0, nodes = [], path_nodes = [], sources = [], sinks = [], sourceCount, sinkCount, joins = [], omissions = [], callers = null, direction = 'both', functions = [{index: 2, instructions_simulated: 40, stopped_at: null}]}) => ({
  schema: 'wasm-value-flow-v2', artifact_id: '7', sha256: 'a'.repeat(64), function_index: 2, type_index: 0, byte_offset: 0x60, byte_end: 0x100, params: 2, locals: 4, results: 1,
  evidence: 'declared_static', complete: false, status: omissions.length ? 'partial' : 'computed',
  request: {direction, control: false, interprocedural: true, node_offset: 0, node_limit: 100, source_offset: 0, source_limit: 100, source_kind: null, sink_offset: 0, sink_limit: 100, sink_kind: null, join_offset: 0, join_limit: 16},
  seed: {kind: 'instruction', byte_offset: seed, operand: null, operand_count: 2, local: null, nodes: [0]},
  instructions_simulated: 40, simulation_stopped_at: null, simulation_bytes: 4096, cached: false, functions,
  node_count: nodes.length + path_nodes.length, transport_count: 3, source_count: sourceCount ?? sources.length, sink_count: sinkCount ?? sinks.length, join_count: joins.length, boundary_count: 0,
  node_offset: 0, next_node_offset: null, nodes, path_nodes, joins, sources: ends(sources, sourceCount), sinks: ends(sinks, sinkCount), callers, omissions,
  limits: {max_body_bytes: 7654321, max_locals: 50000, simulation_memory_bytes: 1 << 30, max_expression_bytes: 160, max_text_bytes: 160},
  notice: 'Declared static value flow from the module bytes.',
});
const seedNode = extra => nodeRow(0, 0, 'import_call', 0xd0, {direction: 'seed', depth: 0, role: 'seed', seed: true, parent: null, edge: null, callee: 0, import: {module: 'env', name: 'send'}, text: 'call 0', ...extra});

await settle();
assert.equal(panel.hidden, false, 'Inspect rows show the panel');
assert.equal($('value-flow-run').disabled, true, 'nothing to trace before a row');
assert.equal($('value-flow-target').textContent, 'Select an instruction row');
assert.equal(panel.dataset.empty, '', 'an empty panel says so, for the pane layout');

// A store lists its two operands before any trace; a call lists none until one.
click(line(0x89).querySelector('.source-text'));
assert.deepEqual($('value-flow-operand').options.map(option => option.textContent), ['Whole instruction', 'Operand 0', 'Operand 1']);
click(line(0xd0).querySelector('.source-text'));
assert.deepEqual($('value-flow-operand').options.map(option => option.textContent), ['Whole instruction']);
assert.match($('value-flow-target').textContent, /0xd0/);
console.log('PASS Trace value operands: fixed-arity rows list their operands before a trace, calls wait for operand_count');

// Loading, then a small trace: the seed, both sections open with their groups
// and items, an end that is both a source and a sink, captured markup in its
// text, callers and omissions.
click($('value-flow-run'));
assert.match($('value-flow-status').textContent, /Tracing 0xd0… 0 s\. Cancel stops the backend analysis\./);
assert.equal($('value-flow-run').textContent, 'Cancel', 'a running trace has no deadline; its button stops it');
assert.equal($('value-flow-run').disabled, false);
assert.deepEqual(query(fetches[0]), {artifact_id: '7', function: '2', offset: '208', direction: 'both', control: 'false', interprocedural: 'true', node_limit: '100', source_limit: '100', sink_limit: '100', join_limit: '16'});
answer(trace({
  nodes: [seedNode()],
  sources: [end(1, 1, 'load', 0x7e, {text: '<img src=x onerror=alert(1)>'}), end(2, 2, 'param', 0x60, {local: 0, class: 'address'}), end(3, 3, 'const', 0x9a, {class: 'control'})],
  // The same instruction reached forward is its own node entry.
  sinks: [end(4, 4, 'store', 0x89, {text: 'i32.store'}), end(7, 7, 'load', 0x7e, {text: '<img src=x onerror=alert(1)>'})],
  callers: {count: 2, indirect: true, undecoded: 0},
  omissions: ['The operand stack is empty at byte 31; the module may not validate, and the missing operand is an unknown value.'],
}));
await settle();
assert.equal($('value-flow-operand').options.length, 3, 'operand_count from the trace lists the call operands');
let shown = texts();
assert.match(shown[0], /^0xd0 seed env\.send · import call call 0$/, `the seed row leads: ${shown[0]}`);
assert.match(shown[1], /Comes from · 3 sources/);
assert.match(shown[2], /^▾ load · 1$/);
assert.match(shown[3], /^▸ 0x7e source load <img src=x onerror=alert\(1\)>$/, `a source item under its kind: ${shown[3]}`);
assert.match(shown[4], /param · 1 \(1 address\)/, 'a class other than value is counted on the group');
assert.match(shown[5], /0x60 source · address local 0 · param · \(declaration\)/);
assert.match(shown[6], /const · 1 \(1 decides\)/);
assert.match(shown[8], /Goes to · 2 sinks/);
assert.ok(shown.some(text => /load · 1/.test(text)) && shown.some(text => /0x7e sink/.test(text)), 'the load is also a sink');
assert.match(shown.at(-1), /Callers · 2 direct call sites of function 2 · also reachable indirectly/);
assert.equal($('value-flow-list').querySelectorAll('img').length, 0, 'captured text is text');
assert.match($('value-flow-status').textContent, /1 nodes · 3 sources · 2 sinks · 0 joins · 1 function · partial/);
assert.equal($('value-flow-omissions').hidden, false);
assert.match($('value-flow-omissions').querySelector('summary').textContent, /1 omission/);
assert.match($('value-flow-omissions').querySelector('li').textContent, /at byte 0x1f;/, 'offsets read as hex, like the listing');
assert.equal(code.querySelector('[data-value-flow="seed"]') !== null, true, 'the seed row is marked');
assert.equal(line(0x7e).dataset.valueFlow, 'source', 'an end is marked');
assert.equal(panel.dataset.empty, undefined, 'a shown trace lets the pane layout resize the panel');
console.log('PASS Trace value tree: seed, sections and groups with exact counts, classes, both ends, marks, omissions, inert captured text');

// A path on demand: the node page at the item's walk position carries its
// ancestors; connectors name the edge, the join's branch and the locals.
const loadRow = listRows()[3];
assert.equal(loadRow.getAttribute('aria-expanded'), 'false');
click(loadRow.querySelector('.value-flow-path'));
await settle();
assert.deepEqual(query(fetches.at(-1)), {artifact_id: '7', function: '2', offset: '208', direction: 'both', control: 'false', interprocedural: 'true', node_offset: '1', node_limit: '1', source_limit: '1', sink_limit: '1', join_limit: '32'}, 'the path is one node page');
assert.match(texts()[4], /reading the path…/);
answer(trace({
  nodes: [nodeRow(1, 1, 'load', 0x7e, {role: 'source', source: true, parent: 5, edge: {kind: 'local_set', operand: 0, result: 0, locals: [3], through: {kind: 'merge', operand: 0, result: 0, via: 'br_table', via_offset: 0x9c}}})],
  path_nodes: [nodeRow(5, 5, 'phi', 0x70, {join: 'loop', local: 3, text: 'join of local 3', parent: 0, edge: {kind: 'local', operand: 0, result: 0, locals: [3], through: {kind: 'argument', operand: 0, result: 0}}}), seedNode()],
  joins: [{node: 5, join: 'loop', byte_offset: 0x70, function: 2, local: 3, incoming_count: 2, incoming_offset: 0, next_incoming_offset: null,
    incoming: [{from: null, from_kind: 'local_init', from_offset: 0x60, via: 'entry', via_offset: 0x70}, {from: 1, from_kind: 'load', from_offset: 0x7e, via: 'br_table', via_offset: 0x9c}]}],
}));
await settle();
shown = texts();
assert.equal(loadRow.getAttribute('aria-expanded') === 'true' || listRows()[3].getAttribute('aria-expanded') === 'true', true);
assert.match(shown[4], /^join · via br_table @0x9c · through local 3 0x70 step loop join · local 3 join of local 3 2 incoming: entry @0x70 ← 0x60, br_table @0x9c ← 0x7e$/, `the first step: ${shown[4]}`);
assert.match(shown[5], /^argument · 0 · through local 3 0xd0 seed env\.send · import call call 0$/, `the path ends at the seed: ${shown[5]}`);
const steps = listRows().filter(row => row.classList.contains('is-step'));
assert.equal(steps.length, 2);
assert.equal(steps[0].style.getPropertyValue('--depth'), '3');
assert.equal(steps[1].style.getPropertyValue('--depth'), '4', 'steps indent toward the seed');
click(listRows()[3].querySelector('.value-flow-path'));
await settle();
assert.equal(listRows().filter(row => row.classList.contains('is-step')).length, 0, 'the path folds without a read');
assert.equal(fetches.length, 2);
console.log('PASS Trace value path: one node page per opened row, connectors with edge, branch and locals, join incoming entries');

// Callers come from the call sites route when the row opens.
click(listRows().at(-1).querySelector('.value-flow-section'));
await settle();
assert.match(fetches.at(-1), /\/api\/wasm\/call-sites\?/);
assert.deepEqual(query(fetches.at(-1)), {artifact_id: '7', function: '2', offset: '0', limit: '200'});
assert.match(texts().at(-2), /reading…/);
answer({schema: 'wasm-call-sites-v1', artifact_id: '7', sha256: 'a'.repeat(64), byte_size: 1, function_index: 2, imported: false, count: 2, offset: 0, limit: 200, next_offset: null,
  sites: [{caller: 3, byte_offset: 0xf0, tail: false}, {caller: 4, byte_offset: 0x140, tail: true}], indirect: {exported: true, start: false, element: false, referenced: false}, undecoded: [], notice: ''});
await settle();
shown = texts();
assert.match(shown.at(-3), /^0xf0 caller func 3 · call$/);
assert.match(shown.at(-2), /^0x140 caller func 4 · return_call$/);
assert.match(shown.at(-1), /also reachable indirectly/);
click(listRows().at(-3).querySelector('.value-flow-link'));
await settle();
assert.deepEqual(moved, [4], 'a caller row reveals the call in its own function');
console.log('PASS Trace value callers: the call sites route lists every direct caller, with tail calls named');

// A failed read keeps the last trace.
click($('value-flow-run'));
answer({error: 'boom at byte 100'}, 500);
await settle();
assert.match($('value-flow-status').textContent, /boom at byte 0x64.*last trace is unchanged/);
assert.ok(listRows().length > 8, 'the rows stay');
console.log('PASS Trace value error: a failed read names the error and keeps the last trace');

// Cancel stops the request, and so the backend analysis, and keeps the last trace.
click($('value-flow-run'));
const running = pending[0];
click($('value-flow-run'));
assert.equal(running.options.signal.aborted, true, 'Cancel aborts the request');
pending.shift().reject(Object.assign(new Error('aborted'), {name: 'AbortError'}));
await settle();
assert.match($('value-flow-status').textContent, /cancelled; its backend analysis was stopped\. The last trace is unchanged/);
assert.equal($('value-flow-run').textContent, 'Trace value');
assert.ok(listRows().length > 8, 'the rows stay');
console.log('PASS Trace value Cancel: a running trace shows elapsed seconds, and Cancel stops it and keeps the last trace');

// Revealing a row from the list selects it, but the header keeps naming the
// trace shown; the button names the row it would trace next.
click(listRows()[3].querySelector('.value-flow-link'));
await settle();
assert.deepEqual(moved, [4, 1]);
line(0x7e).querySelector('.source-gutter').dispatchEvent(new window.Event('focusin', {bubbles: true}));
assert.match($('value-flow-target').textContent, /0xd0/, 'the header names the trace shown');
assert.equal($('value-flow-run').textContent, 'Trace 0x7e');
console.log('PASS Trace value header: a reveal leaves the header on the trace shown and names the next seed on the button');

// A large slice: 5,000 loads in one group stay folded, open to a window of
// rows, and read a page when the window scrolls to rows not yet read.
$('value-flow-direction').value = 'backward';
$('value-flow-control').checked = true;
click($('value-flow-run'));
assert.equal(query(fetches.at(-1)).direction, 'backward');
assert.equal(query(fetches.at(-1)).control, 'true');
const firstPage = Array.from({length: 100}, (_, index) => end(10 + index, 10 + index, 'load', 0x7e + index * 2));
answer(trace({nodes: [seedNode()], sources: firstPage, sourceCount: 5000, direction: 'backward'}));
await settle();
shown = texts();
assert.match($('value-flow-status').textContent, /5000 sources · 0 sinks/);
assert.deepEqual(shown, [shown[0], '▾ Comes from · 5000 sources', '▸ load · 5000'], 'a large group stays folded');
click(listRows()[2].querySelector('.value-flow-group'));
await settle();
assert.ok(listRows().length <= 30, `a window of rows is drawn, not 5,000: ${listRows().length}`);
assert.equal($('value-flow-list').style.paddingTop, '0px');
assert.match($('value-flow-list').style.paddingBottom, /^\d+px$/);
assert.ok(parseInt($('value-flow-list').style.paddingBottom, 10) > 24 * 4900, 'the undrawn rows keep the scroll height');
assert.equal(fetches.length, 6, 'the first page needs no read');
// Rows 1,012 to 1,040 of the tree: items 1,009 to 1,037, one page.
$('value-flow-scroll').scrollTop = 24 * 1020;
$('value-flow-scroll').dispatchEvent(new window.Event('scroll'));
await settle();
assert.ok(listRows().some(row => row.classList.contains('is-pending')), 'rows not read yet say so');
const pageQuery = query(fetches.at(-1));
assert.deepEqual([pageQuery.source_kind, pageQuery.source_offset, pageQuery.source_limit, pageQuery.node_limit, pageQuery.sink_limit], ['load', '1000', '200', '1', '1'], 'the page of the rows in view is read, and nothing else');
const page = Array.from({length: 200}, (_, index) => end(2000 + index, 2000 + index, 'load', 0x1000 + index * 2));
answer(trace({nodes: [seedNode()], sources: page, sourceCount: 5000, direction: 'backward'}));
await settle();
assert.ok(!listRows().some(row => row.classList.contains('is-pending')), 'read rows replace the placeholders');
assert.ok(texts().some(text => /^0x1000/.test(text) || /0x10[0-9a-f]{2} source/.test(text)), `rows of the page appear: ${texts().slice(0, 3)}`);
console.log('PASS Trace value virtual window: folded large groups, a window of rows, pages read as they scroll into view');

// Keyboard: arrows walk the tree beyond the drawn window; Left folds.
$('value-flow-scroll').scrollTop = 0;
$('value-flow-scroll').dispatchEvent(new window.Event('scroll'));
await settle();
const firstLink = listRows()[0].querySelector('.value-flow-link');
firstLink.focus();
listRows()[0].dispatchEvent(Object.assign(new window.Event('keydown', {bubbles: true}), {key: 'End'}));
await settle();
// The DOM model does not track focus; the window moving to the last row is
// the observable part.
assert.ok(listRows().some(row => row.dataset.index === String(2 + 5000)), 'End draws the last row of the tree');
assert.ok(($('value-flow-scroll').scrollTop || 0) > 24 * 4900, 'and scrolls to it');
$('value-flow-scroll').scrollTop = 0;
$('value-flow-scroll').dispatchEvent(new window.Event('scroll'));
await settle();
const groupRow = listRows().find(row => row.classList.contains('is-group'));
groupRow.querySelector('button').focus();
groupRow.dispatchEvent(Object.assign(new window.Event('keydown', {bubbles: true}), {key: 'ArrowLeft'}));
await settle();
assert.deepEqual(texts().slice(1), ['▾ Comes from · 5000 sources', '▸ load · 5000'], 'Left folds the group');
console.log('PASS Trace value keyboard: End moves through undrawn rows, Left folds a group');

// Graph hides the panel and its marks; closing Graph restores both.
document.querySelector('.sources-editor').setAttribute('data-graph', 'true');
await settle();
assert.equal(panel.hidden, true, 'Graph hides the panel');
assert.equal(code.querySelector('[data-value-flow]'), null, 'and its marks');
document.querySelector('.sources-editor').removeAttribute('data-graph');
await settle();
assert.equal(panel.hidden, false);
assert.equal(listRows().length, 3, 'the same trace returns');
assert.notEqual(code.querySelector('[data-value-flow]'), null);
// Hex hides the panel and drops the trace: Inspect again starts empty, with
// no rows, marks or chosen seed left from it.
state.sourceWasm = false;
mount();
await settle();
assert.equal(panel.hidden, true);
state.sourceWasm = true;
mount();
await settle();
assert.equal(panel.hidden, false);
assert.equal(listRows().length, 0, 'the trace is gone');
assert.equal($('value-flow-scroll').hidden, true);
assert.equal($('value-flow-omissions').hidden, true);
assert.equal(code.querySelector('[data-value-flow]'), null, 'no marks remain');
assert.equal($('value-flow-run').disabled, true, 'no seed is carried over');
assert.equal($('value-flow-target').textContent, 'Select an instruction row');
assert.equal(panel.dataset.empty, '');
console.log('PASS Trace value Graph and Hex: Graph hides and restores the trace, Hex drops it');
