// Wasm function names (protocol/wasm-function-names-v1.md). Runs the shipped
// evidence_names.js and wasm_function_names.js, and the Inspect, Graph and
// Flow hooks, in a LinkeDOM document; only HTTP is substituted. This is not
// rendered QA: tools/origin-trace-rendered-ui test39 covers the packaged app.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {namesModels} from './check-evidence-names.mjs';

const {parseHTML} = createRequire(new URL('ui-startup-deps/', import.meta.url))('linkedom');
const root = new URL('..', import.meta.url).pathname;
const read = path => readFile(join(root, path), 'utf8');
const settle = () => new Promise(resolve => setTimeout(resolve, 0));
const SHA = 'a'.repeat(64), OTHER = 'b'.repeat(64);

// The empty library comes from app_state.js, so this fixture follows the
// shipped Analyst shape.
let emptyLibrary = null;
function library() {
  const value = JSON.parse(JSON.stringify(emptyLibrary()));
  value.generation = 1; value.updated_at_ms = 1000;
  return value;
}
function server(initial) {
  const state = {library: initial, posts: []};
  state.fetcher = async (url, options = {}) => {
    if (options.method !== 'POST') return Response.json(state.library);
    const request = JSON.parse(options.body);
    state.posts.push(request);
    if (request.expected_generation !== state.library.generation) return Response.json({error: 'stale'}, {status: 409});
    state.library = {...state.library, generation: state.library.generation + 1,
      files: request.files.map(file => ({...file, content_bytes: Buffer.byteLength(file.content), created_at_ms: 1000, updated_at_ms: 1001}))};
    return Response.json(state.library);
  };
  return state;
}

async function checkDocument() {
  const models = await namesModels(root);
  const {api, validateLibrary} = models;
  emptyLibrary = models.emptyLibrary;
  const identity = api.wasmFunctionIdentity(SHA, 5);
  assert.deepEqual({...identity}, {type: 'wasm-function', sha256: SHA, function: 5});
  assert.equal(api.wasmFunctionKey(SHA, 5), `wasm-function:${SHA}:5`, 'The key the backend uses');
  for (const [sha, index] of [[SHA.toUpperCase(), 1], [SHA, -1], [SHA, 1.5], [SHA, 4294967296], ['abc', 1]]) assert.equal(api.wasmFunctionIdentity(sha, index), null);
  const v1 = api.empty();
  assert.equal(v1.contract_version, 1);
  assert(api.validate(v1), 'Version 1 still validates');
  const named = api.serialize(api.apply(v1, identity, 'encode_payload'));
  assert.equal(named.contract_version, 2);
  assert.deepEqual(Object.keys(named), ['document_kind', 'contract_version', 'scope', 'requests', 'artifacts', 'vm_programs', 'wasm_modules']);
  assert.deepEqual(JSON.parse(JSON.stringify(named.wasm_modules)), [{sha256: SHA, functions: [{function: 5, name: 'encode_payload'}]}]);
  assert(api.validate(named));
  assert.equal(api.index(named).get(api.keyOf(identity)), 'encode_payload');
  const cleared = api.serialize(api.apply(named, identity, ''));
  assert.equal(cleared.contract_version, 1, 'Clearing the last Wasm name writes version 1 again');
  assert(!('wasm_modules' in cleared));
  for (const bad of [
    {...v1, wasm_modules: []},
    {...named, wasm_modules: [{sha256: SHA, functions: []}]},
    {...named, wasm_modules: [{sha256: SHA, functions: [{function: 1, name: 'x'}, {function: 1, name: 'y'}]}]},
    {...named, wasm_modules: [{sha256: SHA, functions: [{function: 1, name: 'x'}]}, {sha256: SHA, functions: [{function: 2, name: 'y'}]}]},
    {...named, wasm_modules: [{sha256: SHA, functions: [{function: 1, name: 'x', note: 'n'}]}]},
    {...named, wasm_modules: [{sha256: SHA, functions: [{function: 1, name: 'a‮b'}]}]},
    {...named, contract_version: 3},
  ]) assert.equal(api.validate(bad), false, JSON.stringify(bad).slice(0, 120));
  const full = {...named, wasm_modules: [{sha256: SHA, functions: Array.from({length: 501}, (_, i) => ({function: i, name: 'n'}))}]};
  assert.equal(api.validate(full), false, 'Wasm names share the 500-name bound');
  full.wasm_modules[0].functions.pop();
  assert(api.validate(full));
  // The Rust validator and this one must agree; the backend's own unit tests
  // pin the same cases (wasm_names.rs).
  const file = content => ({id: 1, folder_id: 1, name: 'Evidence names.reb-names.json', kind: 'scratchpad', language: 'json', content});
  assert.equal(api.locate({files: [file(JSON.stringify(named))]}).status, 'ready');
  assert.equal(api.locate({files: [file('{"document_kind":"reb-evidence-names","contract_version":9}')]}).status, 'malformed');
  assert(validateLibrary(library()));
  console.log('PASS Wasm names document: sha256 + full-index key, version 2 only while a Wasm name exists, closed groups, shared 500-name bound, malformed refused');
}

async function checkSurfaces() {
  const dom = parseHTML('<!doctype html><html><body><section id="screen-sources"><div id="source-name-host"></div><div class="source-tree-row" data-artifact-id="9" tabindex="0">module.wasm</div><div id="editor"><div id="source-graph-host" hidden></div><div id="source-code-wrap" tabindex="0"><div id="source-code"></div></div></div><button id="graph-toggle">Graph</button></section></body></html>');
  const {document, window, Event} = dom;
  // LinkeDOM lacks these; the editor and graph call them.
  window.HTMLElement.prototype.select ??= function select() {};
  window.HTMLElement.prototype.scrollIntoView ??= function scrollIntoView() {};
  document.hasFocus ??= () => true;
  const context = {document, window, Event, location: {protocol: 'http:'}, addEventListener: () => {}, requestAnimationFrame: fn => setTimeout(fn, 0),
    cancelAnimationFrame: clearTimeout, getComputedStyle: () => ({getPropertyValue: () => ''}), innerHeight: 800, dispatchEvent: () => true};
  const extra = `${await read('apps/research-ui/wasm_function_names.js')}\n${await read('apps/research-ui/block_graph.js')}`;
  const {api, validateLibrary, global, wasm, panel: createPanel} = await namesModels(root, context, extra, ', wasm: RebWasmFunctionNames, panel: createSourceGraphPanel');
  const store = server(library());
  let renders = 0;
  const controller = api.mount({fetcher: store.fetcher, validateLibrary, onChange: () => {renders++; wasm.changed();}});
  assert(await controller.load(), controller.model.message);

  // Inspect: a header row gets a slot and a rename button inside its excerpt;
  // a call row gets its callee's slot; body rows get nothing.
  const line = text => {
    const row = document.createElement('span'); row.className = 'source-line';
    const gutter = document.createElement('button'); gutter.className = 'source-gutter';
    const excerpt = document.createElement('span'); excerpt.className = 'source-excerpt';
    const value = document.createElement('span'); value.className = 'source-text'; value.textContent = text; excerpt.append(value);
    row.append(gutter, excerpt); document.querySelector('#source-code').append(row); return row;
  };
  const header = line('function    func 5 (type 1)'), call = line('func 2      call { function_index: 5 }'), body = line('func 5      i32.const 7');
  wasm.decorateInspectRow(header, {kind: 'function', function_index: 5, text: 'func 5 (type 1)'}, SHA);
  wasm.decorateInspectRow(call, {kind: 'instruction', function_index: 2, target_function_index: 5, text: 'call'}, SHA);
  wasm.decorateInspectRow(body, {kind: 'instruction', function_index: 5, text: 'i32.const 7'}, SHA);
  assert.equal(header.dataset.wasmFunction, '5'); assert.equal(call.dataset.wasmFunction, '5'); assert.equal(body.dataset.wasmFunction, undefined);
  assert.equal(header.children.length, 2, 'The grid keeps its gutter and excerpt');
  assert.equal(header.querySelector('.source-text').textContent, 'function    func 5 (type 1)', 'Captured text is unchanged');
  const rename = header.querySelector('.wasm-function-rename');
  assert.equal(rename.getAttribute('aria-label'), 'Rename func 5');

  // Rename through the shared editor, with a hostile name.
  rename.click();
  const input = () => document.querySelector('#source-name-host input'), form = () => document.querySelector('#source-name-host form');
  assert(input(), 'The editor opens in the Sources slot');
  const hostile = '<img src=x onerror="globalThis.__rebInjected=1">';
  input().value = hostile;
  form().dispatchEvent(new Event('submit', {cancelable: true}));
  for (let i = 0; i < 20 && store.posts.length === 0; i++) await settle();
  for (let i = 0; i < 10; i++) await settle();
  assert.equal(store.posts.length, 1, 'One save');
  const saved = JSON.parse(store.posts[0].files.find(file => file.name === 'Evidence names.reb-names.json').content);
  assert.equal(saved.contract_version, 2);
  assert.deepEqual(saved.wasm_modules, [{sha256: SHA, functions: [{function: 5, name: hostile}]}]);
  assert.equal(wasm.nameOf(SHA, 5), hostile);
  assert.equal(wasm.nameOf(OTHER, 5), null, 'Other bytes are another module');
  assert(renders > 0);
  assert.equal(header.querySelector('.wasm-function-name').textContent, hostile, 'The open listing refreshes in place');
  assert.equal(call.querySelector('.wasm-function-target').textContent, hostile, 'The call row names its callee');
  assert.equal(document.querySelectorAll('img').length, 0, 'A name is never parsed as HTML');
  assert.equal(global.__rebInjected, undefined);

  // F2 inside a marked element renames that function; text fields keep F2.
  // LinkeDOM has no KeyboardEvent; a plain event carries the key.
  const press = target => {const event = new Event('keydown', {bubbles: true, cancelable: true}); Object.defineProperty(event, 'key', {value: 'F2'}); target.dispatchEvent(event); return event.defaultPrevented;};
  const label = () => input()?.getAttribute('aria-label') ?? null;
  // Rows are spans and never take focus: a real click leaves it on the code
  // view. The row the pointer pressed names the function under the cursor.
  controller.close(false);
  const wrap = document.querySelector('#source-code-wrap');
  call.querySelector('.source-text').dispatchEvent(new Event('pointerdown', {bubbles: true}));
  assert(press(wrap), 'F2 on the code view after a click on a call row renames its callee');
  assert.equal(label(), 'Researcher name for func 5'); assert.equal(input().value, hostile);
  controller.close(false);
  // A body row names nothing, so the key stays with the Sources handler.
  body.querySelector('.source-text').dispatchEvent(new Event('pointerdown', {bubbles: true}));
  assert.equal(press(wrap), false, 'An unmarked row leaves F2 to the file rename');
  // A tree row always renames the file.
  header.querySelector('.source-text').dispatchEvent(new Event('pointerdown', {bubbles: true}));
  assert.equal(press(document.querySelector('.source-tree-row')), false, 'A tree row keeps the file rename');
  assert(press(wrap), 'The pointed header row renames its function');
  controller.close(false);
  const field = document.createElement('input'); header.append(field);
  assert.equal(press(field), false, 'Text fields keep the key');
  field.remove();

  // Graph: the title shows the name beside the captured title, the list row
  // shows both, and the panel marks itself for F2.
  global.loadWasmFunctionGraph = async () => { throw Object.assign(new Error('offline'), {name: 'AbortError'}); };
  global.readWasmFunctionIndex = async () => ({index: [4, 5], size: new Map([[4, 10], [5, 20]]), names: new Map([[5, '$helper']]), status: 'decoded', omissions: []});
  const host = document.querySelector('#source-graph-host'), button = document.querySelector('#graph-toggle'), editor = document.querySelector('#editor');
  const panel = createPanel({host, editor, button, closeOn: null, revealOffset: () => {}});
  panel.sync({kind: 'wasm', source_type: 'artifact', artifact_id: '9', sha256: SHA});
  button.click();
  for (let i = 0; i < 10; i++) await settle();
  assert.equal(host.dataset.wasmFunction, '5', 'The largest function opens and is marked');
  const analyst = host.querySelector('.block-graph-analyst-name');
  assert.equal(analyst.textContent, hostile); assert.equal(analyst.hidden, false);
  assert.equal(host.querySelector('.block-graph-title').textContent, '$helper (func 5)', 'The captured title stays');
  const renameGraph = host.querySelector('.block-graph-rename');
  assert(renameGraph && !renameGraph.disabled);
  host.querySelector('.block-graph-fn-wrap button[aria-haspopup]').click();
  const rows = [...host.querySelectorAll('.block-graph-fn-row')];
  assert.equal(rows.length, 2);
  assert.equal(rows[1].querySelector('.block-graph-fn-name').textContent, '$helper (func 5)');
  assert.equal(rows[1].querySelector('.block-graph-fn-analyst').textContent, hostile);
  assert.equal(rows[0].querySelector('.block-graph-fn-analyst'), null);
  const filter = host.querySelector('.block-graph-fn-menu input');
  filter.value = 'onerror'; filter.dispatchEvent(new Event('input'));
  assert.equal(host.querySelectorAll('.block-graph-fn-row').length, 1, 'The filter matches researcher names');
  host.querySelector('.block-graph-fn-menu input').dispatchEvent(Object.defineProperty(new Event('keydown', {bubbles: true, cancelable: true}), 'key', {value: 'Escape'}));
  // WebKit can leave focus on the body or the code view after a click on the
  // graph: the open Graph still names the function it draws.
  controller.close(false);
  assert(press(document.body), 'F2 with focus on the body renames the open graph function');
  assert.equal(label(), 'Researcher name for $helper (func 5)');
  controller.close(false);
  for (const row of document.querySelectorAll('#source-code .source-line')) row.remove();
  assert(press(wrap), 'F2 on the code view beside an open graph renames its function');
  assert.equal(label(), 'Researcher name for $helper (func 5)');
  controller.close(false);
  console.log('PASS Wasm names surfaces: Inspect headers and call targets, in-place refresh, F2 routing, hostile names as text, Graph title and function list with filter (LinkeDOM; not rendered QA)');
}

async function checkWiring() {
  const html = await read('apps/research-ui/index.html'), app = await read('apps/research-ui/app.js');
  const order = ['evidence_names.js', 'wasm_function_names.js', 'app.js'].map(name => html.indexOf(`src="${name}"`));
  assert(order.every((at, i) => at > 0 && (i === 0 || at > order[i - 1])), 'Script order: names store, Wasm names, app');
  for (const path of ['scripts/build-research-app.sh', 'apps/research-ui/macos/OriginTraceApp.swift', 'apps/origin-trace-backend/src/app.rs'])
    assert((await read(path)).includes('wasm_function_names.js'), path);
  assert(app.includes("if (typeof RebWasmFunctionNames !== 'undefined') RebWasmFunctionNames.changed();"));
  assert(app.includes("if (view.wasmRows && typeof RebWasmFunctionNames !== 'undefined') RebWasmFunctionNames.decorateInspectRow("));
  const module = await read('apps/research-ui/wasm_function_names.js');
  assert(!/innerHTML|insertAdjacentHTML|outerHTML/.test(module), 'Names are inserted as text only');
  for (const path of ['apps/research-ui/flow_graph.js', 'apps/research-ui/xrefs_view.js', 'apps/research-ui/request_stack.js']) {
    const source = await read(path);
    assert(source.includes('RebWasmFunctionNames'), path);
  }
  // The flow graph helper names only Wasm nodes with a module digest.
  const flow = await read('apps/research-ui/flow_graph.js');
  const helper = flow.slice(flow.indexOf('function flowGraphAnalystName'), flow.indexOf('function flowGraphNodeName'));
  const names = {};
  const ctx = {globalThis: {RebWasmFunctionNames: {nameOf: (sha, index) => names[`${sha}:${index}`] ?? null}}};
  const named = runInNewContext(`${helper}; flowGraphAnalystName`, ctx);
  names[`${SHA}:3`] = 'mix';
  assert.equal(named({kind: 'wasm', sha256: SHA, function_index: 3}), 'mix');
  assert.equal(named({kind: 'wasm', function_index: 3}), null, 'No digest, no name');
  assert.equal(named({kind: 'javascript', sha256: SHA, function_index: 3}), null);
  console.log('PASS Wasm names wiring: packaged and served asset lists, script order, guarded app.js hooks, Flow, xrefs and Initiator consumers');
}

await checkDocument();
await checkSurfaces();
await checkWiring();
