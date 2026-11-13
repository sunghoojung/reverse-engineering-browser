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
  const state = {library: initial, posts: [], gets: []};
  const tag = () => `"local-analyst-${state.library.generation}"`;
  state.fetcher = async (url, options = {}) => {
    if (options.method !== 'POST') {
      const condition = options.headers?.['If-None-Match'] ?? null;
      state.gets.push(condition);
      if (condition && condition === tag()) return new Response(null, {status: 304, headers: {etag: tag()}});
      return Response.json(state.library, {headers: {etag: tag()}});
    }
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
  // Shared with wasm_names.rs `numbers_are_integers_written_as_integers`:
  // a fraction or exponent is refused even where it equals an integer.
  const text = JSON.stringify(named);
  for (const [from, to] of [['"function":5', '"function":5.0'], ['"contract_version":2', '"contract_version":2.0'], ['"function":5', '"function":5e0']]) {
    assert.equal(api.readDocument(file(text.replace(from, to))), null, to);
    assert.equal(api.locate({files: [file(text.replace(from, to))]}).status, 'malformed', to);
  }
  assert(api.readDocument(file(text.replace('"name":"encode_payload"', '"name":"1.5e3 is text"'))), 'Digits inside strings are text');
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
  // The caret selection a click would leave; LinkeDOM has none of its own.
  let caret = null;
  const context = {document, window, Event, getSelection: () => caret ? {rangeCount: 1, anchorNode: caret} : {rangeCount: 0, anchorNode: null},
    location: {protocol: 'http:'}, addEventListener: () => {}, requestAnimationFrame: fn => setTimeout(fn, 0),
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
  assert.equal(header.dataset.wasmFunction, '5'); assert.equal(call.dataset.wasmFunction, '5');
  assert.equal(body.dataset.wasmFunction, '5', 'A body row stands for its containing function');
  assert.equal(body.dataset.wasmBody, 'true'); assert.equal(body.querySelector('.wasm-function-name'), null, 'A body row shows no name of its own');
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
  // A body row (an instruction or locals) renames the function containing it.
  body.querySelector('.source-text').dispatchEvent(new Event('pointerdown', {bubbles: true}));
  assert(press(wrap), 'F2 on a body row renames its containing function');
  assert.equal(label(), 'Researcher name for func 5');
  controller.close(false);
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
  // The rows stay. Another function's header was the last one pointed at,
  // and the Graph draws func 5: the Graph's function wins on the code view.
  const other = line('function    func 4 (type 0)');
  wasm.decorateInspectRow(other, {kind: 'function', function_index: 4, text: 'func 4 (type 0)'}, SHA);
  other.querySelector('.source-text').dispatchEvent(new Event('pointerdown', {bubbles: true}));
  assert(press(wrap), 'F2 on the code view beside an open graph renames a function');
  assert.equal(label(), 'Researcher name for $helper (func 5)', 'A row pointed at earlier does not outrank the Graph');
  controller.close(false);
  // The caret on a marked row of the visible listing names that row.
  caret = other.querySelector('.source-text').firstChild;
  assert(press(wrap));
  assert.equal(label(), 'Researcher name for func 4', 'The caret row in the visible listing wins');
  controller.close(false);
  // With the linear listing hidden beside the Graph, the caret row is not on
  // screen, so the Graph's function wins again.
  document.querySelector('#editor').setAttribute('data-graph-linear-hidden', '');
  assert(press(wrap));
  assert.equal(label(), 'Researcher name for $helper (func 5)', 'A hidden listing does not outrank the Graph');
  controller.close(false);
  document.querySelector('#editor').removeAttribute('data-graph-linear-hidden');
  caret = null;
  console.log('PASS Wasm names surfaces: Inspect headers and call targets, in-place refresh, F2 routing, hostile names as text, Graph title and function list with filter (LinkeDOM; not rendered QA)');
}

// The Flow panel itself, with one Wasm node: Rename in Details, focus after
// a save, and the mark cleared when the session changes.
async function checkFlow() {
  const dom = parseHTML('<!doctype html><html><body><div id="flow"></div></body></html>');
  const {document, window, Event} = dom;
  window.HTMLElement.prototype.select ??= function select() {};
  window.HTMLElement.prototype.scrollIntoView ??= function scrollIntoView() {};
  document.hasFocus ??= () => true;
  let focused = null;
  window.HTMLElement.prototype.focus = function focus() { focused = this; };
  const node = {id: 0, kind: 'wasm', context: 0, status: 'resolved', function_index: 5, sha256: SHA, artifact_id: '9', url: 'https://wasm.test/m.wasm', script_id: 3, hits: 2, entries: 1, leaves: 1};
  const graph = {schema: 'flow-graph-v1', session_id: '1', evidence: 'observed', complete: true, coverage: {stopped: 'end'}, stacks: {records: {request_initiator_stack: 1}, not_walked: {}},
    truncated: {}, limits: {}, not_shown: {}, contexts: [{id: 0, process_id: 1, execution_context_id: '7', origin: 'https://wasm.test', origins: [], frame_ids: [], tab_ids: [], counts: {}}],
    nodes: [node], edges: [], paths: []};
  const store = server(library());
  const fetcher = async (url, options) => String(url).startsWith('/api/flow-graph') ? Response.json(graph) : store.fetcher(url, options);
  const context = {document, window, Event, location: {protocol: 'http:'}, addEventListener: () => {}, fetch: fetcher,
    requestAnimationFrame: fn => setTimeout(() => fn(performance.now()), 0), cancelAnimationFrame: clearTimeout, performance,
    getComputedStyle: () => ({getPropertyValue: () => ''}), innerHeight: 800, innerWidth: 1180, devicePixelRatio: 1, dispatchEvent: () => true, URLSearchParams, AbortSignal};
  const scripts = ['wasm_function_names.js', 'graph_layout_client.js', 'block_graph.js', 'request_stack.js', 'flow_graph_layout.js', 'flow_graph.js'];
  const extra = (await Promise.all(scripts.map(name => read(`apps/research-ui/${name}`)))).join('\n');
  const {api, validateLibrary, wasm, panel: createFlow, flowGraphKey} = await namesModels(root, context, extra, ', wasm: RebWasmFunctionNames, panel: createFlowGraphPanel, flowGraphKey: flowGraphNodeKey');
  const controller = api.mount({fetcher: store.fetcher, validateLibrary, onChange: () => wasm.changed()});
  assert(await controller.load(), controller.model.message);
  const host = document.querySelector('#flow');
  const flow = createFlow({host, open: () => {}, available: () => true});
  flow.show({session: '1'});
  for (let i = 0; i < 40 && !host.querySelector('.flow-graph-canvas'); i++) await settle();
  for (let i = 0; i < 40; i++) await settle();
  flow.select(flowGraphKey(node), {reveal: false});
  for (let i = 0; i < 10; i++) await settle();
  const details = host.querySelector('.flow-graph-details-toggle');
  if (details?.getAttribute('aria-pressed') !== 'true') details?.click();
  for (let i = 0; i < 10; i++) await settle();
  assert.equal(host.dataset.wasmFunction, '5', `The selected Wasm card marks the panel: ${JSON.stringify({state: host.querySelector('.flow-graph-state')?.textContent, selected: flow.selection?.(), canvas: !!host.querySelector('.flow-graph-canvas'), details: host.querySelector('.flow-graph-details-toggle')?.getAttribute('aria-pressed')})}`);
  const rename = host.querySelector('[data-wasm-rename]');
  assert(rename, 'Details offers Rename for a Wasm card');
  rename.focus(); rename.click();
  const input = host.querySelector('.flow-graph-name-host input');
  assert(input, 'The editor opens in the Flow slot');
  input.value = 'mix_state';
  host.querySelector('.flow-graph-name-host form').dispatchEvent(new Event('submit', {cancelable: true}));
  for (let i = 0; i < 40 && wasm.nameOf(SHA, 5) !== 'mix_state'; i++) await settle();
  for (let i = 0; i < 10; i++) await settle();
  assert.equal(wasm.nameOf(SHA, 5), 'mix_state');
  assert(!rename.isConnected, 'Details was redrawn after the save');
  assert(focused && focused.isConnected && focused !== document.body, `Focus returns to a control, not the body: ${focused?.tagName}`);
  assert(focused.matches('[data-wasm-rename], .flow-graph-canvas'), `Focus returns to the redrawn Rename or the canvas: ${focused?.outerHTML?.slice(0, 80)}`);
  assert.equal(host.querySelector('[data-wasm-rename]').textContent, 'Rename');
  // Another session: the previous function is not selected, so F2 must not
  // rename it.
  flow.show({session: '2'});
  assert.equal(host.dataset.wasmFunction, undefined, 'A session change clears the mark');
  console.log('PASS Wasm names in Flow: Details Rename, focus back on the redrawn control after a save, mark cleared on session change (LinkeDOM; not rendered QA)');
}

// Names an agent saves reach an open UI on the 2 s tick: an unchanged
// library costs one conditional read answered 304; a newer one is adopted.
async function checkPoll() {
  const {document, window} = parseHTML('<!doctype html><html><body></body></html>');
  const {api, validateLibrary, emptyLibrary: empty} = await namesModels(root, {document, window, location: {protocol: 'http:'}, addEventListener: () => {}});
  emptyLibrary = empty;
  const store = server(library());
  let renders = 0;
  const controller = api.mount({fetcher: store.fetcher, validateLibrary, onChange: () => renders++});
  assert(await controller.load(), controller.model.message);
  store.gets.length = 0; renders = 0;
  assert.equal(await controller.poll(), false, 'Nothing changed');
  assert.deepEqual(store.gets, ['"local-analyst-1"'], 'One conditional read per tick');
  assert.equal(renders, 0);
  // The agent's set_wasm_function_name lands as a new generation.
  const doc = {document_kind: 'reb-evidence-names', contract_version: 2, scope: 'local-analyst-library', requests: [], artifacts: [], vm_programs: [],
    wasm_modules: [{sha256: SHA, functions: [{function: 3, name: 'agent_named'}]}]};
  const content = JSON.stringify(doc);
  store.library = {...store.library, generation: 2, updated_at_ms: 1001, files: [{id: 1, folder_id: 1, name: 'Evidence names.reb-names.json', kind: 'scratchpad',
    language: 'json', content, content_bytes: Buffer.byteLength(content), created_at_ms: 1001, updated_at_ms: 1001}]};
  assert.equal(await controller.poll(), true, 'A newer generation is adopted');
  assert.equal(controller.nameOf(api.wasmFunctionIdentity(SHA, 3)), 'agent_named');
  assert(renders > 0, 'The views re-render');
  store.gets.length = 0;
  assert.equal(await controller.poll(), false);
  assert.deepEqual(store.gets, ['"local-analyst-2"'], 'The poll follows the new ETag');
  console.log('PASS Wasm names poll: one conditional read per tick, 304 adopts nothing, an agent-set name appears on the next tick');
}

async function checkWiring() {
  const html = await read('apps/research-ui/index.html'), app = await read('apps/research-ui/app.js');
  const order = ['evidence_names.js', 'wasm_function_names.js', 'app.js'].map(name => html.indexOf(`src="${name}"`));
  assert(order.every((at, i) => at > 0 && (i === 0 || at > order[i - 1])), 'Script order: names store, Wasm names, app');
  for (const path of ['scripts/build-research-app.sh', 'apps/research-ui/macos/OriginTraceApp.swift', 'apps/origin-trace-backend/src/app.rs'])
    assert((await read(path)).includes('wasm_function_names.js'), path);
  assert(app.includes("if (typeof RebWasmFunctionNames !== 'undefined') RebWasmFunctionNames.changed();"));
  assert(app.includes("if (view.wasmRows && typeof RebWasmFunctionNames !== 'undefined') RebWasmFunctionNames.decorateInspectRow("));
  assert(app.includes('setInterval(() => { refresh(); evidenceNames.poll?.(); }, 2000);'), 'The 2 s tick polls the names library');
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
await checkFlow();
await checkPoll();
await checkWiring();
