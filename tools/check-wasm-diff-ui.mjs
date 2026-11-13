#!/usr/bin/env node
// Compare with (apps/research-ui/wasm_diff_view.js) in a linkedom document with
// a stub /api/wasm/diff. Not rendered QA: layout, focus and WebKit behavior are
// test40 in tools/origin-trace-rendered-ui.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {runInNewContext} from 'node:vm';

const script = await readFile(new URL('../apps/research-ui/wasm_diff_view.js', import.meta.url), 'utf8');
const {parseHTML} = createRequire(new URL('ui-startup-deps/', import.meta.url))('linkedom');
const sleep = ms => new Promise(done => setTimeout(done, ms));
const HOSTILE = '<img src=x onerror="globalThis.__injected=1">';

const side = (index, extra = {}) => ({function: index, byte_offset: 10 * index + 1, byte_end: 10 * index + 9, name: null, import: null,
  type: '(i32) -> (i32)', instructions: 4, normalized: '0123456789abcdef', structure: 'fedcba9876543210', ...extra});
const ROWS = [
  {status: 'changed', method: 'structural', score: 0.912, a: side(3, {name: HOSTILE}), b: side(4)},
  {status: 'added', method: null, score: null, a: null, b: side(9)},
  {status: 'removed', method: null, score: null, a: side(5), b: null},
  {status: 'ambiguous', method: 'identical', score: 1, a: null, b: null, candidates: {a: [side(6), side(7)], b: [side(6), side(7)], truncated: false}},
  {status: 'identical', method: 'import_name', score: 1, a: side(0, {import: {module: 'env', name: 'log'}}), b: side(0, {import: {module: 'env', name: 'log'}})}
];
function page(parameters, rows = ROWS) {
  const statuses = parameters.get('status')?.split(',') ?? null;
  const selected = rows.filter(row => !statuses || statuses.includes(row.status));
  const offset = Number(parameters.get('row_offset')), limit = Number(parameters.get('row_limit'));
  const kept = selected.slice(offset, offset + limit), next = offset + kept.length;
  const counts = {changed: 0, added: 0, removed: 0, ambiguous: 0, unclassified: 0, renumbered: 0, identical: 0};
  for (const row of rows) counts[row.status] += 1;
  return {schema: 'wasm-module-diff-v1', fingerprint_version: 1, artifact_id: parameters.get('artifact_id'), compare_artifact_id: parameters.get('compare_artifact_id'),
    status: 'complete', a: {analyzed_functions: 8}, b: {analyzed_functions: 10}, requested_statuses: statuses,
    summary: {matched: 2, statuses: counts, methods: {}, comparisons: 1, elapsed_ms: 1}, rows: kept,
    row_window: {offset, rows: kept.length, total_rows: selected.length, next_offset: next < selected.length ? next : null}, omissions: [], limits: {}, notice: ''};
}

function mount({modules, failing = false, rows = ROWS} = {}) {
  const {window, document} = parseHTML(`<!doctype html><html><body><section id="screen-sources">
    <button id="graph" aria-pressed="false">Graph</button><details><summary>More</summary><button id="compare" aria-pressed="false" hidden>Compare with…</button></details>
    <div id="split"></div><section id="diff" hidden></section></section></body></html>`);
  const requests = [], jumps = [];
  async function fetch(input) {
    const url = String(input);
    requests.push(url);
    await new Promise(next => setImmediate(next));
    if (failing) return {ok: false, status: 422, json: async () => ({error: 'WASM decoding failed: unexpected end'})};
    return {ok: true, status: 200, json: async () => structuredClone(page(new URL(url, 'http://local').searchParams, rows))};
  }
  const context = {window, document, fetch, setTimeout, clearTimeout, AbortController, DOMException, URL, URLSearchParams, structuredClone, console, BigInt, module: undefined};
  runInNewContext(script, context, {filename: 'wasm_diff_view.js'});
  const source = {artifact_id: '430', sha256: 'aa'.repeat(32), kind: 'wasm', source_type: 'artifact', url: 'https://cdn.test/app/v1/module.wasm'};
  const panel = context.createWasmDiffPanel({
    button: document.querySelector('#compare'), root: document.querySelector('#diff'), split: document.querySelector('#split'),
    exclusive: [document.querySelector('#graph')], closeOn: [document.querySelector('#graph')],
    getSource: () => source, nameOf: value => value.url,
    listModules: () => modules ?? [
      {artifact_id: '12', sha256: 'cc'.repeat(32), url: 'https://other.test/x.wasm', name: 'x.wasm'},
      source,
      {artifact_id: '431', sha256: 'bb'.repeat(32), url: 'https://cdn.test/app/v2/module.wasm', name: 'module.wasm'}
    ],
    openFunction: (artifactId, index) => jumps.push([artifactId, index])
  });
  panel.sync(source);
  return {window, document, panel, requests, jumps, root: document.querySelector('#diff')};
}
async function until(predicate, message) {
  const deadline = Date.now() + 2000;
  while (!predicate()) { if (Date.now() > deadline) assert.fail(`timed out: ${message}`); await sleep(5); }
}
const click = (ui, node) => node.dispatchEvent(new ui.window.Event('click', {bubbles: true}));
const rows = ui => [...ui.root.querySelectorAll('.wasm-diff-row')];

{
  // The most similar URL is preselected, rows render as text, and each jump
  // names its own module.
  const ui = mount();
  assert.equal(ui.document.querySelector('#compare').hidden, false, 'offered for a Wasm module');
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 5, 'rows render');
  assert.equal([...ui.root.querySelectorAll('.wasm-diff-picker option')].find(option => option.selected)?.value, '431', 'the same path is preferred over a newer unrelated module');
  assert.equal(ui.document.querySelector('#split').hidden, true, 'the table replaces the code view');
  assert.match(ui.requests[0], /artifact_id=430&compare_artifact_id=431/);
  assert.equal(ui.root.querySelectorAll('img').length, 0, 'a captured name is never markup');
  assert(ui.root.textContent.includes(HOSTILE), 'a captured name is shown as text');
  assert.equal(rows(ui)[3].querySelectorAll('.wasm-diff-fn').length, 4, 'ambiguous rows list every candidate');
  assert(ui.root.querySelector('.wasm-diff-summary').textContent.includes('1 changed'));
  const [aChanged, bChanged] = rows(ui)[0].querySelectorAll('.wasm-diff-fn');
  click(ui, aChanged); click(ui, bChanged);
  assert.deepEqual(ui.jumps, [['430', 3], ['431', 4]]);
  assert.equal(rows(ui)[4].querySelector('.wasm-diff-fn').disabled, true, 'an import has no body to open');
  // A filter asks the backend for those statuses.
  const changed = [...ui.root.querySelectorAll('.wasm-diff-filter')].find(node => node.textContent === 'Changed');
  click(ui, changed);
  await until(() => rows(ui).length === 1, 'the filter narrows the rows');
  assert.match(ui.requests.at(-1), /status=changed/);
  assert.equal(changed.getAttribute('aria-pressed'), 'true');
  // Opening Graph closes the table and restores the code view.
  click(ui, ui.document.querySelector('#graph'));
  assert.equal(ui.root.hidden, true);
  assert.equal(ui.document.querySelector('#split').hidden, false);
}
{
  // Paging appends the next page rather than replacing it.
  const many = Array.from({length: 450}, (_, index) => ({status: 'renumbered', method: 'normalized', score: 1, a: side(index), b: side(index)}));
  const ui = mount({rows: many});
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 200, 'the first page');
  const more = ui.root.querySelector('.wasm-diff-more');
  assert.equal(more.hidden, false);
  click(ui, more);
  await until(() => rows(ui).length === 400, 'the second page appends');
  click(ui, more);
  await until(() => rows(ui).length === 450, 'the last page');
  assert.equal(more.hidden, true, 'no more rows to show');
}
{
  // An error keeps a retry, and no other module is a named empty state.
  const ui = mount({failing: true});
  click(ui, ui.document.querySelector('#compare'));
  await until(() => ui.root.textContent.includes('unexpected end'), 'the error is shown');
  const retry = [...ui.root.querySelectorAll('button')].find(node => node.textContent === 'Retry comparison');
  assert.equal(retry.hidden, false);
  const lonely = mount({modules: []});
  click(lonely, lonely.document.querySelector('#compare'));
  assert(lonely.root.textContent.includes('No other captured WebAssembly module'), 'empty state');
  assert.equal(lonely.requests.length, 0, 'nothing is requested without a second module');
}
{
  // A non-Wasm selection hides the action and closes the table.
  const ui = mount();
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 5, 'rows render');
  ui.panel.sync({artifact_id: '9', kind: 'javascript', source_type: 'artifact'});
  assert.equal(ui.document.querySelector('#compare').hidden, true);
  assert.equal(ui.root.hidden, true);
}
console.log('Wasm module diff UI checks passed');
