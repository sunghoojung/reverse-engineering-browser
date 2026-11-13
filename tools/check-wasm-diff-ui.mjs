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
const tie = {id: 0, a: 2, b: 2};
const ROWS = [
  {status: 'changed', method: 'structural', score: 0.912, a: side(3, {name: HOSTILE}), b: side(4)},
  {status: 'added', method: null, score: null, a: null, b: side(9)},
  {status: 'removed', method: null, score: null, a: side(5), b: null},
  {status: 'ambiguous', method: 'identical', score: 1, a: side(6), b: null, group: tie},
  {status: 'ambiguous', method: 'identical', score: 1, a: side(7), b: null, group: tie},
  {status: 'ambiguous', method: 'identical', score: 1, a: null, b: side(6), group: tie},
  {status: 'ambiguous', method: 'identical', score: 1, a: null, b: side(7), group: tie},
  {status: 'identical', method: 'import_name', score: 1, a: side(0, {import: {module: 'env', name: 'log'}}), b: side(0, {import: {module: 'env', name: 'log'}})}
];
function page(parameters, rows, omissions = []) {
  const statuses = parameters.get('status')?.split(',') ?? null;
  const selected = rows.filter(row => !statuses || statuses.includes(row.status));
  const offset = Number(parameters.get('row_offset')), limit = Number(parameters.get('row_limit'));
  const kept = selected.slice(offset, offset + limit), next = offset + kept.length;
  const counts = {changed: 0, added: 0, removed: 0, ambiguous: 0, unclassified: 0, renumbered: 0, identical: 0};
  for (const row of rows) counts[row.status] += 1;
  return {schema: 'wasm-module-diff-v1', fingerprint_version: 1, artifact_id: parameters.get('artifact_id'), compare_artifact_id: parameters.get('compare_artifact_id'),
    status: omissions.length ? 'partial' : 'complete', a: {analyzed_functions: 8, sha256: 'aa'}, b: {analyzed_functions: 10, sha256: 'bb'}, requested_statuses: statuses,
    summary: {matched: 2, statuses: counts, methods: {}, ambiguous_groups: rows.some(row => row.group) ? 1 : 0, comparisons: 1, elapsed_ms: 1}, rows: kept,
    row_window: {offset, rows: kept.length, total_rows: selected.length, next_offset: next < selected.length ? next : null}, omissions, limits: {}, notice: ''};
}

// `pairs` maps a compare_artifact_id to {rows, omissions, failing, hold}. A
// held read waits until released or aborted, like a slow comparison.
function mount({modules, pairs = {}, rows = ROWS} = {}) {
  const {window, document} = parseHTML(`<!doctype html><html><body><section id="screen-sources">
    <button id="graph" aria-pressed="false">Graph</button><details><summary>More</summary><button id="compare" aria-pressed="false" hidden>Compare with…</button></details>
    <div id="split"></div><section id="diff" hidden></section></section></body></html>`);
  const requests = [], jumps = [], focused = [];
  async function fetch(input, init = {}) {
    const url = String(input), parameters = new URL(url, 'http://local').searchParams;
    const entry = {url, other: parameters.get('compare_artifact_id'), aborted: false};
    requests.push(entry);
    const answer = pairs[entry.other] ?? {};
    await new Promise(next => setImmediate(next));
    if (answer.hold) {
      await new Promise((release, reject) => {
        entry.release = release;
        init.signal?.addEventListener('abort', () => { entry.aborted = true; reject(new DOMException('aborted', 'AbortError')); }, {once: true});
      });
    }
    if (answer.failing) return {ok: false, status: 422, json: async () => ({error: 'WASM decoding failed: unexpected end'})};
    return {ok: true, status: 200, json: async () => structuredClone(page(parameters, answer.rows ?? rows, answer.omissions ?? []))};
  }
  const context = {window, document, fetch, setTimeout, clearTimeout, AbortController, DOMException, URL, URLSearchParams, structuredClone, console, BigInt, module: undefined};
  runInNewContext(script, context, {filename: 'wasm_diff_view.js'});
  const sources = {
    430: {artifact_id: '430', sha256: 'aa'.repeat(32), kind: 'wasm', source_type: 'artifact', url: 'https://cdn.test/app/v1/module.wasm', name: 'module.wasm'},
    431: {artifact_id: '431', sha256: 'bb'.repeat(32), kind: 'wasm', source_type: 'artifact', url: 'https://cdn.test/app/v2/module.wasm', name: 'module.wasm'}
  };
  let source = sources[430];
  const summary = document.querySelector('summary');
  summary.focus = () => focused.push('more');
  const panel = context.createWasmDiffPanel({
    button: document.querySelector('#compare'), root: document.querySelector('#diff'), split: document.querySelector('#split'),
    exclusive: [document.querySelector('#graph')], closeOn: [document.querySelector('#graph')],
    getSource: () => source, nameOf: value => value.url,
    listModules: () => modules ?? [
      {artifact_id: '12', sha256: 'cc'.repeat(32), url: 'https://other.test/x.wasm', name: 'x.wasm'},
      sources[430], sources[431]
    ],
    openFunction: (artifactId, index) => jumps.push([artifactId, index])
  });
  panel.sync(source);
  return {window, document, panel, requests, jumps, focused, root: document.querySelector('#diff'),
    select(id) { source = sources[id]; panel.sync(source); }};
}
async function until(predicate, message) {
  const deadline = Date.now() + 2000;
  while (!predicate()) { if (Date.now() > deadline) assert.fail(`timed out: ${message}`); await sleep(5); }
}
const event = (ui, type, init = {}) => Object.assign(new ui.window.Event(type, {bubbles: true, cancelable: true}), init);
const click = (ui, node) => node.dispatchEvent(event(ui, 'click'));
const rows = ui => [...ui.root.querySelectorAll('.wasm-diff-row')];
const chosen = ui => [...ui.root.querySelectorAll('.wasm-diff-picker option')].find(option => option.selected)?.value;
const choose = (ui, id) => {
  // linkedom clears a newly selected option when another is cleared after it.
  const options = [...ui.root.querySelectorAll('.wasm-diff-picker option')];
  for (const option of options) option.selected = false;
  options.find(option => option.value === id).selected = true;
  ui.root.querySelector('.wasm-diff-picker').dispatchEvent(event(ui, 'change'));
};
const header = ui => [...ui.root.querySelectorAll('th')].map(cell => cell.textContent).join('|');

{
  // The most similar URL is preselected, rows render as text, each tie
  // member is its own row, and each jump names its own module.
  const ui = mount();
  assert.equal(ui.document.querySelector('#compare').hidden, false, 'offered for a Wasm module');
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 8, 'rows render');
  assert.equal(chosen(ui), '431', 'the same path is preferred over an unrelated module');
  assert.equal(ui.document.querySelector('#split').hidden, true, 'the table replaces the code view');
  assert.match(ui.requests[0].url, /artifact_id=430&compare_artifact_id=431/);
  assert.equal(ui.root.querySelectorAll('img').length, 0, 'a captured name is never markup');
  assert(ui.root.textContent.includes(HOSTILE), 'a captured name is shown as text');
  const ties = rows(ui).filter(row => row.dataset.status === 'ambiguous');
  assert.equal(ties.length, 4, 'every tie member is a row');
  assert(ties.every(row => row.querySelector('.wasm-diff-method').textContent === 'same bytes'));
  assert.deepEqual(ties.map(row => row.querySelector('.wasm-diff-tie').textContent), ['tie 1 · 2 in B', 'tie 1 · 2 in B', 'tie 1 · 2 in A', 'tie 1 · 2 in A']);
  assert(ui.root.querySelector('.wasm-diff-summary').textContent.includes('4 ambiguous in 1 tie'));
  const [aChanged, bChanged] = rows(ui)[0].querySelectorAll('.wasm-diff-fn');
  click(ui, aChanged); click(ui, bChanged);
  assert.deepEqual(ui.jumps, [['430', 3], ['431', 4]]);
  assert.equal(rows(ui)[7].querySelector('.wasm-diff-fn').disabled, true, 'an import has no body to open');
  // A filter asks the backend for those statuses.
  const changed = [...ui.root.querySelectorAll('.wasm-diff-filter')].find(node => node.textContent === 'Changed');
  click(ui, changed);
  await until(() => rows(ui).length === 1, 'the filter narrows the rows');
  assert.match(ui.requests.at(-1).url, /status=changed/);
  assert.equal(changed.getAttribute('aria-pressed'), 'true');
  // Opening Graph closes the table and restores the code view.
  click(ui, ui.document.querySelector('#graph'));
  assert.equal(ui.root.hidden, true);
  assert.equal(ui.document.querySelector('#split').hidden, false);
}
{
  // A slow read for another module never lands over the cached pair chosen
  // after it, and Show more stays on the pair shown.
  const many = Array.from({length: 450}, (_, index) => ({status: 'renumbered', method: 'normalized', score: 1, a: side(index), b: side(index)}));
  const ui = mount({pairs: {431: {rows: many}, 12: {hold: true}}});
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 200, 'the first page of 431');
  choose(ui, '12');
  await until(() => ui.requests.at(-1).other === '12' && ui.requests.at(-1).release, 'the slow read for 12 is in flight');
  const slow = ui.requests.at(-1);
  choose(ui, '431');
  await until(() => header(ui).includes('B · #431') && rows(ui).length === 200, 'the cached 431 table is shown');
  assert.equal(slow.aborted, true, 'choosing the cached pair aborts the slower read');
  slow.release?.();
  await sleep(30);
  assert(header(ui).includes('B · #431'), 'the late read did not replace the table');
  assert.equal(chosen(ui), '431');
  const body = ui.root.querySelector('.wasm-diff-body');
  body.scrollTop = 900;
  click(ui, ui.root.querySelector('.wasm-diff-more'));
  await until(() => rows(ui).length === 400, 'the second page appends');
  assert.equal(ui.requests.at(-1).other, '431', 'Show more reads the pair shown');
  assert.equal(body.scrollTop, 900, 'Show more keeps the place');
  choose(ui, '12');
  await until(() => ui.requests.at(-1).other === '12', 'another pair');
  choose(ui, '431');
  await until(() => rows(ui).length === 400, 'the cached pair again');
  assert.equal(body.scrollTop, 0, 'a newly chosen pair starts at the top');
  body.scrollTop = 900;
  click(ui, [...ui.root.querySelectorAll('.wasm-diff-filter')].find(node => node.textContent === 'Unchanged'));
  await until(() => ui.requests.at(-1).url.includes('status=renumbered'), 'the filter read');
  await until(() => rows(ui).length === 200, 'the filtered page');
  assert.equal(body.scrollTop, 0, 'a new filter starts at the top');
  click(ui, [...ui.root.querySelectorAll('.wasm-diff-filter')].find(node => node.textContent === 'All'));
  await until(() => rows(ui).length === 400, 'All again, from the cache');
  click(ui, ui.root.querySelector('.wasm-diff-more'));
  await until(() => rows(ui).length === 450, 'the last page');
  assert.equal(ui.root.querySelector('.wasm-diff-more').hidden, true, 'no more rows to show');
}
{
  // Omissions of one pair do not stay above another pair's error, which
  // keeps a retry; no other module is a named empty state.
  const ui = mount({pairs: {431: {omissions: ['Module B: 3 of its 9 functions were fingerprinted.']}, 12: {failing: true}}});
  click(ui, ui.document.querySelector('#compare'));
  await until(() => ui.root.textContent.includes('3 of its 9'), 'the omission is listed');
  choose(ui, '12');
  await until(() => ui.root.textContent.includes('unexpected end'), 'the error is shown');
  assert.equal(ui.root.querySelector('.wasm-diff-notes').hidden, true, 'the earlier omissions are gone');
  assert(!ui.root.textContent.includes('3 of its 9'));
  const retry = [...ui.root.querySelectorAll('button')].find(node => node.textContent === 'Retry comparison');
  assert.equal(retry.hidden, false);
  const lonely = mount({modules: []});
  click(lonely, lonely.document.querySelector('#compare'));
  assert(lonely.root.textContent.includes('No other captured WebAssembly module'), 'empty state');
  assert.equal(lonely.requests.length, 0, 'nothing is requested without a second module');
}
{
  // Escape returns focus to More; reopening on B selects A even when another
  // module's URL is closer to B's; a re-capture with the same bytes is not
  // preselected.
  const ui = mount({modules: [
    {artifact_id: '430', sha256: 'aa'.repeat(32), url: 'https://cdn.test/app/v1/module.wasm', name: 'module.wasm'},
    {artifact_id: '431', sha256: 'bb'.repeat(32), url: 'https://cdn.test/app/v2/module.wasm', name: 'module.wasm'},
    {artifact_id: '432', sha256: 'dd'.repeat(32), url: 'https://cdn.test/app/v2/module.wasm?r=2', name: 'module.wasm'}
  ]});
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 8, 'rows render');
  choose(ui, '431');
  await until(() => ui.requests.at(-1).other === '431' && rows(ui).length === 8, 'the 431 comparison');
  ui.root.dispatchEvent(event(ui, 'keydown', {key: 'Escape'}));
  assert.equal(ui.root.hidden, true);
  assert.deepEqual(ui.focused, ['more'], 'Escape returns focus to More');
  ui.select('431');
  click(ui, ui.document.querySelector('#compare'));
  assert.equal(chosen(ui), '430', 'reopening on B selects A');
  const twin = mount({modules: [
    {artifact_id: '99', sha256: 'aa'.repeat(32), url: 'https://cdn.test/app/v1/module.wasm', name: 'module.wasm'},
    {artifact_id: '12', sha256: 'cc'.repeat(32), url: 'https://other.test/x.wasm', name: 'x.wasm'}
  ]});
  click(twin, twin.document.querySelector('#compare'));
  assert.equal(chosen(twin), '12', 'a same-SHA re-capture is skipped');
}
{
  // A partial report is not kept for reopening: choosing it again reads it
  // again, and Show more says why its pages are unreliable.
  const many = Array.from({length: 300}, (_, index) => ({status: 'unclassified', method: null, score: null, a: side(index), b: null}));
  const ui = mount({pairs: {431: {rows: many, omissions: ['The fingerprinting step stopped at the deadline.']}}});
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 200, 'the partial first page');
  assert.match(ui.root.querySelector('.wasm-diff-more').title, /partial/);
  choose(ui, '12');
  await until(() => ui.requests.at(-1).other === '12', 'another pair');
  await until(() => rows(ui).length === 8, 'the other pair');
  const before = ui.requests.filter(entry => entry.other === '431').length;
  choose(ui, '431');
  await until(() => ui.requests.filter(entry => entry.other === '431').length === before + 1, 'the partial pair is read again');
}
{
  // A non-Wasm selection hides the action and closes the table.
  const ui = mount();
  click(ui, ui.document.querySelector('#compare'));
  await until(() => rows(ui).length === 8, 'rows render');
  ui.panel.sync({artifact_id: '9', kind: 'javascript', source_type: 'artifact'});
  assert.equal(ui.document.querySelector('#compare').hidden, true);
  assert.equal(ui.root.hidden, true);
}
console.log('Wasm module diff UI checks passed');
