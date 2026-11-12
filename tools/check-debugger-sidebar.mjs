#!/usr/bin/env node
// Sources debugger sidebar behavior (apps/research-ui/debugger_sidebar.js).
// Each case loads the shipped script into a fresh linkedom document with real
// timers, a stub backend that holds an event store of byte-addressed records,
// and stub Traffic and Console globals. Not rendered QA: layout, focus and
// WebKit behavior are test31 in tools/origin-trace-rendered-ui.
// An optional argument names another copy of the script (its stylesheet is
// read from beside it), and REB_DEBUGGER_CASE runs only the cases whose name
// contains it, so a case can be shown to fail without its fix:
//   REB_DEBUGGER_CASE=stored node tools/check-debugger-sidebar.mjs old/debugger_sidebar.js
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {dirname, join, resolve} from 'node:path';
import {runInNewContext} from 'node:vm';
import {setTimeout as sleep} from 'node:timers/promises';

const root = fileURLToPath(new URL('..', import.meta.url));
const scriptPath = process.argv[2] ? resolve(process.argv[2]) : join(root, 'apps/research-ui/debugger_sidebar.js');
const script = await readFile(scriptPath, 'utf8');
const css = await readFile(join(dirname(scriptPath), 'debugger_sidebar.css'), 'utf8');
const {parseHTML} = createRequire(new URL('ui-startup-deps/', import.meta.url))('linkedom');
// The poll interval in the script; waits below are measured against it.
const POLL = 2000;

// One observation record per 100 bytes of store, oldest first.
function record(index, extra = {}) {
  return {type: 'timer_observation', session_id: '1', process_id: 42, frame_id: '200', sequence_number: String(index + 1),
    parent_event_id: '0', request_id: '0', monotonic_time_ns: String(1e9 + index),
    stack: {state: 'no_script', total_depth: 0, recorded: 0, async_frames: 0, digest: null, innermost: null},
    detail: {phase: 'fired', kind: 'timeout', string_callback: false, timer_id: index, delay_ms: 0, callback: null}, ...extra};
}

function createStore(count = 0) {
  const store = {records: Array.from({length: count}, (_, index) => record(index)), end: null, scope: null, budget: false,
    frames: [{target_id: '22', label: 'top #22', origin: 'https://a.test', frame: 'top', out_of_process: false}],
    observed: [{session_id: '1', process_id: 42, frame_id: '200', last_sequence: '9', records: 9}], availability: 'unsupported', watch: {state: 'none', armed: null}};
  store.add = (count, extra) => { for (let at = 0; at < count; at += 1) store.records.push(record(store.records.length, extra)); };
  store.storeEnd = () => store.end ?? store.records.length * 100;
  // Paged like get_native_debugger: the newest `limit` matching records before `before`.
  store.answer = parameters => {
    const limit = Number(parameters.get('limit') ?? 128), end = parameters.has('before') ? Number(parameters.get('before')) : store.storeEnd();
    const type = parameters.get('type'), frame = parameters.get('frame_id');
    const matching = store.records.map((value, index) => ({value, offset: index * 100}))
      .filter(({value, offset}) => offset < end && (!type || value.type === type) && (!frame || value.frame_id === frame));
    const chosen = matching.slice(-limit), limited = matching.length > limit;
    const scanStart = limited ? chosen[0].offset : store.budget ? Math.max(0, end - 1000) : 0;
    return {contract_version: 1, availability: store.availability, reason: 'browser_debugger_unsupported', experiment_flag: '--reb-native-debugger',
      policy: 'proposed_pending_approval', detectable: true, lease_limit_ms: 60000, lease: null, paused: false, breakpoints: [],
      threads: {console: 'idle', frames: store.frames, workers: [], observed: store.observed}, watch: store.watch,
      observations: chosen.reverse().map(item => item.value), observations_malformed: 0,
      observations_query: {type, thread: frame ? {session_id: '1', process_id: 42, frame_id: frame} : null,
        scope: store.scope ?? (scanStart === 0 && end === store.storeEnd() ? 'store' : 'bounded_range'), direction: 'backward', limit,
        returned: chosen.length, store_end: String(store.storeEnd()), next_after: String(end), next_before: scanStart > 0 ? String(scanStart) : null,
        limited, budget_exhausted: store.budget},
      observation_budget_gaps: []};
  };
  return store;
}

// A fresh document with the sidebar's mount points and the app globals it
// uses. `hold` keeps matching requests until released or aborted, `failing`
// fails them, and `store.delay` slows each debugger read.
function mount({protocol = 'http:', store = createStore(), hold = null, failing = null, globals = {}} = {}) {
  const {window, document} = parseHTML(`<!doctype html><html><body>
    <section id="screen-sources"><button id="source-debugger-toggle" type="button">Debugger</button>
      <aside id="source-sidebar" hidden></aside><aside id="debugger-sidebar" hidden></aside><div id="source-tree"></div></section>
    <section id="screen-traffic" hidden></section></body></html>`);
  const requests = [], reveals = [], errors = [], timeouts = [];
  // Each deadline the script asks for; a request records the last one asked.
  const signals = {timeout: ms => { timeouts.push(ms); return AbortSignal.timeout(ms); }, any: list => AbortSignal.any(list)};
  window.Element.prototype.scrollIntoView = function scrollIntoView() { reveals.push(this.className); };
  // Each request is answered at once unless `hold` keeps it until released or aborted.
  async function fetch(input, init = {}) {
    const url = String(input), parameters = new URL(url, 'http://local').searchParams;
    const entry = {url, signal: init.signal ?? null, timeout: timeouts.at(-1) ?? null};
    requests.push(entry);
    // Answered on a later turn, as a network answers, so a read loop cannot starve timers.
    await new Promise(next => setImmediate(next));
    if (hold?.(url)) {
      await new Promise((release, reject) => {
        entry.release = release;
        init.signal?.addEventListener('abort', () => reject(init.signal.reason ?? new DOMException('aborted', 'AbortError')), {once: true});
      });
    }
    if (failing?.(url)) throw new TypeError('Load failed');
    if (store.delay && url.startsWith('/api/native-debugger')) await sleep(store.delay);
    const json = body => ({ok: true, status: 200, json: async () => structuredClone(body)});
    if (url.startsWith('/api/native-debugger')) return json(store.answer(parameters));
    if (url.startsWith('/api/request-stack')) return json({status: 'recorded', request: {sequence_number: parameters.get('observation_sequence')}, state: 'no_script', frames: [], observation: {site: null}});
    if (url.startsWith('/api/requests')) return json(context.__requests?.(parameters) ?? {format: 'reb-request-index-v1', requests: [], located: {}});
    return {ok: false, status: 404, json: async () => ({error: 'not served'})};
  }
  const location = {protocol};
  const context = {window, document, location, fetch, console: {...console, error: (...args) => errors.push(args.map(String).join(' '))}, setTimeout, clearTimeout, AbortController, AbortSignal: signals, DOMException,
    URL, URLSearchParams, TextEncoder, structuredClone, MutationObserver: window.MutationObserver, Event: window.Event,
    getComputedStyle: () => ({position: 'static'}), ...globals};
  runInNewContext(script, context, {filename: 'debugger_sidebar.js'});
  const sidebar = document.querySelector('#debugger-sidebar'), toggle = document.querySelector('#source-debugger-toggle');
  const reads = () => requests.filter(entry => entry.url.startsWith('/api/native-debugger'));
  return {window, document, sidebar, toggle, requests, reads, reveals, errors, store, context, location,
    open: () => { if (sidebar.hidden) toggle.click(); }, close: () => { if (!sidebar.hidden) toggle.click(); },
    rows: selector => [...sidebar.querySelectorAll(`${selector} .debugger-list-row`)],
    text: selector => sidebar.querySelector(selector)?.textContent ?? ''};
}

async function until(predicate, message, timeout = 4 * POLL) {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    if (Date.now() > deadline) assert.fail(`timed out: ${message}`);
    await sleep(10);
  }
}
const settle = () => sleep(30);
// A held request can be released once the stub has reached its hold.
const release = async entry => { await until(() => entry?.release, 'a held request'); entry.release(); };
const event = (ui, type, init = {}) => Object.assign(new ui.window.Event(type, {bubbles: true, cancelable: true}), init);
const click = (ui, node, detail = 1) => node.dispatchEvent(event(ui, 'click', {detail}));
const key = (ui, node, name) => node.dispatchEvent(event(ui, 'keydown', {key: name}));
const results = [];
const only = process.env.REB_DEBUGGER_CASE ?? null;
async function check(name, run) {
  if (only !== null && !name.includes(only)) return;
  await run();
  results.push(name);
}

// 1. One Watch rules form, bound to the document its button names; arming
// refuses when the Console's document changed since the form was drawn.
await check('one watch form per Console document, stale arming refused', async () => {
  let live = {session_id: '5', target_id: '22', label: 'top #22'};
  const calls = [];
  // The stub Console arms the way the renderer confirms: the next read reports the set.
  const ui = mount({globals: {RebNativeConsole: {liveDocument: () => live, watch: async rules => {
    calls.push(rules);
    ui.store.watch = rules ? {state: 'armed', armed: {session_id: live.session_id, target_id: live.target_id, rules}} : {state: 'none', armed: null};
    return {status: 'ok'};
  }}}});
  ui.open();
  await until(() => ui.sidebar.querySelector('.debugger-watch-form'), 'the form appears');
  const forms = () => [...ui.sidebar.querySelectorAll('.debugger-watch-form')];
  for (const kind of ['timer_observation', 'all', 'listener_dispatch', 'all']) {
    click(ui, ui.sidebar.querySelector(`.debugger-kind[data-kind="${kind}"]`));
    await settle();
  }
  assert.equal(forms().length, 1, 'repeated renders keep one form');
  // Collapsing and expanding the section releases and redraws it.
  const pane = ui.sidebar.querySelector('[data-debugger-section="watch-rules"]');
  for (let turn = 0; turn < 2; turn += 1) {
    pane.open = false;
    pane.dispatchEvent(event(ui, 'toggle'));
    pane.open = true;
    pane.dispatchEvent(event(ui, 'toggle'));
    click(ui, ui.sidebar.querySelector('.debugger-kind[data-kind="all"]'));
    await settle();
  }
  assert.equal(forms().length, 1, 'collapsing and expanding keeps one form');
  assert.equal(forms()[0].querySelector('.debugger-arm').textContent, 'Arm on document 22');
  // The Console moves to document 23; the form drawn for 22 sends nothing.
  live = {session_id: '5', target_id: '23', label: 'child #23'};
  const stale = forms()[0];
  stale.querySelector('textarea').value = '/collect';
  stale.dispatchEvent(event(ui, 'submit'));
  await settle();
  assert.equal(calls.length, 0, 'a form drawn for another document sends nothing');
  assert.equal(forms().length, 1, 'the redraw keeps one form');
  assert.equal(forms()[0].querySelector('.debugger-arm').textContent, 'Arm on document 23', 'the form is drawn again for the Console document');
  assert.match(ui.text('.debugger-watch-result'), /Not sent: the Console now holds document 23, not document 22/);
  forms()[0].querySelector('textarea').value = '/collect';
  forms()[0].dispatchEvent(event(ui, 'submit'));
  await until(() => /Armed on document 23/.test(ui.text('.debugger-watch-result')), 'arming the current document');
  assert.equal(calls.length, 1);
  assert.equal(JSON.stringify(calls[0].requests), JSON.stringify([{url_contains: '/collect'}]));
  // Disconnected: no form, and the outcome stays readable.
  live = null;
  click(ui, ui.sidebar.querySelector('.debugger-kind[data-kind="timer_observation"]'));
  await settle();
  assert.equal(forms().length, 0, 'no live document, no form');
  live = {session_id: '5', target_id: '22', label: 'top #22'};
  click(ui, ui.sidebar.querySelector('.debugger-kind[data-kind="all"]'));
  await settle();
  assert.equal(forms().length, 1);
  ui.close();
});

// 2. The stored-evidence window reads once and says so; a window without a
// backend reads nothing.
await check('stored window reads once, no-backend window never reads', async () => {
  const stored = mount({protocol: 'reb:', store: createStore(5)});
  stored.open();
  await until(() => stored.rows('#debugger-observations').length === 5, 'stored rows');
  await sleep(POLL + 600);
  assert.equal(stored.reads().length, 1, 'the stored window does not poll');
  assert.match(stored.text('.debugger-sidebar-status'), /Stored evidence: read once/);
  const again = [...stored.sidebar.querySelectorAll('.debugger-sidebar-status button')].find(button => button.textContent === 'Read again');
  assert(again && !again.hidden, 'the stored window offers Read again');
  click(stored, again);
  await until(() => stored.reads().length === 2, 'Read again reads once');
  // Leaving Sources and coming back reads nothing more once read.
  const screen = stored.document.querySelector('#screen-sources');
  screen.hidden = true;
  await settle();
  screen.hidden = false;
  await settle();
  assert.equal(stored.reads().length, 2, 'returning to Sources does not read the fixed store again');
  stored.close();

  const offline = mount({protocol: 'file:'});
  offline.open();
  await sleep(POLL + 300);
  assert.equal(offline.requests.length, 0, 'no backend, no request');
  assert.match(offline.text('.debugger-sidebar-status'), /No backend serves this window/);
  offline.close();
});

// 3. An empty bounded read never says that no records exist.
await check('empty bounded read states how much was read', async () => {
  const store = createStore(0);
  store.end = 5000;
  store.budget = true;
  const ui = mount({store});
  ui.open();
  await until(() => /event store/.test(ui.text('.debugger-observation-notes')), 'the coverage note');
  const note = ui.text('.debugger-observation-notes');
  assert.doesNotMatch(note, /^No observation records in the event store/);
  assert.match(note, /in the newest 1000 bytes of the event store's 5 KiB, where the last read stopped at its 64 MiB budget\. Older bytes were not read/);
  const more = ui.sidebar.querySelector('.debugger-older');
  assert.equal(more.hidden, false, 'the older bytes can be read');
  ui.close();
  // The whole store read empty: only then is nothing said to exist.
  const whole = mount({store: createStore(0)});
  whole.open();
  await until(() => /event store/.test(whole.text('.debugger-observation-notes')), 'the whole-store note');
  assert.match(whole.text('.debugger-observation-notes'), /^No observation records in the event store\./);
  whole.close();
});

// 4 and 13. Older pages stay when records arrive, with scroll and selection;
// a span too long to read keeps the list and says which bytes it lacks.
await check('older pages, scroll and selection survive new records', async () => {
  const store = createStore(300);
  const ui = mount({store});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'the newest page');
  const list = ui.sidebar.querySelector('#debugger-observations');
  const size = () => Number(ui.rows('#debugger-observations')[0].getAttribute('aria-setsize'));
  assert.equal(size(), 128);
  assert(ui.rows('#debugger-observations').length <= 14, 'only rows near the view mount');
  click(ui, ui.sidebar.querySelector('.debugger-older'));
  await until(() => size() === 256, 'the older page');
  list.scrollTop = 44 * 50;
  list.dispatchEvent(event(ui, 'scroll'));
  const chosen = ui.rows('#debugger-observations').find(row => row.dataset.key === '1:42:250');
  assert(chosen, 'row 250 is mounted at the scroll position');
  click(ui, chosen);
  await settle();
  assert(ui.reveals.includes('debugger-detail'), 'choosing a row brings its details into view');
  store.add(3);
  const before = ui.reads().length;
  await until(() => size() === 259, 'the next poll adds the new records to the loaded pages', 2 * POLL + 1000);
  assert(ui.reads().length > before);
  assert.equal(list.scrollTop, 44 * 53, 'rows that arrive above the view do not move it');
  assert.equal(ui.sidebar.querySelector('#debugger-observations [aria-selected="true"]')?.dataset.key, '1:42:250', 'the selection stays');
  assert.match(ui.text('.debugger-detail'), /sequence 250/, 'its details stay');
  // More than the head page and two bridging reads: the list is kept as it is.
  store.add(600);
  await until(() => !ui.sidebar.querySelector('.debugger-observation-pinned').hidden, 'the kept list says so', 2 * POLL + 1000);
  assert.equal(size(), 259, 'the loaded pages stay');
  assert.match(ui.text('.debugger-observation-pinned'), /the 59 KiB written since \(bytes 30300 to 90300\) are more than 2 reads and are not in this list/);
  click(ui, [...ui.sidebar.querySelectorAll('.debugger-show-newest')][0]);
  await until(() => size() === 128 && ui.sidebar.querySelector('.debugger-observation-pinned').hidden, 'Show newest');
  ui.close();
});

// 5. A watched request opens through Traffic's own row selection, and a row
// outside Traffic's block is located in the request index first.
await check('Open request in Traffic selects through selectTrafficRow', async () => {
  const calls = [];
  const indexRow = {id: 'S1:R42:77', method: 'POST', path: '/collect'};
  let block = new Map([['S1:R42:77', {id: 'S1:R42:77', indexRow}]]);
  const store = createStore(0);
  store.records.push(record(0, {type: 'request_watch_match', request_id: '77', detail: {rule: 0, method_matched: true}}));
  const state = {requests: [], sessionMode: 'live', inspectorTab: 'general', trafficIndex: {row: id => block.get(id) ?? null}};
  const ui = mount({store, globals: {state,
    showScreen: name => calls.push(['screen', name]), setConsoleTrafficView: open => calls.push(['console', open]),
    selectTrafficRow: id => calls.push(['select', id, state.inspectorTab]), loadTrafficRequest: (row, select) => calls.push(['load', row.id, select, state.inspectorTab]),
    trafficIndexRequest: (row, origin) => ({id: row.id, origin, indexRow: row}), renderInspector: () => calls.push(['inspector']),
    __requests: parameters => parameters.has('locate')
      ? {format: 'reb-request-index-v1', requests: [], located: {[parameters.get('locate')]: block.size ? null : 2400}}
      : {format: 'reb-request-index-v1', requests: Number(parameters.get('offset')) === 2400 ? [indexRow] : []}}});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 1, 'the request record');
  const openRequest = async () => {
    click(ui, ui.rows('#debugger-observations')[0]);
    await settle();
    click(ui, [...ui.sidebar.querySelectorAll('.debugger-detail button')].find(button => button.textContent === 'Open request in Traffic'));
    await settle();
  };
  await openRequest();
  assert.deepEqual(calls.filter(call => call[0] !== 'inspector'), [['screen', 'traffic'], ['console', false], ['select', 'S1:R42:77', 'initiator']]);
  // Outside the block Traffic holds: located, then read the way a row click reads it.
  block = new Map();
  calls.length = 0;
  ui.sidebar.querySelector('.debugger-detail-close').click();
  await openRequest();
  assert.deepEqual(ui.requests.filter(entry => entry.url.startsWith('/api/requests')).map(entry => entry.url),
    ['/api/requests?sort=capture&order=asc&limit=1&offset=0&locate=S1%3AR42%3A77', '/api/requests?sort=capture&order=asc&limit=1&offset=2400']);
  assert.deepEqual(calls.filter(call => call[0] === 'load'), [['load', 'S1:R42:77', true, 'initiator']]);
  // Not indexed: nothing is selected, and the detail says why.
  ui.context.__requests = () => ({format: 'reb-request-index-v1', requests: [], located: {'S1:R42:77': null}});
  calls.length = 0;
  ui.sidebar.querySelector('.debugger-detail-close').click();
  await openRequest();
  assert.equal(calls.length, 0, 'an unindexed request selects nothing');
  assert.match(ui.text('.debugger-detail'), /Request 77 of renderer 42 is not in the request index/);
  ui.close();
});

// 6. A newer read, closing, leaving Sources and a replaced store abort reads.
await check('superseded and closed reads are aborted', async () => {
  let holding = false;
  const ui = mount({store: createStore(300), hold: url => holding && url.startsWith('/api/native-debugger')});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'the first read');
  holding = true;
  click(ui, ui.sidebar.querySelector('.debugger-kind[data-kind="timer_observation"]'));
  await until(() => ui.reads().length === 2, 'a held read');
  click(ui, ui.sidebar.querySelector('.debugger-kind[data-kind="all"]'));
  await until(() => ui.reads().length === 3, 'the newer read');
  assert.equal(ui.reads()[1].signal.aborted, true, 'a newer read aborts the one it replaces');
  ui.close();
  assert.equal(ui.reads()[2].signal.aborted, true, 'closing aborts the read in flight');
  // Leaving Sources aborts too.
  ui.open();
  await until(() => ui.reads().length === 4, 'reopened');
  ui.document.querySelector('#screen-sources').hidden = true;
  await settle();
  assert.equal(ui.reads()[3].signal.aborted, true, 'leaving Sources aborts the read in flight');
  holding = false;
  ui.document.querySelector('#screen-sources').hidden = false;
  await until(() => ui.rows('#debugger-observations').length > 0, 'coming back reads again');
  // An older-page read is aborted by a replaced (shorter) store.
  holding = true;
  click(ui, ui.sidebar.querySelector('.debugger-older'));
  await until(() => ui.reads().some(entry => entry.url.includes('before=')), 'the older read');
  const older = ui.reads().find(entry => entry.url.includes('before='));
  holding = false;
  ui.store.records.length = 10;
  await until(() => older.signal.aborted, 'a replaced store aborts the older read', 2 * POLL + 1000);
  await until(() => Number(ui.rows('#debugger-observations')[0]?.getAttribute('aria-setsize')) === 10, 'the replaced store is listed');
  ui.close();
});

// 7. Only real state changes are announced.
await check('the live region announces state changes only', async () => {
  const ui = mount({store: createStore(3)});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 3, 'rows');
  const regions = [...ui.sidebar.querySelectorAll('.debugger-sidebar-status [aria-live], .debugger-sidebar-status[aria-live]')];
  assert.equal(regions.length, 1, 'one live region in the status line');
  const changes = [];
  const observer = new ui.window.MutationObserver(records => changes.push(...records));
  observer.observe(regions[0], {childList: true, characterData: true, subtree: true});
  const before = ui.reads().length;
  await until(() => ui.reads().length > before + 1, 'two more polls', 3 * POLL);
  await settle();
  assert.equal(changes.length, 0, `unchanged polls announce nothing: ${regions[0].textContent}`);
  // A failure is a state change and is announced.
  ui.context.fetch = async () => { throw new Error('offline'); };
  ui.store.answer = () => { throw new Error('offline'); };
  await until(() => /Disconnected: offline/.test(regions[0].textContent), 'the failure is announced', 2 * POLL + 1000);
  observer.disconnect();
  ui.close();
});

// 9. The selected thread's origin, frame and process are shown in full.
await check('selected thread details show every field', async () => {
  const store = createStore(1);
  const origin = `https://${'very-long-subdomain.'.repeat(8)}example.test:8443`;
  store.frames = [{target_id: '22', label: 'top #22', origin, frame: 'child', out_of_process: true}];
  const ui = mount({store});
  ui.open();
  await until(() => ui.rows('#debugger-threads').length > 0, 'thread rows');
  const row = ui.rows('#debugger-threads').find(item => item.dataset.key === 'D:22');
  assert.equal(row.querySelector('.debugger-row-main').textContent, origin, 'the origin has the first line');
  click(ui, row);
  await settle();
  const detail = ui.sidebar.querySelector('.debugger-thread-detail');
  assert(detail, 'the selected thread has details');
  for (const value of [origin, 'child · document 22', 'own renderer (site isolation)', 'Out-of-process frame']) {
    assert([...detail.querySelectorAll('dd')].some(dd => dd.textContent === value), `details show ${value}`);
  }
  // A double-click is one choice, not three toggles.
  const reads = ui.reads().length;
  const frame = ui.rows('#debugger-threads').find(item => item.dataset.key === 'F:1:42:200');
  click(ui, frame, 1);
  click(ui, ui.rows('#debugger-threads').find(item => item.dataset.key === 'F:1:42:200'), 2);
  ui.rows('#debugger-threads').find(item => item.dataset.key === 'F:1:42:200').dispatchEvent(event(ui, 'dblclick', {detail: 2}));
  await settle();
  assert.equal(ui.reads().length, reads + 1, 'a double-click selects once');
  assert.equal(ui.sidebar.querySelector('#debugger-threads [aria-selected="true"]')?.dataset.key, 'F:1:42:200');
  // Keyboard: arrows move, Enter chooses.
  const list = ui.sidebar.querySelector('#debugger-threads');
  key(ui, list, 'Home');
  key(ui, list, 'Enter');
  await settle();
  assert.equal(ui.sidebar.querySelector('#debugger-threads [aria-selected="true"]')?.dataset.key, 'D:22', 'Home and Enter choose the first thread');
  ui.close();
});

// 10. The Pausing statement depends on the pausing sections registered.
await check('pausing statement names registered pausing sections', async () => {
  const store = createStore(0);
  store.availability = 'available';
  const ui = mount({store});
  ui.open();
  const statement = () => ui.text('[data-debugger-native="availability"]');
  await until(() => statement(), 'the statement');
  assert.match(statement(), /its controls are not part of this sidebar yet/);
  const remove = ui.context.RebDebuggerSidebar.addSection({id: 'breakpoints', title: 'Breakpoints', order: 45, native: 'pausing', render(body) { body.textContent = 'list'; }});
  await settle();
  assert.match(statement(), /^Available\. A Brave build serves the pausing debugger\. Its controls are in the Breakpoints section\.$/);
  const more = ['call-stack', 'scope'].map((id, index) => ui.context.RebDebuggerSidebar.addSection({id, title: ['Call stack', 'Scope'][index],
    order: 46 + index, native: 'pausing', render(body) { body.textContent = 'list'; }}));
  await settle();
  assert.match(statement(), /Its controls are in the Breakpoints, Call stack and Scope sections\.$/, 'the names read as a list');
  for (const removal of [remove, ...more]) removal();
  await settle();
  assert.match(statement(), /not part of this sidebar yet/);
  ui.close();
});

// 11. A section that refreshes from render does not read back to back, and a
// throwing summary leaves its body.
await check('registry sections cannot loop reads or blank themselves', async () => {
  const ui = mount({store: createStore(2)});
  ui.context.RebDebuggerSidebar.addSection({id: 'eager', title: 'Eager', order: 50, render(body, view) { body.textContent = 'eager body'; view.refresh(); }});
  ui.context.RebDebuggerSidebar.addSection({id: 'broken', title: 'Broken', order: 60, summary() { throw new Error('bad count'); }, render(body) { body.textContent = 'still here'; }});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 2, 'rows');
  await sleep(POLL / 2);
  assert.equal(ui.reads().length, 1, 'refresh during render reads nothing more');
  assert.equal(ui.text('[data-debugger-section="broken"] .debugger-section-body'), 'still here', 'a throwing summary leaves the body');
  assert(ui.errors.some(text => text.includes('bad count')), 'the failure is logged');
  ui.close();
});

// 13. The Observations list is sized by its rows up to a cap, not fixed.
await check('observations list height follows its rows', async () => {
  const rule = /\.debugger-observations \.debugger-list\s*\{([^}]*)\}/.exec(css)?.[1] ?? '';
  assert.doesNotMatch(rule, /(?:^|;)\s*height\s*:/, 'no fixed height');
  assert.match(rule, /max-height\s*:\s*clamp\(/, 'a capped height');
});

// Closed and hidden sidebars make no requests and run no timers.
await check('closed or hidden sidebar stays idle', async () => {
  const ui = mount({store: createStore(4096)});
  await sleep(POLL + 200);
  assert.equal(ui.requests.length, 0, 'never opened, never read');
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  // Every record loaded, and still only the rows near the view mount.
  const size = () => Number(ui.rows('#debugger-observations')[0].getAttribute('aria-setsize'));
  for (let page = 1; size() < 4096; page += 1) {
    assert(page < 40, 'older pages load');
    click(ui, ui.sidebar.querySelector('.debugger-older'));
    const target = Math.min(4096, 128 * (page + 1));
    await until(() => size() === target, `page ${page}`);
  }
  const mounted = ui.rows('#debugger-observations').length;
  assert(mounted >= 6 && mounted <= 12, `6 to 12 of 4,096 rows mount: ${mounted}`);
  assert.equal(ui.sidebar.querySelector('.debugger-older').hidden, true, 'a full list offers no older page');
  ui.document.querySelector('#screen-sources').hidden = true;
  await settle();
  const hidden = ui.requests.length;
  await sleep(POLL + 600);
  assert.equal(ui.requests.length, hidden, 'a hidden Sources screen reads nothing');
  ui.document.querySelector('#screen-sources').hidden = false;
  await until(() => ui.requests.length > hidden, 'shown again, it reads');
  ui.close();
  const closed = ui.requests.length;
  await sleep(POLL + 600);
  assert.equal(ui.requests.length, closed, 'a closed sidebar reads nothing');
});

// Round 2, 1. A chosen observation is marked at once, also where nothing polls.
await check('a chosen observation is marked at once', async () => {
  const ui = mount({protocol: 'reb:', store: createStore(5)});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 5, 'rows');
  const list = ui.sidebar.querySelector('#debugger-observations');
  const marked = () => [...list.querySelectorAll('[aria-selected="true"]')].map(row => row.dataset.key);
  click(ui, ui.rows('#debugger-observations')[0]);
  await settle();
  assert.deepEqual(marked(), ['1:42:5'], 'the clicked row is marked before any read');
  key(ui, list, 'ArrowDown');
  await sleep(250);
  assert.deepEqual(marked(), ['1:42:4'], 'the highlight follows the arrow with the details');
  assert.match(ui.text('.debugger-detail'), /sequence 4/);
  assert.equal(ui.reads().length, 1, 'choosing reads nothing');
  ui.close();
});

// Round 2, 2. Without older pages, a selection or a scrolled list keeps its
// place as records arrive; back at the top with nothing selected, it follows.
await check('the default list keeps the researcher place', async () => {
  const store = createStore(300);
  const ui = mount({store});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  const list = ui.sidebar.querySelector('#debugger-observations');
  const size = () => Number(ui.rows('#debugger-observations')[0]?.getAttribute('aria-setsize'));
  assert.equal(size(), 128);
  list.scrollTop = 44 * 115;
  list.dispatchEvent(event(ui, 'scroll'));
  click(ui, ui.rows('#debugger-observations').find(row => row.dataset.key === '1:42:180'));
  await settle();
  for (let poll = 1; poll <= 3; poll += 1) {
    store.add(10);
    await until(() => size() === 128 + 10 * poll, `poll ${poll} adds its records to the kept rows`, 2 * POLL + 1500);
  }
  assert.equal(list.querySelector('[aria-selected="true"]')?.dataset.key, '1:42:180', 'the selection stays in the list');
  assert.equal(list.scrollTop, 44 * 145, 'the view stays on the rows it showed');
  key(ui, list, 'ArrowDown');
  await sleep(250);
  assert.equal(list.querySelector('[data-active="true"]')?.dataset.key, '1:42:179', 'arrow keys continue from the selection');
  ui.sidebar.querySelector('.debugger-detail-close').click();
  list.scrollTop = 0;
  list.dispatchEvent(event(ui, 'scroll'));
  await until(() => size() === 128, 'at the top with nothing selected the list follows the newest page');
  ui.close();
});

await check('a kept list past its bound says how many rows it dropped', async () => {
  const store = createStore(4200);
  const ui = mount({store});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  const size = () => Number(ui.rows('#debugger-observations')[0]?.getAttribute('aria-setsize'));
  for (let page = 1; size() < 4096; page += 1) {
    click(ui, ui.sidebar.querySelector('.debugger-older'));
    await until(() => size() === Math.min(4096, 128 * (page + 1)), `page ${page}`);
  }
  click(ui, ui.rows('#debugger-observations')[0]);
  await settle();
  store.add(10);
  await until(() => /10 older rows were dropped/.test(ui.text('.debugger-observation-notes')), 'the bound is stated', 2 * POLL + 1500);
  assert.equal(size(), 4096, 'the bound holds');
  assert.equal(ui.sidebar.querySelector('#debugger-observations [aria-selected="true"]')?.dataset.key, '1:42:4200', 'the selection stays');
  assert.doesNotMatch(ui.text('.debugger-observation-notes'), /whole event store/);
  ui.close();
});

// Round 2, 3. How long a read took never reaches the live region.
await check('the live region ignores how long reads take', async () => {
  const store = createStore(3);
  const ui = mount({store});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 3, 'rows');
  const region = ui.sidebar.querySelector('.debugger-sidebar-status [aria-live], .debugger-sidebar-status[aria-live]');
  const first = region.textContent;
  store.delay = 900;
  await until(() => /every 4 seconds/.test(ui.text('.debugger-sidebar-status')), 'a slower read lengthens the interval', 3 * POLL + 2000);
  assert.equal(region.textContent, first, 'the interval is outside the live region');
  ui.close();
});

// Round 2, 4. A refresh a section defers from render neither loops nor hangs.
await check('a refresh deferred from render neither loops nor hangs', async () => {
  for (const protocol of ['http:', 'reb:']) {
    const ui = mount({protocol, store: createStore(2)});
    let renders = 0;
    // The cap ends a runaway loop, so an old script fails here instead of hanging.
    ui.context.RebDebuggerSidebar.addSection({id: 'eager-later', title: 'Eager', order: 60, render(body, view) {
      body.textContent = 'eager';
      renders += 1;
      if (renders < 300) { Promise.resolve().then(view.refresh); setTimeout(view.refresh, 0); }
    }});
    ui.open();
    await sleep(POLL - 400);
    assert.equal(ui.reads().length, 1, `${protocol}: one read, not one per render (${renders} renders)`);
    assert(renders < 10, `${protocol}: renders follow reads (${renders})`);
    ui.close();
  }
});

// Round 2, 6. Opening a watched request is cancelled when the researcher
// moves on, and its link says it is working.
await check('Open request in Traffic cancels when the researcher moves on', async () => {
  const calls = [];
  let holding = true;
  const indexRow = {id: 'S1:R42:77', method: 'POST', path: '/collect'};
  const store = createStore(0);
  store.records.push(record(0, {type: 'request_watch_match', request_id: '77', detail: {rule: 0, method_matched: true}}));
  const state = {requests: [], sessionMode: 'live', inspectorTab: 'general', trafficIndex: {row: () => null}};
  const ui = mount({store, hold: url => holding && url.startsWith('/api/requests'), globals: {state,
    showScreen: name => calls.push(['screen', name]), setConsoleTrafficView: () => {}, renderInspector: () => {},
    selectTrafficRow: id => calls.push(['select', id]), loadTrafficRequest: row => calls.push(['load', row.id]),
    trafficIndexRequest: (row, origin) => ({id: row.id, origin, indexRow: row}),
    __requests: parameters => parameters.has('locate') ? {format: 'reb-request-index-v1', requests: [], located: {'S1:R42:77': 2400}}
      : {format: 'reb-request-index-v1', requests: [indexRow]}}});
  const lookups = () => ui.requests.filter(entry => entry.url.startsWith('/api/requests'));
  const link = () => ui.sidebar.querySelector('.debugger-open-request');
  const choose = async () => { click(ui, ui.rows('#debugger-observations')[0]); await settle(); };
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 1, 'the request record');
  await choose();
  click(ui, link());
  await until(() => lookups().length === 1, 'a lookup');
  assert.equal(link().textContent, 'Opening request in Traffic…', 'the link shows progress');
  assert.equal(link().getAttribute('aria-busy'), 'true');
  click(ui, link());
  await until(() => lookups().length === 2, 'a newer lookup');
  assert.equal(lookups()[0].signal.aborted, true, 'a newer click cancels the earlier lookup');
  ui.close();
  assert.equal(lookups()[1].signal.aborted, true, 'closing the sidebar cancels the lookup');
  // Another screen chosen while the lookup runs: nothing switches.
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 1, 'reopened');
  await choose();
  click(ui, link());
  await until(() => lookups()[2]?.release, 'a third lookup, held');
  ui.document.querySelector('#screen-sources').hidden = true;
  holding = false;
  await release(lookups()[2]);
  await sleep(100);
  assert.deepEqual(calls, [], 'nothing switches screens after the researcher moved on');
  ui.close();
});

// Round 2, 7. An arm outcome ends once a later read says the rules are gone.
await check('a Watch outcome ends when the state it named is gone', async () => {
  let live = {session_id: '5', target_id: '22', label: 'top #22'};
  const store = createStore(1);
  const ui = mount({store, globals: {RebNativeConsole: {liveDocument: () => live, watch: async rules => {
    store.watch = rules ? {state: 'armed', armed: {session_id: '5', target_id: '22', rules}} : {state: 'none', armed: null};
    return {status: 'ok'};
  }}}});
  const section = () => ui.text('[data-debugger-section="watch-rules"] .debugger-section-body');
  ui.open();
  await until(() => ui.sidebar.querySelector('.debugger-watch-form'), 'the form');
  const form = ui.sidebar.querySelector('.debugger-watch-form');
  form.querySelector('textarea').value = '/collect';
  form.dispatchEvent(event(ui, 'submit'));
  await until(() => /Armed on Console document 22/.test(section()), 'the armed set is read', 2 * POLL + 1000);
  assert.match(section(), /Armed on document 22\. The renderer confirmed the set below\./, 'the outcome agrees with the state');
  // A Console Stop disarms the rules and ends the connection.
  store.watch = {state: 'none', armed: null};
  live = null;
  await until(() => /No rules armed/.test(section()), 'the disarmed state is read', 2 * POLL + 1000);
  assert.doesNotMatch(section(), /Armed on document 22/, 'no outcome contradicts the state');
  ui.close();
});

// Round 2, 8. A chosen record's details come into view again once resolved.
await check('details come into view again once positions resolve', async () => {
  let holding = true;
  const store = createStore(0);
  store.records.push(record(0, {type: 'request_watch_match', request_id: '77', detail: {rule: 0, method_matched: true}}));
  const ui = mount({protocol: 'reb:', store, hold: url => holding && url.startsWith('/api/request-stack')});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 1, 'rows');
  click(ui, ui.rows('#debugger-observations')[0]);
  await until(() => /Resolving positions/.test(ui.text('.debugger-detail')), 'resolving');
  const early = ui.reveals.length;
  assert(early > 0, 'the chosen details are revealed');
  await release(ui.requests.find(entry => entry.url.startsWith('/api/request-stack')));
  holding = false;
  await until(() => !/Resolving positions/.test(ui.text('.debugger-detail')), 'resolved');
  await settle();
  assert(ui.reveals.length > early, 'revealed again once resolved');
  assert(ui.reveals.includes('debugger-detail-actions'), 'the action row is brought into view');
  ui.close();
});

// Round 2, 10. A failed bridging read changes neither rows nor their note.
await check('a failed bridging read leaves rows and note as they were', async () => {
  const store = createStore(300);
  let failBefore = false;
  const ui = mount({store, failing: url => failBefore && url.includes('before=')});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  click(ui, ui.sidebar.querySelector('.debugger-older'));
  const size = () => Number(ui.rows('#debugger-observations')[0]?.getAttribute('aria-setsize'));
  await until(() => size() === 256, 'the older page');
  const note = ui.text('.debugger-observation-notes');
  failBefore = true;
  store.add(300);
  await until(() => /Disconnected: Load failed/.test(ui.text('.debugger-sidebar-status')), 'the bridging read fails', 2 * POLL + 1500);
  assert.equal(size(), 256);
  assert.equal(ui.text('.debugger-observation-notes'), note, 'the note still describes the rows shown');
  ui.close();
});

await check('stored reads wait for the bundled backend', async () => {
  const stored = mount({protocol: 'reb:', store: createStore(2)});
  stored.open();
  await until(() => stored.rows('#debugger-observations').length === 2, 'stored rows');
  assert(stored.reads()[0].timeout >= 30000, `a stored read waits past a 15 s backend start: ${stored.reads()[0].timeout} ms`);
  stored.close();
  const live = mount({store: createStore(2)});
  live.open();
  await until(() => live.rows('#debugger-observations').length === 2, 'live rows');
  assert.equal(live.reads()[0].timeout, 10000, 'a live read keeps its 10 s deadline');
  live.close();
});

// Round 3 helpers: a section that hands back the view, and the holes in the
// sequence of the rows the list holds (each record is the next sequence down).
const probe = ui => {
  let seen = null;
  ui.context.RebDebuggerSidebar.addSection({id: 'probe', title: 'Probe', order: 90, render(body, view) { seen = view; body.textContent = 'probe'; }});
  return () => seen;
};
const holes = view => {
  const sequences = [...(view.observations.list?.records ?? view.observations.head)].map(record => Number(record.sequence_number));
  return sequences.flatMap((sequence, index) => index && sequences[index - 1] - sequence !== 1 ? [`${sequences[index - 1]} to ${sequence}`] : []);
};

// Round 3, 1. Show older records continues exactly the rows it was asked
// from, whether a read answers or the researcher returns to the top meanwhile.
await check('a read answering during Show older leaves no hole', async () => {
  const store = createStore(300);
  let holding = false;
  const ui = mount({store, hold: url => holding && url.includes('before=')});
  const view = probe(ui);
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  holding = true;
  click(ui, ui.sidebar.querySelector('.debugger-older'));
  const older = () => ui.reads().find(entry => entry.url.includes('before=') && entry.release);
  await until(() => older(), 'the older read, held');
  holding = false;
  store.add(60);
  await until(() => view().observations.query.store_end === String(store.storeEnd()), 'a read answers meanwhile', 3 * POLL);
  older().release();
  await until(() => !view().observations.loadingOlder, 'the older page');
  assert.deepEqual(holes(view()), [], 'no records are missing between the newest rows and the older page');
  assert.equal(view().observations.list.records.length, 360 - 44, 'records 360 to 45');
  ui.close();
});

await check('returning to the top during Show older leaves no hole', async () => {
  const store = createStore(300);
  let holding = false;
  const ui = mount({store, hold: url => holding && url.includes('before=')});
  const view = probe(ui);
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  const list = ui.sidebar.querySelector('#debugger-observations');
  list.scrollTop = 44 * 20;
  list.dispatchEvent(event(ui, 'scroll'));
  store.add(40);
  await until(() => view().observations.list?.records.length === 168, 'new records join the kept rows', 3 * POLL);
  holding = true;
  click(ui, ui.sidebar.querySelector('.debugger-older'));
  const older = () => ui.reads().find(entry => entry.url.includes('before=') && entry.release);
  await until(() => older(), 'the older read, held');
  holding = false;
  list.scrollTop = 0;
  list.dispatchEvent(event(ui, 'scroll'));
  await settle();
  older().release();
  await sleep(200);
  assert.deepEqual(holes(view()), [], 'no records are missing');
  ui.close();
});

// Round 4, 1. A Show older read that fails, or is cut short by leaving
// Sources, added no page, so the rows follow the newest page as before.
await check('a Show older read that adds no page leaves the rows following the newest', async () => {
  for (const how of ['fails', 'is cut short by leaving Sources']) {
    const store = createStore(300);
    let failing = false, holding = false;
    const ui = mount({store, failing: url => failing && url.includes('before='), hold: url => holding && url.includes('before=')});
    const view = probe(ui);
    ui.open();
    await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
    if (how === 'fails') failing = true; else holding = true;
    click(ui, ui.sidebar.querySelector('.debugger-older'));
    if (how === 'fails') await until(() => view().observations.olderError, 'the older read fails');
    else {
      await until(() => ui.reads().some(entry => entry.url.includes('before=') && entry.release), 'the older read, held');
      const screen = ui.document.querySelector('#screen-sources');
      screen.hidden = true;
      await settle();
      screen.hidden = false;
    }
    failing = false; holding = false;
    store.add(400);
    await until(() => ui.rows('#debugger-observations')[0]?.dataset.key === '1:42:700', `${how}: the newest records`, 3 * POLL);
    assert.equal(ui.sidebar.querySelector('.debugger-observation-pinned').hidden, true, `${how}: no place is claimed as kept`);
    ui.close();
  }
});

// Round 4, 5. The read a Watch action asks for does nothing from a render.
await check('a read asked for from a render starts none', async () => {
  const ui = mount({store: createStore(2)});
  let renders = 0;
  ui.context.RebDebuggerSidebar.addSection({id: 'eager-action', title: 'Eager', order: 60, render(body, view) {
    body.textContent = 'eager';
    renders += 1;
    if (renders < 300) view.readAfterAction();
  }});
  ui.open();
  await sleep(POLL - 400);
  assert.equal(ui.reads().length, 1, `one read, not one per render (${renders} renders)`);
  ui.close();
});

// Round 3, 2. Choosing another record, the kind filter or leaving Sources
// cancels a Traffic lookup, and a cancelled lookup never switches screens.
await check('moving on in the sidebar cancels a Traffic lookup', async () => {
  const calls = [];
  let holding = true;
  const indexRow = {id: 'S1:R42:77', method: 'POST', path: '/collect'};
  const store = createStore(0);
  store.records.push(record(0, {type: 'request_watch_match', request_id: '77', detail: {rule: 0, method_matched: true}}));
  store.records.push(record(1));
  const state = {requests: [], sessionMode: 'live', inspectorTab: 'general', trafficIndex: {row: () => null}};
  const ui = mount({store, hold: url => holding && url.startsWith('/api/requests'), globals: {state,
    showScreen: name => calls.push(['screen', name]), setConsoleTrafficView: () => {}, renderInspector: () => {},
    selectTrafficRow: id => calls.push(['select', id]), loadTrafficRequest: row => calls.push(['load', row.id]),
    trafficIndexRequest: (row, origin) => ({id: row.id, origin, indexRow: row}),
    __requests: parameters => parameters.has('locate') ? {format: 'reb-request-index-v1', requests: [], located: {'S1:R42:77': 2400}}
      : {format: 'reb-request-index-v1', requests: [indexRow]}}});
  const lookups = () => ui.requests.filter(entry => entry.url.startsWith('/api/requests'));
  const row = key => ui.rows('#debugger-observations').find(item => item.dataset.key === key);
  const startLookup = async count => {
    click(ui, row('1:42:1'));
    await settle();
    click(ui, ui.sidebar.querySelector('.debugger-open-request'));
    await until(() => lookups()[count - 1]?.release, `lookup ${count}, held`);
    return lookups()[count - 1];
  };
  ui.open();
  await until(() => ui.rows('#debugger-observations').length === 2, 'rows');
  const first = await startLookup(1);
  click(ui, row('1:42:2'));
  await settle();
  assert.equal(first.signal.aborted, true, 'choosing another record cancels the lookup');
  const second = await startLookup(2);
  click(ui, ui.sidebar.querySelector('.debugger-kind[data-kind="timer_observation"]'));
  await settle();
  assert.equal(second.signal.aborted, true, 'the kind filter cancels the lookup');
  click(ui, ui.sidebar.querySelector('.debugger-kind[data-kind="all"]'));
  await until(() => ui.rows('#debugger-observations').length === 2, 'all records again');
  const third = await startLookup(3);
  const screen = ui.document.querySelector('#screen-sources');
  screen.hidden = true;
  await settle();
  screen.hidden = false;
  await settle();
  holding = false;
  for (const entry of [first, second, third]) entry.release();
  await sleep(200);
  assert.deepEqual(calls, [], 'no cancelled lookup, nor one begun before leaving Sources, switches screens');
  ui.close();
});

// Round 3, 3. A selection carried into a Threads scope keeps its place.
await check('a selection carried into a thread scope keeps its place', async () => {
  const store = createStore(200);
  const ui = mount({store});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  const list = ui.sidebar.querySelector('#debugger-observations');
  list.scrollTop = 44 * 110;
  list.dispatchEvent(event(ui, 'scroll'));
  click(ui, ui.rows('#debugger-observations').find(item => item.dataset.key === '1:42:81'));
  await settle();
  click(ui, ui.rows('#debugger-threads').find(item => item.dataset.key === 'F:1:42:200'));
  await until(() => /in frame 200/.test(ui.text('.debugger-observation-notes')), 'the scoped read');
  assert.equal(list.querySelector('[aria-selected="true"]')?.dataset.key, '1:42:81', 'the record stays selected in the scope');
  store.add(10);
  await until(() => Number(ui.rows('#debugger-observations')[0]?.getAttribute('aria-setsize')) === 138, 'the next read adds to the kept rows', 2 * POLL + 1500);
  assert.equal(list.querySelector('[aria-selected="true"]')?.dataset.key, '1:42:81', 'the selection stays in the list');
  assert.doesNotMatch(ui.text('.debugger-detail'), /no longer in the list/);
  ui.close();
});

// Round 3, 4. Arming reads the confirmed set at once, not at the next poll.
await check('arming reads the confirmed set at once', async () => {
  const live = {session_id: '5', target_id: '22', label: 'top #22'};
  const store = createStore(1);
  const ui = mount({store, globals: {RebNativeConsole: {liveDocument: () => live, watch: async rules => {
    store.watch = rules ? {state: 'armed', armed: {session_id: '5', target_id: '22', rules}} : {state: 'none', armed: null};
    return {status: 'ok'};
  }}}});
  const section = () => ui.text('[data-debugger-section="watch-rules"] .debugger-section-body');
  ui.open();
  await until(() => ui.sidebar.querySelector('.debugger-watch-form'), 'the form');
  // Slow reads stretch the poll to 6 seconds; arming just after one read ends.
  store.delay = 1500;
  await until(() => /every 6 seconds/.test(ui.text('.debugger-sidebar-status')), 'a 6 second interval', 4 * POLL);
  const form = ui.sidebar.querySelector('.debugger-watch-form');
  form.querySelector('textarea').value = '/collect';
  form.dispatchEvent(event(ui, 'submit'));
  await until(() => /Armed on document 22/.test(section()), 'the outcome');
  assert.doesNotMatch(section(), /The renderer confirmed the set below/, 'before its read answers, the outcome does not point at a set not shown');
  await until(() => /Armed on Console document 22/.test(section()), 'the confirmed set, well before the next poll', 4000);
  assert.match(section(), /Armed on document 22\. The renderer confirmed the set below\./);
  // Clearing: until its read answers, the outcome does not stand as final
  // beside the set that was armed.
  click(ui, [...ui.sidebar.querySelectorAll('.debugger-watch-form button')].find(button => button.textContent === 'Clear rules'));
  await until(() => /Cleared on document 22/.test(section()), 'the clear outcome');
  assert.match(section(), /Armed on Console document 22/, 'the read of the cleared set is still out');
  assert.match(section(), /Cleared on document 22\. Reading the set that is left/);
  await until(() => /No rules armed/.test(section()), 'the cleared set', 4000);
  assert.match(section(), /Cleared on document 22\.$|Cleared on document 22\.(?! Reading)/);
  ui.close();
});

// Round 3, 5. Reopened with nothing selected, the list shows the newest records.
await check('reopening shows the newest records, not kept ones', async () => {
  const store = createStore(200);
  const ui = mount({store});
  ui.open();
  await until(() => ui.rows('#debugger-observations').length > 0, 'rows');
  click(ui, ui.rows('#debugger-observations')[0]);
  await settle();
  ui.close();
  store.add(500);
  const reads = ui.reads().length;
  ui.open();
  await until(() => ui.reads().length > reads && ui.rows('#debugger-observations')[0]?.dataset.key === '1:42:700', 'the newest records', 4000);
  assert.equal(ui.sidebar.querySelector('.debugger-observation-pinned').hidden, true, 'no place is claimed as kept');
  assert.equal(ui.sidebar.querySelector('#debugger-observations [aria-selected="true"]'), null);
  ui.close();
});

// Round 3, 7. A read while the Console holds the session judges no outcome.
await check('a busy read leaves the arm outcome', async () => {
  const live = {session_id: '5', target_id: '22', label: 'top #22'};
  const store = createStore(1);
  const ui = mount({store, globals: {RebNativeConsole: {liveDocument: () => live, watch: async rules => {
    store.watch = rules ? {state: 'armed', armed: {session_id: '5', target_id: '22', rules}} : {state: 'none', armed: null};
    return {status: 'ok'};
  }}}});
  const section = () => ui.text('[data-debugger-section="watch-rules"] .debugger-section-body');
  ui.open();
  await until(() => ui.sidebar.querySelector('.debugger-watch-form'), 'the form');
  const form = ui.sidebar.querySelector('.debugger-watch-form');
  form.querySelector('textarea').value = '/collect';
  form.dispatchEvent(event(ui, 'submit'));
  await until(() => /Armed on Console document 22/.test(section()), 'the armed set', 2 * POLL + 1000);
  const armed = store.watch;
  store.watch = {state: 'busy', armed: null};
  await until(() => /A Console action holds the session/.test(section()), 'a busy read', 2 * POLL + 1000);
  assert.match(section(), /Armed on document 22/, 'a busy read does not end the outcome');
  assert.doesNotMatch(section(), /The renderer confirmed the set below/, 'while busy, the outcome does not point at a set not shown');
  store.watch = armed;
  await until(() => /Armed on Console document 22/.test(section()), 'armed again', 2 * POLL + 1000);
  assert.match(section(), /Armed on document 22\. The renderer confirmed the set below\./);
  ui.close();
});

console.log(`PASS debugger sidebar: ${results.length} cases with real timers (offline DOM model; no rendered layout claimed)`);
for (const name of results) console.log(`  ${name}`);
