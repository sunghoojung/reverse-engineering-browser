import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {runInNewContext} from 'node:vm';

// Deterministic production-controller/DOM-work checks, not rendered latency.
// Layout getters below count requests for geometry; they do not simulate a browser.
const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
const traffic = await readFile(new URL('../apps/research-ui/traffic_view.js', import.meta.url), 'utf8') +
  await readFile(new URL('../apps/research-ui/traffic_filter.js', import.meta.url), 'utf8') +
  await readFile(new URL('../apps/research-ui/traffic_index.js', import.meta.url), 'utf8');
const part = (source, first, last) => {
  const start = source.indexOf(first), end = source.indexOf(last, start);
  assert(start >= 0 && end > start, `Missing production boundary: ${first}`);
  return source.slice(start, end);
};

function fixture(appSource = app, trafficSource = traffic, count = 5000, extra = {}) {
  const stats = {};
  const clearStats = () => {
    for (const name of ['created', 'geometryReads', 'scrollWrites', 'attributeWrites', 'moves', 'searches', 'sorts', 'scopes', 'inspector', 'profiles', 'history']) stats[name] = 0;
  };
  clearStats();
  class Node {
    constructor(tag = 'div') {
      this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = new Map(); this.style = {};
      this.listeners = new Map(); this.className = ''; this.textContent = ''; this.tabIndex = -1;
      this._scrollTop = 0; this.scrollLeft = 0; this.value = ''; this.hidden = false;
      this.classList = {
        contains: value => this.className.split(' ').includes(value),
        add: value => { if (!this.classList.contains(value)) this.className += ' ' + value; },
        remove: value => { this.className = this.className.split(' ').filter(item => item !== value).join(' '); },
        toggle: (value, enabled) => enabled ? this.classList.add(value) : this.classList.remove(value)
      };
    }
    get scrollTop() { return this._scrollTop; }
    set scrollTop(value) { stats.scrollWrites++; this._scrollTop = value; }
    get offsetTop() { stats.geometryReads++; return (this.parent?.children.indexOf(this) ?? 0) * 24; }
    get offsetHeight() { stats.geometryReads++; return 24; }
    get lastElementChild() { return this.children.at(-1); }
    setAttribute(key, value) { stats.attributeWrites++; this.attributes.set(key, String(value)); }
    getAttribute(key) { return this.attributes.get(key) ?? null; }
    removeAttribute(key) { this.attributes.delete(key); }
    addEventListener(key, callback) { this.listeners.set(key, callback); }
    append(...nodes) { for (const node of nodes) this.insertBefore(node, null); }
    replaceChildren(...nodes) { for (const node of [...this.children]) node.remove(); this.append(...nodes); }
    insertBefore(node, before) {
      stats.moves++; node.remove(); const index = before ? this.children.indexOf(before) : this.children.length;
      assert(index >= 0); this.children.splice(index, 0, node); node.parent = this;
    }
    remove() {
      if (!this.parent) return;
      if (this.contains(document.activeElement)) document.activeElement = null;
      this.parent.children.splice(this.parent.children.indexOf(this), 1); this.parent = null;
    }
    contains(node) { for (let current = node; current; current = current.parent) if (current === this) return true; return false; }
    querySelectorAll(selector) {
      const result = [];
      for (const child of this.children) {
        if (selector.startsWith('.') && child.classList.contains(selector.slice(1))) result.push(child);
        result.push(...child.querySelectorAll(selector));
      }
      return result;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
    focus() { document.activeElement = this; }
    scrollIntoView() { /* Deliberate keyboard scrolling is outside the render path. */ }
    click() { this.listeners.get('click')?.({currentTarget: this}); }
  }
  const nodes = new Map();
  const document = {
    activeElement: null,
    createElement: tag => { stats.created++; return new Node(tag); },
    querySelector: selector => { if (!nodes.has(selector)) nodes.set(selector, new Node()); return nodes.get(selector); },
    querySelectorAll: () => []
  };
  const elements = Object.fromEntries(['requestTabScopes', 'requestDomain', 'requestFilter', 'requestRows', 'requestLatest', 'selectedMethod', 'selectedStatus', 'selectedUrl',
    'requestCopyUrl', 'prompt'].map(name => [name, new Node()]));
  // A 20-row view: 20 rows plus 8 of overscan mount at the top of the list.
  elements.requestRows.clientHeight = 480; elements.requestRows.dataset.rowHeight = '24';
  const requests = Array.from({length: count}, (_, index) => ({id: `request-${index}`,
    method: index % 3 ? 'GET' : 'POST', path: `https://fixture-${index % 8}.invalid/item-${String(index).padStart(5, '0')}`,
    status: 200, time: index / 10, type: 'xhr', origin: 'demo', tabId: String(index % 8),
    firstTimestamp: BigInt(index), operation: 'authored_fixture', events: []}));
  const state = {requests, nativeRequests: requests, selectedRequestId: null, requestTabId: 'all', requestDomain: 'all', requestType: 'all',
    trafficSort: 'name', trafficSortDirection: 1, trafficWindowStart: 0, trafficWindowAnchor: null,
    trafficNewIds: new Set(), trafficKnownIds: null, originTraceGeneration: 0, signalProfileGeneration: 0,
    sessionMode: 'demo', trafficLoaded: new Map(), trafficLoadController: null, trafficLoadingId: null,
    trafficFlags: {}, trafficRange: null, trafficIndex: undefined, trafficIndexEpoch: null};
  // Native rows carry no bodies; search covers URL, method and status only.
  elements.requestFilter.value = 'fixture-1.invalid';
  const context = {state, elements, document, URL, URLSearchParams, AbortController, AbortSignal, TextDecoder, TextEncoder, Uint8Array, stats,
    matchMedia: () => ({matches: true}), fieldSets: {body: []},
    renderRequestCount() {}, renderEvidence() {},
    resetRequestSelection: () => { state.selectedRequestId = null; },
    renderInspector: () => { stats.inspector++; },
    investigationBeforeSelection: () => { stats.history++; },
    refreshRequestSignalProfile: () => { stats.profiles++; },
    investigationSame: (left, right) => left === right,
    investigationRequestIdentity: request => request.id,
    investigationNotice: text => { state.notice = text; },
    requestsFromEvents: (events, origin) => {
      const id = events[0]?.request_id;
      return id === undefined ? [] : [{id: `request-${id}`, method: 'GET', path: `https://fixture.invalid/item-${id}`, status: 200, time: 1,
        type: 'xhr', origin, tabId: '1', firstTimestamp: 1n, operation: 'authored_fixture', events, details: []}];
    },
    setImmediate, ...extra};
  const instrument = `
    const search = trafficSearchRequests;
    trafficSearchRequests = (...args) => { stats.searches++; return search(...args); };
    const sort = trafficSortedRequests;
    trafficSortedRequests = (...args) => { stats.sorts++; return sort(...args); };
    const scopes = renderRequestScopes;
    renderRequestScopes = (...args) => { stats.scopes++; return scopes(...args); };
  `;
  const added = ['selectTrafficRow', 'loadTrafficRequest', 'rebuildTrafficRequests', 'renderIndexedRequests', 'trafficIndexActive', 'createTrafficIndex',
    'trafficIndexChanged', 'trafficIndexUnchecked', 'trafficIndexRequest'];
  const rebuild = appSource.includes('      function rebuildTrafficRequests(') ? part(appSource, '      function rebuildTrafficRequests(', '      function renderShellStatus(') : '';
  const api = runInNewContext(trafficSource + '\n' +
    part(appSource, '      function requestDomain(', '      function requestTraceRoot(') + rebuild + instrument +
    `;({renderRequests, selectRequest, moveRequestSelection, remountTrafficRows, renderTrafficBudget: typeof renderTrafficBudget === 'function' ? renderTrafficBudget : undefined, ${added.map(name => `${name}: typeof ${name} === 'function' ? ${name} : undefined`).join(', ')}})`, context);
  const rows = () => elements.requestRows.querySelectorAll('.request-row');
  return {state, elements, document, stats, clearStats, api, rows, nodes, context};
}

{
  const t = fixture(); t.api.renderRequests();
  assert.equal(t.rows().length, 28, 'only the rows in view and the overscan are mounted');
  assert.equal(t.state.trafficSearchMatches.size, 625);
  assert.deepEqual([t.rows()[0].getAttribute('aria-posinset'), t.rows()[0].getAttribute('aria-setsize')], ['1', '625']);
  assert.equal(t.elements.requestRows.children.at(-1).className, 'request-spacer', 'a spacer stands for the unmounted rows');
  // Scrolling within the overscan mounts nothing; past it, the read block remounts without filtering or sorting again.
  t.elements.requestRows.scrollTop = 4 * 24; t.clearStats(); t.api.remountTrafficRows(t.elements.requestRows);
  assert.equal(t.stats.moves, 0);
  t.elements.requestRows.scrollTop = 30 * 24; t.api.remountTrafficRows(t.elements.requestRows);
  assert.deepEqual([Number(t.rows()[0].dataset.position), Number(t.rows().at(-1).dataset.position)], [22, 57]);
  assert.equal(t.stats.searches + t.stats.sorts, 0);
  t.elements.requestRows.scrollTop = 0; t.api.remountTrafficRows(t.elements.requestRows);
  const first = t.rows()[20], next = t.rows()[21], firstChildren = [...first.children];
  first.focus(); t.elements.requestRows.scrollTop = 360; t.elements.requestRows.scrollLeft = 11;
  t.clearStats(); first.click();
  assert.equal(t.state.selectedRequestId, first.dataset.requestId);
  assert.equal(t.document.activeElement, first); assert.deepEqual(first.children, firstChildren);
  assert.equal(t.elements.requestRows.scrollTop, 360); assert.equal(t.elements.requestRows.scrollLeft, 11);
  assert.equal(first.getAttribute('aria-selected'), 'true'); assert.equal(first.tabIndex, 0);
  assert.equal(t.state.inspectorTab, undefined, 'Selection does not switch inspector tabs');
  assert.equal(t.stats.searches, 0); assert.equal(t.stats.sorts, 0); assert.equal(t.stats.scopes, 0);
  assert.equal(t.stats.created, 0); assert.equal(t.stats.geometryReads, 0);
  assert.equal(t.stats.scrollWrites, 0); assert.equal(t.stats.moves, 0);
  assert.equal(t.stats.inspector, 1); assert.equal(t.stats.profiles, 1); assert.equal(t.stats.history, 1);
  let prevented = false;
  t.api.moveRequestSelection({key: 'ArrowDown', currentTarget: first, preventDefault() { prevented = true; }});
  assert(prevented); assert.equal(t.document.activeElement, next); assert.equal(t.state.selectedRequestId, next.dataset.requestId);
  assert.equal(first.getAttribute('aria-selected'), 'false'); assert.equal(first.tabIndex, -1);
  assert.equal(next.getAttribute('aria-selected'), 'true'); assert.equal(next.tabIndex, 0);
  assert.equal(t.rows().filter(row => row.tabIndex === 0).length, 1);
  const position = () => Number(t.document.activeElement.dataset.position);
  for (const key of ['Home', 'ArrowDown', 'ArrowUp']) {
    const current = t.document.activeElement;
    t.api.moveRequestSelection({key, currentTarget: current, preventDefault() {}});
    assert.equal(t.document.activeElement.dataset.requestId, t.state.selectedRequestId);
  }
  assert.equal(position(), 0);
  assert.equal(t.stats.searches, 0, 'Repeated navigation does not repeat the filter scan');
  // End and Home reach the whole list, not the mounted block, which moves once to hold the row.
  t.api.moveRequestSelection({key: 'End', currentTarget: t.document.activeElement, preventDefault() {}});
  assert.equal(t.document.activeElement.dataset.requestId, t.state.selectedRequestId);
  assert.equal(position(), t.state.trafficSearchMatches.size - 1);
  assert.equal(t.stats.searches, 1);
  t.api.moveRequestSelection({key: 'ArrowDown', currentTarget: t.document.activeElement, preventDefault() {}});
  assert.equal(position(), t.state.trafficSearchMatches.size - 1, 'ArrowDown stops at the last request');
  t.api.moveRequestSelection({key: 'Home', currentTarget: t.document.activeElement, preventDefault() {}});
  assert.equal(t.document.activeElement.dataset.requestId, t.state.selectedRequestId);
  assert.equal(position(), 0);
  // A focused row scrolled out of the mounted rows leaves focus on the list, and takes it back once mounted again.
  t.document.activeElement = t.rows()[20];
  const focusedId = t.document.activeElement.dataset.requestId;
  t.elements.requestRows.scrollTop = 450 * 24;
  t.api.renderRequests();
  assert(t.state.trafficRenderedView.start > 20);
  assert.equal(t.document.activeElement, t.elements.requestRows);
  assert.deepEqual([Number(t.rows()[0].dataset.position), t.rows().length], [450 - 8, 20 + 16]);
  // The selected row is outside the read block, so the list continues from the first row in view.
  t.api.moveRequestSelection({key: 'ArrowDown', currentTarget: t.elements.requestRows, preventDefault() {}});
  assert.equal(position(), 451);
  t.elements.requestRows.scrollTop = 450 * 24;
  t.api.renderRequests();
  t.document.activeElement = t.elements.requestRows;
  t.elements.requestRows.dataset.focusId = focusedId;
  t.elements.requestRows.scrollTop = 0;
  t.api.renderRequests();
  assert.equal(t.document.activeElement.dataset.requestId, focusedId);
  const offPage = [...t.state.trafficSearchMatches.keys()].find(id => !t.rows().some(row => row.dataset.requestId === id));
  t.api.selectRequest(offPage);
  assert.doesNotMatch(t.nodes.get('#request-window-status').textContent, /Selection outside filter/,
    'A matching request on another page is not a filtered-out request');
  assert.equal(t.rows()[0].tabIndex, 0);
  const outside = t.state.requests[0].id;
  t.api.selectRequest(outside);
  assert.match(t.nodes.get('#request-window-status').textContent, /Selection outside filter/);
  assert.equal(t.rows()[0].tabIndex, 0, 'Off-page/filter selection keeps a reachable row');
  assert.equal(t.rows().filter(row => row.getAttribute('aria-selected') === 'true').length, 0);
  assert.equal(t.state.selectedRequestId, outside, 'Filtering must not discard retained selection');
  const before = t.state.selectedRequestId;
  assert.equal(t.api.selectRequest(t.rows()[0].dataset.requestId, 'different-identity'), false);
  assert.equal(t.state.selectedRequestId, before, 'Exact identity refusal still precedes selection');
}

// The request index path: a real createTrafficIndex over scripted answers, the
// production selection and load functions, and the shared row renderer.
function indexFixture({windowCount = 6, holdIndex = false} = {}) {
  const t = fixture(app, traffic, windowCount, {renderNetworkNotice() {}});
  const {state, api} = t;
  state.sessionMode = 'live'; state.requests.forEach(row => { row.origin = 'live'; }); state.nativeRequests = state.requests;
  state.trafficDetailOpen = false; state.trafficAppliedAnswer = null; state.trafficSeenThrough = null;
  const row = (index, records) => ({id: `request-${index}`, path: `https://fixture.invalid/item-${index}`, method: 'GET', status: 200, time: 1,
    type: 'xhr', target_kind: 'url', failed: false, interrupted: false, tab_id: '1', tab_ids: ['1'], extension_id: null, operation: 'authored_fixture',
    tab_link: null, initiator_frame: null, target: `/item-${index}`, host: 'fixture.invalid', url_truncated: false, target_length: 0, target_malformed: false,
    first_time_ns: String(index + 1), last_time_ns: String(index + 2), transfer_size: 1, resource_size: 1, from_cache: false, from_service_worker: false,
    mime_type: null, protocol: null, response_time_ns: null, error_code: 0, loader_observed: true, initiator: 'browser', main_frame: false,
    browser_internal: false, ordinal: index, records, members: [{session_id: '1', process_id: 7, request_id: String(index + 1), records}],
    first_offset: String(index * 100), end_offset: String((index + 1) * 100), root: null});
  const document_ = rows => ({format: 'reb-request-index-v1', requests: rows, matching: rows.length, total: rows.length, through: rows.length, added: 0,
    index: {epoch: 'epoch-1', complete: true, store_end: '10', indexed_end: '10', unindexed_records: '0', malformed_records: '0', request_limit: 100000},
    sizes: {transferred: 0, resources: 0}, hidden_internal: 0, located: {}, facets: {tabs: [{tab_id: '1', count: rows.length, domains: ['fixture.invalid']}], domains: [{domain: 'fixture.invalid', count: rows.length}]},
    timeline: {first_time_ns: '1', last_time_ns: '9', buckets: []}});
  const pending = [], reads = [];
  const held = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; };
  const answer = body => new Response(JSON.stringify(body), {headers: {ETag: '"a"'}});
  let indexRows = [];
  // A held index read answers only when released, on a later macrotask, as a
  // backend busy with other reads would answer after the event poll.
  const indexGates = [];
  const indexAnswer = () => new Promise(resolve => setImmediate(() => resolve(answer(document_(indexRows)))));
  // The production handler when app.js has one (it is wired to the index below).
  const onChange = () => typeof api.trafficIndexChanged === 'function' ? api.trafficIndexChanged() : api.renderRequests();
  state.trafficIndex = api.createTrafficIndex({onChange, fetcher: async (url, init) => {
    reads.push(url);
    if (url.startsWith('/api/requests?')) {
      if (!holdIndex) return answer(document_(indexRows));
      const gate = held();
      indexGates.push(gate);
      return gate.promise.then(indexAnswer);
    }
    const gate = held();
    pending.push({url, signal: init.signal, gate});
    return gate.promise;
  }});
  const releaseIndex = () => { for (const gate of indexGates.splice(0)) gate.resolve(); };
  return {...t, row, setIndexRows: rows => { indexRows = rows; }, pending, reads, answer, releaseIndex, indexGates};
}
const quiet = async () => { for (let turn = 0; turn < 8; turn++) await new Promise(resolve => setImmediate(resolve)); };
const eventsOf = (id, records) => Array.from({length: records}, (_, sequence) => ({session_id: '1', process_id: 7, sequence_number: String(sequence + 1), monotonic_time_ns: String(sequence + 1), request_id: id}));

{
  // Before the first index answer the newest window's rows serve, and the first read starts.
  const t = indexFixture();
  t.setIndexRows([]);
  t.api.renderRequests();
  assert(t.state.trafficIndex.answer() === null && t.rows().length > 0, 'Window rows serve while the index has not answered');
  assert.match(t.nodes.get('#request-window-status').textContent, /newest window/);
  assert(t.reads.some(url => url.startsWith('/api/requests?')), 'The window path starts the first index read');
}
{
  // H1: a store read for row A does not retake the selection after row B was chosen.
  const t = indexFixture({windowCount: 2});
  t.state.requests = t.state.nativeRequests = t.state.nativeRequests.map(request => ({...request, events: [{}, {}], details: [], origin: 'live'}));
  const whole = t.state.requests[1], partial = t.row(5, 9);
  t.setIndexRows([t.row(1, 2), partial, t.row(0, 2)]);
  t.api.renderRequests(); await quiet();
  assert.equal(t.state.trafficIndex.row('request-5').indexRow.records, 9);
  t.api.selectTrafficRow('request-5');
  await quiet();
  assert.equal(t.state.trafficLoadingId, 'request-5', 'A row the window does not hold whole is read from the store');
  assert.equal(t.pending.length, 1, 'One read of the store is in flight');
  const signal = t.pending[0].signal;
  t.api.selectTrafficRow(whole.id);
  assert.equal(t.state.selectedRequestId, whole.id, 'A row retained whole selects immediately');
  assert(signal.aborted, 'Choosing another row aborts the in-flight store read');
  assert.equal(t.state.trafficLoadController, null);
  t.pending[0].gate.resolve(t.answer({events: eventsOf('5', 3), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  assert.equal(t.state.selectedRequestId, whole.id, 'A late store answer does not select the older row');
  assert(!t.state.requests.some(request => request.id === 'request-5'), 'A cancelled read adds no row');
}
{
  // A store read that completes still selects its own row.
  const t = indexFixture({windowCount: 1});
  t.setIndexRows([t.row(5, 2)]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow('request-5');
  await quiet();
  t.pending[0].gate.resolve(t.answer({events: eventsOf('5', 2), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  assert.equal(t.state.selectedRequestId, 'request-5', 'A completed read selects its own row');
  assert.equal(t.state.trafficLoadingId, null);
  assert(t.state.trafficLoaded.has('request-5'), 'The store copy stays for the selection');
  assert.equal(t.document.activeElement?.dataset?.requestId, 'request-5', 'With focus on nothing, the row takes focus');
}
{
  // A service_worker_end_lost gap has no request ID, so the row's store read
  // lacks it; the selected copy keeps End lost from the index row.
  const t = indexFixture({windowCount: 1});
  t.setIndexRows([{...t.row(5, 2), end_lost: true}]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow('request-5');
  await quiet();
  t.pending[0].gate.resolve(t.answer({events: eventsOf('5', 2), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  assert.equal(t.state.trafficLoaded.get('request-5').endLost, true, 'The store copy keeps the index row\'s End lost');
}
{
  // The row a reuse names, with its body, lives only in the index row: the
  // store copy, a row the window holds whole and a later poll all keep it.
  const source = {id: 'S1:R9:41', found: true, path: '/sprite', type: 'img', response_body: {case: 'captured', artifact_id: '7'}};
  const t = indexFixture({windowCount: 1});
  t.setIndexRows([{...t.row(5, 2), memory_cache_source: source, response_body: {case: 'memory_cache'}}]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow('request-5');
  await quiet();
  t.pending[0].gate.resolve(t.answer({events: eventsOf('5', 2), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  assert.deepEqual(t.state.trafficLoaded.get('request-5').memoryCacheSourceRow, source, 'The store copy keeps the reuse\'s source');
  const w = indexFixture({windowCount: 2});
  w.state.requests = w.state.nativeRequests = w.state.nativeRequests.map(request =>
    ({...request, events: [{}, {}], details: [], origin: 'live', rank: 2, status: 'pending'}));
  const whole = w.state.requests[1];
  w.setIndexRows([{...w.row(1, 2), memory_cache_source: source}, {...w.row(0, 2), response_body: {case: 'captured', artifact_id: '9'}}]);
  w.api.renderRequests(); await quiet();
  w.api.selectTrafficRow(whole.id);
  const held = () => w.state.requests.find(request => request.id === whole.id);
  assert.deepEqual(held().memoryCacheSourceRow, source, 'A row the window holds whole keeps the reuse\'s source');
  w.state.nativeRequests = w.state.nativeRequests.map(request => ({...request, memoryCacheSourceRow: null}));
  w.api.rebuildTrafficRequests();
  assert.deepEqual(held().memoryCacheSourceRow, source, 'A later poll keeps the reuse\'s source');
  // Every window row takes its row's body answer: its response_started may have left the window.
  const other = w.state.requests.find(request => request.id !== whole.id);
  assert.equal(other.responseBodyIndex?.case, 'captured', 'A window row without a reuse source keeps its index body answer');
}
{
  // The window can hold the row whole and still lack the gap: selecting it, and
  // the rebuild after a later poll, keep End lost from the index row.
  const t = indexFixture({windowCount: 2});
  t.state.requests = t.state.nativeRequests = t.state.nativeRequests.map(request =>
    ({...request, events: [{}, {}], details: [], origin: 'live', rank: 2, status: 'pending'}));
  const whole = t.state.requests[1];
  t.setIndexRows([{...t.row(1, 2), end_lost: true}, t.row(0, 2)]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow(whole.id);
  assert.equal(t.state.selectedRequestId, whole.id, 'A row the window holds whole selects without a store read');
  const shown = () => t.state.requests.find(request => request.id === whole.id);
  assert.deepEqual([shown().endLost, shown().status], [true, 'incomplete'], 'The selected window row reads End lost');
  t.state.nativeRequests = t.state.nativeRequests.map(request => ({...request, endLost: false, status: 'pending'}));
  t.api.rebuildTrafficRequests();
  assert.deepEqual([shown().endLost, shown().status], [true, 'incomplete'], 'A later poll keeps End lost');
  assert.equal(t.state.requests.find(request => request.id !== whole.id).endLost, false, 'Only the named row is marked');
}
// The index's own answer reaches the selected row: the app wires its handler.
assert.match(app, /createTrafficIndex\(\{onChange: trafficIndexChanged\}\)/, 'The request index reports its answers to trafficIndexChanged');
const pendingWindow = t => {
  t.state.requests = t.state.nativeRequests = t.state.nativeRequests.map(request =>
    ({...request, events: [{}, {}], details: [], origin: 'live', rank: 2, status: 'pending', endLost: false}));
  return t.state.requests[1];
};
{
  // The newest window keeps no gap records (event_window.rs), so it cannot see
  // a service_worker_end_lost gap. A row chosen before the index first answers
  // reads Pending, not yet checked against the index; when the index answers,
  // the selected copy, the strip and the inspector read End lost with the
  // table, with no poll and no second click (rendered test29).
  const t = indexFixture({windowCount: 2, holdIndex: true});
  const lost = pendingWindow(t);
  t.setIndexRows([{...t.row(1, 2), end_lost: true, response_body: {case: 'end_lost'}}, t.row(0, 2)]);
  t.api.renderRequests(); await quiet();
  assert(t.state.trafficIndex.answer() === null && t.indexGates.length === 1, 'The first index read is still outstanding');
  t.rows().find(row => row.dataset.requestId === lost.id).click();
  const shown = () => t.state.requests.find(request => request.id === lost.id);
  assert.equal(t.state.selectedRequestId, lost.id, 'A window row selects while the index has not answered');
  assert.equal(t.elements.selectedStatus.textContent, 'pending', 'Before the index answers, the window says Pending');
  assert.equal(t.api.trafficIndexUnchecked?.(shown()), true, 'and that Pending is not yet checked against the index');
  const drawn = t.stats.inspector;
  t.releaseIndex(); await quiet();
  assert(t.state.trafficIndex.answer() !== null, 'The index answered');
  assert.equal(t.rows().find(row => row.dataset.requestId === lost.id)?.getAttribute('aria-label')?.includes('End lost'), true,
    'The table reads End lost from the index row');
  assert.deepEqual([shown().endLost, shown().status], [true, 'incomplete'], 'The selected copy reads End lost once the index answers');
  assert.equal(shown().responseBodyIndex?.case, 'end_lost', 'and takes its body answer');
  assert.equal(t.elements.selectedStatus.textContent, 'end lost', 'The strip follows the index answer');
  assert(t.stats.inspector > drawn, 'The inspector is drawn again from the index answer');
  assert.equal(t.api.trafficIndexUnchecked(shown()), false, 'The row is checked against the index');
  assert.equal(t.state.requests.find(request => request.id !== lost.id).endLost, false, 'Only the named row is marked');
  // A later answer that changes nothing for the selection draws nothing again.
  const settled = t.stats.inspector;
  t.state.trafficIndex.invalidate(); await quiet();
  assert.equal(t.stats.inspector, settled, 'An unchanged answer does not redraw the inspector');
}
{
  // A watch match's rule is an index row fact too: a later index answer that
  // changes only it reaches the selected row and draws the inspector again.
  const t = indexFixture({windowCount: 2, holdIndex: true});
  const watched = pendingWindow(t);
  t.setIndexRows([t.row(1, 2), t.row(0, 2)]);
  t.api.renderRequests(); await quiet();
  t.rows().find(row => row.dataset.requestId === watched.id).click();
  t.releaseIndex(); await quiet();
  const shown = () => t.state.requests.find(request => request.id === watched.id);
  assert.equal(shown().watch ?? null, null, 'The first answer names no watch');
  const drawn = t.stats.inspector;
  t.setIndexRows([{...t.row(1, 2), watch: {session_id: '1', process_id: 7, sequence_number: '3', frame_id: '9', rule: 2, method_matched: true}}, t.row(0, 2)]);
  t.state.trafficIndex.invalidate(); await quiet();
  t.releaseIndex(); await quiet();
  assert.equal(shown().watch?.rule, 2, 'The selected copy takes the later answer\'s watch');
  assert(t.stats.inspector > drawn, 'The inspector is drawn again for it');
}
{
  // Rows are reused by request ID, so a row first drawn from the newest window
  // keeps its element when the index answers. A click on it afterwards selects
  // through the index, as a row first drawn from the index does: a row the
  // window does not hold whole is read from the store before it opens.
  const t = indexFixture({windowCount: 2, holdIndex: true});
  const partial = pendingWindow(t);
  t.setIndexRows([{...t.row(1, 9), end_lost: true}, t.row(0, 2)]);
  t.api.renderRequests(); await quiet();
  const element = t.rows().find(row => row.dataset.requestId === partial.id);
  t.releaseIndex(); await quiet();
  assert.equal(t.rows().find(row => row.dataset.requestId === partial.id), element, 'The index answer reuses the window row\'s element');
  element.click();
  assert.equal(t.state.trafficLoadingId, partial.id, 'The reused row selects through the index: its records are read from the store');
  assert.equal(t.state.selectedRequestId, null, 'and it opens only once they are read');
}
{
  // A poll rebuilds its rows from the index answer it has, which can predate
  // the gap; the next answer, read because of that poll, names it. The
  // selected row follows that answer without waiting for another poll.
  const t = indexFixture({windowCount: 2});
  const lost = pendingWindow(t);
  t.setIndexRows([t.row(1, 2), t.row(0, 2)]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow(lost.id);
  const shown = () => t.state.requests.find(request => request.id === lost.id);
  assert.deepEqual([shown().endLost, t.elements.selectedStatus.textContent], [false, 'pending'], 'The first answer has no gap');
  assert.equal(t.api.trafficIndexUnchecked?.(shown()), false, 'A row the index answered for is checked');
  t.setIndexRows([{...t.row(1, 2), end_lost: true}, t.row(0, 2)]);
  t.state.trafficIndex.invalidate(); await quiet();
  assert.deepEqual([shown().endLost, shown().status], [true, 'incomplete'], 'The later answer marks the selected row');
  assert.equal(t.elements.selectedStatus.textContent, 'end lost', 'The strip follows the later answer');
}
{
  // A store copy takes its tabs from the index row; a later answer that links
  // the row to more tabs reaches the copy, as it reaches the table.
  const t = indexFixture({windowCount: 1});
  t.setIndexRows([t.row(5, 2)]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow('request-5');
  await quiet();
  t.pending[0].gate.resolve(t.answer({events: eventsOf('5', 2), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  const copy = () => t.state.requests.find(request => request.id === 'request-5');
  assert.deepEqual([...copy().tabIds], ['1'], 'The store copy has the index row\'s tabs');
  const drawn = t.stats.inspector;
  t.setIndexRows([{...t.row(5, 2), tab_ids: ['1', '2'], tab_link: {kind: 2, count: 2, complete: true}}]);
  t.state.trafficIndex.invalidate(); await quiet();
  assert.deepEqual([...copy().tabIds], ['1', '2'], 'The store copy follows the later answer\'s tabs');
  assert.deepEqual({...copy().tabLink}, {kind: 2, count: 2, complete: true}, 'and its tab link');
  assert(t.stats.inspector > drawn, 'The inspector is drawn again for the new tabs');
}
{
  // A watch match's rule comes from the backend's decode beside the record;
  // where none came (the stored-evidence window's own window), the index row
  // names it, on every path that rebuilds the row.
  const watch = {session_id: '1', process_id: 7, sequence_number: '3', frame_id: '9', rule: 2, method_matched: true};
  const shownWatch = {sessionId: '1', processId: 7, sequenceNumber: '3', frameId: '9', rule: 2, methodMatched: true, ruleRead: true};
  const read = indexFixture({windowCount: 1});
  read.setIndexRows([{...read.row(5, 2), watch}]);
  read.api.renderRequests(); await quiet();
  read.api.selectTrafficRow('request-5');
  await quiet();
  read.pending[0].gate.resolve(read.answer({events: eventsOf('5', 2), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  assert.equal(JSON.stringify(read.state.trafficLoaded.get('request-5').watch), JSON.stringify(shownWatch), 'The store copy keeps the index row\'s watch');
  const t = indexFixture({windowCount: 2});
  t.state.requests = t.state.nativeRequests = t.state.nativeRequests.map(request =>
    ({...request, events: [{}, {}], details: [], origin: 'live', watch: null}));
  const whole = t.state.requests[1], other = t.state.requests[0];
  t.setIndexRows([{...t.row(1, 2), watch}, t.row(0, 2)]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow(whole.id);
  assert.equal(t.state.selectedRequestId, whole.id, 'A row the window holds whole selects without a store read');
  const shown = () => t.state.requests.find(request => request.id === whole.id);
  assert.equal(JSON.stringify(shown().watch), JSON.stringify(shownWatch), 'The selected window row is marked watched');
  t.state.nativeRequests = t.state.nativeRequests.map(request => ({...request, watch: null}));
  t.api.rebuildTrafficRequests();
  assert.equal(shown().watch?.rule, 2, 'A later poll keeps the watch mark');
  assert.equal(t.state.requests.find(request => request.id === other.id).watch, null, 'Only the watched row is marked');
  // A row the index answer does not hold (the debugger sidebar locates one
  // outside Traffic's block): no rebuild can restore the mark, so the store
  // read itself must carry it.
  const located = indexFixture({windowCount: 1});
  located.setIndexRows([]);
  located.api.renderRequests(); await quiet();
  located.api.loadTrafficRequest(located.api.trafficIndexRequest({...located.row(9, 2), watch}, 'live'), true);
  await quiet();
  located.pending[0].gate.resolve(located.answer({events: eventsOf('9', 2), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  assert.equal(located.state.trafficIndex.row('request-9'), null, 'the index answer does not hold the row');
  assert.equal(JSON.stringify(located.state.requests.find(request => request.id === 'request-9')?.watch), JSON.stringify(shownWatch),
    'a located row read from the store is marked watched');
  // A window row carries no decode: its match names no rule read here, and the
  // index row's rule replaces it; a record the core refused (read, no rule) stays.
  t.state.nativeRequests = t.state.nativeRequests.map(request => ({...request,
    watch: request.id === whole.id ? {...shownWatch, rule: null, methodMatched: null, ruleRead: false} : null}));
  t.api.rebuildTrafficRequests();
  assert.equal(shown().watch.rule, 2, 'an unread rule takes the index row\'s');
  t.state.nativeRequests = t.state.nativeRequests.map(request => ({...request,
    watch: request.id === whole.id ? {...shownWatch, rule: null, methodMatched: null, ruleRead: true} : null}));
  t.api.rebuildTrafficRequests();
  assert.equal(shown().watch.rule, null, 'a record read and refused keeps no rule');
  // A rule the record's own decode names is never replaced.
  const decoded = {...shownWatch, rule: 4};
  t.state.nativeRequests = t.state.nativeRequests.map(request => ({...request, watch: request.id === whole.id ? decoded : null}));
  t.api.rebuildTrafficRequests();
  assert.equal(shown().watch.rule, 4, 'The record\'s own decode wins');
}
{
  // A store read finishing after the researcher moved to the filter box leaves focus there.
  const t = indexFixture({windowCount: 1});
  t.setIndexRows([t.row(5, 2)]);
  t.api.renderRequests(); await quiet();
  t.api.selectTrafficRow('request-5');
  await quiet();
  t.document.activeElement = t.elements.requestFilter;
  t.pending[0].gate.resolve(t.answer({events: eventsOf('5', 2), query: {limited: false, budget_exhausted: false, next_after: '9'}}));
  await quiet();
  assert.equal(t.state.selectedRequestId, 'request-5', 'The late read still selects its row');
  assert.equal(t.document.activeElement, t.elements.requestFilter, 'The late read does not take focus from the filter box');
}
{
  // H2: a selected row retained whole stays selected once it leaves the newest window.
  const t = indexFixture({windowCount: 3});
  const selected = t.state.requests[0];
  t.state.trafficIndex = undefined;
  t.api.selectRequest(selected.id);
  assert(t.state.trafficLoaded.has(selected.id), 'Selection pins the row');
  t.state.nativeRequests = t.state.nativeRequests.filter(request => request.id !== selected.id);
  t.api.rebuildTrafficRequests();
  assert(t.state.requests.some(request => request.id === selected.id), 'The pinned row survives leaving the window');
  assert.equal(t.state.selectedRequestId, selected.id);
  // The pinned copy follows the window while the window still holds it.
  const newer = {...t.state.requests[1], events: [{}, {}], details: []};
  t.api.selectRequest(newer.id);
  t.state.nativeRequests = t.state.nativeRequests.map(request => request.id === newer.id ? {...newer} : request);
  t.api.rebuildTrafficRequests();
  assert.equal(t.state.trafficLoaded.get(newer.id).events.length, 2, 'A later window copy with as many records replaces the pinned one');
  // F9: without an index answer the list is state.requests itself, so an earlier selection does not stay listed.
  const other = {...t.state.requests[0]};
  t.api.selectRequest(other.id);
  t.state.nativeRequests = t.state.nativeRequests.filter(request => request.id !== other.id && request.id !== newer.id);
  t.api.rebuildTrafficRequests();
  assert(!t.state.requests.some(request => request.id === newer.id), 'A row selected earlier leaves the list once the window left it');
  assert(t.state.requests.some(request => request.id === other.id), 'The current selection stays pinned');
  assert.deepEqual([...t.state.trafficLoaded.keys()], [other.id], 'Only the selection is pinned without an index');
  // At most 32 rows stay, always including the selection.
  for (let index = 0; index < 40; index++) t.state.trafficLoaded.set(`extra-${index}`, {id: `extra-${index}`, events: [], details: []});
  t.api.selectRequest(other.id);
  assert(t.state.trafficLoaded.size <= 32 && t.state.trafficLoaded.has(other.id), 'Pinning stays bounded and keeps the selection');
}
{
  // M1: an empty state drops the block, so a resize cannot remount the old rows.
  const t = fixture(app, traffic, 80);
  t.state.trafficIndex = undefined;
  t.api.renderRequests();
  assert(t.elements.requestRows.trafficBlock, 'Rows mount a block');
  const before = t.rows().length;
  assert(before > 0);
  t.elements.requestFilter.value = 'nothing-matches';
  t.api.renderRequests();
  assert.equal(t.rows().length, 0, 'The filter empties the list');
  t.elements.requestRows.clientHeight = 4000;
  t.api.remountTrafficRows(t.elements.requestRows);
  assert.equal(t.rows().length, 0, 'A resize does not remount rows over the empty state');
  assert.match(t.elements.requestRows.children[0].textContent, /No requests match/);
}
{
  // The index read: pagination, retention of the last answer on failure, unsupported backends and detail paging.
  const urls = [], changes = [];
  const doc = () => ({format: 'reb-request-index-v1', requests: [], matching: 0, total: 0, through: 0, added: 0,
    index: {epoch: 'e', complete: true}, facets: {tabs: [], domains: []}, located: {}, sizes: {transferred: 0, resources: 0}, timeline: {first_time_ns: null, last_time_ns: null, buckets: []}});
  const t = fixture(app, traffic, 1);
  const respond = (status, body) => new Response(body === undefined ? '' : JSON.stringify(body), {status, headers: {ETag: '"v"'}});
  let script = [() => respond(200, doc())];
  const index = t.api.createTrafficIndex({onChange: () => changes.push(index.answer()), fetcher: async (url, init) => {
    urls.push({url, init}); const next = script.shift() ?? (() => { throw new Error('unexpected read'); });
    return next(url, init);
  }});
  index.want({query: 'sort=capture', start: 0, origin: 'live', locate: ['a']});
  await quiet();
  assert(index.answer() && urls[0].url.includes('limit=500') && urls[0].url.includes('locate=a'), 'The first want reads one 500-row page');
  assert.equal(urls[0].init.headers['If-None-Match'], undefined, 'A first read sends no validator');
  script = [() => respond(200, doc())]; index.invalidate(); await quiet();
  assert.match(urls[1].url, /since=0/, 'A refresh names what the last answer covered');
  script = [() => respond(304)]; index.invalidate(); await quiet();
  assert.equal(urls[2].init.headers['If-None-Match'], '"v"', 'A refresh of the same page revalidates');
  assert(index.answer(), 'A 304 keeps the answer');
  script = [() => respond(503)]; index.invalidate(); await quiet();
  assert(index.answer() && /HTTP 503/.test(index.error()), 'A failed read keeps the last answer and states why');
  script = [() => respond(200, {format: 'wrong'})]; index.invalidate(); await quiet();
  assert(index.answer() && /malformed/.test(index.error()), 'A malformed answer keeps the last answer');
  const beforeRetry = urls.length;
  script = [() => respond(503)]; index.retry(); await quiet();
  assert.equal(urls.length, beforeRetry + 1, 'A poll retries a failed read once and no more');
  script = [() => respond(200, doc())]; index.retry(); await quiet();
  assert.equal(index.error(), null, 'A retried read that answers clears the failure');
  script = []; index.retry(); await quiet();
  assert.equal(urls.length, beforeRetry + 2, 'A poll retries nothing when no read failed');
  script = [() => respond(404)]; index.invalidate(); await quiet();
  assert(/HTTP 404/.test(index.error()));
  script = []; index.invalidate(); await quiet();
  assert.equal(urls.length, 8, 'A workspace without the index is not asked again');
  // Detail paging stops at the row's end, and a malformed page fails the read.
  const detailReads = [];
  const page = (events, next, limited) => respond(200, {events, query: {next_after: next, limited, budget_exhausted: false}});
  const details = t.api.createTrafficIndex({fetcher: async url => {
    detailReads.push(url); return detailReads.length === 1 ? page(eventsOf('1', 200), '50', true) : page(eventsOf('1', 200).map((event, i) => ({...event, sequence_number: String(i + 201)})), '60', false);
  }});
  const row = {first_offset: '10', end_offset: '100', members: [{session_id: '1', process_id: 7, request_id: '1', records: 400}]};
  const {events, partial} = await details.events(row, new AbortController().signal);
  assert.equal(events.length, 400, 'Every page of a member is read');
  assert.equal(partial, false, 'A complete read is not partial');
  assert.match(detailReads[1], /after=50/);
  // Absence after a partial read is unknown: a limited member list, the page cap, a damaged line, a short read.
  const readWith = async (pages, rowOverride = {}) => {
    let calls = 0;
    const reader = t.api.createTrafficIndex({fetcher: async () => respond(200, pages[Math.min(calls++, pages.length - 1)])});
    return reader.events({first_offset: '0', end_offset: '1000000', members: [{session_id: '1', process_id: 7, request_id: '1', records: 400}], ...rowOverride}, new AbortController().signal);
  };
  const part = (query, count = 200) => ({events: eventsOf('1', count).map((event, i) => ({...event, sequence_number: String(i + calls())})), query});
  let serial = 1000; function calls() { serial += 1000; return serial; }
  assert.equal((await readWith([part({next_after: '1', limited: false, budget_exhausted: false}, 400)], {members_limited: true})).partial, true, 'A row with unlisted members is partial');
  const full = {next_after: '2', limited: true, budget_exhausted: false};
  const capped = await readWith(Array.from({length: 17}, () => part(full, 20)));
  assert.equal(capped.partial, true, 'Stopping at the page cap with records unread is partial');
  assert.equal((await readWith([part({next_after: '1', limited: false, budget_exhausted: false, malformed_lines: 1}, 400)])).partial, true, 'A damaged line is partial');
  assert.equal((await readWith([part({next_after: '1', limited: false, budget_exhausted: false}, 300)])).partial, true, 'Fewer records than indexed is partial');
  const broken = t.api.createTrafficIndex({fetcher: async () => respond(200, {events: 'no'})});
  await assert.rejects(broken.events(row, new AbortController().signal), /malformed/);
}
console.log('PASS Traffic request index: a stale store read cannot override a newer selection, a selected row outlives the newest window within a bound, an empty state keeps old rows out, window rows serve until the first answer, the index pages, revalidates, keeps its last answer and stops asking a workspace without it (controller/DOM model, not rendered UI)');

// Any snapshot/filter/window change requires normal full rendering. Ordinary
// renderRequests() also always sees in-place authored test mutations.
for (const change of [
  t => { t.state.requests = [...t.state.requests]; },
  t => { t.state.requests.push({...t.state.requests[0], id: 'authored-arrival'}); },
  t => { t.elements.requestFilter.value = '/item-'; },
  t => { t.state.requestTabId = '1'; },
  t => { t.state.requestDomain = 'fixture-1.invalid'; },
  t => { t.state.requestType = 'other'; },
  t => { t.state.trafficSort = 'capture'; },
  t => { t.state.trafficSortDirection = -1; },
  t => { t.state.trafficWindowStart = 500; t.state.trafficWindowAnchor = null; }
]) {
  const t = fixture(); t.api.renderRequests(); const id = t.rows()[0].dataset.requestId;
  change(t); t.clearStats(); t.api.selectRequest(id);
  assert.equal(t.stats.searches, 1); assert.equal(t.stats.scopes, 1);
}
{
  const t = fixture(); t.api.renderRequests(); const id = t.rows()[0].dataset.requestId;
  t.state.requests.find(row => row.id === id).status = 'failed'; t.clearStats(); t.api.renderRequests();
  assert.equal(t.stats.searches, 1); assert.equal(t.rows().find(row => row.dataset.requestId === id).children[1].textContent, 'failed');
  t.elements.requestFilter.value = 'not-retained'; t.api.renderRequests();
  assert.equal(t.rows().length, 0); t.clearStats(); t.api.selectRequest(id);
  assert.equal(t.stats.searches, 0); assert.equal(t.state.selectedRequestId, id);
  assert.match(t.nodes.get('#request-window-status').textContent, /Selection outside filter/);
  t.elements.requestFilter.value = ''; t.api.renderRequests();
  assert.equal(t.rows().length, 28); assert.equal(t.state.selectedRequestId, id);
  t.state.requests = t.state.requests.filter(row => row.id !== id); t.api.renderRequests();
  assert.equal(t.state.selectedRequestId, null, 'Eviction clears rather than reuses selection');
  t.state.requests = []; t.api.renderRequests(); assert.equal(t.rows().length, 0);
  assert.equal(t.elements.requestRows.children[0].textContent, 'No developer evidence is available.');
}
// Preview/session reset retires the guard before any render can be skipped or
// fail. No DOM paint or garbage-collection timing is needed to prove ownership.
{
  const oldRequests = [{id: 'retired', path: 'authored-prior.invalid'}];
  const state = {requests: oldRequests, selectedRequestId: 'retired', trafficRenderedView: {requests: oldRequests}};
  const noop = () => {};
  const context = {state, elements: {gaps: {}}, evidencePackagePanel: {sync: noop}, passiveSecurityPanel: {sync: noop},
    eventGapLabel: () => '', emptyLocalAnalystWorkspace: () => ({limits: {}}), emptyDecoderEngine: () => ({})};
  for (const name of ['renderShellStatus', 'setNetworkNotice', 'renderEvidence', 'renderDebugger', 'renderSources',
    'renderVmLab', 'renderApiCollection', 'renderLocalAnalyst', 'setToolsNotice', 'renderTools']) context[name] = noop;
  context.renderRequests = () => assert.equal(state.trafficRenderedView, null, 'Preview retires the old snapshot before repaint');
  const api = runInNewContext(part(app, '      function resetRequestSelection()', '      function renderRequestCount(') +
    part(app, '      function setEventConnection(', '      function useStandalonePreview()') +
    part(app, '      function useStandalonePreview()', '      function enableTabKeyboardNavigation(') +
    ';({resetRequestSelection, useStandalonePreview})', context);
  api.resetRequestSelection(); assert.equal(state.trafficRenderedView, null);
  state.trafficRenderedView = {requests: oldRequests};
  api.useStandalonePreview(); assert.equal(state.trafficRenderedView, null); assert.equal(state.requests.length, 0);
}
console.log('PASS Traffic selection reuses rendered search/sort/window; only rows in view plus overscan mount with list positions for assistive technology; no geometry reads, remounts or scroll writes on selection; keyboard across unmounted rows, focus hand-off and return, filters, exact-identity refusal, mutation refresh, partial/empty/evicted selection (controller/DOM model, not rendered UI)');

// The Traffic footer names each used budget. Its counts are the session
// summary's (the whole session), not the loaded rows', which give only a lower
// bound until the summary answers; the size comes from the session context.
// In a live session the figure is exact only while nothing has arrived since
// the summary was read.
{
  const check = (category, reason, count, extra = {}) => ({code: 'request_content_not_retained', category, reason, count: String(count),
    budget_mib: null, retained_bytes: '0', retained_complete: true, ...extra});
  const settle = async () => { for (let turn = 0; turn < 4; turn += 1) await new Promise(resolve => setImmediate(resolve)); };
  const footer = ({summary, context = null, live = false} = {}) => {
    const reads = [];
    const answers = {summary, context};
    let release = null;
    const fetch = async url => {
      reads.push(url);
      if (release) await new Promise(resolve => { const go = release; release = null; go(resolve); });
      const body = url === '/api/session/summary' ? answers.summary : answers.context;
      return {ok: body !== null, json: async () => body};
    };
    const clock = {now: 1_000_000};
    const t = fixture(app, traffic, 40, {fetch, Date: {now: () => clock.now}, renderShellStatus() {}});
    if (live) { t.state.sessionMode = 'live'; t.state.requestContentCaptureEnabled = true; t.state.eventEtag = '"store-1"'; }
    const notice = t.document.querySelector('#request-budget');
    const toggle = t.document.createElement('button'), line = t.document.createElement('span');
    notice.querySelector = selector => ({'#request-budget-toggle': toggle, '#request-budget-text': line})[selector] ?? null;
    notice.dataset.expanded = 'false';
    const api = runInNewContext(`({renderTrafficBudget, refreshSessionContentLimits, toggleTrafficBudget})`, t.context);
    return {t, api, reads, answers, clock, notice, toggle, line, hold: () => { let go; release = resume => { go = resume; }; return () => go(); }};
  };

  // A session that used no budget reads the summary once and shows nothing.
  {
    const quiet = footer({summary: {checks: []}});
    quiet.api.renderTrafficBudget(); await settle();
    assert.deepEqual(quiet.reads, ['/api/session/summary'], 'every session reads the summary once');
    assert.equal(quiet.notice.hidden, true, 'no refusal, no notice');
    quiet.api.renderTrafficBudget(); await settle();
    assert.equal(quiet.reads.length, 1, 'a session with nothing used and no content does not read it again');
  }
  // A stored capture whose refusals are all outside the loaded rows still shows
  // them: nothing arrives in a stored window, so the figure is exact.
  {
    const stored = footer({summary: {checks: [check('response_body', 'not_captured_session_budget', 5)]}});
    stored.api.renderTrafficBudget(); await settle();
    assert.equal(stored.notice.hidden, false);
    assert.equal(stored.line.textContent, 'Response body budget used, 0 KiB kept: 5 response bodies not kept · Raise it in New Live Session… for the next session.');
  }

  // A live content session.
  const f = footer({live: true,
    summary: {checks: [check('response_body', 'not_captured_session_budget', 2400, {retained_bytes: String(511 * 1048576)}),
      check('request_body', 'not_captured_session_budget', 30, {retained_bytes: '1048576', retained_complete: false}),
      check('request_target', 'not_retained_session_budget', 12, {retained_bytes: '1048576', retained_complete: false}),
      check('response_body', 'not_captured_type', 7)]},
    context: {capture_options: {content_limits: {version: 1, request_content_budget_mib: 256, response_body_budget_mib: 512, response_media: false}}}});
  const {t, api, reads, line, toggle, notice, clock} = f;
  // Two response refusals and one request refusal are loaded: a lower bound
  // until the summary answers.
  t.state.requests[3].responseBody = {state: 'not_captured_session_budget'};
  t.state.requests[4].responseBody = {state: 'not_captured_session_budget'};
  t.state.requests[5].body = {state: 'not_captured_session_budget'};
  t.state.requests[7].responseBody = {state: 'captured'};
  const resume = f.hold();
  api.renderTrafficBudget();
  assert.equal(notice.hidden, false);
  assert.equal(line.textContent, 'Request content budget used: at least 1 request body or URL not kept · '
    + 'Response body budget used: at least 2 response bodies not kept · Raise them in New Live Session… for the next session.');
  assert.equal(toggle.textContent, 'Budgets used', 'the stacked layout\'s one-line button');
  // The session context names each budget's size; the summary its whole count,
  // exact while the store is as it was when the summary was read.
  api.refreshSessionContentLimits();
  resume(); await settle();
  assert.deepEqual(reads, ['/api/session/summary', '/api/session/context']);
  assert.equal(line.textContent, 'Request content budget (256 MiB) used, at least 1.0 MiB kept: 42 request bodies or URLs not kept · '
    + 'Response body budget (512 MiB) used, 511.0 MiB kept: 2,400 response bodies not kept · Raise them in New Live Session… for the next session.');
  assert.doesNotMatch(line.textContent, /REB_/);
  api.refreshSessionContentLimits();
  assert.equal(reads.length, 2, 'the context is read once it answers');
  // 50 more bodies are refused and 3 of them load: the store changed since the
  // summary was read, so its figure is a lower bound until the next read.
  t.state.eventEtag = '"store-2"';
  for (const index of [8, 9, 10]) t.state.requests[index].responseBody = {state: 'not_captured_session_budget'};
  api.renderTrafficBudget();
  assert.equal(reads.length, 2, 'within 30 s the summary is not read again');
  assert.match(line.textContent, / · Response body budget \(512 MiB\) used, 511\.0 MiB kept: at least 2,400 response bodies not kept · /,
    'a figure read before the store changed is a lower bound');
  assert.match(line.textContent, /: at least 42 request bodies or URLs not kept · /);
  // The next read is exact again while nothing arrives.
  clock.now += 30_000;
  f.answers.summary = {checks: [check('response_body', 'not_captured_session_budget', 2450, {retained_bytes: String(511 * 1048576)})]};
  api.renderTrafficBudget(); await settle();
  assert.equal(reads.length, 3);
  assert.match(line.textContent, /Response body budget \(512 MiB\) used, 511\.0 MiB kept: 2,450 response bodies not kept · Raise /);
  // A failed re-read keeps the last figure, as a lower bound, even though the
  // store has not changed since.
  clock.now += 30_000;
  f.answers.summary = null;
  api.renderTrafficBudget(); await settle();
  assert.equal(reads.length, 4);
  assert.match(line.textContent, /: at least 2,450 response bodies not kept · /, 'a failed read makes the figure a lower bound');
  // Refusals outside the loaded rows still show, from the summary alone; a
  // bounded summary scan is a lower bound too.
  clock.now += 30_000;
  for (const index of [3, 4, 5, 8, 9, 10]) { t.state.requests[index].responseBody = null; t.state.requests[index].body = null; }
  f.answers.summary = {checks: [check('response_body', 'not_captured_session_budget', 2400, {retained_bytes: String(511 * 1048576)}),
    {code: 'bounded_scope', severity: 'info', message: 'bounded'}]};
  api.renderTrafficBudget(); await settle();
  assert.equal(reads.length, 5);
  assert.equal(line.textContent, 'Response body budget (512 MiB) used, 511.0 MiB kept: at least 2,400 response bodies not kept · '
    + 'Raise it in New Live Session… for the next session.');
  assert.equal(toggle.textContent, 'Response body budget used');
  // The stacked layout's button opens and closes the sentence.
  api.toggleTrafficBudget();
  assert.equal(notice.dataset.expanded, 'true');
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  api.toggleTrafficBudget(false);
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  // A session that is not live or keeps no content has no size.
  const stored = fixture(app, traffic, 40, {fetch: async () => ({ok: true, json: async () => ({capture_options: {content_limits: null}})}),
    renderShellStatus() {}});
  runInNewContext('refreshSessionContentLimits()', stored.context); await settle();
  assert.equal(stored.state.sessionContentLimits, null);
  assert.equal(stored.state.sessionContentLimitsRead, 'answered');
  const odd = fixture(app, traffic, 40, {fetch: async () => ({ok: true, json: async () => ({capture_options: {content_limits:
    {version: 2, request_content_budget_mib: 64, response_body_budget_mib: 128, response_media: true}}})}), renderShellStatus() {}});
  runInNewContext('refreshSessionContentLimits()', odd.context); await settle();
  assert.equal(odd.state.sessionContentLimits, null, 'an unknown version names no size');
}
console.log('PASS Traffic footer budget notice: the summary read once in every session, its whole-session counts, at least the loaded rows\' until it answers, after the live store changed, after a failed read or when its scan was bounded, refusals outside the loaded rows, sizes only from the versioned session context, the bytes kept, the stacked layout\'s button and the start panel control for the next session');

const baseline = process.argv.find(value => value.startsWith('--baseline-ref='))?.slice('--baseline-ref='.length);
if (baseline) {
  const prior = path => execFileSync('git', ['show', `${baseline}:${path}`], {encoding: 'utf8', maxBuffer: 8 * 1024 * 1024});
  function measure(appSource, trafficSource) {
    const t = fixture(appSource, trafficSource); t.api.renderRequests();
    const ids = t.rows().slice(0, 30).map(row => row.dataset.requestId);
    for (let index = 0; index < 5; index++) t.api.selectRequest(ids[index]);
    t.clearStats(); const samples = [];
    for (const id of ids) {
      const start = performance.now(); t.api.selectRequest(id); samples.push(performance.now() - start);
    }
    samples.sort((left, right) => left - right);
    return {selections: ids.length, median_ms: +samples[Math.floor(samples.length / 2)].toFixed(3),
      p95_ms: +samples[Math.floor(samples.length * 0.95)].toFixed(3), work: {...t.stats}};
  }
  console.log(JSON.stringify({kind: 'Node controller/DOM-work benchmark, not rendered browser latency', node: process.version,
    fixture: {retained: 5000, mounted: '20-row view + 8 overscan', search: 'URL / method / status literal', sort: 'name'},
    baseline, before: measure(prior('apps/research-ui/app.js'), prior('apps/research-ui/traffic_view.js')),
    after: measure(app, traffic)}, null, 2));
}
