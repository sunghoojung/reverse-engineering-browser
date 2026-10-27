import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {runInNewContext} from 'node:vm';

// Deterministic production-controller/DOM-work checks, not rendered latency.
// Layout getters below count requests for geometry; they do not simulate a browser.
const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
const traffic = await readFile(new URL('../apps/research-ui/traffic_view.js', import.meta.url), 'utf8');
const part = (source, first, last) => {
  const start = source.indexOf(first), end = source.indexOf(last, start);
  assert(start >= 0 && end > start, `Missing production boundary: ${first}`);
  return source.slice(start, end);
};

function fixture(appSource = app, trafficSource = traffic, count = 5000) {
  const stats = {};
  const clearStats = () => {
    for (const name of ['created', 'geometryReads', 'scrollWrites', 'attributeWrites', 'moves', 'searches', 'sorts', 'scopes', 'bodyReads', 'bodyUnits', 'inspector', 'profiles', 'history']) stats[name] = 0;
  };
  clearStats();
  class Node {
    constructor(tag = 'div') {
      this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = new Map();
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
  const elements = Object.fromEntries(['requestTabScopes', 'requestDomain', 'requestFilter', 'requestSearchScope',
    'requestSearchStatus', 'requestRows', 'requestLatest', 'selectedMethod', 'selectedStatus', 'selectedUrl',
    'requestCopyUrl', 'prompt'].map(name => [name, new Node()]));
  const text = 'Authored fixture padding '.repeat(170) + 'retained-needle';
  const response = () => ({state: 'available', mime: 'text/plain', headers: [['x-authored', 'fixture']],
    get text() { stats.bodyReads++; stats.bodyUnits += text.length; return text; }});
  const requests = Array.from({length: count}, (_, index) => ({id: `request-${index}`,
    method: index % 3 ? 'GET' : 'POST', path: `https://fixture-${index % 8}.invalid/item-${String(index).padStart(5, '0')}`,
    status: 200, time: index / 10, type: 'xhr', origin: 'demo', tabId: String(index % 8),
    firstTimestamp: BigInt(index), operation: 'authored_fixture', events: [],
    exchange: {request: {state: 'empty', headers: []}, response: response()}}));
  const state = {requests, selectedRequestId: null, requestTabId: 'all', requestDomain: 'all', requestType: 'all',
    trafficSort: 'name', trafficSortDirection: 1, trafficWindowStart: 0, trafficWindowAnchor: null,
    trafficNewIds: new Set(), trafficKnownIds: null, originTraceGeneration: 0, signalProfileGeneration: 0,
    sessionMode: 'demo', selectedCaptureIdentity: null};
  elements.requestFilter.value = 'retained-needle'; elements.requestSearchScope.value = 'content';
  const context = {state, elements, document, URL, TextDecoder, TextEncoder, Uint8Array, stats,
    matchMedia: () => ({matches: true}), fieldSets: {body: []},
    renderRequestCount() {}, renderEvidence() {},
    resetRequestSelection: () => { state.selectedRequestId = null; },
    renderInspector: () => { stats.inspector++; },
    investigationBeforeSelection: () => { stats.history++; },
    refreshRequestSignalProfile: () => { stats.profiles++; },
    investigationSame: (left, right) => left === right,
    investigationRequestIdentity: request => request.id,
    investigationNotice: text => { state.notice = text; },
    apiCatalogRequestIdentity: request => request.id};
  const instrument = `
    const search = trafficSearchRequests;
    trafficSearchRequests = (...args) => { stats.searches++; return search(...args); };
    const sort = trafficSortedRequests;
    trafficSortedRequests = (...args) => { stats.sorts++; return sort(...args); };
    const scopes = renderRequestScopes;
    renderRequestScopes = (...args) => { stats.scopes++; return scopes(...args); };
  `;
  const api = runInNewContext(trafficSource + '\n' +
    part(appSource, '      function requestDomain(', '      function requestTraceRoot(') + instrument +
    ';({renderRequests, selectRequest, moveRequestSelection})', context);
  const rows = () => elements.requestRows.querySelectorAll('.request-row');
  return {state, elements, document, stats, clearStats, api, rows, nodes};
}

{
  const t = fixture(); t.api.renderRequests();
  assert.equal(t.rows().length, 500); assert.match(t.elements.requestSearchStatus.textContent, /Partial content search/);
  const first = t.rows()[20], next = t.rows()[21], firstChildren = [...first.children];
  first.focus(); t.elements.requestRows.scrollTop = 360; t.elements.requestRows.scrollLeft = 11;
  t.clearStats(); first.click();
  assert.equal(t.state.selectedRequestId, first.dataset.requestId);
  assert.equal(t.document.activeElement, first); assert.deepEqual(first.children, firstChildren);
  assert.equal(t.elements.requestRows.scrollTop, 360); assert.equal(t.elements.requestRows.scrollLeft, 11);
  assert.equal(first.getAttribute('aria-selected'), 'true'); assert.equal(first.tabIndex, 0);
  assert.equal(t.state.inspectorTab, 'response', 'Content match still opens the exact matching side');
  assert.equal(t.stats.searches, 0); assert.equal(t.stats.sorts, 0); assert.equal(t.stats.scopes, 0);
  assert.equal(t.stats.bodyReads, 0); assert.equal(t.stats.created, 0); assert.equal(t.stats.geometryReads, 0);
  assert.equal(t.stats.scrollWrites, 0); assert.equal(t.stats.moves, 0);
  assert.equal(t.stats.inspector, 1); assert.equal(t.stats.profiles, 1); assert.equal(t.stats.history, 1);
  let prevented = false;
  t.api.moveRequestSelection({key: 'ArrowDown', currentTarget: first, preventDefault() { prevented = true; }});
  assert(prevented); assert.equal(t.document.activeElement, next); assert.equal(t.state.selectedRequestId, next.dataset.requestId);
  assert.equal(first.getAttribute('aria-selected'), 'false'); assert.equal(first.tabIndex, -1);
  assert.equal(next.getAttribute('aria-selected'), 'true'); assert.equal(next.tabIndex, 0);
  assert.equal(t.rows().filter(row => row.tabIndex === 0).length, 1);
  for (const key of ['Home', 'End', 'ArrowUp']) {
    const current = t.document.activeElement;
    t.api.moveRequestSelection({key, currentTarget: current, preventDefault() {}});
    assert.equal(t.document.activeElement.dataset.requestId, t.state.selectedRequestId);
  }
  assert.equal(t.stats.searches, 0, 'Repeated navigation does not repeat a bounded content scan');
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

// Any snapshot/filter/window change requires normal full rendering. Ordinary
// renderRequests() also always sees in-place authored test mutations.
for (const change of [
  t => { t.state.requests = [...t.state.requests]; },
  t => { t.state.requests.push({...t.state.requests[0], id: 'authored-arrival'}); },
  t => { t.elements.requestFilter.value = '/item-'; },
  t => { t.elements.requestSearchScope.value = 'url'; },
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
  assert.equal(t.rows().length, 500); assert.equal(t.state.selectedRequestId, id);
  t.state.requests = t.state.requests.filter(row => row.id !== id); t.api.renderRequests();
  assert.equal(t.state.selectedRequestId, null, 'Eviction clears rather than reuses selection');
  t.state.requests = []; t.api.renderRequests(); assert.equal(t.rows().length, 0);
  assert.equal(t.elements.requestRows.children[0].textContent, 'No developer evidence is available.');
}
// Preview/session reset retires the guard before any render can be skipped or
// fail. No DOM paint or garbage-collection timing is needed to prove ownership.
{
  const oldRequests = [{id: 'retired', exchange: {response: {text: 'authored prior body'}}}];
  const state = {requests: oldRequests, selectedRequestId: 'retired', trafficRenderedView: {requests: oldRequests}};
  const noop = () => {};
  const context = {state, elements: {gaps: {}}, evidencePackagePanel: {sync: noop}, passiveSecurityPanel: {sync: noop},
    eventGapLabel: () => '', emptyLocalAnalystWorkspace: () => ({limits: {}}), emptyDecoderEngine: () => ({})};
  for (const name of ['renderShellStatus', 'setNetworkNotice', 'renderEvidence', 'renderDebugger', 'renderSources',
    'renderVmLab', 'renderApiCollection', 'renderLocalAnalyst', 'setToolsNotice', 'renderTools']) context[name] = noop;
  context.renderRequests = () => assert.equal(state.trafficRenderedView, null, 'Preview retires old bodies before repaint');
  const api = runInNewContext(part(app, '      function resetRequestSelection()', '      function renderRequestCount(') +
    part(app, '      function useStandalonePreview()', '      function enableTabKeyboardNavigation(') +
    ';({resetRequestSelection, useStandalonePreview})', context);
  api.resetRequestSelection(); assert.equal(state.trafficRenderedView, null);
  state.trafficRenderedView = {requests: oldRequests};
  api.useStandalonePreview(); assert.equal(state.trafficRenderedView, null); assert.equal(state.requests.length, 0);
}
console.log('PASS Traffic selection reuses rendered search/sort/window; no content reads, geometry reads, remounts or scroll writes; keyboard, focus, filters, exact-identity refusal, mutation refresh, partial/empty/evicted selection (controller/DOM model, not rendered UI)');

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
    fixture: {retained: 5000, mounted: 500, contentSearch: '8 MiB budget; partial results; literal response-body match', sort: 'name'},
    baseline, before: measure(prior('apps/research-ui/app.js'), prior('apps/research-ui/traffic_view.js')),
    after: measure(app, traffic)}, null, 2));
}
