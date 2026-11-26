#!/usr/bin/env node
// The Backend screen (backend_map.js) against the shipped scripts in an
// offline DOM model with fetch faked: loading, empty, Metadata-only, partial,
// malformed and failed reads, a 304 that keeps the map, a failure that keeps
// the last map, inert captured text, scope groups, declared evidence, the
// Hosts tab with its party filter, declared-only hosts and routes, and
// citations that open their Traffic row. Layout and focus are covered by the
// rendered Backend test in tools/origin-trace-rendered-ui/.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {runInContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const {loadShippedUi} = createRequire(import.meta.url)('./check-native-only-startup.cjs');
const {window, context, asyncErrors, release} = loadShippedUi();
const document = window.document;
const settle = async () => { for (let turn = 0; turn < 8; turn += 1) await nextTurn(); };
const get = name => runInContext(name, context);
const shipped = document.getElementById('screen-backend');
assert(shipped, 'index.html declares the Backend screen');
assert(document.querySelector('.primary-nav .nav-button[data-screen="backend"]'), 'the sidebar lists Backend');
assert.equal(typeof get('createBackendMapPanel'), 'function', 'index.html loads backend_map.js');
// The shipped screen has the app's own panel; this one drives a copy.
const root = shipped.cloneNode(true);
root.id = 'screen-backend-check';
root.hidden = false;
document.body.append(root);

const place = (row, header) => ({row_id: row, request_id: '17', hop: 0, time_ns: '1000', ...(header ? {header} : {})});
const signal = (id, on, hosts, extra = {}) => ({signal_id: id, on, tier: 'vendor', weight: 100, content: false,
  description: `${id} description`, hosts, ...extra});
const technology = (id, name, scope, extra = {}) => ({id, name, category: 'hosting', category_label: 'Hosting and platform',
  confidence: 100, basis: 'direct', strongest_tier: 'vendor', implied_by: [], party: scope === 'site' ? 'first_party' : 'third_party',
  scope, hosts: ['app.test'], details: {}, signals: [], references: [], ...extra});
const host = (name, extra = {}) => ({host: name, site: 'app.test', party: 'first_party', document: false, rows: 1, entries: 1,
  role: 'api', methods: {GET: 1}, statuses: {'2xx': 1}, types: {xhr: 1}, mime_types: {}, protocols: {h2: 1}, addresses: [],
  entries_with_response_headers: 1, technologies: [], api_styles: {json: 1}, cors: {exposed: [], allowed: [], requested: []},
  routes: [], static: {count: 0, prefixes: []}, ...extra});
const coverage = (extra = {}) => ({complete: true, index: {}, rows: 3, entries: 3, unlinked_entries: 0,
  entries_with_response_headers: 3, entries_without_response_headers: 0, entries_with_urls: 3, credential_values_dropped: 1,
  response_bodies_read: 1, response_bodies_binary: 0, response_bodies_not_captured: 2, request_bodies_read: 0,
  captures_refused: 0, declarations: 1, ...extra});
const hostile = '<img src=x onerror="globalThis.pwned=1">';
const map = (extra = {}) => ({
  format: 'reb-backend-map-v1', mode: 'offline-passive', network_requests: 0,
  rule_set: {format: 'reb-backend-signatures-v1', reviewed: '2026-11-25', sha256: 'a'.repeat(64), technologies: 2, signals: 3,
    ranges: {format: 'reb-backend-ip-ranges-v1', retrieved: '2026-11-25', sha256: 'b'.repeat(64), providers: []}},
  first_party: {sites: ['app.test'], from_documents: true},
  technologies: [
    technology('vercel', 'Vercel', 'site', {details: {edge_region: [{value: 'iad1', count: 3}]},
      signals: [signal('vercel.x-vercel-id', 'response_header', [{host: 'app.test', party: 'first_party', declared: false, count: 3,
        first: place('S1:B1', 'X-Vercel-Id'), last: place('S1:B9', 'X-Vercel-Id')}]),
        signal('nextjs.next-version', 'body', [{host: 'app.test', party: 'first_party', declared: false, count: 1,
          first: {artifact_id: '19', sha256: 'c'.repeat(64)}}], {content: true})]}),
    technology('react', 'React', 'site', {basis: 'implied', strongest_tier: null, implied_by: ['vercel'], party: 'implied', hosts: []}),
    technology('pusher', hostile, 'service', {basis: 'declared', confidence: 40, category: 'realtime', category_label: 'Realtime',
      hosts: ['ws.pusher.test'], signals: [signal('pusher.pusher', 'host', [{host: 'ws.pusher.test', party: 'third_party',
        declared: true, count: 1, first: place('S1:B1', 'Content-Security-Policy')}])]}),
    technology('nginx', 'nginx', 'vendor', {category: 'web_server', category_label: 'Web server', hosts: ['js.stripe.test']}),
  ],
  hosts: [
    host('app.test', {document: true, role: 'document', technologies: ['vercel'], cors: {exposed: ['x-total-count'], allowed: [], requested: []},
      routes: [{method: 'GET', template: '/api/users/{int}', count: 2, api_style: 'json', statuses: {'2xx': 2}, mime_types: {},
        query_keys: ['expand'], matched_paths: ['/api/users/[id]'], first: place('S1:B4')}]}),
    host('js.stripe.test', {party: 'third_party', site: 'stripe.test', role: 'static', technologies: ['nginx']}),
  ],
  declared_hosts: [{host: 'ws.pusher.test', party: 'third_party', wildcard: false, contacted: false, sources: ['csp:connect-src'],
    count: 1, technologies: ['pusher'], first: place('S1:B1', 'Content-Security-Policy')}],
  coverage: coverage(),
  limitations: ['Every finding is a guess.'],
  ...extra
});

let answer = () => new Promise(() => {});
const reads = [];
window.fetch = (url, init) => {
  reads.push({url: String(url), headers: init?.headers ?? {}});
  return new Promise((resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new window.DOMException('The read was aborted', 'AbortError')));
    Promise.resolve(answer(String(url))).then(resolve, reject);
  });
};
const json = (status, body, headers = {}) => new window.Response(status === 304 ? null : JSON.stringify(body),
  {status, headers: {'content-type': 'application/json', ...headers}});
const opened = [], artifacts = [];
const panel = get('createBackendMapPanel')({root, openRow: id => opened.push(id), openArtifact: id => artifacts.push(id)});
// Leaf texts joined by spaces, as a reader sees separate elements.
const text = selector => {
  const node = selector ? root.querySelector(selector) : root;
  const leaves = node.children.length ? [...node.querySelectorAll('*')].filter(child => !child.children.length) : [node];
  return leaves.map(leaf => leaf.textContent).join(' ').replace(/\s+/g, ' ').trim();
};
const notice = () => root.querySelector('.backend-map-notice');

// Loading: opening the screen reads once; closing it aborts the read.
panel.setVisible(true);
await settle();
assert.equal(reads.length, 1);
assert.equal(reads[0].url, '/api/backend-map');
assert.match(notice().textContent, /Reading every captured request/);
assert.equal(root.getAttribute('aria-busy'), 'true');
panel.setVisible(false);
await settle();
assert.equal(root.querySelector('.backend-map-refresh').disabled, false, 'an aborted read gives Refresh back');

// A malformed answer is named and nothing is drawn.
answer = () => json(200, {format: 'something-else'});
panel.setVisible(true);
await settle();
assert.match(notice().textContent, /could not be read: the answer is not a reb-backend-map-v1 document/);
assert.equal(root.querySelectorAll('.backend-map-item').length, 0);
panel.setVisible(false);

// Empty: no requests yet.
answer = () => json(200, map({technologies: [], hosts: [], declared_hosts: [], coverage: coverage({rows: 0, entries: 0,
  entries_with_response_headers: 0, entries_with_urls: 0})}), {etag: '"empty"'});
panel.setVisible(true);
await settle();
assert.match(notice().textContent, /No requests are captured yet/);
assert.match(text('.backend-map-stack-list'), /No signal matched\. Absence is not evidence/);
panel.setVisible(false);

// Metadata only: no URLs and no headers, and an index still folding.
answer = () => json(200, map({coverage: coverage({entries_with_response_headers: 0, entries_with_urls: 0, complete: false})}), {etag: '"meta"'});
panel.setVisible(true);
await settle();
assert.match(notice().textContent, /Metadata only/);
assert.match(notice().textContent, /still catching up/);
assert.equal(root.querySelector('.backend-map-status').dataset.kind, 'limited');
panel.setVisible(false);

// Ready: groups by scope, inert captured text, the first technology selected.
answer = () => json(200, map(), {etag: '"ready"'});
panel.setVisible(true);
await settle();
assert.equal(notice().hidden, true);
const titles = [...root.querySelectorAll('.backend-map-stack-list .backend-map-group-title')].map(node => node.textContent);
assert.deepEqual(titles, ['Site stack (2)', 'Services the site uses (1)', 'Vendor infrastructure (1)']);
assert.equal(root.querySelector('img'), null, 'a captured name is text, never markup');
assert.equal(get('globalThis.pwned'), undefined);
assert(text('.backend-map-stack-list').includes(hostile));
const selected = () => root.querySelector('.backend-map-stack-list .backend-map-item[aria-pressed="true"]');
assert.equal(selected().dataset.technology, 'vercel');
assert.match(text('.backend-map-stack-detail'), /Captured edge region iad1 ×3/);
assert.match(text('.backend-map-stack-detail'), /First row S1:B1 · hop 0 · X-Vercel-Id/);
assert.match(text('.backend-map-status'), /2 seen · 2 in the site stack · 3 requests/);
assert.match(text('.backend-map-rules'), /reviewed 2026-11-25: 2 technologies, 3 signals/);
// A citation opens its Traffic row.
root.querySelector('.backend-map-stack-detail .backend-map-evidence').click();
assert.deepEqual(opened, ['S1:B1']);
// A script citation names its artifact and opens it in Sources.
const script = [...root.querySelectorAll('.backend-map-stack-detail .backend-map-evidence')].find(node => node.textContent.includes('artifact'));
assert.equal(script.textContent, 'First script artifact 19');
script.click();
assert.deepEqual(artifacts, ['19']);
// Implied and declared technologies say so.
root.querySelector('.backend-map-item[data-technology="react"]').click();
assert.match(text('.backend-map-stack-detail'), /implied, not seen directly/);
assert.match(text('.backend-map-stack-detail'), /Implied by Vercel/);
root.querySelector('.backend-map-item[data-technology="pusher"]').click();
assert.match(text('.backend-map-stack-detail'), /only declared: named in a policy, CORS header or body, not contacted/);
assert.equal(root.querySelector('.backend-map-signal-host').dataset.declared, 'true');
assert.match(text('.backend-map-stack-detail'), /Named in row S1:B1 · hop 0 · Content-Security-Policy/);
assert.equal(root.querySelector('.backend-map-party').hidden, true, 'the party filter is for Hosts');

// Refresh with the tag: a 304 keeps the map and its selection.
answer = () => json(304, null, {etag: '"ready"'});
root.querySelector('.backend-map-refresh').click();
await settle();
assert.equal(reads.at(-1).headers['If-None-Match'], '"ready"');
assert.equal(selected().dataset.technology, 'pusher');

// A failed refresh keeps the last map and says so.
answer = () => json(500, {error: 'store unreadable'});
root.querySelector('.backend-map-refresh').click();
await settle();
assert.match(notice().textContent, /Refresh failed \(store unreadable\); showing the previous map\./);
assert.equal(root.querySelectorAll('.backend-map-stack-list .backend-map-item').length, 4);

// Hosts: contacted hosts, then declared-only ones; the party filter narrows both.
root.querySelector('#backend-tab-hosts').click();
assert.equal(root.querySelector('#backend-panel-hosts').hidden, false);
assert.equal(root.querySelector('#backend-panel-stack').hidden, true);
assert.equal(root.querySelector('.backend-map-party').hidden, false);
const groups = [...root.querySelectorAll('.backend-map-host-list .backend-map-group-title')].map(node => node.textContent);
assert.deepEqual(groups, ['Contacted (2)', 'Named, not contacted (1)']);
assert.match(text('.backend-map-host-detail'), /CORS exposes x-total-count/);
const route = root.querySelector('.backend-map-routes tbody tr');
assert.equal(route.dataset.style, 'json');
assert.match(route.textContent, /\/api\/users\/\{int\}/);
assert.match(route.textContent, /\/api\/users\/\[id\]/);
route.querySelector('.backend-map-evidence').click();
assert.deepEqual(opened, ['S1:B1', 'S1:B4']);
root.querySelector('.backend-map-item[data-declared="true"]').click();
assert.match(text('.backend-map-host-detail'), /Named by csp:connect-src/);
assert.match(text('.backend-map-host-detail'), /no request to it was captured/);
root.querySelector('[data-backend-party="first_party"]').click();
assert.deepEqual([...root.querySelectorAll('.backend-map-host-list .backend-map-item')].map(node => node.dataset.host), ['app.test']);
root.querySelector('[data-backend-party="third_party"]').click();
assert.deepEqual([...root.querySelectorAll('.backend-map-host-list .backend-map-item')].map(node => node.dataset.host),
  ['js.stripe.test', 'ws.pusher.test']);

// The app's own panel follows showScreen.
const appReads = reads.length;
runInContext("showScreen('backend')", context);
await settle();
assert.equal(reads.length, appReads + 1, 'opening Backend reads the map');
runInContext("showScreen('traffic')", context);

assert.deepEqual(asyncErrors, []);
release();
console.log('Backend map UI checks passed');
