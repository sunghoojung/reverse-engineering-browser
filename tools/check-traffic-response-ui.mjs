// The shipped Response and Preview tabs (apps/research-ui/traffic_response.js)
// against decoded response_body records in a DOM model: capture states and
// reasons, the artifact join, reads checked by size and SHA-256, pretty print
// through the shared Oxc or in-page layout with raw ranges, wrap, hex, find
// and copy, a JSON tree, a signature-checked image, and captured markup
// inserted as text. Not rendered QA.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {runInContext, createContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const require = createRequire(import.meta.url);
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const ui = name => readFile(new URL(`../apps/research-ui/${name}`, import.meta.url), 'utf8');
const {window, document} = parseHTML('<!doctype html><div id="panel"></div>');
const reads = [], copied = [];
const blobs = new Map();
const state = {artifacts: [], events: [], content: true};
let pendingDigests = 0;
const countedCrypto = {subtle: {digest: (...args) => {
  pendingDigests += 1;
  return globalThis.crypto.subtle.digest(...args).finally(() => {pendingDigests -= 1;});
}}};
const context = createContext({
  window, document, location: {protocol: 'http:'}, console, TextDecoder, TextEncoder, Uint8Array, AbortController, Date,
  setTimeout, clearTimeout, crypto: countedCrypto, btoa, Response, Promise, AbortSignal, URLSearchParams,
  decodePayload: event => Buffer.from(event.payload, 'hex').toString(),
  navigator: {clipboard: {writeText: async text => {copied.push(text);}}},
  fetch: async url => {
    reads.push(url);
    const [, id, offset, limit] = /artifacts\/(\d+)\/content\?offset=(\d+)&limit=(\d+)/.exec(url);
    const bytes = blobs.get(id);
    return bytes ? new Response(bytes.subarray(Number(offset), Number(offset) + Number(limit))) : new Response('', {status: 404});
  }
});
runInContext(`${await ui('source_syntax.js')}\n${await ui('source_format.js')}\n${await ui('code_view.js')}\n${await ui('source_facts.js')}\n${await ui('traffic_view.js')}\n${await ui('traffic_payload.js')}\n${await ui('traffic_response.js')}
globalThis.api = {trafficResponseCapture, trafficResponseArtifact, trafficImageType, createTrafficResponse, createSourceLayoutWorker, createTrafficArtifactLookup};`, context);
const {api} = context;
const panel = document.getElementById('panel');
// SHA-256 runs off the event loop, so no fixed number of turns is sure to outlast
// a digest. Settle once none is pending and the loop has stayed quiet.
const settle = async () => {for (let quiet = 0; quiet < 30;) {await nextTurn(); quiet = pendingDigests ? 0 : quiet + 1;}};
const notes = () => [...panel.querySelectorAll('.traffic-body-note')].map(node => node.textContent).join(' ');
const until = async (condition, label) => {
  for (let i = 0; i < 400 && !condition(); i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert(condition(), label);
};
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
let renders = 0;
let current = null;
// get_source_format replies queued by the test; the in-page layout runs without a worker.
const formatReplies = [], formatReads = [];
const view = api.createTrafficResponse({getArtifacts: () => state.artifacts, getEvents: () => state.events,
  contentSession: () => state.content, readable: () => true, onChange: () => {renders += 1; if (current) view.render(panel, ...current);},
  request: async url => {formatReads.push(url); return formatReplies.shift()(url);},
  worker: api.createSourceLayoutWorker({spawn: null, defer: callback => callback()})});
const show = async (request, tab = 'response') => {current = [request, tab]; view.render(panel, request, tab); await settle();};

let nextId = 500;
const retain = (bytes, mime, extra = {}) => {
  const id = String(nextId++);
  const data = typeof bytes === 'string' ? Buffer.from(bytes) : Buffer.from(bytes);
  blobs.set(id, new Uint8Array(data));
  const artifact = {artifact_id: id, session_id: '7', kind: 'response_body', capture_origin: 'network_response',
    creator_event_id: '30', mime_type: mime, url: 'https://api.fixture.test/r', byte_size: data.length,
    sha256: sha(data), sensitive: true, ...extra};
  state.artifacts.push(artifact);
  return artifact;
};
const record = (artifact, extra = {}) => ({state: 'captured', shared: false, fromCache: false, serviceWorker: false,
  stillEncoded: false, codingsOmitted: false, completionUnobserved: false, contentType: artifact?.mime_type ?? 'application/json',
  codings: [], bodyLength: String(artifact?.byte_size ?? 0), capturedLength: String(artifact?.byte_size ?? 0), partialIndex: 0,
  sha256: artifact?.sha256 ?? null, artifactId: artifact?.artifact_id ?? '0', sequenceNumber: '31', parentEventId: '30',
  sessionId: '7', processId: 42, ...extra});
const request = (body, extra = {}) => ({id: `r${nextId}`, origin: 'live', type: 'xhr', responseBody: body,
  responseStarted: {sequenceNumber: '30', sessionId: '7', processId: 42}, redirectedBody: false, ...extra});

// Every state says why, and no state reads as an empty body.
const capture = api.trafficResponseCapture;
assert.match(capture({responseStarted: null}, true), /recorded no response.*Service-worker and memory-cache/);
assert.match(capture({responseStarted: null, redirectedBody: true}, true), /discards redirect bodies/);
assert.match(capture({responseStarted: {}, type: 'xhr'}, false), /only in content capture sessions/);
assert.match(capture({responseStarted: {}, type: 'xhr'}, true), /No response body record/);
assert.match(capture({responseStarted: {}, type: 'js'}, true), /Scripts and Wasm are retained as source artifacts/);
assert.match(capture({responseBody: {malformed: true}}, true), /malformed/);
const states = {captured_truncated: /16 MiB capture limit/, partial: /snapshot 2 while the body was still arriving/,
  aborted: /network failed mid-body/, cancelled: /stopped reading/, empty: /Empty body/, not_modified: /304/,
  redirected: /discards redirect bodies/, not_captured_type: /REB_CAPTURE_RESPONSE_MEDIA=1/,
  not_captured_artifact_unavailable: /artifact channel/, not_captured_transfer_refused: /in-flight memory/,
  not_captured_session_budget: /REB_RESPONSE_BODY_BUDGET_MIB/};
for (const [name, pattern] of Object.entries(states)) {
  assert.match(capture({responseBody: record(null, {state: name, partialIndex: 2, bodyLength: '9', capturedLength: '9'})}, true), pattern, name);
}
assert.match(capture({responseBody: record(null, {state: 'aborted', capturedLength: '0'})}, true), /before any byte/);

// The join: a record's own artifact by creator, a shared one by ID, scripts by response creator.
const json = '{"challenge":"c1","answers":[1,2,{"deep":[true,null]}],"html":"<b>x</b>"}';
const jsonArtifact = retain(json, 'application/json');
assert(api.trafficResponseArtifact(request(record(jsonArtifact)), state.artifacts) === jsonArtifact);
assert(api.trafficResponseArtifact(request(record(jsonArtifact, {parentEventId: '99'})), state.artifacts) === null);
assert(api.trafficResponseArtifact(request(record(jsonArtifact, {parentEventId: '99', shared: true})), state.artifacts) === jsonArtifact);
const script = retain('console.log(1)', 'text/javascript', {kind: 'javascript', sensitive: false});
assert(api.trafficResponseArtifact(request(null), state.artifacts) === script);
state.artifacts.pop();

// Response: inert syntax-colored text, then pretty print, wrap, find, copy and hex.
await show(request(record(jsonArtifact)));
assert.equal(reads.length, 1);
assert.match(panel.textContent, /Retained in full\./);
assert(panel.querySelector('b') === null, 'captured markup is text');
assert(panel.querySelector('.traffic-response-code .syntax-string'), 'JSON strings are colored');
assert.equal(panel.querySelectorAll('.traffic-response-line').length, 1);
const press = async control => {panel.querySelector(`[data-control="${control}"]`).click(); await settle();};
// The backend Oxc layout of the retained JSON body; a clicked token names its raw range.
const laid = '{\n  "challenge": "c1",\n  "answers": [1, 2, { "deep": [true, null] }],\n  "html": "<b>x</b>"\n}';
formatReplies.push(() => ({ok: true, status: 200, json: async () => ({schema: 'source-format-v1', mapping: 'whitespace-only', language: 'json',
  source: {artifact_id: jsonArtifact.artifact_id, sha256: jsonArtifact.sha256}, status: 'formatted', text: laid})}));
await press('pretty');
assert.equal(formatReads.at(-1), `/api/source-format?session_id=7&artifact_id=${jsonArtifact.artifact_id}`);
assert.equal(panel.querySelectorAll('.traffic-response-line').length, 5, 'pretty print shows the Oxc layout');
assert.equal(panel.querySelector('[data-control="pretty"]').getAttribute('aria-pressed'), 'true');
assert.match(panel.querySelector('.traffic-response-code').textContent, /"<b>x<\/b>"/);
assert.doesNotMatch(notes(), /Whitespace layout/);
[...panel.querySelectorAll('.traffic-response-code .syntax-key')].find(node => node.textContent === 'deep').click();
assert.equal(panel.querySelector('.code-view-raw').textContent,
  `Line 3, Column ${laid.split('\n')[2].indexOf('deep') + 1} · raw 1:${json.indexOf('deep') + 1}–1:${json.indexOf('deep') + 5} (offsets ${json.indexOf('deep')}–${json.indexOf('deep') + 4})`);
assert(panel.querySelector('.traffic-response-code').classList.contains('is-wrapped'));
await press('wrap');
assert(!panel.querySelector('.traffic-response-code').classList.contains('is-wrapped'));
const find = panel.querySelector('[data-control="find"]');
find.value = 'deep';
find.dispatchEvent(new window.Event('input'));
await settle();
assert.deepEqual([...panel.querySelectorAll('.traffic-response-code mark')].map(mark => mark.textContent), ['deep']);
assert.match(panel.querySelector('.traffic-response-count').textContent, /^1 of 1$/);
const enter = new window.Event('keydown');
Object.defineProperty(enter, 'key', {value: 'Enter'});
panel.querySelector('[data-control="find"]').dispatchEvent(enter);
await settle();
assert(panel.querySelector('.traffic-response-code mark.is-current'));
await press('copy');
assert.equal(copied.at(-1).split('\n').length, panel.querySelectorAll('.traffic-response-line').length);
assert.equal(copied.at(-1).replaceAll(/\s/g, ''), json.replaceAll(/\s/g, ''), 'Copy writes the shown text with its line breaks');
await press('hex');
assert.match(panel.querySelector('.traffic-response-code').textContent, /^00000000  7b 22 63 68/);
await press('hex');
await press('pretty');
// A body Oxc refuses is laid out in the page, with the reason.
const broken = retain('{"a":1,}', 'application/json');
formatReplies.push(() => ({ok: true, status: 200, json: async () => ({schema: 'source-format-v1', mapping: 'whitespace-only', language: 'json',
  source: {artifact_id: broken.artifact_id, sha256: broken.sha256}, status: 'unavailable', reason: 'parse-failed', text: null})}));
await show(request(record(broken)));
await press('pretty');
assert.match(notes(), /Whitespace layout: Oxc could not parse this file\./);
await press('pretty');
const findAgain = panel.querySelector('[data-control="find"]');
findAgain.value = '';
findAgain.dispatchEvent(new window.Event('input'));
await settle();

// Preview: the Payload tree, every value reachable by keyboard without a node cap.
await show(request(record(jsonArtifact)), 'preview');
assert.equal(panel.querySelector('.traffic-payload-tree').getAttribute('role'), 'tree');
assert(panel.querySelector('.traffic-payload-tree [role="treeitem"]'), 'the tree has tree items');
assert.match(panel.textContent, /challenge: "c1"/);
assert.match(panel.textContent, /Array\(3\)/);
assert(panel.querySelector('b') === null);
const keyInTree = key => {
  const event = new window.Event('keydown', {bubbles: true});
  Object.defineProperty(event, 'key', {value: key});
  return panel.querySelector('.traffic-payload-tree [tabindex="0"]').dispatchEvent(event);
};
const wide = retain(JSON.stringify(Object.fromEntries(Array.from({length: 3000}, (_, index) => [`k${index}`, index]))), 'application/json');
await show(request(record(wide)), 'preview');
assert.match(panel.textContent, /\[0 … 99\]/, 'a wide object folds into ranges rather than stopping');
assert.doesNotMatch(panel.textContent, /more not shown|first 2,000/);
const rows = () => panel.querySelectorAll('.traffic-payload-tree [role="treeitem"]').length;
const closed = rows();
keyInTree('ArrowDown');
keyInTree('ArrowRight');
assert(rows() > closed, 'Arrow keys open a range in the Preview tree');

// HTML is source in both tabs and never parsed into elements.
const html = '<!doctype html><title>t</title><script>alert(1)</script><img src=x onerror=alert(2)><p>body';
const htmlRequest = request(record(retain(html, 'text/html'), {codings: ['gzip']}));
await show(htmlRequest, 'preview');
assert.match(panel.textContent, /never rendered/);
assert(panel.querySelector('script, img, title, p:not(.traffic-body-note)') === null, 'no captured element exists');
assert.match(panel.textContent, /<script>alert\(1\)<\/script>/);
await show(htmlRequest);
assert(panel.querySelector('.syntax-tag'));
assert.match(panel.textContent, /gzip · bytes are decoded/);

// Images: only a raster signature that matches the bytes becomes an image.
const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
assert.equal(api.trafficImageType(png, 'image/png'), 'image/png');
assert.equal(api.trafficImageType(png, 'text/html'), null);
assert.equal(api.trafficImageType(Buffer.from('<svg onload=alert(1)>'), 'image/svg+xml'), null);
assert.equal(api.trafficImageType(Buffer.from('RIFF\0\0\0\0WEBPVP8 '), 'image/webp'), 'image/webp');
assert.equal(api.trafficImageType(Buffer.from('\0\0\0\x1cftypavif'), 'image/avif'), 'image/avif');
await show(request(record(retain(png, 'image/png'))), 'preview');
assert.match(panel.querySelector('.traffic-response-image img').getAttribute('src'), /^data:image\/png;base64,iVBORw0KGgo/);
const svg = retain('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', 'image/svg+xml');
await show(request(record(svg)), 'preview');
assert(panel.querySelector('img, svg') === null, 'SVG is never rendered');
assert.match(panel.textContent, /never rendered/);

// Binary bodies are hex only.
const binary = retain(Uint8Array.from([0, 1, 2, 0xff, 0xfe, 0x41]), 'application/octet-stream');
await show(request(record(binary)));
assert.match(panel.querySelector('.traffic-response-code').textContent, /^00000000  00 01 02 ff fe 41/);
assert.equal(panel.querySelector('[data-control="hex"]').disabled, true);
await show(request(record(binary)), 'preview');
assert.match(panel.textContent, /Binary body: no preview/);

// A large body loads by range and is verified once complete.
const large = 'x'.repeat(2 * 1024 * 1024 + 100);
const largeRequest = request(record(retain(large, 'text/plain')));
await show(largeRequest);
assert.match(notes(), /Showing the first 2,097,152 bytes of 2,097,252 bytes retained/);
// Show the next 2 MiB keeps the reader's place in the shown text.
const beforeMore = panel.querySelector('.traffic-response-code');
beforeMore.scrollTop = 40;
panel.querySelector('.traffic-body-more').click();
await until(() => !panel.querySelector('.traffic-body-more'), 'the next range completes the body');
assert.doesNotMatch(notes(), /Showing the first|could not be rechecked/);
assert.equal(panel.querySelector('.traffic-response-code').scrollTop, 40, 'the next range keeps the scroll position');
// Preview reads every range without a click, then shows the whole body.
const autoRequest = request(record(retain(JSON.stringify({text: 'x'.repeat(2 * 1024 * 1024 + 100)}), 'application/json')));
await show(autoRequest, 'preview');
await until(() => panel.querySelector('.traffic-payload-tree'), 'Preview pages the whole body itself');
assert.equal(reads.filter(url => url.includes(`/${state.artifacts.at(-1).artifact_id}/content`)).length, 2, 'Each retained range is read once');
// Copy says what it wrote and how much remains, and survives a denied clipboard.
const partialRequest = request(record(retain('y'.repeat(2 * 1024 * 1024 + 50), 'text/plain')));
await show(partialRequest);
await press('copy');
await settle();
assert.match(panel.querySelector('.traffic-response-status').textContent, /Copied the 2,097,152 bytes loaded so far; 50 bytes more are retained/);
const clipboard = context.navigator.clipboard.writeText;
context.navigator.clipboard.writeText = async () => {throw new Error('denied');};
await press('copy');
await settle();
assert.match(panel.querySelector('.traffic-response-status').textContent, /Copy failed/);
context.navigator.clipboard.writeText = clipboard;
// Typing in Find reveals the first match, and Enter then moves to the next.
await show(request(record(jsonArtifact)));
let revealed = 0;
const scrollIntoView = window.HTMLElement.prototype.scrollIntoView;
window.HTMLElement.prototype.scrollIntoView = function reveal() {revealed += 1;};
const typing = panel.querySelector('[data-control="find"]');
typing.value = 'deep';
typing.dispatchEvent(new window.Event('input'));
await settle();
assert.equal(panel.querySelector('.code-view-mark.is-current').textContent, 'deep');
assert(revealed > 0, 'typing reveals the first match');
window.HTMLElement.prototype.scrollIntoView = scrollIntoView;
const emptied = panel.querySelector('[data-control="find"]');
emptied.value = '';
emptied.dispatchEvent(new window.Event('input'));
await settle();
// Text that is not UTF-8 keeps a text view and enables Hex.
const latin = retain(Uint8Array.from(Buffer.from('caf\xe9 cr\xe8me\n', 'latin1')), 'text/plain');
await show(request(record(latin)));
assert.equal(panel.querySelector('[data-control="hex"]').disabled, false);
assert.match(notes(), /Not valid UTF-8; shown with replacement characters/);
assert.match(panel.querySelector('.traffic-response-code').textContent, /caf\uFFFD cr\uFFFDme/);
await show(request(record(latin)), 'preview');
assert.match(notes(), /Not valid UTF-8/);
// A partial, aborted or cancelled UTF-8 body ending inside a character is text.
for (const name of ['partial', 'aborted', 'cancelled', 'captured_truncated']) {
  const cut = retain(new Uint8Array([...Buffer.from('{"k":"caf'), 0xc3]), 'application/json');
  await show(request(record(cut, {state: name, partialIndex: 1, capturedLength: '10', bodyLength: '20'})));
  assert.equal(panel.querySelector('[data-control="hex"]').disabled, false, `${name} keeps a text view`);
  assert.doesNotMatch(panel.querySelector('.traffic-response-code').textContent, /^00000000/, `${name} is not shown as hex`);
  assert.doesNotMatch(notes(), /Not valid UTF-8/, `${name} has no lossy notice: the character was cut`);
  await show(request(record(cut, {state: name, partialIndex: 1, capturedLength: '10', bodyLength: '20'})), 'preview');
  assert.doesNotMatch(panel.textContent, /Binary body/, `${name} keeps a preview`);
}
// A range that ends inside a character is still text.
await show(request(record(retain('a'.repeat(2 * 1024 * 1024 - 1) + 'é' + 'b'.repeat(100), 'text/plain'))));
assert.match(notes(), /Showing the first 2,097,152 bytes/);
assert.equal(panel.querySelector('[data-control="hex"]').disabled, false, 'a split character is not binary');

// Integrity failures stay explicit and are not retried; refusals name their reason.
const tampered = retain('{"a":1}', 'application/json');
tampered.sha256 = '0'.repeat(64);
await show(request(record(tampered)));
await until(() => /SHA-256/.test(notes()), 'a digest mismatch is reported');
assert.match(notes(), /do not match the retained SHA-256/);
assert.doesNotMatch(notes(), /read again/);
const refused = record({artifact_id: '900', byte_size: 4, sha256: 'a'.repeat(64), mime_type: 'application/json'});
state.events.push({type: 'artifact_capture_failed', artifact_id: '900', session_id: '7', parent_event_id: '30',
  payload: Buffer.from('sensitive_capture_disabled').toString('hex')});
await show(request(refused));
assert.match(panel.textContent, /not started for sensitive capture/);
await show(request(record({artifact_id: '901', byte_size: 4, sha256: 'b'.repeat(64), mime_type: 'application/json'})));
assert.match(panel.textContent, /not in the artifact manifest: its acknowledgment is pending/);

// A body past the catalog is read by ID; a refusal is read by ID too.
const lookupReads = [];
const manifestRecord = retain('{"late":true}', 'application/json');
state.artifacts.pop();
let manifestAnswer = {artifacts: [manifestRecord], query: {next_after: '9', limited: false, budget_exhausted: false}};
let eventAnswer = {events: [], query: {next_after: '9', limited: false, budget_exhausted: false}};
const reply = body => new Response(JSON.stringify(body));
const lookups = api.createTrafficArtifactLookup({onChange: () => {if (current) view.render(panel, ...current);},
  valid: body => Array.isArray(body?.artifacts), refusalText: event => `refused:${event.artifact_id}`,
  fetcher: async url => {lookupReads.push(url); return reply(url.startsWith('/api/artifacts?') ? manifestAnswer : eventAnswer);}});
const byIdRecord = record(manifestRecord);
let entry = lookups.lookup(byIdRecord, '1500');
assert.equal(entry.status, 'loading');
await settle();
entry = lookups.lookup(byIdRecord, '1500');
assert.equal(entry.status, 'found');
assert.equal(entry.artifact.artifact_id, manifestRecord.artifact_id);
assert.equal(lookupReads.length, 1, 'A found artifact is read once');
assert.match(lookupReads[0], /artifact_id=\d+&session_id=7&after=0&limit=1/);
// Neither manifest nor event scan reached it: unknown, not absent.
const missing = record({artifact_id: '902', byte_size: 2, sha256: 'c'.repeat(64), mime_type: 'application/json'});
manifestAnswer = {artifacts: [], query: {next_after: '64', limited: false, budget_exhausted: false}};
eventAnswer = {events: [], query: {next_after: '64', limited: false, budget_exhausted: true}};
lookups.lookup(missing, '1500');
await settle();
assert.equal(lookups.lookup(missing, '1500').status, 'unknown');
assert.match(lookupReads.at(-1), /type=artifact_capture_failed&artifact_id=902&session_id=7&after=1500&limit=1/);
// A whole-manifest miss with no refusal is pending; a refusal names its reason.
const pending = record({artifact_id: '903', byte_size: 2, sha256: 'c'.repeat(64), mime_type: 'application/json'});
eventAnswer = {events: [], query: {next_after: '64', limited: false, budget_exhausted: false}};
lookups.lookup(pending);
await settle();
assert.equal(lookups.lookup(pending).status, 'absent');
const reads0 = lookupReads.length;
assert.equal(lookups.lookup(pending).status, 'absent');
assert.equal(lookupReads.length, reads0, 'No extra reads inside the retry interval');
const refusedById = record({artifact_id: '904', byte_size: 2, sha256: 'c'.repeat(64), mime_type: 'application/json'});
eventAnswer = {events: [{artifact_id: '904'}], query: {next_after: '64', limited: false, budget_exhausted: false}};
lookups.lookup(refusedById);
await settle();
assert.deepEqual({status: lookups.lookup(refusedById).status, reason: lookups.lookup(refusedById).reason}, {status: 'refused', reason: 'refused:904'});
const byIdView = api.createTrafficResponse({getArtifacts: () => state.artifacts, getEvents: () => state.events, contentSession: () => true,
  readable: () => true, onChange: () => {}, lookup: item => lookups.lookup(item)});
const lookupPanel = document.createElement('div');
byIdView.render(lookupPanel, request(byIdRecord), 'response');
await settle();
byIdView.render(lookupPanel, request(byIdRecord), 'response');
assert(lookupPanel.querySelector('.traffic-response-code'), 'A body past the catalog renders after an ID read');
byIdView.render(lookupPanel, request(refusedById), 'response');
assert.match(lookupPanel.textContent, /did not retain it \(refused:904\)/);
const unknownRecord = record({artifact_id: '905', byte_size: 2, sha256: 'c'.repeat(64), mime_type: 'application/json'});
manifestAnswer = {artifacts: [], query: {next_after: '64', limited: false, budget_exhausted: false}};
eventAnswer = {events: [], query: {next_after: '64', limited: false, budget_exhausted: true}};
byIdView.render(lookupPanel, request(unknownRecord), 'response');
await settle();
byIdView.render(lookupPanel, request(unknownRecord), 'response');
assert.match(lookupPanel.textContent, /not in the scanned range of the artifact manifest/);

// Unchanged inputs do not rebuild the panel.
await show(request(record(jsonArtifact)));
const before = panel.firstChild;
view.render(panel, ...current);
assert(panel.firstChild === before, 'an unchanged render keeps its nodes');
assert(renders > 0);
// A parsed preview counts toward the byte budget and goes with its view, so a
// tree cannot outlive the bytes it came from. A low budget makes eviction observable.
{
  const scriptText = `${await ui('source_syntax.js')}\n${await ui('source_format.js')}\n${await ui('code_view.js')}\n${await ui('source_facts.js')}\n${await ui('traffic_view.js')}\n${await ui('traffic_payload.js')}\n${(await ui('traffic_response.js')).replace('TRAFFIC_RESPONSE_CACHE_BYTES = 48 * 1024 * 1024', 'TRAFFIC_RESPONSE_CACHE_BYTES = 200')}\nglobalThis.api = {createTrafficResponse, createSourceLayoutWorker};`;
  const small = createContext({window, document, location: {protocol: 'http:'}, console, TextDecoder, TextEncoder, Uint8Array, AbortController, Date,
    setTimeout, clearTimeout, crypto: countedCrypto, btoa, Response, Promise, AbortSignal, URLSearchParams,
    decodePayload: () => '', navigator: {clipboard: {writeText: async () => {}}},
    fetch: async url => {
      reads.push(url);
      const [, id, offset, limit] = /artifacts\/(\d+)\/content\?offset=(\d+)&limit=(\d+)/.exec(url);
      const bytes = blobs.get(id);
      return new Response(bytes.subarray(Number(offset), Number(offset) + Number(limit)));
    }});
  runInContext(scriptText, small);
  let drawn = null;
  const reduced = small.api.createTrafficResponse({getArtifacts: () => state.artifacts, getEvents: () => state.events,
    contentSession: () => state.content, readable: () => true, onChange: () => {if (drawn) reduced.render(panel, ...drawn);},
    request: async () => {throw new Error('unused');},
    worker: small.api.createSourceLayoutWorker({spawn: null, defer: callback => callback()})});
  const render = async doc => {drawn = [request(record(doc)), 'preview']; reduced.render(panel, ...drawn); await settle();};
  const first = retain(JSON.stringify({value: 'a'.repeat(70)}), 'application/json');
  const second = retain(JSON.stringify({value: 'b'.repeat(70)}), 'application/json');
  await render(first);
  await render(second);
  const before = reads.length;
  await render(first);
  assert(reads.length > before, 'The first preview was evicted, because bytes and parsed source together passed the budget');
}
console.log(`PASS traffic response UI: every capture state and reason, artifact join, pretty print by the Oxc layout with token raw ranges or the in-page layout with its reason, wrap/find/copy/hex, ` +
  `JSON tree bound, inert HTML and SVG, signature-checked image, ranged verified reads, integrity and refusal notes ` +
  `(${reads.length} reads; DOM model, not rendered QA)`);
