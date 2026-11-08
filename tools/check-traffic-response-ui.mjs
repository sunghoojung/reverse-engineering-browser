// The shipped Response and Preview tabs (apps/research-ui/traffic_response.js)
// against decoded response_body records in a DOM model: capture states and
// reasons, the artifact join, reads checked by size and SHA-256, pretty print,
// wrap, hex, find and copy, a JSON tree, a signature-checked image, and
// captured markup inserted as text. Not rendered QA.
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
const context = createContext({
  window, document, location: {protocol: 'http:'}, console, TextDecoder, TextEncoder, Uint8Array, AbortController, Date,
  setTimeout, clearTimeout, crypto: globalThis.crypto, btoa, Response, Promise,
  decodePayload: event => Buffer.from(event.payload, 'hex').toString(),
  navigator: {clipboard: {writeText: async text => {copied.push(text);}}},
  fetch: async url => {
    reads.push(url);
    const [, id, offset, limit] = /artifacts\/(\d+)\/content\?offset=(\d+)&limit=(\d+)/.exec(url);
    const bytes = blobs.get(id);
    return bytes ? new Response(bytes.subarray(Number(offset), Number(offset) + Number(limit))) : new Response('', {status: 404});
  }
});
runInContext(`${await ui('source_syntax.js')}\n${await ui('source_facts.js')}\n${await ui('traffic_response.js')}
globalThis.api = {trafficResponseCapture, trafficResponseArtifact, trafficImageType, trafficJsonTree, createTrafficResponse};`, context);
const {api} = context;
const panel = document.getElementById('panel');
const settle = async () => {for (let i = 0; i < 30; i++) await nextTurn();};
const notes = () => [...panel.querySelectorAll('.traffic-body-note')].map(node => node.textContent).join(' ');
const until = async (condition, label) => {
  for (let i = 0; i < 400 && !condition(); i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert(condition(), label);
};
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
let renders = 0;
let current = null;
const view = api.createTrafficResponse({getArtifacts: () => state.artifacts, getEvents: () => state.events,
  contentSession: () => state.content, readable: () => true, onChange: () => {renders += 1; if (current) view.render(panel, ...current);}});
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
await press('pretty');
assert(panel.querySelectorAll('.traffic-response-line').length > 5, 'pretty print splits the JSON');
assert.equal(panel.querySelector('[data-control="pretty"]').getAttribute('aria-pressed'), 'true');
assert.match(panel.querySelector('.traffic-response-code').textContent, /"<b>x<\/b>"/);
assert(panel.querySelector('.traffic-response-code').classList.contains('wrap'));
await press('wrap');
assert(!panel.querySelector('.traffic-response-code').classList.contains('wrap'));
const find = panel.querySelector('[data-control="find"]');
find.value = 'deep';
find.dispatchEvent(new window.Event('input'));
await settle();
assert.equal(panel.querySelectorAll('.traffic-response-line.search-match').length, 1);
assert.match(panel.querySelector('.traffic-response-count').textContent, /^1 line$/);
const enter = new window.Event('keydown');
Object.defineProperty(enter, 'key', {value: 'Enter'});
panel.querySelector('[data-control="find"]').dispatchEvent(enter);
assert(panel.querySelector('.traffic-response-line.current'));
await press('copy');
assert.equal(copied.at(-1).split('\n').length, panel.querySelectorAll('.traffic-response-line').length);
assert.equal(copied.at(-1).replaceAll(/\s/g, ''), json.replaceAll(/\s/g, ''), 'Copy writes the shown text with its line breaks');
await press('hex');
assert.match(panel.querySelector('.traffic-response-code').textContent, /^00000000  7b 22 63 68/);
await press('hex');
await press('pretty');
const findAgain = panel.querySelector('[data-control="find"]');
findAgain.value = '';
findAgain.dispatchEvent(new window.Event('input'));
await settle();

// Preview: a bounded JSON tree of text nodes.
await show(request(record(jsonArtifact)), 'preview');
assert(panel.querySelector('.traffic-json-tree details > summary'));
assert.match(panel.textContent, /challenge: "c1"/);
assert.match(panel.textContent, /Array\(3\)/);
assert(panel.querySelector('b') === null);
const wide = api.trafficJsonTree(Object.fromEntries(Array.from({length: 3000}, (_, index) => [`k${index}`, index])));
assert.match(wide.textContent, /more not shown/);
assert.match(wide.textContent, /first 2,000 values/);

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
await show(largeRequest, 'preview');
assert.match(notes(), /Preview needs every retained byte/);
await show(largeRequest);
panel.querySelector('.traffic-body-more').click();
await until(() => !panel.querySelector('.traffic-body-more'), 'the next range completes the body');
assert.doesNotMatch(notes(), /Showing the first|could not be rechecked/);
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
assert.match(panel.textContent, /not in the current catalog/);

// Unchanged inputs do not rebuild the panel.
await show(request(record(jsonArtifact)));
const before = panel.firstChild;
view.render(panel, ...current);
assert(panel.firstChild === before, 'an unchanged render keeps its nodes');
assert(renders > 0);
console.log(`PASS traffic response UI: every capture state and reason, artifact join, pretty/wrap/find/copy/hex, ` +
  `JSON tree bound, inert HTML and SVG, signature-checked image, ranged verified reads, integrity and refusal notes ` +
  `(${reads.length} reads; DOM model, not rendered QA)`);
