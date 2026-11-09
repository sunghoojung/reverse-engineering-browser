// The shipped Headers tab (apps/research-ui/traffic_headers.js) against the
// shipped decoder's blocks in a DOM model: hop order, provisional notice,
// retained reads checked by size and SHA-256, Raw and copy, and captured
// markup inserted as text. Not rendered QA.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {runInContext, createContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const require = createRequire(import.meta.url);
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const source = await readFile(new URL('../apps/research-ui/traffic_view.js', import.meta.url), 'utf8') +
  await readFile(new URL('../apps/research-ui/traffic_headers.js', import.meta.url), 'utf8');
const {window, document} = parseHTML('<!doctype html><div id="panel"></div>');
const reads = [], copied = [];
const blobs = new Map();
let pendingDigests = 0;
const countedCrypto = {subtle: {digest: (...args) => {
  pendingDigests += 1;
  return globalThis.crypto.subtle.digest(...args).finally(() => {pendingDigests -= 1;});
}}};
const context = createContext({
  window, document, location: {protocol: 'http:'}, console, TextDecoder, Uint8Array, AbortController, Date,
  setTimeout, clearTimeout, crypto: countedCrypto, state: {events: []}, decodePayload: () => 'sensitive_capture_disabled',
  navigator: {clipboard: {writeText: async text => {copied.push(text);}}},
  fetch: async url => {
    reads.push(url);
    const id = /artifacts\/(\d+)\//.exec(url)[1];
    return blobs.has(id) ? new Response(blobs.get(id)) : new Response('', {status: 404});
  }
});
runInContext(`${source};globalThis.api={trafficHeaderLines, trafficHeaderHops, renderTrafficHeaders};`, context);
const {api} = context;
const panel = document.getElementById('panel');
const sha = text => createHash('sha256').update(text).digest('hex');
let next = 100;
const block = (kind, source, text, extra = {}) => {
  const id = String(next++);
  blobs.set(id, text);
  return {kind, source, state: 'captured', headerCount: text.split('\r\n').length - 1, blockLength: Buffer.byteLength(text),
    hop: 0, statusCode: kind === 'response' ? 200 : 0, referrerPolicy: source === 'browser' && kind === 'request' ? 'strict-origin-when-cross-origin' : null,
    remoteAddress: kind === 'response' && source === 'browser' ? '127.0.0.1' : null, remotePort: 8443, unattributedBlocks: 0,
    sha256: sha(text), artifactId: id, sequenceNumber: id, sessionId: '7', processId: 42, ...extra};
};
let renders = 0;
const rerender = () => {renders += 1; api.renderTrafficHeaders(panel, request, rerender);};
// SHA-256 runs off the event loop, so no fixed number of turns is sure to outlast
// a digest. Settle once none is pending and the loop has stayed quiet.
const settle = async () => {for (let quiet = 0; quiet < 20;) {await nextTurn(); quiet = pendingDigests ? 0 : quiet + 1;}};

assert.deepEqual(JSON.parse(JSON.stringify(api.trafficHeaderLines(':path: /a\r\nx: y: z\r\n', 2))),
  [{name: ':path', value: '/a'}, {name: 'x', value: 'y: z'}]);
assert.equal(api.trafficHeaderLines('a: b\r\n', 2), null);
assert.equal(api.trafficHeaderLines('a:b\r\n', 1), null);

const markup = '<img src=x onerror=alert(1)>';
const request = {id: 'r', origin: 'live', method: 'GET', path: 'https://echo.test/final', status: 200, hostOnly: false,
  headerBlocks: [
    block('request', 'browser', 'Accept: */*\r\n'),
    block('request', 'network', `:method: GET\r\ncookie: sid=1\r\nx-markup: ${markup}\r\n`),
    block('response', 'browser', 'Location: /final\r\nSet-Cookie: a=b\r\n', {statusCode: 302}),
    block('request', 'browser', 'Accept: */*\r\n', {hop: 1}),
    block('response', 'early_hints', 'link: </a.css>; rel=preload\r\n', {hop: 1, statusCode: 103, remoteAddress: null}),
    block('response', 'browser', `X-Large: ${'v'.repeat(200 * 1024)}\r\n`, {hop: 1}),
    {malformed: true, kind: 'request', sequenceNumber: '99'}]};
api.renderTrafficHeaders(panel, request, rerender);
assert.match(panel.textContent, /Loading retained headers/);
await settle();
const sections = [...panel.querySelectorAll('details')];
assert.deepEqual(sections.map(section => section.querySelector('summary').firstChild.textContent),
  ['General', 'Response headers · hop 1 (200)', 'Early hints · hop 1 (103)', 'Request headers · hop 1',
    'Response headers · hop 0 (302)', 'Request headers · hop 0']);
const general = sections[0].textContent;
assert.match(general, /127\.0\.0\.1:8443/);
assert.match(general, /strict-origin-when-cross-origin/);
assert.match(general, /Redirect hops1/);
// A truncated URL names that it is cut and, once loaded, reads whole.
{
  const prefix = 'https://echo.test/final?a=1';
  const cut = {id: 'cut', origin: 'live', method: 'GET', path: prefix, status: 200, hostOnly: false, urlTruncated: true, targetLength: 400,
    fullTarget: {retention: 'retained'}, headerBlocks: []};
  const cutPanel = document.createElement('div');
  const generalText = () => [...cutPanel.querySelectorAll('details')][0].textContent;
  api.renderTrafficHeaders(cutPanel, cut, () => {}, {status: 'loading'});
  assert.match(generalText(), /truncated; the original path and query are 400 bytes; loading the retained full target/);
  api.renderTrafficHeaders(cutPanel, cut, () => {}, {status: 'ready', complete: true, url: 'https://echo.test', text: '/final?a=1&b=2'});
  assert.match(generalText(), /Request URLhttps:\/\/echo\.test\/final\?a=1&b=2/);
  assert.doesNotMatch(generalText(), /truncated/);
}
assert.match(panel.textContent, /1 header record is malformed and not shown/);
// Hop 1 has only its provisional block; hop 0 shows what the network sent.
assert.match(sections[3].textContent, /Provisional headers are shown/);
assert.equal(sections[3].dataset.source, 'browser');
assert.doesNotMatch(sections[5].textContent, /Provisional headers/);
assert.equal(sections[5].dataset.source, 'network');
assert.equal(panel.querySelectorAll('img').length, 0, 'captured markup is text');
assert(sections[5].textContent.includes(markup));
assert(sections[1].querySelector('.traffic-header-value').textContent.length === 200 * 1024);
// Raw shows the exact block; copy writes the value or the whole block.
const raw = [...sections[4].querySelectorAll('button')].find(button => button.textContent === 'Raw');
raw.dispatchEvent(new window.Event('click'));
assert.equal(raw.getAttribute('aria-pressed'), 'true');
assert.equal(sections[4].querySelector('pre').textContent, 'Location: /final\r\nSet-Cookie: a=b\r\n');
[...sections[4].querySelectorAll('button')].find(button => button.textContent === 'Copy all').dispatchEvent(new window.Event('click'));
sections[5].querySelector('.traffic-header-copy').dispatchEvent(new window.Event('click'));
await settle();
assert.deepEqual(copied, ['Location: /final\r\nSet-Cookie: a=b\r\n', 'GET']);
assert.equal(reads.length, 5, 'one read per shown retained block; a superseded provisional block is not read');
const before = renders;
api.renderTrafficHeaders(panel, request, rerender);
await settle();
assert.equal(renders, before, 'an unchanged view does not reread or rerender');
assert.equal(panel.querySelector('pre')?.textContent, 'Location: /final\r\nSet-Cookie: a=b\r\n', 'Raw survives a refresh');

// Integrity failure, refusal and every not-retained state read as sentences.
const wrong = block('request', 'network', 'a: b\r\n');
blobs.set(wrong.artifactId, 'a: c\r\n');
const refused = block('response', 'browser', 'b: c\r\n');
context.state.events = [{type: 'artifact_capture_failed', artifact_id: refused.artifactId, session_id: '7'}];
const states = {id: 's', origin: 'live', method: 'GET', path: 'https://echo.test/', status: 200,
  headerBlocks: [wrong, refused, {...block('request', 'browser', 'x: y\r\n'), hop: 2, state: 'not_captured_session_budget', artifactId: '0'},
    {...block('response', 'browser', 'x: y\r\n'), hop: 2, state: 'not_captured_block_limit', artifactId: '0', sha256: null}]};
const statesRender = () => api.renderTrafficHeaders(panel, states, statesRender);
statesRender();
await settle();
assert.match(panel.textContent, /do not match the recorded SHA-256/);
assert.match(panel.textContent, /receiver refused this block: sensitive_capture_disabled/);
assert.match(panel.textContent, /already retained 64 MiB of header blocks/);
assert.match(panel.textContent, /320 KiB block limit/);

// Metadata-only and legacy rows say why there is nothing to show.
api.renderTrafficHeaders(panel, {id: 'm', origin: 'live', method: 'GET', path: 'echo.test', status: 200, hostOnly: true, headerBlocks: []}, () => {});
assert.match(panel.textContent, /recorded only in content capture sessions/);
api.renderTrafficHeaders(panel, {id: 'l', origin: 'sample', method: 'GET', path: 'x', status: 200}, () => {});
assert.match(panel.textContent, /no native header record/);
// A partial store read must not state that nothing was retained.
api.renderTrafficHeaders(panel, {id: 'p', origin: 'live', method: 'GET', path: 'https://echo.test/a', status: 200, hostOnly: false, headerBlocks: [], recordsPartial: true}, () => {});
assert.match(panel.textContent, /unknown rather than missing/);
assert.doesNotMatch(panel.textContent, /No header record was retained/);
api.renderTrafficHeaders(panel, {id: 'c', origin: 'live', method: 'GET', path: 'https://echo.test/a', status: 200, hostOnly: false, headerBlocks: []}, () => {});
assert.match(panel.textContent, /No header record was retained/, 'A complete read may still state absence');
console.log('PASS Traffic Headers tab: hops newest first, provisional notice, size and SHA-256 checked reads, raw and copy, ' +
  'text-only values, refusal, integrity and not-retained states, metadata-only and legacy rows (DOM model; not rendered QA)');
