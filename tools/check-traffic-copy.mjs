#!/usr/bin/env node
// Copy as cURL and Copy as fetch, run for real: each generated command is
// executed by curl in a shell, or evaluated as fetch, against a loopback
// server that records exactly what arrives.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {createServer} from 'node:http';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const {trafficCurl, trafficFetch, trafficCopyGaps, trafficHarEntry, trafficClipboardWrite} = require('../apps/research-ui/traffic_copy.js');

const received = [];
const server = createServer((request, response) => {
  const chunks = [];
  request.on('data', chunk => chunks.push(chunk));
  request.on('end', () => {
    received.push({method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks)});
    response.end('ok');
  });
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

function shell(command) {
  return new Promise((resolve, reject) => execFile('/bin/sh', ['-c', `${command} --silent --show-error --output /dev/null`],
    {timeout: 30000}, (error, stdout, stderr) => error ? reject(new Error(`${error.message}\n${stderr}`)) : resolve(stdout)));
}
async function run(entry) {
  received.length = 0;
  await shell(trafficCurl(entry));
  const viaCurl = received.pop();
  // The copied text is a complete statement: evaluated as written, it sends the request.
  const response = await new Function(`return ${trafficFetch(entry).replace(/;$/, '')}`)();
  await response.text();
  const viaFetch = received.pop();
  return [viaCurl, viaFetch];
}
const header = (name, value, extra = {}) => ({name, value, ...extra});

// Quotes, a newline and a captured cookie travel as captured; pseudo and
// framing headers are left for the client to compute.
const tricky = `it's "quoted" $HOME \`date\` \\ done`;
// WHATWG URLs percent-encode ' in a query, so the target is written that way.
const query = encodeURIComponent(tricky).replaceAll("'", '%27');
const put = {
  _reb: {hop: 0, outcome: 'complete', url_complete: true},
  request: {method: 'PUT', url: `${origin}/items/7?q=${query}&n=1`, headers: [
    header(':authority', '127.0.0.1'), header('Host', 'stale.example'), header('Content-Length', '999'), header('Connection', 'close'),
    header('X-Quote', tricky), header('Cookie', 'sid=s3cr3t; theme=dark'), header('Content-Type', 'application/json')],
  postData: {mimeType: 'application/json', text: `{"note":"${tricky.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}",\n"n":1}`, _reb_state: 'complete'}}
};
for (const sent of await run(put)) {
  assert.equal(sent.method, 'PUT');
  assert.equal(sent.url, `/items/7?q=${query}&n=1`);
  assert.equal(sent.headers['x-quote'], tricky, 'shell metacharacters reach the server as text');
  assert.equal(sent.headers.cookie, 'sid=s3cr3t; theme=dark');
  assert.equal(sent.headers.host, `127.0.0.1:${server.address().port}`, 'the client computes Host from the URL');
  assert.equal(sent.body.toString(), put.request.postData.text);
  assert.equal(sent.headers['content-length'], String(Buffer.byteLength(put.request.postData.text)));
}
assert.doesNotMatch(trafficCurl(put), /-X 'PUT'.*-X/s);
assert.match(trafficCurl(put), /^curl '/);

// A POST with a body needs no -X; a GET without one sends no body.
const post = {_reb: {hop: 0}, request: {method: 'POST', url: `${origin}/form`, headers: [header('Content-Type', 'text/plain')],
  postData: {mimeType: 'text/plain', text: 'a=1&b=2', _reb_state: 'complete'}}};
assert.doesNotMatch(trafficCurl(post), / -X /);
for (const sent of await run(post)) assert.deepEqual([sent.method, sent.body.toString()], ['POST', 'a=1&b=2']);
const get = {_reb: {hop: 0}, request: {method: 'GET', url: `${origin}/plain`, headers: [header('Accept', '*/*')]}};
assert.equal(trafficCurl(get), `curl '${origin}/plain' \\\n  -H 'Accept: */*'`);
for (const sent of await run(get)) assert.deepEqual([sent.method, sent.body.length], ['GET', 0]);

// Bytes that are not text go through the shell's base64 decoder into stdin.
const bytes = Buffer.from([0, 1, 2, 255, 254, 10, 13, 39, 34]);
const binary = {_reb: {hop: 0}, request: {method: 'POST', url: `${origin}/upload`, headers: [header('Content-Type', 'application/octet-stream')],
  postData: {mimeType: 'application/octet-stream', text: '', _reb_base64: bytes.toString('base64'), _reb_state: 'complete'}}};
for (const sent of await run(binary)) assert.deepEqual(sent.body, bytes, 'binary bodies arrive byte for byte');

// What a copy cannot carry is said, not hidden.
assert.deepEqual(trafficCopyGaps(put), []);
const missing = {_reb: {hop: 0, url_complete: false}, request: {method: 'POST', url: `${origin}/cut`,
  headers: [header('Authorization', '', {_reb_withheld: true, _reb_value_bytes: 12})], postData: {mimeType: '', text: '', _reb_state: 'not_captured'}}};
assert.deepEqual(trafficCopyGaps(missing), ['credential values were withheld', 'the body was not retained whole (not captured), so the copy sends none', 'the URL is not the whole captured target']);
assert.doesNotMatch(trafficCurl(missing), /Authorization/, 'a withheld value is not copied as an empty header');
assert.deepEqual(trafficCopyGaps({_reb: {hop: 0}, request: {method: 'GET', url: origin, headers: [], postData: {text: '', _reb_state: 'no_body'}}}), []);
assert.deepEqual(trafficCopyGaps({_reb: {hop: 0}, request: {method: 'POST', url: origin, headers: [], postData: {text: '', _reb_state: 'captured'}}}),
  ['the captured body could not be read, so the copy sends none']);

// The row's first hop, read from the backend with credential values asked for.
const answers = [];
const fetcher = (url, init) => { answers.push([url, init.cache]); return Promise.resolve(next); };
let next = {ok: true, status: 200, json: async () => ({log: {entries: [{_reb: {hop: 1}}, {_reb: {hop: 0}, request: get.request}], _reb: {complete: true}}})};
assert.equal((await trafficHarEntry('R 7', fetcher)).request.url, get.request.url);
assert.deepEqual(answers.at(-1), ['/api/requests/har?rows=R+7&credential_values=1', 'no-store']);
next = {ok: true, status: 200, json: async () => ({log: {entries: [{_reb: {outcome: 'unlinked'}, request: get.request}], _reb: {complete: true}}})};
assert.equal((await trafficHarEntry('R8', fetcher))._reb.outcome, 'unlinked', 'an unlinked row is its own single entry');
next = {ok: true, status: 200, json: async () => ({log: {entries: [], _reb: {complete: false, error: 'the store was replaced'}}})};
await assert.rejects(trafficHarEntry('R9', fetcher), /the store was replaced/);
next = {ok: false, status: 404, json: async () => ({error: 'No request row has ID R9'})};
await assert.rejects(trafficHarEntry('R9', fetcher), /No request row has ID R9/);
next = {ok: false, status: 502, json: async () => { throw new SyntaxError('not JSON'); }};
await assert.rejects(trafficHarEntry('R9', fetcher), /the backend returned 502/);

// The clipboard write starts at once and takes the text when it arrives. Like
// WebKit, this clipboard rejects a write whose text failed as NotAllowedError;
// the copy reports the text's own failure, and a refused write as refused.
const written = [];
let refuse = false;
globalThis.ClipboardItem = class { constructor(items) { this.items = items; } };
Object.defineProperty(globalThis, 'navigator', {configurable: true, value: {clipboard: {write: async ([item]) => {
  const blob = await item.items['text/plain'].catch(() => null);
  if (!blob || refuse) throw new DOMException('The request is not allowed by the user agent or the platform in the current context.', 'NotAllowedError');
  written.push(await blob.text());
}}}});
await trafficClipboardWrite(Promise.resolve('curl https://copied.test'));
assert.deepEqual(written, ['curl https://copied.test']);
await assert.rejects(trafficClipboardWrite(Promise.reject(new TypeError('the archive is incomplete'))), /the archive is incomplete/);
refuse = true;
await assert.rejects(trafficClipboardWrite(Promise.resolve('curl https://refused.test')), {name: 'NotAllowedError'});
assert.deepEqual(written, ['curl https://copied.test'], 'a failed or refused write puts nothing on the clipboard');

server.close();
console.log('PASS Copy as cURL and Copy as fetch send the captured method, URL, headers and text or binary body as captured, leave framing to the client, report withheld values, unretained bodies and partial URLs, read the row\'s first hop, and report why a clipboard write failed');
