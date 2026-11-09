// The shipped Payload tab (apps/research-ui/traffic_payload.js) with the shipped
// tokenizer, shared code view and body record helpers in a DOM model: query
// parameters, JSON tree and source laid out by Oxc or the in-page layout, raw
// ranges of laid-out tokens, form, multipart, text, binary, empty and missing
// bodies, capture limits, digest and load failures, a 5 MiB JSON body,
// keyboard, find and copy. Captured markup must stay text. Not rendered QA.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createContext, runInContext} from 'node:vm';

const require = createRequire(import.meta.url);
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const ui = new URL('../apps/research-ui/', import.meta.url);
const {window, document} = parseHTML('<!doctype html><div id="panel"></div>');
const copied = [];
const context = createContext({window, document, URL, TextDecoder, TextEncoder, Uint8Array, console, AbortController, setTimeout, clearTimeout,
  navigator: {clipboard: {writeText: async text => {copied.push(text);}}}});
for (const file of ['source_syntax.js', 'source_format.js', 'code_view.js', 'traffic_view.js', 'traffic_payload.js']) {
  runInContext(await readFile(new URL(file, ui), 'utf8'), context, {filename: file});
}
// get_source_format replies queued by the test; the in-page layout runs without a worker.
const formatReplies = [], formatReads = [];
context.formatRequest = async url => {formatReads.push(url); return formatReplies.shift()(url);};
runInContext(`trafficPayloadLayouts = createCodeLayouts({request: formatRequest, layouts: createSourceLayoutWorker({spawn: null, defer: callback => callback()}),
  onChange: () => trafficPayloadShown?.relayout?.()});
globalThis.api = {renderTrafficPayload, trafficPayloadPairs, trafficPayloadMultipart};`, context);
const {api} = context;
const panel = document.getElementById('panel');
// The DOM model has no focus tracking; record what the view focuses.
let focused = null;
window.HTMLElement.prototype.focus = function focus() {focused = this;};
const encoder = new TextEncoder();
const markup = '<img src=x onerror="window.__payloadInjected=1">';

const record = (extra = {}) => ({kind: 'bytes', state: 'captured', contentCapture: true, lengthPartial: false, contentType: 'application/json',
  contentTypeOmitted: false, bodyLength: '64', capturedLength: '64', elementCount: 1, sha256: 'ab'.repeat(32), digestSizeLimit: false,
  artifactId: '901', sequenceNumber: '12', sessionId: '7', processId: 42, ...extra});
let serial = 0;
const request = (body, extra = {}) => ({id: `r${serial++}`, origin: 'live', method: 'POST', status: 200, hostOnly: false, targetKind: 'url',
  host: 'api.test', target: '/collect', path: 'https://api.test/collect', tabId: '1', body, ...extra});
const ready = (content, extra = {}) => {
  const bytes = typeof content === 'string' ? encoder.encode(content) : content;
  return {status: 'ready', bytes, text: new TextDecoder().decode(bytes), lossy: false, verified: true, ...extra};
};
const render = (row, view) => api.renderTrafficPayload(panel, row, view);
const text = selector => panel.querySelector(selector)?.textContent ?? '';
const all = selector => [...panel.querySelectorAll(selector)];
const section = name => panel.querySelector(`[data-section="${name}"]`);
const event = (target, type, extra = {}) => {
  const created = new window.Event(type, {bubbles: true, cancelable: true});
  Object.assign(created, extra);
  target.dispatchEvent(created);
  return created;
};
const press = (target, key, extra = {}) => event(target, 'keydown', {key, ...extra});
const click = target => event(target, 'click');
const button = label => all('button').find(node => node.textContent === label || node.getAttribute('aria-label') === label);
const settle = () => new Promise(resolve => setTimeout(resolve, 0));
const assertInert = context => {
  assert.equal(all('img, svg, script').length, 0, `${context}: captured markup created no element`);
  assert.equal(window.__payloadInjected, undefined, `${context}: captured markup never ran`);
};

// Query string parameters come from the captured target, decoded or as sent.
assert.deepEqual(JSON.parse(JSON.stringify(api.trafficPayloadPairs('a=1&&b&c=%ZZ&d=x+y%20z'))), [
  {name: 'a', value: '1', decodedName: 'a', decodedValue: '1'}, {name: 'b', value: '', decodedName: 'b', decodedValue: ''},
  {name: 'c', value: '%ZZ', decodedName: 'c', decodedValue: null}, {name: 'd', value: 'x+y%20z', decodedName: 'd', decodedValue: 'x y z'}]);
const target = `/collect?v=1&tid=G-1&cid=a%20b&s=${encodeURIComponent(markup)}`;
render(request(null, {target, path: `https://api.test${target}`}), null);
assert.match(text('[data-section="query"] h2'), /Query String Parameters4/);
const queryRows = () => all('[data-section="query"] .traffic-payload-pair:not(.traffic-payload-columns)').map(row => row.textContent);
assert.deepEqual(queryRows(), ['v1', 'tidG-1', 'cida b', `s${markup}`]);
assertInert('decoded query');
click(button('Encoded'));
assert.deepEqual(queryRows().slice(2), ['cida%20b', `s${encodeURIComponent(markup)}`]);
click(button('Decoded'));
assert.match(text('[data-section="payload"]'), /No body record for this request/);
assert.equal(panel.querySelector('.traffic-payload-notices'), null, 'an uncut target has no notice');
const firstQueryRow = panel.querySelector('[data-section="query"] [data-index="2"]');
click(firstQueryRow);
click(button('Copy value'));
click(button('Copy as JSON'));
await settle();
assert.deepEqual(copied.splice(0), ['a b', '{\n  "name": "cid",\n  "value": "a b"\n}']);
render(request(null, {target: '/collect?v=1&q=abc', urlTruncated: true, targetLength: 412}), null);
assert.match(text('.traffic-payload-notices'), /first part of the 412-byte path and query was captured; later parameters are missing/);
assert(panel.firstElementChild.classList.contains('traffic-payload-notices'), 'cut targets are noted at the top');
render(request(null, {hostOnly: true, target: undefined, path: 'api.test'}), null);
assert.match(text('[data-section="query"]'), /recorded only in content capture sessions/);
render(request(null), null);
assert.equal(section('query'), null, 'a target without a query has no query section');
render(request(null, {target: '/collect?'}), null);
assert.match(text('[data-section="query"]'), /query string is empty/);
// A retained full target supplies the whole query; only an unavailable one keeps a notice.
const fullQuery = `/collect?${Array.from({length: 40}, (_, index) => `param${index}=value${index}`).join('&')}`;
const truncated = request(null, {target: fullQuery.slice(0, 116), path: `https://api.test${fullQuery.slice(0, 116)}`, urlTruncated: true,
  targetLength: fullQuery.length, fullTarget: {retention: 'retained'}});
api.renderTrafficPayload(panel, truncated, null, {status: 'loading'});
assert.match(text('.traffic-payload-notices'), /reading the retained full target/);
assert(queryRows().length < 40, 'the prefix shows the captured parameters while the target loads');
api.renderTrafficPayload(panel, truncated, null, {status: 'ready', complete: true, text: fullQuery, url: 'https://api.test', loaded: fullQuery.length});
assert.equal(queryRows().length, 40, 'the retained full target gives every parameter');
assert.equal(queryRows().at(-1), 'param39value39');
assert.equal(panel.querySelector('.traffic-payload-notices'), null, 'a whole target has no cut notice');
api.renderTrafficPayload(panel, truncated, null, {status: 'missing', unknown: true});
assert.match(text('.traffic-payload-notices'), /not in the scanned range of the artifact manifest/);
api.renderTrafficPayload(panel, truncated, null, {status: 'refused', reason: 'x'});
assert.match(text('.traffic-payload-notices'), /was not retained by the artifact receiver/);
api.renderTrafficPayload(panel, truncated, null, {status: 'error', error: 'timed out after 10 seconds'});
assert.match(text('.traffic-payload-notices'), /could not be read: timed out after 10 seconds/);
console.log('PASS Payload query parameters: decoded and encoded, inert markup, copy, cut targets noted at the top, host-only and empty queries, the full retained target parsed whole');

// JSON: a tree that starts with the root open, plus pretty-printed source.
const json = `{"sitekey":"site-key","note":${JSON.stringify(markup)},"nested":{"list":[1,2.5,true,null],"deep":{"x":"y"}},"big":12345678901234567890}`;
const jsonRequest = request(record({bodyLength: String(json.length), capturedLength: String(json.length)}));
render(jsonRequest, ready(json));
const tree = () => panel.querySelector('.traffic-payload-tree');
const treeRows = () => all('.traffic-payload-tree [role="treeitem"]');
assert.equal(tree().getAttribute('role'), 'tree');
assert.deepEqual(treeRows().map(row => row.textContent), ['{…} 4 keys', 'sitekey: "site-key"', `note: ${JSON.stringify(markup)}`,
  'nested: {…} 2 keys', 'big: 12345678901234567000']);
assert.equal(treeRows()[0].getAttribute('aria-expanded'), 'true');
assert.equal(treeRows()[3].getAttribute('aria-expanded'), 'false');
assert.match(treeRows()[4].querySelector('.traffic-payload-leaf').title, /Beyond exact double precision/);
assertInert('JSON tree');
assert.equal(treeRows().filter(row => row.getAttribute('tabindex') === '0').length, 1, 'one tree row is in the Tab order');
// Arrow keys move, expand and collapse; focus follows the selected row.
press(treeRows()[0], 'ArrowDown');
press(treeRows()[1], 'ArrowDown');
press(treeRows()[2], 'ArrowDown');
assert.equal(treeRows()[3].getAttribute('aria-selected'), 'true');
press(treeRows()[3], 'ArrowRight');
assert.equal(treeRows()[3].getAttribute('aria-expanded'), 'true', 'Right expands');
assert.deepEqual(treeRows().slice(4, 6).map(row => row.textContent), ['list: Array(4)', 'deep: {…} 1 key']);
assert.equal(focused?.textContent, 'nested: {…} 2 keys', 'focus stays on the expanded row');
assert.equal(focused?.getAttribute('tabindex'), '0');
press(treeRows()[3], 'ArrowRight');
assert.equal(treeRows()[4].getAttribute('aria-selected'), 'true', 'Right on an open row moves to its first child');
press(treeRows()[4], 'Enter');
assert.deepEqual(treeRows().slice(5, 9).map(row => row.textContent), ['0: 1', '1: 2.5', '2: true', '3: null']);
press(treeRows()[5], 'ArrowLeft');
assert.equal(treeRows()[4].getAttribute('aria-selected'), 'true', 'Left on a leaf moves to its parent');
press(treeRows()[4], 'ArrowLeft');
assert.equal(treeRows()[4].getAttribute('aria-expanded'), 'false', 'Left collapses');
assert.equal(treeRows()[4].getAttribute('tabindex'), '0');
click(button('Copy value'));
click(button('Copy as JSON'));
await settle();
assert.deepEqual(copied.splice(0).map(value => JSON.parse(value)), [[1, 2.5, true, null], [1, 2.5, true, null]]);
// Polling with the same record and view keeps the DOM, so expansion and focus survive.
const keptTree = tree();
render(jsonRequest, ready(json));
assert.equal(tree(), keptTree, 'an unchanged body is not rebuilt');
click(button('Source'));
const sourceLines = () => all('.traffic-payload-lines .traffic-payload-line').map(row => row.textContent);
assert.deepEqual(sourceLines(), [json], 'the body shows as sent until its layout settles');
assert.match(text('[data-section="payload"]'), /Formatting…/);
await settle();
assert.deepEqual(sourceLines().slice(0, 3), ['{', '  "sitekey": "site-key",', `  "note": ${JSON.stringify(markup)},`]);
assert.equal(formatReads.length, 0, 'a body without a catalog artifact is laid out in the page');
assert(panel.querySelector('.traffic-payload-lines .syntax-string'), 'source is syntax-colored');
assertInert('JSON source');
assert(panel.querySelector('.traffic-payload-lines').classList.contains('is-wrapped'));
click(button('Wrap'));
assert(!panel.querySelector('.traffic-payload-lines').classList.contains('is-wrapped'), 'Wrap toggles');
click(button('Wrap'));
click(button('Copy value'));
await settle();
assert.equal(copied.pop(), json, 'Copy value in Source copies the body as sent');
click(button('Parsed'));
console.log('PASS Payload JSON: root-open tree, Arrow keys move, expand and collapse with one Tab stop, copy, pretty-printed colored source, wrap');

// Find covers every section, counts matches and reveals collapsed nodes.
const find = () => panel.querySelector('.traffic-payload-find');
find().value = 'X';
event(find(), 'input');
assert.equal(text('.traffic-payload-matches'), '1 of 2');
assert.equal(text('.traffic-payload-tree .is-current'), `note: ${JSON.stringify(markup)}`);
assert.equal(treeRows().find(row => row.textContent === 'x: "y"'), undefined, 'the second match is still collapsed');
press(find(), 'Enter');
assert.equal(text('.traffic-payload-matches'), '2 of 2');
assert.equal(text('.traffic-payload-tree .is-current'), 'x: "y"', 'Enter reveals a match inside a collapsed object');
press(find(), 'Enter', {shiftKey: true});
assert.equal(text('.traffic-payload-matches'), '1 of 2');
click(button('Source'));
await settle();
assert.equal(text('.traffic-payload-matches'), '1 of 2');
assert.deepEqual(all('.traffic-payload-lines mark').map(mark => mark.textContent), ['x', 'x']);
assert.equal(all('.traffic-payload-lines mark.is-current').length, 1);
press(find(), 'Escape');
assert.equal(all('.traffic-payload-lines mark').length, 0, 'Escape clears find');
click(button('Parsed'));
console.log('PASS Payload find: counts, next and previous, reveals collapsed tree nodes, marks source text, Escape clears');

// A retained JSON body uses the backend Oxc layout, whose tokens map to exact raw ranges; a refused layout falls back with its reason.
{
  const sha = 'cd'.repeat(32), body = '{"a":[1,2],"b":{"c":"d"}}', laid = '{ "a": [1, 2], "b": { "c": "d" } }';
  const artifact = {artifact_id: '902', session_id: '7', kind: 'request_body', mime_type: 'application/json', url: 'https://api.test/collect',
    sha256: sha, byte_size: body.length};
  const document = (extra = {}) => url => ({ok: true, status: 200, json: async () => ({schema: 'source-format-v1', mapping: 'whitespace-only',
    source: {artifact_id: '902', sha256: sha}, language: 'json', ...extra})});
  formatReplies.push(document({status: 'formatted', text: laid}));
  const oxcRequest = request(record({artifactId: '902', bodyLength: String(body.length), capturedLength: String(body.length)}));
  render(oxcRequest, ready(body, {artifact}));
  click(button('Source'));
  await settle();
  assert.match(formatReads.at(-1), /^\/api\/source-format\?session_id=7&artifact_id=902&language=json$/);
  assert.deepEqual(sourceLines(), [laid]);
  assert.doesNotMatch(text('[data-section="payload"]'), /Whitespace layout|Formatting/);
  const token = all('.traffic-payload-lines .syntax-key').find(node => node.textContent === 'c');
  click(token);
  const raw = body.indexOf('"c"') + 1;
  assert.equal(text('.code-view-raw'), `Line 1, Column ${laid.indexOf('"c"') + 2} · raw 1:${raw + 1}–1:${raw + 2} (offsets ${raw}–${raw + 1})`);
  formatReplies.push(document({status: 'unavailable', reason: 'parse-failed', text: null}));
  render(request(record({artifactId: '903'})), ready(body, {artifact: {...artifact, artifact_id: '903', sha256: 'ef'.repeat(32)}}));
  await settle();
  assert.match(text('[data-section="payload"]'), /Formatter response does not match this artifact/);
  const refused = {...artifact, artifact_id: '904', sha256: '12'.repeat(32)};
  formatReplies.push(url => ({ok: true, status: 200, json: async () => ({schema: 'source-format-v1', mapping: 'whitespace-only',
    source: {artifact_id: '904', sha256: refused.sha256}, status: 'unavailable', reason: 'parse-failed', text: null})}));
  render(request(record({artifactId: '904'})), ready(body, {artifact: refused}));
  await settle();
  assert.match(text('[data-section="payload"]'), /Whitespace layout: Oxc could not parse this file\./);
  assert.equal(sourceLines()[0], '{', 'the in-page layout is shown instead');
  click(button('Parsed'));
}
console.log('PASS Payload source layout: Oxc layout of a retained JSON body by exact artifact and language, token raw range, failed and refused layouts fall back to the in-page layout with the reason');

// Large containers expand in ranges of at most 100 rows.
const array = JSON.stringify(Array.from({length: 25000}, (_, index) => index));
render(request(record()), ready(array));
assert.deepEqual(treeRows().map(row => row.textContent), ['Array(25000)', '[0 … 9999]', '[10000 … 19999]', '[20000 … 24999]']);
press(treeRows()[3], 'ArrowRight');
assert.equal(treeRows().length, 4 + 50);
assert.equal(treeRows()[4].textContent, '[20000 … 20099]');
press(treeRows()[4], 'ArrowRight');
assert.equal(treeRows().length, 4 + 50 + 100);
assert.equal(treeRows()[5].textContent, '20000: 20000');
console.log('PASS Payload JSON ranges: 25,000 items open as three ranges, then 50, then 100 rows');

// Forms and multipart bodies parse; their source stays available.
render(request(record({contentType: 'application/x-www-form-urlencoded'})), ready(`a=1&b=x+y&bad=%ZZ&m=${encodeURIComponent(markup)}`));
const formRows = () => all('[data-section="payload"] .traffic-payload-pair:not(.traffic-payload-columns)');
assert.deepEqual(formRows().map(row => row.textContent), ['a1', 'bx y', 'bad%ZZ', `m${markup}`]);
assert.match(formRows()[2].title, /Not valid percent-encoding/);
assertInert('form');
click(button('Source'));
assert.deepEqual(sourceLines(), [`a=1&b=x+y&bad=%ZZ&m=${encodeURIComponent(markup)}`]);
click(button('Parsed'));
const boundary = '----WebKitFormBoundaryP4yl0ad';
const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
const multipart = new Uint8Array([...encoder.encode(`--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\n${markup}\r\n` +
  `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="a \\"b\\".png"\r\nContent-Type: image/png\r\n\r\n`), ...png,
  ...encoder.encode(`\r\n--${boundary}--\r\n`)]);
const parsedParts = api.trafficPayloadMultipart(multipart);
assert.equal(parsedParts.boundary, boundary);
assert.equal(parsedParts.closed, true);
assert.deepEqual(JSON.parse(JSON.stringify(parsedParts.parts)), [
  {name: 'title', filename: null, type: null, size: encoder.encode(markup).length, value: markup, cut: false},
  {name: 'file', filename: 'a "b".png', type: 'image/png', size: 10, value: null, cut: false}]);
render(request(record({contentType: 'multipart/form-data', bodyLength: String(multipart.length), capturedLength: String(multipart.length)})),
  ready(multipart, {lossy: true}));
const partRows = () => all('.traffic-payload-parts [role="listitem"]').map(row => row.textContent);
assert.deepEqual(partRows(), [`title${encoder.encode(markup).length} bytes${markup}`, 'filefile a "b".png · image/png · 10 bytes']);
assertInert('multipart');
click(button('Source'));
assert.match(text('[data-section="payload"]'), /shown as hex and never interpreted/);
assert.match(sourceLines()[0], /^00000000 {2}2d 2d 2d 2d/);
click(button('Parsed'));
const cut = multipart.subarray(0, multipart.length - 20);
assert.equal(api.trafficPayloadMultipart(cut).parts.at(-1).cut, true, 'a part without its delimiter is cut');
render(request(record({contentType: 'multipart/form-data'})), ready('no boundary line'));
assert.match(text('[data-section="payload"]'), /boundary could not be read from the first line/);
assert.equal(button('Parsed'), undefined, 'an unreadable multipart body has only its source');
console.log('PASS Payload form and multipart: fields, undecodable values flagged, boundary from the first line, file parts sized, binary source as hex');

// Plain text is colored by its type and wraps; binary is only hex.
render(request(record({contentType: 'text/plain'})), ready(`line one\r\n${markup}`));
assert.equal(button('Parsed'), undefined);
assert.deepEqual(sourceLines(), ['line one', markup]);
assert(button('Wrap'));
assertInert('text');
render(request(record({contentType: 'application/octet-stream'})), ready(Uint8Array.from([0x3c, 0x62, 0x3e, 0, 255])));
assert.equal(button('Wrap'), undefined, 'hex rows do not wrap');
assert.deepEqual(sourceLines().map(line => line.replace(/ +/g, ' ')), ['00000000 3c 62 3e 00 ff |<b>..|']);
click(button('Copy as JSON'));
await settle();
assert.match(text('.traffic-payload-status'), /Binary payloads have no JSON form/);
render(request(record({contentType: null})), ready('{"inferred":true}'));
assert.equal(treeRows()[1].textContent, 'inferred: true', 'a JSON-shaped body without a JSON type still parses');
console.log('PASS Payload text and binary: colored wrapped text, hex only for binary, no JSON copy for binary, untyped JSON parses');

// States without bytes say why, and Capture details keeps the record facts collapsed.
for (const [body, pattern] of [
  [undefined, /This row has no native body record/],
  [null, /No body record for this request/],
  [{malformed: true}, /malformed and was not interpreted/],
  [record({kind: 'none', state: 'no_body', bodyLength: '0', capturedLength: '0', elementCount: 0, sha256: null, contentType: null, artifactId: '0'}), /No request body/],
  [record({state: 'empty', bodyLength: '0', capturedLength: '0', artifactId: '0'}), /Empty body \(0 bytes\)/],
  [record({state: 'metadata_only', contentCapture: false, capturedLength: '0', artifactId: '0'}), /content capture was off/],
  [record({kind: 'file', state: 'not_captured_body_kind', lengthPartial: true, sha256: null, capturedLength: '0', artifactId: '0'}), /file upload parts were described, not read/],
  [record({kind: 'chunked_data_pipe', state: 'not_captured_read_incomplete', lengthPartial: true, read: true, sha256: null, capturedLength: '0', artifactId: '0'}), /a file, blob or stream part was not read whole/],
]) {
  render(body === undefined ? {...request(null), origin: 'sample'} : request(body), null);
  assert.match(text('[data-section="payload"]'), pattern);
  assert.equal(panel.querySelector('.traffic-payload-view'), null, 'no payload view without retained bytes');
  assert.equal(panel.querySelector('.traffic-payload-tools'), null, 'no find or copy without content');
}
render(jsonRequest, ready(json));
const details = panel.querySelector('details.traffic-payload-details');
assert.equal(details.hasAttribute('open'), false, 'Capture details starts collapsed');
assert.match(details.textContent, /SHA-256(ab){32}Body kindIn-memory bytes · 1 partRetained.*Artifact ID901/);
assert.doesNotMatch(panel.textContent, /artifact URL/i, 'the duplicate URL row is gone');
console.log('PASS Payload states without bytes: no record, missing, malformed, no body, empty, metadata-only, file; Capture details collapsed without the URL row');

// The capture limit, a digest mismatch and a failed re-read.
const prefix = json.slice(0, 40);
render(request(record({state: 'captured_truncated', bodyLength: '300000', capturedLength: '262144'})), ready(prefix));
assert.match(text('.traffic-payload-notices'), /Retained prefix: 262,144 bytes of 300,000 bytes/);
assert.match(text('[data-section="payload"]'), /retained prefix ends before the JSON does, so it is shown as sent/);
assert.deepEqual(sourceLines(), [prefix]);
render(jsonRequest, ready(json));
render(jsonRequest, {status: 'loading'});
assert.match(text('[data-section="payload"]'), /Showing the last read copy/);
assert(tree(), 'a pending re-read keeps the last good view');
render(jsonRequest, {status: 'error', error: 'the artifact store returned 503', retryable: true});
assert.match(text('[data-section="payload"]'), /could not be read: the artifact store returned 503\. It is read again on the next refresh\. Showing the last read copy\./);
assert(tree(), 'a transient failure keeps the last good view');
render(jsonRequest, {status: 'missing'});
assert(tree(), 'an artifact that left the catalog keeps the last good view');
render(jsonRequest, {status: 'error', error: 'its bytes do not match the retained SHA-256', retryable: false});
assert.match(text('[data-section="payload"]'), /do not match the retained SHA-256\./);
assert.equal(panel.querySelector('.traffic-payload-view'), null, 'a digest mismatch shows no bytes, even ones read before');
render(request(record()), {status: 'loading'});
assert.match(text('[data-section="payload"]'), /Loading the retained body/);
render(request(record()), {status: 'refused', reason: 'sensitive_capture_disabled'});
assert.match(text('[data-section="payload"]'), /not started for sensitive capture/);
render(request(record()), ready('{}', {verified: false}));
assert.match(text('[data-section="payload"]'), /digest could not be rechecked/);
// Ranged reads: a prefix stays source with the next-range control until every byte is read.
const ranged = request(record({bodyLength: '300000', capturedLength: '300000'}));
render(ranged, ready(prefix, {verified: false, complete: false, loaded: 262144, total: 300000, key: '7:901:x'}));
assert.match(text('[data-section="payload"]'), /Showing the first 262,144 bytes of 300,000 bytes retained/);
assert.equal(panel.querySelector('.traffic-body-more')?.dataset.contentKey, '7:901:x');
assert.doesNotMatch(text('[data-section="payload"]'), /not valid JSON/, 'a partly read body is not judged invalid');
render(ranged, ready(json, {complete: true, loaded: json.length, total: json.length}));
assert.equal(panel.querySelector('.traffic-body-more'), null, 'a complete body has no next-range control');
assert(tree(), 'the whole body parses once every byte is read');
console.log('PASS Payload limits and failures: cut prefix noted at the top and shown as sent, ranged reads continue to the whole body, failed or pending re-reads keep the last view, digest mismatch shows none');

// A 5 MiB JSON body: parsing and every interaction render a bounded number of rows.
const items = [];
for (let index = 0, size = 0; size < 5 * 1024 * 1024; index += 1) {
  const item = JSON.stringify({id: index, name: `item-${index}`, tags: ['a', 'b'], nested: {x: index * 1.5, ok: true, v: null}});
  items.push(item);
  size += item.length + 1;
}
items[items.length - 7] = items.at(-7).replace('"ok":true', '"needle":"deep-match"');
const large = `{"items":[${items.join(',')}]}`;
assert(large.length >= 5 * 1024 * 1024);
const largeBytes = encoder.encode(large);
const largeRequest = request(record({bodyLength: String(largeBytes.length), capturedLength: String(largeBytes.length)}));
let started = performance.now();
render(largeRequest, {status: 'ready', bytes: largeBytes, text: large, lossy: false, verified: true});
const opened = performance.now() - started;
assert(all('.traffic-payload-tree [role="treeitem"]').length <= 3, 'only the root and its key render at first');
press(treeRows()[1], 'ArrowRight');
assert(treeRows().length <= 2 + rangeCount(items.length));
started = performance.now();
find().value = 'deep-match';
event(find(), 'input');
const found = performance.now() - started;
assert.equal(text('.traffic-payload-matches'), '1 of 1');
assert.equal(text('.traffic-payload-tree .is-current'), 'needle: "deep-match"');
assert(panel.querySelectorAll('*').length < 2500, `the DOM stays bounded: ${panel.querySelectorAll('*').length} elements`);
started = performance.now();
click(button('Source'));
await settle();
const source = performance.now() - started;
assert(all('.traffic-payload-lines .traffic-payload-line').length <= 400, 'source renders its rows in blocks');
assert(all('.traffic-payload-lines mark.is-current').length === 1, 'the source match is revealed');
for (const [label, elapsed] of [['open', opened], ['find', found], ['source', source]]) {
  assert(elapsed < 4000, `5 MiB ${label} took ${Math.round(elapsed)} ms`);
}
click(button('Parsed'));
console.log(`PASS Payload 5 MiB JSON: open ${Math.round(opened)} ms, find ${Math.round(found)} ms, source ${Math.round(source)} ms, DOM bounded (DOM model; rendered timing is the packaged-app check)`);

function rangeCount(count) {
  let step = 100;
  while (count / step > 100) step *= 100;
  return Math.ceil(count / step);
}
