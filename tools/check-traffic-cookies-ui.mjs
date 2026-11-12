// The shipped Cookies tab (apps/research-ui/traffic_cookies.js) against the
// shipped decoders in a DOM model: hop order, filtered-out request cookies
// with reasons, every response attribute and block reason, sorting, tooltips
// and copy, provenance from a name to the response, script and requests, and
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
const source = await readFile(new URL('../apps/research-ui/traffic_view.js', import.meta.url), 'utf8') +
  await readFile(new URL('../apps/research-ui/traffic_cookies.js', import.meta.url), 'utf8');
const models = await readFile(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
const {decodeScriptCookieRecord} = new Function(`${models}\nreturn {decodeScriptCookieRecord};`)();
const {window, document} = parseHTML('<!doctype html><div id="panel"></div>');
const reads = [], copied = [];
let provenanceAnswer = null;
const blobs = new Map();
let pendingDigests = 0;
const countedCrypto = {subtle: {digest: (...args) => {
  pendingDigests += 1;
  return globalThis.crypto.subtle.digest(...args).finally(() => {pendingDigests -= 1;});
}}};
const context = createContext({
  window, document, location: {protocol: 'http:'}, console, TextDecoder, TextEncoder, Uint8Array, DataView,
  AbortController, Date, setTimeout, clearTimeout, crypto: countedCrypto, CustomEvent: window.CustomEvent,
  state: {events: []}, decodePayload: () => 'sensitive_capture_disabled', decodeScriptCookieRecord,
  navigator: {clipboard: {writeText: async text => {copied.push(text);}}},
  AbortSignal, URLSearchParams,
  fetch: async url => {
    reads.push(url);
    if (url.startsWith('/api/cookie-provenance?')) {
      return provenanceAnswer ? new Response(JSON.stringify(provenanceAnswer)) : new Response('', {status: 503});
    }
    const id = /artifacts\/(\d+)\//.exec(url)[1];
    return blobs.has(id) ? new Response(blobs.get(id)) : new Response('', {status: 404});
  }
});
runInContext(`${source};globalThis.api={trafficCookieList, trafficCookieHops, renderTrafficCookies};`, context);
const {api} = context;
const panel = document.getElementById('panel');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
// SHA-256 runs off the event loop, so no fixed number of turns is sure to outlast
// a digest. Settle once none is pending and the loop has stayed quiet.
const settle = async () => {for (let quiet = 0; quiet < 30;) {await nextTurn(); quiet = pendingDigests ? 0 : quiet + 1;}};

// RBCK layout, protocol/native-network-v3.md.
const cookie = ({exclusions = 0n, warnings = 0n, flags = 1, sameSite = 3, priority = 2, effective = 2, scheme = 2,
  port = 443, expiry = 0n, strings = ['', '', '', '', '', '']}) => {
  const fixed = Buffer.alloc(64);
  fixed.writeBigUInt64LE(exclusions, 0);
  fixed.writeBigUInt64LE(warnings, 8);
  if (flags & 1) {
    fixed.writeBigInt64LE(expiry, 16);
    Object.assign(fixed, {});
    fixed[25] = sameSite; fixed[26] = priority; fixed[27] = effective; fixed[28] = scheme;
    fixed.writeInt32LE(port, 32);
  }
  fixed[24] = flags;
  const parts = strings.map(text => Buffer.from(text));
  parts.forEach((part, index) => fixed.writeUInt32LE(part.length, 36 + index * 4));
  return Buffer.concat([fixed, ...parts]);
};
const list = (direction, cookies) => {
  const header = Buffer.alloc(16);
  header.write('RBCK', 0, 'latin1');
  header.writeUInt16LE(1, 4);
  header[6] = direction === 'sent' ? 1 : 2;
  header.writeUInt32LE(cookies.length, 8);
  return Buffer.concat([header, ...cookies.map(cookie)]);
};
let next = 100;
const record = (direction, cookies, extra = {}) => {
  const id = String(next++);
  const bytes = list(direction, cookies);
  blobs.set(id, bytes);
  return {direction, state: 'captured', cookieCount: cookies.length,
    blockedCount: cookies.filter(item => item.exclusions).length, listLength: bytes.length, hop: 0,
    unattributedLists: 0, sha256: sha(bytes), artifactId: id, sequenceNumber: id, sessionId: '7', processId: 42, ...extra};
};

const markup = '<img src=x onerror=alert(1)>';
const sentCookies = [
  {strings: ['sid', `abc${markup}`, '.echo.test', '/', 'https://top.test', ''], flags: 0x3f, expiry: 1700000000000n},
  {strings: ['pref', 'dark', 'echo.test', '/settings', '', ''], exclusions: 1n << 5n, sameSite: 4, priority: 3}];
const receivedCookies = [
  {strings: ['track', '1', 'echo.test', '/', '', 'track=1; SameSite=None'], exclusions: 1n << 8n, sameSite: 2, flags: 0x01},
  {strings: ['', '', '', '', '', 'bad\u0001=1'], exclusions: 1n << 24n, flags: 0}];

// The list parser accepts the exact layout and refuses anything else.
const sample = new Uint8Array(list('sent', sentCookies));
const parsed = api.trafficCookieList(sample, 'sent', 2);
assert.equal(parsed.length, 2);
assert.equal(parsed[0].name, 'sid');
assert.equal(parsed[0].partitionSite, 'https://top.test');
assert.equal(parsed[0].crossSite, true);
assert.equal(parsed[0].sameSite, 'Lax');
assert.equal(parsed[0].expiry, 1700000000000);
assert.deepEqual([...parsed[1].exclusions], ['samesite_strict']);
assert.equal(api.trafficCookieList(sample, 'sent', 3), null);
assert.equal(api.trafficCookieList(sample, 'received', 2), null);
assert.equal(api.trafficCookieList(sample.slice(0, -1), 'sent', 2), null);
assert.equal(api.trafficCookieList(new Uint8Array(list('sent', [{strings: ['a', 'b', '', '', '', 'a=b']}])), 'sent', 1), null,
  'a sent cookie carries no line');
assert.notEqual(api.trafficCookieList(new Uint8Array(list('sent', [{strings: ['a', 'b', '', '/', '', ''], flags: 1, expiry: 1700000000000n}])), 'sent', 1), null,
  'the same cookie with an ordinary expiry parses');
assert.equal(api.trafficCookieList(new Uint8Array(list('sent', [{strings: ['a', 'b', '', '/', '', ''], flags: 1, expiry: 9000000000000000n}])), 'sent', 1), null,
  'an expiry a Date cannot hold is refused, not thrown on render');

// A script write of sid's value, in the renderer record layout.
const write = Buffer.alloc(128);
write.writeUInt16LE(1, 0); write.writeUInt16LE(128, 2);
write[4] = 1; write[5] = 2; write.writeUInt32LE(1, 8);
write.writeUInt32LE(3, 12); write.writeUInt32LE(Buffer.byteLength(`abc${markup}`), 16); write.writeUInt32LE(64, 20);
write[24] = 1; write.writeUInt32LE(77, 28); write.writeUInt32LE(1234, 32);
createHash('sha256').update(`abc${markup}`).digest().copy(write, 72);
write.write('sid', 104, 'latin1');
const scriptEvent = {protocol_version: 3, session_id: '7', sequence_number: '5', monotonic_time_ns: '5', process_id: 9,
  thread_id: 1, tab_id: 0, navigation_id: '0', frame_id: '31', artifact_id: '0', parent_event_id: '0', request_id: '0',
  encoded_data_length: '0', decoded_body_length: '0', status_code: 0, error_code: 0, resource_type: 0, flags: 0,
  payload_truncated: false, category: 'network', type: 'script_cookie', payload_size: 128, payload_encoding: 'hex',
  payload: write.toString('hex')};
assert(decodeScriptCookieRecord(scriptEvent), 'the fixture script record is valid');

const request = {id: 'r', origin: 'live', method: 'GET', path: 'https://echo.test/home', status: 200, hostOnly: false,
  cookieLists: [record('sent', sentCookies), record('received', receivedCookies),
    record('sent', [], {hop: 1, state: 'empty', cookieCount: 0, listLength: 0, artifactId: '0'}),
    {malformed: true, sequenceNumber: '99'}]};
const later = {id: 'later', origin: 'live', method: 'POST', path: 'https://echo.test/api', status: 200,
  cookieLists: [record('sent', [sentCookies[0]])]};
const selected = [];
const opened = [];
const ui = {requests: [request, later], events: [scriptEvent], selectRequest: id => selected.push(id),
  openFrame: frame => opened.push(frame.artifact_id)};
let renders = 0;
const rerender = () => {renders += 1; api.renderTrafficCookies(panel, request, rerender, ui);};
api.renderTrafficCookies(panel, request, rerender, ui);
assert.match(panel.textContent, /Loading retained cookies/);
await settle();
let sections = [...panel.querySelectorAll('details')];
assert.deepEqual(sections.map(section => section.querySelector('summary').firstChild.textContent),
  ['Request cookies · hop 1', 'Response cookies · hop 0', 'Request cookies · hop 0']);
assert.match(panel.textContent, /1 cookie record is malformed and not shown/);
assert.match(sections[0].textContent, /No cookies\./);
// Filtered-out request cookies stay hidden until asked for, then show why.
let sent = sections[2];
assert.equal(sent.querySelectorAll('tbody tr').length, 1);
assert.match(sent.textContent, /Show filtered out request cookies \(1\)/);
assert.equal(panel.querySelectorAll('img').length, 0, 'captured markup is text');
assert(sent.querySelector('.traffic-cookie-col-value').textContent.includes(markup));
assert.equal(sent.querySelector('.traffic-cookie-col-value').title, `abc${markup}`, 'the full value is the tooltip');
assert.equal(sent.querySelector('.traffic-cookie-col-partition').textContent, 'https://top.test');
assert.equal(sent.querySelector('.traffic-cookie-col-expires').textContent, '2023-11-14T22:13:20.000Z');
const box = sent.querySelector('input[type="checkbox"]');
box.checked = true;
box.dispatchEvent(new window.Event('change'));
await settle();
sections = [...panel.querySelectorAll('details')];
sent = sections[2];
assert.equal(sent.querySelectorAll('tbody tr').length, 2);
assert.equal(sent.querySelector('.traffic-cookie-blocked .traffic-cookie-col-blocked').textContent, 'samesite_strict');
assert.match(sent.querySelector('.traffic-cookie-blocked .traffic-cookie-col-blocked').title, /Not sent because it is SameSite=Strict/);
// Every response attribute and the block reason; an unparsed line keeps its text.
const received = sections[1];
const headers = [...received.querySelectorAll('th')].map(cell => cell.textContent);
assert.deepEqual(headers, ['Name', 'Value', 'Domain', 'Path', 'Expires / Max-Age', 'Size', 'HttpOnly', 'Secure', 'SameSite',
  'Partition Key Site', 'Cross Site', 'Priority', 'Blocked because', '']);
const rows = [...received.querySelectorAll('tbody tr')];
assert.match(rows[0].querySelector('.traffic-cookie-col-blocked').title, /This Set-Cookie was blocked because it is SameSite=None without Secure/);
assert.equal(rows[1].querySelector('.traffic-cookie-col-name').textContent, '(unparsed)');
assert.equal(rows[1].querySelector('.traffic-cookie-col-value').textContent, 'bad\u0001=1');
// Sorting toggles direction and is announced.
const byName = () => [...panel.querySelectorAll('details')][2].querySelector('button[data-column="name"]');
byName().dispatchEvent(new window.Event('click'));
await settle();
assert.equal(byName().parentNode.getAttribute('aria-sort'), 'ascending');
assert.deepEqual([...[...panel.querySelectorAll('details')][2].querySelectorAll('tbody .traffic-cookie-name')].map(node => node.textContent), ['pref', 'sid']);
byName().dispatchEvent(new window.Event('click'));
await settle();
assert.equal(byName().parentNode.getAttribute('aria-sort'), 'descending');
assert.deepEqual([...[...panel.querySelectorAll('details')][2].querySelectorAll('tbody .traffic-cookie-name')].map(node => node.textContent), ['sid', 'pref']);
// Copy writes the exact value.
[...panel.querySelectorAll('details')][2].querySelector('.traffic-header-copy').dispatchEvent(new window.Event('click'));
await settle();
assert.deepEqual(copied, [`abc${markup}`]);
const before = renders;
api.renderTrafficCookies(panel, request, rerender, ui);
await settle();
assert.equal(renders, before, 'an unchanged view does not rerender');

// Provenance: the response that set it, the script that wrote it, the requests that sent it.
const sid = [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === 'sid');
sid.dispatchEvent(new window.Event('click'));
await settle();
const provenance = panel.querySelector('.traffic-cookie-provenance');
assert.match(provenance.textContent, /Provenance of sid/);
assert.match(provenance.textContent, /Set by responses \(0\)/);
assert.match(provenance.textContent, /Script access \(1\)document\.cookie set in frame 31, script 77 at character 1234/);
assert.match(provenance.textContent, /Sent with requests \(2\)/);
assert.match(provenance.textContent, /POST https:\/\/echo\.test\/api — the value document\.cookie set wrote/);
[...provenance.querySelectorAll('.traffic-cookie-request')].at(-1).dispatchEvent(new window.Event('click'));
assert.deepEqual(selected, ['later']);
// get_cookie_provenance resolves the write's position; a failed read kept the raw one.
assert(reads.some(url => url === '/api/cookie-provenance?session_id=7&name=sid'));
provenanceAnswer = {script: [{process_id: 9, sequence_number: '5', stack: {frames: [{resolution: {status: 'resolved',
  artifact_id: '21', url: 'https://app.test/static/a.js?v=2', line: 3, column: 3, function_name: 'setSid'}}]}},
  // A service worker's call, beyond the decoded window, names the worker.
  {process_id: 9, sequence_number: '6', api: 'cookieStore.set', count: 1, frame_id: '20823', thread: 'service_worker',
    script_frame: {kind: 'javascript', script_id: 4, position: 12}, stack_digest: null, name_prefix_only: false, stack: null}]};
await new Promise(resolve => setTimeout(resolve, 2100));
api.renderTrafficCookies(panel, request, rerender, ui);
await settle();
const resolved = panel.querySelector('.traffic-cookie-provenance');
assert.match(resolved.textContent, /document\.cookie set in frame 31 at a\.js:3:3 \(setSid\)/);
assert.match(resolved.textContent, /cookieStore\.set in a service worker 20823, script 4 at character 12/);
assert.doesNotMatch(resolved.textContent, /in frame 20823/);
[...resolved.querySelectorAll('.traffic-cookie-request')].find(button => button.textContent === 'Show in Sources')
  .dispatchEvent(new window.Event('click'));
assert.deepEqual(opened, ['21']);
const track = [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === 'track');
track.dispatchEvent(new window.Event('click'));
await settle();
assert.match(panel.querySelector('.traffic-cookie-provenance').textContent,
  /Set by responses \(1\)GET https:\/\/echo\.test\/home — This Set-Cookie was blocked because it is SameSite=None without Secure/);
panel.querySelector('.traffic-cookie-provenance button').dispatchEvent(new window.Event('click'));
await settle();
assert.equal(panel.querySelector('.traffic-cookie-provenance'), null, 'Close removes the provenance');
// Evidence older than the loaded requests comes from the store, and absence names the range that was read.
provenanceAnswer = {set_by: [{request_id: '900', hop: 2, sequence_number: '900', blocked: true, exclusion_reasons: ['secure_only']}],
  sent_with: [{request_id: '901', hop: 0, sequence_number: '901', blocked: false, exclusion_reasons: []}], script: [],
  lists_read: 3, lists_unread: 0, stacks_unresolved: 0, malformed_records: 0};
const prefName = [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === 'pref');
prefName.dispatchEvent(new window.Event('click'));
await settle();
let older = panel.querySelector('.traffic-cookie-provenance');
assert.match(older.textContent, /Set by responses \(1\)request 900 · hop 2 — This Set-Cookie was blocked because it is Secure/);
assert.match(older.textContent, /Sent with requests \(2\).*request 901/);
assert.match(older.textContent, /Not in the scanned range: the backend reads the newest retained network records/);
assert.doesNotMatch(older.textContent, /No recorded document\.cookie/, 'A partial store read does not claim absence');
panel.querySelector('.traffic-cookie-provenance button').dispatchEvent(new window.Event('click'));
await settle();
// A settled answer is read again once the store changed, but not on every render.
const refreshes = name => reads.filter(url => url === `/api/cookie-provenance?session_id=7&name=${name}`).length;
{
  const refreshRequest = {...request, cookieLists: [record('sent', [{strings: ['fresh', 'v', 'echo.test', '/', '', ''], flags: 1}])]};
  const revised = {...ui, storeRevision: '"a"'};
  const redraw = () => api.renderTrafficCookies(panel, refreshRequest, redraw, revised);
  const open = async () => {redraw(); await settle();};
  await open();
  const nameButton = [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === 'fresh');
  nameButton.dispatchEvent(new window.Event('click'));
  await settle();
  await open();
  const first = refreshes('fresh');
  assert(first >= 1, 'The name was read');
  await open();
  assert.equal(refreshes('fresh'), first, 'An unchanged store is not read again');
  revised.storeRevision = '"b"';
  await new Promise(resolve => setTimeout(resolve, 5100));
  await open();
  await settle();
  assert.equal(refreshes('fresh'), first + 1, 'A changed store is read again after the interval');
  panel.querySelector('.traffic-cookie-provenance button')?.dispatchEvent(new window.Event('click'));
  await settle();
  api.renderTrafficCookies(panel, request, rerender, ui);
  await settle();
}
// A complete store read may state absence.
provenanceAnswer = {set_by: [], sent_with: [], script: [], lists_read: 3, lists_unread: 0, stacks_unresolved: 0, malformed_records: 0, coverage: {complete: true}};
const another = [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === 'track');
another.dispatchEvent(new window.Event('click'));
await settle();
await new Promise(resolve => setTimeout(resolve, 0));
assert.match(panel.querySelector('.traffic-cookie-provenance').textContent, /Provenance of track/);
panel.querySelector('.traffic-cookie-provenance button').dispatchEvent(new window.Event('click'));
await settle();
// Keyboard focus survives sort, the filter switch and Close.
{
  let active = null;
  Object.defineProperty(document, 'activeElement', {configurable: true, get: () => active});
  const focus = window.HTMLElement.prototype.focus;
  window.HTMLElement.prototype.focus = function focusTracked() {active = this;};
  byName().focus();
  byName().dispatchEvent(new window.Event('click'));
  await settle();
  assert.equal(active?.dataset.focusKey, 'sort:sent-0-0:name', 'focus stays on the sort button');
  const filterBox = [...panel.querySelectorAll('details')][2].querySelector('input[type="checkbox"]');
  filterBox.focus();
  filterBox.checked = false;
  filterBox.dispatchEvent(new window.Event('change'));
  await settle();
  assert.equal(active?.dataset.focusKey, 'filter:sent-0-0', 'focus stays on the filter switch');
  const nameButton = [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === 'sid');
  const openerKey = nameButton.dataset.focusKey;
  nameButton.focus();
  nameButton.dispatchEvent(new window.Event('click'));
  await settle();
  const closeButton = panel.querySelector('.traffic-cookie-provenance button');
  closeButton.focus();
  closeButton.dispatchEvent(new window.Event('click'));
  await settle();
  assert.equal(active?.dataset.focusKey, openerKey, 'focus returns to the name that opened provenance');
  delete document.activeElement;
  window.HTMLElement.prototype.focus = focus;
}
assert.equal(panel.querySelectorAll('img').length, 0, 'captured markup is still text');

// Version 3 reads: a name record joins its name; a nameless read record never
// joins one, even the empty name, and reads that did not name every cookie
// make an absent read unproven.
{
  const read = (version, name, readRecord, count, unrecorded, sequence) => {
    const bytes = Buffer.alloc(128);
    bytes.writeUInt16LE(version, 0); bytes.writeUInt16LE(128, 2);
    bytes[4] = 2; bytes[5] = 2 | (readRecord ? 16 : 0); bytes[6] = version >= 2 ? 1 : 0;
    bytes.writeUInt32LE(count, 8); bytes.writeUInt32LE(Buffer.byteLength(name), 12);
    bytes.writeUInt32LE(unrecorded, 16); bytes.writeUInt32LE(40, 20);
    bytes[24] = 1; bytes.writeUInt32LE(77, 28); bytes.writeUInt32LE(99, 32);
    bytes.write(name, 104, 'latin1');
    return {...scriptEvent, sequence_number: String(sequence), payload: bytes.toString('hex')};
  };
  const readEvents = [read(3, 'token', false, 3, 0, 40), read(3, '', true, 3, 5, 41), read(2, '', false, 1, 0, 42),
    read(3, '', false, 2, 0, 43)];
  assert(readEvents.every(event => decodeScriptCookieRecord(event)), 'the fixture read records are valid');
  const readRequest = {id: 'reads', origin: 'live', method: 'GET', path: 'https://echo.test/r', status: 200,
    cookieLists: [record('sent', [{strings: ['token', 'v', 'echo.test', '/', '', ''], flags: 1},
      {strings: ['', 'bare', 'echo.test', '/', '', ''], flags: 1}])]};
  const readUi = {requests: [readRequest], events: readEvents};
  const draw = () => api.renderTrafficCookies(panel, readRequest, draw, readUi);
  provenanceAnswer = null;
  draw();
  await settle();
  [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === 'token')
    .dispatchEvent(new window.Event('click'));
  await settle();
  let text = panel.querySelector('.traffic-cookie-provenance').textContent;
  assert.match(text, /Script access \(1\)document\.cookie get × 3 in frame 31, script 77 at character 99/);
  assert.match(text, /4 document\.cookie reads did not name every cookie they returned \(1 recorded before reads named cookies; 5 names past the 360-name bound or a full table\), so a read of token may have no record/);
  // The store's answer covers more than the loaded window, so it decides.
  provenanceAnswer = {set_by: [], sent_with: [], script: [], lists_read: 1, lists_unread: 0, stacks_unresolved: 0,
    malformed_records: [], coverage: {complete: true},
    read_coverage: {complete: false, whole_jar_reads: 0, reads_with_unrecorded_names: 6, unrecorded_names: 9}};
  await new Promise(resolve => setTimeout(resolve, 2100));
  draw();
  await settle();
  text = panel.querySelector('.traffic-cookie-provenance').textContent;
  assert.match(text, /6 document\.cookie reads did not name every cookie they returned \(9 names past the 360-name bound or a full table\)/);
  assert.doesNotMatch(text, /malformed record/, 'an empty malformed list is no note');
  panel.querySelector('.traffic-cookie-provenance button').dispatchEvent(new window.Event('click'));
  await settle();
  // The nameless cookie: its name record only, not the jar's read records.
  [...panel.querySelectorAll('.traffic-cookie-name')].find(node => node.textContent === '')
    .dispatchEvent(new window.Event('click'));
  await settle();
  text = panel.querySelector('.traffic-cookie-provenance').textContent;
  assert.match(text, /Script access \(1\)document\.cookie get × 2 in frame 31/);
  panel.querySelector('.traffic-cookie-provenance button').dispatchEvent(new window.Event('click'));
  await settle();
}

// A hop the content session saw but the network never reported has no list,
// and says why; so does a sent list without a received one.
{
  const browser = (type, extra = {}) => ({category: 'network', type, flags: 0, browser_context_id_high: '5',
    browser_context_id_low: '6', ...extra});
  const missingRow = {id: 'missing', origin: 'live', method: 'GET', path: 'https://echo.test/m', status: 'failed',
    cookieLists: [record('sent', [sentCookies[1]])],
    headerBlocks: [{kind: 'request', source: 'browser', state: 'captured', hop: 0},
      {kind: 'request', source: 'network', state: 'captured', hop: 0},
      {kind: 'request', source: 'browser', state: 'captured', hop: 1}],
    events: [browser('request_started'), browser('request_redirected'), browser('request_failed')]};
  const view = document.createElement('div');
  api.renderTrafficCookies(view, missingRow, () => {}, {});
  await settle();
  const notes = [...view.querySelectorAll('.traffic-cookie-missing')].map(node =>
    [node.querySelector('h3').textContent, node.dataset.reason, node.textContent]);
  assert.deepEqual(notes.map(([title, reason]) => [title, reason]),
    [['Request cookies · hop 1', 'failed'], ['Response cookies · hop 0', 'not_reported']]);
  assert.match(notes[0][2], /reported no cookie list for this hop\. It failed before the network stack reported the headers it sent/);
  // A row without header blocks (metadata-only, legacy) adds no hop of its own.
  assert.equal(panel.querySelectorAll('.traffic-cookie-missing').length, 0);
}

// Integrity failure, refusal and not-retained states read as sentences.
const wrong = record('sent', [sentCookies[1]]);
blobs.set(wrong.artifactId, list('sent', [sentCookies[0]]));
const refused = record('received', [receivedCookies[0]], {hop: 2});
context.state.events = [{type: 'artifact_capture_failed', artifact_id: refused.artifactId, session_id: '7'}];
const states = {id: 's', origin: 'live', method: 'GET', path: 'https://echo.test/', status: 200,
  cookieLists: [wrong, refused, {...record('sent', [sentCookies[0]]), hop: 3, state: 'not_captured_session_budget', artifactId: '0'},
    {...record('received', [receivedCookies[0]]), hop: 3, state: 'not_captured_block_limit', artifactId: '0', sha256: null}]};
const statesRender = () => api.renderTrafficCookies(panel, states, statesRender, {});
statesRender();
await settle();
assert.match(panel.textContent, /(size|SHA-256)/);
assert.match(panel.textContent, /receiver refused this list: sensitive_capture_disabled/);
assert.match(panel.textContent, /already retained 64 MiB of header blocks and cookie lists/);
assert.match(panel.textContent, /2 MiB list limit/);

// A partial store read must not state that nothing was retained.
api.renderTrafficCookies(panel, {id: 'p', origin: 'live', method: 'GET', path: 'https://echo.test/a', status: 200, hostOnly: false, cookieLists: [], recordsPartial: true}, () => {});
assert.match(panel.textContent, /unknown rather than missing/);
assert.doesNotMatch(panel.textContent, /No cookie list was retained/);
api.renderTrafficCookies(panel, {id: 'c', origin: 'live', method: 'GET', path: 'https://echo.test/a', status: 200, hostOnly: false, cookieLists: []}, () => {});
assert.match(panel.textContent, /No cookie list was retained/, 'A complete read may still state absence');
// Metadata-only and legacy rows say why there is nothing to show.
api.renderTrafficCookies(panel, {id: 'm', origin: 'live', method: 'GET', path: 'echo.test', status: 200, hostOnly: true, cookieLists: []}, () => {});
assert.match(panel.textContent, /recorded only in content capture sessions/);
api.renderTrafficCookies(panel, {id: 'l', origin: 'sample', method: 'GET', path: 'x', status: 200}, () => {});
assert.match(panel.textContent, /no native cookie record/);
assert.equal(reads.filter(url => url.startsWith('/api/artifacts/')).length, 7,
  'one read per distinct retained list, including the store-refresh block; refused and not-retained lists are not read');
assert.equal(reads.filter(url => url.startsWith('/api/cookie-provenance?session_id=7&name=sid')).length, 2, 'a failed position read retries once');
console.log('PASS Traffic Cookies tab: hops newest first, filtered-out request cookies and reasons, every response attribute ' +
  'and block reason, unparsed line, sort, tooltip and copy, provenance to response, script write at its resolved position and later request, ' +
  'document.cookie reads by name with their read coverage, hops without a list and why, ' +
  'size and SHA-256 checked reads, refusal and not-retained states, metadata-only and legacy rows (DOM model; not rendered QA)');
