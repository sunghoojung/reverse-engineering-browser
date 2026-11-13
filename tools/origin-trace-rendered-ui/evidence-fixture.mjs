// Builds one bounded, synthetic evidence session for rendered UI acceptance.
// Inputs are the deterministic `make e2e` demo stores plus the native Wasm
// evidence stores exported by `make native-wasm-golden-check` from the real C++
// encoders. Nothing here is captured from a website.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {cp, mkdir, readFile, writeFile} from 'node:fs/promises';
import {join} from 'node:path';

// Captured values that would execute if any renderer inserted them as HTML.
export const HOSTILE_URL = 'inert.test<svg/onload=window.__rebInjected=1>';
export const HOSTILE_URL_MARKER = 'onload=window.__rebInjected=1';
export const HOSTILE_SOURCE_URL = 'https://inert.test/<b id=reb-injected-markup>source</b>.js';
export const HOSTILE_SOURCE_MARKER = '<img src=x onerror="window.__rebInjected=2">';
// Guest bytecode is binary. Markup inside it must reach the hex view as inert
// printable text, and invalid UTF-8 must not become decoded text.
export const HOSTILE_BYTECODE_MARKUP = '<img src=x onerror="window.__rebInjected=3">';
export const SYNTHETIC_REQUEST_COUNT = 72;
// The reasons a live page produced when its Wasm br_table and call_indirect
// interpreters exhausted their 16-observation budgets. Sampling limits in the
// vm category, never queue drops or Traffic and Fingerprinting loss.
export const NAMED_GAP_REASONS = ['native_wasm_dispatch_budget_incomplete', 'native_wasm_indirect_budget_incomplete'];
export const SOURCE_LINE_COUNT = 400;
// A content-capture POST whose target and retained body carry markup that would
// execute if rendered as HTML, and a metadata-only POST (native-network-v2.md).
export const REQUEST_BODY_HOST = 'api.body.test';
export const REQUEST_BODY_TARGET = '/getcaptcha/site-key?s=<svg/onload=window.__rebInjected=5>';
export const REQUEST_BODY_MARKER = '<img src=x onerror="window.__rebInjected=4">';
export const METADATA_BODY_HOST = 'api.metadata.test';
// A content-session response body (native-network-v3.md) whose JSON carries markup.
export const RESPONSE_BODY_HOST = 'api.response.test';
// A content-session POST, recorded as real capture records it: its target's
// first 116 bytes, the rest refused by the request content budget, and its
// body and response refused by their budgets (native-network-v2.md target
// retention 4 and body state 10, v3 response state 12).
export const BUDGET_HOST = 'api.budget.test';
export const BUDGET_TARGET = `/collect/batch?session=fixture&events=${'e'.repeat(160)}`;
// Rows only the renderer finishes (protocol/native-network-v3.md).
export const MEMORY_CACHE_HOST = 'cdn.memory.test';
export const MEMORY_CACHE_TARGET = '/sprite.png?v=3';
export const SERVICE_WORKER_FAILED_HOST = 'api.worker.test';
// A service worker's end the renderer could not join to its start: End lost.
export const SERVICE_WORKER_LOST_HOST = 'api.lost.test';
const FIXTURE_TAB_ID = 1;
// A service worker's install-time fetch, linked to the tab that registered it.
export const REGISTRANT_HOST = 'sw.install.test';
// Body cases (protocol/native-network-v3.md "Bodies the proxy never sees"): a
// retained response and the memory-cache reuse naming it, a service worker's
// answer and its own fetch of the same URL, a partial stream and a binary body
// past one hex window, in renderer stream BODY_CASE_PROCESS.
export const BODY_CASE_PROCESS = 4949;
export const REUSED_HOST = 'cdn.reused.test';
export const REUSED_MARKER = '<img src=x onerror="window.__rebInjected=10">';
export const REUSED_TARGET = '/sprite.json?v=1';
export const WORKER_ANSWER_HOST = 'feed.worker.test';
export const PARTIAL_HOST = 'events.partial.test';
export const HEX_BODY_HOST = 'blob.hex.test';
export const HEX_BODY_BYTES = 600 * 1024;
export const RESPONSE_BODY_MARKER = '<img src=x onerror="window.__rebInjected=9">';
export const HEADER_VALUE_MARKER = '<img src=x onerror="window.__rebInjected=7">';
// A content-session request the HTTP cache answered: provisional headers
// only, with the reason ("Missing final blocks" in native-network-v3.md).
export const CACHED_HEADERS_HOST = 'cdn.cached.test';
export const COOKIE_VALUE_MARKER = '<img src=x onerror="window.__rebInjected=8">';
// A retained glue script for Track calls: the real window.hsw binder, decoys
// in a string and a comment that must never match, and two definitions of
// o.dup that must be refused as ambiguous. Context lines carry markup as text.
export const INVOCATION_ARTIFACT_ID = '330';
export const INVOCATION_SOURCE = "var s='window.hsw=function(a){}';/* window.hsw=function(b){} <img src=x onerror=\"window.__rebInjected=6\"> */\n" +
  '(function(){window.hsw=function(aGh,jR,qN){if(0===aGh)return Mk().then(function(){return awb(jR)});return qN}})();\n' +
  "o.dup=function(d){return '<img src=x onerror=\"window.__rebInjected=7\">'};if(z){o.dup=function(e){return e}}\n";

// A one-line source map over 16 KiB, which Sources opens pretty-printed (#433).
export const MINIFIED_ARTIFACT_ID = '332';
const MINIFIED_SOURCE_MAP = JSON.stringify({version: 3, file: 'vendor.min.js',
  sources: Array.from({length: 400}, (_, index) => `src/module-${index}.js`),
  names: Array.from({length: 6000}, (_, index) => `n${index.toString(36)}`), mappings: 'AAAA,SAASA,CAAC;'.repeat(12000)});

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = text => Buffer.from(text, 'utf8').toString('hex');

async function writeBlob(root, bytes) {
  const hash = sha256(bytes);
  await writeFile(join(root, 'blobs', `${hash}.bin`), bytes);
  return hash;
}

// A deterministic module for the Sources Map: structure, a repetitive data
// segment and a noisy one, so entropy and kind both have regions to show. About
// 1 MiB by default. REB_RENDERED_UI_MAP_MIB raises it for a memory measurement;
// the bytes are generated at test time and never committed.
function mapFixtureModule() {
  const mebibytes = Number(process.env.REB_RENDERED_UI_MAP_MIB ?? 1);
  assert(Number.isSafeInteger(mebibytes) && mebibytes >= 1 && mebibytes <= 512, 'REB_RENDERED_UI_MAP_MIB must be 1 to 512');
  const segmentBytes = mebibytes * 420 * 1024;
  const leb = value => { const out = []; do { let byte = value & 0x7f; value >>>= 7; if (value) byte |= 0x80; out.push(byte); } while (value); return out; };
  const section = (id, body) => Buffer.concat([Buffer.from([id, ...leb(body.length)]), body]);
  let state = 0x2545f491;
  const noise = Buffer.alloc(segmentBytes);
  const pattern = Buffer.alloc(segmentBytes);
  for (let index = 0; index < segmentBytes; index += 1) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5; state >>>= 0;
    noise[index] = state & 0xff;
    pattern[index] = (index >> 12) & 0x0f;
  }
  const segment = bytes => Buffer.concat([Buffer.from([0, 0x41, 0, 0x0b, ...leb(bytes.length)]), bytes]);
  const body = Buffer.concat([Buffer.from([0]), Buffer.alloc(180 * 1024, 0x01), Buffer.from([0x0b])]);
  const code = Buffer.concat([Buffer.from([1, ...leb(body.length)]), body]);
  return Buffer.concat([Buffer.from('\0asm\x01\0\0\0', 'latin1'),
    section(1, Buffer.from([1, 0x60, 0, 0])), section(3, Buffer.from([1, 0])), section(10, code),
    section(11, Buffer.concat([Buffer.from([2]), segment(pattern), segment(noise)]))]);
}

async function artifact(root, fields, bytes) {
  const hash = await writeBlob(root, bytes);
  return {protocol_version: 1, parent_artifact_id: '0', creator_event_id: '0', execution_context_id: '1',
    capture_origin: 'unknown', mime_type: 'application/octet-stream', sensitive: false, ...fields,
    byte_size: bytes.length, sha256: hash, content_path: `blobs/${hash}.bin`};
}

// Run offline (test42): add(a, b) returns a + b, and stamp(a, b) adds a clock
// read from the import env.now, so it traps until that import is stubbed. The
// export names are markup, which must stay text. Built by hand like the module
// below; tools/fixtures/wasm-runs/ holds the .wat fixtures the Rust tests use.
export const RUN_OFFLINE_ARTIFACT_ID = '450';
function offlineRunnerWasm() {
  const text = value => [...Buffer.from(value, 'utf8')];
  const name = value => [text(value).length, ...text(value)];
  const section = (id, data) => [id, data.length, ...data];
  const add = [0x00, 0x20, 0, 0x20, 1, 0x6a, 0x0b];
  const stamp = [0x00, 0x20, 0, 0x10, 0, 0xaa, 0x6a, 0x0b];
  return Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...section(1, [2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 1, 0x7c]),
    ...section(2, [1, ...name('env'), ...name('now'), 0x00, 1]),
    ...section(3, [2, 0, 0]),
    ...section(7, [2, ...name('add'), 0x00, 1, ...name('stamp<b>'), 0x00, 2]),
    ...section(10, [2, add.length, ...add, stamp.length, ...stamp])]);
}

// A flattened dispatcher: a loop around a br_table with one block per arm, each
// arm branching back to the loop. Built here so the fixture needs no wat tool.
function dispatcherWasm(arms) {
  const leb = n => { const out = []; do { let b = n & 127; n >>>= 7; out.push(n ? b | 128 : b); } while (n); return out; };
  const section = (id, data) => [id, ...leb(data.length), ...data];
  const body = [1, 1, 0x7f, 0x03, 0x40, 0x02, 0x40];
  for (let index = 0; index < arms; index += 1) body.push(0x02, 0x40);
  body.push(0x20, 0, 0x0e, ...leb(arms));
  for (let index = 0; index < arms; index += 1) body.push(...leb(index));
  body.push(...leb(arms));
  for (let index = 0; index < arms; index += 1) body.push(0x0b, 0x41, ...leb(index & 63), 0x21, 0, 0x0c, ...leb(arms - index));
  body.push(0x0b, 0x41, 0, 0x0f, 0x0b, 0x41, 1, 0x0b);
  return Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...section(1, [1, 0x60, 1, 0x7f, 1, 0x7f]), ...section(3, [1, 0]),
    ...section(7, [1, 8, ...Buffer.from('dispatch'), 0, 0]), ...section(10, [1, ...leb(body.length), ...body])]);
}

// test39: an import (func 0), an unexported helper (func 1) and an export
// (func 2) that calls it, so a name shows on a header and on a call row.
export const NAMED_WASM_ARTIFACT_ID = '420';
function namedFunctionsWasm() {
  const leb = n => { const out = []; do { let b = n & 127; n >>>= 7; out.push(n ? b | 128 : b); } while (n); return out; };
  const section = (id, data) => [id, ...leb(data.length), ...data];
  const text = value => [value.length, ...Buffer.from(value)];
  return Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...section(1, [1, 0x60, 0, 0]),
    ...section(2, [1, ...text('env'), ...text('log'), 0, 0]), ...section(3, [2, 0, 0]),
    ...section(7, [1, ...text('run'), 0, 2]), ...section(10, [2, 2, 0, 0x0b, 4, 0, 0x10, 1, 0x0b])]);
}

function jsonLines(text) {
  return text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
}

// The exact evidence stores that `make native-wasm-golden-check` built from the
// actual C++ encoders and validated through the Rust workspace builder: one
// adapter-interpreted guest sample with its synchronous host child, and one
// physical br_table observation with the widest identities the wire allows.
// `make vm-observed-evidence` exports the observed-claims test store the same way.
async function goldenEvidence(root, store) {
  const artifacts = jsonLines(await readFile(join(store, 'manifest.jsonl'), 'utf8'));
  const events = jsonLines(await readFile(join(store, 'events.jsonl'), 'utf8'));
  assert(artifacts.length && events.length, `${store} must hold an exported golden store`);
  for (const record of artifacts) {
    const bytes = await readFile(join(store, record.content_path));
    assert.equal(sha256(bytes), record.sha256, `golden blob ${record.content_path}`);
    await writeFile(join(root, record.content_path), bytes);
  }
  return {artifacts, events};
}

// A request whose renderer and browser records no initiator edge joined, as on a
// live capture where initiator resolution did not close. The renderer record sits
// 113 us before request_started in its own process, so Flow Lineage reports it as
// a time-adjacent row after the missing-predecessor gap, outside coverage.
export const TIME_ADJACENT_HOST = 'adjacent.trace.test';
function timeAdjacentRequest(template, firstSequence, firstTime) {
  const requestId = '2000', renderer = 41, start = BigInt(firstTime) + 1_000_000n;
  assert.notEqual(template.process_id, renderer, 'the renderer record needs its own process');
  // Sequence numbers are per process. The renderer row keeps its own stream at
  // 1; browser rows continue firstSequence without a hole. Sharing one counter
  // across both processes invented a fingerprint sequence-gap ID on the browser
  // stream and made coverage look partial for an unrelated VM budget check.
  const browser = {initiator_process_id: renderer, initiator_request_id: Number(requestId)};
  const rows = [
    [{process_id: renderer, initiator_process_id: 0, initiator_request_id: 0, sequence_number: '1'},
      'request_initiated', `GET ${TIME_ADJACENT_HOST}`, 0, 0n],
    [{...browser, sequence_number: String(firstSequence)},
      'request_started', `GET ${TIME_ADJACENT_HOST}`, 0, 113_000n],
    [{...browser, sequence_number: String(firstSequence + 1)},
      'response_started', 'application/json', 200, 400_000n],
    [{...browser, sequence_number: String(firstSequence + 2)},
      'request_completed', 'completed', 200, 900_000n],
  ];
  return rows.map(([fields, type, text, status, offset]) => ({...template, ...fields,
    monotonic_time_ns: String(start + offset), request_id: requestId,
    parent_event_id: '0', type, status_code: status, payload_size: Buffer.byteLength(text), payload: hex(text)}));
}

// Enough native network rows to require list scrolling, one with a hostile URL.
// Each completion records the lengths Size shows (syntheticTransferSize).
export const syntheticTransferSize = index => 1000 + index * 10;
function syntheticRequests(template, firstSequence, firstTime) {
  const events = [];
  let sequence = firstSequence, time = BigInt(firstTime);
  for (let index = 0; index < SYNTHETIC_REQUEST_COUNT; index += 1) {
    const requestId = String(1000 + index);
    // Native network payloads carry the method and host only.
    const url = index === 7 ? HOSTILE_URL : `item-${index}.scroll.test`;
    const lengths = {encoded_data_length: String(syntheticTransferSize(index)), decoded_body_length: String(2000 + index)};
    const steps = [['request_initiated', `GET ${url}`, 0], ['request_started', `GET ${url}`, 0],
      ['response_started', 'application/json; protocol=h2', 200], ['request_completed', 'completed', 200, lengths]];
    let parent = '0';
    for (const [type, text, status, extra = {}] of steps) {
      time += 1000n;
      const event = {...template, sequence_number: String(sequence), monotonic_time_ns: String(time), request_id: requestId,
        parent_event_id: parent, type, status_code: status, payload_size: Buffer.byteLength(text), payload: hex(text), ...extra};
      parent = event.sequence_number;
      sequence += 1;
      events.push(event);
    }
  }
  return events;
}

function requestBodyPayload({state, content, bytes, contentType = 'application/json', captured = 0}) {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload[4] = 1;
  payload[5] = state;
  payload[6] = (content ? 1 : 0) | 2 | 16;
  payload[7] = contentType.length;
  payload.writeBigUInt64LE(BigInt(bytes.length), 8);
  payload.writeBigUInt64LE(BigInt(captured), 16);
  payload.writeUInt32LE(1, 24);
  createHash('sha256').update(bytes).digest().copy(payload, 32);
  payload.write(contentType, 64, 'ascii');
  return payload.toString('hex');
}

// protocol/native-network-v3.md: one header record per block.
function headerBlockPayload({source, block, status = 0, policy = 0, hop = 0, state = 1}) {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload[4] = source;
  payload[5] = state;
  payload[6] = policy;
  payload.writeUInt32LE(block.toString().split('\r\n').length - 1, 8);
  payload.writeUInt32LE(block.length, 12);
  payload.writeUInt32LE(hop, 16);
  payload.writeUInt16LE(status, 20);
  if (status) {
    payload[7] = 4;
    payload.writeUInt16LE(8443, 22);
    Buffer.from([127, 0, 0, 1]).copy(payload, 24);
  }
  createHash('sha256').update(block).digest().copy(payload, 48);
  return payload.toString('hex');
}

// "Cookies" in protocol/native-network-v3.md: an RBCK list, its record and a
// renderer script_cookie write.
function cookieListBytes(direction, cookies) {
  const header = Buffer.alloc(16);
  header.write('RBCK', 0, 'latin1');
  header.writeUInt16LE(1, 4);
  header[6] = direction;
  header.writeUInt32LE(cookies.length, 8);
  return Buffer.concat([header, ...cookies.map(({strings, exclusions = 0n, flags = 0x07, sameSite = 3}) => {
    const fixed = Buffer.alloc(64);
    fixed.writeBigUInt64LE(exclusions, 0);
    fixed[24] = flags;
    fixed[25] = sameSite;
    fixed[26] = 2;
    fixed[27] = 2;
    fixed[28] = 2;
    fixed.writeInt32LE(443, 32);
    const parts = strings.map(text => Buffer.from(text));
    parts.forEach((part, index) => fixed.writeUInt32LE(part.length, 36 + index * 4));
    return Buffer.concat([fixed, ...parts]);
  })]);
}

function cookieListPayload(direction, bytes, count, blocked) {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload[4] = direction;
  payload[5] = 1;
  payload.writeUInt32LE(count, 8);
  payload.writeUInt32LE(blocked, 12);
  payload.writeUInt32LE(bytes.length, 16);
  createHash('sha256').update(bytes).digest().copy(payload, 32);
  return payload.toString('hex');
}

function scriptCookiePayload(name, value) {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload[4] = 1;
  payload[5] = 2;
  payload.writeUInt32LE(1, 8);
  payload.writeUInt32LE(name.length, 12);
  payload.writeUInt32LE(value.length, 16);
  payload.writeUInt32LE(name.length + value.length + 8, 20);
  payload[24] = 1;
  payload.writeUInt32LE(77, 28);
  payload.writeUInt32LE(1234, 32);
  createHash('sha256').update(value).digest().copy(payload, 72);
  payload.write(name, 104, 'latin1');
  return payload.toString('hex');
}

function responseBodyPayload(bytes, contentType = 'application/json') {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload[4] = 1;
  payload[5] = 0x40;
  payload[6] = contentType.length;
  payload.writeBigUInt64LE(BigInt(bytes.length), 8);
  payload.writeBigUInt64LE(BigInt(bytes.length), 16);
  createHash('sha256').update(bytes).digest().copy(payload, 32);
  payload.write(contentType, 64, 'ascii');
  return payload.toString('hex');
}

// A response_body record refused by the session's response body budget:
// no artifact, no captured bytes and no digest.
function budgetResponsePayload(length, contentType = 'application/json') {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload[4] = 12;
  payload[5] = 0x40;
  payload[6] = contentType.length;
  payload.writeBigUInt64LE(BigInt(length), 8);
  payload.write(contentType, 64, 'ascii');
  return payload.toString('hex');
}

// A version 2 request_target whose bytes past the prefix were not retained.
function requestTargetPayloadV2(target, retention) {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(2, 0);
  payload.writeUInt16LE(128, 2);
  payload.writeUInt32LE(Buffer.byteLength(target), 4);
  payload[8] = 2;
  payload[9] = retention;
  payload.write(target.slice(0, 116), 12, 'utf8');
  return payload.toString('hex');
}

function requestTargetPayload(target) {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload.writeUInt32LE(Buffer.byteLength(target), 4);
  payload[8] = 2;
  payload.write(target.slice(0, 116), 12, 'utf8');
  return payload.toString('hex');
}

// Two POSTs from the browser stream: one retained by a content session with its
// target, body record, body artifact and receiver acknowledgment as exact
// children, and one from a metadata-only session with only its body summary.
async function requestBodyRequests(template, firstSequence, firstTime, artifactsRoot) {
  const body = Buffer.from(JSON.stringify({sitekey: 'site-key', note: REQUEST_BODY_MARKER, motionData: 'm'.repeat(600)}));
  const metadataBody = Buffer.from('v=1&answers=redacted-by-session');
  let sequence = firstSequence, time = BigInt(firstTime);
  const events = [];
  const row = (fields, type, payload, extra = {}) => {
    time += 1000n;
    // Browser network records carry no navigation, transfer sizes or error.
    const event = {...template, ...fields, sequence_number: String(sequence), monotonic_time_ns: String(time),
      type, navigation_id: '0', artifact_id: '0', parent_event_id: '0', status_code: 0, error_code: 0,
      encoded_data_length: '0', decoded_body_length: '0', resource_type: 0, flags: 0, payload_truncated: false,
      payload_size: payload.length / 2, payload, ...extra};
    sequence += 1;
    events.push(event);
    return event;
  };
  const retained = {request_id: '3000'};
  const start = row(retained, 'request_started', hex(`POST ${REQUEST_BODY_HOST}`), {resource_type: 13});
  row(retained, 'request_target', requestTargetPayload(REQUEST_BODY_TARGET), {parent_event_id: start.sequence_number});
  const record = row(retained, 'request_body', requestBodyPayload({state: 4, content: true, bytes: body, captured: body.length}),
    {parent_event_id: start.sequence_number, artifact_id: '320'});
  const sentBlock = Buffer.from(`:method: POST\r\n:path: /getcaptcha/site-key\r\ncookie: sid=fixture\r\nx-note: ${HEADER_VALUE_MARKER}\r\n`);
  const receivedBlock = Buffer.from('content-type: application/json\r\nset-cookie: hc=1; Secure; HttpOnly\r\n');
  const sent = row(retained, 'request_headers', headerBlockPayload({source: 2, block: sentBlock}),
    {parent_event_id: start.sequence_number, artifact_id: '321'});
  const sentCookies = cookieListBytes(1, [{strings: ['sid', 'fixture', 'api.body.test', '/', '', '']},
    {strings: ['pref', 'dark', 'api.body.test', '/settings', '', ''], exclusions: 1n << 5n, flags: 0x01, sameSite: 4}]);
  const sentList = row(retained, 'cookie_list', cookieListPayload(1, sentCookies, 2, 1),
    {parent_event_id: start.sequence_number, artifact_id: '323'});
  const response = row(retained, 'response_started', hex('application/json'), {status_code: 200});
  const received = row(retained, 'response_headers', headerBlockPayload({source: 1, block: receivedBlock, status: 200}),
    {parent_event_id: response.sequence_number, artifact_id: '322'});
  const receivedCookies = cookieListBytes(2, [{strings: ['hc', '1', 'api.body.test', '/', '', 'hc=1; Secure; HttpOnly']},
    {strings: ['track', COOKIE_VALUE_MARKER, 'api.body.test', '/', '', `track=${COOKIE_VALUE_MARKER}; SameSite=None`],
      exclusions: 1n << 8n, flags: 0x01, sameSite: 2}]);
  const receivedList = row(retained, 'cookie_list', cookieListPayload(2, receivedCookies, 2, 1),
    {parent_event_id: start.sequence_number, artifact_id: '324'});
  row({request_id: '0'}, 'script_cookie', scriptCookiePayload('sid', 'fixture'));
  row(retained, 'request_completed', hex('completed'), {status_code: 200});
  row({...retained, category: 'artifact'}, 'artifact_captured', hex('accepted'),
    {artifact_id: '320', parent_event_id: record.sequence_number});
  const metadata = {request_id: '3001'};
  const metadataStart = row(metadata, 'request_started', hex(`POST ${METADATA_BODY_HOST}`), {resource_type: 13});
  row(metadata, 'request_body', requestBodyPayload({state: 3, content: false, bytes: metadataBody,
    contentType: 'application/x-www-form-urlencoded'}), {parent_event_id: metadataStart.sequence_number});
  row(metadata, 'response_started', hex('application/json'), {status_code: 200});
  row(metadata, 'request_completed', hex('completed'), {status_code: 200});
  const bodyArtifact = await artifact(artifactsRoot, {artifact_id: '320', session_id: template.session_id, navigation_id: '0',
    frame_id: template.frame_id, creator_event_id: record.sequence_number, execution_context_id: '0',
    capture_origin: 'network_request', kind: 'request_body', mime_type: 'application/json', sensitive: true,
    url: `https://${REQUEST_BODY_HOST}${REQUEST_BODY_TARGET}`}, body);
  const headerArtifacts = [];
  for (const [id, kind, creator, bytes] of [['321', 'request_headers', sent, sentBlock], ['322', 'response_headers', received, receivedBlock],
    ['323', 'cookie_list', sentList, sentCookies], ['324', 'cookie_list', receivedList, receivedCookies]]) {
    headerArtifacts.push(await artifact(artifactsRoot, {artifact_id: id, session_id: template.session_id, navigation_id: '0',
      frame_id: template.frame_id, creator_event_id: creator.sequence_number, execution_context_id: '0',
      capture_origin: 'network_request', kind, mime_type: kind === 'cookie_list' ? 'application/x-reb-cookie-list' : 'text/plain',
      sensitive: true, url: `https://${REQUEST_BODY_HOST}${REQUEST_BODY_TARGET}`}, bytes));
  }
  // The response body artifact is created by response_started, its record's parent.
  const answer = Buffer.from(JSON.stringify({challenge: 'c1', tasks: [{id: 1, note: RESPONSE_BODY_MARKER}], pass: false}));
  const responding = {request_id: '3002'};
  row(responding, 'request_started', hex(`GET ${RESPONSE_BODY_HOST}`), {resource_type: 13});
  const responded = row(responding, 'response_started', hex('application/json'), {status_code: 200});
  row(responding, 'response_body', responseBodyPayload(answer), {parent_event_id: responded.sequence_number, artifact_id: '325'});
  row(responding, 'request_completed', hex('completed'), {status_code: 200});
  row({...responding, category: 'artifact'}, 'artifact_captured', hex('accepted'),
    {artifact_id: '325', parent_event_id: responded.sequence_number});
  // Answered by the HTTP cache: its provisional block, refused by the session
  // budget, is all there is, and the Headers tab and footer say why.
  const browserContext = template.browser_context_id_high !== '0' || template.browser_context_id_low !== '0'
    ? {} : {browser_context_id_high: '5', browser_context_id_low: '6'};
  const cached = {request_id: '3003', ...browserContext};
  const cachedStart = row(cached, 'request_started', hex(`GET ${CACHED_HEADERS_HOST}`), {resource_type: 2});
  row(cached, 'request_headers', headerBlockPayload({source: 1, block: Buffer.from('accept: text/css\r\n'), policy: 2, state: 7}),
    {parent_event_id: cachedStart.sequence_number});
  row(cached, 'response_started', hex('text/css'), {status_code: 200, flags: 2});
  row(cached, 'request_completed', hex('completed'), {status_code: 200});
  const refused = {request_id: '3004'};
  const refusedStart = row(refused, 'request_started', hex(`POST ${BUDGET_HOST}`), {resource_type: 13});
  row(refused, 'request_target', requestTargetPayloadV2(BUDGET_TARGET, 4), {parent_event_id: refusedStart.sequence_number});
  row(refused, 'request_body', requestBodyPayload({state: 10, content: true, bytes: Buffer.from('{"events":[1,2,3]}')}),
    {parent_event_id: refusedStart.sequence_number});
  const refusedResponse = row(refused, 'response_started', hex('application/json'), {status_code: 200});
  row(refused, 'response_body', budgetResponsePayload(2048), {parent_event_id: refusedResponse.sequence_number});
  row(refused, 'request_completed', hex('completed'), {status_code: 200});
  const responseArtifact = await artifact(artifactsRoot, {artifact_id: '325', session_id: template.session_id, navigation_id: '0',
    frame_id: template.frame_id, creator_event_id: responded.sequence_number, execution_context_id: '0',
    capture_origin: 'network_response', kind: 'response_body', mime_type: 'application/json', sensitive: true,
    url: `https://${RESPONSE_BODY_HOST}/challenge`}, answer);
  return {events, artifacts: [bodyArtifact, ...headerArtifacts, responseArtifact]};
}

// A request a dedicated worker started (protocol/native-network-v3.md): its
// version 3 stack names the worker's isolate, and its task chain is a
// Promise.then registration in the worker, a MessagePort post from the page's
// renderer (another process) and an event scheduled with no script. Script 7
// is a different script in each isolate, so a wrong scope would mis-resolve.
export const WORKER_STACK_HOST = 'w.stack.test';
export const WORKER_STACK_PROCESSES = [5151, 5152];
const WORKER_KEY = 0x77n;
async function workerStackRequest(template, firstTime, artifactsRoot) {
  const [workerProcess, pageProcess] = WORKER_STACK_PROCESSES;
  const workerSource = "function work() {\n  fetch('/w');\n}\nfunction start() {\n  ready.then(work);\n}\n";
  const pageSource = 'function post() {\n  port.postMessage(1);\n}\n';
  const at = (text, needle) => text.indexOf(needle);
  const frame = (script, position, start) => {
    const bytes = Buffer.alloc(16);
    bytes[0] = 1;
    bytes.writeUInt32LE(script, 4);
    bytes.writeUInt32LE(position, 8);
    bytes.writeUInt32LE(start, 12);
    return bytes;
  };
  const scope = (thread, key) => {
    const bytes = Buffer.alloc(16);
    bytes[0] = thread;
    bytes.writeBigUInt64LE(key, 8);
    return bytes;
  };
  const stack = (process, thread, key, frames, segments) => {
    const header = Buffer.alloc(48);
    header.writeUInt32LE(0x4b534252, 0);
    header.writeUInt16LE(3, 4);
    header.writeUInt16LE(48, 6);
    header.writeUInt16LE(16, 8);
    header.writeUInt32LE(frames.length, 12);
    header.writeUInt32LE(frames.length, 16);
    header.writeUInt16LE(segments.length, 26);
    header.writeUInt16LE(segments.length, 28);
    header.writeUInt32LE(process, 32);
    header[36] = thread;
    header.writeBigUInt64LE(key, 40);
    return Buffer.concat([header, ...frames, ...segments]);
  };
  const segment = (kind, state, registration, recorded, digest) => {
    const bytes = Buffer.alloc(48);
    bytes[0] = kind;
    bytes[1] = state;
    bytes[3] = registration;
    bytes.writeUInt32LE(recorded, 4);
    if (digest) Buffer.from(digest, 'hex').copy(bytes, 16);
    return bytes;
  };
  const work = frame(7, at(workerSource, 'fetch'), at(workerSource, '() {'));
  const then = frame(7, at(workerSource, 'ready.then'), at(workerSource, '() {\n  ready'));
  const post = frame(7, at(pageSource, 'port'), at(pageSource, '() {'));
  const registered = stack(workerProcess, 2, WORKER_KEY, [then], []);
  const posted = stack(pageProcess, 1, 0n, [post], []);
  const requestStack = stack(workerProcess, 2, WORKER_KEY, [work], [
    segment(9, 1, 1, 1, sha256(registered)), segment(10, 1, 0, 1, sha256(posted)), segment(8, 7, 0, 0, null)]);
  const events = [];
  const sequences = new Map(WORKER_STACK_PROCESSES.map(process => [process, 1]));
  let time = BigInt(firstTime);
  const row = (process, type, payload, fields = {}) => {
    time += 1000n;
    const sequence = sequences.get(process);
    sequences.set(process, sequence + 1);
    const event = {...template, process_id: process, thread_id: process + 1, sequence_number: String(sequence),
      monotonic_time_ns: String(time), type, navigation_id: '0', artifact_id: '0', parent_event_id: '0',
      request_id: '0', status_code: 0, error_code: 0, encoded_data_length: '0', decoded_body_length: '0',
      resource_type: 0, flags: 0, payload_truncated: false, initiator_process_id: 0, initiator_request_id: 0,
      payload_size: payload.length, payload: payload.toString('hex'), ...fields};
    events.push(event);
    return event;
  };
  const workerFrame = String(WORKER_KEY);
  // The record shapes the renderer sink writes: request stack version 3,
  // async_task_stack and script_identity version 2.
  const taskRecord = (process, thread, key, kind, registration, digest, innermost) => {
    const payload = Buffer.alloc(128);
    payload.writeUInt16LE(2, 0);
    payload.writeUInt16LE(128, 2);
    payload[4] = kind;
    payload[6] = registration;
    payload.writeUInt32LE(1, 8);
    payload.writeUInt32LE(1, 16);
    Buffer.from(digest, 'hex').copy(payload, 32);
    innermost.copy(payload, 64);
    scope(thread, key).copy(payload, 80);
    return row(process, 'async_task_stack', payload, {frame_id: thread === 1 ? template.frame_id : workerFrame});
  };
  const identity = (process, thread, key, parent, source) => {
    const payload = Buffer.alloc(128);
    payload.writeUInt16LE(2, 0);
    payload.writeUInt16LE(128, 2);
    payload[4] = 1;
    payload[5] = 0x02;
    payload.writeUInt32LE(7, 8);
    payload.writeBigUInt64LE(99n, 24);
    payload.writeBigUInt64LE(BigInt(Buffer.byteLength(source)), 32);
    Buffer.from(sha256(Buffer.from(source)), 'hex').copy(payload, 40);
    scope(thread, key).copy(payload, 72);
    return row(process, 'script_identity', payload,
      {parent_event_id: parent.sequence_number, frame_id: thread === 1 ? template.frame_id : workerFrame});
  };
  const postedRecord = taskRecord(pageProcess, 1, 0n, 10, 0, sha256(posted), post);
  const pageIdentity = identity(pageProcess, 1, 0n, postedRecord, pageSource);
  const registeredRecord = taskRecord(workerProcess, 2, WORKER_KEY, 9, 1, sha256(registered), then);
  const initiated = row(workerProcess, 'request_initiated', Buffer.from(`GET ${WORKER_STACK_HOST}`),
    {request_id: '3100', frame_id: workerFrame});
  const recordPayload = Buffer.alloc(128);
  recordPayload.writeUInt16LE(3, 0);
  recordPayload.writeUInt16LE(128, 2);
  recordPayload[4] = 1;
  recordPayload[5] = 0x01;
  recordPayload.writeUInt16LE(3, 6);
  recordPayload.writeUInt32LE(1, 8);
  recordPayload.writeUInt32LE(1, 12);
  recordPayload.writeUInt16LE(3, 22);
  recordPayload.writeUInt32LE(1, 28);
  Buffer.from(sha256(requestStack), 'hex').copy(recordPayload, 32);
  work.copy(recordPayload, 64);
  scope(2, WORKER_KEY).copy(recordPayload, 80);
  const record = row(workerProcess, 'request_initiator_stack', recordPayload,
    {request_id: '3100', frame_id: workerFrame, parent_event_id: initiated.sequence_number});
  const workerIdentity = identity(workerProcess, 2, WORKER_KEY, registeredRecord, workerSource);
  const retain = (id, creator, bytes, fields) => artifact(artifactsRoot, {artifact_id: id, session_id: template.session_id,
    navigation_id: '0', frame_id: creator.frame_id, creator_event_id: creator.sequence_number, execution_context_id: '99',
    ...fields}, bytes);
  const stackFields = digest => ({capture_origin: 'request_stack', kind: 'stack', mime_type: 'application/x-reb-stack',
    url: `reb-stack:sha256-${digest}`});
  const artifacts = [
    await retain('350', record, requestStack, stackFields(sha256(requestStack))),
    await retain('351', postedRecord, posted, stackFields(sha256(posted))),
    await retain('352', registeredRecord, registered, stackFields(sha256(registered))),
    await retain('353', pageIdentity, Buffer.from(pageSource), {capture_origin: 'stack_script', kind: 'javascript',
      mime_type: 'text/javascript', url: 'https://page.stack.test/page.js'}),
    await retain('354', workerIdentity, Buffer.from(workerSource), {capture_origin: 'stack_script', kind: 'javascript',
      mime_type: 'text/javascript', url: 'https://page.stack.test/worker.js'})];
  return {events, artifacts};
}

// A memory-cache reuse with its content target, and a page request its service
// worker ended without a response, in a renderer stream of their own.
function rendererAnsweredRequests(template, events) {
  const processId = 4343;
  assert(!events.some(event => event.session_id === template.session_id && event.process_id === processId), 'renderer stream must be its own');
  let sequence = 0, time = BigInt(events.at(-1).monotonic_time_ns);
  const row = (type, payload, extra) => {
    sequence += 1;
    time += 1000n;
    const event = {...template, process_id: processId, thread_id: processId, sequence_number: String(sequence),
      monotonic_time_ns: String(time), tab_id: FIXTURE_TAB_ID, type, navigation_id: '0', artifact_id: '0',
      parent_event_id: '0', status_code: 0, error_code: 0, encoded_data_length: '0', decoded_body_length: '0',
      resource_type: 0, flags: 0, browser_context_id_high: '0', browser_context_id_low: '0', initiator_request_id: 0,
      initiator_process_id: 0, payload_truncated: false, payload_size: payload.length / 2, payload, ...extra};
    delete event.scheme_class;
    delete event.loader_kind;
    return Object.assign(event, extra);
  };
  const reusePayload = Buffer.alloc(128);
  reusePayload.writeUInt16LE(1, 0);
  reusePayload.writeUInt16LE(128, 2);
  reusePayload[4] = 1;
  reusePayload[6] = MEMORY_CACHE_HOST.length;
  reusePayload.write(MEMORY_CACHE_HOST, 8, 'ascii');
  const reused = row('memory_cache_reuse', reusePayload.toString('hex'),
    {request_id: '5000', scheme_class: 2, loader_kind: 16, status_code: 200, decoded_body_length: '2048'});
  const target = row('request_target', requestTargetPayload(MEMORY_CACHE_TARGET), {request_id: '5000', parent_event_id: reused.sequence_number});
  const start = row('request_initiated', hex(`GET ${SERVICE_WORKER_FAILED_HOST}`), {request_id: '5001', scheme_class: 2, loader_kind: 16});
  const startTarget = row('request_target', requestTargetPayload('/api?id=7'), {request_id: '5001', parent_event_id: start.sequence_number});
  const failed = row('request_failed', hex('failed'), {request_id: '5001', scheme_class: 2, error_code: -2, flags: 4});
  const lostStart = row('request_initiated', hex(`GET ${SERVICE_WORKER_LOST_HOST}`), {request_id: '5002', scheme_class: 2, loader_kind: 16});
  const lostTarget = row('request_target', requestTargetPayload('/lost?id=9'), {request_id: '5002', parent_event_id: lostStart.sequence_number});
  // The gap has no request ID of its own, so the store read of the row lacks it.
  const lost = row('gap', hex('service_worker_end_lost'), {request_id: '0', frame_id: '0',
    initiator_process_id: processId, initiator_request_id: 5002});
  return [reused, target, start, startTarget, failed, lostStart, lostTarget, lost];
}

function responseBodyRecord(state, length, captured, digest, partial = 0, contentType = 'application/json') {
  const payload = Buffer.alloc(128);
  payload.writeUInt16LE(1, 0);
  payload.writeUInt16LE(128, 2);
  payload[4] = state;
  payload[5] = 0x40;
  payload[6] = contentType.length;
  payload.writeBigUInt64LE(BigInt(length), 8);
  payload.writeBigUInt64LE(BigInt(captured), 16);
  payload.writeUInt16LE(partial, 28);
  if (digest) digest.copy(payload, 32);
  payload.write(contentType, 64, 'ascii');
  return payload.toString('hex');
}

// Artifact IDs 370 to 373; every other fixture ID is distinct from them.
async function bodyCaseRequests(template, firstSequence, firstTime, artifactsRoot) {
  const renderer = BODY_CASE_PROCESS, workerRenderer = BODY_CASE_PROCESS + 1;
  let browserSequence = firstSequence, rendererSequence = 0, time = BigInt(firstTime);
  const events = [], artifacts = [];
  const base = {...template, navigation_id: '0', artifact_id: '0', parent_event_id: '0', status_code: 0, error_code: 0,
    encoded_data_length: '0', decoded_body_length: '0', resource_type: 0, flags: 0, payload_truncated: false, tab_id: FIXTURE_TAB_ID};
  const record = (fields, type, payload, extra = {}) => {
    time += 1000n;
    const event = {...base, ...fields, monotonic_time_ns: String(time), type, payload_size: payload.length / 2, payload, ...extra};
    events.push(event);
    return event;
  };
  const browser = (request, type, payload, extra = {}) => record({sequence_number: String(browserSequence++), request_id: request,
    browser_context_id_high: '5', browser_context_id_low: '6'}, type, payload, extra);
  const rendered = (request, type, payload, extra = {}) => {
    rendererSequence += 1;
    const event = record({process_id: renderer, thread_id: renderer, sequence_number: String(rendererSequence), request_id: request,
      browser_context_id_high: '0', browser_context_id_low: '0', initiator_process_id: 0, initiator_request_id: 0}, type, payload, extra);
    delete event.scheme_class;
    delete event.loader_kind;
    return Object.assign(event, extra);
  };
  const retain = async (id, creator, bytes, mime, url) => {
    const stored = await artifact(artifactsRoot, {artifact_id: id, session_id: template.session_id, navigation_id: '0',
      frame_id: template.frame_id, creator_event_id: creator.sequence_number, execution_context_id: '0',
      capture_origin: 'network_response', kind: 'response_body', mime_type: mime, sensitive: true, url}, bytes);
    artifacts.push(stored);
    return createHash('sha256').update(bytes).digest();
  };
  // A body a later reuse names, then the reuse (payload version 2, bit 2).
  const sprite = Buffer.from(JSON.stringify({sprite: 'cache', note: REUSED_MARKER}));
  const owner = {initiator_process_id: renderer, initiator_request_id: 61};
  rendered('61', 'request_initiated', hex(`GET ${REUSED_HOST}`), {scheme_class: 2, loader_kind: 16});
  browser('3100', 'request_started', hex(`GET ${REUSED_HOST}`), {...owner, resource_type: 13});
  const loaded = browser('3100', 'response_started', hex('application/json'), {...owner, status_code: 200});
  const spriteDigest = await retain('370', loaded, sprite, 'application/json', `https://${REUSED_HOST}/sprite.json`);
  browser('3100', 'response_body', responseBodyRecord(1, sprite.length, sprite.length, spriteDigest),
    {...owner, parent_event_id: loaded.sequence_number, artifact_id: '370'});
  browser('3100', 'request_completed', hex('completed'), {...owner, status_code: 200, decoded_body_length: String(sprite.length)});
  const reuse = Buffer.alloc(128);
  reuse.writeUInt16LE(2, 0);
  reuse.writeUInt16LE(128, 2);
  reuse[4] = 5;
  reuse[5] = 4;
  reuse[6] = REUSED_HOST.length;
  reuse.write(REUSED_HOST, 8, 'ascii');
  const reused = rendered('62', 'memory_cache_reuse', reuse.toString('hex'), {scheme_class: 2, loader_kind: 16, status_code: 200,
    decoded_body_length: String(sprite.length), initiator_process_id: renderer, initiator_request_id: 61});
  rendered('62', 'request_target', requestTargetPayload(REUSED_TARGET), {parent_event_id: reused.sequence_number});
  // The page's request its service worker answered, and the worker's own fetch
  // of the same URL while the page's request was open.
  const page = rendered('63', 'request_initiated', hex(`GET ${WORKER_ANSWER_HOST}`), {scheme_class: 2, loader_kind: 16});
  rendered('63', 'request_target', requestTargetPayload('/feed?x=1'), {parent_event_id: page.sequence_number});
  // The worker controls the fixture tab's page, so its fetch has that tab.
  const worker = {initiator_process_id: workerRenderer, initiator_request_id: 7, tab_id: FIXTURE_TAB_ID};
  const fetched = browser('3101', 'request_started', hex(`GET ${WORKER_ANSWER_HOST}`), {...worker, flags: 4, resource_type: 13});
  browser('3101', 'request_target', requestTargetPayload('/feed?x=1'), {...worker, parent_event_id: fetched.sequence_number});
  const feed = Buffer.from('{"feed":[1,2,3]}');
  const feedStarted = browser('3101', 'response_started', hex('application/json'), {...worker, status_code: 200});
  const feedDigest = await retain('371', feedStarted, feed, 'application/json', `https://${WORKER_ANSWER_HOST}/feed?x=1`);
  browser('3101', 'response_body', responseBodyRecord(1, feed.length, feed.length, feedDigest),
    {...worker, parent_event_id: feedStarted.sequence_number, artifact_id: '371'});
  browser('3101', 'request_completed', hex('completed'), {...worker, status_code: 200});
  rendered('63', 'request_completed', hex('completed'), {scheme_class: 2, status_code: 200, flags: 4,
    decoded_body_length: String(feed.length)});
  // An event stream still open: its second snapshot.
  const stream = Buffer.from('data: one\n\n'.repeat(100));
  browser('3102', 'request_started', hex(`GET ${PARTIAL_HOST}`), {resource_type: 13});
  const opened = browser('3102', 'response_started', hex('text/event-stream'), {status_code: 200});
  const streamDigest = await retain('372', opened, stream, 'text/event-stream', `https://${PARTIAL_HOST}/events`);
  browser('3102', 'response_body', responseBodyRecord(3, stream.length, stream.length, streamDigest, 2, 'text/event-stream'),
    {parent_event_id: opened.sequence_number, artifact_id: '372'});
  // A binary body longer than one 256 KiB hex window.
  const blob = Buffer.alloc(HEX_BODY_BYTES);
  for (let offset = 0; offset < blob.length; offset += 1) blob[offset] = (offset * 13 + 1) & 0xff;
  browser('3103', 'request_started', hex(`GET ${HEX_BODY_HOST}`), {resource_type: 13});
  const binary = browser('3103', 'response_started', hex('application/octet-stream'), {status_code: 200});
  const blobDigest = await retain('373', binary, blob, 'application/octet-stream', `https://${HEX_BODY_HOST}/blob.bin`);
  browser('3103', 'response_body', responseBodyRecord(1, blob.length, blob.length, blobDigest, 0, 'application/octet-stream'),
    {parent_event_id: binary.sequence_number, artifact_id: '373'});
  browser('3103', 'request_completed', hex('completed'), {status_code: 200, decoded_body_length: String(blob.length)});
  return {events, artifacts};
}

// A renderer-only service-worker request linked to the fixture tab as its
// registrant (request_tab_link kind 5), and two requests of a service worker no
// page used, counted as class 68 (protocol/native-network-v3.md).
function serviceWorkerRegistrantRequest(template, firstSequence, firstTime) {
  const renderer = 5161, fold = '4660';
  let sequence = firstSequence, time = BigInt(firstTime);
  const base = {...template, navigation_id: '0', artifact_id: '0', parent_event_id: '0', status_code: 0, error_code: 0,
    encoded_data_length: '0', decoded_body_length: '0', resource_type: 0, flags: 0, payload_truncated: false};
  const at = (fields, payload) => {
    time += 1000n;
    return {...base, monotonic_time_ns: String(time), ...fields, payload_size: payload.length / 2, payload};
  };
  const workerRecord = {process_id: renderer, thread_id: renderer, request_id: '61', frame_id: fold, tab_id: 0, scheme_class: 2};
  const start = at({...workerRecord, sequence_number: '1', type: 'request_initiated', loader_kind: 19}, hex(`GET ${REGISTRANT_HOST}`));
  const done = at({...workerRecord, sequence_number: '2', type: 'request_completed', status_code: 200}, hex('completed'));
  const browser = (fields, bytes) => at({sequence_number: String(sequence++), request_id: '0', ...fields}, bytes.toString('hex'));
  const set = Buffer.alloc(128);
  set.writeUInt16LE(1, 0); set.writeUInt16LE(128, 2); set[4] = 19; set.writeBigUInt64LE(1n, 8);
  set.writeUInt32LE(1, 16); set.writeUInt16LE(1, 20); set.writeUInt32LE(FIXTURE_TAB_ID, 24);
  const link = Buffer.alloc(24);
  link.writeUInt16LE(1, 0); link.writeUInt16LE(24, 2); link[4] = 5; link.writeBigUInt64LE(1n, 8); link.writeUInt32LE(1, 16);
  const counted = Buffer.alloc(16);
  counted.writeUInt16LE(1, 0); counted.writeUInt16LE(16, 2); counted[4] = 68; counted.writeBigUInt64LE(2n, 8);
  return [start, done,
    browser({type: 'tab_set', tab_id: FIXTURE_TAB_ID, frame_id: fold}, set),
    browser({type: 'request_tab_link', tab_id: FIXTURE_TAB_ID, frame_id: fold, parent_event_id: start.sequence_number,
      initiator_process_id: renderer, initiator_request_id: 61}, link),
    browser({type: 'capture_exclusion', tab_id: 0, frame_id: '0', initiator_process_id: 0, initiator_request_id: 0}, counted)];
}

// Debugger observation records (protocol/native-debugger-observation-v1.md)
// from one renderer of its own: frame 200 holds the retained sources, so its
// thread scope narrows the Sources tree, and the listener, timer and throw
// sites name a retained compiled script. Workers come from request records
// with loader kinds 17 to 19. No budget gap is written: a runtime gap would
// mark Fingerprinting coverage partial, which test14 rules out for this store.
// Runtime records also count as Fingerprinting activity, so the default stays
// well under its 500-event window. REB_RENDERED_UI_DEBUGGER_RECORDS raises it.
export const DEBUGGER_PROCESS = 4747;
export const DEBUGGER_FRAME = '200';
// At most 27 printable bytes, the event type bound; it would load an image if parsed as HTML.
export const DEBUGGER_HOSTILE_EVENT = '<img/src=x/onerror=f()>';
export const DEBUGGER_SOURCE = "// Debugger fixture: the handlers observation records name.\n" +
  "document.querySelector('#go').addEventListener('click', function onTap(event) {\n" +
  "  event.preventDefault();\n" +
  "  setTimeout(function later() { fetch('/api/x'); }, 100);\n" +
  "});\n";
export const DEBUGGER_ARTIFACT_ID = '360';
export async function debuggerObservations(template, artifactsRoot, {records = Number(process.env.REB_RENDERED_UI_DEBUGGER_RECORDS ?? 120),
  frames = ['200', '7101', '7102', '7103', '7104', '7105'], workers = 3} = {}) {
  assert(Number.isSafeInteger(records) && records >= 8 && records <= 20000, 'REB_RENDERED_UI_DEBUGGER_RECORDS must be 8 to 20000');
  const source = Buffer.from(DEBUGGER_SOURCE, 'utf8');
  const tap = DEBUGGER_SOURCE.indexOf('(event) {'), later = DEBUGGER_SOURCE.indexOf('() { fetch'), fetchAt = DEBUGGER_SOURCE.indexOf("fetch('/api/x')");
  const frameBytes = (position, start) => {
    const bytes = Buffer.alloc(16);
    bytes[0] = 1;
    bytes.writeUInt32LE(7, 4);
    bytes.writeUInt32LE(position, 8);
    bytes.writeUInt32LE(start, 12);
    return bytes;
  };
  const observation = tail => {
    const payload = Buffer.alloc(128);
    payload.set([1, 0, 128, 0, 2, 0x08]);
    Buffer.from(tail).copy(payload, 80);
    return payload.toString('hex');
  };
  const name = (length, text) => [length, ...Buffer.from(text, 'latin1')];
  const tails = {
    listener_dispatch: index => [index % 2, 1, 1, 0, ...frameBytes(tap, tap), ...name(index % 7 ? 5 : DEBUGGER_HOSTILE_EVENT.length, index % 7 ? 'click' : DEBUGGER_HOSTILE_EVENT)],
    timer_observation: index => {
      const tail = Buffer.alloc(48);
      tail[0] = 1 + (index % 2); tail[1] = 1;
      tail.writeUInt32LE(100 + index, 4);
      tail.writeUInt32LE(index % 2 ? 0 : 100, 8);
      frameBytes(later, later).copy(tail, 12);
      return [...tail];
    },
    csp_violation: () => [19, 1, ...name(16, 'cdn.blocked.test')],
    exception_observation: index => [1 + (index % 3), 0, 0, 0, ...(index % 3 === 2 ? Buffer.alloc(16) : frameBytes(fetchAt, later))],
    dom_mutation: () => [1, 0, 1, 0, ...name(5, 'class')]
  };
  const kinds = Object.keys(tails);
  const events = [];
  let sequence = 0, time = BigInt(template.monotonic_time_ns);
  const row = (fields, type, payload) => {
    sequence += 1; time += 1000n;
    const event = {...template, process_id: DEBUGGER_PROCESS, thread_id: DEBUGGER_PROCESS, sequence_number: String(sequence),
      monotonic_time_ns: String(time), navigation_id: '0', artifact_id: '0', parent_event_id: '0', request_id: '0', category: 'runtime',
      initiator_process_id: 0, initiator_request_id: 0, status_code: 0, error_code: 0, resource_type: 0, flags: 0,
      encoded_data_length: '0', decoded_body_length: '0', payload_truncated: false, payload_size: payload.length / 2, payload, type, ...fields};
    events.push(event);
    return event;
  };
  const identity = Buffer.alloc(128);
  identity.set([1, 0, 128, 0, 1, 0x02]);
  identity.writeUInt32LE(7, 8);
  identity.writeBigUInt64LE(99n, 24);
  identity.writeBigUInt64LE(BigInt(source.length), 32);
  createHash('sha256').update(source).digest().copy(identity, 40);
  const scriptIdentity = row({category: 'network', frame_id: DEBUGGER_FRAME}, 'script_identity', identity.toString('hex'));
  // A watched request and its match; the match names the request record as parent.
  const watched = row({category: 'network', frame_id: DEBUGGER_FRAME, request_id: '5100', loader_kind: 16}, 'request_initiated', hex('GET watch.debugger.test'));
  row({category: 'network', frame_id: DEBUGGER_FRAME, request_id: '5100', parent_event_id: watched.sequence_number}, 'request_watch_match', observation([0, 1]));
  for (let index = 0; index < workers; index += 1) {
    for (let request = 0; request <= index; request += 1) {
      row({category: 'network', frame_id: String(9001 + index), request_id: String(6000 + index * 40 + request), loader_kind: 17 + (index % 3)},
        'request_initiated', hex(`GET worker-${index}.debugger.test`));
    }
  }
  for (let index = 0; index < records; index += 1) {
    const kind = kinds[index % kinds.length];
    row({frame_id: frames[index % frames.length]}, kind, observation(tails[kind](index)));
  }
  // Two records the core refuses.
  row({frame_id: DEBUGGER_FRAME}, 'listener_dispatch', observation([0, 1, 1, 0]));
  row({frame_id: DEBUGGER_FRAME}, 'dom_mutation', observation([2, 0, 1, 0, 1, 120]));
  const script = await artifact(artifactsRoot, {artifact_id: DEBUGGER_ARTIFACT_ID, session_id: template.session_id, navigation_id: '100',
    frame_id: DEBUGGER_FRAME, creator_event_id: scriptIdentity.sequence_number, capture_origin: 'compiled_script', kind: 'javascript',
    mime_type: 'text/javascript', url: 'https://app.debugger.test/handlers.js'}, source);
  return {events, artifacts: [script]};
}

// Like the browser, each gap takes its renderer's own sequence slot, so the
// stream has no hole. The payload is the reason text, as the producers write it.
function namedBudgetGaps(template, events) {
  const processId = 4242;
  assert(!events.some(event => event.session_id === template.session_id && event.process_id === processId), 'budget gap stream must be its own');
  const time = BigInt(events.at(-1).monotonic_time_ns);
  return NAMED_GAP_REASONS.map((reason, index) => ({...template, process_id: processId, thread_id: processId,
    sequence_number: String(index + 1), monotonic_time_ns: String(time + BigInt(index + 1)), artifact_id: '0',
    parent_event_id: '0', request_id: '0', type: 'gap', payload_size: Buffer.byteLength(reason), payload: hex(reason)}));
}

export async function buildEvidence({root, sessions, guestStore, dispatchStore, observedStore}) {
  const artifacts = join(root, 'artifacts');
  await mkdir(join(artifacts, 'blobs'), {recursive: true});
  for (const name of ['origin-trace.jsonl', 'request-signals.jsonl']) await cp(join(sessions, name), join(root, name));
  const demoEvents = jsonLines(await readFile(join(sessions, 'demo.jsonl'), 'utf8'));
  // Browser network records carry their tab (protocol/native-network-v3.md); the demo producer's do not.
  for (const event of demoEvents) if (event.category === 'network') event.tab_id = FIXTURE_TAB_ID;
  const demoArtifacts = jsonLines(await readFile(join(sessions, 'artifacts/manifest.jsonl'), 'utf8'));
  for (const record of demoArtifacts) await cp(join(sessions, 'artifacts', record.content_path), join(artifacts, record.content_path));
  const network = demoEvents.find(event => event.category === 'network');
  assert(network, 'demo store must contain a native network event');
  const last = demoEvents.at(-1);
  const scrolled = syntheticRequests(network, Number(last.sequence_number) + 1, last.monotonic_time_ns);
  const adjacent = timeAdjacentRequest(network, Number(scrolled.at(-1).sequence_number) + 1, scrolled.at(-1).monotonic_time_ns);
  const lastBrowser = adjacent.filter(event => event.process_id === network.process_id).at(-1);
  const withBodies = await requestBodyRequests(network, Number(lastBrowser.sequence_number) + 1, lastBrowser.monotonic_time_ns, artifacts);
  const workerStack = await workerStackRequest(network, withBodies.events.at(-1).monotonic_time_ns, artifacts);
  const lastBodies = withBodies.events.filter(event => event.process_id === network.process_id).at(-1);
  const registrant = serviceWorkerRegistrantRequest(network, Number(lastBodies.sequence_number) + 1,
    workerStack.events.at(-1).monotonic_time_ns);
  const answered = rendererAnsweredRequests(network,
    [...demoEvents, ...scrolled, ...adjacent, ...withBodies.events, ...workerStack.events, ...registrant]);
  const lastRegistrant = registrant.filter(event => event.process_id === network.process_id).at(-1);
  const bodyCases = await bodyCaseRequests(network, Number(lastRegistrant.sequence_number) + 1, answered.at(-1).monotonic_time_ns, artifacts);
  assert(![...demoEvents, ...scrolled, ...adjacent, ...withBodies.events, ...workerStack.events, ...registrant, ...answered]
    .some(event => event.process_id === BODY_CASE_PROCESS), 'the body case renderer stream must be its own');
  const requests = [...scrolled, ...adjacent, ...withBodies.events, ...workerStack.events, ...registrant, ...answered, ...bodyCases.events];
  const lines = Array.from({length: SOURCE_LINE_COUNT}, (_, index) => index === 2
    ? `// ${HOSTILE_SOURCE_MARKER}` : `const retainedLine${index} = ${index}; // long line ${'x'.repeat(index % 7 === 0 ? 180 : 12)}`);
  const source = await artifact(artifacts, {artifact_id: '303', session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'network_response', kind: 'javascript', mime_type: 'text/javascript', url: HOSTILE_SOURCE_URL},
  Buffer.from(lines.join('\n') + '\n', 'utf8'));
  // A synthetic native guest bytecode buffer beside the real golden one (109).
  const bytecode = await artifact(artifacts, {artifact_id: '310', session_id: '1', navigation_id: '100', frame_id: '200',
    parent_artifact_id: '303', creator_event_id: '1', capture_origin: 'native_wasm_guest', kind: 'bytecode_buffer',
    url: 'fixture://native-guest-hostile'},
  Buffer.concat([Buffer.from(HOSTILE_BYTECODE_MARKUP, 'utf8'), Buffer.from([0xff, 0xfe, 0x00, 0x80]), Buffer.from(Array.from({length: 32}, (_, index) => index))]));
  // The real analyzer must retain a displayable parse omission without making
  // the entire workspace response invalid or inventing handler proof.
  const parseFailure = await artifact(artifacts, {artifact_id: '311', session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'dynamic_javascript', kind: 'javascript', mime_type: 'text/javascript', url: 'fixture://parse-failed.js'},
  Buffer.from('function vm(code,stack){var pc=0;var ops={1:function(){stack.push(code[pc++])},2:function(){stack.pop()},3:function(){pc=code.length}};while(pc<code.length){ops[code[pc++]]();}return stack;}\nlet broken=;'));
  const glue = await artifact(artifacts, {artifact_id: INVOCATION_ARTIFACT_ID, session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'network_response', kind: 'javascript', mime_type: 'text/javascript', url: 'https://hcaptcha.test/glue.js'},
  Buffer.from(INVOCATION_SOURCE, 'utf8'));
  const sourceMap = await artifact(artifacts, {artifact_id: MINIFIED_ARTIFACT_ID, session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'network_response', kind: 'source_map', mime_type: 'application/json', url: 'https://cdn.test/vendor.min.js.map'},
  Buffer.from(MINIFIED_SOURCE_MAP, 'utf8'));
  const mapped = await artifact(artifacts, {artifact_id: '312', session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'network_response', kind: 'wasm', execution_context_id: '0', mime_type: 'application/wasm', url: 'https://fixture.invalid/map-module.wasm'},
  mapFixtureModule());
  const graphWasm = await artifact(artifacts, {artifact_id: '340', session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'webassembly_compile', kind: 'wasm', mime_type: 'application/wasm', url: 'fixture://graph-dispatcher.wasm'},
  dispatcherWasm(32));
  const namedWasm = await artifact(artifacts, {artifact_id: NAMED_WASM_ARTIFACT_ID, session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'webassembly_compile', kind: 'wasm', mime_type: 'application/wasm', url: 'fixture://named-functions.wasm'},
  namedFunctionsWasm());
  const offlineRunner = await artifact(artifacts, {artifact_id: RUN_OFFLINE_ARTIFACT_ID, session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'network_response', kind: 'wasm', mime_type: 'application/wasm', url: 'https://fixture.invalid/offline-runner.wasm'},
  offlineRunnerWasm());
  // A synthetic Rust and wasm-bindgen shaped module for library
  // identification (test38), built from its checked-in .wat source.
  const identified = await artifact(artifacts, {artifact_id: '410', session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'network_response', kind: 'wasm', mime_type: 'application/wasm', url: 'https://fixture.invalid/identified-module.wasm'},
  await readFile(new URL('../fixtures/wasm-identification/rust-wasm-bindgen.wasm', import.meta.url)));
  const guest = await goldenEvidence(artifacts, guestStore);
  const physical = await goldenEvidence(artifacts, dispatchStore);
  assert(guest.events.some(event => event.type === 'wasm_guest_dispatch'), 'guest golden store holds a guest sample');
  assert(physical.events.some(event => event.type === 'wasm_dispatch_observation'), 'dispatch golden store holds an observation');
  // An owned two-level interpreter: observed claims, one contradicting its
  // static arm label, and an inner interpreter linked to its outer handler.
  const observed = await goldenEvidence(artifacts, observedStore);
  assert(observed.events.filter(event => event.type === 'wasm_guest_invocation').length === 2, 'observed store holds outer and inner activations');
  const debuggerRecords = await debuggerObservations(network, artifacts);
  const manifest = [...demoArtifacts, source, bytecode, parseFailure, glue, sourceMap, mapped, graphWasm, namedWasm, offlineRunner, identified, ...withBodies.artifacts, ...bodyCases.artifacts, ...workerStack.artifacts, ...guest.artifacts, ...physical.artifacts, ...observed.artifacts, ...debuggerRecords.artifacts];
  const retained = [...demoEvents, ...requests, ...guest.events, ...physical.events, ...observed.events];
  for (const process of WORKER_STACK_PROCESSES) {
    assert.equal(retained.filter(event => event.process_id === process).length,
      workerStack.events.filter(event => event.process_id === process).length, 'worker stack renderers must be their own');
  }
  const vm = demoEvents.find(event => event.category === 'vm');
  assert(vm, 'demo store must contain a native vm event');
  // The debugger renderer's records come first, so its requests list last in Traffic.
  const events = [...debuggerRecords.events, ...retained, ...namedBudgetGaps(vm, retained)];
  await writeFile(join(artifacts, 'manifest.jsonl'), manifest.map(record => JSON.stringify(record) + '\n').join(''));
  await writeFile(join(root, 'events.jsonl'), events.map(event => JSON.stringify(event) + '\n').join(''));
  return {
    store: join(root, 'events.jsonl'), traceStore: join(root, 'origin-trace.jsonl'),
    signalStore: join(root, 'request-signals.jsonl'), artifacts,
    apiCollection: join(root, 'api-collection.json'), localAnalyst: join(root, 'local-analyst.json'),
    invocationSites: join(root, 'app-support', 'js-invocation-sites-v1.json'),
  };
}
