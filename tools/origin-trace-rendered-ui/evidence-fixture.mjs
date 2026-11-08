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
// A retained glue script for Track calls: the real window.hsw binder, decoys
// in a string and a comment that must never match, and two definitions of
// o.dup that must be refused as ambiguous. Context lines carry markup as text.
export const INVOCATION_ARTIFACT_ID = '330';
export const INVOCATION_SOURCE = "var s='window.hsw=function(a){}';/* window.hsw=function(b){} <img src=x onerror=\"window.__rebInjected=6\"> */\n" +
  '(function(){window.hsw=function(aGh,jR,qN){if(0===aGh)return Mk().then(function(){return awb(jR)});return qN}})();\n' +
  "o.dup=function(d){return '<img src=x onerror=\"window.__rebInjected=7\">'};if(z){o.dup=function(e){return e}}\n";

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = text => Buffer.from(text, 'utf8').toString('hex');

async function writeBlob(root, bytes) {
  const hash = sha256(bytes);
  await writeFile(join(root, 'blobs', `${hash}.bin`), bytes);
  return hash;
}

async function artifact(root, fields, bytes) {
  const hash = await writeBlob(root, bytes);
  return {protocol_version: 1, parent_artifact_id: '0', creator_event_id: '0', execution_context_id: '1',
    capture_origin: 'unknown', mime_type: 'application/octet-stream', sensitive: false, ...fields,
    byte_size: bytes.length, sha256: hash, content_path: `blobs/${hash}.bin`};
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
// 113 us before request_started in its own process, so Backtraces reports it as
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
  row(retained, 'response_started', hex('application/json'), {status_code: 200});
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
  return {events, artifact: bodyArtifact};
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
  const demoArtifacts = jsonLines(await readFile(join(sessions, 'artifacts/manifest.jsonl'), 'utf8'));
  for (const record of demoArtifacts) await cp(join(sessions, 'artifacts', record.content_path), join(artifacts, record.content_path));
  const network = demoEvents.find(event => event.category === 'network');
  assert(network, 'demo store must contain a native network event');
  const last = demoEvents.at(-1);
  const scrolled = syntheticRequests(network, Number(last.sequence_number) + 1, last.monotonic_time_ns);
  const adjacent = timeAdjacentRequest(network, Number(scrolled.at(-1).sequence_number) + 1, scrolled.at(-1).monotonic_time_ns);
  const lastBrowser = adjacent.filter(event => event.process_id === network.process_id).at(-1);
  const withBodies = await requestBodyRequests(network, Number(lastBrowser.sequence_number) + 1, lastBrowser.monotonic_time_ns, artifacts);
  const requests = [...scrolled, ...adjacent, ...withBodies.events];
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
  const guest = await goldenEvidence(artifacts, guestStore);
  const physical = await goldenEvidence(artifacts, dispatchStore);
  assert(guest.events.some(event => event.type === 'wasm_guest_dispatch'), 'guest golden store holds a guest sample');
  assert(physical.events.some(event => event.type === 'wasm_dispatch_observation'), 'dispatch golden store holds an observation');
  // An owned two-level interpreter: observed claims, one contradicting its
  // static arm label, and an inner interpreter linked to its outer handler.
  const observed = await goldenEvidence(artifacts, observedStore);
  assert(observed.events.filter(event => event.type === 'wasm_guest_invocation').length === 2, 'observed store holds outer and inner activations');
  const manifest = [...demoArtifacts, source, bytecode, parseFailure, glue, withBodies.artifact, ...guest.artifacts, ...physical.artifacts, ...observed.artifacts];
  const retained = [...demoEvents, ...requests, ...guest.events, ...physical.events, ...observed.events];
  const vm = demoEvents.find(event => event.category === 'vm');
  assert(vm, 'demo store must contain a native vm event');
  const events = [...retained, ...namedBudgetGaps(vm, retained)];
  await writeFile(join(artifacts, 'manifest.jsonl'), manifest.map(record => JSON.stringify(record) + '\n').join(''));
  await writeFile(join(root, 'events.jsonl'), events.map(event => JSON.stringify(event) + '\n').join(''));
  return {
    store: join(root, 'events.jsonl'), traceStore: join(root, 'origin-trace.jsonl'),
    signalStore: join(root, 'request-signals.jsonl'), artifacts,
    apiCollection: join(root, 'api-collection.json'), localAnalyst: join(root, 'local-analyst.json'),
    invocationSites: join(root, 'app-support', 'js-invocation-sites-v1.json'),
  };
}
