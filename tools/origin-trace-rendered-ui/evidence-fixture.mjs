// Builds one bounded, synthetic evidence session for rendered UI acceptance.
// Inputs are the deterministic `make e2e` demo stores plus events emitted by
// the real C++ native Wasm encoders. Nothing here is captured from a website.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {cp, mkdir, readFile, writeFile} from 'node:fs/promises';
import {join} from 'node:path';

// Captured values that would execute if any renderer inserted them as HTML.
export const HOSTILE_URL = 'inert.test<svg/onload=window.__rebInjected=1>';
export const HOSTILE_URL_MARKER = 'onload=window.__rebInjected=1';
export const HOSTILE_SOURCE_URL = 'https://inert.test/<b id=reb-injected-markup>source</b>.js';
export const HOSTILE_SOURCE_MARKER = '<img src=x onerror="window.__rebInjected=2">';
export const SYNTHETIC_REQUEST_COUNT = 72;
export const SOURCE_LINE_COUNT = 400;

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = text => Buffer.from(text, 'utf8').toString('hex');

// Mirrors `crate::vm::canonical`: sorted object keys, compact, ASCII-only.
function canonical(value) {
  const sort = item => Array.isArray(item) ? item.map(sort)
    : item && typeof item === 'object' ? Object.fromEntries(Object.keys(item).sort().map(key => [key, sort(item[key])])) : item;
  return JSON.stringify(sort(value)).replace(/[\u0080-￿]/g, ch => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

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

// Same module and recipe as the backend `native_guest_cpp_golden` host
// fixture, so the C++ encoder's recipe digest binds a real adapter artifact.
async function nativeGuestEvidence(root, guestGolden) {
  const bytes = [...Buffer.from('0061736d010000000104016000000302010005030100010a1d011b01017f0340200041016a210041002d00001a41000e020000000b0b', 'hex')];
  bytes[24] += 2; bytes[26] += 2;
  bytes.splice(32, 0, 0x10, 0);
  bytes.splice(14, 0, 2, 7, 1, 1, 0x68, 1, 0x66, 0, 0);
  const identity = {session_id: '101', navigation_id: '0', frame_id: '103'};
  const module = await artifact(root, {artifact_id: '107', ...identity, kind: 'wasm',
    capture_origin: 'webassembly_compile', url: 'fixture://native-guest'}, Buffer.from(bytes));
  const recipe = {version: 1, sample_limit: 16, module_sha256: module.sha256, function_index: 1, dispatch_module_offset: 58,
    pc: {local_index: 0, value_type: 'i32', adjustment: '0', subtract_memory_base: true},
    bytecode: {memory_index: 0, base: {kind: 'constant', value: '256'}, length: {kind: 'constant', value: '4'}},
    opcode: {width: 1, endian: 'little'}, import_call_offsets: [41]};
  const adapter = await artifact(root, {artifact_id: '108', ...identity, parent_artifact_id: '107', creator_event_id: '104',
    kind: 'wasm_guest_adapter', capture_origin: 'native_wasm_guest', url: 'fixture://native-guest'},
  Buffer.from(canonical(recipe), 'utf8'));
  const bytecode = await artifact(root, {artifact_id: '109', ...identity, parent_artifact_id: '107', creator_event_id: '105',
    kind: 'bytecode_buffer', capture_origin: 'native_wasm_guest', url: 'fixture://native-guest'}, Buffer.from([0, 0x42, 0, 0]));
  const events = jsonLines(execFileSync(guestGolden,
    ['--host-fixture', '--recipe-sha', adapter.sha256, '--case', 'wide-identities'], {encoding: 'utf8'}));
  assert.equal(events.length, 2, 'guest encoder emits invocation and dispatch');
  // A synchronous retained host child of the guest dispatch, as in the golden test.
  const host = {...events[1], category: 'runtime', type: 'api_call', sequence_number: '106',
    parent_event_id: '105', payload_size: 0, payload: ''};
  return {artifacts: [module, adapter, bytecode], events: [...events, host]};
}

// Physical br_table observation with the widest identities the wire allows.
async function nativeWasmEvidence(root, dispatchGolden) {
  const [event] = jsonLines(execFileSync(dispatchGolden, ['--case', 'wide-identities'], {encoding: 'utf8'}));
  const module = await artifact(root, {artifact_id: event.artifact_id, session_id: event.session_id,
    navigation_id: event.navigation_id, frame_id: event.frame_id, kind: 'wasm', mime_type: 'application/wasm',
    url: 'fixture://native-wasm-golden'},
  Buffer.from('0061736d010000000104016000000302010005030100010a1d011b01017f0340200041016a210041002d00001a41000e020000000b0b', 'hex'));
  return {artifacts: [module], events: [event]};
}

// Enough native network rows to require list scrolling, one with a hostile URL.
function syntheticRequests(template, firstSequence, firstTime) {
  const events = [];
  let sequence = firstSequence, time = BigInt(firstTime);
  for (let index = 0; index < SYNTHETIC_REQUEST_COUNT; index += 1) {
    const requestId = String(1000 + index);
    // Native network payloads carry the method and host only.
    const url = index === 7 ? HOSTILE_URL : `item-${index}.scroll.test`;
    const steps = [['request_initiated', `GET ${url}`, 0], ['request_started', `GET ${url}`, 0],
      ['response_started', 'application/json', 200], ['request_completed', 'completed', 200]];
    let parent = '0';
    for (const [type, text, status] of steps) {
      time += 1000n;
      const event = {...template, sequence_number: String(sequence), monotonic_time_ns: String(time), request_id: requestId,
        parent_event_id: parent, type, status_code: status, payload_size: Buffer.byteLength(text), payload: hex(text)};
      parent = event.sequence_number;
      sequence += 1;
      events.push(event);
    }
  }
  return events;
}

export async function buildEvidence({root, sessions, guestGolden, dispatchGolden}) {
  const artifacts = join(root, 'artifacts');
  await mkdir(join(artifacts, 'blobs'), {recursive: true});
  for (const name of ['origin-trace.jsonl', 'request-signals.jsonl']) await cp(join(sessions, name), join(root, name));
  const demoEvents = jsonLines(await readFile(join(sessions, 'demo.jsonl'), 'utf8'));
  const demoArtifacts = jsonLines(await readFile(join(sessions, 'artifacts/manifest.jsonl'), 'utf8'));
  for (const record of demoArtifacts) await cp(join(sessions, 'artifacts', record.content_path), join(artifacts, record.content_path));
  const network = demoEvents.find(event => event.category === 'network');
  assert(network, 'demo store must contain a native network event');
  const last = demoEvents.at(-1);
  const requests = syntheticRequests(network, Number(last.sequence_number) + 1, last.monotonic_time_ns);
  const lines = Array.from({length: SOURCE_LINE_COUNT}, (_, index) => index === 2
    ? `// ${HOSTILE_SOURCE_MARKER}` : `const retainedLine${index} = ${index}; // long line ${'x'.repeat(index % 7 === 0 ? 180 : 12)}`);
  const source = await artifact(artifacts, {artifact_id: '303', session_id: '1', navigation_id: '100', frame_id: '200',
    capture_origin: 'network_response', kind: 'javascript', mime_type: 'text/javascript', url: HOSTILE_SOURCE_URL},
  Buffer.from(lines.join('\n') + '\n', 'utf8'));
  const guest = await nativeGuestEvidence(artifacts, guestGolden);
  const physical = await nativeWasmEvidence(artifacts, dispatchGolden);
  const manifest = [...demoArtifacts, source, ...guest.artifacts, ...physical.artifacts];
  const events = [...demoEvents, ...requests, ...guest.events, ...physical.events];
  await writeFile(join(artifacts, 'manifest.jsonl'), manifest.map(record => JSON.stringify(record) + '\n').join(''));
  await writeFile(join(root, 'events.jsonl'), events.map(event => JSON.stringify(event) + '\n').join(''));
  return {
    store: join(root, 'events.jsonl'), traceStore: join(root, 'origin-trace.jsonl'),
    signalStore: join(root, 'request-signals.jsonl'), artifacts,
    apiCollection: join(root, 'api-collection.json'), localAnalyst: join(root, 'local-analyst.json'),
  };
}
