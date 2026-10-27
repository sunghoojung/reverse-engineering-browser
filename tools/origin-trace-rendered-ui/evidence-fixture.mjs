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
export const SOURCE_LINE_COUNT = 400;

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

export async function buildEvidence({root, sessions, guestStore, dispatchStore}) {
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
  // A synthetic native guest bytecode buffer beside the real golden one (109).
  const bytecode = await artifact(artifacts, {artifact_id: '310', session_id: '1', navigation_id: '100', frame_id: '200',
    parent_artifact_id: '303', creator_event_id: '1', capture_origin: 'native_wasm_guest', kind: 'bytecode_buffer',
    url: 'fixture://native-guest-hostile'},
  Buffer.concat([Buffer.from(HOSTILE_BYTECODE_MARKUP, 'utf8'), Buffer.from([0xff, 0xfe, 0x00, 0x80]), Buffer.from(Array.from({length: 32}, (_, index) => index))]));
  const guest = await goldenEvidence(artifacts, guestStore);
  const physical = await goldenEvidence(artifacts, dispatchStore);
  assert(guest.events.some(event => event.type === 'wasm_guest_dispatch'), 'guest golden store holds a guest sample');
  assert(physical.events.some(event => event.type === 'wasm_dispatch_observation'), 'dispatch golden store holds an observation');
  const manifest = [...demoArtifacts, source, bytecode, ...guest.artifacts, ...physical.artifacts];
  const events = [...demoEvents, ...requests, ...guest.events, ...physical.events];
  await writeFile(join(artifacts, 'manifest.jsonl'), manifest.map(record => JSON.stringify(record) + '\n').join(''));
  await writeFile(join(root, 'events.jsonl'), events.map(event => JSON.stringify(event) + '\n').join(''));
  return {
    store: join(root, 'events.jsonl'), traceStore: join(root, 'origin-trace.jsonl'),
    signalStore: join(root, 'request-signals.jsonl'), artifacts,
    apiCollection: join(root, 'api-collection.json'), localAnalyst: join(root, 'local-analyst.json'),
  };
}
