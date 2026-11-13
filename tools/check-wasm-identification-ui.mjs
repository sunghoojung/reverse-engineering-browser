#!/usr/bin/env node
// The Sources identification summary and the Functions menu badges against
// the shipped scripts in an offline DOM model with fetch faked: the loading,
// error, empty and ready states, inert captured text, the badge lookup the
// Functions filter runs on every keystroke, and returning to a module whose
// report the four-report cache evicted. Layout and focus are covered by
// rendered test38 in tools/origin-trace-rendered-ui/.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {runInContext} from 'node:vm';
import {setImmediate as nextTurn} from 'node:timers/promises';

const {loadShippedUi} = createRequire(import.meta.url)('./check-native-only-startup.cjs');
const {window, context, asyncErrors, release} = loadShippedUi();
const document = window.document;
const settle = async () => { for (let turn = 0; turn < 6; turn += 1) await nextTurn(); };
const get = name => runInContext(name, context);
assert(document.getElementById('wasm-identification'), 'index.html declares the summary host');
assert.equal(typeof get('createWasmIdentificationPanel'), 'function', 'index.html loads wasm_identification.js');

const sha = index => String(index).padStart(64, '0');
const source = index => ({artifact_id: String(index), sha256: sha(index), kind: 'wasm', source_type: 'artifact'});
const report = (index, {suggestions = [], matches = [], conclusions = []} = {}) => ({
  schema: 'wasm-identification-v1', artifact_id: String(index), sha256: sha(index), status: 'complete', omissions: [],
  toolchain: {conclusions}, constants: {matches},
  functions: {imported_functions: 2, defined_functions: 8, labeled_functions: suggestions.length, suggestions,
    suggestion_window: {offset: 0, rows: suggestions.length, total_rows: suggestions.length, next_offset: null}}
});

let answer = () => new Promise(() => {});
const reads = [];
window.fetch = async url => { reads.push(String(url)); return answer(String(url)); };
const json = (status, body) => new window.Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json'}});

let selected = source(1);
const root = document.createElement('section');
document.body.append(root);
const reveals = [];
const panel = get('createWasmIdentificationPanel')({root, getSource: () => selected, inspecting: () => true,
  reveal: (_, offset) => reveals.push(offset)});
const text = () => root.textContent.replace(/\s+/g, ' ');

// Loading: the read starts once and the state says what is happening.
panel.sync();
await settle();
assert.equal(reads.length, 1);
assert.match(reads[0], /^\/api\/wasm\/identification\?artifact_id=1$/);
assert.match(text(), /Identifying toolchain, functions and constants/);
panel.sync();
assert.equal(reads.length, 1, 'a read in flight is not started again');

// Error: the backend's reason, an alert and Retry; Retry reads again.
selected = source(2);
answer = () => json(422, {error: 'WASM decoding failed: synthetic'});
panel.sync();
await settle();
assert.match(text(), /WASM decoding failed: synthetic/);
assert.equal(root.querySelector('[role=alert]')?.textContent, 'WASM decoding failed: synthetic');
const hostile = '<img src=x onerror=window.__rebInjected=1>';
answer = () => json(200, report(2, {
  conclusions: [{id: 'rust', label: 'Rust', kind: 'language', confidence: 'high', evidence_count: 1, evidence_truncated: false,
    evidence: [{record: 'producers', byte_offset: 12, detail: `language: ${hostile}`, function_index: null, confidence: 'high'}]}],
  suggestions: [[0, `JS glue: ${hostile}`, 'js_glue', 'wasm-bindgen', 'high', 'import', 38]],
  matches: [{id: 'crc32_table', label: 'CRC-32 table (reflected polynomial 0xEDB88320)', family: 'crc32', location: 'data',
    match: 'partial', matched: 255, total: 256, byte_offset: 400, byte_end: 1420, data_segment: 0, data_segments: [0],
    referenced_by: [{function_index: 5, byte_offset: 90, via: 'load_offset'}], reference_count: 1}]
}));
[...root.querySelectorAll('button')].find(button => button.textContent === 'Retry identification').click();
await settle();
assert.match(text(), /Rust · high/);
assert.match(text(), /CRC-32 table 255\/256/, 'the chip names the set; the tooltip keeps the full label');
assert.equal(root.querySelector('.wasm-id-chip[data-match=partial]')?.dataset.byteOffset, '400');
root.querySelector('.wasm-id-chip[data-byte-offset="400"]').click();
assert.deepEqual(reveals, [400], 'a chip reveals its evidence byte');
// Details lists captured text as text, never markup.
[...root.querySelectorAll('button')].find(button => button.textContent.startsWith('Details')).click();
assert.match(text(), /JS glue: <img src=x onerror=window.__rebInjected=1>/);
assert.equal(root.querySelector('img'), null, 'captured text is inserted as text');
assert.equal(window.__rebInjected, undefined);

// Empty: nothing matched is said, and nothing is concluded from absence.
selected = source(3);
answer = () => json(200, report(3));
panel.sync();
await settle();
assert.match(text(), /No toolchain evidence; nothing is concluded from absence\./);
assert.match(text(), /No known constants matched\./);
assert.match(text(), /0 of 10 functions labeled/);

// The badge map: built once per report, one lookup per function.
const many = Array.from({length: 20000}, (_, index) => [index, `label ${index}`, index % 2 ? 'allocator' : 'js_glue', 'lib', 'high', 'export', index]);
selected = source(4);
answer = () => json(200, report(4, {suggestions: many, matches: [{id: 'sha256_k', label: 'SHA-256 round constants', location: 'immediate',
  match: 'complete', matched: 64, total: 64, byte_offset: 9, byte_end: 9, function_index: 30000}]}));
panel.sync();
await settle();
const badge = get('wasmIdentificationBadge');
const started = performance.now();
for (let pass = 0; pass < 5; pass += 1) for (let index = 0; index < 20000; index += 1) badge(selected, index);
const elapsed = performance.now() - started;
// A scan per lookup took 87 s here; a map lookup is microseconds, even under load.
assert(elapsed < 5000, `100,000 badge lookups took ${elapsed.toFixed(0)} ms`);
assert.equal(badge(selected, 1).text, 'alloc');
assert.equal(badge(selected, 2).text, 'JS glue');
assert.equal(badge(selected, 30000).text, 'constant', 'a function holding a constant is badged');
assert.match(badge(selected, 30000).title, /SHA-256 round constants: 64\/64 complete/);
assert.equal(badge(selected, 25000), null);
assert.equal(badge(source(99), 1), null, 'no report, no badge');

// Eviction: four reports are kept. Returning to the first evicted module
// reads it again instead of showing a ready state with nothing to show.
for (const index of [5, 6]) {
  selected = source(index);
  answer = () => json(200, report(index));
  panel.sync();
  await settle();
}
const before = reads.length;
selected = source(2);
answer = () => json(200, report(2));
panel.sync();
await settle();
assert.equal(reads.length, before + 1, 'the evicted report is read again');
assert.equal(root.querySelector('[role=alert]'), null, 'no empty alert');
assert.match(text(), /0 of 10 functions labeled/);

assert.deepEqual(asyncErrors, []);
release();
console.log('PASS wasm identification UI: loading, error with Retry, empty, inert captured text, chip reveal, a 20,000-function badge map and a re-read after cache eviction');
