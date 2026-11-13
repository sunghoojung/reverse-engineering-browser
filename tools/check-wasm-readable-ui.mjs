#!/usr/bin/env node
// Readable view model and panel against stubbed wasm-pseudocode-v1 windows.
// Offline: no rendered layout or focus is claimed. Rendered acceptance is
// test37WasmReadableView in the packaged-app gate.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createContext, runInContext} from 'node:vm';

const require = createRequire(import.meta.url);
const {parseHTML} = require('./ui-startup-deps/node_modules/linkedom');
const ui = name => readFile(new URL(`../apps/research-ui/${name}`, import.meta.url), 'utf8');
const {wasmReadableDocument, wasmReadableSummary} = require('../apps/research-ui/wasm_readable.js');

const line = (depth, kind, owned, start) => [depth, kind, owned, [[start, start + 2]]];
const documentFor = (offset, count, total, extra = {}) => ({
  schema: 'wasm-pseudocode-v1', artifact_id: '400', sha256: 'a'.repeat(64), byte_size: 4096, function_index: 1,
  name: 'readable_run', name_source: 'export', status: 'complete', instruction_count: total * 2, lifted_instructions: total * 2,
  line_count: total, fallback_count: 1, spill_count: 0, omissions: [],
  lines: Array.from({length: count}, (_, index) => line(1, index === 1 ? 6 : 1, 2, 100 + (offset + index) * 2)),
  text: Array.from({length: count}, (_, index) => index === 0 ? '  <img src=x onerror=alert(1)>(l1)' : `  line ${offset + index}`).join('\n') + '\n',
  window: {line_offset: offset, line_limit: 400, lines: count, next_line_offset: offset + count < total ? offset + count : null},
  ...extra
});

// The validator refuses documents that do not answer the request.
const valid = wasmReadableDocument(documentFor(0, 3, 3), '400', 1, 0);
assert.equal(valid.lines.length, 3);
assert.equal(valid.lines[1].kind, 'fallback');
assert.deepEqual(valid.lines[0].ranges, [[100, 102]]);
assert.throws(() => wasmReadableDocument(documentFor(0, 3, 3), '401', 1, 0), /invalid document/);
assert.throws(() => wasmReadableDocument(documentFor(0, 3, 3), '400', 2, 0), /invalid document/);
assert.throws(() => wasmReadableDocument(documentFor(0, 3, 3), '400', 1, 3), /invalid document/);
assert.throws(() => wasmReadableDocument({...documentFor(0, 3, 3), schema: 'wasm-block-graph-v1'}, '400', 1, 0), /invalid document/);
assert.throws(() => wasmReadableDocument({...documentFor(0, 3, 3), text: 'one line\n'}, '400', 1, 0), /do not match/);
// A range past the module or reversed is dropped rather than revealed.
const ranged = documentFor(0, 1, 1);
ranged.lines[0][3] = [[5000, 5002], [9, 3], [10, 12]];
assert.deepEqual(wasmReadableDocument(ranged, '400', 1, 0).lines[0].ranges, [[10, 12]]);
assert.equal(wasmReadableSummary(documentFor(0, 3, 3)), '3 lines · 6 instructions · 1 raw');
assert.match(wasmReadableSummary({...documentFor(0, 3, 3), status: 'partial', spill_count: 2}), /2 temporaries · partial$/);

// The panel against a stubbed backend.
const {window, document} = parseHTML(`<!doctype html><section class="sources-editor"><button id="readable" hidden></button><button id="graph"></button>
  <section id="host" hidden></section></section>`);
const reads = [];
const total = 450;
const fetch = async url => {
  reads.push(url);
  if (url.startsWith('/api/wasm/functions')) return new Response(JSON.stringify({schema: 'wasm-function-index-v1', artifact_id: '400', functions: [[1, 10, 90, 1]], names: [[1, 'readable_run']], status: 'decoded', omissions: []}));
  const offset = Number(/line_offset=(\d+)/.exec(url)[1]);
  return new Response(JSON.stringify(documentFor(offset, Math.min(400, total - offset), total)));
};
const context = createContext({window, document, console, fetch, Response, AbortController, Error, TypeError, Map, JSON, Number, String, Math, setTimeout});
runInContext(`${await ui('block_graph.js')}\n${await ui('wasm_readable.js')}\nglobalThis.create = createWasmReadablePanel;`, context);
const host = document.getElementById('host'), button = document.getElementById('readable');
const revealed = [];
let focusedList = 0;
const panel = context.create({host, editor: host.closest('.sources-editor'), button, closeOn: [document.getElementById('graph')],
  revealOffset: offset => revealed.push(offset), initialFunction: () => null});
host.querySelector('.wasm-readable-lines').focus = () => { focusedList += 1; };
const settle = async () => { for (let i = 0; i < 20; i += 1) await new Promise(resolve => setTimeout(resolve, 0)); };
panel.sync({kind: 'javascript', source_type: 'artifact', artifact_id: '9', sha256: 'b'});
assert.equal(button.hidden, true, 'Readable is offered only for a Wasm artifact');
panel.sync({kind: 'wasm', source_type: 'artifact', artifact_id: '400', sha256: 'a'.repeat(64)});
assert.equal(button.hidden, false);
button.dispatchEvent(new window.Event('click'));
await settle();
assert.equal(panel.isOpen(), true);
assert.equal(host.closest('.sources-editor').getAttribute('data-readable'), 'true');
assert.ok(reads.some(url => url.includes('/api/wasm/pseudocode?artifact_id=400&function=1&line_offset=0&line_limit=400')), reads.join('\n'));
const rows = () => [...host.querySelectorAll('.wasm-readable-line')];
assert.equal(rows().length, 400);
// Captured text stays text.
assert.equal(host.querySelectorAll('img').length, 0, 'captured markup became DOM');
assert.equal(rows()[0].querySelector('.wasm-readable-text').textContent, '  <img src=x onerror=alert(1)>(l1)');
assert.equal(rows()[1].querySelectorAll('.wasm-readable-raw').length, 1, 'a fallback line carries the raw chip');
assert.equal(rows()[0].querySelector('.wasm-readable-offset').textContent, '000064');
assert.equal(host.querySelector('.wasm-readable-title').textContent, 'readable_run (func 1)');
// Choosing a line reveals its first byte; keys move the selection.
rows()[2].dispatchEvent(new window.Event('click'));
assert.deepEqual(revealed, [104]);
assert.equal(rows()[2].getAttribute('aria-selected'), 'true');
const list = host.querySelector('.wasm-readable-lines');
const press = key => { const event = new window.Event('keydown'); event.key = key; event.preventDefault = () => {}; list.dispatchEvent(event); };
press('ArrowDown');
assert.equal(rows()[3].getAttribute('aria-selected'), 'true');
press('Enter');
assert.deepEqual(revealed, [104, 106]);
assert.equal(focusedList, 2, 'the list takes focus back after each reveal');
press('End');
assert.equal(rows()[399].getAttribute('aria-selected'), 'true');
// Past the window's edge the next window is read.
press('ArrowDown');
await settle();
assert.ok(reads.some(url => url.includes('line_offset=400')), 'the next window was read');
assert.equal(rows().length, 50);
assert.equal(rows()[0].getAttribute('aria-selected'), 'true');
press('ArrowUp');
await settle();
assert.equal(rows().length, 400, 'moving back reads the earlier window');
assert.equal(rows()[399].getAttribute('aria-selected'), 'true');
// Graph closes Readable; a different module releases it.
document.getElementById('graph').dispatchEvent(new window.Event('click'));
assert.equal(panel.isOpen(), false);
assert.equal(host.hidden, true);
panel.sync({kind: 'wasm', source_type: 'artifact', artifact_id: '401', sha256: 'c'.repeat(64)});
assert.equal(rows().length, 0, 'another module drops the old lines');
console.log('Wasm readable view checks passed');
