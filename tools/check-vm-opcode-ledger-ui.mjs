#!/usr/bin/env node
// Browser-portable model parity and interruption-safe editor controller checks.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import {webcrypto} from 'node:crypto';
import model from '../apps/research-ui/vm_opcode_ledger.js';
import {inspectLedger} from './vm-opcode-ledger.mjs';
const definition = JSON.stringify({format: 'reb-vm-definition-v1', definition_id: 'owned', architecture: 'stack', opcode_bytes: 1,
  operand_endianness: 'little', register_count: 0, opcodes: [{code: '00', mnemonic: 'UNKNOWN', operands: [], semantics: {operation: 'unknown', args: []}, flow: {kind: 'unknown'}}]});
const ledger = await model.createLedger(definition);
ledger.entries.push({opcode: '00', status: 'inferred', meaning: '<img src=x onerror=alert(1)>', handler_location: null,
  operand_format: null, source_refs: [{artifact_id: 'owned', event_id: null}], test_status: 'not_run', test_refs: [], unresolved_questions: ['Unknown overflow?']});
const text = JSON.stringify(ledger);
assert.deepEqual(await model.inspectLedger(text, definition), inspectLedger(text, definition));
await assert.rejects(() => model.inspectLedger(text, definition + ' '));
await assert.rejects(() => model.inspectLedger(text.replace('"entries":', '"entries":[],"entries":'), definition));
await assert.rejects(() => model.inspectLedger(' '.repeat(1048577), definition));
const context = {TextEncoder, crypto: webcrypto};
const browserSource = await Promise.all(['captured_client.js', 'vm_static.js', 'vm_opcode_ledger.js'].map(name => readFile(new URL('../apps/research-ui/' + name, import.meta.url), 'utf8')));
const portable = runInNewContext(browserSource.join('\n') + ';vmOpcodeLedger', context);
assert.deepEqual(JSON.parse(JSON.stringify(await portable.inspectLedger(text, definition))), inspectLedger(text, definition));
const source = await readFile(new URL('../apps/research-ui/vm_opcode_ledger_view.js', import.meta.url), 'utf8');
const document = {activeElement: null};
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.attributes = {}; this.style = {}; this.text = ''; this.value = ''; this.files = []; }
  set textContent(value) { this.text = String(value); this.children = []; } get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...items) { this.children.push(...items); } replaceChildren(...items) { this.text = ''; this.children = items; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  addEventListener(key, action) { this.events[key] = action; } focus() { document.activeElement = this; }
}
document.createElement = tag => new Element(tag);
const api = runInNewContext(source + ';RebVmOpcodeLedgerView', {document, TextEncoder, TextDecoder, vmOpcodeLedger: model});
const root = new Element('section'), ui = api.mount(root);
const bytes = text => new TextEncoder().encode(text);
const file = text => ({size: bytes(text).length, arrayBuffer: async () => bytes(text).buffer});
const deferred = () => { let resolve; const promise = new Promise(done => resolve = done); return {resolve, promise}; };
assert.equal(ui.exportText(), null);
await ui.importFile('definition', file(definition)); await ui.create();
assert.deepEqual(JSON.parse(ui.editors.ledger.value).entries, []);
await ui.validate(); assert.equal(ui.getReport().coverage.counts.missing_entries, 1);
await ui.importFile('ledger', file(text)); await ui.validate();
assert.deepEqual(JSON.parse(ui.exportText()), ledger); assert.match(ui.results.textContent, /<img src=x/);
assert(!ui.results.children.some(child => child.tagName === 'img'));
await ui.create(); assert.match(ui.notice.textContent, /existing work was kept/);
ui.editors.ledger.value = '{}'; ui.editors.ledger.events.input(); assert.equal(ui.exportText(), null);
await ui.validate(); assert.match(ui.notice.textContent, /Validation refused.*stale/);
assert.equal(ui.getReport().ledger.entries[0].meaning, ledger.entries[0].meaning);
await ui.importFile('ledger', null); assert.equal(ui.editors.ledger.value, '{}');
let read = false;
await ui.importFile('ledger', {size: 1048577, arrayBuffer: async () => {read = true;}}); assert(!read);
await ui.importFile('ledger', {size: 1, arrayBuffer: async () => new Uint8Array([255]).buffer}); assert.match(ui.notice.textContent, /Import refused/);
await ui.importFile('ledger', file('\ufeff' + text)); assert.match(ui.notice.textContent, /BOM/);
const old = deferred(); const loading = ui.importFile('ledger', {size: 10, arrayBuffer: () => old.promise});
ui.editors.ledger.value = text; ui.editors.ledger.events.input(); await ui.validate();
old.resolve(bytes('{}').buffer); await loading; assert.equal(ui.editors.ledger.value, text); assert(ui.exportText());
const clearing = deferred(); const loadBeforeClear = ui.importFile('ledger', {size: 10, arrayBuffer: () => clearing.promise});
ui.clear.events.click(); assert.equal(ui.getReport(), null); assert.equal(document.activeElement, ui.files.definition);
await ui.importFile('definition', file(definition)); await ui.create(); await ui.validate(); assert(ui.exportText());
clearing.resolve(bytes('{}').buffer); await loadBeforeClear; assert(ui.exportText());
const hash = deferred(); const slow = api.mount(new Element('section'), {...model, inspectLedger: () => hash.promise});
slow.editors.definition.value = definition; slow.editors.ledger.value = text;
const validating = slow.validate(); slow.clear.events.click(); hash.resolve(await model.inspectLedger(text, definition)); await validating;
assert.equal(slow.getReport(), null); assert.equal(slow.exportText(), null);
console.log('Opcode ledger browser model/CLI parity and editor controller passed: exact identity, inert markup, malformed imports, stale export guard, cancelled and interrupted reads/validation.');
