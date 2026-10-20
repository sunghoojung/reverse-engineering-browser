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
// Native HTTP WKWebView deliberately copies on click; it must never use Blob downloads.
let copied = [], rejectCopy = false, clipboardWait = null, nativeBlobCalls = 0;
const nativeDocument = {...document, documentElement: {classList: {contains: value => value === 'native-shell'}}};
const nativeAPI = runInNewContext(source + ';RebVmOpcodeLedgerView', {
  document: nativeDocument, TextEncoder, TextDecoder, vmOpcodeLedger: model,
  Blob: function () { nativeBlobCalls++; throw Error('Native Blob path must not run'); },
  navigator: {clipboard: {writeText: async value => {
    copied.push(value); if (rejectCopy) throw Error('denied'); if (clipboardWait) await clipboardWait.promise;
  }}}
});
const native = nativeAPI.mount(new Element('section'));
native.editors.definition.value = definition; native.editors.ledger.value = text;
await native.validate(); assert.equal(copied.length, 0, 'Validation must not write the clipboard');
assert.equal(native.download.textContent, 'Copy validated ledger JSON');
await native.download.events.click(); assert.deepEqual(JSON.parse(copied[0]), ledger);
assert.match(native.notice.textContent, /copied to the clipboard/);
rejectCopy = true; await native.download.events.click(); assert.match(native.notice.textContent, /Could not copy/);
assert(native.exportText(), 'Copy denial preserves the valid local draft'); rejectCopy = false;
clipboardWait = deferred(); const copyPending = native.download.events.click();
const count = copied.length; await native.download.events.click(); assert.equal(copied.length, count, 'Repeated clicks cannot overlap clipboard writes');
native.clear.events.click(); clipboardWait.resolve(); await copyPending;
assert.match(native.notice.textContent, /cleared/, 'Old clipboard completion cannot overwrite newer state');
await native.download.events.click(); assert.equal(copied.length, count, 'Cleared/stale drafts cannot be copied');
assert.equal(nativeBlobCalls, 0, 'Native clipboard paths never attempt Blob downloads');
const noClipboardAPI = runInNewContext(source + ';RebVmOpcodeLedgerView', {document: nativeDocument, TextEncoder, TextDecoder, vmOpcodeLedger: model});
const unavailable = noClipboardAPI.mount(new Element('section'));
unavailable.editors.definition.value = definition; unavailable.editors.ledger.value = text; await unavailable.validate();
await unavailable.download.events.click(); assert.match(unavailable.notice.textContent, /unavailable or denied/);
console.log('Opcode ledger browser model/CLI parity and editor controller passed: exact identity, inert markup, malformed imports, stale export guard, cancelled and interrupted reads/validation.');

const descendants = element => [element, ...element.children.flatMap(descendants)];
const presentationRoot = new Element('section'), presentation = api.mount(presentationRoot);
assert(descendants(presentationRoot).filter(element => element.attributes['data-ledger-editor']).every(element => !element.open), 'JSON editors are secondary, closed by default');
assert.equal(presentation.editors.ledger.rows, 10);
await presentation.importFile('definition', file(definition)); await presentation.importFile('ledger', file(text)); await presentation.validate();
assert(descendants(presentation.results).some(element => element.tagName === 'table' && element.className === 'vm-tool-table'));

const presentationButtons = descendants(presentationRoot).filter(element => element.tagName === 'button');
assert(presentationButtons.find(element => element.textContent === 'Validate ledger').className.includes('vm-tool-primary'));
assert(presentationButtons.find(element => element.textContent === 'Clear all ledger inputs').className.includes('vm-tool-tertiary'));

// Full bounded coverage remains reachable; the inspector preserves every field.
const richDefinition = JSON.stringify({...JSON.parse(definition), definition_id: 'complete-ledger',
  opcodes: Array.from({length: 256}, (_, index) => ({code: index.toString(16).padStart(2, '0'), mnemonic: 'UNKNOWN',
    operands: [{name: 'value', width: 2, signed: true, kind: 'immediate'}], semantics: {operation: 'unknown', args: []}, flow: {kind: 'unknown'}}))});
const richLedger = await model.createLedger(richDefinition);
const richEntry = {opcode: 'ff', status: 'observed', meaning: 'Braces { } and "quoted" text remain inert <script>void 0</script>',
  handler_location: {artifact_id: 'handler-full', byte_offset: Number.MAX_SAFE_INTEGER}, operand_format: 'Signed 16-bit researcher note',
  source_refs: Array.from({length: 16}, (_, index) => ({artifact_id: `source-citation-${index}`, event_id: index % 2 ? `source-event-${index}` : null})),
  test_status: 'failed', test_refs: Array.from({length: 16}, (_, index) => ({artifact_id: `test-citation-${index}`, event_id: `test-event-${index}`})),
  unresolved_questions: Array.from({length: 16}, (_, index) => `Unresolved question ${index}?`)};
richLedger.entries.push(ledger.entries[0], {opcode: 'fe', status: 'unmodeled', meaning: null, handler_location: null,
  operand_format: null, source_refs: [], test_status: 'not_run', test_refs: [], unresolved_questions: []}, richEntry);
const richRoot = new Element('section'), rich = api.mount(richRoot);
const findElement = (root, predicate) => descendants(root).find(predicate);
const richButton = title => findElement(richRoot, element => element.tagName === 'button' && element.textContent === title);
const rowElements = () => descendants(rich.results).filter(element => element.attributes['data-ledger-opcode']);
const inspectorElement = () => findElement(richRoot, element => element.className === 'vm-review-inspector');
const search = () => findElement(richRoot, element => element.attributes['aria-label'] === 'Filter opcode coverage');
const statusFilter = () => findElement(richRoot, element => element.attributes['aria-label'] === 'Filter evidence status');
const query = () => { const detail = {search: false, previous: false, next: false}; richRoot.events['vm-workspace-query']({detail}); return detail; };
assert.deepEqual(query(), {search: false, previous: false, next: false});
assert(findElement(richRoot, element => Object.hasOwn(element.attributes, 'data-ledger-inputs')).open);
rich.editors.definition.value = richDefinition;
rich.editors.ledger.value = JSON.stringify(richLedger, null, 2).replace('"entries"', '"entr\\u0069es"');
await rich.validate();
assert.equal(findElement(richRoot, element => Object.hasOwn(element.attributes, 'data-ledger-inputs')).open, false);
assert.equal(rowElements().length, 32, 'DOM rows are bounded to one coverage page');
assert.deepEqual(query(), {search: true, previous: false, next: true});
const seenOpcodes = new Set();
for (let page = 0; page < 8; page++) {
  for (const row of rowElements()) seenOpcodes.add(row.attributes['data-ledger-opcode']);
  assert.equal(rowElements().length, 32);
  if (page < 7) {
    richButton('Next page').events.click();
    assert.equal(document.activeElement.attributes['aria-label'], `Inspect opcode ${((page + 1) * 32).toString(16)}`, 'Paging focuses the selected row when the clicked pager becomes disabled');
  }
}
assert.equal(seenOpcodes.size, 256, 'Every declared opcode is reachable, with no pagination truncation');
assert(richButton('Next page').disabled);
richButton('Previous page').events.click();
assert.equal(rowElements()[0].attributes['data-ledger-opcode'], 'c0');
richRoot.events['vm-workspace-search'](); assert.equal(document.activeElement, search());
search().value = 'TEST-CITATION-15'; search().events.input();
assert.equal(rowElements().length, 1); assert.equal(rowElements()[0].attributes['data-ledger-opcode'], 'ff');
assert.match(inspectorElement().textContent, /9007199254740991/);
assert.match(inspectorElement().textContent, /Signed 16-bit researcher note/);
assert.match(inspectorElement().textContent, /"width": 2/);
assert.match(inspectorElement().textContent, /failed.*tests were not executed/);
assert.deepEqual(query(), {search: true, previous: false, next: false});
richButton('References').events.click();
for (const ref of [...richEntry.source_refs, ...richEntry.test_refs]) {
  assert(inspectorElement().textContent.includes(ref.artifact_id));
  if (ref.event_id) assert(inspectorElement().textContent.includes(ref.event_id));
}
assert.match(inspectorElement().textContent, /event null \(not supplied\)/);
richButton('Questions').events.click();
for (const question of richEntry.unresolved_questions) assert(inspectorElement().textContent.includes(question));
richButton('Identity').events.click();
for (const identity of [richLedger.format, richLedger.definition_id, richLedger.definition_source_sha256, rich.getReport().source_sha256]) assert(inspectorElement().textContent.includes(identity));
richButton('Exact JSON').events.click();
assert.deepEqual(JSON.parse(findElement(inspectorElement(), element => element.tagName === 'pre').textContent), richEntry);
const beforeEditing = rich.editors.ledger.value;
rich.editors.ledger.setSelectionRange = (start, end) => { rich.editors.ledger.selectionStart = start; rich.editors.ledger.selectionEnd = end; };
richButton('Edit selected entry').events.click();
assert.equal(document.activeElement, rich.editors.ledger);
assert.deepEqual(JSON.parse(beforeEditing.slice(rich.editors.ledger.selectionStart, rich.editors.ledger.selectionEnd)), richEntry);
assert.equal(rich.editors.ledger.value, beforeEditing, 'Opening an exact entry editor never rewrites the draft');
assert.deepEqual(JSON.parse(rich.exportText()), richLedger, 'Coverage filters/selection do not change exported fields');
rich.editors.ledger.value = '{}';
const failedValidation = rich.validate();
assert.match(inspectorElement().textContent, /Stale validated snapshot/, 'Revalidation marks retained inspector stale before awaiting');
await failedValidation; assert.match(rich.notice.textContent, /Validation refused/); assert.equal(rich.exportText(), null);
rich.editors.ledger.value = beforeEditing; await rich.validate();
statusFilter().value = 'missing'; statusFilter().events.change();
assert.equal(rowElements().length, 0); assert.match(inspectorElement().textContent, /No opcode selected/);
assert.deepEqual(query(), {search: true, previous: false, next: false});
richButton('Clear coverage filters').events.click();
assert.equal(rowElements()[0].attributes['data-ledger-opcode'], '00');
for (let index = 0; index < 32; index++) richRoot.events['vm-workspace-next']();
assert.equal(rowElements()[0].attributes['data-ledger-opcode'], '20', 'Next selection crosses page boundaries');
assert.equal(document.activeElement.attributes['aria-label'], 'Inspect opcode 20');
richRoot.events['vm-workspace-previous']();
assert.equal(rowElements()[0].attributes['data-ledger-opcode'], '00');
assert.equal(document.activeElement.attributes['aria-label'], 'Inspect opcode 1f');
let prevented = 0;
for (const modifier of ['isComposing', 'altKey', 'ctrlKey', 'metaKey']) {
  document.activeElement.events.keydown({key: 'End', [modifier]: true, preventDefault: () => prevented++});
  assert.equal(document.activeElement.attributes['aria-label'], 'Inspect opcode 1f');
}
assert.equal(prevented, 0, 'Modified and IME row keys are not intercepted');
document.activeElement.events.keydown({key: 'End', preventDefault: () => prevented++});
assert.equal(prevented, 1); assert.equal(document.activeElement.attributes['aria-label'], 'Inspect opcode ff');
assert.deepEqual(query(), {search: true, previous: true, next: false});
richButton('Entry').events.click();
for (const modifier of ['isComposing', 'altKey', 'ctrlKey', 'metaKey']) {
  richButton('Entry').events.keydown({key: 'ArrowRight', [modifier]: true, preventDefault: () => assert.fail('Modified and IME tab keys are not intercepted')});
  assert.equal(document.activeElement.textContent, 'Entry');
}
richButton('Entry').events.keydown({key: 'ArrowRight', preventDefault() {}});
assert.equal(document.activeElement.textContent, 'References', 'Inspector tabs preserve keyboard focus');
rich.editors.ledger.value += ' '; rich.editors.ledger.events.input();
assert.equal(rich.exportText(), null); assert.match(inspectorElement().textContent, /Stale validated snapshot/);
richButton('Edit selected entry').events.click(); assert.match(rich.notice.textContent, /stale snapshot/);
await rich.validate(); assert(rich.exportText());
statusFilter().value = 'missing'; statusFilter().events.change();
richButton('Open JSON editor to add entry').events.click();
assert.match(rich.notice.textContent, /No entry was inserted/);
assert.equal(JSON.parse(rich.editors.ledger.value).entries.length, 3);
rich.clear.events.click();
assert.deepEqual(query(), {search: false, previous: false, next: false});
assert.equal(rich.exportText(), null);
console.log('Opcode ledger workbench passed: all 256 opcodes reachable with 32-row pages; full-field search, status filters, linked keyboard selection, all citations/questions/identity, exact JSON edit selection, stale guard, missing entries and unchanged exports.');

const refusedRoot = new Element('section');
const refusedCreation = api.mount(refusedRoot, {...model, createLedger: async () => { throw new TypeError('creation refused for test'); }});
refusedCreation.editors.definition.value = definition; refusedCreation.editors.ledger.value = JSON.stringify(await model.createLedger(definition));
await refusedCreation.validate(); assert(refusedCreation.exportText());
refusedCreation.editors.ledger.value = '';
const creating = refusedCreation.create();
assert.match(refusedCreation.results.textContent, /Stale validated snapshot/);
await creating; assert.match(refusedCreation.notice.textContent, /Creation refused/);
assert.equal(refusedCreation.exportText(), null, 'Failed creation preserves the previous snapshot as stale and blocks export');
