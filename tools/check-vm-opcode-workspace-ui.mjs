#!/usr/bin/env node
// Authored fixtures and shipped rendering functions only. No captured WASM is executed.
import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';

const root = fileURLToPath(new URL('..', import.meta.url));
// Inputs come only from REB_NATIVE_WASM_* variables. Rendered acceptance is
// `make rendered-ui-check`; a stale or misspelled flag must fail, not be ignored.
if (process.argv.length > 2) throw new Error(`Unexpected arguments: ${process.argv.slice(2).join(' ')}`);
const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
const model = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const fixture = JSON.parse(await readFile(join(root, 'tests/research_ui/fixtures/vm-opcode-workspace-v2.json'), 'utf8'));
const hostWorkspace = structuredClone(fixture), hostSource = hostWorkspace.workspaces[0], sample = hostSource.samples[0];
const hostLinks = {contract_version: 1, document_kind: 'vm-host-links', workspace_document_digest: hostWorkspace.document_digest,
  document_digest: 'e'.repeat(64), workspaces: [{interpreter_artifact_id: hostSource.interpreter_artifact_id,
    source_artifact_sha256: hostSource.source_artifact_sha256, omissions: [], links: [{
      host_event: {...sample.event, sequence_number: '50'}, category: 'runtime', type: 'api_call', state: 'observed',
      reason: 'direct-dispatch-parent', guest_position: {sample_event: sample.event, invocation_event: sample.invocation_event,
        invocation_id: sample.invocation_id, instruction_pointer: sample.instruction_pointer,
        instruction_pointer_units: sample.instruction_pointer_units}}]}]};
assert(runInNewContext(`${model}\nisVmHostLinksDocument(hostLinks, hostWorkspace)`, {hostLinks, hostWorkspace, TextEncoder}));
const workspace = fixture.workspaces[0];
workspace.runtime = 'webassembly'; workspace.model = 'unknown'; workspace.samples = []; workspace.sample_count = 0;
workspace.evidence_class = 'handler-table-candidate'; delete workspace.machine_state;
workspace.handlers = [
  {opcode: 0, state: 'inferred', source: {byte_offset: 45, byte_size: 5}, label: 'br_table selector 0', operand_width: 0,
    sample_count: 0, effects: [], notes: 'Dispatch selector only; guest opcode binding is unproven.'},
  {opcode: null, state: 'unknown', source: {byte_offset: 50, byte_size: 3}, label: 'call_indirect target', operand_width: 0,
    sample_count: 0, effects: [], notes: '<img src=x onerror=alert(1)> is inert captured text. No static index.'},
  {opcode: 0, state: 'inferred', source: {byte_offset: 70, byte_size: 5}, label: 'br_table selector 0', operand_width: 0,
    sample_count: 0, effects: [], notes: 'A separate dispatch site has its own selector 0.'}
];
workspace.coverage.handler_count = fixture.summary.handler_count = 3; fixture.summary.sample_count = 0;
assert(runInNewContext(`${model}\nisVmOpcodeWorkspaceDocument(fixture)`, {fixture, TextEncoder}));
const helper = app.slice(app.indexOf('      function textElement('), app.indexOf('      function emptyListboxOption('));
const renders = app.slice(app.indexOf('      function vmField('), app.indexOf('      function renderVmOpcodeWorkspaceInPlace('));
assert(helper.includes('function textElement')); assert(renders.includes('function renderVmOpcodeWorkspace'));
console.log('PASS authored WASM workspace fixture and shipped-renderer boundaries (model check, not rendered QA)');

// Renderer-level exhaustive paging checks; authored inputs are never executed.
class TestElement {
  constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.attributes = {}; this.dataset = {}; this.style = {}; this.value = ''; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.text = ''; this.children = items; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  addEventListener(key, action) { this.events[key] = action; }
  focus() { testDocument.activeElement = this; }
  click() { if (!this.disabled) this.events.click?.(); }
  dispatchEvent(event) { this.events[event.type]?.(event); }
}
const testDocument = {createElement: tag => new TestElement(tag), createTextNode: text => { const node = new TestElement('#text'); node.textContent = text; return node; }, querySelector: () => null};
const renderApiState = {vmOpcodeWorkspace: hostWorkspace, vmHostLinks: hostLinks, vmHostLinksStatus: 'ready'};
const renderApi = runInNewContext(`${model}\n${helper}\n${renders}\n({renderVmEffects,renderVmReachability,renderVmBytecode,renderVmHostLinks,renderVmSessionSources,renderVmWorkspaceCoverage,appendVmPagedRows,renderVmHandlers,renderVmDispatchInventory,renderVmDispatchStructure,renderVmDispatchSites,renderVmHandlerTables,renderNativeWasmObservations,vmOpcodeRows})`, {document: testDocument, state: renderApiState, TextEncoder, Event});
const descendants = element => [element, ...element.children.flatMap(descendants)];
const findButton = (root, label) => descendants(root).find(node => node.tagName === 'button' && node.textContent === label);
const many = structuredClone(hostSource);
const effect = {effect_id:'e', operation:'constant', evidence_class:'inferred',instruction_size:1,operand_layout:[],reads:[],writes:[],flow:{kind:'next',target_operand:null,target_offset:null},atomic_group:null,superoperator:null};
many.handlers = Array.from({length:257}, (_,index) => ({...hostSource.handlers[0],opcode:index,effects:[{...effect,effect_id:`effect-${index}`}]}));
many.traversal = {...many.traversal,instructions:Array.from({length:257}, (_,index) => ({artifact_id:'108',byte_offset:index,opcode:1,byte_size:1,effect_id:`effect-${index}`})),edges:[]};
for (const [node,label,needle] of [[renderApi.renderVmEffects(many),'effects','effect-256'],[renderApi.renderVmReachability(many),'reachable instructions','byte 256']]) {
  const rows = () => descendants(node).find(item => item.dataset.vmPagedRows === label);
  assert.equal(rows().children.length,32); assert(!rows().textContent.includes(needle));
  const next = findButton(node,`Next ${label}`), previous = findButton(node,`Previous ${label}`);
  for(let page=0;page<8;page++)next.click();
  assert.equal(rows().children.length,1);assert(rows().textContent.includes(needle));assert(next.disabled);assert.equal(testDocument.activeElement,previous);
  previous.click();assert.equal(rows().children.length,32);assert(!next.disabled);
}
many.snapshots = [{artifact_id:'108',origin:'runtime-typed-array',byte_count:1,preview_hex:'01',truncated:false,unavailable_reason:null},{artifact_id:'109',origin:'runtime-typed-array',byte_count:2,preview_hex:'aabb',truncated:true,unavailable_reason:'authored partial'}];many.bytecode_artifact_id='108';
const bytesView=renderApi.renderVmBytecode(many),selector=descendants(bytesView).find(node=>node.tagName==='select');
assert.equal(selector.children.length,2);assert(bytesView.textContent.includes('01'));
selector.value='1';selector.events.change();assert(bytesView.textContent.includes('aa bb'));assert(bytesView.textContent.includes('authored partial'));
const noBytes=renderApi.renderVmBytecode({...many,snapshots:[]});assert(descendants(noBytes).find(node=>node.tagName==='select').disabled);assert(noBytes.textContent.includes('No bytecode preview'));
const modulePreview = {artifact_id: workspace.interpreter_artifact_id, byte_offset: 45, byte_count: 5, preview_hex: '0e01020304', truncated: false};
const moduleDocument = structuredClone(fixture);
moduleDocument.workspaces[0].captured_module_preview = modulePreview;
const validateModule = value => runInNewContext(`${model}\nisVmOpcodeWorkspaceDocument(value)`, {value, TextEncoder});
assert(validateModule(moduleDocument));
const callerDocument = structuredClone(hostWorkspace);
const callerWorkspace = callerDocument.workspaces[0];
for (const retained of callerWorkspace.samples) {
  retained.provenance = {source: 'caller-supplied', source_artifact_sha256: callerWorkspace.source_artifact_sha256, input_sha256: 'a'.repeat(64)};
  retained.event.process_id = 0;
  retained.instruction_pointer_units = 'unknown'; retained.invocation_id = null; retained.invocation_event = null;
  retained.bytecode_artifact_id = '0';
}
for (const handler of callerWorkspace.handlers) if (handler.state === 'observed') {
  handler.state = 'inferred'; handler.notes = 'Caller-supplied report; no independent runtime observation.';
}
callerWorkspace.coverage.complete = false;
callerWorkspace.coverage.omissions.push({reason: 'caller-samples-unverified'}, {reason: 'sampler-unavailable'});
// Unknown PC units and inferred handlers are not a guest ISA. Numeric cases remain a static candidate.
callerWorkspace.evidence_class = 'handler-table-candidate';
assert(validateModule(callerDocument), 'caller provenance remains visible without native proof');
assert(runInNewContext(`${model}\nvmStaticSampleNoticeText(value)`, {value: callerWorkspace, TextEncoder}).includes('not native runtime observations'));
assert(runInNewContext(`${model}\nvmOpcodeSamplePositions(value)[0]`, {value: callerWorkspace.samples, TextEncoder}).startsWith('Caller-reported PC'));
for (const corrupt of [
  doc => { doc.workspaces[0].samples[0].provenance.source = 'native'; },
  doc => { delete doc.workspaces[0].samples[0].provenance; },
  doc => { doc.workspaces[0].samples[0].provenance.source_artifact_sha256 = 'f'.repeat(64); },
  doc => { doc.workspaces[0].samples[0].event.process_id = 7; },
  doc => { doc.workspaces[0].samples[0].bytecode_artifact_id = '401'; },
  doc => { doc.workspaces[0].samples[0].instruction_pointer_units = 'byte-offset'; },
  doc => { doc.workspaces[0].handlers.find(handler => handler.sample_count > 0).state = 'observed'; },
  doc => { doc.workspaces[0].coverage.omissions = doc.workspaces[0].coverage.omissions.filter(row => row.reason !== 'caller-samples-unverified'); }
]) {
  const invalid = structuredClone(callerDocument); corrupt(invalid);
  assert(!validateModule(invalid), 'unknown or stripped provenance cannot become native proof');
}
assert(!runInNewContext(`${model}\nisVmHostLinksDocument(hostLinks, value)`, {hostLinks, value: callerDocument, TextEncoder}), 'native host position cannot bind a caller report');

assert.equal(moduleDocument.summary.snapshot_count, fixture.summary.snapshot_count);
for (const changes of [
  {artifact_id: '999'}, {byte_offset: 46}, {byte_offset: -1}, {byte_offset: Number.MAX_SAFE_INTEGER},
  {byte_count: 1}, {preview_hex: ''}, {preview_hex: 'zz'}, {truncated: true}, {origin: 'captured-module'}
]) {
  const malformed = structuredClone(moduleDocument);
  Object.assign(malformed.workspaces[0].captured_module_preview, changes);
  assert(!validateModule(malformed), JSON.stringify(changes));
}
const staticFrontier = structuredClone(moduleDocument);
staticFrontier.workspaces[0].traversal = {
  entry_offsets: [], instructions: [], edges: [], complete: false,
  frontier: [{artifact_id: null, byte_offset: null, reason: 'static-module-only'}]
};
assert(validateModule(staticFrontier), 'static module bytes are not a guest snapshot frontier');
const repeatedSample = structuredClone(moduleDocument);
const unbound = structuredClone(sample);
unbound.opcode = 0;
unbound.interpreter_artifact_id = repeatedSample.workspaces[0].interpreter_artifact_id;
repeatedSample.workspaces[0].samples = [unbound];
repeatedSample.workspaces[0].sample_count = 1;
repeatedSample.summary.sample_count = 1;
assert(validateModule(repeatedSample), 'repeated selectors stay unbound when one sample exists');
repeatedSample.workspaces[0].handlers[0].sample_count = 1;
repeatedSample.workspaces[0].handlers[0].state = 'observed';
assert(!validateModule(repeatedSample), 'one sample cannot mark every repeated selector observed');
const wrongRuntime = structuredClone(hostWorkspace);
wrongRuntime.workspaces[0].captured_module_preview = modulePreview;
assert(!validateModule(wrongRuntime));
const sourceAsSnapshot = structuredClone(fixture);
sourceAsSnapshot.workspaces[0].snapshots[0].origin = 'captured-module';
assert(!validateModule(sourceAsSnapshot), 'Source instructions cannot masquerade as runtime snapshots');
const capturedModule=renderApi.renderVmBytecode({snapshots:[],captured_module_preview:modulePreview});
assert(capturedModule.textContent.includes('0e 01'));
assert(capturedModule.textContent.includes('Dispatch instruction bytes from the captured module. This is not a runtime memory snapshot.'));
assert(capturedModule.textContent.includes('dispatch at byte 45'));
assert(capturedModule.textContent.includes('module byte offset45'));
const capturedAlongsideRuntime=renderApi.renderVmBytecode({...many,captured_module_preview:modulePreview});
const evidenceSelector=descendants(capturedAlongsideRuntime).find(node=>node.tagName==='select');
assert.equal(evidenceSelector.children.length,3);
assert(!capturedAlongsideRuntime.textContent.includes('This is not a runtime memory snapshot.'));
evidenceSelector.value='2';evidenceSelector.events.change();
assert(capturedAlongsideRuntime.textContent.includes('0e 01'));
assert(capturedAlongsideRuntime.textContent.includes('module byte offset45'));
assert.equal(many.snapshots.length,2,'Rendering must not mutate runtime snapshots');
const originalLinks=hostLinks.workspaces[0].links;hostLinks.workspaces[0].links=Array.from({length:65},(_,index)=>({...originalLinks[0],host_event:{...originalLinks[0].host_event,sequence_number:String(50+index)}}));
const hostView=renderApi.renderVmHostLinks(hostSource);findButton(hostView,'Next host links').click();findButton(hostView,'Next host links').click();assert(hostView.textContent.includes('event 1:1:114'));assert(hostView.textContent.includes('guest_position PC'));assert(findButton(hostView,'Next host links').disabled);hostLinks.workspaces[0].links=originalLinks;
const staticLinks=structuredClone(hostLinks);
staticLinks.workspaces[0].omissions=['dispatch-samples-unavailable'];
staticLinks.workspaces[0].links=[{host_event:{...sample.event,sequence_number:'50'},category:'network',type:'request_initiated',state:'unknown',reason:'dispatch-samples-unavailable',guest_position:null}];
renderApiState.vmHostLinks=staticLinks;
const staticHost=renderApi.renderVmHostLinks(hostSource);
assert(staticHost.textContent.includes('Static only'));
assert(staticHost.textContent.includes('dispatch-samples-unavailable'));
assert(staticHost.textContent.includes('guest_position null'));
assert(staticHost.textContent.includes('not an empty workspace'));
assert(staticHost.textContent.includes('correlation'));
assert(!staticHost.textContent.includes('guest_position PC'));
renderApiState.vmHostLinks={...hostLinks, workspace_document_digest:'f'.repeat(64)};
const staleHost=renderApi.renderVmHostLinks(hostSource);
assert(staleHost.textContent.includes('Guest position unknown'));
renderApiState.vmHostLinks=hostLinks;
const unscopedSources=renderApi.renderVmSessionSources(hostSource);
assert(unscopedSources.textContent.includes('not in the retained catalog'));
assert(!unscopedSources.textContent.includes('guest_position PC'));
const sampleWorkspace={...hostSource,samples:Array.from({length:65},(_,index)=>({...sample,sample_index:index})),handlers:[{...hostSource.handlers.find(handler=>handler.opcode===sample.opcode),sample_count:65}]};
const sampleRow=renderApi.vmOpcodeRows(sampleWorkspace)[0];assert.equal(sampleRow.positions.length,4);assert.equal(sampleRow.retainedSamples.length,65);assert.equal(sampleRow.operandWidth,sampleWorkspace.handlers[0].operand_width);
const authoredSpans = workspace.handlers.map(handler => `${handler.source.byte_offset}:${handler.source.byte_size}`);
assert.equal(new Set(authoredSpans).size, workspace.handlers.length, 'authored WASM arms use distinct source spans');
const authoredRows = renderApi.vmOpcodeRows(workspace);
assert.deepEqual(Array.from(authoredRows, row => row.key), ['0::45', 'null::50', '0::70']);
assert.deepEqual(Array.from(authoredRows, row => row.label), ['br_table selector 0', 'call_indirect target', 'br_table selector 0']);
const authoredListing = renderApi.renderVmHandlers(workspace);
assert(authoredListing.textContent.includes('3 dispatch-arm candidates'));
assert(!authoredListing.textContent.includes('dispatch sites'));
assert.equal(descendants(authoredListing).filter(node => node.className === 'vm-handler-row').length, 3);
const handler = (opcode, state, offset, size, label, samples, notes, operandWidth = 0) =>
  ({opcode, state, source: {byte_offset: offset, byte_size: size}, label, operand_width: operandWidth, sample_count: samples, effects: [], notes});
const sharedHandlers = [
  handler(0, 'inferred', 20465, 117, 'br_table selector 0', 1, 'The source range cites the dispatch instruction.'),
  handler(1, 'inferred', 20465, 117, 'br_table selector 1', 2, 'Second selector.'),
  handler(2, 'unknown', 20465, 117, 'br_table selector 2', 0, 'Third selector.'),
  handler(4, 'inferred', 90, 6, 'br_table selector 4', 1, 'Alone.', 1),
  handler(null, 'unknown', 400, 8, 'call_indirect target', 0, 'First indirect.'),
  handler(7, 'inferred', 400, 8, 'br_table selector 7', 5, 'Not every label is br_table.', 2)
];
sharedHandlers[3].handler_index = 4;
const sharedWorkspace = {runtime: 'webassembly', handlers: sharedHandlers, samples: [
  {opcode: 0, instruction_pointer: 1, instruction_pointer_units: 'instruction-index', handler_index: 0, bytecode_artifact_id: '401'},
  {opcode: 1, instruction_pointer: 2, instruction_pointer_units: 'instruction-index', handler_index: 1, bytecode_artifact_id: '401'},
  {opcode: 99, instruction_pointer: 9, instruction_pointer_units: 'instruction-index', handler_index: 9, bytecode_artifact_id: '401'}
]};
const handlersBefore = structuredClone(sharedHandlers);
const sharedRows = renderApi.vmOpcodeRows(sharedWorkspace);
assert.deepEqual(sharedWorkspace.handlers, handlersBefore);
assert.equal(sharedWorkspace.handlers.length, 6);
assert.deepEqual(Array.from(sharedRows, row => row.key), ['span:20465:117', '4:4:90', 'span:400:8']);
assert.equal(sharedRows[0].opcode, 'shared');
assert.equal(sharedRows[0].label, 'br_table · 3 selectors');
assert.equal(sharedRows[0].state, 'unknown');
assert.equal(sharedRows[0].samples, 3);
assert.equal(sharedRows[0].operandWidth, 0);
assert.equal(sharedRows[0].source, '20465 + 117 bytes');
assert.equal(sharedRows[0].notes, 'The source range cites the dispatch instruction. 3 selectors share this instruction and are not separate handler bodies.');
assert.equal(sharedRows[0].retainedSamples.length, 2);
assert.equal(sharedRows[0].retainedPositions, 2);
assert.equal(sharedRows[1].label, 'br_table selector 4');
assert.equal(sharedRows[1].opcode, '0x04');
assert.equal(sharedRows[1].state, 'inferred');
assert.equal(sharedRows[1].samples, 1);
assert.equal(sharedRows[1].operandWidth, 1);
assert.equal(sharedRows[1].notes, 'Alone.');
assert.equal(sharedRows[2].label, 'Shared dispatch · 2 selectors');
assert.equal(sharedRows[2].state, 'unknown');
assert.equal(sharedRows[2].samples, 5);
assert.equal(sharedRows[2].operandWidth, 0);
assert.equal(sharedRows[2].notes, 'First indirect. 2 selectors share this instruction and are not separate handler bodies.');
const inferredHandlers = [
  handler(0, 'inferred', 11, 4, 'call_indirect target', 4, 'Mixed labels.', 2),
  handler(1, 'inferred', 11, 4, 'br_table selector 1', 1, 'Still inferred.', 2)
];
const inferredRows = renderApi.vmOpcodeRows({runtime: 'webassembly', handlers: inferredHandlers, samples: []});
assert.equal(inferredRows.length, 1);
assert.equal(inferredRows[0].label, 'Shared dispatch · 2 selectors');
assert.equal(inferredRows[0].state, 'inferred');
assert.equal(inferredRows[0].opcode, 'shared');
assert.equal(inferredRows[0].operandWidth, 2);
assert.equal(inferredRows[0].samples, 5);
const duplicateOpcode = {runtime: 'webassembly', samples: [
  {opcode: 0, instruction_pointer: 8, instruction_pointer_units: 'byte', handler_index: 0, bytecode_artifact_id: '9'}
], handlers: [
  handler(0, 'inferred', 1, 2, 'br_table selector 0', 1, 'A'),
  handler(0, 'inferred', 1, 2, 'br_table selector 0', 1, 'B')
]};
const duplicateRows = renderApi.vmOpcodeRows(duplicateOpcode);
assert.equal(duplicateRows[0].retainedSamples.length, 1);
assert.equal(duplicateRows[0].samples, 2);
assert.equal(duplicateRows[0].state, 'inferred');
const sharedListing = renderApi.renderVmHandlers(sharedWorkspace);
assert(sharedListing.textContent.includes('3 dispatch sites · 6 retained arms'));
assert(!sharedListing.textContent.includes('dispatch-arm candidates'));
const sharedButtons = descendants(sharedListing).filter(node => node.className === 'vm-handler-row');
assert.equal(sharedButtons.length, 3);
assert.equal(sharedButtons[0].dataset.handlerKey, 'span:20465:117');
assert.equal(descendants(sharedButtons[0]).find(node => node.className === 'vm-handler-opcode').textContent, 'shared');
assert.equal(descendants(sharedButtons[0]).find(node => node.className === 'vm-handler-state').dataset.state, 'unknown');
const javascript = structuredClone(hostSource);
const sharedSource = {byte_offset: 10, byte_size: 4};
javascript.handlers = javascript.handlers.slice(0, 2).map(item => ({...item, source: sharedSource}));
const javascriptRows = renderApi.vmOpcodeRows(javascript);
assert.equal(javascriptRows.length, 2);
assert.deepEqual(Array.from(javascriptRows, row => row.key), ['1:0:10', '7:1:10']);
assert(renderApi.renderVmHandlers(javascript).textContent.includes('2 candidate handlers'));
// Authored ranking metadata has exact counts independent of retained handler arms.
const site = (offset, arms, index = 0) => ({kind: arms === null ? 'call_indirect' : 'br_table',
  function_index: index, byte_offset: offset, byte_size: 5, function_body_offset: 40,
  function_body_size: 500, arm_count: arms, unique_target_count: arms === null ? null : arms,
  element_fanout: arms === null ? 40 : null, loop_depth: 1, ip_like: true, structural_score: 60,
  classification: arms === null ? 'indirect-handler-candidate' : arms < 32 ? 'cff-helper-candidate' : 'dispatch-candidate',
  evidence_class: arms === null ? 'call-indirect-table' : arms >= 32 ? 'handler-table-candidate' : 'cff-helper'});
const inventory = {ranking_version: 1, site_count: 3, br_table_count: 2, call_indirect_count: 1,
  omitted_site_count: 0, selected_byte_offset: 45, candidates: [site(45, 200), site(70, 8, 1), site(50, null)]};
const inventoryDocument = structuredClone(fixture);
inventoryDocument.workspaces[0].dispatch_inventory = inventory;
assert(validateModule(inventoryDocument));
for (const mutate of [
  value => { value.site_count = 4; }, value => { value.omitted_site_count = 1; },
  value => { value.selected_byte_offset = 49; }, value => { value.ranking_version = 2; },
  value => { value.candidates[0].arm_count = null; }, value => { value.candidates[2].arm_count = 200; },
  value => { value.candidates[0].unique_target_count = 0; },
  value => { value.candidates[0].unique_target_count = value.candidates[0].arm_count + 2; },
  value => { value.candidates[0].element_fanout = 3; },
  value => { value.candidates[2].classification = 'dispatch-candidate'; },
  value => { value.candidates[2].unique_target_count = 2; },
  value => { value.candidates[2].element_fanout = -1; },
  value => { value.candidates[0].byte_offset = 539; }, value => { value.candidates[0].classification = 'proven-vm'; },
  value => { value.candidates[0].evidence_class = 'guest-opcode-isa'; },
  value => { value.candidates[1].evidence_class = 'handler-table-candidate'; },
  value => { value.candidates[0].byte_size = Number.MAX_SAFE_INTEGER; },
  value => { value.candidates.push(value.candidates[0]); value.site_count++; value.br_table_count++; }
]) {
  const malformed = structuredClone(inventoryDocument); mutate(malformed.workspaces[0].dispatch_inventory);
  assert(!validateModule(malformed), String(mutate));
}
const inventoryPanel = renderApi.renderVmDispatchInventory(inventoryDocument.workspaces[0]);
const inventorySummaries = descendants(inventoryPanel).filter(node => node.tagName === 'summary').map(node => node.textContent);
assert(inventoryPanel.textContent.includes('Default · f0 · br_table · 200 arms + default'));
assert.equal(inventorySummaries[0], '#1 · Default · f0 · br_table · 200 arms + default · 200 unique branch targets · byte 45 · handler-table candidate');
assert.equal(inventorySummaries[1], '#2 · f1 · br_table · 8 arms + default · 8 unique branch targets · byte 70 · CFF / relooper candidate');
assert.equal(inventorySummaries[2], '#3 · f0 · call_indirect · 40 static element entries · byte 50 · indirect funcref candidate');
assert.equal(descendants(inventoryPanel).find(node => node.tagName === 'details').open, true);
assert(inventoryPanel.textContent.includes('CFF / relooper candidate'));
assert(inventoryPanel.textContent.includes('indirect funcref candidate'));
assert(inventoryPanel.textContent.includes('not a proven guest opcode ISA'));
assert(inventoryPanel.textContent.includes('does not invent registers, a stack, or a guest PC'));
assert(inventoryPanel.textContent.includes('CFF helper'));
assert(inventoryPanel.textContent.includes('Handler table candidate'));
assert(inventoryPanel.textContent.includes('Call-indirect table'));
assert(!inventoryPanel.textContent.includes('Guest opcode ISA'));
const promoted = structuredClone(inventoryDocument);
promoted.workspaces[0].evidence_class = 'guest-opcode-isa';
assert(!validateModule(promoted), 'static arms cannot be labeled guest-opcode-isa');
const tables = [{
  kind: 'br_table', evidence_class: 'cff-helper', function_index: 0, byte_offset: 70, byte_size: 5,
  table_index: null, arm_count: 11, entry_count: 11, unique_target_count: 3, default_target: 0,
  omitted_cluster_count: 0,
  clusters: [
    {target: 0, selector_count: 5, selectors: [0, 2, 4, 6, 8]},
    {target: 1, selector_count: 5, selectors: [1, 3, 5, 7, 9]},
    {target: 2, selector_count: 1, selectors: [10]}
  ]
}, {
  kind: 'br_table', evidence_class: 'handler-table-candidate', function_index: 1, byte_offset: 45, byte_size: 5,
  table_index: null, arm_count: 100, entry_count: 100, unique_target_count: 1, default_target: 0,
  omitted_cluster_count: 0,
  clusters: [{target: 0, selector_count: 100, selectors: Array.from({length: 32}, (_, index) => index)}]
}];
const tableWorkspace = {...inventoryDocument.workspaces[0], handler_tables: tables, evidence_class: 'handler-table-candidate'};
assert(validateModule({...inventoryDocument, workspaces: [tableWorkspace]}));
const tablePanel = renderApi.renderVmHandlerTables(tableWorkspace);
assert(tablePanel.textContent.includes('cff-helper'));
assert(tablePanel.textContent.includes('11 arms, 3 unique targets'));
assert(tablePanel.textContent.includes('label depth 0 · selectors 0, 2, 4, 6, 8'));
assert(tablePanel.textContent.includes('listed 32 of 100'));
assert(tablePanel.textContent.includes('do not prove a guest PC'));
assert(!tablePanel.textContent.includes('guest-opcode-isa'));
assert(inventoryPanel.textContent.includes('3 module sites'));
// Structural dispatch classification: closed axes, derived role, inert text.
const shape = (offset, kind, source, repeats, role, extra = {}) => ({artifact_id: workspace.interpreter_artifact_id,
  dispatch_kind: kind, selector_source: source, repeats, role, confidence: 'structural',
  instruction: kind === 'handler_table' ? 'call_indirect' : kind === 'compare_chain' ? 'i32.eq ladder' : 'br_table',
  location: {function_index: 0, function_body_offset: 40, byte_offset: offset, byte_size: 5, line: null, column: null},
  selector: {expression: 'local4 = i32.load8_u[(param0 + local2)]', byte_offset: offset - 4}, arm_count: 200,
  loop: repeats === 'once' ? null : {byte_offset: 41, byte_size: 300}, buffer_kind: null, table: null, ...extra});
const classification = {classification_version: 1, site_count: 4, omitted_site_count: 0,
  role_counts: {'interpreter-candidate': 2, multiplexer: 1, other: 1},
  kind_counts: {switch_on_value: 2, handler_table: 1, compare_chain: 1, export_per_role: 0, threaded: 0},
  sites: [
    shape(45, 'switch_on_value', 'cursor_index', 'loop', 'interpreter-candidate'),
    shape(50, 'handler_table', 'cursor_index', 'loop', 'interpreter-candidate',
      {table: {table_index: 0, type_index: 0, populated_slot_count: 5, matching_slot_count: 4, matching_slots: [1, 2, 3, 5]}, arm_count: 4}),
    shape(70, 'switch_on_value', 'call_argument', 'unknown', 'other'),
    shape(90, 'compare_chain', 'call_argument', 'once', 'multiplexer',
      {selector: {expression: '<img src=x onerror=alert(1)> == constant (4 comparisons)', byte_offset: null}, arm_count: 4})]};
const shapedWorkspace = {...tableWorkspace, dispatch_classification: classification};
shapedWorkspace.handler_tables = [...tables, {kind: 'element', evidence_class: 'call-indirect-table', function_index: null,
  byte_offset: null, byte_size: null, table_index: 0, arm_count: null, entry_count: 5, unique_target_count: 5, default_target: null,
  omitted_cluster_count: 0, clusters: [1, 2, 3, 5, 6].map((slot, target) => ({target, selector_count: 1, selectors: [slot]})),
  segments: [{segment_index: 0, placement: 'placed', offset: 1, global_index: null, entry_count: 3},
    {segment_index: 1, placement: 'relative', offset: null, global_index: 0, entry_count: 2}]}];
const shapedDocument = {...inventoryDocument, workspaces: [shapedWorkspace]};
assert(validateModule(shapedDocument), 'classified workspace with element segments');
for (const mutate of [
  value => { value.dispatch_classification.sites[2].role = 'interpreter-candidate'; },
  value => { value.dispatch_classification.sites[3].role = 'other'; },
  value => { value.dispatch_classification.sites[0].confidence = 'observed'; },
  value => { value.dispatch_classification.sites[0].dispatch_kind = 'vm'; },
  value => { value.dispatch_classification.sites[0].selector_source = 'opcode'; },
  value => { value.dispatch_classification.sites[0].artifact_id = '999'; },
  value => { value.dispatch_classification.sites[0].location.line = 3; },
  value => { value.dispatch_classification.sites[0].selector.expression = 'x'.repeat(161); },
  value => { value.dispatch_classification.site_count = 5; },
  value => { value.dispatch_classification.role_counts.other = 2; },
  value => { value.dispatch_classification.classification_version = 2; },
  value => { value.dispatch_classification.sites[1].table.matching_slots = [1, 1]; },
  value => { value.handler_tables[2].segments[0].offset = null; },
  value => { value.handler_tables[2].segments[1].placement = 'passive'; },
  value => { value.handler_tables[0].segments = []; },
]) {
  const malformed = structuredClone(shapedDocument); mutate(malformed.workspaces[0]);
  assert(!validateModule(malformed), String(mutate));
}
const shapedInventory = renderApi.renderVmDispatchSites(shapedWorkspace);
const shapedSummaries = descendants(shapedInventory).filter(node => node.tagName === 'summary').map(node => node.textContent);
assert.equal(shapedSummaries[0], '#1 · Default · f0 · br_table · 200 arms + default · 200 unique branch targets · byte 45 · handler-table candidate · switch_on_value / cursor_index / loop · cursor-loop interpreter candidate');
assert.equal(shapedSummaries[1], '#2 · f1 · br_table · 8 arms + default · 8 unique branch targets · byte 70 · CFF / relooper candidate · switch_on_value / call_argument / unknown · not an interpreter loop');
assert(shapedSummaries.includes('i32.eq ladder · f0 · byte 90 · compare_chain / call_argument / once · router, no guest opcodes claimed'));
assert(shapedInventory.textContent.includes('4 classified sites: 2 cursor-loop interpreter candidates, 1 router, 1 other'));
assert(shapedInventory.textContent.includes('<img src=x onerror=alert(1)> == constant'), 'selector text stays inert text');
assert(shapedInventory.textContent.includes('4 of 5 placed slots match type 0: 1, 2, 3, 5'));
const shapedTables = renderApi.renderVmHandlerTables(shapedWorkspace);
assert(shapedTables.textContent.includes('br_table · cff-helper · 11 arms, 3 unique targets · switch_on_value / call_argument / unknown · not an interpreter loop'));
assert(shapedTables.textContent.includes('function 0 · selectors 1'));
assert(shapedTables.textContent.includes('segment 0 at slot 1 · 3 entries'));
assert(shapedTables.textContent.includes('segment 1 relative to imported global 0 · 2 entries, slots unknown'));
const javascriptShape = {...javascript, dispatch_classification: {...classification, site_count: 1,
  role_counts: {'interpreter-candidate': 0, multiplexer: 1, other: 0},
  kind_counts: {switch_on_value: 0, handler_table: 0, compare_chain: 1, export_per_role: 0, threaded: 0},
  sites: [{...shape(12, 'compare_chain', 'call_argument', 'once', 'multiplexer'), artifact_id: javascript.interpreter_artifact_id,
    instruction: 'if ladder', location: {function_index: null, function_body_offset: 3, byte_offset: 12, byte_size: 12, line: 7, column: 7}}]}};
const javascriptStructure = renderApi.renderVmDispatchStructure(javascriptShape);
assert(javascriptStructure.textContent.includes('if ladder · line 7:7 · compare_chain / call_argument / once · router, no guest opcodes claimed'));
// A sample cannot promote a router or ordinary branch arm to a guest opcode ISA.
const sampledArm = structuredClone(shapedDocument);
const sampledWorkspace = sampledArm.workspaces[0];
sampledWorkspace.handlers = [handler(3, 'observed', 70, 5, 'br_table f1 selector 3', 0, 'Static selector only.')];
sampledWorkspace.handlers[0].sample_count = 1;
sampledWorkspace.samples = [{...sample, opcode: 3, instruction_pointer_units: 'byte-offset'}];
sampledWorkspace.sample_count = 1;
assert.equal(runInNewContext(`${model}\nvmGuestOpcodeIsaProven(value)`, {value: sampledWorkspace, TextEncoder}), false);
sampledWorkspace.handlers[0].source.byte_offset = 45;
assert.equal(runInNewContext(`${model}\nvmGuestOpcodeIsaProven(value)`, {value: sampledWorkspace, TextEncoder}), true);
delete sampledWorkspace.dispatch_classification;
sampledWorkspace.handlers[0].source.byte_offset = 70;
assert.equal(runInNewContext(`${model}\nvmGuestOpcodeIsaProven(value)`, {value: sampledWorkspace, TextEncoder}), true, 'older documents keep their rule');
console.log('PASS structural dispatch classification: derived roles, router text, element segments, inert selectors and guest-ISA gating');
const rankedHandlers = Array.from({length: 200}, (_, opcode) => handler(opcode, 'inferred', 45, 5,
  `br_table selector ${opcode}`, 0, 'Static selector only.'));
rankedHandlers.push(handler(null, 'unknown', 45, 5, 'br_table default', 0, 'Default branch.'));
const rankedWorkspace = {...inventoryDocument.workspaces[0], handlers: rankedHandlers};
assert.equal(renderApi.vmOpcodeRows(rankedWorkspace)[0].label, 'br_table · 200 selectors + default');
renderApiState.selectedVmHandlerKey = 'null::50';
renderApi.renderVmHandlers(inventoryDocument.workspaces[0]);
assert.equal(renderApiState.selectedVmHandlerKey, 'null::50', 'refresh must preserve an explicitly selected retained site');
renderApiState.selectedVmHandlerKey = null;
renderApi.renderVmHandlers(rankedWorkspace);
assert.equal(renderApiState.selectedVmHandlerKey, 'span:45:5', 'the first ranked retained site is the initial default');
// Exercise the actual selection callback, not just its label or stored key.
const filteredListing = renderApi.renderVmHandlers(inventoryDocument.workspaces[0]);
const filteredNodes = descendants(filteredListing);
const filteredRows = filteredNodes.filter(node => node.className === 'vm-handler-row');
const filteredList = filteredNodes.find(node => node.className === 'vm-handler-list');
const filteredToolbar = filteredNodes.find(node => node.className === 'vm-listing-toolbar');
const retainedFilter = filteredNodes.find(node => node.tagName === 'input');
filteredList.querySelectorAll = () => filteredRows;
filteredToolbar.querySelectorAll = () => descendants(filteredToolbar).filter(node => node.tagName === 'button');
filteredListing.querySelector = () => retainedFilter;
for (const row of filteredRows) { row.closest = () => filteredListing; row.scrollIntoView = () => {}; }
testDocument.querySelectorAll = selector => selector === '.vm-handler-row' ? filteredRows : [];
retainedFilter.value = 'call_indirect'; retainedFilter.dispatchEvent(new Event('input'));
assert.equal(filteredRows[0].hidden, true);
findButton(inventoryPanel, 'Select retained site').click();
assert.equal(retainedFilter.value, '', 'the production selection callback clears an excluding filter');
assert.equal(filteredRows[0].hidden, false);
assert.equal(testDocument.activeElement, filteredRows[0]);
assert.equal(renderApiState.selectedVmHandlerKey, '0::45');
retainedFilter.value = 'call_indirect'; retainedFilter.dispatchEvent(new Event('input'));
assert.equal(filteredRows[0].hidden, true);
const retainedButton = findButton(inventoryPanel, 'Select retained site');
const enter = {type: 'keydown', key: 'Enter', defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }};
retainedButton.dispatchEvent(enter);
assert.equal(enter.defaultPrevented, true, 'Enter is handled by the button, not left to a missing default click');
assert.equal(retainedFilter.value, '', 'Enter on Select retained site clears an excluding filter');
assert.equal(filteredRows[0].hidden, false);
assert.equal(renderApiState.selectedVmHandlerKey, '0::45');
const boundedInventory = structuredClone(inventory);
boundedInventory.candidates = Array.from({length: 65}, (_, index) => site(45 + index * 6, 200, index));
boundedInventory.site_count = 70; boundedInventory.br_table_count = 70; boundedInventory.call_indirect_count = 0;
boundedInventory.omitted_site_count = 5;
const pagedInventory = renderApi.renderVmDispatchInventory({...workspace, dispatch_inventory: boundedInventory});
assert(pagedInventory.textContent.includes('5 omitted'));
findButton(pagedInventory, 'Next dispatch candidates').click(); findButton(pagedInventory, 'Next dispatch candidates').click();
assert(pagedInventory.textContent.includes('f64')); assert(findButton(pagedInventory, 'Next dispatch candidates').disabled);
console.log('PASS ranked module inventory counts, bounded paging, malformed metadata, default-vs-explicit selection and static inference labels');
const symbolTree = app.slice(app.indexOf('      function renderVmOpcodeWorkspaceInPlace('), app.indexOf('      function renderVmDetail('));
assert(symbolTree.includes('const rows = workspace ? vmOpcodeRows(workspace) : [];'));
assert(symbolTree.includes('row.label'));
assert(!symbolTree.includes('workspace.handlers'));
console.log('PASS shared Wasm dispatch spans group in the handler listing; distinct spans and JavaScript rows stay separate');
const samplePanel = new TestElement('section');
renderApi.appendVmPagedRows(samplePanel, sampleRow.retainedSamples, 'retained samples', record => { const row = new TestElement('p'); row.textContent = `Sample ${record.sample_index}`; return row; });
assert.equal(descendants(samplePanel).find(node=>node.dataset.vmPagedRows==='retained samples').children.length,32);
findButton(samplePanel,'Next retained samples').click();findButton(samplePanel,'Next retained samples').click();
assert(samplePanel.textContent.includes('Sample 64'));assert(findButton(samplePanel,'Next retained samples').disabled);
const coverageWorkspace={...hostSource,coverage:{...hostSource.coverage,attributions:Array.from({length:65},(_,index)=>({artifact_id:'401',byte_offset:index,byte_size:1,opcode:1,kind:'opcode',evidence_class:'inferred'}))}};
const coveragePanel=renderApi.renderVmWorkspaceCoverage(coverageWorkspace);
findButton(coveragePanel,'Next byte attributions').click();findButton(coveragePanel,'Next byte attributions').click();
assert(coveragePanel.textContent.includes('bytes [64, 65)'));assert(findButton(coveragePanel,'Next byte attributions').disabled);
console.log('PASS complete bounded Findings paging: 257 effects/instructions, 65 host links/samples, multi-snapshot selection, empty inputs and keyboard focus');

// Native physical observations use independent exact-site counters, not guest PCs.
const nativeDocument = structuredClone(inventoryDocument), nativeWorkspace = nativeDocument.workspaces[0];
const nativeRow = {event:{session_id:'1',process_id:1,sequence_number:'1'},function_index:0,module_byte_offset:45,
  selector:0,table_count:200,sample_index:0,selected_arm:0,is_default:false};
nativeWorkspace.native_wasm_observations = [nativeRow];nativeWorkspace.native_wasm_observation_count = 1;
nativeWorkspace.sample_count = nativeDocument.summary.sample_count = 1;
nativeWorkspace.handlers[0].sample_count = nativeWorkspace.handlers[0].native_wasm_sample_count = 1;
nativeWorkspace.handlers[0].state = 'observed';
assert(validateModule(nativeDocument), 'exact native site can confirm one repeated selector');
assert.equal(nativeWorkspace.handlers[2].sample_count,0);
assert(runInNewContext(`${model}\nvmOpcodeSamplePositions(value)[0]`,{value:[nativeRow],TextEncoder}).includes('guest PC unknown'));
for (const mutate of [
  doc=>{doc.workspaces[0].native_wasm_observations[0].module_byte_offset=70;},
  doc=>{doc.workspaces[0].native_wasm_observations[0].function_index=1;},
  doc=>{doc.workspaces[0].native_wasm_observations[0].table_count=199;},
  doc=>{doc.workspaces[0].native_wasm_observations[0].selector=-1;},
  doc=>{doc.workspaces[0].native_wasm_observations[0].selected_arm=1;},
  doc=>{doc.workspaces[0].native_wasm_observations[0].sample_index=16;},
  doc=>{doc.workspaces[0].native_wasm_observations[0].guest_pc=1;},
  doc=>{doc.workspaces[0].handlers[2].sample_count=doc.workspaces[0].handlers[2].native_wasm_sample_count=1;doc.workspaces[0].handlers[2].state='observed';},
  doc=>{delete doc.workspaces[0].native_wasm_observation_count;}
]) {const invalid=structuredClone(nativeDocument);mutate(invalid);assert(!validateModule(invalid),'malformed or wrong-site native observations rejected');}
const defaultDocument=structuredClone(nativeDocument), dw=defaultDocument.workspaces[0];
Object.assign(dw.native_wasm_observations[0],{selector:0xffffffff,selected_arm:200,is_default:true});
Object.assign(dw.handlers[0],{opcode:null,label:'br_table default'});
assert(validateModule(defaultDocument),'unsigned max selects default without inventing an opcode');
// Producer 2.7.0 keeps physical and guest counts out of sample_count. One
// br_table execution at an adapter site emits both records.
const separateDocument=structuredClone(nativeDocument), sw=separateDocument.workspaces[0];
separateDocument.producer.version='2.7.0';
sw.sample_count=separateDocument.summary.sample_count=0;sw.handlers[0].sample_count=0;
assert(validateModule(separateDocument),'separate native counts accepted from producer 2.7.0');
const summedNew=structuredClone(nativeDocument);summedNew.producer.version='2.7.0';
assert(!validateModule(summedNew),'producer 2.7.0 cannot sum native observations into sample_count');
const bothDocument=structuredClone(defaultDocument), bw=bothDocument.workspaces[0];
bothDocument.producer.version='2.7.0';
bw.sample_count=bothDocument.summary.sample_count=0;
bw.native_guest_samples=[];bw.native_guest_sample_count=0;
Object.assign(bw.handlers[0],{sample_count:0,native_wasm_sample_count:1});
assert(validateModule(bothDocument),'native-only default arm is observed with zero dispatch reports');
bw.handlers[0].sample_count=1;
assert(!validateModule(bothDocument),'native-only default arm cannot report dispatch samples');
bw.handlers[0].sample_count=0;
const executions=runInNewContext(`${model}\nvmOpcodeHandlerRow(workspace, workspace.handlers[0]).samples`,
  {workspace:{...bw,handlers:[{...bw.handlers[0],native_guest_sample_count:1}]},TextEncoder});
assert.equal(executions,1,'one execution with physical and guest records displays once');
const nativePanel=renderApi.renderNativeWasmObservations({...nativeWorkspace,
  native_wasm_observation_count:66,native_wasm_observations:Array.from({length:65},(_,i)=>({...nativeRow,selector:i,selected_arm:i}))});
assert(nativePanel.textContent.includes('not guest-interpreter PCs'));
assert(nativePanel.textContent.includes('1 accepted observations are outside the retained window'));
const nativePageRows=()=>descendants(nativePanel).find(row=>row.dataset.vmPagedRows==='native Wasm observations');
assert.equal(nativePageRows().children.length,32);
const nativeNext=findButton(nativePanel,'Next native Wasm observations');nativeNext.click();nativeNext.click();
assert.equal(nativePageRows().children.length,1);assert(nativePageRows().textContent.includes('selector 64'));assert(nativeNext.disabled);
assert(renderApi.renderNativeWasmObservations({...nativeWorkspace,native_wasm_observations:[],native_wasm_observation_count:0}).textContent.includes('No native Wasm dispatch observations retained'));
// Every native row exposes time, source, category/operation and its exact correlation identity.
assert(nativePanel.textContent.includes('time outside retained event window · session 1 · process 1 · seq 1 · native probe · vm/wasm_dispatch_observation'));
renderApiState.events=[{session_id:'1',process_id:1,sequence_number:'1',monotonic_time_ns:'4242',category:'vm',type:'wasm_dispatch_observation'}];
assert(renderApi.renderNativeWasmObservations({...nativeWorkspace,native_wasm_observations:[nativeRow],native_wasm_observation_count:1}).textContent
  .includes('time 4242 ns · session 1 · process 1 · seq 1 · native probe · vm/wasm_dispatch_observation'));
delete renderApiState.events;
const guestRow={event:{session_id:'101',process_id:3,sequence_number:'105'},invocation_event:{session_id:'101',process_id:3,sequence_number:'104'},
  instance_id:'18446744073709551615',instruction_pointer:1,instruction_pointer_units:'byte-offset',opcode:66,interpretation:'explicit-adapter',module_byte_offset:58};
const guestPanel=renderApi.renderNativeWasmObservations({native_wasm_observations:[],native_wasm_observation_count:0,native_guest_samples:[guestRow],native_guest_sample_count:3});
assert(guestPanel.textContent.includes('session 101 · process 3 · seq 105 · native probe · vm/wasm_guest_dispatch'));
assert(guestPanel.textContent.includes('PC 1 bytes · opcode 66 · instance 18446744073709551615 · explicit-adapter'));
assert(guestPanel.textContent.includes('2 accepted guest samples are outside the retained window.'));
// Older or partially migrated documents: missing, malformed or summed counts never invent or hide rows.
for (const legacy of [{native_guest_samples:[guestRow]},{native_guest_samples:[guestRow],native_guest_sample_count:'7'},
  {native_guest_samples:[guestRow],native_guest_sample_count:0},{native_guest_samples:'bad'},{}]) {
  const text=renderApi.renderNativeWasmObservations(legacy).textContent;
  assert(!text.includes('outside the retained window'),JSON.stringify(legacy));
  assert(!text.includes('NaN'),JSON.stringify(legacy));
}
console.log('PASS native physical and guest rows expose time/source/operation/correlation identity and separate retained-window notices');
if (process.env.REB_NATIVE_WASM_WORKSPACE_INPUT) {
  const actual=JSON.parse(await readFile(process.env.REB_NATIVE_WASM_WORKSPACE_INPUT,'utf8'));
  assert(validateModule(actual),'actual C++ → Rust workspace accepted by shipped viewer');
  assert(actual.workspaces.some(row=>row.native_wasm_observation_count>0));
  const physical=actual.workspaces.flatMap(row=>row.native_wasm_observations??[]);
  assert(physical.length>0 && physical.every(row=>/^(0|[1-9][0-9]{0,19})$/.test(row.monotonic_time_ns)),'physical rows carry canonical decimal event times');
  const identity=runInNewContext(`${model}\nvmNativeRowIdentityText(row, [])`,{row:physical[0],TextEncoder});
  assert.match(identity,new RegExp(`^time ${physical[0].monotonic_time_ns} ns · `),'row time renders without a retained event');
  const legacy=structuredClone(actual);for(const row of legacy.workspaces.flatMap(row=>row.native_wasm_observations??[]))delete row.monotonic_time_ns;
  assert(validateModule(legacy),'documents without the optional time stay valid');
  const badTime=structuredClone(actual);badTime.workspaces.find(row=>row.native_wasm_observations?.length).native_wasm_observations[0].monotonic_time_ns=1;
  assert(!validateModule(badTime),'a numeric time is not a canonical decimal string');
  console.log('PASS actual C++ → Rust → viewer workspace with wide identities');
}
if (process.env.REB_NATIVE_WASM_GOLDEN) {
  for (const mode of ['default','arm','wide-identities','envelope-version','reserved','version','size','truncated','big-endian','sample-index','offset','function','count','flags','parent','identity']) {
    const event=JSON.parse(execFileSync(process.env.REB_NATIVE_WASM_GOLDEN,['--case',mode],{encoding:'utf8'}));
    const valid=runInNewContext(`${model}\nisBrokerEvent(event)`,{event,TextEncoder});
    assert.equal(valid,['default','arm','wide-identities','offset','function','count'].includes(mode),`actual native event ${mode}`);
    const python = spawnSync('python3',['-c',"import runpy,json,sys; runpy.run_path('tools/validate-evidence-store.py')['validate_event'](json.load(sys.stdin),1)"],
      {cwd:root,input:JSON.stringify(event),encoding:'utf8'});
    assert.equal(python.status === 0,valid,`Python/native event ${mode}: ${python.stderr}`);
  }
  console.log('PASS actual C++ → viewer typed payload, unsigned fields, envelope and reserved-byte cases');
}
console.log('PASS native exact-site/default/counter schema regressions');
