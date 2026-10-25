#!/usr/bin/env node
// Authored fixtures and shipped rendering functions only. No captured WASM is executed.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {startSandboxedChromium} from './sandboxed-chromium-startup.mjs';
import {mkdtemp, readFile, writeFile, rm, mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';

const root = fileURLToPath(new URL('..', import.meta.url));
const output = process.env.REB_VM_WORKSPACE_UI_OUTPUT || join(root, 'build/vm-workspace-ui-qa');
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
}
const testDocument = {createElement: tag => new TestElement(tag), createTextNode: text => { const node = new TestElement('#text'); node.textContent = text; return node; }, querySelector: () => null};
const renderApiState = {vmOpcodeWorkspace: hostWorkspace, vmHostLinks: hostLinks, vmHostLinksStatus: 'ready'};
const renderApi = runInNewContext(`${model}\n${helper}\n${renders}\n({renderVmEffects,renderVmReachability,renderVmBytecode,renderVmHostLinks,renderVmSessionSources,renderVmWorkspaceCoverage,appendVmPagedRows,renderVmHandlers,vmOpcodeRows})`, {document: testDocument, state: renderApiState, TextEncoder});
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
}
for (const handler of callerWorkspace.handlers) if (handler.state === 'observed') handler.state = 'inferred';
callerWorkspace.coverage.complete = false;
callerWorkspace.coverage.omissions.push({reason: 'caller-samples-unverified'}, {reason: 'sampler-unavailable'});
assert(validateModule(callerDocument), 'caller provenance remains visible without native proof');
assert(runInNewContext(`${model}\nvmStaticSampleNoticeText(value)`, {value: callerWorkspace, TextEncoder}).includes('not native runtime observations'));
assert(runInNewContext(`${model}\nvmOpcodeSamplePositions(value)[0]`, {value: callerWorkspace.samples, TextEncoder}).startsWith('Caller-reported PC'));
for (const corrupt of [
  doc => { doc.workspaces[0].samples[0].provenance.source = 'native'; },
  doc => { delete doc.workspaces[0].samples[0].provenance; },
  doc => { doc.workspaces[0].samples[0].provenance.source_artifact_sha256 = 'f'.repeat(64); },
  doc => { doc.workspaces[0].samples[0].event.process_id = 7; },
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
assert(sharedListing.textContent.includes('3 dispatch sites · 6 selectors'));
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

if (process.argv.includes('--browser')) {
  fixture.workspaces[0].captured_module_preview = modulePreview;
  const selected = {findingId: 'analysis:c5e529342af22aafd3d7ddbc', sourceArtifactId: '302'};
  const setup = `const fixture=${JSON.stringify(fixture)};const selected=${JSON.stringify(selected)};
const hostWorkspace=${JSON.stringify(hostWorkspace)},hostLinks=${JSON.stringify(hostLinks)};
const state={vmOpcodeWorkspace:fixture,lastValidVmOpcodeWorkspace:fixture,vmOpcodeWorkspaceStatus:'ready',selectedVmHandlerKey:null,vmFindings:[selected],selectedVmFindingId:selected.findingId,
vmAnalysisDocument:{document_digest:fixture.analysis_digest,capture_mode:'unknown'}};
const elements={vmSessionStatus:document.querySelector('#status')};
function render(){document.querySelector('#workspace').replaceChildren(renderVmOpcodeWorkspace(selected));renderVmSessionStatus();}
render();`;
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/app.css"><style>html,body{overflow:auto;height:auto;min-height:100%}body{margin:0}main{padding:16px;max-width:1100px;margin:auto;min-width:0}</style>
</head><body><main><p>Authored static WASM workspace. No module execution or browser capture.</p><div id="status" class="vm-session-status"></div><div id="workspace"></div></main>
<script>${model}\n${helper}\n${renders}\n${setup}</script></body></html>`;
  const css = await readFile(join(root, 'apps/research-ui/app.css'));
  const server = createServer((request, response) => {
    if (request.url === '/') { response.setHeader('content-type', 'text/html'); response.end(html); }
    else if (request.url === '/app.css') { response.setHeader('content-type', 'text/css'); response.end(css); }
    else response.writeHead(404).end();
  });
  const profile = await mkdtemp(join(tmpdir(), 'reb-vm-workspace-'));
  let browser, socket, closed = false, diagnostics = '', sequence = 0;
  const pending = new Map(), errors = [], pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const until = async (test, label, timeoutMs = 10000) => {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) { if (await test()) return; await pause(40); }
    throw Error(`Timed out: ${label}`);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence, timer = setTimeout(() => { pending.delete(id); reject(Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, {resolve, reject, timer}); socket.send(JSON.stringify({id, method, params}));
  });
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  await mkdir(output, {recursive: true});
  try {
    await new Promise((ready, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ready); });
    const chromium = startSandboxedChromium(process.env.REB_UI_CHROMIUM || '/usr/bin/chromium', profile, text => { diagnostics = text; });
    browser = chromium.browser;
    browser.once('close', () => { closed = true; });
    const port = await chromium.ready();
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket = new WebSocket(pages.find(page => page.type === 'page').webSocketDebuggerUrl);
    await new Promise((ready, reject) => { socket.addEventListener('open', ready, {once: true}); socket.addEventListener('error', reject, {once: true}); });
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data), request = pending.get(message.id);
      if (message.method === 'Runtime.exceptionThrown') errors.push(message.params);
      if (!request) return;
      pending.delete(message.id); clearTimeout(request.timer);
      if (message.error) request.reject(Error(message.error.message)); else request.resolve(message.result);
    });
    await send('Runtime.enable'); await send('Page.enable');
    await send('Page.navigate', {url: `http://127.0.0.1:${server.address().port}/`});
    // These three authored arms use distinct source spans, so each stays its own row.
    await until(() => evaluate("document.querySelectorAll('.vm-handler-row').length === 3"), 'WASM handler rows');
    const text = await evaluate('document.body.textContent');
    assert(text.includes('WebAssembly')); assert(text.includes('3 dispatch-arm candidates')); assert(text.includes('unknown'));
    assert.equal(await evaluate("document.querySelectorAll('#workspace img').length"), 0);
    for (const width of [1440, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      const point = await evaluate("(async()=>{const e=document.querySelector('.vm-handler-row');e.scrollIntoView({block:'center'});await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));const b=e.getBoundingClientRect();return{x:b.x+b.width/2,y:b.y+b.height/2};})()");
      for (const type of ['mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', {type, ...point, button: 'left', clickCount: 1});
      for (const type of ['rawKeyDown', 'keyUp']) await send('Input.dispatchKeyEvent', {type, key: 'ArrowDown', code: 'ArrowDown', windowsVirtualKeyCode: 40});
      assert.equal(await evaluate("document.activeElement === document.querySelectorAll('.vm-handler-row')[1]"), true);
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-selected')"), 'true');
      assert.equal(await evaluate("document.querySelector('.vm-selection-inspector h3').textContent"), 'call_indirect target');
      assert((await evaluate("document.querySelector('.vm-selection-inspector').textContent")).includes('50 + 3 bytes'));
      assert.equal(await evaluate("document.querySelectorAll('.vm-selection-inspector img').length"), 0);
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      for (const panel of ['bytecode', 'reachability', 'coverage', 'unknowns', 'experiment', 'host-links', 'sources', 'effects']) {
        await evaluate(`document.querySelector('[data-vm-panel="${panel}"]').click()`);
        assert.equal(await evaluate(`document.querySelector('[data-vm-panel-content="${panel}"]').hidden`), false);
        assert.equal(await evaluate("document.querySelectorAll('.vm-workbench-panels > :not([hidden])').length"), 1);
      }
      await evaluate("document.querySelector('[data-vm-panel=bytecode]').click();document.querySelector('.vm-snapshot-selector').focus()");
      for (const type of ['rawKeyDown', 'keyUp']) await send('Input.dispatchKeyEvent', {type, key: 'End', code: 'End', windowsVirtualKeyCode: 35});
      assert.equal(await evaluate("document.querySelector('.vm-snapshot-selector').value"), '1');
      const moduleText = await evaluate("document.querySelector('[data-vm-panel-content=bytecode]').textContent");
      assert(moduleText.includes('module byte offset45')); assert(moduleText.includes('0e 01'));
      assert(moduleText.includes('This is not a runtime memory snapshot.'));
      assert.equal(await evaluate('fixture.workspaces[0].snapshots.length'), 1);
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      await evaluate('scrollTo(0,0)');
      const {data} = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `wasm-${width}.png`), Buffer.from(data, 'base64'));
      for (const [mode, label] of [['native-stealth', 'Native stealth'], ['cdp-attached', 'CDP attached'], ['unknown', 'Recorded evidence']]) {
        await evaluate(`fixture.workspaces[0].capture_mode=${JSON.stringify(mode)};state.debuggerSession={state:'running',target:{}};renderVmSessionStatus()`);
        assert.equal(await evaluate("document.querySelector('.vm-session-chip').textContent"), label);
        assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
        const capture = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
        await writeFile(join(output, `capture-${mode}-${width}.png`), Buffer.from(capture.data, 'base64'));
      }
      await evaluate("fixture.workspaces[0].capture_mode='native-stealth';state.vmAnalysisDocument.document_digest='stale';renderVmSessionStatus()");
      assert.equal(await evaluate("document.querySelector('.vm-session-chip').textContent"), 'Recorded evidence');
      await evaluate("delete state.vmAnalysisDocument.capture_mode;state.broker='connected';state.sessionMode='live';renderVmSessionStatus()");
      assert.equal(await evaluate("document.querySelector('.vm-session-chip').textContent"), 'Recorded evidence');
      await evaluate("state.vmAnalysisDocument={document_digest:fixture.analysis_digest,capture_mode:'unknown'};renderVmSessionStatus()");

    }
    await evaluate("fixture.workspaces[0].coverage.omissions.push({reason:'sampler-unavailable',detail:'No runtime dispatch samples were retained.'});state.vmOpcodeWorkspace=fixture;state.vmWorkspacePanel='host-links';render()");
    assert((await evaluate('document.body.textContent')).includes('Static only. sampler-unavailable'));
    assert((await evaluate('document.body.textContent')).includes('--emit-dispatch-events-v1'));
    await evaluate("state.vmOpcodeWorkspace=hostWorkspace;state.vmHostLinks=hostLinks;state.vmHostLinksStatus='ready';state.vmWorkspacePanel='host-links';render()");
    assert.equal(await evaluate("document.querySelector('[data-vm-panel-content=\"host-links\"]').hidden"), false);
    assert((await evaluate('document.body.textContent')).includes('event 1:1:50'));
    assert((await evaluate('document.body.textContent')).includes('exact request-value provenance'));
    for (const width of [1440, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      const {data} = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `host-links-${width}.png`), Buffer.from(data, 'base64'));
    }
    await evaluate(`hostLinks.workspaces[0].omissions=['dispatch-samples-unavailable']; hostLinks.workspaces[0].links=[{host_event:hostLinks.workspaces[0].links[0].host_event, category:'network', type:'request_initiated', state:'unknown', reason:'dispatch-samples-unavailable', guest_position:null}]; state.vmHostLinks=hostLinks; state.artifacts=[{artifact_id:'302', session_id:'1', kind:'wasm', url:'wasm://wasm/003c0d96', capture_origin:'webassembly_compile', sha256:hostWorkspace.workspaces[0].source_artifact_sha256, byte_size:8},{artifact_id:'1', session_id:'1', kind:'javascript', url:'chrome://newtab/strings.js', capture_origin:'network_response', sha256:'${'b'.repeat(64)}', byte_size:12}]; state.events=[{session_id:'1'}]; state.sessionMode='live'; state.debuggerSession={scripts:[{script_id:'32', url:'https://newassets.hcaptcha.com/captcha/v1/hsw.js', language:'JavaScript'},{script_id:'25', url:'wasm://module', language:'WebAssembly'}]}; state.vmFindings=[{findingId:selected.findingId, sourceArtifactId:'302'}]; state.selectedVmFindingId=selected.findingId; state.vmAnalysisSelection=null; state.vmWorkspacePanel='host-links'; render();`);
    const staticText = await evaluate("document.querySelector('[data-vm-panel-content=\"host-links\"]').textContent");
    assert(staticText.includes('Static only'));
    assert(staticText.includes('dispatch-samples-unavailable'));
    assert(staticText.includes('guest_position null'));
    assert(staticText.includes('correlation'));
    assert(!staticText.includes('guest_position PC'));
    await evaluate("document.querySelector('[data-vm-panel=\"sources\"]').focus(); document.querySelector('[data-vm-panel=\"sources\"]').click()");
    const sourceText = await evaluate("document.querySelector('[data-vm-panel-content=\"sources\"]').textContent");
    assert(sourceText.includes('chrome://newtab/strings.js'));
    assert(sourceText.includes('hsw.js'));
    assert(sourceText.includes('No page or challenge JavaScript artifact'));
    assert(sourceText.includes('guest_position stays null'));
    assert(!sourceText.includes('wasm://module'));
    for (const width of [1440, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      await evaluate("document.querySelector('[data-vm-panel=\"host-links\"]').click()");
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      const hostShot = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `static-host-links-${width}.png`), Buffer.from(hostShot.data, 'base64'));
      await evaluate("document.querySelector('[data-vm-panel=\"sources\"]').click()");
      const open = await evaluate("(()=>{const button=[...document.querySelectorAll('[data-vm-panel-content=\"sources\"] button')].find(item=>item.textContent==='Open stored artifact'); button.scrollIntoView({block:'center'}); button.focus(); const b=button.getBoundingClientRect(); return {x:b.x, y:b.y, w:b.width, h:b.height, focused:document.activeElement===button};})()");
      assert.equal(open.focused, true);
      assert.equal(open.w > 0 && open.h > 0 && open.x >= 0 && open.y >= 0, true);
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      const sourceShot = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `session-sources-${width}.png`), Buffer.from(sourceShot.data, 'base64'));
    }
    await evaluate("hostLinks.workspace_document_digest='stale';render()");
    assert((await evaluate('document.body.textContent')).includes('Guest position unknown'));
    await evaluate("state.vmOpcodeWorkspace=fixture;state.vmHostLinks=null;render()");
    await evaluate("retainVmOpcodeWorkspaceOnFailure(state,'malformed','synthetic malformed fixture');render()");
    assert((await evaluate('document.body.textContent')).includes('last valid workspace is retained'));
    await evaluate("state.vmOpcodeWorkspace={...fixture,workspaces:[]};state.vmOpcodeWorkspaceStatus='ready';render()");
    assert.equal(await evaluate("document.querySelectorAll('.vm-handler-row').length"), 0);
    assert((await evaluate('document.body.textContent')).includes('Workspace unavailable for this finding'));
    await evaluate(`state.vmOpcodeWorkspace=${JSON.stringify(callerDocument)};state.lastValidVmOpcodeWorkspace=state.vmOpcodeWorkspace;state.vmOpcodeWorkspaceStatus='ready';state.vmHostLinks=null;state.selectedVmHandlerKey=null;render()`);
    assert((await evaluate('document.body.textContent')).includes('not native runtime observations'));
    for (const width of [1440, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      await evaluate("(()=>{const key=vmOpcodeRows(state.vmOpcodeWorkspace.workspaces[0]).find(row=>row.retainedSamples.length).key;[...document.querySelectorAll('.vm-handler-row')].find(row=>row.dataset.handlerKey===key).click();})()");
      assert((await evaluate("document.querySelector('.vm-selection-inspector').textContent")).includes('Caller-reported PC'));
      await evaluate("document.querySelector('.vm-selection-inspector details summary').click()");
      assert((await evaluate("document.querySelector('.vm-selection-inspector details').textContent")).includes('caller-supplied'));
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      const callerShot = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `caller-reports-${width}.png`), Buffer.from(callerShot.data, 'base64'));
    }
    await evaluate("retainVmOpcodeWorkspaceOnFailure(state,'malformed','unknown caller provenance');render()");
    assert((await evaluate('document.body.textContent')).includes('last valid workspace is retained'));
    assert((await evaluate('document.body.textContent')).includes('not native runtime observations'));
    assert.deepEqual(errors, []);
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'passed', viewports: [1440, 390],
      scope: 'Shipped workspace rendering with authored fixtures; no native capture, WASM execution or full-app polling acceptance'}, null, 2));
    console.log(`PASS rendered WASM rows and persisted capture modes, keyboard selection, inert text, narrow layout, retained error and empty states: ${output}`);
  } catch (error) {
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'failed', error: String(error.stack || error), diagnostics, errors}, null, 2));
    throw error;
  } finally {
    for (const request of pending.values()) clearTimeout(request.timer);
    socket?.close();
    if (browser?.pid) {
      for (const signal of ['SIGTERM', 'SIGKILL']) {
        try { if (process.platform !== 'win32') process.kill(-browser.pid, signal); else if (!closed) browser.kill(signal); }
        catch (error) { if (error.code !== 'ESRCH') throw error; }
        const end = Date.now() + 2000; while (!closed && Date.now() < end) await pause(25);
        if (closed) break;
      }
    }
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    if (!browser?.pid || closed) await rm(profile, {recursive: true, force: true, maxRetries: 5, retryDelay: 100});
    else throw Error(`Browser did not close; retained its owned profile at ${profile}`);
  }
}
